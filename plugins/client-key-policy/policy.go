package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Policy is a provider policy stored in Vault under <prefix>/policies/<name>.
type Policy struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Providers lists the CPA provider keys this policy may use. "*" allows every provider.
	Providers []string `json:"providers"`
	// AllowModels optionally restricts models with glob patterns matched against
	// "model" or "provider/model". Empty allows every model of the allowed providers.
	AllowModels []string `json:"allow_models,omitempty"`
	// DenyModels removes models matched by glob patterns; deny wins over allow.
	DenyModels []string `json:"deny_models,omitempty"`
	// Aliases maps a client-visible name to a provider/model target.
	Aliases map[string]Target `json:"aliases,omitempty"`
	// Winners resolves a model name served by several allowed providers to one
	// provider. Without a winner, colliding models are exposed as provider/model.
	Winners map[string]string `json:"winners,omitempty"`
}

// Target is an upstream provider/model pair.
type Target struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// Catalog maps provider keys to the models they currently serve.
type Catalog map[string][]string

// View is the resolved set of models a policy exposes to its clients.
type View struct {
	// Models maps client-visible model names to their upstream target.
	Models map[string]Target
	// targets indexes every allowed provider/model pair for enforcement.
	targets map[string]map[string]struct{}
}

func (p *Policy) normalize() {
	p.Name = strings.TrimSpace(p.Name)
	p.Description = strings.TrimSpace(p.Description)
	p.Providers = normalizeList(p.Providers, true)
	p.AllowModels = normalizeList(p.AllowModels, false)
	p.DenyModels = normalizeList(p.DenyModels, false)
	aliases := make(map[string]Target, len(p.Aliases))
	for name, target := range p.Aliases {
		name = strings.TrimSpace(name)
		target.Provider = strings.ToLower(strings.TrimSpace(target.Provider))
		target.Model = strings.TrimSpace(target.Model)
		if name != "" {
			aliases[name] = target
		}
	}
	p.Aliases = aliases
	winners := make(map[string]string, len(p.Winners))
	for model, provider := range p.Winners {
		model = strings.TrimSpace(model)
		provider = strings.ToLower(strings.TrimSpace(provider))
		if model != "" && provider != "" {
			winners[model] = provider
		}
	}
	p.Winners = winners
}

// Validate checks a normalized policy.
func (p *Policy) Validate() error {
	if !namePattern.MatchString(p.Name) {
		return fmt.Errorf("policy name must match %s", namePattern.String())
	}
	if len(p.Providers) == 0 {
		return fmt.Errorf("policy must allow at least one provider (use * for all)")
	}
	for _, pattern := range append(append([]string{}, p.AllowModels...), p.DenyModels...) {
		if _, errMatch := path.Match(pattern, ""); errMatch != nil {
			return fmt.Errorf("invalid model pattern %q", pattern)
		}
	}
	for name, target := range p.Aliases {
		if strings.ContainsAny(name, " \t\r\n") {
			return fmt.Errorf("alias %q must not contain whitespace", name)
		}
		if target.Provider == "" || target.Model == "" {
			return fmt.Errorf("alias %q needs a provider and a model", name)
		}
		if !p.allowsProvider(target.Provider) {
			return fmt.Errorf("alias %q targets provider %q which the policy does not allow", name, target.Provider)
		}
	}
	for model, provider := range p.Winners {
		if !p.allowsProvider(provider) {
			return fmt.Errorf("winner for %q is provider %q which the policy does not allow", model, provider)
		}
	}
	return nil
}

func (p *Policy) allowsProvider(provider string) bool {
	for _, allowed := range p.Providers {
		if allowed == "*" || allowed == provider {
			return true
		}
	}
	return false
}

func (p *Policy) allowsModel(provider, model string) bool {
	qualified := provider + "/" + model
	if matchesAny(p.DenyModels, model, qualified) {
		return false
	}
	if len(p.AllowModels) == 0 {
		return true
	}
	return matchesAny(p.AllowModels, model, qualified)
}

// Resolve computes the models this policy exposes for the given catalog.
func (p *Policy) Resolve(catalog Catalog) View {
	view := View{Models: map[string]Target{}, targets: map[string]map[string]struct{}{}}

	// Group allowed provider/model pairs by bare model name.
	byModel := map[string][]string{}
	for provider, models := range catalog {
		if !p.allowsProvider(provider) {
			continue
		}
		for _, model := range models {
			if p.allowsModel(provider, model) {
				byModel[model] = append(byModel[model], provider)
			}
		}
	}
	for model, providers := range byModel {
		sort.Strings(providers)
		providers = uniqueSorted(providers)
		if len(providers) == 1 {
			view.add(model, Target{Provider: providers[0], Model: model})
			continue
		}
		if winner, ok := p.Winners[model]; ok && contains(providers, winner) {
			// Losers do not contribute this model name at all.
			view.add(model, Target{Provider: winner, Model: model})
			continue
		}
		for _, provider := range providers {
			view.add(displayPrefix(provider, catalog)+"/"+model, Target{Provider: provider, Model: model})
		}
	}
	// Aliases are explicit grants and override catalog-derived names.
	for name, target := range p.Aliases {
		if p.allowsProvider(target.Provider) {
			view.add(name, target)
		}
	}
	return view
}

// displayPrefix shortens openai-compatibility provider keys for client-visible
// names ("openai-compatible-openrouter" -> "openrouter"), unless the short form
// would collide with another provider key.
func displayPrefix(provider string, catalog Catalog) string {
	short := strings.TrimPrefix(provider, "openai-compatible-")
	if short == provider || short == "" {
		return provider
	}
	if _, taken := catalog[short]; taken {
		return provider
	}
	return short
}

func (v *View) add(name string, target Target) {
	v.Models[name] = target
	if v.targets[target.Provider] == nil {
		v.targets[target.Provider] = map[string]struct{}{}
	}
	v.targets[target.Provider][target.Model] = struct{}{}
}

// Lookup resolves a client-requested model (optionally with a thinking suffix).
func (v View) Lookup(requested string) (Target, bool) {
	base, suffix := splitThinkingSuffix(requested)
	target, ok := v.Models[base]
	if !ok {
		return Target{}, false
	}
	target.Model += suffix
	return target, true
}

// Permits reports whether the view grants the upstream provider/model pair.
func (v View) Permits(provider, model string) bool {
	base, _ := splitThinkingSuffix(model)
	models := v.targets[strings.ToLower(strings.TrimSpace(provider))]
	_, ok := models[base]
	return ok
}

// SortedNames returns the exposed model names in stable order.
func (v View) SortedNames() []string {
	names := make([]string, 0, len(v.Models))
	for name := range v.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// splitThinkingSuffix separates CPA's "model(suffix)" thinking notation.
func splitThinkingSuffix(model string) (string, string) {
	model = strings.TrimSpace(model)
	if strings.HasSuffix(model, ")") {
		if idx := strings.LastIndex(model, "("); idx > 0 {
			return model[:idx], model[idx:]
		}
	}
	return model, ""
}

func matchesAny(patterns []string, values ...string) bool {
	for _, pattern := range patterns {
		for _, value := range values {
			if ok, _ := path.Match(pattern, value); ok {
				return true
			}
		}
	}
	return false
}

func normalizeList(values []string, lower bool) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueSorted(values []string) []string {
	out := values[:0]
	for i, value := range values {
		if i == 0 || value != values[i-1] {
			out = append(out, value)
		}
	}
	return out
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
