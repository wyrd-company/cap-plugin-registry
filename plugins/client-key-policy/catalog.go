package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// catalogFetcher reads which models each CPA provider serves from the CPA
// Management API, since the plugin ABI has no host callback for the model registry.
type catalogFetcher struct {
	cfg  CPAConfig
	http *http.Client
}

func newCatalogFetcher(cfg CPAConfig) *catalogFetcher {
	return &catalogFetcher{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
}

func (f *catalogFetcher) Fetch(ctx context.Context) (Catalog, error) {
	key := envValue(f.cfg.ManagementKeyEnv)
	if key == "" {
		return nil, fmt.Errorf("management key env %s is empty", f.cfg.ManagementKeyEnv)
	}
	var list struct {
		Files []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Provider string `json:"provider"`
			Disabled bool   `json:"disabled"`
		} `json:"files"`
	}
	if errGet := f.get(ctx, "/v8/management/credentials", key, &list); errGet != nil {
		return nil, errGet
	}
	sets := map[string]map[string]struct{}{}
	add := func(provider, model string) {
		provider = strings.ToLower(strings.TrimSpace(provider))
		model = strings.TrimSpace(model)
		if provider == "" || model == "" {
			return
		}
		if sets[provider] == nil {
			sets[provider] = map[string]struct{}{}
		}
		sets[provider][model] = struct{}{}
	}
	for _, file := range list.Files {
		provider := strings.ToLower(strings.TrimSpace(file.Provider))
		if provider == "" || file.Disabled {
			continue
		}
		id := file.ID
		if id == "" {
			id = file.Name
		}
		var models struct {
			Models []struct {
				ID string `json:"id"`
			} `json:"models"`
		}
		if errGet := f.get(ctx, "/v8/management/credentials/models?name="+url.QueryEscape(id), key, &models); errGet != nil {
			return nil, errGet
		}
		for _, model := range models.Models {
			add(provider, model.ID)
		}
	}
	// API-key providers defined in config.yaml are not listed as credentials,
	// so derive their models from the configuration itself.
	if errConfig := f.addConfigProviders(ctx, key, add); errConfig != nil {
		return nil, errConfig
	}
	catalog := Catalog{}
	for provider, models := range sets {
		names := make([]string, 0, len(models))
		for model := range models {
			names = append(names, model)
		}
		sort.Strings(names)
		catalog[provider] = names
	}
	return catalog, nil
}

type configModel struct {
	Name  string `json:"name"`
	Alias string `json:"alias"`
}

type configEntry struct {
	Name           string        `json:"name"`
	Prefix         string        `json:"prefix"`
	Disabled       bool          `json:"disabled"`
	Models         []configModel `json:"models"`
	ExcludedModels []string      `json:"excluded-models"`
}

func (f *catalogFetcher) addConfigProviders(ctx context.Context, key string, add func(provider, model string)) error {
	var cfg struct {
		APIKeys map[string]json.RawMessage `json:"api-keys"`
	}
	if errGet := f.get(ctx, "/v8/management/config", key, &cfg); errGet != nil {
		return errGet
	}
	for group, raw := range cfg.APIKeys {
		var entries []configEntry
		if json.Unmarshal(raw, &entries) != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Disabled {
				continue
			}
			provider := group
			if group == "openai-compatibility" {
				provider = openAICompatibleProviderKey(entry.Name)
			}
			names := make([]string, 0, len(entry.Models))
			for _, model := range entry.Models {
				name := model.Alias
				if name == "" {
					name = model.Name
				}
				names = append(names, name)
			}
			if len(names) == 0 && group != "openai-compatibility" {
				names = f.staticModels(ctx, key, group)
			}
			for _, name := range names {
				if matchesExcluded(entry.ExcludedModels, name) {
					continue
				}
				if prefix := strings.Trim(entry.Prefix, "/ "); prefix != "" {
					name = prefix + "/" + name
				}
				add(provider, name)
			}
		}
	}
	return nil
}

// staticModels returns CPA's built-in model definitions for a channel; unknown
// channels yield nothing.
func (f *catalogFetcher) staticModels(ctx context.Context, key, channel string) []string {
	var defs struct {
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if f.get(ctx, "/v8/management/routing/model-definitions/"+url.PathEscape(channel), key, &defs) != nil {
		return nil
	}
	out := make([]string, 0, len(defs.Models))
	for _, model := range defs.Models {
		out = append(out, model.ID)
	}
	return out
}

// openAICompatibleProviderKey mirrors CPA's provider key for openai-compatibility entries.
func openAICompatibleProviderKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case name == "":
		return "openai-compatibility"
	case name == "openai-compatibility" || strings.HasPrefix(name, "openai-compatible-"):
		return name
	}
	return "openai-compatible-" + name
}

// matchesExcluded applies CPA's excluded-models wildcard semantics (* only).
func matchesExcluded(patterns []string, model string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		parts := strings.Split(pattern, "*")
		if len(parts) == 1 {
			if pattern == model {
				return true
			}
			continue
		}
		rest := model
		ok := strings.HasPrefix(rest, parts[0])
		rest = strings.TrimPrefix(rest, parts[0])
		for _, part := range parts[1 : len(parts)-1] {
			idx := strings.Index(rest, part)
			if idx < 0 {
				ok = false
				break
			}
			rest = rest[idx+len(part):]
		}
		if ok && strings.HasSuffix(rest, parts[len(parts)-1]) {
			return true
		}
	}
	return false
}

func (f *catalogFetcher) get(ctx context.Context, path, key string, out any) error {
	req, errNew := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.ManagementURL+path, nil)
	if errNew != nil {
		return errNew
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, errDo := f.http.Do(req)
	if errDo != nil {
		return fmt.Errorf("cpa catalog %s: %w", path, errDo)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if errRead != nil {
		return fmt.Errorf("cpa catalog %s: %w", path, errRead)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cpa catalog %s: status %d", path, resp.StatusCode)
	}
	if errUnmarshal := json.Unmarshal(raw, out); errUnmarshal != nil {
		return fmt.Errorf("cpa catalog %s: decode: %w", path, errUnmarshal)
	}
	return nil
}
