package main

import (
	"reflect"
	"testing"
)

var testCatalog = Catalog{
	"codex":                        {"gpt-5", "gpt-5-mini"},
	"claude":                       {"claude-sonnet-4-6"},
	"openai-compatible-openrouter": {"gpt-5", "claude-sonnet-4-6", "llama-4"},
}

func resolve(t *testing.T, p Policy) View {
	t.Helper()
	p.normalize()
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	return p.Resolve(testCatalog)
}

func TestResolvePrefixesCollisions(t *testing.T) {
	view := resolve(t, Policy{Name: "a", Providers: []string{"codex", "openai-compatible-openrouter"}})
	want := map[string]Target{
		"codex/gpt-5":       {"codex", "gpt-5"},
		"openrouter/gpt-5":  {"openai-compatible-openrouter", "gpt-5"},
		"gpt-5-mini":        {"codex", "gpt-5-mini"},
		"claude-sonnet-4-6": {"openai-compatible-openrouter", "claude-sonnet-4-6"},
		"llama-4":           {"openai-compatible-openrouter", "llama-4"},
	}
	if !reflect.DeepEqual(view.Models, want) {
		t.Fatalf("Models = %#v, want %#v", view.Models, want)
	}
}

func TestResolveWinnerDropsLosers(t *testing.T) {
	view := resolve(t, Policy{
		Name:      "a",
		Providers: []string{"*"},
		Winners:   map[string]string{"gpt-5": "codex", "claude-sonnet-4-6": "claude"},
	})
	if got := view.Models["gpt-5"]; got != (Target{"codex", "gpt-5"}) {
		t.Fatalf("gpt-5 = %#v", got)
	}
	if _, ok := view.Models["openrouter/gpt-5"]; ok {
		t.Fatal("loser should not contribute a prefixed name")
	}
	if view.Permits("openai-compatible-openrouter", "gpt-5") {
		t.Fatal("loser provider must not be permitted for gpt-5")
	}
	if !view.Permits("openai-compatible-openrouter", "llama-4") {
		t.Fatal("non-colliding model of loser should remain permitted")
	}
}

func TestResolveAllowDenyAndAliases(t *testing.T) {
	view := resolve(t, Policy{
		Name:        "a",
		Providers:   []string{"codex", "claude"},
		AllowModels: []string{"gpt-5*", "claude/*"},
		DenyModels:  []string{"gpt-5-mini"},
		Aliases:     map[string]Target{"fast": {Provider: "codex", Model: "gpt-5-mini"}},
	})
	names := view.SortedNames()
	want := []string{"claude-sonnet-4-6", "fast", "gpt-5"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	target, ok := view.Lookup("fast(high)")
	if !ok || target != (Target{"codex", "gpt-5-mini(high)"}) {
		t.Fatalf("Lookup(fast(high)) = %#v, %v", target, ok)
	}
	if !view.Permits("codex", "gpt-5-mini(high)") {
		t.Fatal("alias target should be permitted")
	}
	if view.Permits("openai-compatible-openrouter", "gpt-5") {
		t.Fatal("provider outside the policy must not be permitted")
	}
}

func TestValidateRejectsAliasOutsidePolicy(t *testing.T) {
	p := Policy{Name: "a", Providers: []string{"codex"}, Aliases: map[string]Target{"x": {Provider: "claude", Model: "m"}}}
	p.normalize()
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for alias targeting a disallowed provider")
	}
}

func TestDisplayPrefixKeepsFullKeyOnCollision(t *testing.T) {
	catalog := Catalog{"codex": {"m"}, "openai-compatible-codex": {"m"}}
	p := Policy{Name: "a", Providers: []string{"*"}}
	p.normalize()
	view := p.Resolve(catalog)
	if _, ok := view.Models["openai-compatible-codex/m"]; !ok {
		t.Fatalf("expected full key when short prefix collides, got %v", view.SortedNames())
	}
	if _, ok := view.Models["codex/m"]; !ok {
		t.Fatalf("expected codex/m, got %v", view.SortedNames())
	}
}
