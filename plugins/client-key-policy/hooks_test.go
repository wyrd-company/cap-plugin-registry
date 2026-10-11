package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"testing"
)

func testRuntime(t *testing.T) (*runtime, *client) {
	t.Helper()
	cfg := defaultConfig()
	rt, err := newRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	policy := &Policy{Name: "team", Providers: []string{"codex", "claude"}, Winners: map[string]string{}}
	policy.normalize()
	record := &client{ID: "team/bot", Policy: "team", Name: "bot", keyHash: sha256.Sum256([]byte("cpa_secret"))}
	rt.snap.Store(buildSnapshot(map[string]*Policy{"team": policy}, map[string]*client{record.ID: record}, testCatalog))
	return rt, record
}

func call[T any](t *testing.T, fn func([]byte) (any, error), req any) T {
	t.Helper()
	raw, _ := json.Marshal(req)
	out, err := fn(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(out)
	var decoded T
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestFrontendAuth(t *testing.T) {
	rt, _ := testRuntime(t)
	ok := call[frontendAuthResponse](t, rt.handleFrontendAuth, map[string]any{"Headers": http.Header{"Authorization": {"Bearer cpa_secret"}}})
	if !ok.Authenticated || ok.Principal != "team/bot" || ok.Metadata["policy"] != "team" {
		t.Fatalf("unexpected auth result %#v", ok)
	}
	withHeader := call[frontendAuthResponse](t, rt.handleFrontendAuth, map[string]any{"Headers": http.Header{"X-Api-Key": {"cpa_secret"}, "X-Cpa-Client-Id": {"team/bot"}}})
	if !withHeader.Authenticated {
		t.Fatal("client id header path should authenticate")
	}
	rt.lastMiss.Store(1 << 62) // suppress Vault refresh on miss
	wrongID := call[frontendAuthResponse](t, rt.handleFrontendAuth, map[string]any{"Headers": http.Header{"X-Api-Key": {"cpa_secret"}, "X-Cpa-Client-Id": {"team/other"}}})
	if wrongID.Authenticated {
		t.Fatal("mismatched client id must not authenticate")
	}
	bad := call[frontendAuthResponse](t, rt.handleFrontendAuth, map[string]any{"Headers": http.Header{"Authorization": {"Bearer nope"}}})
	if bad.Authenticated {
		t.Fatal("unknown key must not authenticate")
	}
}

func TestRouteAndIntercept(t *testing.T) {
	rt, record := testRuntime(t)
	meta := map[string]any{"caller_scope": callerScope(record.ID)}
	route := call[modelRouteResponse](t, rt.handleModelRoute, map[string]any{"RequestedModel": "claude-sonnet-4-6", "Metadata": meta})
	if !route.Handled || route.Target != "claude" || route.TargetModel != "claude-sonnet-4-6" {
		t.Fatalf("route = %#v", route)
	}
	allowed := call[requestInterceptResponse](t, rt.handleInterceptBefore, map[string]any{"RequestedModel": "gpt-5", "Metadata": meta})
	if allowed.Terminate {
		t.Fatal("gpt-5 should be allowed")
	}
	denied := call[requestInterceptResponse](t, rt.handleInterceptBefore, map[string]any{"RequestedModel": "llama-4", "Metadata": meta})
	if !denied.Terminate || denied.StatusCode != http.StatusForbidden {
		t.Fatalf("llama-4 should be denied: %#v", denied)
	}
	internal := call[requestInterceptResponse](t, rt.handleInterceptBefore, map[string]any{"RequestedModel": "llama-4"})
	if internal.Terminate {
		t.Fatal("host-internal requests without caller identity pass through")
	}
}

func TestSchedulerEnforcesProviders(t *testing.T) {
	rt, record := testRuntime(t)
	opts := map[string]any{"Metadata": map[string]any{"caller_scope": callerScope(record.ID)}}
	pick := func(model string, providers ...string) schedulerPickResponse {
		candidates := []map[string]string{}
		for i, p := range providers {
			candidates = append(candidates, map[string]string{"ID": p + string(rune('0'+i)), "Provider": p})
		}
		return call[schedulerPickResponse](t, rt.handleSchedulerPick, map[string]any{"Model": model, "Options": opts, "Candidates": candidates})
	}
	if r := pick("gpt-5", "codex"); r.Handled {
		t.Fatalf("all permitted should delegate to CPA: %#v", r)
	}
	if r := pick("gpt-5", "codex", "openai-compatible-openrouter"); !r.Handled || r.Reject || r.AuthID != "codex0" {
		t.Fatalf("expected pick of codex candidate: %#v", r)
	}
	if r := pick("llama-4", "openai-compatible-openrouter"); !r.Handled || !r.Reject {
		t.Fatalf("expected rejection: %#v", r)
	}
	unknown := call[schedulerPickResponse](t, rt.handleSchedulerPick, map[string]any{
		"Model": "gpt-5", "Options": map[string]any{"Metadata": map[string]any{"caller_scope": "deadbeef"}},
		"Candidates": []map[string]string{{"ID": "a", "Provider": "codex"}},
	})
	if !unknown.Reject {
		t.Fatal("unknown caller scope must be rejected")
	}
}

func TestFilterModelLists(t *testing.T) {
	rt, _ := testRuntime(t)
	openai := `{"object":"list","data":[{"id":"gpt-5","object":"model","owned_by":"openai"},{"id":"llama-4","object":"model"}]}`
	resp := call[responseInterceptResponse](t, rt.handleResponseIntercept, map[string]any{
		"SourceFormat": "openai", "RequestHeaders": http.Header{"Authorization": {"Bearer cpa_secret"}}, "Body": []byte(openai),
	})
	var doc struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, d := range doc.Data {
		ids = append(ids, d["id"].(string))
	}
	want := []string{"claude-sonnet-4-6", "gpt-5", "gpt-5-mini"}
	if len(ids) != len(want) || ids[0] != want[0] || ids[1] != want[1] || ids[2] != want[2] {
		t.Fatalf("ids = %v, want %v", ids, want)
	}

	gemini := `{"models":[{"name":"models/gpt-5","displayName":"GPT 5"}]}`
	resp = call[responseInterceptResponse](t, rt.handleResponseIntercept, map[string]any{
		"SourceFormat": "gemini", "RequestHeaders": http.Header{"X-Goog-Api-Key": {"cpa_secret"}}, "Body": []byte(gemini),
	})
	var gdoc struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(resp.Body, &gdoc); err != nil {
		t.Fatal(err)
	}
	if len(gdoc.Models) != 3 || gdoc.Models[1]["name"] != "models/gpt-5" {
		t.Fatalf("gemini models = %v", gdoc.Models)
	}

	anon := call[responseInterceptResponse](t, rt.handleResponseIntercept, map[string]any{"SourceFormat": "openai", "Body": []byte(openai)})
	if err := json.Unmarshal(anon.Body, &doc); err != nil || len(doc.Data) != 0 {
		t.Fatalf("unidentified caller should see an empty list, got %s", anon.Body)
	}

	completion := call[responseInterceptResponse](t, rt.handleResponseIntercept, map[string]any{"Model": "gpt-5", "Body": []byte(`{}`)})
	if len(completion.Body) != 0 {
		t.Fatal("completion responses must pass through")
	}
}

func modelIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var doc struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, d := range doc.Data {
		ids = append(ids, d["id"].(string))
	}
	return ids
}

// A ?key= caller reaches the model-list hook with neither headers nor metadata
// identifying it (CPA's current behaviour), so it gets an empty list; once the
// host forwards caller_scope, the same request is filtered to the policy view.
func TestModelListForQueryKeyCaller(t *testing.T) {
	rt, record := testRuntime(t)
	list := []byte(`{"object":"list","data":[{"id":"gpt-5","object":"model"}]}`)

	current := call[responseInterceptResponse](t, rt.handleResponseIntercept, map[string]any{
		"SourceFormat": "openai", "RequestHeaders": http.Header{}, "Body": list,
	})
	if ids := modelIDs(t, current.Body); len(ids) != 0 {
		t.Fatalf("unidentified ?key= caller should get an empty list, got %v", ids)
	}

	withScope := call[responseInterceptResponse](t, rt.handleResponseIntercept, map[string]any{
		"SourceFormat": "openai", "RequestHeaders": http.Header{}, "Body": list,
		"Metadata": map[string]any{"caller_scope": callerScope(record.ID)},
	})
	if ids := modelIDs(t, withScope.Body); len(ids) != 3 || ids[1] != "gpt-5" {
		t.Fatalf("caller_scope should resolve the policy view, got %v", ids)
	}
}
