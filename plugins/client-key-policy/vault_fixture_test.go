package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeKV is a minimal in-memory KV v2 engine with check-and-set semantics,
// mounted at "secret".
type fakeKV struct {
	mu      sync.Mutex
	secrets map[string]fakeSecret
}

type fakeSecret struct {
	version  int
	data     map[string]any
	versions map[int]map[string]any // nil value = destroyed
}

func newFakeVault(t *testing.T) (*fakeKV, *httptest.Server) {
	t.Helper()
	kv := &fakeKV{secrets: map[string]fakeSecret{}}
	srv := httptest.NewServer(http.HandlerFunc(kv.serve))
	t.Cleanup(srv.Close)
	return kv, srv
}

func (kv *fakeKV) serve(w http.ResponseWriter, r *http.Request) {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	writeJSON := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
		path := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
		switch r.Method {
		case http.MethodGet:
			secret, ok := kv.secrets[path]
			if !ok {
				writeJSON(http.StatusNotFound, map[string]any{"errors": []string{}})
				return
			}
			writeJSON(http.StatusOK, map[string]any{"data": map[string]any{"data": secret.data, "metadata": map[string]any{"version": secret.version}}})
		case http.MethodPost:
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				Data    map[string]any `json:"data"`
				Options *struct {
					CAS *int `json:"cas"`
				} `json:"options"`
			}
			_ = json.Unmarshal(raw, &body)
			current := kv.secrets[path].version
			if body.Options != nil && body.Options.CAS != nil && *body.Options.CAS != current {
				writeJSON(http.StatusBadRequest, map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}})
				return
			}
			secret := kv.secrets[path]
			if secret.versions == nil {
				secret.versions = map[int]map[string]any{}
			}
			secret.version, secret.data = current+1, body.Data
			secret.versions[secret.version] = body.Data
			kv.secrets[path] = secret
			writeJSON(http.StatusOK, map[string]any{"data": map[string]any{"version": current + 1}})
		}
	case strings.HasPrefix(r.URL.Path, "/v1/secret/destroy/") && r.Method == http.MethodPost:
		path := strings.TrimPrefix(r.URL.Path, "/v1/secret/destroy/")
		var body struct {
			Versions []int `json:"versions"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		secret := kv.secrets[path]
		for _, v := range body.Versions {
			if _, ok := secret.versions[v]; ok {
				secret.versions[v] = nil
			}
		}
		kv.secrets[path] = secret
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/"):
		path := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/")
		switch r.Method {
		case "LIST":
			prefix := strings.TrimSuffix(path, "/") + "/"
			seen := map[string]struct{}{}
			for key := range kv.secrets {
				if rest, ok := strings.CutPrefix(key, prefix); ok {
					if head, _, nested := strings.Cut(rest, "/"); nested {
						seen[head+"/"] = struct{}{}
					} else {
						seen[rest] = struct{}{}
					}
				}
			}
			if len(seen) == 0 {
				writeJSON(http.StatusNotFound, map[string]any{"errors": []string{}})
				return
			}
			keys := make([]string, 0, len(seen))
			for key := range seen {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			writeJSON(http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})
		case http.MethodDelete:
			delete(kv.secrets, path)
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		writeJSON(http.StatusNotFound, map[string]any{"errors": []string{"unsupported"}})
	}
}

func (kv *fakeKV) apiKey(path string) string {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	key, _ := kv.secrets[path].data["api_key"].(string)
	return key
}

// vaultRuntime returns a runtime wired to the fake Vault without starting its
// background loop.
func vaultRuntime(t *testing.T, addr string) *runtime {
	t.Helper()
	t.Setenv("VAULT_TOKEN", "test-token")
	cfg := defaultConfig()
	cfg.Vault.Address = addr
	rt, err := newRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Suppress refresh-on-miss so snapshots stay as stale as the test makes them.
	rt.lastMiss.Store(1 << 62)
	return rt
}

// liveKeyVersions counts versions of path whose data still contains an api_key.
func (kv *fakeKV) liveKeyVersions(path string) int {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	n := 0
	for _, data := range kv.secrets[path].versions {
		if key, _ := data["api_key"].(string); key != "" {
			n++
		}
	}
	return n
}
