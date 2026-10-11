package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

//go:embed ui/index.html
var uiHTML []byte

const routePrefix = "/client-key-policy"

type managementRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Query   url.Values
	Body    []byte
}

type managementResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

type managementRoute struct {
	Method      string
	Path        string
	Description string
}

type resourceRoute struct {
	Path        string
	Menu        string
	Description string
}

func managementRegistration() any {
	route := func(method, path, description string) managementRoute {
		return managementRoute{Method: method, Path: routePrefix + path, Description: description}
	}
	return map[string]any{
		"routes": []managementRoute{
			route(http.MethodGet, "/state", "Policies, keys, catalog and resolved model views"),
			route(http.MethodPost, "/policies", "Create or update a provider policy"),
			route(http.MethodPost, "/policies/delete", "Delete a provider policy (?name=)"),
			route(http.MethodPost, "/keys", "Issue a key for a client"),
			route(http.MethodPost, "/keys/rotate", "Rotate a client key (?id=policy/client)"),
			route(http.MethodPost, "/keys/revoke", "Revoke a client key (?id=policy/client)"),
			route(http.MethodPost, "/refresh", "Reload Vault data and the CPA model catalog"),
		},
		"resources": []resourceRoute{
			{Path: "/ui", Menu: "Client Keys", Description: "Manage provider policies and client keys"},
		},
	}
}

func (rt *runtime) handleManagement(raw []byte) (any, error) {
	var req managementRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	if strings.HasSuffix(req.Path, "/ui") && strings.Contains(req.Path, "/v0/resource/") {
		return managementResponse{
			StatusCode: http.StatusOK,
			Headers: http.Header{
				"Content-Type":            {"text/html; charset=utf-8"},
				"Cache-Control":           {"no-store"},
				"Content-Security-Policy": {"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'self'"},
			},
			Body: uiHTML,
		}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	idx := strings.Index(req.Path, routePrefix+"/")
	if idx < 0 {
		return jsonResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
	}
	route := req.Path[idx+len(routePrefix):]
	method := strings.ToUpper(req.Method)
	switch {
	case method == http.MethodGet && route == "/state":
		return jsonResponse(http.StatusOK, rt.stateView()), nil
	case method == http.MethodPost && route == "/policies":
		var policy Policy
		if errDecode := json.Unmarshal(req.Body, &policy); errDecode != nil {
			return badRequest("invalid policy JSON: " + errDecode.Error()), nil
		}
		if errSave := rt.savePolicy(ctx, policy); errSave != nil {
			return badRequest(errSave.Error()), nil
		}
		return jsonResponse(http.StatusOK, map[string]string{"status": "ok"}), nil
	case method == http.MethodPost && route == "/policies/delete":
		if errDelete := rt.deletePolicy(ctx, req.Query.Get("name")); errDelete != nil {
			return badRequest(errDelete.Error()), nil
		}
		return jsonResponse(http.StatusOK, map[string]string{"status": "ok"}), nil
	case method == http.MethodPost && route == "/keys":
		var body struct {
			Policy      string `json:"policy"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if errDecode := json.Unmarshal(req.Body, &body); errDecode != nil {
			return badRequest("invalid JSON: " + errDecode.Error()), nil
		}
		record, errIssue := rt.issueKey(ctx, strings.TrimSpace(body.Policy), strings.TrimSpace(body.Name), strings.TrimSpace(body.Description), false)
		if errIssue != nil {
			return badRequest(errIssue.Error()), nil
		}
		return jsonResponse(http.StatusOK, record), nil
	case method == http.MethodPost && route == "/keys/rotate":
		policyName, name, _ := strings.Cut(req.Query.Get("id"), "/")
		record, errRotate := rt.issueKey(ctx, policyName, name, "", true)
		if errRotate != nil {
			return badRequest(errRotate.Error()), nil
		}
		return jsonResponse(http.StatusOK, record), nil
	case method == http.MethodPost && route == "/keys/revoke":
		if errRevoke := rt.revokeKey(ctx, req.Query.Get("id")); errRevoke != nil {
			return badRequest(errRevoke.Error()), nil
		}
		return jsonResponse(http.StatusOK, map[string]string{"status": "ok"}), nil
	case method == http.MethodPost && route == "/refresh":
		rt.refreshAll()
		return jsonResponse(http.StatusOK, rt.stateView()), nil
	}
	return jsonResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
}

type viewEntry struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

func (rt *runtime) stateView() map[string]any {
	snap := rt.snap.Load()
	policies := make([]*Policy, 0, len(snap.policies))
	for _, policy := range snap.policies {
		policies = append(policies, policy)
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	clients := make([]*client, 0, len(snap.clients))
	for _, record := range snap.clients {
		clients = append(clients, record)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	views := map[string][]viewEntry{}
	for name, view := range snap.views {
		entries := make([]viewEntry, 0, len(view.Models))
		for _, model := range view.SortedNames() {
			target := view.Models[model]
			entries = append(entries, viewEntry{Name: model, Provider: target.Provider, Model: target.Model})
		}
		views[name] = entries
	}
	rt.statusMu.Lock()
	status := map[string]any{
		"last_vault_refresh":   rt.lastRefresh,
		"vault_error":          rt.refreshErr,
		"last_catalog_refresh": rt.lastCatalog,
		"catalog_error":        rt.catalogErr,
		"vault_address":        rt.cfg.Vault.Address,
		"vault_namespace":      rt.cfg.Vault.Namespace,
		"vault_keys_path":      rt.vault.FullDataPath(keysDir),
		"client_id_header":     rt.cfg.ClientIDHeader,
	}
	rt.statusMu.Unlock()
	return map[string]any{
		"status":   status,
		"policies": policies,
		"keys":     clients,
		"catalog":  snap.catalog,
		"views":    views,
	}
}

func jsonResponse(status int, v any) managementResponse {
	body, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":"encode response"}`)
	}
	return managementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}},
		Body:       body,
	}
}

func badRequest(message string) managementResponse {
	return jsonResponse(http.StatusBadRequest, map[string]string{"error": message})
}
