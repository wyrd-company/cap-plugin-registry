package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// The host encodes these RPC payloads with Go field names (no json tags), so the
// local mirrors below keep the same names. []byte fields travel as base64.

type frontendAuthRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Query   url.Values
}

type frontendAuthResponse struct {
	Authenticated bool
	Principal     string
	Metadata      map[string]string
}

type modelRouteRequest struct {
	SourceFormat   string
	RequestedModel string
	Headers        http.Header
	Metadata       map[string]any
}

type modelRouteResponse struct {
	Handled     bool
	TargetKind  string
	Target      string
	TargetModel string
	Reason      string
}

type requestInterceptRequest struct {
	SourceFormat   string
	Model          string
	RequestedModel string
	Headers        http.Header
	Metadata       map[string]any
}

type requestInterceptResponse struct {
	Terminate       bool
	StatusCode      int
	ResponseHeaders http.Header
	ResponseBody    []byte
}

type schedulerCandidate struct {
	ID       string
	Provider string
}

type schedulerPickRequest struct {
	Provider string
	Model    string
	Options  struct {
		Headers  http.Header
		Metadata map[string]any
	}
	Candidates []schedulerCandidate
}

type schedulerPickResponse struct {
	AuthID       string `json:"auth_id,omitempty"`
	Handled      bool   `json:"handled"`
	Reject       bool   `json:"reject,omitempty"`
	RejectReason string `json:"reject_reason,omitempty"`
	RejectCode   string `json:"reject_code,omitempty"`
}

type responseInterceptRequest struct {
	SourceFormat   string
	Model          string
	RequestHeaders http.Header
	RequestBody    []byte
	Body           []byte
}

type responseInterceptResponse struct {
	Body []byte `json:",omitempty"`
}

func (rt *runtime) handleFrontendAuth(raw []byte) (any, error) {
	var req frontendAuthRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	record := rt.authenticate(req.Headers, req.Query)
	if record == nil {
		return frontendAuthResponse{Authenticated: false}, nil
	}
	return frontendAuthResponse{
		Authenticated: true,
		Principal:     record.ID,
		Metadata:      map[string]string{"client_id": record.ID, "policy": record.Policy},
	}, nil
}

// handleModelRoute sends policy-visible names (aliases, provider/model, winners)
// to their upstream provider so CPA does not pick a different provider itself.
func (rt *runtime) handleModelRoute(raw []byte) (any, error) {
	var req modelRouteRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	record, _ := rt.clientFromMetadata(req.Metadata, req.Headers)
	view, ok := rt.viewFor(record)
	if !ok {
		return modelRouteResponse{Handled: false}, nil
	}
	target, found := view.Lookup(req.RequestedModel)
	if !found {
		return modelRouteResponse{Handled: false}, nil
	}
	return modelRouteResponse{
		Handled:     true,
		TargetKind:  "provider",
		Target:      target.Provider,
		TargetModel: target.Model,
		Reason:      "client-key-policy:" + record.Policy,
	}, nil
}

// handleInterceptBefore rejects models outside the client's policy with a clear 403.
func (rt *runtime) handleInterceptBefore(raw []byte) (any, error) {
	var req requestInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	record, identified := rt.clientFromMetadata(req.Metadata, req.Headers)
	if !identified {
		return requestInterceptResponse{}, nil
	}
	requested := req.RequestedModel
	if requested == "" {
		requested = req.Model
	}
	view, ok := rt.viewFor(record)
	if !ok {
		return deny("this client key is not associated with an active provider policy"), nil
	}
	if _, found := view.Lookup(requested); !found {
		return deny(fmt.Sprintf("model %q is not available to this client", requested)), nil
	}
	return requestInterceptResponse{}, nil
}

func deny(message string) requestInterceptResponse {
	body, _ := json.Marshal(map[string]any{"error": map[string]string{
		"message": message,
		"type":    "permission_error",
		"code":    "model_not_allowed",
	}})
	return requestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusForbidden,
		ResponseHeaders: http.Header{"Content-Type": {"application/json"}},
		ResponseBody:    body,
	}
}

// handleSchedulerPick is the hard enforcement point: only credentials whose
// provider/model pair the policy grants may be selected, whatever routed the request.
func (rt *runtime) handleSchedulerPick(raw []byte) (any, error) {
	var req schedulerPickRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	record, identified := rt.clientFromMetadata(req.Options.Metadata, req.Options.Headers)
	if !identified {
		return schedulerPickResponse{Handled: false}, nil
	}
	view, ok := rt.viewFor(record)
	if !ok {
		return reject("client has no active provider policy"), nil
	}
	allowed := make([]string, 0, len(req.Candidates))
	for _, candidate := range req.Candidates {
		provider := candidate.Provider
		if provider == "" {
			provider = req.Provider
		}
		if view.Permits(provider, req.Model) {
			allowed = append(allowed, candidate.ID)
		}
	}
	switch {
	case len(allowed) == 0:
		return reject(fmt.Sprintf("model %q is not available to this client on the selected providers", req.Model)), nil
	case len(allowed) == len(req.Candidates):
		// Everything is permitted; keep CPA's own scheduling behaviour.
		return schedulerPickResponse{Handled: false}, nil
	default:
		return schedulerPickResponse{Handled: true, AuthID: rt.pickRoundRobin(allowed)}, nil
	}
}

func reject(reason string) schedulerPickResponse {
	return schedulerPickResponse{Handled: true, Reject: true, RejectReason: reason, RejectCode: "model_not_allowed"}
}

// handleResponseIntercept rewrites model list responses to the client's policy view.
// Completion responses pass through untouched.
func (rt *runtime) handleResponseIntercept(raw []byte) (any, error) {
	var req responseInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	if req.Model != "" || len(req.RequestBody) > 0 || len(req.Body) == 0 {
		return responseInterceptResponse{}, nil
	}
	record, _ := rt.clientFromMetadata(nil, req.RequestHeaders)
	view, _ := rt.viewFor(record)
	body, changed, errFilter := filterModelList(req.SourceFormat, req.Body, view)
	if errFilter != nil || !changed {
		return responseInterceptResponse{}, errFilter
	}
	return responseInterceptResponse{Body: body}, nil
}

// filterModelList replaces the entries of an OpenAI, Claude or Gemini model list
// with the names in view. Entries are copied from the upstream list when the
// underlying model exists there, otherwise synthesized.
func filterModelList(format string, body []byte, view View) ([]byte, bool, error) {
	var doc map[string]any
	if errUnmarshal := json.Unmarshal(body, &doc); errUnmarshal != nil {
		return nil, false, nil
	}
	listKey, idKey, idPrefix := "data", "id", ""
	if strings.EqualFold(format, "gemini") || doc["models"] != nil {
		listKey, idKey, idPrefix = "models", "name", "models/"
	}
	items, ok := doc[listKey].([]any)
	if !ok {
		return nil, false, nil
	}
	byID := map[string]map[string]any{}
	for _, item := range items {
		entry, okEntry := item.(map[string]any)
		if !okEntry {
			continue
		}
		id, _ := entry[idKey].(string)
		byID[strings.TrimPrefix(id, idPrefix)] = entry
	}
	out := make([]any, 0, len(view.Models))
	for _, name := range view.SortedNames() {
		target := view.Models[name]
		entry := map[string]any{}
		if upstream, okUp := byID[target.Model]; okUp {
			for k, v := range upstream {
				entry[k] = v
			}
		} else {
			entry = synthesizeEntry(format, listKey, target)
		}
		entry[idKey] = idPrefix + name
		if listKey == "models" {
			entry["displayName"] = name
		} else if _, hasDisplay := entry["display_name"]; hasDisplay {
			entry["display_name"] = name
		}
		out = append(out, entry)
	}
	doc[listKey] = out
	if listKey == "data" {
		if _, hasFirst := doc["first_id"]; hasFirst {
			doc["first_id"], doc["last_id"] = nil, nil
			if len(out) > 0 {
				doc["first_id"] = out[0].(map[string]any)["id"]
				doc["last_id"] = out[len(out)-1].(map[string]any)["id"]
			}
			doc["has_more"] = false
		}
	}
	encoded, errMarshal := json.Marshal(doc)
	if errMarshal != nil {
		return nil, false, errMarshal
	}
	return encoded, true, nil
}

func synthesizeEntry(format, listKey string, target Target) map[string]any {
	switch {
	case listKey == "models":
		return map[string]any{"supportedGenerationMethods": []string{"generateContent", "streamGenerateContent"}}
	case strings.EqualFold(format, "claude"):
		return map[string]any{"type": "model", "display_name": "", "created_at": "1970-01-01T00:00:00Z"}
	}
	return map[string]any{"object": "model", "created": 0, "owned_by": target.Provider}
}
