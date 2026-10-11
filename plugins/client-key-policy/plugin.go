package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

const (
	pluginName    = "client-key-policy"
	pluginVersion = "0.1.0"
	// schemaVersion is the CPA plugin RPC schema this plugin implements.
	schemaVersion = 6
)

var (
	runtimeMu sync.Mutex
	current   *runtime
	configErr error
)

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type rpcEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func dispatch(method string, request []byte) []byte {
	if method == "plugin.register" || method == "plugin.reconfigure" {
		return okEnvelope(configure(request))
	}
	if method == "plugin.shutdown" {
		shutdown()
		return okEnvelope(map[string]any{})
	}
	if method == "management.register" {
		return okEnvelope(managementRegistration())
	}
	if method == "frontend_auth.identifier" {
		return okEnvelope(map[string]string{"identifier": pluginName})
	}

	rt, errRuntime := activeRuntime()
	if errRuntime != nil {
		// Fail closed: without a valid configuration no client is authenticated.
		switch method {
		case "frontend_auth.authenticate":
			return okEnvelope(frontendAuthResponse{Authenticated: false})
		case "management.handle":
			return okEnvelope(jsonResponse(503, map[string]string{"error": errRuntime.Error()}))
		}
		return errorEnvelope("not_configured", errRuntime.Error(), 503)
	}

	var (
		result any
		err    error
	)
	switch method {
	case "frontend_auth.authenticate":
		result, err = rt.handleFrontendAuth(request)
	case "model.route":
		result, err = rt.handleModelRoute(request)
	case "request.intercept_before":
		result, err = rt.handleInterceptBefore(request)
	case "request.intercept_after":
		result = requestInterceptResponse{}
	case "scheduler.pick":
		result, err = rt.handleSchedulerPick(request)
	case "response.intercept_after":
		result, err = rt.handleResponseIntercept(request)
	case "management.handle":
		result, err = rt.handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method, 0)
	}
	if err != nil {
		return errorEnvelope("plugin_error", err.Error(), 500)
	}
	return okEnvelope(result)
}

func configure(request []byte) any {
	var req lifecycleRequest
	if len(request) > 0 {
		if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
			setRuntime(nil, fmt.Errorf("decode lifecycle request: %w", errUnmarshal))
			return registration()
		}
	}
	cfg, errConfig := parseConfig(req.ConfigYAML)
	if errConfig != nil {
		setRuntime(nil, errConfig)
		return registration()
	}
	rt, errRuntime := newRuntime(cfg)
	if errRuntime != nil {
		setRuntime(nil, errRuntime)
		return registration()
	}
	setRuntime(rt, nil)
	rt.start()
	return registration()
}

func setRuntime(rt *runtime, err error) {
	runtimeMu.Lock()
	previous := current
	current, configErr = rt, err
	runtimeMu.Unlock()
	if err != nil {
		log.Printf("client-key-policy: configuration error, rejecting all clients: %v", err)
	}
	if previous != nil {
		previous.close()
	}
}

func activeRuntime() (*runtime, error) {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	if current == nil {
		if configErr != nil {
			return nil, configErr
		}
		return nil, fmt.Errorf("plugin not configured")
	}
	return current, nil
}

func shutdown() {
	setRuntime(nil, fmt.Errorf("plugin shut down"))
}

func registration() any {
	field := func(name, kind, description string) map[string]any {
		return map[string]any{"Name": name, "Type": kind, "Description": description}
	}
	return map[string]any{
		"schema_version": schemaVersion,
		"metadata": map[string]any{
			"Name":             pluginName,
			"Version":          pluginVersion,
			"Author":           "Wyrd Company",
			"GitHubRepository": "https://github.com/wyrd-company/cap-plugin-registry",
			"ConfigFields": []map[string]any{
				field("vault", "object", "Vault/OpenBao connection: address, namespace, mount, prefix, auth_method (token|approle), token_env, approle_mount, role_id_env, secret_id_env, ca_cert, tls_skip_verify."),
				field("cpa", "object", "CPA catalog source: management_url, management_key_env, catalog_interval."),
				field("client_id_header", "string", "Optional header carrying the client id (default X-CPA-Client-Id)."),
				field("refresh_interval", "string", "How often policies and keys are re-read from Vault (default 1m)."),
			},
		},
		"capabilities": map[string]any{
			"frontend_auth_provider":           true,
			"frontend_auth_provider_exclusive": true,
			"model_router":                     true,
			"request_interceptor":              true,
			"scheduler":                        true,
			"response_interceptor":             true,
			"management_api":                   true,
		},
	}
}

func okEnvelope(v any) []byte {
	result, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return errorEnvelope("encode_error", errMarshal.Error(), 500)
	}
	raw, _ := json.Marshal(rpcEnvelope{OK: true, Result: result})
	return raw
}

func errorEnvelope(code, message string, status int) []byte {
	raw, _ := json.Marshal(rpcEnvelope{OK: false, Error: &rpcError{Code: code, Message: message, HTTPStatus: status}})
	return raw
}
