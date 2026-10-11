package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// errVaultNotFound reports a missing KV path.
var errVaultNotFound = errors.New("vault: not found")

// errVaultCASMismatch reports a KV v2 check-and-set conflict: the secret was
// created or changed since the version the caller expected.
var errVaultCASMismatch = errors.New("vault: check-and-set version mismatch")

// vaultClient is a minimal KV v2 client for Vault and OpenBao.
type vaultClient struct {
	cfg  VaultConfig
	http *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

func newVaultClient(cfg VaultConfig) (*vaultClient, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACert != "" {
		pem, errRead := os.ReadFile(cfg.CACert)
		if errRead != nil {
			return nil, fmt.Errorf("read vault ca_cert: %w", errRead)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("vault ca_cert contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	tlsConfig.InsecureSkipVerify = cfg.TLSSkipVerify
	transport.TLSClientConfig = tlsConfig
	return &vaultClient{cfg: cfg, http: &http.Client{Transport: transport, Timeout: 15 * time.Second}}, nil
}

// kvPath joins the plugin prefix with a relative path.
func (v *vaultClient) kvPath(rel string) string {
	rel = strings.Trim(rel, "/")
	if v.cfg.Prefix == "" {
		return rel
	}
	if rel == "" {
		return v.cfg.Prefix
	}
	return v.cfg.Prefix + "/" + rel
}

// FullDataPath returns the API path (without /v1/) clients use to read a secret.
func (v *vaultClient) FullDataPath(rel string) string {
	return v.cfg.Mount + "/data/" + v.kvPath(rel)
}

// Read returns the latest data of a secret and its KV v2 version.
func (v *vaultClient) Read(ctx context.Context, rel string) (map[string]any, int, error) {
	var out struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if errDo := v.do(ctx, http.MethodGet, v.cfg.Mount+"/data/"+escapePath(v.kvPath(rel)), nil, &out); errDo != nil {
		return nil, 0, errDo
	}
	if out.Data.Data == nil {
		// A deleted (soft) latest version returns null data.
		return nil, 0, errVaultNotFound
	}
	return out.Data.Data, out.Data.Metadata.Version, nil
}

// Write stores a new version of a secret and returns that version. A non-nil
// cas makes the write conditional: 0 means "only if the secret does not exist",
// n means "only if the current version is n" (errVaultCASMismatch otherwise).
func (v *vaultClient) Write(ctx context.Context, rel string, data map[string]any, cas *int) (int, error) {
	body := map[string]any{"data": data}
	if cas != nil {
		body["options"] = map[string]any{"cas": *cas}
	}
	var out struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	if errDo := v.do(ctx, http.MethodPost, v.cfg.Mount+"/data/"+escapePath(v.kvPath(rel)), body, &out); errDo != nil {
		return 0, errDo
	}
	return out.Data.Version, nil
}

// List returns the child names under rel. Folder names keep their trailing slash.
func (v *vaultClient) List(ctx context.Context, rel string) ([]string, error) {
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	errDo := v.do(ctx, "LIST", v.cfg.Mount+"/metadata/"+escapePath(v.kvPath(rel)), nil, &out)
	if errors.Is(errDo, errVaultNotFound) {
		return nil, nil
	}
	if errDo != nil {
		return nil, errDo
	}
	return out.Data.Keys, nil
}

// Destroy permanently removes all versions and metadata of a secret.
func (v *vaultClient) Destroy(ctx context.Context, rel string) error {
	errDo := v.do(ctx, http.MethodDelete, v.cfg.Mount+"/metadata/"+escapePath(v.kvPath(rel)), nil, nil)
	if errors.Is(errDo, errVaultNotFound) {
		return nil
	}
	return errDo
}

func (v *vaultClient) do(ctx context.Context, method, apiPath string, body any, out any) error {
	token, errToken := v.currentToken(ctx)
	if errToken != nil {
		return errToken
	}
	status, errRequest := v.request(ctx, method, apiPath, token, body, out)
	if status == http.StatusForbidden && v.cfg.AuthMethod == "approle" {
		// The token may have been revoked or expired early; log in again once.
		v.mu.Lock()
		v.token = ""
		v.mu.Unlock()
		token, errToken = v.currentToken(ctx)
		if errToken != nil {
			return errToken
		}
		_, errRequest = v.request(ctx, method, apiPath, token, body, out)
	}
	return errRequest
}

func (v *vaultClient) request(ctx context.Context, method, apiPath, token string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		raw, errMarshal := json.Marshal(body)
		if errMarshal != nil {
			return 0, errMarshal
		}
		reader = bytes.NewReader(raw)
	}
	req, errNew := http.NewRequestWithContext(ctx, method, v.cfg.Address+"/v1/"+apiPath, reader)
	if errNew != nil {
		return 0, errNew
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if v.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, errDo := v.http.Do(req)
	if errDo != nil {
		return 0, fmt.Errorf("vault %s %s: %w", method, apiPath, errDo)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if errRead != nil {
		return resp.StatusCode, fmt.Errorf("vault %s %s: read body: %w", method, apiPath, errRead)
	}
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, errVaultNotFound
	}
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(strings.ToLower(string(raw)), "check-and-set") {
		return resp.StatusCode, fmt.Errorf("vault %s %s: %w: %s", method, apiPath, errVaultCASMismatch, vaultErrors(raw))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("vault %s %s: status %d: %s", method, apiPath, resp.StatusCode, vaultErrors(raw))
	}
	if out != nil && len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, out); errUnmarshal != nil {
			return resp.StatusCode, fmt.Errorf("vault %s %s: decode: %w", method, apiPath, errUnmarshal)
		}
	}
	return resp.StatusCode, nil
}

func (v *vaultClient) currentToken(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cfg.AuthMethod == "token" {
		token := envValue(v.cfg.TokenEnv)
		if token == "" {
			return "", fmt.Errorf("vault token env %s is empty", v.cfg.TokenEnv)
		}
		return token, nil
	}
	if v.token != "" && (v.tokenExpiry.IsZero() || time.Now().Before(v.tokenExpiry)) {
		return v.token, nil
	}
	roleID := envValue(v.cfg.RoleIDEnv)
	secretID := envValue(v.cfg.SecretIDEnv)
	if roleID == "" {
		return "", fmt.Errorf("vault approle role id env %s is empty", v.cfg.RoleIDEnv)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	payload := map[string]any{"role_id": roleID}
	if secretID != "" {
		payload["secret_id"] = secretID
	}
	mount := strings.Trim(v.cfg.AppRoleMount, "/")
	if _, errLogin := v.request(ctx, http.MethodPost, "auth/"+mount+"/login", "", payload, &out); errLogin != nil {
		return "", fmt.Errorf("vault approle login: %w", errLogin)
	}
	if out.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault approle login returned no token")
	}
	v.token = out.Auth.ClientToken
	v.tokenExpiry = time.Time{}
	if out.Auth.LeaseDuration > 0 {
		// Renew by logging in again once 80% of the lease has elapsed.
		v.tokenExpiry = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second * 8 / 10)
	}
	return v.token, nil
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func vaultErrors(raw []byte) string {
	var body struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &body) == nil && len(body.Errors) > 0 {
		return strings.Join(body.Errors, "; ")
	}
	text := strings.TrimSpace(string(raw))
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}
