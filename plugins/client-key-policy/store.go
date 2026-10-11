package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	policiesDir = "policies"
	keysDir     = "keys"
	// missRefreshInterval bounds how often an unknown key may trigger a Vault re-read.
	missRefreshInterval = 10 * time.Second
)

// client is the in-memory view of a key record. The plaintext key is never kept.
type client struct {
	ID          string    `json:"id"`
	Policy      string    `json:"policy"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   time.Time `json:"rotated_at"`
	VaultPath   string    `json:"vault_path"`
	keyHash     [32]byte
}

// snapshot is an immutable copy of everything the request hooks need.
type snapshot struct {
	policies map[string]*Policy
	clients  map[string]*client
	byHash   map[[32]byte]*client
	byScope  map[string]*client
	catalog  Catalog
	views    map[string]View
}

type runtime struct {
	cfg     Config
	vault   *vaultClient
	catalog *catalogFetcher

	snap atomic.Pointer[snapshot]

	// writeMu serializes Vault refreshes and admin mutations.
	writeMu     sync.Mutex
	lastMiss    atomic.Int64
	rrCounter   atomic.Uint64
	statusMu    sync.Mutex
	lastRefresh time.Time
	lastCatalog time.Time
	refreshErr  string
	catalogErr  string

	stop chan struct{}
	done chan struct{}
}

func newRuntime(cfg Config) (*runtime, error) {
	vault, errVault := newVaultClient(cfg.Vault)
	if errVault != nil {
		return nil, errVault
	}
	rt := &runtime{
		cfg:     cfg,
		vault:   vault,
		catalog: newCatalogFetcher(cfg.CPA),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	rt.snap.Store(buildSnapshot(nil, nil, nil))
	return rt, nil
}

func (rt *runtime) start() {
	go rt.loop()
}

func (rt *runtime) close() {
	close(rt.stop)
	<-rt.done
}

func (rt *runtime) loop() {
	defer close(rt.done)
	rt.refreshAll()
	refresh := time.NewTicker(rt.cfg.RefreshInterval)
	defer refresh.Stop()
	catalogTicker := time.NewTicker(rt.cfg.CPA.CatalogInterval)
	defer catalogTicker.Stop()
	// CPA's management API is usually not listening yet while plugins load,
	// so retry the catalog quickly until the first fetch succeeds.
	retry := time.NewTicker(3 * time.Second)
	defer retry.Stop()
	for {
		select {
		case <-rt.stop:
			return
		case <-refresh.C:
			rt.refreshVault()
		case <-catalogTicker.C:
			rt.refreshCatalog()
		case <-retry.C:
			rt.statusMu.Lock()
			ready := !rt.lastCatalog.IsZero()
			rt.statusMu.Unlock()
			if ready {
				retry.Stop()
				continue
			}
			rt.refreshCatalog()
		}
	}
}

func (rt *runtime) refreshAll() {
	rt.refreshVault()
	rt.refreshCatalog()
}

func (rt *runtime) refreshVault() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rt.writeMu.Lock()
	defer rt.writeMu.Unlock()
	errLoad := rt.loadFromVault(ctx)
	rt.statusMu.Lock()
	defer rt.statusMu.Unlock()
	if errLoad != nil {
		rt.refreshErr = errLoad.Error()
		log.Printf("client-key-policy: vault refresh failed: %v", errLoad)
		return
	}
	rt.refreshErr = ""
	rt.lastRefresh = time.Now().UTC()
}

func (rt *runtime) refreshCatalog() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	catalog, errFetch := rt.catalog.Fetch(ctx)
	rt.statusMu.Lock()
	if errFetch != nil {
		rt.catalogErr = errFetch.Error()
		rt.statusMu.Unlock()
		return
	}
	rt.catalogErr = ""
	rt.lastCatalog = time.Now().UTC()
	rt.statusMu.Unlock()

	rt.writeMu.Lock()
	defer rt.writeMu.Unlock()
	current := rt.snap.Load()
	rt.snap.Store(buildSnapshot(current.policies, current.clients, catalog))
}

// loadFromVault re-reads all policies and key records. Callers hold writeMu.
func (rt *runtime) loadFromVault(ctx context.Context) error {
	policyNames, errList := rt.vault.List(ctx, policiesDir)
	if errList != nil {
		return errList
	}
	policies := map[string]*Policy{}
	for _, name := range policyNames {
		if strings.HasSuffix(name, "/") {
			continue
		}
		policy, errRead := rt.readPolicy(ctx, name)
		if errRead != nil {
			if errors.Is(errRead, errVaultNotFound) {
				continue
			}
			return errRead
		}
		policies[policy.Name] = policy
	}

	clients := map[string]*client{}
	folders, errFolders := rt.vault.List(ctx, keysDir)
	if errFolders != nil {
		return errFolders
	}
	for _, folder := range folders {
		if !strings.HasSuffix(folder, "/") {
			continue
		}
		policyName := strings.TrimSuffix(folder, "/")
		names, errNames := rt.vault.List(ctx, keysDir+"/"+policyName)
		if errNames != nil {
			return errNames
		}
		for _, name := range names {
			if strings.HasSuffix(name, "/") {
				continue
			}
			record, errRead := rt.readClient(ctx, policyName, name)
			if errRead != nil {
				if errors.Is(errRead, errVaultNotFound) {
					continue
				}
				return errRead
			}
			clients[record.ID] = record
		}
	}
	current := rt.snap.Load()
	rt.snap.Store(buildSnapshot(policies, clients, current.catalog))
	return nil
}

func (rt *runtime) readPolicy(ctx context.Context, name string) (*Policy, error) {
	data, errRead := rt.vault.Read(ctx, policiesDir+"/"+name)
	if errRead != nil {
		return nil, errRead
	}
	var policy Policy
	if errDecode := decodeMap(data, &policy); errDecode != nil {
		return nil, fmt.Errorf("policy %s: %w", name, errDecode)
	}
	policy.Name = name
	policy.normalize()
	return &policy, nil
}

// keyRecord is the Vault document a downstream client reads.
type keyRecord struct {
	APIKey         string `json:"api_key"`
	ClientID       string `json:"client_id"`
	ClientIDHeader string `json:"client_id_header,omitempty"`
	Policy         string `json:"policy"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	CreatedAt      string `json:"created_at"`
	RotatedAt      string `json:"rotated_at"`
}

func (rt *runtime) readClient(ctx context.Context, policyName, name string) (*client, error) {
	rel := keysDir + "/" + policyName + "/" + name
	data, errRead := rt.vault.Read(ctx, rel)
	if errRead != nil {
		return nil, errRead
	}
	var record keyRecord
	if errDecode := decodeMap(data, &record); errDecode != nil {
		return nil, fmt.Errorf("key %s/%s: %w", policyName, name, errDecode)
	}
	if record.APIKey == "" {
		return nil, fmt.Errorf("key %s/%s has no api_key", policyName, name)
	}
	created, _ := time.Parse(time.RFC3339, record.CreatedAt)
	rotated, _ := time.Parse(time.RFC3339, record.RotatedAt)
	return &client{
		// The path, not the stored fields, is authoritative for identity.
		ID:          clientID(policyName, name),
		Policy:      policyName,
		Name:        name,
		Description: record.Description,
		CreatedAt:   created,
		RotatedAt:   rotated,
		VaultPath:   rt.vault.FullDataPath(rel),
		keyHash:     sha256.Sum256([]byte(record.APIKey)),
	}, nil
}

func buildSnapshot(policies map[string]*Policy, clients map[string]*client, catalog Catalog) *snapshot {
	snap := &snapshot{
		policies: map[string]*Policy{},
		clients:  map[string]*client{},
		byHash:   map[[32]byte]*client{},
		byScope:  map[string]*client{},
		catalog:  Catalog{},
		views:    map[string]View{},
	}
	for name, policy := range policies {
		snap.policies[name] = policy
	}
	for provider, models := range catalog {
		snap.catalog[provider] = models
	}
	for id, record := range clients {
		snap.clients[id] = record
		snap.byHash[record.keyHash] = record
		snap.byScope[callerScope(id)] = record
	}
	for name, policy := range snap.policies {
		snap.views[name] = policy.Resolve(snap.catalog)
	}
	return snap
}

// callerScope mirrors CPA's caller_scope derivation from the authenticated principal.
func callerScope(principal string) string {
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + strings.TrimSpace(principal)))
	return hex.EncodeToString(sum[:])
}

func clientID(policyName, name string) string {
	return policyName + "/" + name
}

// authenticate resolves a client from inbound credentials.
func (rt *runtime) authenticate(headers http.Header, query url.Values) *client {
	key := extractAPIKey(headers, query)
	if key == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(key))
	id := ""
	if rt.cfg.ClientIDHeader != "" {
		id = strings.TrimSpace(headers.Get(rt.cfg.ClientIDHeader))
	}
	match := func(snap *snapshot) *client {
		if id != "" {
			record := snap.clients[id]
			if record != nil && subtle.ConstantTimeCompare(record.keyHash[:], hash[:]) == 1 {
				return record
			}
			return nil
		}
		return snap.byHash[hash]
	}
	if record := match(rt.snap.Load()); record != nil {
		return record
	}
	// The key may have been issued or rotated by another CPA instance.
	if rt.allowMissRefresh() {
		rt.refreshVault()
		return match(rt.snap.Load())
	}
	return nil
}

func (rt *runtime) allowMissRefresh() bool {
	now := time.Now().UnixNano()
	last := rt.lastMiss.Load()
	if now-last < int64(missRefreshInterval) {
		return false
	}
	return rt.lastMiss.CompareAndSwap(last, now)
}

// clientFromMetadata identifies the caller in post-auth hooks.
// The second result is false when the request carries no caller identity at all,
// which only happens for host-internal calls (e.g. other plugins' host.model.execute).
func (rt *runtime) clientFromMetadata(metadata map[string]any, headers http.Header) (*client, bool) {
	snap := rt.snap.Load()
	if scope, _ := metadata["caller_scope"].(string); scope != "" {
		return snap.byScope[scope], true
	}
	if key := extractAPIKey(headers, nil); key != "" {
		return snap.byHash[sha256.Sum256([]byte(key))], true
	}
	return nil, false
}

func (rt *runtime) viewFor(record *client) (View, bool) {
	if record == nil {
		return View{}, false
	}
	view, ok := rt.snap.Load().views[record.Policy]
	return view, ok
}

// extractAPIKey reads the client key from the header conventions CPA accepts.
func extractAPIKey(headers http.Header, query url.Values) string {
	if headers != nil {
		if auth := strings.TrimSpace(headers.Get("Authorization")); auth != "" {
			if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
				return strings.TrimSpace(auth[7:])
			}
			return auth
		}
		for _, name := range []string{"X-Api-Key", "X-Goog-Api-Key"} {
			if value := strings.TrimSpace(headers.Get(name)); value != "" {
				return value
			}
		}
	}
	if query != nil {
		if value := strings.TrimSpace(query.Get("key")); value != "" {
			return value
		}
	}
	return ""
}

// --- admin mutations ---

func (rt *runtime) savePolicy(ctx context.Context, policy Policy) error {
	policy.normalize()
	if errValidate := policy.Validate(); errValidate != nil {
		return errValidate
	}
	data, errEncode := encodeMap(policy)
	if errEncode != nil {
		return errEncode
	}
	rt.writeMu.Lock()
	defer rt.writeMu.Unlock()
	if errWrite := rt.vault.Write(ctx, policiesDir+"/"+policy.Name, data); errWrite != nil {
		return errWrite
	}
	current := rt.snap.Load()
	policies := copyPolicies(current.policies)
	policies[policy.Name] = &policy
	rt.snap.Store(buildSnapshot(policies, current.clients, current.catalog))
	return nil
}

func (rt *runtime) deletePolicy(ctx context.Context, name string) error {
	rt.writeMu.Lock()
	defer rt.writeMu.Unlock()
	current := rt.snap.Load()
	for _, record := range current.clients {
		if record.Policy == name {
			return fmt.Errorf("policy %s still has keys; revoke them first", name)
		}
	}
	if errDestroy := rt.vault.Destroy(ctx, policiesDir+"/"+name); errDestroy != nil {
		return errDestroy
	}
	policies := copyPolicies(current.policies)
	delete(policies, name)
	rt.snap.Store(buildSnapshot(policies, current.clients, current.catalog))
	return nil
}

// issueKey creates or rotates a key. The plaintext key is only written to Vault.
func (rt *runtime) issueKey(ctx context.Context, policyName, name, description string, rotate bool) (*client, error) {
	if !namePattern.MatchString(policyName) || !namePattern.MatchString(name) {
		return nil, fmt.Errorf("policy and client names must match %s", namePattern.String())
	}
	rt.writeMu.Lock()
	defer rt.writeMu.Unlock()
	current := rt.snap.Load()
	if _, ok := current.policies[policyName]; !ok {
		return nil, fmt.Errorf("policy %s does not exist", policyName)
	}
	id := clientID(policyName, name)
	existing := current.clients[id]
	if rotate && existing == nil {
		return nil, fmt.Errorf("key %s does not exist", id)
	}
	if !rotate && existing != nil {
		return nil, fmt.Errorf("key %s already exists; rotate it instead", id)
	}
	apiKey, errKey := generateKey()
	if errKey != nil {
		return nil, errKey
	}
	now := time.Now().UTC()
	record := keyRecord{
		APIKey:         apiKey,
		ClientID:       id,
		ClientIDHeader: rt.cfg.ClientIDHeader,
		Policy:         policyName,
		Name:           name,
		Description:    description,
		CreatedAt:      now.Format(time.RFC3339),
		RotatedAt:      now.Format(time.RFC3339),
	}
	if existing != nil {
		record.CreatedAt = existing.CreatedAt.Format(time.RFC3339)
		if description == "" {
			record.Description = existing.Description
		}
	}
	data, errEncode := encodeMap(record)
	if errEncode != nil {
		return nil, errEncode
	}
	rel := keysDir + "/" + policyName + "/" + name
	if errWrite := rt.vault.Write(ctx, rel, data); errWrite != nil {
		return nil, errWrite
	}
	created, _ := time.Parse(time.RFC3339, record.CreatedAt)
	updated := &client{
		ID:          id,
		Policy:      policyName,
		Name:        name,
		Description: record.Description,
		CreatedAt:   created,
		RotatedAt:   now,
		VaultPath:   rt.vault.FullDataPath(rel),
		keyHash:     sha256.Sum256([]byte(apiKey)),
	}
	clients := copyClients(current.clients)
	clients[id] = updated
	rt.snap.Store(buildSnapshot(current.policies, clients, current.catalog))
	return updated, nil
}

func (rt *runtime) revokeKey(ctx context.Context, id string) error {
	policyName, name, ok := strings.Cut(id, "/")
	if !ok || !namePattern.MatchString(policyName) || !namePattern.MatchString(name) {
		return fmt.Errorf("invalid client id %q", id)
	}
	rt.writeMu.Lock()
	defer rt.writeMu.Unlock()
	if errDestroy := rt.vault.Destroy(ctx, keysDir+"/"+policyName+"/"+name); errDestroy != nil {
		return errDestroy
	}
	current := rt.snap.Load()
	clients := copyClients(current.clients)
	delete(clients, id)
	rt.snap.Store(buildSnapshot(current.policies, clients, current.catalog))
	return nil
}

func (rt *runtime) pickRoundRobin(ids []string) string {
	sort.Strings(ids)
	return ids[rt.rrCounter.Add(1)%uint64(len(ids))]
}

func generateKey() (string, error) {
	raw := make([]byte, 32)
	if _, errRead := rand.Read(raw); errRead != nil {
		return "", fmt.Errorf("generate key: %w", errRead)
	}
	return "cpa_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func copyPolicies(in map[string]*Policy) map[string]*Policy {
	out := make(map[string]*Policy, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyClients(in map[string]*client) map[string]*client {
	out := make(map[string]*client, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func encodeMap(v any) (map[string]any, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	var out map[string]any
	if errUnmarshal := json.Unmarshal(raw, &out); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return out, nil
}

func decodeMap(in map[string]any, v any) error {
	raw, errMarshal := json.Marshal(in)
	if errMarshal != nil {
		return errMarshal
	}
	return json.Unmarshal(raw, v)
}
