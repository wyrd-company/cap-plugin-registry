package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const samplePath = "cliproxyapi/keys/sample/client"

// setupStaleInstances returns two runtimes sharing one Vault; both loaded the
// "sample" policy but neither has seen any key yet.
func setupStaleInstances(t *testing.T) (*fakeKV, *runtime, *runtime) {
	t.Helper()
	kv, srv := newFakeVault(t)
	ctx := context.Background()
	a, b := vaultRuntime(t, srv.URL), vaultRuntime(t, srv.URL)
	if err := a.savePolicy(ctx, Policy{Name: "sample", Providers: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	if err := b.loadFromVault(ctx); err != nil {
		t.Fatal(err)
	}
	return kv, a, b
}

func authenticates(rt *runtime, key string) bool {
	return rt.authenticate(http.Header{"Authorization": {"Bearer " + key}}, nil) != nil
}

func TestIssueKeyOnStaleInstanceDoesNotOverwrite(t *testing.T) {
	kv, a, b := setupStaleInstances(t)
	ctx := context.Background()
	if _, err := a.issueKey(ctx, "sample", "client", "", false); err != nil {
		t.Fatal(err)
	}
	original := kv.apiKey(samplePath)

	// b has not refreshed, so its snapshot does not know the key exists.
	_, err := b.issueKey(ctx, "sample", "client", "", false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected create conflict, got %v", err)
	}
	if got := kv.apiKey(samplePath); got != original {
		t.Fatal("stale create overwrote the existing key in Vault")
	}
	if rec := b.snap.Load().clients["sample/client"]; rec != nil && rec.keyHash != sha256.Sum256([]byte(original)) {
		t.Fatal("conflict must not install a different key in the snapshot")
	}
	if !authenticates(a, original) {
		t.Fatal("original client lost access")
	}
}

func TestRotateWithStaleVersionConflicts(t *testing.T) {
	kv, a, b := setupStaleInstances(t)
	ctx := context.Background()
	if _, err := a.issueKey(ctx, "sample", "client", "", false); err != nil {
		t.Fatal(err)
	}
	if err := b.loadFromVault(ctx); err != nil { // b now knows version 1
		t.Fatal(err)
	}
	if _, err := a.issueKey(ctx, "sample", "client", "", true); err != nil { // version 2
		t.Fatal(err)
	}
	rotatedByA := kv.apiKey(samplePath)

	_, err := b.issueKey(ctx, "sample", "client", "", true)
	if err == nil || !strings.Contains(err.Error(), "changed in Vault") {
		t.Fatalf("expected rotate conflict, got %v", err)
	}
	if got := kv.apiKey(samplePath); got != rotatedByA {
		t.Fatal("stale rotation overwrote the newer key")
	}

	// After reloading, b rotates against the current version.
	if err := b.loadFromVault(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.issueKey(ctx, "sample", "client", "", true); err != nil {
		t.Fatalf("rotation after reload failed: %v", err)
	}
	if kv.apiKey(samplePath) == rotatedByA {
		t.Fatal("rotation after reload did not change the key")
	}
}

func TestVaultWriteCASMismatchError(t *testing.T) {
	_, srv := newFakeVault(t)
	rt := vaultRuntime(t, srv.URL)
	zero := 0
	if _, err := rt.vault.Write(context.Background(), "x", map[string]any{"a": 1}, &zero); err != nil {
		t.Fatal(err)
	}
	_, err := rt.vault.Write(context.Background(), "x", map[string]any{"a": 2}, &zero)
	if !errors.Is(err, errVaultCASMismatch) {
		t.Fatalf("expected errVaultCASMismatch, got %v", err)
	}
}

// Revoking destroys the secret's metadata, so a re-issued key restarts at
// version 1; an instance that still knows the revoked key at version 1 must
// not be able to rotate over the re-issued one.
func TestRotateAfterRevokeAndReissueConflicts(t *testing.T) {
	kv, a, b := setupStaleInstances(t)
	ctx := context.Background()
	if _, err := a.issueKey(ctx, "sample", "client", "", false); err != nil {
		t.Fatal(err)
	}
	if err := b.loadFromVault(ctx); err != nil { // b knows the first key at version 1
		t.Fatal(err)
	}
	if err := a.revokeKey(ctx, "sample/client"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.issueKey(ctx, "sample", "client", "", false); err != nil { // version 1 again
		t.Fatal(err)
	}
	reissued := kv.apiKey(samplePath)
	if n := kv.liveKeyVersions(samplePath); n != 1 {
		t.Fatalf("expected only the re-issued key to be readable, got %d versions", n)
	}

	_, err := b.issueKey(ctx, "sample", "client", "", true)
	if err == nil || !strings.Contains(err.Error(), "changed in Vault") {
		t.Fatalf("expected rotate conflict after revoke/reissue, got %v", err)
	}
	if got := kv.apiKey(samplePath); got != reissued {
		t.Fatal("stale rotation overwrote the re-issued key")
	}
	if !authenticates(a, reissued) {
		t.Fatal("re-issued client lost access")
	}
}

func TestRotateAfterRevokeConflicts(t *testing.T) {
	kv, a, b := setupStaleInstances(t)
	ctx := context.Background()
	if _, err := a.issueKey(ctx, "sample", "client", "", false); err != nil {
		t.Fatal(err)
	}
	if err := b.loadFromVault(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.revokeKey(ctx, "sample/client"); err != nil {
		t.Fatal(err)
	}
	_, err := b.issueKey(ctx, "sample", "client", "", true)
	if err == nil || !strings.Contains(err.Error(), "changed in Vault") {
		t.Fatalf("expected rotate conflict after revoke, got %v", err)
	}
	if got := kv.apiKey(samplePath); got != "" {
		t.Fatal("stale rotation resurrected a revoked key")
	}
	if n := kv.liveKeyVersions(samplePath); n != 0 {
		t.Fatalf("revocation left %d readable key versions", n)
	}
}

// Re-issuing on a stale instance that never saw the revocation tombstone must
// still be conditional: it uses the tombstone's version, not cas=0.
func TestReissueAfterRevokeOnStaleInstance(t *testing.T) {
	kv, a, b := setupStaleInstances(t)
	ctx := context.Background()
	if _, err := a.issueKey(ctx, "sample", "client", "", false); err != nil {
		t.Fatal(err)
	}
	if err := a.revokeKey(ctx, "sample/client"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.issueKey(ctx, "sample", "client", "", false); err != nil {
		t.Fatalf("re-issue over a tombstone should succeed: %v", err)
	}
	if kv.apiKey(samplePath) == "" {
		t.Fatal("re-issued key missing")
	}
	if err := a.loadFromVault(ctx); err != nil {
		t.Fatal(err)
	}
	if !authenticates(a, kv.apiKey(samplePath)) {
		t.Fatal("other instance should accept the re-issued key after reload")
	}
}

func TestRevokeUnknownKeyIsNoop(t *testing.T) {
	kv, a, _ := setupStaleInstances(t)
	if err := a.revokeKey(context.Background(), "sample/missing"); err != nil {
		t.Fatal(err)
	}
	if _, ok := kv.secrets["cliproxyapi/keys/sample/missing"]; ok {
		t.Fatal("revoking an unknown key should not write a tombstone")
	}
}
