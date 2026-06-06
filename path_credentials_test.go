package aap

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestRevokeHelpers covers the failure-path revoke helpers used when a request
// fails after minting (they build a fresh client from the snapshot config).
func TestRevokeHelpers(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	ctx := context.Background()

	cfg := &aapConfig{Address: srv.URL, Token: "admin-token", TokensAPIPath: "/api/gateway/v1", SkipTLSVerify: true}
	c, err := newClient(cfg)
	require.NoError(t, err)

	tok, err := c.CreateToken(ctx, "read", "to-revoke")
	require.NoError(t, err)
	require.NoError(t, revokeWithConfig(ctx, cfg, tok.ID))
	require.True(t, m.wasRevoked(tok.ID))

	// Best-effort revoke of an already-gone token is silent (idempotent 404).
	revokeBestEffort(ctx, cfg, tok.ID)
}

// TestCredentials_PerUserMint verifies that a role with a bootstrap_token mints a
// token owned by that user (the engine authenticates as the bootstrap identity),
// and that the username ownership guard passes. A role without a bootstrap_token
// mints as the engine identity.
func TestCredentials_PerUserMint(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addIdentity("svc-deploy-token", 7) // svc-deploy's own token mints as id 7
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "deploy", map[string]interface{}{
		"scope":           "write",
		"username":        "svc-deploy", // id 7, asserted by the guard
		"bootstrap_token": "svc-deploy-token",
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/deploy", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	tokenID := resp.Data["token_id"].(int64)
	require.Equal(t, int64(7), m.mintUserFor(tokenID), "token must be minted as svc-deploy")

	// A role with no bootstrap_token mints as the engine identity (admin, id 2).
	testRoleCreate(t, b, s, "plain", map[string]interface{}{"scope": "read"})
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/plain", Storage: s,
	})
	require.NoError(t, err)
	plainID := resp.Data["token_id"].(int64)
	require.Equal(t, int64(2), m.mintUserFor(plainID))
}

// TestCredentials_PerUserMint_OwnershipGuard covers the guard firing: a role names
// one user but supplies a bootstrap_token for another user. The engine must
// detect the mismatch, revoke the misattributed token, and fail loudly.
func TestCredentials_PerUserMint_OwnershipGuard(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addIdentity("svc-readonly-token", 8)
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "deploy", map[string]interface{}{
		"scope":           "read",
		"username":        "svc-deploy", // id 7
		"bootstrap_token": "svc-readonly-token",
	})

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/deploy", Storage: s,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not \"svc-deploy\"")
	require.Equal(t, 0, m.liveCount(), "the misattributed token must be revoked, not leaked")
}

func TestCredentials_PerUserMint_OwnershipGuardReportsRevokeFailure(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addIdentity("svc-readonly-token", 8)
	m.failRevoke = true
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "deploy", map[string]interface{}{
		"scope":           "read",
		"username":        "svc-deploy",
		"bootstrap_token": "svc-readonly-token",
	})

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/deploy", Storage: s,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to revoke minted token")
	require.Equal(t, 1, m.liveCount(), "the cleanup failure should be visible because the token remains live")
}

// TestCredentials_PerUserMint_UnknownUser surfaces a clear error when the role's
// username does not resolve, and mints nothing.
func TestCredentials_PerUserMint_UnknownUser(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addIdentity("ghost-token", 9)
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ghost", map[string]interface{}{
		"scope":           "read",
		"username":        "does-not-exist",
		"bootstrap_token": "ghost-token",
	})

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ghost", Storage: s,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does-not-exist")
	require.Equal(t, 0, m.liveCount(), "no token should be minted when the user is unknown")
}

// TestCredentials_MintRenewRevoke exercises the full dynamic-secret lifecycle
// against the in-process mock AAP.
func TestCredentials_MintRenewRevoke(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{
		"scope":       "write",
		"description": "vault-ci",
		"ttl":         "1h",
		"max_ttl":     "8h",
	})

	// Mint.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Secret)
	require.NotEmpty(t, resp.Data["token"])
	require.Equal(t, "write", resp.Data["scope"])
	require.Equal(t, time.Hour, resp.Secret.TTL)
	require.Equal(t, 8*time.Hour, resp.Secret.MaxTTL)
	require.Equal(t, 1, m.liveCount())

	tokenID, err := strconv.ParseInt(resp.Secret.InternalData["token_id"].(string), 10, 64)
	require.NoError(t, err)
	require.Equal(t, "ci", resp.Secret.InternalData["role"])

	// Renew → same token, lease extended.
	renewResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RenewOperation, Path: "creds/ci", Storage: s,
		Secret: resp.Secret,
	})
	require.NoError(t, err)
	require.NotNil(t, renewResp)
	require.Equal(t, time.Hour, renewResp.Secret.TTL)
	require.Equal(t, 1, m.liveCount(), "renew must not mint a new token")

	// Revoke → token deleted in AAP.
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/ci", Storage: s,
		Secret: resp.Secret,
	})
	require.NoError(t, err)
	require.True(t, m.wasRevoked(tokenID))
	require.Equal(t, 0, m.liveCount())
}

// TestCredentials_RevokeAfterLeasePersisted simulates Vault persisting a lease
// and reloading it: the secret's InternalData is round-tripped through JSON
// (turning token_id into a float64) before revoke. This is the real production
// path that a purely in-memory test would miss.
func TestCredentials_RevokeAfterLeasePersisted(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{"scope": "write", "ttl": "1h"})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.NoError(t, err)
	tokenIDStr := resp.Secret.InternalData["token_id"].(string)
	tokenID, err := strconv.ParseInt(tokenIDStr, 10, 64)
	require.NoError(t, err)

	// Round-trip InternalData through JSON, as Vault does when persisting leases.
	raw, err := json.Marshal(resp.Secret.InternalData)
	require.NoError(t, err)
	var reloaded map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &reloaded))
	gotID, isString := reloaded["token_id"].(string)
	require.True(t, isString, "token_id is stored as a string and survives the round-trip exactly")
	require.Equal(t, tokenIDStr, gotID)
	resp.Secret.InternalData = reloaded

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/ci", Storage: s, Secret: resp.Secret,
	})
	require.NoError(t, err)
	require.True(t, m.wasRevoked(tokenID), "revoke must work after JSON round-trip")
}

func TestCredentials_RevokeUsesOriginalConfigAfterRotation(t *testing.T) {
	original := newMockAAP("token-a")
	originalSrv := original.server(t)
	defer originalSrv.Close()
	rotated := newMockAAP("token-b")
	rotatedSrv := rotated.server(t)
	defer rotatedSrv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, originalSrv.URL, "token-a")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{"scope": "write", "ttl": "1h"})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.NoError(t, err)
	tokenID, err := strconv.ParseInt(resp.Secret.InternalData["token_id"].(string), 10, 64)
	require.NoError(t, err)

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address":         rotatedSrv.URL,
			"token":           "token-b",
			"tokens_api_path": "/api/gateway/v1",
			"skip_tls_verify": true,
		},
	})
	require.NoError(t, err)

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/ci", Storage: s, Secret: resp.Secret,
	})
	require.NoError(t, err)
	require.True(t, original.wasRevoked(tokenID), "revoke must use the config that minted the token")
	require.False(t, rotated.wasRevoked(tokenID), "revoke must not be sent to the rotated config")
}

func TestCredentials_RevokeAfterConfigDeletedUsesLeaseConfig(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{"scope": "read", "ttl": "1h"})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.NoError(t, err)
	tokenID, err := strconv.ParseInt(resp.Secret.InternalData["token_id"].(string), 10, 64)
	require.NoError(t, err)

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/ci", Storage: s, Secret: resp.Secret,
	})
	require.NoError(t, err)
	require.True(t, m.wasRevoked(tokenID))
}

func TestCredentials_UnknownRole(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/nope", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
}

func TestCredentials_RenewAfterRoleDeleted(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "tmp", map[string]interface{}{"scope": "read", "ttl": "1h"})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/tmp", Storage: s,
	})
	require.NoError(t, err)
	secret := resp.Secret

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "role/tmp", Storage: s,
	})
	require.NoError(t, err)

	// Renewing a lease whose role was deleted must fail cleanly, not panic.
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RenewOperation, Path: "creds/tmp", Storage: s, Secret: secret,
	})
	require.Error(t, err)
}

// TestAcceptance_LiveAAP runs against a real AAP instance. It is skipped unless
// VAULT_ACC is set and TEST_AAP_ADDRESS / TEST_AAP_TOKEN are provided.
//
//	VAULT_ACC=1 TEST_AAP_ADDRESS=... TEST_AAP_TOKEN=... go test -run TestAcceptance -v
func TestAcceptance_LiveAAP(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("acceptance test skipped; set VAULT_ACC=1 to run against live AAP")
	}

	address := os.Getenv("TEST_AAP_ADDRESS")
	token := os.Getenv("TEST_AAP_TOKEN")
	require.NotEmpty(t, address, "TEST_AAP_ADDRESS required")
	require.NotEmpty(t, token, "TEST_AAP_TOKEN required")

	apiPath := os.Getenv("TEST_AAP_TOKENS_API_PATH")
	if apiPath == "" {
		apiPath = defaultTokensAPIPath
	}
	skipTLS := os.Getenv("TEST_AAP_SKIP_TLS_VERIFY") == "true"

	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address":         address,
			"token":           token,
			"tokens_api_path": apiPath,
			"skip_tls_verify": skipTLS,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	testRoleCreate(t, b, s, "acc", map[string]interface{}{
		"scope":       "read",
		"description": "vault-acceptance-test",
		"ttl":         "10m",
		"max_ttl":     "1h",
	})

	// Mint a real token.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/acc", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data["token"], "expected a real AAP token")
	t.Logf("minted live AAP token id=%v scope=%v", resp.Secret.InternalData["token_id"], resp.Data["scope"])

	// Revoke it so we don't leak tokens in the lab.
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/acc", Storage: s, Secret: resp.Secret,
	})
	require.NoError(t, err, "live revoke must succeed")
}

// TestAcceptance_PerUserMintLiveAAP verifies per-user issuance against a real AAP
// using the bootstrap-token mechanism: the engine authenticates with the target
// user's own token, so the minted token is owned by that user. The role also sets
// username, and the engine's ownership guard confirms the owner matches.
// Opt-in: set TEST_AAP_USERNAME and TEST_AAP_BOOTSTRAP_TOKEN (that user's token).
//
//	VAULT_ACC=1 TEST_AAP_ADDRESS=... TEST_AAP_TOKEN=<admin> \
//	  TEST_AAP_USERNAME=svc-deploy TEST_AAP_BOOTSTRAP_TOKEN=<svc-deploy's token> \
//	  go test -run TestAcceptance_PerUserMint -v
func TestAcceptance_PerUserMintLiveAAP(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("acceptance test skipped; set VAULT_ACC=1 to run against live AAP")
	}
	username := os.Getenv("TEST_AAP_USERNAME")
	bootstrap := os.Getenv("TEST_AAP_BOOTSTRAP_TOKEN")
	if username == "" || bootstrap == "" {
		t.Skip("set TEST_AAP_USERNAME and TEST_AAP_BOOTSTRAP_TOKEN to test per-user minting")
	}

	address := os.Getenv("TEST_AAP_ADDRESS")
	token := os.Getenv("TEST_AAP_TOKEN")
	require.NotEmpty(t, address, "TEST_AAP_ADDRESS required")
	require.NotEmpty(t, token, "TEST_AAP_TOKEN required")
	apiPath := os.Getenv("TEST_AAP_TOKENS_API_PATH")
	if apiPath == "" {
		apiPath = defaultTokensAPIPath
	}
	skipTLS := os.Getenv("TEST_AAP_SKIP_TLS_VERIFY") == "true"

	cfg := &aapConfig{Address: address, Token: token, TokensAPIPath: apiPath, SkipTLSVerify: skipTLS}
	client, err := newClient(cfg)
	require.NoError(t, err)
	ctx := context.Background()

	wantUserID, err := client.ResolveUserID(ctx, username)
	require.NoError(t, err, "username must resolve")

	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address": address, "token": token, "tokens_api_path": apiPath, "skip_tls_verify": skipTLS,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	testRoleCreate(t, b, s, "peruser", map[string]interface{}{
		"scope": "read", "description": "vault-peruser-acc",
		"username": username, "bootstrap_token": bootstrap, "ttl": "10m",
	})

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/peruser", Storage: s,
	})
	require.NoError(t, err, "per-user mint should succeed with a valid bootstrap token")
	require.NotNil(t, resp)

	// The minted token must genuinely be owned by the requested user.
	tokenID := resp.Data["token_id"].(int64)
	gotUserID, err := client.tokenOwner(ctx, tokenID)
	require.NoError(t, err)
	require.Equal(t, wantUserID, gotUserID, "minted token must be owned by %q", username)

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/peruser", Storage: s, Secret: resp.Secret,
	})
	require.NoError(t, err, "live revoke must succeed")
}
