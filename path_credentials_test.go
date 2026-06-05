package aap

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

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

	tokenID := resp.Secret.InternalData["token_id"].(int64)
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
	tokenID := resp.Secret.InternalData["token_id"].(int64)

	// Round-trip InternalData through JSON, as Vault does when persisting leases.
	raw, err := json.Marshal(resp.Secret.InternalData)
	require.NoError(t, err)
	var reloaded map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &reloaded))
	_, isFloat := reloaded["token_id"].(float64)
	require.True(t, isFloat, "JSON round-trip should yield float64 token_id")
	resp.Secret.InternalData = reloaded

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/ci", Storage: s, Secret: resp.Secret,
	})
	require.NoError(t, err)
	require.True(t, m.wasRevoked(tokenID), "revoke must work after JSON round-trip")
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
