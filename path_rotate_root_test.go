package aap

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestRotateRoot(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	// First rotation: the operator's token id is unknown, so it can't be revoked.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Warnings)
	require.Contains(t, resp.Warnings[0], "operator-supplied")

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.NotEqual(t, "admin-token", cfg.Token, "token must have been replaced")
	require.NotZero(t, cfg.TokenID, "the new token's id must be recorded")
	firstID := cfg.TokenID

	// Second rotation: now the previous (engine-minted) token's id is known and
	// gets revoked, with no warning.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Empty(t, resp.Warnings, "second rotation should revoke cleanly: %v", resp.Warnings)
	require.True(t, m.wasRevoked(firstID), "the previous engine-minted token must be revoked")

	cfg2, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.NotEqual(t, firstID, cfg2.TokenID)
}

func TestRotateRoot_BasicAuthRejected(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addBasicIdentity("svc-admin", "pw", 2)
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address": srv.URL, "username": "svc-admin", "password": "pw", "skip_tls_verify": true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "only supported for token")
}

// TestRevoke_FallsBackToCurrentConfig confirms that when the lease's snapshot
// credential no longer works (e.g. revoked by rotate-root), revocation falls
// back to the engine's current config.
func TestRevoke_FallsBackToCurrentConfig(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	// Mint a live token via the current (valid) admin credential.
	c, err := newClient(&aapConfig{Address: srv.URL, Token: "admin-token", TokensAPIPath: "/api/gateway/v1", SkipTLSVerify: true})
	require.NoError(t, err)
	tok, err := c.CreateToken(ctx, "read", "to-revoke")
	require.NoError(t, err)

	// Snapshot points at a bogus (now-unauthorized) credential.
	data := map[string]interface{}{
		revocationAddressKey:       srv.URL,
		revocationTokenKey:         "revoked-old-token",
		revocationTokensAPIPathKey: "/api/gateway/v1",
		revocationSkipTLSVerifyKey: true,
	}
	require.NoError(t, b.revokeToken(ctx, s, data, tok.ID))
	require.True(t, m.wasRevoked(tok.ID), "revoke must succeed via current-config fallback")
}

// TestAcceptance_RotateRootLiveAAP rotates the engine's privileged token against
// a real AAP, confirms the new token works (mint + revoke a creds token), then
// revokes the newly-minted privileged token to avoid leaking it. The original
// operator token is left intact (its id is unknown to the engine).
//
//	VAULT_ACC=1 TEST_AAP_ADDRESS=... TEST_AAP_TOKEN=<admin> \
//	  go test -run TestAcceptance_RotateRoot -v
func TestAcceptance_RotateRootLiveAAP(t *testing.T) {
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
			"address": address, "token": token, "tokens_api_path": apiPath, "skip_tls_verify": skipTLS,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.NotEqual(t, token, cfg.Token, "config token must have been rotated")
	require.NotZero(t, cfg.TokenID)
	t.Logf("rotated root token; new token id=%d", cfg.TokenID)

	// The new token must actually work: mint and revoke a creds token.
	testRoleCreate(t, b, s, "acc", map[string]interface{}{"scope": "read", "description": "vault-rotate-acc", "ttl": "10m"})
	credResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/acc", Storage: s,
	})
	require.NoError(t, err, "minting with the rotated token must work")
	require.NotEmpty(t, credResp.Data["token"])
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/acc", Storage: s, Secret: credResp.Secret,
	})
	require.NoError(t, err)

	// Cleanup: revoke the newly-minted privileged token via the original token.
	adminClient, err := newClient(&aapConfig{Address: address, Token: token, TokensAPIPath: apiPath, SkipTLSVerify: skipTLS})
	require.NoError(t, err)
	require.NoError(t, adminClient.RevokeToken(ctx, cfg.TokenID), "cleanup: revoke the minted root token")
}
