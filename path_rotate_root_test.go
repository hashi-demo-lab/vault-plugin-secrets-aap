package aap

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
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

func TestRotateRoot_ReportsNewTokenCleanupFailure(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	m.failVerify = true
	m.failRevoke = true
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to revoke newly minted root token")
	require.Equal(t, 1, m.liveCount(), "the cleanup failure should be visible because the new root token remains live")
}

func TestRotateRoot_ConcurrentRotationsDoNotOrphanIntermediateToken(t *testing.T) {
	m := newMockAAP("admin-token")
	m.createDelay = 50 * time.Millisecond
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s,
			})
			if err != nil {
				errs <- err
				return
			}
			if resp != nil && resp.IsError() {
				errs <- resp.Error()
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.NotZero(t, cfg.TokenID)
	require.Equal(t, 1, m.liveCount(), "only the currently configured root token should remain live")
	require.False(t, m.wasRevoked(cfg.TokenID), "the configured root token should be the surviving token")
}

func TestRotateRoot_OldTokenRevokeFailureRecordsRetryWAL(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s,
	})
	require.NoError(t, err)
	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	firstID := cfg.TokenID

	m.failRevoke = true
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Warnings, 1)
	require.Contains(t, resp.Warnings[0], "retry recorded")
	require.Equal(t, 2, m.liveCount(), "old and new root tokens are live until retry runs")

	wals, err := framework.ListWAL(ctx, s)
	require.NoError(t, err)
	require.Len(t, wals, 1)

	m.failRevoke = false
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true},
	})
	require.NoError(t, err)
	require.True(t, m.wasRevoked(firstID), "WAL rollback should retry old-root cleanup")
	cfg, err = getConfig(ctx, s)
	require.NoError(t, err)
	require.False(t, m.wasRevoked(cfg.TokenID), "current root token must remain live")
	require.Equal(t, 1, m.liveCount())
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
