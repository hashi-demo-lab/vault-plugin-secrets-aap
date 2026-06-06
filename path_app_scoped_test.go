package aap

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestCredentials_AppScopedMint verifies a role with an application binds the
// minted token to that OAuth2 application.
func TestCredentials_AppScopedMint(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{
		"scope": "read", "application": "ci-app", // resolves to id 20
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	tokenID := resp.Data["token_id"].(int64)
	require.Equal(t, int64(20), m.mintAppFor(tokenID), "token must be bound to ci-app")
}

// TestCredentials_AppScopedMint_Guard reproduces an AAP that drops the
// application binding; the engine must detect the mismatch, revoke, and error.
func TestCredentials_AppScopedMint_Guard(t *testing.T) {
	m := newMockAAP("admin-token")
	m.ignoreApp = true
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{
		"scope": "read", "application": "ci-app",
	})

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not bound to application")
	require.Equal(t, 0, m.liveCount(), "the mis-scoped token must be revoked, not leaked")
}

func TestCredentials_AppScopedMint_GuardReportsRevokeFailure(t *testing.T) {
	m := newMockAAP("admin-token")
	m.ignoreApp = true
	m.failRevoke = true
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{
		"scope": "read", "application": "ci-app",
	})

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to revoke minted token")
	require.Equal(t, 1, m.liveCount(), "the cleanup failure should be visible because the token remains live")
}

// TestCredentials_AppScopedMint_UnknownApp errors clearly and mints nothing when
// the application name does not resolve.
func TestCredentials_AppScopedMint_UnknownApp(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{
		"scope": "read", "application": "does-not-exist",
	})

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does-not-exist")
	require.Equal(t, 0, m.liveCount())
}

func TestRole_ApplicationPersistedAndReturned(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	testRoleCreate(t, b, s, "ci", map[string]interface{}{"scope": "read", "application": "ci-app"})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "role/ci", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "ci-app", resp.Data["application"])
}
