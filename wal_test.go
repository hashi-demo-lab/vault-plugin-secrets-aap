package aap

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestWALRollback_RevokesOrphanedToken simulates a token that was minted in AAP
// but whose lease never persisted: the periodic WAL rollback must revoke it.
func TestWALRollback_RevokesOrphanedToken(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	// Mint directly via the client to create an "orphan" with no lease.
	client, err := b.getClient(ctx, s)
	require.NoError(t, err)
	tok, err := client.CreateToken(ctx, "read", "orphan")
	require.NoError(t, err)
	require.Equal(t, 1, m.liveCount())

	// Rollback should revoke it.
	err = b.walRollback(ctx, &logical.Request{Storage: s}, walTypeToken, map[string]interface{}{
		"token_id": strconv.FormatInt(tok.ID, 10),
		"role":     "ci",
	})
	require.NoError(t, err)
	require.True(t, m.wasRevoked(tok.ID))
	require.Equal(t, 0, m.liveCount())
}

// TestWALRollback_Idempotent confirms rolling back an already-gone token is fine
// (the AAP delete is idempotent on 404).
func TestWALRollback_Idempotent(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	err := b.walRollback(ctx, &logical.Request{Storage: s}, walTypeToken, map[string]interface{}{
		"token_id": "424242",
		"role":     "ci",
	})
	require.NoError(t, err)
}

func TestWALRollback_BadInput(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	req := &logical.Request{Storage: s}

	require.Error(t, b.walRollback(ctx, req, "not-a-token", map[string]interface{}{}))
	require.Error(t, b.walRollback(ctx, req, walTypeToken, "not-a-map"))
	require.Error(t, b.walRollback(ctx, req, walTypeToken, map[string]interface{}{}))
	require.Error(t, b.walRollback(ctx, req, walTypeToken, map[string]interface{}{"token_id": "abc"}))
}

// TestCredentials_WALCleanedUpOnSuccess verifies the happy path leaves no WAL
// behind (the lease owns revocation).
func TestCredentials_WALCleanedUpOnSuccess(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{"scope": "read", "ttl": "1h"})

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/ci", Storage: s,
	})
	require.NoError(t, err)

	keys, err := s.List(ctx, "wal/")
	require.NoError(t, err)
	require.Empty(t, keys, "no WAL entries should remain after a successful mint")
}
