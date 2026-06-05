package aap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, address, token string) *aapClient {
	t.Helper()
	c, err := newClient(&aapConfig{
		Address:       address,
		Token:         token,
		TokensAPIPath: "/api/gateway/v1",
		SkipTLSVerify: true,
	})
	require.NoError(t, err)
	return c
}

func TestClient_newClient_validation(t *testing.T) {
	_, err := newClient(nil)
	require.ErrorIs(t, err, errBackendNotConfigured)

	_, err = newClient(&aapConfig{Address: "https://x"})
	require.ErrorIs(t, err, errMissingToken)

	_, err = newClient(&aapConfig{Token: "t"})
	require.ErrorIs(t, err, errMissingAddress)

	_, err = newClient(&aapConfig{Address: "https://x", Token: "t", CACert: "not-a-pem"})
	require.Error(t, err)
}

func TestClient_normalize(t *testing.T) {
	require.Equal(t, "https://aap.example.com", normalizeAddress("https://aap.example.com/"))
	require.Equal(t, "https://aap.example.com", normalizeAddress("  https://aap.example.com  "))
	require.Equal(t, "/api/gateway/v1", normalizeBasePath(""))
	require.Equal(t, "/api/gateway/v1", normalizeBasePath("api/gateway/v1/"))
	require.Equal(t, "/api/controller/v2", normalizeBasePath("/api/controller/v2"))
}

func TestClient_CreateAndRevoke(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "admin-token")
	ctx := context.Background()

	tok, err := c.CreateToken(ctx, "write", "vault-test")
	require.NoError(t, err)
	require.NotZero(t, tok.ID)
	require.NotEmpty(t, tok.Token)
	require.Equal(t, "write", tok.Scope)
	require.Equal(t, 1, m.liveCount())

	require.NoError(t, c.RevokeToken(ctx, tok.ID))
	require.True(t, m.wasRevoked(tok.ID))
	require.Equal(t, 0, m.liveCount())
}

func TestClient_Revoke_idempotentOn404(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "admin-token")
	// Revoking a token that never existed must succeed (idempotent).
	require.NoError(t, c.RevokeToken(context.Background(), 999999))
}

func TestClient_CreateToken_badAuth(t *testing.T) {
	m := newMockAAP("the-right-token")
	srv := m.server(t)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "the-wrong-token")
	_, err := c.CreateToken(context.Background(), "read", "x")
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
}
