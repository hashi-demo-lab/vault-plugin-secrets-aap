package aap

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	_, err = newClient(&aapConfig{Address: "http://x", Token: "t"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "https")
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

func TestClient_ResolveUserID(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "admin-token")
	ctx := context.Background()

	id, err := c.ResolveUserID(ctx, "svc-deploy")
	require.NoError(t, err)
	require.Equal(t, int64(7), id)

	_, err = c.ResolveUserID(ctx, "nope")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestClient_CreateToken_OwnedByCaller(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	ctx := context.Background()

	// The admin token mints as the admin identity (id 2).
	admin := newTestClient(t, srv.URL, "admin-token")
	tok, err := admin.CreateToken(ctx, "read", "as-admin")
	require.NoError(t, err)
	require.Equal(t, int64(2), m.mintUserFor(tok.ID))

	// A client authenticating with a service account's own (bootstrap) token
	// mints a token owned by that account — the basis of per-user issuance.
	m.addIdentity("svc-deploy-token", 7)
	svc := newTestClient(t, srv.URL, "svc-deploy-token")
	tok, err = svc.CreateToken(ctx, "read", "as-svc")
	require.NoError(t, err)
	require.Equal(t, int64(7), m.mintUserFor(tok.ID))
}

func TestClient_BasicAuth(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addBasicIdentity("svc", "pw", 5)
	srv := m.server(t)
	defer srv.Close()

	c, err := newClient(&aapConfig{
		Address: srv.URL, Username: "svc", Password: "pw",
		TokensAPIPath: "/api/gateway/v1", SkipTLSVerify: true,
	})
	require.NoError(t, err)
	require.Equal(t, "basic", c.auth.scheme())

	tok, err := c.CreateToken(context.Background(), "read", "via-basic")
	require.NoError(t, err)
	require.Equal(t, int64(5), m.mintUserFor(tok.ID), "basic-auth client mints as its user")
}

func TestClient_authenticatorFromConfig(t *testing.T) {
	a, err := authenticatorFromConfig(&aapConfig{Token: "t"})
	require.NoError(t, err)
	require.Equal(t, "bearer", a.scheme())

	a, err = authenticatorFromConfig(&aapConfig{Username: "u", Password: "p"})
	require.NoError(t, err)
	require.Equal(t, "basic", a.scheme())

	_, err = authenticatorFromConfig(&aapConfig{})
	require.ErrorIs(t, err, errMissingToken)
}

func TestClient_ResolveUserID_Ambiguous(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "admin-token")
	_, err := c.ResolveUserID(context.Background(), "ambiguous")
	require.Error(t, err)
	require.Contains(t, err.Error(), "ambiguous")
}

func TestClient_tokenOwner(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "admin-token")
	ctx := context.Background()

	tok, err := c.CreateToken(ctx, "read", "owned")
	require.NoError(t, err)
	owner, err := c.tokenOwner(ctx, tok.ID)
	require.NoError(t, err)
	require.Equal(t, int64(2), owner) // admin token mints as id 2

	// A token that does not exist returns an error (non-200).
	_, err = c.tokenOwner(ctx, 999999)
	require.Error(t, err)
}

func TestClient_VerifyToken_Errors(t *testing.T) {
	// Wrong bearer → auth error.
	m := newMockAAP("right")
	srv := m.server(t)
	c := newTestClient(t, srv.URL, "wrong")
	err := c.VerifyToken(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "rejected")

	// Unreachable endpoint → transport error.
	srv.Close()
	err = c.VerifyToken(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "could not reach")
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

func TestClient_CreateToken_rejectsMissingOrZeroID(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"missing id", `{"token":"secret-token","scope":"read"}`},
		{"zero id", `{"id":0,"token":"secret-token","scope":"read"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := newTestClient(t, srv.URL, "admin-token")
			_, err := c.CreateToken(context.Background(), "read", "vault-test")
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid token id")
		})
	}
}
