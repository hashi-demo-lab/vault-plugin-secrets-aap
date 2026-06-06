package aap

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConfig_CRUD(t *testing.T) {
	// Config write verifies connectivity, so back it with mock AAP servers: one
	// for the initial connection and one for the rotated connection.
	original := newMockAAP("super-secret")
	originalSrv := original.server(t)
	defer originalSrv.Close()
	rotated := newMockAAP("rotated-secret")
	rotatedSrv := rotated.server(t)
	defer rotatedSrv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	// Read before write → no config.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Create.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address":         originalSrv.URL,
			"token":           "super-secret",
			"tokens_api_path": "/api/gateway/v1",
			"skip_tls_verify": true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	// Read → token must NOT be disclosed.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, originalSrv.URL, resp.Data["address"])
	require.Equal(t, "/api/gateway/v1", resp.Data["tokens_api_path"])
	require.Equal(t, true, resp.Data["skip_tls_verify"])
	require.Equal(t, true, resp.Data["token_set"])
	require.NotContains(t, resp.Data, "token", "token value must never be returned")

	// Updating connection details without a fresh token would redirect the
	// preserved privileged token, so it is rejected.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"address": rotatedSrv.URL},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "credential (token or password) is required")

	// Supplying a token makes the endpoint rotation explicit.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"address": rotatedSrv.URL, "token": "rotated-secret"},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.Equal(t, rotatedSrv.URL, cfg.Address)
	require.Equal(t, "rotated-secret", cfg.Token)

	// Delete.
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	cfg, err = getConfig(ctx, s)
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestConfig_DefaultsTokensAPIPath(t *testing.T) {
	m := newMockAAP("t")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address":         srv.URL,
			"token":           "t",
			"skip_tls_verify": true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.Equal(t, defaultTokensAPIPath, cfg.TokensAPIPath)
}

// TestConfig_VerificationRejectsBadToken confirms a config write is rejected when
// the privileged token is wrong, so misconfiguration surfaces at config time
// rather than on the first creds/ read.
func TestConfig_VerificationRejectsBadToken(t *testing.T) {
	m := newMockAAP("correct-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address":         srv.URL,
			"token":           "wrong-token",
			"skip_tls_verify": true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "verification failed")

	// Nothing should have been persisted.
	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestConfig_CreateRequiresAddressAndToken(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"address": "https://aap.example.com"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError(), "missing token should error")

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"token": "t"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError(), "missing address should error")
}

func TestConfig_ExistenceCheck(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	_, exists, err := b.HandleExistenceCheck(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	require.False(t, exists)

	testConfigCreate(t, b, s, srv.URL, "admin-token")

	_, exists, err = b.HandleExistenceCheck(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	require.True(t, exists)
}

func TestConfig_BasicAuth(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addBasicIdentity("svc-admin", "s3cret", 2)
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	// Configure with basic auth (no token). Verification runs against the mock.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address":         srv.URL,
			"username":        "svc-admin",
			"password":        "s3cret",
			"skip_tls_verify": true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "basic-auth config should succeed: %v", resp)

	// Read shows auth_type/username but never the password.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "basic", resp.Data["auth_type"])
	require.Equal(t, "svc-admin", resp.Data["username"])
	require.Equal(t, true, resp.Data["password_set"])
	require.NotContains(t, resp.Data, "password", "password must never be returned")
}

func TestConfig_UpdateTokenClearsRotateRootTokenID(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addIdentity("manual-token", 2)
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
	require.NotZero(t, cfg.TokenID)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"token": "manual-token",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "manual token update should succeed: %v", resp)

	cfg, err = getConfig(ctx, s)
	require.NoError(t, err)
	require.Equal(t, "manual-token", cfg.Token)
	require.Zero(t, cfg.TokenID, "operator-supplied tokens have no known AAP token id")
}

func TestConfig_CanSwitchAuthSchemes(t *testing.T) {
	m := newMockAAP("admin-token")
	m.addBasicIdentity("svc-admin", "s3cret", 2)
	m.addIdentity("rotated-token", 2)
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"username": "svc-admin",
			"password": "s3cret",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "bearer -> basic should succeed: %v", resp)
	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.Empty(t, cfg.Token)
	require.Equal(t, "svc-admin", cfg.Username)
	require.Equal(t, "s3cret", cfg.Password)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"token": "rotated-token",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "basic -> bearer should succeed: %v", resp)
	cfg, err = getConfig(ctx, s)
	require.NoError(t, err)
	require.Equal(t, "rotated-token", cfg.Token)
	require.Empty(t, cfg.Username)
	require.Empty(t, cfg.Password)
}

func TestConfig_RejectsBothSchemes(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address": "https://aap.example.com", "token": "t", "username": "u", "password": "p",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "not both")
}

func TestConfig_BasicAuthRequiresBoth(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address": "https://aap.example.com", "username": "u", // no password
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "username and password")
}

func TestConfig_RejectsPlainHTTPAddress(t *testing.T) {
	b, s := getTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address": "http://aap.example.com",
			"token":   "t",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "https")
}
