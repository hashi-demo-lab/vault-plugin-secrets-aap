package aap

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConfig_CRUD(t *testing.T) {
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
			"address":         "https://aap.example.com",
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
	require.Equal(t, "https://aap.example.com", resp.Data["address"])
	require.Equal(t, "/api/gateway/v1", resp.Data["tokens_api_path"])
	require.Equal(t, true, resp.Data["skip_tls_verify"])
	require.Equal(t, true, resp.Data["token_set"])
	require.NotContains(t, resp.Data, "token", "token value must never be returned")

	// Updating connection details without a fresh token would redirect the
	// preserved privileged token, so it is rejected.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"address": "https://aap2.example.com"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "token is required")

	// Supplying a token makes the endpoint rotation explicit.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"address": "https://aap2.example.com", "token": "rotated-secret"},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.Equal(t, "https://aap2.example.com", cfg.Address)
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
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"address": "https://aap.example.com",
			"token":   "t",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.Equal(t, defaultTokensAPIPath, cfg.TokensAPIPath)
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
