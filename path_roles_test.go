package aap

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestRole_CRUDAndList(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	testRoleCreate(t, b, s, "ci", map[string]interface{}{
		"scope":       "write",
		"description": "CI pipeline token",
		"ttl":         "1h",
		"max_ttl":     "8h",
	})

	// Read.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "role/ci", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "write", resp.Data["scope"])
	require.Equal(t, "CI pipeline token", resp.Data["description"])
	require.Equal(t, int64(3600), resp.Data["ttl"])
	require.Equal(t, int64(28800), resp.Data["max_ttl"])

	// Second role + list.
	testRoleCreate(t, b, s, "readonly", map[string]interface{}{"scope": "read"})
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "role/", Storage: s,
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"ci", "readonly"}, resp.Data["keys"])

	// Delete.
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "role/ci", Storage: s,
	})
	require.NoError(t, err)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "role/ci", Storage: s,
	})
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestRole_InvalidScopeRejected(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "role/bad", Storage: s,
		Data: map[string]interface{}{"scope": "delete"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "invalid scope")
}

func TestRole_TTLCannotExceedMaxTTL(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "role/bad", Storage: s,
		Data: map[string]interface{}{"scope": "read", "ttl": "10h", "max_ttl": "1h"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "cannot exceed max_ttl")
}

func TestRole_DefaultScopeIsWrite(t *testing.T) {
	b, s := getTestBackend(t)
	testRoleCreate(t, b, s, "defaulted", map[string]interface{}{})

	role, err := b.getRole(context.Background(), s, "defaulted")
	require.NoError(t, err)
	require.Equal(t, "write", role.Scope)
}
