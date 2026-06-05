package aap

import (
	"context"
	"encoding/json"
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

func TestRole_ExistenceCheck(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	_, exists, err := b.HandleExistenceCheck(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "role/ci", Storage: s,
	})
	require.NoError(t, err)
	require.False(t, exists)

	testRoleCreate(t, b, s, "ci", map[string]interface{}{"scope": "read"})

	_, exists, err = b.HandleExistenceCheck(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "role/ci", Storage: s,
	})
	require.NoError(t, err)
	require.True(t, exists)
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

func TestRole_DefaultScopeIsRead(t *testing.T) {
	b, s := getTestBackend(t)
	testRoleCreate(t, b, s, "defaulted", map[string]interface{}{})

	role, err := b.getRole(context.Background(), s, "defaulted")
	require.NoError(t, err)
	require.Equal(t, "read", role.Scope, "default scope should be least-privilege 'read'")
}

func TestRole_UsernamePersistedAndReturned(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	testRoleCreate(t, b, s, "deploy", map[string]interface{}{
		"scope":    "write",
		"username": "svc-deploy",
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "role/deploy", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "svc-deploy", resp.Data["username"])

	// Empty by default for roles that don't target a user.
	testRoleCreate(t, b, s, "plain", map[string]interface{}{"scope": "read"})
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "role/plain", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "", resp.Data["username"])
}

// TestRole_SchemaUpgrade confirms a role persisted before the username field was
// added decodes cleanly, with username defaulting to empty (mint-as-engine).
func TestRole_SchemaUpgrade(t *testing.T) {
	oldBlob := []byte(`{"scope":"write","description":"legacy","ttl":3600,"max_ttl":28800}`)
	var role aapRoleEntry
	require.NoError(t, json.Unmarshal(oldBlob, &role))
	require.Equal(t, "write", role.Scope)
	require.Equal(t, "legacy", role.Description)
	require.Equal(t, "", role.Username, "new field defaults to empty on legacy entries")
}
