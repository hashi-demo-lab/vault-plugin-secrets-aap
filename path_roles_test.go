package aap

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

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
	require.Equal(t, "read", role.Scope, "default scope should be least-privilege read")
}

func TestRole_UsernameRequiresBootstrapToken(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "role/deploy", Storage: s,
		Data: map[string]interface{}{
			"scope":    "read",
			"username": "svc-deploy",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "bootstrap_token")
}

func TestRole_UsernamePersistedAndReturned(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	testRoleCreate(t, b, s, "deploy", map[string]interface{}{
		"scope":           "write",
		"username":        "svc-deploy",
		"bootstrap_token": "svc-deploy-secret-token",
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "role/deploy", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "svc-deploy", resp.Data["username"])
	require.Equal(t, true, resp.Data["bootstrap_token_set"])
	require.NotContains(t, resp.Data, "bootstrap_token", "bootstrap_token must never be returned on read")

	// The bootstrap token is persisted (used internally) but not disclosed.
	role, err := b.getRole(ctx, s, "deploy")
	require.NoError(t, err)
	require.Equal(t, "svc-deploy-secret-token", role.BootstrapToken)

	// Empty by default for roles that don't target a user.
	testRoleCreate(t, b, s, "plain", map[string]interface{}{"scope": "read"})
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "role/plain", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "", resp.Data["username"])
	require.Equal(t, false, resp.Data["bootstrap_token_set"])
}

func TestRole_UpdateCanClearOptionalFields(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	testRoleCreate(t, b, s, "deploy", map[string]interface{}{
		"scope":           "write",
		"description":     "deploy tokens",
		"username":        "svc-deploy",
		"bootstrap_token": "svc-deploy-token",
		"application":     "ci-app",
		"ttl":             "1h",
		"max_ttl":         "8h",
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "role/deploy", Storage: s,
		Data: map[string]interface{}{
			"description":     "",
			"username":        "",
			"bootstrap_token": "",
			"application":     "",
			"ttl":             0,
			"max_ttl":         0,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "clear update should succeed: %v", resp)

	role, err := b.getRole(ctx, s, "deploy")
	require.NoError(t, err)
	require.Equal(t, "write", role.Scope)
	require.Empty(t, role.Description)
	require.Empty(t, role.Username)
	require.Empty(t, role.BootstrapToken)
	require.Empty(t, role.Application)
	require.Zero(t, role.TTL)
	require.Zero(t, role.MaxTTL)
}

func TestRole_ConcurrentUpdatesMergeWithLatestState(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	testRoleCreate(t, b, s, "deploy", map[string]interface{}{"scope": "read"})

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	update := func(data map[string]interface{}) {
		defer wg.Done()
		<-start
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation, Path: "role/deploy", Storage: s, Data: data,
		})
		if err != nil {
			errs <- err
			return
		}
		if resp != nil && resp.IsError() {
			errs <- resp.Error()
		}
	}

	wg.Add(2)
	go update(map[string]interface{}{"description": "merged", "ttl": "30m"})
	go update(map[string]interface{}{"application": "ci-app", "max_ttl": "2h"})
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	role, err := b.getRole(ctx, s, "deploy")
	require.NoError(t, err)
	require.Equal(t, "merged", role.Description)
	require.Equal(t, "ci-app", role.Application)
	require.Equal(t, 30*time.Minute, role.TTL)
	require.Equal(t, 2*time.Hour, role.MaxTTL)
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
