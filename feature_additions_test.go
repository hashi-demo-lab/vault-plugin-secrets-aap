package aap

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// writeConfigWith writes the engine config with an arbitrary data map (the
// testConfigCreate helper only covers the minimal fields). It returns the
// response so callers can assert warnings.
func writeConfigWith(tb testing.TB, b *aapBackend, s logical.Storage, data map[string]interface{}) (*logical.Response, error) {
	tb.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.CreateOperation,
		Path:       "config",
		MountPoint: "aap/",
		Storage:    s,
		Data:       data,
	})
}

// mintCreds reads creds/<role> and returns the minted token's AAP id.
func mintCreds(tb testing.TB, b *aapBackend, s logical.Storage, role string) int64 {
	tb.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + role,
		Storage:   s,
	})
	require.NoError(tb, err)
	require.NotNil(tb, resp)
	require.False(tb, resp.IsError(), "mint errored: %v", resp.Error())
	id, ok := resp.Data["token_id"].(int64)
	require.True(tb, ok, "token_id missing or wrong type: %#v", resp.Data["token_id"])
	return id
}

// --- request_timeout -------------------------------------------------------

func TestConfig_RequestTimeout_RoundTripAndClient(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := writeConfigWith(t, b, s, map[string]interface{}{
		"address":         srv.URL,
		"token":           "admin-token",
		"skip_tls_verify": true,
		"request_timeout": "45s",
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	rd, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: s})
	require.NoError(t, err)
	require.Equal(t, int64(45), rd.Data["request_timeout"])

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.Equal(t, 45*time.Second, cfg.RequestTimeout)

	c, err := newClient(cfg)
	require.NoError(t, err)
	require.Equal(t, 45*time.Second, c.httpClient.Timeout)
}

func TestConfig_RequestTimeout_DefaultsWhenUnset(t *testing.T) {
	cfg := &aapConfig{Address: "https://aap.example.com", Token: "x", SkipTLSVerify: true}
	c, err := newClient(cfg)
	require.NoError(t, err)
	require.Equal(t, defaultHTTPTimeout, c.httpClient.Timeout)
}

func TestConfig_RequestTimeout_RejectsNegative(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	b, s := getTestBackend(t)

	// TypeDurationSecond rejects negatives at field validation, before the handler.
	resp, err := writeConfigWith(t, b, s, map[string]interface{}{
		"address":         srv.URL,
		"token":           "admin-token",
		"skip_tls_verify": true,
		"request_timeout": -5,
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "negative value")
}

// --- token_description_prefix ----------------------------------------------

func TestCreds_DescriptionPrefixApplied(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	b, s := getTestBackend(t)

	_, err := writeConfigWith(t, b, s, map[string]interface{}{
		"address":                  srv.URL,
		"token":                    "admin-token",
		"skip_tls_verify":          true,
		"token_description_prefix": "vault:ci:",
	})
	require.NoError(t, err)
	testRoleCreate(t, b, s, "ci", map[string]interface{}{"scope": "read", "description": "deploy", "ttl": "1h"})

	id := mintCreds(t, b, s, "ci")
	require.Equal(t, "vault:ci:deploy", m.mintDescFor(id))
}

func TestCreds_NoPrefixLeavesDescriptionUnchanged(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	b, s := getTestBackend(t)

	testConfigCreate(t, b, s, srv.URL, "admin-token")
	testRoleCreate(t, b, s, "ci", map[string]interface{}{"scope": "read", "description": "deploy", "ttl": "1h"})

	id := mintCreds(t, b, s, "ci")
	require.Equal(t, "deploy", m.mintDescFor(id))
}

// Note: a "token_expiry_buffer" / server-side expiry backstop was prototyped and
// then removed — AAP controls token expiry globally (OAUTH2_PROVIDER) and ignores
// any client-supplied per-token "expires", so the engine cannot shorten a token's
// life. The description prefix above is the supported orphan-mitigation lever.

// --- automated rotation (Rotation Manager integration) ---------------------

func TestConfig_RotationPeriodPersistsWithWarningOnCE(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := writeConfigWith(t, b, s, map[string]interface{}{
		"address":         srv.URL,
		"token":           "admin-token",
		"skip_tls_verify": true,
		"rotation_period": 86400,
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "config write must succeed even when RM is unavailable")
	// StaticSystemView (the test/CE system view) cannot register rotation jobs, so
	// the engine downgrades that to a warning rather than failing the write.
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Warnings)

	rd, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: s})
	require.NoError(t, err)
	require.Equal(t, 86400, rd.Data["rotation_period"])
}

func TestConfig_RotationRequiresBearerAuth(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	m.addBasicIdentity("svc", "pw", 2)
	b, s := getTestBackend(t)

	resp, err := writeConfigWith(t, b, s, map[string]interface{}{
		"address":         srv.URL,
		"username":        "svc",
		"password":        "pw",
		"skip_tls_verify": true,
		"rotation_period": 3600,
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "requires bearer-token auth")
}

func TestConfig_RotationScheduleAndPeriodMutuallyExclusive(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	b, s := getTestBackend(t)

	resp, err := writeConfigWith(t, b, s, map[string]interface{}{
		"address":           srv.URL,
		"token":             "admin-token",
		"skip_tls_verify":   true,
		"rotation_schedule": "0 0 * * *",
		"rotation_window":   3600,
		"rotation_period":   3600,
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "invalid rotation settings")
}

func TestRotateCredentialCallback_Wired(t *testing.T) {
	b, _ := getTestBackend(t)
	require.NotNil(t, b.RotateCredential, "RM callback must be wired so scheduled rotations route here")
}

func TestRotateCredentialCallback_RotatesRoot(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()
	b, s := getTestBackend(t)
	ctx := context.Background()

	testConfigCreate(t, b, s, srv.URL, "admin-token")

	// Invoke the Rotation Manager callback directly; it shares rotate-root's logic.
	err := b.rotateRootCredential(ctx, &logical.Request{
		Storage:    s,
		Path:       "config",
		MountPoint: "aap/",
	})
	require.NoError(t, err)

	cfg, err := getConfig(ctx, s)
	require.NoError(t, err)
	require.NotEqual(t, "admin-token", cfg.Token, "the privileged token should have been replaced")
	require.Greater(t, cfg.TokenID, int64(0), "the engine should now track the rotated token's id")
}
