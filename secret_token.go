package aap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// aapTokenType is the framework.Secret Type string Vault uses to route
// Renew/Revoke callbacks back to this engine for leased AAP tokens.
const aapTokenType = "aap_token"

// aapToken declares the dynamic secret. Vault invokes Revoke when a lease
// expires or is explicitly revoked, and Renew when a holder extends a lease.
//
// Renewal strategy (A): a renew extends the Vault lease but keeps the SAME AAP
// token. This is safe here because AAP tokens default to a one-year server-side
// expiry, comfortably outliving any reasonable max_ttl, so the lease — not the
// AAP token — is the binding clock. (AAP exposes no "extend token expiry" API,
// so re-minting would be the only alternative; it is unnecessary given the
// long default expiry.)
func (b *aapBackend) aapToken() *framework.Secret {
	return &framework.Secret{
		Type: aapTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "The AAP OAuth2 token value.",
			},
			"token_id": {
				Type:        framework.TypeInt64,
				Description: "The AAP token ID (used for revocation).",
			},
			"scope": {
				Type:        framework.TypeString,
				Description: "The OAuth2 scope granted to the token.",
			},
			"expires": {
				Type:        framework.TypeString,
				Description: "The AAP token's upstream expiration timestamp.",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

// createToken mints a new AAP token for the given role using the configured
// client.
func (b *aapBackend) createToken(ctx context.Context, s logical.Storage, role *aapRoleEntry) (*aapToken, *aapConfig, error) {
	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	if config == nil {
		return nil, nil, errBackendNotConfigured
	}

	client, err := newClient(config)
	if err != nil {
		return nil, nil, err
	}

	// When the role targets a specific AAP user, resolve it to the numeric id the
	// mint payload requires. A zero id means "mint as the engine's identity".
	var userID int64
	if role.Username != "" {
		userID, err = client.ResolveUserID(ctx, role.Username)
		if err != nil {
			return nil, nil, fmt.Errorf("error resolving AAP user %q: %w", role.Username, err)
		}
	}

	token, err := client.CreateToken(ctx, role.Scope, role.Description, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AAP token: %w", err)
	}

	// Per-user safety guard. AAP mints a token for the *authenticating* identity;
	// some versions (e.g. the 2.5 gateway) silently ignore the requested "user"
	// field rather than rejecting it, which would misattribute the token. When a
	// role targets a user, confirm the minted token is actually owned by that
	// user; if not, revoke it and fail loudly rather than hand back a token that
	// carries the wrong identity's RBAC.
	if userID > 0 {
		owner, verr := client.tokenOwner(ctx, token.ID)
		if verr != nil {
			_ = client.RevokeToken(ctx, token.ID)
			return nil, nil, fmt.Errorf("could not verify owner of token minted for %q: %w", role.Username, verr)
		}
		if owner != userID {
			_ = client.RevokeToken(ctx, token.ID)
			return nil, nil, fmt.Errorf("AAP did not honor per-user issuance: token was minted for user id %d, not %q (id %d). This AAP version may not support minting on behalf of another user with the configured token", owner, role.Username, userID)
		}
	}

	return token, cloneConfig(config), nil
}

// tokenRevoke deletes the AAP token recorded in the lease's internal data.
func (b *aapBackend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	idRaw, ok := req.Secret.InternalData["token_id"]
	if !ok {
		return nil, errors.New("token_id missing from secret internal data")
	}

	id, err := coerceTokenID(idRaw)
	if err != nil {
		return nil, err
	}

	client, err := b.revocationClient(ctx, req.Storage, req.Secret.InternalData)
	if err != nil {
		return nil, fmt.Errorf("error getting client during revoke: %w", err)
	}

	if err := client.RevokeToken(ctx, id); err != nil {
		return nil, fmt.Errorf("error revoking AAP token %d: %w", id, err)
	}
	return nil, nil
}

func (b *aapBackend) revocationClient(ctx context.Context, s logical.Storage, data map[string]interface{}) (*aapClient, error) {
	config, ok, err := configFromRevocationData(data)
	if err != nil {
		return nil, err
	}
	if ok {
		return newClient(config)
	}
	return b.getClient(ctx, s)
}

// tokenRenew extends the lease using the originating role's TTL/MaxTTL. The
// underlying AAP token is unchanged (strategy A).
func (b *aapBackend) tokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("role missing from secret internal data")
	}
	roleName, ok := roleRaw.(string)
	if !ok {
		return nil, errors.New("role internal data is not a string")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role %q during renew: %w", roleName, err)
	}
	if role == nil {
		// The role was deleted after issuance. Deny the renewal; the lease keeps
		// its current TTL and expires on schedule, at which point Revoke fires.
		return nil, fmt.Errorf("cannot renew: role %q no longer exists", roleName)
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

// coerceTokenID normalizes the token ID out of internal data. The engine stores
// it as a string so the lease's JSON round-trip preserves it exactly; the other
// cases are defensive (e.g. leases written before that change, where a JSON
// number decodes to float64).
func coerceTokenID(raw interface{}) (int64, error) {
	switch v := raw.(type) {
	case string:
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid token_id %q: %w", v, err)
		}
		return id, nil
	case json.Number:
		return v.Int64()
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case float64:
		// Legacy numeric form; exact for AAP-scale ids (well under 2^53).
		return int64(v), nil
	default:
		return 0, fmt.Errorf("unexpected token_id type %T", raw)
	}
}
