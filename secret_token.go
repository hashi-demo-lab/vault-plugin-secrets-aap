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
				Type:        framework.TypeString,
				Description: "The AAP token ID (used for revocation).",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

// createToken mints a new AAP token for the given role using the configured
// client.
func (b *aapBackend) createToken(ctx context.Context, s logical.Storage, role *aapRoleEntry) (*aapToken, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	token, err := client.CreateToken(ctx, role.Scope, role.Description)
	if err != nil {
		return nil, fmt.Errorf("error creating AAP token: %w", err)
	}
	return token, nil
}

// tokenRevoke deletes the AAP token recorded in the lease's internal data.
func (b *aapBackend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client during revoke: %w", err)
	}

	idRaw, ok := req.Secret.InternalData["token_id"]
	if !ok {
		return nil, errors.New("token_id missing from secret internal data")
	}

	id, err := coerceTokenID(idRaw)
	if err != nil {
		return nil, err
	}

	if err := client.RevokeToken(ctx, id); err != nil {
		return nil, fmt.Errorf("error revoking AAP token %d: %w", id, err)
	}
	return nil, nil
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
		// The role was deleted after issuance; let the lease run out naturally.
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
