package aap

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCredentials defines the creds/<role> path that mints leased AAP tokens.
func pathCredentials(b *aapBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixAAP,
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role to mint a token for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
		},
		HelpSynopsis:    pathCredentialsHelpSynopsis,
		HelpDescription: pathCredentialsHelpDescription,
	}
}

// pathCredentialsRead mints a fresh AAP token for the named role and returns it
// wrapped in a Vault lease.
func (b *aapBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	return b.createCreds(ctx, req, roleName, role)
}

// createCreds mints the token and assembles the leased secret response.
//
// A WAL entry is written around the mint so that if the request fails after the
// token is created in AAP but before the lease is durably stored, the periodic
// WAL rollback revokes the orphaned token. On success the WAL is removed before
// returning, because the lease itself then carries the token ID for revocation.
func (b *aapBackend) createCreds(ctx context.Context, req *logical.Request, roleName string, role *aapRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("error creating AAP token: nil token returned")
	}

	tokenIDStr := strconv.FormatInt(token.ID, 10)

	walID, err := framework.PutWAL(ctx, req.Storage, walTypeToken, &walToken{
		TokenID: tokenIDStr,
		Role:    roleName,
	})
	if err != nil {
		// Could not record the rollback intent; revoke now so we don't orphan
		// the token, then surface the failure.
		b.revokeBestEffort(ctx, req.Storage, token.ID)
		return nil, fmt.Errorf("failed to write WAL for minted token: %w", err)
	}

	// The first map is returned to the caller; the second (internal) carries
	// the data Revoke/Renew need and is never exposed. token_id is stored as a
	// string so it survives the lease's JSON round-trip exactly.
	resp := b.Secret(aapTokenType).Response(
		map[string]interface{}{
			"token":    token.Token,
			"token_id": token.ID,
			"scope":    token.Scope,
			"expires":  token.Expires,
		},
		map[string]interface{}{
			"token_id": tokenIDStr,
			"role":     roleName,
		},
	)

	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	// The lease now owns revocation; drop the WAL safety net.
	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		b.revokeBestEffort(ctx, req.Storage, token.ID)
		return nil, fmt.Errorf("failed to commit WAL for minted token: %w", err)
	}

	return resp, nil
}

// revokeBestEffort attempts to revoke a token, ignoring errors. Used on failure
// paths where the caller will not receive a lease, to avoid orphaning a token.
func (b *aapBackend) revokeBestEffort(ctx context.Context, s logical.Storage, id int64) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return
	}
	_ = client.RevokeToken(ctx, id)
}

const (
	pathCredentialsHelpSynopsis    = "Mint a dynamic AAP OAuth2 token for a role."
	pathCredentialsHelpDescription = `
This path mints a new AAP OAuth2 token using the scope and description of the
named role, and returns it under a Vault lease. When the lease expires or is
revoked, the engine deletes the token from AAP.
`
)
