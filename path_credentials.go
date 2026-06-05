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
	token, revocationConfig, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("error creating AAP token: nil token returned")
	}

	tokenIDStr := strconv.FormatInt(token.ID, 10)
	cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), defaultHTTPTimeout)
	defer cancelCleanup()

	walID, err := framework.PutWAL(cleanupCtx, req.Storage, walTypeToken, newWALToken(tokenIDStr, roleName, revocationConfig))
	if err != nil {
		// Could not record the rollback intent; revoke now so we don't orphan
		// the token, then surface the failure.
		revokeBestEffort(cleanupCtx, revocationConfig, token.ID)
		return nil, fmt.Errorf("failed to write WAL for minted token: %w", err)
	}
	if err := ctx.Err(); err != nil {
		if revokeErr := revokeWithConfig(cleanupCtx, revocationConfig, token.ID); revokeErr != nil {
			return nil, fmt.Errorf("request canceled after minting AAP token; WAL retained for rollback after revoke failed: %w", err)
		}
		_ = framework.DeleteWAL(cleanupCtx, req.Storage, walID)
		return nil, err
	}

	// The first map is returned to the caller; the second (internal) carries
	// the data Revoke/Renew need and is never exposed. token_id is stored as a
	// string so it survives the lease's JSON round-trip exactly.
	internalData := map[string]interface{}{
		"token_id": tokenIDStr,
		"role":     roleName,
	}
	addRevocationData(internalData, revocationConfig)

	resp := b.Secret(aapTokenType).Response(
		map[string]interface{}{
			"token":    token.Token,
			"token_id": token.ID,
			"scope":    token.Scope,
			"expires":  token.Expires,
		},
		internalData,
	)

	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	// The lease now owns revocation; drop the WAL safety net.
	if err := framework.DeleteWAL(cleanupCtx, req.Storage, walID); err != nil {
		revokeBestEffort(cleanupCtx, revocationConfig, token.ID)
		return nil, fmt.Errorf("failed to commit WAL for minted token: %w", err)
	}

	return resp, nil
}

func revokeWithConfig(ctx context.Context, config *aapConfig, id int64) error {
	client, err := newClient(config)
	if err != nil {
		return err
	}
	return client.RevokeToken(ctx, id)
}

// revokeBestEffort attempts to revoke a token, ignoring errors. Used on failure
// paths where the caller will not receive a lease, to avoid orphaning a token.
func revokeBestEffort(ctx context.Context, config *aapConfig, id int64) {
	_ = revokeWithConfig(ctx, config, id)
}

const (
	pathCredentialsHelpSynopsis    = "Mint a dynamic AAP OAuth2 token for a role."
	pathCredentialsHelpDescription = `
This path mints a new AAP OAuth2 token using the scope and description of the
named role, and returns it under a Vault lease. When the lease expires or is
revoked, the engine deletes the token from AAP.
`
)
