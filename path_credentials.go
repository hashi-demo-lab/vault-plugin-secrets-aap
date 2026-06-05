package aap

import (
	"context"
	"errors"
	"fmt"

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
func (b *aapBackend) createCreds(ctx context.Context, req *logical.Request, roleName string, role *aapRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("error creating AAP token: nil token returned")
	}

	// The first map is returned to the caller; the second (internal) carries
	// the data Revoke/Renew need and is never exposed.
	resp := b.Secret(aapTokenType).Response(
		map[string]interface{}{
			"token":    token.Token,
			"token_id": token.ID,
			"scope":    token.Scope,
			"expires":  token.Expires,
		},
		map[string]interface{}{
			"token_id": token.ID,
			"role":     roleName,
		},
	)

	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

const (
	pathCredentialsHelpSynopsis    = "Mint a dynamic AAP OAuth2 token for a role."
	pathCredentialsHelpDescription = `
This path mints a new AAP OAuth2 token using the scope and description of the
named role, and returns it under a Vault lease. When the lease expires or is
revoked, the engine deletes the token from AAP.
`
)
