package aap

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// rotateRootDescription is applied to the freshly minted privileged token so it
// is identifiable in AAP as the engine's own root credential.
const rotateRootDescription = "vault-aap-secrets-engine root"

// pathRotateRoot defines config/rotate-root, which rotates the engine's own
// privileged AAP token.
func (b *aapBackend) pathRotateRoot() *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixAAP,
			OperationVerb:   "rotate",
			OperationSuffix: "root-credential",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRootWrite,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},
		HelpSynopsis:    "Rotate the engine's privileged AAP token.",
		HelpDescription: "Mints a fresh AAP token for the configured identity, swaps it into config, and revokes the previous engine-minted token.",
	}
}

// rotateRootCredential is the Rotation Manager callback (wired as
// b.Backend.RotateCredential). When the RM fires the scheduled job registered by
// the config endpoint, the framework routes a RotationOperation here. It shares
// the exact rotation logic with the manual config/rotate-root endpoint; only the
// response (warnings) is discarded, since the RM only inspects the error.
func (b *aapBackend) rotateRootCredential(ctx context.Context, req *logical.Request) error {
	_, err := b.rotateRoot(ctx, req.Storage)
	return err
}

// pathRotateRootWrite is the manual config/rotate-root handler; it delegates to
// the shared rotateRoot routine.
func (b *aapBackend) pathRotateRootWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.rotateRoot(ctx, req.Storage)
}

// rotateRoot mints a new privileged token for the configured identity, verifies
// it works, swaps it into config, then best-effort revokes the previous
// engine-minted token. Only supported for bearer-token auth — basic-auth
// rotation would mean changing a password, a different operation.
func (b *aapBackend) rotateRoot(ctx context.Context, storage logical.Storage) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	config, err := getConfig(ctx, storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}
	if config.Token == "" {
		return logical.ErrorResponse("rotate-root is only supported for token (bearer) auth, not basic auth"), nil
	}

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}

	// Mint a new token for the same identity (the current token's owner).
	newToken, err := client.CreateToken(ctx, "write", rotateRootDescription)
	if err != nil {
		return nil, fmt.Errorf("rotate-root: minting new token failed: %w", err)
	}

	// Verify the new token actually works before committing to it.
	newConfig := cloneConfig(config)
	newConfig.Token = newToken.Token
	newConfig.TokenID = newToken.ID
	newClientForVerify, err := newClient(newConfig)
	if err != nil {
		return nil, cleanupNewRootToken(ctx, client, newToken.ID,
			fmt.Errorf("rotate-root: building client for new token failed: %w", err))
	}
	if err := newClientForVerify.VerifyToken(ctx); err != nil {
		return nil, cleanupNewRootToken(ctx, client, newToken.ID,
			fmt.Errorf("rotate-root: new token failed verification, keeping old token: %w", err))
	}

	// Commit the new token.
	oldTokenID := config.TokenID
	entry, err := logical.StorageEntryJSON(configStoragePath, newConfig)
	if err != nil {
		return nil, cleanupNewRootToken(ctx, client, newToken.ID, err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		return nil, cleanupNewRootToken(ctx, client, newToken.ID, err)
	}
	b.reset()

	// Revoke the previous token. We can only do this when the engine knows its id
	// (i.e. a prior rotate-root minted it). An operator-supplied token's id is
	// unknown; warn so it can be revoked out of band. Outstanding leases that
	// snapshotted the old token still revoke, because revocation falls back to
	// the current config on an auth failure (see revocationClient usage).
	resp := &logical.Response{}
	if oldTokenID > 0 {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultHTTPTimeout)
		defer cancel()
		if err := newClientForVerify.RevokeToken(cleanupCtx, oldTokenID); err != nil {
			walID, walErr := framework.PutWAL(cleanupCtx, storage, walTypeToken, newWALToken(strconv.FormatInt(oldTokenID, 10), "config/rotate-root", newConfig))
			if walErr != nil {
				resp.AddWarning(fmt.Sprintf("rotated root token, but revoking the previous token (id %d) failed and retry state could not be recorded: %s; WAL error: %s", oldTokenID, err, walErr))
			} else {
				resp.AddWarning(fmt.Sprintf("rotated root token, but revoking the previous token (id %d) failed: %s; retry recorded in WAL entry %s", oldTokenID, err, walID))
			}
		}
	} else {
		resp.AddWarning("rotated root token; the previous token's id is unknown (it was operator-supplied), so it was not revoked — revoke it in AAP manually")
	}
	return resp, nil
}

func cleanupNewRootToken(ctx context.Context, client *aapClient, id int64, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultHTTPTimeout)
	defer cancel()

	if err := client.RevokeToken(cleanupCtx, id); err != nil {
		return fmt.Errorf("%w; additionally failed to revoke newly minted root token %d: %v", cause, id, err)
	}
	return cause
}
