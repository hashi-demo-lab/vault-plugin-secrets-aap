package aap

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// walTypeToken identifies WAL entries that record a freshly minted AAP token.
const walTypeToken = "token"

// walRollbackMinAge bounds how long an orphaned token may linger before the
// periodic WAL rollback revokes it.
const walRollbackMinAge = 5 * time.Minute

// walToken is the rollback record written around a freshly minted token. If a
// credentials request fails after minting but before the lease is durably
// stored, walRollback revokes the token so it is not orphaned in AAP.
//
// TokenID is a string so it survives the WAL's JSON round-trip without the
// float64 precision loss an integer would suffer.
type walToken struct {
	TokenID string `json:"token_id"`
	Role    string `json:"role"`
}

// walRollback revokes the AAP token recorded by a WAL entry whose originating
// request never completed. Revocation is idempotent, so re-running a rollback
// (or rolling back a token already cleaned up via its lease) is safe.
func (b *aapBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	if kind != walTypeToken {
		return fmt.Errorf("unknown WAL type %q", kind)
	}

	m, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected WAL data type %T", data)
	}
	idStr, ok := m["token_id"].(string)
	if !ok {
		return fmt.Errorf("WAL entry missing token_id")
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid token_id %q in WAL: %w", idStr, err)
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}
	return client.RevokeToken(ctx, id)
}
