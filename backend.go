// Package aap implements a HashiCorp Vault secrets engine that dynamically
// mints and revokes Ansible Automation Platform (AAP) OAuth2 tokens.
//
// The engine treats AAP tokens as dynamic secrets: each read of a credentials
// path mints a fresh token via the AAP API, hands it to the caller under a
// Vault lease, and revokes it when the lease expires or is explicitly revoked.
package aap

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// operationPrefixAAP prefixes OpenAPI operation IDs generated for this engine.
const operationPrefixAAP = "aap"

// Factory returns a configured AAP backend as a logical.Backend. Vault calls
// this when the plugin is mounted.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// aapBackend is the secrets engine. It embeds *framework.Backend and caches a
// single AAP API client guarded by a read/write lock so that configuration
// changes can safely invalidate it.
type aapBackend struct {
	*framework.Backend
	lock       sync.RWMutex
	configLock sync.Mutex
	client     *aapClient
}

// backend builds the framework.Backend wiring together every path and the
// dynamic secret type.
func backend() *aapBackend {
	var b aapBackend

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			// The config and roles hold the privileged AAP token and policy;
			// seal-wrap them for defense in depth at rest.
			SealWrapStorage: []string{
				"config",
				"role/*",
				framework.WALPrefix,
			},
			// WAL entries are local cleanup state; don't replicate them.
			LocalStorage: []string{
				framework.WALPrefix,
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				b.pathRotateRoot(),
				pathCredentials(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.aapToken(),
		},
		BackendType:       logical.TypeLogical,
		Invalidate:        b.invalidate,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: walRollbackMinAge,
	}

	return &b
}

// reset drops the cached client so the next operation rebuilds it from the
// current stored configuration.
func (b *aapBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate is called by Vault when a storage key changes (including via
// replication). A config change must force a client rebuild.
func (b *aapBackend) invalidate(_ context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient returns a cached AAP client, building one from stored config if
// necessary. It uses double-checked locking so the common path takes only a
// read lock.
func (b *aapBackend) getClient(ctx context.Context, s logical.Storage) (*aapClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	// Upgrade to a write lock to build the client.
	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	// Another goroutine may have built it while we waited for the write lock.
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}

	b.client = client
	return b.client, nil
}

const backendHelp = `
The AAP secrets engine dynamically generates Ansible Automation Platform
(AAP) OAuth2 tokens.

After mounting this engine, configure the connection to AAP with the
"config" path, define one or more issuance policies with "role/<name>",
then read "creds/<name>" to mint a leased AAP token.
`
