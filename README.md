# vault-plugin-secrets-aap

A HashiCorp Vault **secrets engine** that dynamically mints and revokes
**Ansible Automation Platform (AAP)** OAuth2 tokens.

Each read of a credentials path mints a fresh AAP token via the AAP REST API, hands it to
the caller under a Vault **lease**, and revokes it from AAP when the lease expires or is
revoked. Vault becomes the single point of issuance, audit, and revocation for AAP tokens.

> AAP has no official Go SDK, so this engine calls the AAP REST API directly — the same
> approach used by Ansible's own [`terraform-provider-aap`](https://github.com/ansible/terraform-provider-aap).
> See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the design and [`docs/RESEARCH.md`](./docs/RESEARCH.md)
> for the background research.

## Features

- **Dynamic secrets** — one fresh AAP token per `creds/` read, leased and auto-revoked.
- **AAP 2.5 gateway and 2.4 controller** — configurable `tokens_api_path`.
- **Renewable leases** — extend without re-minting (AAP tokens default to ~1-year expiry).
- **Idempotent revocation** — a token already gone (`404`) is treated as revoked.
- **Enterprise hardening** — seal-wrapped config/roles, token never disclosed on read,
  optional custom CA trust, scope-locked roles.

## Quick start

```bash
# 1. Build
make build                       # -> vault/plugins/vault-plugin-secrets-aap

# 2. Run a dev Vault with the plugin mounted (separate shell)
make dev                         # vault server -dev -dev-plugin-dir=vault/plugins

# 3. Register + enable
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
make enable                      # registers by sha256 and mounts at aap/

# 4. Configure the connection to AAP
vault write aap/config \
  address="https://aap.example.com" \
  token="<privileged AAP token>" \
  tokens_api_path="/api/gateway/v1" \
  skip_tls_verify=true            # lab only; prefer ca_cert in prod

# 5. Define an issuance role
vault write aap/role/ci scope=write description="vault-ci" ttl=1h max_ttl=8h

# 6. Mint a dynamic token
vault read aap/creds/ci
# token / token_id / scope / expires, under a renewable lease

# 7. Revoke early (also deletes the token in AAP)
vault lease revoke <lease_id>
```

## Paths

| Path | Ops | Purpose |
|------|-----|---------|
| `aap/config` | write / read / delete | AAP connection (token is write-only) |
| `aap/role/:name` | write / read / delete | issuance policy: scope, description, TTLs |
| `aap/role` | list | list role names |
| `aap/creds/:name` | read | mint a leased AAP token |

### Config fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `address` | yes | — | AAP base URL, no API path |
| `token` | yes | — | privileged AAP token used to mint/revoke (write-only) |
| `tokens_api_path` | no | `/api/gateway/v1` | `/api/gateway/v1` (2.5) or `/api/controller/v2` (2.4) |
| `ca_cert` | no | — | PEM CA to trust for the AAP endpoint |
| `skip_tls_verify` | no | `false` | skip TLS verification (insecure; lab only) |

### Role fields

| Field | Default | Description |
|-------|---------|-------------|
| `scope` | `write` | `read` or `write` |
| `description` | — | description applied to minted AAP tokens |
| `ttl` | mount default | lease TTL for minted tokens |
| `max_ttl` | mount default | maximum lease TTL |

## Development

```bash
make test       # unit tests (race + cover), in-process mock AAP — no network
make testacc    # acceptance tests against a live AAP (needs .env, see below)
make lint       # golangci-lint v2
make fmt vet    # format + vet
```

### Acceptance tests against a live AAP

Copy `.env.example` to `.env` (git-ignored) and fill in your lab values, then:

```bash
set -a && . ./.env && set +a
make testacc
```

The acceptance test mints a real token and revokes it; it is skipped unless `VAULT_ACC`
is set. **Never commit `.env` or real tokens** — `.gitignore` blocks them.

## Status

Verified end-to-end against AAP 4.8.0: unit + acceptance tests pass, `golangci-lint`
clean, and the built plugin mints/renews/revokes real AAP tokens through a dev Vault
(revoke confirmed to `404` the token in AAP).

## License

MPL-2.0
