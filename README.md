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
- **Config-time verification** — writing `config` makes an authenticated probe to AAP, so a
  bad address, base path, TLS trust, or privileged token is rejected up front.
- **Hardening** — seal-wrapped config/roles, token never disclosed on read,
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
| `scope` | `read` | `read` or `write` (defaults to least-privilege `read`) |
| `description` | — | description applied to minted AAP tokens |
| `username` | — | optional AAP user/service account to mint on behalf of (see below) |
| `ttl` | mount default | lease TTL for minted tokens |
| `max_ttl` | mount default | maximum lease TTL |

#### Per-user token issuance (`username`) — limited; see status below

By default every token is minted as the engine's own configured identity, so it carries that
identity's RBAC. The intent of `username` is to mint **on behalf of a specific AAP user/service
account** — the engine resolves the name to its id (`GET {base}/users/?username=`) and requests
that owner on the mint, so the token would inherit **that** user's RBAC and audit attribution.

```bash
vault write aap/role/deploy scope=read username="svc-deploy"
vault read  aap/creds/deploy
```

**Status / important limitation.** On the **AAP 2.5 gateway** (`/api/gateway/v1`) there is no
admin-token API path to mint a token owned by another user: the `user` field on
`POST .../tokens/` is **silently ignored** (the token is owned by the caller), the
`users/{id}/personal_tokens/` sub-resource is read-only, and the controller API exposes no
token endpoints. A token always belongs to whoever authenticates.

To avoid misattribution, the engine **verifies ownership after minting**: when `username` is
set, it confirms the new token is actually owned by that user and, if not, **revokes the token
and returns an error** rather than handing back a token with the wrong identity. As a result,
on AAP 2.5 a role with `username` set will **fail with a clear error** — it never issues a
mis-owned token. Delivering real per-user issuance requires a per-user-credentials design
(the engine authenticating as the target identity); tracked in
[issue #3](https://github.com/hashi-demo-lab/vault-plugin-secrets-aap/issues/3).

Leave `username` empty for the supported mint-as-engine behavior.

## Lease model: renewable (strategy A — the Vault norm)

Tokens are issued under **renewable** Vault leases, the standard model for Vault dynamic
secrets:

- **Read `creds/:name`** → mints a fresh AAP token and returns it under a lease whose TTL
  comes from the role (`ttl`, capped at `max_ttl`).
- **`vault lease renew`** → extends the lease and keeps the **same** AAP token. It does
  *not* re-mint. AAP has no "extend token expiry" API, but AAP tokens default to a ~1-year
  server-side expiry — comfortably longer than any sane `max_ttl` — so the **Vault lease
  is the binding clock**, and renewing the lease is sufficient. `tokenRenew` reloads the
  role and re-applies its TTLs; if the role was deleted, renew fails cleanly.
- **`vault lease revoke`** (or lease/`max_ttl` expiry) → deletes the token in AAP
  (`DELETE .../tokens/{id}/`). Revocation is **idempotent**: a `404` (already gone) counts
  as success, so Vault's retries converge.

> **Why renewable rather than non-renewable?** The original research
> ([`docs/RESEARCH.md`](./docs/RESEARCH.md)) proposed *non-renewable* leases (strategy C),
> on the assumption that an AAP token's own expiry might fall short of the lease. Live
> probing showed AAP tokens default to a ~1-year expiry, eliminating that drift risk — so
> the shipped engine uses **renewable leases (strategy A)**, matching how Vault's
> first-party dynamic secrets engines (database, AWS, Terraform Cloud, …) behave. This is
> the least-surprising model for operators: leases renew and revoke the way they expect,
> and the token ID for revocation is carried in the lease's internal data (and survives the
> JSON round-trip Vault performs when persisting leases).

> **Security note — revocation snapshot blast radius.** So that a token can always be
> revoked even after the operator changes or deletes `config`, the engine snapshots the AAP
> connection (including the **privileged token**) into each lease's internal data. The
> engine's own storage (`config`, `role/*`, WAL) is seal-wrapped, but these lease copies
> live in Vault core's expiration-manager storage, which a plugin cannot seal-wrap (it is
> barrier-encrypted only). Treat the privileged token as present wherever active leases are,
> and **rotate it through this engine's `config`** — never out-of-band in AAP — since
> out-of-band rotation would strand the snapshots on a dead credential.

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
