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

> For production installation (release artifacts, checksum verification, plugin
> registration, upgrades, HA notes), see [`docs/INSTALL.md`](./docs/INSTALL.md). The steps
> below are the local dev-Vault flow.

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
| `aap/config` | write / read / delete | AAP connection (credential is write-only) |
| `aap/config/rotate-root` | write | rotate the engine's own privileged AAP token |
| `aap/role/:name` | write / read / delete | issuance policy: scope, description, TTLs |
| `aap/role` | list | list role names |
| `aap/creds/:name` | read | mint a leased AAP token |

### Config fields

Provide **one** auth scheme: a bearer `token`, or basic `username`+`password`.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `address` | yes | — | AAP base URL, no API path |
| `token` | one scheme | — | privileged AAP bearer token used to mint/revoke (write-only) |
| `username` | one scheme | — | privileged AAP username for basic auth |
| `password` | with `username` | — | password for basic auth (write-only) |
| `tokens_api_path` | no | `/api/gateway/v1` | `/api/gateway/v1` (2.5) or `/api/controller/v2` (2.4) |
| `ca_cert` | no | — | PEM CA to trust for the AAP endpoint |
| `skip_tls_verify` | no | `false` | skip TLS verification (insecure; lab only) |

The auth scheme is pluggable behind an internal `authenticator` interface (bearer and
basic today); `vault read aap/config` reports `auth_type`. Bearer is recommended — a
token is revocable and scoped, whereas a password is not. Per-user `bootstrap_token`s
are always bearer regardless of the engine's own scheme. Updating `config` with a bearer
`token` clears any stored basic credentials; updating it with `username`+`password` clears
any stored bearer token and root-rotation token id.

### Role fields

| Field | Default | Description |
|-------|---------|-------------|
| `scope` | `read` | `read` or `write`; set `write` explicitly when callers need mutation privileges |
| `description` | — | description applied to minted AAP tokens |
| `username` | — | optional AAP user the minted token must be owned by; requires `bootstrap_token` |
| `bootstrap_token` | — | that user's own AAP token, so tokens are minted *as* them (write-only) |
| `application` | — | optional AAP OAuth2 application name to bind minted tokens to |
| `ttl` | mount default | lease TTL for minted tokens |
| `max_ttl` | mount default | maximum lease TTL |

#### Application-scoped tokens (`application`)

Set `application` to bind minted tokens to a named AAP OAuth2 application (so they can be
managed at the application level in AAP). The engine resolves the name to its id
(`GET {base}/applications/?name=`), requests the binding on mint, then **verifies** it — if the
minted token isn't bound to that application it is revoked and the request errors (the same
guard pattern used for per-user issuance). Composable with `username`/`bootstrap_token`.
Unit-tested with the guard; verify live against an AAP that has the target OAuth2 application
(`TestCredentials_AppScopedMint`).

#### Per-user token issuance (`bootstrap_token` + `username`)

By default every token is minted as the engine's own configured identity, so it carries that
identity's RBAC. To issue tokens **owned by a specific AAP user/service account**, give the role
that user's own token as `bootstrap_token`: AAP owns a minted token to whichever identity
authenticates the call, so the engine authenticates with the bootstrap token and the issued
token belongs to that user — inheriting their RBAC and audit attribution.

```bash
# svc-deploy-token is svc-deploy's own AAP token (created once in AAP)
vault write aap/role/deploy scope=write username="svc-deploy" bootstrap_token="svc-deploy-token"
vault read  aap/creds/deploy   # token owned by svc-deploy
```

How it works and why it's safe:
- **`bootstrap_token`** is the per-identity credential the engine mints with. It is stored
  seal-wrapped (`role/*` is in `SealWrapStorage`) and **never returned on read** (`role` read
  shows `bootstrap_token_set: true`).
- **`username`** is an ownership **guard**: after minting, the engine reads the new token's
  owner and, if it is not this user, **revokes the token and errors** — so a misconfigured
  `bootstrap_token` can never hand back a token carrying the wrong identity. Role writes that set
  `username` without `bootstrap_token` are rejected up front.
- Revocation is unchanged — token IDs are global, revoked with the engine's config token.

Why a bootstrap token and not the `user` field or a password grant? On the **AAP 2.5 gateway**
there is no admin-token path to mint for another user (the `user` field on `POST .../tokens/` is
silently ignored, `users/{id}/personal_tokens/` is read-only, the controller exposes no token
endpoints). Authenticating as the target — with their own revocable, scoped token — is the
mechanism AAP supports, and avoids storing user passwords. Verified end-to-end against live AAP
2.5 (see `TestAcceptance_PerUserMintLiveAAP`).

Leave both empty for the default mint-as-engine behavior.

### Rotating the root credential

```bash
vault write -f aap/config/rotate-root
```

Mints a fresh AAP token for the configured identity, verifies it, swaps it into `config`, and
revokes the previous **engine-minted** token. Rotations are serialized in-process so overlapping
requests cannot leave an intermediate privileged token untracked. The first rotation can't revoke the original
operator-supplied token (its id is unknown to the engine) and warns you to revoke it manually;
subsequent rotations revoke the prior token automatically. Outstanding leases still revoke
correctly afterward — revocation falls back to the current (rotated) credential if the lease's
snapshotted credential has been revoked. Bearer-token auth only.

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

## Examples

A runnable Terraform example (mount + config + role; dynamic reads happen outside Terraform to
avoid storing live tokens in state) lives in
[`examples/terraform/`](./examples/terraform/).

## Troubleshooting

### Choosing `tokens_api_path` (AAP 2.5 gateway vs 2.4 controller)

The engine talks to AAP's REST API at `<address><tokens_api_path>/tokens/`. Pick the path
for your AAP version:

| AAP version | `tokens_api_path` | Notes |
|-------------|-------------------|-------|
| 2.5+ (platform gateway) | `/api/gateway/v1` (default) | Token management lives on the gateway. |
| 2.4 (automation controller) | `/api/controller/v2` | Legacy controller API. |

Symptoms of the wrong path:
- **`AAP connection verification failed ... HTTP 404`** on `vault write aap/config` — the
  base path is wrong for this AAP version. Try the other value from the table.
- **`HTTP 401`** on config write — the `token` is wrong or unprivileged, not a path issue.

Unsure which you have? `GET <address>/api/gateway/v1/ping/` returns 200 on 2.5 gateways.

### `token was minted for user id N, not "<user>"` on `creds/<role>`

The role sets `username` but the minted token came back owned by someone else, so the engine
revoked it. Causes:
- The role has **no `bootstrap_token`** — without it the token is minted as the engine's own
  identity. Set `bootstrap_token` to that user's own AAP token.
- The `bootstrap_token` belongs to a **different** user than `username`. They must match.

See [Per-user token issuance](#per-user-token-issuance-bootstrap_token--username).

### `AAP user "<name>" not found` / `... is ambiguous`

`username` did not resolve to exactly one AAP user via `GET <base>/users/?username=`. Check the
exact username, and that the `config` token can list users.

## Status

Verified end-to-end against AAP 4.8.0: unit + acceptance tests pass, `golangci-lint`
clean, and the built plugin mints/renews/revokes real AAP tokens through a dev Vault
(revoke confirmed to `404` the token in AAP).

## License

MPL-2.0
