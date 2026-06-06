# AAP Secrets Engine — Architecture

Dynamically mints and revokes **Ansible Automation Platform (AAP) OAuth2 tokens**
as HashiCorp Vault dynamic secrets.

## Service API Summary

- **Base URL:** the AAP platform address, e.g. `https://aap.example.com`
- **Token API path** (`tokens_api_path`, configurable):
  - AAP 2.5+ (platform gateway): `/api/gateway/v1` — **default**
  - AAP 2.4 (controller direct): `/api/controller/v2`
- **Authentication:** pluggable (`client.go` `authenticator` interface):
  - **bearer** — `Authorization: Bearer <token>` (default, recommended)
  - **basic** — `Authorization: Basic <user:pass>`
- **Credential Type:** AAP OAuth2 tokens (scope `read` or `write`)
- **Lifecycle:** create (`POST .../tokens/`) and delete (`DELETE .../tokens/{id}/`).
  AAP has **no update/extend-expiry** call. Tokens default to a ~1-year expiry.
- **Auxiliary lookups:** `GET .../users/?username=` and `GET .../applications/?name=`
  resolve names to ids for per-user and application-scoped issuance.

There is **no AAP Go SDK** — Ansible's own `terraform-provider-aap` also talks to the
REST API directly with `net/http`. This engine does the same (see `client.go`).

### Verified API behavior (live probe, AAP 2.5 gateway / 4.8.0)

| Operation | Request | Result |
|-----------|---------|--------|
| Mint | `POST /api/gateway/v1/tokens/` `{"scope","description"[,"application"]}` | `201` → `{id, token, scope, expires, user, application, ...}` |
| Revoke | `DELETE /api/gateway/v1/tokens/{id}/` | `204` |
| Read after revoke | `GET .../tokens/{id}/` | `404` |
| No / bad auth | any | `401` |
| Resolve user | `GET /api/gateway/v1/users/?username=<n>` | `200` → `{count, results:[{id, username}]}` |
| Resolve application | `GET /api/gateway/v1/applications/?name=<n>` | `200` → `{count, results:[{id, name}]}` |

**Token ownership is assigned by AAP from the authenticating identity.** Two consequences
drive the design:

- The `user` field on `POST .../tokens/` is **silently ignored** on the 2.5 gateway
  (`users/{id}/personal_tokens/` is read-only; the controller API exposes no token
  endpoints). So per-user issuance is achieved by *authenticating as the target user*, not
  by requesting an owner — see **Per-user issuance**.
- The controller path `/api/controller/v2/tokens/` returns `404` on AAP 2.5 — token
  management moved to the gateway. This is why `tokens_api_path` is configurable.

## Decision Framework Outcome

- AAP supports **multiple** tokens and **programmatic deletion** → **dynamic secrets**
  (not static). Each `creds/` read mints a new token; Vault revokes it on lease end.
- No existing Vault engine fits (not PKI/transit/identity) → custom engine justified.

## Domain Mapping

| Vault concept | Purpose | Fields |
|---------------|---------|--------|
| **Config** (`config`) | AAP connection | `address`, auth: `token` **or** `username`+`password` (sensitive), `tokens_api_path`, `ca_cert`, `skip_tls_verify`, `request_timeout`, `token_description_prefix`, automated rotation fields; internal `token_id` (rotate-root) |
| **Role** (`role/<name>`) | Issuance policy | `scope` (read\|write, default `read`), `description`, `username` (owner guard, requires `bootstrap_token`), `bootstrap_token` (sensitive), `application`, `ttl`, `max_ttl` |
| **Credentials** (`creds/<name>`) | Mint a leased token | returns `token`, `token_id`, `scope`, `expires` |

## Vault API

```
POST   aap/config              # configure AAP connection (token OR username+password)
GET    aap/config              # read (credential never disclosed; reports auth_type)
DELETE aap/config              # remove configuration
POST   aap/config/rotate-root  # rotate the engine's own privileged token

POST   aap/role/:name          # create/update an issuance role
GET    aap/role/:name          # read role (bootstrap_token never disclosed)
LIST   aap/role                # list roles (sorted)
DELETE aap/role/:name          # delete role

GET    aap/creds/:name         # mint a leased AAP token
```

### Configuration

Provide exactly one auth scheme.

```hcl
# Bearer (recommended)
POST aap/config { "address": "...", "token": "<privileged token>",
                  "tokens_api_path": "/api/gateway/v1" }

# Basic
POST aap/config { "address": "...", "username": "svc-admin", "password": "..." }
```

Writing `config` **verifies connectivity** (an authenticated probe to the tokens endpoint)
before persisting, so a bad address/path/TLS/credential fails the write rather than the
first `creds/` read (`pathConfigWrite` → `client.VerifyToken`). Config updates are
replace-oriented for auth schemes: supplying a bearer token clears stored basic credentials,
and supplying username/password clears the bearer token and any rotate-root `token_id`.

### Roles

```hcl
# Plain: token owned by the engine identity
POST aap/role/ci { "scope": "read", "description": "vault-ci", "ttl": "1h", "max_ttl": "8h" }

# Per-user: token owned by a specific service account
POST aap/role/deploy { "scope": "write", "username": "svc-deploy",
                       "bootstrap_token": "<svc-deploy's own token>" }

# Application-scoped: token bound to an OAuth2 application
POST aap/role/app { "scope": "read", "application": "ci-app" }
```

### Credentials (dynamic)

```json
GET aap/creds/ci
{ "lease_id": "aap/creds/ci/<id>", "lease_duration": 3600, "renewable": true,
  "data": { "token": "...", "token_id": 31, "scope": "read", "expires": "..." } }
```

The AAP-side token description is the configured `token_description_prefix` plus
the role's base `description`, followed by a unique `vault-aap-request:<id>`
marker. That marker gives the engine an exact cleanup target when AAP commits a
create request but the HTTP response is lost before Vault sees the token id.

## Authentication schemes (pluggable)

`client.go` defines an `authenticator` interface (`authenticate(req)` + `scheme()`) with
`bearerAuth` and `basicAuth` implementations. `newClient` selects the scheme from config;
`newClientWithAuth` is the seam used for per-user bootstrap tokens (always bearer). New
schemes plug in here without touching request code.

## Per-user issuance (`bootstrap_token` + `username`)

AAP owns a minted token to whoever authenticates the mint call. To issue a token owned by a
specific user, the role supplies that user's **own** token as `bootstrap_token`; `createToken`
builds a mint client authenticating as it (bearer), so the issued token belongs to that user.

`username` is an **ownership guard**: after minting, the engine reads the new token's owner
(`tokenOwner`) and, if it isn't the resolved `username` id, **revokes the token and errors**.
This catches a misconfigured `bootstrap_token`; role writes that set `username` without a
`bootstrap_token` are rejected before any token can be minted as the engine identity.
`bootstrap_token` is seal-wrapped and never returned on read (`bootstrap_token_set: true`).

## Application-scoped tokens (`application`)

`application` names an AAP OAuth2 application. `createToken` resolves it to an id
(`ResolveApplicationID`), requests the binding on mint (`createTokenForApp`), then **verifies**
the minted token is bound to it (`tokenApplication`), revoking + erroring on mismatch — the
same guard pattern as per-user. Composable with `username`/`bootstrap_token`.

> Both guards share one principle: **mint → read back → revoke-and-error on mismatch.** The
> failure mode (a mis-owned/mis-scoped secret) is made impossible, so the feature is safe
> even against an AAP version that ignores a requested field.

## Root credential rotation (`config/rotate-root`)

Mints a fresh token for the configured identity (authenticating with the current token),
verifies it works, swaps it into `config` (recording its `token_id`), then revokes the
previous **engine-minted** token. Rotation is serialized in-process so overlapping calls do
not overwrite each other's root token bookkeeping. The first rotation can't revoke an
operator-supplied token (its id is unknown) and warns; later rotations revoke the prior
token. Bearer-only (rotating basic auth would mean changing a password — a different
operation, rejected).

## Implementation Notes

### Lease renewal — strategy A (renewable, same token)
A renew extends the **Vault lease** and keeps the **same** AAP token. AAP exposes no
extend-expiry API, but its tokens default to a ~1-year expiry, comfortably outliving any
reasonable `max_ttl`, so the lease is the binding clock. `tokenRenew` reloads the role and
re-applies `ttl`/`max_ttl`; it errors if the role was deleted.

> The original research (`docs/RESEARCH.md`) proposed non-renewable (strategy C). The live
> finding that AAP tokens default to a 1-year expiry removed the drift risk that motivated
> C, so the engine uses renewable leases — the Vault norm.

### Revocation (resilient)
On lease expiry or explicit revoke, `tokenRevoke` reads `token_id` from the lease's
`InternalData` and deletes the token. Revocation is **idempotent** (a `404` is success). The
`token_id` is stored as a **string** so it survives the lease's JSON round-trip exactly (a
numeric id would decode back as `float64` and lose precision above 2^53).

`revokeToken` prefers the lease's **snapshot** credential (see below) but **falls back to the
current config** on failure — so after `rotate-root` revokes the old token, outstanding leases
still revoke (the new credential, same owner, can delete the token).

### Revocation snapshot & blast radius
`createCreds` snapshots the AAP connection — **including the privileged credential** — into
each lease's `InternalData` (and into the WAL) so revocation survives a later config change or
delete. Deliberate tradeoff: the engine's own storage (`config`, `role/*`, WAL) is seal-wrapped
via `PathsSpecial`, but these lease copies live in Vault core's expiration-manager storage,
which a plugin cannot seal-wrap (barrier-encrypted only). Treat the privileged credential as
present wherever active leases are, and rotate it **through `config`/rotate-root**, never out of
band.

### Orphaned-token cleanup (WAL)
Minting is wrapped in a Vault **write-ahead log** entry (`wal.go`): the token id is recorded
before the leased response is returned, and the WAL is deleted on success. If the request
fails after the token is created but before the lease is durably stored, the periodic
`walRollback` (min age 5m) revokes the orphaned token. On failure paths where no lease will be
issued, the engine also best-effort revokes immediately. One sub-second window is irreducible
(crash between `CreateToken` returning and `PutWAL`): AAP has no reserve-then-commit API.

### Error handling
- Unconfigured backend → `errBackendNotConfigured`.
- Non-2xx mint → error including the (truncated) AAP response body.
- TLS: optional custom `ca_cert` trust pool; `skip_tls_verify` for lab/self-signed only.

## Source map

| File | Responsibility |
|------|----------------|
| `backend.go` | Factory, backend struct, path registration, client cache/invalidation |
| `client.go` | HTTP client, authenticators, mint/revoke/verify, user & application resolution |
| `path_config.go` | `config` CRUD, auth-scheme selection, connectivity verification |
| `path_rotate_root.go` | `config/rotate-root` |
| `path_roles.go` | role CRUD/list/schema |
| `path_credentials.go` | `creds/<name>` mint + WAL wrapping |
| `secret_token.go` | dynamic secret (mint + guards), renew, revoke |
| `revocation_config.go` | lease/WAL credential snapshot helpers |
| `wal.go` | WAL record + rollback |
| `errors.go` | sentinel errors |
| `cmd/.../main.go` | plugin entry point (`serveOpts`) |

## Security Considerations

- The `config` credential is **privileged** (mints/revokes tokens). Seal-wrapped at rest
  (`config`, `role/*`); **never returned** by `GET aap/config` (only `auth_type`,
  `token_set`/`password_set`).
- Per-role `bootstrap_token` is likewise seal-wrapped and never returned.
- The privileged credential is **snapshotted into lease/WAL storage** for revocation
  robustness — see *Revocation snapshot & blast radius*. Use `rotate-root` to rotate it.
- Minted token secret values are returned **once** and held only under a Vault lease.
- `skip_tls_verify=true` is insecure; production should configure `ca_cert` instead.
- Least privilege: roles fix `scope` (default `read`; set `write` explicitly when mutation
  privileges are required); ownership/application guards prevent
  issuing a token with the wrong identity or binding.
- No orphaned credentials: WAL rollback revokes any token created in AAP whose lease was
  never durably stored.

## Completion Checklist

- [x] All AAP token API endpoints mapped to Vault operations
- [x] Revocation path confirmed (idempotent on 404) + resilient fallback
- [x] Identity/permission model (scope per role; per-user + application guards)
- [x] Lease renewal behavior specified (strategy A)
- [x] Pluggable authentication (bearer + basic)
- [x] Root credential rotation (`rotate-root`)
- [x] Error conditions documented
- [x] Security considerations noted
