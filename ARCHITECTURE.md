# AAP Secrets Engine — Architecture

Dynamically mints and revokes **Ansible Automation Platform (AAP) OAuth2 tokens**
as HashiCorp Vault dynamic secrets.

## Service API Summary

- **Base URL:** the AAP platform address, e.g. `https://aap.example.com`
- **Token API path:**
  - AAP 2.5+ (platform gateway): `/api/gateway/v1` — **default**
  - AAP 2.4 (controller direct): `/api/controller/v2`
- **Authentication:** `Authorization: Bearer <token>` (a privileged AAP OAuth2 token)
- **Credential Type:** AAP OAuth2 tokens (scope `read` or `write`)
- **Lifecycle:** create (`POST .../tokens/`) and delete (`DELETE .../tokens/{id}/`).
  AAP has **no update/extend-expiry** call. Tokens default to a ~1-year expiry.

There is **no AAP Go SDK** — Ansible's own `terraform-provider-aap` also talks to the
REST API directly with `net/http`. This engine does the same (see `client.go`).

### Verified API behavior (live probe, AAP 4.8.0)

| Operation | Request | Result |
|-----------|---------|--------|
| Mint | `POST /api/gateway/v1/tokens/` `{"scope","description"}` | `201` → `{id, token, scope, expires, ...}` |
| Revoke | `DELETE /api/gateway/v1/tokens/{id}/` | `204` |
| Read after revoke | `GET .../tokens/{id}/` | `404` |
| No / bad auth | any | `401` |

> The controller path `/api/controller/v2/tokens/` returns `404` on AAP 2.5 — token
> management moved to the gateway. This is why `tokens_api_path` is configurable.

## Decision Framework Outcome

- AAP supports **multiple** tokens and **programmatic deletion** → **dynamic secrets**
  (not static). Each `creds/` read mints a new token; Vault revokes it on lease end.
- No existing Vault engine fits (not PKI/transit/identity) → custom engine justified.

## Domain Mapping

| Vault concept | Purpose | Fields |
|---------------|---------|--------|
| **Config** (`config`) | AAP connection | `address`, `token` (sensitive), `tokens_api_path`, `ca_cert`, `skip_tls_verify` |
| **Role** (`role/<name>`) | Issuance policy | `scope` (read\|write), `description`, `ttl`, `max_ttl` |
| **Credentials** (`creds/<name>`) | Mint a leased token | returns `token`, `token_id`, `scope`, `expires` |

## Vault API

```
POST   aap/config              # configure AAP connection
GET    aap/config              # read (token never disclosed)
DELETE aap/config              # remove configuration

POST   aap/role/:name          # create/update an issuance role
GET    aap/role/:name          # read role
LIST   aap/role                # list roles
DELETE aap/role/:name          # delete role

GET    aap/creds/:name         # mint a leased AAP token
```

### Configuration

```hcl
POST aap/config
{
  "address":         "https://aap.example.com",
  "token":           "<privileged AAP token>",
  "tokens_api_path": "/api/gateway/v1",
  "ca_cert":         "<optional PEM>",
  "skip_tls_verify": false
}
```

### Roles

```hcl
POST aap/role/ci
{
  "scope":       "write",
  "description": "vault-ci",
  "ttl":         "1h",
  "max_ttl":     "8h"
}
```

### Credentials (dynamic)

```json
GET aap/creds/ci
{
  "lease_id": "aap/creds/ci/<id>",
  "lease_duration": 3600,
  "renewable": true,
  "data": { "token": "...", "token_id": 31, "scope": "write", "expires": "..." }
}
```

## Implementation Notes

### Service API Calls
- **Create:** `POST {address}{tokens_api_path}/tokens/` with `{scope, description}`.
- **Delete:** `DELETE {address}{tokens_api_path}/tokens/{id}/`.

### Lease Renewal — strategy A (renewable, same token)
A renew extends the **Vault lease** and keeps the **same** AAP token. AAP exposes no
extend-expiry API, but its tokens default to a ~1-year expiry, comfortably outliving any
reasonable `max_ttl`, so the lease is the binding clock. `tokenRenew` reloads the role and
re-applies `ttl`/`max_ttl`; it returns an error if the role was deleted.

> The original research (`docs/RESEARCH.md`) proposed non-renewable (strategy C). The live
> finding that AAP tokens default to a 1-year expiry removed the drift risk that motivated
> C, so the enterprise build uses renewable leases — the Vault norm.

### Revocation
On lease expiry or explicit revoke, `tokenRevoke` reads `token_id` from the lease's
`InternalData` and calls AAP's delete endpoint. Revocation is **idempotent**: a `404`
(token already gone) is treated as success so Vault retries converge.

### Error Handling
- Unconfigured backend → `errBackendNotConfigured`.
- Non-2xx mint → error including the (truncated) AAP response body.
- TLS: optional custom `ca_cert` trust pool; `skip_tls_verify` for lab/self-signed only.

## Security Considerations

- The `config` token is a **privileged** AAP credential (mints/revokes tokens). It is
  seal-wrapped at rest (`PathsSpecial.SealWrapStorage` covers `config` and `role/*`) and
  is **never returned** by `GET aap/config` (only `token_set: true`).
- Minted token secret values are returned **once** and held only under a Vault lease.
- `skip_tls_verify=true` is insecure; production should configure `ca_cert` instead.
- Least privilege: roles fix `scope`, so a `read` role cannot mint `write` tokens.

## Completion Checklist

- [x] All AAP token API endpoints mapped to Vault operations
- [x] Revocation path confirmed (idempotent on 404)
- [x] Identity/permission model defined (scope per role)
- [x] Lease renewal behavior specified (strategy A)
- [x] Error conditions documented
- [x] Security considerations noted
