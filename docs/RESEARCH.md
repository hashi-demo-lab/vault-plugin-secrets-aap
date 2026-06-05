# Vault Secrets Engine for Minting AAP Tokens — Research & Findings

> **Note:** This is the original background research, written *before* the live API probe.
> [`../ARCHITECTURE.md`](../ARCHITECTURE.md) is the authoritative record of the shipped
> design. Where this document differs, the shipped design wins. The corrections the probe
> produced (so you can read the narrative below in context):
>
> | This doc assumed (pre-probe) | Shipped reality |
> |---|---|
> | Token API at the controller path `/api/v2/tokens/` | AAP 2.5 **gateway** `/api/gateway/v1/tokens/` (the controller path 404s) |
> | Engine authenticates with **username/password** | A privileged **bearer token** (`token` / `Authorization: Bearer`) |
> | TLS field `verify_ssl` | `skip_tls_verify` (+ optional `ca_cert`) |
> | Lease model: non-renewable (strategy C, §6) | **Renewable** (strategy A), since AAP tokens default to a ~1-year expiry |
>
> The `/api/v2/...`, `username`/`password`, and `verify_ssl` references in the prose and
> diagrams below reflect those pre-probe assumptions; mentally substitute the right-hand
> column.

**Date:** 2026-06-05
**Goal:** Make HashiCorp Vault mint Ansible Automation Platform (AAP) OAuth2 tokens as
*dynamic secrets* — issued on demand, leased, and automatically revoked when the lease
expires.

---

## TL;DR

- There is **no off-the-shelf Vault secrets engine for AAP**. The official, documented
  HashiCorp ↔ AAP integration runs the **opposite direction**: AAP's *credential plugins*
  pull secrets *out of* Vault. That does not mint AAP tokens.
- To make Vault *issue* AAP tokens, you build a **custom secrets engine plugin** (Go,
  using the Vault SDK `framework` package) that wraps AAP's `/api/v2/tokens/` API for
  **create** and `/api/v2/tokens/{id}/` for **revoke**.
- The model to copy is HashiCorp's official **`vault-plugin-secrets-hashicups`** tutorial —
  it mints/revokes a token against an external HTTP API and is a near 1:1 shape match for
  what AAP needs.
- A custom plugin is the "correct" answer but is real Go engineering + an operational
  burden (build, sign, register, upgrade). **Weigh it against two lighter alternatives**
  (§7) before committing.

---

## 1. Why there's no built-in engine

Searching HashiCorp's and Red Hat's docs surfaces only the **reverse** integration:

| What exists (documented)                              | Direction                  | Mints AAP tokens? |
|-------------------------------------------------------|----------------------------|-------------------|
| AAP **HashiCorp Vault Secret Lookup** credential plugin | AAP → reads from Vault     | ❌                |
| AAP **Vault Signed SSH** credential plugin            | AAP → reads from Vault SSH | ❌                |
| Vault **SSH secrets engine** + AAP                    | Vault issues SSH certs     | ❌ (SSH, not AAP) |
| **This project** — custom AAP token secrets engine    | **Vault → mints in AAP**   | ✅                |

So the gap is real, and the only supported way to fill it is the Vault **plugin SDK**.

`★ Insight ─────────────────────────────────────`
- Vault's *secrets engines* are themselves plugins behind a stable interface
  (`logical.Backend`). The built-in ones (AWS, database, PKI…) and a custom one you write
  are loaded the same way — the only difference is yours lives in the plugin catalog
  instead of being compiled into the Vault binary.
- "Dynamic secret" is a precise contract: Vault must know how to **create** a credential
  *and* how to **revoke** it later. If you can't programmatically revoke an AAP token,
  you don't have a dynamic secret — you have a glorified KV store. AAP's
  `DELETE /api/v2/tokens/{id}/` is what makes the dynamic pattern viable here.
`─────────────────────────────────────────────────`

---

## 2. Architecture

```
        ┌────────────────────────────────────────────────────────────┐
        │  Client / CI job / ansible-playbook                         │
        │     vault read aap/creds/<role>                             │
        └───────────────────────────┬────────────────────────────────┘
                                     │ (1) read creds
                                     ▼
        ┌────────────────────────────────────────────────────────────┐
        │  HashiCorp Vault                                            │
        │  ┌──────────────────────────────────────────────────────┐  │
        │  │  aap/ secrets engine (custom plugin)                  │  │
        │  │   • config/        ← AAP base URL, admin creds, CA    │  │
        │  │   • role/<name>    ← scope, ttl, max_ttl              │  │
        │  │   • creds/<name>   ← MINT on read                     │  │
        │  │   • Secret: "aap_token" {Renew, Revoke}               │  │
        │  └───────────────┬──────────────────────────────────────┘  │
        │       (2) POST /api/v2/tokens/      (4) DELETE on lease exp │
        └───────────────────┬────────────────────────┬───────────────┘
                            │                          │
                            ▼                          ▼
        ┌────────────────────────────────────────────────────────────┐
        │  Ansible Automation Platform (controller / gateway)         │
        │   POST   /api/v2/tokens/        → returns {id, token}       │
        │   DELETE /api/v2/tokens/{id}/   → revokes                   │
        └────────────────────────────────────────────────────────────┘
```

**Lease lifecycle**: client reads `aap/creds/<role>` → plugin calls AAP, mints a token →
Vault wraps it in a **lease** with the role's TTL → on expiry (or explicit
`vault lease revoke`), Vault invokes the plugin's `Revoke` → plugin calls
`DELETE /api/v2/tokens/{id}/`. The AAP token's own `expires` should be set **≥** the Vault
lease so Vault is the source of truth for revocation.

---

## 3. AAP API surface the plugin wraps

Only two calls matter (see `../ARCHITECTURE.md` for the verified API details):

**Mint** — authenticate with the engine's configured admin user/password:

```http
POST /api/v2/tokens/            (or /api/controller/v2/tokens/ on AAP 2.5 gateway)
Authorization: Basic <admin creds>
Content-Type: application/json

{ "description": "vault-lease-<id>", "scope": "write" }
```
Response (secret shown **once**):
```json
{ "id": 42, "token": "•••", "scope": "write", "expires": "..." }
```

**Revoke**:
```http
DELETE /api/v2/tokens/42/
Authorization: Basic <admin creds>
```

> Store the returned **`id`** in the Vault secret's `InternalData` — that's the handle
> `Revoke` needs later. Never expose `id`-only as the usable credential; the caller needs
> the `token` string.

---

## 4. Plugin shape (mirrors the HashiCups tutorial)

A custom secrets engine is four moving parts. File layout:

```
vault-plugin-secrets-aap/
├── main.go            # plugin.Serve(...) entrypoint
├── backend.go         # framework.Backend: Paths, Secrets, PathsSpecial
├── client.go          # thin AAP HTTP client (mint + revoke)
├── path_config.go     # write/read AAP url, admin creds, CA, verify_ssl
├── path_roles.go      # role definitions: scope, ttl, max_ttl
├── path_credentials.go# creds/<role> → mints token, returns leased secret
└── secret_token.go    # framework.Secret{Type, Fields, Renew, Revoke}
```

### Backend

```go
type aapBackend struct {
    *framework.Backend
    lock   sync.RWMutex
    client *aapClient
}

func backend() *aapBackend {
    b := &aapBackend{}
    b.Backend = &framework.Backend{
        BackendType: logical.TypeLogical,
        PathsSpecial: &logical.Paths{
            SealWrapStorage: []string{"config", "role/*"},
        },
        Paths: framework.PathAppend(
            pathConfig(b),
            pathRoles(b),
            []*framework.Path{pathCredentials(b)},
        ),
        Secrets:    []*framework.Secret{b.aapToken()},
        Invalidate: b.invalidate,
    }
    return b
}
```

### The dynamic secret (the heart of it)

```go
const aapTokenType = "aap_token"

func (b *aapBackend) aapToken() *framework.Secret {
    return &framework.Secret{
        Type: aapTokenType,
        Fields: map[string]*framework.FieldSchema{
            "token": {Type: framework.TypeString, Description: "AAP OAuth2 token"},
        },
        Revoke: b.tokenRevoke, // calls DELETE /api/gateway/v1/tokens/{id}/
        Renew:  b.tokenRenew,  // renewable lease (strategy A); see §6
    }
}
```

### Returning a leased credential on read

```go
// inside pathCredentialsRead, after minting via the AAP client:
resp := b.Secret(aapTokenType).Response(
    map[string]interface{}{ // shown to caller
        "token": minted.Token,
        "token_id": minted.ID,
    },
    map[string]interface{}{ // InternalData — for Revoke, hidden from caller
        "token_id": minted.ID,
    },
)
resp.Secret.TTL    = role.TTL
resp.Secret.MaxTTL = role.MaxTTL
return resp, nil
```

### main.go

```go
func main() {
    if err := plugin.ServeMultiplex(&plugin.ServeOpts{
        BackendFactoryFunc: aap.Factory, // returns the backend above
    }); err != nil {
        log.Fatal(err)
    }
}
```

`★ Insight ─────────────────────────────────────`
- The **two-map** `Response(data, internal)` split is the crux of dynamic secrets: the
  first map is what the caller sees (`token`), the second (`InternalData`) is private
  bookkeeping Vault hands back to your `Revoke`/`Renew` later. Putting the AAP `token_id`
  in `InternalData` is what lets Vault revoke a credential it can no longer "see."
- `SealWrapStorage` on `config` and `role/*` means the AAP admin password is encrypted
  with the seal key (e.g. your KMS/HSM) at rest inside Vault — defense in depth beyond
  Vault's normal barrier encryption, because that config holds a *highly* privileged
  credential.
`─────────────────────────────────────────────────`

---

## 5. Build, register, deploy

```bash
go build -o vault/plugins/vault-plugin-secrets-aap ./cmd/...

# register in the plugin catalog (Vault computes/needs the sha256)
SHA=$(sha256sum vault/plugins/vault-plugin-secrets-aap | cut -d' ' -f1)
vault plugin register -sha256="$SHA" \
  secret vault-plugin-secrets-aap

vault secrets enable -path=aap vault-plugin-secrets-aap

# configure the engine to talk to AAP
vault write aap/config \
  address="https://aap.example.com" \
  token="<privileged AAP token>" \
  tokens_api_path="/api/gateway/v1" \
  skip_tls_verify=false

# define a role (TTL = how long minted tokens live)
vault write aap/role/ci scope="write" ttl=1h max_ttl=8h

# mint on demand
vault read aap/creds/ci
```

Production notes: ship the binary to every Vault node at the same `plugin_directory`,
pin by sha256, and treat plugin upgrades as a `vault plugin reload` operation. In
Kubernetes, bake the plugin into a sidecar/init image or a custom Vault image.

---

## 6. Design decision: renewal semantics — **SHIPPED: (A) renewable**

> This section originally concluded (C) non-renewable. It was **reversed during the build**
> — see the note at the top of this file. The shipped engine uses **(A) renewable**;
> [`../ARCHITECTURE.md`](../ARCHITECTURE.md) is the authoritative record.

AAP OAuth2 tokens **cannot have their `expires` extended in place**; the API has no "renew
token" call. The options were:

- **✅ (A) No-op renew up to `max_ttl`** *(shipped)* — Vault extends the lease and the
  *same* AAP token keeps working. The original objection was that the AAP token's own
  `expires` might fall short of the lease — but live probing showed AAP tokens default to a
  **~1-year expiry**, comfortably longer than any reasonable `max_ttl`, so the Vault lease
  is the binding clock and this is safe. This is also how Vault's first-party dynamic
  engines (database, AWS, Terraform Cloud) behave, so it's the least-surprising model.
- **(B) Re-mint on renew** — `Renew` mints a new AAP token, revokes the old one, swaps it
  in. Clean rotation, but the caller's cached token string changes and API churn doubles.
- **(C) Disallow renew** — `Renew: nil`; callers request a fresh `creds/` read each time.
  Maximally auditable, but given the ~1-year token expiry it adds churn for no real
  security gain over (A) bounded by `max_ttl`. (This was the initial lean before the
  expiry finding.)

Implemented in [`../secret_token.go`](../secret_token.go): `aapToken()` sets
`Renew: b.tokenRenew`, which reloads the role and re-applies its `ttl`/`max_ttl`. Vault
caps the lease at `max_ttl` measured from creation, so renew cannot extend a token
indefinitely. To rotate the token value itself, re-read `aap/creds/<role>`.

---

## 7. Lighter-weight alternatives (consider before building Go)

A custom plugin is ~600 lines of Go plus a build/sign/upgrade pipeline forever. Two
cheaper paths may meet the actual requirement:

1. **Let AAP own expiry; use Vault only to store the minting creds.**
   Set short `OAUTH2_PROVIDER` token TTLs in AAP and have jobs mint their own PAT at
   runtime (the curl from the earlier session), pulling the *admin* credential from a
   Vault KV mount. No dynamic engine, no Go — but no centralized lease/revoke either.

2. **Vault-internal "fake dynamic" via the `database` secrets engine pattern? No** — AAP
   isn't a SQL/recognized DB, so that doesn't fit. The honest options are: build the
   plugin, or accept (1).

Decision rubric: **build the plugin only if you need Vault to be the single revocation
authority and audit point for AAP tokens across many consumers.** If it's one CI system
minting its own short-lived tokens, alternative (1) is dramatically less to own.

---

## 8. Open questions to resolve before coding

- **AAP version / routing**: 2.4 direct (`/api/v2/...`) vs 2.5 gateway
  (`/api/controller/v2/...`)? Affects the client base path. → store as config, don't
  hardcode.
- **Service account scoping**: the engine's admin user mints tokens *as itself* unless you
  use `users/{id}/personal_tokens/`. Do tokens need to belong to the *requesting* user, or
  is a shared service identity acceptable? (RBAC + audit implications.)
- **Scope policy**: fixed per role (`read`/`write`) — confirmed sufficient, or do you need
  application-scoped tokens too?
- **TLS**: AAP behind a private CA? `config` needs a `ca_cert` field (the scaffold has it).
- **HA**: plugin binary distribution to all Vault nodes + reload story.

---

## Sources

- [Implement secrets for the secrets engine — HashiCorp (custom secrets engine, renew/revoke)](https://developer.hashicorp.com/vault/tutorials/custom-secrets-engine/custom-secrets-engine-secrets)
- [Define a backend for the secrets engine — HashiCorp](https://developer.hashicorp.com/vault/tutorials/custom-secrets-engine/custom-secrets-engine-backend)
- [Define a configuration for the secrets engine — HashiCorp](https://developer.hashicorp.com/vault/tutorials/custom-secrets-engine/custom-secrets-engine-config)
- [Custom database secrets engines — HashiCorp](https://developer.hashicorp.com/vault/docs/secrets/databases/custom)
- [Secrets engines overview — HashiCorp](https://developer.hashicorp.com/vault/docs/secrets)
- [Automating secrets management with HashiCorp Vault and Red Hat Ansible Automation Platform — Red Hat](https://www.redhat.com/en/blog/automating-secrets-management-hashicorp-vault-and-red-hat-ansible-automation-platform)
- [Secret Management System — Automation Controller User Guide (credential plugins)](https://docs.ansible.com/automation-controller/4.5/html/userguide/credential_plugins.html)
- [Vault integration — Getting started with HashiCorp and AAP 2.6 — Red Hat](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.6/html/getting_started_with_hashicorp_and_ansible_automation_platform/vault-product)
- [Integrate Vault SSH with Ansible Automation Platform — HashiCorp Validated Patterns](https://developer.hashicorp.com/validated-patterns/vault/integrate-vault-ssh-with-ansible-automation-platform)
