# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Per-user token issuance** — role `bootstrap_token` mints tokens *as* a specific AAP
  user/service account (the engine authenticates with that user's own token); role
  `username` acts as a post-mint **ownership guard** (revoke + error on mismatch). (#4, #5)
- **Application-scoped tokens** — role `application` binds minted tokens to a named AAP
  OAuth2 application, with a post-mint **binding guard**. (#11)
- **`config/rotate-root`** — rotate the engine's own privileged token: mint → verify → swap
  → revoke the previous engine-minted token. Rotation is serialized and cleanup failures are
  surfaced so operators know when a newly minted privileged token may still be live. (#9)
- **Pluggable authentication** — `authenticator` interface with **bearer** and **basic**
  (username/password) schemes; `GET config` reports `auth_type`. (#8)
- **Config-time connectivity verification** — writing `config` probes AAP and rejects a bad
  address/path/TLS/credential before persisting. (#4)
- **Release automation** — GoReleaser workflow building multi-arch archives + `SHA256SUMS`
  on a `v*` tag; `make snapshot` for local dry-runs. (#7)
- Terraform example (`examples/terraform/`), troubleshooting docs, and an installation /
  plugin-registration guide (`docs/INSTALL.md`). (#6, #10)
- Plugin entrypoint test coverage via an extracted `serveOpts`. (#7)

### Changed
- Role `scope` now defaults to least-privilege **`read`**; set `scope=write` explicitly when
  callers need mutation privileges.
- `config` auth updates now replace the active auth scheme: bearer-token writes clear basic
  credentials, and username/password writes clear bearer credentials and rotate-root token id.
- Role writes now reject `username` without `bootstrap_token`, surfacing per-user
  misconfiguration before the first `creds/` read.
- `role` list output is sorted for a stable API response.
- Revocation snapshot (lease + WAL) now carries whichever credential the config used
  (bearer or basic) so basic-auth configs can revoke after a config change.

### Security
- Documented the **revocation-snapshot blast radius**: the privileged credential is copied
  into each lease's (core-managed, non-seal-wrapped) internal data for revocation
  robustness; rotate it via `config`/`rotate-root`, never out of band.
- Per-role `bootstrap_token` and config `password` are write-only (never returned on read).
- Terraform examples no longer read dynamic credentials into state; dynamic tokens are read
  at consume time with `vault read`.

## [0.1.0] — baseline

### Added
- AAP secrets engine: dynamic mint-on-read of OAuth2 tokens under renewable Vault leases,
  with idempotent auto-revoke (`404` treated as success).
- Configurable `tokens_api_path` for AAP 2.5 gateway (`/api/gateway/v1`) and 2.4 controller
  (`/api/controller/v2`).
- Renewable leases (strategy A): renew extends the lease, keeps the same AAP token.
- WAL rollback for orphaned tokens; `token_id` stored as a string to survive the lease JSON
  round-trip exactly.
- Seal-wrapped `config` and `role/*`; privileged token never disclosed on read; optional
  custom CA trust.

[Unreleased]: https://github.com/hashi-demo-lab/vault-plugin-secrets-aap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hashi-demo-lab/vault-plugin-secrets-aap/releases/tag/v0.1.0
