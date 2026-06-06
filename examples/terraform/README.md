# Terraform example: AAP secrets engine

Configures the AAP secrets engine end to end: mount, connection config, and an
issuance role. It intentionally does **not** read a dynamic token in Terraform,
because data source results are persisted in Terraform state.

## Prerequisites

- The plugin is built and **registered** in Vault's catalog as
  `vault-plugin-secrets-aap` (see the repo [README](../../README.md) "Quick start").
- `VAULT_ADDR` and `VAULT_TOKEN` exported for the `vault` provider.

## Usage

```bash
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root

terraform init
terraform apply \
  -var 'aap_address=https://aap.example.com' \
  -var 'aap_token=<privileged AAP token>' \
  -var 'skip_tls_verify=true'      # lab only; prefer a trusted CA in prod

vault read "$(terraform output -raw ci_creds_path)" # mint at consume time
```

## Notes

- `vault_generic_endpoint.config` uses `disable_read = true` because the AAP
  token is write-only — reading it back would produce a permanent diff.
- For **per-user issuance**, uncomment `username` + `bootstrap_token` on the role
  (and the `svc_ci_token` variable). `bootstrap_token` is that user's own AAP
  token; the minted token is then owned by that user. See the repo README.
- Dynamic credentials are read outside Terraform with `vault read
  aap/creds/<role>`. Avoid `vault_generic_secret` data sources for `creds/`
  paths: every refresh/apply can mint a fresh leased token and Terraform stores
  the secret value in state.
- **AAP 2.4 controller** instead of 2.5 gateway? Set
  `-var 'tokens_api_path=/api/controller/v2'`.
