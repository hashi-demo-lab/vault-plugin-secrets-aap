# Terraform example: AAP secrets engine

Configures the AAP secrets engine end to end — mount, connection config, an
issuance role — and reads a dynamic token.

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

terraform output -raw ci_token     # the minted AAP token (sensitive)
```

## Notes

- `vault_generic_endpoint.config` uses `disable_read = true` because the AAP
  token is write-only — reading it back would produce a permanent diff.
- For **per-user issuance**, uncomment `username` + `bootstrap_token` on the role
  (and the `svc_ci_token` variable). `bootstrap_token` is that user's own AAP
  token; the minted token is then owned by that user. See the repo README.
- `data.vault_generic_secret.ci_token` mints a **fresh leased token** on every
  refresh/apply. For real workflows, read `aap/creds/<role>` at consume time
  rather than storing the token in Terraform state.
- **AAP 2.4 controller** instead of 2.5 gateway? Set
  `-var 'tokens_api_path=/api/controller/v2'`.
