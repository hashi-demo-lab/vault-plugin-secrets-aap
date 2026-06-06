# Terraform example: AAP secrets engine

Configures the AAP secrets engine mount and an issuance role. It intentionally
does **not** manage the privileged AAP connection config or read dynamic tokens in
Terraform, because Terraform state can retain both resource configuration values
and data source results.

## Prerequisites

- The plugin is built and **registered** in Vault's catalog as
  `vault-plugin-secrets-aap` (see the repo [README](../../README.md) "Quick start").
- `VAULT_ADDR` and `VAULT_TOKEN` exported for the `vault` provider.

## Usage

```bash
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root

terraform init
terraform apply

# Configure the privileged connection out of band so the token is not stored in
# Terraform state. Prefer ca_cert over skip_tls_verify in production.
vault write aap/config \
  address=https://aap.example.com \
  token="$AAP_TOKEN" \
  tokens_api_path=/api/gateway/v1 \
  skip_tls_verify=true             # lab only; prefer a trusted CA in prod

vault read "$(terraform output -raw ci_creds_path)" # mint at consume time
```

## Notes

- The privileged `aap/config` write is deliberately outside Terraform. Even a
  sensitive variable or `disable_read = true` does not prevent Terraform state
  from retaining state-backed resource configuration values.
- For **per-user issuance**, uncomment `username` + `bootstrap_token` on the role
  only if your Terraform state is protected for that user's token. Prefer writing
  per-user roles out of band when the bootstrap token should not enter state.
  `bootstrap_token` is that user's own AAP token; the minted token is then owned
  by that user. See the repo README.
- Dynamic credentials are read outside Terraform with `vault read
  aap/creds/<role>`. Avoid `vault_generic_secret` data sources for `creds/`
  paths: every refresh/apply can mint a fresh leased token and Terraform stores
  the secret value in state.
- **AAP 2.4 controller** instead of 2.5 gateway? Set
  `-var 'tokens_api_path=/api/controller/v2'`.
