###############################################################################
# Example: manage the AAP secrets engine mount and roles with Terraform.
#
# Requires the plugin to be registered in Vault's plugin catalog (see the repo
# README "Quick start"). The privileged AAP connection config is intentionally
# not managed here because Terraform state stores resource configuration values,
# including sensitive write-only token fields.
###############################################################################

terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.0"
    }
  }
}

# Provider auth comes from VAULT_ADDR / VAULT_TOKEN in the environment.
provider "vault" {}

# Enable the engine at <mount>/ (plugin must already be registered by name).
resource "vault_mount" "aap" {
  path        = var.mount_path
  type        = "vault-plugin-secrets-aap"
  description = "Ansible Automation Platform dynamic OAuth2 tokens"
}

# Configure the privileged AAP connection outside Terraform, for example:
#
#   vault write "${var.mount_path}/config" \
#     address="https://aap.example.com" \
#     token="$AAP_TOKEN" \
#     tokens_api_path="/api/gateway/v1"
#
# Keeping this out of Terraform avoids persisting the privileged AAP token in
# state. Protect Vault audit logs and shell history when running the command.

# An issuance role. Set username + bootstrap_token to mint on behalf of a
# specific AAP user (see variables); omit both to mint as the engine identity.
resource "vault_generic_endpoint" "role_ci" {
  depends_on           = [vault_mount.aap]
  path                 = "${vault_mount.aap.path}/role/ci"
  disable_read         = true # bootstrap_token is write-only
  ignore_absent_fields = true

  data_json = jsonencode({
    scope       = "read"
    description = "vault-managed CI token"
    ttl         = "1h"
    max_ttl     = "8h"
    # username        = "svc-ci"
    # bootstrap_token = var.svc_ci_token
  })
}

# Read this path at consume time with `vault read`; do not read dynamic
# credentials through Terraform data sources because Terraform persists data
# source results in state.
output "ci_creds_path" {
  value = "${vault_mount.aap.path}/creds/ci"
}
