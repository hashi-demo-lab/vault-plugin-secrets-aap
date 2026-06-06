###############################################################################
# Example: configure the AAP secrets engine with Terraform.
#
# Manages the mount, connection config, and an issuance role. Requires the plugin
# to be registered in Vault's plugin catalog (see the repo README "Quick start");
# this config enables and configures it.
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

# Connection config. Writing this verifies connectivity to AAP, so a bad
# address/token/TLS fails the apply rather than the first creds read.
resource "vault_generic_endpoint" "config" {
  path                 = "${vault_mount.aap.path}/config"
  disable_read         = true # token is write-only; reading back would diff
  disable_delete       = false
  ignore_absent_fields = true

  data_json = jsonencode({
    address         = var.aap_address
    token           = var.aap_token
    tokens_api_path = var.tokens_api_path
    skip_tls_verify = var.skip_tls_verify
  })
}

# An issuance role. Set username + bootstrap_token to mint on behalf of a
# specific AAP user (see variables); omit both to mint as the engine identity.
resource "vault_generic_endpoint" "role_ci" {
  depends_on           = [vault_generic_endpoint.config]
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
