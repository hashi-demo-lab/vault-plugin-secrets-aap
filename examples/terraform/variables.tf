variable "mount_path" {
  description = "Mount path for the AAP secrets engine."
  type        = string
  default     = "aap"
}

variable "aap_address" {
  description = "AAP base URL, e.g. https://aap.example.com (no API path)."
  type        = string
}

variable "aap_token" {
  description = "Privileged AAP token the engine uses to mint and revoke tokens."
  type        = string
  sensitive   = true
}

variable "tokens_api_path" {
  description = "Token API base path. Gateway (AAP 2.5+): /api/gateway/v1. Controller (AAP 2.4): /api/controller/v2."
  type        = string
  default     = "/api/gateway/v1"
}

variable "skip_tls_verify" {
  description = "Skip TLS verification (insecure; lab/self-signed only)."
  type        = bool
  default     = false
}

# variable "svc_ci_token" {
#   description = "svc-ci's own AAP token, for per-user issuance via the role bootstrap_token."
#   type        = string
#   sensitive   = true
# }
