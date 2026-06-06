variable "mount_path" {
  description = "Mount path for the AAP secrets engine."
  type        = string
  default     = "aap"
}

# variable "svc_ci_token" {
#   description = "svc-ci's own AAP token, for per-user issuance via the role bootstrap_token."
#   type        = string
#   sensitive   = true
# }
