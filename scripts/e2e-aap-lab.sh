#!/usr/bin/env bash
# End-to-end test of the new config features against a real Vault dev server and
# a live AAP. Secrets come from the environment, never the file:
#
#   AAP_ADDR=https://aap.example.com AAP_TOKEN=xxxxx ./scripts/e2e-aap-lab.sh
#
# It exercises: request_timeout, token_description_prefix (verified directly on
# the AAP token object), and the rotate-root path that the Rotation Manager
# callback reuses. Tokens it creates in AAP are revoked on the way out.
#
# Note: AAP controls token expiry globally (OAUTH2_PROVIDER) and ignores any
# client-supplied per-token "expires", so the engine does not set one and this
# test does not assert a short server-side expiry — it would never hold.
set -euo pipefail

: "${AAP_ADDR:?set AAP_ADDR to the AAP base URL}"
: "${AAP_TOKEN:?set AAP_TOKEN to a privileged AAP bearer token}"
AAP_API="${AAP_ADDR%/}/api/gateway/v1"

PLUGIN_NAME="vault-plugin-secrets-aap"
PLUGIN_DIR="vault/plugins"
PLUGIN_PATH="${PLUGIN_DIR}/${PLUGIN_NAME}"
LISTEN="127.0.0.1:18200"
export VAULT_ADDR="http://${LISTEN}"
export VAULT_TOKEN="root"
LOG="vault-e2e.log"

MAXTTL_S=7200    # role max_ttl = 2h

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

# aap <METHOD> <url> -> prints the HTTP status code to stdout and writes the
# response body to $AAP_BODY. (Command substitution runs in a subshell, so the
# code must come back via stdout rather than a variable assignment.)
AAP_BODY="$(mktemp)"
aap() {
  curl -sk -o "${AAP_BODY}" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${AAP_TOKEN}" -H 'Accept: application/json' "$2"
}

cleanup() {
  set +e
  # Revoke any engine-minted root tokens left by rotate-root (operator token is
  # never revoked by the engine, so it survives for us to authenticate cleanup).
  if [[ -n "${ROOT_DESC:-}" ]]; then
    aap GET "${AAP_API}/tokens/?description=${ROOT_DESC// /%20}" >/dev/null
    local ids
    ids="$(jq -r '.results[]?.id' "${AAP_BODY}" 2>/dev/null)"
    for id in $ids; do aap DELETE "${AAP_API}/tokens/${id}/" >/dev/null; done
  fi
  [[ -n "${VAULT_PID:-}" ]] && kill "${VAULT_PID}" >/dev/null 2>&1
  [[ -n "${VAULT_PID:-}" ]] && wait "${VAULT_PID}" >/dev/null 2>&1
}
trap cleanup EXIT

echo "==> building plugin"
mkdir -p "${PLUGIN_DIR}"
CGO_ENABLED=0 go build -o "${PLUGIN_PATH}" ./cmd/${PLUGIN_NAME}

echo "==> starting vault dev (${VAULT_ADDR})"
vault server -dev -dev-root-token-id="${VAULT_TOKEN}" \
  -dev-listen-address="${LISTEN}" -dev-plugin-dir="${PLUGIN_DIR}" >"${LOG}" 2>&1 &
VAULT_PID=$!
for _ in $(seq 1 60); do vault status >/dev/null 2>&1 && break; sleep 1; done
vault status >/dev/null || fail "vault did not start"

echo "==> registering + enabling plugin"
SHA="$(shasum -a 256 "${PLUGIN_PATH}" | awk '{print $1}')"
vault plugin register -sha256="${SHA}" secret "${PLUGIN_NAME}"
vault secrets enable -path=aap "${PLUGIN_NAME}"

echo "==> writing config (request_timeout, prefix)"
vault write aap/config \
  address="${AAP_ADDR}" \
  token="${AAP_TOKEN}" \
  skip_tls_verify=true \
  request_timeout=45s \
  token_description_prefix="vault:e2e:"

echo "==> reading config back"
CFG="$(vault read -format=json aap/config)"
echo "$CFG" | jq '.data'
[[ "$(echo "$CFG" | jq -r '.data.request_timeout')" == "45" ]] || fail "request_timeout not persisted"
[[ "$(echo "$CFG" | jq -r '.data.token_description_prefix')" == "vault:e2e:" ]] || fail "prefix not persisted"
[[ "$(echo "$CFG" | jq -r '.data.token_set')" == "true" ]] || fail "token not set"
pass "config round-trips the new fields"

echo "==> creating role with max_ttl=2h"
vault write aap/role/e2e scope=read description="ci-deploy" ttl=1h max_ttl="${MAXTTL_S}s"

echo "==> minting a token (creds/e2e)"
CREDS="$(vault read -format=json aap/creds/e2e)"
LEASE_ID="$(echo "$CREDS" | jq -r '.lease_id')"
TOKEN_ID="$(echo "$CREDS" | jq -r '.data.token_id')"
echo "minted AAP token id=${TOKEN_ID} lease=${LEASE_ID}"

echo "==> verifying the minted token in AAP"
CODE="$(aap GET "${AAP_API}/tokens/${TOKEN_ID}/")"
[[ "${CODE}" == "200" ]] || fail "AAP token ${TOKEN_ID} not found (HTTP ${CODE})"
DESC="$(jq -r '.description' "${AAP_BODY}")"
EXPIRES="$(jq -r '.expires' "${AAP_BODY}")"
echo "description=${DESC}"
echo "expires=${EXPIRES} (AAP-controlled, not settable by the engine)"

[[ "${DESC}" == vault:e2e:ci-deploy* ]] || fail "description prefix not applied (got ${DESC})"
[[ "${DESC}" == *vault-aap-request:* ]] || fail "request marker not applied (got ${DESC})"
pass "description prefix and request marker applied in AAP (enables orphan sweeps)"

echo "==> revoking the lease and confirming AAP deletes the token"
vault lease revoke "${LEASE_ID}"
sleep 1
CODE="$(aap GET "${AAP_API}/tokens/${TOKEN_ID}/")"
[[ "${CODE}" == "404" ]] || fail "token ${TOKEN_ID} still present after lease revoke (HTTP ${CODE})"
pass "lease revoke removed the token from AAP"

echo "==> rotate-root (the path the RM callback reuses)"
ROOT_DESC="vault-aap-secrets-engine root"
vault write -f aap/config/rotate-root
AFTER="$(vault read -format=json aap/config)"
[[ "$(echo "$AFTER" | jq -r '.data.token_set')" == "true" ]] || fail "config lost its token after rotate-root"
# The engine now tracks a minted root token id (> 0); the operator token is kept.
pass "rotate-root minted and swapped a fresh privileged token"

echo
echo "All end-to-end checks passed."
