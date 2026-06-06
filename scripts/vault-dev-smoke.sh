#!/usr/bin/env bash
set -euo pipefail

if ! command -v vault >/dev/null 2>&1; then
  echo "vault binary not found; install Vault to run the dev smoke test" >&2
  exit 1
fi

PLUGIN_NAME="${PLUGIN_NAME:-vault-plugin-secrets-aap}"
PLUGIN_DIR="${PLUGIN_DIR:-vault/plugins}"
PLUGIN_PATH="${PLUGIN_DIR}/${PLUGIN_NAME}"
VAULT_DEV_LISTEN_ADDRESS="${VAULT_DEV_LISTEN_ADDRESS:-127.0.0.1:18200}"
VAULT_ADDR="http://${VAULT_DEV_LISTEN_ADDRESS}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
VAULT_LOG="${VAULT_LOG:-vault-dev-smoke.log}"

if [[ ! -x "${PLUGIN_PATH}" ]]; then
  echo "plugin binary not found or not executable: ${PLUGIN_PATH}" >&2
  exit 1
fi

export VAULT_ADDR VAULT_TOKEN

vault server \
  -dev \
  -dev-root-token-id="${VAULT_TOKEN}" \
  -dev-listen-address="${VAULT_DEV_LISTEN_ADDRESS}" \
  -dev-plugin-dir="${PLUGIN_DIR}" \
  >"${VAULT_LOG}" 2>&1 &
VAULT_PID=$!

cleanup() {
  kill "${VAULT_PID}" >/dev/null 2>&1 || true
  wait "${VAULT_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 60); do
  if vault status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

vault status >/dev/null
SHA="$(shasum -a 256 "${PLUGIN_PATH}" | awk '{print $1}')"
vault plugin register -sha256="${SHA}" secret "${PLUGIN_NAME}"
vault secrets enable -path=aap "${PLUGIN_NAME}"
vault path-help aap/config >/dev/null
vault secrets list -format=json | grep -q '"aap/"'

echo "Vault dev smoke test passed"
