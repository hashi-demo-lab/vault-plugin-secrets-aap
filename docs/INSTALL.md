# Installing and registering the plugin

`vault-plugin-secrets-aap` is an external Vault secrets plugin: you place its binary in
Vault's plugin directory, register it in the plugin catalog by SHA-256, then enable it on a
mount path. This guide covers production installs from a release, air-gapped/manual builds,
and upgrades.

## 1. Obtain the binary

### From a GitHub release (recommended)

Each tagged release (built by the [GoReleaser workflow](../.github/workflows/release.yml))
publishes per-OS/arch archives and a `*_SHA256SUMS` file.

```bash
VERSION=v0.1.0
OS=linux ARCH=amd64        # darwin/windows, arm64 also published

cd /tmp
curl -fsSLO https://github.com/hashi-demo-lab/vault-plugin-secrets-aap/releases/download/${VERSION}/vault-plugin-secrets-aap_${VERSION#v}_${OS}_${ARCH}.zip
curl -fsSLO https://github.com/hashi-demo-lab/vault-plugin-secrets-aap/releases/download/${VERSION}/vault-plugin-secrets-aap_${VERSION#v}_SHA256SUMS

# Verify the download against the published checksums, then unzip.
grep "${OS}_${ARCH}.zip" vault-plugin-secrets-aap_${VERSION#v}_SHA256SUMS | shasum -a 256 -c -
unzip -o vault-plugin-secrets-aap_${VERSION#v}_${OS}_${ARCH}.zip
```

### Build from source (air-gapped / custom)

```bash
make build      # -> vault/plugins/vault-plugin-secrets-aap
# or: CGO_ENABLED=0 go build -o vault-plugin-secrets-aap ./cmd/vault-plugin-secrets-aap
```

## 2. Place it in Vault's plugin directory

Vault only loads plugins from the configured `plugin_directory`:

```hcl
# vault.hcl
plugin_directory = "/etc/vault/plugins"
```

```bash
sudo install -m 0755 vault-plugin-secrets-aap /etc/vault/plugins/
```

The directory and binary must be owned appropriately and **not** writable by other users;
Vault refuses to run a world-writable plugin.

## 3. Register in the plugin catalog (by SHA-256)

Vault pins each plugin to a checksum so a swapped binary won't load.

```bash
SHA=$(shasum -a 256 /etc/vault/plugins/vault-plugin-secrets-aap | cut -d' ' -f1)

vault plugin register \
  -sha256="$SHA" \
  -command="vault-plugin-secrets-aap" \
  secret vault-plugin-secrets-aap

vault plugin info secret vault-plugin-secrets-aap   # confirm registration
```

You can pin a version label with `-version=v0.1.0` for `vault plugin list` visibility.

## 4. Enable on a mount

```bash
vault secrets enable -path=aap vault-plugin-secrets-aap
```

Then configure it and define roles — see the [README](../README.md#quick-start).

## Upgrading

1. Drop the new binary in `plugin_directory` (same filename).
2. Re-register the new checksum:
   ```bash
   SHA=$(shasum -a 256 /etc/vault/plugins/vault-plugin-secrets-aap | cut -d' ' -f1)
   vault plugin register -sha256="$SHA" -command="vault-plugin-secrets-aap" \
     -version=v0.2.0 secret vault-plugin-secrets-aap
   ```
3. Reload the plugin (in place, no remount):
   ```bash
   vault plugin reload -plugin vault-plugin-secrets-aap
   ```

Existing mounts, config, roles, and leases are preserved across a reload.

## Notes

- **HA / replication:** register and place the binary on **every** Vault node (the binary is
  not replicated). Config/roles are replicated storage; WALs are local.
- **Checksum mismatch on enable** → the binary on disk doesn't match the registered SHA-256;
  re-register the current checksum.
- **`dev` quick start:** `make dev` runs a dev Vault with `-dev-plugin-dir` so the plugin is
  auto-available; `make enable` registers + mounts it. For development only.
