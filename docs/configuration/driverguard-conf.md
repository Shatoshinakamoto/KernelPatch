<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/driverguard.conf`

DriverGuard (v8 add-on): hashes and backs up the kernel module tree, reports tampered or new modules and, in `enforce`, restores them from the backup.

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/driverguard.conf` (template `temporary/config/driverguard.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** secure-sudo-driverguard (`temporary/driverguard/driverguard.c`). Check it with `secure-sudo-driverguard check-config`.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The add-on's acting commands (daemon, scan, ...) refuse to run while its config has errors.
- **Reload:** Read at every run; the hourly `secure-sudo-driverguard.timer` scan picks up changes. Run `secure-sudo-driverguard baseline` after changing `driver_dir`.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `mode` | enum | `monitor`, `enforce` | `monitor` | `monitor` |
| `rotate` | bool | 0, 1 | `1` | `1` |
| `driver_dir` | path | absolute path, required | `/lib/modules/$(uname -r)` | (commented) |
| `backup_root` | path | absolute path, required | `/var/lib/secure_sudo/addons/driverguard/backups` | `/var/lib/secure_sudo/addons/driverguard/backups` |
| `baseline_trust` | enum | `local`, `signed` | `local` | `local` |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`mode`**: `monitor` reports a tampered module; `enforce` also restores it from the backup. *Recommended:* `monitor` until the baseline has been checked on this host, then `enforce`. NIST SI-7, SI-7(1).
- **`rotate`**: `1` stores into an hourly bucket (`root/YYYYMMDDHH`), `0` into one fixed bucket. Rotation means a fixed path cannot be reused, for example to re-expand a quarantined sample. *Recommended:* `1`. NIST SI-7, AU-9.
- **`driver_dir`**: The module tree to protect. The default follows the running kernel; set it only to protect another tree. NIST SI-7.
- **`backup_root`**: Where backups go when Locus is not used. Keep it on a root-only (`0700`) local file system. NIST CP-9.
- **`baseline_trust`**: `local` trusts the baseline stored on this host; root on a compromised host could rewrite the baseline and its backups together. `signed` repairs or restores only while the manifest carries a valid Ed25519 signature by the operator's key (`/etc/secure_sudo/addons/baseline-signing.pub`, private key off the host); without it tampering is still reported. *Recommended:* `signed` where root compromise is in scope. NIST SI-7, SI-7(6). Details: [ADDONS.md](../ADDONS.md) "Baseline trust".

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
