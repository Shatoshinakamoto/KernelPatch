<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/bootguard.conf`

BootGuard (v8 add-on): hashes and backs up `/boot`, and on tamper stages a restore that `secure-sudo-bootguard-restore.service` applies at the **next boot** (never live).

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/bootguard.conf` (template `temporary/config/bootguard.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** secure-sudo-bootguard (`temporary/bootguard/bootguard.c`). Check it with `secure-sudo-bootguard check-config`.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The add-on's acting commands (daemon, scan, ...) refuse to run while its config has errors.
- **Reload:** Read at every run. Run `secure-sudo-bootguard baseline` after a legitimate kernel or bootloader update and after changing `boot_dir`.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `mode` | enum | `monitor`, `enforce` | `enforce` | `enforce` |
| `rotate` | bool | 0, 1 | `1` | `1` |
| `boot_dir` | path | absolute path, required | `/boot` | `/boot` |
| `backup_root` | path | absolute path, required | `/var/lib/secure_sudo/addons/bootguard/backups` | `/var/lib/secure_sudo/addons/bootguard/backups` |
| `baseline_trust` | enum | `local`, `signed` | `local` | `local` |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`mode`**: `enforce` stages a restore of tampered files for the next boot; `monitor` only reports. The default is `enforce` because staging is safe: nothing is rewritten while the system runs, and the owner's decision of 2026-10-26 keeps boot partition repair. NIST SI-7, CP-10.
- **`rotate`**: `1` stores into an hourly bucket (`root/YYYYMMDDHH`), `0` into one fixed bucket. Rotation means a fixed path cannot be reused, for example to re-expand a quarantined sample. *Recommended:* `1`. NIST SI-7, AU-9.
- **`boot_dir`**: The boot directory to protect. If the EFI system partition is mounted separately, run a second baseline and scan with `boot_dir` pointing at it. NIST SI-7.
- **`backup_root`**: Where backups go when Locus is not used. Root-only local storage. NIST CP-9.
- **`baseline_trust`**: `local` trusts the baseline stored on this host; root on a compromised host could rewrite the baseline and its backups together. `signed` repairs or restores only while the manifest carries a valid Ed25519 signature by the operator's key (`/etc/secure_sudo/addons/baseline-signing.pub`, private key off the host); without it tampering is still reported. *Recommended:* `signed` where root compromise is in scope. NIST SI-7, SI-7(6). Details: [ADDONS.md](../ADDONS.md) "Baseline trust".

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
