<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/biosguard.conf`

BiosGuard: **detection only** (owner's decision of 2026-10-26: detect, log and notify, never repair). It fingerprints the firmware (DMI identity, ACPI tables and the sources below) at `baseline` and logs CRITICAL and notifies on any change at `scan`. It never writes, reflashes or stages firmware.

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/biosguard.conf` (template `temporary/config/biosguard.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** secure-sudo-biosguard (`temporary/biosguard/biosguard.c`). Check it with `secure-sudo-biosguard check-config`.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The add-on's acting commands (daemon, scan, ...) refuse to run while its config has errors.
- **Reload:** Read at every run. After a legitimate firmware or Secure Boot database update run `secure-sudo-biosguard refresh <reason>`.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `baseline_trust` | enum | `local`, `signed` | `local` | (commented) |
| `smbios` | bool | 0, 1 | `1` | (commented) |
| `efi` | bool | 0, 1 | `1` | (commented) |
| `tpm_pcrs` | PCR list | comma-separated PCR numbers 0-23, or empty for none | `0,2,7` | (commented) |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`baseline_trust`**: `local` trusts the baseline stored on this host; root on a compromised host could rewrite the baseline and its backups together. `signed` trusts the fingerprint only while it carries a valid Ed25519 signature by the operator's key (`/etc/secure_sudo/addons/baseline-signing.pub`, private key off the host); . *Recommended:* `signed` where root compromise is in scope. NIST SI-7, SI-7(6). Details: [ADDONS.md](../ADDONS.md) "Baseline trust".
- **`smbios`**: Fingerprint the raw SMBIOS table and entry point. *Recommended:* `1`. NIST SI-7, SI-7(9) (boot process integrity).
- **`efi`**: Fingerprint the Secure Boot variables (SecureBoot, SetupMode, PK, KEK, db, dbx) and the UEFI update table (ESRT). A legacy-BIOS boot has neither. *Recommended:* `1`. NIST SI-7(9).
- **`tpm_pcrs`**: TPM PCRs that measure firmware: 0 firmware code, 2 option ROMs, 7 Secure Boot policy. PCR 4 and up change with every bootloader or kernel update and PCR 1 with firmware settings, so they are left out by default to avoid false alarms. An invalid list is an error and the default is kept. NIST SI-7(9).

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
