<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/procguard.conf`

ProcGuard (v8 add-on): scans running processes and, in `enforce`, kills any executable not in [procguard_allow.conf](../files/procguard_allow.md); one that keeps coming back is treated as an infection and quarantined.

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/procguard.conf` (template `temporary/config/procguard.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** secure-sudo-procguard (`temporary/procguard/procguard.c`). Check it with `secure-sudo-procguard check-config`.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The add-on's acting commands (daemon, scan, ...) refuse to run while its config has errors.
- **Reload:** the daemon reads the config and the allowlist when it starts; restart `secure-sudo-procguard` after a change. `secure-sudo-procguard status` shows what is in effect.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `mode` | enum | `monitor`, `enforce` | `monitor` | `monitor` |
| `interval` | integer | 1-3600 seconds | `5` | `5` |
| `respawn_threshold` | integer | 1-1000 | `3` | `3` |
| `respawn_window` | integer | 1-86400 seconds | `60` | `60` |
| `remove_on_infection` | bool | 0, 1 | `1` | `1` |
| `rotate` | bool | 0, 1 | `1` | `1` |
| `quarantine_root` | path | absolute path, required | `/var/lib/secure_sudo/addons/procguard/quarantine` | `/var/lib/secure_sudo/addons/procguard/quarantine` |
| `sync_cmd` | command | shell command with `%f`, or empty | empty (off) | (commented) |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`mode`**: `monitor` only logs "would kill"; `enforce` kills. Enforce also stays report-only until a clean pass or `secure-sudo-procguard arm`. *Recommended:* run `monitor` until the allowlist covers everything you need. NIST CM-7(5), SI-4.
- **`interval`**: Seconds between scans. Shorter catches short-lived processes sooner and costs CPU. NIST SI-4.
- **`respawn_threshold`**: Kills within `respawn_window` before an executable counts as an infection (quarantined, optionally removed). NIST IR-4.
- **`respawn_window`**: See `respawn_threshold`.
- **`remove_on_infection`**: `1` removes the on-disk file of a confirmed infection (a compressed sample is quarantined either way); `0` leaves it. NIST IR-4, SI-3.
- **`rotate`**: `1` stores into an hourly bucket (`root/YYYYMMDDHH`), `0` into one fixed bucket. Rotation means a fixed path cannot be reused, for example to re-expand a quarantined sample. *Recommended:* `1`. NIST SI-7, AU-9.
- **`quarantine_root`**: Where samples go when Locus is not used. Root-only (`0700`). NIST IR-4, AU-9.
- **`sync_cmd`**: Ships each quarantined sample off-box. **Runs through `/bin/sh`**; `%f` is replaced by the sample path in single quotes, and a path containing a quote is refused, so the sample name cannot inject a command (CWE-78). Point it at a fixed command or script; leave it unset to disable. NIST IR-4, AU-9(2).

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
