<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/tamperwatch.conf`

tamperwatch: real-time tamper attribution for the PheonixBox protected set. It records **which process** modified a protected file and, in `quarantine` mode, compresses that process's executable into quarantine and kills it.

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/tamperwatch.conf` (template `temporary/config/tamperwatch.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** secure-sudo-tamperwatch (`temporary/tamperwatch/tamperwatch.c`). Check it with `secure-sudo-tamperwatch check-config`.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The add-on's acting commands (daemon, scan, ...) refuse to run while its config has errors.
- **Reload:** Read when the daemon starts; restart `secure-sudo-tamperwatch` after a change.

**Path lines:** besides `key = value`, a line that is an absolute path adds an extra file or directory to watch (same path rules as above). The PheonixBox protected set (`/etc/secure_sudo/pheonixbox.conf`) is always watched. The template ships none.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `mode` | enum | `log`, `quarantine` | `log` | `log` |
| `rotate` | bool | 0, 1 | `1` | `1` |
| `quarantine_root` | path | absolute path, required | `/var/lib/secure_sudo/addons/tamperwatch/quarantine` | `/var/lib/secure_sudo/addons/tamperwatch/quarantine` |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`mode`**: `log` records the writer only; `quarantine` also quarantines and kills it. Opt-in, because killing the writer of a file that legitimate software updates can stop that software. NIST IR-4, SI-4, AU-3.
- **`rotate`**: `1` stores into an hourly bucket (`root/YYYYMMDDHH`), `0` into one fixed bucket. Rotation means a fixed path cannot be reused, for example to re-expand a quarantined sample. *Recommended:* `1`. NIST SI-7, AU-9.
- **`quarantine_root`**: Where samples go when Locus is not used. Root-only. NIST IR-4.

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
