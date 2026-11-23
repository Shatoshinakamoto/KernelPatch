<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/gui.conf`

The local management console (P2-5).

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/gui.conf` (template `temporary/config/gui.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** `secure-sudo-gui` (`temporary/gui/secure-sudo-gui`, its own Python parser with the same rules). Check it with `secure-sudo-gui check-config`.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The console refuses to start while its config has errors.
- **Reload:** read when `secure-sudo-gui` starts; restart it after a change.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `bind` | host | host name or address | `127.0.0.1` | `127.0.0.1` |
| `port` | port | 1-65535 | `8790` | `8790` |
| `mode` | enum | `read_only`, `admin` | `read_only` | (commented) |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`bind`**: The listen address. **Keep it on loopback.** The console can edit config and quarantine or kill processes; to reach it from elsewhere, put your own authenticated TLS proxy in front and leave `bind` on `127.0.0.1`. Every `/api` request also needs the per-install token (stored `0600` at `/var/lib/secure_sudo/addons/gui/token`), and the server checks the Host header. NIST AC-17, SC-7, CWE-306.
- **`port`**: The listen port.
- **`mode`**: `read_only` shows everything and refuses every change; `admin` also lets the console edit configs, set knobs, run scans and baselines, and quarantine processes. *Recommended:* `read_only`, switching to `admin` only while making a change. NIST AC-6, AC-3.

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
