<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/locus.conf`

Locus (v8 add-on), the rotating-location allocator: hands each guard this hour's bucket under the root for its purpose, and shows a read-only status page.

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/locus.conf` (template `temporary/config/locus.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** secure-sudo-locus (`temporary/locus/locus.c`). Check it with `secure-sudo-locus check-config`.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The add-on's acting commands (daemon, scan, ...) refuse to run while its config has errors.
- **Reload:** Read when `secure-sudo-locus serve` starts; restart it after a change.

**Root lines:** `root PURPOSE = PATH` (absolute path, at most 32 lines) sets the root for one purpose (`procguard-quarantine`, `driverguard-backup`, `bootguard-backup`, ...). The template sets those three to the guards' own default roots.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `alloc_bind` | host | host name or address, required | `127.0.0.1` | `127.0.0.1` |
| `alloc_port` | port | 1-65535 | `8787` | `8787` |
| `gui_bind` | host | host name or address, required | `127.0.0.1` | `127.0.0.1` |
| `gui_port` | port | 1-65535 | `8788` | `8788` |
| `default_root` | path | absolute path, or empty | empty | `/var/lib/secure_sudo/addons/locus/alloc` |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`alloc_bind`**: Where guards request locations. Keep `127.0.0.1` unless other hosts must request locations; then use one LAN address of this host, never `0.0.0.0`. NIST SC-7, CM-7.
- **`alloc_port`**: The allocator port. Allocator and status page may not share one address and port (an error).
- **`gui_bind`**: The read-only status page (HTTP GET only, no inputs, no file serving). Keep it on loopback unless you mean to expose it. NIST SC-7.
- **`gui_port`**: The status page port.
- **`default_root`**: The root for any purpose without its own `root` line. Empty means such a request gets no location.

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
