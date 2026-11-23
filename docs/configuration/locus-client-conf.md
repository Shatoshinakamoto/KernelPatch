<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/locus-client.conf`

Where the guards ask for a rotating location. If the file is absent or `host` is empty, each guard uses its own configured root (still rotated hourly), so Locus is optional.

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/locus-client.conf` (template `temporary/config/locus-client.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** every guard that stores files (`temporary/common/ssaddon_store.c`). Each guard's `check-config` checks it.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The add-on's acting commands (daemon, scan, ...) refuse to run while its config has errors.
- **Reload:** Read each time a guard needs a location.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `host` | host | host name or address, or empty | empty (no allocator) | empty |
| `port` | port | 1-65535 | `8787` | `8787` |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`host`**: The `locus serve` allocator. Requests are plain TCP without authentication, so use loopback or a trusted network. NIST SC-7, SC-8.
- **`port`**: The allocator port.

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
