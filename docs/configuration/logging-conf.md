<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/addons/logging.conf`

Shared logging for all `temporary/` add-ons (ProcGuard, DriverGuard, BiosGuard, BootGuard, Locus, tamperwatch): local logs, off-box shipping and notifications.

## Location, format and reload

- **Path:** `/etc/secure_sudo/addons/logging.conf` (template `temporary/config/logging.conf`), installed by `temporary/install-temporary.sh`.
- **Read by:** every add-on (`temporary/common/ssaddon_log.c`). Each add-on's `check-config` checks it.
- **Format and checking (all add-ons):** `key = value`, `#` comment lines. Parsing is strict (`temporary/common/ssaddon_conf.c`, TODO P2-2): an unknown key, a line without `=`, a key set twice, an enum value that is not listed, a number that does not parse in full or is out of range, a relative path or one containing `..`, a value too long for its buffer, or a control character is an **error**, never a silent fallback. The file must be owned by root and not group- or world-writable, because it names paths and commands a root daemon acts on (NIST CM-5, CWE-732). A missing file is not an error: the built-in defaults apply. The add-on's acting commands (daemon, scan, ...) refuse to run while its config has errors.
- **Reload:** each add-on reads it when it starts or runs.

## Key reference

No key is required unless the Allowed column says so; every key has a built-in default.

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `log_dir` | path | absolute path, required | `/var/log/secure_sudo/addons` | `/var/log/secure_sudo/addons` |
| `log_max_bytes` | integer | 65536-1073741824 | `8388608` | `8388608` |
| `remote_enabled` | bool | 0, 1 | `0` | `0` |
| `remote_proto` | enum | `udp`, `tcp` | `udp` | `udp` |
| `remote_host` | host | host name or address; required when `remote_enabled = 1` | empty | empty |
| `remote_port` | port | 1-65535 | `514` | `514` |
| `notify_cmd` | command | argv template with `%m %l %f`, or empty | empty (off) | (commented) |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`log_dir`**: Each add-on writes `<log_dir>/<feature>.log` (root-only, `0700`), rotated to `.1` at the size cap. NIST AU-9.
- **`log_max_bytes`**: The local rotation size. The remote collector, if set, is the long-term archive. NIST AU-4, AU-11.
- **`remote_enabled`**: `1` ships every log line to `remote_host` as RFC 5424 syslog, so a compromised host cannot erase the record. *Recommended:* `1`. NIST AU-4(1), AU-9(2).
- **`remote_proto`**: `udp` (fire-and-forget) or `tcp` (octet-framed, reliable). **Neither is encrypted or authenticated**, unlike the core daemon's `remote_syslog_transport = tls`. *Recommended:* `tcp` to a collector on a trusted network, or to a local relay that forwards over TLS. CWE-319; NIST SC-8.
- **`remote_host`**: The collector. `remote_enabled = 1` without it is an error.
- **`remote_port`**: The collector port.
- **`notify_cmd`**: Run for notable events (for example a BIOS change). **No shell:** the line is split into words (quotes group), each placeholder is replaced inside its word, and the program runs directly, so message text cannot become a command (CWE-78). The same message within 300 s is sent once, at most 10 run a minute, and a command that fails or runs past 10 s is logged ERROR. NIST SI-4(5), IR-6.

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
