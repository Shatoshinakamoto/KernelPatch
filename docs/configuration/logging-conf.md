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
| `remote_proto` | enum | `udp`, `tcp`, `tls` | `udp` | `udp` |
| `remote_host` | host | host name or address; required when `remote_enabled = 1` | empty | empty |
| `remote_port` | port | 1-65535 | `514` | `514` |
| `remote_ca_file` | path | absolute path to a PEM CA bundle; must load when `remote_proto = tls` | `/etc/ssl/certs/ca-certificates.crt` | `/etc/ssl/certs/ca-certificates.crt` |
| `notify_cmd` | command | argv template with `%m %l %f`, or empty | empty (off) | (commented) |
<!-- config-keys:end -->

## What each key does, and its security impact

- **`log_dir`**: Each add-on writes `<log_dir>/<feature>.log` (root-only, `0700`), rotated to `.1` at the size cap. NIST AU-9.
- **`log_max_bytes`**: The local rotation size. The remote collector, if set, is the long-term archive. NIST AU-4, AU-11.
- **`remote_enabled`**: `1` ships every log line to `remote_host` as RFC 5424 syslog, so a compromised host cannot erase the record. *Recommended:* `1`. NIST AU-4(1), AU-9(2).
- **`remote_proto`**: `udp` (fire-and-forget, unencrypted), `tcp` (octet-framed, unencrypted) or `tls` (syslog over TLS, RFC 5425: octet-framed, encrypted, and the collector is authenticated). With `tls` the connection uses TLS 1.2 or newer, the collector's certificate must chain to `remote_ca_file`, and it must name `remote_host` (DNS name, with SNI) or match it as an IP address, the same rules as the core daemon's `remote_syslog_transport = tls`. Connect, handshake and writes time out after 3 s. If the collector is down, the add-on keeps logging locally, writes one `remote log shipping FAILED` line to its local log, tries again at most every 30 s and logs `remote log shipping restored` when it is back; a collector that closed the connection is reconnected before the next line, so a restart loses nothing. `tcp` reconnects the same way. Lines logged while the collector is unreachable are only in the local log; they are not queued and resent. *Recommended:* `tls` (use a collector port such as 6514). `udp` and `tcp` let anyone on the path read, change or drop the records (CWE-319). NIST SC-8, SC-8(1), SC-23, AU-9(2).
- **`remote_host`**: The collector. `remote_enabled = 1` without it is an error.
- **`remote_port`**: The collector port. The default 514 suits `udp`; for `tls` collectors usually listen on 6514.
- **`remote_ca_file`**: The CA bundle that must have issued the collector's certificate (`tls` only; ignored otherwise). The default is the Debian and Ubuntu system bundle; on Fedora and RHEL use `/etc/pki/tls/certs/ca-bundle.crt`. *Recommended:* a file holding only your own log CA, so a certificate from any public CA for that name is not enough. With `remote_enabled = 1` and `remote_proto = tls`, a file that is missing or holds no certificate is a config error (`check-config` names it), so the problem is found before the first event, not after. CWE-295; NIST SC-23, IA-3.
- **`notify_cmd`**: Run for notable events (for example a BIOS change). **No shell:** the line is split into words (quotes group), each placeholder is replaced inside its word, and the program runs directly, so message text cannot become a command (CWE-78). The same message within 300 s is sent once, at most 10 run a minute, and a command that fails or runs past 10 s is logged ERROR. NIST SI-4(5), IR-6.

## Related

- [ADDONS.md](../ADDONS.md) for the add-on itself, its maturity level and its threat model.
- `temporary/maturity.json`: every add-on is published as experimental.
