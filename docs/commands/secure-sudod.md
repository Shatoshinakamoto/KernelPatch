<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudod`

The userspace companion to the secure_sudo LSM. The kernel enforces policy
and emits events; the daemon does the work that must not run in kernel
context: it writes the dated event logs (#9) and forwards them off-box, kills
a sudo brute-forcer's processes (#8), applies the `lan-only`/`public-only`
nft table (#10), and runs TimeVault's scan and quarantine (#13).

- **Source:** [`userspace/daemon/secure-sudod.c`](../../userspace/daemon/secure-sudod.c)
- **Installed as:** `/usr/sbin/secure-sudod`, run by
  [`secure-sudod.service`](../../userspace/daemon/secure-sudod.service).
- **Takes no options or arguments.** Everything comes from
  [`secure-sudo.conf`](../configuration/secure-sudo-conf.md) (the daemon keys)
  and [`net.conf`](../configuration/net-conf.md).

## Running it

```sh
sudo systemctl enable --now secure-sudod     # installed by install.sh
sudo systemctl reload secure-sudod           # SIGHUP: re-read the config
sudo secure-sudo health                      # is it running, fresh, losing nothing?
```

The unit runs `secure-sudo load` first (`ExecStartPre`), so the policy in
`/etc/secure_sudo/` reaches the kernel at every boot; the kernel starts
root-only until then. The unit only starts when the LSM is active
(`ConditionPathExists=/sys/kernel/security/secure_sudo/events`).

| Signal | Effect |
|---|---|
| `SIGHUP` | Re-read the configuration and log `config reloaded`. |
| `SIGTERM` | Stop cleanly. With `net.conf` `on_stop = keep` (default) the network rules stay loaded. |

## Files

| Path | What |
|---|---|
| `/sys/kernel/security/secure_sudo/events` | Kernel event ring it drains |
| `/sys/kernel/secure_sudo/` | Live knobs it reads |
| `/var/log/secure_sudo/YYYY-MM-DD.log` | Dated event logs (`retain_days`, `max_total_mb`) |
| `/var/lib/secure_sudo/` | State: heartbeat, metrics, remote queue, TimeVault manifest |
| `/usr/libexec/secure-sudo/{apply-net,quarantine}.sh` | Helpers it runs: [apply-net](apply-net.md), [quarantine](quarantine-sh.md) |

## Security notes

- Runs as root (securityfs, signalling, nft, quarantine), with
  `NoNewPrivileges`, `ProtectHome`, `ProtectKernelModules`,
  `ProtectControlGroups`, `RestrictRealtime` and `RestrictSUIDSGID` set in
  the unit. NIST AC-6.
- Helpers are run with an argument vector, never through a shell, and
  `alert_cmd` is split into words without a shell (CWE-78).
- Remote forwarding over `tls` verifies the collector's certificate and
  host name (NIST SC-8, AU-9(2)); see the `remote_syslog_*` keys.

## Related

- [EVENTS.md](../EVENTS.md): event and log formats
- [`secure-sudo health`](secure-sudo-health.md)
- [secure-sudo-conf.md](../configuration/secure-sudo-conf.md)
