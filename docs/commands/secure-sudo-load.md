<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo load [--force]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Read every file under `/etc/secure_sudo/` and push it into the kernel. This is
what makes the on-disk configuration take effect: scalar keys from
`secure-sudo.conf` are written to their `/sys/kernel/secure_sudo/` knobs, and
each policy `*.conf` is written to its securityfs file.

`load` runs automatically at every boot (the systemd unit calls it with
`ExecStartPre`), so the kernel starts in `root-only` safe defaults and then
picks up your saved policy. Run it by hand after editing a `.conf`.

It runs `lint` first (PAM problems count as warnings there) and **refuses to
change anything** if lint finds an error, so a typo cannot leave the kernel
running half a policy; `--force` loads anyway. Then it reports every setting:

```
  accepted  block_setid = 1
  rejected  sudo_max_fails = 7: Operation not permitted
  skipped   retain_days (read by secure-sudod, not the kernel)
load: 41 accepted, 1 rejected, 6 skipped
secure-sudo: load INCOMPLETE: the kernel is running a partial policy; ...
```

Exit status is non-zero on a refusal or when any setting was rejected.
Daemon-only keys (`retain_days`, `remote_syslog`, …) and `timevault_enabled`
are reported as skipped, never as errors.

Remote forwarding uses the daemon-only settings in
[`CONFIGURATION.md`](../CONFIGURATION.md#logging--retention-9). Configure
`remote_syslog_transport = tls` with a collector `host:port` to enable
certificate-verified RFC 5425 syslog and a bounded persistent retry queue.
`secure-sudo health --json` reports transport state, queue backlog and drops;
neither UDP datagram sends nor TLS stream writes claim collector persistence.

Before writing anything, `load` takes a [snapshot](secure-sudo-snapshot.md)
of the configuration files and the live kernel state, and afterwards it
appends a line to the [change history](#secure-sudo-history) (who, the lint
result, how many settings differed, what was accepted and rejected). A
partial load names the rejected settings and the snapshot to go back to:

```
secure-sudo: load INCOMPLETE: the kernel is running a partial policy (rejected:
bpf_guard); fix the rejected lines and run load again, or `secure-sudo restore
20261101T104942Z-418230117` to go back to the state before this load
```

```sh
sudo secure-sudo lint && sudo secure-sudo diff && sudo secure-sudo load
```

Recovery from a policy that locks you out: [RECOVERY.md](../RECOVERY.md).

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
