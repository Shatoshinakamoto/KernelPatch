<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo contain ...`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Incident containment (TODO P1-7); the runbook is
[INCIDENT_RESPONSE.md](../INCIDENT_RESPONSE.md) section 4.

| Command | What it does |
|---|---|
| `contain network [--allow ADDR]... [--no-collector]` | drop all traffic except loopback, the `--allow` addresses, your SSH client and the `remote_syslog` collector (nft table `inet secure_sudo_contain`) |
| `contain account USER [--terminate]` | lock and expire the account, freeze (or with `--terminate` kill) its processes; refuses UID 0 and your own account |
| `contain process PID [--kill]` | freeze the process and its descendants and save its evidence (executable copy and hash, cmdline, environment, maps, open files, sockets); `--kill` kills after that |
| `contain release network \| account USER \| process PID` | undo the step; the evidence stays |
| `contain status` | what is contained now |

Every action takes `--dry-run` (shows the plan, changes nothing) and asks
for `yes` unless given `-y`; anything but `yes` exits 3 with nothing
changed. State and evidence are under `/var/lib/secure_sudo/contain/`
(root-only). Each action that ran is recorded in `secure-sudo history` as
`contain` or `release`, with its arguments and whether it succeeded.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
