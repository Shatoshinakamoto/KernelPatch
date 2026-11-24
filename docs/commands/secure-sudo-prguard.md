<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo prguard <on|off|status|list|add|remove> [path]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Drive the Process Runtime Guard (#20), which protects the runtime memory of
every process except whitelisted ones (denies cross-process ptrace/memory
tampering and writable+executable mappings).

| Form | What it does |
|------|--------------|
| `prguard on` / `prguard off` | enable/disable the guard (kernel + persisted) |
| `prguard status` | print the live `prguard_enabled` value |
| `prguard list` | print the live kernel exemption list |
| `prguard add <path>` | add an absolute **executable path** to the exemption list and push it |
| `prguard remove <path>` | remove an exemption |

The exemption list is `/etc/secure_sudo/prguard_allow.conf` (securityfs
`prguard_allow`); list a program here only if it genuinely needs to debug other
processes or map W+X memory (gdb, strace, perf, some JITs). Refused once the
config is locked.

```sh
sudo secure-sudo prguard add /usr/bin/gdb     # let gdb debug (exempt it)
sudo secure-sudo prguard on                    # guard everything else
sudo secure-sudo prguard status
sudo secure-sudo prguard list
```

See [BINARYVAULT.md](../BINARYVAULT.md) for the companion anti-tamper feature, and
[CONFIGURATION.md](../CONFIGURATION.md) for every setting these commands touch.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
