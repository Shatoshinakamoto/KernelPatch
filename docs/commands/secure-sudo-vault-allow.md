<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo vault-allow <subcommand>`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Manage the TimeVault exec allowlist. Entries are stored as `<path> <sha256>`
in `/etc/secure_sudo/timevault_allow.conf` and pushed to the kernel
immediately. Full details — including the standalone script equivalent — are
in [SCRIPTS.md](../SCRIPTS.md#timevault-whitelist).

| Subcommand | What it does |
|------------|--------------|
| `vault-allow scan [-n] [-x] <dir>…` | hash every executable binary/script under each `<dir>` and add it. `-n` dry run; `-x` stay on one filesystem |
| `vault-allow add <file>…` | hash and add single files |
| `vault-allow add-auto <file>…` | add a self-updating **file** as an auto-update entry (exec allowed without a hash check) |
| `vault-allow add-autodir <dir>…` | add a self-updating **directory**: any binary under it execs without a hash check |
| `vault-allow remove <file>…` | drop entries by path |
| `vault-allow remove-dir <dir>…` | walk a directory and remove every executable binary / script found under it from the allowlist (plus an `autodir` entry for the dir itself) |
| `vault-allow list` | print the saved allowlist |
| `vault-allow wipe [-y] [--force]` | empty the allowlist (asks unless `-y`; refuses while engaged unless `--force`) |

Auto-update entries are only honoured while `timevault_allow_autoupdate = 1`
(see [CONFIGURATION.md](../CONFIGURATION.md)); set that to `0` to refuse every
auto-update entry at once. The allowlist size is capped by
`timevault_max_entries`.

```sh
sudo secure-sudo vault-allow scan /usr/bin /usr/sbin /opt/app
sudo secure-sudo vault-allow add /usr/local/bin/mytool
sudo secure-sudo vault-allow add-autodir /opt/self-updating-app
sudo secure-sudo vault-allow remove-dir /opt/old-app
sudo secure-sudo vault-allow list
```

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
