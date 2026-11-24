<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo list <name>`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Show a policy list's **current kernel contents** (not the on-disk file).
`<name>` is the securityfs name or the `.conf` file name, e.g. `blacklist`,
`timevault_allow`, `setid_exec_allow`. Read-only.

```sh
sudo secure-sudo list blacklist
sudo secure-sudo list setid_exec_allow
sudo secure-sudo list binvault_allow
```

To change a policy list, edit its file under `/etc/secure_sudo/` and run
`load` (or, for the TimeVault allowlist, use `vault-allow`, which edits and
pushes in one step).

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
