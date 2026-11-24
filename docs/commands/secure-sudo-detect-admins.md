<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo detect-admins [-n]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Re-detect every admin group on the box (the GIDs of `sudo`, `wheel`, `admin`
and any `%group`/`%#gid` rule in sudoers) and set `admin_gid` to that list, in
both the kernel and `secure-sudo.conf`. Run it after creating a new admin
group. `-n` prints what it found without saving. The installer runs the same
logic once at install time.

```sh
sudo secure-sudo detect-admins -n     # preview
sudo secure-sudo detect-admins        # apply
```

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
