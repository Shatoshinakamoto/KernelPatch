<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo set <knob> <value>`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Change one scalar knob. The value is written to the kernel first; **only if the
kernel accepts it** is it also written back to `/etc/secure_sudo/secure-sudo.conf`,
so the saved configuration can never drift from live policy and the change
survives a reboot. Refused while locked, or if the kernel rejects the value
(for example a number outside its allowed range).

```sh
sudo secure-sudo set block_userns 1
sudo secure-sudo set max_ram_percent 85
sudo secure-sudo set block_setid_exec 1
sudo secure-sudo set binaryvault 1       # freeze all binaries (see CONFIGURATION.md #17)
```

Knob names are exactly the keys listed by `settings` (and documented in
[CONFIGURATION.md](../CONFIGURATION.md)).

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
