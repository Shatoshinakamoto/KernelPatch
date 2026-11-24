<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo timevault <on|off>`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Engage or disengage TimeVault (#13). **Engaging latches the config lock** and
is refused if the allowlist is empty (that would leave nothing runnable).
Because engaging locks the configuration, an engaged vault cannot be
disengaged until the next reboot. The state is persisted.

```sh
sudo secure-sudo vault-allow scan /usr/bin /usr/sbin   # populate first
sudo secure-sudo timevault on
```

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
