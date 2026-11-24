<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo lock [-y]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Engage the one-way configuration lock (#16). After this, **no** secure_sudo
setting can change until the machine reboots — the command cannot be re-run to
unlock, and the kernel refuses every write (and blocks module loads, kexec,
hibernation and kernel-memory patching while locked). You are asked to confirm
unless you pass `-y`.

```sh
sudo secure-sudo lock          # prompts "type yes"
sudo secure-sudo lock -y       # no prompt (for scripts)
```

The lock freezes the policy the kernel is *running*. If that differs from
`/etc/secure_sudo/` (a partial load, a `set` that was not persisted), `lock`
says so first; `secure-sudo diff` shows where. It takes a `pre-lock`
snapshot (the frozen state) and records the lock in the history.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
