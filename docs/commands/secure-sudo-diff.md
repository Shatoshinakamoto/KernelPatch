<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo diff` (also `load --dry-run`)

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Preview a change (TODO P1-6): run lint, then compare every file `load` reads
with what the running kernel holds, and print each difference. Nothing is
written and no snapshot is taken.

```
  change    sudo_max_fails                     live 5 -> config 6
  change    blacklist
              + /usr/bin/socat
              - /usr/bin/nc
              (1 to add, 1 to remove)
  unknown   bpf_guard                          live value unreadable
diff: 2 change(s), 1 unreadable
```

Settings not in `secure-sudo.conf` are not shown (load leaves them alone).
List entries are compared ignoring comments, blank lines, order and
duplicates; at most 20 entries are shown per list. A value lint rejects is
marked `(invalid: load rejects it)`. If lint finds an error, diff says load
would refuse and still shows the differences. On a locked box it says the
changes apply at the next boot. Right after a `load`, `diff: 0 change(s)`
means the kernel runs exactly the configuration; anything else shows what a
partial load did not apply.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
