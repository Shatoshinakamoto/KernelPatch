<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo restore ID [--no-load] [-y]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Return to a known-good policy (TODO P1-6) without editing files by hand:

1. refuses while locked, unless `--no-load` (that only puts the files back,
   for the next boot);
2. checks the snapshot (`snapshot verify`) and refuses one that fails;
3. shows what changes in `/etc/secure_sudo/`: each setting (`now 6 ->
   snapshot 5`), each list entry, files it will create or remove;
4. asks for `yes` (or `-y`);
5. takes a `pre-restore` snapshot of the current state, so the restore can
   be undone with `restore` again;
6. writes the files atomically (a list file that the snapshot did not have
   is removed, as `load` then clears that list);
7. runs `load`, recorded as `action: restore` with `restored_from`.

Restore puts back the *configuration files*; the kernel then gets them
through the normal `load` (lint included). The `live/` part of a snapshot is
the record of what the kernel ran, used for review and `diff`, not written
back.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
