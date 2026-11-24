<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo snapshot`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

| Command | What it does |
|---|---|
| `snapshot [create] [-m REASON]` | take a snapshot now |
| `snapshot list` | id, reason, who, and whether the box was locked |
| `snapshot show ID` | its metadata, files and hashes, and an integrity check |
| `snapshot verify [ID]` | check one snapshot, or all of them |

A snapshot is a directory `/var/lib/secure_sudo/policy/snapshots/ID/`
(root-only) holding:

* `disk/`: every file `load` reads from `/etc/secure_sudo/`, as it was;
* `live/`: every kernel setting (`live/settings`) and list, as the kernel
  reported them;
* `meta`: format version, time, reason, uid, login uid and `SUDO_USER`,
  kernel release, boot id, lock state, and the previous snapshot's id and
  the SHA-256 of its `SHA256SUMS`;
* `SHA256SUMS`: the hash of every file above.

`load`, `restore`, `set`, `net`, `lock` and `timevault on` take one before
they change anything (reasons `pre-load`, `pre-restore`, `pre-set`,
`pre-lock`, `pre-timevault`). The newest 100 are kept. IDs are the UTC time
plus nanoseconds, so they sort by age and are never reused.

`verify` fails if a file was changed, removed or added, or if the previous
snapshot's `SHA256SUMS` is no longer the one this snapshot recorded. A forger
who edits a snapshot *and* rewrites its sums is caught by the next snapshot
and by `history --verify`. Root can still rewrite everything consistently;
the history's syslog copy, forwarded off the box, is the record that cannot
be rewritten.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
