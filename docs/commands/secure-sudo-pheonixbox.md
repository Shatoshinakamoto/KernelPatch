<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo pheonixbox <on|off|snapshot|scan|status|add|remove|list> [path]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

PheonixBox (#21): snapshot-based tamper protection with automatic repair for a
chosen set of files and directories. Delegated to the
`/usr/bin/secure-sudo-pheonixbox` helper; each form is root-only. Full detail is
in [PHEONIXBOX.md](../PHEONIXBOX.md).

**Important:** this does *not* reverse a hash — a SHA-256 hash is one-way and
cannot be turned back into a file. PheonixBox uses a SHA-256 manifest to
**detect** tampering and a root-only, zlib-compressed **snapshot store of the
original bytes** to **restore** it (reversible, no password). The hash finds the
damage; the snapshot store does the repair.

| Form | What it does |
|------|--------------|
| `pheonixbox on` / `enable` | snapshot the protected files (hashes + compressed originals + owner/mode/ACLs), lock them read-only, and start periodic scanning |
| `pheonixbox off` / `disable` | restore every file's original permissions (and ACLs) from the PermissionsSnapshot and stop protecting |
| `pheonixbox snapshot` | (while off) re-capture current contents, hashes and permissions as the new known-good baseline |
| `pheonixbox scan [--quiet]` | check every protected file now and repair any tampering (the daemon runs this on a ~30 s timer) |
| `pheonixbox status` | show whether protection is on, how many files are covered, and the last scan |
| `pheonixbox add <path>` | add a file or directory (recursive) to the protected set |
| `pheonixbox remove <path>` | remove a path from the protected set |
| `pheonixbox list` | list the protected paths |

The protected set lives in `/etc/secure_sudo/pheonixbox.conf` (one absolute path
per line). A real update to a protected file is a deliberate `off` → edit →
`on` (or `off` → edit → `snapshot` → `on`).

```sh
sudo secure-sudo pheonixbox add /etc/ssh/sshd_config
sudo secure-sudo pheonixbox add /usr/local/bin        # whole dir, recursive
sudo secure-sudo pheonixbox on                         # lock + begin repairing
sudo secure-sudo pheonixbox status
```

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
