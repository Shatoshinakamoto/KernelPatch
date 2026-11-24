<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo node-scan [--dry-run] [--quiet] [DIR|FILE...]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Find Node.js runtimes that are not at a standard path and register them for
the Node child guard (#11), so their children must be on
`node_allowed_children`. A runtime is an executable ELF file holding Node's
SEA fuse (a single-executable app, or a renamed `node`) or pkg's markers.
Electron apps embed Node too but are reported, not registered; list one in
`node_sea_binaries.conf` to confine it.

With no DIR it searches `node_sea_scan_dirs`. With DIRs it searches only
those and keeps what earlier scans found elsewhere. Results go to
`/var/lib/secure_sudo/node_sea_auto.list`; the kernel gets the hand-written
`node_sea_binaries.conf` entries first, then these, up to 256 entries (the
command exits 1 and says how many did not fit). Unchanged files are not
read again. The daemon runs it at start and every `node_sea_scan_interval`
minutes; run it yourself right after deploying an app. `--dry-run` prints
`PATH<TAB>KIND` lines (`sea`, `node`, `pkg`) and changes nothing.

```sh
sudo secure-sudo node-scan --dry-run /opt/myapp   # what would be registered
sudo secure-sudo node-scan                         # scan and register
```

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
