<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo net <monitor|host|lan-only|public-only>`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

Shortcut for `set net_mode <mode>`; also persisted. See
[CONFIGURATION.md](../CONFIGURATION.md#net_mode) for what each mode does. The LAN
and public modes are enforced by the daemon's nftables helper; `host` mode's
raw/packet-socket block is in the kernel. What counts as the LAN, and what
happens on failures and when the daemon stops, is set in
`/etc/secure_sudo/net.conf`. No mode isolates the host: during an incident use
[`secure-sudo contain network`](secure-sudo-contain.md).

```sh
sudo secure-sudo net host
sudo /usr/libexec/secure-sudo/apply-net.sh status   # mode=lan-only status=applied table=loaded ...
```

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
