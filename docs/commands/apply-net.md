<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `userspace/daemon/helpers/apply-net.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

Called by `secure-sudod` when `net_mode` changes and every 15 seconds after
(not run by hand, except `status`). Installs or removes a single nftables
table `inet secure_sudo` for the chosen mode, with `input`, `output` and (with
`forward = 1`) `forward` chains.

```
apply-net.sh <monitor|host|lan-only|public-only>   apply or refresh
apply-net.sh stop                                   daemon stopping: net.conf on_stop
apply-net.sh status                                 loaded mode, pending/applied, table present
```

* `monitor`, `host` — removes the secure_sudo table (no nft rules; `host`
  mode's socket block is in the kernel).
* `lan-only` — allow only loopback, the LAN and local bridges, plus DHCP and
  neighbour discovery, for IPv4 **and** IPv6.
* `public-only` — drop traffic to the LAN and private IPv6 ranges, but keep
  DHCP/DHCPv6, ICMPv6 neighbour discovery and DNS to a LAN gateway.

The LAN is every LAN interface's subnets (`/etc/secure_sudo/net.conf`:
`lan_interfaces`, `vpn_interfaces`, `extra_lan`), see
[CONFIGURATION.md](../CONFIGURATION.md#net_mode). The ruleset's hash is kept in
`/run/secure_sudo/net.state`; a refresh with nothing changed does not touch
nft, and a change is logged to syslog (`secure-sudo-net`).

Exit status: 0 applied or unchanged; 1 failed, current rules kept (nft error,
bad `net.conf`, no LAN subnet while this mode's rules are loaded); 2 unknown
mode; 3 no LAN subnet and nothing loaded yet, so the fail-closed *pending*
rules were loaded. The daemon retries 1 and 3 every 5 seconds, logs once, and
reports `net_state` in its heartbeat (`secure-sudo health`).

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
