<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `/etc/secure_sudo/net.conf`

Tells the `lan-only` and `public-only` network modes (`net_mode` in
[secure-sudo-conf.md](secure-sudo-conf.md)) what counts as the LAN, and what
happens to the rules when the daemon stops. Background, failure modes and the
fail-safe policy: [CONFIGURATION.md#net_mode](../CONFIGURATION.md#net_mode).

## Location, format and reload

- **Path:** `/etc/secure_sudo/net.conf`, root-owned, not group- or
  world-writable (whoever edits it decides what "LAN" means; NIST CM-5).
- **Read by:** `/usr/libexec/secure-sudo/apply-net.sh`, which `secure-sudod`
  runs when `net_mode` changes and every 15 seconds after.
- **Format:** `key = value`. Unlike `secure-sudo.conf`, a trailing `# comment`
  after a value is stripped here. If a key appears twice, the last one wins.
  A missing file or key uses the default.
- **Reload:** automatic within 15 seconds. When nothing changed, nft is not
  touched.
- **Validation:** interface names and patterns may only contain
  `A-Z a-z 0-9 _ . : @ * -`; `extra_lan` entries only hex digits, `:`, `.`
  and `/`; `forward` must be `0` or `1`. A bad value is logged and the
  **current rules stay loaded** (fail-safe: a typo never opens the network).
  The characters are restricted because the values are placed into an nft
  ruleset (CWE-78, CWE-20).

## Key reference

<!-- config-keys:begin -->
| Key | Type | Allowed | Default | Shipped |
|-----|------|---------|---------|---------|
| `lan_interfaces` | word list | `auto`, or interface names | `auto` | `auto` |
| `vpn_interfaces` | glob list | interface name patterns | `wg* tun* tap* ppp* tailscale* zt* nordlynx* ipsec* vti* utun*` | `wg* tun* tap* ppp* tailscale* zt* nordlynx* ipsec* vti* utun*` |
| `extra_lan` | CIDR list | IPv4 or IPv6 CIDRs | empty | empty |
| `forward` | bool | `0`, `1` | `1` | `1` |
| `on_stop` | enum | `keep`, `remove` | `keep` | `keep` |
<!-- config-keys:end -->

No key is required.

## What each key does, and its security impact

- **`lan_interfaces`**: `auto` takes every interface with a global address
  except loopback, VPN interfaces and bridges that carry no default route
  (`docker0`, `virbr0`; those count as "local" and are reachable in both
  modes). Naming interfaces is stricter and predictable on multi-homed hosts.
  NIST SC-7.
- **`vpn_interfaces`**: never treated as LAN, whatever `lan_interfaces` says.
  Any link that is not Ethernet, Wi-Fi or InfiniBand is a VPN too. With a
  VPN, `lan-only` cuts the tunnel and `public-only` lets it work while the
  LAN stays blocked. NIST SC-7, AC-4.
- **`extra_lan`**: more LAN subnets that are not on a local interface (for
  example a routed office network). *Security impact:* every CIDR added here
  is reachable in `lan-only` and blocked in `public-only`; keep it to real
  internal ranges. NIST SC-7(5).
- **`forward`**: `1` also filters traffic this host forwards, so routed
  containers and network namespaces follow the mode. *Recommended:* `1`.
  `0` lets every routed container ignore the policy. A namespace with its
  own uplink (macvlan, passed-through NIC) is never covered. NIST SC-7, AC-4.
- **`on_stop`**: what a clean daemon stop does: `keep` leaves the rules
  loaded, `remove` deletes them. A crash always keeps them. *Recommended:*
  `keep`, so stopping or killing the daemon never opens the network
  (fail-secure, NIST SC-24). Lift the rules by hand with
  `secure-sudo net monitor`.

## Coexistence with other firewalls

Only the `inet secure_sudo` table is ever replaced or deleted. A packet must
pass every table, so this policy cannot loosen another firewall and another
firewall's `accept` cannot bypass it. A CIS firewall made by
`scripts/cis-nftables.sh` lives in `inet filter`; `stig-harden.sh` stops the
stock `/etc/nftables.conf` and `nftables.service` from flushing this table
(OSB-23, OSB-24, VM-verified 21/21 in
`HistoryTest/runs/2026-11-23_134551Z_vm-osb24_8d432e8/`).

## Tests

`tests/userspace/test-netpolicy.sh` (real traffic in network namespaces) and
`tests/userspace/test-cis-firewall.sh` (both tables together).
