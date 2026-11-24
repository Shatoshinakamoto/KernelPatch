<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Network modes

## Overview

Network host mode denies raw/`AF_PACKET` sockets; nft rules for LAN/public modes. (feature #10)

## How it works

The daemon detects LAN/router subnets and writes one `nft` table `secure_sudo`, deleting it on every mode change. Host mode also has the kernel deny `AF_PACKET`/raw sockets (`socket_create`), so pcap sniffing fails even if libpcap is installed.

**Code:** [`kernel/security/secure_sudo/ss_net.c`](../../kernel/security/secure_sudo/ss_net.c), [`userspace/daemon/helpers/apply-net.sh`](../../userspace/daemon/helpers/apply-net.sh).

## How it is secure

**Threat:** `host`: packet sniffing from a compromised process. `lan-only` / `public-only`: limit where the host can talk to.

**Standards:** NIST SC-7, SC-7(5), AC-4, CM-7; STIG CCI-000382; CWE-923.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** the `net_mode` knob (the kernel half refuses raw and packet sockets in `host` mode, root included); `secure-sudod` loading the `secure_sudo` nft table; netfilter in the kernel (SECURITY_REVIEW #47).

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `net_mode`.

**Configuration:** [net-conf.md](../configuration/net-conf.md).

**Commands:** [secure-sudo-net](../commands/secure-sudo-net.md), [apply-net](../commands/apply-net.md), [cis-nftables](../commands/cis-nftables.md).

```sh
sudo secure-sudo net lan-only      # or host | public-only | monitor
sudo /usr/libexec/secure-sudo/apply-net.sh status
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

The LAN/public modes are nft rules loaded from userspace, so root can flush them (the daemon re-applies within 15 s; the flush itself is not prevented). An `accept` in another nft table cannot bypass them (a drop in any base chain is final). LAN detection is automatic and can be wrong on unusual networks (override in `net.conf`). A namespace with its own uplink (macvlan) is not covered. `host` mode breaks DHCP clients that use packet sockets (§4.6). Not application-aware. **None of the modes is host isolation**: that is `secure-sudo contain network`.

## Troubleshooting

- **The network stopped working after a mode change.** `sudo secure-sudo net monitor` lifts the rules; then check `lan_interfaces` in [net-conf.md](../../configuration/net-conf.md).
- **Another firewall flushed the rules.** Use `scripts/cis-nftables.sh` / `stig-harden.sh`, which keep the `inet secure_sudo` table (OSB-23, OSB-24).
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_net` (packet socket in host mode, root included, event); `tests/userspace/test-netpolicy.sh` (real traffic through namespaces: IPv4/IPv6, two LAN NICs, a VPN, a DHCP subnet change, forwarded container traffic, existing nftables and iptables-nft rules, restart, failed detection, on_stop); `test-helpers.sh` (ruleset text, `nft -c`); `test-daemon-events.sh` (refresh, pending, stop).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
