<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# SysctlGuard

## Overview

**SysctlGuard:** freezes the security-critical sysctls (`core_pattern`, `modprobe`, `kptr_restrict`, `ptrace_scope`, `randomize_va_space`, `fs.protected_*`, ...) and binfmt_misc registration for every user, root included. Plus: `audit_events` feeds every kernel event to auditd, and `lock_confidentiality` extends the lock to kernel-memory reads. (feature #23)

## How it works

**Code:** [`kernel/security/secure_sudo/ss_sysctl.c`](../../kernel/security/secure_sudo/ss_sysctl.c).

## How it is secure

**Threat:** root persistence or weakening through `core_pattern`, `modprobe`, `kptr_restrict` and the other protected sysctls, or a binfmt_misc handler.

**Standards:** NIST CM-6, CM-5, SI-7; STIG SRG-OS-000480 (CM-6); CWE-15.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `sysctl_guard=1` after `sysctl.d` has applied; the lock to freeze the knob.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `sysctl_guard`.

**Commands:** [secure-sudo-set](../commands/secure-sudo-set.md).

```sh
sudo secure-sudo get sysctl_guard
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

A fixed list; per-network-namespace sysctls are not frozen (containers set them). A bad value set before the guard is turned on is what gets frozen.

## Troubleshooting

- **`sysctl -w` of a hardening setting fails.** By design those sysctls are frozen for everyone; set them in the configuration and reboot.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_sysctl`, and the core-dump helper test in `t_events`.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
