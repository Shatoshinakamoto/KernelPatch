<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# One-way configuration lock

## Overview

One-way config lock until reboot (TimeVault latches it); blocks module loads, kexec and kernel-memory patching while locked. (feature #16)

## How it works

A one-way `lock` switch. Once it's set, config only changes after a reboot. TimeVault sets it automatically.

**Code:** [`kernel/security/secure_sudo/ss_core.c`](../../kernel/security/secure_sudo/ss_core.c), [`kernel/security/secure_sudo/ss_hooks.c`](../../kernel/security/secure_sudo/ss_hooks.c).

## How it is secure

**Threat:** root, after boot, changes secure_sudo's policy, loads kernel code, or patches the kernel to undo the protections.

**Standards:** NIST CM-5, CM-6, SI-7, AC-3; CWE-15.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** the lock engaged (`secure-sudo lock`, or TimeVault); `lock_modules=1` (default); `lock_confidentiality=1` to also stop kernel memory reads; a protected boot path, or a reboot undoes it.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `lock_modules`, `lock_confidentiality`.

**Commands:** [secure-sudo-lock](../commands/secure-sudo-lock.md), [secure-sudo-status](../commands/secure-sudo-status.md).

```sh
sudo secure-sudo lint && sudo secure-sudo load
sudo secure-sudo lock          # irreversible until reboot
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

Until reboot only. It does not limit root outside the kernel and secure_sudo's policy (§2). Modules and BPF programs loaded before the lock stay. It cannot be undone without a reboot (recovery exercise E4).

## Troubleshooting

- **Every `set`/`load` fails with EPERM.** The lock is engaged (TimeVault latches it). Reboot to change the configuration.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_lock` (lock latches and cannot be cleared, knobs and lists refuse writes, module loads and tracing BPF refused, normal exec works); recovery exercise E4 in the Ubuntu guest.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
