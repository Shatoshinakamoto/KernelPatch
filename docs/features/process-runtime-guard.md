<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Process Runtime Guard

## Overview

**Process Runtime Guard:** denies cross-process ptrace / `process_vm_writev` / `/proc/pid/mem` tampering and W^X mappings, with a CLI-managed exemption list; optional `prguard_observe` memory-access feed. `secure-sudo prguard ...` (feature #20)

## How it works

**Code:** [`kernel/security/secure_sudo/ss_prguard.c`](../../kernel/security/secure_sudo/ss_prguard.c).

## How it is secure

**Threat:** process injection (ptrace attach, `process_vm_writev`, `/proc/<pid>/mem` writes) and writable-and-executable memory used by injected code.

**Standards:** NIST SI-16 (memory protection), SC-39, AC-6; CWE-94, CWE-787.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `prguard_enabled=1` (off by default); `prguard_allow` for debuggers, profilers and JITs.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `prguard_enabled`, `prguard_observe`.

**Policy files:** [prguard_allow.conf](../files/prguard_allow.md).

**Commands:** [secure-sudo-prguard](../commands/secure-sudo-prguard.md).

```sh
sudo secure-sudo prguard status
sudo secure-sudo prguard add /usr/bin/gdb
sudo secure-sudo prguard on
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

A process already being traced when the guard is turned on stays traced. Exempt programs can still inject. W^X refusal breaks JIT runtimes (browsers, Java, Node) that are not exempt. Read-mode access (`/proc/<pid>/environ`, `maps`, `stat`, what `ps` and `top` use) is left alone; `process_vm_readv` and `/proc/<pid>/mem` reads need attach mode and are refused.

## Troubleshooting

- **A JIT (browser, Java, Node) crashes.** W^X mappings are denied; add the runtime to the exemption list.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_prguard` (attach, `process_vm_writev`, `/proc/<pid>/mem`, root, W+X, exemption).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
