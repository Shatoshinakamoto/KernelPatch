<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# RAM-spike cache drop

## Overview

RAM-spike detection drops caches (`si_mem_available`, kernel worker). (feature #7)

## How it works

The kernel worker calls the drop-cache routine directly, so there's no process or command anyone could run or hijack, which is the "private field" requirement. It measures with `si_mem_available()`, and the threshold and interval are configurable.

**Code:** [`kernel/security/secure_sudo/ss_ram.c`](../../kernel/security/secure_sudo/ss_ram.c).

## How it is secure

**Threat:** none in the security sense. It is an availability aid: drop the page and slab caches when real memory use crosses a threshold.

**Standards:** NIST SC-5 (resource availability), SI-4; CWE-400.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `ram_spike_enabled=1` (off by default).

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `ram_spike_enabled`, `max_ram_percent`, `check_interval_ms`, `drop_cooldown_ms`.

**Commands:** [secure-sudo-set](../commands/secure-sudo-set.md).

```sh
sudo secure-sudo get max_ram_percent
sudo secure-sudo set max_ram_percent 90
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

It does not free process memory or stop a memory-exhaustion attack (the OOM killer does that), and dropping caches costs performance. Do not count it as a security control.

## Troubleshooting

- **I/O got slower under memory pressure.** Dropping caches costs re-reads; raise the threshold or the interval.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_ram` (drop above the threshold, logged as a `ram_guard` event raised by the kernel worker; no drop when off).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
