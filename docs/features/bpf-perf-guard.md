<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# BPF and perf guard

## Overview

**BPF & perf guard:** `bpf_guard` / `perf_guard` deny bpf(2) and perf_event_open to non-sudo users; `bpf_lock_tracing` (default on) refuses tracing-class BPF programs (kprobe, tracepoint, fentry, BPF-LSM, freplace) for everyone once the lock latches. (feature #22)

## How it works

**Code:** [`kernel/security/secure_sudo/ss_bpf.c`](../../kernel/security/secure_sudo/ss_bpf.c).

## How it is secure

**Threat:** non-sudo users reaching kernel attack surface or side channels through `bpf(2)` and `perf_event_open(2)`; root loading tracing BPF (rootkits) after the lock.

**Standards:** NIST CM-7, AC-6, SI-4; STIG SRG-OS-000480; CWE-284.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `bpf_guard=1`, `perf_guard=1` (installed defaults); the lock for `bpf_lock_tracing`.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `bpf_guard`, `perf_guard`, `bpf_lock_tracing`.

**Commands:** [secure-sudo-set](../commands/secure-sudo-set.md).

```sh
sudo secure-sudo get bpf_guard
sudo secure-sudo set perf_guard 1
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

Programs loaded before the lock keep running. Networking, cgroup and `struct_ops` BPF stay allowed on purpose. Admin-group members are exempt from the non-sudo half. Root before the lock is not limited.

## Troubleshooting

- **A monitoring agent's eBPF probes fail after the lock.** `bpf_lock_tracing` refuses tracing programs once locked; load them before locking or turn the knob off.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_perf_bpf`, `t_lock`.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
