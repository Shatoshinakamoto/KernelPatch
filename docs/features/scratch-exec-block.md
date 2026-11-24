<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Scratch-tree exec block

## Overview

Restrict exec and `PROT_EXEC` mmap from `/tmp`, `/var/tmp`, `/dev/shm`. (feature #12)

## How it works

Deny exec and `PROT_EXEC` mmap from those trees unless they're allowlisted (`bprm_check_security`, `mmap_file`).

**Code:** [`kernel/security/secure_sudo/ss_tmpexec.c`](../../kernel/security/secure_sudo/ss_tmpexec.c).

## How it is secure

**Threat:** download-and-run from `/tmp`, `/var/tmp` or `/dev/shm` by a non-sudo process; with `block_tmpfs_exec`, fileless `memfd` exec and exec from any tmpfs.

**Standards:** NIST CM-7, SI-3; STIG SRG-OS-000480 (noexec on temporary storage); CWE-434.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `block_tmp_exec=1` (default); `block_tmpfs_exec=1` for memfd and every tmpfs (off by default).

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `block_tmp_exec`, `block_tmpfs_exec`.

**Policy files:** [tmp_exec_allow.conf](../files/tmp_exec_allow.md).

**Commands:** [secure-sudo-load](../commands/secure-sudo-load.md).

```sh
sudo secure-sudo get block_tmp_exec
sudoedit /etc/secure_sudo/tmp_exec_allow.conf && sudo secure-sudo load
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

Interpreters read scripts as data (`sh /tmp/x`, `python3 /tmp/x.py` run). Other user-writable places (home, application directories) are not covered: use #4 or #13. A `PROT_EXEC` mapping of a memfd is allowed on purpose (JIT compilers). Admin-group members are exempt.

## Troubleshooting

- **An installer that runs from /tmp fails.** Run it from another directory, or add its path to `tmp_exec_allow.conf`.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_tmpexec` (exec and mmap from `/tmp`, root, allowlist, memfd with and without `block_tmpfs_exec`, events).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
