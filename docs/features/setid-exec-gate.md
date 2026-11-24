<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Setuid and file-capability exec gate

## Overview

Deny non-sudo users exec of setuid and file-capability programs, except an allowlist, so a bug in one of those programs (the PwnKit, Baron Samedit, Looney Tunables class) is not a way to root. (feature #1b)

## How it works

**Code:** [`kernel/security/secure_sudo/ss_creds.c`](../../kernel/security/secure_sudo/ss_creds.c), [`kernel/security/secure_sudo/ss_exec.c`](../../kernel/security/secure_sudo/ss_exec.c).

## How it is secure

**Threat:** a non-sudo user escalates through a setuid-root or file-capability program (the PwnKit, Baron Samedit, Looney Tunables class).

**Standards:** NIST AC-6, CM-7(5) (allow by exception); CWE-269, CWE-250.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `block_setid_exec=1` and `setid_exec_allow` listing the setuid programs users really need. Off by default.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `block_setid_exec`.

**Policy files:** [setid_exec_allow.conf](../files/setid_exec_allow.md).

**Commands:** [secure-sudo-set](../commands/secure-sudo-set.md), [secure-sudo-load](../commands/secure-sudo-load.md).

```sh
sudoedit /etc/secure_sudo/setid_exec_allow.conf     # e.g. /usr/bin/passwd, /usr/bin/sudo
sudo secure-sudo lint && sudo secure-sudo load
sudo secure-sudo set block_setid_exec 1
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

Off by default. A bug in an allowlisted setuid program (sudo, passwd) is not stopped. Matching is by path. A wrong allowlist locks users out of passwd/su (recovery exercises E1, E2).

## Troubleshooting

- **Users can no longer run `passwd`, `su` or `sudo`.** Add the program to `setid_exec_allow.conf` and `secure-sudo load`; recovery exercises E1 and E2 in [RECOVERY.md](../../RECOVERY.md).
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_setid_exec`; recovery exercises E1 and E2 in the Ubuntu guest.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
