<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# BinaryVault

## Overview

**BinaryVault:** freeze every executable + shared library (write/truncate/unlink/rename/hardlink/chmod/xattr) for all UIDs incl. root. Updates via a `secure_sudo.binvault_maint=1` maintenance reboot. See [docs/BINARYVAULT.md](../BINARYVAULT.md). (feature #17)

## How it works

One `install.sh` + one playbook, covering the Debian/Ubuntu, Fedora/RHEL, Arch and openSUSE families and detecting derivatives through `ID_LIKE`.

**Code:** [`kernel/security/secure_sudo/ss_binvault.c`](../../kernel/security/secure_sudo/ss_binvault.c).

Full write-up: [BINARYVAULT.md](../BINARYVAULT.md).

## How it is secure

**Threat:** tampering with installed programs and libraries for persistence, by any UID including root.

**Standards:** NIST SI-7, CM-5, CM-14; STIG SRG-OS-000480 / CCI-001749; CWE-494.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `binaryvault=1` (installed default 0, opt-in); `CONFIG_SECURITY_PATH`; a maintenance boot for updates.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `binaryvault`.

**Policy files:** [binvault_allow.conf](../files/binvault_allow.md).

**Commands:** [secure-sudo-set](../commands/secure-sudo-set.md).

```sh
sudo secure-sudo set binaryvault 1
# updates: reboot once with secure_sudo.binvault_maint=1
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

New files are not blocked: a new program can be written and run unless #12 or #13 stops it. A hard link made before the vault engaged, and a filesystem mounted over a system directory, are left to TimeVault. What counts as a program: a regular file with an execute bit, or a `.so` under a library tree; scripts without `+x`, configuration files and libraries elsewhere are not covered. The maintenance boot parameter is on the kernel command line (§4.4). Package updates and IMA/EVM relabelling are refused while it is on.

## Troubleshooting

- **Package updates fail.** BinaryVault freezes every executable and library; update in a `secure_sudo.binvault_maint=1` maintenance boot.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_binvault` (root cannot write, unlink, rename, hard-link, chmod or set an xattr on a program; libraries covered; data files and new files not; programs still run; allowlist; off again).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
