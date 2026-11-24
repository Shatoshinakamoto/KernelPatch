<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# TPM clear block

## Overview

Block TPM clear: `ppi/request` for everyone unless booted with `secure_sudo.tpm_maint=1`; once locked, only `tpm_openers` programs may open `/dev/tpm*`; the installer sets a TPM lockout password (shown once) and `disableClear`. (feature #5)

## How it works

Deny writes to `tpm*/ppi/request` for everyone, root included. It's unlocked only by the boot parameter `secure_sudo.tpm_maint=1`. Once locked, only programs on `tpm_openers` may open `/dev/tpm*`, and the installer sets a TPM lockout password and `disableClear` (THREAT_MODEL.md gap G4).

**Code:** [`kernel/security/secure_sudo/ss_tpm.c`](../../kernel/security/secure_sudo/ss_tpm.c).

## How it is secure

**Threat:** anyone, root included, schedules a TPM clear through the Physical Presence Interface (`echo 5 > /sys/class/tpm/tpm0/ppi/request`), wiping TPM-sealed disk keys at the next boot.

**Standards:** NIST SI-7, SC-12, CM-5; CWE-284.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** a TPM whose PPI is in sysfs; normal boots without `secure_sudo.tpm_maint=1`.

**Policy files:** [tpm_openers.conf](../files/tpm_openers.md).

**Commands:** [install-sh](../commands/install-sh.md), [secure-sudo-list](../commands/secure-sudo-list.md).

```sh
sudo ./install/install.sh tpm-lockout     # lockout password (shown once) + disableClear
sudo secure-sudo list tpm_openers
# planned TPM maintenance: boot once with secure_sudo.tpm_maint=1
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

Before the lock, root can open the device and, if the lockout password was never set (or root knows it), clear the TPM. A program on `tpm_openers` can send any command, clear included, if it has the lockout password. The guard knows the TPM major only with `CONFIG_TCG_TPM=y` (the installer builds it in); with `=m` only `/dev/tpm0` is guarded. A TPM whose lockout password was already set is left alone. The firmware setup menu can always clear the TPM.

## Troubleshooting

- **A TPM tool fails after the lock.** Only programs on `tpm_openers.conf` may open `/dev/tpm*` once locked; add it before locking, or reboot to change the list.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** the in-kernel tests (`t_tpm_prepare`, `t_tpm_locked`: TPM device nodes made with `mknod`; unlocked any program reaches the driver, locked an unlisted one is refused for both tpmrm and tpm0 while a listed one is not, the list is frozen, the refusal is logged); `tests/install/test-install.sh` (`tpm-lockout` with stand-in tpm2-tools); the Ubuntu VM run with a software TPM (lockout password and `disableClear` set, `tpm2_clear` refused with and without the password). The PPI route: HARDWARE_SMOKE_TEST.md §3 (harmless request `0` as root is refused and logged). The denial is logged as a `tpm_guard` event since P1-5.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
