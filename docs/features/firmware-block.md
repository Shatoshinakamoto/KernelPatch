<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Firmware, flash and raw-memory block

## Overview

Block non-sudo firmware/flash access: `/dev/mem`, `/dev/port`, `/dev/mtd*`, `/dev/mei*`, and `/sys/firmware` writes. (feature #3)

## How it works

The CLI loads `/etc/secure_sudo/blacklist.conf` into securityfs. The kernel matches by inode, path and content (SHA-256 + size, taken at load) rather than basename, so renaming a binary or copying it to a new path doesn't get around it (a copy with changed bytes is a different program: SECURITY_REVIEW #56).

**Code:** [`kernel/security/secure_sudo/ss_firmware.c`](../../kernel/security/secure_sudo/ss_firmware.c).

## How it is secure

**Threat:** a non-sudo process with a leaked `CAP_SYS_RAWIO` or loose device permissions reads or writes physical memory, flashes SPI/MTD/ME firmware, or writes EFI variables.

**Standards:** NIST SI-7 (firmware integrity), AC-6, SC-3; CWE-284.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `block_flash=1` (default); the standard device numbers and `/sys/firmware` layout.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `block_flash`.

**Commands:** [secure-sudo-get](../commands/secure-sudo-get.md).

```sh
sudo secure-sudo get block_flash
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

Root and admin-group members are not blocked; root is stopped only by the lock (#16) and kernel lockdown. Firmware paths through other devices (NVMe admin commands, GPU or vendor ioctls, a BMC) are not covered.

## Troubleshooting

- **A firmware update tool run by a normal user fails.** Run it with sudo; admin-group members are exempt.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_firmware` (`/dev/mem` at mode 0666 with `CAP_SYS_RAWIO`, root, knob off, event). `/dev/mtd*`, `/dev/mei*` and efivars: no such devices in the VM; HARDWARE_SMOKE_TEST.md §4.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
