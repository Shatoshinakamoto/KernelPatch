<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# RadioGuard

## Overview

**RadioGuard:** Wi-Fi / Bluetooth lockdown + `ethernet_only` master switch (refuses wireless/BT modules by file and module name, `AF_BLUETOOTH` sockets, `/dev/rfkill` writes). `secure-sudo radio ...` (feature #19)

## How it works

**Matching:** the core Wi-Fi/Bluetooth module names, checked against the file name and, since P1-5, the **module's own name** (a renamed copy, a compressed module and `init_module` are caught); `AF_BLUETOOTH` sockets; writes to `/dev/rfkill`.

**Code:** [`kernel/security/secure_sudo/ss_radio.c`](../../kernel/security/secure_sudo/ss_radio.c).

## How it is secure

**Threat:** Wi-Fi or Bluetooth as a way in or out on a machine that should be wired-only.

**Standards:** NIST AC-18, AC-18(3), SC-40, CM-7; CWE-284.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** the knobs set by `secure-sudo load` at early boot, before radio modules load; radio drivers built as modules; rfkill.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `block_wifi`, `block_bluetooth`, `ethernet_only`.

**Commands:** [secure-sudo-radio](../commands/secure-sudo-radio.md).

```sh
sudo secure-sudo radio wifi off
sudo secure-sudo radio bluetooth off
sudo secure-sudo radio ethernet-only on
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

Drivers built into the kernel are never loaded, so only the rfkill layer applies. A radio already up this boot stays up until `rfkill block` or a reboot. Other radios (LTE modems, Zigbee, SDR) are not covered.

## Troubleshooting

- **Wi-Fi does not come back after `on`.** Modules refused while off are not reloaded by themselves; reload the driver or reboot.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_radio` (socket for non-sudo and root, rfkill write refused and read allowed, module names including `.ko.zst` and dash spellings, a renamed copy of `mac80211_hwsim` refused by its module name via `finit_module` and `init_module`, `ethernet_only`); HARDWARE_SMOKE_TEST.md §5 for real radios.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
