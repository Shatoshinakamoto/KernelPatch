<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Driver blacklist (anti-BYOVD)

## Overview

Driver blacklist / anti-BYOVD: file SHA-256 + file name checked at load, and the module's own name checked before its init runs (catches renamed and compressed copies and `init_module(2)`). (feature #6)

## How it works

`kernel_read_file`/`kernel_load_data` (module), matched by SHA-256 and by name (the file name and the module's own name, so a renamed file is caught: SECURITY_REVIEW #56). The installer enforces module signing for real: the playbook's `options module.sig_enforce=1` in modprobe.d does nothing, so it becomes a kernel parameter.

**Matching:** the SHA-256 of the exact bytes loaded (`finit_module` and `init_module`); a name entry against the file name and, since P1-5, against the **module's own name** (checked just before its init code runs, so a renamed file, a compressed module and `init_module` with no file are all caught).

**Code:** [`kernel/security/secure_sudo/ss_driver.c`](../../kernel/security/secure_sudo/ss_driver.c).

## How it is secure

**Threat:** root, or an installer running as root, loads a known-vulnerable or malicious signed driver to get code into the kernel ("bring your own vulnerable driver").

**Standards:** NIST CM-7(5), SI-7, CM-11; CWE-829.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `driver_blacklist` with the SHA-256 of known-bad module files and/or module names; module signatures enforced (installer); the lock with `lock_modules=1` for "no new modules at all".

**Policy files:** [driver_blacklist.conf](../files/driver_blacklist.md).

**Commands:** [secure-sudo-load](../commands/secure-sudo-load.md), [secure-sudo-list](../commands/secure-sudo-list.md).

```sh
sha256sum /path/to/vulnerable.ko | sudo tee -a /etc/secure_sudo/driver_blacklist.conf
sudo secure-sudo lint && sudo secure-sudo load
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

A blacklist knows only the drivers you list; any other vulnerable but validly signed driver loads. A recompressed or re-signed module has a different file hash (a name entry still catches it). Built-in drivers are never loaded, so never checked. Root can clear the list before the lock.

## Troubleshooting

- **A module you need is refused.** Remove its hash or name from `driver_blacklist.conf` and reload; check `dmesg` for the secure_sudo denial.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_modules` (name via `finit_module` and `init_module`, a renamed copy, hash via both calls, cleared list), `t_lock` (`lock_modules`).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
