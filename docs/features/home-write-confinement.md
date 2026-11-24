<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Home-write confinement

## Overview

Confine non-sudo writes to home + scratch/device trees + an allowlist. Opt-in (aggressive). Built on `file_open` + the `path_*` hooks; both source versions used a `path_permission` hook that does not exist. (feature #4)

## How it works

Write-only restriction outside home + configured allow paths. Off by default. Exec control lives in #12.

**Code:** [`kernel/security/secure_sudo/ss_home.c`](../../kernel/security/secure_sudo/ss_home.c).

## How it is secure

**Threat:** a non-sudo user or service account plants files outside its home: in world-writable or wrongly group-writable directories, to persist or to attack other users.

**Standards:** NIST AC-3, AC-6; CWE-732.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `block_home_write=1` (off by default); `home_map` for every user (written by `secure-sudo load`); `home_write_allow` for legitimate places (mail spool, cron spool, application data).

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `block_home_write`.

**Policy files:** [home_map.conf](../files/home_map.md), [home_write_allow.conf](../files/home_write_allow.md).

**Commands:** [secure-sudo-load](../commands/secure-sudo-load.md), [secure-sudo-set](../commands/secure-sudo-set.md).

```sh
sudoedit /etc/secure_sudo/home_map.conf            # user -> writable home
sudoedit /etc/secure_sudo/home_write_allow.conf    # extra writable prefixes
sudo secure-sudo lint && sudo secure-sudo load
sudo secure-sudo set block_home_write 1             # opt-in
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

`/tmp`, `/var/tmp`, `/dev/shm`, `/dev`, `/run`, `/proc`, `/sys` and `/var/lock` stay writable (the dangerous parts of `/dev` and `/sys` are #3's job). Writes a privileged service makes on the user's behalf (D-Bus services, spoolers, cron) are not confined. Files opened before the knob was turned on stay writable. Admin-group members are exempt. It breaks programs that write elsewhere, which is why it is opt-in.

## Troubleshooting

- **An application cannot write its cache or lock file.** Add its prefix to `home_write_allow.conf` and reload; this control is aggressive and off by default.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_home` (write and mkdir outside home denied at mode 0777, inside home and `/tmp` allowed, root, allowlist).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
