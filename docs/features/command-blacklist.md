<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Command blacklist

## Overview

Command blacklist, matched by device + inode, path, and content (SHA-256 of each entry, so a renamed copy is refused too). (feature #2)

## How it works

Deny non-sudo opens of `/dev/mem`, `/dev/port`, `/dev/mtd*`, `/dev/mei*`, and writes to efivars/firmware sysfs (`file_open`). The installer also enables kernel lockdown (integrity).

**Matching:** the path, the inode (a rename or hard link), and since P1-5 the **content**: each entry's SHA-256 and size are taken at load, and a same-size program is hashed at exec, so an exact copy at a new path is refused. Only same-size files are hashed.

**Code:** [`kernel/security/secure_sudo/ss_exec.c`](../../kernel/security/secure_sudo/ss_exec.c).

## How it is secure

**Threat:** a non-sudo user runs a specific installed program the administrator forbids (a compiler, `nc`, a debugger).

**Standards:** NIST CM-7, CM-7(2) (prevent program execution); CWE-284.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** absolute paths that exist when the list is loaded. Reload the list after an upgrade replaces a listed program, so its new contents are fingerprinted.

**Policy files:** [blacklist.conf](../files/blacklist.md).

**Commands:** [secure-sudo-load](../commands/secure-sudo-load.md), [secure-sudo-list](../commands/secure-sudo-list.md).

```sh
echo /usr/bin/nc | sudo tee -a /etc/secure_sudo/blacklist.conf
sudo secure-sudo lint && sudo secure-sudo load
sudo secure-sudo list blacklist
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

A copy with changed bytes is a different program and runs (use TimeVault, an allowlist, for that). Interpreters read scripts as data: blacklisting a script does not stop `sh script`. The same job done by another program is not covered. Admin-group members and root are exempt.

## Troubleshooting

- **A blacklisted program runs again after an upgrade.** The upgrade replaced it; `secure-sudo load` again so the new contents are fingerprinted.
- **`load` fails with E2BIG.** More than 1024 entries; the kernel refuses the whole list and keeps the old one ([files/blacklist.md](../../files/blacklist.md)).
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_blacklist` (path, hard link, exact copy, changed copy, root, cleared list, events), `t_concurrency`.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
