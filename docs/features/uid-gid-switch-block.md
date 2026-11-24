<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# UID/GID switch block and user-namespace gate

## Overview

Block non-sudo UID/GID switching (setuid/setgid/setgroups) and unprivileged user namespaces. **1b:** deny non-sudo exec of setuid/file-cap binaries unless allowlisted. (feature #1)

## How it works

`task_fix_setuid` + `task_fix_setgid` + `task_fix_setgroups`. "Sudo user" means root, or a member of a configurable admin GID (sudo/wheel). Also gate unprivileged user namespaces (`userns_create`), since those are the usual way around UID checks.

**Code:** [`kernel/security/secure_sudo/ss_creds.c`](../../kernel/security/secure_sudo/ss_creds.c).

## How it is secure

**Threat:** a non-sudo process that holds or obtains `CAP_SETUID` or `CAP_SETGID` (a misconfigured service, a file capability, a leaked capability) switches to another user or to root; a non-sudo user creates a user namespace to get namespaced root and the kernel attack surface that comes with it.

**What you see when it acts:** a `credential_change` event per denial (`operation` is `setuid`, `setgid`, `setgroups` or `userns_create`), severity critical, forwarded and alerted on ([EVENTS.md](../EVENTS.md)). At most 20 per 5 s are recorded; the next record says how many were not.

**Standards:** NIST AC-6, AC-6(10) (non-privileged users cannot run privileged functions), CM-7; STIG SRG-OS-000324 / CCI-002235; CWE-269, CWE-250.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `block_setid=1` and `block_userns=1` (defaults); `admin_gid` set to the real admin groups.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `block_setid`, `block_userns`, `admin_gid`.

**Commands:** [secure-sudo-detect-admins](../commands/secure-sudo-detect-admins.md), [secure-sudo-set](../commands/secure-sudo-set.md).

```sh
sudo secure-sudo get block_setid          # 1 = on (default)
sudo secure-sudo detect-admins -n         # preview the admin groups
sudo secure-sudo detect-admins            # set admin_gid from sudoers
sudo secure-sudo set block_userns 1
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

It does not stop gaining privilege by *running* a setuid or file-capability program (that is #1b, off by default), or sudo/su with a valid password. Admin-group members are exempt. `block_userns` breaks rootless containers and some sandboxes (§4.1). A kernel bug reachable without a user namespace is not affected.

## Troubleshooting

- **A rootless container, Flatpak or browser sandbox fails to start for a normal user.** That needs unprivileged user namespaces. Either run it as an admin-group member, or `sudo secure-sudo set block_userns 0` on that host (§4.1 of the threat model).
- **A real administrator is refused.** Their group is not in `admin_gid`. Run `sudo secure-sudo detect-admins` after creating admin groups.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_creds` (denial with the capability held, and its `credential_change` event; no-op change allowed, admin GID, root, knob off; user namespaces for non-sudo, root and knob off) and `tests/vm/distro/alert-trace-guest.sh` (the event traced to a collector and an alert).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
