<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# TimeVault

## Overview

**TimeVault:** hash-based exec gate with allowlist (+ auto-update entries), size cap, package-manager deny, and quarantine of blocked binaries. (feature #13)

## How it works

K: an exec allowlist (path + hash) while the vault is on, with package managers (apt, dpkg, dnf, yum, rpm, zypper, pacman, snap, flatpak) forced to deny, and a count of every denied attempt. U: the daemon keeps the Merkle tree over watched trees (a manifest taken when the vault engages; its RFC 6962 root is logged and forwarded, and `evidence-verify --timevault` checks it; built for THREAT_MODEL.md gap G2), moves new or changed files to `/var/lib/secure_sudo/quarantine/*.zip` with their metadata, and ships logs off-box. The BPF status map becomes a plain `secure-sudo status`.

**Code:** [`kernel/security/secure_sudo/ss_timevault.c`](../../kernel/security/secure_sudo/ss_timevault.c), [`userspace/daemon/secure-sudod.c`](../../userspace/daemon/secure-sudod.c), [`userspace/cli/vault_allow.c`](../../userspace/cli/vault_allow.c).

## How it is secure

**Threat:** running any program that is not approved and pinned by hash, root included, once the vault is engaged: malware, swapped binaries, unapproved installs.

**Standards:** NIST CM-7(5) (allow by exception), SI-7, SI-3, AU-9(2); CWE-494.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** an allowlist with a SHA-256 for every program the system runs (and, with `timevault_strict_mmap=1`, every shared library); those programs root-owned and not group/world-writable; `secure-sudod` for quarantine; forwarding so the record survives. Engaging latches the lock until reboot. The daemon's first scan after engaging records the watched trees as the baseline (gap G2): files already there then are trusted, so engage on a known-good system.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `vault_action`, `vault_watch`, `timevault_max_entries`, `timevault_allow_autoupdate`, `timevault_strict_mmap`.

**Policy files:** [timevault_allow.conf](../files/timevault_allow.md).

**Commands:** [secure-sudo-timevault](../commands/secure-sudo-timevault.md), [secure-sudo-vault-allow](../commands/secure-sudo-vault-allow.md), [timevault-whitelist](../commands/timevault-whitelist.md), [quarantine-sh](../commands/quarantine-sh.md).

```sh
sudo secure-sudo vault-allow scan /usr/bin /usr/sbin
sudo secure-sudo vault-allow list | head
sudo secure-sudo timevault on
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

An allowlisted interpreter (bash, python, perl) runs any script. Without `timevault_strict_mmap` (default off) shared libraries are not checked, so `LD_PRELOAD` or `dlopen` of an unlisted library runs code inside an allowed program. Auto-update entries (`timevault_allow_autoupdate`, default on) skip the hash: anything written into an auto-update directory runs. Package managers are refused by program name. Code already running when the vault engages keeps running. Code generated in memory inside an allowed process is #20's concern. Quarantine is done by the daemon after the denial (the program does not run either way). It cannot be turned off until reboot; follow the TODO's caution and test it off production first.

## Troubleshooting

- **A program is refused while the vault is on.** It is not on the allowlist or its hash changed; `vault-allow add PATH` before engaging.
- **Package installs fail.** By design: package managers are denied while TimeVault is engaged, and engaging latches the lock until reboot. Reboot, update, rescan with `vault-allow scan`, then engage again.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_timevault_prepare` and `t_timevault` (empty list refused without locking, matching hash runs, unlisted and changed binaries refused for root too, package manager refused even with its hash, memfd refused, listed binary cannot be opened for writing, event, counter, cannot disengage); `test-daemon-events.sh` (quarantine path checks, SECURITY_REVIEW #48 and #52; the baseline, rescans, the Merkle root, a rewritten or deleted manifest, #60); `test-evidence-export.sh` (`--timevault` against the collector's roots).
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
