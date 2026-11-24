<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Sudo brute-force cooldown

## Overview

Sudo brute-force cooldown: PAM feeds failures, the kernel blocks, the daemon kills the offender. (feature #8)

## How it works

A `pam_secure_sudo` module in the sudo/su auth stack reports failures. After N failures in the window, the kernel blocks sudo/su exec for that UID and the daemon freezes and kills the offending process tree (the `SIGSTOP` then `SIGKILL` the TODO asks for).

**Code:** [`kernel/security/secure_sudo/ss_cooldown.c`](../../kernel/security/secure_sudo/ss_cooldown.c), [`userspace/pam/`](../../userspace/pam/), [`userspace/daemon/secure-sudod.c`](../../userspace/daemon/secure-sudod.c).

## How it is secure

**Threat:** a local user, or malware in their session, guesses the sudo/su password online.

**Standards:** NIST AC-7 (unsuccessful logon attempts); STIG SRG-OS-000021 / CCI-000044; CWE-307.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `pam_secure_sudo` in the auth stack of sudo and su (installer, order fixed by SECURITY_REVIEW #37); `sudo_cooldown_enabled=1` (default); `secure-sudod` running to stop and kill the offender's sudo processes.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `sudo_cooldown_enabled`, `sudo_max_fails`, `sudo_window_sec`, `sudo_block_time_sec`.

**Commands:** [secure-sudod](../commands/secure-sudod.md), [secure-sudo-health](../commands/secure-sudo-health.md).

```sh
# one line, first in the auth section of /etc/pam.d/sudo and /etc/pam.d/su:
auth  optional  pam_secure_sudo.so
sudo secure-sudo get sudo_max_fails
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

Only failures reported through `pam_secure_sudo` count: polkit over D-Bus, ssh, the login screen, and tools without that PAM stack are not counted, and a polkit authorization that does not exec `pkexec` is not blocked. Each UID has its own budget. The table is in memory and resets at reboot. Root can clear a block (`ok <uid>`). The block stops new runs of sudo-like programs; it does not end sessions already elevated (the daemon's kill does). The distro's `pam_faillock` is the standard equivalent and can run alongside.

## Troubleshooting

- **Nothing is blocked after many wrong passwords.** The PAM line is missing or below the password include; install.sh prints the exact line. Check `secure-sudo health`.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_cooldown` (kernel: 4 failures allowed, 5th blocks sudo and any setuid-root program, other programs and users unaffected, success lifts it, block event carries `target_uid`); `tests/userspace/test-pam.sh` (PAM reports); `test-daemon-events.sh` (the daemon takes the UID from `target_uid`). The kill itself is tested against recorded events, not a live sudo session.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
