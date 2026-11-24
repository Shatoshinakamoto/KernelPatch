<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# Events, logging, forwarding and evidence

## Overview

Versioned JSON security events with per-boot sequence/clock/actor metadata and visible ring/audit loss counters; the daemon writes dated, rotated logs. `secure-sudo health` reports loss and component status; `evidence-export` creates hash-chained, optionally externally signed bundles. (feature #9)

## How it works

The kernel emits events to a securityfs ring. The daemon writes `/var/log/secure_sudo/YYYY-MM-DD.log` with a wall-clock timestamp, enforces `retain_days` + `max_total_mb`, and can forward to a remote syslog (TimeVault needs that).

**Code:** [`kernel/security/secure_sudo/ss_log.c`](../../kernel/security/secure_sudo/ss_log.c), [`userspace/daemon/secure-sudod.c`](../../userspace/daemon/secure-sudod.c), [`userspace/daemon/helpers/`](../../userspace/daemon/helpers/).

Full write-up: [EVENTS.md](../EVENTS.md).

## How it is secure

**Threat:** an attacker hides their activity by erasing, forging or flooding the record.

**Standards:** NIST AU-2, AU-3, AU-4(1), AU-6, AU-9, AU-9(2), AU-10, AU-11, AU-12; STIG SRG-OS-000037 / CCI-000130; CWE-117.

Enforced in the kernel LSM. Its settings and lists are root-only, and the [one-way lock](config-lock.md) freezes them until reboot, so root cannot quietly switch it off on a locked host. The general model and what it does not defend against: [THREAT_MODEL.md](../THREAT_MODEL.md).

## How to use it

**Needs:** `secure-sudod` running; TLS forwarding to a collector for records to survive a root compromise; `audit_events=1` for auditd; `secure-sudo evidence-export` for incident bundles.

**Settings** ([secure-sudo-conf.md](../configuration/secure-sudo-conf.md)): `audit_events`, `retain_days`, `max_total_mb`, `remote_syslog`, `remote_syslog_transport`, `remote_syslog_ca_file`, `remote_queue_max_mb`, `alert_cmd`.

**Commands:** [secure-sudod](../commands/secure-sudod.md), [secure-sudo-health](../commands/secure-sudo-health.md), [secure-sudo-evidence-export](../commands/secure-sudo-evidence-export.md), [secure-sudo-evidence-verify](../commands/secure-sudo-evidence-verify.md).

```sh
sudo secure-sudo health
sudo secure-sudo evidence-export /root/incident.tar.gz
secure-sudo evidence-verify /root/incident.tar.gz
```

## Dependencies

| Name | Version | Purpose | CVE check |
|---|---|---|---|
| Linux kernel | 6.12 LTS (6.12.114 tested) | the LSM is built into it | kernel CVEs are tracked per LTS point release ([MAINTENANCE.md](../MAINTENANCE.md)); not checked for this page |

The release SBOM (`scripts/gen-sbom.sh`) lists exact versions. Run `apt list --installed` / `rpm -q` and your distro's security tracker (for example `ubuntu-security-status`) for the live CVE status.

## Limitations and known risks

The ring is 64 KiB; a local user can flood it with denials, and the overflow is counted but lost. Root can stop the daemon and delete local logs. Records show UIDs, PIDs, program names and paths ([INTEGRATION.md](../../kernel/security/secure_sudo/INTEGRATION.md), "What a record can reveal"). An evidence signature proves the bundle has not changed since export, not that the events in it are true. Denials made by DAC or another LSM before secure_sudo are not recorded by secure_sudo. Until P1-5, #2, #3, #5, #10 and #12 denials reached only the kernel log (SECURITY_REVIEW #54).

## Troubleshooting

- **`health` reports event loss.** The ring or the forwarding queue overflowed; see the loss counters in [EVENTS.md](../../EVENTS.md) and check the collector.
- **Nothing reaches the collector.** Check `remote_syslog`, the transport and the CA file; `health` shows the forwarding state.
- **It does nothing at all.** Check that the secure_sudo kernel is running (`cat /sys/kernel/security/lsm` lists `secure_sudo`), that the setting is on (`secure-sudo status`), and whether the user is exempt (the Limitations above say who is).

More: [RECOVERY.md](../RECOVERY.md).

## Test evidence

**Tests:** `t_events` (schema, sequence, ordering, loss counters, a 20,000-record burst, audit feed, kernel-started helpers) and the event checks in every control test; `test-daemon-events.sh`, `test-remote-forwarding.sh`, `test-evidence-export.sh`.
- In-kernel functional tests on 6.12.114, 305/0: [`HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/`](../../HistoryTest/runs/2026-11-23_215527Z_vm-functest_aaffc26/)
- Full build gate (every host suite), overall pass: [`HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/`](../../HistoryTest/runs/2026-11-23_224258Z_gate_20f89d5/)
- Whole host suite: [`HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/`](../../HistoryTest/runs/2026-11-23_220703Z_suite_2894faf/)
