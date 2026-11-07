<!-- SPDX-License-Identifier: Apache-2.0
     SPDX-FileCopyrightText: 2026 Johnathan Edward Brown -->
# Events, severity and alerts

This page covers how a secure_sudo event travels from the kernel to the
people who need to see it (TODO P2-3):

* the record formats;
* how a severity is assigned to each record;
* how records are forwarded, and what a SIEM sees;
* when an alert runs, and how duplicates, floods and failures are handled;
* how to trace one test event end to end.

## 1. The path of an event

```
kernel hook ──> event ring ──> secure-sudod ──┬─> local log (/var/log/secure_sudo, hash-chained)
 (ss_log.c)    (securityfs,     (drains it,   ├─> collector (UDP, or RFC 5425 TLS with a disk queue),
               0400, seq per    acts on it)   │   syslog priority set from the severity
               boot)                          └─> alert_cmd for records at alert_min_severity or above
 (optional) ──> kernel audit (audit_events = 1): AUDIT_KERNEL_OTHER records for auditd
```

The `temporary/` add-ons have a path of their own. Each one writes its own
log, can forward it with `remote_enabled` in `logging.conf`, and runs
`notify_cmd` for notable events ([ADDONS.md](ADDONS.md)). PheonixBox logs
through `syslog(3)`.

## 2. Record formats

All records are one JSON object per line.

* **Kernel records** use schema v1:
  * fields: `schema_version`, `boot_id`, `sequence`, `realtime_ns`,
    `monotonic_ns`, `event_type`, `actor{pid,uid,kernel_started}`, `target`,
    `operation`, `object`, `decision` (`deny`, `allow`, `observe` or
    `enforce`), `reason`, `target_pid`, `target_uid`, `message` and
    `truncated`;
  * the field reference is in
    [INTEGRATION.md](../kernel/security/secure_sudo/INTEGRATION.md);
  * `sequence` has no gaps unless records were lost, and the daemon reports
    any loss itself (`event_gap`).
* **Daemon records** have `"source":"secure-sudod"`, `realtime_ns`,
  `event_type` and fields of their own. The types are listed with their
  severities in section 3.
* **Plain lines** (`secure-sudod started`, configuration reloads) are not
  records. They are forwarded with severity `low`.

Consumers should act on the typed fields, never on `message`. Paths and
process names in a message are chosen by users. The daemon itself only acts
on typed fields: it takes the UID to kill from `target_uid` and the
TimeVault path from `object`.

## 3. Severity

Every record gets one of `info`, `low`, `medium`, `high` or `critical`. The
severity is worked out from `event_type` and `decision`, never from the
message text.

| Event type | `deny` | other decisions |
|---|---|---|
| `credential_change` (a non-sudo UID/GID/groups change or user-namespace creation, #1) | critical | low |
| `configuration_lock` (a change refused after the lock, #16) | critical | info |
| `firmware_guard` (#3), `tpm_guard` (#5) | critical | low |
| `setid_exec` (#1b), `driver_blacklist` (#2/#6), `binary_vault` (#17), `time_vault` (#13), `process_runtime_guard` (#20) | high | low |
| `sudo_cooldown` (#8) | high | high |
| `bpf`, `perf` (#22), `command_blacklist`, `tmp_exec` (#12), `home_write` (#4), `node_guard` (#11), `network_guard` (#10), `radio_guard` (#19), `sysctl_guard` (#23) | medium | low |
| `ram_guard` (#7) | low | low |
| `policy_measurement`, `event_log` | info | info |
| any other kernel type | medium | low |

Daemon records (they have no decision):

| Record | Severity | Meaning |
|---|---|---|
| `log_modified` | critical | a local log no longer matches its hash chain |
| `timevault_manifest_modified` | critical | the TimeVault manifest was changed outside the daemon |
| `event_gap`, `event_sequence_error` | high | kernel records were lost, or the sequence went backwards |
| `timevault_manifest_unreadable`, `timevault_disengaged` | high | TimeVault lost its baseline, or was turned off |
| `alert_failed`, `alert_rate_limited` | medium | an alert could not be delivered (section 5) |
| `event_stream`, `log_checkpoint`, `timevault_baseline`, `timevault_merkle` | info | bookkeeping and anchors |

`observe` means "would have denied" (monitor mode). It is `low` so that a
monitor-mode soak does not page anyone, but it is still logged and
forwarded.

## 4. Forwarding and syslog priority

Each forwarded record is the original line, unchanged, so the hash chain and
evidence exports still match. Its syslog PRI is facility `authpriv` (10)
with a syslog severity taken from ours:

| Ours | syslog severity | PRI |
|---|---|---|
| critical | crit (2) | 82 |
| high | err (3) | 83 |
| medium | warning (4) | 84 |
| low | notice (5) | 85 |
| info | info (6) | 86 |

A collector can therefore route on priority alone. For example, send
`authpriv.err` and above to on-call and everything else to storage, without
parsing JSON. The transports, the TLS queue and its limits are described in
[CONFIGURATION.md](CONFIGURATION.md#logging--retention-9).

## 5. Alerts

Set these in `/etc/secure_sudo/secure-sudo.conf`. `secure-sudo lint` checks
them, and the daemon reads them at start and on `SIGHUP`.

| Key | Default | Meaning |
|---|---|---|
| `alert_cmd` | *(empty: off)* | Command to run for each alert. Runs without a shell (see below). |
| `alert_min_severity` | `high` | Lowest severity that alerts. |
| `alert_dedup_seconds` | `300` | Repeats of the same alert within this window are counted, not run (0 to 86400). |
| `alert_max_per_minute` | `10` | At most this many alerts run per minute (1 to 600). |
| `alert_timeout_seconds` | `10` | A command still running after this long is killed (1 to 300). |

**No shell.** `alert_cmd` is split into words: single and double quotes
group, and a backslash escapes the next character. The result is run with
`execvp`. A first word without a slash is looked up in a fixed `PATH`
(`/usr/local/sbin` … `/bin`), never the daemon's environment. Placeholders
inside a word are replaced by the record's values, with control bytes
written as `\xNN`:

| Placeholder | Value |
|---|---|
| `%s` | severity |
| `%t` | event type |
| `%d` | decision |
| `%r` | reason |
| `%o` | object |
| `%u` | target UID |
| `%m` | message |
| `%j` | the whole JSON record |
| `%h` | host name |
| `%n` | alerts held back as duplicates since the last one |
| `%%` | a literal `%` |

**Sandbox.** The command runs as root inside secure-sudod's systemd sandbox
(`secure-sudod.service`): `ProtectHome=yes` hides `/home`, `/root` and
`/run/user`, and `NoNewPrivileges=yes` means setuid or setgid helpers (for
example a `sendmail` that hands mail to a setgid `postdrop`) do not gain their
privileges. Have it write under `/run`, `/var` or `/tmp`, or send over the
network, or relax the unit with a drop-in if you must.

A path or process name in a record, such as `$(reboot)` or `; rm -rf /`,
reaches the command as text. Pipes, redirects and `$VARS` do not work in
`alert_cmd` itself; to use them, point `alert_cmd` at a script. Example:

```
alert_cmd = /usr/local/sbin/page-oncall %s %t "%h: %m" %j
```

**Duplicates.** Two alerts are the same when they share event type,
operation, decision, reason, object and target UID. A repeat within
`alert_dedup_seconds` is counted and not run. The next one that does run
receives the count in `%n`.

**Floods.** Once `alert_max_per_minute` alerts have run in a minute, or four
commands are already running, further alerts are dropped. Each minute that
dropped any ends with an `alert_rate_limited` record (`dropped`,
`window_seconds`, `max_per_minute`). That record is logged and forwarded,
so a flood is visible at the collector even when the pager went quiet. The
kernel limits the core `credential_change` records to 20 per 5 s, so one
user cannot flush other records out of the ring. Each record says how many
earlier denials were not recorded.

**Failures.** An `alert_failed` record is written when the command:

* cannot start (`could_not_start`);
* exits non-zero (`exited_nonzero`, with `status`);
* runs past the timeout (`timed_out`; it is killed).

The record carries `alert_for` (the event type) and the running count. It
also goes to the system log. Alert records never raise alerts themselves,
so a broken command cannot loop.

**Health.** The daemon's heartbeat carries `alert_state`
(`off`, `ok`, `failing` or `config_error`), `alerts_sent`, `alerts_failed`,
`alerts_suppressed` and `alerts_dropped`. `secure-sudo health` shows them,
and reports `degraded` while the last alert failed or `alert_cmd` was
refused.

### Add-on notifications

The add-ons' `notify_cmd` (`logging.conf`) follows the same rules. It runs
without a shell, with `%m`, `%l` and `%f`. The same message within 300 s is
sent once, and the next one says how many were held back. At most 10 run a
minute. A failure or a timeout (10 s) is logged ERROR in the add-on's log,
which is forwarded with the rest.

## 6. Integrations

Everything below consumes the forwarded syslog stream or the local files.
What is tested in this repository is marked as tested. The rest are
starting points to adapt.

* **Any RFC 5425 collector (tested).** `remote_syslog_transport = tls`
  against rsyslog, syslog-ng or a SIEM's syslog input.
  `tests/userspace/test-remote-forwarding.sh` covers TLS delivery,
  certificate checks, the queue and outages. The distro VM test sends real
  kernel records to a collector (section 7).
* **rsyslog receiver** (example):

  ```
  module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1"
         StreamDriver.AuthMode="anon")
  global(DefaultNetstreamDriverCAFile="/etc/ssl/ca.pem"
         DefaultNetstreamDriverCertFile="/etc/ssl/collector.pem"
         DefaultNetstreamDriverKeyFile="/etc/ssl/collector.key")
  input(type="imtcp" port="6514")
  if $programname == "secure_sudo" then {
      action(type="omfile" file="/var/log/fleet/secure_sudo.json" template="RSYSLOG_FileFormat")
      if $syslogseverity <= 3 then action(type="omprog" binary="/usr/local/sbin/page-oncall")
  }
  ```

* **auditd (tested in the VM).** `audit_events = 1` adds an
  `AUDIT_KERNEL_OTHER` record per kernel event (`ausearch -m KERNEL_OTHER`),
  for sites whose SIEM already reads audit logs.
* **Splunk, Elastic, Wazuh and similar** (examples). Parse the syslog
  message body as JSON, for example Splunk `KV_MODE = json` on the
  sourcetype, an Elastic `decode_json_fields` processor, or a Wazuh JSON
  decoder. Then alert on `event_type` plus `decision`, or on the syslog
  priority. Use the typed fields and `boot_id`/`sequence` (the latter to
  spot loss); do not use `message`.
* **Local scripts.** Use `alert_cmd`, which runs on the host itself.

## 7. Tracing a test event

On a host running the secure_sudo kernel, as root:

```sh
# a non-sudo user holding CAP_SETUID tries to become root: the kernel denies it
# (group first, as root: setpriv changes the UID before the GID, and the GID
# change of a non-sudo UID is itself refused, as a "setgid" record)
setpriv --regid=plain --clear-groups -- setpriv --reuid=plain --inh-caps=+setuid \
        --ambient-caps=+setuid python3 -c 'import os; os.setuid(0)'
grep '"event_type":"credential_change"' /var/log/secure_sudo/$(date +%F).log | tail -1
secure-sudo health          # Alerts: ok (1 sent, ...)
```

Then check that the collector received the record with PRI `<82>`, and that
your `alert_cmd` ran. `tests/vm/distro/alert-trace-guest.sh` does exactly
this in the distro VM test, using a local collector and an alert command
that records its arguments. It then swaps in a failing command and checks
that `alert_failed` reaches the log and the collector, and that health turns
`degraded`.

## 8. Gaps you can see

| What can go wrong | Where it shows |
|---|---|
| the ring overflowed before the daemon read it | `event_gap` record (high), `events_dropped` in health |
| the audit backlog refused a record | `audit_events_dropped` in health |
| the collector is down or refuses TLS | `remote_state`, `remote_failures`, queue size and drops in health; TLS events stay queued |
| the TLS queue is full | newest dropped and counted (`remote_queue_dropped`) |
| `alert_cmd` fails or hangs | `alert_failed` record, `alert_state=failing`, health degraded |
| an alert flood | `alert_rate_limited` record, `alerts_dropped` |
| duplicates held back | `alerts_suppressed`; the next alert's `%n` |
| a user floods credential changes | "N earlier denials not recorded" in the next `credential_change` record; the kernel's "callbacks suppressed" line in dmesg |
| a local log was edited | `log_modified` (critical), `evidence-verify` |

What is not covered: UDP delivery is unconfirmed, and a successful TLS write
does not prove the collector stored the record
([CONFIGURATION.md](CONFIGURATION.md#logging--retention-9)).
