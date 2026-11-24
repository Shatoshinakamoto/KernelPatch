<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `secure-sudo health [--json]`

Every `secure-sudo` command is **root only**, except the read-only `lint`
(which skips the checks that need root) and `evidence-verify`. Once the one-way lock is engaged,
every write is refused with `EPERM` until the next reboot; reads (`status`,
`get`, `list`) keep working. See the
[command reference](../COMMANDS.md) for the full list.

report whether secure_sudo is active, whether the configured kernel audit feed
and root-owned mode-0600 daemon heartbeat/metrics are active and fresh, whether
configured kernel settings match their live values, whether local log writes
failed, whether event or forwarding queues have reported loss, and whether
log retention is active or held for an investigation. It also
reports the last `load` outcome
and its accepted, rejected and skipped counts. Refused or partial loads degrade
health; the root-owned mode-0600 result is atomically updated after each load
and bound to the current boot ID, so a result from a previous boot is stale.
The result includes rejected setting names (up to eight, with an omitted count)
without persisting their configured values or error text.
Missing or untrusted load status is reported as unknown and degrades health.
Exit status is zero only when all available checks are healthy. `--json` emits
a machine-readable object for monitoring; unavailable loss counters are
`null`, never treated as zero.
An active `/var/lib/secure_sudo/retention.hold` marker suspends age- and
size-based log deletion; health reports `held`, while an invalid marker
reports `hold_error` and degrades health. See
[`INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) for the preservation procedure.

```sh
sudo secure-sudo health
sudo secure-sudo health --json
```

This is an initial health view, not a complete fleet-health or collector
delivery guarantee. It reports UDP send errors and labels successful
`sendto` calls `udp_unconfirmed`; configured UDP forwarding remains degraded.
TLS queue state and loss are reported, but successful TLS writes are also
unconfirmed at the collector-application level. The JSON includes
`addon_health` plus the load, active and enabled states of optional add-on
services and timers installed by `temporary/`. Disabled optional units do not
degrade health; enabled units that failed to start do. If systemd status cannot
be queried, add-on health is `unavailable` and the overall result is degraded.
Timer entries include their last trigger time and the associated scan service's
last exit time, result, and exit status; a failed scan or enabled timer with no
successful scan in the preceding 26 hours degrades health. DriverGuard,
BootGuard and BiosGuard timer
entries also report baseline age. An enabled scan timer with no root-owned
regular baseline, a baseline older than 30 days, or a future timestamp
degrades health.

## Related

- [Command reference](../COMMANDS.md)
- [Configuration](../CONFIGURATION.md) and [docs/configuration/](../README.md)
