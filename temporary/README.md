# secure_sudo — temporary/ add-ons

Opt-in add-ons that sit beside the core secure_sudo stack. The core
`install.sh` does **not** touch this tree; install it deliberately:

```sh
sudo bash temporary/install-temporary.sh
```

Installing enables nothing and kills nothing — every enforcing behaviour is
opt-in and starts in a safe mode (ProcGuard in monitor, no timers enabled).

Contents:

| Dir | Binary | What it does |
|-----|--------|--------------|
| `common/` | — | shared logging (`ssaddon_log`, local + off-box syslog) and hourly-rotating compressed storage + Locus client (`ssaddon_store`) |
| `procguard/` | `secure-sudo-procguard` | kill non-allowlisted processes; quarantine + remove respawning infections |
| `driverguard/` | `secure-sudo-driverguard` | driver-file integrity + repair from hourly-rotated backups |
| `biosguard/` | `secure-sudo-biosguard` | firmware tamper **detection only**: log + notify, never writes firmware (operator decision 2026-10-26) |
| `bootguard/` | `secure-sudo-bootguard` | boot-partition tamper detection + restore **at next boot** |
| `locus/` | `secure-sudo-locus` | LAN request-only allocator for the rotating locations + read-only GUI |
| `tamperwatch/` | `secure-sudo-tamperwatch` | names (and in quarantine mode stops) the process that wrote a protected file |
| `gui/` | `secure-sudo-gui` | local management console (loopback, token-gated) |
| `failure/` | `secure-sudo-addon-failure` | reports a failed add-on unit (OnFailure=): CRITICAL log, off-box syslog, notify_cmd |
| `config/` | — | config templates copied to `/etc/secure_sudo/addons/` |
| `systemd/` | — | sandboxed, resource-limited service + timer units (restore-at-boot, hourly scans, daemons) |
| `maturity.json` | — | the published maturity status of every add-on (all experimental), checked by the gate |

Every add-on has `check-config` and refuses to act on a config with an error.
All of them are **experimental** (see docs/ADDONS.md "Maturity").

Full description, the honesty notes on BIOS/boot, and every command and setting
are in [`../docs/ADDONS.md`](../docs/ADDONS.md). Everything is local; nothing is
pushed.
