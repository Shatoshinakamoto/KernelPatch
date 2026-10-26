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
| `biosguard/` | `secure-sudo-biosguard` | firmware tamper **detection** + staged restore (reflash operator-only) |
| `bootguard/` | `secure-sudo-bootguard` | boot-partition tamper detection + restore **at next boot** |
| `locus/` | `secure-sudo-locus` | LAN request-only allocator for the rotating locations + read-only GUI |
| `config/` | — | config templates copied to `/etc/secure_sudo/addons/` |
| `systemd/` | — | service + timer units (restore-at-boot, hourly scans, daemons) |

Full description, the honesty notes on BIOS/boot, and every command and setting
are in [`../docs/ADDONS.md`](../docs/ADDONS.md). Everything is local; nothing is
pushed.
