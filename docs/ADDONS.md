# secure_sudo — temporary/ add-ons (v10), in depth

The `temporary/` tree is an **opt-in** set of add-ons that sit beside the core
secure_sudo stack. They are not built or installed by the core `install.sh`;
you add them deliberately with `temporary/install-temporary.sh`, and the name
reflects that they are a staging area for extra ideas (more will be added here
over time). Installing them **enables nothing and kills nothing** — every
enforcing behaviour is opt-in and starts in a safe mode.

Everything here is local. Nothing is pushed anywhere.

The add-ons:

| Add-on | Purpose | Enforcing? |
|--------|---------|-----------|
| **ProcGuard** | kill non-allowlisted processes; remove respawning infections; quarantine them compressed | monitor by default |
| **DriverGuard** | detect driver-file tampering; repair from rotated compressed backups | monitor by default |
| **BiosGuard** | detect firmware (BIOS/UEFI) tampering; **log and notify only** | detection only, never writes firmware |
| **BootGuard** | detect boot-partition tampering; restore **at next boot** | staged, never live |
| **Locus** | hand out the rotating storage locations over the LAN; read-only GUI | n/a (allocator) |
| **tamperwatch** | real-time attribution of *which process* tampered a protected file; optional quarantine | log by default |
| **GUI** | local web console to view and configure all of the above | n/a (console) |

Three things are shared by all of them:

* **Logging** (`ssaddon_log`): every add-on writes timestamped, leveled lines to
  a root-only local log under `/var/log/secure_sudo/addons/<feature>.log` (rotated
  at a size cap) and, if you enable it, ships every line to an **external log
  server** (UDP or TCP syslog, RFC 5424) so a compromised host cannot erase the
  record. It can also fire a **notification** on important events (`ssl_notify`)
  by running a configured `notify_cmd`. Configure in
  `/etc/secure_sudo/addons/logging.conf`.
* **Rotating compressed storage** (`ssaddon_store`): quarantine and backups are
  written into a directory named by the hour (`<root>/YYYYMMDDHH`), so the active
  location changes every hour. Each storing guard has a **`rotate` toggle** — set
  `rotate = 0` and it uses a single fixed `<root>/fixed` bucket instead. Stored
  bytes are zlib-compressed with the same 8-byte-header format the rest of the
  project uses. The root can be a fixed configured path or one requested at
  runtime from **Locus**.
* **Off-box notification** (`notify_cmd`): set `notify_cmd` in `logging.conf` to
  run a command on a critical event (the message, level, and feature are passed
  as safely-quoted `%m`/`%l`/`%f`). Examples: `logger`, `wall`, or your own
  alerting script.

---

## 1. ProcGuard — process allowlist enforcer

Watches every running process and compares its **on-disk executable**
(`/proc/<pid>/exe`) against an allowlist. A process whose executable is not
allowed is an intruder:

1. it is killed (`SIGKILL`);
2. if the **same executable path keeps respawning** — `respawn_threshold` kills
   within `respawn_window` seconds — it is classified as an **infection**;
3. on infection the binary is located, compressed into the **rotating
   quarantine** (so a fixed path can never be used to re-expand it and
   reinfect), the on-disk file is removed, and — if `sync_cmd` is set — the
   compressed sample is shipped off-box for later analysis.

**Safety.** "Kill everything not listed" can take a box down if the list is
incomplete, so ProcGuard:

* refuses to run with an **empty allowlist**;
* always exempts **PID 1**, kernel threads, its own process tree, and the
  secure_sudo binaries, whatever the list says;
* defaults to **`mode = monitor`** — it only logs what it *would* kill. Only
  `mode = enforce` acts. Build the allowlist in monitor mode first.

```sh
secure-sudo-procguard status          # show config
secure-sudo-procguard scan            # one pass (monitor: detect; enforce: act)
secure-sudo-procguard daemon          # the watch loop (systemd unit runs this)
```

Config `/etc/secure_sudo/addons/procguard.conf` (mode, interval, respawn
thresholds, `remove_on_infection`, `rotate`, `quarantine_root`, `sync_cmd`) and
the allowlist `/etc/secure_sudo/addons/procguard_allow.conf` (absolute exe
paths). Off-box sync example: `sync_cmd = rclone copy %f remote:infections/`
(`%f` = the compressed sample). `rotate = 1` (default) keeps samples in an
hourly bucket an attacker cannot predict; `rotate = 0` uses one fixed bucket.

## 2. DriverGuard — driver integrity + repair

Protects the kernel's on-disk **module files**.

```sh
secure-sudo-driverguard baseline   # hash every module + store compressed backups
secure-sudo-driverguard backup     # refresh the backups only
secure-sudo-driverguard scan       # check vs baseline; repair in enforce mode
secure-sudo-driverguard status
```

`baseline` records a SHA-256 manifest of every module under the driver tree
(default `/lib/modules/$(uname -r)`) and stores a compressed failsafe backup of
each in the backup location (hourly bucket, or fixed if `rotate = 0`). `scan`
re-hashes; a changed or missing module is a tamper, and in `mode = enforce` it
is restored from the newest backup that has it. (This protects the files the
kernel loads; a module *already loaded* is the core LSM's job — #6 driver-BYOVD
hashes the loaded bytes.) Config `/etc/secure_sudo/addons/driverguard.conf`.

## 3. BiosGuard — firmware tamper **detection only**

**Honesty note.** You cannot safely reflash a running machine's firmware from
generic Linux userspace — it needs vendor/chipset tooling and a bad write
bricks the board. So BiosGuard **only detects, logs, and notifies**; it never
writes firmware:

```sh
secure-sudo-biosguard baseline   # fingerprint DMI + ACPI tables
secure-sudo-biosguard scan       # detect tamper; log CRITICAL + notify (writes nothing)
secure-sudo-biosguard status
```

`baseline` hashes the firmware identity (`/sys/class/dmi/id/*`) and the ACPI
tables the firmware exposes (`/sys/firmware/acpi/tables/*`). `scan` recomputes
and, on a mismatch, logs CRITICAL and fires `ssl_notify` (so it reaches your
`notify_cmd` and off-box collector). There is **no repair/reflash path** — if a
firmware change is detected, remediation is a deliberate operator action with
vendor tooling, out of scope for this tool. Config
`/etc/secure_sudo/addons/biosguard.conf`.

## 4. BootGuard — boot-partition tamper detection (restore at next boot)

**Honesty note.** Rewriting the live `/boot` (or ESP) under a running kernel can
leave the machine unbootable. So BootGuard **stages** a restore that is applied
**at the next boot**:

```sh
secure-sudo-bootguard baseline         # hash all boot files + store compressed backups
secure-sudo-bootguard scan             # detect tamper; stage a restore for NEXT BOOT
secure-sudo-bootguard restore-staged   # applied early at boot by the systemd unit (no-op otherwise)
secure-sudo-bootguard status
secure-sudo-bootguard apply-now --i-understand-the-risk   # operator-only live restore
```

`scan` in `mode = enforce` writes a restore list and drops a `PENDING` flag;
nothing is written to the live boot partition. The shipped
`secure-sudo-bootguard-restore.service` runs `restore-staged` early at boot and,
if `PENDING` is set, restores each listed file from its compressed backup before
the system is fully up, then clears the flag. New, unknown files in `/boot` are
reported, not deleted (a kernel update legitimately adds files — re-run
`baseline` after a real update). Backups honour the `rotate` toggle. Config
`/etc/secure_sudo/addons/bootguard.conf`.

> Assurance note: the systemd unit applies the restore as early as a normal
> systemd unit can (after `/boot` is mounted, before services use it). For the
> strongest guarantee — restoring before anything from `/boot` is used at all —
> wire `restore-staged` into the initramfs; the systemd unit is the practical
> default.

## 5. Locus — the rotating-location allocator

The guards store things in directories that rotate every hour. Locus is the
single authority that hands out those locations, so two components never race on
a path, and it does **exactly one thing**:

* an **allocator** socket (the LAN request point): a client sends
  `ALLOC <purpose>` and gets back `OK <absolute-path>` — this hour's bucket
  under the root configured for that purpose. It never reads, writes, lists, or
  deletes files, never runs anything, and only ever emits paths under its
  configured roots. The purpose must be a short `[A-Za-z0-9-]` token, so it
  cannot be coaxed into naming an arbitrary path.
* a **read-only GUI** (HTTP): one page that *displays* the configured roots and
  each purpose's current location. GET only, no inputs, no file serving — the
  display cannot be turned into a way to read the disk.

```sh
secure-sudo-locus serve     # run both listeners (systemd unit runs this)
secure-sudo-locus status    # show binds and roots
```

Both listeners bind to configurable addresses: put the **allocator** on a LAN
IP if other hosts need locations; keep the **GUI** on `127.0.0.1` unless you
deliberately expose it. Configure the main root directories per purpose in
`/etc/secure_sudo/addons/locus.conf`. Guards find Locus via
`/etc/secure_sudo/addons/locus-client.conf`; if that is absent each guard falls
back to its own configured root (still rotated), so Locus is optional.

The guard→Locus reply is validated (must be an absolute path with no `..` and no
control characters) before any guard writes to it — Locus is trusted only to
*name a location*, nothing more.

## 6. tamperwatch — real-time tamper attribution

PheonixBox (the core snapshot feature) detects *that* a protected file changed,
on a timer — but not *who* changed it. tamperwatch fills that gap with
**fanotify**: it watches the protected files in real time and, the moment one is
modified, records **which process** did it (pid + its on-disk executable), logs
it CRITICAL (shippable off-box, visible in the GUI), and can quarantine that
process.

```sh
secure-sudo-tamperwatch daemon    # watch + attribute (systemd unit runs this)
secure-sudo-tamperwatch status
```

It watches every regular file under the PheonixBox protected set
(`/etc/secure_sudo/pheonixbox.conf`) plus any extra absolute paths in
`/etc/secure_sudo/addons/tamperwatch.conf`. `mode = log` (default) only
attributes; `mode = quarantine` additionally compresses the offender's
executable into the rotating quarantine and `SIGKILL`s it. Needs root and
`CONFIG_FANOTIFY`. Honest limit: it marks the regular files that exist when it
starts/rescans; a brand-new file created under a protected dir is covered on the
next rescan.

## 7. Kernel memory-access feed (prguard_observe)

The core Process Runtime Guard (#20, `ss_prguard.c`) already brokers
`ptrace`/`process_vm_*` cross-process memory access. v10 adds an **observe
knob**: when `prguard_observe = 1`, every cross-process memory access is emitted
to the kernel event log as

```
prguard: mem-access READ|WRITE by pid N (comm) -> pid M (comm)
```

so you can *see* which process read or wrote another process's memory, and from
where. It is a pure observation feed — enforcement is unchanged. Toggle it with
the CLI (`secure-sudo set prguard_observe 1`) or from the GUI's Memory Access
tab. The secure-sudod daemon writes these lines into
`/var/log/secure_sudo/YYYY-MM-DD.log`, which the GUI reads.

---

## Management GUI (local web console)

A single dependency-free (Python 3 stdlib) service — `secure-sudo-gui` — that
lets an operator view and configure the whole stack from a browser:

* **Status** of every guard + PheonixBox, and the live kernel knobs (with
  on/off pills);
* **Kernel logs** — the daemon's dated event logs and each guard's log;
* **Memory access** — the `prguard_observe` read/write feed, with an
  enable/disable toggle;
* **PheonixBox & tamper** — PheonixBox status, tamperwatch attribution events,
  and a one-click **quarantine a process by PID** (pinpoints its exe, compresses
  it, kills it);
* **Config** — edit each guard's config, with quick toggles for the
  **rotating ↔ fixed quarantine** switch and enable/disable, plus auto-detect
  helpers (driver tree; seed the ProcGuard allowlist from running processes).

```sh
secure-sudo-gui                       # run (systemd unit: secure-sudo-gui)
# then open http://127.0.0.1:8790/ ON THIS HOST
```

**Signing in.** Open the page and paste the access token:

```sh
sudo cat /var/lib/secure_sudo/addons/gui/token
```

The token stays in that browser tab only (cleared when the tab closes); **Sign
out** forgets it.

**Attack surface.** Root-only service, bound to `127.0.0.1` by default
(`gui.conf`). The page itself holds no secret. **Every** API call, reads
included, needs the token, which lives only in a root-only `0600` file, so
being able to reach the port is not enough: only someone who can read that
file (root) can use the console. Tokens are compared in constant time, failed
attempts are logged, and the `Host` header is checked on every call. (v10 put
the token in the page, which let any local user read it; fixed in v11, see
SECURITY_REVIEW #29.) Keep the bind on loopback unless you front it with your
own authenticated TLS proxy: this console can change config and kill processes.

---

## Logging and off-box backup (shared)

`/etc/secure_sudo/addons/logging.conf`:

```
log_dir = /var/log/secure_sudo/addons     # root-only, 0700
log_max_bytes = 8388608                    # local rotation cap
remote_enabled = 0                         # set 1 to ship off-box
remote_proto = udp                         # udp | tcp
remote_host =                              # your collector
remote_port = 514
# notify_cmd =                             # run on important events (%m %l %f)
```

With `remote_enabled = 1`, every line is also sent as RFC 5424 syslog to your
collector (rsyslog/syslog-ng, a SIEM, or a LAN log box) — the off-box backup, so
evidence survives a compromised host. With `notify_cmd` set, important events
also run that command (message/level/feature passed as safely-quoted
`%m`/`%l`/`%f`). The core PheonixBox feature also logs its tamper/repair and
enable/disable events via `syslog(3)`, which your system syslog can forward the
same way.

## Install (opt-in)

```sh
sudo bash temporary/install-temporary.sh
```

Builds and installs the binaries (ProcGuard, DriverGuard, BiosGuard, BootGuard,
Locus, tamperwatch) and the GUI, drops config **templates** (never overwriting
your edits), installs the systemd units, and creates the state/log dirs —
enabling nothing. Follow the printed next-steps (and §1–§7 above) to turn on
only what you want, in a safe order (ProcGuard in monitor first, baselines
before scans). Second-pass security review of the whole suite is in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md).
