# secure_sudo — temporary/ add-ons (v8), in depth

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
| **DriverGuard** | detect driver-file tampering; repair from hourly-rotated compressed backups | monitor by default |
| **BiosGuard** | detect firmware (BIOS/UEFI) tampering; **detect-and-stage** a restore | detection; reflash operator-only |
| **BootGuard** | detect boot-partition tampering; restore **at next boot** | staged, never live |
| **Locus** | hand out the hourly-rotating storage locations over the LAN; read-only GUI | n/a (allocator) |

Two things are shared by all of them:

* **Logging** (`ssaddon_log`): every add-on writes timestamped, leveled lines to
  a root-only local log under `/var/log/secure_sudo/addons/<feature>.log` (rotated
  at a size cap) and, if you enable it, ships every line to an **external log
  server** (UDP or TCP syslog, RFC 5424) so a compromised host cannot erase the
  record. Configure in `/etc/secure_sudo/addons/logging.conf`.
* **Hourly-rotating compressed storage** (`ssaddon_store`): quarantine and
  backups are written into a directory named by the hour (`<root>/YYYYMMDDHH`),
  so the active location changes every hour. Stored bytes are zlib-compressed
  with the same 8-byte-header format the rest of the project uses. The root can
  be a fixed configured path or one requested at runtime from **Locus**.

---

## 1. ProcGuard — process allowlist enforcer

Watches every running process and compares its **on-disk executable**
(`/proc/<pid>/exe`) against an allowlist. A process whose executable is not
allowed is an intruder:

1. it is killed (`SIGKILL`);
2. if the **same executable path keeps respawning** — `respawn_threshold` kills
   within `respawn_window` seconds — it is classified as an **infection**;
3. on infection the binary is located, compressed into the **hourly-rotated
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
thresholds, `remove_on_infection`, `quarantine_root`, `sync_cmd`) and the
allowlist `/etc/secure_sudo/addons/procguard_allow.conf` (absolute exe paths).
Off-box sync example: `sync_cmd = rclone copy %f remote:infections/` (`%f` =
the compressed sample). The quarantine keeps samples for analysis; because the
location rotates hourly, an attacker cannot predict or pre-empt the path.

## 2. DriverGuard — driver integrity + repair

Protects the kernel's on-disk **module files**.

```sh
secure-sudo-driverguard baseline   # hash every module + store compressed backups (hourly bucket)
secure-sudo-driverguard backup     # refresh the hourly backups only
secure-sudo-driverguard scan       # check vs baseline; repair in enforce mode
secure-sudo-driverguard status
```

`baseline` records a SHA-256 manifest of every module under the driver tree
(default `/lib/modules/$(uname -r)`) and stores a compressed failsafe backup of
each in the hourly-rotated backup location. `scan` re-hashes; a changed or
missing module is a tamper, and in `mode = enforce` it is restored from the
newest backup that has it. (This protects the files the kernel loads; a module
*already loaded* is the core LSM's job — #6 driver-BYOVD hashes the loaded
bytes.) Config `/etc/secure_sudo/addons/driverguard.conf`.

## 3. BiosGuard — firmware tamper detection (detect-and-stage)

**Honesty note.** You cannot safely reflash a running machine's firmware from
generic Linux userspace — it needs vendor/chipset tooling and a bad write
bricks the board. So BiosGuard is **detect-and-stage**:

```sh
secure-sudo-biosguard baseline   # fingerprint DMI + ACPI tables (+ store a known-good image if configured)
secure-sudo-biosguard scan       # detect tamper; STAGE the known-good image (flashes nothing)
secure-sudo-biosguard status
secure-sudo-biosguard apply --i-understand-the-risk   # operator-only reflash
```

`baseline` hashes the firmware identity (`/sys/class/dmi/id/*`) and the ACPI
tables the firmware exposes (`/sys/firmware/acpi/tables/*`), and — if you set
`good_image` to a verified full flash dump — stores it compressed as the restore
source. `scan` recomputes and, on a mismatch, logs CRITICAL and **stages** the
good image into `…/biosguard/staged/` with instructions; it never flashes.
`apply` is the only path that writes firmware, refuses without
`--i-understand-the-risk`, requires `flashrom` + a configured programmer, and is
operator-invoked — never a timer or daemon. Config
`/etc/secure_sudo/addons/biosguard.conf`.

## 4. BootGuard — boot-partition tamper detection (restore at next boot)

**Honesty note.** Rewriting the live `/boot` (or ESP) under a running kernel can
leave the machine unbootable. So BootGuard **stages** a restore that is applied
**at the next boot**:

```sh
secure-sudo-bootguard baseline         # hash all boot files + store compressed backups (hourly)
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
`baseline` after a real update). Config
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
back to its own configured root (still hourly-rotated), so Locus is optional.

The guard→Locus reply is validated (must be an absolute path with no `..` and no
control characters) before any guard writes to it — Locus is trusted only to
*name a location*, nothing more.

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
```

With `remote_enabled = 1`, every line is also sent as RFC 5424 syslog to your
collector (rsyslog/syslog-ng, a SIEM, or a LAN log box) — the off-box backup, so
evidence survives a compromised host. The core PheonixBox feature also logs its
tamper/repair and enable/disable events via `syslog(3)`, which your system
syslog can forward the same way.

## Install (opt-in)

```sh
sudo bash temporary/install-temporary.sh
```

Builds and installs the five binaries, drops config **templates** (never
overwriting your edits), installs the systemd units, and creates the state/log
dirs — enabling nothing. Follow the printed next-steps (and §1–§5 above) to turn
on only what you want, in a safe order (ProcGuard in monitor first, baselines
before scans). Second-pass security review of the whole suite is in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) (findings #21–#25).
