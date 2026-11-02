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

Every add-on is **experimental**: see [Maturity](#maturity) for what that means,
what is done and what is still open before any of them is promoted.

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
* always exempts **PID 1**, kernel threads, its own process **and every
  ancestor** (the shell/unit that started it), and the secure_sudo binaries,
  whatever the list says. The secure_sudo exemption is by **path and owner**,
  not process name: only root-owned, non-group/world-writable executables at
  `/usr/bin/secure-sudo*`, `/usr/sbin/secure-sudod` or `/usr/libexec/secure-sudo/`
  count, so a renamed `/tmp/secure-sudo-x` is *not* exempt (SECURITY_REVIEW #64);
* never deletes a binary from a system directory (`/usr`, `/bin`, `/sbin`,
  `/lib*`, `/boot`, `/etc`) on infection: the sample is still quarantined and
  shipped, and the log says `INFECTION left on disk` so the operator removes or
  reinstalls it through the package manager;
* defaults to **`mode = monitor`** — it only logs what it *would* kill. Only
  `mode = enforce` acts, and only once armed: it arms itself after a pass
  with nothing to kill, or `secure-sudo-procguard arm` arms it
  ([Enforce arming](#enforce-arming)). Build the allowlist in monitor mode first.

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
re-hashes; a changed or missing module is a tamper, and in `mode = enforce`
(once armed: [Enforce arming](#enforce-arming)) it is restored from the newest
backup whose bytes match the baseline. (This protects the files the
kernel loads; a module *already loaded* is the core LSM's job — #6 driver-BYOVD
hashes the loaded bytes.) Config `/etc/secure_sudo/addons/driverguard.conf`.

**Updates are not tampering.** While a package manager holds its lock (dpkg,
rpm or zypper), `scan` is deferred and logs `scan deferred`, so a module being
replaced by an update is never "repaired" back to the old file. After the
update, the shipped package/kernel hooks run `secure-sudo-driverguard refresh`,
which re-baselines and logs what changed (`DRIVER baseline refreshed (reason)`)
so the change is on the record (SECURITY_REVIEW #66). Run
`secure-sudo-driverguard refresh` yourself after a manual module install.

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
reported, not deleted. Backups honour the `rotate` toggle. Config
`/etc/secure_sudo/addons/bootguard.conf`.

**Updates are not tampering.** A kernel or bootloader update legitimately
rewrites `/boot`. While a package manager holds its lock, `scan` is deferred
(`scan deferred`). Afterwards the shipped hooks run
`secure-sudo-bootguard refresh <reason>`, which re-baselines, logs every
changed/added/removed path (`BOOT baseline refreshed (reason): ...`), and drops
any restore staged before the update (`BOOT staged restore DROPPED by refresh`),
so the next boot does not roll the update back (SECURITY_REVIEW #66). Run
`refresh` yourself after a manual kernel install.

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
executable into the rotating quarantine and `SIGKILL`s it, once the operator
has run `secure-sudo-tamperwatch arm` (until then it reports what it would
kill). Needs root and
`CONFIG_FANOTIFY`. Honest limit: it marks the regular files that exist when it
starts/rescans; a brand-new file created under a protected dir is covered on the
next rescan.

**Never killed**, even in `mode = quarantine`: PID 1, tamperwatch itself, any
secure_sudo stack binary (so a PheonixBox repair or `secure-sudo restore` is
attributed but not killed), and any writer while a package manager holds its
lock (so a package update that touches a protected file is logged, not
broken). Each skip is logged as `not killed: pid N (exe): reason`
(SECURITY_REVIEW #65).

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

## Package and kernel hooks

`install-temporary.sh` installs `/usr/libexec/secure-sudo/addons-refresh` and
wires it into the distro's update path, so BootGuard and DriverGuard
re-baseline after a legitimate update instead of treating it as tampering:

| Hook | Distro | Fires |
|---|---|---|
| `/etc/apt/apt.conf.d/99secure-sudo-addons` | Debian/Ubuntu | after every dpkg run |
| `/etc/kernel/postinst.d/zzz-secure-sudo-addons`, `postrm.d/` | Debian/Ubuntu | kernel install/remove |
| `/etc/kernel/install.d/99-secure-sudo-addons.install` | Fedora/RHEL/SUSE (kernel-install) | kernel add/remove |
| `/etc/dnf/libdnf5-plugins/actions.d/secure-sudo-addons.actions` or `/etc/dnf/plugins/post-transaction-actions.d/` | Fedora/RHEL | after a dnf transaction |

Each run is logged (`baseline refreshed (reason)`), so an attacker who installs
a package to slip a change past the baseline still leaves a record, and the
record is shipped off-box with everything else. Tested by
`tests/userspace/test-addons.sh`.

## Logging and off-box backup (shared)

`/etc/secure_sudo/addons/logging.conf`:

```
# root-only, 0700
log_dir = /var/log/secure_sudo/addons
# local rotation cap (65536 .. 1 GiB)
log_max_bytes = 8388608
# 1 = ship every line off-box (needs remote_host)
remote_enabled = 0
# udp | tcp
remote_proto = udp
# your collector
remote_host =
remote_port = 514
# run on important events (%m %l %f)
# notify_cmd =
```

(Comments go on their own lines: the config is checked strictly, see
[Config checking](#config-checking).)

With `remote_enabled = 1`, every line is also sent as RFC 5424 syslog to your
collector (rsyslog/syslog-ng, a SIEM, or a LAN log box) — the off-box backup, so
evidence survives a compromised host. With `notify_cmd` set, important events
also run that command (message/level/feature passed as safely-quoted
`%m`/`%l`/`%f`). The core PheonixBox feature also logs its tamper/repair and
enable/disable events via `syslog(3)`, which your system syslog can forward the
same way.

## Maturity

Every add-on here is **experimental** (TODO P2-2). That is a published status,
kept in [`temporary/maturity.json`](../temporary/maturity.json) and checked on
every gate run by `ci/check-addon-maturity.py`: the gate fails if the tree and
the file disagree (a unit without failure reporting, an add-on without
`check-config`, a shipped default that is not the published one, a promotion
without an operator's approval).

Experimental means: install it to try it, run it in its monitor/log mode, and do
not rely on its enforcing mode on a production host yet. The TODO's caution
stands: do not turn on automatic quarantine, repair or broad allowlist
enforcement on production systems as a substitute for the tests and recovery
work still open below.

| Add-on | Level | Default mode | Acts by | Still open before promotion |
|--------|-------|--------------|---------|-----------------------------|
| `procguard` | experimental | monitor | killing processes; removing a respawning executable | 14-day host soak, then promotion |
| `tamperwatch` | experimental | log | killing the writer of a protected file (quarantine mode) | 14-day host soak, then promotion |
| `driverguard` | experimental | monitor | overwriting a changed module file from its backup | 14-day host soak, then promotion |
| `bootguard` | experimental | enforce (staged) | overwriting changed /boot files at the next boot | 14-day host soak, then promotion |
| `biosguard` | experimental | detect | nothing (log + notify) | 14-day host soak, then promotion |
| `locus` | experimental | serve | nothing destructive (hands out directory names) | 14-day host soak, then promotion |
| `gui` | experimental | loopback | editing configs, running scans, quarantining on request | 14-day host soak, then promotion |
| `failure` | experimental | report | nothing (reports another unit's failure) | 14-day host soak, then promotion |
| `pheonixbox` | experimental | off | repairing a changed protected file from its stored copy | baseline trust source, 14-day host soak, then promotion |

PheonixBox is a core feature (installed by `install.sh`, run by `secure-sudod`,
[PHEONIXBOX.md](PHEONIXBOX.md)), but TODO P2-2 holds it to the same gate, so it
is listed here too.

BootGuard's default is `enforce` because that mode only *stages* a restore; the
restore is applied by a separate unit at the next boot, and the installer
enables neither the timer nor the restore unit.

Done for every add-on: strict config checking, a sandboxed and
resource-limited unit, failure reporting, a threat model (below), upgrade
and rollback steps (below) and adversarial tests
([Adversarial tests](#adversarial-tests)). Done where it applies: an independent trust source
for the baselines and evidence kept before every repair, restore, removal or
quarantine ([Baseline trust and evidence](#baseline-trust-and-evidence)).

### Promotion criteria

Approved by the operator (Pheonix) on 2026-11-02 (the "standard" option) and
recorded in `maturity.json` under `criteria`:

* **beta**: every requirement above done (or not applicable, with the reason),
  then a **14-day soak**: at least 14 consecutive days in monitor (log) mode
  on a real host that is not a test machine, with its alerts shipped off the
  host. Every alert raised in the soak is explained in the promotion record:
  a real finding, a false positive fixed in the code or config, or an
  exclusion with its reason.
* **stable**: beta, then at least **30 consecutive days in its acting mode**
  (enforce or quarantine, armed) on that host, every alert explained the same
  way and no unexplained kill, repair or quarantine, plus a **recovery
  drill**: undo one of its actions (restore a quarantined sample or a repaired
  file from its evidence, or roll the add-on back as in
  [Upgrade and rollback](#upgrade-and-rollback)) and confirm the host is back
  to normal.

The gate enforces this. An add-on whose `level` is above experimental must
have no open requirement and a `promotion` record that meets the criteria,
or `ci/check-addon-maturity.py` fails:

```json
"promotion": {
  "beta": {
    "approved_by": "Pheonix", "date": "2026-12-01", "host": "srv1",
    "soak_start": "2026-11-10", "soak_end": "2026-11-24",
    "alerts": [{"alert": "killed /opt/x/agent", "explained": "missing from the allowlist; added"}]
  },
  "stable": {
    "approved_by": "Pheonix", "date": "2027-01-05", "host": "srv1",
    "enforce_start": "2026-12-02", "enforce_end": "2027-01-01", "alerts": [],
    "recovery_drill": {"date": "2027-01-02", "what": "restored a quarantined sample from evidence"}
  }
}
```

To promote an add-on: run the soak, keep its log, fill in the record, move
`host-soak` and `promotion-approved` to `done`, set `level`, and update the
table above. No add-on has been through a soak yet, so all are still
experimental.

## Config checking

Every add-on reads its config strictly (`temporary/common/ssaddon_conf.c`):

* an unknown key, a line without `=`, and a key set twice are errors, so a
  typo is never silently ignored (`mode = enforec` used to mean monitor);
* an enum must be one of its values, a number must parse in full and be in
  range, a path must be absolute with no `..`, a value too long is an error
  (never truncated), and control characters are errors;
* there are no inline comments: `mode = monitor  # note` is an error, put the
  note on its own line;
* the file must be owned by root and not group/world writable: these files name
  commands (`notify_cmd`, `sync_cmd`) and paths that a root daemon acts on.

Each guard's `check-config` checks its own file and the shared `logging.conf`
and `locus-client.conf` (ProcGuard also its allowlist: one absolute path per
line) and prints every problem as `file:line: message`:

```sh
secure-sudo-procguard check-config     # 0 = OK, 1 = problems listed
secure-sudo-gui check-config           # the console's gui.conf
```

While a config has an error the acting commands (`daemon`, `scan`, `baseline`,
`refresh`, `restore-staged`, `serve`, ...) refuse to run and exit 78
(EX_CONFIG); `status` still works and says how many problems there are. A
missing file is not an error: the built-in defaults apply. The console runs the
owning guard's `check-config` after every config change it makes and puts the
previous file back if the change is rejected.

## Baseline trust and evidence

DriverGuard, BootGuard and BiosGuard act on a baseline they recorded
themselves, so by default it is only as trustworthy as the host. Each now has
`baseline_trust`:

* `local` (default): the host's own copy is trusted, as before.
* `signed`: the guard acts on its baseline (`manifest`, BiosGuard's
  `fingerprint`) only when `<baseline>.sig` is a valid Ed25519 signature over
  it by the operator's key. The host holds only the public half, at
  `/etc/secure_sudo/addons/baseline-signing.pub` (root-owned, not group/world
  writable). Without a valid signature the guard reports and never repairs,
  stages or restores, and the run exits 3, so the unit fails and the failure
  is reported. A staged BootGuard restore is checked again at boot.

Set it up once, with the private key kept off the host:

```sh
# on the operator's machine (or removable media)
openssl genpkey -algorithm ed25519 -out baseline-signing.key
openssl pkey -in baseline-signing.key -pubout -out baseline-signing.pub
# on the host
install -m0644 baseline-signing.pub /etc/secure_sudo/addons/
# set baseline_trust = signed in driverguard.conf / bootguard.conf / biosguard.conf
# after every baseline or refresh, copy the manifest out, sign it, copy the .sig back:
openssl pkeyutl -sign -rawin -inkey baseline-signing.key \
    -in manifest -out manifest.sig
```

Every new baseline (`baseline`, a package hook's `refresh`) deletes the old
signature and is logged CRITICAL with its SHA-256, entry count and the key's
fingerprint, so the record is off the host as soon as it is made. After a
kernel or package update the guard therefore stops repairing until the
operator signs the new baseline. That is the point: a baseline nobody has
looked at is not trusted. `status` shows the trust state.

Two protections apply in both modes:

* **Restores are checked against the baseline.** A backup is decompressed in
  memory and written back only if its SHA-256 equals the baseline's. If the
  newest backup does not match, older hourly ones (and the fixed bucket) are
  tried; if none does, nothing is written. The file goes through a temporary
  name in the same directory, created exclusively (a planted symlink there is
  not followed), then renamed into place. The owner and mode of what was
  there are kept only while they cannot hand the restored file to someone
  else: a file not owned by root comes back root-owned, and setuid, setgid
  and group/world write bits are dropped.
* **A baseline matches its own backups.** The hash recorded for each file is
  the hash of exactly the bytes that were backed up (one read, not two), so a
  file rewritten while the baseline runs cannot leave a baseline its backup
  does not match. A file that changes size while it is read is not backed up.
* **A baseline that cannot be backed up is refused.** If any file cannot be
  backed up in full (a full disk shows up at write, flush, fsync or close),
  the new baseline is not installed, the previous one stays, and the refusal
  is logged CRITICAL. No partial backup is left behind.
* **No repair without evidence.** If the evidence copy cannot be kept (a full
  disk), the file is not repaired, restored or removed; the log says why.
* **Baseline entries are checked.** A manifest line naming a file outside
  `driver_dir` / `boot_dir` (or with a `..`, `.` or empty component, or a
  control character) is never acted on: it is logged CRITICAL and the scan
  exits 3. BootGuard's staged restore list is checked the same way, and the
  hash staged with each file must be the baseline's.
* **Symlinks are not followed.** A module or boot file replaced by a symlink
  is tampering even when it points at identical bytes; it is not hashed,
  backed up or written through, and the evidence records the link and its
  target.
* **Evidence is kept.** Before DriverGuard repairs, BootGuard restores,
  ProcGuard removes, or tamperwatch or the console quarantines, the current
  file's bytes are kept compressed under
  `/var/lib/secure_sudo/addons/evidence/<feature>/`, and one JSON line is
  appended to `evidence/<feature>.jsonl`: time, action, path, SHA-256, the
  baseline's SHA-256, size, mode, owner, mtime, ctime, inode and the copy.
  It is also logged CRITICAL (and shipped off-box).

Not yet covered: a signature over PheonixBox's own snapshots (it is core;
tracked in `maturity.json`; its repairs are now verified against its
manifest and keep evidence, see its threat model), and a root attacker who replaces the public key; for that,
compare the key fingerprint in the off-box log, or use remote attestation
([ATTESTATION.md](ATTESTATION.md)).

## Enforce arming

Turning ProcGuard or DriverGuard to `mode = enforce`, or tamperwatch to
`mode = quarantine`, does not make it act at once (TODO P2-2, monitor to
enforce). Until it is **armed** it only reports what it would do, logged as
`NOT ARMED: would kill ...` / `DRIVER would repair ... (not armed)`:

* a scanner (ProcGuard, DriverGuard) arms itself after one full enforce pass
  that finds nothing to act on: the allowlist is complete, the module tree
  matches its baseline;
* otherwise it logs, CRITICAL, `ENFORCE NOT ARMED: ... would have killed N`
  (ProcGuard at most every 10 minutes) and the operator, after reading the
  report, runs `secure-sudo-procguard arm` / `secure-sudo-driverguard arm`;
* tamperwatch only reacts to events, so it is armed only by
  `secure-sudo-tamperwatch arm`;
* going back to monitor (log) mode disarms it, so the next switch to enforce
  is reviewed again.

The state is `/var/lib/secure_sudo/addons/<add-on>/enforce-armed` (root-only;
it records when and how it was armed) and `status` shows it. BootGuard is not
armed this way: its enforce mode only stages a restore, applied at the next
boot by a unit the installer does not enable, and every staged file is
checked against the trusted baseline when it is applied.

## Adversarial tests

`tests/userspace/test-addons.sh` (135 checks) and
`tests/userspace/test-pheonixbox.sh` (41) attack each add-on the way the
threat models below expect, run on every gate:

| Attack | Add-ons | Result |
|--------|---------|--------|
| a file name with a newline forging a log line | DriverGuard, BiosGuard, failure reporter | logged escaped (`\x0a`); every log line starts with its own timestamp; not baselined |
| a file name with a quote, run through a shell | BiosGuard, PheonixBox | no command runs (BiosGuard **did** run one: it hashed with `sha256sum` through a shell; fixed) |
| a symlink planted at a guarded path, even to identical bytes | DriverGuard, BootGuard, PheonixBox | treated as tampering, replaced by the real file, never written through (PheonixBox **did** write through it, and `off` changed the target's mode; fixed) |
| an edited baseline naming a file outside the guarded tree | DriverGuard, BootGuard (restore list), PheonixBox | ignored, logged CRITICAL, scan exits 3 |
| a swapped backup or snapshot | DriverGuard, BootGuard, PheonixBox | refused; an older matching backup is used when there is one |
| the path of a running program replaced after it started | ProcGuard, tamperwatch | the binary that actually ran is quarantined (via `/proc/PID/exe`); the new file at the path is not deleted |
| no room for backups or evidence (a small tmpfs) | DriverGuard, BootGuard, PheonixBox | baseline refused and the old one kept; no repair without evidence |
| a setuid, group-writable tampered file | DriverGuard | restored root-owned, mode 0755 |
| monitor to enforce | ProcGuard, DriverGuard, tamperwatch | reports until armed; arms itself only after a clean pass (not tamperwatch) |
| an ACPI table added after the baseline | BiosGuard | reported (only changed and vanished sources were before) |
| oversized, path-like or unknown requests; a client that sends nothing | Locus | refused; a silent client is dropped after 2 s instead of stalling the allocator |
| no or wrong token, another Host, negative or huge Content-Length, a non-numeric count, a non-object body, a config or log name outside its list, quarantining PID 1 | console | 401 / 403 / 413 / 400 or refused; the kill uses a pidfd so a reused PID is never hit |
| a bad config | PheonixBox | `check-config` lists it; `on` and `snapshot` refuse (78) |

## Service hardening and failure reporting

Each unit in `temporary/systemd/` is sandboxed as far as its job allows, and the
gate holds each to a maximum `systemd-analyze security` exposure (listed in
`maturity.json`; 9.6 "UNSAFE" for every unit before this step):

| Unit | Exposure | Writable | Why not stricter |
|------|---------:|----------|------------------|
| procguard | 3.4 | everything but /usr, /boot, /efi, /etc | it removes infected files in /home and /tmp; the system dirs are read-only, so "never delete from a system directory" is enforced by the kernel too |
| tamperwatch | 3.5 | its state and log | fanotify needs CAP_SYS_ADMIN |
| driverguard | 2.6 | state, log, /lib/modules, /usr/lib/modules | enforce mode repairs module files |
| bootguard | 2.3 | state and log (the scan only stages) | |
| bootguard-restore | 2.0 | state, log, /boot, /efi; no network | it writes the boot partition at boot |
| biosguard | 2.3 | state and log | |
| locus | 2.1 | state and log | |
| gui | 7.5 | everything | the scans, repairs, `secure-sudo set` and quarantine it runs inherit its sandbox |
| addon-failure@ | 3.9 | /var | it runs `notify_cmd`, which may mail or post |

Every unit also has resource limits (`MemoryMax=`, `TasksMax=`, `CPUQuota=`;
the scans run at `Nice=10` with idle I/O priority) and
`OnFailure=secure-sudo-addon-failure@%n.service`. When a guard crashes, is
killed, hits its memory limit, keeps failing, or refuses to start because its
config is invalid, that unit runs `/usr/libexec/secure-sudo/secure-sudo-addon-failure`,
which raises a CRITICAL notification through the shared logging: the local add-on
log, the off-box collector when one is set, and `notify_cmd`. A guard that
silently stopped guarding would otherwise look the same as a quiet host. The
daemons do not restart-loop on a config error (`RestartPreventExitStatus=78`).

Limits of the sandbox: `sync_cmd` and `notify_cmd` run inside the guard's
sandbox, so a command that writes outside the writable paths (for example ssh
updating `/root/.ssh/known_hosts` under tamperwatch's read-only /home) fails;
pre-seed what it needs. A `driver_dir` or `boot_dir` outside the default trees
needs the matching `ReadWritePaths=` in a drop-in.

## Threat model

Common to all: the adversary is a process on the host, possibly root, trying to
persist, to hide what it did, or to make a guard do damage for it. A root
attacker who can rewrite the guards, their configs or their units defeats
every add-on here: they are tripwires and responders, not a boundary against
root. What they add is detection that is shipped off the host as it happens,
and response in the window before the attacker has turned them off. What every
add-on must never do is the attacker's work for them: a false positive that
kills or overwrites the wrong thing is the main risk, which is why each acting
mode is opt-in and each config is checked strictly.

#### procguard

* **Defends:** a non-allowlisted program running at all; an implant that keeps
  respawning (removed after a compressed sample is quarantined).
* **Does not defend:** code inside an allowlisted executable (an interpreter on
  the list runs any script), anything faster than one scan interval, or an
  attacker who edits the allowlist (root).
* **Harm if wrong:** killing a legitimate service missing from the allowlist,
  or removing its file. Mitigations: monitor is the default; an empty list
  refuses to run; PID 1, kernel threads, its own ancestors and the installed
  secure_sudo programs are never killed; nothing is removed from a system
  directory (now enforced by the unit's read-only system dirs too).
* **Evidence:** before an executable is removed, its hash, owner, mode, times
  and the quarantined copy are recorded (`evidence/procguard.jsonl`); if the
  record cannot be written, it is not removed.
* **Races:** the binary is opened through `/proc/PID/exe` before the kill, so
  the quarantined copy is the program that ran; the path is removed only
  while it is still that file (same device and inode, not a symlink).
  Turned to enforce, it reports until armed ([Enforce arming](#enforce-arming)).

#### tamperwatch

* **Defends:** names, in real time, the process that wrote a protected file,
  and in quarantine mode stops it after compressing its executable.
* **Does not defend:** writes through paths it does not watch (a bind mount, a
  new hard link), a writer that exits before the event is read, or a root
  attacker who stops it first (the stop is reported by failure reporting only
  if the unit fails, not if it is stopped cleanly).
* **Harm if wrong:** killing a legitimate writer. Mitigations: log mode by
  default; quarantine mode reports until the operator arms it; never kills
  PID 1, itself, a secure_sudo program, or anything while a package manager is
  running.
* **Attribution limit:** fanotify reports the writer's PID after the write.
  A writer that then `exec`s another program is quarantined as that program
  (the PID is still killed). The quarantined binary is read through
  `/proc/PID/exe`, so a replaced path does not change what is kept.

#### driverguard

* **Defends:** a module file on disk changed outside a package transaction,
  repaired from its backup in enforce mode.
* **Does not defend:** a module already loaded (that is the kernel LSM's job),
  or a baseline rewritten by root while `baseline_trust = local` (the
  default). With `signed`, a rewritten baseline is not acted on; a root
  attacker can still replace the public key, which the off-box log shows
  (every new baseline is logged with its hash and the key fingerprint).
  A backup is only written back if its bytes match the baseline, so a
  swapped backup is refused.
* **Harm if wrong:** putting back an old module over a legitimate update.
  Mitigations: monitor by default; enforce reports until armed; scans defer
  while a package manager holds its lock, and the package hooks re-baseline
  after an update.

#### bootguard

* **Defends:** a changed kernel, initrd or boot loader config in /boot, put back
  from its backup at the next boot.
* **Does not defend:** firmware or the ESP outside `boot_dir`, a change that
  never touches the files (a different boot entry in NVRAM), or a rewritten
  baseline while `baseline_trust = local`. The staged restore re-checks the
  baseline's trust at boot, and writes back only backups that match it.
* **Harm if wrong:** booting an older kernel or initrd after a legitimate
  update. Mitigations: restores are staged, never live (`apply-now` needs
  `--i-understand-the-risk`); scans defer during a package transaction; the
  hooks re-baseline and drop a staged restore that predates an update.

#### biosguard

* **Defends:** detects a change in the DMI identity or ACPI tables and reports
  it CRITICAL; it never writes firmware.
* **Does not defend:** firmware changes that leave DMI and ACPI unchanged
  (measured boot, P2-1, is the stronger check), or a fingerprint rewritten
  while `baseline_trust = local` (with `signed`, an unsigned or edited
  fingerprint fails the scan with a CRITICAL notification).
* **Harm if wrong:** a false alarm after a legitimate firmware update; nothing
  is changed. A table that appeared after the baseline is reported as well
  as one that changed or vanished; a table name with whitespace or control
  characters is reported, not fingerprinted.

#### locus

* **Defends:** spreads quarantine and backup locations across hourly buckets
  so a fixed path cannot be targeted.
* **Does not defend:** anything on its own; a rogue allocator can only name a
  location, which the guards check (absolute, no `..`, no control characters).
* **Harm if wrong:** a guard writing to a different directory than expected.
  It listens on 127.0.0.1 by default; the allocator protocol has no
  authentication, so do not widen `alloc_bind` beyond a trusted LAN. It serves
  one client at a time, and drops one that sends nothing within 2 seconds.

#### gui

* **Defends:** nothing itself; it is the operator's console.
* **Risk:** it can change every config and kill any process, so it is the
  highest-value target here. Mitigations: loopback by default, a per-install
  token on every request, a Host header check, request bodies capped at
  512 KiB, config and log names limited to their lists, config changes rolled
  back when `check-config` rejects them, PID 1 and itself never killed, the
  kill sent through a pidfd (never to a reused PID), and failure reporting on
  its unit.

#### pheonixbox

* **Defends:** a protected file changed while protection is on: it is put back
  from the stored copy on the next scan, and the file is kept read-only.
* **Does not defend:** a change made while protection is off, or by root
  rewriting the stored copies and manifest together, unless `trust = signed`
  (docs/PHEONIXBOX.md "Snapshot trust"): then a snapshot the operator has
  not signed is reported on but never repaired from.
* **Harm if wrong:** undoing a legitimate change to a protected file.
  Mitigations: off by default; `disable` restores the original permissions;
  tamperwatch never kills a PheonixBox repair (SECURITY_REVIEW #65).
* **Repairs:** a stored copy is used only if it hashes to the manifest's
  value; it is written to a new file and renamed over the target, so a
  symlink planted at a protected path is replaced, never written through;
  the captured owner comes back with it. Before each repair the current bytes
  are kept under `/var/lib/secure_sudo/pheonixbox/evidence/` and logged
  CRITICAL with their hash; if that copy cannot be kept, the file is not
  repaired. `off` never changes permissions through a symlink.
* **Config:** `secure-sudo pheonixbox check-config` checks the path list
  strictly; `on` and `snapshot` refuse while it has an error.

#### failure

* **Defends:** makes a guard that stops guarding visible off the host.
* **Does not defend:** a clean `systemctl stop` by root (not a failure), or a
  host whose logging is turned off.

## Upgrade and rollback

**Upgrade.** Install the new tree over the old one with
`sudo bash temporary/install-temporary.sh`. It replaces the binaries, units and
hooks, keeps every config you edited, and enables nothing new. Then:

1. Run `check-config` for every add-on you use (the installer prints a warning
   for each that fails). A config that was accepted before may be rejected now
   (strict checking arrived in P2-2): fix what it lists. Until you do, that
   add-on's acting commands refuse to run and its unit fails with status 78,
   which is reported.
2. `systemctl daemon-reload`, then restart the daemons you run
   (`systemctl restart secure-sudo-procguard` and so on).
3. Baselines (`/var/lib/secure_sudo/addons/*/manifest`, BiosGuard's
   `fingerprint`) and backups are kept across upgrades; re-baseline only if the
   release notes say the format changed. With `baseline_trust = signed`, sign
   any baseline the upgrade rewrote.

**Rollback.** Keep the previous release tarball. To go back, stop the add-on
units, install the previous tree with its own `install-temporary.sh`, then
`systemctl daemon-reload` and start them again. Configs are kept either way.
A release from before strict checking ignores keys it does not know; a strict
one rejects them, so a config written for a newer release can fail
`check-config` on an older one: compare it with that release's templates. A staged BootGuard restore (`PENDING`) survives
both: inspect `restore.list` before rebooting into either version.

**Turn an add-on off.** `systemctl disable --now` its unit or timer. Nothing
else depends on it; its state and logs stay until you remove
`/var/lib/secure_sudo/addons/<name>` and `/var/log/secure_sudo/addons/<name>.log`.

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
