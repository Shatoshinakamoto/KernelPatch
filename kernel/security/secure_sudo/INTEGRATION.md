# Wiring secure_sudo into a kernel tree

This directory is dropped in at `security/secure_sudo/` inside a kernel source
tree (target: **6.12 LTS**). Two one-line edits connect it to the build; the
installer (step 4) applies them automatically.

**1. `security/Kconfig`** — source our Kconfig alongside the other LSMs, inside
the `menu "Security options"` ... `endmenu` block (near the other
`source "security/.../Kconfig"` lines):

```
source "security/secure_sudo/Kconfig"
```

**2. `security/Makefile`** — add the directory to the security build:

```
subdir-$(CONFIG_SECURITY_SECURE_SUDO) += secure_sudo
obj-$(CONFIG_SECURITY_SECURE_SUDO)    += secure_sudo/
```

**3. Kernel config** — enable the LSM and make it active:

```
CONFIG_SECURITY=y
CONFIG_SECURITY_SECURE_SUDO=y
# add secure_sudo to the active LSM list:
CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,secure_sudo,bpf"
```

secure_sudo is a *minor* LSM (it only augments, never replaces, the major LSM),
so its position in `CONFIG_LSM` is not critical, but keeping it late in the list
means its denials run after the stacked majors have had their say.

## Files

| File | Purpose |
|------|---------|
| `secure_sudo.h` | shared config, `ss_cred_is_sudo()`, per-subsystem init decls |
| `ss_core.c`     | LSM registration (`DEFINE_LSM`), defaults, sysfs root, helpers |
| `ss_creds.c`    | Protection #1: non-sudo UID/GID switch block + userns gate; #1b setid-exec gate + `setid_exec_allow` |
| `ss_exec.c`     | Protection #2: command blacklist (securityfs, inode+path+content match) |
| `ss_firmware.c` | Protection #3: firmware/flash + raw-memory access block |
| `ss_tpm.c`      | Protection #5: block TPM clear (ppi/request) |
| `ss_ram.c`      | Protection #7: RAM-spike detection -> drop caches |
| `ss_tmpexec.c`  | Protection #12: block exec/PROT_EXEC mmap from scratch trees |
| `ss_net.c`      | Protection #10 (kernel half): deny raw/packet sockets in host mode |
| `ss_log.c`      | Protection #9: event ring drained via securityfs `events` |
| `ss_node.c`     | Protection #11: NodeJS child guard (defines the LSM task blob) |
| `ss_cooldown.c` | Protection #8: sudo brute-force cooldown (PAM-fed) |
| `ss_driver.c`   | Protection #6: driver blacklist (SHA-256 / file name / module name via a module notifier); exports `ss_sha256_file()` |
| `ss_timevault.c`| Protection #13: TimeVault exec allowlist + pkg-mgr deny |
| `ss_home.c`     | Protection #4: confine non-sudo writes to home (file_open + path_*) |
| `ss_binvault.c` | Protection #17: BinaryVault (freeze executables and libraries) |
| `ss_radio.c`    | Protection #19: RadioGuard (Wi-Fi/Bluetooth modules, sockets, rfkill) |
| `ss_prguard.c`  | Protection #20: Process Runtime Guard (ptrace, process_vm_writev, /proc/pid/mem, W^X) |
| `ss_bpf.c`      | Protection #22: BPF and perf guard (hook signature chosen per kernel version) |
| `ss_sysctl.c`   | Protection #23: SysctlGuard |
| `ss_hooks.c`    | One registration per shared hook, dispatching to the protections in order. Since 6.9 each LSM gets one static-call slot per hook; registering a hook twice exhausts them and panics at boot (v11). `ci/check-lsm-hooks.sh` enforces this |

All kernel-side protections from the feature map are present, plus the #1b
privilege-gaining-exec gate added in the security review. The userspace
companions (PAM modules, `secure-sudod`, the `secure-sudo` CLI) and the
installers are complete; see `docs/` for the full command, configuration,
script and security-review documentation.

## Runtime interface so far

| Node | Mode | Meaning |
|------|------|---------|
| `/sys/kernel/secure_sudo/admin_gid` | rw | comma list of up to 16 GIDs treated as sudo, e.g. `27,10` (`unset` = root only); auto-detected at install |
| `/sys/kernel/secure_sudo/block_setid` | rw | enforce #1 UID/GID switch block |
| `/sys/kernel/secure_sudo/block_userns` | rw | gate unprivileged user namespaces |
| `/sys/kernel/secure_sudo/block_setid_exec` | rw | #1b deny non-sudo exec of setuid/setgid/file-cap binaries unless allowlisted |
| `/sys/kernel/secure_sudo/block_flash` | rw | enforce #3 firmware/flash/raw-memory block |
| `/sys/kernel/secure_sudo/lock` | rw (0600) | #16 one-way config lock; writing 1 latches it, writes of 0 are refused, only a reboot clears it |
| `/sys/kernel/secure_sudo/lock_modules` | rw | #16 while locked, also refuse ALL module loads (not just blacklisted) |
| `/sys/kernel/secure_sudo/max_ram_percent` | rw | #7 drop-caches threshold (% used) |
| `/sys/kernel/secure_sudo/check_interval_ms` | rw | #7 sampling interval |
| `/sys/kernel/secure_sudo/drop_cooldown_ms` | rw | #7 minimum gap between drops |
| `/sys/kernel/secure_sudo/ram_spike_enabled` | rw | #7 enable the worker (off by default) |
| `/sys/kernel/secure_sudo/block_tmp_exec` | rw | #12 enforce scratch-tree exec/mmap/mprotect block |
| `/sys/kernel/secure_sudo/block_tmpfs_exec` | rw | #12 extend the block to every tmpfs/ramfs mount and memfd |
| `/sys/kernel/secure_sudo/net_mode` | rw | #10 monitor/host/lan-only/public-only |
| `/sys/kernel/secure_sudo/sudo_max_fails` | rw | #8 failures before a UID is blocked |
| `/sys/kernel/secure_sudo/sudo_window_sec` | rw | #8 sliding window |
| `/sys/kernel/secure_sudo/sudo_block_time_sec` | rw | #8 block duration |
| `/sys/kernel/secure_sudo/sudo_cooldown_enabled` | rw | #8 enable cooldown |
| `/sys/kernel/secure_sudo/timevault` | rw | #13 engage/disengage vault (engage latches `lock`) |
| `/sys/kernel/secure_sudo/timevault_strict_mmap` | rw | #13 also gate PROT_EXEC mmap (shared libraries) while engaged |
| `/sys/kernel/secure_sudo/timevault_denied` | r | #13 count of denied exec attempts |
| `/sys/kernel/security/secure_sudo/events` | r | #9 kernel event stream (blocking read + poll) |
| `/sys/kernel/security/secure_sudo/blacklist` | rw (root) | #2 absolute paths non-sudo users may not exec (matched by device+inode+generation, path, and the SHA-256 of each listed file taken at write time, so a copy elsewhere is refused) |
| `/sys/kernel/security/secure_sudo/setid_exec_allow` | rw (root) | #1b absolute paths of setuid/setgid/file-cap binaries non-sudo users may still run |
| `/sys/kernel/security/secure_sudo/tmp_exec_allow` | rw (root) | #12 scratch-tree exec/mmap exemptions (prefix match) |
| `/sys/kernel/security/secure_sudo/node_allowed_children` | rw (root) | #11 basenames node/SEA may spawn |
| `/sys/kernel/security/secure_sudo/node_sea_binaries` | rw (root) | #11 registered SEA/pkg binary paths |
| `/sys/kernel/security/secure_sudo/sudo_auth` | w (root) | #8 PAM feed: `fail <uid>` / `ok <uid>` |
| `/sys/kernel/security/secure_sudo/driver_blacklist` | rw (root) | #6 blacklisted module SHA-256 hashes and/or names; a name matches the file name and the module's own name (`-` and `_` equal), checked before the module's init runs |
| `/sys/kernel/security/secure_sudo/timevault_allow` | rw (root) | #13 allowlist: `path` or `path <sha256>`, max 16384 entries / 4 MiB, whole list per single write; manage with `secure-sudo vault-allow` |
| `/sys/kernel/secure_sudo/block_home_write` | rw | #4 confine non-sudo writes to home (opt-in) |
| `/sys/kernel/security/secure_sudo/home_map` | rw (root) | #4 `<uid> <home-path>` per line |
| `/sys/kernel/security/secure_sudo/home_write_allow` | rw (root) | #4 extra always-writable path prefixes |
| `/sys/kernel/secure_sudo/binaryvault` | rw (0600) | #17 freeze all executables + libraries (all UIDs); effective at boot via `load` |
| `/sys/kernel/secure_sudo/binvault_maint` | r (0400) | #17 read-only: 1 if THIS boot opened the vault for maintenance |
| `/sys/kernel/security/secure_sudo/binvault_allow` | rw (root) | #17 directory prefixes exempt from BinaryVault; whole list per write |
| `/sys/kernel/secure_sudo/block_wifi` | rw (0600) | #19 RadioGuard: 1 = keep Wi-Fi off |
| `/sys/kernel/secure_sudo/block_bluetooth` | rw (0600) | #19 RadioGuard: 1 = keep Bluetooth off |
| `/sys/kernel/secure_sudo/ethernet_only` | rw (0600) | #19 RadioGuard master switch: 1 = keep both radios off |
| boot param `secure_sudo.tpm_maint=1` | — | #5 permit TPM clear this boot |
| boot param `secure_sudo.binvault_maint=1` | — | #17 open BinaryVault this boot so binaries can be updated |
| `/sys/kernel/secure_sudo/timevault_allow_autoupdate` | rw (0600) | #13 honour auto-update (no-hash) entries; 0 refuses them |
| `/sys/kernel/secure_sudo/timevault_max_entries` | rw (0600) | #13 configurable allowlist cap (1..131072) |
| `/sys/kernel/secure_sudo/prguard_enabled` | rw (0600) | #20 Process Runtime Guard on/off |
| `/sys/kernel/security/secure_sudo/prguard_allow` | rw (root) | #20 exempt exe paths; whole list per write |
| `/sys/kernel/secure_sudo/prguard_observe` | rw (0600) | #20 emit a mem-access event per cross-process read/write |
| `/sys/kernel/secure_sudo/bpf_guard` | rw (0600) | #22 deny bpf(2) to non-sudo users |
| `/sys/kernel/secure_sudo/bpf_lock_tracing` | rw (0600) | #22 once locked, refuse tracing-class BPF programs (all UIDs); default 1 |
| `/sys/kernel/secure_sudo/perf_guard` | rw (0600) | #22 deny perf_event_open(2) to non-sudo users |
| `/sys/kernel/secure_sudo/sysctl_guard` | rw (0600) | #23 refuse writes to security-critical sysctls + binfmt_misc (all UIDs) |
| `/sys/kernel/secure_sudo/audit_events` | rw (0600) | #9 also send events to the kernel audit subsystem (auditd) |
| `/sys/kernel/secure_sudo/lock_confidentiality` | rw (0600) | #16 while locked, also refuse lockdown's confidentiality class |
| `/sys/kernel/secure_sudo/events_dropped` | r (0400) | #9 events lost because the ring was full (whole events are dropped, never parts of lines) |
| `/sys/kernel/secure_sudo/audit_events_dropped` | r (0400) | #9 audit records refused by the audit backlog |
| `/sys/kernel/secure_sudo/events_sequence` | r (0400) | #9 the last sequence number given to an event this boot |
| `/sys/kernel/secure_sudo/events_boot_id` | r (0400) | #9 the `boot_id` this boot's event records carry |

Kernel event lines use schema-v1 JSON: `schema_version`, per-boot random
`boot_id`, per-boot `sequence`, `realtime_ns`, `monotonic_ns`, an event
category, the current task under `actor` (`pid`, `uid`, `kernel_started`),
typed `target`, `operation`, `object`, `decision`, `reason`, numeric
`target_pid` and `target_uid`, the escaped original `message`, and a
`truncated` boolean that is true if the formatted message, event type, or a
typed string was shortened to its bound. Missing structured values are JSON
null.

Target identity is always typed:

* A denial of the calling task's own action (most of them) names that task:
  `target_pid`/`target_uid` equal the actor's, and `target` is a short label
  of what kind of subject it is (`current_user`, `current_process`,
  `module_loader`, ...).
* Cross-process events (ptrace, `process_vm_writev`, `/proc/<pid>/mem`)
  carry the other task's PID and UID.
* The cooldown block (`failure_threshold`) carries the blocked UID and a
  null `target_pid`, since its subject is a user, not a task.
* Only the boot-time `event_log` record has a null target: no task or user
  is its subject.

`object` holds the path or name acted on, bounded at 256 output bytes, so a
consumer never needs the message: `secure-sudod` takes the TimeVault path
from `object` and the cooldown UID from `target_uid`. A record with any field
cut short has `"truncated":true` and is never acted on.

Deferred work: `actor.kernel_started` is true when the actor is a kernel
thread or a process the kernel started itself, such as `modprobe` run for a
module autoload or a core-dump pipe handler (its parent is a kernel thread).
Such a record names the helper, not the userspace task whose action caused
the work, which the kernel does not keep; the flag says so rather than
leaving the helper to look like the initiator. PID 1 is not marked.

Typed string fields are escaped and bounded to keep records within the ring's
record-size limit. Decisions use `deny`, `allow`, `observe`, or `enforce`;
operation, object and reason values are producer-defined stable identifiers,
not inferred from message text. Non-ASCII message bytes are encoded as
`\u00xx` byte escapes so the JSON remains valid even when a path is not UTF-8;
`secure-sudod` decodes these escapes back to the original bytes.
`audit_events_dropped` counts calls for which the audit subsystem did not
provide an event buffer; it is not a complete audit backlog accounting
interface.

What a record can reveal. Records hold UIDs and PIDs, process names
(`comm`), and the paths, module names or hashes, sysctl names and exec
targets a denial was about. Paths and process names are chosen by users, so
they can carry personal or project names. No producer records file
contents, command arguments, environment, passwords, OTP codes or keys.
Every copy is root-only on the host: the ring is `0400`, the daemon's local
log and queue are `0600` in `0700` directories. The audit feed (opt-in) is
as readable as the host's audit log. A collector or an evidence bundle that
receives the records needs the same protection as the host's own logs.

Sequence numbers are given under the ring lock, in the order records enter
the ring, starting at 1 each boot. Because the ring drops the oldest whole
records, the records a reader sees form contiguous runs, and any jump in
`sequence` is exactly the records lost to a full ring. `events_dropped` also
counts events raised before securityfs was up, which never got a number.

`secure-sudod` turns loss into records of its own, written to the local log
and forwarded like kernel events, with `"source":"secure-sudod"`:

* `event_stream`: the first record of a boot it had not seen. Carries the
  new and previous `boot_id`, and the last sequence seen in the previous
  boot.
* `event_gap`: `first_missing`..`last_missing` for a jump in the sequence,
  with `kernel_events_dropped` at that moment.
* `event_sequence_error`: a number that did not increase.

The daemon keeps its position in `/var/lib/secure_sudo/event-cursor`, so
records lost while it was stopped are reported when it restarts. After a
daemon crash a gap can be overstated by a few records, but never hidden.
`secure-sudo health` reports `event_gaps`/`events_missing` and degrades
while they are non-zero.

The ring is 64 KiB and each complete JSON line is capped at 1024 bytes (the
record is built in a static buffer under the ring lock, not on the hook's
stack; with `audit_events` on, the audit feed gets its own copy, made with
GFP_ATOMIC, and a failed copy counts in `audit_events_dropped`). It has no producer-side rate limit: on saturation it discards oldest
whole records, increments `events_dropped`, and preserves complete-line
framing. At least 64 maximum-size records fit at once; typical records are
400 to 600 bytes, so 100 to 160 fit. A read returns whole records only (up
to the last complete one that fits the buffer), so a reader with a buffer
smaller than the ring never holds half a record that a producer then
discards; only a buffer smaller than one record gets a partial one. Consumers
must monitor the drop counter and sequence numbers rather than assume complete
history.

Example shape:

```json
{"schema_version":1,"boot_id":"0123...","sequence":42,"realtime_ns":0,"monotonic_ns":0,"event_type":"perf","actor":{"pid":1000,"uid":1000,"kernel_started":false},"target":"current_user","operation":"perf_event_open","object":"performance_event","decision":"deny","reason":"perf_guard","target_pid":1000,"target_uid":1000,"message":"perf: denied ...","truncated":false}
```

All `/sys/kernel/secure_sudo/*` knobs are mode 0600 (root only) and refuse writes once the config is locked. Every securityfs policy file is a whole-file replace: one write sets the entire list. The CLI (`secure-sudo`) is the supported way to drive all of them: `settings`, `get`, `set`, `list`, `load`, `net`, `radio`, `timevault`, `prguard`, `lock`, `vault-allow`, `detect-admins`. See `docs/` for the full reference.
