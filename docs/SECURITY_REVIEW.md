# secure_sudo — security review and hardening

This is a defensive code review of the whole secure_sudo source tree (the
kernel LSM, the userspace CLI/PAM/daemon/OTP helper, the scripts and the
installers), done from a NIST perspective — NIST SP 800-218 (Secure Software
Development Framework, practice PW.7/PW.8: review and verify) and the relevant
SP 800-53 Rev. 5 controls (AC-6 least privilege, SC-39 process isolation,
SI-10 input validation, AU-9 protection of audit information, CM-5 access
restrictions for change) — and against the classes of publicly known CVEs that
apply to an LSM that parses untrusted input and makes exec/privilege
decisions.

Every issue below was **fixed in this tree**, and each fix was then re-reviewed
for issues of its own. Findings #15, #16, #18 and #19 are the second-pass reviews of the new
BinaryVault (#17), RadioGuard (#19), TimeVault v6, and Process Runtime Guard
(#20) work. The full LSM (16 `.c` files, including BinaryVault and RadioGuard) compiles
cleanly with `-Werror` against real 6.11 kernel header trees; the CLI, daemon
and PAM modules compile cleanly with `-Wall -Wextra`.

Scope note: this review hardens the implementation. It does not change the
project's threat model — several protections (home-write, TimeVault strict
mmap) remain opt-in because they are aggressive, and the design still assumes a
trusted install-time root. "fail closed" below means that when the code cannot
make a decision (out of memory, an unresolvable path), it denies rather than
allows.

---

## Findings and fixes

### 1. Confused-deputy on the policy-write check (CWE-863) — AC-6

**Was:** every securityfs/sysfs write checked `capable(CAP_SYS_ADMIN)`, which
tests the *current task*. A less-privileged process could open the control
file and pass the fd to a privileged one (or vice versa), the classic
confused-deputy pattern behind bugs like CVE-2019-13272.

**Fix:** a shared `ss_may_admin(file)` helper that requires CAP_SYS_ADMIN *in
the initial user namespace* and, for securityfs files, also checks the
credentials the file was **opened** with (`file_ns_capable`). Every knob and
list writer now uses it. All knobs are also mode `0600`.

**Re-review:** the opener-credential check is skipped only where `file` is
genuinely absent (sysfs `kobj_attribute` stores, which the VFS only routes from
a writer that already passed the open-time permission check); those still
require init-ns CAP_SYS_ADMIN.

### 2. Path checks bypassable from a chroot / mount namespace (CWE-41) — SC-39

**Was:** path-based decisions used `d_path()`, which renders a path relative to
the **caller's** root. A non-sudo user in a chroot could make
`/jail/usr/bin/x` appear as `/usr/bin/x` and slip past (or fail to match) a
path rule.

**Fix:** a shared `ss_file_path()` uses `d_absolute_path()` (namespace-root
relative), falling back to `d_path()` only for pseudo files with no absolute
path. Used by the command blacklist, tmp-exec, TimeVault, home-write, the node
guard, firmware and TPM checks.

**Re-review:** pseudo files (pipes, sockets, memfd) correctly return a
non-`/` string; callers that must fail closed check `IS_ERR()` and, where
relevant, that the path begins with `/`.

### 3. Several hooks failed *open* on error (CWE-636) — SI-10

**Was:** on `kmalloc`/`d_path` failure the command blacklist, tmp-exec and
firmware hooks returned `0` (allow). An attacker can induce allocation failure
or over-long paths (`d_path` returns `-ENAMETOOLONG`) to skate past a deny
rule.

**Fix:** these hooks now fail **closed** — a non-sudo exec / sensitive open
whose decision cannot be completed is denied (`-EPERM`/`-ENOMEM`). The
RAM worker and the event log, where a failure is not a security decision, still
degrade gracefully.

**Re-review:** fail-closed is scoped to non-sudo actors and to the specific
sensitive operation, so it cannot wedge normal system boot (sudo users and
unrelated opens are unaffected).

### 4. Setuid/file-capability exec left non-sudo privilege escalation open (CWE-269) — AC-6

**Was:** #1 blocked the `setuid()` *syscall* path, but a non-sudo user could
still gain another identity by **executing** a setuid-root or
file-capability binary — `su` with a known password, or a vulnerable helper.
This is the entire class behind CVE-2021-4034 (PwnKit/pkexec),
CVE-2021-3156 (Baron Samedit/sudo) and CVE-2023-4911 (Looney Tunables via the
setuid dynamic loader).

**Fix:** a new `bprm_creds_from_file` hook (`block_setid_exec`, with the
`setid_exec_allow` list) denies any non-sudo exec whose computed credentials
would raise euid/egid or the permitted capability set, unless the program is
explicitly allowlisted. Off by default (needs its allowlist populated first).

**Re-review:** the privilege comparison is against the acting task's current
creds (`cap_issubset`, `uid_eq`), so a root daemon dropping privileges and a
sudo user are unaffected; the hook runs before the exec's point of no return so
a denial is returned cleanly to userspace.

### 5. Driver blacklist hashed the wrong bytes and missed `init_module` (CWE-367) — CM-5

**Was:** #6 hashed the module file via a separate read in `kernel_read_file`.
That is a time-of-check/time-of-use gap (the file can change between our read
and the loader's, e.g. on NFS/FUSE), and `init_module(2)` — which passes a
memory buffer and no file — bypassed the hash list entirely.

**Fix:** hashing now happens in `kernel_post_read_file` **and**
`kernel_post_load_data`, over the exact bytes the kernel is about to load, so
`finit_module` and `init_module` are both covered and there is no TOCTOU
window. Name matching still happens at `kernel_read_file`. The hash uses the
in-kernel SHA-256 library, avoiding a crypto-API allocation inside a load hook.

**Re-review:** both post-hooks are no-ops unless a hash list is loaded; a
hashing failure on a non-empty list denies the load (fail closed).

### 6. TimeVault was bypassable several ways (CWE-367, CWE-693) — SI-7

**Was:** the vault matched only the resolved path, allowed path-only entries
(no hash required), and did not stop `ld.so /allowed/binary`, a swap of the
allowlisted file, or a `PROT_EXEC` mmap of an unlisted library. Disengage was
always permitted even while locked.

**Fix:** every entry must pin a SHA-256; at exec the file must be on the list,
still linked, root-owned, not group/world-writable, not open for writing, and
hash-match. The dynamic loader and package managers are always denied.
Allowlisted files cannot be written or truncated while engaged. An optional
`timevault_strict_mmap` extends the check to `PROT_EXEC` mmap/mprotect.
Engaging requires a non-empty list and latches the lock; disengage is refused
while locked.

**Re-review:** the allowlist is parsed into sorted arrays (binary search, so a
16k-entry list is not an O(n) scan on every exec), the inode index used by the
write-guard is rebuilt atomically with the list, and all buffers use `kvmalloc`
so a large list cannot fail a high-order allocation.

### 7. The one-way lock was not actually one-way (CWE-667) — CM-5

**Was:** the lock lived in a `bool` written with `WRITE_ONCE`, and the TimeVault
*disengage* path cleared `timevault_enabled` while the box was "locked" — and
nothing stopped a root attacker from loading a module or using kexec/`/dev/mem`
to flip the bit back.

**Fix:** the lock is an atomic latch (`atomic_cmpxchg`) with a single writer
(`ss_lock_engage`) and **no clear path anywhere** in the kernel; a write of `0`
is refused and logged. While locked, the LSM answers the `locked_down` hook for
the whole kernel-integrity class (kexec, hibernation, `/dev/mem`/kmem, MSR,
BPF-write, kprobes…) and refuses module loads (`lock_modules`), kexec image
loads and new trust anchors, so the lock cannot be undone without a reboot.

**Re-review:** `ss_lock_engage` is idempotent and logs only on the first latch;
the lockdown hook returns 0 (defers) when unlocked, so it never interferes with
normal operation or with a stacked lockdown LSM.

### 8. Log injection into the event stream (CWE-117) — AU-9

**Was:** event lines embed attacker-chosen strings (file names, exec paths). A
name containing a newline could forge whole event lines, and the daemon
*acts* on some events (it kills processes named in cooldown lines).

**Fix:** `ss_event()` replaces every control character (and DEL) with `?`
before the line enters the ring, so one event is always one line.

**Re-review:** the scrub runs on the already-length-bounded line; the
timestamp and format string are trusted, only the variadic payload is
attacker-influenced, and it is fully covered.

### 9. Event-ring reader/writer race (CWE-362)

**Was:** `ss_event()` removes old bytes when the ring is full, so the kfifo has
two writers' worth of mutation, but the reader used `kfifo_to_user()` without
the ring spinlock — a data race that can corrupt the fifo indices.

**Fix:** the reader drains under `kfifo_out_spinlocked()` into a bounce buffer,
then copies to userspace outside the lock. The "make room" path uses
`kfifo_skip`.

### 10. NodeJS guard cleared its mark too early (CWE-696)

**Was:** the guard flipped the task's node-mark during `bprm_check`. If the
exec then failed after that point, a node process could end up unmarked and
free to spawn anything; and a file merely *named* `node` in a scratch dir was
treated as the runtime.

**Fix:** the decision is *staged* in `bprm_check` and applied only in
`bprm_committing_creds`, past the exec's point of no return. Node runtimes are
recognised by real install paths or the registered SEA list, not by basename.
Child matching supports exact paths, not just basenames.

### 11. Cooldown keyed on `argv[0]`; unbounded table (CWE-400)

**Was:** the cooldown block compared `bprm->filename` (which tracks argv[0]),
so a symlink or a copy evaded it; and the fail-table had no size cap, so the
PAM feed could grow it without limit.

**Fix:** the block is enforced on the resolved program and on every setuid-root
binary (covering sudo/su/doas/pkexec/run0 and renamed tools). The table is
capped (`SS_CD_MAX_ENTRIES`) and prunes expired entries before admitting a new
UID.

### 12. Numeric knobs unbounded (CWE-1284) — SI-10

**Was:** `max_ram_percent`, the intervals and the cooldown counters accepted
any `u32`. A root typo (`max_ram_percent = 0`) could turn the RAM worker into a
constant cache-drop storm.

**Fix:** each numeric knob is range-checked (`ss_check_range`) and returns
`-ERANGE` outside sane bounds (documented in CONFIGURATION.md).

### 13. Command blacklist inode match ignored inode reuse (CWE-367)

**Was:** matching on `(dev, ino)` alone can misfire after an inode number is
reused by a different file.

**Fix:** the match also compares `i_generation`, which the filesystem bumps on
reuse.

### 14. Userspace hardening — SI-10, AC-6

* **CLI `set`** now pushes to the kernel first and only persists to the config
  if the kernel accepted the value, so the saved config can never diverge from
  live policy; `lock` confirms unless `-y`.
* **`vault_allow.c` / `timevault-whitelist.sh`** open files with
  `O_NOFOLLOW`/`realpath`, hold a `flock`, write the conf atomically
  (`mkstemp`+`rename`), reject whitespace paths the kernel cannot store, and
  bound the list to the kernel's limits.
* **`secure-sudod`** sets `umask(077)` so logs and quarantined files are never
  world-readable (AU-9), and process-scan buffers were sized to remove any
  `snprintf` truncation.
* **`quarantine.sh`** uses `--` on every filename-bearing command so an
  attacker-chosen name cannot be parsed as an option (CWE-88).
* **PAM `pam_secure_otp.so`** passes the candidate password on the helper's
  **stdin**, never argv, so it cannot leak through `ps`/`/proc` (CWE-214); the
  OTP helper compares with constant-time `CRYPTO_memcmp` (CWE-208) and wipes
  the seed from an `mlock`'d buffer after use.

### 15. BinaryVault second-pass review (#17) — SI-7 / CM-5

**New feature.** BinaryVault (`ss_binvault.c`) freezes every executable and
shared library against modification, for all UIDs including root, so on-disk
code cannot be tampered with to gain persistence. It was reviewed the same way
as the rest of the tree:

* **Hard-link alias to a no-exec-bit library (CWE-367 / CWE-706).** A library
  is classified as protected partly by *location* (a `.so` under a library
  tree). A privileged attacker could hardlink such a library into a writable
  directory — where the location test no longer matches — and write through
  the alias to mutate the real inode. **Fixed** by a `path_link` hook that
  refuses to create any new hard link whose source is a protected binary, so no
  second, unprotected name to a frozen inode can be made while engaged.
  Executables are caught through any name regardless, because the execute bit
  is an inode property.
* **chmod downgrade (CWE-693).** Stripping a binary's execute bit could slip a
  later rewrite past the classifier. **Covered** by the `path_chmod` hook,
  which gates on the *current* mode: a file that is a binary now cannot be
  chmod'd at all while engaged.
* **xattr / capability re-labelling (CWE-732).** File capabilities and IMA/EVM
  labels live in extended attributes, so writing them changes what a binary
  *is* without changing its bytes (e.g. `setcap cap_setuid+ep`). **Covered** by
  `inode_setxattr`/`inode_removexattr` hooks.
* **Atomic replace via rename (CWE-367).** The standard dpkg/rpm "write new
  file, rename into place" swap. **Covered**: `path_rename` gates both the
  source and the destination, so renaming *over* an existing binary is refused.
* **Fail-closed.** Every hook denies on an unresolvable or truncated path, out
  of memory, or any state it cannot classify — consistent with finding #3.
* **Update path is not forgeable.** The only way to open the vault is the
  read-only boot parameter `secure_sudo.binvault_maint=1` (0444, settable only
  on the kernel command line), not a package-manager heuristic that a process
  could spoof. The toggle knob is `0600` and frozen by the #16 lock.

Residual (documented, in scope by design): a hard link that *predates* boot,
and mounting a filesystem *over* a system directory, are left to #13 TimeVault,
which pins each allowed file by SHA-256 and so detects changed bytes or an
overlay regardless of path. BinaryVault freezes existing files; deciding
whether a *new* program may execute is #2/#1b/#12/#13's job.


### 16. RadioGuard second-pass review (#19) — AC-18 / SC-40 / CM-7

**New feature.** RadioGuard (`ss_radio.c`) disables Wi-Fi/Bluetooth and offers
an `ethernet_only` master switch. It was reviewed for the ways a wireless
lockdown is usually defeated:

* **Config flag ≠ enforcement.** A knob that only userspace honours is bypassed
  by not asking userspace. RadioGuard enforces in the kernel across three
  independent layers so no single trick re-enables a radio: the driver stack's
  **core module is refused at load** (`kernel_read_file`/READING_MODULE — a
  driver cannot run without `cfg80211`/`bluetooth`), **AF_BLUETOOTH sockets are
  denied** (`socket_create`), and **`/dev/rfkill` writes are denied**
  (`file_open` FMODE_WRITE) so a soft-blocked radio cannot be un-blocked.
* **Module-name evasion (CWE-41).** The load check resolves the module's path
  with the chroot-safe `ss_file_path()` and matches the basename with the
  `.ko`/`.ko.zst` suffix stripped and `-`→`_` normalised, so `cfg-80211.ko`,
  `cfg80211.ko.zst` and a path-games copy all match the same core name.
* **rfkill match precision.** The `/dev/rfkill` deny matches the fully resolved
  absolute path exactly (not a substring), so an attacker cannot dodge it with
  a look-alike name, and cannot satisfy it with a chrooted `/dev/rfkill` (the
  path is resolved against the real mount namespace root).
* **Honest scope (documented, not papered over).** If the wireless drivers are
  built *into* the kernel there is no module load to intercept (layer 1 is
  moot) — the real control there is rfkill (layer 3) plus not compiling those
  drivers; and enabling a knob does not tear down an already-resident driver
  this boot. On a configured box `secure-sudo load` runs at early boot so the
  module is denied before it can load; a running box needs `rfkill block` or a
  reboot. `init_module(2)` with a raw buffer carries no name, so the backstop
  for a locked appliance is #16's `lock_modules` (refuses all module loads).
* **Same gate discipline as the rest of the tree.** All three knobs are
  `0600`, go through `ss_may_admin()`, and are refused once the config lock
  latches (CM-5), so the lockdown itself cannot be toggled off on a locked box.


### 17. Command blacklist used an uninitialised generation (CWE-457/CWE-908) — CM-5

**Found during the v5 full-source comment pass.** `ss_bprm_check_security()`
compared the exec'd inode's generation (`bl_list[i].gen == gen`) but never
assigned `gen` from `inode->i_generation`, so the comparison used an
uninitialised stack value. Effect: the robust device+inode+**generation** match
(the half of #2 that catches a *renamed* blacklisted binary) almost never fired
- it matched only when the garbage stack value happened to equal the stored
generation. Path matching still worked, but the inode match was effectively
dead. **Fixed** by reading `gen = inode->i_generation;` alongside `dev`/`ino`
before the match. (It slipped past `-Werror` because the value is read across a
`kmalloc`/`mutex_lock`, which defeats the compiler's uninitialised-use
analysis.)


### 18. TimeVault auto-update + quarantine review (#13, v6) — SI-7 / CM-5

The v6 TimeVault additions (auto-update entries, a configurable size cap, and
quarantine-on-exec-mismatch) were reviewed:

* **Auto-update entries are a deliberate hole, gated twice.** An `auto` /
  `autodir` entry skips the hash check, so it is only as safe as the path it
  names. Two gates bound the risk: (1) the entries exist only if an admin wrote
  them while the config was unlocked, and (2) they are honoured only while
  `timevault_allow_autoupdate = 1` — turning that off refuses them outright (no
  silent fall-through). Auto-update files are deliberately **not** added to the
  inode write-guard (they must be writable to self-update), which is documented
  as the cost of the feature; hash entries remain write-protected.
* **autodir uses the component-boundary prefix test** (`ss_path_under`), so
  `/opt/app autodir` covers `/opt/app/...` but never `/opt/app-evil`, closing
  the usual prefix-confusion (CWE-41).
* **No weakening of the hard denials.** Package managers, the dynamic loader,
  and unlinked files are still denied *before* any allowlist lookup, so an
  auto-update entry can never re-enable them.
* **Configurable cap can't over-allocate (CWE-789).** `timevault_max_entries`
  is range-checked (1..131072) and the parser allocates to that cap, not an
  attacker-chosen size; the 16 MiB text cap still bounds a single write.
* **Quarantine path parsing is strict.** The daemon acts only on the kernel's
  own `timevault: denied exec <path> (hash mismatch|not on allowlist)` events,
  requires an absolute path and an existing regular file before touching
  anything, and reuses the `--`-hardened quarantine helper (CWE-88). The kernel
  has already blocked the exec, so quarantine is post-hoc cleanup, not the
  enforcement — a failed quarantine cannot let the binary run.

### 19. Process Runtime Guard second-pass review (#20) — SC-39 / SI-16 / AC-6

New feature (`ss_prguard.c`). Reviewed for the ways a memory-tamper guard is
usually bypassed:

* **One choke point for three attack routes.** `process_vm_writev()` and
  `/proc/pid/mem` writes both call `ptrace_may_access(... ATTACH ...)`, which
  invokes the `ptrace_access_check` hook — so guarding that one hook covers all
  three of ptrace-attach, `process_vm_writev`, and `/proc/pid/mem`. Verified the
  hook only denies **ATTACH** mode, leaving non-invasive `PTRACE_MODE_READ`
  alone so ordinary tooling is not broken.
* **traceme can't be used to invite a non-exempt tracer.** `ptrace_traceme` is
  hooked separately and resolves the *prospective tracer* (@parent), not the
  caller, so a victim cannot `PTRACE_TRACEME` its way open to a non-exempt
  process (CWE-284).
* **W^X is enforced on both creation and transition.** `mmap_file` and
  `file_mprotect` both reject `PROT_WRITE|PROT_EXEC` together, so neither
  mapping W+X directly nor `mprotect`-ing an existing page to W+X works.
  Well-behaved JITs that flip between W and X (never both at once) are
  unaffected; those that truly need W+X go on the exemption list.
* **Fail-closed identity.** Exemption is keyed on the resolved path of the
  process's own `mm->exe_file` (reference-counted via `get_mm_exe_file`, always
  `fput`); if it cannot be resolved while the guard is on, the process is
  treated as non-exempt (guarded), never exempt. The list is sorted and
  bsearch'd.
* **Lock discipline.** The toggle and the exemption list are `0600`, go through
  `ss_may_admin()`, and are refused once the #16 lock latches, so the guard
  cannot be turned off or widened on a locked box (CM-5).

Residual (documented): a process already being traced when the guard is enabled
is not retro-actively detached; the guard prevents *new* attaches. Enable it
early (at boot via `load`) on an appliance that wants the full guarantee.

### 20. PheonixBox second-pass review (#21) — SI-7 / SC-28 / CM-5

New userspace feature (`userspace/pheonixbox/pheonixbox.c` + a daemon timer).
Reviewed for the ways a snapshot/repair tool is usually broken, and for the
central honesty issue:

* **No "reversible hash" — stated, not faked.** The request asked to "compress
  the contents into a reversible hash". SHA-256 is one-way; it cannot be
  reversed with or without a password. Building a tool that pretended to would
  be a lie that fails the first time it is relied on. PheonixBox instead uses
  the hash only to *detect* (manifest) and a zlib-compressed copy of the real
  bytes to *restore* (snapshot store). The design header, the docs, and the CLI
  help all say this plainly. (This is a correctness/trust finding, not a CWE.)
* **The store is the trust root, and it is root-only.** `/var/lib/secure_sudo/
  pheonixbox` is created `0700`, every blob/acl/manifest is `chmod 0600`, and
  the program refuses to run as non-root. So no unprivileged user can read the
  originals, forge a blob, or tamper the manifest to make a malicious file
  "known good" (CWE-276/SC-28). A reviewer confirmed no path writes the store
  world- or group-readable.
* **Repair never leaves a file writable.** `blob_restore` makes the target
  writable only for the in-place overwrite, `fsync`s, then immediately re-applies
  the read-only mode (`mode & ~(S_IWUSR|S_IWGRP|S_IWOTH)`) on every exit path.
  The scan also re-locks a file whose write bits merely re-appeared, so the
  read-only invariant is self-healing (SI-7).
* **Symlink / traversal safety.** The recursive walk uses `lstat` and only
  descends real directories and snapshots real regular files — symlinks, device
  nodes, FIFOs and sockets are skipped, so a planted symlink under a protected
  tree cannot redirect a restore to overwrite an arbitrary file (CWE-59). Depth
  is capped at 24 to bound a crafted-tree recursion, and oversized files
  (>256 MB) are skipped rather than read into RAM (CWE-400).
* **Manifest parsing is robust.** The path is taken as the entire remainder of
  the line (not a fixed token), so paths with internal spaces are not silently
  truncated; paths containing whitespace are refused at snapshot time with a
  warning, because the line format cannot round-trip them unambiguously. Mode is
  parsed as octal, uid/gid as unsigned; a malformed line is skipped, not acted
  on.
* **Atomic writes.** The manifest and the conf file are written to a `mkstemp`
  temp and `rename`d into place, so an interrupted snapshot or edit never leaves
  a half-written, trusted file (CWE-367).
* **Shell use in ACL capture.** `getfacl`/`setfacl` are invoked via `system()`
  with the path single-quoted. Because the program is root-only and the paths
  come from a root-written conf (and whitespace paths are already refused), this
  is not an injection vector a non-root user can reach; noted so a future change
  that lets non-root influence the path list would need to revisit it.

Residual (documented): PheonixBox is periodic (daemon runs `scan` ~every 30 s),
so repair happens within one interval, not inline — it is a *healing* layer, not
an inline *blocking* one; pair it with BinaryVault (#17) / TimeVault (#13) for
inline immutability of executables. If the store itself is deleted there is
nothing to restore from, so keep `/var/lib/secure_sudo` on protected storage.

### 21. ProcGuard review (runtime guard) — AC-3 / SI-4 / SC-28

Allowlist process enforcer. The dangerous property is "kill everything not
listed", reviewed accordingly:

* **Fail-safe against an incomplete list.** Refuses to run with an empty/missing
  allowlist (would mean "kill all"); always exempts PID 1, kernel threads (no
  `/proc/pid/exe`), its own process tree, and the secure_sudo binaries,
  regardless of the list. Default `mode = monitor` only logs what it *would*
  kill — enforce is a deliberate opt-in after the list is proven in monitor.
* **Identity by on-disk path, not name.** A process is matched by the realpath
  of `/proc/<pid>/exe`, not by `comm`/`argv[0]` (which an implant sets freely),
  so renaming to `[kworker]` does not grant it allow status (CWE-290).
* **Respawn classification bounds action.** A one-off non-allowed process is
  killed; only a path that respawns past the threshold within the window is
  escalated to quarantine+remove, so a transient is not deleted off disk.
* **Quarantine is compressed + hourly-rotated + root-only.** The infected binary
  is stored compressed under a 0700 tree in this hour's bucket, so the stored
  sample cannot be executed in place and a fixed path cannot be targeted to
  re-expand it (the stated anti-reinfection goal). Removal of the live file is
  gated by `remove_on_infection`.
* **Off-box sync is operator-defined.** `sync_cmd` is a root-written template
  with `%f` single-quoted; it runs only if configured. Noted: it is `system()`,
  so the operator owns what it runs — it is not reachable by a non-root user.

Residual: ProcGuard is a userspace poller (default 5 s), so a very short-lived
process can run to completion between scans; it is an allowlist *enforcer/
remover*, complementary to the kernel's exec-time controls (#2/#1b/#12/#13),
not a replacement for them.

### 22. DriverGuard review (runtime guard) — SI-7 / CM-5

Driver-file integrity + repair. `baseline` pins each module by SHA-256 and keeps
an hourly-rotated compressed backup; `scan` restores a changed/missing module
from the newest backup only in `mode = enforce`. Restore writes via a temp-free
`store_restore_compressed` (O_TRUNC + fsync, 0600). The manifest and backups are
0600 under a 0700 tree. Honest scope: this guards the module files on disk; a
module already resident in the kernel is covered by core finding #5/#6 (loaded-
bytes hashing), noted so the two are not confused. New modules added by a
legitimate kernel update are not in the manifest and are simply not protected
until the next `baseline` — they are never deleted.

### 23. BootGuard review (runtime guard) — SI-7 / CM-5 (stage-at-boot)

Same safety stance for `/boot`: a live rewrite under a running kernel is unsafe,
so tamper is **staged** (restore list + `PENDING` flag, 0600) and applied at the
next boot by a systemd unit that no-ops unless `PENDING` is set; a forced live
restore needs `apply-now --i-understand-the-risk`. Restores come from the
hourly-rotated compressed backups. Honest limit, documented: the systemd unit
applies as early as a normal unit can (after `/boot` mounts, before services use
it); restoring before *anything* reads `/boot` needs an initramfs hook — the
unit is the practical default, the initramfs hook the stronger option. New boot
files are reported, never deleted (kernel updates add files).

### 24. Locus + shared libs review (runtime guard) — SC-39 / SC-28 / AC-4

The allocator is a minimal attack surface by design: a fixed `ALLOC <purpose>`
→ `OK <path>` protocol that only names a directory and touches nothing else.
Reviewed:

* **Purpose is constrained**, `[A-Za-z0-9-]`, ≤63 chars, so it cannot encode a
  path or `..`; an unknown purpose is refused unless a `default_root` is set.
* **The GUI is read-only**: GET-only, no request path is ever interpreted as a
  filesystem path, no file serving, `X-Content-Type-Options: nosniff`. It can be
  kept on `127.0.0.1` (default) while the allocator is on the LAN.
* **Client-side validation**: a guard validates Locus's reply (absolute, no
  `..`, no control chars) before writing to it, so a rogue/spoofed allocator
  cannot steer a guard's writes. Locus is trusted only to *name* a location.
* **Logging never blocks the guard**: `ssaddon_log` sends to the remote
  collector best-effort (failed `send()` ignored), local writes are 0600 under a
  0700 dir, and a size cap rotates the local file. Exposure note: the
  allocator/GUI bind addresses are the operator's responsibility — the defaults
  are loopback, and the docs say to put only the allocator on the LAN.


---

## Residual notes / assumptions

* The model trusts root at install time: whoever runs `install.sh` and sets the
  initial policy is trusted. The lock exists precisely to freeze that trusted
  state afterwards.
* `secure_sudo` is a *minor* LSM and stacks after the major LSMs; its denials
  are additive. It must be built-in (it registers credential hooks) and listed
  in `CONFIG_LSM` — the installer does this.
* TPM-clear (#5) and firmware (#3) blocks rely on the standard device
  numbers / sysfs layout; a wildly non-standard platform should be verified.
* The home-write (#4) and TimeVault strict-mmap knobs stay **opt-in**: they are
  powerful enough to break a running system if enabled without the matching
  allowlists, which would itself be an availability problem.
* Not yet exercised against a *booted* 6.12 kernel on real hardware — it
  compiles clean against 6.11/6.14 header trees here and builds as part of
  `install.sh`; a boot test on the target is the last mile.
