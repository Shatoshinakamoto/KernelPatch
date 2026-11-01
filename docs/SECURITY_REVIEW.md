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
(#20) work. Findings #35–#47 came from v12's tests and boot runs rather than
from reading the code, and several of them (the boot panic, OTP replay, the
PAM order, the IPv6 gap) had survived every earlier review. Findings
#48–#50 came from reviewing the P1 event, forwarding and evidence work
merged after v12. The full LSM (20
`.c` files) compiles cleanly with `-Werror` against the 6.11, 6.12.114 and
6.14 headers and in six in-tree kernel configurations (`ci/build-gate.sh`);
the CLI, daemon, PAM modules and add-ons compile with `-Werror`.

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

### 21. ProcGuard review (v8 add-on) — AC-3 / SI-4 / SC-28

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

### 22. DriverGuard review (v8 add-on) — SI-7 / CM-5

Driver-file integrity + repair. `baseline` pins each module by SHA-256 and keeps
an hourly-rotated compressed backup; `scan` restores a changed/missing module
from the newest backup only in `mode = enforce`. Restore writes via a temp-free
`store_restore_compressed` (O_TRUNC + fsync, 0600). The manifest and backups are
0600 under a 0700 tree. Honest scope: this guards the module files on disk; a
module already resident in the kernel is covered by core finding #5/#6 (loaded-
bytes hashing), noted so the two are not confused. New modules added by a
legitimate kernel update are not in the manifest and are simply not protected
until the next `baseline` — they are never deleted.

### 23. BiosGuard review (v10 add-on) — SI-7 / CM-5 (detection only)

The central decision is to **not** write firmware at all. A generic userspace
firmware write bricks boards, so BiosGuard was reduced to pure detection in v10:
it fingerprints DMI (`/sys/class/dmi/id/*`) and the ACPI tables
(`/sys/firmware/acpi/tables/*`), and on a mismatch logs CRITICAL and fires
`ssl_notify`. There is **no reflash/apply/stage path and no `flashrom`
dependency** — the previous `apply`/`good_image` code was removed. It links only
the shared logger, not the store (it keeps no sample). Residual/honest limit,
stated plainly: ACPI+DMI hashing detects a large class of firmware tamper but is
**not** a full SPI-flash measurement (that needs `flashrom -r` or a TPM event
log), and remediation of a detected change is a deliberate operator action with
vendor tooling, out of scope.

### 24. BootGuard review (v8 add-on) — SI-7 / CM-5 (stage-at-boot)

Same safety stance for `/boot`: a live rewrite under a running kernel is unsafe,
so tamper is **staged** (restore list + `PENDING` flag, 0600) and applied at the
next boot by a systemd unit that no-ops unless `PENDING` is set; a forced live
restore needs `apply-now --i-understand-the-risk`. Restores come from the
hourly-rotated compressed backups. Honest limit, documented: the systemd unit
applies as early as a normal unit can (after `/boot` mounts, before services use
it); restoring before *anything* reads `/boot` needs an initramfs hook — the
unit is the practical default, the initramfs hook the stronger option. New boot
files are reported, never deleted (kernel updates add files).

### 25. Locus + shared libs review (v8 add-on) — SC-39 / SC-28 / AC-4

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

### 26. tamperwatch review (v10 add-on) — SI-7 / AU-10 / AC-6

Real-time attribution via fanotify (`FAN_CLASS_NOTIF`, classic pid-carrying
mode). Reviewed:

* **Default is non-destructive**: `mode = log` only attributes (pid → `/proc/
  pid/exe` → log CRITICAL). `mode = quarantine` is opt-in and is the only path
  that kills; it only kills when the resolved exe is an absolute path (never a
  `(exited pid N)` placeholder), closing a kill-wrong-pid race on exit.
* **Watched set is bounded**: it marks regular files under the PheonixBox
  protected set plus explicit absolute paths from its own conf; directory walk
  is depth-capped (24) and skips `.`/`..`. No user-controlled input chooses what
  to kill — only a modification of an already-protected file triggers handling.
* **Honest limit, documented**: files created after start under a protected dir
  are covered on the next rescan, not instantly; needs `CONFIG_FANOTIFY` + root.
  Quarantine honours the `rotate` toggle and uses the shared compressed store.

### 27. Management GUI review (v10 add-on) — AC-3 / AC-4 / SC-8 / CSRF

> **Superseded in part by #29.** The token-in-page design described below
> stopped other *origins* but not other *local users*; v11 fixes that.

This is the one add-on that both *changes config* and *kills processes* from a
network listener, so it got the closest look:

* **Loopback + root only**: binds `127.0.0.1` by default; refuses to run as
  non-root. Docs forbid widening the bind without a fronting authenticated TLS
  proxy.
* **CSRF/token**: every state-changing request (POST) requires a per-install
  token (`secrets.token_hex(24)`, stored `0600`) that the server injects into
  the served page — an off-origin page cannot read it. The server also checks
  the `Host` header against the allowed set. GETs are read-only.
* **No arbitrary writes/exec**: config writes are confined to a fixed
  `CONF_FILES` whitelist of known `.conf` names (no path from the client);
  `setkey` validates key `[a-z_]+` and value `[\w./:\- ]*`; `set_knob` delegates
  to the `secure-sudo` CLI so **kernel-side validation still applies** and the
  arg is constrained to `[a-z_]+=[\w.\-]+`; actions are a fixed dispatch table,
  never a shell string. `X-Content-Type-Options: nosniff` on every response.
* **Quarantine-by-PID is explicit and logged**: resolves `/proc/pid/exe`,
  compresses a copy, then `SIGKILL`s — a deliberate operator action behind the
  token, mirroring tamperwatch's quarantine. Residual note: a loopback root
  console is as trusted as root; the token defends against CSRF/other-origin
  reads, not against an operator who is already root on the box.

### 28. prguard_observe memory-access feed (v10) — AU-10 / SI-4

The new observe knob only *emits* events (`ss_event("prguard: mem-access …")`)
for cross-process memory access; it changes no enforcement decision. Reviewed:
it is gated behind the same `ss_may_admin` + one-way-lock check as every other
prguard knob (0600 sysfs), reads the flag with `READ_ONCE`, and skips self
access (`current->pid != child->pid`) to avoid self-noise. It can be chatty on a
busy box — it is off by default and toggled deliberately; the event ring's
existing overwrite semantics bound memory. Honest limit: the kernel change is
reviewed by hand, not recompiled here (no 6.12 headers in the build container).


### 29. Management GUI: the access token was handed to any local user (v10 bug, fixed in v11) — AC-3 / IA-2 / CWE-306

**Finding (high).** The v10 console injected its access token into the page it
served. The page was served on loopback with no authentication, so **any local
user** could `curl http://127.0.0.1:8790/`, read the token out of the HTML, and
then drive a root-run console: rewrite guard configs, flip kernel knobs through
the `secure-sudo` CLI (which the server runs as root, so `ss_may_admin` passes),
and kill or quarantine arbitrary processes. Finding #27's CSRF reasoning was
right about other *origins* but missed other *users* on the same host: a
loopback bind does not separate local users. That made it a local privilege
escalation.

**Fix.**
* The page is now static and holds no secret.
* **Every** `/api/*` request, reads included (logs can leak information),
  needs the token in `X-SS-Token`. Missing or wrong gets `401`, and the attempt
  is logged.
* The token lives only in `/var/lib/secure_sudo/addons/gui/token` (0600 in a
  0700 dir; tightened on start if an older install left it wider). Reading it
  needs root, so possession of the token is proof of root. The operator pastes
  it into a sign-in screen; the page keeps it in `sessionStorage` for that tab
  only.
* The token is compared with `hmac.compare_digest` (constant time), and the
  Host check now covers every API call, not just POST (DNS rebinding).

**Verified.** The attack was replayed as the unprivileged user `nobody`: the
page contains no token, the token file gives `Permission denied`, and every API
call without the right token returns `401` (wrong Host: `403`). The sign-in
flow was driven in headless Chromium: the wrong token is rejected, the right
one loads the dashboard, it survives a reload in the same tab, and sign-out
returns to the login screen, with no page errors.

### 30. BPF & perf guard (#22) — SI-4 / CM-7 / SC-39

Reviewed: the `bpf` hook only gates non-sudo callers, which is what
`bpf_guard` promises; root still needs `bpf_lock_tracing` to be refused, and
that hook (`bpf_prog_load`) reads `prog->type`, which the kernel sets before
the hook and before the verifier, so a refused program never runs. Hooks are
compiled only under `CONFIG_BPF_SYSCALL` / `CONFIG_PERF_EVENTS`, matching the
hook definitions; both were confirmed enabled in the 6.11 and 6.14 header
configs used for the compile check, so the code is really compiled, not
skipped. Honest limits: programs loaded before the lock keep running;
`struct_ops` is allowed on purpose.

### 31. SysctlGuard (#23) — CM-6 / CM-5 / SI-7

The match is on `dentry_path_raw()` within a `PROC_SUPER_MAGIC` superblock, so
a second procfs mounted elsewhere resolves to the same protected names; a
resolution failure on a procfs write-open is a deny (fail closed); an
allocation failure returns `-ENOMEM` (normal open semantics), never allow.
binfmt_misc is matched by `BINFMTFS_MAGIC`, so its mount point does not
matter. The protected list is fixed and global-only; per-netns sysctls are
excluded on purpose (containers). Interaction: STIG/CIS remediation writes
these sysctls, so run remediation **before** engaging the guard (or with the
guard off), then turn it on.

### 32. Audit feed (#9 `audit_events`) — AU-3 / AU-12 / CWE-117

Events reach auditd as `AUDIT_KERNEL_OTHER` with `lsm=secure_sudo msg=`. The
message is passed through `audit_log_untrustedstring()`, which hex-encodes it
when it contains spaces, quotes or control characters, so an attacker-chosen
file name in an event cannot inject fake `key=value` fields into the audit
record. This is on top of the existing control-character scrubbing for the
ring (#8). `GFP_ATOMIC` keeps it safe from any hook context and never waits on
the audit backlog, at the cost that records can be dropped under audit
backpressure; the ring and the daemon's log remain the primary record.

### 33. Lock: confidentiality class (`lock_confidentiality`) — SC-39 / AC-6

Extends `locked_down` from the integrity class to lockdown's confidentiality
class (`/proc/kcore`, kprobes, `bpf_probe_read_kernel`, perf, tracefs, xfrm
secrets) while locked. Opt-in and documented as such, because it also disables
legitimate tracing tools. Only reachable once locked, and the knob itself is
frozen by the lock like every other.

### 34. STIG / CIS tooling (#18) second pass — CM-6 / RA-5

Building the earlier manual oscap fixes into `stig-harden.sh` was reviewed for
safety: every patch checks that its problem is present before acting, keeps a
`.pre-patch` backup of files it edits (`ssh_confirm.sh`, `sssd.conf`), and the
banner repair restores the original if the result fails `bash -n`. The
AppArmor mismatch (OSB-15) is **detect-and-advise only**, because enforcing
every profile automatically can break applications. `--skip-rules` removes
whole fix blocks by oscap's own BEGIN/END delimiters and records what it
skipped; skipped rules still show as fail in the report, so nothing is hidden.
Full record: [OSCAP_BUGS.md](OSCAP_BUGS.md).


### 35. v11 kernel panicked at boot: LSM static-call slots exhausted (v11 bug, fixed in v12) — SI-17 / CP-10

Found by the first real boot (`tests/vm/boot-test.sh`, upstream 6.14 under
QEMU): `Kernel panic - not syncing: lsm_static_call_init - Ran out of static
slots`, before userspace. Since 6.9 the LSM framework gives each hook one
static-call slot per LSM; v11 registered `file_open` seven times (and other
hooks several times). Every compile check passed, which is exactly why
compilation is not a boot test. Fix: `ss_hooks.c` registers each shared hook
once and calls the protections' handlers in their old order, first non-zero
return wins (the framework's own rule), so behaviour is unchanged. Proven by
118/118 in-kernel checks, with and without AppArmor stacked; the panic log and
both runs are in `docs/vm/results/`.

### 36. OTP codes could be used twice; prefix setup always failed (v11 bugs, fixed in v12) — IA-2(8) / CWE-294

RFC 6238 §5.2 requires that a verified code is not accepted again. v11 kept
no record, so a code seen over a shoulder or in a log could be replayed for
the rest of its window. Now the last verified time step is stored under an
exclusive lock (two concurrent sudo prompts cannot both spend one code) and
only later steps are accepted; if the record cannot be written the code is
refused (fail closed). Also fixed: `otp setup --prefix` always failed, and
`otp reset` silently dropped the prefix. 66 checks, including the RFC 4226 and
RFC 6238 test vectors (`tests/userspace/test-otp.sh`).

### 37. The documented PAM lines denied the right password (v11 bug, fixed in v12) — IA-2 / availability

`pam_secure_otp.so` read and set PAM's shared password item. After
`pam_unix` it verified the Unix password as an OTP; before it, it handed the
OTP to `pam_unix` as the Unix password. Either documented order failed every
sudo. It now prompts for its own `OTP password:` and touches the shared item
only with `use_first_pass`. Proven through libpam with the documented stacks,
against the real `pam_unix` and `pam_faillock` on a throwaway account in a
private mount namespace (`tests/userspace/test-pam.sh`, 50 checks). `secure-sudo lint` now also reports a wrong order, a missing
module, an OTP line with no OTP set up, and `[default=die]` on a verifier.

### 38. Network modes: `lan-only` let all IPv6 through; `public-only` cut DHCP and DNS (v11 bugs, fixed in v12) — SC-7 / AC-4

The `lan-only` rules matched IPv4 only, so every IPv6 destination was
allowed: the mode did not do what it said. `public-only` dropped the
gateway's DHCP and DNS, so a host in that mode lost its lease and its name
resolution. Both are now tested with real `nft` rules in network namespaces
(`tests/userspace/test-helpers.sh`): IPv6 is filtered like IPv4 (link-local,
multicast and ICMPv6 stay allowed for neighbour discovery), and DHCP/DHCPv6
and DNS to the gateway are kept.

### 39. Quarantine deleted the original when archiving failed (v11 bug, fixed in v12) — SI-7 / CWE-460

`quarantine.sh` removed the file even if the archive step failed (disk full,
`zip` missing and `tar` failing), destroying the evidence it was meant to keep.
The original is now removed only after the archive exists and is checked to
contain it.

### 40. The daemon treated failed helpers as success (v11 bug, fixed in v12) — AU-5 / SI-11

`secure-sudod` did not check the exit status of `apply-net.sh` and
`quarantine.sh`, so a network mode that was never applied was reported as
active. Failures are now logged with the status, and a network mode that did
not apply is retried every 5 seconds and reported as `NOT applied yet`.

### 41. `ss_bpf.c` did not build against 6.12; the setuid allowlist file was never created (v11 bugs, fixed in v12) — CM-2 / AC-6

* The `perf_event_open` hook's signature differs between kernels: the
  6.12.114 headers take only the event type, the 6.11 (Ubuntu) and 6.14
  headers also take the attributes. v11 used the two-argument form, so it did
  not compile for the project's own target with `-Werror`. `ss_bpf.c` now
  picks the matching form at compile time (`__builtin_choose_expr` on the
  hook's type). Caught by the new build gate (`ci/build-gate.sh`), which
  compiles the LSM against the 6.11, 6.12.114 and 6.14 headers and builds six
  in-tree kernel config variants.
* `ss_creds_secfs()` was never called, so
  `/sys/kernel/security/secure_sudo/setid_exec_allow` did not exist and
  `block_setid_exec = 1` could not be given an allowlist: every setuid
  program, `passwd` included, was refused for non-sudo users. `ss_core.c` now
  creates it with the other policy files; the in-kernel tests and the VM
  recovery drill (allowlist `/usr/bin/passwd`) use it.
* `ci/check-lsm-hooks.sh` (part of the gate) fails when a hook is
  registered twice, so the #35 panic cannot come back unnoticed.

### 42. `load` silently applied part of a policy (v11 behaviour, fixed in v12) — CM-6 / SI-10

v11 skipped unknown keys without a word (so a typo such as `block_setid_exce`
left the protection off), continued after rejected writes, and ended with
`finished with errors`. v12 runs `secure-sudo lint` first and refuses to
change anything when it finds an error, then reports every setting as
accepted, rejected or skipped, and ends with `load INCOMPLETE` if the kernel
holds a partial policy. Lint checks syntax, unknown keys, kernel support
for each key, allowlist files and paths (existence; root-owned and not
writable by others), dependent settings, the admin group (exists, has
members, covers the admin running it), PAM order and what the one-way lock
will freeze. The recovery drills for a wrong admin
GID, an incomplete allowlist, a bad PAM line and an accidental lock run on
the real kernel in the distro VM test (`docs/RECOVERY.md`).

### 43. Installer review (v12 rewrite) — CM-3 / CM-5 / CP-10 / SI-7

Each of these was a v11 `install.sh` behaviour:

* **`module.sig_enforce=1` on the shared GRUB command line** applied to every
  kernel, including the fallback one; a distro kernel with unsigned DKMS
  modules could then fail to boot exactly when it was needed. Signature
  enforcement is now built into the secure_sudo kernel only
  (`CONFIG_MODULE_SIG_FORCE`); uninstall reverts the old edit.
* **`update-grub` failures were ignored.** Install now stops on a failure, and
  checks that the regenerated menu lists both the new and the running kernel.
* **`rpm -i --force`** could overwrite files of an installed distro kernel,
  and the `kernel-headers` package replaced the distro's userspace headers.
  Neither is done any more.
* **An upgrade overwrote `admin_gid`** in an existing `secure-sudo.conf`.
  Existing configuration files are now never touched; the detected value is
  written only into a newly created file.
* **No known-good boot, no rollback, removal by glob.** The new kernel now
  boots once (`grub-reboot`) while the running kernel stays the default
  until `verify --commit`; `CONFIG_PANIC_TIMEOUT=10` makes a panicking trial
  reboot into it. Every installed file is recorded with its hash; uninstall
  removes only unchanged recorded files, restores what it replaced, and
  refuses while PAM still uses the modules.
* **Secure Boot**: an unsigned kernel installed with Secure Boot on is not
  bootable. Preflight now blocks unless an enrolled MOK is given, and
  `verify` checks the image signature.
* **`lsm=` on the kernel command line removes secure_sudo** (any LSM can be
  left out that way). That is a recovery route (`docs/RECOVERY.md`) and also
  a bypass for anyone at the boot menu, so a GRUB password is required on a
  hardened box (STIG `grub2_password`); the STIG VM run sets one with
  `--unrestricted` entries so unattended boots still work (and the
  installer keeps kernels out of Ubuntu's restricted submenu, #51).

Covered by `tests/install/test-install.sh` (131 checks: manifest, backups,
upgrade, refusals, byte-identical removal, interrupted installs, GRUB entry
parsing) and by the distro VM run (`tests/vm/distro/run-install-test.sh`).

### 44. Event ring cut lines on overflow (v11 bug, fixed in v12) — AU-9 / AU-5

When the ring wrapped, the oldest bytes were overwritten wherever the write
landed, so the reader could start in the middle of a line and pass a
fragment to the daemon as an event. The ring now drops whole events and
counts them in `events_dropped` (root-only, `0400`), so loss is visible
instead of silent. Covered by the in-kernel tests (wrap and reader
behaviour).

### 45. Every package shipped its scripts without the executable bit (v1–v11) — CM-2

The release archives were made from a network share that drops file modes,
so every shipped script was `0644` and the documented `./install.sh` failed.
`ci/make-release.sh` now sets modes explicitly (`0755` for anything with a
shebang), refuses to finish if a program lacks the bit, and produces a
byte-identical archive from the same inputs.

### 46. The compliance scanner reported an unencrypted disk as encrypted (found in v12) — CA-2 / CA-7

In the STIG VM, OpenSCAP passed `encrypt_partitions` on a plain ext4 root.
Ubuntu's OpenSCAP 1.3.9 is built with PCRE2, and its partition probe counts
only a return of 0 as a pattern match while PCRE2 returns 1, so no mount
point ever matches; the cloud image's comment-only `/etc/crypttab` satisfied
the rule's other test. `dir_perms_world_writable_sticky_bits` is emptied the
same way and passes without searching. A gate that trusted the scanner would
have certified encryption that was not there. `stig-harden.sh` now checks
both rules itself after every scan, and the gate uses that result and fails a
release result that lacks it (OSCAP_BUGS OSB-19, 13 gate tests).

### 47. A trimmed kernel build could leave the host without a working firewall (found in v12) — SC-7 / CM-7

Building with `SS_LOCALMOD` (localmodconfig) keeps only modules loaded at
that moment. On a host whose firewall was not up yet, conntrack, `nft_compat`,
the xt matches and `ip_tables` were left out, and in the VM `ufw enable` then
failed half-way (and new SSH connections hung). `install.sh build-kernel` now
always keeps that netfilter set with `SS_LOCALMOD` and stops if it does not
stick (OSB-21). The default build, from the distro's config, was not
affected. Rebuilt and booted in CI on 6.12.114: a second missing match
(`hl`, used by ufw's IPv6 rules) was found that way and added; ufw now
starts in the guest.

### 48. Crafted file names could make the daemon quarantine any file or kill root's sudo (v1–v12, fixed after v12) — AC-6 / SI-10 / CWE-77 / CWE-59

`secure-sudod` runs as root and does two drastic things for the kernel: it
kills a UID's sudo/su processes (cooldown) and it quarantines or deletes a
file (TimeVault). It picked both by searching every event's text for
`cooldown: UID ` or `timevault: denied exec `, and that text carries paths
the user chooses. An unprivileged user only had to get any denial to log a
file named like
`/home/u/x/timevault: denied exec /usr/bin/sudo (hash mismatch)`
to have `/usr/bin/sudo` quarantined. A file named `cooldown: UID 0 blocked`
killed root's sudo sessions. Even for a real TimeVault denial, the path was
cut at its first ` (` and then handed to `lstat()` and the helper, which
follow symlinks in the directories on the way. So a user could swap their
own directory for a symlink to `/etc` after the denial and get `/etc` files
quarantined instead.

The daemon now parses each record as JSON and chooses an action only from
the typed fields, which are kernel constants. The cooldown UID comes from
`target_uid`, which the kernel now fills in. A TimeVault path is accepted
only from an untruncated record whose message matches the kernel's exact
format, from its first byte to its last.

The file itself is opened one directory at a time with `O_NOFOLLOW`. It is
archived from that checked descriptor (`quarantine.sh --origin`). The
original is unlinked through its pinned parent directory, and only while
the name still refers to the same inode. The TimeVault directory scan uses
the same path. 22 tests in `tests/userspace/test-daemon-events.sh`.

### 49. A record split across two ring reads was logged as two broken lines and its action lost (v9–v12, fixed after v12) — AU-9 / SI-4

A read of the ring returns whatever bytes are queued, so a read can end in
the middle of a record. The daemon handled each read as complete lines, so a
cooldown block that straddled two reads killed nothing, and the log held two
fragments. The daemon now keeps the unfinished tail for the next read.

### 50. A collector outage stalled the daemon, and the last events of a TLS connection could be lost (P1-2 work, fixed after v12) — AU-4 / AU-9 / SC-5

With TLS forwarding, every event triggered a DNS lookup, a TCP connect
(3 s timeout) and a TLS handshake inline, and then a retry of the whole
queue. While the collector dropped packets, each event held up the daemon,
including cooldown kills and TimeVault quarantines, for 3 s or more per
address, and the kernel ring overflowed behind it. Events are now written
locally, acted on, and only queued. The main loop sends the queue in
batches of up to 512 over one connection. After a failure it waits 5 s,
then twice as long after each further failure, up to 5 minutes. A config
reload retries at once.

The daemon also closed each connection without reading what the collector
had sent (TLS 1.3 session tickets). Closing a socket with unread data makes
the kernel send a reset, and the collector then discarded the last events
of the connection before reading them. A three-event batch lost one of
them in the test. Connections now end with `close_notify` and a bounded
read.

### 51. With a GRUB password, every boot stopped at the menu (v12 installer, found in CI) — CP-10 / AC-3

A hardened box needs a GRUB password (STIG `grub2_password`), and its menu
entries need `--unrestricted` so that booting stays unattended while
editing the command line (`lsm=`, #43) needs the password. On Ubuntu that
is not enough with this installer: `10_linux` writes the "Advanced options"
submenu without the entries' `CLASS`, so the submenu itself is restricted,
and `install.sh` armed and committed kernels by their path inside it
(`gnulinux-advanced-…>gnulinux-<release>-advanced-…`). After STIG hardening
the guest stopped at a password prompt on the screen, which a server
without a console never gets past. The CI STIG run showed it as a guest that
never came back after its reboot.

The installer's GRUB drop-in now also sets `GRUB_DISABLE_SUBMENU=true`, so
every kernel is a top-level entry with the distribution's `CLASS`, and an
older drop-in (GRUB_DEFAULT=saved only) is replaced on the next
`install-kernel` (one an administrator edited is kept, with a warning).
`install.sh verify` fails when GRUB has a superuser and the saved or
one-shot entry would need the password, and the STIG VM run checks that
before its reboot. Host tests: `tests/install/test-install.sh` (flat menu,
password check, drop-in upgrade).

### 52. TimeVault never quarantined a binary whose path was longer than 64 bytes (#48 fix, fixed 2026-11-01) — SI-7 / AU-3

Since #48 the daemon acts only on a record whose `truncated` flag is false,
so that a cut-off path can never name another file. The kernel bounded the
typed `object` field, which holds the path, at 64 output bytes and set the
flag when it cut it. So a tampered or unlisted binary under a path of 65
bytes or more (common under `/usr/lib/...` or `/opt/...`) was denied at exec
but never quarantined or wiped, and nothing said so apart from the record's
flag. `object` now holds 256 bytes and the daemon takes the path from it
rather than from the message (P1-1); longer paths are still never acted on.
In-kernel test: a 220-byte path is whole in `object`, record not truncated.
Host tests: the daemon takes a 244-byte path whole and ignores the message.

### 53. A ring read that ended mid-record could lose the next record without counting it (v12, fixed 2026-11-01) — AU-9 / AU-5

A read returned whatever bytes were queued, up to the reader's buffer, so it
usually ended inside a record (the daemon reads 8 KiB at a time). If the ring
then filled before the next read, the producer making room discarded the
rest of that record and counted one drop, and the reader joined the half it
held to the next record. That record was then unparseable: lost without
being counted, which made a sequence gap one larger than `events_dropped`,
and a garbled line reached the log. Reads now return records only up to the
last whole one that fits (a buffer smaller than one record still gets
bytes). In-kernel test: 20,000 denials read in 4 KiB chunks, every read ends
at a record boundary and every record is read or counted.

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
* Boot-tested in QEMU on upstream 6.14 and, in CI under KVM, on kernel.org
  6.12.114 (an initramfs run and a full Ubuntu 24.04 guest with GRUB,
  systemd and AppArmor). Not under UEFI/Secure Boot, and not on real
  hardware. See [ROADMAP_STATUS.md](ROADMAP_STATUS.md).
