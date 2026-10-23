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
for issues of its own (second column). The LSM compiles cleanly with `-Werror`
against real 6.11 and 6.14 kernel header trees; the CLI, daemon and PAM modules
compile cleanly with `-Wall -Wextra`.

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
