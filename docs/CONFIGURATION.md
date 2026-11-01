# secure_sudo — configuration reference

All configuration lives under **`/etc/secure_sudo/`**. `secure-sudo load`
(run automatically at boot) pushes it into the kernel. There are two kinds of
file:

* **`secure-sudo.conf`** — `key = value` scalar settings. Some keys are read by
  the kernel, a few only by the `secure-sudod` daemon.
* **policy list files** — one entry per line, `#` starts a comment. Each is
  pushed verbatim into a securityfs file as a whole-list replacement.

A "sudo user" throughout means root (by real or effective UID) or a member of
any GID in `admin_gid`. Protections that target "non-sudo users" never affect
sudo users.

Mode note: every kernel knob is root-only (`0600`) and refuses writes once the
config is **locked** (see `lock`). Policy-list files are likewise frozen once
locked.

---

## `secure-sudo.conf` — scalar settings

### Privilege model (#1, #1b)

| Key | Default | Meaning |
|-----|---------|---------|
| `admin_gid` | auto-detected | Comma list of up to 16 GIDs whose members count as sudo users, e.g. `27,10`. `unset` = root only. The installer fills this from `sudo`/`wheel`/`admin` and sudoers; re-run `secure-sudo detect-admins` after adding a group. |
| `block_setid` | `1` | Deny non-sudo users calling `setuid`/`setgid`/`setgroups` and creating user namespaces (the `setuid`/namespace route to another identity). |
| `block_userns` | `1` | Deny non-sudo users creating unprivileged user namespaces specifically (kept separate so you can allow namespaces while still blocking setid). |
| `block_setid_exec` | `0` | Deny non-sudo users **executing** a setuid/setgid or file-capability binary (su, newgrp, pkexec, mount…) unless its path is in `setid_exec_allow.conf`. Off by default because it needs that allowlist populated first; this is the switch that removes the whole setuid attack surface from ordinary users. |

### Firmware / flash (#3)

| Key | Default | Meaning |
|-----|---------|---------|
| `block_flash` | `1` | Deny non-sudo users opening raw-memory / firmware device nodes and writing firmware sysfs/efivarfs attributes. |

### RAM-spike → drop caches (#7)

| Key | Default | Range | Meaning |
|-----|---------|-------|---------|
| `ram_spike_enabled` | `0` | 0/1 | Enable the sampling worker (it drops caches, so opt-in). |
| `max_ram_percent` | `90` | 1–100 | Drop caches at or above this % of real memory used. |
| `check_interval_ms` | `5000` | 100–3600000 | How often the worker samples memory. |
| `drop_cooldown_ms` | `2000` | 1000–86400000 | Minimum gap between two drops. |

### Exec from scratch trees (#12)

| Key | Default | Meaning |
|-----|---------|---------|
| `block_tmp_exec` | `1` | Deny non-sudo exec, `PROT_EXEC` mmap and `mprotect(PROT_EXEC)` of files under `/tmp`, `/var/tmp`, `/dev/shm`. Exemptions go in `tmp_exec_allow.conf`. |
| `block_tmpfs_exec` | `0` | Extend that block to **every** tmpfs/ramfs mount (e.g. `/run/user/<uid>`) and to `memfd_create` files, closing the "fileless" memfd+exec route. Off by default — turn it on once you know your scratch dirs. |

### Home write-restriction (#4)

| Key | Default | Meaning |
|-----|---------|---------|
| `block_home_write` | `0` | Confine non-sudo writes (open-for-write, create, unlink, rename, mkdir, truncate, chmod, chown) to the user's home plus the normal scratch/device trees and `home_write_allow.conf`. Aggressive; opt-in. Needs `home_map.conf`. |

### Network mode (#10) {#net_mode}

| Key | Default | Meaning |
|-----|---------|---------|
| `net_mode` | `monitor` | One of `monitor`, `host`, `lan-only`, `public-only`. |

* `monitor` — observe only, no restriction.
* `host` — the kernel denies raw / `AF_PACKET` sockets, so packet sniffing
  fails even with libpcap present.
* `lan-only` — the daemon installs an nftables table allowing only traffic
  to/from the detected LAN subnet(s).
* `public-only` — the daemon drops traffic to/from the LAN subnet(s).

### Sudo brute-force cooldown (#8)

| Key | Default | Range | Meaning |
|-----|---------|-------|---------|
| `sudo_cooldown_enabled` | `1` | 0/1 | Enable the cooldown. |
| `sudo_max_fails` | `5` | 1–1000 | Failed auths within the window before a UID is blocked. |
| `sudo_window_sec` | `60` | 1–86400 | Sliding window length. |
| `sudo_block_time_sec` | `300` | 1–604800 | How long a blocked UID stays blocked. |

Failures are fed to the kernel by `pam_secure_sudo.so`; the kernel blocks the
UID from exec'ing any privilege tool (sudo, su, doas, pkexec, run0, and any
setuid-root binary) and the daemon freezes+kills the offending processes.

### TimeVault (#13)

TimeVault is a **hash-based anti-tamper exec gate**. While engaged, the kernel
intercepts every exec and, right before the program runs, re-hashes the file
and compares it to the SHA-256 pinned in the allowlist. A match runs; a
mismatch (or an unlisted binary) is **blocked at exec**, and the daemon then
**compresses the offending file into the quarantine folder and removes the
original** (or deletes it, if `vault_action=wipe`). See "The exec decision" and
"Anti-tamper quarantine flow" below.

| Key | Default | Range | Meaning |
|-----|---------|-------|---------|
| `timevault_strict_mmap` | `0` | 0/1 | While engaged, also require every `PROT_EXEC` file mapping (shared libraries) to be on the allowlist by path. Off by default — enabling it without allowlisting `/usr/lib*` stops every dynamic program. |
| `timevault_allow_autoupdate` | `1` | 0/1 | Honour auto-update allowlist entries (the `auto` / `autodir` kind, which skip hash validation). Set `0` to **disable auto-update apps**: every auto-update entry is then refused at exec (there is no hash to fall back to), while normal hash-checked entries keep working. |
| `timevault_max_entries` | `16384` | 1–131072 | Configurable cap on how many entries the allowlist may hold. Takes effect on the next allowlist write; lower it to bound memory on small systems. |

The engage flag itself is set with `secure-sudo timevault on` (it latches the
lock); the allowlist is managed with `secure-sudo vault-allow`. Daemon-only
TimeVault keys:

| Key | Default | Meaning |
|-----|---------|---------|
| `vault_action` | `quarantine` | `quarantine` (zip aside, keep evidence) or `wipe` (delete). Applies both to a new/changed file the daemon finds while scanning **and** to a binary the kernel blocked at exec for a hash mismatch or for not being listed. |
| `vault_watch` | `/etc,/usr/local/bin,/opt,/usr/local/sbin` | Comma list of trees the daemon scans while engaged. |

Node child guard (#11) keys, read by `secure-sudo node-scan` and the daemon:

| Key | Default | Meaning |
|-----|---------|---------|
| `node_sea_scan_dirs` | `/opt,/usr/local/bin,/usr/local/sbin,/usr/local/lib,/srv` | Comma list of absolute directories `node-scan` searches for Node runtimes outside the standard paths. |
| `node_sea_scan_interval` | `60` | Minutes between the daemon's scans (it also scans at start); `0` turns the daemon's scans off. 0–10080. |

#### The allowlist file format

`timevault_allow.conf` (managed by `secure-sudo vault-allow`) holds one entry
per line. There are three kinds:

| Line form | Kind | Behaviour at exec |
|-----------|------|-------------------|
| `/path/to/binary <64-hex-sha256>` | hash entry | runs only if the file still hashes to that SHA-256 (the normal anti-tamper entry) |
| `/path/to/binary auto` | auto-update **file** | runs without a hash check — for a single binary that rewrites itself |
| `/path/to/dir autodir` | auto-update **directory** | any binary under this directory runs without a hash check — for a self-updating app tree |

Auto-update entries exist because some software legitimately replaces its own
binaries at runtime (so a pinned hash would break it the moment it updates).
They are only honoured while `timevault_allow_autoupdate = 1`; with it `0` they
are refused, so you can disable self-updating software in one switch without
editing the list. Auto-update files are **not** write-protected (unlike hash
entries, whose inodes are frozen against writes while engaged), precisely
because they are meant to change.

#### The exec decision (in order)

1. Package managers and the dynamic loader (`ld-linux*`, `ld.so`, `ld-musl*`)
   are **always** denied — installing software, or `ld.so /any/binary`, would
   defeat the vault.
2. An unlinked file is denied (its name no longer pins its inode).
3. If the path is under an `autodir`, or matches an `auto` entry: it runs
   **iff** `timevault_allow_autoupdate = 1`, otherwise it is denied.
4. Otherwise the path must be a hash entry; the file must be root-owned, not
   group/world-writable, and not open for writing; and its SHA-256 must equal
   the pinned hash. Only then does it run.
5. Anything else is denied (and quarantined — see below).

#### Anti-tamper quarantine flow

When the kernel blocks an exec for **hash mismatch** (a listed binary whose
bytes changed) or **not on allowlist** (an unknown binary), it emits an event.
`secure-sudod` reads that event and moves the offending file aside: with
`vault_action=quarantine` (default) the file is compressed with its origin
metadata into `/var/lib/secure_sudo/quarantine/` and the original removed; with
`vault_action=wipe` it is deleted. So a tampered or unapproved binary is
stopped **before it runs** and then retained in compressed form for
investigation.

### BinaryVault (#17)

| Key | Default | Meaning |
|-----|---------|---------|
| `binaryvault` | `0` | Freeze **every executable and shared library** on the machine. While on, no write, truncate, delete, rename-over, hardlink, chmod or xattr change to a binary is allowed for **anyone, root included** — the anti-tamper / anti-persistence control. `secure-sudo load` makes it effective at every boot, so a configured box comes up with binaries already frozen. Off by default; review the update procedure before enabling. |

Because the vault applies to root too, you cannot write a system binary at
runtime once it is on. To apply package upgrades you reboot into a maintenance
window: add the read-only boot parameter

```
secure_sudo.binvault_maint=1
```

to the kernel command line (a GRUB one-shot is ideal), run your package
upgrade, then reboot normally. There is deliberately no runtime way to open the
vault — that is what makes it tamper-proof. `secure-sudo status` shows
`binvault_maint` = 1 during such a boot. Genuinely self-updating software goes
in `binvault_allow.conf` instead. Full rationale and the second-pass review are
in [SECURITY_REVIEW.md](SECURITY_REVIEW.md) (#15) and the file header of
`ss_binvault.c`.

### RadioGuard — Wi-Fi / Bluetooth / Ethernet-only (#19)

| Key | Default | Meaning |
|-----|---------|---------|
| `block_wifi` | `0` | `1` keeps Wi-Fi off. |
| `block_bluetooth` | `0` | `1` keeps Bluetooth off. |
| `ethernet_only` | `0` | Master switch: `1` keeps **both** radios off regardless of the two keys above — the one-line "wired only" setting. |

Effective state is the OR of the specific key and `ethernet_only`, so
`ethernet_only=1` alone locks the box to Ethernet. Enforcement is in-kernel and
layered: (1) the Wi-Fi/Bluetooth **core modules are refused at load**
(`cfg80211`/`mac80211`, `bluetooth` + transports) so no dependent driver can
start; (2) **AF_BLUETOOTH sockets are denied**; (3) **writes to `/dev/rfkill`
are denied** so a blocked radio cannot be un-blocked. All three knobs are
root-only (`0600`) and frozen once the config is locked. Drive them with the
friendly `secure-sudo radio` command (see [COMMANDS.md](COMMANDS.md)) or the
generic `set`.

Limitation: if the wireless drivers are built *into* the kernel (not modules),
layer 1 has nothing to intercept — an Ethernet-only appliance should build
without those drivers and use RadioGuard as reinforcement; and a radio already
live this boot should be `rfkill block`ed or the box rebooted after enabling
(on a configured box `secure-sudo load` denies the module at early boot). Full
detail is in the `ss_radio.c` header and [SECURITY_REVIEW.md](SECURITY_REVIEW.md) (#16).

### Process Runtime Guard (#20)

| Key | Default | Meaning |
|-----|---------|---------|
| `prguard_enabled` | `0` | Guard the **runtime memory** of every process (except whitelisted ones). When on, the kernel denies cross-process memory tampering and writable-and-executable memory. Opt-in. |
| `prguard_observe` | `0` | Emit one event per cross-process memory access (`prguard: mem-access READ\|WRITE by pid N (comm) -> pid M (comm)`), shown on the GUI's Memory access tab. Observation only; enforcement is unchanged. Verbose, opt-in. |

With the guard on, for every process whose executable is **not** listed in
`prguard_allow.conf` the kernel denies:

* `ptrace(PTRACE_ATTACH)` — the debugger-style attach that can read/write
  another process's registers and memory;
* `process_vm_writev()` and writes to `/proc/<pid>/mem` — other routes into
  another process's memory (both gated by the same ptrace-attach check);
* **W^X** mappings — any `mmap`/`mprotect` that requests `PROT_WRITE` and
  `PROT_EXEC` at the same time (the classic shellcode / JIT-spray primitive).

Non-invasive, read-only ptrace (used by e.g. `gdb`'s info commands without
attach) is left alone; only the attach mode that permits *writing* another
process is denied. The exemption list (`prguard_allow.conf`, securityfs
`prguard_allow`) holds the absolute executable paths of the few programs that
legitimately need these powers — debuggers, profilers, some JIT runtimes. A
process is matched by the path of its main executable. Manage it with
`secure-sudo prguard add|remove|list|on|off` (see [COMMANDS.md](COMMANDS.md)).
Both the toggle and the list are root-only (`0600`) and frozen once the config
is locked, so the guard cannot be weakened on a locked box. Second-pass review:
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) (#19).

### BPF & perf guard (#22)

| Key | Kernel default | Template | Meaning |
|-----|---------------:|---------:|---------|
| `bpf_guard` | `0` | `1` | Deny every `bpf(2)` command to non-sudo users. Backs up `kernel.unprivileged_bpf_disabled`, which root can flip back. |
| `bpf_lock_tracing` | `1` | `1` | Once the #16 lock latches, refuse to **load** tracing-class BPF programs for every user, root included: kprobe, tracepoint, raw tracepoint (incl. writable), perf_event, fentry/fexit (`TRACING`), BPF-LSM and freplace (`EXT`). These are the program types BPF rootkits use. Networking and cgroup BPF (systemd, firewalls, container runtimes) is untouched. |
| `perf_guard` | `0` | `1` | Deny `perf_event_open(2)` to non-sudo users. Backs up `kernel.perf_event_paranoid`. |

Limits: `bpf_lock_tracing` acts at program load, so a tracing program loaded
before the lock latched keeps running (the daemon latches early in boot).
BPF `struct_ops` (TCP congestion control, sched_ext) is deliberately allowed.

### SysctlGuard (#23)

| Key | Kernel default | Template | Meaning |
|-----|---------------:|---------:|---------|
| `sysctl_guard` | `0` | `1` | Refuse **write-opens** of the security-critical sysctls below for every user, root included, and refuse all `binfmt_misc` writes (no new interpreter registrations). Reads are unaffected. |

Protected set (fixed): `kernel.kptr_restrict`, `dmesg_restrict`,
`perf_event_paranoid`, `yama.ptrace_scope`, `sysrq`, `kexec_load_disabled`,
`modules_disabled`, `unprivileged_bpf_disabled`, `io_uring_disabled`,
`core_pattern`, `modprobe`, `usermodehelper.bset`, `usermodehelper.inheritable`,
`randomize_va_space`, `unprivileged_userns_clone`,
`apparmor_restrict_unprivileged_userns`; `net.core.bpf_jit_harden`,
`bpf_jit_kallsyms`; `vm.mmap_min_addr`, `unprivileged_userfaultfd`;
`fs.protected_symlinks`, `protected_hardlinks`, `protected_fifos`,
`protected_regular`, `suid_dumpable`; `user.max_user_namespaces`;
`dev.tty.ldisc_autoload`.

`core_pattern` and `modprobe` matter most: each names a program the kernel runs
as root, so changing them is a classic persistence trick. The match uses the
file's path inside procfs (not the mount path), so mounting a second procfs
elsewhere does not get around it. Order at boot: `systemd-sysctl` applies your
`sysctl.d` values, then `secure-sudo load` engages the guard, then the lock
freezes the knob itself. To retune a value on an unlocked box: set
`sysctl_guard 0`, change it, set it back to `1`. Per-network-namespace sysctls
(`net.ipv4.*`) are deliberately not frozen, because container runtimes set them
inside their own namespaces.

### PheonixBox (#21) — userspace, not a kernel knob

PheonixBox is a userspace feature (the `secure-sudo-pheonixbox` helper + a
daemon timer), so it has **no `/sys/kernel/secure_sudo/` knob**. Its state is a
marker file, and it is configured by one plain config file:

| File | Meaning |
|------|---------|
| `/etc/secure_sudo/pheonixbox.conf` | the protected set — one absolute path per line (file, or directory protected recursively); `#` comments, blanks and relative paths ignored; whitespace paths skipped. Managed by `secure-sudo pheonixbox add/remove`. |
| `/var/lib/secure_sudo/pheonixbox/` | the store (mode `0700`, root-only): `enabled` marker, `manifest` (`<sha> <mode> <uid> <gid> <path>`), `blobs/*.z` (compressed originals), `acls/*.acl`, `lastscan`. |

Enabling (`secure-sudo pheonixbox on`) snapshots every protected file (SHA-256
manifest for **detection** + a root-only zlib-compressed copy of the originals
for **restoration**), captures each file's owner/mode/ACLs (the
PermissionsSnapshot), locks the files read-only, and starts the daemon's timer
scan (~30 s), which restores any tampered or deleted file from the snapshot
store. Disabling restores the original permissions. A SHA-256 hash is one-way
and is **not** what restores — the compressed snapshot store is. Full detail in
[PHEONIXBOX.md](PHEONIXBOX.md).

### Config lock (#16)

| Key | Default | Meaning |
|-----|---------|---------|
| `lock_modules` | `1` | When the lock engages, also refuse **all** kernel module loads (not only blacklisted ones), so a locked box loads no new code. |
| `lock_confidentiality` | `0` | While locked, also refuse kernel lockdown's **confidentiality** class: reading kernel memory via `/proc/kcore`, kprobes, `bpf_probe_read_kernel`, perf and tracefs kernel reads. Opt-in, because it also stops legitimate tracing and profiling tools (`perf`, `bpftrace`). The integrity class is always refused while locked. |

The lock itself is engaged with `secure-sudo lock` or automatically by
TimeVault; it is one-way until reboot. `lock_modules` is read at the moment the
lock engages.

### Logging / retention (#9)

| Key | Kernel default | Template | Meaning |
|-----|---------------:|---------:|---------|
| `audit_events` | `0` | `1` | Also send every secure_sudo kernel event to the kernel **audit** subsystem as an `AUDIT_KERNEL_OTHER` record (`lsm=secure_sudo msg=...`), so `auditd`, `ausearch -m KERNEL_OTHER` and SIEM pipelines see them. The message is hex-encoded when it contains spaces or quotes, so a crafted file name cannot forge audit fields. Needs `CONFIG_AUDIT`. |

The daemon-side settings:

| Key | Default | Meaning |
|-----|---------|---------|
| `retain_days` | `14` | Delete logs older than this. |
| `max_total_mb` | `512` | Trim oldest logs once the total exceeds this. |
| `remote_syslog` | *(empty)* | Collector `host:port` (IPv6 literals use `[address]:port`). |
| `remote_syslog_transport` | `udp` | `udp` retains legacy unauthenticated datagrams; `tls` selects RFC 5425 syslog over TLS with CA and host/IP verification. Configure this explicitly for authenticated forwarding. |
| `remote_syslog_ca_file` | `/etc/ssl/certs/ca-certificates.crt` | CA bundle used to authenticate the collector in TLS mode. The configured host or IP must match the certificate. |
| `remote_queue_max_mb` | `10` | TLS-only disk queue cap (1–1024 MiB), stored mode 0700 under `/var/lib/secure_sudo/remote-queue`, with a hard limit of 4096 pending event files. Events are retried oldest first after reconnect and daemon restart. When either bound is full, the newest event is dropped and counted; `secure-sudo health` reports queue size and drops. |

TLS mode retains events locally until a TLS write succeeds. A write is not an
application-level acknowledgment: RFC 5425 does not prove that the collector
persisted or indexed the event. Retries after ambiguous disconnects can deliver
duplicates; a successful write followed by a collector-side failure can still
lose an event. UDP remains explicitly unconfirmed. The local log is written
before either forwarding path and continues when the collector is unavailable.

TLS uses server authentication only; client certificates and client private
keys are not configured. For collector CA rotation, install an overlap bundle
containing both old and new trust anchors at `remote_syslog_ca_file`, then
switch the collector certificate, confirm forwarding, and remove the old
anchor. Replace the bundle atomically so a connection cannot read a partial
file. The daemon creates a new TLS context for each connection, so a bundle
replacement takes effect on the next send without restarting it. A changed
configuration path requires restarting the daemon. The forwarding test
verifies that an atomically replaced bundle is used for the next connection.

---

## Policy list files

Each is one entry per line; `#` comments and blank lines are ignored. Edit the
file, then `secure-sudo load` (the TimeVault allowlist has its own command).

| File → securityfs | Feature | Entry format |
|-------------------|---------|--------------|
| `blacklist.conf` → `blacklist` | #2 | Absolute path non-sudo users may not exec. Matched by device+inode+generation (catches a rename) and by path (catches a swap). |
| `setid_exec_allow.conf` → `setid_exec_allow` | #1b | Absolute path of a setuid/setgid/file-cap binary non-sudo users *may* still run when `block_setid_exec=1`. |
| `tmp_exec_allow.conf` → `tmp_exec_allow` | #12 | Path prefix exempted from the scratch-tree exec block. Matches on a path-component boundary (`/tmp/build` covers `/tmp/build/…` but not `/tmp/buildx`). |
| `node_allowed_children.conf` → `node_allowed_children` | #11 | A child a node/SEA process may exec. `/`-prefixed = exact path; a bare word = basename. |
| `node_sea_binaries.conf` → `node_sea_binaries` | #11 | Absolute path of a single-executable-application / pkg binary to treat as a node runtime. `load` sends these first, then what `secure-sudo node-scan` found (kept apart in `/var/lib/secure_sudo/node_sea_auto.list`), up to the kernel's 256 entries. |
| `driver_blacklist.conf` → `driver_blacklist` | #6 | A 64-hex SHA-256 (matches the loaded module's bytes) or a module basename. |
| `timevault_allow.conf` → `timevault_allow` | #13 | `<path> <sha256>` (hash entry), `<path> auto` (auto-update file), or `<dir> autodir` (auto-update directory). Managed by `vault-allow`. |
| `home_map.conf` → `home_map` | #4 | `<uid> <home-path>` per line. Generated from `/etc/passwd` by the installer. |
| `home_write_allow.conf` → `home_write_allow` | #4 | Extra always-writable path prefix for non-sudo users. |
| `binvault_allow.conf` → `binvault_allow` | #17 | Absolute directory prefix EXEMPT from BinaryVault (self-updating software). Keep minimal — each entry is a hole in the freeze. |
| `prguard_allow.conf` → `prguard_allow` | #20 | Absolute executable path EXEMPT from the Process Runtime Guard (debuggers, profilers, JITs). Managed by `secure-sudo prguard`. |

---

## OTP secret storage {#otp}

`secure-sudo otp setup` creates, under `/var/lib/secure_sudo/otp/` (mode 0700,
root only):

| File | Contents |
|------|----------|
| `masterkey` | 32 random bytes — the AES-256-GCM key for the seed (0600). |
| `secret.enc` | `[12B IV][16B tag][ciphertext]` — the base32 TOTP seed, authenticated-encrypted. |
| `prefix.hash` | A yescrypt (`crypt(3)`) hash of the optional prefix word — never decrypted, only verified. |
| `meta` | Account / issuer strings for the `otpauth://` URI. |
| `qr.png` | The QR image written by `show-qr` (0600). |
| `last_step` | The last TOTP time step accepted, so a code cannot be replayed (0600). |

At verify time the seed is decrypted into an `mlock`'d buffer that is wiped
immediately after use. The password is `prefix` + the 6-digit rotating code.

### Wiring OTP (and the cooldown feed) into PAM

PAM changes are deliberately left manual so a mistake cannot lock you out.
Keep a root shell open while testing, and test from a second terminal with
`sudo -k; sudo true`. The installer prints the same lines.

**Cooldown feed (#8).** One line, as the first `auth` line of
`/etc/pam.d/sudo` and `/etc/pam.d/su`, above `@include common-auth`
(Debian/Ubuntu/openSUSE) or `auth include system-auth` (Fedora/RHEL/Arch):

```
auth  optional  pam_secure_sudo.so
```

It never changes the result. It marks each attempt; sudo and su call
`pam_setcred()` only after a successful login, which reports `ok`, and an
attempt that ends any other way (wrong password, ^C, sudo's retry, a failed
account check) is reported as `fail`. Because it does not depend on jump
counts it works unchanged with `pam_faillock`, `pam_sss` or OTP in the stack.

> Earlier versions documented a four-line stack starting with
> `auth [default=die] pam_unix.so`. That stack **denies the correct password**
> (PAM returns `PAM_PERM_DENIED`) and never reports a failure. If you added
> it, replace it with the line above. `tests/userspace/test-pam.sh` checks
> both against the real `pam_unix`.

**Rotating OTP (#14), as a second factor.** After `secure-sudo otp setup`
and a successful `secure-sudo otp verify`, add right after the password
include:

```
@include common-auth                 # or: auth include system-auth
auth  required  pam_secure_otp.so
```

The module asks for its own `OTP password:` and never reuses the Unix
password (earlier versions did, which failed every login whichever order
the lines were in). With `use_first_pass` it takes the password an earlier
module collected instead, for a stack where OTP replaces the Unix password.

Each code is accepted once (RFC 6238 section 5.2): the helper records the last
time step it accepted in `last_step` and refuses that code and any older one,
so a code seen over someone's shoulder cannot be reused. It fails closed: if
that record cannot be written, OTP logins are refused. If the clock is stepped
backwards, OTP logins resume once it passes the last accepted step (about a
minute for a typical NTP correction).
