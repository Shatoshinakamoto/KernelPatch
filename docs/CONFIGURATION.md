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

| Key | Default | Meaning |
|-----|---------|---------|
| `timevault_strict_mmap` | `0` | While the vault is engaged, also require every `PROT_EXEC` file mapping (shared libraries) to be on the allowlist by path. Off by default — enabling it without allowlisting `/usr/lib*` stops every dynamic program. |

The engage flag itself is set with `secure-sudo timevault on` (it latches the
lock); the allowlist is managed with `secure-sudo vault-allow`. Daemon-only
TimeVault keys:

| Key | Default | Meaning |
|-----|---------|---------|
| `vault_action` | `quarantine` | `quarantine` (zip aside, keep evidence) or `wipe` (delete) a new/changed file found while engaged. |
| `vault_watch` | `/etc,/usr/local/bin,/opt,/usr/local/sbin` | Comma list of trees the daemon scans while engaged. |

### Config lock (#16)

| Key | Default | Meaning |
|-----|---------|---------|
| `lock_modules` | `1` | When the lock engages, also refuse **all** kernel module loads (not only blacklisted ones), so a locked box loads no new code. |

The lock itself is engaged with `secure-sudo lock` or automatically by
TimeVault; it is one-way until reboot. `lock_modules` is read at the moment the
lock engages.

### Logging / retention (#9) — daemon only

| Key | Default | Meaning |
|-----|---------|---------|
| `retain_days` | `14` | Delete logs older than this. |
| `max_total_mb` | `512` | Trim oldest logs once the total exceeds this. |
| `remote_syslog` | *(empty)* | `host:port` to forward events to over UDP syslog (TimeVault relies on this so a locked box's logs survive off-box). |

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
| `node_sea_binaries.conf` → `node_sea_binaries` | #11 | Absolute path of a single-executable-application / pkg binary to treat as a node runtime. |
| `driver_blacklist.conf` → `driver_blacklist` | #6 | A 64-hex SHA-256 (matches the loaded module's bytes) or a module basename. |
| `timevault_allow.conf` → `timevault_allow` | #13 | `<path> <sha256>` per line. Every entry must pin a hash. Managed by `vault-allow`. |
| `home_map.conf` → `home_map` | #4 | `<uid> <home-path>` per line. Generated from `/etc/passwd` by the installer. |
| `home_write_allow.conf` → `home_write_allow` | #4 | Extra always-writable path prefix for non-sudo users. |

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

At verify time the seed is decrypted into an `mlock`'d buffer that is wiped
immediately after use. The password is `prefix` + the 6-digit rotating code.

### Wiring OTP (and the cooldown feed) into PAM

PAM changes are deliberately left manual so a typo cannot lock you out. Keep a
root shell open while testing. The installer prints the exact lines; in
`/etc/pam.d/sudo` (and `/etc/pam.d/su`):

```
auth  [default=die]  pam_unix.so            # your existing verifier
auth  required       pam_secure_sudo.so authfail
auth  sufficient     pam_unix.so
auth  required       pam_secure_sudo.so authsucc
```

For the rotating OTP password, after `secure-sudo otp setup` and a successful
`secure-sudo otp verify` test:

```
auth  required       pam_secure_otp.so
```
