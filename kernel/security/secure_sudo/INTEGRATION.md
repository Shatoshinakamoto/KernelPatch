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
| `ss_creds.c`    | Protection #1: non-sudo UID/GID switch block + userns gate |
| `ss_exec.c`     | Protection #2: command blacklist (securityfs, inode+path match) |
| `ss_firmware.c` | Protection #3: firmware/flash + raw-memory access block |
| `ss_tpm.c`      | Protection #5: block TPM clear (ppi/request) |
| `ss_ram.c`      | Protection #7: RAM-spike detection -> drop caches |
| `ss_tmpexec.c`  | Protection #12: block exec/PROT_EXEC mmap from scratch trees |
| `ss_net.c`      | Protection #10 (kernel half): deny raw/packet sockets in host mode |
| `ss_log.c`      | Protection #9: event ring drained via securityfs `events` |
| `ss_node.c`     | Protection #11: NodeJS child guard (defines the LSM task blob) |
| `ss_cooldown.c` | Protection #8: sudo brute-force cooldown (PAM-fed) |
| `ss_driver.c`   | Protection #6: driver blacklist (SHA-256 / name); exports `ss_sha256_file()` |
| `ss_timevault.c`| Protection #13: TimeVault exec allowlist + pkg-mgr deny |
| `ss_home.c`     | Protection #4: confine non-sudo writes to home (file_open + path_*) |

All kernel-side protections from the feature map are now present. Userspace
companions (PAM modules, the `secure-sudod` daemon, the `secure-sudo` CLI) and
the installers are the next steps.

## Runtime interface so far

| Node | Mode | Meaning |
|------|------|---------|
| `/sys/kernel/secure_sudo/admin_gid` | rw | GID treated as sudo (`unset` = root only) |
| `/sys/kernel/secure_sudo/block_setid` | rw | enforce #1 UID/GID switch block |
| `/sys/kernel/secure_sudo/block_userns` | rw | gate unprivileged user namespaces |
| `/sys/kernel/secure_sudo/block_flash` | rw | enforce #3 firmware/flash/raw-memory block |
| `/sys/kernel/secure_sudo/lock` | rw | #16 one-way config lock (set-only until reboot) |
| `/sys/kernel/secure_sudo/max_ram_percent` | rw | #7 drop-caches threshold (% used) |
| `/sys/kernel/secure_sudo/check_interval_ms` | rw | #7 sampling interval |
| `/sys/kernel/secure_sudo/drop_cooldown_ms` | rw | #7 minimum gap between drops |
| `/sys/kernel/secure_sudo/ram_spike_enabled` | rw | #7 enable the worker (off by default) |
| `/sys/kernel/secure_sudo/block_tmp_exec` | rw | #12 enforce scratch-tree exec/mmap block |
| `/sys/kernel/secure_sudo/net_mode` | rw | #10 monitor/host/lan-only/public-only |
| `/sys/kernel/secure_sudo/sudo_max_fails` | rw | #8 failures before a UID is blocked |
| `/sys/kernel/secure_sudo/sudo_window_sec` | rw | #8 sliding window |
| `/sys/kernel/secure_sudo/sudo_block_time_sec` | rw | #8 block duration |
| `/sys/kernel/secure_sudo/sudo_cooldown_enabled` | rw | #8 enable cooldown |
| `/sys/kernel/secure_sudo/timevault` | rw | #13 engage/disengage vault (engage latches `lock`) |
| `/sys/kernel/secure_sudo/timevault_denied` | r | #13 count of denied exec attempts |
| `/sys/kernel/security/secure_sudo/events` | r | #9 kernel event stream (blocking read + poll) |
| `/sys/kernel/security/secure_sudo/blacklist` | rw (root) | #2 absolute paths non-sudo users may not exec |
| `/sys/kernel/security/secure_sudo/tmp_exec_allow` | rw (root) | #12 scratch-tree exec/mmap exemptions (prefix match) |
| `/sys/kernel/security/secure_sudo/node_allowed_children` | rw (root) | #11 basenames node/SEA may spawn |
| `/sys/kernel/security/secure_sudo/node_sea_binaries` | rw (root) | #11 registered SEA/pkg binary paths |
| `/sys/kernel/security/secure_sudo/sudo_auth` | w (root) | #8 PAM feed: `fail <uid>` / `ok <uid>` |
| `/sys/kernel/security/secure_sudo/driver_blacklist` | rw (root) | #6 blacklisted module SHA-256 hashes and/or names |
| `/sys/kernel/security/secure_sudo/timevault_allow` | rw (root) | #13 allowlist: `path` or `path <sha256>` |
| `/sys/kernel/secure_sudo/block_home_write` | rw | #4 confine non-sudo writes to home (opt-in) |
| `/sys/kernel/security/secure_sudo/home_map` | rw (root) | #4 `<uid> <home-path>` per line |
| `/sys/kernel/security/secure_sudo/home_write_allow` | rw (root) | #4 extra always-writable path prefixes |
| boot param `secure_sudo.tpm_maint=1` | — | #5 permit TPM clear this boot |
