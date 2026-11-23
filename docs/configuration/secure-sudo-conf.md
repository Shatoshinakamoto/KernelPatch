<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `/etc/secure_sudo/secure-sudo.conf`

The main settings file. It holds kernel settings, which `secure-sudo load`
pushes into `/sys/kernel/secure_sudo/`, and daemon settings, which
`secure-sudod` reads itself. Narrative background for each feature is in
[CONFIGURATION.md](../CONFIGURATION.md). This page is the per-key reference
that CLAUDE.MD section 5 asks for. `ci/check-config-docs.py` (gate lint
stage) fails when a key in the code is missing here, or when the "Shipped"
column disagrees with `userspace/config/secure-sudo.conf`.

## Location, format and load order

- **Path:** `/etc/secure_sudo/secure-sudo.conf`. Owner root, mode `0644` is
  enough: it holds no secrets (the OTP secret is stored elsewhere, see
  [CONFIGURATION.md#otp](../CONFIGURATION.md#otp)). Keep it root-owned and not
  group- or world-writable, because anyone who can edit it can turn the
  protections off at the next `load` (NIST CM-5, CM-6).
- **Format:** one `key = value` per line. `#` at the start of a line is a
  comment; a `#` later in the line is part of the value, so do not put a
  comment after a value. Whitespace around the key and value is trimmed. An
  unknown key is an error in `secure-sudo lint` and makes `load` refuse to
  touch the kernel. A key set twice is a warning, and the last value wins.
- **Precedence:** each kernel setting starts at the kernel's built-in default
  at boot. `secure-sudo load` (run at boot as the `ExecStartPre` of
  `secure-sudod.service`) then writes every key present in this file. A key that is absent or
  commented out keeps the built-in default. Daemon keys work the same way
  inside `secure-sudod`.
- **Validation:** `load` and `lint` share one model (`userspace/cli/policy.c`)
  with the type and range each sysfs store handler accepts, and check the
  whole file before writing anything, so a typo cannot leave the machine on
  half a policy. The kernel stays the authority and rejects out-of-range
  writes too.
- **Reload:**
  - Kernel keys: `sudo secure-sudo load`. Once the config lock (#16) is
    engaged, every kernel knob refuses writes until reboot. This is
    deliberate: root cannot quietly loosen a locked box.
  - Daemon keys: `sudo systemctl reload secure-sudod` (SIGHUP). An invalid
    daemon value is logged and the default (or "off", for alerting) is kept.

## Key reference

"Built-in default" is the value before this file is read: the kernel's for
kernel keys (`kernel/security/secure_sudo/ss_core.c`), the daemon's for
daemon keys (`userspace/daemon/secure-sudod.c`). "Shipped" is the value in
the template the installer writes; `(commented)` means the template lists the
key commented out, `(absent)` means it is not in the template. No key is
required: every one has a built-in default. Types: `bool` is `0` or `1`,
`u32` is a whole number in the range shown.

<!-- config-keys:begin -->
| Key | Read by | Type | Allowed | Built-in default | Shipped |
|-----|---------|------|---------|------------------|---------|
| `admin_gid` | kernel | GID list | up to 16 comma-separated GIDs, or `unset` | `unset` (root only) | `unset` |
| `block_setid` | kernel | bool | 0, 1 | `1` | `1` |
| `block_userns` | kernel | bool | 0, 1 | `1` | `1` |
| `block_setid_exec` | kernel | bool | 0, 1 | `0` | `0` |
| `block_flash` | kernel | bool | 0, 1 | `1` | `1` |
| `ram_spike_enabled` | kernel | bool | 0, 1 | `0` | `0` |
| `max_ram_percent` | kernel | u32 | 1-100 | `90` | `90` |
| `check_interval_ms` | kernel | u32 | 100-3600000 | `5000` | `5000` |
| `drop_cooldown_ms` | kernel | u32 | 1000-86400000 | `2000` | `2000` |
| `block_tmp_exec` | kernel | bool | 0, 1 | `1` | `1` |
| `block_tmpfs_exec` | kernel | bool | 0, 1 | `0` | `0` |
| `block_home_write` | kernel | bool | 0, 1 | `0` | `0` |
| `net_mode` | kernel + daemon | enum | `monitor`, `host`, `lan-only`, `public-only` | `monitor` | `monitor` |
| `sudo_cooldown_enabled` | kernel | bool | 0, 1 | `1` | `1` |
| `sudo_max_fails` | kernel | u32 | 1-1000 | `5` | `5` |
| `sudo_window_sec` | kernel | u32 | 1-86400 | `60` | `60` |
| `sudo_block_time_sec` | kernel | u32 | 1-604800 | `300` | `300` |
| `timevault_strict_mmap` | kernel | bool | 0, 1 | `0` | `0` |
| `timevault_allow_autoupdate` | kernel | bool | 0, 1 | `1` | `1` |
| `timevault_max_entries` | kernel | u32 | 1-131072 | `16384` | `16384` |
| `lock_modules` | kernel | bool | 0, 1 | `1` | `1` |
| `lock_confidentiality` | kernel | bool | 0, 1 | `0` | `0` |
| `binaryvault` | kernel | bool | 0, 1 | `0` | `0` |
| `block_wifi` | kernel | bool | 0, 1 | `0` | `0` |
| `block_bluetooth` | kernel | bool | 0, 1 | `0` | `0` |
| `ethernet_only` | kernel | bool | 0, 1 | `0` | `0` |
| `prguard_enabled` | kernel | bool | 0, 1 | `0` | `0` |
| `prguard_observe` | kernel | bool | 0, 1 | `0` | `0` |
| `bpf_guard` | kernel | bool | 0, 1 | `0` | `1` |
| `bpf_lock_tracing` | kernel | bool | 0, 1 | `1` | `1` |
| `perf_guard` | kernel | bool | 0, 1 | `0` | `1` |
| `sysctl_guard` | kernel | bool | 0, 1 | `0` | `1` |
| `audit_events` | kernel | bool | 0, 1 | `0` | `1` |
| `retain_days` | daemon | integer | 1 or more days | `14` | (commented) |
| `max_total_mb` | daemon | integer | 1 or more MiB | `512` | (commented) |
| `remote_syslog` | daemon | string | `host:port`, `[v6]:port`, or empty | empty (off) | (commented) |
| `remote_syslog_transport` | daemon | enum | `udp`, `tls` | `udp` | (commented) |
| `remote_syslog_ca_file` | daemon | path | readable CA bundle | `/etc/ssl/certs/ca-certificates.crt` | (commented) |
| `remote_queue_max_mb` | daemon | integer | 1-1024 | `10` | (commented) |
| `vault_action` | daemon | enum | `quarantine`, `wipe` | `quarantine` | (commented) |
| `vault_watch` | daemon | path list | comma-separated absolute directories | `/etc,/usr/local/bin,/opt,/usr/local/sbin` | (absent) |
| `node_sea_scan_dirs` | `node-scan` | path list | comma-separated absolute directories | `/opt,/usr/local/bin,/usr/local/sbin,/usr/local/lib,/srv` | (commented) |
| `node_sea_scan_interval` | daemon | integer | 0-10080 minutes (0 = off) | `60` | (commented) |
| `alert_cmd` | daemon | argv template | command and placeholders, no shell | empty (off) | (commented) |
| `alert_min_severity` | daemon | enum | `info`, `low`, `medium`, `high`, `critical` | `high` | (commented) |
| `alert_dedup_seconds` | daemon | integer | 0-86400 | `300` | (commented) |
| `alert_max_per_minute` | daemon | integer | 1-600 | `10` | (commented) |
| `alert_timeout_seconds` | daemon | integer | 1-300 | `10` | (commented) |
<!-- config-keys:end -->

Four kernel guards (`bpf_guard`, `perf_guard`, `sysctl_guard`,
`audit_events`) are off in the kernel and on in the template. That is on
purpose: they are only safe once userspace is ready (for example
`sysctl_guard` must engage after `systemd-sysctl` has applied `sysctl.d`), so
`load` turns them on at the right point in boot. A box where `load` never ran
does not have them.

## What each key does, and its security impact

References are NIST SP 800-53 Rev. 5 controls. Where the CIS or STIG profile
has a matching rule it is named in [STIG.md](../STIG.md); no rule IDs are
quoted here that were not checked against a benchmark.

### Privilege model (#1, #1b)

- **`admin_gid`**: members of these groups count as sudo users. The installer
  fills it from the `sudo`, `wheel` and `admin` groups and sudoers; re-run
  `secure-sudo detect-admins` after adding a group. *Security impact:* every
  GID listed bypasses all "non-sudo" protections. Recommended: only the real
  admin group. `unset` means root only, the strictest value. NIST AC-6, AC-6(5).
- **`block_setid`**: denies non-sudo `setuid`, `setgid`, `setgroups` and
  user-namespace creation. This is the project's core requirement.
  *Recommended:* `1`. Setting `0` lets any user switch identity through
  these calls. NIST AC-6, AC-6(10). CWE-269.
- **`block_userns`**: denies non-sudo users unprivileged user namespaces
  separately, so namespaces can be allowed while setid stays blocked.
  *Recommended:* `1` unless rootless containers are needed. User namespaces
  are a common kernel-exploit entry point. NIST CM-7, SC-39.
- **`block_setid_exec`**: denies non-sudo users running any setuid, setgid or
  file-capability binary not in `setid_exec_allow.conf`. *Recommended:* `1`
  once that allowlist holds what users need (it removes the setuid attack
  surface). Off by default because an empty allowlist would stop `passwd`
  and similar tools. NIST AC-6, CM-7(2).

### Firmware (#3)

- **`block_flash`**: denies non-sudo users raw memory and firmware device
  nodes and firmware sysfs/efivarfs writes. *Recommended:* `1`. NIST SI-7,
  CM-7.

### RAM spike (#7)

- **`ram_spike_enabled`**, **`max_ram_percent`**, **`check_interval_ms`**,
  **`drop_cooldown_ms`**: a kernel worker drops the page cache when used
  memory reaches `max_ram_percent`, at most once per `drop_cooldown_ms`.
  *Security impact:* availability only, no access control. Dropping caches
  costs I/O, so it is opt-in. A very short interval or cooldown wastes CPU;
  the ranges stop values that would starve the system. NIST SC-5 (resource
  availability).

### Exec from scratch trees (#12)

- **`block_tmp_exec`**: denies non-sudo exec and executable mappings of files
  under `/tmp`, `/var/tmp` and `/dev/shm`, except `tmp_exec_allow.conf`.
  *Recommended:* `1`; this is the usual "noexec /tmp" control enforced in the
  kernel, so a remount cannot undo it. NIST CM-7(2).
- **`block_tmpfs_exec`**: extends that to every tmpfs and ramfs mount and to
  `memfd_create` files (fileless malware). *Recommended:* `1` once you know
  which per-user scratch directories your software runs code from.
  NIST CM-7(2), SI-3.

### Home write restriction (#4)

- **`block_home_write`**: confines non-sudo writes to the user's home, normal
  scratch and device trees, and `home_write_allow.conf`. Needs `home_map.conf`.
  *Security impact:* strong containment of a compromised user account, but it
  breaks software that writes elsewhere. Opt-in; test first. NIST AC-3, AC-6.

### Network mode (#10)

- **`net_mode`**: `monitor` (observe), `host` (kernel denies raw and
  `AF_PACKET` sockets, so no sniffing), `lan-only` or `public-only` (the
  daemon loads the `inet secure_sudo` nftables table described in
  [net-conf.md](net-conf.md)). *Security impact:* none of the modes isolates a
  host; use `secure-sudo contain network` in an incident. The table coexists
  with a CIS firewall table: a packet must pass both (OSB-23, OSB-24).
  Recommended: `host` on servers that never need raw sockets; `lan-only` on
  internal-only hosts. NIST SC-7, AC-4.

### Sudo cooldown (#8)

- **`sudo_cooldown_enabled`**, **`sudo_max_fails`**, **`sudo_window_sec`**,
  **`sudo_block_time_sec`**: after `sudo_max_fails` failed authentications
  within `sudo_window_sec`, the UID cannot run any privilege tool for
  `sudo_block_time_sec`, and the daemon freezes and kills its processes.
  Failures come from `pam_secure_sudo.so`. *Recommended:* enabled, 3-5
  failures, a window of at least 60 s and a block of at least 300 s. Very low
  values let a user lock themselves (or a shared account) out. NIST AC-7.

### TimeVault (#13)

- **`timevault_strict_mmap`**: while TimeVault is engaged, every executable
  file mapping (shared libraries) must also be allowlisted by path.
  *Security impact:* closes library injection, but without `/usr/lib*` on the
  list it stops every dynamic program. Opt-in. NIST CM-7(5), SI-7.
- **`timevault_allow_autoupdate`**: honours `auto` and `autodir` allowlist
  entries, which skip the hash check. *Recommended:* `0` on high-assurance
  hosts (every entry is then hash-checked); `1` where self-updating software
  is needed. NIST SI-7, CM-7(5).
- **`timevault_max_entries`**: the cap on the allowlist size. It bounds kernel
  memory; lower it on small systems. NIST SC-5.
- **`vault_action`** (daemon): what happens to a file that changed or was
  blocked: `quarantine` (compressed copy kept as evidence, original removed)
  or `wipe` (deleted). *Recommended:* `quarantine`, the owner's decision of
  2026-10-23, because it keeps evidence. NIST IR-4, AU-9, SI-7.
- **`vault_watch`** (daemon): the trees the daemon scans while engaged. Every
  file here is baselined at engagement, so engage on a known-good system.
  NIST SI-7(1).

### BinaryVault (#17)

- **`binaryvault`**: freezes every executable and shared library against
  writes, deletes, renames, hard links, mode and xattr changes, for everyone
  including root. *Security impact:* strongest anti-persistence control, but
  package updates need the documented procedure
  ([BINARYVAULT.md](../BINARYVAULT.md)). NIST SI-7, CM-5.

### RadioGuard (#19)

- **`block_wifi`**, **`block_bluetooth`**, **`ethernet_only`**: keep the
  radios off; `ethernet_only = 1` overrides the other two. *Recommended:* `1`
  on wired servers. NIST AC-18(3).

### Process runtime guard (#20)

- **`prguard_enabled`**: denies cross-process memory tampering and
  writable-and-executable memory, except `prguard_allow.conf`. *Security
  impact:* blocks code injection; JITs and debuggers need allowlisting.
  Opt-in. NIST SI-16, SC-39.
- **`prguard_observe`**: logs every cross-process memory access. Monitoring
  only, verbose. NIST SI-4.

### BPF and perf guard (#22)

- **`bpf_guard`**: denies all `bpf(2)` to non-sudo users, backing up
  `kernel.unprivileged_bpf_disabled`. *Recommended:* `1`. NIST CM-7, AC-6.
- **`bpf_lock_tracing`**: once locked, refuses to load tracing-class BPF
  programs (the kinds BPF rootkits use) for everyone, root included.
  Networking and cgroup BPF still work. *Recommended:* `1`. NIST SI-7, CM-7.
- **`perf_guard`**: denies `perf_event_open(2)` to non-sudo users, backing up
  `kernel.perf_event_paranoid`. *Recommended:* `1`. NIST AC-6, SC-39.

### Sysctl guard (#23)

- **`sysctl_guard`**: refuses write-opens of the security-critical sysctls
  (list in [CONFIGURATION.md](../CONFIGURATION.md)) for everyone, root
  included, and all `binfmt_misc` writes. *Recommended:* `1`. It stops the
  `core_pattern` and `modprobe` persistence tricks. NIST CM-6, CM-5.

### Config lock (#16)

- **`lock_modules`**: when the lock engages, refuse all module loads, not only
  blacklisted ones. *Recommended:* `1`. Read at the moment the lock engages.
  NIST CM-7, SI-7.
- **`lock_confidentiality`**: while locked, also refuse kernel lockdown's
  confidentiality class (`/proc/kcore`, kprobes, kernel reads via BPF, perf
  and tracefs). *Security impact:* stops kernel memory disclosure, and also
  stops `perf` and `bpftrace`. Opt-in. NIST SC-4, AC-6.

### Logging and forwarding (#9)

- **`audit_events`**: sends every secure_sudo event to the audit subsystem
  (`AUDIT_KERNEL_OTHER`), hex-encoding messages with spaces or quotes so a
  crafted file name cannot forge audit fields. *Recommended:* `1`.
  NIST AU-2, AU-12. CWE-117.
- **`retain_days`**, **`max_total_mb`**: local log retention by age and total
  size. *Security impact:* too short loses evidence; too large can fill
  `/var`. Set retention to your incident-response policy. NIST AU-11, AU-4.
- **`remote_syslog`**: the collector address. *Recommended:* set it, so logs
  survive a compromised host. NIST AU-4(1), AU-9(2).
- **`remote_syslog_transport`**: `udp` is unauthenticated and unencrypted
  (legacy). *Recommended:* `tls` (RFC 5425, certificate and host checked).
  NIST SC-8, AU-9. CWE-319.
- **`remote_syslog_ca_file`**: the CA bundle that authenticates the collector
  in TLS mode. Use a bundle with only your collector's CA where possible.
  NIST SC-8, IA-3.
- **`remote_queue_max_mb`**: the TLS disk queue cap (also capped at 4096
  files). When full, the newest event is dropped and counted in
  `secure-sudo health`. NIST AU-5, AU-4.

### Node child guard (#11)

- **`node_sea_scan_dirs`**: where `secure-sudo node-scan` looks for Node
  runtimes outside the standard paths. Narrow it if a scan stops early.
  NIST CM-8.
- **`node_sea_scan_interval`**: minutes between the daemon's scans; `0` turns
  the timer off. NIST CM-8.

### Alerting (P2-3)

- **`alert_cmd`**: a command run for each alert, without a shell (quoting
  groups words; placeholders `%s %t %d %r %o %u %m %j %h %n %%`). The daemon
  refuses an unsafe template and turns alerting off. *Security impact:* no
  shell means event text cannot inject commands. NIST SI-4(5), IR-6. CWE-78.
- **`alert_min_severity`**: the lowest severity that alerts. An invalid value
  turns alerting off and is logged. Recommended: `high`.
- **`alert_dedup_seconds`**, **`alert_max_per_minute`**,
  **`alert_timeout_seconds`**: dedup window, rate limit and kill timeout, so a
  burst of events cannot flood the on-call channel or hang the daemon.
  NIST SI-4, SC-5.

## Related

- [net-conf.md](net-conf.md), [pheonixbox-conf.md](pheonixbox-conf.md)
- `secure-sudo lint` checks this file without changing anything.
- [CONFIGURATION.md](../CONFIGURATION.md) for the full feature narrative.
