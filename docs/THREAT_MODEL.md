# secure_sudo — threat model and supported deployment profile

This is the TODO P1-5 deliverable. It says what secure_sudo is meant to
stop, what it relies on, what it does **not** stop, where it is supported,
and which test proves each control. If a feature's name, the README, or a
compliance mapping seems to promise more than this document, this document
is the one that matches the code. Where the docs used to promise more than
the code did, the gap is listed in §7 as work to build, not dropped.

How each control in §5 is described:

* **Threat**: the attack it is meant to stop.
* **Needs**: what must be true for it to work (knobs, policy, other parts).
* **Limits**: what it does not stop, including known ways around it.
* **Tested by**: the automated test, or the manual step where no automated
  test is possible yet.

Test names refer to `tests/vm/ss-functest.c` (in-kernel tests, run in CI on
kernel.org 6.12.114 by the `kernel-boot` job), the host suites under
`tests/` (run by `ci/build-gate.sh`), the full Ubuntu guest under
`tests/vm/distro/` (the `distro-vm` job) and the manual
[HARDWARE_SMOKE_TEST.md](HARDWARE_SMOKE_TEST.md).

---

## 1. What secure_sudo is for

It hardens one Linux host against **local** misuse: a non-sudo user, or a
program running as one, trying to become someone else, run or plant code it
should not, reach firmware or kernel internals, or tamper with other
processes. After the one-way lock (#16), it also limits what **root** can
change in the kernel and in secure_sudo's own policy until the next reboot.

## 2. Trust assumptions: what it does not defend against

secure_sudo does **not**, by itself, defeat any of these. Each needs another
control, named where there is one.

| Not defended | Why | What does help |
|---|---|---|
| The install-time administrator | Whoever runs `install.sh` and writes the first policy decides what is allowed. | Review the policy (`secure-sudo lint`), keep the install record. |
| Root **before** the lock | Root can change or switch off every knob and list, and can rewrite the config files that load at boot. | Engage the lock (`secure-sudo lock`, or TimeVault does it) once the box is configured. |
| Root **after** the lock, outside secure_sudo's scope | The lock freezes secure_sudo's policy and the kernel-integrity paths (module loads, kexec, `/dev/mem`, BPF tracing, protected sysctls). Root can still read every file, kill processes, stop `secure-sudod`, flush nft rules, delete local logs, edit PAM and boot files for the next boot. | BinaryVault/TimeVault for programs, off-box log forwarding, a GRUB password and Secure Boot for the boot path. |
| A compromised kernel | secure_sudo runs inside the kernel. A kernel exploit, or code already loaded into the kernel, can switch it off. | Fewer reachable kernel paths (#1 user namespaces, #22 BPF/perf), module signing, `lock_modules`. |
| A physical attacker | They can boot other media, reset firmware, clear the TPM from the firmware menu, or read an unencrypted disk. | Firmware password, disk encryption (`install/encrypted/`), Secure Boot. |
| Malicious or compromised firmware (UEFI, BMC, ME) | It runs below the kernel. | Vendor firmware updates; BiosGuard (add-on) can only *detect* some changes. |
| Anyone who can boot another kernel or command line | `lsm=`, `init=`, `secure_sudo.tpm_maint=1`, `secure_sudo.binvault_maint=1` or another kernel undo everything. | GRUB password (STIG `grub2_password`, kept working by SECURITY_REVIEW #51), Secure Boot with the MOK, a firmware password. |
| Members of the admin group | secure_sudo treats them as sudo for every "non-sudo" check (§4.2), even in processes they run without sudo. | Separate admin accounts, a small admin group, the OTP (#14). |
| Network attackers | Only #10's raw-socket and nft modes touch the network. It is not a firewall product or an IDS. | A real firewall, P1-8 network tests. |
| The build host and kernel source | The build trusts the host it runs on and kernel.org's signing key. | `scripts/verify-kernel-source.sh` (fails closed), reproducible packages, the SBOM. |

## 3. Who it is designed to stop

1. **A local non-sudo user**, or a service account, trying to gain another
   UID, run a forbidden or planted program, flash firmware, sniff traffic,
   plant files outside its home, inject into other processes, or brute-force
   sudo.
2. **A compromised application running as a non-sudo UID**, for example a
   Node.js server with a remote-code-execution bug, trying to pivot to a
   shell or other programs (#11, #12, #13).
3. **Root after the lock**, for example on a locked appliance that is
   compromised after boot, trying to change secure_sudo's policy, load kernel
   code (modules, tracing BPF, kexec), patch kernel memory, change the
   protected sysctls, or (with BinaryVault/TimeVault) change or run programs.

## 4. Supported deployment profile

### 4.1 Roles, distributions and kernels

* **Supported:** a physical machine or VM running the kernel that
  `install.sh` builds, as a workstation, a multi-user host or a server.
  A container **host** is supported: container processes are checked like
  any other process, by their real (initial namespace) UID. Rootful
  containers run as real root and are treated as sudo. Rootless containers
  need user namespaces, which #1 refuses to non-sudo users by default.
* **Not supported:** running secure_sudo inside a container (it is part of
  the kernel); hosts where non-sudo users need unprivileged user namespaces
  (rootless Podman/Docker, unprivileged LXC, Flatpak's bubblewrap without
  setuid, Chromium/Electron sandboxes that use them) unless `block_userns=0`,
  which reopens a route around #1; hosts that need unsigned out-of-tree
  modules (the kernel enforces module signatures).
* **Distributions:** `install.sh` handles the Debian/Ubuntu, Fedora/RHEL,
  Arch and openSUSE families. **Only Ubuntu 24.04 is tested end to end**
  (the `distro-vm` CI job). Treat the others as unsupported until the
  hardware smoke test passes on them.
* **Kernels:** 6.12 LTS is the target (CI boots kernel.org 6.12.114). The
  LSM compiles against 6.11 and 6.14 headers and boots on 6.14 in QEMU.
* **Hardware:** not yet tested on real machines. Run
  [HARDWARE_SMOKE_TEST.md](HARDWARE_SMOKE_TEST.md) on each model first.

### 4.2 Who counts as "sudo"

The kernel's rule (`ss_cred_is_sudo()` in `ss_core.c`):

* real or effective UID 0, in the initial user namespace; or
* real, effective or filesystem GID, or any supplementary group, in
  `admin_gid` (up to 16 GIDs). `unset` means root only.

The installer fills `admin_gid` from the `sudo`, `wheel` and `admin` groups
(`scripts/detect-admin-gids.sh`). What this means in practice:

* It is **membership, not authentication**. Every process an admin-group
  member runs, sudo or not (browser, editor, a malicious download), is exempt
  from every "non-sudo" check: #1, #1b, #2, #3, #4, #12 and the non-sudo half
  of #22. Malware in an admin's session is outside those controls.
* A setuid-root program counts as sudo while its effective UID is 0.
* Root inside a user namespace is not root here: its UID maps to a non-zero
  UID in the initial namespace.
* Group changes apply to new logins (the kernel reads the process's
  credentials, not `/etc/group`).

### 4.3 LSM order and stacking

* `install.sh` adds `secure_sudo` to `CONFIG_LSM` just before `bpf`, or last.
  The test kernels use `landlock,lockdown,yama,secure_sudo,bpf`.
* secure_sudo is a **minor** LSM: it only adds denials. It never grants what
  DAC, capabilities or another LSM refuses. A request refused earlier never
  reaches secure_sudo, so secure_sudo logs nothing for it.
* **AppArmor:** tested stacked. The Ubuntu guest runs AppArmor with profiles
  loaded next to secure_sudo, and an initramfs build with AppArmor stacked
  passes the in-kernel suite (`docs/vm/results/03-*`).
* **SELinux:** **not tested.** It should stack the same way (secure_sudo uses
  only an LSM task blob), but Fedora/RHEL hosts are unsupported until the
  hardware smoke test passes with SELinux enforcing.
* **Yama, Landlock, lockdown:** present in every test kernel and independent.
  `t_registration` checks they are active and that secure_sudo comes after
  Yama. While locked, #16 answers the kernel's `locked_down` check for the
  integrity class itself, whatever mode the lockdown LSM is in.
* **IMA/EVM:** not tested. While BinaryVault is on, it refuses xattr writes
  on programs, which includes IMA/EVM relabelling.

### 4.4 Boot path, Secure Boot and lockdown

* Without Secure Boot and a GRUB password, anyone who reaches the boot menu
  can boot without secure_sudo or with a maintenance parameter. The STIG
  GRUB password is supported (`install.sh verify` checks a normal boot needs
  no password, SECURITY_REVIEW #51).
* `secure_sudo.tpm_maint=1` and `secure_sudo.binvault_maint=1` open #5 and
  #17 for one boot. Whoever can edit the kernel command line can use them.
* The encrypted variant signs the kernel and modules with an enrolled MOK
  and can build a signed UKI. **It is not tested under UEFI Secure Boot**
  (no UEFI in CI, no hardware run yet).

### 4.5 Logging and audit

* Every secure_sudo denial is a JSON record in a 64 KiB kernel ring
  (`/sys/kernel/security/secure_sudo/events`, mode 0400). `secure-sudod`
  writes dated logs and can forward them over TLS (P1-2).
* With `audit_events=1` (installed default) each record also goes to auditd
  as `AUDIT_KERNEL_OTHER`. Records lost to a full ring or audit backlog are
  counted (`events_dropped`, `audit_events_dropped`), not prevented.
* Root can stop the daemon and delete the local logs. Only records already
  forwarded off the box survive that.

### 4.6 Distribution tooling

* **Package managers** are refused while TimeVault is engaged, and
  BinaryVault refuses updates to existing programs. Unattended upgrades fail
  while either is on; update in a maintenance boot.
* **DKMS / out-of-tree modules** must be signed with the kernel's key, and
  `lock_modules` refuses every module load once locked.
* **STIG/CIS remediation** writes sysctls: run it before turning on
  `sysctl_guard` (`stig-harden.sh` does).
* **Firewalls:** #10 adds its own nft table; CIS's default-deny nftables
  rules are left out on purpose (OSB-16).
* **systemd:** services that create user namespaces run as root and are
  allowed; `systemd --user` units with `PrivateUsers=` for a non-sudo user
  fail while `block_userns=1`.
* **Network mode `host`** refuses raw and packet sockets to everyone. DHCP
  clients that use packet sockets (dhclient, systemd-networkd,
  NetworkManager's internal client) and tcpdump stop working in that mode;
  check your network setup before using it.

---

## 5. Controls

### #1 UID/GID switch block and user-namespace gate (kernel)

* **Threat:** a non-sudo process that holds or obtains `CAP_SETUID` or
  `CAP_SETGID` (a misconfigured service, a file capability, a leaked
  capability) switches to another user or to root; a non-sudo user creates a
  user namespace to get namespaced root and the kernel attack surface that
  comes with it.
* **Needs:** `block_setid=1` and `block_userns=1` (defaults); `admin_gid`
  set to the real admin groups.
* **Limits:** it does not stop gaining privilege by *running* a setuid or
  file-capability program (that is #1b, off by default), or sudo/su with a
  valid password. Admin-group members are exempt. `block_userns` breaks
  rootless containers and some sandboxes (§4.1). A kernel bug reachable
  without a user namespace is not affected.
* **Tested by:** `t_creds` (denial with the capability held, no-op change
  allowed, admin GID, root, knob off; user namespaces for non-sudo, root and
  knob off).

### #1b Setuid/file-capability exec gate (kernel)

* **Threat:** a non-sudo user escalates through a setuid-root or
  file-capability program (the PwnKit, Baron Samedit, Looney Tunables class).
* **Needs:** `block_setid_exec=1` and `setid_exec_allow` listing the setuid
  programs users really need. Off by default.
* **Limits:** off by default. A bug in an allowlisted setuid program (sudo,
  passwd) is not stopped. Matching is by path. A wrong allowlist locks users
  out of passwd/su (recovery exercises E1, E2).
* **Tested by:** `t_setid_exec`; recovery exercises E1 and E2 in the Ubuntu
  guest.

### #2 Command blacklist (kernel)

* **Threat:** a non-sudo user runs a specific installed program the
  administrator forbids (a compiler, `nc`, a debugger).
* **Needs:** absolute paths that exist when the list is loaded. Reload the
  list after an upgrade replaces a listed program, so its new contents are
  fingerprinted.
* **Limits:** a copy with changed bytes is a different program and runs
  (use TimeVault, an allowlist, for that). Interpreters read scripts as data:
  blacklisting a script does not stop `sh script`. The same job done by
  another program is not covered. Admin-group members and root are exempt.
* **Matches:** the path, the inode (a rename or hard link), and since P1-5
  the **content**: each entry's SHA-256 and size are taken at load, and a
  same-size program is hashed at exec, so an exact copy at a new path is
  refused. Only same-size files are hashed.
* **Tested by:** `t_blacklist` (path, hard link, exact copy, changed copy,
  root, cleared list, events), `t_concurrency`.

### #3 Firmware, flash and raw-memory block (kernel)

* **Threat:** a non-sudo process with a leaked `CAP_SYS_RAWIO` or loose
  device permissions reads or writes physical memory, flashes SPI/MTD/ME
  firmware, or writes EFI variables.
* **Needs:** `block_flash=1` (default); the standard device numbers and
  `/sys/firmware` layout.
* **Limits:** root and admin-group members are not blocked; root is stopped
  only by the lock (#16) and kernel lockdown. Firmware paths through other
  devices (NVMe admin commands, GPU or vendor ioctls, a BMC) are not covered.
* **Tested by:** `t_firmware` (`/dev/mem` at mode 0666 with
  `CAP_SYS_RAWIO`, root, knob off, event). `/dev/mtd*`, `/dev/mei*` and
  efivars: no such devices in the VM; HARDWARE_SMOKE_TEST.md §4.

### #4 Home-write confinement (kernel)

* **Threat:** a non-sudo user or service account plants files outside its
  home: in world-writable or wrongly group-writable directories, to persist
  or to attack other users.
* **Needs:** `block_home_write=1` (off by default); `home_map` for every
  user (written by `secure-sudo load`); `home_write_allow` for legitimate
  places (mail spool, cron spool, application data).
* **Limits:** `/tmp`, `/var/tmp`, `/dev/shm`, `/dev`, `/run`, `/proc`,
  `/sys` and `/var/lock` stay writable (the dangerous parts of `/dev` and
  `/sys` are #3's job). Writes a privileged service makes on the user's
  behalf (D-Bus services, spoolers, cron) are not confined. Files opened
  before the knob was turned on stay writable. Admin-group members are
  exempt. It breaks programs that write elsewhere, which is why it is
  opt-in.
* **Tested by:** `t_home` (write and mkdir outside home denied at mode 0777,
  inside home and `/tmp` allowed, root, allowlist).

### #5 TPM clear block (kernel)

* **Threat:** anyone, root included, schedules a TPM clear through the
  Physical Presence Interface (`echo 5 > /sys/class/tpm/tpm0/ppi/request`),
  wiping TPM-sealed disk keys at the next boot.
* **Needs:** a TPM whose PPI is in sysfs; normal boots without
  `secure_sudo.tpm_maint=1`.
* **Limits:** only the PPI route is blocked. A `TPM2_Clear` command sent
  through `/dev/tpm0` or `/dev/tpmrm0` with the lockout authorization (empty
  by default on many machines) is **not** blocked: secure_sudo cannot see the
  bytes written to the device. Set a lockout password (`tpm2_changeauth -c
  lockout`). The firmware setup menu can always clear the TPM. Listed as gap
  G4 in §7.
* **Tested by:** no automated test (no TPM in the CI guest).
  HARDWARE_SMOKE_TEST.md §3 (harmless request `0` as root is refused and
  logged). The denial is logged as a `tpm_guard` event since P1-5.

### #6 Driver blacklist, anti-BYOVD (kernel)

* **Threat:** root, or an installer running as root, loads a known-vulnerable
  or malicious signed driver to get code into the kernel ("bring your own
  vulnerable driver").
* **Needs:** `driver_blacklist` with the SHA-256 of known-bad module files
  and/or module names; module signatures enforced (installer); the lock
  with `lock_modules=1` for "no new modules at all".
* **Matches:** the SHA-256 of the exact bytes loaded (`finit_module` and
  `init_module`); a name entry against the file name and, since P1-5,
  against the **module's own name** (checked just before its init code runs,
  so a renamed file, a compressed module and `init_module` with no file are
  all caught).
* **Limits:** a blacklist knows only the drivers you list; any other
  vulnerable but validly signed driver loads. A recompressed or re-signed
  module has a different file hash (a name entry still catches it). Built-in
  drivers are never loaded, so never checked. Root can clear the list before
  the lock.
* **Tested by:** `t_modules` (name via `finit_module` and `init_module`, a
  renamed copy, hash via both calls, cleared list), `t_lock`
  (`lock_modules`).

### #7 RAM-spike cache drop (kernel)

* **Threat:** none in the security sense. It is an availability aid: drop
  the page and slab caches when real memory use crosses a threshold.
* **Needs:** `ram_spike_enabled=1` (off by default).
* **Limits:** it does not free process memory or stop a memory-exhaustion
  attack (the OOM killer does that), and dropping caches costs performance.
  Do not count it as a security control.
* **Tested by:** `t_ram` (drop above the threshold, logged as a `ram_guard`
  event raised by the kernel worker; no drop when off).

### #8 Sudo brute-force cooldown (kernel + PAM + daemon)

* **Threat:** a local user, or malware in their session, guesses the sudo/su
  password online.
* **Needs:** `pam_secure_sudo` in the auth stack of sudo and su (installer,
  order fixed by SECURITY_REVIEW #37); `sudo_cooldown_enabled=1` (default);
  `secure-sudod` running to stop and kill the offender's sudo processes.
* **Limits:** only failures reported through `pam_secure_sudo` count:
  polkit over D-Bus, ssh, the login screen, and tools without that PAM stack
  are not counted, and a polkit authorization that does not exec `pkexec` is
  not blocked. Each UID has its own budget. The table is in memory and resets
  at reboot. Root can clear a block (`ok <uid>`). The block stops new runs of
  sudo-like programs; it does not end sessions already elevated (the daemon's
  kill does). The distro's `pam_faillock` is the standard equivalent and can
  run alongside.
* **Tested by:** `t_cooldown` (kernel: 4 failures allowed, 5th blocks sudo
  and any setuid-root program, other programs and users unaffected, success
  lifts it, block event carries `target_uid`); `tests/userspace/test-pam.sh`
  (PAM reports); `test-daemon-events.sh` (the daemon takes the UID from
  `target_uid`). The kill itself is tested against recorded events, not a
  live sudo session.

### #9 Events, logging, forwarding and evidence (kernel + daemon + CLI)

* **Threat:** an attacker hides their activity by erasing, forging or
  flooding the record.
* **Needs:** `secure-sudod` running; TLS forwarding to a collector for
  records to survive a root compromise; `audit_events=1` for auditd;
  `secure-sudo evidence-export` for incident bundles.
* **Limits:** the ring is 64 KiB; a local user can flood it with denials,
  and the overflow is counted but lost. Root can stop the daemon and delete
  local logs. Records show UIDs, PIDs, program names and paths
  ([INTEGRATION.md](../kernel/security/secure_sudo/INTEGRATION.md), "What a
  record can reveal"). An evidence signature proves the bundle has not
  changed since export, not that the events in it are true. Denials made by
  DAC or another LSM before secure_sudo are not recorded by secure_sudo.
  Until P1-5, #2, #3, #5, #10 and #12 denials reached only the kernel log
  (SECURITY_REVIEW #54).
* **Tested by:** `t_events` (schema, sequence, ordering, loss counters, a
  20,000-record burst, audit feed, kernel-started helpers) and the event
  checks in every control test; `test-daemon-events.sh`,
  `test-remote-forwarding.sh`, `test-evidence-export.sh`.

### #10 Network modes (kernel + daemon)

* **Threat:** `host`: packet sniffing from a compromised process.
  `lan-only` / `public-only`: limit where the host can talk to.
* **Needs:** the `net_mode` knob (the kernel half refuses raw and packet
  sockets in `host` mode, root included); `secure-sudod` loading the
  `secure_sudo` nft table; netfilter in the kernel (SECURITY_REVIEW #47).
* **Limits:** the LAN/public modes are nft rules loaded from userspace, so
  root can flush them, and other nft tables can still accept traffic. LAN
  detection is automatic and can be wrong on unusual networks. `host` mode
  breaks DHCP clients that use packet sockets (§4.6). Not application-aware.
* **Tested by:** `t_net` (packet socket in host mode, root included,
  event); `tests/userspace/test-helpers.sh` (each mode's ruleset loaded into
  real nft in network namespaces, IPv6, DHCP and DNS kept). P1-8 adds more.

### #11 Node.js child-process guard (kernel)

* **Threat:** remote code execution in a Node.js application pivots to a
  shell or other programs (`child_process.exec`).
* **Needs:** the application runs as a program named `node`/`nodejs`, at a
  standard path, or registered in `node_sea_binaries`; `node_allowed_children`
  lists exactly the programs it needs to start. `secure-sudo node-scan`
  (run by the daemon at start and hourly) registers single-executable apps,
  pkg builds and renamed node binaries it finds under `node_sea_scan_dirs`.
* **Limits:** it guards exec only. The attacker still runs any JavaScript or
  native addon code inside the Node process, with its UID's rights (files,
  network). A child on the allowlist runs unguarded: allowlisting a shell,
  an interpreter, `git`, `npm` or anything else that starts programs reopens
  the pivot. A Node build under another name is guarded only once it is
  registered: `node-scan` finds it by Node's SEA fuse or pkg's markers, but
  only under the scanned directories and only up to an hour after it
  appears (run `node-scan` after deploying one). A build with the markers
  stripped is not found. Electron apps are reported, not registered (they
  would confine a whole desktop UI). Registering a file only adds
  restriction, so a planted marker gains an attacker nothing; root-owned
  files are listed ahead of others so planted ones cannot crowd them out of
  the kernel's 256 entries. A bare name entry matches that name in any
  directory. It applies to root too.
* **Tested by:** `t_node` (unlisted child refused, event, root, allowed
  child, registered single-executable app); `tests/userspace/test-node-scan.sh`
  (finding SEA/pkg/renamed node by marker, real Node with a flipped fuse,
  Electron skipped, merge order and limits, cache, partial scans); the
  Ubuntu VM run (a found app's child refused by the real kernel, G1 steps).

### #12 Scratch-tree exec block (kernel)

* **Threat:** download-and-run from `/tmp`, `/var/tmp` or `/dev/shm` by a
  non-sudo process; with `block_tmpfs_exec`, fileless `memfd` exec and exec
  from any tmpfs.
* **Needs:** `block_tmp_exec=1` (default); `block_tmpfs_exec=1` for memfd
  and every tmpfs (off by default).
* **Limits:** interpreters read scripts as data (`sh /tmp/x`, `python3
  /tmp/x.py` run). Other user-writable places (home, application
  directories) are not covered: use #4 or #13. A `PROT_EXEC` mapping of a
  memfd is allowed on purpose (JIT compilers). Admin-group members are
  exempt.
* **Tested by:** `t_tmpexec` (exec and mmap from `/tmp`, root, allowlist,
  memfd with and without `block_tmpfs_exec`, events).

### #13 TimeVault (kernel + daemon)

* **Threat:** running any program that is not approved and pinned by hash,
  root included, once the vault is engaged: malware, swapped binaries,
  unapproved installs.
* **Needs:** an allowlist with a SHA-256 for every program the system runs
  (and, with `timevault_strict_mmap=1`, every shared library); those programs
  root-owned and not group/world-writable; `secure-sudod` for quarantine;
  forwarding so the record survives. Engaging latches the lock until reboot.
  The daemon's first scan after engaging records the watched trees as the
  baseline (gap G2): files already there then are trusted, so engage on a
  known-good system.
* **Limits:** an allowlisted interpreter (bash, python, perl) runs any
  script. Without `timevault_strict_mmap` (default off) shared libraries are
  not checked, so `LD_PRELOAD` or `dlopen` of an unlisted library runs code
  inside an allowed program. Auto-update entries (`timevault_allow_autoupdate`,
  default on) skip the hash: anything written into an auto-update directory
  runs. Package managers are refused by program name. Code already running
  when the vault engages keeps running. Code generated in memory inside an
  allowed process is #20's concern. Quarantine is done by the daemon after
  the denial (the program does not run either way). It cannot be turned off
  until reboot; follow the TODO's caution and test it off production first.
* **Tested by:** `t_timevault_prepare` and `t_timevault` (empty list
  refused without locking, matching hash runs, unlisted and changed binaries
  refused for root too, package manager refused even with its hash, memfd
  refused, listed binary cannot be opened for writing, event, counter,
  cannot disengage); `test-daemon-events.sh` (quarantine path checks,
  SECURITY_REVIEW #48 and #52; the baseline, rescans, the Merkle root, a
  rewritten or deleted manifest, #60); `test-evidence-export.sh`
  (`--timevault` against the collector's roots).

### #14 Rotating OTP sudo password and #15 encrypted OTP secret (PAM + helper)

* **Threat:** a stolen or guessed account password alone is enough for sudo;
  an observed code is replayed.
* **Needs:** `pam_secure_otp` in sudo's PAM stack, set up before it is
  wired in (recovery exercise E3); a correct clock.
* **Limits:** a real-time phishing relay still works. The secret is
  AES-256-GCM under a root-only key file, **not TPM-sealed** (gap G3 in §7):
  root, or anyone who reads an unencrypted disk, can decrypt it. Codes are
  valid for their time step (each accepted once). It protects only the PAM
  services it is added to.
* **Tested by:** `tests/userspace/test-otp.sh`, `test-pam.sh` (real
  `pam_unix` stacks as root), recovery exercise E3.

### #16 One-way lock (kernel)

* **Threat:** root, after boot, changes secure_sudo's policy, loads kernel
  code, or patches the kernel to undo the protections.
* **Needs:** the lock engaged (`secure-sudo lock`, or TimeVault);
  `lock_modules=1` (default); `lock_confidentiality=1` to also stop kernel
  memory reads; a protected boot path, or a reboot undoes it.
* **Limits:** until reboot only. It does not limit root outside the kernel
  and secure_sudo's policy (§2). Modules and BPF programs loaded before the
  lock stay. It cannot be undone without a reboot (recovery exercise E4).
* **Tested by:** `t_lock` (lock latches and cannot be cleared, knobs and
  lists refuse writes, module loads and tracing BPF refused, normal exec
  works); recovery exercise E4 in the Ubuntu guest.

### #17 BinaryVault (kernel)

* **Threat:** tampering with installed programs and libraries for
  persistence, by any UID including root.
* **Needs:** `binaryvault=1` (installed default 0, opt-in);
  `CONFIG_SECURITY_PATH`; a maintenance boot for updates.
* **Limits:** new files are not blocked: a new program can be written and
  run unless #12 or #13 stops it. A hard link made before the vault engaged,
  and a filesystem mounted over a system directory, are left to TimeVault.
  What counts as a program: a regular file with an execute bit, or a `.so`
  under a library tree; scripts without `+x`, configuration files and
  libraries elsewhere are not covered. The maintenance boot parameter is on
  the kernel command line (§4.4). Package updates and IMA/EVM relabelling are
  refused while it is on.
* **Tested by:** `t_binvault` (root cannot write, unlink, rename, hard-link,
  chmod or set an xattr on a program; libraries covered; data files and new
  files not; programs still run; allowlist; off again).

### #18 STIG / OpenSCAP tooling (userspace)

* **Threat:** configuration drift from a hardened baseline.
* **Needs:** OpenSCAP and the SCAP Security Guide; the Ubuntu 24.04 profile.
* **Limits:** a passing scan shows the configuration matches the rules. It
  does not show that secure_sudo stops any attack. Accepted exceptions:
  FIPS mode (`is_fips_mode_enabled`, a self-built kernel cannot be
  FIPS-certified) and `service_sssd_enabled`. CIS's default-deny nftables
  rules are left out (OSB-16). Only the Ubuntu 24.04 STIG profile is tested.
* **Tested by:** the CI STIG release gate on 6.12.114 (16/16), 
  `tests/oscap/stig-gate.sh`, `test-oscap-results.sh`.

### #19 RadioGuard (kernel)

* **Threat:** Wi-Fi or Bluetooth as a way in or out on a machine that should
  be wired-only.
* **Needs:** the knobs set by `secure-sudo load` at early boot, before radio
  modules load; radio drivers built as modules; rfkill.
* **Matches:** the core Wi-Fi/Bluetooth module names, checked against the
  file name and, since P1-5, the **module's own name** (a renamed copy, a
  compressed module and `init_module` are caught); `AF_BLUETOOTH` sockets;
  writes to `/dev/rfkill`.
* **Limits:** drivers built into the kernel are never loaded, so only the
  rfkill layer applies. A radio already up this boot stays up until
  `rfkill block` or a reboot. Other radios (LTE modems, Zigbee, SDR) are not
  covered.
* **Tested by:** `t_radio` (socket for non-sudo and root, rfkill write
  refused and read allowed, module names including `.ko.zst` and dash
  spellings, a renamed copy of `mac80211_hwsim` refused by its module name
  via `finit_module` and `init_module`, `ethernet_only`); HARDWARE_SMOKE_TEST.md
  §5 for real radios.

### #20 Process Runtime Guard (kernel)

* **Threat:** process injection (ptrace attach, `process_vm_writev`,
  `/proc/<pid>/mem` writes) and writable-and-executable memory used by
  injected code.
* **Needs:** `prguard_enabled=1` (off by default); `prguard_allow` for
  debuggers, profilers and JITs.
* **Limits:** a process already being traced when the guard is turned on
  stays traced. Exempt programs can still inject. W^X refusal breaks JIT
  runtimes (browsers, Java, Node) that are not exempt. Read-mode access
  (`/proc/<pid>/environ`, `maps`, `stat`, what `ps` and `top` use) is left
  alone; `process_vm_readv` and `/proc/<pid>/mem` reads need attach mode and
  are refused.
* **Tested by:** `t_prguard` (attach, `process_vm_writev`,
  `/proc/<pid>/mem`, root, W+X, exemption).

### #21 PheonixBox (userspace)

* **Threat:** tampering with or deleting chosen files (for example
  configuration), repaired after the fact.
* **Needs:** `secure-sudod`'s timer (about every 30 s); the store
  (`/var/lib/secure_sudo/pheonixbox`) on protected storage.
* **Limits:** it repairs within one interval, it does not block; whatever a
  tampered file did meanwhile has happened. Root can change the store or turn
  it off (the lock does not cover userspace). Pair it with #17/#13 for
  programs.
* **Tested by:** `tests/userspace/test-pheonixbox.sh` (ROOT-ONLY, in a
  private mount namespace: snapshot, tamper, detect, restore, permissions).

### #22 BPF and perf guard (kernel)

* **Threat:** non-sudo users reaching kernel attack surface or side channels
  through `bpf(2)` and `perf_event_open(2)`; root loading tracing BPF
  (rootkits) after the lock.
* **Needs:** `bpf_guard=1`, `perf_guard=1` (installed defaults); the lock
  for `bpf_lock_tracing`.
* **Limits:** programs loaded before the lock keep running. Networking,
  cgroup and `struct_ops` BPF stay allowed on purpose. Admin-group members
  are exempt from the non-sudo half. Root before the lock is not limited.
* **Tested by:** `t_perf_bpf`, `t_lock`.

### #23 SysctlGuard (kernel)

* **Threat:** root persistence or weakening through `core_pattern`,
  `modprobe`, `kptr_restrict` and the other protected sysctls, or a
  binfmt_misc handler.
* **Needs:** `sysctl_guard=1` after `sysctl.d` has applied; the lock to
  freeze the knob.
* **Limits:** a fixed list; per-network-namespace sysctls are not frozen
  (containers set them). A bad value set before the guard is turned on is
  what gets frozen.
* **Tested by:** `t_sysctl`, and the core-dump helper test in `t_events`.

### Install and boot-path controls

| Control | Tested by |
|---|---|
| kernel.org signature check before the build (fails closed) | `tests/provenance/test-verify-kernel-source.sh` |
| trial boot, rollback, commit, clean uninstall | the `distro-vm` CI job (`run-install-test.sh`) |
| module signatures enforced in the secure_sudo kernel only | `distro-vm` (`verify: module signatures enforced`) |
| GRUB password compatibility | `distro-vm` (top-level entries), SECURITY_REVIEW #51 |
| reproducible release and SBOM | `ci/build-gate.sh` package stage |
| encrypted source, MOK signing, signed UKI | **not tested** (no UEFI Secure Boot in CI) |

### Add-ons in `temporary/` (outside the supported profile)

ProcGuard, DriverGuard, BiosGuard, BootGuard, Locus, tamperwatch and the
management GUI are opt-in and **not part of the supported profile**. Each
is built with `-Werror` (the GUI is byte-compiled) by the gate, and none has
a functional test yet. Their honest limits are in [ADDONS.md](ADDONS.md):
ProcGuard is a 5-second poller that kills by program path, BiosGuard only
detects, BootGuard restores at the next boot, tamperwatch only watches files
that existed when it started, the GUI's token protects it only on loopback.
Do not rely on them until they have tests.

---

## 6. What names and compliance mappings do not mean

* **TimeVault** is not about time. It is an exec allowlist pinned by hash.
* **BinaryVault** freezes existing programs. It does not stop new ones.
* **PheonixBox** heals after the fact. It does not block.
* **BiosGuard** only detects. It never writes firmware.
* **Command blacklist** is a deny list for non-sudo users: a changed copy
  or an interpreter gets around it.
* **RAM-spike drop** is not a defence against memory exhaustion.
* **The lock (#16)** is not the kernel's lockdown LSM, though it answers the
  same check for the integrity class while engaged.
* **Encrypted OTP secret** is not TPM-sealed (yet: gap G3).
* **"sudo"** in this project means "root or a member of an admin group",
  not "authenticated through sudo".
* **NIST SP 800-53 control IDs** in SECURITY_REVIEW.md frame the review.
  They are not an assessment or a certification.
* **STIG/CIS results** show configuration conformance on Ubuntu 24.04. FIPS
  is not achievable with a self-built kernel.

## 7. Promises not yet kept (work to build)

Pheonix's rule for this project: a doc that promises more than the code is a
missing feature to build, not a sentence to delete. These were found while
writing this document. Each is tracked in [TODO.md](../TODO.md) under
"Doc promises to build".

| Gap | Promised in | What is missing | Plan |
|---|---|---|---|
| G1 | FEATURE_MAP #11 | "The daemon finds SEA binaries by their fuse marker and registers them." Nothing did. | **Built 2026-11-01:** `secure-sudo node-scan`, run by the daemon at start and every `node_sea_scan_interval` minutes; `load` sends its finds after the hand-written list. |
| G2 | FEATURE_MAP #13 | "The daemon keeps the Merkle tree over watched trees." It kept a flat SHA-256 manifest. | **Built 2026-11-01:** the manifest is a baseline taken when the vault engages; its Merkle root is logged and forwarded (baseline, load, findings, every checkpoint); the daemon puts back a rewritten manifest and `evidence-verify --timevault` flags one (SECURITY_REVIEW #60). |
| G3 | FEATURE_MAP #15 | "Sealed with TPM2 when there is one, with a root-only key file as the fallback." Only the key file exists. | Seal the OTP key with the TPM (systemd-creds or tpm2-tools) when present, key file as fallback, swtpm in the distro VM test. |
| G4 | README #5 "Block TPM clear" | Only the PPI route is blocked; `TPM2_Clear` through `/dev/tpm*` is not, and an LSM cannot read the command bytes. | Needs a decision: set a TPM lockout password at install, and/or restrict which programs may open `/dev/tpm*`. |

Built during P1-5 because the docs already promised them:

* #2 now refuses an exact copy of a blacklisted program at a new path
  (FEATURE_MAP #3 said copies were caught; they were not).
* #6 and #19 now check the module's own name, so a renamed module file, a
  compressed module and `init_module(2)` are caught (SECURITY_REVIEW #16
  implied renamed files were caught; they were not).
* #2, #3, #5, #10 and #12 denials now reach the event log, the daemon, the
  forwarder and auditd (README #9; HARDWARE_SMOKE_TEST.md §3 expected a TPM
  event that was never raised). #7 drops are logged too.
