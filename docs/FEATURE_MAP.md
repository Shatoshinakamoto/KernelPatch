# secure_sudo: merged feature map (step 1)

Written 2026-10-23. Sources: `Kernel/secure_sudo.c` (v1, the same file as `KernelNew/`), `Kernel/v2/secure_sudo_v2.0.c` + `Readme.md` (v2), `Kernel/v2/new.md` (the v2 add-on: Merkle tree, quarantine, BPF UI), `KernelNew/otp-generator` (the same as `OTP test/otp-generator`), `OTP Test C++/TODO.md`, the root `TODO.md` (the same as `Kernel/TODO.md`), the README, `secure_kernel_build.sh` and `secure_kernel_deploy.yml`.

`pheonix-cli` and `node-pkg-plugin` are separate Node products. They stay as they are and aren't merged into the kernel patch. The Node guard below is written so it also covers their SEA binaries.

## The short version

- **v2 dropped the most important v1 protection.** The UID/GID switch block (`task_fix_setuid`) only exists in v1. v2 also lost the command blacklist (its loop body is empty) and the GPU/BIOS flash checks. All three come back in the merge.
- **Neither version runs today.** v1 never registers its hooks. v2 calls APIs that were removed from the kernel: `set_fs`/`get_fs` (removed in 5.10), `nf_register_hook` (removed in 4.13), and the `task_create`/`module_permission` LSM hooks (these don't exist). It assigns `current->security` directly, takes a mutex inside a netfilter hook (that crashes in softirq context), and writes a log file once per packet. `security_add_hooks` also can't be called from a loadable module, so the merged LSM is compiled into the kernel, which matches the plan.
- **The OTP generator works, with one dangerous gap.** When it's built without OpenCV, its QR fallback tells the user to paste the `otpauth://` URI, secret included, into third-party websites. The merge replaces that with local `libqrencode` output.

## Where each feature goes

K = in-kernel LSM `security/secure_sudo/` (built-in, `CONFIG_SECURITY_SECURE_SUDO`). U = userspace (`secure-sudod` daemon, `secure-sudo` CLI, PAM modules). Every U command checks for root/sudo before it does anything.

| # | Feature | Where it exists now | Status | Merged home | What changes |
|---|---|---|---|---|---|
| 1 | **Block non-sudo UID/GID switching** | v1 only | Logic is fine, hook never registered, v2 dropped it | K | `task_fix_setuid` + `task_fix_setgid` + `task_fix_setgroups`. "Sudo user" means root, or a member of a configurable admin GID (sudo/wheel). Also gate unprivileged user namespaces (`userns_create`), since those are the usual way around UID checks. |
| 2 | Block GPU / motherboard flashing | v1 stubs | Never called | K | Deny non-sudo opens of `/dev/mem`, `/dev/port`, `/dev/mtd*`, `/dev/mei*`, and writes to efivars/firmware sysfs (`file_open`). The installer also enables kernel lockdown (integrity). |
| 3 | Command blacklist | v1 (kernel parses the file), v2 empty | v1 truncates at 4 KB and matches by basename | K + U | The CLI loads `/etc/secure_sudo/blacklist.conf` into securityfs. The kernel matches by inode + path rather than basename, so copying or renaming a binary doesn't get around it. |
| 4 | Home-directory restriction | v1, v2 | v1 uses an uninitialised username. v2 uses `/home/<uid>`, which matches no real home and denies exec of every system binary | K | Write-only restriction outside home + configured allow paths. Off by default. Exec control lives in #12. |
| 5 | **Block TPM clear** (`echo 5 > .../tpm0/ppi/request`) | TODO only | Missing | K | Deny writes to `tpm*/ppi/request` for everyone, root included. It's unlocked only by the boot parameter `secure_sudo.tpm_maint=1`. |
| 6 | Driver blacklist (BYOVD) | v2 | Uses a hook that doesn't exist | K + U | `kernel_read_file`/`kernel_load_data` (module), matched by name and SHA-256. The installer enforces module signing for real: the playbook's `options module.sig_enforce=1` in modprobe.d does nothing, so it becomes a kernel parameter. |
| 7 | RAM spike → drop caches | v2 | Uses `set_fs`. Counts page cache as "used", so it would fire constantly | K | The kernel worker calls the drop-cache routine directly, so there's no process or command anyone could run or hijack, which is the "private field" requirement. It measures with `si_mem_available()`, and the threshold and interval are configurable. |
| 8 | Sudo brute-force cooldown + kill offender | v2 table | Nothing records a failure (exec can't see whether a password was wrong) | U + K | A `pam_secure_sudo` module in the sudo/su auth stack reports failures. After N failures in the window, the kernel blocks sudo/su exec for that UID and the daemon freezes and kills the offending process tree (the `SIGSTOP` then `SIGKILL` the TODO asks for). |
| 9 | Logging with dates + retention | v2 | Writes files from kernel context (that recurses and crashes in netfilter) | K + U | The kernel emits events to a securityfs ring. The daemon writes `/var/log/secure_sudo/YYYY-MM-DD.log` with a wall-clock timestamp, enforces `retain_days` + `max_total_mb`, and can forward to a remote syslog (TimeVault needs that). |
| 10 | Network modes: monitor / host / LAN-only / public-only | v2 netfilter | Removed API, sleeps in softirq | U + K | The daemon detects LAN/router subnets and writes one `nft` table `secure_sudo`, deleting it on every mode change. Host mode also has the kernel deny `AF_PACKET`/raw sockets (`socket_create`), so pcap sniffing fails even if libpcap is installed. |
| 11 | NodeJS child-process guard (binaries + scripts) | v2 | Writes `current->security` directly | K | A task blob marks processes whose exe is `node`/`nodejs` or a registered SEA/pkg binary. Their children's exec has to be on `node_allowed_children`. The daemon finds SEA binaries by their fuse marker and registers them. |
| 12 | Restrict exec from `/tmp`, `/var/tmp`, `/dev/shm` | v2 design table only | Missing | K | Deny exec and `PROT_EXEC` mmap from those trees unless they're allowlisted (`bprm_check_security`, `mmap_file`). |
| 13 | **TimeVault** lockdown | v2 basename whitelist, new.md Merkle + in-kernel zlib + BPF | Design only | K + U | K: an exec allowlist (path + hash) while the vault is on, with package managers (apt, dpkg, dnf, yum, rpm, zypper, pacman, snap, flatpak) forced to deny, and a count of every denied attempt. U: the daemon keeps the Merkle tree over watched trees, moves new or changed files to `/var/lib/secure_sudo/quarantine/*.zip` with their metadata, and ships logs off-box. The BPF status map becomes a plain `secure-sudo status`. |
| 14 | **OTP rotating sudo password** (`prefix + 6-digit code`) | otp-generator CLI | TOTP works, no PAM, no prefix, no reset | U | `pam_secure_otp` checks `prefix$code`. The CLI covers `otp setup / show-qr / show-key / verify / reset / disable`. `show-qr` writes a root-only PNG and prints its `file://` URL. |
| 15 | Encrypted at-rest OTP secret + prefix, held privately at runtime | otp-generator (triple AES-CBC) | Works, but all three layers come from the same password | U | Sealed with TPM2 when there is one, with a root-only key file as the fallback. Single AES-256-GCM. At runtime the secret lives in `mlock`ed memory that's wiped after use. The prefix is stored as a yescrypt hash, which is stronger than decryptable storage because it never has to be decrypted. |
| 16 | Lock config after boot | not present | Root can currently rewrite every knob | K | A one-way `lock` switch. Once it's set, config only changes after a reboot. TimeVault sets it automatically. |
| 17 | Per-distro install, single script + YAML | build.sh, deploy.yml | Bugs listed below | U | One `install.sh` + one playbook, covering the Debian/Ubuntu, Fedora/RHEL, Arch and openSUSE families and detecting derivatives through `ID_LIKE`. |
| 18 | Encrypted kernel install variant | TODO, README | Missing | U | `install-encrypted.sh` + `deploy-encrypted.yml`. The source bundle is encrypted (age) and decrypted into tmpfs for the build. The kernel and module are signed with an enrolled MOK for Secure Boot, and the install is optionally a signed UKI. |

## Install script and playbook bugs that get fixed along the way

- The `linux-5.15.0.tar.xz` URL doesn't exist on kernel.org, and the merge targets a newer kernel anyway.
- `sed` into `security_init()` is not how an LSM gets registered. The merge uses `DEFINE_LSM` + Kconfig + `CONFIG_LSM`.
- The build runs in world-writable `/tmp`, which another local user could tamper with. It moves to a root-owned dir.
- The playbook handler `command: echo 1 > /sys/...` never redirects, because `command` doesn't use a shell.
- `MODULE_LICENSE("GPL-v3")` / `"GPL-v2"` aren't valid strings. It has to be `"GPL"`, or the kernel taints and refuses GPL-only symbols.
- `make install` with no uninstall path. The merge builds a distro package instead (`bindeb-pkg`, `binrpm-pkg`, or a PKGBUILD), so the kernel can be removed cleanly and the old one stays in the boot menu.

## Defaults I'm using (tell me if you want any different)

1. **Kernel target: 6.12 LTS.** It's the current long-term branch, and it builds on every distro family above.
2. **TimeVault quarantines new files instead of wiping them.** The TODO says "wipe", but a wipe can't be undone and destroys the evidence. `vault_action=wipe` stays available as a setting.
3. **Recovery path.** Root on the local console can always fall back to the normal password, so a lost phone can't lock the box out.
