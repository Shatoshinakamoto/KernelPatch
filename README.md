# secure_sudo — merged kernel security patch + userspace + installers

A defensive Linux hardening stack built around one in-kernel LSM. It is the
reconciled merge of the project's split-up v1 module and v2 LSM designs; see
`docs/FEATURE_MAP.md` for how every feature maps from the originals, and
`kernel/security/secure_sudo/INTEGRATION.md` for the kernel wiring and the full
runtime interface.

Target kernel: **6.12 LTS**. Everything here is local; nothing is pushed.

## Layout

```
kernel/security/secure_sudo/   The LSM (built into the kernel)
userspace/
  cli/        secure-sudo         control CLI (loads policy, status, knobs)
  pam/        pam_secure_sudo.so  feeds sudo/su auth results to the kernel
              pam_secure_otp.so   verifies the rotating OTP password
  daemon/     secure-sudod        logs, cooldown kill, nft, TimeVault
  otp/        secure-sudo-otp     TOTP setup/verify, local QR, sealed secret
  config/     templates for /etc/secure_sudo/
install/
  install.sh                      per-distro build+install (Debian/Fedora/Arch/openSUSE)
  ansible/secure_sudo.yml         YAML scaffold wrapping the installer
  encrypted/install-encrypted.sh  encrypted-source + Secure Boot (MOK) variant
  encrypted/deploy-encrypted.yml  Ansible wrapper for the encrypted variant
```

## What the LSM enforces

| # | Protection |
|---|------------|
| 1 | Block non-sudo UID/GID switching (setuid/setgid/setgroups) + unprivileged userns |
| 2 | Command blacklist (matched by device+inode and path, not basename) |
| 3 | Block non-sudo firmware/flash: /dev/mem, /dev/port, /dev/mtd*, /dev/mei*, /sys/firmware writes |
| 4 | Confine non-sudo writes to home + scratch/device trees + allowlist (opt-in) |
| 5 | Block TPM clear (ppi/request) for everyone unless booted `secure_sudo.tpm_maint=1` |
| 6 | Driver blacklist / anti-BYOVD (SHA-256 + name at module load) |
| 7 | RAM-spike detection → drop caches (si_mem_available, kernel worker) |
| 8 | Sudo brute-force cooldown (PAM-fed; kernel blocks, daemon kills offender) |
| 9 | Security event ring → daemon writes dated, rotated, retained logs |
| 10 | Network host mode: deny raw/AF_PACKET sockets; nft for lan/public modes |
| 11 | NodeJS child-process guard (LSM task blob + allowlist) |
| 12 | Restrict exec/PROT_EXEC mmap from /tmp, /var/tmp, /dev/shm |
| 13 | TimeVault exec allowlist + package-manager deny + quarantine |
| 16 | One-way config lock until reboot (TimeVault latches it) |

(#4 is implemented with `file_open` + the `path_*` hooks — both source versions
had built it on a non-existent `path_permission` hook. It is opt-in because it
is aggressive.)

#14/#15 (rotating OTP sudo password with a locally-rendered QR, AES-256-GCM
sealed secret, yescrypt prefix) are in `userspace/otp` + `pam_secure_otp`.

## Install (quick)

```sh
sudo ./install/install.sh          # builds kernel 6.12 + userspace, packages it
# reboot into the new kernel, then:
sudo secure-sudo status
sudo secure-sudo load              # push /etc/secure_sudo/* into the kernel
```

PAM wiring (cooldown + OTP) is deliberately left as a reviewed manual step —
`install.sh` prints the exact lines — so a typo can't lock you out.

## Status

The kernel LSM and all userspace components are written. The CLI, daemon, both
PAM modules and the OTP helper compile cleanly; the OTP TOTP is verified against
the RFC 6238 test vectors. The kernel modules are **not yet compiled against a
real 6.12 tree** (that happens inside `install.sh`); any residual header/symbol
nits surface there.
