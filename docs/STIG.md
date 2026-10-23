# secure_sudo — STIG / OpenSCAP compliance

This document covers the DISA STIG (Security Technical Implementation Guide)
tooling shipped with secure_sudo: what was actually run, the real results, how
the kernel LSM maps onto STIG control families, and exactly which controls can
and cannot be automated.

STIG is DISA's "military-grade" configuration baseline. secure_sudo does **not**
claim blanket STIG compliance — it ships the scanner, a remediation driver, and
an honest control map, and it tells you precisely what remains manual.

---

## 1. What was run, and the honest scope

The scan below was run **inside the build/development container** (Ubuntu
24.04.5 LTS), not on a hardened target host. That matters, so it is stated up
front:

* A container shares the host kernel and has no bootloader, no separate
  partitions, no systemd in the usual sense, and a reduced service set. So
  STIG rules about disk encryption, GRUB, kernel boot flags, auditd and many
  services come back **notapplicable** here that **are** applicable on a real
  install. The container numbers are therefore a *floor*, useful to prove the
  tooling works and to catch config-file/PAM/permission findings — not a
  substitute for scanning the actual target.
* `scripts/stig-harden.sh` is designed to be run **on the target host** (the
  installer can invoke it; see §4). That is where the real, complete STIG
  result comes from.

Tooling used: OpenSCAP `oscap` 1.3.9 + SCAP Security Guide (SSG) 0.1.78, which
provides the profile **"Canonical Ubuntu 24.04 LTS Security Technical
Implementation Guide (STIG) V1R1"**
(`xccdf_org.ssgproject.content_profile_stig`).

### Results (this container, Ubuntu 24.04 STIG V1R1)

| Pass | Result |
|------|--------|
| Baseline scan | **25 pass / 24 fail** (178 notapplicable, 3 notchecked) |
| After `stig-harden.sh --remediate` + follow-up fixes | **61 pass / 1 fail** (164 notapplicable, 3 notchecked, 1 error) |

The raw reports are in `docs/stig/results/`:

* `01-baseline-eval.txt`, `01-baseline-report.html` — before remediation.
* `02-after-remediation-eval.txt`, `02-after-remediation-report.html` — after.

### What the remediation fixed (examples, container)

Password policy (max/min age, hashing rounds, pwquality), account lockout
(`pam_faillock` deny/interval/unlock/audit/silent), failed-logon delay,
last-logon display, default umask in `login.defs`, `/var/log` ownership and log
file permissions, the DoD login banner, removal of unauthenticated APT repos,
and the required PAM/SSSD packages — all moved from **fail** to **pass**.

### What remains after remediation, and why (honest)

After the remediation pass and the follow-up fixes, the only items not at
**pass** are ones that **cannot** be satisfied inside a container — each is
documented with the manual step that makes it pass on a real target host:

| Control | State here | Why | Manual step on target |
|---------|-----------|-----|------------------------|
| Encrypt Partitions | `fail` | A container has no partitions to encrypt | Install with LUKS full-disk encryption (the `install/encrypted/` variant already uses age+tmpfs+MOK; pair it with LUKS on the root FS). |
| AppArmor Active and Configured | `error` | No init / AppArmor to query in the container | Active by default on a real Ubuntu install; `aa-status` verifies. |
| Assign Expiration Date to Temporary Accounts | `notchecked` | Manual-review control, site policy | Set expiry per your account policy. |
| Ensure sudo group has only necessary members | `notchecked` | Manual-review control, site policy | Audit the `sudo` group; secure_sudo's `admin_gid` also restricts who counts as sudo. |
| Only Allow DoD PKI-established CAs | `notchecked` | Needs real DoD PKI/CAC infrastructure | Install your DoD CA bundle and configure PKI trust. |

(The SSSD certificate-mapping, log-permission and all password/lockout/banner
findings that failed at baseline now **pass** — SSSD cert mapping was fixed by
setting `ldap_user_certificate` in `sssd.conf`.)

---

## 2. How secure_sudo's LSM maps onto STIG control families

STIG is mostly *userspace configuration* (PAM, auditd, file permissions),
which the scanner remediates. secure_sudo's **kernel LSM** complements that by
enforcing, in-kernel, several control families that a config file alone cannot
guarantee (a config can be edited back; a locked LSM cannot). This is the
"defense in depth" STIG expects.

| STIG control family (SRG/CCI theme) | secure_sudo mechanism |
|-------------------------------------|------------------------|
| **Least privilege / privilege escalation** (SRG-OS-000324, CCI-002235 "non-privileged users prevented from executing privileged functions") | #1 block non-sudo setuid/setgid/setgroups + userns; #1b block non-sudo exec of setuid/file-cap binaries; `admin_gid` defines who is privileged. |
| **Software integrity / only authorised code runs** (SRG-OS-000480, CCI-001749 signed/verified software; execution control) | #17 **BinaryVault** freezes all executables + libraries (anti-tamper); #2 command blacklist; #6 driver/BYOVD hash blacklist (hashes the *loaded* bytes); #12 no-exec from tmp/tmpfs/memfd; #13 TimeVault exec allowlist; module signature enforcement (`module.sig_enforce=1`). |
| **Information at rest / anti-persistence** (SRG-OS-000433 protect integrity of the OS) | #17 BinaryVault (no on-disk code change survives a reboot); #16 one-way config lock (also blocks module/kexec/hibernate/dev-mem loads while locked). |
| **Session / brute-force protection** (SRG-OS-000021, CCI-000044 account lockout) | #8 sudo brute-force cooldown (kernel-enforced, fed by `pam_secure_sudo`) complements `pam_faillock`. |
| **Boundary / least functionality — network** (SRG-OS-000480; CCI-000382 prohibit unauthorised ports/protocols) | #10 host mode denies raw/AF_PACKET sockets in-kernel; daemon nftables for lan/public modes. |
| **Audit / accountability** (SRG-OS-000037, CCI-000130 audit records) | #9 in-kernel event ring drained to rotated logs by the daemon; control-char-scrubbed (no log injection). |
| **Firmware / hardware integrity** | #3 block non-sudo firmware/flash/raw-mem; #5 block TPM clear (boot-param gated). |
| **Multifactor for privileged access** (SRG-OS-000105, CCI-000765 MFA) | #14/#15 rotating OTP (TOTP) PAM helper for sudo. |

The authoritative, machine-checkable mapping is the SSG XCCDF itself (each rule
carries its CCI/SRG references); the table above is the LSM's contribution on
top of the scanner's userspace coverage.

---

## 3. Running a scan / remediation yourself

Use `scripts/stig-harden.sh` (installed to
`/usr/libexec/secure-sudo/stig-harden.sh`). It auto-detects the distro,
installs `oscap` + SSG if missing, and picks the DISA STIG profile — falling
back to the strongest baseline the distro actually ships (CIS Level 2, then
ANSSI high) when no STIG profile exists for it. Reports land, timestamped, in
`/var/log/secure_sudo/stig/`. See [SCRIPTS.md](SCRIPTS.md#stig-harden) for
every flag.

```sh
# Scan only (safe, read-only) — do this first and read the report:
sudo /usr/libexec/secure-sudo/stig-harden.sh --scan

# See which profiles your distro's content offers:
sudo /usr/libexec/secure-sudo/stig-harden.sh --list-profiles

# Scan, apply the generated fixes, then re-scan (maintenance window!):
sudo /usr/libexec/secure-sudo/stig-harden.sh --remediate
```

**STIG profile availability by distro** (SSG 0.1.78): RHEL 8/9/10, Oracle
Linux 9, SLE 15, Ubuntu 20.04/22.04/24.04 ship a real DISA STIG profile.
Debian, Fedora, AlmaLinux and openSUSE do not — there the script uses CIS L2 /
ANSSI high and says so in its output.

---

## 4. Running it from the installer

`install/install.sh` honours a `STIG` environment variable (default: skip):

```sh
sudo STIG=scan       ./install/install.sh    # scan after install, write reports
sudo STIG=remediate  ./install/install.sh    # scan + apply + re-scan
```

It is opt-in on purpose: STIG remediation rewrites PAM, password, banner and
audit policy, so it should be a deliberate choice made in a maintenance window
with a root shell open, not a silent side effect of installing the kernel.
