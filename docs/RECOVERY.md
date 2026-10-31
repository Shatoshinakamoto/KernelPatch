# secure_sudo — recovery

How to get a machine back when an install, an upgrade or a policy change
goes wrong (TODO P0-5, P0-6). Each section says what you see, what to do,
and whether the route has been exercised in the distro VM test
(`tests/vm/distro/run-install-test.sh`, Ubuntu 24.04 cloud image, BIOS boot,
GRUB; results in `docs/vm/results/`).

**Before any change, keep a root session open** (a console login, `ssh
root@…`, or `sudo -i` in a second terminal) and test from another terminal.
Root is always exempt from every secure_sudo protection, so that session is
your way back from every policy mistake below. The installer never edits PAM
for the same reason.

| Problem | Fastest way back | VM-tested |
|---|---|---|
| New kernel does not boot (trial) | Power-cycle; the previous kernel boots by itself | yes |
| New kernel misbehaves after `verify --commit` | `install.sh rollback`, reboot | yes |
| No running system to run that from | GRUB menu → previous kernel | no (cloud image has no menu timeout) |
| Every boot stops at a GRUB password prompt | Enter it once; then section 1, "GRUB password" | no (the cause was found and fixed in CI) |
| Secure Boot rejects the kernel | Enroll the MOK, re-run `install-kernel` | no (VM boots BIOS) |
| Package install interrupted / dpkg error | `dpkg --configure -a`, then `install.sh verify` or `install.sh uninstall` | partly (host suite) |
| Wrong `admin_gid` (sudo users lose sudo) | Root session: fix, `secure-sudo lint`, `secure-sudo load` | yes |
| Incomplete allowlist (a program stops working) | Root session: add the path, `secure-sudo load` | yes |
| PAM change breaks sudo/login | Root session: revert the line | yes |
| Lock engaged by accident | Fix the config, reboot | yes |
| No root session left at all | Previous kernel, or `lsm=` without secure_sudo, or recovery mode | no |

---

## 1. The new kernel does not boot

`install.sh install-kernel` (and `install.sh all`) leave the running kernel as
the GRUB **default** and arm the new kernel for **one** boot (`grub-reboot`).
The secure_sudo kernel is built with `CONFIG_PANIC_TIMEOUT=10`, so a panic
reboots by itself after 10 seconds.

* **Panic or failed boot during the trial:** the next boot is the previous
  kernel; nothing to do. If it hangs without panicking, power-cycle it.
  Then `install.sh verify` reports `the trial boot of … did not stay up`.
  Look at the serial console or `journalctl -k -b -1` (if it got as far as
  journald), fix, and arm a new trial with `install.sh install-kernel`.
* **Trouble after you committed it** (`install.sh verify --commit` made it the
  default): from the running system, `install.sh rollback` boots the previous
  kernel once; `install.sh rollback --default` makes it the default again.
* **Cannot get to a running system:** pick the previous kernel in the GRUB
  menu (the installer lists every kernel at the top level; without its
  drop-in, Ubuntu keeps them under *Advanced options*). To see the menu,
  hold `Shift` (BIOS) or tap `Esc` (UEFI) while booting; on images with
  `GRUB_TIMEOUT=0` use the serial or hypervisor console. If GRUB itself is broken, boot rescue media, chroot into
  the root file system and run `update-grub`.
* **GRUB password: every boot waits at a prompt.** With a GRUB superuser
  (STIG `grub2_password`), any entry or submenu without `--unrestricted`
  needs the password to boot. `install.sh verify` reports it (`saved_entry
  needs it to boot`). Enter the password at the console once, then:
  1. give the entries `--unrestricted` (on Debian/Ubuntu, add it to `CLASS`
     in `/etc/grub.d/10_linux`);
  2. run `install.sh install-kernel` again with the current installer, which
     rewrites `/etc/default/grub.d/99-secure-sudo.cfg` with
     `GRUB_DISABLE_SUBMENU=true` (Ubuntu's *Advanced options* submenu is
     never `--unrestricted`); or add that line yourself, run `update-grub`
     and `grub-set-default gnulinux-<release>-advanced-<uuid>` (the id from
     `grep -o "gnulinux-[^']*-advanced-[^']*" /boot/grub/grub.cfg`);
  3. `install.sh verify` shows `saved_entry boots without it`.
* **Trial boot was not available** (preflight said so: not GRUB, or
  `GRUB_DEFAULT` is not `saved` on a non-Debian system, or `SS_TRIAL_BOOT=0`):
  the new kernel is the default; use the menu as above.

`install.sh` stops instead of continuing if `update-grub`/`grub2-mkconfig`
fails. `grub-mkconfig` only replaces `grub.cfg` after it has generated a
complete one, so the old menu stays in place; fix the reported error and run
`update-grub` again. Install also stops if the regenerated menu lacks either
the new kernel or the running one: **do not reboot** in that state, run
`update-grub` and check `grep vmlinuz /boot/grub/grub.cfg`.

## 2. Secure Boot rejects the kernel or the MOK enrollment failed

A self-built kernel is not signed by a key that shim trusts. Preflight blocks
`install-kernel` while Secure Boot is on unless `SS_SB_KEY` and `SS_SB_CERT`
name an **enrolled** Machine Owner Key; install then signs the image with
`sbsign` and checks it with `sbverify`.

* Symptom: GRUB/shim prints `bad shim signature` or `Verification failed`
  and returns; during a trial boot the next boot is the previous kernel.
* Enroll the key: `mokutil --import "$SS_SB_CERT"` (sets a one-time
  password), reboot, choose *Enroll MOK* in MokManager, enter the password.
  If MokManager timed out or the enrollment was skipped, run `mokutil
  --import` again. Check with `mokutil --test-key "$SS_SB_CERT"` (`is already
  enrolled`), then re-run `install.sh install-kernel` so the image is signed.
* `install.sh verify` checks the image signature (`sbverify --list`) and fails
  when Secure Boot is on and the image is unsigned.

Not tested in the VM (it boots with SeaBIOS); the preflight and state logic
are covered by `tests/install/test-install.sh` with simulated efivars.

## 3. An interrupted or failed package install

The install record (`/var/lib/secure_sudo/install/manifest`) is written
atomically after every step, and the kernel package name is recorded
*before* `dpkg`/`rpm` runs, so a half-done install can always be finished or
removed.

* Debian/Ubuntu: `dpkg --configure -a`, then `install.sh verify`. To back
  out instead: `install.sh uninstall` (the running kernel is never touched).
* Fedora/openSUSE: `rpm -q kernel` / `dnf history`, then `install.sh verify`
  or `install.sh uninstall`.
* Userspace: `install.sh userspace` can simply be run again (it is
  idempotent and keeps your configuration), or `install.sh uninstall`.
  Files that already existed were backed up before being replaced and are
  restored by uninstall.

## 4. Policy lockout

Protections apply to non-sudo users; root (real or effective UID 0) is always
exempt. Run `secure-sudo lint` before every `secure-sudo load`: `load` runs
the same checks and refuses to apply a configuration with errors (`load
--force` overrides, and then reports every setting the kernel rejected).

### 4a. Wrong `admin_gid` — sudo users lose sudo

With `block_setid_exec = 1`, a user outside `admin_gid` cannot execute
setuid programs, `sudo` included (`sudo: … Operation not permitted`).
`secure-sudo lint` reports a GID that does not exist, a group with no
members, and an `admin_gid` that does not cover the admin running it.

From the root session: `secure-sudo detect-admins`, fix `admin_gid` in
`/etc/secure_sudo/secure-sudo.conf`, `secure-sudo lint`, `secure-sudo load`.

### 4b. Incomplete allowlist — a program stops working

`setid_exec_allow`, `tmp_exec_allow`, the TimeVault allowlist and the other
lists only allow what they list. Add the missing path to the list file in
`/etc/secure_sudo/`, then `secure-sudo load`. If TimeVault is engaged it has
latched the lock (section 4d); TimeVault's engage flag is not persisted, so
a reboot brings the box up with the vault off.

### 4c. A PAM change breaks sudo or login

Example: `auth required pam_secure_otp.so` added before `secure-sudo otp
setup` — every sudo then fails. `secure-sudo lint` reports it (`no OTP is set
up`, wrong order, missing module, `[default=die]` on a verifier).

From the root session that you kept open, take the line out again; PAM reads
its files on every authentication, so the fix is immediate. Without a root
session, a different kernel does not help (PAM is userspace): use the GRUB
*recovery mode* entry (root shell), or edit the GRUB entry (`e`) and boot with
`init=/bin/bash`, or rescue media.

### 4d. The one-way lock engaged by accident

`secure-sudo lock` (and engaging TimeVault) freezes every kernel setting and
list until reboot: `load` reports each rejected setting and ends with `load
INCOMPLETE`, `lint` reports `locked until reboot`, and writing `0` to `lock`
is refused. The configuration file can still be edited by root. Fix the file,
then reboot; `secure-sudo load` runs at boot (in `secure-sudod.service`) and
applies the fixed configuration.

### 4e. No root session left at all

1. Boot the previous kernel (section 1): no secure_sudo LSM, so nothing is
   enforced; fix the configuration, reboot into secure_sudo.
2. Or edit the GRUB entry (`e`) and add `lsm=` with the list from
   `/proc/cmdline`/`CONFIG_LSM` minus `secure_sudo`, e.g.
   `lsm=landlock,lockdown,yama,integrity,apparmor`. The kernel then starts
   without secure_sudo. (This is also why GRUB must be password-protected on
   a hardened box: the STIG profile's `grub2_password` rule.)
3. Or recovery mode / `init=/bin/bash` / rescue media as in 4c.

## 5. Rollback and removal

1. `install.sh rollback` (next boot only) or `install.sh rollback --default`,
   then reboot into the previous kernel. Uninstall refuses to remove the
   kernel you are running.
2. `install.sh uninstall`. It refuses while any `/etc/pam.d` file still uses
   `pam_secure_sudo.so` or `pam_secure_otp.so` (removing them would break
   that PAM stack); take the lines out yourself, or pass
   `--remove-pam-lines` (copies of the old files go to
   `/var/backups/secure_sudo-pam-<time>/`).
3. It removes only what the install record lists, and only if unchanged:
   files you edited are kept and listed, files it replaced are restored,
   directories it created are removed when empty, the GRUB drop-in and the
   saved/one-shot GRUB entries are cleared, the kernel packages are purged
   and the menu is regenerated. `--purge` also deletes `/etc/secure_sudo` and
   `/var/log/secure_sudo`. TimeVault quarantine (`/var/lib/secure_sudo/
   quarantine`) is evidence and is always kept. Distro runtime packages
   (libqrencode, nftables, zip, unzip) are left installed.
4. When something was kept the record stays, so `install.sh uninstall` can be
   run again after you deal with it.

The VM test checks that after rollback + uninstall + reboot every file under
the directories install.sh touches is byte-identical to the fresh image,
apart from the files of those runtime packages.
