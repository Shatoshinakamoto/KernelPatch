# secure_sudo — BinaryVault (#17), in depth

BinaryVault freezes **every executable and shared library on the machine** so
that, once the box has booted, the on-disk code the kernel will run cannot be
modified — not by a user, not by a service, and not by root. It is an
anti-tamper / anti-persistence control: the single most common thing an
intruder does after gaining code execution is to make their change survive a
reboot (overwrite `/usr/bin/sshd`, swap a library under `/usr/lib`, drop a
trojaned helper into `/usr/sbin`, flip a file capability with `setcap`).
BinaryVault removes that entire class of persistence.

This document explains exactly how it works, what it does and does not cover,
how to update a vaulted machine, and every command and setting that touches it.

---

## 1. The model in one paragraph

When BinaryVault is engaged, the kernel LSM intercepts every operation that
could change an existing binary's bytes, identity, or labels and denies it.
Creating brand-new files is never blocked — only mutation of existing binaries
— so normal operation (writing logs, configs, user data) is unaffected. The
guard applies to **all UIDs including root**, because a protection root can
switch off is not a protection. The only way to legitimately change a system
binary is to reboot into a maintenance window.

## 2. What counts as a "binary"

A target is protected when it is a **regular file** and either:

* it has **any execute bit** set (`S_IXUGO`) — ELF programs and `+x` scripts; or
* it is a **shared library**: its name ends in `.so` or contains `.so.`
  (e.g. `libc.so.6`) **and** it lives under a known library tree
  (`/usr/lib`, `/lib`, `/usr/lib64`, `/usr/local/lib`, …).

Directories, device nodes, FIFOs, sockets, and plain data files are never
touched. A data file that merely happens to sit under `/usr/lib` is not frozen
unless it looks like a shared object.

## 3. The logic gate

Every write-type operation is decided by one gate, evaluated identically from
every hook. A write is denied when, and only when, **all** of these hold:

1. the feature is on — `binaryvault = 1`;
2. this boot is **not** a maintenance boot — `secure_sudo.binvault_maint` unset;
3. the target is a protected binary (section 2);
4. the target is not under an allowlisted directory (`binvault_allow.conf`).

If any one is false, the operation passes through untouched. Conditions are
checked cheapest-first, so the common "feature off" case costs a single read.

## 4. The hooks (what is actually blocked)

Every path by which an existing binary's bytes, identity, or labels could
change is covered, and each **fails closed** (an unresolvable or over-long
path is denied):

| Hook | Blocks |
|------|--------|
| `file_open` (write mode) | opening a binary for writing — covers `O_TRUNC`, `O_APPEND`, and creating over an existing binary |
| `file_truncate` | `ftruncate()` on an already-open descriptor |
| `path_unlink` | deleting a binary (first half of a delete-then-recreate swap) |
| `path_rename` | renaming a binary away, **and** renaming something else *over* an existing binary (the atomic "replace a binary" trick dpkg/rpm use) |
| `path_link` | creating a new hard link to a protected binary (so no second, unprotected name to a frozen inode can be made) |
| `path_chmod` | changing a binary's mode (e.g. stripping `+x` to dodge the classifier, or adding setuid) |
| `inode_setxattr` / `inode_removexattr` | changing a binary's extended attributes — file capabilities live in `security.capability`, IMA/EVM labels in `security.ima`/`security.evm` |

## 5. When it engages

The `binaryvault` knob defaults **off** in the kernel and is turned on by
`secure-sudo load` at every boot (the systemd unit runs `load` in its
`ExecStartPre`, before any multi-user service starts). So on a configured box
the vault is effectively engaged "from boot": there is no window between the
root filesystem mounting and the vault closing in which a service could rewrite
a binary. The knob is root-only (`0600`) and frozen once the #16 config lock
latches, so on a locked box it cannot even be toggled off until reboot.

## 6. How to update a vaulted machine

**Chosen mechanism: a maintenance reboot**, gated by the read-only boot
parameter

```
secure_sudo.binvault_maint=1
```

(modelled on the TPM-clear gate, #5). It was chosen over a "let the package
manager write" carve-out because a package-manager rule is trivially forgeable
— a process just names itself `dpkg` — whereas a boot parameter cannot be set
from a running, locked system; changing it requires editing the boot loader and
rebooting, which is itself privileged and loud.

Update procedure:

1. Reboot with `secure_sudo.binvault_maint=1` on the kernel command line (a
   GRUB one-shot via `grub-reboot` / editing the entry once is ideal).
2. During this boot the vault is open (gate condition 2 is false), so
   `apt/dnf/pacman/zypper upgrade` works normally.
3. Reboot normally. The vault closes again over the new binaries.

`secure-sudo status` shows `binvault_maint = 1` during a maintenance boot, so
you can confirm the window is open before upgrading and closed afterwards.

For software that *legitimately* rewrites its own binaries at runtime (a
browser that self-updates under `/opt`, say), add its directory to
`binvault_allow.conf` instead of opening the whole vault — but keep that list
as small as possible, since each entry is a hole in the freeze.

## 7. Commands

All are root-only and refused once the config is locked (reads still work).

```sh
# Turn the vault on / off (off only works before the config lock latches):
sudo secure-sudo set binaryvault 1
sudo secure-sudo set binaryvault 0

# See the live state, including whether this is a maintenance boot:
sudo secure-sudo status            # shows binaryvault and binvault_maint
sudo secure-sudo get binaryvault   # just this knob

# Exempt / un-exempt a self-updating directory:
sudoedit /etc/secure_sudo/binvault_allow.conf   # add an absolute dir path
sudo secure-sudo load                            # push the edited list
sudo secure-sudo list binvault_allow             # show the live exempt list
```

There is no dedicated `binvault` subcommand — BinaryVault is driven through the
standard `set` / `get` / `status` / `list` / `load` interface, like every other
knob. `secure-sudo settings` lists it alongside the rest.

## 8. Settings and files

| Thing | Where | Meaning |
|-------|-------|---------|
| `binaryvault` | `secure-sudo.conf` → `/sys/kernel/secure_sudo/binaryvault` | master on/off (0600, lock-frozen) |
| `secure_sudo.binvault_maint=1` | kernel command line | open the vault for *this* boot only (read-only `/sys/kernel/secure_sudo/binvault_maint`, mode 0400) |
| `binvault_allow.conf` | `/etc/secure_sudo/` → securityfs `binvault_allow` | absolute directory prefixes exempt from the vault |

## 9. Known limitations (honest)

These are deliberate scope boundaries, documented rather than hidden (full
second-pass review in [SECURITY_REVIEW.md](SECURITY_REVIEW.md) finding #15):

* BinaryVault freezes **existing** binaries. It does not decide whether a *new*
  program may run — that is the job of #2 (blacklist), #1b (setid-exec), #12
  (no-exec-from-tmp), and #13 (TimeVault's hash allowlist). Freezing and
  exec-control are complementary layers.
* A hard link to a no-`+x` library created **before** the vault engaged is a
  second path to the same inode. New links are blocked (`path_link`); links that
  predate boot are out of scope — use #13 TimeVault, which pins each file by
  SHA-256, to detect a library whose bytes changed.
* Mounting a fresh filesystem *over* a system directory (e.g. tmpfs over
  `/usr/bin`) does not modify the frozen files, so BinaryVault ignores it; #13
  TimeVault defeats that instead, because a binary served from the overlay will
  not match its pinned hash and is refused execution.

## 10. Relationship to TimeVault (#13)

BinaryVault and TimeVault are complementary and strongest together:

* **BinaryVault** makes existing binaries *immutable* — cheap, always-on,
  covers every binary without a list to maintain.
* **TimeVault** makes exec *allowlist-only and hash-verified* — nothing runs
  unless it is listed and its bytes match, which also catches an overlay or a
  pre-existing alternate inode that BinaryVault's file-level freeze cannot see.

On a high-assurance appliance, enable both: BinaryVault to stop tampering,
TimeVault to stop anything unapproved from executing at all.
