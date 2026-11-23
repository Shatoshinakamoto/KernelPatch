<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/timevault_allow.conf`

While TimeVault is engaged, the **only** programs that may run, each pinned to its SHA-256. Package managers (apt, apt-get, aptitude, dpkg, dnf, yum, rpm, zypper, pacman, snap, snapd, flatpak) are always denied while engaged, even if listed.

## Facts

- **Feature:** #13 TimeVault. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/timevault_allow.conf` (template `userspace/config/timevault_allow.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/timevault_allow` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_timevault.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:0 -->
- **Limit:** 16 MiB of text (comments count). `timevault_max_entries` path entries (default 16384, at most 131072) and 4096 `autodir` entries. The kernel refuses a longer list as a whole (`E2BIG`); `secure-sudo lint` reports it first.
- **Security reference:** NIST SP 800-53 CM-7(5), SI-7, SI-7(6).

## Format

One entry per line, three kinds:

| Line | Meaning |
|---|---|
| `/usr/bin/bash <64-hex SHA-256>` | hash-checked: the file's bytes must match at every exec |
| `/opt/app/bin/app auto` | auto-update file: runs without a hash check |
| `/opt/app/bin autodir` | auto-update directory (prefix), no hash check |

A bare path is refused: a path alone could be satisfied by a different file in another mount namespace or chroot, or by a binary swapped in place. One malformed line, or the same path twice, makes the kernel refuse the **whole** list, so a typo can never silently shrink it. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** Hash entries: the file must also be root-owned, not group- or world-writable and not open for writing, then its SHA-256 must match. `auto` and `autodir` entries are refused at exec when `timevault_allow_autoupdate = 0`.

Example:

```
/usr/bin/bash 9f2b...<64 hex>
/opt/google/chrome/chrome auto
```

## Changing it safely

- Do not write hashes by hand: `sudo secure-sudo vault-allow scan DIR...`, `vault-allow add FILE...`, `add-auto` and `add-autodir` compute and add them. Build the list **before** `secure-sudo timevault on`: engaging latches the config lock, and the list cannot change until reboot.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

Each `auto` or `autodir` entry is code that can change without the vault noticing; keep them for software that really self-updates. Engaging with an empty list is refused.

## Entries

Entries shipped in the template, with why each is there, who asked for it and when it was added. `ci/check-config-docs.py` fails when the template and this table disagree.

<!-- list-entries:begin -->
| Entry | Why it is there | Requested by | Added |
|---|---|---|---|
<!-- list-entries:end -->

The template ships with no entries (only commented examples), so nothing is exempted or allowed until you add lines.

## Register convention for site entries

Put one comment line directly above each entry you add, so the file itself records why it is there, who asked and when:

```
# 2026-11-23 requested by: ops (ticket 123); approved by: host owner; why: build agent runs tests here
/usr/bin/bash 9f2b...<64 hex>
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
