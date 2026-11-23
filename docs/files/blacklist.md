<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/blacklist.conf`

Programs that non-sudo users may not run. Sudo users are not affected.

## Facts

- **Feature:** #2 command blacklist. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/blacklist.conf` (template `userspace/config/blacklist.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/blacklist` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_exec.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:1024 -->
- **Limit:** 1024 entries and 256 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file.
- **Security reference:** NIST SP 800-53 CM-7(4) (unauthorized software, deny-by-exception).

## Format

One absolute path per line. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** At load the kernel resolves each path and records its device, inode and inode generation, so renaming the binary, or reusing the inode, is still caught. It also matches the canonical path at exec, so a replacement file dropped at the same path is caught too.

Example:

```
/usr/bin/nc
/usr/bin/tcpdump
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load`.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

A denylist: it stops casual use of listed tools but cannot stop a user who brings their own copy under another path (combine with `block_tmp_exec`, `block_home_write` or TimeVault for that). An entry that is missing is simply allowed.

## Entries

Entries shipped in the template, with why each is there, who asked for it and when it was added. `ci/check-config-docs.py` fails when the template and this table disagree.

<!-- list-entries:begin -->
| Entry | Why it is there | Requested by | Added |
|---|---|---|---|
<!-- list-entries:end -->

The template ships with no entries (only commented examples), so nothing is denied until you add lines.

## Register convention for site entries

Put one comment line directly above each entry you add, so the file itself records why it is there, who asked and when:

```
# 2026-11-23 requested by: ops (ticket 123); approved by: host owner; why: build agent runs tests here
/usr/bin/nc
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
