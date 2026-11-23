<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/home_write_allow.conf`

Extra path prefixes every non-sudo user may write to when `block_home_write = 1`, on top of their home and the built-in safe set.

## Facts

- **Feature:** #4 home write restriction. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/home_write_allow.conf` (template `userspace/config/home_write_allow.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/home_write_allow` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_home.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:4096 -->
- **Limit:** 4096 entries and 256 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file.
- **Security reference:** NIST SP 800-53 AC-3, AC-6.

## Format

One absolute path prefix per line. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** Prefix match on a path-component boundary.

Example:

```
/srv/shared/
/var/www/uploads/
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load`.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

Each entry is a place every non-sudo user can write; never list a directory that holds programs or configuration something privileged reads.

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
/srv/shared/
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
