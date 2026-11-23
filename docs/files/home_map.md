<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/home_map.conf`

Which home directory each non-sudo user may write to when `block_home_write = 1`.

## Facts

- **Feature:** #4 home write restriction. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/home_map.conf` (template `userspace/config/home_map.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/home_map` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_home.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:4096 -->
- **Limit:** 4096 entries and 256 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file.
- **Security reference:** NIST SP 800-53 AC-3, AC-6.

## Format

One `<uid> <absolute home path>` per line. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** A non-sudo user may write under their mapped home, the built-in safe set (`/tmp`, `/var/tmp`, `/dev`, `/dev/shm`, `/run`, `/proc`, `/sys`, `/var/lock`) and `home_write_allow.conf`.

Example:

```
1000 /home/alice
1001 /home/bob
```

## Changing it safely

- `install.sh` generates it from `/etc/passwd` (UID 1000 and up with a home under `/home/`), only into the shipped, still empty file. After adding users, add their line, then `sudo secure-sudo load`.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

A user with no line can write only to the safe set. A wrong home path lets a user write into someone else's tree.

## Entries

Entries shipped in the template, with why each is there, who asked for it and when it was added. `ci/check-config-docs.py` fails when the template and this table disagree.

<!-- list-entries:begin -->
| Entry | Why it is there | Requested by | Added |
|---|---|---|---|
<!-- list-entries:end -->

The template ships with no entries; `install.sh` fills it on the host from `/etc/passwd`.

## Register convention for site entries

Put one comment line directly above each entry you add, so the file itself records why it is there, who asked and when:

```
# 2026-11-23 requested by: ops (ticket 123); approved by: host owner; why: build agent runs tests here
1000 /home/alice
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
