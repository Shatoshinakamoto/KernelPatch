<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/node_allowed_children.conf`

The programs a Node.js (or registered single-executable) process may start. Anything else it tries to exec is denied.

## Facts

- **Feature:** #11 Node.js child guard. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/node_allowed_children.conf` (template `userspace/config/node_allowed_children.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/node_allowed_children` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_node.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:256 -->
- **Limit:** 256 entries and 64 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file.
- **Security reference:** NIST SP 800-53 CM-7(5), SC-39.

## Format

One entry per line: an absolute path, or a bare program name. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** An entry starting with `/` matches that resolved file exactly. A bare name matches the basename, so `git` allows **any** file called `git`, including one the user created. `secure-sudo lint` adds a note for each bare name.

Example:

```
/usr/bin/git
/usr/bin/sh
npm
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load`.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

This is what stops a compromised Node service from spawning a shell. Listing `sh` or `bash` largely undoes the guard; prefer absolute paths to specific tools.

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
/usr/bin/git
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
