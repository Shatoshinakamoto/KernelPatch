<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/setid_exec_allow.conf`

With `block_setid_exec = 1`, the only setuid, setgid or file-capability programs a non-sudo user may run. Everything else that would give them a new identity or capability (su, newgrp, pkexec, mount ...) is denied.

## Facts

- **Feature:** #1b setid-exec allowlist. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/setid_exec_allow.conf` (template `userspace/config/setid_exec_allow.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/setid_exec_allow` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_creds.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:512 -->
- **Limit:** 512 entries and 64 KiB of text (comments count). The kernel refuses a longer list as a whole (`E2BIG`); `secure-sudo lint` reports it first.
- **Security reference:** NIST SP 800-53 AC-6, CM-7(5) (allow-by-exception).

## Format

One absolute path per line; the resolved path of the program must match. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** Exact match on the resolved absolute path.

Example:

```
/usr/bin/passwd
/usr/bin/sudo
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load`. Populate it **before** setting `block_setid_exec = 1`, or users lose `passwd`.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

Every entry is a program a user can use to gain privilege; list only what users need. `sudo` itself is safe to list: it still asks for authentication and the sudo cooldown (#8) applies.

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
/usr/bin/passwd
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
