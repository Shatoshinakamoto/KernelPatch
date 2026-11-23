<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/node_sea_binaries.conf`

Self-contained Node binaries (single-executable applications, `pkg` builds) that the child guard should treat as `node`.

## Facts

- **Feature:** #11 Node.js child guard. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/node_sea_binaries.conf` (template `userspace/config/node_sea_binaries.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/node_sea_binaries` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_node.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:256 -->
- **Limit:** 256 entries and 64 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file. The limit covers this file plus the scanned entries; `load` reports scanned entries it had to drop.
- **Security reference:** NIST SP 800-53 CM-8 (component inventory), CM-7(5).

## Format

One absolute path per line. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** Exact resolved path. `secure-sudo load` sends these first, then what `secure-sudo node-scan` found (kept apart in `/var/lib/secure_sudo/node_sea_auto.list`), up to the kernel's limit in total.

Example:

```
/opt/myapp/myapp
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load`. List only what `node-scan` cannot find (outside `node_sea_scan_dirs`, or with its markers stripped).
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

A Node runtime that is not registered here or found by the scan is not guarded: its children are not checked.

## Entries

Entries shipped in the template, with why each is there, who asked for it and when it was added. `ci/check-config-docs.py` fails when the template and this table disagree.

<!-- list-entries:begin -->
| Entry | Why it is there | Requested by | Added |
|---|---|---|---|
<!-- list-entries:end -->

The template ships with no entries (only commented examples), so nothing is registered until you add lines.

## Register convention for site entries

Put one comment line directly above each entry you add, so the file itself records why it is there, who asked and when:

```
# 2026-11-23 requested by: ops (ticket 123); approved by: host owner; why: build agent runs tests here
/opt/myapp/myapp
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
