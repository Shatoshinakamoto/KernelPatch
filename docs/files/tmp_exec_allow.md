<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/tmp_exec_allow.conf`

Path prefixes under `/tmp`, `/var/tmp` and `/dev/shm` (and every tmpfs when `block_tmpfs_exec = 1`) from which non-sudo users may still exec or map executable code.

## Facts

- **Feature:** #12 scratch-tree exec exemptions. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/tmp_exec_allow.conf` (template `userspace/config/tmp_exec_allow.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/tmp_exec_allow` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_tmpexec.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:256 -->
- **Limit:** 256 entries and 64 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file.
- **Security reference:** NIST SP 800-53 CM-7(2) (prevent program execution).

## Format

One path prefix per line, a file or a directory. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** Prefix match on a path-component boundary: `/tmp/build` covers `/tmp/build/x` but not `/tmp/buildx`.

Example:

```
/tmp/approved-build/
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load`.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

Each entry re-opens a world-writable place for running dropped code. Prefer a dedicated directory owned by the build user over a broad prefix.

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
/tmp/approved-build/
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
