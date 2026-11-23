<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/prguard_allow.conf`

Programs exempt from the runtime memory guard: debuggers, profilers and JIT runtimes that need to inspect other processes or map writable-and-executable memory.

## Facts

- **Feature:** #20 process runtime guard. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/prguard_allow.conf` (template `userspace/config/prguard_allow.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/prguard_allow` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_prguard.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:1024 -->
- **Limit:** 1024 entries and 128 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file.
- **Security reference:** NIST SP 800-53 SI-16, SC-39.

## Format

One absolute executable path per line; a process is matched by the path of its main executable. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** Exact resolved path of the main executable.

Example:

```
/usr/bin/gdb
/usr/bin/strace
```

## Changing it safely

- `sudo secure-sudo prguard add PATH` and `prguard remove PATH` edit the file and push it.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

Each entry may ptrace other processes and use W+X memory, which is exactly what code injection needs. Remove debuggers from production hosts' lists.

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
/usr/bin/gdb
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
