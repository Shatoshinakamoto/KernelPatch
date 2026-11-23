<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/driver_blacklist.conf`

Kernel modules that are refused at load even if validly signed: known-vulnerable drivers used in "bring your own vulnerable driver" attacks.

## Facts

- **Feature:** #6 driver blacklist (anti-BYOVD). Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/driver_blacklist.conf` (template `userspace/config/driver_blacklist.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/driver_blacklist` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_driver.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:256 -->
- **Limit:** 256 entries and 64 KiB of text (comments count). The kernel keeps at most 256 hashes and 256 names and ignores the rest without an error; `secure-sudo lint` refuses a longer file.
- **Security reference:** NIST SP 800-53 SI-7, CM-7(4).

## Format

One entry per line: a 64-hex SHA-256 of the module's bytes (any case), or a module file basename. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** A module whose contents hash to a listed value, or whose file name matches a listed name, is refused.

Example:

```
dbutil_2_3.ko
e3f1...<64 hex>
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load`.
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

Hash entries are exact and cannot be dodged by renaming; name entries catch renamed rebuilds but can be dodged by renaming. Use both for a known driver. With `lock_modules = 1`, a locked box loads no modules at all, which is stronger.

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
dbutil_2_3.ko
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
