<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/binvault_allow.conf`

Directory prefixes exempt from BinaryVault: binaries under them may still be written or updated while the vault is on.

## Facts

- **Feature:** #17 BinaryVault. Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/binvault_allow.conf` (template `userspace/config/binvault_allow.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/binvault_allow` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_binvault.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:1024 -->
- **Limit:** 1024 entries and 128 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file.
- **Security reference:** NIST SP 800-53 SI-7, CM-5.

## Format

One absolute directory path per line. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** Prefix match on a path-component boundary.

Example:

```
/opt/google/chrome
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load`. Use it only for software that rewrites its own binaries at runtime; for package updates use the maintenance-reboot procedure in [BINARYVAULT.md](../BINARYVAULT.md).
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

Every entry is a hole in the anti-tamper guarantee, for root too. Keep it as small as you can.

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
/opt/google/chrome
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
