<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->

# `/etc/secure_sudo/tpm_openers.conf`

Programs that may open `/dev/tpm0` or `/dev/tpmrm0` once the config lock (#16) is engaged. An LSM cannot read the commands sent to the TPM, so it cannot tell `TPM2_Clear` from an unseal; instead, while locked, every other program, root's `tpm2_clear` included, is refused the device.

## Facts

- **Feature:** #5 TPM device guard (gap G4). Background: [CONFIGURATION.md](../CONFIGURATION.md#policy-list-files).
- **Location:** `/etc/secure_sudo/tpm_openers.conf` (template `userspace/config/tpm_openers.conf`). Root-owned, not group- or world-writable: `secure-sudo lint` checks the owner and mode, because whoever can edit it changes the policy at the next `load` (NIST CM-5).
- **Read by:** `secure-sudo load`, which writes the whole file to `/sys/kernel/security/secure_sudo/tpm_openers` as one replacement; the kernel parses it in `kernel/security/secure_sudo/ss_tpm.c`. Once the config lock is engaged the list cannot change until reboot.
<!-- list-limit:64 -->
- **Limit:** 64 entries and 16 KiB of text (comments count). The kernel stops reading at this limit **without an error**, so extra entries would silently not apply; `secure-sudo lint` (and therefore `load`) refuses a longer file.
- **Security reference:** NIST SP 800-53 AC-6, SI-7, SC-12.

## Format

One absolute executable path per line. `#` at the start of a line is a comment; blank lines are ignored.

**Matching:** Exact path of the main executable, which must be owned by root and not group- or world-writable. The list is frozen while locked; booting with `secure_sudo.tpm_maint=1` lifts the guard for a maintenance window.

Example:

```
/usr/bin/systemd-creds
```

## Changing it safely

- Edit the file, then `sudo secure-sudo load` **before** locking. Until `load` writes it, the kernel uses the same defaults as the shipped file (`to_default` in `ss_tpm.c`).
- Run `sudo secure-sudo lint` first. It checks every line's shape and the limits, and `load` refuses to touch the kernel when lint finds an error (unless `--force`).
- `sudo secure-sudo diff` shows what `load` would change; every `load` keeps a snapshot, so `secure-sudo restore ID` undoes it.
- **Approval:** a change to this file changes security policy. On a managed host the host owner approves it, and the reason is recorded next to the entry (see the register convention below).

## Security impact

A listed program can use the TPM after the lock. `systemd-pcrextend` and `tpm2-abrmd` are left out on purpose: either lets root extend any PCR and forge the policy measurement that remote attestation relies on ([ATTESTATION.md](../ATTESTATION.md)). Add them only if you need them after the lock, and enroll such hosts with `--accept-pcr-extenders`.

## Entries

Entries shipped in the template, with why each is there, who asked for it and when it was added. `ci/check-config-docs.py` fails when the template and this table disagree.

<!-- list-entries:begin -->
| Entry | Why it is there | Requested by | Added |
|---|---|---|---|
| `/usr/bin/systemd-creds` | Unseals the OTP master key (gap G3). | TODO G4, owner's security review | 2026-11-01 (ab3a83a) |
| `/usr/bin/systemd-cryptenroll` | Enrolls TPM-bound disk unlocking. | TODO G4 | 2026-11-01 (ab3a83a) |
| `/usr/lib/systemd/systemd-cryptsetup` | Unlocks TPM-bound disks at boot. | TODO G4 | 2026-11-01 (ab3a83a) |
| `/usr/lib/systemd/systemd-pcrlock` | Manages PCR lock policies for disk unlocking. | TODO G4 | 2026-11-01 (ab3a83a) |
| `/usr/lib/systemd/systemd-tpm2-setup` | Sets up the TPM storage root key at boot. | TODO G4 | 2026-11-01 (ab3a83a) |
| `/usr/lib/systemd/systemd-measure` | Pre-calculates PCR values for signed boot policies. | TODO G4 | 2026-11-01 (ab3a83a) |
| `/usr/libexec/secure-sudo/secure-sudo-attest` | Remote attestation: reads PCRs and the EK certificate, signs quotes with its own restricted key, answers credential-activation challenges. It cannot extend, clear or write NV. | TODO P2-1 | 2026-11-01 (7781882) |
<!-- list-entries:end -->

Removed from the defaults:

| Entry | Why it was removed | Removed |
|---|---|---|
| `/usr/lib/systemd/systemd-pcrextend` | Lets root extend any PCR, so root could forge the policy measurement. | 2026-11-01 (c1d6cbe) |
| `/usr/sbin/tpm2-abrmd` | Same: a resource manager that lets root extend any PCR. | 2026-11-01 (c1d6cbe) |

## Register convention for site entries

Put one comment line directly above each entry you add, so the file itself records why it is there, who asked and when:

```
# 2026-11-23 requested by: ops (ticket 123); approved by: host owner; why: build agent runs tests here
/usr/bin/systemd-creds
```

Lint ignores comments, so this costs nothing at load, but comments count toward the text limit.
