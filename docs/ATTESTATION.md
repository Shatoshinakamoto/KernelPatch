# Remote attestation and measured boot (TODO P2-1)

This page explains how an operator on another machine can check that a
secure_sudo host booted the expected boot chain and is running an allowed
policy. It covers enrollment, what the verifier trusts, revocation, recovery
after updates, and what is still missing.

## Pieces

| Piece | Where it runs | What it does |
|---|---|---|
| `secure-sudo-attest` (`/usr/libexec/secure-sudo/`) | host, as root | Talks to the TPM through tpm2-tss. Recreates the attestation key (AK) and signs a TPM2_Quote over the boot PCRs. It cannot extend, clear, or write NV, and it holds no stored key material. |
| `attest-report.sh` (`/usr/libexec/secure-sudo/`) | host, as root | Builds the host report, asks the tool to sign it, and prints the bundle. |
| `secure-sudo attest ...` | host, as root | The front end: `attest quote --nonce HEX [--pcrs L]`, `attest ak`, `attest digest`. |
| `secure-sudo-attest-verify` (`/usr/bin/`) | **verifier** (any machine you trust) | Needs only python3 and the `openssl` command. No TPM and no secure_sudo install. Generates nonces, enrolls hosts, and verifies bundles. |

Because `secure-sudo-attest` is in the kernel's default `tpm_openers` list
(G4), it keeps working after `secure-sudo lock`. See CONFIGURATION.md.

## The attestation key

The AK is a **restricted ECC P-256 signing primary key in the owner
hierarchy**, created from a fixed template (`unique.x` = `secure_sudo
attestation key v1`). A primary key is derived from the TPM's owner seed, so
on a given TPM the same template always gives the same key. Nothing is
stored on disk, and there is nothing for root to steal and replay elsewhere:
the private part never leaves the TPM. Because the key is *restricted*, the
TPM will only use it to sign data the TPM itself generated (quotes). It
cannot be made to sign a forged quote.

The AK changes only when the owner seed changes, which happens on
`TPM2_Clear`. While the policy is locked, the G4 guard refuses `tpm2_clear`
from userspace. A clear through the firmware menu still changes the AK, and
the verifier then reports that the AK does not match, which is the intended
result.

If the owner hierarchy has an auth value, put it in a root-only file and
point `SS_ATTEST_OWNER_AUTH_FILE` at it.

## Which PCRs mean what

The default quote covers PCRs `0,1,2,3,4,5,7,8,9`. Use `--pcrs` to choose
others. On enrollment the verifier records whatever set was quoted.

| PCR | Measured by | Covers |
|---|---|---|
| 0 | firmware | Firmware code (BIOS/UEFI image). Changes on a firmware update. |
| 1 | firmware | Firmware configuration (setup settings, boot order on some machines). |
| 2 | firmware | Option ROMs and UEFI drivers from add-in cards. |
| 3 | firmware | Option ROM configuration. |
| 4 | firmware | Boot loader and the EFI applications it starts (shim, GRUB, systemd-boot, UKI). |
| 5 | firmware | GPT/partition table, boot variables. |
| 7 | firmware | **Secure Boot state and policy**: PK/KEK/db/dbx, and which db entries authorised the boot. |
| 8 | GRUB / sd-boot | Kernel command line and GRUB commands. |
| 9 | GRUB / sd-boot / kernel | Kernel and initramfs images that were read. |
| 11 | systemd-stub | UKI sections (kernel, initrd, cmdline) on a measured UKI boot. Add it with `--pcrs` if you boot UKIs. |
| 15 | systemd | Machine id and the root filesystem volume key, on systems that use it. |

So the default set answers "same firmware, same Secure Boot keys, same boot
loader, same kernel, same initramfs, same command line". The exact contents
depend on the firmware and boot loader. That is why enrollment records the
values from a trusted boot rather than computing them.

## Enrollment (trust on first use)

Do this on a boot you trust, for example straight after provisioning from
known media, before the host is reachable by anyone else:

```sh
# on the verifier
N=$(secure-sudo-attest-verify nonce)
# on the host
sudo secure-sudo attest quote --nonce "$N" > bundle.json
# copy bundle.json to the verifier, then
secure-sudo-attest-verify enroll bundle.json --nonce "$N" --out hosts/web1.json --require-lock
```

The host record (`hosts/web1.json`) holds the AK public key and name, the
"golden" PCR values, the allowed policy digests, whether the policy must be
locked, and the kernel and Secure Boot state at enrollment. To allow more
policy versions, use `--allow-policy SHA256` (repeatable). `secure-sudo
attest digest` prints the digest of the policy that is currently loaded.

**Verifier trust.** Enrollment is trust on first use. The verifier trusts
that the AK it sees at enrollment belongs to the host's real TPM, because
you enrolled it at a time and place you control. It does not yet check the
TPM manufacturer's endorsement key (EK) certificate or run credential
activation (MakeCredential/ActivateCredential) to bind the AK to that EK
cryptographically. That is listed under "Not done yet" below. Until then,
protect the enrollment step the way you protect SSH host-key enrollment.

Keep the host records on the verifier and not on the host. They are not
secret, but they are the trust anchor: anyone who can edit them can change
what counts as "good".

## Verifying

```sh
N=$(secure-sudo-attest-verify nonce)
ssh web1 sudo secure-sudo attest quote --nonce "$N" > bundle.json
secure-sudo-attest-verify verify bundle.json --host hosts/web1.json --nonce "$N" --max-age 300
```

Each check prints `PASS` or `FAIL`, and the exit status is 0 only if all of
them pass. Use `--json` for machine output. The checks are:

1. The bundle is well formed, and its AK name matches the host record.
2. The signature verifies with the enrolled AK, and the quote is a genuine
   TPM-generated `TPM_ST_ATTEST_QUOTE`. The verifier checks the signer
   against the AK's qualified name.
3. The quote's `extraData` equals `sha256(nonce || report)`. A fresh nonce
   proves the bundle is fresh, and the hash binds the report to the quote:
   changing any byte of the report breaks it.
4. The PCR digest in the quote equals the sha256 of the reported PCR values,
   so the values shown are the values that were signed.
5. The boot chain matches the enrolled one. On a mismatch the failing PCRs
   are named.
6. The report says the secure_sudo LSM is active.
7. The reported policy digest is one of the allowed ones.
8. The policy is locked, if the record requires it.
9. The report is no older than `--max-age` seconds, if `--max-age` is given.

**What a pass proves.** This TPM, with the enrolled key, signed PCR values
equal to the enrolled boot chain, for your nonce, together with this exact
report. Root on the host cannot fake checks 1–5: that needs the AK private
key, which only the TPM has, and PCRs can only be extended, never set.

**What it does not prove yet.** Checks 6–8 come from the report, which
`attest-report.sh` builds as root (`"policy_source": "reported"`). A
root-level attacker who has already compromised the running system could
report the expected digest. Part 2 below closes this gap by having the
kernel measure the policy into a PCR. Until then, read checks 6–8 as "the
host claims", and checks 1–5 as proven.

## Revocation

To revoke a host, delete its record (`hosts/web1.json`) from the verifier.
After that, nothing from that TPM can verify. If the machine is
decommissioned or its TPM is suspected compromised, also clear the TPM.
That changes the owner seed, so the old AK can never be recreated.

## Recovery after updates

A firmware, boot loader, kernel, initramfs, or command-line update changes
the PCRs, and verification then fails with "PCR N differ". This is
expected. After the update has been applied and rebooted from a trusted
source, re-enroll against the existing record:

```sh
secure-sudo-attest-verify enroll bundle.json --nonce "$N" --out hosts/web1.json --previous hosts/web1.json --require-lock
```

`--previous` requires that the AK is the one already enrolled. A
re-enrollment therefore cannot quietly swap in a different TPM, and swapping
TPMs needs a deliberate new enrollment. Keep the old record if you need to
tell an expected update from an attack. The PCRs named in the failure tell
you which layer changed (see the table above).

A policy change (`secure-sudo load` with a new policy) changes only the
digest. Either re-enroll, or add the new digest with `--allow-policy`.

## Evaluation: IMA/EVM, fs-verity, dm-verity

P2-1 asked for these to be evaluated as complementary controls, not
reimplemented in each userspace monitor.

- **IMA measurement** (`ima_policy=tcb`) extends a hash of every executed
  file into PCR 10 and keeps a log in
  `/sys/kernel/security/ima/ascii_runtime_measurements`. It can be added to
  a quote with `--pcrs 0,...,10`. The verifier does not replay the IMA log
  yet, so PCR 10 can only be compared against a golden value. That rarely
  works, because PCR 10 changes with every new program run. Log replay is
  listed under "Not done yet".
- **IMA appraisal + EVM** refuse to run files whose signature or hash xattr
  is wrong. This is the right tool for "only signed executables run", and it
  overlaps with ProcGuard's allowlist (temporary/), which is a userspace
  best-effort monitor. Enabling it needs signed packages (Fedora/RHEL ship
  IMA signatures; Debian/Ubuntu do not by default) and a key in the `.ima`
  keyring. **Recommendation:** use it where the distro ships signatures, and
  keep ProcGuard as the monitor elsewhere. secure_sudo does not turn it on
  automatically, because the TODO forbids broad allowlist enforcement in
  place of testing.
- **fs-verity** gives per-file Merkle-tree integrity for read-only files.
  It suits the shipped binaries in `/usr/libexec/secure-sudo/`, which would
  let BinaryVault/TamperWatch check a root hash instead of re-hashing whole
  files. It needs ext4/f2fs/btrfs with the verity feature.
- **dm-verity** makes a whole read-only root (image-based or immutable
  distros) tamper-evident at block level. It is the strongest option, but
  it needs an image-based deployment, which this project's mutable
  multi-distro installs are not.

None of these replaces the attestation above. They answer "were the files
intact", while the quote answers "what booted".

## Not done yet

These are features the design needs. They are tracked in TODO P2-1 as
missing work, not as permanent limits:

- **Part 2: kernel policy measurement.** The LSM extends a PCR with the
  digest of every policy load, lock, and knob change, and exposes the event
  log via securityfs. The verifier replays the log against the quoted PCR,
  and the policy fields stop being "reported".
- **EK certificate and credential activation**, to replace trust on first
  use at enrollment.
- **IMA log replay** in the verifier, so PCR 10 can be checked event by
  event.
- **A TPM event-log parser** in the verifier. Today the report carries only
  the event log's sha256 (`tpm_eventlog_sha256`), not a replay of it.
