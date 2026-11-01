# Remote attestation and measured boot (TODO P2-1)

This page explains how an operator on another machine can check that a
secure_sudo host booted the expected boot chain and is running an allowed
policy. It covers enrollment, what the verifier trusts, revocation, recovery
after updates, and what is still missing.

## Pieces

| Piece | Where it runs | What it does |
|---|---|---|
| `secure-sudo-attest` (`/usr/libexec/secure-sudo/`) | host, as root | Talks to the TPM through tpm2-tss. Recreates the attestation key (AK) and signs a TPM2_Quote over the boot PCRs; recreates the endorsement key (EK), reads its certificate and answers credential-activation challenges. It cannot extend, clear, or write NV, and it holds no stored key material. |
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
| 6 | firmware | Host platform events (usually just a separator). Quoted only with an IMA log, for the `boot_aggregate` check. |
| 10 | IMA | One record per file IMA measured ("The IMA log" below). Quoted automatically when IMA is measuring; not part of the golden boot chain. |
| 11 | systemd-stub | UKI sections (kernel, initrd, cmdline) on a measured UKI boot. Add it with `--pcrs` if you boot UKIs. |
| 15 | systemd | Machine id and the root filesystem volume key, on systems that use it. |
| 13 | secure_sudo LSM | Every policy change the kernel accepted ("Policy measurement" below). Quoted automatically; not part of the golden boot chain. |

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

**Verifier trust.** Without `--ek-ca`, enrollment is trust on first use.
The verifier then trusts that the AK it sees at enrollment belongs to the
host's real TPM, because you enrolled it at a time and place you control.
Protect that step the way you protect SSH host-key enrollment. With
`--ek-ca` the verifier checks the TPM itself instead ("Endorsement key and
credential activation" below).

### Endorsement key and credential activation

Every TPM has an endorsement key (EK). The manufacturer stores a
certificate for it in TPM NV (index `0x01c00002` for the RSA 2048 EK),
signed by the manufacturer's CA. That certificate says "this key is the EK
of a genuine TPM". Credential activation then proves that the AK lives in
the same TPM.

1. The host sends its EK with the bundle (`attest quote --ek`, or `attest
   ek` on its own). The tool recreates the EK from the TCG EK Credential
   Profile's default RSA template, so it is the key the certificate is for.
2. The verifier checks that the EK uses the standard template (restricted
   decryption key, `PolicySecret(endorsement)` policy, fixedTPM), that the
   certificate is for that EK, and that the certificate chains to a CA you
   pass with `--ek-ca` (roots; repeatable) and `--ek-intermediate`
   (repeatable). Get those from the TPM vendor (Infineon, STMicro, Nuvoton,
   Intel PTT and AMD fTPM all publish them).
3. The verifier makes a challenge in software (`TPM2_MakeCredential`): a
   random secret, encrypted to the EK and bound to the AK's name. It writes
   the challenge next to the host record (`HOST.json.challenge`, or
   `--challenge FILE`). The record says `"ek_activation": "pending"` and
   holds only the secret's sha256.
4. On the host, `sudo secure-sudo attest activate CHALLENGE > response.json`
   runs `TPM2_ActivateCredential`. The TPM releases the secret only if an
   object with exactly the AK's name is loaded next to the EK that the
   challenge was encrypted to. A different TPM, or a different key, gets
   nothing.
5. `secure-sudo-attest-verify activate HOST.json --response response.json`
   checks the secret, marks the record `"ek_activation": "done"`, and drops
   the hash, so a response cannot be used twice.

```sh
N=$(secure-sudo-attest-verify nonce)
sudo secure-sudo attest quote --nonce "$N" --ek > bundle.json              # host
secure-sudo-attest-verify enroll bundle.json --nonce "$N" --out hosts/web1.json \
    --ek-ca infineon-root.pem --ek-intermediate infineon-ica.pem --require-lock
sudo secure-sudo attest activate web1.json.challenge > response.json        # host
secure-sudo-attest-verify activate hosts/web1.json --response response.json
```

Until activation is done, `verify` fails ("the attestation key is bound to
the enrolled TPM's endorsement key"). Re-enrolling with `--previous` and the
same AK keeps the binding. With `--ek-ca` again, the EK must also be the one
already enrolled. A TPM without an EK certificate (most software TPMs, some
firmware TPMs) can still be bound with `--ek-no-cert`. That proves the AK
and that EK share a TPM, but not that the TPM is genuine. Use it only when
you recorded the EK from a trusted inventory.

The challenge and response cross the network in the clear. That is safe:
only the TPM can decrypt the challenge, and the response is useless once
used.

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
   are named and, when the host was enrolled with its firmware event log,
   so is the first event that changed in each.
6. The report says the secure_sudo LSM is active.
7. The policy digest is one of the allowed ones: measured by the kernel
   (the policy-log checks below) or, on an older kernel, reported.
8. The policy is locked, if the record requires it (the lock event in the
   measured log, or the reported lock state).
9. The report is no older than `--max-age` seconds, if `--max-age` is given.
10. The firmware event log replays to the quoted PCRs, and the reported
    Secure Boot state and command line are the measured ones ("The firmware
    event log" below).
11. The IMA log replays to the quoted PCR 10, and, with a reference list,
    every measured file has a known hash ("The IMA log" below).
12. For a host enrolled with `--ek-ca` or `--ek-no-cert`, credential
    activation is done, so the AK is bound to the enrolled TPM's EK.

Lines marked `INFO` are shown for the operator and do not fail the result.

**What a pass proves.** This TPM, with the enrolled key, signed PCR values
equal to the enrolled boot chain, for your nonce, together with this exact
report. Root on the host cannot fake checks 1–5: that needs the AK private
key, which only the TPM has, and PCRs can only be extended, never set.

**Reported or measured policy.** On a kernel with policy measurement
(below), checks 7 and 8 come from the kernel's own log, replayed against
the TPM, and the bundle says `"policy_source": "measured"`. On an older
kernel they come from the report, which `attest-report.sh` builds as root
(`"policy_source": "reported"`), so read them as "the host claims". A
host enrolled as measured never verifies with a reported policy, so root
cannot hide the log to fall back.

## Policy measurement (the kernel side)

The secure_sudo LSM records every policy change it accepts, in order, in
`/sys/kernel/security/secure_sudo/policy_log` (root, read-only). It also
extends each one into a TPM PCR, `CONFIG_SECURITY_SECURE_SUDO_MEASURE_PCR`,
default **13**:

| Event | When |
|---|---|
| `knob NAME VALUE` | a write under `/sys/kernel/secure_sudo/` was accepted (all knobs go through one store hook) |
| `list NAME SHA256` | a policy list under `/sys/kernel/security/secure_sudo/` was replaced; the hash is of the exact text the kernel kept, taken under that list's lock. The boot-time `tpm_openers` defaults are measured too |
| `lock WHY 1` | the one-way lock latched. It comes after the knob write that caused it (`knob lock 1` or `knob timevault_enabled 1`) |
| `foreign pcr VALUE` | before an extend, the kernel found the PCR at VALUE rather than at the value its own events give. Something else extended it |

Each extend is `PCR = SHA256(PCR || SHA256(event text))`. Writing a value
that is already in effect adds nothing. Refused writes are not measured.
The log keeps at most 8192 entries. Past that, measuring stops and the
header says `overflow=1`, which the verifier fails. Extends run on a
kernel work item, because the TPM may come up after the first policy
writes; entries wait as not extended (`count` > `extended` in the header)
until it does. `attest quote` waits up to 30 s for them, and the verifier
fails while any is pending. Other PCR banks get the SHA-256 digest cut or
zero-padded to their size; only the SHA-256 bank is checked.

The bundle carries the log and quotes the policy PCR with the boot chain.
The verifier then checks that:

* every line's digest is the sha256 of its text, and the log replays to the
  quoted PCR (so root cannot edit, drop or reorder a kernel event);
* nothing is pending and the log did not overflow;
* there is no `foreign` marker;
* no list changed after the lock (the kernel refuses that, so such an
  entry is not the kernel's). A knob that may only tighten while locked,
  such as `timevault_enabled 1`, is allowed;
* the reported `tpm_openers` text hashes to the measured one, and every
  program on it is one that cannot extend a chosen value into a PCR (see
  below).

The measured policy is the last value of every knob and list, plus whether
the lock event is present, hashed as `secure_sudo-measured-policy-v1`.
Enrollment stores that digest; `--allow-policy` adds others.
`secure-sudo-attest-verify policy BUNDLE` prints the state and digest from a
bundle, so you can allow a new policy before rolling it out. The policy PCR
is not part of the golden boot chain, because its value depends on what was
loaded.

**What this proves, and when.** Root can still extend PCR 13 itself, and
a SHA-256 of any text is easy to make. So made-up events are only kept out
if root has no way to extend that PCR once the policy is locked:

* While unlocked, root is trusted by design (THREAT_MODEL.md §2), and an
  unlocked measured policy is only as good as root. Use `--require-lock`.
* Once locked, only programs on `tpm_openers` can open the TPM (G4). The
  verifier fails if any of them can extend arbitrary values: everything
  except systemd-creds, systemd-cryptenroll, systemd-cryptsetup,
  systemd-pcrlock, systemd-tpm2-setup, systemd-measure, and
  secure-sudo-attest. That is why the defaults (kernel and shipped
  `tpm_openers.conf`) leave out `/usr/lib/systemd/systemd-pcrextend` and
  `/usr/sbin/tpm2-abrmd`: systemd-pcrextend writes any string into any
  PCR, and abrmd brokers every tpm2-tools client. On measured-UKI systems
  systemd-pcrphase runs systemd-pcrextend at shutdown, and tpm2-tools users
  go through abrmd. If you need either after the lock, add it to
  `/etc/secure_sudo/tpm_openers.conf` before `secure-sudo lock`, enroll
  with `--accept-pcr-extenders`, and treat the policy as "the host claims"
  again.
  An upgrade keeps an existing `/etc/secure_sudo/tpm_openers.conf` (the
  installer never overwrites config), so a host installed before this
  change still lists both until you remove them and `secure-sudo load`;
  the verifier names them until you do.
* A program that opened the TPM before the lock keeps its file descriptor.
  The kernel's `foreign` check catches its extends at the next policy
  event, and the replay catches any extend that has no log line. What it
  cannot catch is a made-up event appended after the kernel's last one by
  someone who held such a descriptor from before the lock. That is the
  pre-lock trust boundary again.
* The PCR must be free. 13 is unused unless systemd-stub measures system
  extensions on a UKI boot. If the very first event already shows
  `foreign`, pick another PCR in the kernel config.

## The firmware event log

The firmware, shim, GRUB and the kernel's EFI stub log every measurement
they make in `/sys/kernel/security/tpm0/binary_bios_measurements` (the TCG
"crypto agile" TPM 2.0 log). The report carries the whole log
(`tpm_eventlog_b64`) next to its sha256. The file is only root-readable and
root could rewrite it, but it could not make a rewritten log replay to the
PCR values the TPM signed. So a log that replays is the log of this boot.

The verifier parses the log, replays its SHA-256 bank (honouring a
`StartupLocality` event for PCR 0, skipping `EV_NO_ACTION`), and checks:

* the log is well formed, declares a SHA-256 bank, and is the one the
  report hashed;
* it replays to every quoted PCR in 0-9 and 14 (shim's MokList), apart from
  the policy PCR;
* the reported Secure Boot state equals the one the firmware measured. That
  is the `SecureBoot` variable event in PCR 7, accepted only if its digest
  is the sha256 of the variable data shown;
* the reported kernel command line is the one GRUB measured (the
  `kernel_cmdline:` event in PCR 8, again only if the digest matches).

Enrollment stores every event (PCR, type, SHA-256, description) and the
Secure Boot state as measured (`"secure_boot_source": "measured"`). When the
boot chain later differs, the verifier names the first event that changed in
each changed PCR, for example:

```
FAIL the boot chain matches the enrolled one (PCR 4 differs) - PCR 4: EV_EFI_BOOT_SERVICES_APPLICATION EFI\ubuntu\grubx64.efi changed
```

That tells an expected update (a new `grubx64.efi` or `vmlinuz`) from an
unexpected one (a new boot option, a changed `db`) without guessing from PCR
numbers. A host enrolled with a log must always send one, so root cannot
hide it later. `secure-sudo-attest-verify eventlog FILE` prints a log (raw
`binary_bios_measurements`, or the one in a bundle) event by event, with the
PCR values it replays to, and marks any that differ from a bundle's quote.

Some firmware writes logs that do not replay (vendor bugs). Such a host
fails enrollment with the PCRs that disagree. Enroll it with
`--ignore-eventlog` to fall back to comparing PCR values only.

The parser was checked against a real boot: Ubuntu 24.04 under OVMF with a
software TPM (`VM_UEFI=1 VM_TPM=1 tests/vm/distro/vm.sh`). All of PCRs 0-9
and 14 match what that TPM held, and match `tpm2_eventlog` from tpm2-tools.
The captured logs are the test fixtures in
`tests/userspace/fixtures/eventlog/`.

## The IMA log

With IMA measuring (for example `ima_policy=tcb ima_hash=sha256
ima_template=ima-ng` on the kernel command line, or a custom policy), the
kernel hashes each program, library and root-read file before it is used,
and extends PCR 10 with a record of it. When
`/sys/kernel/security/ima/binary_runtime_measurements` is not empty, `attest
quote` adds PCRs 10 and 6 to the quote. PCR 6 is there so all of 0-9 are
quoted for the `boot_aggregate` check below. The host reads the log
**after** the quote, so the log holds every record the quoted PCR 10
covers, plus whatever IMA measured in between. The log goes in the bundle
(`ima_log_b64`) outside the signed report, because what makes it
trustworthy is PCR 10, not the signature.

The verifier replays the records (SHA-256 bank: `SHA256(template data)`
per record, `0xff..ff` for a violation) and finds the record at which the
value equals the quoted PCR 10. Records after that point came after the
quote and are ignored. It checks:

* the log is well formed and has a supported template (`ima-ng`,
  `ima-sig`, `ima-buf`, `ima-modsig`, `evm-sig`);
* the replay reaches the quoted PCR 10, so root cannot drop, edit or
  reorder a record;
* IMA's first record, `boot_aggregate`, is the sha256 of this boot's
  quoted PCRs 0-9 (when IMA uses SHA-256), which ties the IMA log to the
  boot chain above;
* with `--ima-reference FILE`: every measured file listed in FILE has a
  listed hash. FILE is in `sha256sum` format, so `sha256sum` output from a
  known-good host or from package contents works. Files that are not in
  FILE are shown as `INFO`, or fail with `--ima-unknown fail`.

It also prints, as `INFO`, how many files were measured and how many
violations IMA recorded (a file changed, or opened for write, while being
measured or run). PCR 10 is never part of the golden boot chain, because it
grows with every new file. A host enrolled with an IMA log must keep sending
one (no downgrade); `--ignore-ima` at enrollment opts out. `secure-sudo-
attest-verify ima BUNDLE [--ima-reference FILE] [--list]` shows the same
checks and, with `--list`, every record up to the quote.

The replay was checked against the same Ubuntu guest booted with
`ima_policy=tcb`: its 2099 records replay to the PCR 10 its TPM held, and
its `boot_aggregate` matches its PCRs 0-9.

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
digest. Either re-enroll, or add the new digest with `--allow-policy`; for
a measured host take it from `secure-sudo-attest-verify policy BUNDLE` on a
host running the new policy.

## Evaluation: IMA/EVM, fs-verity, dm-verity

P2-1 asked for these to be evaluated as complementary controls, not
reimplemented in each userspace monitor.

- **IMA measurement** (`ima_policy=tcb`) extends a hash of every executed
  file into PCR 10 and keeps a log in
  `/sys/kernel/security/ima/ascii_runtime_measurements`. The verifier
  replays that log against the quoted PCR 10 and can check every file
  against a reference list ("The IMA log" above). **Recommendation:** turn
  it on (`ima_policy=tcb` or a narrower custom policy) on hosts you attest;
  secure_sudo does not do it for you, since it changes boot parameters.
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

- **Credential activation with an ECC EK.** Only the RSA 2048 EK is
  supported. Nearly every TPM has one, but a TPM that ships only an ECC EK
  certificate (`0x01c0000a`) cannot be bound yet. Making the challenge for
  it needs ECDH and the KDFe key derivation in the verifier.
- **Automatic retrieval of intermediate CA certificates.** The verifier does
  not follow the EK certificate's Authority Information Access URL. Pass
  intermediates with `--ek-intermediate`.

The firmware event-log parser, the IMA log replay and the RSA EK
certificate check with credential activation that used to be listed here
are built (sections above).
