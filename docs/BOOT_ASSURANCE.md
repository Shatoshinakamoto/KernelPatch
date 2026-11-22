# Boot and firmware assurance (TODO P2-4)

What BootGuard and BiosGuard can and cannot claim, what is tested on a real
platform, and how an operator recovers safely. Everything here is detect, log,
notify, or restore **files** from a hash-checked backup. There is no automatic
firmware reflashing, and there never will be a generic one: a bad write bricks
the board and needs vendor tooling.

## 1. What BiosGuard measures

| Source | Read from | Catches | Limit |
|---|---|---|---|
| DMI identity | `/sys/class/dmi/id/*` | vendor/BIOS version/serial edits | what the firmware reports |
| ACPI tables | `/sys/firmware/acpi/tables/*` | table injection or edits | tables the OS is shown |
| SMBIOS | `/sys/firmware/dmi/tables/{DMI,smbios_entry_point}` | raw table edits | same |
| Secure Boot state | efivars `SecureBoot`, `SetupMode`, `PK`, `KEK`, `db`, `dbx` | key enrolment, Secure Boot turned off, revocation list rolled back | the variables as the kernel reads them |
| Firmware update table | `/sys/firmware/efi/esrt/entries/*` | version rollback, failed update attempts | present only on firmware that publishes ESRT |
| TPM PCRs | `/sys/class/tpm/tpm0/pcr-sha256/N` | PCR 0 (firmware code), 2 (option ROMs), 7 (Secure Boot policy) change | PCRs 4+ change with every bootloader/kernel update, 1 with firmware settings, so they are not defaults |

Settings: `smbios`, `efi`, `tpm_pcrs` in `biosguard.conf` (`check-config`
rejects a bad PCR list). `status` says whether the host is UEFI or legacy BIOS,
how many sources were fingerprinted, and which PCRs.

**None of this is authenticated by BiosGuard.** These are values the running
kernel reports. A compromised firmware can report the old values. A TPM PCR is
better evidence than a sysfs file, but a local scan still trusts the local
kernel to read it. The authenticated route is a TPM **quote** checked by a
remote verifier that replays the firmware event log: `secure-sudo attest`
(docs/ATTESTATION.md, P2-1). Use BiosGuard as the cheap local tripwire and
attestation as the proof.

After a real firmware update run `secure-sudo-biosguard refresh <reason>`: it
logs every changed, added and removed source as CRITICAL (so the change is on
the off-box log) and then re-baselines.

## 2. Baseline provenance

A baseline is only as trustworthy as the moment it was taken. Take it on a
freshly installed or freshly updated host you trust, then either keep
`baseline_trust = local` (the baseline on the host is believed) or
`baseline_trust = signed` (a repair/restore is done only when the manifest
carries your signature, docs/ADDONS.md "Baseline trust"). Every re-baseline
(`refresh`) is logged with its reason. With `local` trust, an attacker who can
write the baseline can also bless their change; with `signed` they cannot.

## 3. The initramfs stage

`bash temporary/install-temporary.sh --initramfs` (initramfs-tools: Debian,
Ubuntu) installs a build hook and a `local-bottom` script. After the real root
is mounted (for an encrypted root, after it is unlocked) and before the switch
to it, if BootGuard staged a restore (the `PENDING` flag) the script:

0. remounts the root read-write if it is still read-only (it usually is at this stage; `restore-staged` writes its log, evidence and state under `/var`) and puts it back to read-only afterwards;
1. mounts the separate `/boot`, `/boot/efi` and `/efi` listed in the root's
   `/etc/fstab` under the root (`rw,nodev,nosuid,noexec`);
2. runs the root's `secure-sudo-bootguard restore-staged` in a chroot, which
   checks the baseline trust and each backup's SHA-256 as always and keeps the
   replaced bytes as evidence;
3. unmounts what it mounted.

It never stops the boot. A failure is logged to the kernel log and the system
comes up with the restore still staged (the systemd unit tries again).
`secure_sudo.bootguard=off` on the kernel command line skips it.
`--remove-initramfs` undoes it. The install re-baselines `/boot` (reason
`initramfs-hook`) because the rebuilt initramfs is a legitimate change.

**What it gives:** the restore runs before systemd, independent of unit
ordering and of fstab mounting by systemd, before any process of the real root
can hold or change the boot files, with the separate `/boot` and ESP handled.
**What it does not give:** it does not protect the boot that is already
running. The kernel and the initramfs were loaded before it ran, so a tampered
kernel or initramfs has already executed by then. It repairs the files for the
**next** boot. Protecting the current boot needs Secure Boot plus measured boot
and a remote verifier (section 1, attestation). A boot-time scan that
*decides* tampering (rather than applying one staged earlier) was considered
and not built: it would revert legitimate updates that were not refreshed.

## 4. What is tested, and what is not

| Claim | Evidence |
|---|---|
| Staged restore is applied by the initramfs stage before systemd, on a separate ESP, BIOS/GRUB and UEFI/OVMF, Ubuntu 24.04 | `tests/vm/distro/run-bootguard-initramfs-test.sh` (result recorded in the PR) |
| Restore script logic: nothing staged, opt-out, missing binary, missing device, normal path | `tests/userspace/test-addons.sh` (fake root) |
| BiosGuard sources, defaults, malformed config, refresh | `tests/userspace/test-addons.sh` (fake sysfs/efivars/TPM) |
| Encrypted root (LUKS) | **not tested.** The script runs after the root is unlocked by design, but it has not been run against a LUKS guest. Do not rely on it until it has. |
| systemd-boot, other bootloaders | **not tested** |
| dracut distros (Fedora, RHEL family) | **not supported**: no hook is shipped; the systemd unit is the restore path there |
| Real hardware firmware (ESRT, PCRs on a real board) | **not tested**; the readers are unit-tested against fake trees only |

The VM tests run under emulation with a software TPM and OVMF, so they prove
the restore mechanics, not firmware behaviour on real boards.

## 5. Operator recovery path

If the machine does not boot after a restore, or you doubt a restore:

1. Boot with `secure_sudo.bootguard=off` (GRUB: edit the entry, append it).
   The initramfs stage is skipped; the systemd unit is still there (disable it
   from a rescue shell with `systemctl disable secure-sudo-bootguard-restore`).
2. The replaced files are kept as evidence under the BootGuard state dir
   (`/var/lib/secure_sudo/addons/bootguard`), and the compressed backups are in
   the backup root. Nothing is deleted by a restore.
3. `secure-sudo-bootguard status` shows whether a restore is pending and
   whether the initramfs stage is installed.
4. To remove the initramfs stage: `bash temporary/install-temporary.sh
   --remove-initramfs`.
5. After a legitimate kernel/bootloader change: `secure-sudo-bootguard refresh
   <reason>` (the package hooks do this on apt/dnf/kernel installs).
6. A firmware change flagged by BiosGuard is never repaired by this tool.
   Investigate, update or restore firmware with the vendor's tooling, then run
   `secure-sudo-biosguard refresh <reason>`.

See also docs/RECOVERY.md and docs/ATTESTATION.md.
