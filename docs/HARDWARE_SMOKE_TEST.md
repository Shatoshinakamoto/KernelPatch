# secure_sudo — hardware smoke test

The VM tests (`tests/vm/`, results in `docs/vm/results/`) prove the kernel
boots, the protections work and the installer can roll back. They cannot
prove anything about real firmware, Secure Boot, a TPM, radios or the
storage and network drivers of a given machine (TODO P0-3). Run this plan on
every machine model before relying on secure_sudo there, and keep the filled
results table next to the release you tested.

It is written so that nothing in it is destructive: no TPM clear, no
firmware write, no partition change. Keep a root session open throughout
(`docs/RECOVERY.md`).

## 0. Before you start

- [ ] Note the machine: vendor, model, firmware version
      (`cat /sys/class/dmi/id/{sys_vendor,product_name,bios_version}`),
      boot mode (`[ -d /sys/firmware/efi ] && echo UEFI || echo BIOS`),
      Secure Boot (`mokutil --sb-state`).
- [ ] List out-of-tree modules: `dkms status`; `lsmod` lines whose
      `modinfo -F signer` is empty. **The secure_sudo kernel refuses unsigned
      modules** (`CONFIG_MODULE_SIG_FORCE`): NVIDIA, ZFS, VirtualBox and
      other DKMS modules must be signed with the kernel's key or they will not
      load. Decide what you will do about each before installing.
- [ ] `install.sh preflight` passes; read every line.

## 1. Install and trial boot

- [ ] `install.sh` (or `install-kernel` + `userspace`) completes; `install.sh
      verify` is OK and says the trial boot is armed.
- [ ] Reboot. The secure_sudo kernel comes up (`uname -r` ends in
      `-secure-sudo`).
- [ ] `install.sh verify`: the running-kernel section is all `ok`.
- [ ] `cat /sys/kernel/security/lsm` lists `secure_sudo` and the distro's
      major LSM (AppArmor or SELinux), in the expected order.
- [ ] `cat /sys/kernel/security/lockdown`: matches what you expect (re-run
      verify with `SS_EXPECT_LOCKDOWN=integrity` or `confidentiality` to
      check it).
- [ ] `systemctl --failed` shows nothing new compared with the distro
      kernel; `secure-sudod` is active; `secure-sudo lint` has no errors.
- [ ] Power-cycle **without** `verify --commit`: the previous kernel boots.
      Re-arm (`install.sh install-kernel`), boot it, `install.sh verify
      --commit`.
- [ ] From the boot menu (hold `Shift` on BIOS, `Esc` on UEFI) the previous
      kernel is listed (at the top level) and boots.
- [ ] With a GRUB password set (STIG `grub2_password`, `--unrestricted`
      entries): `install.sh verify` says `saved_entry boots without it`,
      and a reboot needs no password.

## 2. Secure Boot and MOK (UEFI machines with Secure Boot on)

- [ ] The MOK is enrolled (`mokutil --test-key <cert>` says *already
      enrolled*); preflight did not block.
- [ ] `sbverify --list /boot/vmlinuz-<rel>` shows a signature;
      `install.sh verify` reports the image signed.
- [ ] The kernel boots with Secure Boot on; `mokutil --sb-state` still says
      enabled; `dmesg | grep -i 'secure boot'`.
- [ ] Lockdown under Secure Boot is at least `integrity`.
- [ ] Negative check (optional, spare machine): an unsigned copy of the image
      added as a separate entry is refused by shim, and the machine falls
      back to the previous kernel.

## 3. TPM

- [ ] `ls /sys/class/tpm/`; `tpm2_getcap properties-fixed | head` (tpm2-tools)
      works as root: secure_sudo does not block normal TPM use.
- [ ] TPM-backed disk unlock (if used: `systemd-cryptenroll --tpm2-device`,
      Clevis) still unlocks at boot.
- [ ] The clear request is refused **for root** — test with the harmless
      no-op request `0`, never `5`:
      `echo 0 | sudo tee /sys/class/tpm/tpm0/ppi/request` → `Operation not
      permitted`, and a `secure_sudo` event appears in today's
      `/var/log/secure_sudo/<date>.log`. If the file does not exist the
      platform has no PPI; note it.

## 4. Firmware interfaces

- [ ] As a non-sudo user: `cat /dev/mem` and `cat /dev/port` are refused
      (`block_flash`); as root they behave as on the distro kernel.
- [ ] `fwupdmgr get-devices` works for an admin; firmware updates are applied
      only in a maintenance window, as documented.
- [ ] UEFI variables read normally (`efibootmgr -v`); `efibootmgr` changes by
      an admin still work (needed for recovery).
- [ ] If the BiosGuard add-on is installed: its baseline is recorded and a
      re-check reports no change (detection only, it never writes firmware).

## 5. Radios (Wi-Fi, Bluetooth)

- [ ] With `block_wifi = 0` and `block_bluetooth = 0`: Wi-Fi associates
      (`nmcli dev wifi`), Bluetooth pairs (`bluetoothctl show`), exactly as
      on the distro kernel.
- [ ] With `block_wifi = 1` / `block_bluetooth = 1` (`secure-sudo radio …`,
      then reboot as documented): the radio stays off, `rfkill unblock` is
      refused, Bluetooth sockets are refused; Ethernet still works.
- [ ] Back to `0`, reboot: radios work again.

## 6. Storage and network drivers

- [ ] Every disk the machine has is visible and mounted as before
      (`lsblk -f`, `findmnt`); NVMe, SATA/AHCI, USB mass storage, SD readers,
      RAID/LVM/LUKS layers all come up.
- [ ] `dmesg --level=err,warn` has nothing new compared with the distro
      kernel (`journalctl -k -b -1` from the distro kernel boot is the
      baseline). Look for `module verification failed`, `Lockdown:` and
      `secure_sudo` lines.
- [ ] Ethernet and Wi-Fi drivers load; DHCP and DNS work.
- [ ] `net_mode` checks with the machine's real interfaces: `monitor` (no
      change), `host`, `lan-only` (LAN reachable over IPv4 and IPv6, the
      internet not), `public-only` (internet reachable, LAN not, DHCP and DNS
      to the gateway still work). Return to your normal mode.
- [ ] Suspend/resume and a full shutdown work.

## 7. Policy and recovery on this machine

- [ ] `secure-sudo lint` then `secure-sudo load` with your real policy:
      `0 rejected`.
- [ ] Each sudo user can still use sudo; one non-sudo account can log in and
      use `passwd` (with `block_setid_exec = 1`, `/usr/bin/passwd` must be in
      `setid_exec_allow.conf`).
- [ ] If OTP is used: OTP setup, a sudo with the OTP, and a reused code being
      refused.
- [ ] Rollback drill once: `install.sh rollback`, reboot, back on the previous
      kernel, then boot secure_sudo again.

## Results

Copy this table per machine into `docs/hardware/<vendor>-<model>.md`
(or your own records) and fill it in.

| Section | Result (pass / fail / n/a) | Notes |
|---|---|---|
| 0. Machine, firmware, boot mode, Secure Boot | | |
| 0. Out-of-tree modules and their plan | | |
| 1. Install, trial boot, fallback, commit, menu | | |
| 2. Secure Boot / MOK | | |
| 3. TPM use, TPM unlock, clear refused | | |
| 4. Firmware interfaces | | |
| 5. Wi-Fi / Bluetooth on, off, on | | |
| 6. Storage, network, net modes, suspend | | |
| 7. Policy load, sudo/non-sudo, OTP, rollback | | |
| secure_sudo release, kernel release, date, tester | | |
