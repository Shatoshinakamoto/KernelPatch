# Recorded VM runs

Raw output of the boot and VM tests behind [ROADMAP_STATUS.md](../../ROADMAP_STATUS.md),
kept as produced (paths inside them point at the build machine's scratch
directory). Runs 01-07: QEMU under TCG emulation (no KVM), SeaBIOS, 2026-10-26,
upstream Linux 6.14 (Ubuntu archive `.orig` tarball, no distro patches;
provenance in each `build-info.txt` / `kernel-source.txt`).

| Run | What | Result |
|---|---|---|
| `01-v11-panic/` | v11 LSM, initramfs boot (`tests/vm/boot-test.sh`) | **kernel panic** before userspace: `lsm_static_call_init - Ran out of static slots` (SECURITY_REVIEW #35) |
| `02-initramfs-functest/` | v12 LSM, same boot, `tests/vm/ss-functest.c` as PID 1 | 118/118 |
| `03-initramfs-functest-apparmor/` | as 02 with AppArmor stacked (`CONFIG_LSM=…,apparmor,secure_sudo,bpf`) | 118/118 |
| `04-distro-install-run1/` | Ubuntu 24.04 cloud image, `tests/vm/distro/run-install-test.sh`, first run | kernel install, trial boot (secure_sudo + AppArmor active), automatic fallback, rollback and uninstall worked; **userspace install failed** on a fresh image (no apt lists), so commit was refused and the drills could not run. Also showed `grub.cfg` cannot be compared byte-for-byte with the image's copy. Both fixed for run 2 |
| `05-distro-install-run2/` | same scenario after the run 1 fixes | 50/51: everything passed, including commit, all four recovery drills on the real kernel and a byte-clean removal; the one miss was the guest preflight flagging the build tools for a prebuilt userspace (fixed: `preflight userspace --prebuilt DIR`) |
| `06-distro-install-final/` | same scenario on the tree that is packaged as 0.12.0 | **51/51**, plus 35 drill checks in the guest and 4 after the lock reboot. After removal every file under the directories `install.sh` touches is byte-identical to the fresh image (apart from the runtime packages `libqrencode4 zip unzip`), and `grub.cfg` is byte-identical to what GRUB generated before the install |
| `07-distro-stig/` | Ubuntu 24.04 guest with the committed secure_sudo kernel, `tests/vm/distro/run-stig-test.sh`, DISA STIG (SSG 0.1.78) | install, commit, site steps and both remediation passes ran: **206 pass / 11 fail / 0 error / 8 n/a / 5 notchecked** after pass 2 (`pass2-not-pass.txt`, classified in OSCAP_BUGS §5). The post-remediation scan was cut off by the 2-hour job limit and the final rescan was skipped to ship 0.12.0, so the gate has not run on a final VM result. Found OSB-19 (scanner false pass on `encrypt_partitions`, `oscap-partition-probe.txt`) and OSB-21 (ufw cannot start on the trimmed test kernel, `site-ufw-enable.log`; that last step left the guest unreachable over SSH) |
| `08-ci-kernel-boot-6.12/` | first GitHub Actions `kernel-boot` job: **6.12.114** (kernel.org, signature-verified) with secure_sudo built in, initramfs boot under **KVM**, current `ss-functest.c` | **126/126**, active LSMs `lockdown,capability,landlock,yama,secure_sudo`, no kernel splat. First boot of 6.12 and first run of the current in-kernel tests. The job was red only on a too-broad warning scan that matched the CPU's SRSO notice (fixed). Console lines in `summary.txt`; the full console is the run's `kernel-boot-results` artifact |
| `09-ci-distro-install-6.12/` | CI `distro-vm` job: `install.sh build-kernel` package of **6.12.114**, `tests/vm/distro/run-install-test.sh` on Ubuntu 24.04 under KVM | **51/51** (recovery drills 35/35). The attempt before was 50/51: uninstall left the daemon's runtime state (fixed). Summary in `summary.txt` |
