# Distro VM tests

`tests/vm/boot-test.sh` boots the LSM in a RAM-only initramfs: fast, but
there is no bootloader, package manager, systemd or AppArmor. The scripts
here use a real distro cloud image instead, on a copy-on-write overlay that
is thrown away afterwards, and drive it over SSH. They work without KVM (TCG
emulation: about 3–4 minutes per boot on 4 cores).

| Script | What it proves |
|---|---|
| `run-install-test.sh` | install.sh end to end: preflight, kernel package, trial boot, automatic fallback, commit, the P0-6 recovery drills (`recovery-exercises.sh`), rollback, uninstall, clean removal (`guest-snapshot.sh`) |
| `run-stig-test.sh` | the DISA STIG release gate on a hardened guest running the secure_sudo kernel with AppArmor |
| `vm.sh` | up / boot / ssh / put / get / reboot / stop / down |
| `fetch-kernel-source.sh` | an upstream kernel tree through the Ubuntu archive, with a provenance record install.sh accepts |

## Inputs

1. **The image**, checked against Ubuntu's signed checksum list:

       curl -fLO https://cloud-images.ubuntu.com/noble/current/SHA256SUMS
       curl -fLO https://cloud-images.ubuntu.com/noble/current/SHA256SUMS.gpg
       gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg SHA256SUMS.gpg SHA256SUMS
       curl -fLO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
       sha256sum -c --ignore-missing SHA256SUMS

2. **The kernel packages**, built by the installer itself. With kernel.org
   reachable, `install.sh build-kernel` fetches and verifies 6.12 LTS. Without
   it, take upstream source through the Ubuntu archive:

       tree=$(tests/vm/distro/fetch-kernel-source.sh /var/tmp/ksrc)
       SS_KERNEL_TREE=$tree SS_KERNEL_TREE_PROVENANCE=/var/tmp/ksrc/kernel-source.txt \
       SS_BASE_CONFIG=<the guest's /boot/config-*> SS_LOCALMOD=<the guest's lsmod> \
       BUILD_ROOT=/var/tmp/ssbuild install/install.sh build-kernel

   `SS_LOCALMOD` (localmodconfig) and a base config without `DEBUG_INFO` only
   make the test build faster; they are not what a normal install uses.

3. For the STIG run, the SSG datastream the gate is pinned to (SSG 0.1.78,
   `ssg-ubuntu2404-ds.xml`; docs/OSCAP_BUGS.md).

## Running

    tests/vm/distro/run-install-test.sh noble-server-cloudimg-amd64.img \
        /var/tmp/ssbuild/out/6.14.0-secure-sudo results/install
    tests/vm/distro/run-stig-test.sh noble-server-cloudimg-amd64.img \
        /var/tmp/ssbuild/out/6.14.0-secure-sudo ssg-ubuntu2404-ds.xml results/stig

Both print TAP and keep every guest command's output and the serial console
in the results directory. The host must run the guest's release (userspace
is built on the host). Recorded runs are in `docs/vm/results/`.

Without KVM the STIG run takes two to three hours (the AIDE database build
and five full scans dominate). Its long guest steps run detached from the
SSH session and are polled, so a dropped connection does not stop them;
`JOB_TIMEOUT` (seconds, default 21600) bounds each one. `VM_PORT`, `VM_CPUS`
and `VM_MEM` let two guests run side by side.
