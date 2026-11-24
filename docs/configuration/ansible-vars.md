<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# Ansible variables (`install/ansible/`)

The variables of the `secure_sudo` role, used by the playbook
`install/ansible/secure_sudo.yml`. How to run it: [INSTALL.md, method 4](../INSTALL.md#method-4-ansible-fleets).

## Location, format and precedence

- **Defaults:** `install/ansible/roles/secure_sudo/defaults/main.yml` (lowest
  precedence; do not edit, override instead).
- **Your settings:** `install/ansible/group_vars/secure_sudo.yml` (copy
  `group_vars/secure_sudo.yml.example`), `host_vars/<host>.yml`, inventory
  variables, or `--extra-vars` (highest precedence), as usual in Ansible.
- **Format:** YAML. Booleans are `true`/`false`.
- **Not in the release:** `inventory.ini`, `group_vars/secure_sudo.yml` and
  `host_vars/` name your own hosts. They are in `.gitignore`, and
  `scripts/gen-sbom.sh` leaves them out of the release archive and the tree
  hash (CWE-200).
- **Validation:** `roles/secure_sudo/tasks/validate.yml` checks every value
  below before any host is changed; a wrong value fails the run (CWE-20,
  NIST SI-10). `tests/install/test-ansible.sh` tests that.
- **Secrets:** none of these variables is a secret. Become passwords belong in
  `ansible-vault` or `--ask-become-pass`, never in these files. The role does
  not set the TPM lockout password, because Ansible would print or log it; set
  it at the console (`install.sh tpm-lockout`, see INSTALL.md).

## Key reference

| Variable | Type | Default | Allowed values | Description | Security impact |
|---|---|---|---|---|---|
| `secure_sudo_serial` | int or % | `1` | `1` or more, or a percentage | Hosts per batch (the play's `serial`). | Keep `1` for a first rollout: with `max_fail_percentage: 0` the run stops at the first failed host, so a bad kernel reaches one machine (NIST CM-3). |
| `secure_sudo_source` | string | `controller` | `controller`, `archive` | Where the code comes from: `controller` builds a release archive from the checkout the playbook is in (`ci/make-release.sh`, in a temporary directory); `archive` uses `secure_sudo_archive`. | Either way the target checks the archive's SHA-256 before unpacking (SI-7). With `controller`, you are trusting the checkout you reviewed. |
| `secure_sudo_archive` | path | `""` | controller path to `secure_sudo-X.Y.Z.tar.gz` | The release archive for `secure_sudo_source: archive`. | Verify its signature yourself first (INSTALL.md, "Verify a release"). |
| `secure_sudo_archive_sha256` | string | `""` | 64 hex digits | Expected SHA-256 of that archive (from its `.sha256` file). Required with `archive`. | Pins the exact archive; a different file is refused on the target. |
| `secure_sudo_remote_dir` | path | `/opt/secure_sudo` | absolute, `[A-Za-z0-9._/-]`, no `..` | Where the archive is copied and unpacked on the target (root:root, 0755). | Root-owned so no other user can swap the code before `install.sh` runs (CWE-367). |
| `secure_sudo_kernel` | string | `build` | `build`, `prebuilt` | `build`: each target runs `install.sh build-kernel` (signature-verified kernel.org source; needs ~20 GB and time). `prebuilt`: install packages built once on a build host. | `build` keeps the source verification on every host. `prebuilt` trusts your build host; the packages' `SHA256SUMS` is checked on the target. |
| `secure_sudo_kernel_dir` | path | `""` | controller directory | With `prebuilt`: the build host's `/usr/src/secure_sudo-build/out/<release>/` (packages, `SHA256SUMS`, `build-info.txt`). | Same distro release as the targets. |
| `secure_sudo_kver` | string | `""` | empty or `N.N[.N]` | Kernel version for `build`; empty uses the release `install.sh` pins (6.12.114). | Stay on the pinned LTS release unless you have a reason (docs/SUPPORT.md). |
| `secure_sudo_userspace_dir` | path | `""` | empty or controller directory | A directory made by `install.sh stage-userspace DIR`: install those prebuilt programs instead of compiling on each target. | Trusts the build host; targets then need no compiler. |
| `secure_sudo_trial_boot` | bool | `true` | `true`, `false` | Reboot into the new kernel once, check it, then `install.sh verify --commit`. `false` stops after the install. | `true` never commits a kernel that did not come up and pass `verify` (CP-10). |
| `secure_sudo_reboot_timeout` | int | `1800` | `60` or more (seconds) | How long to wait for a host to come back after the trial reboot. | |
| `secure_sudo_require_new_kernel` | bool | `true` | `true`, `false` | Fail the host when it came back on another kernel (the trial fell back). | Keep `true`: a silent fallback would otherwise look like a success. |
| `secure_sudo_net_mode` | string | `monitor` | `monitor`, `host`, `lan-only`, `public-only` | Written to `net_mode` in `/etc/secure_sudo/secure-sudo.conf`; restarts `secure-sudod` when it changes. | `lan-only`/`public-only` cut traffic; test reachability on one host first ([CONFIGURATION.md#net_mode](../CONFIGURATION.md#net_mode)). |
| `secure_sudo_load_policy` | bool | `true` | `true`, `false` | After the commit: `secure-sudo lint`, then `secure-sudo load` (only on the secure_sudo kernel). | A lint error or an incomplete load fails the host instead of leaving a partial policy (CM-6). |
| `secure_sudo_addons` | bool | `false` | `true`, `false` | Run `temporary/install-temporary.sh` (builds and installs the add-ons; enables nothing). | Off by default; each add-on's enforcing mode stays off until you turn it on ([ADDONS.md](../ADDONS.md)). |
| `secure_sudo_addons_initramfs` | bool | `false` | `true` (needs `secure_sudo_addons`) | Also install the BootGuard initramfs stage (`--initramfs`). | See [BOOT_ASSURANCE.md](../BOOT_ASSURANCE.md) for what it does and does not protect. |
| `secure_sudo_stig` | string | `""` | `""`, `scan` | Run a STIG scan after the install (reports in `/var/log/secure_sudo/stig/`). | Remediation is not offered here on purpose: it changes PAM, SSH and the firewall and is a reviewed step ([STIG.md](../STIG.md)). |
| `secure_sudo_enable_pam_cooldown` | bool | `false` | `true`, `false` | Add the observe-only `pam_secure_sudo.so` line to `sudo` and `su`. | Keep a root session open; `secure-sudo lint` checks the wiring afterwards. |
| `secure_sudo_enable_pam_otp` | bool | `false` | `true`, `false` | Add `pam_secure_otp.so` after the password in `sudo`. | Run `secure-sudo otp setup` for every sudo user first, or they are locked out of sudo. |

## Annotated example

```yaml
# group_vars/secure_sudo.yml
secure_sudo_serial: 1            # one host at a time, stop at the first failure
secure_sudo_kernel: prebuilt     # built once on a build host of the same distro release
secure_sudo_kernel_dir: /srv/secure_sudo/6.12.114-secure-sudo
secure_sudo_userspace_dir: /srv/secure_sudo/stage
secure_sudo_net_mode: monitor    # change on one host first
secure_sudo_addons: false
```
