<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
-->
# `install/encrypted/install-encrypted.sh`

Run as root. Part of the [script reference](../SCRIPTS.md).

Encrypted-source + Secure Boot variant. Decrypts an age-encrypted source
bundle into a tmpfs (RAM), builds there so the plaintext never touches disk,
and installs through `install.sh` with the Machine Owner Key, so the kernel
image is signed and the trial boot, rollback and uninstall work as usual.
Optionally assembles a signed Unified Kernel Image. Run as root.

With Secure Boot on, the first run creates the MOK, asks `mokutil` to enroll
it and stops: reboot, confirm the enrollment in MokManager, run it again.
(`install.sh` refuses to install a kernel signed with a key that is not
enrolled yet, because it would not boot.)

Prerequisites on the builder: `age`, `mokutil`, `sbsigntool`, `openssl`, and
for the UKI `systemd-ukify`. Driven by environment variables:

| Variable | Required? | Default | Effect |
|----------|-----------|---------|--------|
| `SRC_AGE` | **yes** | — | Path to `secure_sudo-src.tar.age`. |
| `AGE_IDENTITY` | **yes** | — | Path to the age private key. |
| `MOK_KEY` | no | `/var/lib/secure_sudo/mok/MOK.key` | MOK private key (generated if absent). |
| `MOK_CRT` | no | `/var/lib/secure_sudo/mok/MOK.der` | MOK certificate (generated if absent; a PEM copy is kept next to it). |
| `MAKE_UKI` | no | `0` | `1` to also build+install a signed UKI. |
| `ESP` | no | `/boot/efi` | EFI system partition mount point. |
| `ENC_TMPFS_SIZE` | no | `24g` | Size limit of the RAM build area (a distro-config kernel build needs ~20 GB; preflight checks it). |
| `KVER` | no | install.sh's | Kernel version (passed through to `install.sh`). |

```sh
sudo SRC_AGE=secure_sudo-src.tar.age AGE_IDENTITY=~/key.txt \
     MAKE_UKI=1 ./install/encrypted/install-encrypted.sh
```

The tmpfs with the plaintext source is unmounted (and so wiped) on exit.

## Related

- [Script reference](../SCRIPTS.md)
- [Install guide](../INSTALL.md)
