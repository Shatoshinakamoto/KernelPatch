# secure_sudo — script reference

Every shell script shipped with secure_sudo, what it does, how to run it, and
every flag it accepts. There are three groups:

* **`scripts/`** — standalone admin tools, installed to
  `/usr/libexec/secure-sudo/`. These are the dependency-free (bash + coreutils)
  equivalents of CLI subcommands, for use where the compiled `secure-sudo` CLI
  is not available.
* **`install/`** — the build/install scripts.
* **`userspace/daemon/helpers/`** — small helpers the `secure-sudod` daemon
  shells out to, so the daemon core stays small and auditable.

All of them must run as root.

---

## `scripts/timevault-whitelist.sh` {#timevault-whitelist}

Manage the TimeVault exec allowlist with nothing but bash, coreutils and
findutils. Functionally identical to `secure-sudo vault-allow`. Saves to
`/etc/secure_sudo/timevault_allow.conf` (as `<path> <sha256>` lines) and pushes
the whole list to `/sys/kernel/security/secure_sudo/timevault_allow`. Holds a
`flock` on `/run/secure_sudo-vault-allow.lock` so two editors never race.

```
timevault-whitelist.sh <subcommand> [options]
```

| Subcommand | Options | What it does |
|------------|---------|--------------|
| `scan <dir>…` | `-n`, `-x` | Walk each `<dir>`, and for every executable binary (ELF) or `#!` script, hash it (SHA-256) and add/refresh its entry. |
| `add <file>…` | — | Hash and add single files (warns, but still adds, if a file is not executable). |
| `remove <file>…` | — | Drop entries by path. |
| `list` | — | Print the saved allowlist. |
| `wipe` | `-y`, `--force` | Empty the allowlist. |

Flags:

* `-n`, `--dry-run` *(scan)* — print what would be added; change nothing.
* `-x`, `--one-file-system` *(scan)* — do not cross mount points.
* `-y`, `--yes` *(wipe)* — skip the confirmation prompt.
* `--force` *(wipe)* — wipe even while TimeVault is engaged (normally refused,
  since an empty allowlist would block nearly every exec).

Behaviour notes:

* Paths are canonicalised with `realpath`; a symlink is stored as its target,
  because that is the path the kernel sees at exec time.
* Paths containing whitespace cannot be represented in the kernel list and are
  skipped with a warning.
* Re-running `scan` re-hashes changed files and leaves unchanged ones alone.
* Limits match the kernel: 16384 entries / 4 MiB. Over that, nothing is saved.
* If the LSM is not loaded yet, it still writes the `.conf` and tells you the
  kernel will pick it up at next boot.
* This bash twin manages hash entries only. Auto-update entries (`add-auto`,
  `add-autodir`) and `remove-dir` are features of the compiled `secure-sudo
  vault-allow` CLI.

```sh
sudo /usr/libexec/secure-sudo/timevault-whitelist.sh scan -n /usr/local/bin
sudo /usr/libexec/secure-sudo/timevault-whitelist.sh scan /usr/bin /usr/sbin
sudo /usr/libexec/secure-sudo/timevault-whitelist.sh add /opt/app/bin/app
sudo /usr/libexec/secure-sudo/timevault-whitelist.sh wipe        # prompts
```

## `scripts/detect-admin-gids.sh`

Print every admin-group GID on the box as a comma list (e.g. `27,10`), for
`admin_gid`. Sources: the groups `sudo`, `wheel`, `admin` that exist, plus
every `%group` / `%#gid` rule in `/etc/sudoers` and `/etc/sudoers.d/`
(skipping the files sudo itself ignores). The compiled CLI has the same logic
as `secure-sudo detect-admins`. `install.sh` calls this at install time.

```
detect-admin-gids.sh [--apply]
```

* *(no option)* — print the detected list to stdout and exit.
* `--apply` — also write it to `admin_gid` in `secure-sudo.conf` and to the
  live kernel knob (root only). Warns if no admin groups are found (only root
  would then count as sudo).

```sh
/usr/libexec/secure-sudo/detect-admin-gids.sh            # just print
sudo /usr/libexec/secure-sudo/detect-admin-gids.sh --apply
```

Caps at 16 GIDs (the kernel limit); extras are reported and ignored.

## `scripts/stig-harden.sh` {#stig-harden}

Run a DISA STIG (or the closest hardening baseline the distro actually ships)
OpenSCAP evaluation on the host, and optionally apply the generated
remediation. Installed to `/usr/libexec/secure-sudo/stig-harden.sh`. Auto-
detects the distro, installs `oscap` + SCAP Security Guide content if missing,
picks the right datastream + profile, and writes timestamped HTML + XML reports
to `/var/log/secure_sudo/stig/`. Full context, the kernel→STIG control mapping,
and the real before/after results are in [STIG.md](STIG.md).

```
stig-harden.sh [--scan] [--remediate] [--profile <id>] [--datastream <f>]
               [--tailoring <f>] [--list-profiles] [--outdir <dir>] [--yes]
               [--passes <n>] [--skip-rules <regex>] [--post-patch-only]
```

| Flag | What it does |
|------|--------------|
| `--scan` *(default)* | Scan only; produce reports. Read-only, safe anytime. |
| `--remediate` | Scan, apply the generated bash fixes, then re-scan. Asks for confirmation unless `--yes`. Rewrites PAM/password/banner/audit/permission policy — do it in a maintenance window with a root shell open. |
| `--profile <id>` | Force a specific XCCDF profile (see `--list-profiles`). |
| `--datastream <f>` | Force a specific SSG datastream file. |
| `--tailoring <f>` | XCCDF tailoring file with your site's values (time servers, ...); scans and fixes use its profile. Example: `tests/vm/distro/stig-vm-tailoring.xml`. |
| `--list-profiles` | List the profiles in the chosen datastream and exit. |
| `--outdir <dir>` | Report directory (default `/var/log/secure_sudo/stig`). |
| `--yes`, `-y` | Do not prompt before remediating. |
| `--passes <n>` | Remediation passes before the final scan (default 2). |
| `--skip-rules <regex>` | Leave matching rules unremediated (listed in `*.skipped`, still in the report). |
| `--post-patch-only` | Apply only the known-issue patches (OSB-03..07, OSB-20), then rescan. |

Every scan also writes `<result>.crosscheck`: independent checks of the rules
the platform's scanner cannot evaluate (OSB-19, `encrypt_partitions` and
`dir_perms_world_writable_sticky_bits` on Ubuntu 24.04), which the STIG gate
uses instead of the scanner's answer.

Profile selection prefers the DISA STIG profile and falls back, in order, to
CIS Level 2 → ANSSI high → the standard profile, announcing which it chose.
STIG profiles exist (SSG 0.1.78) for RHEL 8/9/10, Oracle Linux 9, SLE 15 and
Ubuntu 20.04/22.04/24.04; other distros use the fallback.

```sh
sudo /usr/libexec/secure-sudo/stig-harden.sh --scan          # read-only scan
sudo /usr/libexec/secure-sudo/stig-harden.sh --list-profiles # what's available
sudo /usr/libexec/secure-sudo/stig-harden.sh --remediate     # scan+fix+rescan
```

The installer can run it automatically: `sudo STIG=scan ./install/install.sh`
or `STIG=remediate` (opt-in; off by default).

---

## `install/install.sh`

Build, install, verify, roll back and remove the secure_sudo kernel and
userspace on Debian/Ubuntu, Fedora/RHEL, Arch and openSUSE (family from
`/etc/os-release` `ID`/`ID_LIKE`). Run as root; review it first — it compiles
and installs a kernel. Recovery from every failure: [RECOVERY.md](RECOVERY.md).

```sh
sudo ./install/install.sh --dry-run          # what would happen; changes nothing
sudo ./install/install.sh                    # everything below, in order
# reboot: the new kernel boots ONCE; if it fails, the next boot is the old one
sudo ./install/install.sh verify --commit    # make it the default
```

| Command | What it does |
|---|---|
| `all` (default) | preflight → build deps → fetch + verify source → build the kernel package → `install-kernel` → `userspace` → `verify` |
| `preflight [all\|build-kernel\|install-kernel\|userspace [--prebuilt DIR]]` (`--dry-run`) | distro support, boot method, bootloader, Secure Boot state and keys, trial-boot availability, `/boot` and build space, DKMS modules, missing tools, PAM files that use the modules, the runtime packages it would install, and the list of changes. Changes nothing; non-zero exit on a blocking problem. `install-kernel` and `userspace` run their own preflight first |
| `build-kernel` | verified source → graft the LSM → configure from the running kernel's config → `bindeb-pkg`/`binrpm-pkg` into `$BUILD_ROOT/out/<release>/` with `build-info.txt`, `kernel.config`, `kernel-source.txt`, an SPDX SBOM and `SHA256SUMS` |
| `install-kernel [DIR\|PKG…]` | checks `SHA256SUMS`, installs the package next to the running kernel, signs the image when a MOK is given, regenerates the boot menu (failure stops the run), checks the menu has both kernels, arms the trial boot |
| `userspace [--prebuilt DIR]` | preflight, then installs the CLI, daemon, PAM modules, OTP helper, PheonixBox and `scripts/` tools, recording each file with its hash; backs up anything it replaces; creates missing `/etc/secure_sudo/*.conf` (never overwrites them); installs runtime packages (libqrencode, nftables, zip, unzip; on Debian/Ubuntu it refreshes the package lists first when a package has no candidate, as on a fresh cloud image); checks every program finds its libraries; enables `secure-sudod` |
| `stage-userspace DIR` | builds userspace into DIR, for `userspace --prebuilt` on other machines of the same distro release |
| `verify [--commit]` | installed files unchanged; libraries resolve; per kernel: image, `CONFIG_SECURITY_SECURE_SUDO`, `CONFIG_LSM`, `MODULE_SIG_FORCE`, initramfs, signed modules, boot entry, image signature; the known-good kernel still in the menu; on the running secure_sudo kernel: active LSMs, `sig_enforce`, lockdown (`SS_EXPECT_LOCKDOWN`), `secure-sudod` and `secure-sudo lint` (when userspace is installed); the trial-boot state. `--commit` makes a trial-booted kernel the default when everything passed |
| `rollback [--default]` | boot the kernel that ran before secure_sudo: next boot only, or as the default |
| `uninstall [--remove-pam-lines] [--keep-kernel] [--purge]` | refuses while PAM uses the modules or while the secure_sudo kernel is running; removes only recorded, unchanged files; restores what it replaced; clears the GRUB drop-in and entries; purges the kernel packages. `--purge` also deletes `/etc/secure_sudo` and `/var/log/secure_sudo`; TimeVault quarantine is always kept |

The install record is `/var/lib/secure_sudo/install/manifest` (kind, path,
value per line; rewritten atomically after every change).

| Variable | Default | Effect |
|----------|---------|--------|
| `KVER` | `6.12.114` | kernel.org 6.12 LTS point release to fetch and build. |
| `JOBS` | `nproc` | Parallel build jobs. |
| `BUILD_ROOT` | `/usr/src/secure_sudo-build` | Where the kernel is fetched and built (root-owned, never world-writable `/tmp`). |
| `KERNEL_TARBALL`, `KERNEL_SIGNATURE` | download | Local copies for offline builds; verified the same way. |
| `SS_KERNEL_TREE` + `SS_KERNEL_TREE_PROVENANCE` | — | Build a tree verified some other way; the record (with a `verified_by=` line) is required and kept as the build's `kernel-source.txt`. |
| `SS_BASE_CONFIG` | running kernel's | Config to start from. |
| `SS_LOCALMOD` | — | `lsmod` output for `localmodconfig` (smaller, faster builds; only those modules). |
| `SS_TRIAL_BOOT` | `1` | `0` lets the new kernel become the default at once. |
| `SS_PANIC_TIMEOUT` | `10` | Seconds before a panicking secure_sudo kernel reboots (so a trial falls back). |
| `SS_SB_KEY`, `SS_SB_CERT` | — | MOK key + PEM certificate: the image is signed with them; required when Secure Boot is on. |
| `SS_EXPECT_LOCKDOWN` | — | `verify` fails unless the running lockdown mode matches (`none`, `integrity`, `confidentiality`). |
| `STIG` | *(unset)* | `scan` / `remediate` after install ([STIG.md](STIG.md)). |

What changed from 0.11: module signatures are enforced by the new kernel's
own config (`CONFIG_MODULE_SIG_FORCE`) instead of `module.sig_enforce=1` on
the shared GRUB command line, which also applied to the previous kernel and
its unsigned DKMS modules (uninstall removes that old edit); `update-grub`
failures stop the run instead of being ignored; RPM installs no longer use
`--force` or install `kernel-headers` over the distro's; an upgrade no longer
rewrites a hand-set `admin_gid`.

## `install/encrypted/install-encrypted.sh`

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

## `scripts/oscap-results.py`

Reads OpenSCAP results (XCCDF/ARF XML, or saved `oscap xccdf eval` console
output with its `\r` rewrites) and is what `stig-harden.sh` and the STIG gate
use to count and compare results.

```
oscap-results.py tally FILE                    pass=… fail=… error=… notapplicable=… notchecked=…
oscap-results.py rules FILE [--not-pass]       "<result> <rule>" per rule (short ids)
oscap-results.py skip-fix FIX.sh REGEX         drop matching fix blocks (lists them in FIX.sh.skipped)
oscap-results.py gate FILE --expect EXPECT [--mode release|diagnostic]
```

`gate` compares **rule IDs**, not totals: every result that is not
pass/notapplicable must be listed in the expect file
(`tests/oscap/ubuntu2404-stig.expect`) with a reason; `error` and `unknown`
never pass in release mode; a listed rule missing from the results fails
(the profile changed); entries marked `container-only` are tolerated only in
`--mode diagnostic`.

## `ci/` — build gate and release

| Script | What it does |
|---|---|
| `ci/build-gate.sh [--stages …] [--kernel-tree DIR] [--headers DIR]… [--headers-direct DIR]… [--record FILE]` | The release gate, in a scratch copy of the tree: `lint` (bash -n, shellcheck, py_compile, duplicate-hook check), `userspace` and `addons` (`-Werror`), `lsm-headers` (LSM against installed or downloaded header trees), `lsm-tree` (in-tree build per `ci/kconfig/*.config` variant), `tests` (`tests/run-all.sh`), `package` (release tarball built twice, compared). Writes a record with compiler, tree hash, kernel tree, per-variant config hashes and each stage's result |
| `ci/make-release.sh [--out DIR]` | Reproducible release tarball + `.sha256` + SPDX SBOM |
| `ci/graft-lsm.sh TREE` | Copy the LSM into a kernel tree and register it (Kconfig, Makefile, `lsm_count.h`) |
| `ci/lsm-compile-check.sh` | Compile every LSM file against a header tree (`--mode kbuild\|direct`) |
| `ci/check-lsm-hooks.sh` | Fails if any LSM hook is registered twice (the v11 boot panic) |

The GitHub workflow `.github/workflows/build-gate.yml` runs the gate on every
push and pull request, and nightly the distro VM scenario followed by the
STIG release gate in a fresh guest (written locally; not yet run on GitHub).

## `tests/`

`tests/run-all.sh` runs every host suite (TAP). The distro VM tests are in
`tests/vm/distro/` ([README](../tests/vm/distro/README.md)); the initramfs
LSM boot test is `tests/vm/boot-test.sh`.

---

## `userspace/daemon/helpers/apply-net.sh`

Called by `secure-sudod` whenever `net_mode` changes (not run by hand).
Installs or removes a single nftables table `inet secure_sudo` for the chosen
mode.

```
apply-net.sh <monitor|host|lan-only|public-only>
```

* `monitor`, `host` — removes any secure_sudo table (no nft rules; `host`
  mode's socket block is in the kernel).
* `lan-only` — allow only loopback and the detected LAN, for IPv4 **and**
  IPv6 (link-local, unique-local and the interface's own prefixes).
* `public-only` — drop traffic to the LAN and private IPv6 ranges, but keep
  DHCP/DHCPv6, ICMPv6 neighbour discovery and DNS to the gateway, so the box
  stays reachable and keeps its address.

The mode is validated first, and the old table is replaced in the same
`nft -f` transaction as the new one: a typo or a missing route leaves the
current rules in place instead of removing them. The daemon retries a failed
apply every 5 seconds and logs the failure once.

## `userspace/daemon/helpers/quarantine.sh`

Called by `secure-sudod` in two cases, both when `vault_action=quarantine`
(the default): when TimeVault is engaged and a new or changed file appears in a
watched tree, and when the kernel **blocks an exec** because a listed binary's
hash no longer matches or an unlisted binary tried to run. Not run by hand.

```
quarantine.sh <file>
```

It records the file's origin path, timestamp and SHA-256 in a `.meta` sidecar
(newlines in names escaped), packages file + metadata into a uniquely named
zip under `/var/lib/secure_sudo/quarantine/` (`tar.gz` if `zip` is absent),
**verifies the archive** (`unzip -l` / `tar -tzf`), and only then removes the
original. If archiving fails the original stays where it was and the daemon
logs it and retries later; two files with the same name never overwrite each
other's evidence. All filename handling uses `--` so an attacker-chosen name
cannot be read as an option.
