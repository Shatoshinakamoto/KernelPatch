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

---

## `install/install.sh`

Build and install the patched kernel and all userspace on Debian/Ubuntu,
Fedora/RHEL, Arch and openSUSE (family detected from `/etc/os-release`
`ID`/`ID_LIKE`). Run as root; review it first — it compiles and installs a
kernel.

```sh
sudo ./install/install.sh
```

It takes no positional arguments; a few environment variables tune it:

| Variable | Default | Effect |
|----------|---------|--------|
| `KVER` | `6.12.48` | Kernel.org 6.12 LTS point release to fetch and build. |
| `JOBS` | `nproc` | Parallel build jobs. |
| `BUILD_ROOT` | `/usr/src/secure_sudo-build` | Where the kernel is fetched and built (root-owned, never world-writable `/tmp`). |

What it does, in order: detect distro → install build deps → fetch kernel
`$KVER` → graft the LSM into `security/secure_sudo/` and register it in Kconfig
and the Makefile → configure (enable the LSM, add it to `CONFIG_LSM`, turn on
module signing) → build a removable distro package and install it → set
`module.sig_enforce=1` on the kernel command line → build and install the
userspace (CLI, PAM modules, daemon, OTP helper), install the `scripts/`
tools to `/usr/libexec/secure-sudo/`, generate `home_map.conf`, auto-detect
`admin_gid`, enable the daemon → print the manual PAM-wiring guidance. PAM is
**not** edited automatically, on purpose. Reboot into the new kernel to
activate the LSM.

## `install/encrypted/install-encrypted.sh`

Encrypted-source + Secure Boot variant. Decrypts an age-encrypted source
bundle into a tmpfs (RAM), builds there so the plaintext never touches disk,
signs the kernel and modules with an enrolled Machine Owner Key, and optionally
assembles a signed Unified Kernel Image. Run as root.

Prerequisites on the builder: `age`, `mokutil`, `sbsigntool` (sbsign), and for
the UKI `systemd-ukify`. Driven entirely by environment variables:

| Variable | Required? | Default | Effect |
|----------|-----------|---------|--------|
| `SRC_AGE` | **yes** | — | Path to `secure_sudo-src.tar.age`. |
| `AGE_IDENTITY` | **yes** | — | Path to the age private key. |
| `MOK_KEY` | no | `/var/lib/secure_sudo/mok/MOK.key` | MOK private key (generated if absent). |
| `MOK_CRT` | no | `/var/lib/secure_sudo/mok/MOK.der` | MOK certificate (generated if absent). |
| `MAKE_UKI` | no | `0` | `1` to also build+install a signed UKI. |
| `ESP` | no | `/boot/efi` | EFI system partition mount point. |
| `KVER` | no | `6.12.48` | Kernel version (passed through to `install.sh`). |

```sh
sudo SRC_AGE=secure_sudo-src.tar.age AGE_IDENTITY=~/key.txt \
     MAKE_UKI=1 ./install/encrypted/install-encrypted.sh
```

Enrolling a new MOK requires confirming at the MOK Manager screen on the next
reboot (you set a one-time password during the run). The tmpfs with the
plaintext source is unmounted (and so wiped) on exit.

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
* `lan-only` — allow only traffic to/from the auto-detected LAN subnet(s) on
  the default-route interface (plus loopback).
* `public-only` — drop traffic to/from those subnets.

It always deletes the old table first, so switching modes never leaves stale
rules. Multi-homed hosts may need the detected subnets tuned.

## `userspace/daemon/helpers/quarantine.sh`

Called by `secure-sudod` when TimeVault is engaged and a new or changed file
appears in a watched tree, if `vault_action=quarantine` (the default). Not run
by hand.

```
quarantine.sh <file>
```

It records the file's origin path, timestamp and SHA-256 in a `.meta` sidecar,
packages the file plus metadata into a timestamped zip under
`/var/lib/secure_sudo/quarantine/` (falling back to `tar.gz` if `zip` is
absent), then removes the original — a reversible "move" that preserves the
evidence a `wipe` would destroy. All filename handling uses `--` so an
attacker-chosen name cannot be read as an option.
