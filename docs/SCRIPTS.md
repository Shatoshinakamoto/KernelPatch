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

Each script has its own page under [commands/](commands/), with every flag
and example.

| Script | What it does |
|---|---|
| [`scripts/timevault-whitelist.sh`](commands/timevault-whitelist.md) | Manage the TimeVault exec allowlist with nothing but bash, coreutils and findutils. |
| [`scripts/detect-admin-gids.sh`](commands/detect-admin-gids.md) | Print every admin-group GID on the box as a comma list (used by the installer and `secure-sudo detect-admins`). |
| [`scripts/cis-nftables.sh`](commands/cis-nftables.md) | Install or check CIS's own firewall table, `inet filter`, next to secure_sudo's `inet secure_sudo` (they coexist). |
| [`scripts/stig-harden.sh`](commands/stig-harden.md) | Run a DISA STIG (or the closest hardening baseline the distro actually ships) OpenSCAP evaluation on the host, and optionally apply the generated remediation. |
| [`install/install.sh`](commands/install-sh.md) | Build, install, verify, roll back and remove the secure_sudo kernel and userspace on Debian/Ubuntu, Fedora/RHEL, Arch and openSUSE (family from `/etc/os-release` `ID`/`ID_LIKE`). |
| [`install/encrypted/install-encrypted.sh`](commands/install-encrypted.md) | Encrypted-source + Secure Boot variant. |
| [`scripts/oscap-results.py`](commands/oscap-results.md) | Reads OpenSCAP results (XCCDF/ARF XML, or saved `oscap xccdf eval` console output with its `\r` rewrites) and is what `stig-harden.sh` and the STIG gate use to count and compare results. |
| [`userspace/daemon/helpers/apply-net.sh`](commands/apply-net.md) | Called by `secure-sudod` when `net_mode` changes and every 15 seconds after (not run by hand, except `status`). |
| [`userspace/daemon/helpers/quarantine.sh`](commands/quarantine-sh.md) | Called by `secure-sudod` in two cases, both when `vault_action=quarantine` (the default). |
| [`userspace/daemon/helpers/evidence-export.sh`](commands/evidence-export-sh.md) | Invoked by `sudo secure-sudo evidence-export OUTPUT.tar.gz` to create a root-only incident bundle. |
| [`userspace/daemon/helpers/evidence-verify.py`](commands/evidence-verify-py.md) | Invoked by `secure-sudo evidence-verify ARCHIVE.tar.gz [--trusted-key PUBLIC.pem] [--checkpoints COLLECTOR.log]`. |
| [`userspace/attest/` (remote attestation, P2-1)](commands/attest-tools.md) | The attestation programs: the host-side TPM quote tool and report builder, and the verifier. |

## `ci/` — build gate and release

| Script | What it does |
|---|---|
| `ci/build-gate.sh [--stages …] [--kernel-tree DIR] [--headers DIR]… [--headers-direct DIR]… [--record FILE]` | The release gate, in a scratch copy of the tree: `lint` (bash -n, shellcheck, py_compile, duplicate-hook check), `userspace` and `addons` (`-Werror`), `lsm-headers` (LSM against installed or downloaded header trees), `lsm-tree` (in-tree build per `ci/kconfig/*.config` variant), `tests` (`tests/run-all.sh`), `package` (release tarball built twice, compared). Writes a record with compiler, tree hash, kernel tree, per-variant config hashes and each stage's result |
| `ci/make-release.sh [--out DIR]` | Reproducible release tarball + `.sha256` + SPDX SBOM |
| `ci/publish-release.sh --notes FILE [--sign KEYID] [--publish]` | Build locally and create a GitHub Release with `gh` (a draft unless `--publish`) with the archive, checksum, SBOM and optional signature |
| `ci/check-command-docs.py ROOT` | Fails if a `secure-sudo` subcommand, a script, a helper or an add-on binary has no `docs/commands/` page, a page's copied header drifted from its script, a `docs/features/` page lacks a required section, or a page is not linked from `docs/README.md` (gate lint stage; tested by `tests/userspace/test-command-docs.sh`) |
| `ci/graft-lsm.sh TREE` | Copy the LSM into a kernel tree and register it (Kconfig, Makefile, `lsm_count.h`) |
| `ci/lsm-compile-check.sh` | Compile every LSM file against a header tree (`--mode kbuild\|direct`) |
| `ci/check-lsm-hooks.sh` | Fails if any LSM hook is registered twice (the v11 boot panic) |
| `ci/check-config-docs.py ROOT` | Fails if `docs/configuration/` or `docs/files/` drifts from the code (core and `temporary/` add-on configs): a key with no row or an unknown row, a built-in default that differs from `ss_core.c` or `apply-net.sh`, a shipped value that differs from the template, a policy list with no `docs/files/` page, a wrong list limit, a shipped list entry with no row, or a page not linked from `docs/README.md` (gate lint stage; tested by `tests/userspace/test-config-docs.sh`) |

Tools the gate's tests expect on a bare Ubuntu builder (the runner image had them preinstalled): `zip unzip nftables iptables iproute2 iputils-ping netcat-openbsd swtpm swtpm-tools tpm2-tools libtss2-tcti-swtpm0t64`, plus the build packages in `.github/workflows/build-gate.yml`. Run the `tests` stage as root. The network-namespace suites skip, rather than fail, when `ping` is missing. The record's `source_tree_sha256` and the release package come from a pristine copy of the checkout that no stage builds in, so they are the same for the same commit (the gate's own copy used to leak build output into both, found on 2026-11-23). Auto-discovered `/usr/src/linux-headers-*-generic` trees older than 6.11 (unsupported, see SUPPORT.md; 6.8 has no BPF-token hooks) are reported and not compiled; headers named with `--headers` are always compiled.

The GitHub workflow `.github/workflows/build-gate.yml` runs the gate on every
push and pull request and nightly. Weekly (Sunday) and on demand it also
runs two VM jobs after the gate: `kernel-boot` (6.12.114 with secure_sudo,
the in-kernel tests as PID 1) and `distro-vm` (the distro install scenario,
then the STIG release gate in a fresh guest). A manual run's `vm` input picks
`all`, `kernel-boot` or `distro-vm`.

## `tests/`

`tests/run-all.sh` runs every host suite (TAP). The distro VM tests are in
`tests/vm/distro/` ([README](../tests/vm/distro/README.md)); the initramfs
LSM boot test is `tests/vm/boot-test.sh`.

---

