# Changelog

All notable changes, newest first ([Keep a Changelog](https://keepachangelog.com)).
Entries start on 2026-11-22. For earlier history see the git log and
[SECURITY_REVIEW.md](SECURITY_REVIEW.md). Test evidence for each entry is in
[HistoryTest/](../HistoryTest/README.md) or in `docs/vm/results/`.

## [Unreleased]

### Added
- 2026-11-24: `docs/INSTALL.md`, the installation guide: six methods (guided quick install, step by step, build once for many machines, Ansible for fleets, Secure Boot with an encrypted source bundle, offline), verifying a release, post-install checks, add-ons and hardening, rollback and removal, troubleshooting, and how each step is secured.
- 2026-11-24: `install/quick-install.sh`: verifies a release archive (SHA-256, optional signature by a pinned fingerprint, refuses unsafe members), runs the preflight, asks, then runs `install.sh`. It never downloads code. Reference `docs/commands/quick-install.md`; tests `tests/install/test-quick-install.sh` (37/0).
- 2026-11-24: Ansible role `install/ansible/roles/secure_sudo/`: one host at a time, stops at the first failure, target-side SHA-256 check, preflight, prebuilt or per-host kernel, trial reboot, commit only on the secure_sudo kernel, `lint` before `load`, idempotent on committed hosts. Variables in `docs/configuration/ansible-vars.md`; tests `tests/install/test-ansible.sh` (25/0).
- 2026-11-23: TLS log shipping for the `temporary/` add-ons: `logging.conf` `remote_proto = tls` and `remote_ca_file`. The collector's certificate must come from that CA and name `remote_host`; an outage is noted in the local log and retried every 30 s (SECURITY_REVIEW #79). New suite `tests/userspace/test-addon-log-tls.sh`. The add-ons now link `libssl`.
- 2026-11-23: configuration pages for the nine `temporary/` add-on config files and the ProcGuard allowlist (`docs/configuration/*-conf.md`, `docs/files/procguard_allow.md`). `ci/check-config-docs.py` now also checks them against each add-on's parser table and template. Found while writing them: add-on log shipping has no TLS (tracked in TODO P2-3).
- 2026-11-23: `docs/files/` pages for all 12 policy lists: format, matching, kernel limits, how to change safely, security impact, NIST reference and every shipped entry with why, who and when (with the two TPM openers removed on 2026-11-01). `ci/check-config-docs.py` now holds them to the templates and kernel limits.
- 2026-11-23: `docs/configuration/` pages for `secure-sudo.conf`, `net.conf` and `pheonixbox.conf`: every key's type, allowed values, built-in and shipped value, security impact and NIST reference. `ci/check-config-docs.py` keeps them in step with the code in the gate's lint stage.
- 2026-11-23: `HistoryTest/` test-run archive with the recorder `scripts/history_test.py` (run, add, note, invalidate, index, verify). Its integrity is checked in the build gate's lint stage. Also added: `docs/README.md`, this changelog and `docs/SECURITY-LOG.md` (CLAUDE.MD).
- 2026-11-23: `scripts/cis-nftables.sh` and `stig-harden.sh --cis-firewall [--allow-tcp P]`: CIS's own nftables table next to secure_sudo's (owner's choice: coexist) (#58).
- 2026-11-23: regression tests for the STIG known-issue patches, profile and datastream selection, the summary, OSB-15, OSB-18 and package-install drift (#51, #52, #55, #56).
- 2026-11-22: `ci/publish-release.sh`: GitHub Releases are built locally and uploaded with `gh`, as drafts unless `--publish` is given (#49).

### Changed
- 2026-11-24: `install/ansible/secure_sudo.yml` is now a play using that role. The old single play pinned kernel 6.12.48, ran the whole installer without a trial reboot or commit, and ignored failures of the policy load and the service; its example inventory had an active `localhost ansible_connection=local` entry, so running it unedited targeted the controller. The new example inventory lists no host.
- 2026-11-24: `scripts/gen-sbom.sh` leaves an operator's `install/ansible/inventory.ini`, `group_vars/secure_sudo.yml` and `host_vars/` out of the tree hash and the release archive (they name real hosts); `.gitignore` lists them.
- 2026-11-24: the owner confirmed the disclosure and support policies: the response targets in `SECURITY.md` and `docs/MAINTENANCE.md` and the end-of-support policy in `docs/SUPPORT.md` are no longer marked proposed. `SECURITY.md` now names GitHub private vulnerability reporting as the only channel, for the repository going public. `docs/SUPPORT.md` cites the 2026-11-23 PC runs (in-kernel 305/0, install 71/71, STIG gate 16/16, add-ons 22/22, CIS Level 2) and says no hardware run is recorded yet.
- 2026-11-23: `stig-harden.sh` post_patch honours a `STIG_ROOT` test hook, which is empty by default (#51, #55).
- 2026-11-22: the docs no longer list GitHub Actions as a blocker. The project builds and tests locally (#48). SECURITY.md says reports go to the owner while the repository is private (#50).

### Fixed
- 2026-11-23: an add-on shipping logs over `tcp` never reconnected, so after the collector restarted no more lines left the host until the add-on itself restarted. `tcp` and `tls` now reconnect before the next line (SECURITY_REVIEW #79).
- 2026-11-23: the kernel silently stopped reading ten policy lists at its entry limit, so entries past it (for example the 1025th blacklist path) were not enforced. Each list write now fails with `E2BIG` and keeps the loaded list (SECURITY_REVIEW #78). The blacklist page now describes its content match correctly.
- 2026-11-23: `test-cis-firewall.sh` check 8 failed when the build gate ran as root, because uid 65534 could not read the script inside the gate's 0700 scratch copy. The check now runs a readable copy. Found by the PC gate on 4b5474f (`HistoryTest/runs/2026-11-23_213828Z_gate_4b5474f/`), fixed run `HistoryTest/runs/2026-11-23_213829Z_unit-cis-firewall_d457f1f/` (29/0).
- 2026-11-23: `secure-sudo lint` accepted `timevault_allow.conf` lines the kernel refuses (a bare path, a bad hash, a duplicate path, more entries than `timevault_max_entries`), so `load` passed lint and then the whole allowlist write failed. It also rejected the absolute paths `node_allowed_children.conf` supports, and did not notice lists longer than the kernel reads: the kernel stops reading most lists at its limit without an error, so a long `blacklist.conf` silently lost entries. Lint now checks all of these, and the `timevault_allow.conf` and `node_allowed_children.conf` templates describe the real format.
- 2026-11-23: the `secure-sudo.conf` template put comments after example values (`# vault_action = quarantine  # quarantine | wipe`). Neither parser strips a trailing comment, so uncommenting such a line gave an invalid value. The comments are now on their own lines. `pheonixbox.conf` now documents its `trust` key.
- 2026-11-23: `systemctl restart nftables` deleted secure_sudo's network-mode table (vendor `ExecStop=nft flush ruleset`). Fixed with a drop-in, OSB-24 (#59). VM-verified 21/21 (`HistoryTest/runs/2026-11-23_134551Z_vm-osb24_8d432e8/`).
- 2026-11-23: the stock `/etc/nftables.conf` `flush ruleset` deleted secure_sudo's table on every load. It now resets only its own tables, OSB-23 (#57).
- 2026-11-23: the build-gate record's `source_tree_sha256` and package came from the gate's build directory. They now come from a pristine copy. Header trees older than 6.11 are reported as unsupported instead of failing the gate (#54).
- 2026-11-23: network-namespace tests skip instead of falsely failing without `ping`, and the builder prerequisites are documented (#53).
