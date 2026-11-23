# Changelog

All notable changes, newest first ([Keep a Changelog](https://keepachangelog.com)).
Entries start on 2026-11-22. For earlier history see the git log and
[SECURITY_REVIEW.md](SECURITY_REVIEW.md). Test evidence for each entry is in
[HistoryTest/](../HistoryTest/README.md) or in `docs/vm/results/`.

## [Unreleased]

### Added
- 2026-11-23: configuration pages for the nine `temporary/` add-on config files and the ProcGuard allowlist (`docs/configuration/*-conf.md`, `docs/files/procguard_allow.md`). `ci/check-config-docs.py` now also checks them against each add-on's parser table and template. Found while writing them: add-on log shipping has no TLS (tracked in TODO P2-3).
- 2026-11-23: `docs/files/` pages for all 12 policy lists: format, matching, kernel limits, how to change safely, security impact, NIST reference and every shipped entry with why, who and when (with the two TPM openers removed on 2026-11-01). `ci/check-config-docs.py` now holds them to the templates and kernel limits.
- 2026-11-23: `docs/configuration/` pages for `secure-sudo.conf`, `net.conf` and `pheonixbox.conf`: every key's type, allowed values, built-in and shipped value, security impact and NIST reference. `ci/check-config-docs.py` keeps them in step with the code in the gate's lint stage.
- 2026-11-23: `HistoryTest/` test-run archive with the recorder `scripts/history_test.py` (run, add, note, invalidate, index, verify). Its integrity is checked in the build gate's lint stage. Also added: `docs/README.md`, this changelog and `docs/SECURITY-LOG.md` (CLAUDE.MD).
- 2026-11-23: `scripts/cis-nftables.sh` and `stig-harden.sh --cis-firewall [--allow-tcp P]`: CIS's own nftables table next to secure_sudo's (owner's choice: coexist) (#58).
- 2026-11-23: regression tests for the STIG known-issue patches, profile and datastream selection, the summary, OSB-15, OSB-18 and package-install drift (#51, #52, #55, #56).
- 2026-11-22: `ci/publish-release.sh`: GitHub Releases are built locally and uploaded with `gh`, as drafts unless `--publish` is given (#49).

### Fixed
- 2026-11-23: `secure-sudo lint` accepted `timevault_allow.conf` lines the kernel refuses (a bare path, a bad hash, a duplicate path, more entries than `timevault_max_entries`), so `load` passed lint and then the whole allowlist write failed. It also rejected the absolute paths `node_allowed_children.conf` supports, and did not notice lists longer than the kernel reads: the kernel stops reading most lists at its limit without an error, so a long `blacklist.conf` silently lost entries. Lint now checks all of these, and the `timevault_allow.conf` and `node_allowed_children.conf` templates describe the real format.
- 2026-11-23: the `secure-sudo.conf` template put comments after example values (`# vault_action = quarantine  # quarantine | wipe`). Neither parser strips a trailing comment, so uncommenting such a line gave an invalid value. The comments are now on their own lines. `pheonixbox.conf` now documents its `trust` key.
- 2026-11-23: `systemctl restart nftables` deleted secure_sudo's network-mode table (vendor `ExecStop=nft flush ruleset`). Fixed with a drop-in, OSB-24 (#59). VM-verified 21/21 (`HistoryTest/runs/2026-11-23_134551Z_vm-osb24_8d432e8/`).
- 2026-11-23: the stock `/etc/nftables.conf` `flush ruleset` deleted secure_sudo's table on every load. It now resets only its own tables, OSB-23 (#57).
- 2026-11-23: the build-gate record's `source_tree_sha256` and package came from the gate's build directory. They now come from a pristine copy. Header trees older than 6.11 are reported as unsupported instead of failing the gate (#54).
- 2026-11-23: network-namespace tests skip instead of falsely failing without `ping`, and the builder prerequisites are documented (#53).

### Changed
- 2026-11-23: `stig-harden.sh` post_patch honours a `STIG_ROOT` test hook, which is empty by default (#51, #55).
- 2026-11-22: the docs no longer list GitHub Actions as a blocker. The project builds and tests locally (#48). SECURITY.md says reports go to the owner while the repository is private (#50).
