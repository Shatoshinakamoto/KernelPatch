# Changelog

All notable changes, newest first ([Keep a Changelog](https://keepachangelog.com)).
Entries start on 2026-11-22. For earlier history see the git log and
[SECURITY_REVIEW.md](SECURITY_REVIEW.md). Test evidence for each entry is in
[HistoryTest/](../HistoryTest/README.md) or in `docs/vm/results/`.

## [Unreleased]

### Added
- 2026-11-23: `HistoryTest/` test-run archive with the recorder `scripts/history_test.py` (run, add, note, invalidate, index, verify). Its integrity is checked in the build gate's lint stage. Also added: `docs/README.md`, this changelog and `docs/SECURITY-LOG.md` (CLAUDE.MD).
- 2026-11-23: `scripts/cis-nftables.sh` and `stig-harden.sh --cis-firewall [--allow-tcp P]`: CIS's own nftables table next to secure_sudo's (owner's choice: coexist) (#58).
- 2026-11-23: regression tests for the STIG known-issue patches, profile and datastream selection, the summary, OSB-15, OSB-18 and package-install drift (#51, #52, #55, #56).
- 2026-11-22: `ci/publish-release.sh`: GitHub Releases are built locally and uploaded with `gh`, as drafts unless `--publish` is given (#49).

### Fixed
- 2026-11-23: `systemctl restart nftables` deleted secure_sudo's network-mode table (vendor `ExecStop=nft flush ruleset`). Fixed with a drop-in, OSB-24 (#59).
- 2026-11-23: the stock `/etc/nftables.conf` `flush ruleset` deleted secure_sudo's table on every load. It now resets only its own tables, OSB-23 (#57).
- 2026-11-23: the build-gate record's `source_tree_sha256` and package came from the gate's build directory. They now come from a pristine copy. Header trees older than 6.11 are reported as unsupported instead of failing the gate (#54).
- 2026-11-23: network-namespace tests skip instead of falsely failing without `ping`, and the builder prerequisites are documented (#53).

### Changed
- 2026-11-23: `stig-harden.sh` post_patch honours a `STIG_ROOT` test hook, which is empty by default (#51, #55).
- 2026-11-22: the docs no longer list GitHub Actions as a blocker. The project builds and tests locally (#48). SECURITY.md says reports go to the owner while the repository is private (#50).
