# Security log

Every security patch, hardening change, CVE remediation and accepted risk,
newest first (CLAUDE.MD section 5). Entries start on 2026-11-22. Earlier
findings, #1 to #75, are in [SECURITY_REVIEW.md](SECURITY_REVIEW.md), which
stays the detailed record. Each entry here points to it.

CVSS and EPSS scores are given only where a CVE exists. These are project
findings without CVE IDs, so none are given; no scores are invented.

## 2026-11-23 — nftables.service stop deleted secure_sudo's network-mode table
- **Type:** patch
- **CVE / CWE / advisory:** none; CWE-693 (protection mechanism failure)
- **Severity:** no CVSS (no CVE). Project rating: medium. `lan-only`/`public-only` were off for up to one daemon refresh (about 15 s) after every `systemctl restart nftables`. KEV: not applicable.
- **Affected:** hosts running Ubuntu 24.04's `nftables.service` (nftables 1.0.9-1ubuntu0.1) alongside secure_sudo network modes. Code: `scripts/cis-nftables.sh`, `scripts/stig-harden.sh`.
- **What changed:** a drop-in `nftables.service.d/secure-sudo-keep-tables.conf` replaces the vendor `ExecStop=nft flush ruleset` with a delete of only the CIS/conf tables (OSB-24).
- **Why it is secure now:** stopping or restarting the firewall service can no longer remove another component's boundary rules (NIST SC-7, CM-7).
- **Verification:** `tests/userspace/test-stig-patches.sh` (63 ok) and `tests/userspace/test-cis-firewall.sh` (29 ok). Both use real nft in network namespaces: the vendor stop deletes the table, the drop-in stop keeps it. Found by the CIS L2 VM run (`docs/vm/results/13-pc-cis-l2-2026-11-23/`). The VM re-check is pending. SECURITY_REVIEW #77, PR #59.

## 2026-11-23 — CIS firewall coexists with secure_sudo's table
- **Type:** hardening
- **CVE / CWE / advisory:** none
- **Severity:** not applicable
- **Affected:** `scripts/cis-nftables.sh` (new), `scripts/stig-harden.sh --cis-firewall`
- **What changed:** CIS's default-deny `inet filter` table is loaded next to `inet secure_sudo`. A packet must pass both, so the stricter rule wins. This replaces the blanket firewall `--skip-rules` workaround (OSB-16).
- **Why it is secure now:** the CIS nftables controls are applied instead of skipped, without weakening secure_sudo's modes (CIS Ubuntu 24.04 L2 section 4, NIST SC-7).
- **Verification:** `test-cis-firewall.sh` (real TCP between namespaces). The CIS L2 VM run had 441 pass, 9 fail (site decisions) and 0 error, and no firewall rule failed. PR #58.

## 2026-11-23 — stock nftables.conf "flush ruleset" deleted secure_sudo's table
- **Type:** patch
- **CVE / CWE / advisory:** none; CWE-693
- **Severity:** no CVSS (no CVE). Project rating: medium (same window as above, on every load of the file).
- **Affected:** hosts that load Ubuntu's stock `/etc/nftables.conf`; `scripts/stig-harden.sh`.
- **What changed:** post_patch rewrites `flush ruleset` to reset only the file's own tables. It checks the result with `nft -c` and restores the original on failure (OSB-23).
- **Why it is secure now:** loading the firewall file no longer removes other tables (NIST SC-7).
- **Verification:** `test-stig-patches.sh`, with real nft load in a namespace. SECURITY_REVIEW #76, PR #57.

## 2026-11-23 — build-gate record named a build directory instead of the sources
- **Type:** hardening (supply chain)
- **CVE / CWE / advisory:** none
- **Severity:** not applicable
- **Affected:** `ci/build-gate.sh`
- **What changed:** `source_tree_sha256` and the release package come from a pristine copy, so the same commit always gives the same hashes.
- **Why it is secure now:** a release can be rebuilt and matched to its recorded inputs (SLSA provenance, NIST SSDF PS.3, TODO P0-1/P0-4).
- **Verification:** two full gate runs on the owner's PC (main 4885cdc) gave identical tree and package hashes, equal to the clean checkout. PR #54.

## 2026-11-22 — repository stays private; reporting channel
- **Type:** accepted risk
- **CVE / CWE / advisory:** none
- **Severity:** not applicable
- **Affected:** SECURITY.md
- **What changed:** the owner chose to keep the repository private. GitHub private vulnerability reporting is unavailable, so reports go to the owner directly.
- **Why it is acceptable:** there are no outside users yet. Revisit when the repository goes public (NIST SSDF RV.1).
- **Verification:** the gh API returned 404 for private vulnerability reporting on the private repository. PR #50.
