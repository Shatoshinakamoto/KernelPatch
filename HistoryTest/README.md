# HistoryTest: the test-run archive

Every test run of this project is archived here so that anyone can review,
verify and reproduce it (CLAUDE.MD section 9). That covers unit and
integration suites, the build gate, VM runs on the owner's PC, security scans
and manual checks, whether they passed, failed, aborted, were flaky or turned
out invalid.

This is a **development record, not a product feature**. It is never shipped:
`scripts/gen-sbom.sh` (the release file list) excludes `HistoryTest/`, so
release archives, packages and the installer never contain it.

## Rules

1. **Use the recorder**, `scripts/history_test.py`
   ([docs/commands/history-test.md](../docs/commands/history-test.md)). Never
   create or edit run folders by hand.
2. **Every run gets a folder:**
   `runs/<YYYY-MM-DD>_<HHMMSS>Z_<area>_<short-commit>/`, named by the time it
   was archived. For a run received from elsewhere, the time it actually ran
   is in `RUN.md` and the index.
3. **`RUN.md` is required.** It says what was tested and why, how, the
   results, the failures, the verdict (`pass | fail | partial | invalid`) and
   how to reproduce.
4. **Redact.** The recorder replaces e-mail addresses, home-directory user
   names, this host's name, RFC 1918 addresses and common token formats
   before writing (CWE-532, CWE-200, NIST AU-9). Run `python3
   scripts/history_test.py verify`, and `gitleaks detect --no-git --source
   HistoryTest/runs/<run>` where gitleaks is installed, before every commit.
5. **Append-only.** Past runs are never rewritten. Corrections are dated
   notes (`note`) or a new run. Unreliable results are marked `invalid`
   (`invalidate`) with the reason.
6. **Integrity (NIST AU-10).** `manifest.json` holds the SHA-256 of every file
   in the run and the SHA-256 of the previous run's manifest. `NOTES.md`,
   `notes.json` and `INVALID` are the only files that may be added later, and
   `notes.json` chains them. The build gate's lint stage runs `verify`.
7. **Generated index.** `INDEX.csv` and the table below are written by
   `history_test.py index` (also after every `run`, `add` and
   `invalidate`). Never edit them by hand.
8. **Size.** No model weights, images, VM disks, keys, `node_modules`,
   virtualenvs or caches. Text files up to 5 MB only. Binary files are
   refused; record their name and digest in `RUN.md` instead.
9. **Every report of test results links its run folder.**

## Folder layout

```
runs/<run-id>/
  RUN.md            required summary (template below)
  manifest.json     SHA-256 of every file + link to the previous manifest
  command.txt       the exact command(s)
  environment.md    OS, kernel, CPU count, Python (no host or user names)
  results/          TAP summaries, scanner tallies, received result files
  logs/             stdout.log, stderr.log
  projects/input/   inputs the run used (optional)
  projects/output/  outputs it produced (optional)
  artifacts/        anything else small and textual
  NOTES.md          dated, append-only notes (optional)
  INVALID           present only when the run was marked invalid
```

## RUN.md template

```
# <title>

- **Run id:** `<run-id>`
- **Area:** <area>
- **Commit:** `<short commit>`
- **Date (UTC):** <ISO 8601>
- **Where:** <local | owner PC (Docker, QEMU TCG) | ...>
- **Verdict:** **pass | fail | partial | invalid**

## What was tested and why
## How
## Results
## Failures
## Reproduce
```

Runs received from elsewhere (for example the owner's PC) are archived with
`history_test.py add`, from the report that machine sent. When the raw logs
stay on that machine, `RUN.md` says where they are kept.

## Runs

<!-- history-test:index:begin -->
| Run | Date (UTC) | Area | Commit | Verdict | Where | ok / not ok / skipped |
|---|---|---|---|---|---|---|
| [`2026-11-23_215528Z_gate_aaffc26`](runs/2026-11-23_215528Z_gate_aaffc26/RUN.md) | 2026-11-23T21:55:27+00:00 | gate | `aaffc26` | **pass** | Pheonix's PC, Docker container on WSL2, QEMU TCG (no KVM) | 0 / 0 / 0 |
| [`2026-11-23_215527Z_vm-functest_aaffc26`](runs/2026-11-23_215527Z_vm-functest_aaffc26/RUN.md) | 2026-11-23T21:55:27+00:00 | vm-functest | `aaffc26` | **pass** | Pheonix's PC, Docker container on WSL2, QEMU TCG (no KVM) | 0 / 0 / 0 |
| [`2026-11-23_214119Z_gate-lint_e82717f`](runs/2026-11-23_214119Z_gate-lint_e82717f/RUN.md) | 2026-11-23T21:41:19+00:00 | gate-lint | `e82717f` | **pass** | cloud container (Ubuntu) | 1 / 0 / 0 |
| [`2026-11-23_214105Z_lsm-compile_e82717f`](runs/2026-11-23_214105Z_lsm-compile_e82717f/RUN.md) | 2026-11-23T21:41:05+00:00 | lsm-compile | `e82717f` | **pass** | cloud container (Ubuntu), linux-headers-6.17.0-42-generic from the Ubuntu archive | 0 / 0 / 0 |
| [`2026-11-23_214051Z_lsm-compile_e82717f`](runs/2026-11-23_214051Z_lsm-compile_e82717f/RUN.md) | 2026-11-23T21:40:51+00:00 | lsm-compile | `e82717f` | **pass** | cloud container (Ubuntu), linux-headers-6.14.0-37-generic from the Ubuntu archive | 0 / 0 / 0 |
| [`2026-11-23_213829Z_unit-cis-firewall_d457f1f`](runs/2026-11-23_213829Z_unit-cis-firewall_d457f1f/RUN.md) | 2026-11-23T21:38:29+00:00 | unit-cis-firewall | `d457f1f` | **pass** | cloud container (Ubuntu), as root | 29 / 0 / 0 |
| [`2026-11-23_213828Z_gate_4b5474f`](runs/2026-11-23_213828Z_gate_4b5474f/RUN.md) | 2026-11-23T21:38:28+00:00 | gate | `4b5474f` | **fail** | Pheonix's PC, Docker container on WSL2 (QEMU TCG for VM stages) | 0 / 0 / 0 |
| [`2026-11-23_213450Z_gate-lint_4b76813`](runs/2026-11-23_213450Z_gate-lint_4b76813/RUN.md) | 2026-11-23T21:34:50+00:00 | gate-lint | `4b76813` | **pass** | cloud container (Ubuntu) | 1 / 0 / 0 |
| [`2026-11-23_213440Z_unit-config-docs_4b76813`](runs/2026-11-23_213440Z_unit-config-docs_4b76813/RUN.md) | 2026-11-23T21:34:40+00:00 | unit-config-docs | `4b76813` | **pass** | cloud container (Ubuntu) | 25 / 0 / 0 |
| [`2026-11-23_213003Z_gate-lint_cc21580`](runs/2026-11-23_213003Z_gate-lint_cc21580/RUN.md) | 2026-11-23T21:30:03+00:00 | gate-lint | `cc21580` | **pass** | cloud container (Ubuntu) | 1 / 0 / 0 |
| [`2026-11-23_212221Z_suite_cc21580`](runs/2026-11-23_212221Z_suite_cc21580/RUN.md) | 2026-11-23T21:22:21+00:00 | suite | `cc21580` | **fail** | cloud container (Ubuntu); this sandbox puts a refusing rm wrapper first in PATH | 1349 / 2 / 6 |
| [`2026-11-23_212216Z_unit-config-docs_cc21580`](runs/2026-11-23_212216Z_unit-config-docs_cc21580/RUN.md) | 2026-11-23T21:22:16+00:00 | unit-config-docs | `cc21580` | **pass** | cloud container (Ubuntu) | 20 / 0 / 0 |
| [`2026-11-23_212209Z_unit-cli_cc21580`](runs/2026-11-23_212209Z_unit-cli_cc21580/RUN.md) | 2026-11-23T21:22:09+00:00 | unit-cli | `cc21580` | **pass** | cloud container (Ubuntu) | 180 / 0 / 0 |
| [`2026-11-23_211112Z_gate-lint_6544e45`](runs/2026-11-23_211112Z_gate-lint_6544e45/RUN.md) | 2026-11-23T21:11:12+00:00 | gate-lint | `6544e45` | **pass** | cloud container (Ubuntu) | 1 / 0 / 0 |
| [`2026-11-23_211103Z_unit-pheonixbox_6544e45`](runs/2026-11-23_211103Z_unit-pheonixbox_6544e45/RUN.md) | 2026-11-23T21:11:03+00:00 | unit-pheonixbox | `6544e45` | **pass** | cloud container (Ubuntu), no root kernel | 61 / 0 / 2 |
| [`2026-11-23_211056Z_unit-cli_6544e45`](runs/2026-11-23_211056Z_unit-cli_6544e45/RUN.md) | 2026-11-23T21:10:56+00:00 | unit-cli | `6544e45` | **pass** | cloud container (Ubuntu), no root kernel | 169 / 0 / 0 |
| [`2026-11-23_211054Z_unit-config-docs_6544e45`](runs/2026-11-23_211054Z_unit-config-docs_6544e45/RUN.md) | 2026-11-23T21:10:54+00:00 | unit-config-docs | `6544e45` | **pass** | cloud container (Ubuntu), no root kernel | 14 / 0 / 0 |
| [`2026-11-23_134551Z_vm-osb24_8d432e8`](runs/2026-11-23_134551Z_vm-osb24_8d432e8/RUN.md) | 2026-11-23T13:45:51+00:00 | vm-osb24 | `8d432e8` | **pass** | PC Docker container (QEMU TCG, no KVM), Ubuntu 24.04 guest | 0 / 0 / 0 |
| [`2026-11-23_133808Z_gate-lint_24d1c85`](runs/2026-11-23_133808Z_gate-lint_24d1c85/RUN.md) | 2026-11-23T13:38:08+00:00 | gate-lint | `24d1c85` | **pass** | cloud container (Ubuntu 24.04, root, no KVM) | 1 / 0 / 0 |
| [`2026-11-23_133728Z_unit-history-test_3ff68f6`](runs/2026-11-23_133728Z_unit-history-test_3ff68f6/RUN.md) | 2026-11-23T13:37:27+00:00 | unit-history-test | `3ff68f6` | **pass** | cloud container (Ubuntu 24.04, root, no KVM) | 45 / 0 / 0 |
| [`2026-11-23_133727Z_vm-cis_e6aacc7`](runs/2026-11-23_133727Z_vm-cis_e6aacc7/RUN.md) | 2026-11-23T11:17:00+00:00 | vm-cis | `e6aacc7` | **partial** | owner PC (Docker, QEMU TCG) | 15 / 2 / 0 |
| [`2026-11-23_133726Z_vm-regression_4885cdc`](runs/2026-11-23_133726Z_vm-regression_4885cdc/RUN.md) | 2026-11-23T07:55:00+00:00 | vm-regression | `4885cdc` | **pass** | owner PC (Docker, QEMU TCG) | 0 / 0 / 0 |
| [`2026-11-23_133652Z_gate_4885cdc`](runs/2026-11-23_133652Z_gate_4885cdc/RUN.md) | 2026-11-23T03:44:30+00:00 | gate | `4885cdc` | **pass** | owner PC (Docker, kp-vm) | 0 / 0 / 0 |
| [`2026-11-23_133555Z_unit-stig-selection_3ff68f6`](runs/2026-11-23_133555Z_unit-stig-selection_3ff68f6/RUN.md) | 2026-11-23T13:35:55+00:00 | unit-stig-selection | `3ff68f6` | **pass** | cloud container (Ubuntu 24.04, root, no KVM) | 23 / 0 / 0 |
| [`2026-11-23_133548Z_unit-cis-firewall_3ff68f6`](runs/2026-11-23_133548Z_unit-cis-firewall_3ff68f6/RUN.md) | 2026-11-23T13:35:48+00:00 | unit-cis-firewall | `3ff68f6` | **pass** | cloud container (Ubuntu 24.04, root, no KVM) | 29 / 0 / 0 |
| [`2026-11-23_133547Z_unit-stig-patches_3ff68f6`](runs/2026-11-23_133547Z_unit-stig-patches_3ff68f6/RUN.md) | 2026-11-23T13:35:47+00:00 | unit-stig-patches | `3ff68f6` | **pass** | cloud container (Ubuntu 24.04, root, no KVM) | 63 / 0 / 0 |
| [`2026-11-23_133545Z_unit-history-test_3ff68f6`](runs/2026-11-23_133545Z_unit-history-test_3ff68f6/RUN.md) | 2026-11-23T13:35:45+00:00 | unit-history-test | `3ff68f6` | **pass** | cloud container (Ubuntu 24.04, root, no KVM) | 44 / 0 / 0 |
<!-- history-test:index:end -->
