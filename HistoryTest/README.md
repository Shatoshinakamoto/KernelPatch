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
   `runs/<YYYY-MM-DD>_<HHMMSS>Z_<area>_<short-commit>/`.
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
<!-- history-test:index:end -->
