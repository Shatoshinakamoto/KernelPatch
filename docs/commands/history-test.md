# `scripts/history_test.py`: the HistoryTest recorder

Archives test runs in `HistoryTest/` (rules: [HistoryTest/README.md](../../HistoryTest/README.md)).
Python 3 standard library only. It needs no privileges. Run it as an ordinary
user unless the command being recorded needs root.

```
history_test.py run        --area AREA [--commit SHA] [--title T] [--what TEXT|FILE] [--where W] [--timeout S] -- COMMAND [ARG...]
history_test.py add        --area AREA --commit SHA --title T --verdict V --where W --command-text TEXT|FILE
                           [--date ISO] [--what|--how|--results|--failures|--reproduce|--environment TEXT|FILE] [--file F]...
history_test.py note       RUN_ID --text TEXT
history_test.py invalidate RUN_ID --reason TEXT
history_test.py index
history_test.py verify
```

## Subcommands and options

| Subcommand | Option | Type / default | What it does | Security note |
|---|---|---|---|---|
| `run` | `--area` | `[a-z0-9-]`, 1 to 41 chars, required | Area name in the run id (for example `unit-stig`, `gate`, `vm-cis`). | Allow-listed so it cannot leave `HistoryTest/` (CWE-22). |
| | `--commit` | 7 to 12 hex chars, default `git rev-parse --short=7 HEAD` | Commit under test. | |
| | `--title` | text | Title of `RUN.md`. | Redacted. |
| | `--what` | text or file | "What was tested and why". | Redacted. |
| | `--where` | text, default `local` | Where it ran. | Do not put host names here; they are redacted anyway. |
| | `--timeout` | seconds, default 3600 | A hung command is stopped and recorded with exit 124. | Bounds resource use. |
| | `-- COMMAND...` | argument list | The command to run, from the repository root. | Executed without a shell (CWE-78). stdout/stderr are redacted before storage. |
| `add` | `--area`, `--commit`, `--title` | as above, all required | | |
| | `--verdict` | `pass`, `fail`, `partial`, `invalid` | Verdict of the received run. | |
| | `--where` | text, required | For example `owner PC (Docker, QEMU TCG)`. | |
| | `--date` | ISO 8601 UTC | When the run started (default: now). | |
| | `--command-text` | text or file, required | The commands the other machine ran. | Redacted. |
| | `--what`, `--how`, `--results`, `--failures`, `--reproduce`, `--environment` | text or file | Sections of `RUN.md` and `environment.md`. TAP lines in `--results` are counted. | Redacted. |
| | `--file` | path, repeatable | Text result file copied to `results/`. | Max 5 MB; binary files refused; redacted. |
| `note` | `RUN_ID`, `--text` | | Appends a dated entry to `NOTES.md` and chains it in `notes.json`. | Append-only; never changes sealed files. |
| `invalidate` | `RUN_ID`, `--reason` | | Writes `INVALID` and a note; the index shows `invalid`. | Append-only. |
| `index` | | | Regenerates `INDEX.csv` and the README table. | |
| `verify` | | | Recomputes every SHA-256 and manifest link, looks for files outside the manifest, rescans for unredacted data, checks required files and that the index is current. | NIST AU-10. Exit 1 on any problem; problems go to stderr as `not ok - ...`. |

## Environment

`SS_HISTORYTEST_DIR` overrides the archive location (tests use a throwaway
directory).

## Exit codes

`0` success (`run`: the command passed), `1` the recorded command failed or
`verify` found problems, `2` usage or refused input.

## Examples

```sh
# a local suite
python3 scripts/history_test.py run --area unit-stig -- bash tests/userspace/test-stig-patches.sh

# a VM run reported by the owner's PC
python3 scripts/history_test.py add --area vm-cis --commit e6aacc7 \
  --title "CIS Level 2 VM run" --verdict partial --where "owner PC (Docker, QEMU TCG)" \
  --date 2026-11-23T11:17:00Z --command-text cis-commands.txt --results cis-tap.txt

# a correction
python3 scripts/history_test.py note <run-id> --text "check 13 failed because of OSB-24, fixed in PR #59"

python3 scripts/history_test.py verify
```

Tests: `tests/userspace/test-history-test.sh`.
