# Notes (append-only)

## 2026-11-23T21:29:56+00:00 - note

The 2 failures (test-helpers.sh 52 and 54, quarantine tar fallback) are caused by this sandbox: its PATH starts with a wrapper that refuses rm, and the test links 'command -v rm' into its minimal PATH, so quarantine.sh gets exit 127. The same two fail on main 4b5474f/b2d4634 in this sandbox, and passed in the PC gate run 2026-11-23_133652Z_gate_4885cdc. Not caused by this change.
