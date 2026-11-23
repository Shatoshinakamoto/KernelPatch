# Notes (append-only)

## 2026-11-23T22:09:59+00:00 - note

The 2 failures are test-helpers.sh 52 and 54 only: this container puts a harness rm-guard wrapper first in PATH, so the tar fallback's rm returns 127. Same on main (see note on 2026-11-23_212221Z_suite_cc21580). Every other suite passes, including the new test-addon-log-tls.sh (20/0) and test-addons.sh (163/0).
