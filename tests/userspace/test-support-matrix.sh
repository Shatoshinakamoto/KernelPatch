#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-support-matrix.sh - ci/check-support-matrix.py (TODO P3-1): the release
# fails when docs/SUPPORT.md is stale or dishonest, and passes for the real
# document.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
CHK="$ROOT/ci/check-support-matrix.py"
mk() { rm -rf "$T/r"; mkdir -p "$T/r/docs"; cp "$ROOT/VERSION" "$T/r/VERSION"; cp "$ROOT/docs/SUPPORT.md" "$T/r/docs/SUPPORT.md"; }
run() { python3 -B "$CHK" "$T/r" 2>&1; }

check "the real matrix passes for the real VERSION" python3 -B "$CHK" "$ROOT"
mk; echo 9.9.9 > "$T/r/VERSION"
refute_with "a matrix for another release than VERSION fails" 'is for release' python3 -B "$CHK" "$T/r"
mk; sed -i 's/^Matrix reviewed:.*/Matrix reviewed: soon/' "$T/r/docs/SUPPORT.md"
refute_with "a review date that is not a date fails" "no valid 'Matrix reviewed" python3 -B "$CHK" "$T/r"
mk; sed -i '0,/| expected |/s/| expected |/| works-fine |/' "$T/r/docs/SUPPORT.md"
refute_with "an invented status fails" "is not one of" python3 -B "$CHK" "$T/r"
mk; python3 - "$T/r/docs/SUPPORT.md" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
# strip every date from the first tested row
lines = s.splitlines(); out = []; done = False
for ln in lines:
    if not done and ln.startswith("|") and "| tested |" in ln:
        ln = re.sub(r"\d{4}-\d\d-\d\d", "recently", ln); done = True
    out.append(ln)
open(p, "w").write("\n".join(out) + "\n")
PY
refute_with "a tested row without a date fails" "must name the date" python3 -B "$CHK" "$T/r"
mk; sed -i '/^## 5\. End-of-support policy/d' "$T/r/docs/SUPPORT.md"
refute_with "a matrix without the end-of-support section fails" "missing section" python3 -B "$CHK" "$T/r"
tap_done
