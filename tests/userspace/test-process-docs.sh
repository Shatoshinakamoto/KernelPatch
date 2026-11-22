#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-process-docs.sh - ci/check-process-docs.py (TODO P3-3): the disclosure
# and maintenance process documents pass as shipped and fail when a part of the
# process is removed.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
CHK="$ROOT/ci/check-process-docs.py"
mk() { # a copy of the files the checker reads
	rm -rf "$T/r"; mkdir -p "$T/r"
	(cd "$ROOT" && cp -r --parents SECURITY.md docs/MAINTENANCE.md docs/SUPPORT.md docs/RECOVERY.md docs/THREAT_MODEL.md \
		ci/build-gate.sh ci/make-release.sh ci/release-epoch ci/lsm-compile-check.sh ci/check-support-matrix.py \
		install/keys/release-signers.txt "$T/r/")
}
check "the shipped process documents pass" python3 -B "$CHK" "$ROOT"
mk; sed -i '/^## Reporting a vulnerability/d' "$T/r/SECURITY.md"
refute_with "a SECURITY.md without the reporting section fails" "lacks the reporting section" python3 -B "$CHK" "$T/r"
mk; sed -i 's/[0-9]* days/a while/g' "$T/r/SECURITY.md"
refute_with "no response time in days fails" "no response time" python3 -B "$CHK" "$T/r"
mk; sed -i '/^## 4\. Dependency updates/d' "$T/r/docs/MAINTENANCE.md"
refute_with "a maintenance process without dependency updates fails" "lacks '## 4" python3 -B "$CHK" "$T/r"
mk; rm "$T/r/docs/SUPPORT.md"
refute_with "a link to a file that is gone fails" "does not exist" python3 -B "$CHK" "$T/r"
mk; rm "$T/r/SECURITY.md"
refute_with "a missing SECURITY.md fails" "SECURITY.md is missing" python3 -B "$CHK" "$T/r"
tap_done
