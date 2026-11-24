#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-command-docs.sh - ci/check-command-docs.py passes on the repo and fails
# on each kind of drift: a CLI subcommand with no page, a script no page
# names, an add-on binary with no page, a copied header that no longer
# matches its script, a feature page missing a required section, and a
# command or feature page not linked from docs/README.md.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
C="$ROOT/ci/check-command-docs.py"
fresh() {
	rm -rf "$T/r"; mkdir -p "$T/r"
	(cd "$ROOT" && tar -cf - docs/README.md docs/commands docs/features userspace/cli/secure-sudo.c \
		scripts ci userspace/daemon/helpers tests/run-all.sh temporary) | tar -C "$T/r" -xf -
}
run() { python3 -B "$C" "$T/r" > "$T/out" 2>&1; echo $?; }
fails() { # description regex
	local rc; rc="$(run)"
	if [ "$rc" = 1 ] && grep -E '^FAIL' "$T/out" | grep -qE -- "$2"; then ok "$1"
	else not_ok "$1 (rc=$rc: $(head -3 "$T/out"))"; fi
}

fresh
eq "the repository passes" "$(run)" 0

fresh
rm "$T/r/docs/commands/secure-sudo-lock.md"
sed -i 's#(commands/secure-sudo-lock.md)#(x)#' "$T/r/docs/README.md"
fails "a CLI subcommand with no page" 'secure-sudo-lock.md is missing'

fresh
printf '#!/bin/sh\n# new-tool.sh - a new helper\n' > "$T/r/scripts/new-tool.sh"
fails "a script no page names" 'no docs/commands/ page names scripts/new-tool.sh'

fresh
rm "$T/r/docs/commands/secure-sudo-procguard.md"
sed -i 's#(commands/secure-sudo-procguard.md)#(x)#' "$T/r/docs/README.md"
fails "an add-on binary with no page" 'secure-sudo-procguard.md is missing'

fresh
printf '#!/bin/bash\n# make-release.sh - something else entirely\n# now\n' > "$T/r/ci/make-release.sh"
fails "a copied header that drifted from its script" "make-release.md: the usage block differs"

fresh
sed -i 's/^## Troubleshooting$/## Problems/' "$T/r/docs/features/timevault.md"
fails "a feature page missing a required section" "timevault.md: no '## Troubleshooting' section"

fresh
sed -i 's#(features/timevault.md)#(x)#' "$T/r/docs/README.md"
fails "a feature page not linked from docs/README.md" 'does not link features/timevault.md'

fresh
sed -i 's#(commands/run-all.md)#(x)#' "$T/r/docs/README.md"
fails "a command page not linked from docs/README.md" 'does not link commands/run-all.md'
tap_done
