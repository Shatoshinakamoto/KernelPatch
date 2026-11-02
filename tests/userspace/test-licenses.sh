#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# test-licenses.sh - the license policy holds for every source file.
#
#   * LICENSE is the unmodified Apache License 2.0 text.
#   * LICENSES/GPL-2.0 is present, because the in-kernel LSM is dual-licensed.
#   * NOTICE names the copyright holder.
#   * Every source file has exactly one SPDX-License-Identifier line near the
#     top: "GPL-2.0 OR Apache-2.0" under kernel/ (code built into the kernel
#     must be GPLv2-compatible), "Apache-2.0" everywhere else.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/tap.sh
. "$HERE/../lib/tap.sh"

# sha256 of the canonical text at https://www.apache.org/licenses/LICENSE-2.0.txt
APACHE_SHA=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
eq "LICENSE is the unmodified Apache-2.0 text" \
	"$(sha256sum "$ROOT/LICENSE" 2>/dev/null | cut -d' ' -f1)" "$APACHE_SHA"
check "LICENSES/GPL-2.0 is the GPL version 2 text" \
	grep -q "GNU GENERAL PUBLIC LICENSE" "$ROOT/LICENSES/GPL-2.0"
check "LICENSES/GPL-2.0 is version 2" grep -q "Version 2, June 1991" "$ROOT/LICENSES/GPL-2.0"
check "NOTICE names the copyright holder" \
	grep -q "^Copyright 2026 Johnathan Edward Brown$" "$ROOT/NOTICE"

# Source files: code, scripts, build files, playbooks, the GUI.
mapfile -t FILES < <(cd "$ROOT" && find . -type f \
	! -path './.git/*' ! -path './docs/stig/results/*' \
	\( -name '*.c' -o -name '*.h' -o -name '*.sh' -o -name '*.py' \
	   -o -name '*.yml' -o -name '*.yaml' -o -name Makefile -o -name Kconfig \
	   -o -name 'secure-sudo-gui' \) -printf '%P\n' | LC_ALL=C sort)

# A header is the identifier at the start of a comment line, so a file that
# merely mentions the tag (like this one) is not counted twice.
HDR='^(#|//|/\*|<!--) ?SPDX-License-Identifier:'
missing=(); wrong=(); many=()
for f in "${FILES[@]}"; do
	case "$f" in
	kernel/*) want='GPL-2.0 OR Apache-2.0' ;;
	*) want='Apache-2.0' ;;
	esac
	n="$(grep -cE "$HDR" "$ROOT/$f")"
	if [ "$n" -gt 1 ]; then many+=("$f"); continue; fi
	line="$(head -n 5 "$ROOT/$f" | grep -m1 -E "$HDR")"
	if [ -z "$line" ]; then missing+=("$f"); continue; fi
	id="$(printf '%s' "$line" | sed -E 's/.*SPDX-License-Identifier: *//; s/ *\*\/ *$//; s/ *-->.*$//; s/ +$//')"
	[ "$id" = "$want" ] || wrong+=("$f: '$id', want '$want'")
done
ok_count=$(( ${#FILES[@]} - ${#missing[@]} - ${#wrong[@]} - ${#many[@]} ))
if [ "${#FILES[@]}" -ge 100 ]; then ok "found ${#FILES[@]} source files to check"
else not_ok "found only ${#FILES[@]} source files (wrong root?)"; fi
if [ "${#missing[@]}" -eq 0 ]; then ok "every source file has an SPDX line in its first 5 lines"
else not_ok "no SPDX line: ${missing[*]}"; fi
if [ "${#wrong[@]}" -eq 0 ]; then ok "every SPDX line names the right license ($ok_count files)"
else for w in "${wrong[@]}"; do echo "# $w"; done; not_ok "${#wrong[@]} files name the wrong license"; fi
if [ "${#many[@]}" -eq 0 ]; then ok "no file has more than one SPDX line"
else not_ok "several SPDX lines: ${many[*]}"; fi

# The policy test itself must catch a wrong header, or the checks above
# prove nothing. Run the same rule on a scratch tree.
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/kernel" "$T/userspace"
printf '// SPDX-License-Identifier: Apache-2.0\n' > "$T/kernel/a.c"
printf '# SPDX-License-Identifier: GPL-2.0\n' > "$T/userspace/b.sh"
bad=0
for f in kernel/a.c userspace/b.sh; do
	case "$f" in kernel/*) want='GPL-2.0 OR Apache-2.0' ;; *) want='Apache-2.0' ;; esac
	id="$(head -n 5 "$T/$f" | grep -m1 -E "$HDR" | sed -E 's/.*SPDX-License-Identifier: *//')"
	[ "$id" = "$want" ] || bad=$((bad + 1))
done
eq "rule rejects Apache-only kernel file and GPL-only userspace file" "$bad" 2

tap_done
