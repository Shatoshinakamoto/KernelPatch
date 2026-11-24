#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-licenses.sh - the license policy holds for every source file.
#
#   * LICENSE is the Apache License 2.0 text, appendix filled in, otherwise unmodified.
#   * LICENSES/GPL-2.0 is present, because the in-kernel LSM is dual-licensed.
#   * NOTICE, LICENSE and LICENSES/GPL-2.0 name the project, year and holder.
#   * Every source file has an SPDX-FileCopyrightText line.
#   * Every source file has exactly one SPDX-License-Identifier line near the
#     top: "GPL-2.0 OR Apache-2.0" under kernel/ (code built into the kernel
#     must be GPLv2-compatible), "Apache-2.0" everywhere else.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/tap.sh
. "$HERE/../lib/tap.sh"

# LICENSE is the canonical Apache-2.0 text with only its appendix boilerplate
# filled in: put the placeholder back and the hash must match apache.org's.
# sha256 of https://www.apache.org/licenses/LICENSE-2.0.txt
APACHE_SHA=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
check "LICENSE appendix names the project" grep -qx '   secure_sudo' "$ROOT/LICENSE"
check "LICENSE appendix names the holder and year" \
	grep -qx '   Copyright 2026 Johnathan Edward Brown' "$ROOT/LICENSE"
eq "LICENSE is otherwise the unmodified Apache-2.0 text" \
	"$(sed -e '/^   secure_sudo$/d' \
	       -e 's/^   Copyright 2026 Johnathan Edward Brown$/   Copyright [yyyy] [name of copyright owner]/' \
	       "$ROOT/LICENSE" 2>/dev/null | sha256sum | cut -d' ' -f1)" "$APACHE_SHA"

# LICENSES/GPL-2.0: a filled-in notice, a separator, then the verbatim text.
# sha256 of the GPL v2 text as shipped in Debian /usr/share/common-licenses/GPL-2
GPL2_SHA=8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643
check "LICENSES/GPL-2.0 notice names the project" \
	grep -q '^secure_sudo kernel LSM' "$ROOT/LICENSES/GPL-2.0"
check "LICENSES/GPL-2.0 notice names the holder and year" \
	grep -qx 'Copyright (C) 2026  Johnathan Edward Brown' "$ROOT/LICENSES/GPL-2.0"
eq "LICENSES/GPL-2.0 carries the unmodified GPL v2 text" \
	"$(sed '1,/^-\{20,\}$/d' "$ROOT/LICENSES/GPL-2.0" 2>/dev/null | sed '1{/^$/d}' | sha256sum | cut -d' ' -f1)" "$GPL2_SHA"
check "NOTICE names the project" grep -qx 'SatoshiNakamoto Kernel Patch (secure_sudo)' "$ROOT/NOTICE"
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
missing=(); wrong=(); many=(); nocopy=()
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
	head -n 6 "$ROOT/$f" | grep -qE '(#|//|/\*|^ +) ?SPDX-FileCopyrightText: 2026 Johnathan Edward Brown' \
		|| nocopy+=("$f")
done
ok_count=$(( ${#FILES[@]} - ${#missing[@]} - ${#wrong[@]} - ${#many[@]} ))
if [ "${#FILES[@]}" -ge 100 ]; then ok "found ${#FILES[@]} source files to check"
else not_ok "found only ${#FILES[@]} source files (wrong root?)"; fi
if [ "${#missing[@]}" -eq 0 ]; then ok "every source file has an SPDX line in its first 5 lines"
else not_ok "no SPDX line: ${missing[*]}"; fi
if [ "${#wrong[@]}" -eq 0 ]; then ok "every SPDX line names the right license ($ok_count files)"
else for w in "${wrong[@]}"; do echo "# $w"; done; not_ok "${#wrong[@]} files name the wrong license"; fi
if [ "${#nocopy[@]}" -eq 0 ]; then ok "every source file names the copyright holder"
else not_ok "no SPDX-FileCopyrightText line: ${nocopy[*]}"; fi
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
