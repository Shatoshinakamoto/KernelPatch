#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-config-docs.sh - ci/check-config-docs.py passes on the repo and fails
# on each kind of drift between docs/configuration/ and the code: a key with
# no row, a row for a key the code does not read, a wrong built-in default, a
# wrong shipped value, a net.conf default that differs from apply-net.sh, a
# missing trust row and a page not linked from docs/README.md.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
C="$ROOT/ci/check-config-docs.py"
FILES="userspace/cli/policy.c kernel/security/secure_sudo/ss_core.c
userspace/config/secure-sudo.conf userspace/config/net.conf
userspace/config/pheonixbox.conf userspace/daemon/helpers/apply-net.sh
docs/README.md docs/configuration/secure-sudo-conf.md
docs/configuration/net-conf.md docs/configuration/pheonixbox-conf.md"
fresh() {
	rm -rf "$T/r"
	for f in $FILES; do mkdir -p "$T/r/$(dirname "$f")"; cp "$ROOT/$f" "$T/r/$f"; done
}
run() { python3 -B "$C" "$T/r" > "$T/out" 2>&1; echo $?; }
fails() { # description regex : the check exits 1 and prints a FAIL matching regex
	local rc; rc="$(run)"
	if [ "$rc" = 1 ] && grep -E '^FAIL' "$T/out" | grep -qE -- "$2"; then ok "$1"
	else not_ok "$1 (rc $rc: $(head -2 "$T/out" | tr '\n' ' '))"; fi
}
sub() { # file python-regex replacement
	python3 -I -c 'import re,sys; p=sys.argv[1]; s=open(p).read(); n=re.sub(sys.argv[2],sys.argv[3],s,count=1,flags=re.M); assert n!=s, "no change"; open(p,"w").write(n)' "$T/r/$1" "$2" "$3"
}

python3 -B "$C" "$ROOT" > "$T/out" 2>&1
eq "the repo passes" "$?" 0
check "it says ok" grep -qx 'check-config-docs: ok' "$T/out"

fresh; sub docs/configuration/secure-sudo-conf.md '^\| `block_flash` \|.*\n' ''
fails "a kernel key with no row" 'no row for block_flash'
fresh; sub docs/configuration/secure-sudo-conf.md '^\| `alert_cmd` \|.*\n' ''
fails "a daemon key with no row" 'no row for alert_cmd'
fresh; sub docs/configuration/secure-sudo-conf.md '^(\| `block_flash` \|.*\n)' '\1| `block_flsh` | kernel | bool | 0, 1 | `1` | (absent) |\n'
fails "a row for a key the code does not read" 'row block_flsh is not a key'
fresh; sub docs/configuration/secure-sudo-conf.md '^(\| `bpf_guard` \|[^|]*\|[^|]*\|[^|]*\| )`0`' '\1`1`'
fails "a wrong kernel built-in default" "bpf_guard Built-in default is '1', ss_core.c has '0'"
fresh; sub userspace/config/secure-sudo.conf '^block_setid = 1$' 'block_setid = 0'
fails "the template changed but the doc did not" "block_setid Shipped is '1', the template has '0'"
fresh; sub userspace/config/secure-sudo.conf '^# alert_cmd = .*$' 'alert_cmd = /bin/true'
fails "a commented key uncommented in the template" "alert_cmd Shipped is '\(commented\)'"
fresh; printf 'block_nothing = 1\n' >> "$T/r/userspace/config/secure-sudo.conf"
fails "a template key the code does not read" 'block_nothing is not a key the code reads'
fresh; sub userspace/daemon/helpers/apply-net.sh '\$\(conf on_stop keep\)' '$(conf on_stop remove)'
fails "a net.conf default that differs from apply-net.sh" "on_stop Default is 'keep', apply-net.sh has 'remove'"
fresh; sub userspace/config/net.conf '^forward = 1$' 'forward = 0'
fails "a net.conf shipped value that differs" "forward Shipped is '1', the template has '0'"
fresh; sub docs/configuration/pheonixbox-conf.md '^\| `trust` \|.*\n' ''
fails "no trust row" 'no row for trust'
fresh; sub docs/README.md '^.*\(configuration/net-conf\.md\).*\n' ''
fails "a page not linked from docs/README.md" 'does not link configuration/net-conf.md'
fresh; sub docs/configuration/net-conf.md '<!-- config-keys:begin -->' ''
fails "a page without the key-table markers" 'net-conf.md: no <!-- config-keys'
tap_done
