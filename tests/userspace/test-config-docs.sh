#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-config-docs.sh - ci/check-config-docs.py passes on the repo and fails
# on each kind of drift between docs/configuration/ and the code: a key with
# no row, a row for a key the code does not read, a wrong built-in default, a
# wrong shipped value, a net.conf default that differs from apply-net.sh, a
# missing trust row, a page not linked from docs/README.md, and for the
# policy-list pages in docs/files/: a missing page, a wrong kernel limit, a
# shipped entry with no row and a row for an entry the template lacks; and
# for the temporary/ add-on pages: a parser key with no row, a row the parser
# does not accept, a shipped value that differs and a ProcGuard allowlist entry
# with no row.
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
docs/configuration/net-conf.md docs/configuration/pheonixbox-conf.md
$(cd "$ROOT" && ls userspace/config/*.conf docs/files/*.md docs/configuration/*.md temporary/config/*.conf)
temporary/driverguard/driverguard.c temporary/bootguard/bootguard.c
temporary/biosguard/biosguard.c temporary/procguard/procguard.c
temporary/tamperwatch/tamperwatch.c temporary/common/ssaddon_log.c
temporary/locus/locus.c temporary/common/ssaddon_store.c
temporary/gui/secure-sudo-gui"
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
fresh; rm "$T/r/docs/files/blacklist.md"
fails "a policy list with no docs/files page" 'docs/files/blacklist.md is missing'
fresh; sub docs/files/tpm_openers.md '<!-- list-limit:64 -->' '<!-- list-limit:65 -->'
fails "a list page whose limit differs from the kernel's" 'tpm_openers.md: limit marker 65, policy.c has 64'
fresh; echo "/usr/bin/tpm2_unseal" >> "$T/r/userspace/config/tpm_openers.conf"
fails "a shipped entry with no row" 'shipped entry /usr/bin/tpm2_unseal has no row'
fresh; sub docs/files/tpm_openers.md '^\| `/usr/bin/systemd-creds` \|.*\n' ''
fails "a shipped entry whose row was deleted" 'shipped entry /usr/bin/systemd-creds has no row'
fresh; sub docs/files/blacklist.md '(<!-- list-entries:begin -->\n.*\n.*\n)' '\1| `/usr/bin/nc` | x | y | z |\n'
fails "a row for an entry the template does not ship" 'row /usr/bin/nc is not in userspace/config/blacklist.conf'
fresh; sub docs/README.md '^.*\(files/prguard_allow\.md\).*\n' ''
fails "a list page not linked from docs/README.md" 'does not link files/prguard_allow.md'
fresh; sub docs/configuration/procguard-conf.md '^\| `sync_cmd` \|.*\n' ''
fails "an add-on key with no row" 'procguard-conf.md: no row for sync_cmd'
fresh; sub temporary/locus/locus.c '(\{ "default_root", SSC_PATH)' '{ "tls_cert", SSC_PATH, C.default_root, sizeof(C.default_root), 0, 0, NULL },\n\t\t\1'
fails "a key added to an add-on parser without a row" 'locus-conf.md: no row for tls_cert'
fresh; sub docs/configuration/gui-conf.md '^(\| `port` \|.*\n)' '\1| `theme` | enum | x | y | (absent) |\n'
fails "a GUI row the console does not accept" 'gui-conf.md: row theme is not a key'
fresh; sub temporary/config/bootguard.conf '^mode = enforce$' 'mode = monitor'
fails "an add-on template value that differs from its page" "bootguard-conf.md: mode Shipped is 'enforce', the template has 'monitor'"
fresh; echo "/usr/sbin/sshd" >> "$T/r/temporary/config/procguard_allow.conf"
fails "a ProcGuard allowlist entry with no row" 'procguard_allow.md: shipped entry /usr/sbin/sshd has no row'
tap_done
