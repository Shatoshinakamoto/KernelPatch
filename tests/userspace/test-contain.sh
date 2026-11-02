#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# test-contain.sh - tests for userspace/daemon/helpers/contain.sh (TODO P1-7:
# safe containment). The account tools (usermod, chage, getent, loginctl)
# are stand-ins that record what they were asked; processes and, with root,
# nftables in a throwaway network namespace are real.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

H="$ROOT/userspace/daemon/helpers/contain.sh"
T="$(mktemp -d)"
KIDS=()
cleanup() {
	local p
	for p in "${KIDS[@]}"; do kill -KILL "$p" 2>/dev/null; done
	rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$T/bin"
export SS_CONTAIN_STATE="$T/state" SS_CONTAIN_CONF="$T/secure-sudo.conf"
export SS_CONTAIN_OPERATOR=opsbob SS_CONTAIN_SSH_ADDR=192.0.2.7
echo "remote_syslog = 198.51.100.4:6514" > "$SS_CONTAIN_CONF"

for t in usermod chage loginctl; do
	printf '#!/bin/sh\necho "%s $*" >> "%s/acct.log"\n' "$t" "$T" > "$T/bin/$t"
done
cat > "$T/bin/getent" <<STUB
#!/bin/sh
case "\$1 \$2" in
"passwd mallory") echo "mallory:x:4242:4242::/home/mallory:/bin/sh" ;;
"passwd opsbob") echo "opsbob:x:4343:4343::/home/opsbob:/bin/sh" ;;
"passwd root") echo "root:x:0:0:root:/root:/bin/bash" ;;
"passwd toor") echo "toor:x:0:0::/root:/bin/sh" ;;
"shadow mallory") if [ -e "$T/locked" ]; then echo 'mallory:!\$6\$x:19000:0:99999:7::20000:'; else echo 'mallory:\$6\$x:19000:0:99999:7:::'; fi ;;
*) exit 2 ;;
esac
STUB
chmod 0755 "$T/bin/"*
export PATH="$T/bin:$PATH"
C() { bash "$H" "$@"; }
# pstate PID: R/S/T..., or "gone" (a program, so the sh -c checks can use it)
printf '#!/bin/sh\nawk '"'"'{print $3}'"'"' "/proc/$1/stat" 2>/dev/null || echo gone\n' > "$T/bin/pstate"
chmod 0755 "$T/bin/pstate"

echo "# network"
export SS_CONTAIN_NFT_DRYRUN="$T/ruleset"
C network --allow 10.9.9.9 --dry-run > "$T/out" 2>&1; rc=$?
check "dry run: plan lists loopback, --allow, the SSH client and the collector" sh -c \
	"[ $rc -eq 0 ] && grep -q 'except loopback and 10.9.9.9 192.0.2.7 198.51.100.4' '$T/out' && grep -q 'dry run: nothing changed' '$T/out'"
check "dry run: shows the ruleset and loads nothing" sh -c \
	"grep -q 'policy drop;' '$T/out' && grep -q 'ip saddr 192.0.2.7 accept' '$T/out' && [ ! -e '$T/ruleset' ] && [ ! -e '$T/state/network' ]"
C network --allow 10.9.9 -y > "$T/out" 2>&1; rc=$?
check "an --allow that is not an address is refused" sh -c "[ $rc -eq 1 ] && grep -q 'not an IP address' '$T/out'"
echo no | C network > "$T/out" 2>&1; rc=$?
check "no 'yes': aborted (exit 3), nothing loaded" sh -c "[ $rc -eq 3 ] && [ ! -e '$T/ruleset' ]"
SS_CONTAIN_SSH_ADDR="" C network --no-collector --dry-run > "$T/out" 2>&1
check "no SSH client found: warns that a remote operator would be cut off" sh -c \
	"grep -q 'WARNING: no SSH client' '$T/out' && ! grep -q 198.51.100.4 '$T/out'"
C network --allow 2001:db8::5 -y > "$T/out" 2>&1; rc=$?
check "network -y: one table, policy drop both ways, lo and allowed kept" sh -c \
	"[ $rc -eq 0 ] && grep -c 'policy drop' '$T/ruleset' | grep -qx 3 && grep -q 'oif \"lo\" accept' '$T/ruleset' && grep -q 'ip6 daddr 2001:db8::5 accept' '$T/ruleset' && grep -q 'ip daddr 198.51.100.4 accept' '$T/ruleset'"
check "... replaces itself in one transaction, leaves net_mode's table alone" sh -c \
	"head -2 '$T/ruleset' | tr '\n' ' ' | grep -q '^table inet secure_sudo_contain delete table inet secure_sudo_contain ' && ! grep -qE 'table inet secure_sudo( |$)' '$T/ruleset'"
check "... state is root-only and status says contained" sh -c \
	"[ \"\$(stat -c %a '$T/state')\" = 700 ] && bash '$H' status | grep -q 'network: CONTAINED'"
C release network -y > "$T/out" 2>&1; rc=$?
check "release network removes the table" sh -c \
	"[ $rc -eq 0 ] && [ ! -s '$T/ruleset' ] && [ ! -e '$T/state/network' ] && bash '$H' status | grep -q 'network: normal'"
unset SS_CONTAIN_NFT_DRYRUN

echo "# account"
C account root -y > "$T/out" 2>&1; rc=$?
check "account: root refused" sh -c "[ $rc -eq 1 ] && grep -q 'refusing to contain UID 0' '$T/out'"
C account toor -y > "$T/out" 2>&1; rc=$?
check "account: any UID 0 name refused" sh -c "[ $rc -eq 1 ] && grep -q 'UID 0' '$T/out'"
C account opsbob -y > "$T/out" 2>&1; rc=$?
check "account: the operator's own account refused" sh -c "[ $rc -eq 1 ] && grep -q 'your own account' '$T/out'"
C account nosuch -y > "$T/out" 2>&1; rc=$?
check "account: unknown user refused" sh -c "[ $rc -eq 1 ] && grep -q 'no such user' '$T/out'"
C account 'x;rm' -y > "$T/out" 2>&1; rc=$?
check "account: a name that is not a user name refused" sh -c "[ $rc -eq 1 ] && grep -q 'not a user name' '$T/out'"

echo "# process"
C process 1 -y > "$T/out" 2>&1; rc=$?
check "process: PID 1 refused" sh -c "[ $rc -eq 1 ] && grep -q 'PID 1' '$T/out'"
C process 2 -y > "$T/out" 2>&1; rc=$?
check "process: a kernel thread refused" sh -c "[ $rc -eq 1 ] && grep -qE 'kernel thread|no process' '$T/out'"
C process $$ -y > "$T/out" 2>&1; rc=$?
check "process: the operator's own shell chain refused" sh -c "[ $rc -eq 1 ] && grep -q 'one of its parents' '$T/out'"
sleep 300 & P=$!; KIDS+=("$P")
C process "$P" --dry-run > "$T/out" 2>&1
check "process dry run: plan, nothing stopped" sh -c "grep -q 'STOP (freeze)' '$T/out' && [ \"\$(pstate $P)\" = S ]"
C process "$P" -y > "$T/out" 2>&1; rc=$?
EV="$(ls -d "$T/state/process-$P-"* 2>/dev/null | head -1)"
check "process -y: stopped" sh -c "[ $rc -eq 0 ] && [ \"\$(pstate $P)\" = T ]"
check "... evidence first: cmdline, status, maps, fds, executable copy and hash" sh -c \
	"grep -q 'sleep 300' '$EV/cmdline' && [ -s '$EV/status' ] && [ -s '$EV/maps' ] && [ -s '$EV/fds.txt' ] && [ \"\$(cat '$EV/exe.sha256')\" = \"\$(sha256sum \"\$(readlink -f /proc/$P/exe)\" | cut -d' ' -f1)\" ]"
check "... status lists it" sh -c "bash '$H' status | grep -q 'process: $P STOPPED'"
C release process "$P" -y > "$T/out" 2>&1; rc=$?
check "release process continues it, evidence kept" sh -c \
	"[ $rc -eq 0 ] && [ \"\$(pstate $P)\" = S ] && [ -d '$EV.released' ]"
sh -c 'sleep 301 & wait' & PP=$!; KIDS+=("$PP"); sleep 0.3
CH="$(awk -v p="$PP" '$4 == p {print $1}' /proc/[0-9]*/stat 2>/dev/null | head -1)"
C process "$PP" -y > "$T/out" 2>&1
check "process: its descendants are stopped too" sh -c \
	"[ -n '$CH' ] && [ \"\$(pstate $PP)\" = T ] && [ \"\$(pstate $CH)\" = T ]"
C process "$PP" --kill -y > "$T/out" 2>&1 || true
C release process "$PP" -y > /dev/null 2>&1
sleep 302 & K=$!; KIDS+=("$K")
C process "$K" --kill -y > "$T/out" 2>&1; rc=$?
wait "$K" 2>/dev/null
check "process --kill: killed after the evidence is saved" sh -c \
	"[ $rc -eq 0 ] && [ \"\$(pstate $K)\" = gone ] && ls '$T/state/process-$K-'*/exe.sha256 >/dev/null"
C release process "$K" -y > "$T/out" 2>&1; rc=$?
check "release of a killed process is refused" sh -c "[ $rc -eq 1 ] && grep -q 'was killed' '$T/out'"

if [ "$(id -u)" -eq 0 ] && command -v setpriv >/dev/null; then
	echo "# account (root: a real process of another user)"
	setpriv --reuid=4242 --regid=4242 --clear-groups sleep 303 & M=$!; KIDS+=("$M"); sleep 0.3
	: > "$T/acct.log"
	C account mallory -y > "$T/out" 2>&1; rc=$?
	check "account -y: password locked and account expired" sh -c \
		"[ $rc -eq 0 ] && grep -qx 'usermod --lock mallory' '$T/acct.log' && grep -qx 'usermod --expiredate 1 mallory' '$T/acct.log'"
	check "... its processes stopped, not killed, and listed in the evidence" sh -c \
		"[ \"\$(pstate $M)\" = T ] && grep -q 'sleep 303' '$T/state/account-mallory/processes.txt'"
	C account mallory -y > "$T/out" 2>&1; rc=$?
	check "... containing it again is refused" sh -c "[ $rc -eq 1 ] && grep -q 'already contained' '$T/out'"
	: > "$T/acct.log"
	C release account mallory -y > "$T/out" 2>&1; rc=$?
	check "release account: expiry cleared, password unlocked, processes continue" sh -c \
		"[ $rc -eq 0 ] && grep -qx 'usermod --expiredate  mallory' '$T/acct.log' && grep -qx 'usermod --unlock mallory' '$T/acct.log' && [ \"\$(pstate $M)\" = S ]"
	touch "$T/locked"; : > "$T/acct.log"
	C account mallory -y > /dev/null 2>&1; C release account mallory -y > /dev/null 2>&1
	check "release puts back what was there: an expiry date, a password that was already locked stays locked" sh -c \
		"grep -qx 'chage -E 20000 mallory' '$T/acct.log' && ! grep -q -- '--unlock' '$T/acct.log'"
	rm -f "$T/locked"
	C account mallory --terminate -y > /dev/null 2>&1
	wait "$M" 2>/dev/null
	check "account --terminate kills the processes and the sessions" sh -c \
		"[ \"\$(pstate $M)\" = gone ] && grep -q 'loginctl terminate-user mallory' '$T/acct.log'"

	if command -v nft >/dev/null && command -v unshare >/dev/null; then
		echo "# network (root: real nftables in a throwaway namespace)"
		unshare -n bash -c "
			ip link set lo up
			SS_CONTAIN_SSH_ADDR= bash '$H' network --allow 10.0.0.1 --no-collector -y >/dev/null 2>&1 || exit 10
			nft list table inet secure_sudo_contain | grep -q 'ip saddr 10.0.0.1 accept' || exit 11
			ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 || exit 12
			bash '$H' release network -y >/dev/null 2>&1 || exit 13
			! nft list table inet secure_sudo_contain >/dev/null 2>&1 || exit 14
		" 2> "$T/ns.err"; rc=$?
		eq "real nft: table loads, loopback works, release removes it" "$rc" 0
	else
		skip "real nft in a namespace (needs nft and unshare)"
	fi
else
	skip "account and real-nft cases (need root and setpriv)"
fi
tap_done
