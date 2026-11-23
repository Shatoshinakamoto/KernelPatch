#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-cis-firewall.sh - the CIS firewall table (scripts/cis-nftables.sh) and
# secure_sudo's network-mode table coexist (TODO P3-2, OSB-16, owner's choice
# 2026-11-23). Real nftables and real TCP between two network namespaces:
#   * the CIS table alone: inbound SSH allowed, other inbound dropped,
#     outbound allowed, replies allowed;
#   * a secure_sudo table that blocks a destination wins over CIS's
#     outbound accept (stricter wins), and CIS's inbound drop wins over a
#     secure_sudo table that accepts everything (neither loosens the other);
#   * loading the CIS file again keeps the secure_sudo table (OSB-23).
# Needs root, nft, ip netns and python3; skipped otherwise.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
CIS="$ROOT/scripts/cis-nftables.sh"
T="$(mktemp -d)"

# --- generator checks (no root needed)
SS_CIS_SSH_PORTS="2222" bash "$CIS" --allow-tcp 443 --print > "$T/cis.nft"
check "generator: the sshd port and --allow-tcp are allowed inbound" grep -q 'tcp dport { 443,2222 } ct state new accept' "$T/cis.nft"
refute "generator: never flushes the whole ruleset (OSB-23)" grep -qE '^[[:space:]]*flush[[:space:]]+ruleset' "$T/cis.nft"
check "generator: resets only its own table" grep -qx 'delete table inet filter' "$T/cis.nft"
eq "generator: three default-deny base chains" "$(grep -c 'policy drop;' "$T/cis.nft")" 3
check "generator: loopback accepted and spoofed loopback dropped" bash -c "grep -q 'iif \"lo\" accept' '$T/cis.nft' && grep -q 'ip saddr 127.0.0.0/8 counter drop' '$T/cis.nft' && grep -q 'ip6 saddr ::1 counter drop' '$T/cis.nft'"
SS_CIS_SSH_PORTS=22 bash "$CIS" --forward drop > "$T/cis-fd.nft"
refute "generator: --forward drop routes nothing" bash -c "sed -n '/chain forward/,/}/p' '$T/cis-fd.nft' | grep -q accept"
refute_with "generator: a bad port is refused" "bad port" bash "$CIS" --allow-tcp 70000
# The unprivileged user must be able to read the script: the build gate runs
# the suite as root from a 0700 mktemp copy of the tree, where uid 65534
# cannot reach it and bash fails before the script can refuse.
PUB="$(mktemp -d)"; chmod 0755 "$PUB"; cp "$CIS" "$PUB/cis-nftables.sh"; chmod 0644 "$PUB/cis-nftables.sh"
refute_with "generator: --apply needs root or refuses cleanly" "needs root" env SS_CIS_NFT_CONF="$PUB/none.conf" setpriv --reuid=65534 --regid=65534 --clear-groups bash "$PUB/cis-nftables.sh" --apply
rm -rf "$PUB"

S="$ROOT/scripts/stig-harden.sh"
check "stig-harden: --cis-firewall is wired to cis-nftables.sh --apply" grep -q 'cis-nftables.sh" --apply' "$S"
check "stig-harden: the CIS table is loaded before the baseline scan" bash -c "awk '/cis-nftables.sh\" --apply/{a=NR} /^scan baseline/{b=NR} END{exit !(a && b && a<b)}' '$S'"
check "stig-harden: only on --remediate (a scan changes nothing)" grep -q 'CIS_FW" -eq 1 \] && \[ "\$MODE" = remediate' "$S"
check "install.sh ships cis-nftables.sh next to stig-harden.sh" grep -q 'stig-harden.sh oscap-results.py cis-nftables.sh' "$ROOT/install/install.sh"

# OSB-24: the nftables.service drop-in
bash "$CIS" --print-dropin > "$T/dropin.conf"
check "drop-in: clears the vendor ExecStop" grep -qx 'ExecStop=' "$T/dropin.conf"
check "drop-in: deletes only inet filter on stop" bash -c "[ \"\$(grep '^ExecStop=-' '$T/dropin.conf')\" = 'ExecStop=-/usr/sbin/nft delete table inet filter' ]"
refute "drop-in: never flushes the ruleset" bash -c "grep -v '^#' '$T/dropin.conf' | grep -q 'flush ruleset'"
if [ "$(id -u)" -eq 0 ] && command -v nft >/dev/null && unshare -n true 2>/dev/null; then
	mkdir -p "$T/apply/etc" "$T/apply/units"
	check "--apply in a namespace: loads, installs the drop-in, keeps secure_sudo's table" unshare -n bash -c '
		nft add table inet secure_sudo || exit 9
		SS_CIS_NFT_CONF="$1/etc/nftables.conf" SS_CIS_UNIT_DIR="$1/units" SS_CIS_NO_SYSTEMCTL=1 SS_CIS_SSH_PORTS=22 bash "$2" --apply >/dev/null || exit 1
		test -f "$1/units/nftables.service.d/secure-sudo-keep-tables.conf" || exit 2
		nft list table inet filter >/dev/null && nft list table inet secure_sudo >/dev/null' _ "$T/apply" "$CIS"
	eq "--apply: the drop-in is mode 0644" "$(stat -c %a "$T/apply/units/nftables.service.d/secure-sudo-keep-tables.conf" 2>/dev/null)" 644
else
	skip "--apply in a namespace (needs root, nft and unshare)"
fi

if [ "$(id -u)" -ne 0 ] || ! command -v nft >/dev/null || ! command -v python3 >/dev/null ||
   ! ip netns add "sscis-probe-$$" 2>/dev/null; then
	skip "real nft and TCP in network namespaces (need root, nft, python3, ip netns)"
	rm -rf "$T"; tap_done; exit $?
fi
ip netns del "sscis-probe-$$"
H="sscis-h-$$"; P="sscis-p-$$"
cleanup() { ip netns del "$H" 2>/dev/null; ip netns del "$P" 2>/dev/null; kill "${SRV[@]}" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
SRV=()
ip netns add "$H"; ip netns add "$P"
ip link add "vh$$" netns "$H" type veth peer name "vp$$" netns "$P"
ip -n "$H" addr add 10.77.0.1/24 dev "vh$$"; ip -n "$P" addr add 10.77.0.2/24 dev "vp$$"; ip -n "$P" addr add 10.77.0.3/24 dev "vp$$"
for n in "$H" "$P"; do ip -n "$n" link set lo up; done
ip -n "$H" link set "vh$$" up; ip -n "$P" link set "vp$$" up
listen() { # ns port
	ip netns exec "$1" python3 -c 'import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",int(sys.argv[1]))); s.listen(16)
while True:
    c,_=s.accept(); c.close()' "$2" & SRV+=($!)
}
conn() { # ns addr port
	ip netns exec "$1" python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(1.5)
try: s.connect((sys.argv[1],int(sys.argv[2])))
except Exception: sys.exit(1)' "$2" "$3"
}
listen "$H" 2222; listen "$H" 8080; listen "$P" 9000
sleep 0.5
check "before: inbound 8080 reachable with no firewall" conn "$P" 10.77.0.1 8080

ip netns exec "$H" nft -f "$T/cis.nft"
check "CIS: inbound SSH port reachable" conn "$P" 10.77.0.1 2222
refute "CIS: other inbound port dropped" conn "$P" 10.77.0.1 8080
check "CIS: outbound new connection allowed (and its replies)" conn "$H" 10.77.0.2 9000

# secure_sudo-style table that blocks one destination (like public-only's LAN drop)
cat > "$T/ss.nft" <<'NFT'
table inet secure_sudo {
	chain output { type filter hook output priority filter; policy accept; ip daddr 10.77.0.3 drop; }
	chain input { type filter hook input priority filter; policy accept; }
}
NFT
ip netns exec "$H" nft -f "$T/ss.nft"
refute "coexist: secure_sudo's drop wins over CIS's outbound accept" conn "$H" 10.77.0.3 9000
check "coexist: other outbound destinations still work" conn "$H" 10.77.0.2 9000
check "coexist: CIS's SSH allowance is unaffected" conn "$P" 10.77.0.1 2222
ip netns exec "$H" nft -f "$T/cis.nft"
check "coexist: reloading the CIS file keeps the secure_sudo table" ip netns exec "$H" nft list table inet secure_sudo
refute "coexist: ... and its drop still applies" conn "$H" 10.77.0.3 9000

# secure_sudo table that accepts everything cannot open what CIS drops
ip netns exec "$H" nft delete table inet secure_sudo
printf 'table inet secure_sudo {\n\tchain input { type filter hook input priority -10; policy accept; accept; }\n}\n' > "$T/ss-open.nft"
ip netns exec "$H" nft -f "$T/ss-open.nft"
refute "coexist: a secure_sudo accept does not open CIS's inbound drop" conn "$P" 10.77.0.1 8080
ip netns exec "$H" nft delete table inet filter
check "coexist: removing the CIS table leaves the secure_sudo table" ip netns exec "$H" nft list table inet secure_sudo
check "after: inbound 8080 reachable again without the CIS table" conn "$P" 10.77.0.1 8080
tap_done
