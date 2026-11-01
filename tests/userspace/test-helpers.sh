#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# test-helpers.sh - tests for the daemon's helpers (TODO P0-2): apply-net.sh
# (#10 network modes) and quarantine.sh (#13 TimeVault quarantine).
#
# Part 1 needs no root: `ip` and `nft` are replaced by stubs on PATH, the
# ruleset is written to a file (SS_NET_DRYRUN) and quarantines go to a scratch
# directory (SS_QUARANTINE_DIR). Part 2 is ROOT-ONLY: it loads the rulesets
# with the real nft into two throwaway network namespaces joined by a veth
# pair and checks which traffic actually passes. The host's own network
# namespace and firewall are never touched. Skipped when not root.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
NET="$ROOT/userspace/daemon/helpers/apply-net.sh"
QUAR="$ROOT/userspace/daemon/helpers/quarantine.sh"

T="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT

echo "# part 1: no root needed"

# --- apply-net.sh with stub ip/nft ---
mkdir -p "$T/stub"
cat > "$T/stub/ip" <<'EOF'
#!/bin/sh
# Stub ip: a laptop on Wi-Fi with IPv4 and global IPv6, unless STUB_NET says
# otherwise (noroute: no default route; noaddr: route but no addresses;
# v4only: no IPv6).
case "${STUB_NET:-}:$*" in
  noroute:*route*) ;;
  noaddr:*addr*) ;;
  v4only:-6\ route*) ;;
  *:"route show default") echo "default via 192.168.1.1 dev wlan0 proto dhcp metric 600" ;;
  *:"-6 route show default") echo "default via fe80::1 dev wlan0 proto ra metric 600 pref medium" ;;
  *:"-o addr show scope global")
	echo "3: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic wlan0"
	[ "${STUB_NET:-}" = v4only ] ||
		echo "3: wlan0    inet6 2001:db8:1:2::23/64 scope global dynamic" ;;
esac
EOF
cat > "$T/stub/nft" <<EOF
#!/bin/sh
[ "\$1" = list ] && exit 1
cat > "$T/nft.loaded"
exit "\${STUB_NFT_RC:-0}"
EOF
chmod 0755 "$T/stub/ip" "$T/stub/nft"
export SS_NET_CONF="$T/net.conf" SS_NET_SYSFS="$T/sysnet"
net() { # mode -> NRC, ruleset in $T/rules (absent if nothing was produced)
	rm -f "$T/rules" "$T/nft.loaded" "$T/net.state"
	export SS_NET_STATE="$T/net.state"
	PATH="$T/stub:$PATH" SS_NET_DRYRUN="$T/rules" sh "$NET" "$@" >/dev/null 2>"$T/net.err"
	NRC=$?
}
rules_have() { grep -qF -- "$1" "$T/rules" 2>/dev/null; }

net bogus
eq "net: unknown mode exits 2" "$NRC" 2
check "net: unknown mode loads nothing (current rules stay)" test ! -e "$T/rules"
net host
eq "net: host mode exits 0" "$NRC" 0
eq "net: host mode only removes the table" "$(cat "$T/rules")" \
	"$(printf 'table inet secure_sudo\ndelete table inet secure_sudo')"
net lan-only
eq "net: lan-only exits 0" "$NRC" 0
check "net: replaces the old table in the same transaction" \
	sh -c "head -2 '$T/rules' | grep -qx 'delete table inet secure_sudo'"
check "net: lan-only LAN set has the IPv4 subnet" rules_have "elements = { 127.0.0.0/8, 192.168.1.23/24 }"
check "net: lan-only LAN set has the IPv6 prefix" rules_have "2001:db8:1:2::23/64 }"
check "net: lan-only drops non-LAN IPv4 out" rules_have "ip daddr != @lan drop"
check "net: lan-only drops non-LAN IPv6 out (was let through before)" rules_have "ip6 daddr != @lan6 drop"
check "net: lan-only drops non-LAN IPv6 in" rules_have "ip6 saddr != @lan6 drop"
check "net: lan-only keeps link-local IPv6 (neighbour discovery)" rules_have "fe80::/10"
net public-only
eq "net: public-only exits 0" "$NRC" 0
check "net: public-only drops the IPv4 LAN" rules_have "ip daddr @lan drop"
check "net: public-only drops the IPv6 LAN" rules_have "ip6 daddr @lan6 drop"
check "net: public-only keeps DHCP" rules_have "udp sport { 67, 68 } udp dport { 67, 68 } accept"
check "net: public-only keeps DHCPv6" rules_have "udp sport { 546, 547 } udp dport { 546, 547 } accept"
check "net: public-only keeps DNS to the IPv4 gateway" rules_have "ip daddr 192.168.1.1 meta l4proto { tcp, udp } th dport 53 accept"
check "net: public-only keeps DNS to the IPv6 gateway" rules_have "ip6 daddr fe80::1 meta l4proto { tcp, udp } th dport 53 accept"
check "net: public-only keeps neighbour discovery (ICMPv6 nd-*)" rules_have "nd-neighbor-solicit, nd-neighbor-advert"
refute "net: public-only no longer passes every ICMPv6 type (echo reached the LAN)" rules_have "meta l4proto ipv6-icmp accept"
first_line() { grep -nF -- "$1" "$T/rules" | head -1 | cut -d: -f1; }
check "net: exemptions come before the LAN drop" \
	test "$(first_line 'dport 53 accept')" -lt "$(first_line 'ip daddr @lan drop')"
STUB_NET=noroute net public-only
eq "net: no default route: the LAN is still known, rules apply (exit 0)" "$NRC" 0
refute "net: ... with no gateway, no DNS exemption" rules_have "dport 53 accept"
STUB_NET=noaddr net lan-only
eq "net: no address and no rules yet: fail-closed pending rules (exit 3)" "$NRC" 3
check "net: ... pending lan-only allows only loopback in the LAN set" rules_have "elements = { 127.0.0.0/8 }"
STUB_NET=noaddr net public-only
eq "net: pending public-only (exit 3)" "$NRC" 3
check "net: ... pending public-only drops every private range" rules_have "elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }"
echo "extra_lan = 10.0.0.0/8 }" > "$T/net.conf"
net lan-only
eq "net: a bad net.conf value is refused (exit 1)" "$NRC" 1
check "net: ... nothing loaded" test ! -e "$T/rules"
echo "extra_lan = 10.20.0.0/16 2001:db8:aa::/48" > "$T/net.conf"
net lan-only
check "net: extra_lan adds IPv4 and IPv6 subnets" sh -c "grep -q '10.20.0.0/16' '$T/rules' && grep -q '2001:db8:aa::/48' '$T/rules'"
: > "$T/net.conf"
mkdir -p "$T/sysnet/wlan0"; echo 65534 > "$T/sysnet/wlan0/type"
net lan-only
eq "net: a non-Ethernet link (WireGuard/tun type) is never LAN" "$NRC" 3
rm -rf "$T/sysnet"
STUB_NET=v4only net lan-only
eq "net: IPv4-only host still works" "$NRC" 0
check "net: IPv4-only host still drops IPv6 in lan-only" rules_have "ip6 daddr != @lan6 drop"
rm -f "$T/nft.loaded" "$T/net.state"
PATH="$T/stub:$PATH" STUB_NFT_RC=1 sh "$NET" lan-only >/dev/null 2>&1; rc=$?
check "net: nft load failure is reported (non-zero exit)" test "$rc" -ne 0
check "net: the real run feeds nft the same ruleset" grep -q 'ip6 daddr != @lan6 drop' "$T/nft.loaded"

# --- quarantine.sh ---
Q="$T/q"
quar() { SS_QUARANTINE_DIR="$Q" sh "$QUAR" "$@" >/dev/null 2>"$T/quar.err"; QRC=$?; }
archives() { find "$Q" -maxdepth 1 -type f \( -name '*.zip' -o -name '*.tar.gz' \) | sort; }

quar "$T/does-not-exist"
eq "quar: missing file exits 0" "$QRC" 0
mkdir -p "$T/v1" "$T/v2"
printf 'evil payload\n' > "$T/v1/tool"
want="$(sha256sum < "$T/v1/tool" | awk '{print $1}')"
quar "$T/v1/tool"
eq "quar: exits 0" "$QRC" 0
check "quar: original removed" test ! -e "$T/v1/tool"
check "quar: quarantine dir is 0700" sh -c "[ \"\$(stat -c %a '$Q')\" = 700 ]"
z="$(archives | head -1)"
check "quar: archive holds the file" sh -c "unzip -p '$z' tool | grep -qx 'evil payload'"
check "quar: metadata records the original path" sh -c "unzip -p '$z' '*.meta' | grep -qx 'original_path: $T/v1/tool'"
check "quar: metadata sha256 matches the file" sh -c "unzip -p '$z' '*.meta' | grep -qx 'sha256: $want'"
check "quar: no leftover metadata or reservation files" sh -c "[ \$(find '$Q' -type f | wc -l) -eq 1 ]"
printf 'one\n' > "$T/v1/same"; printf 'two\n' > "$T/v2/same"
quar "$T/v1/same"; quar "$T/v2/same"
check "quar: same name twice in a second -> two archives, both kept" \
	sh -c "for z in \$(find '$Q' -name '*-same.zip'); do unzip -p \"\$z\" same; done | sort | tr '\n' ' ' | grep -qx 'one two '"
nl="$T/v1/evil
original_path: shadow"
printf 'x\n' > "$nl"
quar "$nl"
z="$(find "$Q" -name '*-evil_original_path__shadow.zip' | head -1)"
check "quar: archive name is sanitised" test -n "$z"
check "quar: a newline in the name cannot forge a metadata line" \
	sh -c "[ \"\$(unzip -p '$z' '*.meta' | grep -c '^original_path:')\" = 1 ]"
printf 'dash\n' > "$T/v1/-rf"
(cd "$T/v1" && SS_QUARANTINE_DIR="$Q" sh "$QUAR" -- 2>/dev/null; SS_QUARANTINE_DIR="$Q" sh "$QUAR" "-rf" >/dev/null 2>&1)
check "quar: a relative name starting with '-' is archived, not parsed" \
	sh -c "test ! -e '$T/v1/-rf' && unzip -p \"\$(find '$Q' -name '*--rf.zip' | head -1)\" -- -rf | grep -qx dash"

# zip that fails (disk full): the original must stay
mkdir -p "$T/badzip"; printf '#!/bin/sh\nexit 12\n' > "$T/badzip/zip"; chmod 0755 "$T/badzip/zip"
printf 'keep me\n' > "$T/v1/keep"
n0="$(find "$Q" -type f | wc -l)"
SS_QUARANTINE_DIR="$Q" PATH="$T/badzip:$PATH" sh "$QUAR" "$T/v1/keep" >/dev/null 2>&1; rc=$?
check "quar: archive failure exits non-zero" test "$rc" -ne 0
check "quar: archive failure leaves the original in place (was deleted before)" grep -qx 'keep me' "$T/v1/keep"
check "quar: archive failure leaves no partial files" test "$(find "$Q" -type f | wc -l)" -eq "$n0"

# no zip installed: tar.gz fallback, with a PATH that has everything but zip
mkdir -p "$T/nozip"
for t in sh mkdir chmod date basename dirname mktemp sed sha256sum awk ls head tar gzip grep rm cat tr; do
	ln -sf "$(command -v "$t")" "$T/nozip/$t"
done
printf 'tarred\n' > "$T/v1/viatar"
SS_QUARANTINE_DIR="$Q" PATH="$T/nozip" sh "$QUAR" "$T/v1/viatar" >/dev/null 2>&1; rc=$?
eq "quar: without zip falls back to tar.gz" "$rc" 0
z="$(find "$Q" -name '*-viatar.tar.gz' | head -1)"
check "quar: tar.gz holds the file and its metadata" \
	sh -c "tar -xzOf '$z' ./viatar | grep -qx tarred && tar -tzf '$z' | grep -q '\\.meta\$'"
check "quar: tar fallback removed the original" test ! -e "$T/v1/viatar"
printf '#!/bin/sh\nexit 2\n' > "$T/nozip/tar.fail"; chmod 0755 "$T/nozip/tar.fail"
ln -sf "$T/nozip/tar.fail" "$T/nozip/tar"
printf 'keep too\n' > "$T/v1/keep2"
SS_QUARANTINE_DIR="$Q" PATH="$T/nozip" sh "$QUAR" "$T/v1/keep2" >/dev/null 2>&1; rc=$?
check "quar: tar failure keeps the original too" sh -c "[ $rc -ne 0 ] && grep -qx 'keep too' '$T/v1/keep2'"

# ----------------------------------------------------------------- part 2
echo "# part 2: ROOT-ONLY - real nft in throwaway network namespaces"
if [ "$(id -u)" -ne 0 ] || ! command -v ip >/dev/null || ! command -v nft >/dev/null ||
	! command -v nsenter >/dev/null || ! command -v ping >/dev/null || ! command -v nc >/dev/null; then
	skip "network namespace tests (need root, ip, nft, nsenter, ping, nc)"
	tap_done; exit $?
fi
for m in lan-only public-only host; do
	PATH="$T/stub:$PATH" SS_NET_DRYRUN="$T/rules-$m" sh "$NET" "$m" >/dev/null 2>&1
	check "nft accepts the $m ruleset (nft -c)" unshare -n nft -c -f "$T/rules-$m"
done

# gw: the LAN router, 10.99.0.1 / 2001:db8:99::1, also "the internet" at
# 198.51.100.1 / 2001:db8:ff::1. cl: the protected host, 10.99.0.2.
unshare -n sleep 600 >/dev/null 2>&1 & G=$!; PIDS+=("$G")
unshare -n sleep 600 >/dev/null 2>&1 & CL=$!; PIDS+=("$CL")
sleep 0.2
inG() { nsenter -t "$G" -n "$@"; }
inC() { nsenter -t "$CL" -n "$@"; }
if ! { inC ip link add cl0 type veth peer name gw0 && inC ip link set gw0 netns "$G" &&
	inG ip link set lo up && inG ip link set gw0 up &&
	inG ip addr add 10.99.0.1/24 dev gw0 && inG ip addr add 198.51.100.1/32 dev lo &&
	inC ip link set lo up && inC ip link set cl0 up &&
	inC ip addr add 10.99.0.2/24 dev cl0 && inC ip route add default via 10.99.0.1; } 2>"$T/ns.err"; then
	not_ok "network namespaces set up ($(head -1 "$T/ns.err"))"; tap_done; exit 1
fi
ok "network namespaces set up (veth, IPv4, default route)"
# IPv6 only where the kernel has it (some container kernels do not).
V6=0
if { inG ip -6 addr add 2001:db8:99::1/64 dev gw0 nodad && inG ip -6 addr add 2001:db8:ff::1/128 dev lo &&
	inC ip -6 addr add 2001:db8:99::2/64 dev cl0 nodad &&
	inC ip -6 route add default via 2001:db8:99::1; } 2>/dev/null; then V6=1; fi
v6check()  { if [ "$V6" = 1 ]; then check "$@"; else skip "$1 (no IPv6 in this kernel)"; fi; }
v6refute() { if [ "$V6" = 1 ]; then refute "$@"; else skip "$1 (no IPv6 in this kernel)"; fi; }
inG sh -c 'sysctl -qw net.ipv4.ip_forward=1; sysctl -qw net.ipv6.conf.all.forwarding=1' 2>/dev/null
# TCP listeners on the gateway: 53 (DNS) and 8080 (any other LAN service)
# (nsenter execs nc, so $! is the listener itself and cleanup can kill it;
# its output must not hold this script's stdout open)
LISTEN=("10.99.0.1 53" "10.99.0.1 8080" "198.51.100.1 443")
[ "$V6" = 1 ] && LISTEN+=("2001:db8:99::1 8080")
for l in "${LISTEN[@]}"; do
	# shellcheck disable=SC2086 # "addr port" split on purpose
	nsenter -t "$G" -n nc -lk $l </dev/null >/dev/null 2>&1 & PIDS+=($!)
done
sleep 0.3
reach()  { inC ping -c1 -W1 "$1" >/dev/null 2>&1; }
treach() { inC nc -z -w2 "$1" "$2" >/dev/null 2>&1; }
apply()  { inC sh "$NET" "$1" >/dev/null 2>&1; }

check "before: LAN gateway reachable" reach 10.99.0.1
v6check "before: LAN service over IPv6 (tcp/8080) reachable" treach 2001:db8:99::1 8080
check "before: internet reachable" reach 198.51.100.1

apply lan-only; rc=$?
eq "lan-only applied" "$rc" 0
check  "lan-only: LAN gateway (IPv4) reachable" reach 10.99.0.1
refute "lan-only: internet (IPv4) blocked" reach 198.51.100.1
v6check  "lan-only: LAN (IPv6) reachable" reach 2001:db8:99::1
v6refute "lan-only: internet (IPv6) blocked" reach 2001:db8:ff::1
refute "lan-only: internet TCP blocked" treach 198.51.100.1 443

apply bogus
check "unknown mode leaves the lan-only rules in place" inC nft list chain inet secure_sudo output
refute "still blocked after the unknown mode" reach 198.51.100.1

apply public-only; rc=$?
eq "public-only applied" "$rc" 0
refute "public-only: LAN gateway ping blocked" reach 10.99.0.1
refute "public-only: LAN service (tcp/8080) blocked" treach 10.99.0.1 8080
check  "public-only: DNS on the gateway (tcp/53) still reachable" treach 10.99.0.1 53
check  "public-only: internet (IPv4) reachable" reach 198.51.100.1
check  "public-only: internet TCP reachable" treach 198.51.100.1 443
v6check  "public-only: internet (IPv6) reachable" reach 2001:db8:ff::1
v6refute "public-only: LAN (IPv6) ping blocked (only neighbour discovery and errors pass)" reach 2001:db8:99::1
v6refute "public-only: LAN service over IPv6 (tcp/8080) blocked" treach 2001:db8:99::1 8080

inC ip route del default
apply lan-only; rc=$?
eq "no default route: lan-only still applies to the LAN" "$rc" 0
check "no default route: the LAN gateway is reachable" reach 10.99.0.1
inC ip route add default via 10.99.0.1

apply host; rc=$?
eq "host mode applied" "$rc" 0
refute "host mode removed the table" inC nft list table inet secure_sudo
check "host mode: LAN and internet reachable" sh -c "nsenter -t $CL -n ping -c1 -W1 10.99.0.1 >/dev/null && nsenter -t $CL -n ping -c1 -W1 198.51.100.1 >/dev/null"

tap_done
