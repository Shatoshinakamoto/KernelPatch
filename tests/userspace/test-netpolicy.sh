#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-netpolicy.sh - net_mode's nftables rules against real traffic (TODO
# P1-8). A small network is built from network namespaces and veth pairs,
# apply-net.sh loads its real ruleset with the real nft in the host-under-test
# namespace, and ping / UDP probes show what gets through:
#
#   W (internet 203.0.113.2, 2001:db8:99::2)
#   |
#   R (router 192.168.50.1, 2001:db8:50::1; DNS on udp/53)
#   |  eth0 (default route, LAN)
#   H ---- eth1 ---- M (second LAN 10.77.0.2, 2001:db8:77::2)
#   |  \
#   |   wg0 (a VPN interface, by name) ---- W (10.200.0.1)
#   br-ctr (bridge, local) ---- C (a container 172.30.0.2, routed via H)
#
# Covers IPv4 and IPv6, multiple interfaces, a VPN, a subnet change (DHCP
# moving the host), forwarded container traffic, pre-existing nftables and
# iptables-nft rules, a daemon restart, failed subnet detection and the
# on_stop policy. Needs root, `ip netns` and nft; skipped otherwise.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

NET="$ROOT/userspace/daemon/helpers/apply-net.sh"
if [ "$(id -u)" -ne 0 ] || ! command -v nft >/dev/null 2>&1 ||
   ! ip netns add "ssnp-probe-$$" 2>/dev/null; then
	skip "net policy tests need root, nft and network namespaces"
	tap_done; exit 0
fi
ip netns del "ssnp-probe-$$"

T="$(mktemp -d)"
P="ssnp$$"
NSS=(H R W M C)
PIDS=()
cleanup() {
	local n p
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	for n in "${NSS[@]}"; do ip netns del "$P$n" 2>/dev/null; done
	rm -rf "$T"
}
trap cleanup EXIT

ns() { local n="$1"; shift; ip netns exec "$P$n" "$@"; }
for n in "${NSS[@]}"; do
	ip netns add "$P$n"
	ns "$n" ip link set lo up
done
# IPv6 checks run only where the kernel has IPv6; otherwise they are
# reported as skipped, never passed vacuously.
V6=0; ns H test -d /proc/sys/net/ipv6 && V6=1
link() { # nsA ifA nsB ifB
	ip link add "$2" netns "$P$1" type veth peer name "$4" netns "$P$3"
	ns "$1" ip link set "$2" up; ns "$3" ip link set "$4" up
}
addr() { # ns if cidr [6]
	if [ -n "${4:-}" ]; then [ "$V6" = 1 ] && ns "$1" ip addr add "$3" dev "$2" nodad; return 0; fi
	ns "$1" ip addr add "$3" dev "$2"
}
link H eth0 R lan0
link R wan0 W eth0
link H eth1 M eth0
link H wg0 W tun0
link C eth0 H vc0
addr H eth0 192.168.50.2/24; addr H eth0 2001:db8:50::2/64 6
addr R lan0 192.168.50.1/24; addr R lan0 2001:db8:50::1/64 6
addr R wan0 203.0.113.1/24;  addr R wan0 2001:db8:99::1/64 6
addr W eth0 203.0.113.2/24;  addr W eth0 2001:db8:99::2/64 6
addr H eth1 10.77.0.1/24;    addr H eth1 2001:db8:77::1/64 6
addr M eth0 10.77.0.2/24;    addr M eth0 2001:db8:77::2/64 6
addr H wg0 10.200.0.2/24;    addr W tun0 10.200.0.1/24
ns H ip link add br-ctr type bridge
ns H ip link set vc0 master br-ctr; ns H ip link set br-ctr up
addr H br-ctr 172.30.0.1/24; addr C eth0 172.30.0.2/24
ns H ip route add default via 192.168.50.1
[ "$V6" = 1 ] && ns H ip -6 route add default via 2001:db8:50::1
ns W ip route add default via 203.0.113.1
[ "$V6" = 1 ] && ns W ip -6 route add default via 2001:db8:99::1
ns R ip route add 172.30.0.0/24 via 192.168.50.2
ns M ip route add 172.30.0.0/24 via 10.77.0.1
ns C ip route add default via 172.30.0.1
for n in H R; do
	ns "$n" sysctl -qw net.ipv4.ip_forward=1
	[ "$V6" = 1 ] && ns "$n" sysctl -qw net.ipv6.conf.all.forwarding=1
done
# a DNS stand-in on the gateway and a UDP echo on the internet host
udp_server() { # ns addr port (ip netns exec execs python: $! is the server)
	ip netns exec "$P$1" python3 -c '
import socket, sys
fam = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    d, a = s.recvfrom(512)
    s.sendto(d, a)
' "$2" "$3" >/dev/null 2>&1 & PIDS+=($!)
}
udp_server R 192.168.50.1 53
udp_server R 192.168.50.1 5353
udp_server W 203.0.113.2 7777
udp() { # ns addr port -> succeeds when the echo comes back
	ns "$1" python3 -c '
import socket, sys
fam = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(b"x", (sys.argv[1], int(sys.argv[2])))
s.recvfrom(16)
' "$2" "$3"
}
sleep 0.5

reach() { ns "$1" ping -q -c1 -W1 "$2" >/dev/null 2>&1; }
v6skip() { case "$3" in *:*) [ "$V6" = 1 ] && return 1; skip "$1 (no IPv6 here)"; return 0 ;; esac; return 1; }
can() { v6skip "$@" || check "$1" reach "${@:2}"; }
cant() { v6skip "$@" || refute "$1" reach "${@:2}"; }

export SS_NET_CONF="$T/net.conf" SS_NET_STATE="$T/run/net.state"
: > "$SS_NET_CONF"
apply() { ns H sh "$NET" "$@" > "$T/out" 2> "$T/err"; ARC=$?; }
handles() { ns H nft -a list table inet secure_sudo 2>/dev/null | md5sum; }
lanset() { ns H nft list set inet secure_sudo "${1:-lan}" 2>/dev/null; }

# ---- baseline: no rules, everything is reachable --------------------------
check "baseline: H reaches the internet (v4)" reach H 203.0.113.2
check "baseline: the container reaches the internet through H" reach C 203.0.113.2
check "baseline: the internet reaches H" reach W 192.168.50.2

# ---- a pre-existing firewall: one nft table and one iptables-nft rule ----
ns H nft -f - <<'EOF'
table inet admin {
    chain out {
        type filter hook output priority -5; policy accept;
        udp dport 7777 counter drop
    }
}
EOF
IPT=0
if command -v iptables >/dev/null 2>&1 && iptables -V 2>/dev/null | grep -q nf_tables &&
   ns H iptables -A OUTPUT -d 203.0.113.2 -p icmp -j ACCEPT 2>/dev/null; then IPT=1; fi
admin_intact() { ns H nft list table inet admin | grep -q 'udp dport 7777 counter packets [1-9][0-9]* bytes [0-9]* drop'; }

# ---- lan-only -------------------------------------------------------------
apply lan-only
eq "lan-only: applied (exit 0)" "$ARC" 0
can "lan-only: H reaches the LAN gateway (IPv4)" H 192.168.50.1
can "lan-only: H reaches the LAN gateway (IPv6)" H 2001:db8:50::1
cant "lan-only: H cannot reach the internet (IPv4)" H 203.0.113.2
cant "lan-only: H cannot reach the internet (IPv6)" H 2001:db8:99::2
cant "lan-only: the internet cannot reach H" W 192.168.50.2
can "lan-only: the second LAN interface is LAN (IPv4)" H 10.77.0.2
can "lan-only: the second LAN interface is LAN (IPv6)" H 2001:db8:77::2
cant "lan-only: a VPN interface is not LAN (the tunnel is cut)" H 10.200.0.1
can "lan-only: H reaches its local container bridge" H 172.30.0.2
can "lan-only: a container reaches the LAN through H" C 192.168.50.1
cant "lan-only: a container's forwarded traffic to the internet is dropped" C 203.0.113.2
check "lan-only: the VPN subnet is not in the LAN set" sh -c "! (ip netns exec ${P}H nft list set inet secure_sudo lan | grep -q 10.200.0.0)"
if [ "$IPT" = 1 ]; then
	cant "lan-only: an iptables ACCEPT for the internet does not override the mode" H 203.0.113.2
else skip "no iptables-nft"; fi
h1="$(handles)"
apply lan-only
eq "restart/re-run with nothing changed: exit 0" "$ARC" 0
eq "... and nft is not touched (same rule handles)" "$(handles)" "$h1"
check "status: consistent" ns H env SS_NET_STATE="$SS_NET_STATE" sh "$NET" status

# ---- DHCP moves the host to another subnet -------------------------------
ns R ip addr add 192.168.60.1/24 dev lan0
ns H ip addr del 192.168.50.2/24 dev eth0
ns H ip addr add 192.168.60.2/24 dev eth0
ns H ip route replace default via 192.168.60.1
apply lan-only
eq "subnet change: re-applied (exit 0)" "$ARC" 0
check "... logged as a network change" grep -q "network changed, rules re-applied" "$T/out"
check "... the new subnet is LAN" sh -c "ip netns exec ${P}H nft list set inet secure_sudo lan | grep -q 192.168.60.0/24"
check "... the old subnet is not" sh -c "! (ip netns exec ${P}H nft list set inet secure_sudo lan | grep -q 192.168.50.0/24)"
can "... the new gateway is reachable" H 192.168.60.1
cant "... the internet still is not" H 203.0.113.2

# ---- failed subnet detection ----------------------------------------------
ns H ip -o addr show scope global | awk '$2=="eth0"||$2=="eth1"{print $2, $4}' > "$T/saved"
while read -r i a; do ns H ip addr del "$a" dev "$i"; done < "$T/saved"
h1="$(handles)"
apply lan-only
eq "no LAN address any more: exit 1" "$ARC" 1
eq "... and the loaded lan-only rules stay (fail-closed)" "$(handles)" "$h1"
ns H nft delete table inet secure_sudo; rm -f "$SS_NET_STATE"
apply lan-only
eq "no LAN address and no rules yet (boot): pending rules (exit 3)" "$ARC" 3
check "... status says pending" grep -q '^status=pending' "$SS_NET_STATE"
can "... pending lan-only still allows the local bridge" H 172.30.0.2
cant "... and blocks everything else" H 203.0.113.2
apply lan-only
eq "... retried with nothing changed: still exit 3" "$ARC" 3
while read -r i a; do
	case "$a" in *:*) ns H ip addr add "$a" dev "$i" nodad ;; *) ns H ip addr add "$a" dev "$i" ;; esac
done < "$T/saved"
ns H ip route replace default via 192.168.60.1
[ "$V6" = 1 ] && ns H ip -6 route replace default via 2001:db8:50::1
apply lan-only
eq "addresses back: the real rules load (exit 0)" "$ARC" 0
check "... status applied" grep -q '^status=applied' "$SS_NET_STATE"

# move back to the original subnet for the rest
ns H ip addr del 192.168.60.2/24 dev eth0
ns H ip addr add 192.168.50.2/24 dev eth0
ns H ip route replace default via 192.168.50.1

# ---- public-only ----------------------------------------------------------
apply public-only
eq "public-only: applied (exit 0)" "$ARC" 0
cant "public-only: H cannot reach the LAN gateway (IPv4)" H 192.168.50.1
cant "public-only: H cannot reach the LAN gateway (IPv6)" H 2001:db8:50::1
check "public-only: DNS to the LAN gateway still works" udp H 192.168.50.1 53
refute "public-only: other UDP to the gateway is dropped" udp H 192.168.50.1 5353
can "public-only: H reaches the internet (IPv4)" H 203.0.113.2
can "public-only: H reaches the internet (IPv6)" H 2001:db8:99::2
can "public-only: the internet reaches H" W 192.168.50.2
cant "public-only: the second LAN interface is blocked too (IPv4; it leaked before)" H 10.77.0.2
cant "public-only: the second LAN interface is blocked too (IPv6)" H 2001:db8:77::2
can "public-only: the VPN works" H 10.200.0.1
can "public-only: H reaches its local container bridge" H 172.30.0.2
cant "public-only: a container cannot reach the LAN through H" C 192.168.50.1
can "public-only: a container reaches the internet" C 203.0.113.2
refute "public-only: the existing firewall's own drop still applies" udp H 203.0.113.2 7777
check "... and its table and counter are untouched" admin_intact

# ---- bad configuration keeps the current rules ---------------------------
h1="$(handles)"
echo "extra_lan = 10.0.0.0/8; drop" > "$SS_NET_CONF"
apply public-only
eq "bad net.conf value: exit 1" "$ARC" 1
eq "... current rules unchanged" "$(handles)" "$h1"
echo "lan_interfaces = eth0" > "$SS_NET_CONF"
apply public-only
eq "explicit lan_interfaces: exit 0" "$ARC" 0
can "... an interface left out of the list is local, not LAN" H 10.77.0.2
cant "... the listed one is still blocked" H 192.168.50.1
: > "$SS_NET_CONF"
apply public-only
apply bogus
eq "unknown mode: exit 2" "$ARC" 2
cant "... current rules unchanged" H 192.168.50.1

# ---- monitor removes only our table --------------------------------------
apply monitor
eq "monitor: exit 0" "$ARC" 0
refute "monitor: the secure_sudo table is gone" ns H nft list table inet secure_sudo
check "monitor: the existing firewall table is still there" admin_intact
can "monitor: the LAN is reachable again" H 192.168.50.1
[ "$IPT" = 1 ] && check "monitor: the iptables rule is still there" ns H iptables -C OUTPUT -d 203.0.113.2 -p icmp -j ACCEPT

# ---- on_stop policy -------------------------------------------------------
apply lan-only
apply stop
eq "stop with on_stop=keep (default): exit 0" "$ARC" 0
check "... the rules stay loaded" ns H nft list table inet secure_sudo
cant "... and keep blocking" H 203.0.113.2
echo "on_stop = remove" > "$SS_NET_CONF"
apply stop
eq "stop with on_stop=remove: exit 0" "$ARC" 0
refute "... the rules are removed" ns H nft list table inet secure_sudo
check "... the existing firewall is untouched" admin_intact

# ---- forward = 0 ----------------------------------------------------------
echo "forward = 0" > "$SS_NET_CONF"
apply lan-only
can "forward = 0: forwarded container traffic is not filtered" C 203.0.113.2
cant "... the host's own traffic still is" H 203.0.113.2

tap_done
