#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# apply-net.sh <monitor|host|lan-only|public-only>   apply (or refresh) a mode
# apply-net.sh stop                                   daemon stopping: on_stop
# apply-net.sh status                                 what is loaded, and why
#
# Installs (or removes) one nftables table "inet secure_sudo" implementing the
# network mode. secure-sudod runs it when net_mode changes and again every
# few seconds, so a DHCP renewal onto another subnet, a new interface or a
# lost address is picked up (TODO P1-8). When nothing changed it does not
# touch nft at all.
#
#   monitor / host : no nft rules (host mode's raw/packet block is in-kernel).
#   lan-only       : only traffic to/from the LAN and local subnets is allowed.
#   public-only    : traffic to/from the LAN subnets is dropped, except DHCP,
#                    DHCPv6, neighbour discovery and DNS to a LAN gateway.
#
# Which subnets are "LAN" (docs/CONFIGURATION.md, net.conf):
#   * every address on a LAN interface. lan_interfaces = auto (default) means
#     every interface with a global address except loopback, VPN interfaces
#     and bridges that do not carry a default route (docker0, virbr0: those
#     are "local", reachable in both modes); or list them by name;
#   * VPN interfaces (vpn_interfaces patterns, or any non-Ethernet link type
#     such as WireGuard, tun, ppp, GRE) are never LAN: in lan-only a VPN
#     endpoint is not on the LAN, so the VPN is cut; in public-only the tunnel
#     works and the LAN stays blocked inside it too;
#   * plus extra_lan CIDRs.
# The same rules also filter FORWARDED traffic (forward = 1, default), so
# containers and network namespaces routed through this host are held to the
# mode too. A namespace with its own uplink (macvlan, a passed-through NIC)
# never touches this host's tables: see docs/CONFIGURATION.md.
#
# Fail-safe policy:
#   * The old table is replaced in ONE nft transaction: there is never a
#     moment without rules.
#   * An unknown mode, a bad net.conf or an nft load failure leaves the
#     current rules in place (exit 1/2).
#   * No LAN subnet found (no address yet at boot, cable out, DHCP lost):
#     if this mode's rules are already loaded they stay (exit 1); otherwise a
#     fail-closed PENDING ruleset is loaded (exit 3): lan-only allows only
#     loopback, local bridges, DHCP and neighbour discovery; public-only drops
#     every private range (10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7,
#     fe80::/10). The daemon keeps retrying until the real rules load.
#   * Daemon stop: on_stop = keep (default) leaves the rules loaded, so
#     killing the daemon does not open the network; on_stop = remove deletes
#     them on a clean stop. A crash always keeps them. Rules do not survive a
#     reboot; the daemon re-applies at start.
#
# Exit: 0 applied or unchanged, 1 failed (current rules kept), 2 usage,
#       3 fail-closed pending ruleset loaded.
#
# Environment (tests): SS_NET_DRYRUN=<file> writes the ruleset to <file>
# instead of loading it; SS_NET_CONF, SS_NET_STATE, SS_NET_SYSFS override
# /etc/secure_sudo/net.conf, /run/secure_sudo/net.state, /sys/class/net.
set -eu

MODE="${1:-monitor}"
CONF="${SS_NET_CONF:-/etc/secure_sudo/net.conf}"
STATE="${SS_NET_STATE:-/run/secure_sudo/net.state}"
SYSNET="${SS_NET_SYSFS:-/sys/class/net}"

say() { echo "apply-net.sh: $*"; }
err() { echo "apply-net.sh: $*" >&2; }
note() { # also to syslog (authpriv, like the rest of secure_sudo)
	say "$*"
	if command -v logger >/dev/null 2>&1; then
		logger -p authpriv.notice -t secure-sudo-net -- "$*" 2>/dev/null || true
	fi
}

conf() { # key default -> last value set in net.conf, comments stripped
	v=""
	if [ -r "$CONF" ]; then
		v="$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONF" |
			tail -1 | sed 's/[[:space:]]*#.*//; s/[[:space:]]*$//')"
	fi
	printf '%s' "${v:-$2}"
}

state_get() {
	if [ -r "$STATE" ]; then sed -n "s/^$1=//p" "$STATE" | tail -1; fi
}
state_put() { # mode sha status
	d="$(dirname "$STATE")"
	mkdir -p "$d" && chmod 0700 "$d"
	printf 'mode=%s\nsha256=%s\nstatus=%s\nupdated=%s\n' "$1" "$2" "$3" \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATE.tmp" && mv -f "$STATE.tmp" "$STATE"
}

table_loaded() {
	if [ -n "${SS_NET_DRYRUN:-}" ]; then [ -s "$SS_NET_DRYRUN" ]; return; fi
	nft list table inet secure_sudo >/dev/null 2>&1
}

load() { # ruleset on stdin
	if [ -n "${SS_NET_DRYRUN:-}" ]; then cat > "$SS_NET_DRYRUN"; else nft -f -; fi
}

# "table ...; delete table ..." creates the table if missing so the delete
# never fails; the new table (if any) follows in the same transaction.
header() { printf 'table inet secure_sudo\ndelete table inet secure_sudo\n'; }

remove_table() {
	if [ -n "${SS_NET_DRYRUN:-}" ]; then header > "$SS_NET_DRYRUN"; else header | nft -f -; fi
}

case "$MODE" in
  status)
	m="$(state_get mode)"; s="$(state_get status)"
	if table_loaded; then t=loaded; else t=absent; fi
	echo "mode=${m:-none} status=${s:-none} table=$t updated=$(state_get updated)"
	case "${m:-monitor}:$t" in
	  monitor:absent|host:absent|lan-only:loaded|public-only:loaded) exit 0 ;;
	  *) exit 1 ;;
	esac ;;
  stop)
	p="$(conf on_stop keep)"
	case "$p" in
	  remove)
		remove_table
		rm -f "$STATE"
		note "daemon stopping: on_stop=remove, network rules removed" ;;
	  keep)
		if table_loaded; then
			note "daemon stopping: on_stop=keep, network rules ($(state_get mode)) stay loaded"
		fi ;;
	  *) err "on_stop must be keep or remove (got '$p'); rules kept"; exit 1 ;;
	esac
	exit 0 ;;
  monitor|host)
	if [ "$(state_get mode)" = "$MODE" ] && ! table_loaded; then exit 0; fi
	header | load
	state_put "$MODE" - applied
	say "mode $MODE: no nft rules"
	exit 0 ;;
  lan-only|public-only)
	;;
  *)
	err "unknown mode '$MODE'; current rules left in place"
	exit 2 ;;
esac

# ---- configuration --------------------------------------------------------
LAN_IFS="$(conf lan_interfaces auto)"
VPN_PATS="$(conf vpn_interfaces 'wg* tun* tap* ppp* tailscale* zt* nordlynx* ipsec* vti* utun*')"
EXTRA="$(conf extra_lan '')"
FORWARD="$(conf forward 1)"
bad=""
for w in $LAN_IFS $VPN_PATS; do
	case "$w" in *[!A-Za-z0-9_.:@*-]*) bad="$w" ;; esac
done
for w in $EXTRA; do
	case "$w" in *[!0-9A-Fa-f:./]*|"") bad="$w" ;; esac
done
case "$FORWARD" in 0|1) ;; *) bad="forward=$FORWARD" ;; esac
if [ -n "$bad" ]; then
	err "bad value '$bad' in $CONF; current rules left in place"
	exit 1
fi

# ---- detection ------------------------------------------------------------
is_vpn() { # iface
	for p in $VPN_PATS; do
		# shellcheck disable=SC2254 # the pattern is a glob on purpose
		case "$1" in $p) return 0 ;; esac
	done
	# 1 Ethernet/Wi-Fi, 32 InfiniBand; WireGuard/tun are 65534, ppp 512,
	# GRE/IPIP/SIT 768-778: tunnels, not a LAN
	if [ -r "$SYSNET/$1/type" ]; then
		case "$(cat "$SYSNET/$1/type")" in 1|32) ;; *) return 0 ;; esac
	fi
	return 1
}

GW4=""; GW6=""
routes="$(ip route show default 2>/dev/null || true)
$(ip -6 route show default 2>/dev/null || true)"
DEFAULT_DEVS="$(printf '%s\n' "$routes" | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | sort -u)"

is_default_dev() { printf '%s\n' "$DEFAULT_DEVS" | grep -qx -- "$1"; }

class() { # iface -> lan | local | vpn | skip
	[ "$1" = lo ] && { echo skip; return; }
	is_vpn "$1" && { echo vpn; return; }
	if [ "$LAN_IFS" != auto ]; then
		for l in $LAN_IFS; do [ "$l" = "$1" ] && { echo lan; return; }; done
		echo local; return
	fi
	if [ -d "$SYSNET/$1/bridge" ] && ! is_default_dev "$1"; then echo local; return; fi
	echo lan
}

LAN4=""; LAN6=""; LOC4=""; LOC6=""; LANIF=""
addrs="$(ip -o addr show scope global 2>/dev/null || true)"
while read -r _ ifc fam cidr _; do
	[ -n "${cidr:-}" ] || continue
	ifc="${ifc%%@*}"
	case "$(class "$ifc")" in
	  lan)
		case " $LANIF " in *" $ifc "*) ;; *) LANIF="$LANIF $ifc" ;; esac
		if [ "$fam" = inet ]; then LAN4="$LAN4 $cidr"; else LAN6="$LAN6 $cidr"; fi ;;
	  local)
		if [ "$fam" = inet ]; then LOC4="$LOC4 $cidr"; else LOC6="$LOC6 $cidr"; fi ;;
	esac
done <<EOF
$addrs
EOF
for c in $EXTRA; do
	case "$c" in *:*) LAN6="$LAN6 $c" ;; *) LAN4="$LAN4 $c" ;; esac
done
# DNS exemption: gateways of default routes that leave through a LAN interface
while read -r line; do
	# shellcheck disable=SC2086 # split the route into words
	set -- $line
	via=""; dev=""
	while [ $# -gt 1 ]; do
		case "$1" in via) via="$2" ;; dev) dev="$2" ;; esac
		shift
	done
	if [ -z "$via" ] || [ -z "$dev" ]; then continue; fi
	case " $LANIF " in *" $dev "*) ;; *) continue ;; esac
	case "$via" in *:*) GW6="$GW6 $via" ;; *) GW4="$GW4 $via" ;; esac
done <<EOF
$routes
EOF

STATUS=applied
if [ -z "$LAN4$LAN6" ]; then
	if [ "$(state_get mode)" = "$MODE" ] && [ "$(state_get status)" = applied ] && table_loaded; then
		err "no LAN subnet found; the $MODE rules already loaded stay in place"
		exit 1
	fi
	STATUS=pending
	err "no LAN subnet found; loading the fail-closed $MODE pending rules"
	if [ "$MODE" = public-only ]; then
		LAN4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16"
	fi
fi

# ---- ruleset --------------------------------------------------------------
join() { # words -> "a, b, c"
	first=1
	for e in "$@"; do
		[ "$first" = 1 ] || printf ', '
		printf '%s' "$e"; first=0
	done
}
elements() { # words -> an "elements = { ... }" line, or nothing when empty
	[ $# -gt 0 ] || return 0
	printf 'elements = { %s }' "$(join "$@")"
}
# shellcheck disable=SC2086 # the address lists are split into words on purpose
if [ "$MODE" = lan-only ]; then
	# what counts as local: loopback, unspecified (DAD), link-local,
	# multicast, ULA, the LAN and the local bridges
	EL_LAN="$(elements 127.0.0.0/8 $LAN4 $LOC4)"
	EL_LAN6="$(elements ::1 ::/128 fe80::/10 ff00::/8 fc00::/7 $LAN6 $LOC6)"
else
	EL_LAN="$(elements $LAN4)"
	EL_LAN6="$(elements fe80::/10 fc00::/7 $LAN6)"
fi
# shellcheck disable=SC2086
{
	EL_LOC="$(elements $LOC4)"
	EL_LOC6="$(elements $LOC6)"
}

KEEP="udp sport { 67, 68 } udp dport { 67, 68 } accept
        udp sport { 546, 547 } udp dport { 546, 547 } accept
        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, mld-listener-query, mld-listener-report, mld2-listener-report } accept"

if [ "$MODE" = lan-only ]; then
	OUT="$KEEP
        ip daddr != @lan drop
        ip6 daddr != @lan6 drop"
	IN="$KEEP
        ip saddr != @lan drop
        ip6 saddr != @lan6 drop"
	FWD="ip daddr != @lan drop
        ip saddr != @lan drop
        ip6 daddr != @lan6 drop
        ip6 saddr != @lan6 drop"
else
	OUT="$KEEP
        ip daddr @localnet accept
        ip6 daddr @localnet6 accept"
	IN="$KEEP
        ip saddr @localnet accept
        ip6 saddr @localnet6 accept"
	for g in $GW4; do
		OUT="$OUT
        ip daddr $g meta l4proto { tcp, udp } th dport 53 accept"
		IN="$IN
        ip saddr $g meta l4proto { tcp, udp } th sport 53 accept"
	done
	for g in $GW6; do
		OUT="$OUT
        ip6 daddr $g meta l4proto { tcp, udp } th dport 53 accept"
		IN="$IN
        ip6 saddr $g meta l4proto { tcp, udp } th sport 53 accept"
	done
	OUT="$OUT
        ip daddr @lan drop
        ip6 daddr @lan6 drop"
	IN="$IN
        ip saddr @lan drop
        ip6 saddr @lan6 drop"
	FWD="ip daddr @lan drop
        ip saddr @lan drop
        ip6 daddr @lan6 drop
        ip6 saddr @lan6 drop"
fi

FWD_CHAIN=""
if [ "$FORWARD" = 1 ]; then
	FWD_CHAIN="
    chain forward {
        type filter hook forward priority 0; policy accept;
        $FWD
    }"
fi

RULES="$(cat <<EOF
table inet secure_sudo {
    set lan {
        type ipv4_addr
        flags interval
        auto-merge
        $EL_LAN
    }
    set lan6 {
        type ipv6_addr
        flags interval
        auto-merge
        $EL_LAN6
    }
    set localnet {
        type ipv4_addr
        flags interval
        auto-merge
        $EL_LOC
    }
    set localnet6 {
        type ipv6_addr
        flags interval
        auto-merge
        $EL_LOC6
    }
    chain output {
        type filter hook output priority 0; policy accept;
        oif "lo" accept
        $OUT
    }
    chain input {
        type filter hook input priority 0; policy accept;
        iif "lo" accept
        $IN
    }$FWD_CHAIN
}
EOF
)"

SHA="$(printf '%s\n' "$RULES" | sha256sum | awk '{print $1}')"
PREV_MODE="$(state_get mode)"
if [ "$PREV_MODE" = "$MODE" ] && [ "$(state_get sha256)" = "$SHA" ] && table_loaded; then
	[ "$STATUS" = pending ] && exit 3
	exit 0	# nothing changed: nft is not touched
fi

if ! printf '%s\n%s\n' "$(header)" "$RULES" | load; then
	err "nft refused the $MODE ruleset; current rules left in place"
	exit 1
fi
state_put "$MODE" "$SHA" "$STATUS"

summary="lan:$(echo "$LAN4 $LAN6" | tr -s ' \n' ' ')"
[ -n "$LOC4$LOC6" ] && summary="$summary; local:$(echo "$LOC4 $LOC6" | tr -s ' \n' ' ')"
if [ "$STATUS" = pending ]; then
	note "mode $MODE: PENDING fail-closed rules loaded (no LAN subnet detected yet)"
	exit 3
fi
if [ "$PREV_MODE" = "$MODE" ]; then
	note "mode $MODE: network changed, rules re-applied ($summary)"
else
	note "mode $MODE applied ($summary)"
fi
