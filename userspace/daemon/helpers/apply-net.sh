#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# apply-net.sh <monitor|host|lan-only|public-only>
#
# Installs (or removes) a single nftables table "inet secure_sudo" implementing
# the network mode. Called by secure-sudod whenever net_mode changes.
#
#   monitor / host : no nft rules (host mode's raw/packet block is in-kernel).
#   lan-only       : only traffic to/from the local LAN subnet(s) is allowed.
#   public-only    : traffic to/from the local LAN subnet(s) is dropped, except
#                    DHCP and DNS to the default gateway, so the host keeps its
#                    lease and name resolution on a typical home/office LAN.
#
# The LAN subnets are auto-detected from the interface that owns the default
# route, for IPv4 and IPv6 (earlier versions matched only IPv4, so lan-only
# let all IPv6 traffic through). Link-local IPv6, multicast and ICMPv6 stay
# allowed where neighbour discovery needs them. This is a sane starting
# policy; tune it for multi-homed hosts.
#
# The old table is replaced in ONE nft transaction: there is never a moment
# without rules, and when the new rules cannot be worked out or loaded (an
# unknown mode, no default route yet, a syntax error) the previous rules stay
# in place and the script exits non-zero.
#
# Environment (tests only): SS_NET_DRYRUN=<file> writes the ruleset to <file>
# instead of loading it.
set -eu

MODE="${1:-monitor}"

load() { # ruleset on stdin
	if [ -n "${SS_NET_DRYRUN:-}" ]; then cat > "$SS_NET_DRYRUN"; else nft -f -; fi
}

# "table ...; delete table ..." creates the table if missing so the delete
# never fails; the new table (if any) follows in the same transaction.
header() { printf 'table inet secure_sudo\ndelete table inet secure_sudo\n'; }

case "$MODE" in
  monitor|host)
    header | load
    echo "apply-net.sh: mode $MODE: no nft rules"
    exit 0 ;;
  lan-only|public-only)
    ;;
  *)
    echo "apply-net.sh: unknown mode '$MODE'; current rules left in place" >&2
    exit 2 ;;
esac

# Detect the default-route interface, gateway(s) and the subnets on it.
field() { awk -v k="$1" '/default/{for(i=1;i<NF;i++) if($i==k){print $(i+1); exit}}'; }
IFACE="$(ip route show default 2>/dev/null | field dev)"
if [ -z "${IFACE:-}" ]; then
  echo "apply-net.sh: no default route; not applying $MODE (current rules left in place)" >&2
  exit 1
fi
GW4="$(ip route show default 2>/dev/null | field via)"
GW6="$(ip -6 route show default 2>/dev/null | field via)"
LAN4="$(ip -o -f inet addr show dev "$IFACE" 2>/dev/null | awk '{print $4}')"
LAN6="$(ip -o -f inet6 addr show dev "$IFACE" scope global 2>/dev/null | awk '{print $4}')"
if [ -z "$LAN4$LAN6" ]; then
  echo "apply-net.sh: could not determine LAN subnet on $IFACE (current rules left in place)" >&2
  exit 1
fi

# Set elements, comma-separated.
join() {
  first=1
  for e in "$@"; do
    [ "$first" = 1 ] || printf ', '
    printf '%s' "$e"; first=0
  done
}
# shellcheck disable=SC2086 # the address lists are split into words on purpose
{
  LAN4_EL="$(join 127.0.0.0/8 $LAN4)"
  # lan-only: what counts as local for IPv6 - loopback, unspecified (DAD),
  # link-local, multicast, ULA and the interface's own prefixes
  LAN6_EL="$(join ::1 ::/128 fe80::/10 ff00::/8 fc00::/7 $LAN6)"
  # public-only: the IPv6 LAN to block (ICMPv6 is exempt for neighbour discovery)
  PRIV6_EL="$(join fe80::/10 fc00::/7 $LAN6)"
}

if [ "$MODE" = "lan-only" ]; then
  OUT_RULES="ip daddr != @lan drop
        ip6 daddr != @lan6 drop"
  IN_RULES="ip saddr != @lan drop
        ip6 saddr != @lan6 drop"
else # public-only
  KEEP="udp sport { 67, 68 } udp dport { 67, 68 } accept
        udp sport { 546, 547 } udp dport { 546, 547 } accept
        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, mld-listener-query, mld-listener-report, mld2-listener-report } accept"
  OUT_RULES="$KEEP"
  IN_RULES="$KEEP"
  if [ -n "$GW4" ]; then
    OUT_RULES="$OUT_RULES
        ip daddr $GW4 meta l4proto { tcp, udp } th dport 53 accept"
    IN_RULES="$IN_RULES
        ip saddr $GW4 meta l4proto { tcp, udp } th sport 53 accept"
  fi
  if [ -n "$GW6" ]; then
    OUT_RULES="$OUT_RULES
        ip6 daddr $GW6 meta l4proto { tcp, udp } th dport 53 accept"
    IN_RULES="$IN_RULES
        ip6 saddr $GW6 meta l4proto { tcp, udp } th sport 53 accept"
  fi
  OUT_RULES="$OUT_RULES
        ip daddr @lan drop
        ip6 daddr @priv6 drop"
  IN_RULES="$IN_RULES
        ip saddr @lan drop
        ip6 saddr @priv6 drop"
fi

{
  header
  cat <<EOF
table inet secure_sudo {
    set lan {
        type ipv4_addr
        flags interval
        elements = { $LAN4_EL }
    }
    set lan6 {
        type ipv6_addr
        flags interval
        elements = { $LAN6_EL }
    }
    set priv6 {
        type ipv6_addr
        flags interval
        elements = { $PRIV6_EL }
    }
    chain output {
        type filter hook output priority 0; policy accept;
        oif "lo" accept
        $OUT_RULES
    }
    chain input {
        type filter hook input priority 0; policy accept;
        iif "lo" accept
        $IN_RULES
    }
}
EOF
} | load

echo "apply-net.sh: mode $MODE applied on $IFACE (lan: $(echo "$LAN4 $LAN6" | tr '\n' ' '))"
