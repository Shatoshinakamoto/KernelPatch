#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# apply-net.sh <monitor|host|lan-only|public-only>
#
# Installs (or removes) a single nftables table "inet secure_sudo" implementing
# the network mode. Called by secure-sudod whenever net_mode changes; it always
# deletes the old table first, so switching modes never leaves stale rules.
#
#   monitor / host : no nft rules (host mode's raw/packet block is in-kernel).
#   lan-only       : only traffic to/from the local LAN subnet(s) is allowed.
#   public-only    : traffic to/from the local LAN subnet(s) is dropped.
#
# The LAN subnets are auto-detected from the interface that owns the default
# route. This is a sane starting policy; tune it for multi-homed hosts.
set -eu

MODE="${1:-monitor}"

# Always start clean.
nft delete table inet secure_sudo 2>/dev/null || true

case "$MODE" in
  monitor|host)
    exit 0 ;;
  lan-only|public-only)
    ;;
  *)
    echo "apply-net.sh: unknown mode '$MODE'" >&2
    exit 2 ;;
esac

# Detect the default-route interface and its IPv4 subnet(s).
IFACE="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
if [ -z "${IFACE:-}" ]; then
  echo "apply-net.sh: no default route; not applying $MODE" >&2
  exit 1
fi

LAN_CIDRS="$(ip -o -f inet addr show dev "$IFACE" 2>/dev/null | awk '{print $4}')"
if [ -z "$LAN_CIDRS" ]; then
  echo "apply-net.sh: could not determine LAN subnet on $IFACE" >&2
  exit 1
fi

# Build the nft set elements (comma-separated), always including loopback.
ELEMENTS="127.0.0.0/8"
for c in $LAN_CIDRS; do
  ELEMENTS="$ELEMENTS, $c"
done

if [ "$MODE" = "lan-only" ]; then
  OUT_RULE='ip daddr != @lan drop'
  IN_RULE='ip saddr != @lan drop'
else # public-only
  OUT_RULE='ip daddr @lan drop'
  IN_RULE='ip saddr @lan drop'
fi

nft -f - <<EOF
table inet secure_sudo {
    set lan {
        type ipv4_addr
        flags interval
        elements = { $ELEMENTS }
    }
    chain output {
        type filter hook output priority 0; policy accept;
        oif "lo" accept
        $OUT_RULE
    }
    chain input {
        type filter hook input priority 0; policy accept;
        iif "lo" accept
        $IN_RULE
    }
}
EOF

echo "apply-net.sh: mode $MODE applied on $IFACE (lan: $LAN_CIDRS)"
