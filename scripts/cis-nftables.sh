#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# cis-nftables.sh - the CIS firewall table, owned separately from secure_sudo
# (TODO P3-2, OSB-16; owner's choice 2026-11-23: "coexist, separate tables").
#
# Ownership model:
#   * CIS owns table "inet filter": persistent, in /etc/nftables.conf, loaded
#     by nftables.service. Default-deny base chains for input, forward and
#     output, loopback rules, established/related traffic, the ICMP/ICMPv6
#     needed for a working network, and inbound SSH (plus --allow-tcp ports).
#     Outbound new connections are allowed (CIS asks for an explicit rule).
#   * secure_sudo owns table "inet secure_sudo": not persistent, re-applied by
#     secure-sudod (lan-only / public-only). Neither table touches the other.
#   * nftables evaluates every base chain of a hook: a packet must be accepted
#     by both tables, so the stricter of the two always wins and neither can
#     loosen the other.
#   * The file never says "flush ruleset" (OSB-23): it resets only its own
#     table, so loading it never removes secure_sudo's.
#
# Usage:
#   cis-nftables.sh [--allow-tcp PORT]... [--forward drop|established]
#                   [--print | --out FILE | --apply]
#   --allow-tcp     inbound TCP port to allow (repeatable). SSH ports from
#                   `sshd -T` are always added (22 if sshd is not there).
#   --forward       established (default): routed replies pass, new routed
#                   flows are dropped; drop: nothing is routed.
#   --print         write the ruleset to stdout (default)
#   --out FILE      write it to FILE
#   --apply         write /etc/nftables.conf (backup .pre-cis), check with
#                   nft -c, load it, enable nftables.service. Root only.
# Environment (tests): SS_CIS_NFT_CONF overrides /etc/nftables.conf,
# SS_CIS_SSH_PORTS overrides the sshd port lookup.
set -euo pipefail

PORTS=(); FWD=established; ACTION=print; OUT=""
CONF="${SS_CIS_NFT_CONF:-/etc/nftables.conf}"
die() { echo "cis-nftables: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
	case "$1" in
	--allow-tcp) [[ "${2:-}" =~ ^[0-9]{1,5}$ ]] && [ "$2" -ge 1 ] && [ "$2" -le 65535 ] || die "bad port: ${2:-}"
	             PORTS+=("$2"); shift 2 ;;
	--forward)   case "${2:-}" in drop|established) FWD="$2" ;; *) die "bad --forward: ${2:-}" ;; esac; shift 2 ;;
	--print)     ACTION=print; shift ;;
	--out)       ACTION=out; OUT="${2:?}"; shift 2 ;;
	--apply)     ACTION=apply; shift ;;
	-h|--help)   sed -n '3,36p' "$0"; exit 0 ;;
	*) die "unknown argument $1" ;;
	esac
done

ssh_ports() {
	if [ -n "${SS_CIS_SSH_PORTS:-}" ]; then printf '%s\n' $SS_CIS_SSH_PORTS; return; fi
	if command -v sshd >/dev/null 2>&1 && sshd -T 2>/dev/null | awk '$1=="port"{print $2; f=1} END{exit !f}'; then return; fi
	echo 22
}
mapfile -t ALL < <({ ssh_ports; printf '%s\n' "${PORTS[@]+"${PORTS[@]}"}"; } | grep -E '^[0-9]+$' | sort -n -u)
tcp="$(IFS=,; echo "${ALL[*]}")"

ruleset() {
	cat <<RULES
#!/usr/sbin/nft -f
# CIS firewall table, written by secure_sudo's scripts/cis-nftables.sh.
# It resets only its own table; secure_sudo's "inet secure_sudo" table is
# never touched (OSB-23). Do not add "flush ruleset" here.
table inet filter
delete table inet filter

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		ip saddr 127.0.0.0/8 counter drop
		ip6 saddr ::1 counter drop
		ct state established,related accept
		ct state invalid drop
		meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept
		meta l4proto ipv6-icmp icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query } accept
		udp sport 67 udp dport 68 accept
		udp sport 547 udp dport 546 accept
		tcp dport { $tcp } ct state new accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
RULES
	[ "$FWD" = established ] && echo "		ct state established,related accept"
	cat <<'RULES'
	}
	chain output {
		type filter hook output priority filter; policy drop;
		oif "lo" accept
		ct state new,established,related accept
	}
}
RULES
}

case "$ACTION" in
print) ruleset ;;
out)   ruleset > "$OUT" ;;
apply)
	[ "$(id -u)" -eq 0 ] || die "--apply needs root"
	command -v nft >/dev/null || die "nft not installed"
	tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
	ruleset > "$tmp"
	nft -c -f "$tmp" || { echo "cis-nftables: generated ruleset fails nft -c; nothing changed" >&2; exit 1; }
	[ -f "$CONF" ] && cp -p "$CONF" "$CONF.pre-cis"
	install -m 0644 "$tmp" "$CONF"
	nft -f "$CONF" || { [ -f "$CONF.pre-cis" ] && cp -p "$CONF.pre-cis" "$CONF"; echo "cis-nftables: load failed; previous file restored" >&2; exit 1; }
	if command -v systemctl >/dev/null 2>&1; then systemctl enable nftables.service >/dev/null 2>&1 || echo "cis-nftables: could not enable nftables.service" >&2; fi
	echo "cis-nftables: inet filter loaded from $CONF (inbound tcp: $tcp, forward: $FWD)"
	;;
esac
