#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# contain.sh - incident containment (TODO P1-7), run by `secure-sudo contain`.
#
#   contain.sh status
#   contain.sh network [--allow ADDR]... [--no-collector] [--dry-run] [-y]
#   contain.sh account USER [--terminate] [--dry-run] [-y]
#   contain.sh process PID [--kill] [--dry-run] [-y]
#   contain.sh release network | account USER | process PID [-y]
#
# Every action prefers the reversible step and keeps evidence first:
#
#   network  one nftables table (inet secure_sudo_contain) dropping all
#            traffic except loopback, the addresses given with --allow, the
#            SSH client of the operator running this (so a remote responder
#            is not cut off) and the configured remote_syslog collector (so
#            evidence keeps flowing). Loaded in one transaction; `release
#            network` deletes the table. It does not touch the net_mode
#            table (inet secure_sudo).
#   account  lock the password, expire the account (blocks SSH keys too),
#            and STOP (SIGSTOP) every process of the user, after saving the
#            process list. --terminate kills them instead. root, UID 0 and
#            the operator's own account are refused. `release account`
#            puts the lock and expiry back as they were and continues the
#            stopped processes.
#   process  save /proc evidence (cmdline, status, maps, open files,
#            sockets, environment, a copy of the executable and its
#            SHA-256), then STOP the process and its descendants. --kill
#            kills them after the evidence is saved. PID 1, kernel threads
#            and the operator's own shell chain are refused. `release
#            process` continues them.
#
# Without -y every action shows its plan and asks for "yes" (anything else
# exits 3, nothing changed); --dry-run shows the plan and changes nothing. State and evidence go to
# /var/lib/secure_sudo/contain (root-only). The CLI records each action in
# the policy history (`secure-sudo history`).
#
# Tests only: SS_CONTAIN_STATE (state dir), SS_CONTAIN_CONF (config file),
# SS_CONTAIN_NFT_DRYRUN=<file> (write the ruleset there instead of loading
# it), SS_CONTAIN_OPERATOR (the operator's login name), SS_CONTAIN_SSH_ADDR.
set -euo pipefail
umask 077

STATE="${SS_CONTAIN_STATE:-/var/lib/secure_sudo/contain}"
CONF="${SS_CONTAIN_CONF:-/etc/secure_sudo/secure-sudo.conf}"
TABLE="secure_sudo_contain"

die() { printf 'contain: %s\n' "$*" >&2; exit 1; }
say() { printf 'contain: %s\n' "$*"; }
usage() { sed -n '4,9p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

DRY=0 YES=0
confirm() { # plan already printed
	[ "$DRY" = 1 ] && { say "dry run: nothing changed"; exit 0; }
	[ "$YES" = 1 ] && return 0
	printf 'Do this? Type yes: ' >&2
	local a=""
	read -r a || true
	[ "$a" = yes ] || { echo "aborted" >&2; exit 3; }
}

state_dir() {
	mkdir -p "$STATE"
	if [ ! -d "$STATE" ] || [ -L "$STATE" ]; then die "$STATE is not a directory"; fi
	chmod 0700 "$STATE"
}

# The operator: the login behind sudo, not root.
operator() {
	if [ -n "${SS_CONTAIN_OPERATOR:-}" ]; then echo "$SS_CONTAIN_OPERATOR"; return; fi
	if [ -n "${SUDO_USER:-}" ]; then echo "$SUDO_USER"; return; fi
	local lu
	lu="$(cat /proc/self/loginuid 2>/dev/null || echo 4294967295)"
	[ "$lu" != 4294967295 ] && getent passwd "$lu" | cut -d: -f1
	return 0
}

# The operator's SSH client address, if this runs in an SSH session.
ssh_addr() {
	if [ -n "${SS_CONTAIN_SSH_ADDR+x}" ]; then echo "$SS_CONTAIN_SSH_ADDR"; return; fi
	if [ -n "${SSH_CONNECTION:-}" ]; then echo "${SSH_CONNECTION%% *}"; return; fi
	# sudo drops SSH_CONNECTION; utmp still has the remote host of this tty
	who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F:.]*\)).*/\1/p' | head -1
}

is_addr() { # IPv4/IPv6 address or prefix
	local a="$1"
	[[ $a =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] && return 0
	[[ $a =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ && $a == *:* ]] && return 0
	return 1
}

# remote_syslog = host:port (or [v6]:port) from secure-sudo.conf -> addresses
collector_addrs() {
	local v host
	v="$(sed -n 's/^[[:space:]]*remote_syslog[[:space:]]*=[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$CONF" 2>/dev/null | tail -1)"
	[ -n "$v" ] || return 0
	if [[ $v == \[*\]:* ]]; then host="${v#[}"; host="${host%%]*}"; else host="${v%:*}"; fi
	if is_addr "$host"; then echo "$host"; return; fi
	getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u
}

ruleset() { # addresses...
	local a in4="" in6="" out4="" out6=""
	for a in "$@"; do
		if [[ $a == *:* ]]; then
			in6+="		ip6 saddr $a accept"$'\n'; out6+="		ip6 daddr $a accept"$'\n'
		else
			in4+="		ip saddr $a accept"$'\n'; out4+="		ip daddr $a accept"$'\n'
		fi
	done
	cat <<EOF
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
	chain input {
		type filter hook input priority -300; policy drop;
		iif "lo" accept
${in4}${in6}		counter comment "dropped by secure-sudo contain"
	}
	chain output {
		type filter hook output priority -300; policy drop;
		oif "lo" accept
${out4}${out6}		counter comment "dropped by secure-sudo contain"
	}
	chain forward {
		type filter hook forward priority -300; policy drop;
	}
}
EOF
}

nft_load() {
	if [ -n "${SS_CONTAIN_NFT_DRYRUN:-}" ]; then cat > "$SS_CONTAIN_NFT_DRYRUN"; else nft -f -; fi
}

net_contained() {
	if [ -n "${SS_CONTAIN_NFT_DRYRUN:-}" ]; then [ -s "$SS_CONTAIN_NFT_DRYRUN" ]
	else nft list table inet "$TABLE" >/dev/null 2>&1; fi
}

cmd_network() {
	local allow=() collector=1 a ssh
	while [ $# -gt 0 ]; do
		case "$1" in
		--allow) [ $# -ge 2 ] || usage; is_addr "$2" || die "not an IP address or prefix: $2"
			allow+=("$2"); shift 2 ;;
		--no-collector) collector=0; shift ;;
		--dry-run) DRY=1; shift ;;
		-y) YES=1; shift ;;
		*) usage ;;
		esac
	done
	ssh="$(ssh_addr || true)"
	if [ -n "$ssh" ] && is_addr "$ssh"; then
		allow+=("$ssh"); say "keeping your SSH client $ssh reachable"
	else
		say "WARNING: no SSH client found for this session; if you are remote, pass --allow YOUR_ADDRESS or you will be cut off"
	fi
	if [ "$collector" = 1 ]; then
		while read -r a; do
			[ -n "$a" ] && is_addr "$a" && { allow+=("$a"); say "keeping the log collector $a reachable"; }
		done < <(collector_addrs)
	fi
	say "plan: drop all network traffic except loopback${allow[*]:+ and ${allow[*]}}"
	say "      (nft table inet $TABLE; undo: secure-sudo contain release network)"
	if [ "$DRY" = 1 ]; then ruleset "${allow[@]}"; fi
	confirm
	ruleset "${allow[@]}" | nft_load || die "nft refused the ruleset; nothing changed"
	state_dir
	{ date -u +%Y-%m-%dT%H:%M:%SZ; printf '%s\n' "${allow[@]}"; } > "$STATE/network"
	say "network contained"
}

cmd_release_network() {
	net_contained || [ -e "$STATE/network" ] || { say "network is not contained"; return 0; }
	say "plan: delete nft table inet $TABLE (restores normal networking)"
	confirm
	if [ -n "${SS_CONTAIN_NFT_DRYRUN:-}" ]; then : > "$SS_CONTAIN_NFT_DRYRUN"
	else printf 'table inet %s\ndelete table inet %s\n' "$TABLE" "$TABLE" | nft -f -; fi
	rm -f -- "$STATE/network"
	say "network released"
}

# ------------------------------------------------------------- accounts
user_pids() { # uid
	local d
	for d in /proc/[0-9]*; do
		[ "$(stat -c %u "$d" 2>/dev/null || echo -)" = "$1" ] && echo "${d#/proc/}"
	done
	return 0
}

cmd_account() {
	local user="" term=0 uid op shadow was_locked expire pids
	while [ $# -gt 0 ]; do
		case "$1" in
		--terminate) term=1; shift ;;
		--dry-run) DRY=1; shift ;;
		-y) YES=1; shift ;;
		-*) usage ;;
		*) [ -z "$user" ] || usage; user="$1"; shift ;;
		esac
	done
	[ -n "$user" ] || usage
	[[ $user =~ ^[a-z_][a-z0-9_.-]*\$?$ ]] || die "not a user name: $user"
	uid="$(getent passwd "$user" | cut -d: -f3 || true)"
	[ -n "$uid" ] || die "no such user: $user"
	[ "$uid" != 0 ] || die "refusing to contain UID 0 ($user): that would lock out root"
	op="$(operator || true)"
	[ "$user" != "$op" ] || die "refusing to contain your own account ($user)"
	shadow="$(getent shadow "$user" || true)"
	was_locked=0; [[ $(cut -d: -f2 <<<"$shadow") == '!'* ]] && was_locked=1
	expire="$(cut -d: -f8 <<<"$shadow")"
	pids="$(user_pids "$uid" | tr '\n' ' ')"
	say "plan: lock the password of $user (uid $uid), expire the account (blocks SSH keys and new logins),"
	if [ "$term" = 1 ]; then
		say "      and KILL its processes: ${pids:-none}"
	else
		say "      and STOP (freeze) its processes: ${pids:-none}"
	fi
	say "      undo: secure-sudo contain release account $user"
	confirm
	state_dir
	local ev
	ev="$STATE/account-$user"
	[ -e "$ev" ] && die "$user is already contained (release it first)"
	mkdir -m 0700 "$ev"
	printf 'user=%s\nuid=%s\nwas_locked=%s\nexpire=%s\ntime=%s\nterminated=%s\n' \
		"$user" "$uid" "$was_locked" "$expire" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$term" > "$ev/state"
	ps -o pid,ppid,stat,lstart,args -u "$uid" > "$ev/processes.txt" 2>&1 || true
	usermod --lock "$user"
	usermod --expiredate 1 "$user"
	if [ -n "$pids" ]; then
		# shellcheck disable=SC2086
		if [ "$term" = 1 ]; then kill -KILL $pids 2>/dev/null || true
		else kill -STOP $pids 2>/dev/null || true; fi
	fi
	tr ' ' '\n' <<<"$pids" | sed '/^$/d' > "$ev/pids"
	if [ "$term" = 1 ] && command -v loginctl >/dev/null; then
		loginctl terminate-user "$user" 2>/dev/null || true
	fi
	say "account $user contained (evidence: $ev)"
}

cmd_release_account() {
	local user="${1:-}" ev
	shift || true
	[ "${1:-}" = -y ] && YES=1
	[ -n "$user" ] || usage
	[[ $user =~ ^[a-z_][a-z0-9_.-]*\$?$ ]] || die "not a user name: $user"
	ev="$STATE/account-$user"
	[ -f "$ev/state" ] || die "$user is not contained"
	# shellcheck disable=SC1091
	local was_locked expire pids
	was_locked="$(sed -n 's/^was_locked=//p' "$ev/state")"
	expire="$(sed -n 's/^expire=//p' "$ev/state")"
	pids="$(tr '\n' ' ' < "$ev/pids" 2>/dev/null || true)"
	say "plan: restore the expiry of $user (${expire:-none})$([ "$was_locked" = 1 ] && echo ", keep the password locked (it was before)" || echo ", unlock the password"), continue stopped processes"
	confirm
	if [ -n "$expire" ]; then chage -E "$expire" "$user"; else usermod --expiredate '' "$user"; fi
	[ "$was_locked" = 1 ] || usermod --unlock "$user"
	# shellcheck disable=SC2086
	if [ -n "${pids// /}" ]; then kill -CONT $pids 2>/dev/null || true; fi
	mv -- "$ev" "$ev.released-$(date -u +%Y%m%dT%H%M%SZ)"
	say "account $user released (evidence kept)"
}

# ------------------------------------------------------------ processes
descendants() { # pid -> pid and all descendants
	local p c
	echo "$1"
	for p in /proc/[0-9]*/stat; do
		c="${p#/proc/}"; c="${c%/stat}"
		[ "$(awk '{print $4}' "$p" 2>/dev/null)" = "$1" ] && descendants "$c"
	done
	return 0
}

ancestors() { # of this script
	local p=$$
	while [ "$p" -gt 1 ] 2>/dev/null; do
		echo "$p"
		p="$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null || echo 0)"
	done
}

cmd_process() {
	local pid="" kill9=0 tree ev
	while [ $# -gt 0 ]; do
		case "$1" in
		--kill) kill9=1; shift ;;
		--dry-run) DRY=1; shift ;;
		-y) YES=1; shift ;;
		-*) usage ;;
		*) [ -z "$pid" ] || usage; pid="$1"; shift ;;
		esac
	done
	[[ $pid =~ ^[0-9]+$ ]] || usage
	[ -d "/proc/$pid" ] || die "no process $pid"
	[ "$pid" != 1 ] || die "refusing to stop PID 1 (init)"
	if ! readlink "/proc/$pid/exe" >/dev/null 2>&1; then
		die "refusing PID $pid: a kernel thread (no executable)"
	fi
	local mine p
	mine=" $(ancestors | tr '\n' ' ') "
	[[ $mine == *" $pid "* ]] && die "refusing PID $pid: it is this shell or one of its parents"
	tree=""
	for p in $(descendants "$pid"); do
		[[ $mine == *" $p "* ]] || tree+="$p "	# never stop ourselves
	done
	say "plan: save evidence of PID $pid ($(readlink "/proc/$pid/exe")), then $([ "$kill9" = 1 ] && echo KILL || echo "STOP (freeze)") PIDs: $tree"
	say "      undo: secure-sudo contain release process $pid$([ "$kill9" = 1 ] && echo ' (not possible after --kill)')"
	confirm
	state_dir
	ev="$STATE/process-$pid-$(date -u +%Y%m%dT%H%M%SZ)"
	mkdir -m 0700 "$ev"
	# freeze first so the evidence describes a process that is not moving
	# shellcheck disable=SC2086
	kill -STOP $tree 2>/dev/null || true
	tr ' ' '\n' <<<"$tree" | sed '/^$/d' > "$ev/pids"
	printf 'pid=%s\ntime=%s\nkilled=%s\nexe=%s\n' "$pid" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$kill9" \
		"$(readlink "/proc/$pid/exe" 2>/dev/null)" > "$ev/state"
	tr '\0' ' ' < "/proc/$pid/cmdline" > "$ev/cmdline" 2>/dev/null || true
	tr '\0' '\n' < "/proc/$pid/environ" > "$ev/environ" 2>/dev/null || true
	cp -- "/proc/$pid/status" "$ev/status" 2>/dev/null || true
	cp -- "/proc/$pid/maps" "$ev/maps" 2>/dev/null || true
	ls -l "/proc/$pid/fd" > "$ev/fds.txt" 2>&1 || true
	readlink "/proc/$pid/cwd" > "$ev/cwd" 2>/dev/null || true
	if command -v ss >/dev/null; then ss -tunap 2>/dev/null | grep -E "pid=${pid}[,)]" > "$ev/sockets.txt" || true; fi
	if cp -- "/proc/$pid/exe" "$ev/exe" 2>/dev/null; then
		chmod 0400 "$ev/exe"
		sha256sum "$ev/exe" | awk '{print $1}' > "$ev/exe.sha256"
	fi
	if [ "$kill9" = 1 ]; then
		# shellcheck disable=SC2086
		kill -KILL $tree 2>/dev/null || true
		say "PID $pid killed after saving evidence ($ev)"
	else
		say "PID $pid stopped (evidence: $ev)"
	fi
}

cmd_release_process() {
	local pid="${1:-}" ev
	shift || true
	[ "${1:-}" = -y ] && YES=1
	[[ $pid =~ ^[0-9]+$ ]] || usage
	local d
	ev=""
	for d in "$STATE/process-$pid-"*; do
		case "$d" in *.released) continue ;; esac
		[ -f "$d/pids" ] && ev="$d"
	done
	[ -n "$ev" ] || die "process $pid is not contained"
	grep -q '^killed=1' "$ev/state" && die "process $pid was killed; nothing to release"
	say "plan: continue PIDs $(tr '\n' ' ' < "$ev/pids")"
	confirm
	# shellcheck disable=SC2046
	kill -CONT $(cat "$ev/pids") 2>/dev/null || true
	mv -- "$ev" "$ev.released"
	say "process $pid released (evidence kept)"
}

cmd_status() {
	local f any=0
	if net_contained; then say "network: CONTAINED (allowed: $(tail -n +2 "$STATE/network" 2>/dev/null | tr '\n' ' '))"; any=1
	else say "network: normal"; fi
	for f in "$STATE"/account-*/state; do
		[ -f "$f" ] || continue
		say "account: CONTAINED $(sed -n 's/^user=//p' "$f") since $(sed -n 's/^time=//p' "$f")"; any=1
	done
	for f in "$STATE"/process-*/state; do
		[ -f "$f" ] || continue
		case "$f" in *.released/*) continue ;; esac
		say "process: $(sed -n 's/^pid=//p' "$f") $(grep -q '^killed=1' "$f" && echo killed || echo STOPPED) ($(sed -n 's/^exe=//p' "$f"))"; any=1
	done
	[ "$any" = 1 ] || say "nothing contained"
}

[ $# -ge 1 ] || usage
cmd="$1"; shift
case "$cmd" in
status) cmd_status ;;
network) cmd_network "$@" ;;
account) cmd_account "$@" ;;
process) cmd_process "$@" ;;
release)
	[ $# -ge 1 ] || usage
	what="$1"; shift
	case "$what" in
	network) [ "${1:-}" = -y ] && YES=1; cmd_release_network ;;
	account) cmd_release_account "$@" ;;
	process) cmd_release_process "$@" ;;
	*) usage ;;
	esac ;;
*) usage ;;
esac
