#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# timevault-whitelist.sh - manage the secure_sudo TimeVault exec allowlist.
#
#   timevault-whitelist.sh scan [-n] [-x] <dir>...  hash + allow every executable
#                                                   binary/script under <dir>
#   timevault-whitelist.sh add <file>...            hash + allow single files
#   timevault-whitelist.sh remove <file>...         drop entries
#   timevault-whitelist.sh list                     show the saved allowlist
#   timevault-whitelist.sh wipe [-y] [--force]      empty the allowlist
#
# -n  dry run (print what scan would add)     -x  stay on one filesystem
# -y  don't ask before wiping                 --force  wipe even while engaged
#
# Saved to /etc/secure_sudo/timevault_allow.conf as "<path> <sha256>" lines and
# pushed to /sys/kernel/security/secure_sudo/timevault_allow. Root only.
# The installed CLI has the same commands built in: `secure-sudo vault-allow ...`
# (this script is the dependency-free equivalent: bash + coreutils + findutils).
set -euo pipefail

CONF=/etc/secure_sudo/timevault_allow.conf
SECFS=/sys/kernel/security/secure_sudo/timevault_allow
VAULT_KNOB=/sys/kernel/secure_sudo/timevault
LOCK=/run/secure_sudo-vault-allow.lock
MAX_ITEMS=16384                 # TV_MAX_ITEMS in ss_timevault.c
MAX_TEXT=$((4 * 1024 * 1024))   # TV_MAX_TEXT

prog="${0##*/}"
die()  { echo "$prog: $*" >&2; exit 1; }
warn() { echo "$prog: $*" >&2; }

usage() { sed -n '4,14p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

[ "$(id -u)" -eq 0 ] || die "must be run as root (sudo $prog ...)"
[ $# -ge 1 ] || usage

# One editor at a time (shares the lock with `secure-sudo vault-allow`).
exec 9>"$LOCK"
flock 9

# Entries live in an associative array path -> hash; comment/blank lines from
# the conf are kept in order as a header.
declare -A HASH=()
declare -a ORDER=() HEADER=()
DIRTY=0

load() {
	[ -f "$CONF" ] || return 0
	local line p h
	while IFS= read -r line || [ -n "$line" ]; do
		if [[ "$line" =~ ^[[:space:]]*/ ]]; then
			read -r p h <<<"$line"
			[[ "${h:-}" =~ ^[0-9a-f]{64}$ ]] || h=""
			[ -n "${HASH[$p]+x}" ] || ORDER+=("$p")
			HASH[$p]="$h"
		else
			HEADER+=("$line")
		fi
	done <"$CONF"
}

render() {
	local l p
	for l in "${HEADER[@]+"${HEADER[@]}"}"; do printf '%s\n' "$l"; done
	for p in "${ORDER[@]+"${ORDER[@]}"}"; do
		[ -n "${HASH[$p]+x}" ] || continue
		if [ -n "${HASH[$p]}" ]; then printf '%s %s\n' "$p" "${HASH[$p]}"
		else printf '%s\n' "$p"; fi
	done
}

save_and_push() {
	local n=${#HASH[@]} tmp size
	[ "$n" -le "$MAX_ITEMS" ] || die "$n entries exceeds the kernel limit of $MAX_ITEMS; nothing saved"
	mkdir -p "${CONF%/*}"
	tmp="$(mktemp "${CONF%/*}/.timevault_allow.conf.XXXXXX")"
	render >"$tmp"
	size=$(stat -c %s "$tmp")
	if [ "$size" -gt "$MAX_TEXT" ]; then rm -f "$tmp"; die "allowlist is $size bytes (limit $MAX_TEXT); nothing saved"; fi
	chmod 600 "$tmp"
	sync "$tmp" 2>/dev/null || true
	mv -f "$tmp" "$CONF"

	if [ ! -e "$SECFS" ]; then
		echo "$prog: saved $CONF (kernel LSM not active; loads at next boot)"
		return 0
	fi
	# The kernel replaces the whole list per write(), so it must be ONE write:
	# dd with a block larger than the file and fullblock does exactly that.
	if [ "$size" -eq 0 ]; then
		printf '\n' >"$SECFS" || { warn "saved $CONF, kernel refused (config locked?)"; return 1; }
	elif ! dd if="$CONF" of="$SECFS" bs=$((MAX_TEXT + 1)) count=1 iflag=fullblock status=none; then
		warn "saved $CONF, kernel refused the update (config locked?); applies after reboot"
		return 1
	fi
	echo "$prog: $n allowlist entries saved and loaded"
}

# ELF magic or "#!" in the first bytes, on a regular file with an x bit.
is_exec() {
	local f="$1" magic
	[ -f "$f" ] && [ -x "$f" ] || return 1
	magic="$(head -c 4 -- "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
	[ "$magic" = 7f454c46 ] || [ "${magic:0:4}" = 2321 ]
}

# Kernel splits each line on the first space: such paths can't be stored.
representable() { [[ "$1" != *[[:space:]]* ]]; }

# upsert <canonical path>; sets RESULT to added|updated|same
RESULT=""
upsert() {
	local p="$1" h
	h="$(sha256sum -- "$p" 2>/dev/null | cut -d' ' -f1)"
	[ -n "$h" ] || return 1
	if [ -n "${HASH[$p]+x}" ]; then
		if [ "${HASH[$p]}" = "$h" ]; then RESULT=same; return 0; fi
		HASH[$p]="$h"; DIRTY=1; RESULT=updated; return 0
	fi
	HASH[$p]="$h"; ORDER+=("$p"); DIRTY=1; RESULT=added
}

cmd_scan() {
	local dry=0 xdev=() dirs=() d f real
	local added=0 updated=0 same=0 skipped=0
	while [ $# -gt 0 ]; do
		case "$1" in
			-n|--dry-run) dry=1 ;;
			-x|--one-file-system) xdev=(-xdev) ;;
			-*) die "unknown option $1" ;;
			*) dirs+=("$1") ;;
		esac
		shift
	done
	[ ${#dirs[@]} -gt 0 ] || die "usage: $prog scan [-n] [-x] <dir>..."

	for d in "${dirs[@]}"; do
		real="$(realpath -e -- "$d")" && [ -d "$real" ] || die "$d is not a directory"
		[ "$real" != / ] || warn "warning: scanning all of / (may exceed the $MAX_ITEMS-entry limit)"
		# Regular files and symlinks with an x bit; symlinks resolve to the
		# target, which is the path the kernel sees at exec time.
		while IFS= read -r -d '' f; do
			real="$(realpath -e -- "$f" 2>/dev/null)" || continue
			is_exec "$real" || continue
			if ! representable "$real"; then
				warn "skipping $real (whitespace in path)"; skipped=$((skipped + 1)); continue
			fi
			if [ "$dry" -eq 1 ]; then echo "$real"; added=$((added + 1)); continue; fi
			upsert "$real" || { warn "cannot hash $real"; skipped=$((skipped + 1)); continue; }
			case "$RESULT" in added) added=$((added + 1)) ;; updated) updated=$((updated + 1)) ;; *) same=$((same + 1)) ;; esac
		done < <(find "$real" "${xdev[@]}" \( -type f -o -type l \) -perm /111 -print0 2>/dev/null)
	done

	if [ "$dry" -eq 1 ]; then echo "$prog: $added executables would be added (dry run)"; return 0; fi
	echo "$prog: scan: $added added, $updated re-hashed, $same unchanged, $skipped skipped"
	[ "$DIRTY" -eq 0 ] || save_and_push
}

cmd_add() {
	local f real rc=0
	[ $# -gt 0 ] || die "usage: $prog add <file>..."
	for f in "$@"; do
		real="$(realpath -e -- "$f" 2>/dev/null)" || { warn "$f: no such file"; rc=1; continue; }
		[ -f "$real" ] || { warn "$real is not a regular file"; rc=1; continue; }
		representable "$real" || { warn "$real has whitespace in its path; can't be allowlisted"; rc=1; continue; }
		is_exec "$real" || warn "note: $real is not an executable binary/script; adding anyway"
		upsert "$real" || { warn "cannot hash $real"; rc=1; continue; }
		printf '%-7s %s\n' "$RESULT" "$real"
	done
	[ "$DIRTY" -eq 0 ] || save_and_push || rc=1
	return $rc
}

cmd_remove() {
	local f p rc=0
	[ $# -gt 0 ] || die "usage: $prog remove <file>..."
	for f in "$@"; do
		p="$(realpath -- "$f" 2>/dev/null || printf '%s' "$f")"
		if [ -n "${HASH[$p]+x}" ]; then unset 'HASH[$p]'; DIRTY=1; echo "removed $p"
		else warn "$p is not in the allowlist"; rc=1; fi
	done
	[ "$DIRTY" -eq 0 ] || save_and_push || rc=1
	return $rc
}

cmd_list() {
	local p
	for p in "${ORDER[@]+"${ORDER[@]}"}"; do
		[ -n "${HASH[$p]+x}" ] && printf '%s %s\n' "$p" "${HASH[$p]:-(any hash)}"
	done
	echo "${#HASH[@]} entries in $CONF" >&2
}

cmd_wipe() {
	local yes=0 force=0 ans
	while [ $# -gt 0 ]; do
		case "$1" in -y|--yes) yes=1 ;; --force) force=1 ;; *) die "usage: $prog wipe [-y] [--force]" ;; esac
		shift
	done
	if [ "$force" -eq 0 ] && [ "$(cat "$VAULT_KNOB" 2>/dev/null || echo 0)" = 1 ]; then
		die "TimeVault is engaged; an empty allowlist would block nearly every exec. Disengage it first or pass --force."
	fi
	if [ "$yes" -eq 0 ]; then
		read -r -p "Wipe all ${#HASH[@]} TimeVault allowlist entries? Type 'yes': " ans || ans=""
		[ "$ans" = yes ] || die "aborted"
	fi
	HASH=(); ORDER=()
	save_and_push
}

load
sub="$1"; shift
case "$sub" in
	scan)      cmd_scan "$@" ;;
	add)       cmd_add "$@" ;;
	remove|rm) cmd_remove "$@" ;;
	list|ls)   cmd_list ;;
	wipe)      cmd_wipe "$@" ;;
	-h|--help|help) usage ;;
	*) usage ;;
esac
