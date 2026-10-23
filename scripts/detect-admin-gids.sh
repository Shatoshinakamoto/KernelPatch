#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# detect-admin-gids.sh - print every admin group GID on this box as a comma
# list (e.g. "27,10"), for secure_sudo's admin_gid. Members of these groups
# count as sudo users; with an empty list only root does.
#
# Sources: the well-known groups sudo / wheel / admin (whichever exist), plus
# every "%group" or "%#gid" rule in /etc/sudoers and /etc/sudoers.d/.
#
#   detect-admin-gids.sh            print the list
#   detect-admin-gids.sh --apply    also write it to /etc/secure_sudo/secure-sudo.conf
#                                   and the live kernel knob (root only)
#
# install.sh calls this at install time. The installed CLI has the same logic
# built in as `secure-sudo detect-admins`.
set -euo pipefail

MAX_GIDS=16            # SS_MAX_ADMIN_GIDS in the kernel
CONF=/etc/secure_sudo/secure-sudo.conf
KNOB=/sys/kernel/secure_sudo/admin_gid

detect() {
	local names="" n gid gids="" count=0 f base

	for n in sudo wheel admin; do
		getent group "$n" >/dev/null 2>&1 && names="$names $n"
	done

	for f in /etc/sudoers /etc/sudoers.d/*; do
		[ -f "$f" ] || continue
		base="${f##*/}"
		# sudo itself skips sudoers.d files containing '.' or ending in '~'.
		if [ "$f" != /etc/sudoers ]; then
			case "$base" in *.*|*~) continue ;; esac
		fi
		names="$names $(grep -hE '^[[:space:]]*%' "$f" 2>/dev/null \
			| sed -E 's/^[[:space:]]*%([^[:space:]]+).*/\1/' || true)"
	done

	for n in $names; do
		case "$n" in
			\#*) gid="${n#\#}" ;;                          # %#1234 form
			*)   gid="$(getent group "$n" | cut -d: -f3)" ;;
		esac
		[[ "$gid" =~ ^[0-9]+$ ]] || continue
		case ",$gids," in *",$gid,"*) continue ;; esac
		if [ "$count" -ge "$MAX_GIDS" ]; then
			echo "detect-admin-gids: more than $MAX_GIDS admin groups; ignoring GID $gid" >&2
			continue
		fi
		gids="${gids:+$gids,}$gid"
		count=$((count + 1))
	done
	printf '%s' "$gids"
}

gids="$(detect)"

if [ "${1:-}" != "--apply" ]; then
	printf '%s\n' "$gids"
	exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "detect-admin-gids: --apply must run as root" >&2; exit 1; }
val="${gids:-unset}"
[ -n "$gids" ] || echo "detect-admin-gids: warning: no admin groups found; only root counts as sudo" >&2

if [ -f "$CONF" ]; then
	if grep -qE '^[[:space:]]*admin_gid[[:space:]]*=' "$CONF"; then
		sed -i -E "s/^[[:space:]]*admin_gid[[:space:]]*=.*/admin_gid = $val/" "$CONF"
	else
		printf 'admin_gid = %s\n' "$val" >> "$CONF"
	fi
fi
if [ -w "$KNOB" ]; then
	printf '%s' "$val" > "$KNOB" || echo "detect-admin-gids: kernel refused (config locked?); applies at next boot" >&2
fi
echo "admin_gid = $val"
