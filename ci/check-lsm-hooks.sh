#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-lsm-hooks.sh - fail if any LSM hook is registered more than once by
# secure_sudo. Since 6.9 each LSM has one static-call slot per hook, so a
# second registration of the same hook panics the kernel at boot. Hooks used
# by several protections belong in kernel/security/secure_sudo/ss_hooks.c.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../kernel/security/secure_sudo"

dups="$(grep -ho 'LSM_HOOK_INIT([a-z_0-9]*' "$SRC"/*.c | sed 's/LSM_HOOK_INIT(//' | sort | uniq -d)"
if [ -n "$dups" ]; then
	for h in $dups; do
		echo "hook '$h' registered more than once: $(grep -l "LSM_HOOK_INIT($h," "$SRC"/*.c | xargs -n1 basename | tr '\n' ' ')" >&2
	done
	exit 1
fi
echo "check-lsm-hooks: $(grep -ho 'LSM_HOOK_INIT(' "$SRC"/*.c | wc -l) hooks, each registered once"
