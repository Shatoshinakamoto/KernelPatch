#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# graft-lsm.sh - copy the secure_sudo LSM into a kernel source tree and
# register it with Kconfig and the security Makefile. Idempotent. Used by
# install/install.sh, ci/build-gate.sh and tests/vm/build-test-kernel.sh so
# every build wires the LSM in the same way.
#
# Usage: ci/graft-lsm.sh <kernel-source-tree>
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSM_SRC="$(cd "$HERE/.." && pwd)/kernel/security/secure_sudo"
tree="${1:?usage: $0 <kernel-source-tree>}"

if [ ! -f "$tree/security/Kconfig" ] || [ ! -f "$tree/security/Makefile" ]; then
	echo "graft-lsm: $tree is not a kernel source tree" >&2; exit 1
fi

rm -rf "$tree/security/secure_sudo"
cp -a "$LSM_SRC" "$tree/security/secure_sudo"

if ! grep -q 'security/secure_sudo/Kconfig' "$tree/security/Kconfig"; then
	# The Security options menu ends with the file's only top-level endmenu.
	[ "$(grep -c '^endmenu' "$tree/security/Kconfig")" -eq 1 ] ||
		{ echo "graft-lsm: unexpected security/Kconfig layout" >&2; exit 1; }
	sed -i 's|^endmenu|source "security/secure_sudo/Kconfig"\n\nendmenu|' \
		"$tree/security/Kconfig"
fi

if ! grep -q 'secure_sudo/' "$tree/security/Makefile"; then
	cat >> "$tree/security/Makefile" <<-'MK'

	subdir-$(CONFIG_SECURITY_SECURE_SUDO) += secure_sudo
	obj-$(CONFIG_SECURITY_SECURE_SUDO)    += secure_sudo/
	MK
fi

# Since 6.9 every LSM needs a static-call slot per hook, sized by the LSMs
# counted in include/linux/lsm_count.h. An LSM missing from that count has no
# slot of its own and the kernel panics at boot ("Ran out of static slots")
# unless some other compiled-in LSM happens to be inactive.
cnt="$tree/include/linux/lsm_count.h"
if [ -f "$cnt" ] && ! grep -q 'SECURE_SUDO_ENABLED' "$cnt"; then
	# Add our *_ENABLED block after IPE's and append it to MAX_LSM_COUNT.
	awk '
		{ print }
		/^#define IPE_ENABLED$/ { ipe = 1; next }
		ipe && /^#endif/ {
			print ""
			print "#if IS_ENABLED(CONFIG_SECURITY_SECURE_SUDO)"
			print "#define SECURE_SUDO_ENABLED 1,"
			print "#else"
			print "#define SECURE_SUDO_ENABLED"
			print "#endif"
			ipe = 0; added = 1
		}
	' "$cnt" | sed 's/^\t\tIPE_ENABLED)$/\t\tIPE_ENABLED\t\t\\\n\t\tSECURE_SUDO_ENABLED)/' > "$cnt.new"
	if ! grep -q '^#define SECURE_SUDO_ENABLED 1,$' "$cnt.new" ||
	   ! grep -q '^		SECURE_SUDO_ENABLED)$' "$cnt.new"; then
		rm -f "$cnt.new"
		echo "graft-lsm: unexpected lsm_count.h layout; add secure_sudo by hand" >&2
		exit 1
	fi
	mv "$cnt.new" "$cnt"
fi

if ! grep -q 'security/secure_sudo/Kconfig' "$tree/security/Kconfig" ||
   ! grep -q 'secure_sudo/' "$tree/security/Makefile"; then
	echo "graft-lsm: registration failed" >&2; exit 1
fi
echo "graft-lsm: secure_sudo grafted into $tree"
