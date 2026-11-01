#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# test-node-scan.sh - `secure-sudo node-scan` (#11, THREAT_MODEL.md gap G1):
# Node runtimes outside the standard paths (single-executable apps, pkg
# builds, renamed node) are found by their markers and registered for the
# Node child guard, after the hand-written entries and within the kernel's
# limits. The kernel half (a listed path is treated as node) is checked in
# the VM by ss-functest's t_node; this checks the finding and registering.
#
# The CLI is built with SYSFS, SECFS, CONFIG_DIR and the state directory
# pointed into a scratch directory. Needs no root except the ownership case.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
SYS="$T/sys"; SEC="$T/sec"; CFG="$T/etc"; ST="$T/state"; A="$T/apps"
CLI="$T/secure-sudo"
mkdir -p "$SYS" "$SEC" "$CFG" "$A/sub"
echo 0 > "$SYS/lock"
: > "$SEC/node_sea_binaries"

if ! (cd "$ROOT/userspace/cli" && gcc -O2 -Wall -Wextra -Werror \
	-DSYSFS="\"$SYS\"" -DSECFS="\"$SEC\"" -DCONFIG_DIR="\"$CFG\"" \
	-DSS_STATE_DIR="\"$ST\"" -DSS_TESTING \
	-o "$CLI" secure-sudo.c policy.c policy_state.c vault_allow.c detect_admins.c node_scan.c \
	-lcrypto 2> "$T/build.err"); then
	not_ok "CLI builds with test paths ($(head -1 "$T/build.err"))"
	tap_done; exit 1
fi
ok "CLI builds with test paths (-Werror)"
scan() { SS_TEST_ALLOW_ROOT=1 "$CLI" node-scan "$@"; }

FUSE=NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
ELF=/bin/true
# An executable ELF with a marker appended (trailing bytes do not stop it running).
mkapp() { cp "$ELF" "$1"; printf '%s' "$2" >> "$1"; chmod 0755 "$1"; }
mkapp "$A/sea-app"        "$FUSE:1"		# postject flips :0 to :1
mkapp "$A/sub/renamed"    "$FUSE:0"		# a plain node binary under another name
mkapp "$A/pkg-app"        "x PKG_EXECPATH x"	# a pkg build
cp "$ELF" "$A/plain"; chmod 0755 "$A/plain"	# no marker
mkapp "$A/electron-app"   "$FUSE:0 ELECTRON_RUN_AS_NODE"	# embeds node, but is a desktop app
mkapp "$A/not-exec"       "$FUSE:1"; chmod 0644 "$A/not-exec"
printf '#!/bin/sh\n# %s:1\n' "$FUSE" > "$A/script"; chmod 0755 "$A/script"
ln -s sea-app "$A/link-to-sea"
mkapp "$A/new"$'\n'"line" "$FUSE:1"		# cannot be one line of the list
# The marker split across the scanner's 1 MiB reads, and the ":1" flag
# alone in the next read.
B=$((1024 * 1024))
printf '\177ELF' > "$A/split"; truncate -s $((B - 20)) "$A/split"
printf '%s:1' "$FUSE" >> "$A/split"; chmod 0755 "$A/split"
printf '\177ELF' > "$A/flag-next"; truncate -s $((B - ${#FUSE})) "$A/flag-next"
printf '%s:1' "$FUSE" >> "$A/flag-next"; chmod 0755 "$A/flag-next"

echo "# finding"
scan --dry-run "$A" > "$T/dry.out" 2> "$T/dry.err"; RC=$?
eq "a dry run exits 0" "$RC" 0
check "an SEA (fuse flipped to :1) is found as sea" grep -qx "$A/sea-app	sea" "$T/dry.out"
check "a renamed node binary (fuse :0) is found as node" grep -qx "$A/sub/renamed	node" "$T/dry.out"
check "a pkg build is found as pkg" grep -qx "$A/pkg-app	pkg" "$T/dry.out"
check "a marker split across two reads is found" grep -qx "$A/split	sea" "$T/dry.out"
check "the :1 flag in the next read still reads as sea" grep -qx "$A/flag-next	sea" "$T/dry.out"
refute "an ELF without a marker is not listed" grep -q "$A/plain" "$T/dry.out"
refute "a file without the exec bit is not listed" grep -q "not-exec" "$T/dry.out"
refute "a script that only mentions the marker is not listed" grep -q "$A/script" "$T/dry.out"
refute "an Electron app is not registered" grep -q electron-app "$T/dry.out"
check "... and is reported, with how to confine it by hand" grep -q "not registered (an Electron app; list it by hand.*electron-app" "$T/dry.err"
eq "a symlink adds nothing (each file once, by its real path)" "$(grep -c 'sea-app\|link-to-sea' "$T/dry.out")" 1
check "a name with a newline is reported, not listed" grep -q 'cannot be listed' "$T/dry.err"
eq "exactly the five runtimes are found, one line each" "$(wc -l < "$T/dry.out")" 5
check "the summary goes to stderr" grep -q "5 runtimes found (3 sea, 1 node, 1 pkg); dry run" "$T/dry.err"
check "a dry run writes nothing" test ! -e "$ST/node_sea_auto.list"
eq "a dry run leaves the kernel list alone" "$(cat "$SEC/node_sea_binaries")" ""

if [ -x /opt/node22/bin/node ] || command -v node >/dev/null; then
	NODE="$(command -v node || echo /opt/node22/bin/node)"
	NODE="$(readlink -f "$NODE")"
	mkdir -p "$T/real"
	cp "$NODE" "$T/real/my-sea-app"
	# what postject --sentinel-fuse does to the copy it injects into
	python3 - "$T/real/my-sea-app" "$FUSE" <<'PY'
import sys
p, f = sys.argv[1], sys.argv[2].encode()
b = open(p, 'rb').read()
assert b.count(f + b':0') == 1
open(p, 'wb').write(b.replace(f + b':0', f + b':1'))
PY
	scan --dry-run "$NODE" "$T/real" > "$T/real.out" 2>/dev/null
	sed 's/^/# real: /' "$T/real.out"
	# a CI runner's toolcache node is not root-owned: allow the third column
	check "the real node binary ($("$NODE" --version)) is found as node" \
		grep -qE "^$NODE	node(	not-root-owned)?\$" "$T/real.out"
	check "a real node with the fuse flipped is found as sea" \
		grep -qx "$T/real/my-sea-app	sea" "$T/real.out"
	rm -rf "$T/real"
else
	skip "the real node binary is found (node not installed)"
	skip "a real node with the fuse flipped is found as sea (node not installed)"
fi

echo "# registering"
printf '# by hand\n/opt/manual/app\n' > "$CFG/node_sea_binaries.conf"
scan "$A" > "$T/reg.out" 2>&1; RC=$?
eq "a scan exits 0" "$RC" 0
check "new runtimes are reported" grep -q "^node-scan: + $A/sea-app (sea)" "$T/reg.out"
eq "the hand-written entry comes first in the kernel list" "$(head -1 "$SEC/node_sea_binaries")" /opt/manual/app
eq "then every found runtime (1 + 5 lines)" "$(wc -l < "$SEC/node_sea_binaries")" 6
check "the found list is kept apart from the config" grep -qx "$A/sea-app" "$ST/node_sea_auto.list"
refute "... and the config file is not touched" grep -q sea-app "$CFG/node_sea_binaries.conf"
eq "the state files are root-only (0600)" "$(stat -c %a "$ST/node_sea_auto.list") $(stat -c %a "$ST/node_sea_scan.cache")" "600 600"

scan "$A" > "$T/again.out" 2>&1
check "a second scan reads nothing it has seen (cache)" grep -qE ' 0 read, [0-9]+ unchanged' "$T/again.out"
refute "... and reports no changes" grep -q '^node-scan: [+-]' "$T/again.out"

printf '%s:1' "$FUSE" >> "$A/plain"
rm "$A/pkg-app"
scan "$A" > "$T/change.out" 2>&1
check "a file that gains a marker is read again and found" grep -q "^node-scan: + $A/plain (sea)" "$T/change.out"
check "a removed runtime is reported gone" grep -q "^node-scan: - $A/pkg-app (gone)" "$T/change.out"
refute "... and leaves the kernel list" grep -q pkg-app "$SEC/node_sea_binaries"

scan --quiet "$A" > "$T/quiet.out" 2>&1
eq "--quiet prints nothing when nothing changed" "$(cat "$T/quiet.out")" ""

mkdir -p "$T/other"; mkapp "$T/other/elsewhere" "$FUSE:1"
scan "$T/other" > /dev/null 2>&1
scan "$A/sub" > "$T/part.out" 2>&1
check "a scan of one directory keeps what was found in the others" \
	sh -c "grep -qx '$T/other/elsewhere' '$SEC/node_sea_binaries' && grep -qx '$A/sea-app' '$SEC/node_sea_binaries'"
refute "... and reports nothing gone" grep -q '(gone)' "$T/part.out"
check "... from the cache, without reading them again" grep -qE ' 0 read, ' "$T/part.out"
rm "$T/other/elsewhere"
scan "$T/other" > "$T/part.out" 2>&1
check "a scan of a directory drops what is gone from it" grep -q "^node-scan: - $T/other/elsewhere (gone)" "$T/part.out"
scan "$A" > "$T/full2.out" 2>&1
check "the cache still knows the other directories afterwards" grep -qE ' 0 read, ' "$T/full2.out"

echo "# directories from the config"
printf 'node_sea_scan_dirs = %s/sub\n' "$A" > "$CFG/secure-sudo.conf"
scan --dry-run > "$T/cfgdirs.out" 2>/dev/null
eq "node_sea_scan_dirs is used when no DIR is given" "$(cut -f1 "$T/cfgdirs.out")" "$A/sub/renamed"
rm "$CFG/secure-sudo.conf"

echo "# limits"
python3 -c 'import sys; print("\n".join("/opt/m/%03d" % i for i in range(255)))' > "$CFG/node_sea_binaries.conf"
scan "$A" > "$T/full.out" 2> "$T/full.err"; RC=$?
eq "a scan that cannot register everything exits 1" "$RC" 1
check "it says how many were NOT registered" grep -qE 'list is full .*: 4 found runtimes NOT registered' "$T/full.err"
eq "the kernel list stops at its 256 entries" "$(wc -l < "$SEC/node_sea_binaries")" 256
eq "... with every hand-written entry kept" "$(grep -c '^/opt/m/' "$SEC/node_sea_binaries")" 255
printf '/opt/manual/app\n' > "$CFG/node_sea_binaries.conf"

if [ "$(id -u)" -eq 0 ]; then
	chown 65534 "$A/flag-next"
	scan "$A" > /dev/null 2>&1; scan --dry-run "$A" > "$T/own.out" 2>/dev/null
	eq "a file a non-root user owns is listed last" "$(tail -1 "$T/own.out")" "$A/flag-next	sea	not-root-owned"
	chown 0 "$A/flag-next"
	chmod 0777 "$A/split"
	scan --dry-run "$A" > "$T/own.out" 2>/dev/null
	eq "so is a root-owned file others can write" "$(tail -1 "$T/own.out" | cut -f1,3)" "$A/split	not-root-owned"
	chmod 0755 "$A/split"
else
	skip "a file a non-root user owns is listed last (needs root)"
	skip "so is a root-owned file others can write (needs root)"
fi

echo "# refused"
rm "$SEC/node_sea_binaries"; mkdir "$SEC/node_sea_binaries"
scan "$A" > "$T/ref.out" 2> "$T/ref.err"; RC=$?
eq "a kernel refusal makes the scan exit 1" "$RC" 1
check "... and is reported" grep -q 'kernel refused node_sea_binaries' "$T/ref.err"
rmdir "$SEC/node_sea_binaries"; : > "$SEC/node_sea_binaries"
if [ "$(id -u)" -ne 0 ]; then
	refute_with "node-scan needs root" 'must be run as root' "$CLI" node-scan --dry-run "$A"
else
	check "node-scan needs root" sh -c "setpriv --reuid=65534 --regid=65534 --clear-groups '$CLI' node-scan --dry-run '$A' 2>&1 | grep -q 'must be run as root'"
fi

tap_done
