#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# test-addons.sh - guardrail tests for the temporary/ add-ons that act on
# their own (TODO P1-7: "every destructive automation has tested
# guardrails"). Each add-on is built with its paths pointed into a scratch
# directory. ProcGuard kills processes, so its scans run inside a private PID
# and mount namespace (`unshare --pid --mount-proc`): it can only see, and
# only kill, the test's own processes. Needs root; skipped otherwise.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

if [ "$(id -u)" -ne 0 ] || ! command -v unshare >/dev/null; then
	skip "add-on guardrails (need root and unshare)"
	tap_done; exit 0
fi
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
chmod 0755 "$T"
COMMON="$ROOT/temporary/common"
addon_cc() { # out src extra-defines...
	local out="$1" src="$2"; shift 2
	gcc -O2 -Wall -Wextra -Werror -I"$COMMON" \
		-DSSL_CONF="\"$T/logging.conf\"" -DSSL_DEF_DIR="\"$T/log\"" \
		-DLOCUS_CLIENT_CONF="\"$T/locus-client.conf\"" "$@" \
		-o "$out" "$src" "$COMMON/ssaddon_log.c" "$COMMON/ssaddon_store.c" \
		-lcrypto -lz 2> "$T/build.err"
}

# ------------------------------------------------------------ ProcGuard
echo "# ProcGuard (kills processes): in a private PID namespace"
PG="$T/procguard"
if addon_cc "$PG" "$ROOT/temporary/procguard/procguard.c" \
	-DPG_CONF="\"$T/procguard.conf\"" -DPG_ALLOW="\"$T/procguard_allow.conf\"" \
	-DPG_QROOT="\"$T/q\""; then
	ok "ProcGuard builds with test paths (-Werror)"
else
	not_ok "ProcGuard builds with test paths ($(head -1 "$T/build.err"))"; tap_done; exit 1
fi
mkdir -p "$T/evil" "$T/sysbin" "$T/q"
SLEEP="$(readlink -f "$(command -v sleep)")"
cp "$SLEEP" "$T/evil/evil"; cp "$SLEEP" "$T/evil/secure-sudo-x"
cp "$SLEEP" "$T/sysbin/evilsys"
cp "$(readlink -f "$(command -v bash)")" "$T/evil/mybash"
# outer.sh runs inner.sh runs the scan, both under an unlisted shell; each
# writes its pid only after the scan, so a missing file means it was killed
printf '#!%s\n"%s" scan > /dev/null 2>&1\necho $$ > "%s/inner.pid"\n' "$T/evil/mybash" "$PG" "$T" > "$T/evil/inner.sh"
printf '#!%s\n"%s" "%s"\necho $$ > "%s/outer.pid"\n' "$T/evil/mybash" "$T/evil/mybash" "$T/evil/inner.sh" "$T" > "$T/evil/outer.sh"
chmod 0755 "$T/evil/"* "$T/sysbin/"*

# The scenario runs as PID 1 of a new PID namespace and prints "R key=value"
# lines; the checks below read them.
cat > "$T/ns.sh" <<NS
#!/bin/bash
set -u
PG="$PG"; T="$T"
conf() { printf 'mode = %s\nrespawn_threshold = 3\nrespawn_window = 60\nremove_on_infection = 1\nrotate = 0\nquarantine_root = %s/q\n' "\$1" "\$T" > "\$T/procguard.conf"; }
alive() { [ -d "/proc/\$1" ] && [ "\$(awk '{print \$3}' "/proc/\$1/stat")" != Z ] && echo 1 || echo 0; }
reap() { wait "\$@" 2>/dev/null; }

: > "\$T/procguard_allow.conf"; conf enforce
\$PG scan > /dev/null 2>&1; echo "R empty_rc=\$?"

printf '%s\n' "$SLEEP" "$(readlink -f "$(command -v awk)")" > "\$T/procguard_allow.conf"
sleep 1000 & A=\$!
"\$T/evil/evil" 1000 & E=\$!
"\$T/evil/secure-sudo-x" 1000 & X=\$!
conf monitor
\$PG scan > /dev/null 2>&1
echo "R monitor_evil_alive=\$(alive \$E)"
grep -c "MONITOR: would kill pid \$E " "\$T/log/procguard.log" | sed 's/^/R monitor_logged=/'

conf enforce
# scan from under two unlisted shells: they are its parents, never killed
"\$T/evil/mybash" "\$T/evil/outer.sh"
echo "R enforce_evil_alive=\$(alive \$E)"
echo "R enforce_allowed_alive=\$(alive \$A)"
echo "R enforce_name_trick_alive=\$(alive \$X)"
grep -q "killed pid \$E " "\$T/log/procguard.log" && echo "R enforce_logged=1"
reap \$E \$X
# the parents survived: the scan's own shells wrote inner.pid after it ran
[ -s "\$T/inner.pid" ] && [ -s "\$T/outer.pid" ] && echo "R parents_survived=1"

# a program that keeps coming back: killed 3 times -> infection. Respawns
# are counted by the daemon (each scan command starts afresh), one pass a second.
sed -i 's/^mode = .*/mode = enforce\ninterval = 1/' "\$T/procguard.conf"
\$PG daemon > /dev/null 2>&1 & D=\$!
respawn() { # exe: run it 3 times, each until the daemon kills it
	local i p n
	for i in 1 2 3; do
		"\$1" 1000 & p=\$!
		for n in \$(seq 50); do [ "\$(alive \$p)" = 0 ] && break; sleep 0.1; done
		reap \$p
	done
	sleep 1.5
}
respawn "\$T/evil/evil"
echo "R infection_removed=\$([ -e "\$T/evil/evil" ] && echo 0 || echo 1)"
echo "R infection_samples=\$(find "\$T/q" -type f | wc -l)"
grep -q "INFECTION quarantined: \$T/evil/evil" "\$T/log/procguard.log" && echo "R infection_logged=1"

# the same in a system directory: copied, never deleted
mount --bind "\$T/sysbin" /usr/local/sbin
respawn /usr/local/sbin/evilsys
echo "R system_left=\$([ -e /usr/local/sbin/evilsys ] && echo 1 || echo 0)"
grep -q "INFECTION left on disk: /usr/local/sbin/evilsys" "\$T/log/procguard.log" && echo "R system_logged=1"
umount /usr/local/sbin
kill \$D \$A 2>/dev/null; reap \$D
NS
if unshare --pid --fork --mount-proc bash "$T/ns.sh" > "$T/ns.out" 2> "$T/ns.err"; then :; fi
r() { sed -n "s/^R $1=//p" "$T/ns.out" | tail -1; }
eq "empty allowlist: refuses to run (would mean kill everything)" "$(r empty_rc)" 1
eq "monitor mode: the offender is not killed" "$(r monitor_evil_alive)" 1
eq "... and the log says what would have been killed" "$(r monitor_logged)" 1
eq "enforce: a process not on the allowlist is killed" "$(r enforce_evil_alive)" 0
eq "... an allowlisted one is not" "$(r enforce_allowed_alive)" 1
eq "... and the kill is logged" "$(r enforce_logged)" 1
eq "enforce: a name containing secure-sudo is no exemption" "$(r enforce_name_trick_alive)" 0
eq "enforce: the shells it runs under are never killed" "$(r parents_survived)" 1
eq "respawning 3 times: the executable is removed from disk" "$(r infection_removed)" 1
check "... after a compressed sample went to the quarantine" sh -c \
	"[ '$(r infection_samples)' -ge 1 ] && [ '$(r infection_logged)' = 1 ]"
eq "an executable in a system directory is never deleted" "$(r system_left)" 1
eq "... it is quarantined and the log says it was left" "$(r system_logged)" 1
[ -s "$T/ns.err" ] && sed 's/^/# ns: /' "$T/ns.err" | head -5

# ------------------------------------------------------------ BootGuard
echo "# BootGuard (restores /boot at the next boot)"
BG="$T/bin/secure-sudo-bootguard"; DG="$T/bin/secure-sudo-driverguard"
mkdir -p "$T/bin" "$T/boot/grub" "$T/bg" "$T/dg" "$T/mods/kernel/drivers"
LOCK="$T/dpkg.lock"; : > "$LOCK"
if addon_cc "$BG" "$ROOT/temporary/bootguard/bootguard.c" \
	-DBG_CONF="\"$T/bootguard.conf\"" -DBG_STATEDIR="\"$T/bg\"" \
	-DSSADDON_PKG_LOCKS="\"$LOCK\"" &&
   addon_cc "$DG" "$ROOT/temporary/driverguard/driverguard.c" \
	-DDG_CONF="\"$T/driverguard.conf\"" -DDG_STATEDIR="\"$T/dg\"" \
	-DSSADDON_PKG_LOCKS="\"$LOCK\""; then
	ok "BootGuard and DriverGuard build with test paths (-Werror)"
else
	not_ok "BootGuard and DriverGuard build with test paths ($(head -1 "$T/build.err"))"; tap_done; exit 1
fi
bgconf() { printf 'mode = %s\nrotate = 0\nboot_dir = %s/boot\nbackup_root = %s/bg/backups\n' "$1" "$T" "$T" > "$T/bootguard.conf"; }
BGLOG="$T/log/bootguard.log"
echo kernel-v1 > "$T/boot/vmlinuz"; echo initrd-v1 > "$T/boot/initrd.img"; echo menu-v1 > "$T/boot/grub/grub.cfg"
bgconf enforce
"$BG" refresh test > "$T/out" 2>&1
check "refresh with no baseline does nothing (the guard is not in use)" sh -c \
	"grep -q 'no baseline; nothing to refresh' '$T/out' && [ ! -e '$T/bg/manifest' ]"
"$BG" baseline > /dev/null 2>&1
echo evil > "$T/boot/vmlinuz"
"$BG" scan > "$T/out" 2>&1
check "enforce: tamper is staged for the next boot, the live file is left alone" sh -c \
	"[ -e '$T/bg/PENDING' ] && grep -q '$T/boot/vmlinuz' '$T/bg/restore.list' && [ \"\$(cat '$T/boot/vmlinuz')\" = evil ]"
"$BG" apply-now > "$T/out" 2>&1; rc=$?
check "apply-now without --i-understand-the-risk is refused" sh -c "[ $rc -eq 1 ] && [ \"\$(cat '$T/boot/vmlinuz')\" = evil ]"
"$BG" restore-staged > /dev/null 2>&1
check "restore-staged (at boot) puts the known-good file back and clears the flag" sh -c \
	"[ \"\$(cat '$T/boot/vmlinuz')\" = kernel-v1 ] && [ ! -e '$T/bg/PENDING' ]"
# a package manager rewriting /boot: hold the dpkg lock like apt does
python3 -c 'import fcntl,sys,time; f=open(sys.argv[1],"w"); fcntl.lockf(f,fcntl.LOCK_EX); open(sys.argv[2],"w").close(); time.sleep(30)' "$LOCK" "$T/locked" &
LP=$!; for _ in $(seq 50); do [ -e "$T/locked" ] && break; sleep 0.1; done
echo initrd-v2 > "$T/boot/initrd.img"; echo menu-v2 > "$T/boot/grub/grub.cfg"
"$BG" scan > "$T/out" 2>&1
check "scan while a package manager holds its lock is deferred, nothing staged" sh -c \
	"grep -q 'scan deferred' '$T/out' && [ ! -e '$T/bg/PENDING' ]"
kill "$LP"; wait "$LP" 2>/dev/null
SS_ADDONS_BIN="$T/bin" sh "$ROOT/temporary/hooks/addons-refresh" apt-transaction
check "the package hook re-baselines and logs each changed file with the reason" sh -c \
	"grep -q 'BOOT baseline refreshed (apt-transaction): $T/boot/initrd.img changed' '$BGLOG' && grep -q 'grub.cfg changed' '$BGLOG'"
"$BG" scan > "$T/out" 2>&1
check "... so the update is not treated as tampering afterwards" sh -c \
	"grep -q 'boot partition intact' '$T/out' && [ ! -e '$T/bg/PENDING' ]"
echo evil2 > "$T/boot/initrd.img"; "$BG" scan > /dev/null 2>&1
echo initrd-v3 > "$T/boot/initrd.img"
"$BG" refresh kernel-6.12.115 > /dev/null 2>&1
check "refresh drops a staged restore that predates the update (logged)" sh -c \
	"[ ! -e '$T/bg/PENDING' ] && grep -q 'staged restore DROPPED by refresh (kernel-6.12.115)' '$BGLOG'"
bgconf monitor; echo evil3 > "$T/boot/vmlinuz"; "$BG" scan > "$T/out" 2>&1
check "monitor: tamper reported, nothing staged" sh -c \
	"grep -q 'monitor mode: not staged' '$T/out' && [ ! -e '$T/bg/PENDING' ] && grep -q 'BOOT tamper: $T/boot/vmlinuz' '$BGLOG'"

# ---------------------------------------------------------- DriverGuard
echo "# DriverGuard (restores module files)"
dgconf() { printf 'mode = %s\nrotate = 0\ndriver_dir = %s/mods\nbackup_root = %s/dg/backups\n' "$1" "$T" "$T" > "$T/driverguard.conf"; }
DGLOG="$T/log/driverguard.log"
echo mod-v1 > "$T/mods/kernel/drivers/x.ko"
dgconf monitor; "$DG" baseline > /dev/null 2>&1
echo evil > "$T/mods/kernel/drivers/x.ko"; "$DG" scan > "$T/out" 2>&1
check "monitor: a changed module is reported, not restored" sh -c \
	"grep -q '1 tampered, 0 repaired (monitor)' '$T/out' && [ \"\$(cat '$T/mods/kernel/drivers/x.ko')\" = evil ]"
dgconf enforce; "$DG" scan > "$T/out" 2>&1
check "enforce: the module is restored from its backup (logged)" sh -c \
	"[ \"\$(cat '$T/mods/kernel/drivers/x.ko')\" = mod-v1 ] && grep -q 'DRIVER repaired: $T/mods/kernel/drivers/x.ko' '$DGLOG'"
python3 -c 'import fcntl,sys,time; f=open(sys.argv[1],"w"); fcntl.lockf(f,fcntl.LOCK_EX); open(sys.argv[2],"w").close(); time.sleep(30)' "$LOCK" "$T/locked2" &
LP=$!; for _ in $(seq 50); do [ -e "$T/locked2" ] && break; sleep 0.1; done
echo mod-v2 > "$T/mods/kernel/drivers/x.ko"; "$DG" scan > "$T/out" 2>&1
check "enforce: scan during a package transaction is deferred (the update is kept)" sh -c \
	"grep -q 'scan deferred' '$T/out' && [ \"\$(cat '$T/mods/kernel/drivers/x.ko')\" = mod-v2 ]"
kill "$LP"; wait "$LP" 2>/dev/null
SS_ADDONS_BIN="$T/bin" sh "$ROOT/temporary/hooks/addons-refresh" dkms-rebuild
"$DG" scan > "$T/out" 2>&1
check "after the package hook the updated module is the known-good one (logged)" sh -c \
	"grep -q '0 tampered' '$T/out' && [ \"\$(cat '$T/mods/kernel/drivers/x.ko')\" = mod-v2 ] && grep -q 'DRIVER baseline refreshed (dkms-rebuild)' '$DGLOG'"

# ---------------------------------------------------------- TamperWatch
echo "# TamperWatch (kills the writer of a protected file)"
TW="$T/bin/secure-sudo-tamperwatch"
mkdir -p "$T/prot" "$T/twq"
if addon_cc "$TW" "$ROOT/temporary/tamperwatch/tamperwatch.c" \
	-DTW_PBOX_CONF="\"$T/pbox.conf\"" -DTW_CONF="\"$T/tamperwatch.conf\"" \
	-DTW_QROOT="\"$T/twq\"" -DSSADDON_PKG_LOCKS="\"$LOCK\""; then
	ok "TamperWatch builds with test paths (-Werror)"
else
	not_ok "TamperWatch builds with test paths ($(head -1 "$T/build.err"))"; tap_done; exit 1
fi
echo protected > "$T/prot/a.conf"; : > "$T/pbox.conf"
twconf() { printf 'mode = %s\nrotate = 0\nquarantine_root = %s/twq\n%s/prot/a.conf\n' "$1" "$T" "$T" > "$T/tamperwatch.conf"; }
TWLOG="$T/log/tamperwatch.log"
# a writer that stays alive afterwards (its exe stays the copied shell)
# shellcheck disable=SC2016  # $1 and $(seq) belong to the inner shell
writer() { "$T/evil/mybash" -c 'echo x >> "$1"; for _ in $(seq 40); do sleep 0.1; done' w "$T/prot/a.conf" & WP=$!; }
tw_alive() { sleep 1; [ -d "/proc/$WP" ] && echo 1 || echo 0; }
twstart() { twconf "$1"; "$TW" daemon > /dev/null 2>&1 & TWP=$!; sleep 0.5; }
twstop() { kill "$TWP" 2>/dev/null; wait "$TWP" 2>/dev/null; kill "$WP" 2>/dev/null; wait "$WP" 2>/dev/null; }
twstart log
if grep -q "files watched" "$TWLOG" 2>/dev/null && ! grep -q "fanotify_init failed" "$TWLOG"; then
	writer; a=$(tw_alive)
	check "log mode: the writer is named, not killed" sh -c \
		"[ $a = 1 ] && grep -q 'TAMPER: $T/prot/a.conf modified by pid $WP ($T/evil/mybash)' '$TWLOG'"
	twstop
	twstart quarantine
	writer; a=$(tw_alive)
	check "quarantine mode: the writer is killed after its executable is quarantined" sh -c \
		"[ $a = 0 ] && grep -q 'killed tamperer pid $WP' '$TWLOG' && [ -n \"\$(find '$T/twq' -type f)\" ]"
	python3 -c 'import fcntl,sys,time; f=open(sys.argv[1],"w"); fcntl.lockf(f,fcntl.LOCK_EX); open(sys.argv[2],"w").close(); time.sleep(30)' "$LOCK" "$T/locked3" &
	LP=$!; for _ in $(seq 50); do [ -e "$T/locked3" ] && break; sleep 0.1; done
	writer; a=$(tw_alive)
	check "... but not while a package manager is running (logged as not killed)" sh -c \
		"[ $a = 1 ] && grep -q 'not killed: pid $WP .*a package manager is running' '$TWLOG'"
	kill "$LP"; wait "$LP" 2>/dev/null
	twstop
else
	skip "TamperWatch (fanotify not available here)"
fi

tap_done
