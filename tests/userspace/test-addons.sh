#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
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
		-DLOCUS_CLIENT_CONF="\"$T/locus-client.conf\"" -DSSADDON_EVIDENCE_ROOT="\"$T/evidence\"" \
		-DSSADDON_SIGNING_KEY="\"$T/sign.pub\"" "$@" \
		-o "$out" "$src" "$COMMON/ssaddon_log.c" "$COMMON/ssaddon_store.c" "$COMMON/ssaddon_conf.c" "$COMMON/ssaddon_trust.c" \
		-lcrypto -lz 2> "$T/build.err"
}

# ------------------------------------------------------------ ProcGuard
echo "# ProcGuard (kills processes): in a private PID namespace"
PG="$T/procguard"
if addon_cc "$PG" "$ROOT/temporary/procguard/procguard.c" \
	-DPG_CONF="\"$T/procguard.conf\"" -DPG_ALLOW="\"$T/procguard_allow.conf\"" \
	-DPG_QROOT="\"$T/q\"" -DPG_STATEDIR="\"$T/pgstate\""; then
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

# the scenario's own tools are allowed: in daemon mode a pass can land on a
# forked bash child before it execs, or on a \$(seq) subshell, and kill it
# (counting a kill against bash, not the respawning program)
for t in "$SLEEP" awk bash seq find grep sed wc mount umount; do
	readlink -f "\$(command -v "\$t")"
done > "\$T/procguard_allow.conf"
sleep 1000 & A=\$!
"\$T/evil/evil" 1000 & E=\$!
"\$T/evil/secure-sudo-x" 1000 & X=\$!
conf monitor
\$PG scan > /dev/null 2>&1
echo "R monitor_evil_alive=\$(alive \$E)"
grep -c "MONITOR: would kill pid \$E " "\$T/log/procguard.log" | sed 's/^/R monitor_logged=/'

# turned to enforce, it is not armed: it reports, and does not arm itself
# while there is something it would kill
conf enforce
\$PG scan > /dev/null 2>&1
echo "R unarmed_evil_alive=\$(alive \$E)"
grep -q "ENFORCE NOT ARMED: procguard would have killed" "\$T/log/procguard.log" && echo "R unarmed_logged=1"
[ -e "\$T/pgstate/enforce-armed" ] || echo "R unarmed_stays=1"
\$PG arm > /dev/null 2>&1; echo "R arm_rc=\$?"
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
kill \$D 2>/dev/null; reap \$D

# the path is swapped after the program started: the binary that ran is
# quarantined (via /proc/PID/exe), the file now at the path is left alone
sed -i 's/^respawn_threshold = .*/respawn_threshold = 1/' "\$T/procguard.conf"
cp "$SLEEP" "\$T/evil/swap"; chmod 0755 "\$T/evil/swap"
"\$T/evil/swap" 1000 & S=\$!
sleep 0.3
printf '#!/bin/sh\necho decoy\n' > "\$T/evil/decoy"; chmod 0755 "\$T/evil/decoy"
mv "\$T/evil/decoy" "\$T/evil/swap"
\$PG scan > /dev/null 2>&1; kill \$S 2>/dev/null; reap \$S
grep -q "decoy" "\$T/evil/swap" && echo "R swap_left=1"
grep -q "INFECTION: \$T/evil/swap is no longer the binary that ran" "\$T/log/procguard.log" && echo "R swap_logged=1"
q="\$(grep "INFECTION quarantined: \$T/evil/swap" "\$T/log/procguard.log" | tail -1 | sed 's/.*-> //')"
python3 -c 'import struct,sys,zlib; d=open(sys.argv[1],"rb").read(); sys.exit(0 if zlib.decompress(d[8:])==open(sys.argv[2],"rb").read() else 1)' "\$q" "$SLEEP" && echo "R swap_sample_is_ran=1"

# back to monitor: disarmed; then a clean enforce pass arms it by itself
kill \$A 2>/dev/null; reap \$A
conf monitor; \$PG scan > /dev/null 2>&1
[ -e "\$T/pgstate/enforce-armed" ] || echo "R disarmed=1"
conf enforce; \$PG scan > /dev/null 2>&1
[ -e "\$T/pgstate/enforce-armed" ] && grep -q "ENFORCE ARMED: procguard will now act (a clean enforce pass)" "\$T/log/procguard.log" && echo "R autoarmed=1"
NS
if unshare --pid --fork --mount-proc bash "$T/ns.sh" > "$T/ns.out" 2> "$T/ns.err"; then :; fi
r() { sed -n "s/^R $1=//p" "$T/ns.out" | tail -1; }
eq "empty allowlist: refuses to run (would mean kill everything)" "$(r empty_rc)" 1
eq "monitor mode: the offender is not killed" "$(r monitor_evil_alive)" 1
eq "... and the log says what would have been killed" "$(r monitor_logged)" 1
eq "enforce, not armed yet: the offender is not killed" "$(r unarmed_evil_alive)" 1
eq "... the log says what it would have killed and how to arm it" "$(r unarmed_logged)" 1
eq "... and it does not arm itself while there is an offender" "$(r unarmed_stays)" 1
eq "the operator arms it" "$(r arm_rc)" 0
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
eq "a path swapped after the program started: the new file is left alone" "$(r swap_left)" 1
eq "... the log says it is no longer the binary that ran" "$(r swap_logged)" 1
eq "... and the quarantined copy is the binary that actually ran" "$(r swap_sample_is_ran)" 1
eq "back to monitor mode: disarmed" "$(r disarmed)" 1
eq "a clean enforce pass arms it by itself" "$(r autoarmed)" 1
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
check "enforce, not armed yet: reported, not repaired, and it does not arm itself" sh -c "
	[ \"\$(cat '$T/mods/kernel/drivers/x.ko')\" = evil ] && grep -qF 'DRIVER would repair $T/mods/kernel/drivers/x.ko (not armed)' '$DGLOG' &&
	grep -qF 'ENFORCE NOT ARMED: driverguard would have repaired 1' '$DGLOG' && [ ! -e '$T/dg/enforce-armed' ]"
"$DG" status > "$T/out" 2>&1
check "... and status says so" grep -qF 'enforce arming:    NOT ARMED' "$T/out"
"$DG" arm > /dev/null 2>&1; "$DG" scan > "$T/out" 2>&1
check "armed by the operator: the module is restored from its backup (logged)" sh -c \
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
	-DTW_QROOT="\"$T/twq\"" -DTW_STATEDIR="\"$T/tw\"" -DSSADDON_PKG_LOCKS="\"$LOCK\""; then
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
	check "quarantine mode, not armed: the writer is named, not killed" sh -c \
		"[ $a = 1 ] && grep -q 'NOT ARMED: would kill pid $WP' '$TWLOG'"
	twstop
	"$TW" arm > /dev/null 2>&1
	twstart quarantine
	writer; a=$(tw_alive)
	check "armed: the writer is killed after its executable is quarantined" sh -c \
		"[ $a = 0 ] && grep -q 'killed tamperer pid $WP' '$TWLOG' && [ -n \"\$(find '$T/twq' -type f)\" ]"
	python3 -c 'import fcntl,sys,time; f=open(sys.argv[1],"w"); fcntl.lockf(f,fcntl.LOCK_EX); open(sys.argv[2],"w").close(); time.sleep(30)' "$LOCK" "$T/locked3" &
	LP=$!; for _ in $(seq 50); do [ -e "$T/locked3" ] && break; sleep 0.1; done
	writer; a=$(tw_alive)
	check "... but not while a package manager is running (logged as not killed)" sh -c \
		"[ $a = 1 ] && grep -q 'not killed: pid $WP .*a package manager is running' '$TWLOG'"
	kill "$LP"; wait "$LP" 2>/dev/null
	twstop
	# the writer's path is replaced after it started: the binary that ran is
	# what is quarantined (via /proc/PID/exe), not the file now at the path
	twstart quarantine
	cp "$T/evil/mybash" "$T/evil/wb2"; rm -rf "$T/twq"; mkdir -p "$T/twq"
	# shellcheck disable=SC2016  # $1 belongs to the inner shell
	"$T/evil/wb2" -c 'sleep 1; echo x >> "$1"; sleep 4; :' w "$T/prot/a.conf" & WP=$!
	sleep 0.3; printf '#!/bin/sh\necho decoy\n' > "$T/decoy"; mv "$T/decoy" "$T/evil/wb2"
	sleep 2
	check "tamperwatch: a writer whose path was swapped: the binary that ran is quarantined" python3 -c "
import glob, struct, sys, zlib
s = [f for f in glob.glob('$T/twq/**/*.z', recursive=True)]
assert s, 'no sample'
d = open(s[0], 'rb').read()
assert zlib.decompress(d[8:]) == open('$T/evil/mybash', 'rb').read()
assert 'decoy' in open('$T/evil/wb2').read()"
	twstop
else
	skip "TamperWatch (fanotify not available here)"
fi

# ------------------------------------------------- P2-2: strict config checks
echo "# Config checking (ssaddon_conf): every add-on refuses a bad config"
LC="$T/bin/secure-sudo-locus"; BI="$T/bin/secure-sudo-biosguard"; FR="$T/bin/secure-sudo-addon-failure"
if addon_cc "$LC" "$ROOT/temporary/locus/locus.c" -DLOCUS_CONF="\"$T/locus.conf\"" &&
   addon_cc "$BI" "$ROOT/temporary/biosguard/biosguard.c" -DBIOS_CONF="\"$T/biosguard.conf\"" &&
   addon_cc "$FR" "$ROOT/temporary/failure/failure.c"; then
	ok "Locus, BiosGuard and the failure reporter build with test paths (-Werror)"
else
	not_ok "Locus, BiosGuard and the failure reporter build with test paths ($(head -1 "$T/build.err"))"
fi
cp "$PG" "$T/bin/secure-sudo-procguard"
for f in procguard procguard_allow bootguard driverguard tamperwatch logging locus-client locus biosguard; do
	install -m0644 "$ROOT/temporary/config/$f.conf" "$T/$f.conf"
done
# the shipped logging.conf, but logging into the test directory
logconf() { sed "s#^log_dir = .*#log_dir = $T/log#" "$ROOT/temporary/config/logging.conf" > "$T/logging.conf"; }
logconf
allok=1
for b in procguard bootguard driverguard tamperwatch locus biosguard; do
	"$T/bin/secure-sudo-$b" check-config > "$T/cc.$b" 2>&1 || { allok=0; sed "s/^/# $b: /" "$T/cc.$b" | head -5; }
done
eq "the shipped config templates pass every add-on's check-config" "$allok" 1
ccheck() { "$1" check-config > "$T/cc.out" 2>&1; echo $?; }
has() { grep -qF -- "$1" "$T/cc.out"; }

printf 'mode = monitor\nmdoe = enforce\n' > "$T/procguard.conf"
check "an unknown key is an error (file:line named)" sh -c "[ $(ccheck "$PG") = 1 ] &&
	grep -qF \"$T/procguard.conf:2: unknown setting 'mdoe'\" '$T/cc.out'"
printf 'mode = enforec\n' > "$T/procguard.conf"
check "a mistyped mode is an error, not a silent 'monitor'" sh -c "[ $(ccheck "$PG") = 1 ] &&
	grep -qF \"mode: 'enforec' is not one of: monitor, enforce\" '$T/cc.out'"
"$PG" scan > "$T/out" 2>&1; rc=$?
check "... and scan refuses to run (exit 78, EX_CONFIG)" sh -c "[ $rc = 78 ] && grep -qF 'refusing to scan' '$T/out' &&
	grep -qF 'refusing to scan: the configuration has 1 error(s)' '$T/log/procguard.log'"
"$PG" status > "$T/out" 2>&1; rc=$?
check "... while status still works and says so" sh -c "[ $rc = 0 ] && grep -qF 'CONFIG:                1 problem(s)' '$T/out'"
printf 'mode = monitor\ninterval = 0\nrespawn_window = 60s\n' > "$T/procguard.conf"
check "numbers must parse in full and be in range" sh -c "[ $(ccheck "$PG") = 1 ] &&
	grep -qF 'interval: 0 is outside 1..3600' '$T/cc.out' && grep -qF \"respawn_window: '60s' is not a whole number\" '$T/cc.out'"
printf 'mode = monitor\nmode = enforce\n' > "$T/procguard.conf"
check "a key set twice is an error" sh -c "[ $(ccheck "$PG") = 1 ] && grep -qF 'mode is set twice (first on line 1)' '$T/cc.out'"
printf 'mode = monitor  # try it first\n' > "$T/procguard.conf"
check "an inline comment is an error (it would be part of the value)" sh -c "[ $(ccheck "$PG") = 1 ]"
printf 'quarantine_root = q\n' > "$T/procguard.conf"
check "a relative path is an error" sh -c "[ $(ccheck "$PG") = 1 ] && grep -qF \"'q' is not an absolute path\" '$T/cc.out'"
printf 'quarantine_root = /var/lib/../../tmp/q\n' > "$T/procguard.conf"
check "a path with '..' is an error" sh -c "[ $(ccheck "$PG") = 1 ] && grep -qF \"contains '..'\" '$T/cc.out'"
printf 'quarantine_root = /%s\n' "$(head -c 5000 /dev/zero | tr '\0' a)" > "$T/procguard.conf"
check "a value longer than its buffer is an error, never truncated" sh -c "[ $(ccheck "$PG") = 1 ] && grep -qE 'too long' '$T/cc.out'"
printf 'mode = monitor\n' > "$T/procguard.conf"; chmod 0664 "$T/procguard.conf"
check "a config writable by group or others is an error" sh -c "[ $(ccheck "$PG") = 1 ] &&
	grep -qF 'writable by group or others (mode 0664)' '$T/cc.out'"
chmod 0644 "$T/procguard.conf"; chown 65534 "$T/procguard.conf"
check "a config not owned by root is an error" sh -c "[ $(ccheck "$PG") = 1 ] && grep -qF 'not owned by root (uid 65534)' '$T/cc.out'"
chown 0 "$T/procguard.conf"
printf '/usr/bin/true\nbin/evil\n' > "$T/procguard_allow.conf"
check "an allowlist entry that is not an absolute path is an error" sh -c "[ $(ccheck "$PG") = 1 ] &&
	grep -qF \"procguard_allow.conf:2: allowlist entry: 'bin/evil' is not an absolute path\" '$T/cc.out'"
install -m0644 "$ROOT/temporary/config/procguard_allow.conf" "$T/procguard_allow.conf"
printf 'remote_enabled = 1\nremote_proto = tcp\n' > "$T/logging.conf"
check "logging.conf is checked by every guard (remote_enabled needs a host)" sh -c "[ $(ccheck "$BG") = 1 ] &&
	grep -qF 'remote_enabled = 1 needs remote_host' '$T/cc.out' && [ $(ccheck "$PG") = 1 ]"
"$BG" scan > /dev/null 2>&1; rc=$?
eq "... and BootGuard's scan refuses to run with it" "$rc" 78
printf 'remote_port = 99999\n' > "$T/logging.conf"
check "a port out of range is an error" sh -c "[ $(ccheck "$DG") = 1 ] && grep -qF \"remote_port: '99999' is not a port\" '$T/cc.out'"
logconf
printf 'host = 10.0.0.1;rm -rf /\n' > "$T/locus-client.conf"
check "locus-client.conf: a host must be a host name or address" sh -c "[ $(ccheck "$DG") = 1 ] && grep -qF 'is not a host name or address' '$T/cc.out'"
install -m0644 "$ROOT/temporary/config/locus-client.conf" "$T/locus-client.conf"
printf 'mode = log\nprot/a.conf\n/etc/../etc/shadow\n' > "$T/tamperwatch.conf"
check "tamperwatch.conf: protected paths must be absolute, with no '..'" sh -c "[ $(ccheck "$TW") = 1 ] &&
	grep -qF 'tamperwatch.conf:2: not a' '$T/cc.out' && grep -qF \"tamperwatch.conf:3: '/etc/../etc/shadow' contains '..'\" '$T/cc.out'"
printf 'root a = /x\nroot a = /y\nroot b c = /z\ngui_port = 8787\n' > "$T/locus.conf"
check "locus.conf: a root set twice, a bad purpose, alloc and GUI on one port" sh -c "[ $(ccheck "$LC") = 1 ] &&
	grep -qF 'root a is set twice' '$T/cc.out' && grep -qF \"purpose 'b c' may only use\" '$T/cc.out'"
printf 'root a = /x\ngui_port = 8787\n' > "$T/locus.conf"
check "... (the shared port is caught once the rest is valid)" sh -c "[ $(ccheck "$LC") = 1 ] &&
	grep -qF 'alloc and gui listen on the same address and port' '$T/cc.out'"
"$LC" serve > /dev/null 2>&1; rc=$?
eq "... and Locus refuses to serve" "$rc" 78
printf 'scan_interval = 5\n' > "$T/biosguard.conf"
check "biosguard.conf: an unknown key is an error" sh -c "[ $(ccheck "$BI") = 1 ] && grep -qF \"unknown setting 'scan_interval'\" '$T/cc.out'"
install -m0644 "$ROOT/temporary/config/biosguard.conf" "$T/biosguard.conf"

# the console: its own gui.conf, and a change it makes that a guard rejects
GUI="$ROOT/temporary/gui/secure-sudo-gui"
printf 'bind = 127.0.0.1\nport = 0\ncolour = red\n' > "$T/gui.conf"
SS_GUI_CONF="$T/gui.conf" python3 -B "$GUI" check-config > "$T/cc.out" 2>&1; rc=$?
check "secure-sudo-gui check-config: a bad port and an unknown key" sh -c "[ $rc = 1 ] &&
	grep -qF \"port: '0' is not a port\" '$T/cc.out' && grep -qF \"unknown setting 'colour'\" '$T/cc.out'"
bgconf monitor; cp "$T/bootguard.conf" "$T/bootguard.before"
cat > "$T/gui-set.py" <<'GUISET'
import importlib.machinery, importlib.util, json, sys
loader = importlib.machinery.SourceFileLoader("gui", sys.argv[1])
spec = importlib.util.spec_from_loader("gui", loader)
g = importlib.util.module_from_spec(spec); loader.exec_module(g)
print(json.dumps(g.Handler.api_setkey(None, {"name": "bootguard", "key": "mode", "value": sys.argv[2]})))
GUISET
PATH="$T/bin:$PATH" SS_ADDON_CONF="$T" python3 -B "$T/gui-set.py" "$GUI" enforec > "$T/gs.out" 2>&1
check "the console rolls back a change check-config rejects" sh -c "grep -qF 'rejected by check-config' '$T/gs.out' &&
	cmp -s '$T/bootguard.conf' '$T/bootguard.before'"
PATH="$T/bin:$PATH" SS_ADDON_CONF="$T" python3 -B "$T/gui-set.py" "$GUI" enforce > "$T/gs.out" 2>&1
check "... and keeps one it accepts" sh -c "grep -qF '\"ok\": true' '$T/gs.out' && grep -qx 'mode = enforce' '$T/bootguard.conf'"

# ------------------------------------------------- P2-2: failure reporting
echo "# Failure reporting (OnFailure= -> secure-sudo-addon-failure)"
printf '#!/bin/sh\nprintf "%%s|%%s\\n" "$1" "$2" >> "%s/notified"\n' "$T" > "$T/notify.sh"
printf 'log_dir = %s/log\nnotify_cmd = /bin/sh %s/notify.sh %%l %%m\n' "$T" "$T" > "$T/logging.conf"
MONITOR_SERVICE_RESULT=exit-code MONITOR_EXIT_CODE=exited MONITOR_EXIT_STATUS=78 \
	"$FR" secure-sudo-procguard.service > /dev/null 2>&1
check "a unit that failed on its config is reported CRITICAL, logged and notified" sh -c "
	grep -qF 'CRIT|ADD-ON FAILED: secure-sudo-procguard.service (result=exit-code, exited=78) - its configuration is invalid' '$T/notified' &&
	grep -qF 'ADD-ON FAILED: secure-sudo-procguard.service' '$T/log/failure.log'"
MONITOR_SERVICE_RESULT=oom-kill "$FR" secure-sudo-tamperwatch.service > /dev/null 2>&1
check "... one killed at its memory limit says so" grep -qF 'secure-sudo-tamperwatch.service (result=oom-kill, unknown=unknown) - it hit its memory limit' "$T/notified"
# shellcheck disable=SC2016  # the $(...) is the attack: it must stay literal
MONITOR_SERVICE_RESULT='x$(touch '"$T"'/pwned)' "$FR" "u';touch $T/pwned2;'" > /dev/null 2>&1
check "... and a hostile unit name or result cannot run a command" sh -c "[ ! -e '$T/pwned' ] && [ ! -e '$T/pwned2' ]"
# notify_cmd runs without a shell (TODO P2-3). A message full of quotes used
# to be quoted for one and wrote past the command buffer; a message with $(...)
# inside a double-quoted template word was run by it.
cat > "$T/notify-long.c" <<'NLONG'
#include <string.h>
#include <stdlib.h>
#include "ssaddon_log.h"
int main(int argc, char **argv)
{
	char m[1000];
	int i, n = argc > 2 ? atoi(argv[2]) : 1;

	memset(m, '\'', sizeof(m) - 1);
	m[sizeof(m) - 1] = '\0';
	ssl_init("longnotify");
	for (i = 0; i < n; i++)
		ssl_notify(SSL_CRIT, "%s", argc > 1 ? argv[1] : m);
	return 0;
}
NLONG
printf '#!/bin/sh\nprintf "%%s\\n" "$#" "$1" >> "%s/argv"\n' "$T" > "$T/argv.sh"
printf 'log_dir = %s/log\nnotify_cmd = /bin/sh %s/argv.sh "%%f says: %%m"\n' "$T" "$T" > "$T/logging.conf"
asan=""; echo 'int main(void){return 0;}' > "$T/a.c"
gcc -fsanitize=address "$T/a.c" -o "$T/a" 2>/dev/null && "$T/a" 2>/dev/null && asan="-fsanitize=address"
if addon_cc "$T/notify-long" "$T/notify-long.c" $asan -DNOTIFY_TIMEOUT_SECS=2; then
	ASAN_OPTIONS=detect_leaks=0 "$T/notify-long" > "$T/nl.out" 2>&1; rc=$?
	check "a message of 999 quotes reaches the command whole, as one argument${asan:+ (ASan)}" sh -c "
		[ $rc = 0 ] && [ \"\$(sed -n 1p '$T/argv')\" = 1 ] && [ \"\$(sed -n 2p '$T/argv' | wc -c)\" = \$((17 + 999 + 1)) ]"
	rm -f "$T/argv"
	# shellcheck disable=SC2016  # the $(...) and backticks are the attack
	"$T/notify-long" 'x $(touch '"$T"'/pwn1) `touch '"$T"'/pwn2` ; touch '"$T"'/pwn3' > /dev/null 2>&1
	check "shell syntax in a message is passed as text, never run" sh -c "
		[ ! -e '$T/pwn1' ] && [ ! -e '$T/pwn2' ] && [ ! -e '$T/pwn3' ] && grep -qF 'touch' '$T/argv'"
	rm -f "$T/argv"
	"$T/notify-long" 'same message' 5 > /dev/null 2>&1
	eq "the same notification five times in a row runs the command once" "$(grep -c '^1$' "$T/argv")" 1
	rm -f "$T/argv"
	"$T/notify-long" 'line one
line two' > /dev/null 2>&1
	check "a newline in a message reaches the command as \\x0a, not a line break" grep -qF 'line one\x0aline two' "$T/argv"
	printf 'log_dir = %s/log\nnotify_cmd = /bin/false %%m\n' "$T" > "$T/logging.conf"
	"$T/notify-long" 'will fail' > /dev/null 2>&1
	check "a notify_cmd that exits non-zero is logged ERROR" grep -qF 'notify_cmd FAILED: exited 1' "$T/log/longnotify.log"
	printf 'log_dir = %s/log\nnotify_cmd = /nonexistent/notify %%m\n' "$T" > "$T/logging.conf"
	"$T/notify-long" 'cannot start' > /dev/null 2>&1
	check "... one that cannot start is logged ERROR" grep -qF 'notify_cmd FAILED: /nonexistent/notify could not be started' "$T/log/longnotify.log"
	printf 'log_dir = %s/log\nnotify_cmd = /bin/sleep 30\n' "$T" > "$T/logging.conf"
	S0=$(date +%s); "$T/notify-long" 'slow' > /dev/null 2>&1; S1=$(date +%s)
	check "... and one that hangs is killed after the timeout and logged" sh -c "
		[ $((S1 - S0)) -lt 10 ] && grep -qF 'notify_cmd FAILED: killed after 2 s' '$T/log/longnotify.log'"
	printf 'log_dir = %s/log\nnotify_cmd = /bin/sh %s/argv.sh %%m\n' "$T" "$T" > "$T/logging.conf"
	cat > "$T/notify-many.c" <<'NMANY'
#include <stdio.h>
#include "ssaddon_log.h"
int main(void)
{
	int i;

	ssl_init("manynotify");
	for (i = 0; i < 15; i++)
		ssl_notify(SSL_CRIT, "distinct %d", i);
	return 0;
}
NMANY
	if addon_cc "$T/notify-many" "$T/notify-many.c"; then
		rm -f "$T/argv"; "$T/notify-many" > /dev/null 2>&1
		eq "at most 10 different notifications run in a minute" "$(grep -c '^1$' "$T/argv")" 10
		check "... and all 15 are still in the log" sh -c "[ \$(grep -c 'NOTIFY: distinct' '$T/log/manynotify.log') = 15 ]"
	else
		not_ok "the notify rate-limit harness builds ($(head -1 "$T/build.err"))"
	fi
else
	not_ok "the notification test harness builds ($(head -1 "$T/build.err"))"
fi
logconf

# ------------------------------------- P2-2 part 2: baseline trust and evidence
echo "# Baseline trust, verified restores and evidence (ssaddon_trust)"
logconf
X="$T/mods/kernel/drivers/x.ko"
# a stored blob (ssaddon_store format) holding other bytes than the baseline's
mkblob() { python3 -c 'import struct,sys,zlib; d=sys.argv[2].encode(); open(sys.argv[1],"wb").write(struct.pack("<Q",len(d))+zlib.compress(d))' "$1" "$2"; }
dgconf enforce
echo mod-v3 > "$X"; chmod 0640 "$X"; "$DG" baseline > /dev/null 2>&1
check "a new baseline is announced with its SHA-256 (on record off-box)" sh -c "
	grep -qE 'BASELINE driverguard \(baseline\): $T/dg/manifest sha256=[0-9a-f]{64}, 1 entries; trust=local' '$DGLOG'"
GOOD="$(sha256sum "$X" | cut -d' ' -f1)"
echo evil > "$X"; chmod 0640 "$X"; EVIL="$(sha256sum "$X" | cut -d' ' -f1)"
ln -sf "$T/victim" "$X.ss-restore"; echo victim > "$T/victim"
"$DG" scan > "$T/out" 2>&1
check "enforce repair: the module is back, with its owner and mode kept" sh -c "
	[ \"\$(cat '$X')\" = mod-v3 ] && [ \"\$(stat -c %a '$X')\" = 640 ] && grep -qF 'sha256 verified' '$DGLOG'"
check "... and a symlink planted at the temporary name was not written through" sh -c "
	[ \"\$(cat '$T/victim')\" = victim ] && [ ! -e '$X.ss-restore' ]"
check "... and the tampered bytes were kept as evidence first (hash, owner, mode, times, copy)" python3 -c "
import json, os
r = [json.loads(l) for l in open('$T/evidence/driverguard.jsonl')][-1]
assert r['action'] == 'repair' and r['path'] == '$X' and r['sha256'] == '$EVIL', r
assert r['expected_sha256'] == '$GOOD' and r['mode'] == '0640' and r['uid'] == 0 and r['size'] == 5
assert r['mtime'] > 0 and os.path.isfile(r['sample'])"
# a backup that does not match the baseline is never written back
B="$(find "$T/dg/backups/fixed" -name 'drv.*.z' | head -1)"
cp "$B" "$T/good.blob"; mkblob "$B" "attacker module"
echo evil > "$X"; "$DG" scan > "$T/out" 2>&1
check "a swapped backup is refused: the file is not overwritten with it" sh -c "
	[ \"\$(cat '$X')\" = evil ] && grep -qF 'does not match the baseline' '$DGLOG' &&
	grep -qF 'DRIVER not repaired: $X' '$DGLOG'"
# rotating backups: the newest one is bad, an older one is good
mkdir -p "$T/dg/backups/2026010100" "$T/dg/backups/2026010200"
cp "$T/good.blob" "$T/dg/backups/2026010100/$(basename "$B")"
mkblob "$T/dg/backups/2026010200/$(basename "$B")" "newer attacker module"
"$DG" scan > "$T/out" 2>&1
check "... and the restore walks back to the newest backup that matches" sh -c "
	[ \"\$(cat '$X')\" = mod-v3 ] && grep -qF 'restored $X from an older backup: 1 newer one(s) did not match' '$DGLOG'"
rm -rf "$T/dg/backups/2026010100" "$T/dg/backups/2026010200"; cp "$T/good.blob" "$B"

# baseline_trust = signed: an operator key the host only has the public half of
openssl genpkey -algorithm ed25519 -out "$T/sign.key" 2>/dev/null
openssl pkey -in "$T/sign.key" -pubout -out "$T/sign.pub" 2>/dev/null; chmod 0644 "$T/sign.pub"
sign() { openssl pkeyutl -sign -rawin -inkey "$T/sign.key" -in "$1" -out "$1.sig" 2>/dev/null; }
dgconf enforce; echo 'baseline_trust = signed' >> "$T/driverguard.conf"
echo evil > "$X"; "$DG" scan > "$T/out" 2>&1; rc=$?
check "signed mode, unsigned baseline: reported, nothing repaired, the unit fails (3)" sh -c "
	[ $rc = 3 ] && [ \"\$(cat '$X')\" = evil ] && grep -qF 'DRIVER baseline NOT TRUSTED (the baseline is not signed' '$DGLOG'"
"$DG" status > "$T/out" 2>&1
check "... and status says why" grep -qF 'baseline trust:    signed - NOT TRUSTED: the baseline is not signed' "$T/out"
sign "$T/dg/manifest"
"$DG" scan > "$T/out" 2>&1; rc=$?
check "signed by the operator's key: the repair goes ahead" sh -c "[ $rc = 0 ] && [ \"\$(cat '$X')\" = mod-v3 ]"
echo '# edited' >> "$T/dg/manifest"; echo evil > "$X"
"$DG" scan > "$T/out" 2>&1; rc=$?
check "an edited baseline no longer verifies: nothing repaired" sh -c "
	[ $rc = 3 ] && [ \"\$(cat '$X')\" = evil ] && grep -qF 'signature does not verify' '$DGLOG'"
openssl genpkey -algorithm ed25519 -out "$T/other.key" 2>/dev/null
openssl pkeyutl -sign -rawin -inkey "$T/other.key" -in "$T/dg/manifest" -out "$T/dg/manifest.sig" 2>/dev/null
"$DG" scan > /dev/null 2>&1; rc=$?
eq "a baseline signed with another key is refused" "$rc" 3
sign "$T/dg/manifest"; chmod 0664 "$T/sign.pub"
"$DG" scan > /dev/null 2>&1; rc=$?
check "a signing key writable by group or others is not trusted" sh -c "[ $rc = 3 ] && grep -qF 'writable by group or others' '$DGLOG'"
chmod 0644 "$T/sign.pub"
"$DG" scan > /dev/null 2>&1
SS_ADDONS_BIN="$T/bin" sh "$ROOT/temporary/hooks/addons-refresh" kernel-update
check "a refresh (package hook) drops the old signature and names the key to sign with" sh -c "
	[ ! -e '$T/dg/manifest.sig' ] && grep -qE 'BASELINE driverguard \(kernel-update\): .* trust=signed, sign it with the key [0-9a-f]{16}' '$DGLOG'"
dgconf monitor

# BootGuard: the staged restore is checked against the baseline at boot
bgconf enforce
echo kernel-v4 > "$T/boot/vmlinuz"; "$BG" baseline > /dev/null 2>&1
echo evil4 > "$T/boot/vmlinuz"; "$BG" scan > /dev/null 2>&1
check "the staged restore records each file's baseline hash" sh -c "
	grep -qP '^\Q$T/boot/vmlinuz\E\t[0-9a-f]{64}$' '$T/bg/restore.list'"
BB=""
for b in "$T"/bg/backups/fixed/boot.*.z; do
	python3 -c 'import struct,sys,zlib; d=open(sys.argv[1],"rb").read(); n=struct.unpack("<Q",d[:8])[0]; sys.exit(0 if zlib.decompress(d[8:])==b"kernel-v4\n" else 1)' "$b" && BB="$b"
done
cp "$BB" "$T/bgood.blob"; mkblob "$BB" "evil kernel"
"$BG" restore-staged > /dev/null 2>&1
check "a swapped boot backup is refused at boot" sh -c "
	[ \"\$(cat '$T/boot/vmlinuz')\" = evil4 ] && grep -qF 'BOOT restore FAILED: $T/boot/vmlinuz' '$BGLOG'"
cp "$T/bgood.blob" "$BB"
"$BG" scan > /dev/null 2>&1
"$BG" restore-staged > /dev/null 2>&1
check "... a good one is applied, and what it replaced is kept as evidence" sh -c "
	[ \"\$(cat '$T/boot/vmlinuz')\" = kernel-v4 ] && grep -qF '\"action\":\"restore\",\"path\":\"$T/boot/vmlinuz\"' '$T/evidence/bootguard.jsonl'"
echo evil5 > "$T/boot/vmlinuz"; printf '%s\t%s\n' "$T/boot/vmlinuz" "$BB" > "$T/bg/restore.list"; : > "$T/bg/PENDING"
"$BG" restore-staged > /dev/null 2>&1
check "a restore staged by an older release (no hash) is checked against the baseline" sh -c "
	[ \"\$(cat '$T/boot/vmlinuz')\" = kernel-v4 ] && [ ! -e '$T/bg/PENDING' ]"
echo evil6 > "$T/boot/vmlinuz"; "$BG" scan > /dev/null 2>&1
echo 'baseline_trust = signed' >> "$T/bootguard.conf"
"$BG" restore-staged > /dev/null 2>&1; rc=$?
check "signed mode, unsigned baseline: the boot restore is refused and kept for the operator" sh -c "
	[ $rc = 3 ] && [ \"\$(cat '$T/boot/vmlinuz')\" = evil6 ] && [ -e '$T/bg/PENDING' ] &&
	grep -qF 'BOOT restore REFUSED: the baseline is not trusted' '$BGLOG'"
sign "$T/bg/manifest"; "$BG" restore-staged > /dev/null 2>&1
eq "... and applied once the operator signs the baseline" "$(cat "$T/boot/vmlinuz")" kernel-v4
bgconf monitor

# ProcGuard and tamperwatch keep evidence of what they remove or quarantine
check "ProcGuard: the removed implant's hash, owner and mode are on record" python3 -c "
import json
r = [json.loads(l) for l in open('$T/evidence/procguard.jsonl') if '\"$T/evil/evil\"' in l]
assert r and r[0]['action'] == 'remove' and len(r[0]['sha256']) == 64 and r[0]['sample'], r"
if grep -q 'killed tamperer' "$TWLOG" 2>/dev/null; then
	check "tamperwatch: the tamperer's executable is on record before the kill" grep -qF '"action":"quarantine","path":"'"$T"'/evil/mybash"' "$T/evidence/tamperwatch.jsonl"
fi
cat > "$T/gui-ev.py" <<'GUIEV'
import importlib.machinery, importlib.util, json, sys
loader = importlib.machinery.SourceFileLoader("gui", sys.argv[1])
spec = importlib.util.spec_from_loader("gui", loader)
g = importlib.util.module_from_spec(spec); loader.exec_module(g)
r = g.record_evidence(sys.argv[2], "quarantine", "/x.gz")
print(json.dumps(r))
GUIEV
SS_EVIDENCE_ROOT="$T/evidence" python3 -B "$T/gui-ev.py" "$GUI" "$T/evil/mybash" > /dev/null 2>&1
check "the console keeps the same record before its quarantine kill" python3 -c "
import json
r = [json.loads(l) for l in open('$T/evidence/gui.jsonl')][-1]
assert r['feature'] == 'gui' and r['path'] == '$T/evil/mybash' and len(r['sha256']) == 64 and r['sample'] == '/x.gz'"

# ------------------------------------------- P2-2 part 3: adversarial tests
echo "# Adversarial: hostile names, edited baselines, symlinks, full disks, bad requests"
logconf
X="$T/mods/kernel/drivers/x.ko"
dgconf enforce
echo mod-v5 > "$X"; chmod 0640 "$X"; "$DG" baseline > /dev/null 2>&1
# a module name carrying a newline and a forged log entry
NLM="$T/mods/kernel/drivers/y"$'\n'"2026-01-01T00:00:00+0000 CRIT  BASELINE forged.ko"
echo y > "$NLM"
"$DG" baseline > /dev/null 2>&1
check "a file name with a newline is not baselined, and is logged escaped (\\x0a)" sh -c "
	grep -qF 'odd file name skipped (not baselined): $T/mods/kernel/drivers/y\\x0a2026' '$DGLOG' &&
	! grep -qF 'forged' '$T/dg/manifest'"
check "... so no log line was forged: every line starts with its own timestamp" sh -c "
	[ \"\$(grep -cv '^20[0-9][0-9]-' '$DGLOG')\" = 0 ]"
rm -f "$NLM"; "$DG" baseline > /dev/null 2>&1
check "the baseline records the hash of exactly the bytes it backed up" python3 -c "
import hashlib, glob, struct, zlib
blobs = {}
for b in glob.glob('$T/dg/backups/fixed/drv.*.z'):
    d = open(b, 'rb').read(); n = struct.unpack('<Q', d[:8])[0]
    blobs[hashlib.sha256(zlib.decompress(d[8:])).hexdigest()] = n
for l in open('$T/dg/manifest'):
    sha, path = l.split(' ', 1)
    assert sha in blobs, (path, sha)"

# an edited baseline naming a file outside the module tree
echo victim > "$T/victim3"; V3="$(sha256sum "$T/victim3" | cut -d' ' -f1)"
cp "$T/dg/manifest" "$T/dgm.keep"
echo "$V3 $T/mods/../victim3" >> "$T/dg/manifest"; echo "$V3 $T/victim3" >> "$T/dg/manifest"
echo changed > "$T/victim3"
"$DG" scan > /dev/null 2>&1; rc=$?
check "baseline entries outside the module tree are ignored, never repaired over (3)" sh -c "
	[ $rc = 3 ] && [ \"\$(cat '$T/victim3')\" = changed ] &&
	grep -qF 'DRIVER baseline entry IGNORED: $T/victim3 is not a file under $T/mods' '$DGLOG' &&
	grep -qF 'DRIVER baseline entry IGNORED: $T/mods/../victim3' '$DGLOG'"
cp "$T/dgm.keep" "$T/dg/manifest"

# a module replaced by a symlink to a file with the very same bytes: hashing
# through the link would call it intact
cp "$X" "$T/same.ko"; rm -f "$X"; ln -s "$T/same.ko" "$X"
"$DG" scan > /dev/null 2>&1
check "a module replaced by a symlink (even to identical bytes) is tampering, and repaired" sh -c "
	grep -qF 'DRIVER tamper: $X was replaced by a symlink' '$DGLOG' && [ ! -L '$X' ] && [ \"\$(cat '$X')\" = mod-v5 ]"
check "... the evidence records the link and where it pointed, not what it pointed at" python3 -c "
import json
r = [json.loads(l) for l in open('$T/evidence/driverguard.jsonl')][-1]
assert r['state'] == 'symlink' and r['link_target'] == '$T/same.ko' and r['sha256'] == '' and r['sample'] == '', r"
# restored file comes back root-owned, without setuid or group/world write
chmod 6777 "$X"; echo evil > "$X"; "$DG" scan > /dev/null 2>&1
eq "a restore keeps the mode only without setuid/setgid and group/world write" "$(stat -c %a "$X")" 755

# a full disk: the baseline is refused, the old one kept
mkdir -p "$T/full"
head -c 300000 /dev/urandom > "$T/mods/kernel/drivers/big.ko"
printf 'mode = enforce\nrotate = 0\ndriver_dir = %s/mods\nbackup_root = %s/full\n' "$T" "$T" > "$T/driverguard.conf"
OLD="$(sha256sum "$T/dg/manifest")"
unshare -m sh -c "mount -t tmpfs -o size=64k tmpfs '$T/full' && '$DG' baseline" > "$T/out" 2>&1; rc=$?
check "baseline with no room for its backups is refused, the previous baseline kept" sh -c "
	[ $rc = 1 ] && [ \"\$(sha256sum '$T/dg/manifest')\" = '$OLD' ] &&
	grep -qF 'DRIVER backup FAILED for $T/mods/kernel/drivers/big.ko' '$DGLOG' &&
	grep -qF 'DRIVER baseline REFUSED (baseline)' '$DGLOG'"
check "... and no partial backup is left behind" sh -c "[ -z \"\$(find '$T/full' -name '*.z')\" ]"
dgconf enforce; "$DG" baseline > /dev/null 2>&1
# evidence cannot be kept: no repair
head -c 300000 /dev/urandom > "$T/mods/kernel/drivers/big.ko"; BIG="$(sha256sum "$T/mods/kernel/drivers/big.ko")"
unshare -m sh -c "mount -t tmpfs -o size=64k tmpfs '$T/evidence' && '$DG' scan" > /dev/null 2>&1
check "with no room to keep the evidence, the tampered module is not overwritten" sh -c "
	[ \"\$(sha256sum '$T/mods/kernel/drivers/big.ko')\" = '$BIG' ] &&
	grep -qF 'DRIVER not repaired: $T/mods/kernel/drivers/big.ko: its current bytes could not be kept' '$DGLOG'"
rm -f "$T/mods/kernel/drivers/big.ko"; "$DG" baseline > /dev/null 2>&1
dgconf monitor; "$DG" scan > /dev/null 2>&1
check "back in monitor mode: disarmed (logged)" sh -c "[ ! -e '$T/dg/enforce-armed' ] && grep -qF 'enforce disarmed' '$DGLOG'"
dgconf enforce; "$DG" scan > /dev/null 2>&1
check "an enforce pass with nothing to repair arms itself" sh -c "
	[ -e '$T/dg/enforce-armed' ] && grep -qF 'ENFORCE ARMED: driverguard will now act (a clean enforce pass)' '$DGLOG'"
dgconf monitor

# BootGuard: what is restored is decided by the baseline, not restore.list
bgconf enforce
echo kernel-v7 > "$T/boot/vmlinuz"; "$BG" baseline > /dev/null 2>&1
echo victim > "$T/victim4"
printf '%s\t%s\n' "$T/victim4" "$(sha256sum "$T/boot/vmlinuz" | cut -d' ' -f1)" > "$T/bg/restore.list"; : > "$T/bg/PENDING"
"$BG" restore-staged > /dev/null 2>&1
check "a restore.list entry outside boot_dir is refused" sh -c "
	[ \"\$(cat '$T/victim4')\" = victim ] && grep -qF 'BOOT restore REFUSED: $T/victim4 is not a baselined file' '$BGLOG'"
echo evil7 > "$T/boot/vmlinuz"
printf '%s\t%064d\n' "$T/boot/vmlinuz" 0 > "$T/bg/restore.list"; : > "$T/bg/PENDING"
"$BG" restore-staged > /dev/null 2>&1
check "a restore.list hash that is not the baseline's is refused" sh -c "
	[ \"\$(cat '$T/boot/vmlinuz')\" = evil7 ] && grep -qF 'BOOT restore REFUSED: the hash staged for $T/boot/vmlinuz' '$BGLOG'"
echo kernel-v7 > "$T/boot/vmlinuz"; rm -f "$T/bg/PENDING" "$T/bg/restore.list"
# a boot file replaced by a symlink to identical bytes is tampering
cp "$T/boot/vmlinuz" "$T/same-vmlinuz"; rm -f "$T/boot/vmlinuz"; ln -s "$T/same-vmlinuz" "$T/boot/vmlinuz"
"$BG" scan > /dev/null 2>&1; "$BG" restore-staged > /dev/null 2>&1
check "BootGuard: a boot file replaced by a symlink is staged and restored as a real file" sh -c "
	grep -qF 'BOOT tamper: $T/boot/vmlinuz was replaced by a symlink' '$BGLOG' &&
	[ ! -L '$T/boot/vmlinuz' ] && [ \"\$(cat '$T/boot/vmlinuz')\" = kernel-v7 ] && [ \"\$(cat '$T/same-vmlinuz')\" = kernel-v7 ]"
# no room for its backups: the baseline is refused, the old one kept
head -c 300000 /dev/urandom > "$T/boot/big.img"
printf 'mode = enforce\nrotate = 0\nboot_dir = %s/boot\nbackup_root = %s/full\n' "$T" "$T" > "$T/bootguard.conf"
OLD="$(sha256sum "$T/bg/manifest")"
unshare -m sh -c "mount -t tmpfs -o size=64k tmpfs '$T/full' && '$BG' baseline" > /dev/null 2>&1; rc=$?
check "BootGuard: a baseline with no room for its backups is refused, the old one kept" sh -c "
	[ $rc = 1 ] && [ \"\$(sha256sum '$T/bg/manifest')\" = '$OLD' ] && grep -qF 'BOOT baseline REFUSED (baseline)' '$BGLOG'"
rm -f "$T/boot/big.img"
bgconf monitor

# Locus: requests from the LAN are untrusted
PORTS="$(python3 -c 'import socket
s=[socket.socket() for _ in range(2)]
[x.bind(("127.0.0.1",0)) for x in s]
print(*[x.getsockname()[1] for x in s])')"
AP="${PORTS% *}"; GP="${PORTS#* }"
mkdir -p "$T/lroot"
printf 'alloc_port = %s\ngui_port = %s\nroot procguard-quarantine = %s/lroot\nroot my_purpose = %s/lroot\n' "$AP" "$GP" "$T" "$T" > "$T/locus.conf"
"$LC" serve > /dev/null 2>&1 & LCP=$!
for _ in $(seq 50); do python3 -c "import socket,sys; socket.create_connection(('127.0.0.1',$AP),1)" 2>/dev/null && break; sleep 0.1; done
lreq() { python3 -c 'import socket,sys
s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),5); s.sendall(sys.argv[2].encode())
print(s.recv(512).decode().strip())' "$AP" "$1" 2>&1; }
eq "Locus: a well-formed request is served" "$(lreq 'ALLOC procguard-quarantine' | cut -c1-3)" "OK "
eq "... a purpose with an underscore (allowed in its config) is served too" "$(lreq 'ALLOC my_purpose' | cut -c1-3)" "OK "
eq "... a purpose naming a path is refused" "$(lreq 'ALLOC ../../etc')" "ERR bad purpose"
eq "... an oversized purpose is refused, not cut to a valid prefix" \
	"$(lreq "ALLOC procguard-quarantine$(printf 'x%.0s' $(seq 60))")" "ERR bad purpose"
eq "... an unknown verb is refused" "$(lreq 'DELETE /')" "ERR bad request"
python3 -c 'import socket,sys,time; s=socket.create_connection(("127.0.0.1",int(sys.argv[1]))); time.sleep(4)' "$AP" &
SIL=$!; sleep 0.5
eq "... a client that connects and says nothing does not stall it for others" \
	"$(timeout 4 python3 -c 'import socket,sys
s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),5); s.sendall(b"PING")
print(s.recv(16).decode().strip())' "$AP" 2>&1)" PONG
kill "$SIL" "$LCP" 2>/dev/null; wait "$SIL" "$LCP" 2>/dev/null

# the failure reporter's input comes from systemd, but a unit name is chosen
# by whoever wrote the unit: a newline must not forge a log entry
"$FR" "x.service"$'\n'"2026-01-01T00:00:00+0000 CRIT  ADD-ON FAILED: forged" > /dev/null 2>&1
check "failure reporter: a newline in a unit name cannot forge a log line" sh -c "
	[ \"\$(grep -cv '^20[0-9][0-9]-' '$T/log/failure.log')\" = 0 ] && ! grep -q '^2026-01-01' '$T/log/failure.log'"

# BiosGuard reads firmware tables the kernel exposes: built against stand-in
# DMI and ACPI directories
BI2="$T/bin/biosguard-fake"
mkdir -p "$T/fw/dmi" "$T/fw/acpi" "$T/fw/state"
if addon_cc "$BI2" "$ROOT/temporary/biosguard/biosguard.c" -DBIOS_CONF="\"$T/biosguard.conf\"" \
	-DBIOS_STATEDIR="\"$T/fw/state\"" -DBIOS_DMI_DIR="\"$T/fw/dmi\"" -DBIOS_ACPI_DIR="\"$T/fw/acpi\""; then
	BILOG="$T/log/biosguard.log"
	echo Vendor > "$T/fw/dmi/bios_vendor"; echo 1.0 > "$T/fw/dmi/bios_version"
	echo dsdt > "$T/fw/acpi/DSDT"; echo ssdt > "$T/fw/acpi/SSDT1"
	# shellcheck disable=SC2016  # the name is the attack: it must stay literal
	echo q > "$T/fw/acpi/x';touch\${IFS}pwnb;'"
	(cd "$T" && "$BI2" baseline > /dev/null 2>&1)
	(cd "$T" && "$BI2" scan > "$T/out" 2>&1)
	check "BiosGuard: a table name with a quote runs no command (it went through a shell)" sh -c "
		[ ! -e '$T/pwnb' ] && grep -q 'firmware fingerprint intact' '$T/out'"
	echo injected > "$T/fw/acpi/SSDT9"
	"$BI2" scan > /dev/null 2>&1
	check "BiosGuard: an ACPI table that appeared after the baseline is reported" \
		grep -qF 'FIRMWARE source appeared: acpi:SSDT9 (not in the baseline)' "$BILOG"
	rm -f "$T/fw/acpi/SSDT9"; echo dsdt2 > "$T/fw/acpi/DSDT"
	"$BI2" scan > /dev/null 2>&1
	check "BiosGuard: a changed table is reported, and nothing is written back" sh -c "
		grep -qF 'FIRMWARE tamper detected: acpi:DSDT changed' '$BILOG' && [ \"\$(cat '$T/fw/acpi/DSDT')\" = dsdt2 ]"
	echo x > "$T/fw/acpi/T"$'\n'"2026-01-01T00:00:00+0000 CRIT  forged"
	"$BI2" scan > /dev/null 2>&1
	check "BiosGuard: a table name with a newline is reported escaped, not fingerprinted" sh -c "
		grep -qF 'FIRMWARE table with an odd name: $T/fw/acpi/T\\x0a2026' '$BILOG' &&
		[ \"\$(grep -cv '^20[0-9][0-9]-' '$BILOG')\" = 0 ]"
else
	not_ok "BiosGuard builds against stand-in firmware directories ($(head -1 "$T/build.err"))"
fi

# the console's API: token, Host, sizes and names
GPORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
printf 'bind = 127.0.0.1\nport = %s\n' "$GPORT" > "$T/gui.conf"
mkdir -p "$T/guist"
SS_GUI_CONF="$T/gui.conf" SS_ADDON_CONF="$T" SS_GUI_STATE="$T/guist" python3 -B "$GUI" > /dev/null 2>&1 & GUIP=$!
for _ in $(seq 50); do [ -s "$T/guist/token" ] && python3 -c "import socket; socket.create_connection(('127.0.0.1',$GPORT),1)" 2>/dev/null && break; sleep 0.1; done
TOK="$(cat "$T/guist/token" 2>/dev/null)"
cat > "$T/api.py" <<'API'
import http.client, sys
port, method, path, tok, host = sys.argv[1:6]
body = sys.argv[6] if len(sys.argv) > 6 else None
c = http.client.HTTPConnection("127.0.0.1", int(port), timeout=5)
c.putrequest(method, path, skip_host=True)
c.putheader("Host", host)
if tok != "-":
    c.putheader("X-SS-Token", tok)
if body is not None:
    if body.startswith("LEN="):
        c.putheader("Content-Length", body[4:]); body = None
    else:
        c.putheader("Content-Length", str(len(body)))
c.endheaders(body.encode() if body else None)
r = c.getresponse()
print(r.status, r.read().decode()[:200])
API
api() { python3 -B "$T/api.py" "$GPORT" "$@" 2>&1; }
eq "console: no token is refused (401)" "$(api GET /api/status - 127.0.0.1 | cut -d' ' -f1)" 401
eq "... a wrong token is refused (401)" "$(api GET /api/status wrong 127.0.0.1 | cut -d' ' -f1)" 401
eq "... another Host (DNS rebinding) is refused even with the token (403)" \
	"$(api GET /api/status "$TOK" evil.example | cut -d' ' -f1)" 403
eq "... with both, the API answers" "$(api GET /api/status "$TOK" 127.0.0.1 | cut -d' ' -f1)" 200
eq "... a non-numeric count is a client error (400)" "$(api GET '/api/logs?n=abc' "$TOK" 127.0.0.1 | cut -d' ' -f1)" 400
check "... a log name that is not a guard's is refused" sh -c "
	api() { python3 -B '$T/api.py' '$GPORT' \"\$@\"; }; api GET '/api/logs?src=..%2F..%2Fetc%2Fshadow' '$TOK' 127.0.0.1 | grep -qF 'unknown log'"
eq "... a negative Content-Length is refused (413)" "$(api POST /api/action "$TOK" 127.0.0.1 LEN=-1 | cut -d' ' -f1)" 413
eq "... an oversized body is refused unread (413)" "$(api POST /api/action "$TOK" 127.0.0.1 LEN=99999999 | cut -d' ' -f1)" 413
check "... a config name outside its list is refused" sh -c "
	python3 -B '$T/api.py' '$GPORT' POST /api/config '$TOK' 127.0.0.1 '{\"name\":\"../../shadow\",\"content\":\"x\"}' | grep -qF 'unknown config'"
check "... a JSON body that is not an object is refused" sh -c "
	python3 -B '$T/api.py' '$GPORT' POST /api/action '$TOK' 127.0.0.1 '[1,2]' | grep -q '^400'"
check "... quarantining PID 1 is refused" sh -c "
	python3 -B '$T/api.py' '$GPORT' POST /api/action '$TOK' 127.0.0.1 '{\"action\":\"quarantine_pid\",\"arg\":\"1\"}' | grep -qF 'PID 1 and the console itself are never killed'"
kill "$GUIP" 2>/dev/null; wait "$GUIP" 2>/dev/null

tap_done
