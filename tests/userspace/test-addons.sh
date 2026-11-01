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
		-o "$out" "$src" "$COMMON/ssaddon_log.c" "$COMMON/ssaddon_store.c" "$COMMON/ssaddon_conf.c" \
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
check "biosguard.conf: BiosGuard has no settings, so any key is an error" sh -c "[ $(ccheck "$BI") = 1 ] && grep -qF \"unknown setting 'scan_interval'\" '$T/cc.out'"
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
# notify_cmd with a message full of quotes: each ' becomes 4 bytes when quoted;
# this used to write past the command buffer
cat > "$T/notify-long.c" <<'NLONG'
#include <string.h>
#include "ssaddon_log.h"
int main(void)
{
	char m[1000];

	memset(m, '\'', sizeof(m) - 1);
	m[sizeof(m) - 1] = '\0';
	ssl_init("longnotify");
	ssl_notify(SSL_CRIT, "%s", m);
	return 0;
}
NLONG
# (the message twice: two quoted copies do not fit in the command)
printf 'log_dir = %s/log\nnotify_cmd = /bin/true %%m %%m\n' "$T" > "$T/logging.conf"
asan=""; echo 'int main(void){return 0;}' > "$T/a.c"
gcc -fsanitize=address "$T/a.c" -o "$T/a" 2>/dev/null && "$T/a" 2>/dev/null && asan="-fsanitize=address"
if addon_cc "$T/notify-long" "$T/notify-long.c" $asan; then
	ASAN_OPTIONS=detect_leaks=0 "$T/notify-long" > "$T/nl.out" 2>&1; rc=$?
	check "a notification too long to quote safely is not run (it used to write past the buffer)${asan:+; built with ASan}" sh -c "
		[ $rc = 0 ] && grep -qF 'notify_cmd not run: the command would be longer than' '$T/log/longnotify.log'"
else
	not_ok "the long-notification test harness builds ($(head -1 "$T/build.err"))"
fi
logconf

tap_done
