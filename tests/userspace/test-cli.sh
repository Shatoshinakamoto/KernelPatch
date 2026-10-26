#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# test-cli.sh - tests for `secure-sudo lint` and `secure-sudo load` (TODO
# P0-2 CLI/config parsing, P0-6 policy preflight and load report).
#
# The CLI is built with SYSFS, SECFS and CONFIG_DIR pointed into a scratch
# directory: plain files stand in for the kernel's knobs and lists, and a knob
# replaced by a directory stands in for a value the kernel rejects. The real
# kernel's verdicts are exercised in the VM suite (tests/vm/). Needs no root
# except the ownership and non-root cases, which are skipped without it.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
chmod 0755 "$T"
SYS="$T/sys"; SEC="$T/sec"; CFG="$T/etc"
CLI="$T/secure-sudo"
if ! (cd "$ROOT/userspace/cli" && gcc -O2 -Wall -Wextra -Werror \
	-DSYSFS="\"$SYS\"" -DSECFS="\"$SEC\"" -DCONFIG_DIR="\"$CFG\"" \
	-o "$CLI" secure-sudo.c policy.c vault_allow.c detect_admins.c -lcrypto); then
	not_ok "CLI builds with test paths"; tap_done; exit 1
fi
ok "CLI builds with test paths (-Werror)"

# A fresh config (the shipped one) and a fake kernel with every knob/list.
fresh() {
	rm -rf "$CFG" "$SYS" "$SEC"
	mkdir -p "$CFG" "$SYS" "$SEC"
	cp "$ROOT"/userspace/config/*.conf "$CFG/"
	chmod 0755 "$CFG"; chmod 0644 "$CFG"/*.conf
	sed -n 's/^\([a-z_]*\) *=.*/\1/p' "$ROOT/userspace/config/secure-sudo.conf" |
		while read -r k; do echo old > "$SYS/$k"; done
	echo 0 > "$SYS/lock"
	for l in blacklist setid_exec_allow tmp_exec_allow node_allowed_children \
		node_sea_binaries driver_blacklist timevault_allow home_map \
		home_write_allow binvault_allow prguard_allow; do
		echo old > "$SEC/$l"
	done
}
setkey() { # key value: replace or append in secure-sudo.conf
	if grep -qE "^$1[[:space:]]*=" "$CFG/secure-sudo.conf"; then
		sed -i -E "s|^$1[[:space:]]*=.*|$1 = $2|" "$CFG/secure-sudo.conf"
	else
		echo "$1 = $2" >> "$CFG/secure-sudo.conf"
	fi
}
# lint [args]: run lint on $CFG with an empty PAM dir unless given; sets LRC
mkdir -p "$T/pam-empty"
lint() { SUDO_UID='' "$CLI" lint --config-dir "$CFG" --pam-dir "$T/pam-empty" --otp-dir "$T/otp" "$@" > "$T/lint.out" 2>&1; LRC=$?; }
says() { grep -qE -- "$1" "$T/lint.out"; }
lint_err() { # description regex : lint fails and reports an ERROR matching regex
	if [ "$LRC" -eq 1 ] && grep -E "ERROR" "$T/lint.out" | grep -qE -- "$2"; then ok "$1"
	else not_ok "$1 (rc $LRC: $(grep -E 'ERROR|WARN' "$T/lint.out" | head -2 | tr '\n' ' '))"; fi
}

echo "# lint: configuration syntax and values"
"$CLI" lint --config-dir "$ROOT/userspace/config" --source-tree > "$T/lint.out" 2>&1
check "shipped config passes lint (--source-tree)" grep -q '^lint: 0 error(s), 0 warning(s)' "$T/lint.out"

fresh; lint --no-kernel
eq "fresh install config: no errors" "$LRC" 0
fresh; echo "block_setdi = 1" >> "$CFG/secure-sudo.conf"; lint --no-kernel
lint_err "unknown key is an error with its line" "secure-sudo.conf:[0-9]+ +unknown setting 'block_setdi'"
fresh; setkey block_setid maybe; lint --no-kernel
lint_err "non-boolean value" "block_setid = maybe: not a boolean"
fresh; setkey sudo_max_fails 0; lint --no-kernel
lint_err "value below the kernel's range" "sudo_max_fails = 0: out of range \(1\.\.1000\)"
fresh; setkey max_ram_percent 101; lint --no-kernel
lint_err "value above the kernel's range" "max_ram_percent = 101: out of range"
fresh; setkey check_interval_ms 5s; lint --no-kernel
lint_err "number with junk" "check_interval_ms = 5s: not a whole number"
fresh; setkey net_mode lan; lint --no-kernel
lint_err "bad net_mode" "net_mode = lan: not one of"
fresh; setkey admin_gid "27,abc"; lint --no-kernel
lint_err "bad admin_gid list" "admin_gid = 27,abc"
fresh; setkey admin_gid "$(seq -s, 1 17)"; lint --no-kernel
lint_err "more GIDs than the kernel holds" "more than 16 GIDs"
fresh; setkey block_setid "1   # on"; lint --no-kernel
lint_err "inline comment in a value" "comments must be on their own line"
fresh; echo "block_flash" >> "$CFG/secure-sudo.conf"; lint --no-kernel
lint_err "line without '='" "not a \"key = value\" line"
fresh; printf 'block_flash = %02000d\n' 1 >> "$CFG/secure-sudo.conf"; lint --no-kernel
lint_err "over-long line" "line too long"
fresh; echo "block_setid = 0" >> "$CFG/secure-sudo.conf"; lint --no-kernel
check "duplicate key is a warning naming the first line" says "WARN +secure-sudo.conf:[0-9]+ +block_setid is set again \(first on line [0-9]+\)"
fresh; setkey vault_action delete; lint --no-kernel
lint_err "bad daemon value (vault_action)" "vault_action = delete: not quarantine or wipe"
fresh; setkey remote_syslog loghost; lint --no-kernel
lint_err "bad daemon value (remote_syslog)" "remote_syslog = loghost: not host:port"
fresh; setkey timevault_enabled 1; lint --no-kernel
eq "timevault_enabled is not an error" "$LRC" 0
check "... and lint explains load never engages TimeVault" says "note +timevault_enabled +not applied by load"

echo "# lint: allowlists, admin groups, combinations"
fresh; rm "$CFG/blacklist.conf"; lint --no-kernel
check "missing list file warns that load clears the list" says "WARN +blacklist.conf +missing: load will CLEAR"
fresh; echo "usr/bin/nc" >> "$CFG/blacklist.conf"; lint --no-kernel
lint_err "relative path in a path list" "blacklist.conf:[0-9]+ +'usr/bin/nc' is not an absolute path"
fresh; echo "/usr/bin/definitely-not-here" >> "$CFG/setid_exec_allow.conf"; lint --no-kernel
check "listed program that does not exist warns" says "WARN +setid_exec_allow.conf:[0-9]+ +/usr/bin/definitely-not-here does not exist"
fresh; echo "alice /home/alice" >> "$CFG/home_map.conf"; lint --no-kernel
lint_err "malformed home_map line" "home_map.conf:[0-9]+ +want"
fresh; echo "/lib/modules/x/evil.ko" >> "$CFG/driver_blacklist.conf"; lint --no-kernel
lint_err "path where a module name is expected" "driver_blacklist.conf:[0-9]+ +'/lib/modules/x/evil.ko': a name"
fresh; setkey admin_gid 4242424; lint --no-kernel
lint_err "admin GID that does not exist" "GID 4242424 does not exist"
fresh; setkey admin_gid unset; setkey block_setid_exec 1; lint --no-kernel
lint_err "admin_gid unset + block_setid_exec locks admins out of sudo" "only root may run sudo/su"
fresh; setkey admin_gid 0; SUDO_UID=65534 "$CLI" lint --config-dir "$CFG" --pam-dir "$T/pam-empty" --no-kernel > "$T/lint.out" 2>&1; LRC=$?
check "operator not in admin_gid: warning" says "WARN +admin_gid +you \(nobody, uid 65534\) are in none of these groups"
setkey block_setid_exec 1; SUDO_UID=65534 "$CLI" lint --config-dir "$CFG" --pam-dir "$T/pam-empty" --no-kernel > "$T/lint.out" 2>&1; LRC=$?
lint_err "... an error with block_setid_exec (would lose sudo)" "can no longer run sudo"
fresh; setkey block_home_write 1; lint --no-kernel
lint_err "block_home_write with an empty home_map" "home_map.conf is empty"
fresh; setkey prguard_observe 1; lint --no-kernel
check "prguard_observe without prguard_enabled warns" says "WARN +prguard_observe +has no effect"
fresh; setkey block_setid_exec 1; setkey admin_gid 0; lint --no-kernel
check "block_setid_exec with an empty allowlist warns" says "WARN +block_setid_exec +setid_exec_allow.conf is empty"
fresh; setkey lock_confidentiality 1; lint --no-kernel
check "lock effects listed (modules + kernel memory)" says "ALL kernel module loads.*reading kernel memory"
fresh; setkey vault_action wipe; lint --no-kernel
check "vault_action = wipe warns that evidence is lost" says "WARN +vault_action +wipe deletes"

echo "# lint: running kernel"
fresh; lint
eq "fake kernel with every knob: no errors" "$LRC" 0
fresh; rm "$SYS/perf_guard"; lint
lint_err "setting the running kernel does not have" "perf_guard +the running kernel has no"
fresh; echo 1 > "$SYS/lock"; lint
lint_err "config already locked" "locked until reboot"

echo "# lint: PAM order"
P="$T/pam"; mkdir -p "$P" "$T/mod" "$T/otp"
touch "$T/mod/pam_secure_sudo.so" "$T/mod/pam_secure_otp.so"
SS="$T/mod/pam_secure_sudo.so"; OTPM="$T/mod/pam_secure_otp.so"
printf 'auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n' > "$P/common-auth"
plint() { SUDO_UID='' "$CLI" lint --config-dir "$CFG" --pam-dir "$P" --otp-dir "$T/otp" --no-kernel > "$T/lint.out" 2>&1; LRC=$?; }
fresh
printf '#%%PAM-1.0\nauth optional %s\n@include common-auth\n' "$SS" > "$P/sudo"; plint
check "recommended one-line stack: clean" sh -c "! grep -q 'pam.d/sudo' '$T/lint.out'"
printf 'auth [default=die] pam_unix.so\nauth required %s authfail\nauth sufficient pam_unix.so\nauth required %s authsucc\n' "$SS" "$SS" > "$P/sudo"; plint
lint_err "old documented stack is an error (denies the right password)" "pam.d/sudo +a password module with control \[default=die\]"
printf '@include common-auth\nauth optional %s\n' "$SS" > "$P/sudo"; plint
check "pam_secure_sudo after the password check warns" says "WARN +pam.d/sudo +pam_secure_sudo.so comes after the password check"
printf '@include common-auth\n' > "$P/sudo"; plint
check "cooldown on but nothing feeds it warns" says "WARN +pam.d/sudo +sudo_cooldown_enabled = 1 but pam_secure_sudo.so is not in the sudo stack"
printf 'auth optional %s\n@include common-auth\nauth required %s\n' "$SS" "$OTPM" > "$P/sudo"; plint
lint_err "OTP wired before any OTP is set up: lockout error" "no OTP is set up"
touch "$T/otp/secret.enc"; plint
check "... clean once the OTP secret exists" sh -c "! grep -q 'ERROR' '$T/lint.out'"
printf 'auth optional %s\nauth required %s use_first_pass\n@include common-auth\n' "$SS" "$OTPM" > "$P/sudo"; plint
lint_err "OTP use_first_pass before any password module" "use_first_pass comes before any password module"
printf 'auth optional %s\n@include common-auth\nauth required /nonexistent/pam_secure_otp.so\n' "$SS" > "$P/sudo"; plint
lint_err "OTP module not installed: lockout error" "is not installed: every sudo login fails"
printf 'auth optional %s\n@include missing-file\n' "$SS" > "$P/sudo"; plint
check "missing @include warns" says "WARN +missing-file +included PAM file"
rm -f "$P/sudo"

echo "# load"
fresh; setkey admin_gid 0
"$CLI" load > "$T/load.out" 2>&1; rc=$?
eq "load of a clean config exits 0" "$rc" 0
check "settings reach the kernel files" sh -c "[ \"\$(cat '$SYS/sudo_max_fails')\" = 5 ] && [ \"\$(cat '$SYS/net_mode')\" = monitor ]"
check "every setting reported accepted with its line" grep -qE '^  accepted +sudo_max_fails = 5 +line [0-9]+' "$T/load.out"
check "lists are loaded before the settings" sh -c "grep -E '^  (accepted|rejected|skipped) ' '$T/load.out' | head -1 | grep -qE 'blacklist'"
check "summary line counts the results" grep -qE '^load: [0-9]+ accepted, 0 rejected, [0-9]+ skipped$' "$T/load.out"
fresh; setkey admin_gid 0; rm "$CFG/blacklist.conf"; "$CLI" load > "$T/load.out" 2>&1
check "missing list file: reported as cleared, kernel list emptied" sh -c "grep -qE 'blacklist +cleared \(no config file\)' '$T/load.out' && [ \"\$(cat '$SEC/blacklist')\" = '' ]"
fresh; setkey admin_gid 0; setkey retain_days 7; "$CLI" load > "$T/load.out" 2>&1
check "daemon keys reported skipped" grep -qE '^  skipped +retain_days .*read by secure-sudod' "$T/load.out"

fresh; setkey admin_gid 0; setkey sudo_max_fails 0
cp -a "$SYS" "$T/sys-before"
"$CLI" load > "$T/load.out" 2>&1; rc=$?
eq "lint error: load exits 1" "$rc" 1
check "lint error: load refused, nothing written" diff -r "$SYS" "$T/sys-before"
check "lint error: says why" grep -q 'load refused: fix the errors above' "$T/load.out"
"$CLI" load --force > "$T/load.out" 2>&1; rc=$?
eq "--force: still exits 1 (partial policy)" "$rc" 1
check "--force: the bad value is rejected, not written" sh -c "grep -qE '^  rejected +sudo_max_fails = 0 .*out of range' '$T/load.out' && [ \"\$(cat '$SYS/sudo_max_fails')\" = old ]"
check "--force: the other settings were applied" sh -c "[ \"\$(cat '$SYS/sudo_window_sec')\" = 60 ]"
check "--force: says the policy is incomplete" grep -q 'load INCOMPLETE' "$T/load.out"

fresh; setkey admin_gid 0
rm "$SYS/bpf_guard"; mkdir "$SYS/bpf_guard"	# the kernel refuses this one
"$CLI" load --force > "$T/load.out" 2>&1; rc=$?
eq "kernel rejects one setting: exit 1" "$rc" 1
check "kernel rejection reported with the kernel's reason" grep -qE '^  rejected +bpf_guard = 1 +line [0-9]+ +Is a directory' "$T/load.out"
check "kernel rejection: the rest still loaded and counted" grep -qE '^load: [0-9]+ accepted, 1 rejected' "$T/load.out"

mv "$SYS" "$T/sys-away"; "$CLI" load > "$T/load.out" 2>&1; rc=$?
check "no LSM: load fails and says so" sh -c "[ $rc -eq 1 ] && grep -q 'LSM not active' '$T/load.out'"
mv "$T/sys-away" "$SYS"

if [ "$(id -u)" -eq 0 ] && command -v setpriv >/dev/null; then
	fresh
	setpriv --reuid=65534 --regid=65534 --clear-groups "$CLI" load > "$T/load.out" 2>&1; rc=$?
	check "non-root: load refused" sh -c "[ $rc -ne 0 ] && grep -q 'must be run as root' '$T/load.out'"
	setpriv --reuid=65534 --regid=65534 --clear-groups "$CLI" lint --config-dir "$CFG" --pam-dir "$T/pam-empty" --no-kernel > "$T/lint.out" 2>&1; rc=$?
	eq "non-root: lint runs (read-only)" "$rc" 0
	fresh; chmod 0666 "$CFG/blacklist.conf"; lint --no-kernel
	lint_err "world-writable list file is an error" "blacklist.conf +owned by uid 0, mode 0666"
	fresh; chown 65534 "$CFG/secure-sudo.conf"; lint --no-kernel
	lint_err "config not owned by root is an error" "secure-sudo.conf +owned by uid 65534"
else
	skip "non-root and ownership cases (need root and setpriv)"
fi
tap_done
