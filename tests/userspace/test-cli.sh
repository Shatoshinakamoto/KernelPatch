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
HEALTH="$T/daemon.health"
LOAD_HEALTH="$T/load.health"
AUDIT_ENABLED="$T/audit_enabled"
BOOT_ID="$T/boot_id"
SYSTEMCTL="$T/systemctl"
ADDON_STATE="$T/addons"
echo test-boot > "$BOOT_ID"
cat > "$SYSTEMCTL" <<'STUB'
#!/bin/bash
unit="${!#}"
if [[ ${HEALTH_SYSTEMD_UNAVAILABLE:-0} == 1 ]]; then
	exit 1
fi
active=active
enabled=enabled
if [[ $unit == *.timer ]]; then
	active=inactive
	enabled=disabled
fi
if [[ ${HEALTH_FAILED_UNIT:-} == "$unit" ]]; then
	active=failed
elif [[ ${HEALTH_INACTIVE_DISABLED_UNIT:-} == "$unit" ]]; then
	active=inactive
	enabled=disabled
fi
if [[ ${HEALTH_ENABLED_TIMER:-} == "$unit" ]]; then
	active=active
	enabled=enabled
fi
result=success
exit_status=0
exit_mono="$(awk '{printf \"%.0f\", $1 * 1000000 - 1000000}' /proc/uptime)"
if [[ ${HEALTH_FAILED_SCAN:-} == "$unit" ]]; then
	result=exit-code
	exit_status=1
fi
printf 'LoadState=loaded\nActiveState=%s\nUnitFileState=%s\nLastTriggerUSec=Mon 2026-10-26 18:00:00 UTC\nResult=%s\nExecMainStatus=%s\nExecMainExitTimestamp=Mon 2026-10-26 17:59:00 UTC\nExecMainExitTimestampMonotonic=%s\n' \
	"$active" "$enabled" "$result" "$exit_status" "$exit_mono"
STUB
chmod 0755 "$SYSTEMCTL"
if ! (cd "$ROOT/userspace/cli" && gcc -O2 -Wall -Wextra -Werror \
	-DSYSFS="\"$SYS\"" -DSECFS="\"$SEC\"" -DCONFIG_DIR="\"$CFG\"" \
	-DHEALTH_FILE="\"$HEALTH\"" \
	-DLOAD_HEALTH_FILE="\"$LOAD_HEALTH\"" \
	-DAUDIT_ENABLED_FILE="\"$AUDIT_ENABLED\"" \
	-DBOOT_ID_FILE="\"$BOOT_ID\"" \
	-DSYSTEMCTL="\"$SYSTEMCTL\"" \
	-DADDON_STATE_DIR="\"$ADDON_STATE\"" \
	-DSS_TESTING \
	-o "$CLI" secure-sudo.c policy.c vault_allow.c detect_admins.c -lcrypto); then
	not_ok "CLI builds with test paths"; tap_done; exit 1
fi
ok "CLI builds with test paths (-Werror)"

# A fresh config (the shipped one) and a fake kernel with every knob/list.
fresh() {
	rm -rf "$CFG" "$SYS" "$SEC"
	rm -f "$LOAD_HEALTH"
	mkdir -p "$CFG" "$SYS" "$SEC"
	cp "$ROOT"/userspace/config/*.conf "$CFG/"
	chmod 0755 "$CFG"; chmod 0644 "$CFG"/*.conf
	echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0" > "$HEALTH"
	chmod 0600 "$HEALTH"
	sed -n 's/^\([a-z_]*\) *=.*/\1/p' "$ROOT/userspace/config/secure-sudo.conf" |
		while read -r k; do echo old > "$SYS/$k"; done
	echo 0 > "$SYS/events_dropped"
	echo 0 > "$SYS/audit_events_dropped"
	echo 1 > "$AUDIT_ENABLED"
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
fresh; setkey remote_syslog loghost:70000; lint --no-kernel
lint_err "remote syslog port is bounded" "remote_syslog = loghost:70000: port is outside"
fresh; setkey remote_syslog_transport tcp; lint --no-kernel
lint_err "remote transport is explicit" "remote_syslog_transport = tcp: not udp or tls"
fresh; setkey remote_syslog_ca_file relative.pem; lint --no-kernel
lint_err "remote CA path must be absolute" "remote_syslog_ca_file = relative.pem: not an absolute path"
fresh; setkey remote_syslog_ca_file ""; lint --no-kernel
lint_err "remote CA bundle cannot be empty" "remote_syslog_ca_file = : not an absolute path"
fresh; setkey remote_queue_max_mb 1025; lint --no-kernel
lint_err "remote queue has a bounded maximum" "remote_queue_max_mb = 1025: out of range"
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
check "successful load persists a root-only complete result" sh -c \
	"[ \"\$(stat -c '%a' '$LOAD_HEALTH')\" = 600 ] && grep -q 'state=complete .*rejected=0' '$LOAD_HEALTH'"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1
check "health JSON reports last successful load" grep -q '"last_load":"complete"' "$T/health.out"
fresh; setkey admin_gid 0; rm "$CFG/blacklist.conf"; "$CLI" load > "$T/load.out" 2>&1
check "missing list file: reported as cleared, kernel list emptied" sh -c "grep -qE 'blacklist +cleared \(no config file\)' '$T/load.out' && [ \"\$(cat '$SEC/blacklist')\" = '' ]"
fresh; setkey admin_gid 0; setkey retain_days 7; "$CLI" load > "$T/load.out" 2>&1
check "daemon keys reported skipped" grep -qE '^  skipped +retain_days .*read by secure-sudod' "$T/load.out"

echo "# health"
fresh
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
eq "health reports degraded fake kernel and exits non-zero" "$rc" 1
check "health JSON reports live/config policy mismatch" grep -q '"policy":"mismatch"' "$T/health.out"
check "health JSON reports daemon heartbeat" grep -q '"daemon":"active"' "$T/health.out"
check "health reports an unknown load outcome before the first run" grep -q \
	'"last_load":"unknown"' "$T/health.out"
echo 1 > "$SYS/audit_events"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1
check "health reports an enabled kernel audit feed" grep -q '"audit_feed":"active"' "$T/health.out"
echo 0 > "$AUDIT_ENABLED"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1
check "configured audit feed degrades when kernel auditing is inactive" grep -q \
	'"audit_feed":"inactive"' "$T/health.out"
echo 1 > "$AUDIT_ENABLED"
check "health JSON reports remote forwarding state" grep -q '"remote_forwarding":"disabled"' "$T/health.out"
check "health JSON reports remote transport" grep -q '"remote_transport":"udp"' "$T/health.out"
check "health JSON reports active log retention" grep -q '"retention_state":"active"' "$T/health.out"
echo "remote_transport=udp retention_state=held remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1
check "health reports an active evidence retention hold" grep -q '"retention_state":"held"' "$T/health.out"
echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0" > "$HEALTH"
check "health JSON reports heartbeat metric availability" grep -q '"heartbeat_metrics":"available"' "$T/health.out"
check "health JSON reports add-on and timer unit states" sh -c \
	"grep -q '\"systemd\":\"available\"' '$T/health.out' && grep -q 'secure-sudo-driverguard.timer' '$T/health.out'"
HEALTH_FAILED_UNIT=secure-sudo-procguard.service SS_TEST_ALLOW_ROOT=1 \
	"$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health degrades for a failed enabled add-on" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"addon_health\":\"degraded\"' '$T/health.out'"
HEALTH_INACTIVE_DISABLED_UNIT=secure-sudo-procguard.service SS_TEST_ALLOW_ROOT=1 \
	"$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "disabled optional add-on does not degrade health" grep -q \
	'"addon_health":"healthy"' "$T/health.out"
HEALTH_SYSTEMD_UNAVAILABLE=1 SS_TEST_ALLOW_ROOT=1 \
	"$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health reports unavailable systemd inspection" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"addon_health\":\"unavailable\"' '$T/health.out'"
HEALTH_ENABLED_TIMER=secure-sudo-driverguard.timer SS_TEST_ALLOW_ROOT=1 \
	"$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "enabled scanning timer without baseline degrades health" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"baseline\":\"missing\"' '$T/health.out'"
mkdir -p "$ADDON_STATE/driverguard"; echo baseline > "$ADDON_STATE/driverguard/manifest"
HEALTH_ENABLED_TIMER=secure-sudo-driverguard.timer SS_TEST_ALLOW_ROOT=1 \
	"$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "fresh baseline and timer trigger are reported" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"baseline\":\"current\"' '$T/health.out' && grep -q '\"last_trigger\":\"Mon 2026-10-26 18:00:00 UTC\"' '$T/health.out'"
check "health reports scan service result and last successful scan time" sh -c \
	"grep -q '\"scan_result\":\"success\",\"scan_exit_status\":\"0\",\"last_scan\":\"Mon 2026-10-26 17:59:00 UTC\",\"scan_age_seconds\":' '$T/health.out'"
HEALTH_ENABLED_TIMER=secure-sudo-driverguard.timer \
HEALTH_FAILED_SCAN=secure-sudo-driverguard.service SS_TEST_ALLOW_ROOT=1 \
	"$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "failed scan result degrades enabled timer health" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"addon_health\":\"degraded\"' '$T/health.out' && grep -q '\"scan_result\":\"exit-code\"' '$T/health.out'"
HEALTH_ENABLED_TIMER=secure-sudo-driverguard.timer \
SS_TEST_STALE_SCAN=1 SS_TEST_ALLOW_ROOT=1 \
	"$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "scan older than the hourly interval degrades timer health" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"addon_health\":\"degraded\"' '$T/health.out' && grep -q '\"scan_age_seconds\":93601' '$T/health.out'"
touch -d '31 days ago' "$ADDON_STATE/driverguard/manifest"
HEALTH_ENABLED_TIMER=secure-sudo-driverguard.timer SS_TEST_ALLOW_ROOT=1 \
	"$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "stale baseline degrades an enabled scanning timer" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"baseline\":\"stale\"' '$T/health.out'"
echo "remote_transport=udp retention_state=active remote_state=udp_unconfirmed remote_sent=1 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health does not treat UDP send as confirmed delivery" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"remote_forwarding\":\"udp_unconfirmed\"' '$T/health.out'"
echo "remote_transport=tls retention_state=active remote_state=tls_queued remote_sent=0 remote_failures=1 remote_queue_records=2 remote_queue_bytes=300 remote_queue_dropped=4 local_log_failures=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health reports TLS queue backlog and drops" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"remote_transport\":\"tls\"' '$T/health.out' && grep -q '\"remote_queue_records\":2' '$T/health.out' && grep -q '\"remote_queue_dropped\":4' '$T/health.out'"
echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=1" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health reports local log write failures" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"local_log_failures\":1' '$T/health.out'"
echo "remote_transport=udp remote_state=disabled" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health marks incomplete daemon metrics unavailable" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"heartbeat_metrics\":\"unavailable\"' '$T/health.out'"
echo 2 > "$SYS/events_dropped"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health JSON reports event-ring loss" sh -c "[ $rc -eq 1 ] && grep -q '\"events_dropped\":2' '$T/health.out'"
fresh; setkey remote_syslog "not-a-host"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1
check "health detects invalid daemon configuration" grep -q '"policy":"invalid"' "$T/health.out"
fresh; echo "unknown_policy_key = 1" >> "$CFG/secure-sudo.conf"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1
check "health detects unknown policy keys" grep -q '"policy":"invalid"' "$T/health.out"
echo "updated=$(date +%s) boot_id=test-boot state=partial accepted=3 rejected=1 skipped=0 rejected_keys=sudo_max_fails omitted=0" > "$LOAD_HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health JSON reports and degrades for persisted partial load" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"last_load\":\"partial\"' '$T/health.out' && grep -q '\"load_rejected\":1' '$T/health.out' && grep -q '\"load_rejected_keys\":\"sudo_max_fails\"' '$T/health.out'"
sed -i 's/boot_id=test-boot/boot_id=previous-boot/' "$LOAD_HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health rejects a load result from a previous boot" grep -q '"last_load":"stale"' "$T/health.out"
rm -f "$LOAD_HEALTH"

fresh; setkey admin_gid 0; setkey sudo_max_fails 0
cp -a "$SYS" "$T/sys-before"
"$CLI" load > "$T/load.out" 2>&1; rc=$?
eq "lint error: load exits 1" "$rc" 1
check "lint error: load refused, nothing written" diff -r "$SYS" "$T/sys-before"
check "lint error: says why" grep -q 'load refused: fix the errors above' "$T/load.out"
check "refused load is persisted for health" grep -q 'state=refused' "$LOAD_HEALTH"
"$CLI" load --force > "$T/load.out" 2>&1; rc=$?
eq "--force: still exits 1 (partial policy)" "$rc" 1
check "--force: the bad value is rejected, not written" sh -c "grep -qE '^  rejected +sudo_max_fails = 0 .*out of range' '$T/load.out' && [ \"\$(cat '$SYS/sudo_max_fails')\" = old ]"
check "--force: the other settings were applied" sh -c "[ \"\$(cat '$SYS/sudo_window_sec')\" = 60 ]"
check "--force: says the policy is incomplete" grep -q 'load INCOMPLETE' "$T/load.out"
check "partial load rejection count and setting are persisted" grep -q 'state=partial .*rejected=1 .*rejected_keys=sudo_max_fails' "$LOAD_HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health degrades and reports rejected partial load" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"last_load\":\"partial\"' '$T/health.out' && grep -q '\"load_rejected\":1' '$T/health.out'"

fresh; setkey admin_gid 0
rm "$SYS/bpf_guard"; mkdir "$SYS/bpf_guard"	# the kernel refuses this one
"$CLI" load --force > "$T/load.out" 2>&1; rc=$?
eq "kernel rejects one setting: exit 1" "$rc" 1
check "kernel rejection reported with the kernel's reason" grep -qE '^  rejected +bpf_guard = 1 +line [0-9]+ +Is a directory' "$T/load.out"
check "kernel rejection: the rest still loaded and counted" grep -qE '^load: [0-9]+ accepted, 1 rejected' "$T/load.out"

mv "$SYS" "$T/sys-away"; "$CLI" load > "$T/load.out" 2>&1; rc=$?
check "no LSM: load fails and says so" sh -c "[ $rc -eq 1 ] && grep -q 'LSM not active' '$T/load.out'"
check "LSM-inactive refusal is persisted" grep -q 'state=refused' "$LOAD_HEALTH"
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
