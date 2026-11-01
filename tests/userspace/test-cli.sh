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
# Stands in for secure-sudo-otp: records the arguments it was given.
cat > "$T/otp-stub" <<STUB
#!/bin/sh
printf '%s|' "\$@" > "$T/otp-args"
STUB
chmod 0755 "$T/otp-stub"
# Stands in for contain.sh: exits with $CONTAIN_RC.
printf '#!/bin/sh\nexit "${CONTAIN_RC:-0}"\n' > "$T/contain-stub"
chmod 0755 "$T/contain-stub"
if ! (cd "$ROOT/userspace/cli" && gcc -O2 -Wall -Wextra -Werror \
	-DSYSFS="\"$SYS\"" -DSECFS="\"$SEC\"" -DCONFIG_DIR="\"$CFG\"" \
	-DHEALTH_FILE="\"$HEALTH\"" \
	-DLOAD_HEALTH_FILE="\"$LOAD_HEALTH\"" \
	-DAUDIT_ENABLED_FILE="\"$AUDIT_ENABLED\"" \
	-DBOOT_ID_FILE="\"$BOOT_ID\"" \
	-DSYSTEMCTL="\"$SYSTEMCTL\"" \
	-DADDON_STATE_DIR="\"$ADDON_STATE\"" \
	-DSS_STATE_DIR="\"$T/state\"" \
	-DOTP_HELPER="\"$T/otp-stub\"" \
	-DCONTAIN_HELPER="\"$T/contain-stub\"" \
	-DSS_TESTING \
	-o "$CLI" secure-sudo.c policy.c policy_state.c vault_allow.c detect_admins.c node_scan.c -lcrypto); then
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
	echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0 event_gaps=0 events_missing=0" > "$HEALTH"
	chmod 0600 "$HEALTH"
	sed -n 's/^\([a-z_]*\) *=.*/\1/p' "$ROOT/userspace/config/secure-sudo.conf" |
		while read -r k; do echo old > "$SYS/$k"; done
	echo 0 > "$SYS/events_dropped"
	echo 0 > "$SYS/audit_events_dropped"
	echo 1 > "$AUDIT_ENABLED"
	echo 0 > "$SYS/lock"
	for l in blacklist setid_exec_allow tmp_exec_allow node_allowed_children \
		node_sea_binaries driver_blacklist timevault_allow home_map \
		home_write_allow binvault_allow prguard_allow tpm_openers; do
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
fresh; setkey node_sea_scan_interval soon; lint --no-kernel
lint_err "node-scan interval must be whole minutes" "node_sea_scan_interval = soon: out of range \(0 = off"
fresh; setkey node_sea_scan_dirs /opt,srv; lint --no-kernel
lint_err "node-scan directories must be absolute" "node_sea_scan_dirs = /opt,srv: 'srv' is not an absolute directory"
fresh; setkey node_sea_scan_interval 0; setkey node_sea_scan_dirs /opt,/srv; lint --no-kernel
eq "valid node-scan settings pass lint" "$LRC" 0
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
fresh; setkey admin_gid 0; mkdir -p "$T/state"
printf '/opt/by-hand/app\n' >> "$CFG/node_sea_binaries.conf"
printf '# found\n/opt/found/app\n/opt/by-hand/app\n' > "$T/state/node_sea_auto.list"
"$CLI" load > "$T/load.out" 2>&1
check "load reports what node-scan found" grep -qE '^  accepted +node_sea_binaries +2 entries \(1 from node-scan\)' "$T/load.out"
eq "load sends the config's entries first, then node-scan's, once each" \
	"$(tr '\n' ' ' < "$SEC/node_sea_binaries")" "/opt/by-hand/app /opt/found/app "
rm -f "$T/state/node_sea_auto.list"
fresh; setkey admin_gid 0; printf '/bin/a\n# note\n\n/bin/b\n  /bin/c\n' > "$CFG/blacklist.conf"
"$CLI" load > "$T/load.out" 2>&1
check "load counts every entry of a list (not just the first)" grep -qE '^  accepted +blacklist +3 entries$' "$T/load.out"

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
echo "remote_transport=udp retention_state=held remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0 event_gaps=0 events_missing=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1
check "health reports an active evidence retention hold" grep -q '"retention_state":"held"' "$T/health.out"
echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0 event_gaps=0 events_missing=0" > "$HEALTH"
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
echo "remote_transport=udp retention_state=active remote_state=udp_unconfirmed remote_sent=1 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0 event_gaps=0 events_missing=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health does not treat UDP send as confirmed delivery" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"remote_forwarding\":\"udp_unconfirmed\"' '$T/health.out'"
echo "remote_transport=tls retention_state=active remote_state=tls_queued remote_sent=0 remote_failures=1 remote_queue_records=2 remote_queue_bytes=300 remote_queue_dropped=4 local_log_failures=0 event_gaps=0 events_missing=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health reports TLS queue backlog and drops" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"remote_transport\":\"tls\"' '$T/health.out' && grep -q '\"remote_queue_records\":2' '$T/health.out' && grep -q '\"remote_queue_dropped\":4' '$T/health.out'"
echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=1 event_gaps=0 events_missing=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health reports local log write failures" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"local_log_failures\":1' '$T/health.out'"
echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0 event_gaps=2 events_missing=7" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "health degrades when the daemon saw event-stream gaps" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"event_gaps\":2,\"events_missing\":7' '$T/health.out'"
for ns in pending failing; do
	echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0 event_gaps=0 events_missing=0 net_state=$ns" > "$HEALTH"
	SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
	check "health degrades when net_mode rules are $ns (P1-8)" sh -c \
		"[ $rc -eq 1 ] && grep -q '\"network_policy\":\"$ns\"' '$T/health.out'"
done
echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0 event_gaps=0 events_missing=0 net_state=applied" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health > "$T/health.out" 2>&1
check "health shows the network policy rules state" grep -q '^Network policy rules: applied' "$T/health.out"
echo "remote_transport=udp xretention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0 event_gaps=0 events_missing=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "heartbeat keys match whole names only (xretention_state is not retention_state)" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"heartbeat_metrics\":\"unavailable\"' '$T/health.out'"
echo "remote_transport=udp retention_state=active remote_state=disabled remote_sent=0 remote_failures=0 remote_queue_records=0 remote_queue_bytes=0 remote_queue_dropped=0 local_log_failures=0" > "$HEALTH"
SS_TEST_ALLOW_ROOT=1 "$CLI" health --json > "$T/health.out" 2>&1; rc=$?
check "a heartbeat without the event-gap counters is incomplete" sh -c \
	"[ $rc -eq 1 ] && grep -q '\"heartbeat_metrics\":\"unavailable\"' '$T/health.out'"
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
echo "# P1-6: diff (preview), snapshots, history, restore"
ST="$T/state/policy"
rm -rf "$T/state"
export SUDO_USER=opsalice	# who the history and snapshots name
fresh; setkey admin_gid 0
"$CLI" diff > "$T/diff.out" 2>&1; rc=$?
check "diff before any load lists every difference" sh -c \
	"[ $rc -eq 0 ] && grep -qE '^  change +sudo_max_fails +live old -> config 5' '$T/diff.out' && grep -qE '^  change +blacklist$' '$T/diff.out'"
check "... list entries to add and remove, with counts" sh -c \
	"grep -qE '^ +- old$' '$T/diff.out' && grep -qE '^ +\([0-9]+ to add, 1 to remove\)' '$T/diff.out'"
cp -a "$SYS" "$T/sys-before"; cp -a "$SEC" "$T/sec-before"; cp -a "$CFG" "$T/cfg-before"
"$CLI" load --dry-run > "$T/dry.out" 2>&1
check "load --dry-run is the same preview" diff "$T/diff.out" "$T/dry.out"
check "diff and --dry-run change nothing (kernel, config, no snapshot)" sh -c \
	"diff -r '$SYS' '$T/sys-before' && diff -r '$SEC' '$T/sec-before' && diff -r '$CFG' '$T/cfg-before' && [ ! -e '$ST/snapshots' ] || [ -z \"\$(ls -A '$ST/snapshots')\" ]"
rm -rf "$T/sys-before" "$T/sec-before" "$T/cfg-before"
"$CLI" load > "$T/load.out" 2>&1
snap1="$(ls "$ST/snapshots" | head -1)"
check "load takes a snapshot first and names it" grep -q "saved as snapshot $snap1" "$T/load.out"
check "... with the old live state and the config files" sh -c \
	"grep -qx 'sudo_max_fails = old' '$ST/snapshots/$snap1/live/settings' && [ \"\$(cat '$ST/snapshots/$snap1/live/blacklist')\" = old ] && cmp -s '$CFG/blacklist.conf' '$ST/snapshots/$snap1/disk/blacklist.conf'"
check "... root-only, with reason and SHA256SUMS" sh -c \
	"[ \"\$(stat -c %a '$ST/snapshots/$snap1')\" = 700 ] && grep -qx 'reason = pre-load' '$ST/snapshots/$snap1/meta' && (cd '$ST/snapshots/$snap1' && sha256sum -c --quiet SHA256SUMS)"
"$CLI" diff > "$T/diff.out" 2>&1
check "after a clean load diff reports 0 changes" grep -q '^diff: 0 change(s): the kernel runs the configuration' "$T/diff.out"
check "history records the load: result, counts, lint, snapshot" sh -c \
	"tail -1 '$ST/history.jsonl' | grep -q '\"action\":\"load\".*\"result\":\"complete\",\"lint_errors\":0,\"changes\":[1-9][0-9]*,\"accepted\":[0-9]*,\"rejected\":0.*\"snapshot\":\"$snap1\"'"
check "... and who ran it (SUDO_USER)" sh -c "tail -1 '$ST/history.jsonl' | grep -q '\"sudo_user\":\"opsalice\"'"
check "history file is root-only" sh -c "[ \"\$(stat -c %a '$ST/history.jsonl')\" = 600 ]"
"$CLI" snapshot verify "$snap1" > "$T/sv.out" 2>&1; rc=$?
eq "snapshot verify: intact snapshot passes" "$rc" 0

# A partial load: the kernel refuses one setting.
setkey sudo_max_fails 6
rm "$SYS/bpf_guard"; mkdir "$SYS/bpf_guard"
"$CLI" load > "$T/load.out" 2>&1; rc=$?
snap2="$(ls "$ST/snapshots" | tail -1)"
check "partial load: INCOMPLETE names what was rejected and the restore point" sh -c \
	"[ $rc -eq 1 ] && grep -q 'load INCOMPLETE.*rejected: bpf_guard.*secure-sudo restore $snap2' '$T/load.out'"
check "partial load is in the history with the rejected setting" sh -c \
	"tail -1 '$ST/history.jsonl' | grep -q '\"result\":\"partial\".*\"rejected\":1.*\"rejected_keys\":\"bpf_guard\"'"
"$CLI" diff > "$T/diff.out" 2>&1
check "diff after a partial load shows what did not apply" sh -c \
	"grep -qE '^  unknown +bpf_guard' '$T/diff.out' && ! grep -qE 'sudo_max_fails' '$T/diff.out'"
rmdir "$SYS/bpf_guard"; echo 1 > "$SYS/bpf_guard"

# Restore the first snapshot (before sudo_max_fails = 6).
echo "/usr/bin/extra-entry" >> "$CFG/blacklist.conf"
echo n | "$CLI" restore "$snap1" > "$T/rs.out" 2>&1; rc=$?
check "restore previews and stops without 'yes'" sh -c \
	"[ $rc -eq 1 ] && grep -qE '^  change +sudo_max_fails +now 6 -> snapshot 5' '$T/rs.out' && grep -qE '^ +- /usr/bin/extra-entry' '$T/rs.out' && grep -q aborted '$T/rs.out' && grep -q extra-entry '$CFG/blacklist.conf'"
nsnap="$(ls "$ST/snapshots" | wc -l)"
"$CLI" restore "$snap1" -y > "$T/rs.out" 2>&1; rc=$?
pre="$(sed -n 's/^restore: current state saved as snapshot //p' "$T/rs.out")"
check "restore -y: files back as in the snapshot, and loaded" sh -c \
	"[ $rc -eq 0 ] && cmp -s '$CFG/blacklist.conf' '$ST/snapshots/$snap1/disk/blacklist.conf' && grep -qE '^sudo_max_fails *= *5' '$CFG/secure-sudo.conf' && [ \"\$(cat '$SYS/sudo_max_fails')\" = 5 ]"
check "... after saving what it replaced" sh -c \
	"[ -n '$pre' ] && grep -q extra-entry '$ST/snapshots/$pre/disk/blacklist.conf' && [ \$(ls '$ST/snapshots' | wc -l) -eq $((nsnap + 1)) ]"
check "... recorded as a restore with its source" sh -c \
	"tail -1 '$ST/history.jsonl' | grep -q '\"action\":\"restore\".*\"result\":\"complete\".*\"snapshot\":\"$pre\".*\"restored_from\":\"$snap1\"'"

# Integrity: a changed snapshot file and a changed history line are caught.
chmod u+w "$ST/snapshots/$snap1/disk/blacklist.conf"
echo "/tmp/evil" >> "$ST/snapshots/$snap1/disk/blacklist.conf"
"$CLI" snapshot verify "$snap1" > "$T/sv.out" 2>&1; rc=$?
check "snapshot verify: an edited file fails" sh -c \
	"[ $rc -eq 1 ] && grep -q 'disk/blacklist.conf changed since the snapshot was taken' '$T/sv.out'"
"$CLI" restore "$snap1" -y > "$T/rs.out" 2>&1; rc=$?
check "restore refuses a snapshot that fails verification" sh -c \
	"[ $rc -eq 1 ] && grep -q 'failed its integrity check' '$T/rs.out' && ! grep -q /tmp/evil '$CFG/blacklist.conf'"
# A careful forger also rewrites SHA256SUMS: the snapshot then checks out
# on its own, but the next snapshot and the history recorded the old sums.
chmod u+w "$ST/snapshots/$snap1/SHA256SUMS"
(cd "$ST/snapshots/$snap1" && awk '{print $2}' SHA256SUMS | xargs sha256sum > SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS)
"$CLI" snapshot verify "$snap1" > "$T/sv.out" 2>&1; rc=$?
eq "(forged snapshot with rewritten sums checks out on its own)" "$rc" 0
"$CLI" snapshot verify "$snap2" > "$T/sv.out" 2>&1
check "... but the next snapshot sees its predecessor changed" grep -q "previous snapshot $snap1 changed after this one" "$T/sv.out"
"$CLI" history --verify > "$T/hv.out" 2>&1; rc=$?
check "history --verify flags the record whose snapshot changed" sh -c \
	"[ $rc -eq 1 ] && grep -q \"snapshot $snap1 is not the one recorded\" '$T/hv.out'"
rm -rf "${ST:?}/snapshots/$snap1"
"$CLI" history --verify > "$T/hv.out" 2>&1; rc=$?
eq "history --verify: intact chain passes" "$rc" 0
cp "$ST/history.jsonl" "$T/hist.bak"
sed -i '2s/"result":"[a-z]*"/"result":"complete"/; 2s/"accepted":[0-9]*/"accepted":999/' "$ST/history.jsonl"
"$CLI" history --verify > "$T/hv.out" 2>&1; rc=$?
check "history --verify: an edited record breaks the chain" sh -c \
	"[ $rc -eq 1 ] && grep -q 'line 3: does not follow line 2' '$T/hv.out'"
cp "$T/hist.bak" "$T/hist.del"; sed -i '2d' "$T/hist.del"; cp "$T/hist.del" "$ST/history.jsonl"
"$CLI" history --verify > "$T/hv.out" 2>&1; rc=$?
eq "history --verify: a removed record breaks the chain" "$rc" 1
cp "$T/hist.bak" "$ST/history.jsonl"
"$CLI" history -n 2 > "$T/h.out" 2>&1
check "history prints the latest records readably" sh -c \
	"[ \$(wc -l < '$T/h.out') -eq 2 ] && grep -qE 'restore +opsalice +complete +changes=[0-9]+ accepted=[0-9]+ rejected=0' '$T/h.out'"

# set, lock: snapshot first, recorded either way.
"$CLI" set sudo_max_fails 9 > /dev/null 2>&1
check "set is recorded with what it set" sh -c \
	"tail -1 '$ST/history.jsonl' | grep -q '\"action\":\"set\".*\"result\":\"complete\".*\"detail\":\"sudo_max_fails = 9\".*\"snapshot\":\"[0-9TZ-]*\"'"
rm "$SYS/max_ram_percent"; mkdir "$SYS/max_ram_percent"
"$CLI" set max_ram_percent 77 > /dev/null 2>&1; rc=$?
check "a set the kernel refuses is recorded as rejected, not persisted" sh -c \
	"[ $rc -eq 1 ] && tail -1 '$ST/history.jsonl' | grep -q '\"action\":\"set\".*\"result\":\"rejected\".*max_ram_percent = 77' && ! grep -qE '^max_ram_percent *= *77' '$CFG/secure-sudo.conf'"
rmdir "$SYS/max_ram_percent"; echo 80 > "$SYS/max_ram_percent"
echo 7 > "$SYS/sudo_max_fails"
"$CLI" lock -y > "$T/lock.out" 2>&1; rc=$?
check "lock warns when the running policy is not the config's" sh -c \
	"[ $rc -eq 0 ] && grep -q 'running policy differs from .* in [0-9]* place' '$T/lock.out' && grep -q 'locked state is snapshot' '$T/lock.out'"
check "lock is recorded with its pre-lock snapshot" sh -c \
	"tail -1 '$ST/history.jsonl' | grep -q '\"action\":\"lock\".*\"result\":\"complete\"' && grep -lx 'reason = pre-lock' '$ST'/snapshots/*/meta >/dev/null"
any="$(ls "$ST/snapshots" | head -1)"
"$CLI" restore "$any" -y > "$T/rs.out" 2>&1; rc=$?
check "restore refused while locked (points at --no-load)" sh -c \
	"[ $rc -eq 1 ] && grep -q 'locked until reboot.*--no-load' '$T/rs.out'"
"$CLI" restore "$any" --no-load -y > "$T/rs.out" 2>&1; rc=$?
check "restore --no-load while locked: files only, for the next boot" sh -c \
	"[ $rc -eq 0 ] && grep -q 'not loaded (locked: they apply at the next boot)' '$T/rs.out' && cmp -s '$CFG/secure-sudo.conf' '$ST/snapshots/$any/disk/secure-sudo.conf'"
"$CLI" restore ../../etc -y > "$T/rs.out" 2>&1; rc=$?
eq "restore refuses an id that is not a snapshot id" "$rc" 2
echo 0 > "$SYS/lock"
"$CLI" snapshot -m "before upgrade" > "$T/sn.out" 2>&1
check "manual snapshot with a reason" sh -c \
	"id=\$(sed -n 's/^snapshot //p' '$T/sn.out'); grep -qx 'reason = beforeupgrade' '$ST/snapshots/'\$id/meta"
"$CLI" snapshot list > "$T/sl.out" 2>&1
check "snapshot list shows id, reason, lock state" grep -qE '^[0-9]{8}T[0-9]{6}Z-[0-9]{9} +pre-lock +by +opsalice +locked=0' "$T/sl.out"
n0=$(wc -l < "$ST/history.jsonl")
"$CLI" contain network --allow 10.0.0.1 -y > /dev/null 2>&1
check "contain: recorded with what was asked" sh -c \
	"tail -1 '$ST/history.jsonl' | grep -q '\"action\":\"contain\".*\"result\":\"complete\".*\"detail\":\"network --allow 10.0.0.1 -y\"'"
CONTAIN_RC=1 "$CLI" contain release account mallory -y > /dev/null 2>&1; rc=$?
check "release that fails: recorded as failed, exit status passed on" sh -c \
	"[ $rc -eq 1 ] && tail -1 '$ST/history.jsonl' | grep -q '\"action\":\"release\".*\"result\":\"failed\"'"
"$CLI" contain process 4242 --dry-run > /dev/null 2>&1
CONTAIN_RC=3 "$CLI" contain process 4242 > /dev/null 2>&1
"$CLI" contain status > /dev/null 2>&1
eq "dry runs, unconfirmed actions and status are not recorded" "$(wc -l < "$ST/history.jsonl")" "$((n0 + 2))"
"$CLI" history --verify > "$T/hv.out" 2>&1; rc=$?
eq "history chain still verifies after every action" "$rc" 0
unset SUDO_USER

# `secure-sudo otp ...` hands the subcommand to the helper, not "otp".
rm -f "$T/otp-args"
SS_TEST_ALLOW_ROOT=1 "$CLI" otp seal >/dev/null 2>&1
eq "otp passes its subcommand to the helper (not \"otp\")" "$(cat "$T/otp-args" 2>/dev/null)" "seal|"
SS_TEST_ALLOW_ROOT=1 "$CLI" otp setup --key-store=file --prefix >/dev/null 2>&1
eq "... with its options" "$(cat "$T/otp-args" 2>/dev/null)" "setup|--key-store=file|--prefix|"
tap_done
