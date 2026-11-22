#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-gui.sh - the management console over real HTTP (TODO P2-5): token, Host
# and Origin checks, content type, body size, a bad-token throttle, read-only
# mode, the security headers, and the read-only views (status, health, event
# loss, timeline, policy changes, evidence export) compared with what the CLI
# stub and the fake kernel sysfs say. Needs root (the console refuses to run
# otherwise); skipped otherwise. The admin-mode write paths are in
# test-addons.sh.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

if [ "$(id -u)" -ne 0 ] || ! command -v python3 >/dev/null; then
	skip "console tests (need root and python3)"
	tap_done; exit 0
fi
T="$(mktemp -d)"; GUIP=""
trap '[ -n "$GUIP" ] && kill "$GUIP" 2>/dev/null; rm -rf "$T"' EXIT
chmod 0755 "$T"
GUI="$ROOT/temporary/gui/secure-sudo-gui"
mkdir -p "$T/bin" "$T/addons" "$T/klog" "$T/alog" "$T/sysfs" "$T/evidence/bootguard/2026112212" "$T/state"

# the kernel's knobs
echo 1 > "$T/sysfs/sudo_enforce"; echo 5 > "$T/sysfs/sudo_max_fails"; echo off > "$T/sysfs/timevault"
# logs: kernel/daemon records (JSON) and one guard log, out of time order on purpose
cat > "$T/klog/2026-11-22.log" <<'LOG'
{"schema_version":1,"realtime_ns":1795348802000000000,"event_type":"credential_change","operation":"setuid","decision":"deny","reason":"non_sudo_user"}
{"source":"secure-sudod","realtime_ns":1795348800000000000,"event_type":"event_gap","message":"records lost"}
plain daemon line without a time
LOG
cat > "$T/alog/bootguard.log" <<'LOG'
2026-11-22T11:40:01+0000 INFO  boot restore applied: 2 ok, 0 failed
2026-11-22T11:40:00+0000 CRIT  BOOT restored: /boot/ss-p24.txt
LOG
# evidence: two JSON records, a blob, and a symlink that must not be followed
printf '%s\n' '{"time":"2026-11-22T12:00:00Z","feature":"bootguard","action":"restore","path":"/boot/a"}' \
	'{"time":"2026-11-22T12:01:00Z","feature":"gui","action":"quarantine","path":"/tmp/x"}' > "$T/evidence/all.jsonl"
printf 'BLOBSECRET' > "$T/evidence/bootguard/2026112212/evidence.aa.z"
ln -s /etc/passwd "$T/evidence/planted-link"
# CLI stubs
cat > "$T/bin/secure-sudo" <<'STUB'
#!/bin/sh
case "$1 $2" in
"health --json") echo '{"events_dropped":3,"uptime_s":99,"alerts":{"dropped":2,"state":"ok"}}' ;;
"history -n") echo '{"time":"2026-11-22T10:00:00Z","action":"set","result":"complete"}'
	echo '{"time":"2026-11-22T10:05:00Z","action":"lock","result":"complete"}' ;;
"history --verify") echo "history chain intact"; exit 0 ;;
*) exit 2 ;;
esac
STUB
printf '#!/bin/sh\necho "bootguard: baseline 589 files, mode enforce"\n' > "$T/bin/secure-sudo-bootguard"
chmod 0755 "$T/bin/"*

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
printf 'bind = 127.0.0.1\nport = %s\n' "$PORT" > "$T/gui.conf"   # mode is left at its default
chmod 0644 "$T/gui.conf"
PATH="$T/bin:$PATH" SS_GUI_CONF="$T/gui.conf" SS_ADDON_CONF="$T/addons" SS_GUI_STATE="$T/state" \
	SS_EVIDENCE_ROOT="$T/evidence" SS_GUI_KLOG="$T/klog" SS_GUI_ALOG="$T/alog" SS_GUI_SYSFS="$T/sysfs" \
	SS_GUI_CLI="secure-sudo" python3 -B "$GUI" > "$T/gui.out" 2>&1 & GUIP=$!
for _ in $(seq 60); do
	[ -s "$T/state/token" ] && python3 -c "import socket; socket.create_connection(('127.0.0.1',$PORT),1)" 2>/dev/null && break
	sleep 0.1
done
TOK="$(cat "$T/state/token" 2>/dev/null)"
check "the console starts read-only by default" test -n "$TOK"

PATH="$T/bin:$PATH" python3 -B "$HERE/gui-driver.py" "$PORT" "$TOK" "$T" > "$T/driver.out" 2>&1
while IFS= read -r line; do
	case "$line" in
	"R ok "*) ok "console: ${line#R ok }" ;;
	"R fail "*) not_ok "console: ${line#R fail }" ;;
	esac
done < "$T/driver.out"
check "the driver ran to the end" grep -q '^R done' "$T/driver.out"
[ -f "$T/driver.out" ] && grep -vE '^R (ok|fail|done)' "$T/driver.out" | head -20 | sed 's/^/# /'

# gui.conf: the mode is checked like every other key
kill "$GUIP" 2>/dev/null; wait "$GUIP" 2>/dev/null; GUIP=""
printf 'mode = root\n' > "$T/gui.conf"
SS_GUI_CONF="$T/gui.conf" python3 -B "$GUI" check-config > "$T/cc.out" 2>&1; rc=$?
check "gui.conf: a mode that is neither read_only nor admin is refused" sh -c "
	[ $rc = 1 ] && grep -qF 'mode: ' '$T/cc.out'"
printf 'mode = admin\n' > "$T/gui.conf"
SS_GUI_CONF="$T/gui.conf" python3 -B "$GUI" check-config > "$T/cc.out" 2>&1
check "gui.conf: mode = admin is accepted" grep -qF 'configuration OK' "$T/cc.out"
tap_done
