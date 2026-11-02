#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

if ! command -v openssl >/dev/null || ! command -v tar >/dev/null ||
   ! command -v python3 >/dev/null; then
	skip "evidence export verification tests (need OpenSSL, tar and Python)"
	tap_done
	exit 0
fi

T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
chmod 0700 "$T"
mkdir -p "$T/logs" "$T/state/quarantine" "$T/config" "$T/sysfs" \
	"$T/secfs" "$T/proc" "$T/bin"
# Includes the awkward cases for the two chain implementations: an empty
# line, backslashes, trailing blanks and a last line without a newline.
printf '{"schema_version":1,"message":"fixture event"}\n\n  a \\\\ b\\n  \nlast line, no newline' \
	> "$T/logs/2026-10-26.log"
printf 'block_setid = 1\n' > "$T/config/secure-sudo.conf"
printf 'fixture secret\n' > "$T/config/otp-secret.conf"
printf '1\n' > "$T/sysfs/block_setid"
printf '0\n' > "$T/sysfs/events_dropped"
printf '0\n' > "$T/sysfs/audit_events_dropped"
printf 'test-boot-id\n' > "$T/proc/boot_id"
printf 'lockdown,secure_sudo\n' > "$T/proc/lsm"
cat > "$T/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
printf 'ActiveState=active\nSubState=running\nMainPID=1\n'
STUB
chmod 0755 "$T/bin/systemctl"
SCRIPT="$T/evidence-export.sh"
VERIFY="$ROOT/userspace/daemon/helpers/evidence-verify.py"
tr -d '\r' < "$ROOT/userspace/daemon/helpers/evidence-export.sh" |
	sed -e "s|^LOGDIR=.*|LOGDIR=\"$T/logs\"|" \
	    -e "s|^STATEDIR=.*|STATEDIR=\"$T/state\"|" \
	    -e "s|^CONFIGDIR=.*|CONFIGDIR=\"$T/config\"|" \
	    -e "s|^SYSFS=.*|SYSFS=\"$T/sysfs\"|" \
	    -e "s|^SECFS=.*|SECFS=\"$T/secfs\"|" \
	    -e "s|^BOOT_ID_FILE=.*|BOOT_ID_FILE=\"$T/proc/boot_id\"|" \
	    -e "s|^ACTIVE_LSM_FILE=.*|ACTIVE_LSM_FILE=\"$T/proc/lsm\"|" \
	    -e 's/ -eq 0 ]] || {/ -eq ${EUID:-$(id -u)} ]] || {/' \
	    -e 's/== 0 ]] || {/== "$(id -u)" ]] || {/' \
	    > "$SCRIPT"

if [[ $(id -u) -ne 0 ]]; then
	refute_with "production exporter rejects non-root invocations" \
		"must run as root" bash "$ROOT/userspace/daemon/helpers/evidence-export.sh" \
		"$T/should-not-exist.tar.gz"
fi

if PATH="$T/bin:$PATH" bash "$SCRIPT" "$T/evidence.tar.gz" >"$T/out" 2>&1; then
	ok "root export creates a bundle"
else
	not_ok "root export creates a bundle ($(cat "$T/out"))"
	tap_done
	exit 1
fi
check "bundle has checksums and event-chain checkpoints" \
	sh -c "tar -tzf '$T/evidence.tar.gz' | grep -qE '^\\./(SHA256SUMS|event-chain.txt)$'"
eq "bundle archive has private mode 0600" "$(stat -c %a "$T/evidence.tar.gz")" 600
mkdir "$T/unpacked"
tar -xzf "$T/evidence.tar.gz" -C "$T/unpacked"
check "bundle checksum manifest verifies" sh -c \
	"cd '$T/unpacked' && sha256sum -c SHA256SUMS >/dev/null"
check "independent verifier accepts an unsigned intact bundle" \
	python3 "$VERIFY" "$T/evidence.tar.gz"
check "bundle omits secret-named configuration" sh -c \
	"! tar -tzf '$T/evidence.tar.gz' | grep -q 'otp-secret'"

cp -a "$T/unpacked" "$T/tampered"
printf 'tampered\n' > "$T/tampered/logs/2026-10-26.log"
tar -czf "$T/tampered.tar.gz" -C "$T/tampered" .
if python3 "$VERIFY" "$T/tampered.tar.gz" >"$T/out" 2>&1; then
	not_ok "independent verifier rejects modified bundle contents"
else
	ok "independent verifier rejects modified bundle contents"
fi

python3 - "$T/unsafe.tar.gz" "$T/logs/2026-10-26.log" <<'PY'
import sys
import tarfile
with tarfile.open(sys.argv[1], "w:gz") as archive:
    archive.add(sys.argv[2], arcname="../outside")
PY
if python3 "$VERIFY" "$T/unsafe.tar.gz" >"$T/out" 2>&1; then
	not_ok "independent verifier rejects path traversal in archive"
else
	ok "independent verifier rejects path traversal in archive"
fi

if openssl genpkey -algorithm ED25519 -out "$T/external.pem" 2>/dev/null; then
	chmod 0600 "$T/external.pem"
	openssl pkey -in "$T/external.pem" -pubout -out "$T/external.pub" 2>/dev/null
	openssl genpkey -algorithm ED25519 -out "$T/wrong.pem" 2>/dev/null
	openssl pkey -in "$T/wrong.pem" -pubout -out "$T/wrong.pub" 2>/dev/null
	if PATH="$T/bin:$PATH" bash "$SCRIPT" "$T/signed.tar.gz" --signing-key "$T/external.pem" \
		>"$T/out" 2>&1; then
		mkdir "$T/signed"
		tar -xzf "$T/signed.tar.gz" -C "$T/signed"
		tail -n 1 "$T/signed/event-chain.txt" | cut -f 3 > "$T/final"
		check "external Ed25519 key signs the final event-chain checkpoint" \
			openssl pkeyutl -verify -rawin -pubin \
			-inkey "$T/signed/event-chain.pub" -in "$T/final" \
			-sigfile "$T/signed/event-chain.sig"
		check "external Ed25519 key signs the bundle checksum manifest" \
			openssl pkeyutl -verify -rawin -pubin \
			-inkey "$T/signed/event-chain.pub" \
			-in "$T/signed/bundle-manifest.sha256" \
			-sigfile "$T/signed/bundle-manifest.sig"
		check "independent verifier validates signed bundle with trusted key" \
			python3 "$VERIFY" "$T/signed.tar.gz" --trusted-key "$T/external.pub"
		if python3 "$VERIFY" "$T/signed.tar.gz" --trusted-key "$T/wrong.pub" \
			>"$T/out" 2>&1; then
			not_ok "independent verifier rejects an untrusted signing key"
		else
			ok "independent verifier rejects an untrusted signing key"
		fi
	else
		not_ok "signed evidence bundle is created ($(cat "$T/out"))"
	fi
else
	skip "external Ed25519 signing test (openssl provider unavailable)"
fi

if bash "$SCRIPT" "$T/evidence.tar.gz" >"$T/out" 2>&1; then
	not_ok "export refuses to overwrite an existing bundle"
else
	ok "export refuses to overwrite an existing bundle"
fi

# ---- P1-3: the shell fallback chains exactly like the Python path ----
sed -e 's/command -v python3 /command -v python3-absent-for-test /' "$SCRIPT" \
	> "$T/export-noshell.sh"
if PATH="$T/bin:$PATH" bash "$T/export-noshell.sh" "$T/shellchain.tar.gz" >"$T/out" 2>&1; then
	mkdir "$T/shellchain"
	tar -xzf "$T/shellchain.tar.gz" -C "$T/shellchain"
	check "shell and Python exporters write the same event chain" \
		cmp "$T/shellchain/event-chain.txt" "$T/unpacked/event-chain.txt"
else
	not_ok "shell-fallback export runs ($(cat "$T/out"))"
fi

# ---- P1-3: off-host checkpoints (as the collector received them) ----
python3 - "$T/logs/2026-10-27.log" "$T/collector.log" <<'PY'
import hashlib, json, sys
log, collector = sys.argv[1], sys.argv[2]
name = "2026-10-27.log"
c = hashlib.sha256(b"secure_sudo-event-chain-v1\t" + name.encode() + b"\n").hexdigest()
with open(log, "wb") as out, open(collector, "w") as coll:
    for i in range(1, 6):
        line = json.dumps({"schema_version": 1, "sequence": i}).encode()
        out.write(line + b"\n")
        c = hashlib.sha256(c.encode() + b"\t" + line + b"\n").hexdigest()
        if i == 3:   # the collector's copy, behind its syslog header
            coll.write("<85>1 2026-10-27T10:00:00Z host secure_sudo - - - " +
                       json.dumps({"schema_version": 1, "source": "secure-sudod",
                                   "event_type": "log_checkpoint", "log": name,
                                   "lines": 3, "chain": c}) + "\n")
PY
PATH="$T/bin:$PATH" bash "$SCRIPT" "$T/cp-ok.tar.gz" >/dev/null 2>&1
if python3 "$VERIFY" "$T/cp-ok.tar.gz" --checkpoints "$T/collector.log" >"$T/out" 2>&1 &&
	grep -q "2026-10-27.log: lines 1-3 match an off-host checkpoint; 2 later" "$T/out"; then
	ok "off-host checkpoint verifies the logs and reports the unanchored tail"
else
	not_ok "off-host checkpoint verifies the logs ($(cat "$T/out"))"
fi
sed -i '2s/"sequence": 2/"sequence": 20/' "$T/logs/2026-10-27.log"
PATH="$T/bin:$PATH" bash "$SCRIPT" "$T/cp-edited.tar.gz" >/dev/null 2>&1
refute_with "a log edited on the host fails against the off-host checkpoint" \
	"changed after it was checkpointed" \
	python3 "$VERIFY" "$T/cp-edited.tar.gz" --checkpoints "$T/collector.log"
head -n 2 "$T/logs/2026-10-27.log" > "$T/short" && cat "$T/short" > "$T/logs/2026-10-27.log"
PATH="$T/bin:$PATH" bash "$SCRIPT" "$T/cp-short.tar.gz" >/dev/null 2>&1
refute_with "a log truncated on the host fails against the off-host checkpoint" \
	"truncated or replaced" \
	python3 "$VERIFY" "$T/cp-short.tar.gz" --checkpoints "$T/collector.log"
printf '{"source":"secure-sudod","event_type":"log_checkpoint","log":"../x.log","lines":1,"chain":"00"}\n' \
	> "$T/bad-collector.log"
refute_with "a malformed checkpoint record is rejected, not skipped" \
	"malformed log_checkpoint" \
	python3 "$VERIFY" "$T/cp-ok.tar.gz" --checkpoints "$T/bad-collector.log"
# ---- G2: the TimeVault manifest against the off-host Merkle roots ----
printf '# secure_sudo timevault manifest v2\n%064d /etc/a\n%064d /etc/with space\n' 0 1 \
	> "$T/state/manifest"
TVROOT=$(python3 "$VERIFY" --timevault-root "$T/state/manifest")
eq "--timevault-root prints a 64-hex root" "${#TVROOT}" 64
tvrec() { # type root [extra json]
	printf '<85>1 2026-10-27T10:00:00Z host secure_sudo - - - {"schema_version":1,"source":"secure-sudod","realtime_ns":1,"event_type":"%s","reason":"x","root":"%s","leaves":2%s}\n' "$@"
}
{ tvrec timevault_baseline "$TVROOT"; tvrec timevault_merkle "$TVROOT"; } > "$T/tv-collector.log"
PATH="$T/bin:$PATH" bash "$SCRIPT" "$T/tv-ok.tar.gz" >/dev/null 2>&1
if python3 "$VERIFY" "$T/tv-ok.tar.gz" --timevault "$T/tv-collector.log" >"$T/out" 2>&1 &&
	grep -q "the bundle's manifest (2 entries) matches the off-host root" "$T/out" &&
	grep -q "2 root record(s) agree" "$T/out"; then
	ok "G2: the exported TimeVault manifest matches the collector's root"
else
	not_ok "G2: the exported TimeVault manifest matches the collector's root ($(cat "$T/out"))"
fi
sed -i 's|^0000000000000000000000000000000000000000000000000000000000000000 /etc/a$|'"$(printf '%064d' 9)"' /etc/a|' "$T/state/manifest"
PATH="$T/bin:$PATH" bash "$SCRIPT" "$T/tv-edited.tar.gz" >/dev/null 2>&1
refute_with "G2: a manifest rewritten on the host fails against the collector's root" \
	"bundle's TimeVault manifest has root .* it was rewritten" \
	python3 "$VERIFY" "$T/tv-edited.tar.gz" --timevault "$T/tv-collector.log"
tvrec timevault_merkle "$(printf '%064d' 7)" >> "$T/tv-collector.log"
refute_with "G2: a root that changes mid-engagement is flagged" \
	"root changed .* manifest was rewritten" \
	python3 "$VERIFY" "$T/tv-ok.tar.gz" --timevault "$T/tv-collector.log"
: > "$T/tv-empty.log"
refute_with "G2: --timevault with no root in the collector's records fails" \
	"no TimeVault root" \
	python3 "$VERIFY" "$T/tv-ok.tar.gz" --timevault "$T/tv-empty.log"
# ---- P1-6: the policy change history travels with the bundle ----
mkdir -p "$T/state/policy"
echo '{"v":1,"action":"load","result":"partial","prev":"0"}' > "$T/state/policy/history.jsonl"
PATH="$T/bin:$PATH" bash "$SCRIPT" "$T/ph.tar.gz" >/dev/null 2>&1
check "P1-6: the bundle carries the policy change history" sh -c \
	"tar -xzOf '$T/ph.tar.gz' --wildcards '*/live/policy-history.jsonl' | grep -q '\"result\":\"partial\"'"
tap_done
