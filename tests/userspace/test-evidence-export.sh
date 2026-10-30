#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
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
printf '{"schema_version":1,"message":"fixture event"}\n' > "$T/logs/2026-10-26.log"
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
tap_done
