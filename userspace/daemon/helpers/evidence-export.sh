#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail

LOGDIR="/var/log/secure_sudo"
STATEDIR="/var/lib/secure_sudo"
CONFIGDIR="/etc/secure_sudo"
SYSFS="/sys/kernel/secure_sudo"
SECFS="/sys/kernel/security/secure_sudo"
BOOT_ID_FILE="/proc/sys/kernel/random/boot_id"
ACTIVE_LSM_FILE="/sys/kernel/security/lsm"
SIGNING_KEY=""

usage() {
	echo "usage: secure-sudo evidence-export OUTPUT.tar.gz [--signing-key EXTERNAL.pem]" >&2
	exit 2
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
	echo "secure-sudo evidence-export: must run as root" >&2
	exit 1
}
[[ $# -ge 1 ]] || usage
OUTPUT=$1
shift
while (($#)); do
	case $1 in
	--signing-key)
		(($# >= 2)) || usage
		SIGNING_KEY=$2
		shift 2
		;;
	*) usage ;;
	esac
done

PARENT=$(dirname -- "$OUTPUT")
NAME=$(basename -- "$OUTPUT")
[[ -d $PARENT && ! -e $OUTPUT ]] || {
	echo "secure-sudo evidence-export: output parent must exist and output must not exist" >&2
	exit 1
}
[[ $(stat -c %u -- "$PARENT") == 0 ]] || {
	echo "secure-sudo evidence-export: output directory must be root-owned" >&2
	exit 1
}
MODE=$(stat -c %a -- "$PARENT")
(( (8#$MODE & 0022) == 0 )) || {
	echo "secure-sudo evidence-export: output directory must not be group/world-writable" >&2
	exit 1
}
if [[ -n $SIGNING_KEY ]]; then
	[[ -r $SIGNING_KEY ]] || {
		echo "secure-sudo evidence-export: signing key is not readable" >&2
		exit 1
	}
	[[ $(stat -c %u -- "$SIGNING_KEY") == 0 ]] || {
		echo "secure-sudo evidence-export: signing key must be root-owned" >&2
		exit 1
	}
	KEY_MODE=$(stat -c %a -- "$SIGNING_KEY")
	(( (8#$KEY_MODE & 0077) == 0 )) || {
		echo "secure-sudo evidence-export: signing key must not be group/world-readable" >&2
		exit 1
	}
	command -v openssl >/dev/null || {
		echo "secure-sudo evidence-export: openssl is required for signing" >&2
		exit 1
	}
fi

umask 077
WORK=$(mktemp -d "$PARENT/.secure-sudo-evidence.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
BUNDLE="$WORK/bundle"
mkdir -m 0700 "$BUNDLE"
mkdir -p "$BUNDLE/logs" "$BUNDLE/config" "$BUNDLE/quarantine"

if [[ -d $LOGDIR ]]; then
	find "$LOGDIR" -maxdepth 1 -type f -name '*.log' -exec cp -- '{}' "$BUNDLE/logs/" \;
fi
if [[ -d $CONFIGDIR ]]; then
	find "$CONFIGDIR" -type f -name '*.conf' \
		! -iname '*secret*' ! -iname '*token*' ! -iname '*key*' \
		! -iname '*password*' -exec cp --parents -- '{}' "$BUNDLE/config/" \;
fi

{
	printf 'captured_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf 'kernel='
	uname -a
	printf 'boot_id='
	cat "$BOOT_ID_FILE" 2>/dev/null || echo unavailable
	printf 'active_lsms='
	cat "$ACTIVE_LSM_FILE" 2>/dev/null || echo unavailable
} > "$BUNDLE/system.txt"

mkdir -p "$BUNDLE/live"
if [[ -f $STATEDIR/daemon.health && ! -L $STATEDIR/daemon.health ]]; then
	cp -- "$STATEDIR/daemon.health" "$BUNDLE/live/daemon.health"
fi
for f in "$SYSFS"/* "$SECFS"/events_dropped; do
	[[ -r $f && -f $f ]] || continue
	name=${f##*/}
	case $name in *secret*|*token*|*key*|*password*) continue ;; esac
	cat -- "$f" > "$BUNDLE/live/$name"
done

if command -v systemctl >/dev/null; then
	systemctl show -p ActiveState -p SubState -p MainPID secure-sudod.service \
		> "$BUNDLE/service-status.txt" 2>&1 || true
else
	echo "systemctl unavailable" > "$BUNDLE/service-status.txt"
fi

if [[ -d $STATEDIR/quarantine ]]; then
	find "$STATEDIR/quarantine" -type f -printf '%P\t%s\t%m\t%T@\n' |
		LC_ALL=C sort > "$BUNDLE/quarantine/metadata.tsv"
	find "$STATEDIR/quarantine" -type f -exec sha256sum -- '{}' \; \
		> "$BUNDLE/quarantine/sha256sums.txt"
fi

: > "$BUNDLE/event-chain.txt"
chain_count=0
for logfile in "$BUNDLE"/logs/*.log; do
	[[ -f $logfile ]] || continue
	chain_count=$((chain_count + 1))
	chain=$(printf 'secure_sudo-event-chain-v1\t%s\n' "$(basename -- "$logfile")" |
		sha256sum | cut -d ' ' -f 1)
	while IFS= read -r line || [[ -n $line ]]; do
		chain=$(printf '%s\t%s\n' "$chain" "$line" | sha256sum | cut -d ' ' -f 1)
		printf '%s\t%s\n' "$(basename -- "$logfile")" "$chain" \
			>> "$BUNDLE/event-chain.txt"
	done < "$logfile"
	printf '%s\tFINAL\t%s\n' "$(basename -- "$logfile")" "$chain" \
		>> "$BUNDLE/event-chain.txt"
done
if [[ $chain_count -eq 0 ]]; then
	chain=$(printf 'secure_sudo-event-chain-v1\tno-logs\n' |
		sha256sum | cut -d ' ' -f 1)
	printf 'no-logs\tFINAL\t%s\n' "$chain" >> "$BUNDLE/event-chain.txt"
fi

if [[ -n $SIGNING_KEY ]]; then
	tail -n 1 "$BUNDLE/event-chain.txt" | cut -f 3 > "$WORK/event-chain.final"
	openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY" \
		-in "$WORK/event-chain.final" -out "$BUNDLE/event-chain.sig"
	openssl pkey -in "$SIGNING_KEY" -pubout -out "$BUNDLE/event-chain.pub"
fi

(
	cd "$BUNDLE"
	find . -type f ! -name SHA256SUMS -print0 |
		LC_ALL=C sort -z | xargs -0 -r sha256sum > SHA256SUMS
)
if [[ -n $SIGNING_KEY ]]; then
	sha256sum "$BUNDLE/SHA256SUMS" | cut -d ' ' -f 1 \
		> "$BUNDLE/bundle-manifest.sha256"
	openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY" \
		-in "$BUNDLE/bundle-manifest.sha256" \
		-out "$BUNDLE/bundle-manifest.sig"
fi
tar -czf "$WORK/$NAME" -C "$BUNDLE" .
mv --no-clobber -- "$WORK/$NAME" "$OUTPUT"
[[ ! -e $WORK/$NAME && -f $OUTPUT ]] || {
	echo "secure-sudo evidence-export: output already exists; refusing to overwrite" >&2
	exit 1
}
echo "secure-sudo evidence-export: wrote $OUTPUT"
