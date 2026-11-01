#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# attest-report.sh - the host side of remote attestation (TODO P2-1). Run by
# `secure-sudo attest ...`; prints JSON on stdout.
#
#   attest-report.sh quote --nonce HEX [--pcrs 0,1,...]
#       Build the host report (kernel, boot id, command line, secure_sudo LSM,
#       live policy digest and lock state, Secure Boot, TPM event log digest),
#       have secure-sudo-attest sign the boot PCRs together with
#       sha256(nonce || report), and print the bundle for
#       secure-sudo-attest-verify on another machine.
#   attest-report.sh ak
#       The attestation key's public part and name, for enrollment.
#
# The report's own fields are as trustworthy as root on this host at the
# moment it runs; what the TPM signature proves is the PCR values (the boot
# chain) and that the report is fresh and unaltered since signing. Which
# PCRs mean what is in docs/ATTESTATION.md.
#
# Environment (tests): SS_ATTEST_BIN (the TPM tool), SS_ATTEST_CLI
# (secure-sudo, for the policy digest), SS_ATTEST_ROOT (prefix for /proc and
# /sys reads).
set -eu

BIN="${SS_ATTEST_BIN:-/usr/libexec/secure-sudo/secure-sudo-attest}"
CLI="${SS_ATTEST_CLI:-/usr/bin/secure-sudo}"
R="${SS_ATTEST_ROOT:-}"

usage() {
	echo "usage: secure-sudo attest quote --nonce HEX [--pcrs 0,1,...] | ak | digest" >&2
	exit 2
}

[ $# -ge 1 ] || usage
cmd="$1"; shift
case "$cmd" in
  ak) exec "$BIN" ak ;;
  quote) ;;
  *) usage ;;
esac

NONCE=""; PCRS=""
while [ $# -gt 0 ]; do
	case "$1" in
	  --nonce) [ $# -ge 2 ] || usage; NONCE="$2"; shift 2 ;;
	  --pcrs) [ $# -ge 2 ] || usage; PCRS="$2"; shift 2 ;;
	  *) usage ;;
	esac
done
case "$NONCE" in
  ""|*[!0-9a-fA-F]*) echo "attest: --nonce must be hex from the verifier" >&2; exit 2 ;;
esac

# JSON string: escape backslash and quote, drop control characters
js() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
rd() { if [ -r "$R$1" ]; then head -c 4096 "$R$1"; fi; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

kernel="$(uname -r)"
host="$(uname -n)"
boot_id="$(rd /proc/sys/kernel/random/boot_id | tr -d '\n')"
cmdline="$(rd /proc/cmdline)"
case ",$(rd /sys/kernel/security/lsm)," in
  *,secure_sudo,*) lsm=true ;;
  *) lsm=false ;;
esac
pol="$("$CLI" attest digest 2>/dev/null || true)"
psha="$(printf '%s' "$pol" | sed -n 's/.*policy_sha256=\([0-9a-f]\{64\}\).*/\1/p')"
plock="$(printf '%s' "$pol" | sed -n 's/.*locked=\(-\{0,1\}[0-9]\).*/\1/p')"
# Secure Boot: last byte of the EFI variable (4 attribute bytes, then 0/1)
sb=unknown
v="$R/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
if [ -r "$v" ]; then
	case "$(od -An -tu1 -j4 -N1 "$v" | tr -d ' ')" in
	  1) sb=enabled ;; 0) sb=disabled ;;
	esac
fi
[ -d "$R/sys/firmware/efi" ] || sb=no-efi
ev=null
if [ -r "$R/sys/kernel/security/tpm0/binary_bios_measurements" ]; then
	ev="\"$(sha256sum < "$R/sys/kernel/security/tpm0/binary_bios_measurements" | cut -d' ' -f1)\""
fi

printf '{"report_version":1,"time":"%s","host":"%s","kernel":"%s","boot_id":"%s","cmdline":"%s","secure_sudo_lsm":%s,"policy_sha256":"%s","policy_locked":%s,"policy_source":"reported","secure_boot":"%s","tpm_eventlog_sha256":%s}' \
	"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(js "$host")" "$(js "$kernel")" \
	"$(js "$boot_id")" "$(js "$cmdline")" "$lsm" "${psha:-}" "${plock:--1}" \
	"$sb" "$ev" > "$T/report"

if [ -n "$PCRS" ]; then
	"$BIN" quote --nonce "$NONCE" --report "$T/report" --pcrs "$PCRS" > "$T/tpm"
else
	"$BIN" quote --nonce "$NONCE" --report "$T/report" > "$T/tpm"
fi
printf '{"bundle_version":1,"report_b64":"%s","tpm":%s}\n' \
	"$(base64 -w0 < "$T/report")" "$(cat "$T/tpm")"
