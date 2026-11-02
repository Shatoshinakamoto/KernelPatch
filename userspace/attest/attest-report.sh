#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
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
#   attest-report.sh quote --nonce HEX --ek
#       The same bundle, plus the TPM's endorsement key and its
#       manufacturer certificate, for an enrollment that checks them.
#   attest-report.sh ek
#       Only the endorsement key and certificate.
#   attest-report.sh activate CHALLENGE.json
#       Answer the verifier's credential-activation challenge: the TPM
#       recovers its secret only if the challenge's AK and EK are both in
#       this TPM. Prints the response JSON for the verifier.
#
# The report's own fields are as trustworthy as root on this host at the
# moment it runs; what the TPM signature proves is the PCR values (the boot
# chain) and that the report is fresh and unaltered since signing. When the
# kernel measures the policy, the report also carries its policy_log and
# tpm_openers and the policy PCR is quoted, so the verifier can replay the
# policy instead of trusting it. Which PCRs mean what is in
# docs/ATTESTATION.md.
#
# Environment (tests): SS_ATTEST_BIN (the TPM tool), SS_ATTEST_CLI
# (secure-sudo, for the policy digest), SS_ATTEST_ROOT (prefix for /proc and
# /sys reads).
set -eu

BIN="${SS_ATTEST_BIN:-/usr/libexec/secure-sudo/secure-sudo-attest}"
CLI="${SS_ATTEST_CLI:-/usr/bin/secure-sudo}"
R="${SS_ATTEST_ROOT:-}"

usage() {
	echo "usage: secure-sudo attest quote --nonce HEX [--pcrs 0,1,...] [--ek] | ak | ek | activate CHALLENGE | digest" >&2
	exit 2
}

[ $# -ge 1 ] || usage
cmd="$1"; shift
case "$cmd" in
  ak) exec "$BIN" ak ;;
  ek) exec "$BIN" ek ;;
  activate)
	if [ $# -ne 1 ] || [ ! -r "$1" ]; then usage; fi
	# the challenge is the verifier's JSON; take the two base64 fields
	field() { tr -d ' \n' < "$1" | sed -n "s/.*\"$2\":\"\([A-Za-z0-9+\/=]*\)\".*/\1/p"; }
	cred="$(field "$1" credential_b64)"; sec="$(field "$1" secret_b64)"
	if [ -z "$cred" ] || [ -z "$sec" ]; then
		echo "attest: $1 is not a challenge from secure-sudo-attest-verify" >&2; exit 2
	fi
	tmpl="$(tr -d ' \n' < "$1" | sed -n 's/.*"ek_template":"\([a-z0-9-]*\)".*/\1/p')"
	exec "$BIN" activate --ek "${tmpl:-rsa2048}" --credential "$cred" --secret "$sec" ;;
  quote) ;;
  *) usage ;;
esac

NONCE=""; PCRS=""; EK=0
while [ $# -gt 0 ]; do
	case "$1" in
	  --ek) EK=1; shift ;;
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
# P2-1 part 2: the kernel's own policy log (every knob, list and lock it
# applied, extended into one PCR). Wait up to 30 s for pending extends (a
# full policy load is a few hundred TPM commands) so the log and the quoted
# PCR agree; the verifier replays it.
plog="$R/sys/kernel/security/secure_sudo/policy_log"
psrc=reported; ppcr=""; plb=""; topen=null
if [ -r "$plog" ]; then
	i=0
	while :; do
		hdr="$(head -n1 "$plog")"
		c="$(printf '%s' "$hdr" | sed -n 's/.* count=\([0-9]*\).*/\1/p')"
		e="$(printf '%s' "$hdr" | sed -n 's/.* extended=\([0-9]*\).*/\1/p')"
		[ -n "$c" ] && [ "$c" = "$e" ] && break
		i=$((i + 1)); [ "$i" -ge 150 ] && break
		sleep 0.2
	done
	ppcr="$(printf '%s' "$hdr" | sed -n 's/.* pcr=\([0-9]*\).*/\1/p')"
	if [ -n "$ppcr" ]; then
		psrc=measured
		plb="$(base64 -w0 < "$plog")"
		# the verifier checks this against the measured hash, then that
		# nothing on it can extend the policy PCR
		topen="\"$(base64 -w0 < "$R/sys/kernel/security/secure_sudo/tpm_openers" 2>/dev/null)\""
	fi
fi
# The firmware event log (what firmware, shim, GRUB and the EFI stub
# measured into PCRs 0-9): the verifier replays it against the quote and can
# then name the event that changed, and read the measured Secure Boot state.
ev=null; elb=""
if [ -r "$R/sys/kernel/security/tpm0/binary_bios_measurements" ]; then
	cat "$R/sys/kernel/security/tpm0/binary_bios_measurements" > "$T/eventlog"
	ev="\"$(sha256sum < "$T/eventlog" | cut -d' ' -f1)\""
	elb="$(base64 -w0 < "$T/eventlog")"
fi

printf '{"report_version":1,"time":"%s","host":"%s","kernel":"%s","boot_id":"%s","cmdline":"%s","secure_sudo_lsm":%s,"policy_sha256":"%s","policy_locked":%s,"policy_source":"%s","policy_pcr":%s,"policy_log_b64":"%s","tpm_openers_b64":%s,"secure_boot":"%s","tpm_eventlog_sha256":%s,"tpm_eventlog_b64":"%s"}' \
	"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(js "$host")" "$(js "$kernel")" \
	"$(js "$boot_id")" "$(js "$cmdline")" "$lsm" "${psha:-}" "${plock:--1}" \
	"$psrc" "${ppcr:-null}" "$plb" "$topen" "$sb" "$ev" "$elb" > "$T/report"

# the policy PCR is always quoted with the boot chain; with an IMA log, so
# are PCR 10 (IMA) and PCR 6 (IMA's boot_aggregate covers PCRs 0-9)
ima="$R/sys/kernel/security/ima/binary_runtime_measurements"
addpcr() {
	case ",${PCRS:-0,1,2,3,4,5,7,8,9}," in
	  *",$1,"*) PCRS="${PCRS:-0,1,2,3,4,5,7,8,9}" ;;
	  *) PCRS="${PCRS:-0,1,2,3,4,5,7,8,9},$1" ;;
	esac
}
[ -n "$ppcr" ] && addpcr "$ppcr"
if [ -s "$ima" ]; then addpcr 6; addpcr 10; fi
if [ -n "$PCRS" ]; then
	"$BIN" quote --nonce "$NONCE" --report "$T/report" --pcrs "$PCRS" > "$T/tpm"
else
	"$BIN" quote --nonce "$NONCE" --report "$T/report" > "$T/tpm"
fi
# The IMA log is read after the quote, so it holds at least every record in
# the quoted PCR 10 (the verifier finds where the two meet). It is outside
# the signed report on purpose: PCR 10 is what makes it trustworthy.
printf '{"bundle_version":1,"report_b64":"'
base64 -w0 < "$T/report"
printf '","tpm":'
cat "$T/tpm"
if [ "$EK" = 1 ]; then
	printf ',"ek":'
	"$BIN" ek
fi
if [ -s "$ima" ]; then
	printf ',"ima_log_b64":"'
	base64 -w0 < "$ima"
	printf '"'
fi
printf '}\n'
