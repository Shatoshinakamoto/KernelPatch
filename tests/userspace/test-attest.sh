#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# test-attest.sh - remote attestation (TODO P2-1) end to end against software
# TPMs: secure-sudo-attest signs a quote, attest-report.sh builds the bundle,
# secure-sudo-attest-verify enrolls and verifies it. Covers freshness (replay),
# a tampered report or PCR value, a different TPM, a changed boot chain, the
# policy and lock checks, and re-enrollment after an update.
# Needs swtpm; SS_REQUIRE_SWTPM=1 turns "skipped" into a failure.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

A_DIR="$ROOT/userspace/attest"
VERIFY="$A_DIR/secure-sudo-attest-verify"
T="$(mktemp -d)"
cleanup() {
	local p
	for p in "$T"/tpm-*/pid; do [ -s "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
	rm -rf "$T"
}
trap cleanup EXIT

if ! command -v swtpm >/dev/null 2>&1 || [ ! -e /usr/include/tss2/tss2_esys.h ]; then
	if [ "${SS_REQUIRE_SWTPM:-0}" = 1 ]; then
		not_ok "attestation needs swtpm and tpm2-tss headers here (SS_REQUIRE_SWTPM=1)"
	else
		skip "attestation tests need swtpm and the tpm2-tss headers"
	fi
	tap_done; exit $?
fi
if (cd "$A_DIR" && ${CC:-cc} -O2 -Wall -Wextra -Werror -o "$T/secure-sudo-attest" attest.c \
	-ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-rc -lcrypto) 2> "$T/build.err"; then
	ok "secure-sudo-attest builds (-Werror)"
else
	not_ok "secure-sudo-attest builds ($(head -1 "$T/build.err"))"; tap_done; exit 1
fi

start_swtpm() { # name -> prints the TCTI spec
	local d="$T/tpm-$1" port
	mkdir -p "$d"
	for port in $(shuf -i 20000-60000 -n 20); do
		swtpm socket --tpm2 --tpmstate dir="$d" \
			--server type=tcp,port="$port",bindaddr=127.0.0.1 \
			--ctrl type=tcp,port=$((port + 1)),bindaddr=127.0.0.1 \
			--flags not-need-init,startup-clear --daemon \
			--pid file="$d/pid" 2>/dev/null || continue
		echo "swtpm:host=127.0.0.1,port=$port"
		return 0
	done
}
A="$(start_swtpm a)"; B="$(start_swtpm b)"
if [ -z "$A" ] || [ -z "$B" ]; then
	not_ok "two software TPMs started"; tap_done; exit 1
fi

# a stand-in host: /proc and /sys files, and the CLI's policy digest
H="$T/host"
mkdir -p "$H/sys/kernel/security" "$H/proc/sys/kernel/random"
echo "lockdown,capability,landlock,secure_sudo,apparmor" > "$H/sys/kernel/security/lsm"
echo "6c2d1c8e-0000-4000-8000-00000000abcd" > "$H/proc/sys/kernel/random/boot_id"
printf 'BOOT_IMAGE=/vmlinuz-6.12 root=UUID=x ro quiet "odd\\arg"\n' > "$H/proc/cmdline"
POL_A="$(printf 'a%.0s' $(seq 64))"; POL_B="$(printf 'b%.0s' $(seq 64))"
echo "policy_sha256=$POL_A locked=1" > "$T/policy"
printf '#!/bin/sh\ncat "%s"\n' "$T/policy" > "$T/cli"; chmod 0755 "$T/cli"

quote() { # tcti nonce out [extra args]
	local tcti="$1" n="$2" out="$3"; shift 3
	SS_ATTEST_TCTI="$tcti" SS_ATTEST_ROOT="$H" SS_ATTEST_BIN="$T/secure-sudo-attest" \
		SS_ATTEST_CLI="$T/cli" sh "$A_DIR/attest-report.sh" quote --nonce "$n" "$@" > "$out" 2> "$T/quote.err"
}
nonce() { python3 "$VERIFY" nonce; }
verify() { # bundle nonce -> VRC, output in $T/v.out
	python3 "$VERIFY" verify "$1" --host "$T/host.json" --nonce "$2" "${@:3}" > "$T/v.out" 2>&1; VRC=$?
}
has() { grep -qF -- "$1" "$T/v.out"; }

# ---- the TPM tool ----
ak1="$(SS_ATTEST_TCTI="$A" "$T/secure-sudo-attest" ak)"
ak2="$(SS_ATTEST_TCTI="$A" "$T/secure-sudo-attest" ak)"
akb="$(SS_ATTEST_TCTI="$B" "$T/secure-sudo-attest" ak)"
eq "the attestation key is the same key every time (nothing stored on disk)" "$ak1" "$ak2"
check "... and a different TPM has a different key" test "$ak1" != "$akb"
echo '{}' > "$T/r"
SS_ATTEST_TCTI="$A" "$T/secure-sudo-attest" quote --nonce 00ff --report "$T/r" >/dev/null 2>&1; rc=$?
eq "a nonce shorter than 16 bytes is refused" "$rc" 2
SS_ATTEST_TCTI="$A" "$T/secure-sudo-attest" quote --nonce "$(nonce)" --report "$T/r" --pcrs 0,24 >/dev/null 2>&1; rc=$?
eq "a PCR outside 0-23 is refused" "$rc" 2
check "the tool has no extend/clear/NV command (only ak and quote)" sh -c \
	"! '$T/secure-sudo-attest' extend 9 x >/dev/null 2>&1 && ! '$T/secure-sudo-attest' clear >/dev/null 2>&1"

# ---- enroll on a trusted boot ----
N="$(nonce)"; quote "$A" "$N" "$T/b0"
check "the bundle is valid JSON and its report too (escaped command line)" python3 -c "
import json,base64,sys
b=json.load(open('$T/b0')); r=json.loads(base64.b64decode(b['report_b64']))
sys.exit(0 if r['cmdline'].endswith('\"odd\\\\arg\"') and r['policy_sha256']=='$POL_A' and r['secure_sudo_lsm'] is True else 1)"
python3 "$VERIFY" enroll "$T/b0" --nonce "$N" --out "$T/host.json" --require-lock > "$T/e.out" 2>&1; rc=$?
eq "enroll from a trusted boot" "$rc" 0
check "... records the key, the boot-chain PCRs and the policy" python3 -c "
import json; h=json.load(open('$T/host.json'))
assert h['ak_name'] and sorted(h['golden_pcrs'],key=int)==['0','1','2','3','4','5','7','8','9']
assert h['allowed_policy_sha256']==['$POL_A'] and h['require_lock'] is True"

# ---- verify ----
N="$(nonce)"; quote "$A" "$N" "$T/b1"
verify "$T/b1" "$N" --max-age 120
eq "verify: the same boot, a fresh nonce: pass" "$VRC" 0
verify "$T/b1" "$N" --json
check "verify --json reports the result and every check" python3 -c "
import json; j=json.load(open('$T/v.out')); assert j['result']=='pass' and len(j['checks'])>=8"
verify "$T/b1" "$(nonce)"
eq "replay: an old bundle with a new nonce fails" "$VRC" 1
check "... on the freshness check" has "FAIL the quote is for this nonce and this exact report"

# tampered report: the policy digest edited after signing
python3 - "$T/b1" "$T/b-tamper" "$POL_A" "$POL_B" <<'PY'
import base64, json, sys
b = json.load(open(sys.argv[1]))
r = base64.b64decode(b["report_b64"]).replace(sys.argv[3].encode(), sys.argv[4].encode())
b["report_b64"] = base64.b64encode(r).decode()
json.dump(b, open(sys.argv[2], "w"))
PY
verify "$T/b-tamper" "$N"
check "a report edited after signing fails (freshness/integrity check)" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the quote is for this nonce and this exact report' '$T/v.out'"
python3 - "$T/b1" "$T/b-pcr" <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
b["tpm"]["pcrs"]["9"] = "11" * 32
json.dump(b, open(sys.argv[2], "w"))
PY
verify "$T/b-pcr" "$N"
check "a PCR value edited in the bundle fails (not what the TPM quoted)" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the reported PCR values are the ones the TPM quoted' '$T/v.out'"

N="$(nonce)"; quote "$B" "$N" "$T/b-other"
verify "$T/b-other" "$N"
check "a bundle from another TPM fails (not the enrolled key)" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the quote is signed by the enrolled attestation key' '$T/v.out'"

# ---- policy and lock ----
echo "policy_sha256=$POL_B locked=1" > "$T/policy"
N="$(nonce)"; quote "$A" "$N" "$T/b-pol"; verify "$T/b-pol" "$N"
check "a policy that is not allowed fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the active policy is an allowed one' '$T/v.out'"
echo "policy_sha256=$POL_A locked=0" > "$T/policy"
N="$(nonce)"; quote "$A" "$N" "$T/b-unl"; verify "$T/b-unl" "$N"
check "an unlocked policy fails when the host requires the lock" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the policy is locked' '$T/v.out'"
echo "policy_sha256=$POL_A locked=1" > "$T/policy"
echo "lockdown,capability,apparmor" > "$H/sys/kernel/security/lsm"
N="$(nonce)"; quote "$A" "$N" "$T/b-nolsm"; verify "$T/b-nolsm" "$N"
check "a kernel without the secure_sudo LSM fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the secure_sudo LSM is active' '$T/v.out'"
echo "lockdown,capability,secure_sudo" > "$H/sys/kernel/security/lsm"

# ---- the boot chain changes (a kernel update, or a tampered bootloader) ----
tpm_extend() { # tcti pcr
	python3 - "$2" <<'PY' > "$T/ext.bin"
import struct, sys
pcr = int(sys.argv[1])
# TPM2_PCR_Extend(pcrHandle, password session, 1 digest: sha256 of 32 x 0x42)
auth = struct.pack(">IHBH", 0x40000009, 0, 0, 0)
body = struct.pack(">I", pcr) + struct.pack(">I", len(auth)) + auth + struct.pack(">IH", 1, 0x000B) + b"\x42" * 32
cmd = struct.pack(">HII", 0x8002, 10 + len(body), 0x00000182) + body
sys.stdout.buffer.write(cmd)
PY
	local port="${1##*port=}"
	python3 - "$port" "$T/ext.bin" <<'PY'
import socket, struct, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
cmd = open(sys.argv[2], "rb").read()
# swtpm's data socket takes raw TPM commands (the "swtpm" TCTI does the same)
s.sendall(cmd)
hdr = s.recv(10)
rc = struct.unpack(">HII", hdr)[2]
sys.exit(0 if rc == 0 else 1)
PY
}
if tpm_extend "$A" 9; then
	N="$(nonce)"; quote "$A" "$N" "$T/b-boot"; verify "$T/b-boot" "$N"
	check "a changed boot chain fails, naming the PCR" sh -c \
		"[ $VRC -eq 1 ] && grep -qF 'FAIL the boot chain matches the enrolled one (PCR 9 differs)' '$T/v.out'"
	cp "$T/host.json" "$T/host.prev"
	python3 "$VERIFY" enroll "$T/b-boot" --nonce "$N" --out "$T/host.json" --previous "$T/host.prev" --require-lock > "$T/e.out" 2>&1; rc=$?
	eq "re-enroll after an update with --previous (same TPM): ok" "$rc" 0
	N="$(nonce)"; quote "$A" "$N" "$T/b-after"; verify "$T/b-after" "$N"
	eq "... and the new boot chain now verifies" "$VRC" 0
	N="$(nonce)"; quote "$B" "$N" "$T/b-swap"
	python3 "$VERIFY" enroll "$T/b-swap" --nonce "$N" --out "$T/host.swap" --previous "$T/host.json" > "$T/e.out" 2>&1; rc=$?
	check "re-enroll from a different TPM with --previous is refused" sh -c \
		"[ $rc -eq 1 ] && grep -qF 'FAIL the attestation key is the one already enrolled' '$T/e.out' && [ ! -e '$T/host.swap' ]"
else
	not_ok "extend a PCR on the software TPM"
fi

tap_done
