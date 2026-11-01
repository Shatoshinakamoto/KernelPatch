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

# ---- P2-1 part 2: the policy the kernel measured into PCR 13 ----
# kernel-sim.py stands in for ss_measure.c: it extends PCR 13 on a software
# TPM for each event and writes policy_log the way the kernel does, foreign
# markers included. "root:TEXT" extends without logging (root using
# /dev/tpm*); "pending:TEXT" is logged but not yet extended.
cat > "$T/kernel-sim.py" <<'PY'
import hashlib, socket, struct, sys
port, log = int(sys.argv[1]), sys.argv[2]
def extend(dg):
    auth = struct.pack(">IHBH", 0x40000009, 0, 0, 0)
    body = struct.pack(">I", 13) + struct.pack(">I", len(auth)) + auth + struct.pack(">IH", 1, 0x000B) + dg
    cmd = struct.pack(">HII", 0x8002, 10 + len(body), 0x00000182) + body
    s = socket.create_connection(("127.0.0.1", port)); s.sendall(cmd)
    assert struct.unpack(">HII", s.recv(10))[2] == 0
def chain(v, dg): return hashlib.sha256(v + dg).digest()
H = lambda t: hashlib.sha256(t.encode()).digest()
actual = expect = bytes(32); lines = []; n = done = 0
for ev in sys.argv[3:]:
    if ev.startswith("root:"):
        extend(H(ev[5:])); actual = chain(actual, H(ev[5:])); continue
    pend = ev.startswith("pending:"); text = ev[8:] if pend else ev
    if not pend:
        if actual != expect:
            m = "foreign pcr " + actual.hex()
            extend(H(m)); actual = expect = chain(actual, H(m))
            lines.append("%dF 1 %s %s" % (n, H(m).hex(), m))
        extend(H(text)); actual = expect = chain(actual, H(text)); done += 1
    lines.append("%d %d %s %s" % (n, 0 if pend else 1, H(text).hex(), text)); n += 1
with open(log, "w") as f:
    f.write("secure_sudo-policy-log v1 pcr=13 count=%d extended=%d overflow=0 tpm=0\n" % (n, done))
    f.write("".join(l + "\n" for l in lines))
PY
mkdir -p "$H/sys/kernel/security/secure_sudo"
PLOG="$H/sys/kernel/security/secure_sudo/policy_log"
LB="$(printf 'c%.0s' $(seq 64))"; LM="$(printf 'd%.0s' $(seq 64))"
TO="$H/sys/kernel/security/secure_sudo/tpm_openers"
printf '# safe TPM users only\n/usr/bin/systemd-creds\n/usr/libexec/secure-sudo/secure-sudo-attest\n' > "$TO"
TOH="$(sha256sum < "$TO" | cut -d' ' -f1)"
EV="list tpm_openers $TOH|knob admin_gid 27|list blacklist $LB|knob lock 1|lock lock_command 1"
ksim() { # tcti log events...
	local port="${1##*port=}" log="$2"; shift 2
	python3 "$T/kernel-sim.py" "$port" "$log" "$@"
}
IFS='|' read -r -a EVS <<< "$EV"
C="$(start_swtpm c)"; ksim "$C" "$PLOG" "${EVS[@]}"
mquote() { quote "$C" "$@"; }
mverify() { python3 "$VERIFY" verify "$1" --host "$T/mhost.json" --nonce "$2" > "$T/v.out" 2>&1; VRC=$?; }
N="$(nonce)"; mquote "$N" "$T/m0"
check "the bundle carries the kernel policy log and quotes PCR 13" python3 -c "
import json,base64; b=json.load(open('$T/m0')); r=json.loads(base64.b64decode(b['report_b64']))
assert r['policy_source']=='measured' and r['policy_pcr']==13 and r['policy_log_b64'] and '13' in b['tpm']['pcrs']"
python3 "$VERIFY" enroll "$T/m0" --nonce "$N" --out "$T/mhost.json" --require-lock > "$T/e.out" 2>&1; rc=$?
eq "enroll with a measured policy" "$rc" 0
check "... records it as measured and keeps PCR 13 out of the boot chain" python3 -c "
import json; h=json.load(open('$T/mhost.json'))
assert h['policy_source']=='measured' and h['policy_pcr']==13 and '13' not in h['golden_pcrs']"
python3 "$VERIFY" policy "$T/m0" > "$T/p.out" 2>&1
check "'policy' shows the measured state and the enrolled digest" sh -c "
grep -qx 'list blacklist $LB' '$T/p.out' && grep -qx 'locked 1' '$T/p.out' &&
grep -qF \"measured_policy_sha256=\$(python3 -c \"import json;print(json.load(open('$T/mhost.json'))['allowed_policy_sha256'][0])\")\" '$T/p.out'"
check "... and ignores the root-reported digest" sh -c "! grep -q '$POL_A' '$T/p.out'"
N="$(nonce)"; mquote "$N" "$T/m1"; mverify "$T/m1" "$N"
eq "verify a measured, locked policy: pass" "$VRC" 0

# root rewrites the log (a benign blacklist hash, digest recomputed)
cp "$PLOG" "$T/plog.real"
python3 - "$PLOG" "$LB" "$LM" <<'PY'
import hashlib, sys
p, old, new = sys.argv[1:]
out = []
for ln in open(p).read().splitlines():
    f = ln.split(" ", 3)
    if len(f) == 4 and f[3] == "list blacklist " + old:
        f[3] = "list blacklist " + new; f[2] = hashlib.sha256(f[3].encode()).hexdigest()
    out.append(" ".join(f))
open(p, "w").write("\n".join(out) + "\n")
PY
N="$(nonce)"; mquote "$N" "$T/m2"; mverify "$T/m2" "$N"
check "a policy log edited by root does not replay to the PCR" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the kernel policy log replays to the quoted PCR 13' '$T/v.out'"
rm -f "$PLOG"
N="$(nonce)"; mquote "$N" "$T/m3"; mverify "$T/m3" "$N"
check "hiding the log (falling back to a reported policy) fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the kernel measures the policy into PCR 13' '$T/v.out'"
python3 "$VERIFY" enroll "$T/m3" --nonce "$N" --out "$T/mhost.down" --previous "$T/mhost.json" > "$T/e.out" 2>&1; rc=$?
check "... and cannot be re-enrolled over a measured host (no downgrade)" sh -c \
	"[ $rc -eq 1 ] && grep -qF 'FAIL the kernel still measures the policy' '$T/e.out'"
# the log with an entry still pending (the TPM was slow)
python3 - "$T/plog.real" "$PLOG" <<'PY'
import sys
l = open(sys.argv[1]).read().splitlines()
l[0] = l[0].replace("extended=5", "extended=4")
f = l[-1].split(" ", 3); f[1] = "0"; l[-1] = " ".join(f)
open(sys.argv[2], "w").write("\n".join(l) + "\n")
PY
N="$(nonce)"; mquote "$N" "$T/m4"; mverify "$T/m4" "$N"
check "a pending (not yet extended) policy event fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL every policy change is in the PCR' '$T/v.out'"
# a knob that may still tighten after the lock (TimeVault) is the kernel's
cp "$T/plog.real" "$PLOG"
ksim "$C" "$T/junk" "knob timevault_enabled 1"
python3 - "$PLOG" <<'PY'
import hashlib, sys
t = "knob timevault_enabled 1"
l = open(sys.argv[1]).read().splitlines()
l[0] = l[0].replace("count=5 extended=5", "count=6 extended=6")
l.append("5 1 %s %s" % (hashlib.sha256(t.encode()).hexdigest(), t))
open(sys.argv[1], "w").write("\n".join(l) + "\n")
PY
cp "$PLOG" "$T/plog.real"
N="$(nonce)"; mquote "$N" "$T/m4b"; mverify "$T/m4b" "$N"
check "a knob that only tightens after the lock replays, as a new policy" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'PASS the kernel policy log replays' '$T/v.out' && grep -qF 'FAIL the active policy is an allowed one' '$T/v.out'"
# root extends PCR 13 after the lock and lists its own event in the log
cp "$T/plog.real" "$PLOG"
ksim "$C" "$T/junk" "root:list blacklist $LM"
python3 - "$PLOG" "$LM" <<'PY'
import hashlib, sys
p, new = sys.argv[1:]
t = "list blacklist " + new
l = open(p).read().splitlines()
l[0] = l[0].replace("count=6 extended=6", "count=7 extended=7")
l.append("6 1 %s %s" % (hashlib.sha256(t.encode()).hexdigest(), t))
open(p, "w").write("\n".join(l) + "\n")
PY
N="$(nonce)"; mquote "$N" "$T/m5"; mverify "$T/m5" "$N"
check "a list change after the lock (not the kernel's) fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL no list changed after the lock' '$T/v.out' && grep -qF 'PASS the kernel policy log replays' '$T/v.out'"
# tpm_openers: the reported text must be the measured one, and must not let
# root extend PCR 13 (systemd-pcrextend)
cp "$TO" "$T/to.real"; echo "/usr/lib/systemd/systemd-pcrextend" >> "$TO"
N="$(nonce)"; mquote "$N" "$T/m7"; mverify "$T/m7" "$N"
check "a tpm_openers text that is not the measured one fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the reported tpm_openers is the list the kernel measured' '$T/v.out'"
TOX="$(sha256sum < "$TO" | cut -d' ' -f1)"
F="$(start_swtpm f)"
ksim "$F" "$PLOG" "list tpm_openers $TOX" "knob lock 1" "lock lock_command 1"
N="$(nonce)"; quote "$F" "$N" "$T/m8"
python3 "$VERIFY" enroll "$T/m8" --nonce "$N" --out "$T/mhost.f" --require-lock > "$T/e.out" 2>&1; erc=$?
check "systemd-pcrextend on tpm_openers is refused (root could forge PCR 13 events)" sh -c \
	"[ $erc -eq 1 ] && grep -qF 'FAIL no program on tpm_openers can extend the policy PCR (found /usr/lib/systemd/systemd-pcrextend' '$T/e.out'"
python3 "$VERIFY" enroll "$T/m8" --nonce "$N" --out "$T/mhost.f" --require-lock --accept-pcr-extenders > "$T/e.out" 2>&1; erc=$?
N="$(nonce)"; quote "$F" "$N" "$T/m9"
python3 "$VERIFY" verify "$T/m9" --host "$T/mhost.f" --nonce "$N" > "$T/v.out" 2>&1; VRC=$?
check "... unless enrolled with --accept-pcr-extenders" sh -c "[ $erc -eq 0 ] && [ $VRC -eq 0 ]"
cp "$T/to.real" "$TO"
# root extended PCR 13 before the kernel's events: the kernel's foreign marker
D="$(start_swtpm d)"
ksim "$D" "$PLOG" "root:knob admin_gid 0" "${EVS[@]}"
grep -q "F 1 .* foreign pcr " "$PLOG"; rc=$?
N="$(nonce)"; quote "$D" "$N" "$T/m6"
python3 "$VERIFY" enroll "$T/m6" --nonce "$N" --out "$T/mhost.d" > "$T/e.out" 2>&1; erc=$?
check "an extend the kernel did not make is marked foreign and refused" sh -c \
	"[ $rc -eq 0 ] && [ $erc -eq 1 ] && grep -qF 'FAIL nothing but the kernel extended PCR 13' '$T/e.out' && grep -qF 'PASS the kernel policy log replays' '$T/e.out'"
rm -f "$PLOG"

# ---- P2-1: the firmware event log ----
# A real log: OVMF + shim + GRUB + Ubuntu 24.04 on swtpm (VM_UEFI=1 VM_TPM=1
# tests/vm/distro/vm.sh), with the PCR values that guest's TPM held.
FX="$ROOT/tests/userspace/fixtures/eventlog"
cat > "$T/fw.py" <<'FWPY'
# fw.py VERIFIER replay PORT LOG | ima PORT LOG N | imaref LOG N |
#        digest LOG PATTERN | swap LOG OUT OLDHEX NEWHEX
import importlib.machinery, importlib.util, socket, struct, sys
ld = importlib.machinery.SourceFileLoader("v", sys.argv[1])
spec = importlib.util.spec_from_loader("v", ld); v = importlib.util.module_from_spec(spec); ld.exec_module(v)
op = sys.argv[2]
def extend_all(port, items):
    s = socket.create_connection(("127.0.0.1", port))
    auth = struct.pack(">IHBH", 0x40000009, 0, 0, 0)
    for pcr, dg in items:
        body = struct.pack(">I", pcr) + struct.pack(">I", len(auth)) + auth + struct.pack(">IH", 1, 0x000B) + dg
        s.sendall(struct.pack(">HII", 0x8002, 10 + len(body), 0x00000182) + body)
        hdr = b""
        while len(hdr) < 10:
            hdr += s.recv(10 - len(hdr))
        size, rc = struct.unpack(">HII", hdr)[1:]
        if size > 10:
            s.recv(size - 10)
        assert rc == 0
if op == "replay":     # what the firmware did: extend each event's SHA-256
    evs, _ = v.parse_eventlog(open(sys.argv[4], "rb").read())
    extend_all(int(sys.argv[3]), [(e["pcr"], e["sha256"]) for e in evs])
elif op == "ima":      # what IMA did for its first N records
    recs = v.parse_ima(open(sys.argv[4], "rb").read())[:int(sys.argv[5])]
    extend_all(int(sys.argv[3]), [(r["pcr"], r["sha256"]) for r in recs])
elif op == "imaref":   # a sha256sum-style reference list of the first N records
    for r in v.parse_ima(open(sys.argv[3], "rb").read())[:int(sys.argv[4])]:
        if not r["violation"] and r["name"] != "boot_aggregate":
            print("%s  %s" % (r["digest"], r["name"]))
elif op == "digest":   # the SHA-256 of the first event whose description has PATTERN
    evs, _ = v.parse_eventlog(open(sys.argv[3], "rb").read())
    print(next(r[2] for r in v.event_rows(evs) if sys.argv[4] in r[3]))
elif op == "swap":
    b = open(sys.argv[3], "rb").read()
    old, new = bytes.fromhex(sys.argv[5]), bytes.fromhex(sys.argv[6])
    assert b.count(old) >= 1
    open(sys.argv[4], "wb").write(b.replace(old, new, 1))
FWPY
fw() { python3 -B "$T/fw.py" "$VERIFY" "$@"; }
python3 "$VERIFY" eventlog "$FX/ovmf-noble.bin" > "$T/el.out" 2>&1
check "the event log parser replays a real OVMF/GRUB log to that TPM's PCRs" sh -c "
while read -r i v; do grep -qx \"pcr \$(printf '%-2d' \$i) sha256 \$v\" '$T/el.out' || exit 1; done < '$FX/ovmf-noble.pcrs'"
check "... and reads the measured Secure Boot state and kernel command line" sh -c "
grep -qx 'measured secure_boot: disabled' '$T/el.out' &&
grep -qx \"measured cmdline: \$(sed 's/^BOOT_IMAGE=//' '$FX/ovmf-noble.cmdline')\" '$T/el.out'"
if command -v tpm2_eventlog >/dev/null 2>&1; then
	tpm2_eventlog "$FX/ovmf-noble.bin" 2>/dev/null | sed -n '/^  sha256:/,/^  sha384:/p' > "$T/ref.out"
	check "... the same values tpm2_eventlog (tpm2-tools) computes" sh -c "
	while read -r i v; do grep -q \"^ *\$i *: 0x\$v\$\" '$T/ref.out' || exit 1; done < '$FX/ovmf-noble.pcrs'"
fi
mkdir -p "$H/sys/kernel/security/tpm0"
ELOG="$H/sys/kernel/security/tpm0/binary_bios_measurements"
cp "$FX/ovmf-noble.bin" "$ELOG"
cp "$FX/ovmf-noble.cmdline" "$H/proc/cmdline"
E="$(start_swtpm e)"
fw replay "${E##*port=}" "$ELOG"
evq() { quote "$E" "$@"; }
everify() { python3 "$VERIFY" verify "$1" --host "$T/ehost.json" --nonce "$2" > "$T/v.out" 2>&1; VRC=$?; }
N="$(nonce)"; evq "$N" "$T/e0"
python3 "$VERIFY" enroll "$T/e0" --nonce "$N" --out "$T/ehost.json" > "$T/e.out" 2>&1; rc=$?
eq "enroll with a firmware event log that replays" "$rc" 0
check "... records its events and the measured Secure Boot state" python3 -c "
import json; h=json.load(open('$T/ehost.json'))
assert h['eventlog'] is True and len(h['golden_events'])==117
assert h['secure_boot']=='disabled' and h['secure_boot_source']=='measured'"
N="$(nonce)"; evq "$N" "$T/e1"; everify "$T/e1" "$N"
check "verify: the log replays to the quoted PCRs 0-9" sh -c \
	"[ $VRC -eq 0 ] && grep -qF 'PASS the firmware event log replays to the quoted PCRs 0,1,2,3,4,5,7,8,9' '$T/v.out' && grep -qF 'PASS the reported kernel command line is the one GRUB measured' '$T/v.out'"
GRUBD="$(fw digest "$ELOG" 'grubx64.efi')"
fw swap "$FX/ovmf-noble.bin" "$ELOG" "$GRUBD" "$(printf '5%.0s' $(seq 64))"
N="$(nonce)"; evq "$N" "$T/e2"; everify "$T/e2" "$N"
check "a log edited by root (another GRUB hash) does not replay, naming PCR 4" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the firmware event log replays to the quoted PCRs 0,1,2,3,4,5,7,8,9 (PCR 4 differs)' '$T/v.out'"
head -c 20000 "$FX/ovmf-noble.bin" > "$ELOG"
N="$(nonce)"; evq "$N" "$T/e3"; everify "$T/e3" "$N"
check "a truncated log fails as not well formed" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the firmware event log is well formed (the firmware event log is truncated' '$T/v.out'"
rm -f "$ELOG"
N="$(nonce)"; evq "$N" "$T/e4"; everify "$T/e4" "$N"
check "hiding the log from a host enrolled with one fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the report carries the firmware event log' '$T/v.out'"
cp "$FX/ovmf-noble.bin" "$ELOG"
echo "BOOT_IMAGE=/vmlinuz-6.8.0-147-generic root=LABEL=cloudimg-rootfs ro init=/bin/sh" > "$H/proc/cmdline"
N="$(nonce)"; evq "$N" "$T/e5"; everify "$T/e5" "$N"
check "a reported command line that GRUB did not measure fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the reported kernel command line is the one GRUB measured' '$T/v.out'"
cp "$FX/ovmf-noble.cmdline" "$H/proc/cmdline"
mkdir -p "$H/sys/firmware/efi/efivars"
printf '\006\000\000\000\001' > "$H/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
N="$(nonce)"; evq "$N" "$T/e6"; everify "$T/e6" "$N"
check "a reported Secure Boot 'enabled' that the firmware measured as off fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the reported Secure Boot state matches the measured one (disabled)' '$T/v.out'"
rm -rf "${H:?}/sys/firmware"
# the next boot runs another GRUB: same TPM (restarted, so PCRs reset)
kill "$(cat "$T/tpm-e/pid")"; sleep 1
E="$(start_swtpm e)"
fw swap "$FX/ovmf-noble.bin" "$ELOG" "$GRUBD" "$(printf '6%.0s' $(seq 64))"
fw replay "${E##*port=}" "$ELOG"
N="$(nonce)"; evq "$N" "$T/e7"; everify "$T/e7" "$N"
check "a changed boot chain names the event: PCR 4, grubx64.efi changed" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'PCR 4 differs) - PCR 4: EV_EFI_BOOT_SERVICES_APPLICATION EFI\\ubuntu\\grubx64.efi changed' '$T/v.out' &&
	grep -qF 'PASS the firmware event log replays' '$T/v.out' && grep -qF 'PASS the quote is signed by the enrolled attestation key' '$T/v.out'"
fw swap "$FX/ovmf-noble.bin" "$T/bad.bin" "$GRUBD" "$(printf '7%.0s' $(seq 64))"
cp "$T/bad.bin" "$ELOG"
N="$(nonce)"; evq "$N" "$T/e8"
python3 "$VERIFY" enroll "$T/e8" --nonce "$N" --out "$T/ehost.bad" > "$T/e.out" 2>&1; erc=$?
python3 "$VERIFY" enroll "$T/e8" --nonce "$N" --out "$T/ehost.bad" --ignore-eventlog > "$T/e.out" 2>&1; irc=$?
check "a log that does not replay is refused at enroll, unless --ignore-eventlog" sh -c "
[ $erc -eq 1 ] && [ $irc -eq 0 ] && python3 -c \"import json; assert json.load(open('$T/ehost.bad'))['eventlog'] is False\""
rm -f "$ELOG"

# ---- P2-1: the IMA measurement log ----
# The same guest booted with ima_policy=tcb: its firmware log and IMA log.
# The software TPM gets IMA's first 2000 records, the host's log has all
# 2099 (IMA kept measuring after the quote).
gunzip -c "$FX/ima-noble.bin.gz" > "$T/ima.bin"
mkdir -p "$H/sys/kernel/security/ima"
IMAL="$H/sys/kernel/security/ima/binary_runtime_measurements"
cp "$T/ima.bin" "$IMAL"
cp "$FX/ovmf-noble-ima.bin" "$ELOG"; cp "$FX/ovmf-noble-ima.cmdline" "$H/proc/cmdline"
G="$(start_swtpm g)"
fw replay "${G##*port=}" "$ELOG"
fw ima "${G##*port=}" "$T/ima.bin" 2000
iverify() { python3 "$VERIFY" verify "$1" --host "$T/ihost.json" --nonce "$2" "${@:3}" > "$T/v.out" 2>&1; VRC=$?; }
check "the IMA parser replays the real log to that guest's PCR 10" sh -c "
python3 -B '$T/fw.py' '$VERIFY' imaref '$T/ima.bin' 1 >/dev/null &&
python3 -B -c \"
import importlib.machinery as m, importlib.util as u, hashlib
ld=m.SourceFileLoader('v','$VERIFY'); s=u.spec_from_loader('v',ld); v=u.module_from_spec(s); ld.exec_module(v)
r=v.parse_ima(open('$T/ima.bin','rb').read())
want=[l.split()[1] for l in open('$FX/ovmf-noble-ima.pcrs') if l.split()[0]=='10'][0]
assert v.ima_prefix(r, want)==len(r)==2099\""
N="$(nonce)"; quote "$G" "$N" "$T/i0"
python3 "$VERIFY" enroll "$T/i0" --nonce "$N" --out "$T/ihost.json" > "$T/e.out" 2>&1; rc=$?
check "enroll with an IMA log: PCR 10 is quoted but not part of the boot chain" sh -c "[ $rc -eq 0 ] && python3 -c \"
import json; h=json.load(open('$T/ihost.json'))
assert h['ima'] is True and '10' not in h['golden_pcrs'] and '6' in h['golden_pcrs']\""
N="$(nonce)"; quote "$G" "$N" "$T/i1"; iverify "$T/i1" "$N"
check "verify: the IMA log meets the quoted PCR 10 at record 2000 of 2099" sh -c \
	"[ $VRC -eq 0 ] && grep -qF 'PASS the IMA log replays to the quoted PCR 10 (2000 of 2099 records; the rest came after the quote)' '$T/v.out'"
check "... IMA's boot_aggregate is this boot's PCRs 0-9, and the count is shown" sh -c \
	"grep -qF \"PASS IMA's boot_aggregate is this boot's PCRs 0-9\" '$T/v.out' && grep -qF 'INFO IMA measured 2000 files' '$T/v.out'"
fw imaref "$T/ima.bin" 2000 > "$T/imaref"
iverify "$T/i1" "$N" --ima-reference "$T/imaref" --ima-unknown fail
check "every measured file matches a reference list from a known-good host" sh -c \
	"[ $VRC -eq 0 ] && grep -qF 'PASS every measured file is on the reference list' '$T/v.out'"
SH="$(grep -m1 ' /usr/bin/sh$' "$T/imaref" | cut -d' ' -f1)"
sed "s#^$SH  /usr/bin/sh\$#$(printf '0%.0s' $(seq 64))  /usr/bin/sh#" "$T/imaref" > "$T/imaref.sh"
iverify "$T/i1" "$N" --ima-reference "$T/imaref.sh"
check "a program whose hash is not the reference one fails, by name" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL every measured file on the reference list has its reference hash (differs: /usr/bin/sh' '$T/v.out'"
grep -v ' /usr/sbin/sshd$' "$T/imaref" > "$T/imaref.nosshd"
iverify "$T/i1" "$N" --ima-reference "$T/imaref.nosshd"
check "a file not on the list is shown (INFO), and fails with --ima-unknown fail" sh -c "
[ $VRC -eq 0 ] && grep -qF 'INFO every measured file is on the reference list (1 not: /usr/sbin/sshd)' '$T/v.out' &&
python3 '$VERIFY' verify '$T/i1' --host '$T/ihost.json' --nonce '$N' --ima-reference '$T/imaref.nosshd' --ima-unknown fail > '$T/v2.out' 2>&1
[ \$? -eq 1 ] && grep -qF 'FAIL every measured file is on the reference list' '$T/v2.out'"
fw swap "$T/ima.bin" "$IMAL" "$SH" "$(printf '0%.0s' $(seq 64))"
N="$(nonce)"; quote "$G" "$N" "$T/i2"; iverify "$T/i2" "$N"
check "an IMA log edited by root (another hash for /usr/bin/sh) does not replay" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the IMA log replays to the quoted PCR 10' '$T/v.out'"
rm -f "$IMAL"
N="$(nonce)"; quote "$G" "$N" "$T/i3"; iverify "$T/i3" "$N"
check "hiding the IMA log from a host enrolled with one fails" sh -c \
	"[ $VRC -eq 1 ] && grep -qF 'FAIL the bundle carries the IMA measurement log' '$T/v.out'"
cp "$T/ima.bin" "$IMAL"
N="$(nonce)"; quote "$G" "$N" "$T/i4"
python3 "$VERIFY" ima "$T/i4" --list > "$T/ima.out" 2>&1; rc=$?
check "'ima --list' shows the records up to the quote" sh -c \
	"[ $rc -eq 0 ] && grep -qF -- '- sha256:$SH /usr/bin/sh' '$T/ima.out' && [ \$(grep -c ' sha256:' '$T/ima.out') -le 2001 ]"
rm -f "$IMAL" "$ELOG"

# ---- P2-1: the endorsement key and credential activation ----
# swtpm_setup makes a TPM the way a manufacturer does: an EK, and an EK
# certificate in NV signed by a CA (here a throwaway one, via swtpm_localca).
if command -v swtpm_setup >/dev/null 2>&1 && command -v swtpm_localca >/dev/null 2>&1; then
	mkdir -p "$T/ca" "$T/tpm-k"
	printf 'statedir = %s\nsigningkey = %s/signkey.pem\nissuercert = %s/issuercert.pem\ncertserial = %s/certserial\n' \
		"$T/ca" "$T/ca" "$T/ca" "$T/ca" > "$T/localca.conf"
	printf -- '--platform-manufacturer test\n--platform-version 1\n--platform-model test\n' > "$T/localca.options"
	printf 'create_certs_tool = %s\ncreate_certs_tool_config = %s\ncreate_certs_tool_options = %s\nactive_pcr_banks = sha256\n' \
		"$(command -v swtpm_localca)" "$T/localca.conf" "$T/localca.options" > "$T/setup.conf"
	if swtpm_setup --tpm2 --tpmstate "$T/tpm-k" --config "$T/setup.conf" --create-ek-cert \
		--overwrite > "$T/setup.out" 2>&1; then
		ok "a software TPM with a manufacturer-style EK certificate is made"
	else
		not_ok "a software TPM with a manufacturer-style EK certificate is made ($(tail -1 "$T/setup.out"))"
	fi
	ROOTCA="$T/ca/swtpm-localca-rootca-cert.pem"; INTCA="$T/ca/issuercert.pem"
	K="$(start_swtpm k)"
	echo "policy_sha256=$POL_A locked=1" > "$T/policy"
	kq() { quote "$K" "$@"; }
	kenroll() { python3 "$VERIFY" enroll "$1" --nonce "$2" --out "$T/khost.json" "${@:3}" > "$T/e.out" 2>&1; }
	act() { # tcti challenge -> response on stdout
		SS_ATTEST_TCTI="$1" SS_ATTEST_BIN="$T/secure-sudo-attest" sh "$A_DIR/attest-report.sh" activate "$2"
	}
	SS_ATTEST_TCTI="$K" "$T/secure-sudo-attest" ek > "$T/ek.json"
	check "'attest ek' prints the EK and its NV certificate" python3 -c "
import json; j=json.load(open('$T/ek.json')); assert j['ek_alg']=='rsa2048' and j['ek_public'] and j['ek_cert']"
	N="$(nonce)"; kq "$N" "$T/k0" --ek
	kenroll "$T/k0" "$N" --ek-ca "$ROOTCA" --ek-intermediate "$INTCA"; rc=$?
	check "enroll with --ek-ca: the certificate chains and a challenge is written" sh -c "
	[ $rc -eq 0 ] && grep -qF 'PASS the EK certificate chains to a trusted TPM manufacturer CA' '$T/e.out' &&
	grep -qF 'PASS the EK certificate certifies this endorsement key' '$T/e.out' && [ -s '$T/khost.json.challenge' ] &&
	python3 -c \"import json; h=json.load(open('$T/khost.json')); assert h['ek_activation']=='pending' and 'ek_secret_sha256' in h\""
	N="$(nonce)"; kq "$N" "$T/k1"
	python3 "$VERIFY" verify "$T/k1" --host "$T/khost.json" --nonce "$N" > "$T/v.out" 2>&1; VRC=$?
	check "verify fails until the credential is activated" sh -c \
		"[ $VRC -eq 1 ] && grep -qF 'FAIL the attestation key is bound to the enrolled TPM' '$T/v.out'"
	act "$B" "$T/khost.json.challenge" > "$T/resp.b" 2>/dev/null; brc=$?
	check "another TPM cannot answer the challenge" test "$brc" -ne 0
	echo '{"activated_secret":"'"$(printf 'ab%.0s' $(seq 32))"'"}' > "$T/resp.fake"
	python3 "$VERIFY" activate "$T/khost.json" --response "$T/resp.fake" > "$T/a.out" 2>&1; frc=$?
	check "a made-up answer is refused" sh -c "[ $frc -eq 1 ] && grep -qF 'FAIL the host' '$T/a.out'"
	act "$K" "$T/khost.json.challenge" > "$T/resp.k"; krc=$?
	python3 "$VERIFY" activate "$T/khost.json" --response "$T/resp.k" > "$T/a.out" 2>&1; arc=$?
	check "the host's TPM answers it and the verifier accepts the answer" sh -c "
	[ $krc -eq 0 ] && [ $arc -eq 0 ] &&
	python3 -c \"import json; h=json.load(open('$T/khost.json')); assert h['ek_activation']=='done' and 'ek_secret_sha256' not in h\""
	python3 "$VERIFY" activate "$T/khost.json" --response "$T/resp.k" > "$T/a.out" 2>&1; rrc=$?
	check "... once only (the same answer cannot be used again)" test "$rrc" -eq 1
	python3 "$VERIFY" verify "$T/k1" --host "$T/khost.json" --nonce "$N" > "$T/v.out" 2>&1; VRC=$?
	check "verify: the attestation key is bound to the certified TPM" sh -c \
		"[ $VRC -eq 0 ] && grep -qF 'PASS the attestation key is bound to the enrolled TPM' '$T/v.out'"
	cp "$T/khost.json" "$T/khost.prev"
	N="$(nonce)"; kq "$N" "$T/k2"
	python3 "$VERIFY" enroll "$T/k2" --nonce "$N" --out "$T/khost.json" --previous "$T/khost.prev" > "$T/e.out" 2>&1; rc=$?
	check "re-enrollment with --previous (same AK) keeps the activation" sh -c "[ $rc -eq 0 ] &&
	python3 -c \"import json; h=json.load(open('$T/khost.json')); assert h['ek_activation']=='done'\""
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/other.key" -out "$T/other.pem" \
		-subj /CN=other-ca -days 2 >/dev/null 2>&1
	N="$(nonce)"; kq "$N" "$T/k3" --ek
	kenroll "$T/k3" "$N" --ek-ca "$T/other.pem"; rc=$?
	check "an EK certificate from a CA that is not trusted fails" sh -c \
		"[ $rc -eq 1 ] && grep -qF 'FAIL the EK certificate chains to a trusted TPM manufacturer CA' '$T/e.out'"
	SS_ATTEST_TCTI="$B" "$T/secure-sudo-attest" ek > "$T/ekb.json"
	python3 - "$T/k3" "$T/ekb.json" "$T/k-splice" <<'SPLICE'
import json, sys
b = json.load(open(sys.argv[1])); other = json.load(open(sys.argv[2]))
b["ek"]["ek_public"] = other["ek_public"]       # another TPM's EK, this TPM's certificate
json.dump(b, open(sys.argv[3], "w"))
SPLICE
	kenroll "$T/k-splice" "$N" --ek-ca "$ROOTCA" --ek-intermediate "$INTCA"; rc=$?
	check "another TPM's EK with this TPM's certificate fails" sh -c \
		"[ $rc -eq 1 ] && grep -qF 'FAIL the EK certificate certifies this endorsement key' '$T/e.out'"
	kenroll "$T/k-splice" "$N" --ek-no-cert --challenge "$T/splice.ch"; rc=$?
	act "$K" "$T/splice.ch" > /dev/null 2>&1; s1=$?
	act "$B" "$T/splice.ch" > /dev/null 2>&1; s2=$?
	check "... and with --ek-no-cert neither TPM can complete it (AK and EK not in one TPM)" \
		sh -c "[ $rc -eq 0 ] && [ $s1 -ne 0 ] && [ $s2 -ne 0 ]"
	N="$(nonce)"; quote "$B" "$N" "$T/k4" --ek
	python3 "$VERIFY" enroll "$T/k4" --nonce "$N" --out "$T/khost.b" --ek-ca "$ROOTCA" > "$T/e.out" 2>&1; rc=$?
	check "--ek-ca on a TPM without an EK certificate fails" sh -c \
		"[ $rc -eq 1 ] && grep -qF 'FAIL the TPM has a manufacturer EK certificate' '$T/e.out'"
elif [ "${SS_REQUIRE_SWTPM:-0}" = 1 ]; then
	not_ok "EK tests need swtpm_setup and swtpm_localca (swtpm-tools; SS_REQUIRE_SWTPM=1)"
else
	skip "EK tests need swtpm_setup and swtpm_localca (swtpm-tools)"
fi

tap_done
