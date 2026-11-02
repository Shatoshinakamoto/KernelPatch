#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# Builds tests/userspace/test-otp.c against the OTP helper with OTP_DIR in a
# throwaway directory and runs it (TODO P0-2). Needs no root and no network.
# With swtpm and systemd-creds installed it also seals the master key to two
# software TPMs (gap G3): one to use, one standing in for another machine.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

T="$(mktemp -d)"
cleanup() {
	local p
	for p in "$T"/a/pid "$T"/b/pid; do
		[ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null
	done
	rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$T/state"
gcc -O2 -Wall -Wextra -Werror -DOTP_DIR="\"$T/state/otp\"" -DOTP_TESTING \
	-o "$T/test-otp" "$HERE/test-otp.c" -lcrypto -lcrypt || {
	echo "not ok 1 - test-otp.c builds"; echo "1..1"; exit 1; }

# Two software TPMs on free local ports.
start_swtpm() { # name -> prints the TCTI spec, or nothing
	local d="$T/$1" port
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
if command -v swtpm >/dev/null && [ -x /usr/bin/systemd-creds ]; then
	A=$(start_swtpm a); B=$(start_swtpm b)
	# Usable only if systemd-creds can really seal and unseal with it.
	if [ -n "$A" ] && [ -n "$B" ] &&
	   head -c 32 /dev/urandom > "$T/probe" &&
	   SYSTEMD_TPM2_DEVICE="$A" /usr/bin/systemd-creds encrypt --with-key=tpm2 \
		--tpm2-pcrs= --name=probe "$T/probe" "$T/probe.cred" 2>"$T/probe.err" &&
	   SYSTEMD_TPM2_DEVICE="$A" /usr/bin/systemd-creds decrypt --name=probe \
		"$T/probe.cred" - 2>>"$T/probe.err" | cmp -s - "$T/probe"; then
		export SS_TEST_SWTPM_A="$A" SS_TEST_SWTPM_B="$B"
	else
		echo "# swtpm present but systemd-creds cannot use it: $(tail -1 "$T/probe.err" 2>/dev/null)"
	fi
fi
if [ -z "${SS_TEST_SWTPM_A:-}" ] && [ "${SS_REQUIRE_SWTPM:-0}" = 1 ]; then
	echo "not ok 1 - a software TPM is required here (SS_REQUIRE_SWTPM=1) but swtpm/systemd-creds are not usable"
	echo "1..1"
	exit 1
fi
"$T/test-otp"
