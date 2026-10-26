#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Builds tests/userspace/test-otp.c against the OTP helper with OTP_DIR in a
# throwaway directory and runs it (TODO P0-2). Needs no root and no network.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/state"
gcc -O2 -Wall -Wextra -Werror -DOTP_DIR="\"$T/state/otp\"" \
	-o "$T/test-otp" "$HERE/test-otp.c" -lcrypto -lcrypt || {
	echo "not ok 1 - test-otp.c builds"; echo "1..1"; exit 1; }
"$T/test-otp"
