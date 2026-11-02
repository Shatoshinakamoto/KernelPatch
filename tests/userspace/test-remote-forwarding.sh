#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

if ! command -v openssl >/dev/null || ! command -v python3 >/dev/null; then
	skip "remote TLS forwarding tests (need OpenSSL and Python)"
	tap_done
	exit 0
fi

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
if ! (cd "$ROOT" && ${CC:-cc} -O2 -Wall -Wextra -Werror \
	-DREMOTE_QUEUE="\"$T/remote-queue\"" \
	-o "$T/test-remote-forwarding" tests/userspace/test-remote-forwarding.c \
	-lssl -lcrypto); then
	not_ok "remote forwarding harness builds (-Werror)"
	tap_done
	exit 1
fi
ok "remote forwarding harness builds (-Werror)"
if ! python3 "$HERE/test-remote-forwarding.py" \
	"$T/test-remote-forwarding" > "$T/results" 2>&1; then
	not_ok "TLS delivery, verification, queue and outage tests ($(cat "$T/results"))"
	tap_done
	exit 1
fi
while IFS= read -r line; do
	case "$line" in
		ok\ *) ok "${line#ok * - }" ;;
		1..*) ;;
		*) not_ok "$line" ;;
	esac
done < "$T/results"
tap_done
