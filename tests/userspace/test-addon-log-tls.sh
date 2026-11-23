#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-addon-log-tls.sh - the temporary/ add-ons' off-box log shipping
# (logging.conf, temporary/common/ssaddon_log.c + ssaddon_tls.c): delivery
# over TLS, certificate and host name checks, check-config, and recovery when
# the collector is down or restarts. Uses a local Python TLS collector; no
# network beyond 127.0.0.1.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

if ! command -v openssl >/dev/null || ! command -v python3 >/dev/null; then
	skip "add-on TLS log shipping tests (need OpenSSL and Python)"
	tap_done
	exit 0
fi

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
chmod 0755 "$T"
COMMON="$ROOT/temporary/common"
if ! ${CC:-cc} -O2 -Wall -Wextra -Werror -I"$COMMON" \
	-DSSL_CONF="\"$T/logging.conf\"" -DSSL_DEF_DIR="\"$T/log\"" \
	-DSSL_RETRY_SECS=1 -DSST_TIMEOUT_SECS=2 \
	-o "$T/harness" "$HERE/test-addon-log-tls.c" \
	"$COMMON/ssaddon_log.c" "$COMMON/ssaddon_tls.c" "$COMMON/ssaddon_conf.c" \
	-lssl -lcrypto 2> "$T/build.err"; then
	not_ok "add-on logging harness builds (-Werror): $(head -5 "$T/build.err")"
	tap_done
	exit 1
fi
ok "add-on logging harness builds with TLS support (-Werror)"
if ! python3 "$HERE/test-addon-log-tls.py" "$T/harness" "$T" > "$T/results" 2>&1; then
	not_ok "add-on TLS log shipping tests ran ($(tail -5 "$T/results"))"
	tap_done
	exit 1
fi
while IFS= read -r line; do
	case "$line" in
		ok\ *) ok "${line#ok }" ;;
		not\ ok\ *) not_ok "${line#not ok }" ;;
		*) ;;
	esac
done < "$T/results"
tap_done
