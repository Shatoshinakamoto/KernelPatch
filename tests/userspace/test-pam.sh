#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-pam.sh - tests for pam_secure_sudo.so and pam_secure_otp.so and for the
# PAM stacks the docs tell operators to use (TODO P0-2, P0-6 "PAM ordering").
#
# Everything runs through libpam with a private config directory
# (pam_start_confdir, tests/userspace/pam-harness.c), so /etc/pam.d is never
# read or changed. The modules are built with SUDO_AUTH and OTP_HELPER pointed
# into a scratch directory: a plain file stands in for the kernel's sudo_auth
# and a script for the OTP helper.
#
# Part 1 needs no root: a pam_exec script that accepts "correct-horse" stands
# in for the password check (it prompts and shares PAM's password item the way
# pam_unix does). Part 2 is ROOT-ONLY and runs the real pam_unix (and
# pam_faillock) against a throwaway account, inside a private mount namespace
# where passwd/shadow/group and /run are replaced, so the host's accounts and
# lockout tallies are untouched. It is skipped when not root.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
C="$T/conf"; mkdir -p "$C"
ME="$(id -u)"

W="-O2 -Wall -Wextra -Werror"
# shellcheck disable=SC2086
if ! { gcc $W -o "$T/harness" "$HERE/pam-harness.c" -lpam &&
	gcc $W -fPIC -shared -DSUDO_AUTH="\"$T/sudo_auth\"" -o "$T/ss.so" \
		"$ROOT/userspace/pam/pam_secure_sudo.c" -lpam &&
	gcc $W -fPIC -shared -DOTP_HELPER="\"$T/fake-otp\"" -o "$T/otp.so" \
		"$ROOT/userspace/pam/pam_secure_otp.c" -lpam; }; then
	not_ok "harness and modules build"; tap_done; exit 1
fi
ok "harness and modules build with -Werror"

# Fake OTP helper: records argv and stdin, exits with $T/otp.rc ("kill":
# dies on a signal).
cat > "$T/fake-otp" <<EOF
#!/bin/sh
printf '%s\n' "\$*" > "$T/otp.argv"
cat > "$T/otp.stdin"
rc=\$(cat "$T/otp.rc")
[ "\$rc" = kill ] && kill -9 \$\$
exit "\$rc"
EOF
printf '#!/bin/sh\nread -r pw\n[ "$pw" = "correct-horse" ]\n' > "$T/checkpw"
chmod 0755 "$T/fake-otp" "$T/checkpw"

PW="pam_exec.so quiet expose_authtok $T/checkpw"
# A Debian-shaped common-auth around the stand-in password check.
printf 'auth [success=1 default=ignore] %s\nauth requisite pam_deny.so\nauth required pam_permit.so\n' "$PW" > "$C/stand-auth"
printf 'account required pam_permit.so\n' > "$C/acct-ok"
printf 'account required pam_deny.so\n' > "$C/acct-deny"
svc() { local n="$1"; shift; printf '%s\n' "$@" > "$C/$n"; }

svc otp          "auth required $T/otp.so"
svc otp-after    "@include stand-auth" "auth required $T/otp.so"
svc otp-before   "auth required $T/otp.so" "@include stand-auth"
svc otp-ufp      "@include stand-auth" "auth required $T/otp.so use_first_pass"
svc otp-ufp-only "auth required $T/otp.so use_first_pass"
svc ss           "auth optional $T/ss.so" "@include stand-auth" "@include acct-ok"
svc ss-acctfail  "auth optional $T/ss.so" "@include stand-auth" "@include acct-deny"
svc ss-otp       "auth optional $T/ss.so" "@include stand-auth" "auth required $T/otp.so" "@include acct-ok"
svc ss-fail      "auth optional $T/ss.so authfail" "auth required pam_permit.so"
svc ss-succ      "auth optional $T/ss.so authsucc" "auth required pam_permit.so"
svc ss-only      "auth optional $T/ss.so"
# The four lines earlier docs, install.sh and the Ansible play recommended.
svc old-doc      "auth [default=die] $PW" "auth required $T/ss.so authfail" \
		 "auth sufficient $PW" "auth required $T/ss.so authsucc"

# r <harness args...>: one PAM run with fresh records. Sets RES (the harness
# summary), REP (reports to sudo_auth, comma-joined), OTPIN (what the OTP
# helper read; "-" if it did not run) and PROMPTS (prompt texts).
r() {
	: > "$T/sudo_auth"; rm -f "$T/otp.argv" "$T/otp.stdin"
	RES="$("$H" "$@" 2> "$T/prompts")"
	REP="$(paste -sd, "$T/sudo_auth" 2>/dev/null)"
	OTPIN="$(cat "$T/otp.stdin" 2>/dev/null || echo -)"
	PROMPTS="$(sed -n 's/^prompt: //p' "$T/prompts" | paste -sd'|')"
}
has() { case "$2" in *"$3"*) ok "$1" ;; *) not_ok "$1 (got: $2)" ;; esac; }
H="$T/harness"

echo "# part 1: no root needed"

# --- pam_secure_otp: helper verdicts ---
echo 0 > "$T/otp.rc"; r "$C" otp sstest 123456
has "otp: helper exit 0 -> PAM_SUCCESS" "$RES" "result=PAM_SUCCESS"
eq  "otp: token reaches the helper on stdin" "$OTPIN" "123456"
eq  "otp: helper argv is 'verify --pam' (no token on argv)" "$(cat "$T/otp.argv")" "verify --pam"
eq  "otp: prompts 'OTP password:'" "$PROMPTS" "OTP password: "
echo 1 > "$T/otp.rc"; r "$C" otp sstest 123456
has "otp: helper exit 1 -> PAM_AUTH_ERR" "$RES" "result=PAM_AUTH_ERR"
echo 127 > "$T/otp.rc"; r "$C" otp sstest 123456
has "otp: helper exit 127 -> PAM_AUTHINFO_UNAVAIL" "$RES" "result=PAM_AUTHINFO_UNAVAIL"
echo kill > "$T/otp.rc"; r "$C" otp sstest 123456
has "otp: helper killed by a signal -> PAM_AUTHINFO_UNAVAIL" "$RES" "result=PAM_AUTHINFO_UNAVAIL"
echo 0 > "$T/otp.rc"; mv "$T/fake-otp" "$T/fake-otp.off"; r "$C" otp sstest 123456
has "otp: helper missing -> PAM_AUTHINFO_UNAVAIL" "$RES" "result=PAM_AUTHINFO_UNAVAIL"
mv "$T/fake-otp.off" "$T/fake-otp"
r "$C" otp sstest
has "otp: no answer (^D) -> PAM_AUTH_ERR" "$RES" "result=PAM_AUTH_ERR"
eq  "otp: helper not run without a token" "$OTPIN" "-"

# --- pam_secure_otp: ordering with a password module ---
r "$C" otp-after sstest correct-horse 654321
has "otp after password: both right -> PAM_SUCCESS, two prompts" "$RES" "result=PAM_SUCCESS acct=- prompts=2"
eq  "otp after password: helper gets the OTP, not the Unix password" "$OTPIN" "654321"
r "$C" otp-before sstest 654321 correct-horse
has "otp before password: both right -> PAM_SUCCESS, two prompts" "$RES" "result=PAM_SUCCESS acct=- prompts=2"
eq  "otp before password: helper gets the OTP" "$OTPIN" "654321"
r "$C" otp-after sstest wrong 654321
has "otp after password: wrong password -> PAM_AUTH_ERR" "$RES" "result=PAM_AUTH_ERR"
eq  "otp after password: wrong password stops before the OTP prompt" "$OTPIN" "-"
echo 1 > "$T/otp.rc"; r "$C" otp-after sstest correct-horse 654321
has "otp after password: right password, wrong OTP -> PAM_AUTH_ERR" "$RES" "result=PAM_AUTH_ERR"
echo 0 > "$T/otp.rc"; r "$C" otp-ufp sstest correct-horse
has "otp use_first_pass: one prompt" "$RES" "prompts=1"
eq  "otp use_first_pass: takes the earlier module's password" "$OTPIN" "correct-horse"
r "$C" otp-ufp-only sstest
has "otp use_first_pass with no earlier password -> PAM_AUTH_ERR" "$RES" "result=PAM_AUTH_ERR acct=- prompts=0"

# --- pam_secure_sudo: one line, outcome reported once per attempt ---
r --acct --setcred "$C" ss sstest correct-horse
has "ss: right password -> PAM_SUCCESS (module does not change it)" "$RES" "result=PAM_SUCCESS"
eq  "ss: right password reports ok" "$REP" "ok $ME"
r "$C" ss sstest correct-horse
eq  "ss: success without pam_setcred is reported ok at pam_end" "$REP" "ok $ME"
r --tries 3 --acct --setcred "$C" ss sstest a b c
has "ss: three wrong passwords -> PAM_AUTH_ERR" "$RES" "result=PAM_AUTH_ERR"
eq  "ss: each failed try is reported" "$REP" "fail $ME,fail $ME,fail $ME"
r --tries 3 --acct --setcred "$C" ss sstest a b correct-horse
eq  "ss: two typos then the right password" "$REP" "fail $ME,fail $ME,ok $ME"
r --acct --setcred "$C" ss sstest
eq  "ss: ^D at the prompt counts as a failure" "$REP" "fail $ME"
r --acct --setcred "$C" ss-acctfail sstest correct-horse
eq  "ss: right password but account check fails -> fail" "$REP" "fail $ME"
rm -f "$T/sudo_auth"; RES="$("$H" --acct --setcred "$C" ss sstest correct-horse 2>/dev/null)"
has "ss: kernel file absent (LSM off) -> auth unaffected" "$RES" "result=PAM_SUCCESS"
echo 0 > "$T/otp.rc"; r --acct --setcred "$C" ss-otp sstest correct-horse 111111
eq  "ss + otp: both right -> ok" "$REP" "ok $ME"
echo 1 > "$T/otp.rc"; r --acct --setcred "$C" ss-otp sstest correct-horse 111111
eq  "ss + otp: wrong OTP -> fail" "$REP" "fail $ME"
echo 0 > "$T/otp.rc"
r "$C" ss-fail sstest; eq "ss: explicit authfail reports at once" "$REP" "fail $ME"
r "$C" ss-succ sstest; eq "ss: explicit authsucc reports at once" "$REP" "ok $ME"
r "$C" ss-only sstest
case "$RES" in *result=PAM_SUCCESS*) not_ok "ss: never grants on its own ($RES)" ;; *) ok "ss: never grants on its own" ;; esac

# --- the old documented stack, and that nothing ships it any more ---
r --acct --setcred "$C" old-doc sstest correct-horse correct-horse
has "old 4-line stack denied the right password (why it was replaced)" "$RES" "result=PAM_PERM_DENIED"
r --acct --setcred "$C" old-doc sstest wrong wrong
eq  "old 4-line stack never reported a failure" "$REP" ""
# (config lines only: the docs' warning about the old stack quotes it inline)
if grep -rnE '^[[:space:]]*(line: ")?auth[[:space:]]+(\[default=die\][[:space:]]+pam_unix|required[[:space:]]+pam_secure_sudo\.so[[:space:]]+auth(fail|succ))' \
	"$ROOT/install" "$ROOT/docs" "$ROOT/README.md" --include='*.sh' --include='*.yml' --include='*.md' \
	| grep -v 'OSCAP_BUGS\|SECURITY_REVIEW\|/results/' > "$T/old-lines"; then
	not_ok "installer, Ansible and docs no longer recommend the old stack ($(head -1 "$T/old-lines"))"
else
	ok "installer, Ansible and docs no longer recommend the old stack"
fi

# ----------------------------------------------------------------- part 2
echo "# part 2: ROOT-ONLY - real pam_unix/pam_faillock in a private mount namespace"
if [ "$(id -u)" -ne 0 ] || ! command -v unshare >/dev/null || ! command -v openssl >/dev/null; then
	skip "real pam_unix stacks (needs root, unshare and openssl)"
	tap_done; exit $?
fi
cp /etc/passwd "$T/passwd"; cp /etc/group "$T/group"; cp /etc/shadow "$T/shadow"
echo 'sstest:x:4242:4242::/nonexistent:/usr/sbin/nologin' >> "$T/passwd"
echo 'sstest:x:4242:' >> "$T/group"
echo "sstest:$(openssl passwd -6 -salt sstestsalt correct-horse):20000:0:99999:7:::" >> "$T/shadow"
cat > "$T/ns-harness" <<EOF
#!/bin/sh
# Runs the harness with this test's accounts and an empty /run (faillock).
exec unshare -m sh -c 'mount --bind "$T/passwd" /etc/passwd &&
	mount --bind "$T/group" /etc/group &&
	mount --bind "$T/shadow" /etc/shadow &&
	mount -t tmpfs none /run &&
	exec "$T/harness" "\$@"' sh "\$@"
EOF
chmod 0755 "$T/ns-harness"
H="$T/ns-harness"

printf 'auth\t[success=1 default=ignore]\tpam_unix.so nullok nodelay\nauth\trequisite\tpam_deny.so\nauth\trequired\tpam_permit.so\n' > "$C/common-auth"
# The shape pam_faillock/STIG hardening gives Ubuntu's common-auth.
printf '%s\n' 'auth requisite pam_faillock.so preauth' \
	'auth [success=3 default=ignore] pam_unix.so nullok nodelay try_first_pass' \
	'auth [default=die] pam_faillock.so authfail' 'auth sufficient pam_faillock.so authsucc' \
	'auth requisite pam_deny.so' 'auth required pam_permit.so' > "$C/common-auth-stig"
svc sudo        "auth optional $T/ss.so" "@include common-auth" "@include acct-ok"
svc sudo-stig   "auth optional $T/ss.so" "@include common-auth-stig" "@include acct-ok"
svc sudo-otp    "auth optional $T/ss.so" "@include common-auth" "auth required $T/otp.so" "@include acct-ok"
svc sudo-otp1st "auth optional $T/ss.so" "auth required $T/otp.so" "@include common-auth" "@include acct-ok"
svc unix-old    "auth [default=die] pam_unix.so nodelay" "auth required $T/ss.so authfail" \
		"auth sufficient pam_unix.so nodelay" "auth required $T/ss.so authsucc"

r --acct --setcred "$C" sudo sstest correct-horse
has "pam_unix: right password -> PAM_SUCCESS" "$RES" "result=PAM_SUCCESS"
eq  "pam_unix: right password reports ok" "$REP" "ok $ME"
r --acct --setcred "$C" sudo sstest wrong
eq  "pam_unix: wrong password reports fail" "$REP" "fail $ME"
r --tries 3 --acct --setcred "$C" sudo sstest a b correct-horse
eq  "pam_unix: two typos then right, like sudo's retries" "$REP" "fail $ME,fail $ME,ok $ME"
r --acct --setcred "$C" sudo-stig sstest correct-horse
has "pam_faillock stack: right password -> PAM_SUCCESS" "$RES" "result=PAM_SUCCESS"
eq  "pam_faillock stack: reports ok" "$REP" "ok $ME"
r --acct --setcred "$C" sudo-stig sstest wrong
eq  "pam_faillock stack: wrong password reports fail" "$REP" "fail $ME"
r --acct --setcred "$C" sudo-otp sstest correct-horse 222222
has "pam_unix + otp: both right -> PAM_SUCCESS, two prompts" "$RES" "result=PAM_SUCCESS acct=PAM_SUCCESS prompts=2"
eq  "pam_unix + otp: helper gets the OTP, not the Unix password" "$OTPIN" "222222"
r --acct --setcred "$C" sudo-otp1st sstest 222222 correct-horse
has "otp first + pam_unix: both right -> PAM_SUCCESS" "$RES" "result=PAM_SUCCESS"
eq  "otp first + pam_unix: pam_unix did not get the OTP" "$REP" "ok $ME"
r --acct --setcred "$C" unix-old sstest correct-horse correct-horse
has "pam_unix, old 4-line stack: right password denied" "$RES" "result=PAM_PERM_DENIED"

tap_done
