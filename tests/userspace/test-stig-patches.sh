#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-stig-patches.sh - regression tests for the known-issue patches in
# scripts/stig-harden.sh (TODO P3-2, docs/OSCAP_BUGS.md OSB-03..07, OSB-20).
# Each bug is re-created in a fake tree (STIG_ROOT), post_patch is run, and
# the exact result is asserted. A second run must change nothing (idempotent)
# and a repair that fails its own check must restore the original.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
TOK='(?:[n]+|(?:n)+)'

# post_patch alone, taken from the script, with the package manager and the
# group tools stubbed so nothing outside $STIG_ROOT is touched.
mkdir -p "$T/bin"
for c in apt-get chgrp; do printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\nexit 0\n' "$c" "$T" > "$T/bin/$c"; done
# shellcheck disable=SC2016
printf '#!/bin/sh\n[ "$1 $2" = "group syslog" ] && [ -e "%s/has-syslog" ] && { echo syslog:x:110:; exit 0; }\nexit 2\n' "$T" > "$T/bin/getent"
chmod +x "$T/bin/"*
{
	echo 'info() { echo "stig-harden: $*"; }'
	echo 'pkg_install() { apt-get install -y "$@"; }'
	sed -n '/^post_patch() {/,/^}/p' "$ROOT/scripts/stig-harden.sh"
	echo 'post_patch'
} > "$T/pp.sh"
run() { PATH="$T/bin:$PATH" STIG_ROOT="$T/r" bash "$T/pp.sh" 2>&1; }
fresh() { rm -rf "$T/r" "$T/calls" "$T/has-syslog"; mkdir -p "$T/r/etc/profile.d" "$T/r/etc/security" "$T/r/etc/sssd" "$T/r/etc/audit" "$T/r/var/log/audit"; : > "$T/calls"; }

# OSB-03: the OVAL regex token written where newlines belong.
fresh
printf 'echo "Use of this system is monitored."%s%s\n' "$TOK" 'read -r x' > "$T/r/etc/profile.d/ssh_confirm.sh"
printf 'Authorized use only%sLogging is on\n' "$TOK" > "$T/r/etc/issue.net"
out="$(run)"
eq "OSB-03: the token in ssh_confirm.sh becomes newlines" "$(wc -l < "$T/r/etc/profile.d/ssh_confirm.sh")" 2
check "OSB-03: no token is left in issue.net" bash -c "! grep -qF '$TOK' '$T/r/etc/issue.net'"
eq "OSB-03: issue.net now has two lines" "$(wc -l < "$T/r/etc/issue.net")" 2
check "OSB-03: backups are kept" test -f "$T/r/etc/issue.net.pre-patch" -a -f "$T/r/etc/profile.d/ssh_confirm.sh.pre-patch"
check "OSB-03: the repaired script passes bash -n" bash -n "$T/r/etc/profile.d/ssh_confirm.sh"
check "OSB-03: reported as fixed" grep -q "OSB-03 fixed: .*ssh_confirm.sh" <<<"$out"
sum1="$(cd "$T/r" && find . -type f -exec sha256sum {} + | sort)"
out="$(run)"; sum2="$(cd "$T/r" && find . -type f -exec sha256sum {} + | sort)"
eq "second run changes nothing (idempotent)" "$sum2" "$sum1"
refute "second run reports no fix" grep -q " fixed" <<<"$out"

# OSB-03 repair that would break the script is rolled back.
fresh
printf 'if true; then%secho x\n' "$TOK" > "$T/r/etc/profile.d/ssh_confirm.sh"
cp "$T/r/etc/profile.d/ssh_confirm.sh" "$T/orig"
out="$(run)"
check "OSB-03: a repair that fails bash -n restores the original" cmp -s "$T/orig" "$T/r/etc/profile.d/ssh_confirm.sh"
check "OSB-03: the failure is reported, not counted as fixed" grep -q "failed a syntax check" <<<"$out"

# OSB-04: commented retry.
fresh; printf '# retry = 3\nminlen = 15\n' > "$T/r/etc/security/pwquality.conf"; run >/dev/null
eq "OSB-04: retry = 3 is set once" "$(grep -cE '^retry = 3$' "$T/r/etc/security/pwquality.conf")" 1
check "OSB-04: other settings are kept" grep -q '^minlen = 15$' "$T/r/etc/security/pwquality.conf"
fresh; printf 'minlen = 15\n' > "$T/r/etc/security/pwquality.conf"; run >/dev/null
eq "OSB-04: a missing retry line is added" "$(grep -cE '^retry = 3$' "$T/r/etc/security/pwquality.conf")" 1
fresh; printf 'retry = 5\n' > "$T/r/etc/security/pwquality.conf"; run >/dev/null
eq "OSB-04: an existing retry value is not overridden" "$(grep -c 'retry = 5' "$T/r/etc/security/pwquality.conf")" 1

# OSB-05: SSSD certificate mapping.
fresh; printf '[sssd]\ndomains = corp\n[domain/corp]\nid_provider = ldap\n' > "$T/r/etc/sssd/sssd.conf"; chmod 644 "$T/r/etc/sssd/sssd.conf"; run >/dev/null
eq "OSB-05: the mapping is added to the domain section" "$(grep -c '^ldap_user_certificate = userCertificate;binary$' "$T/r/etc/sssd/sssd.conf")" 1
eq "OSB-05: sssd.conf is 0600" "$(stat -c %a "$T/r/etc/sssd/sssd.conf")" 600
check "OSB-05: backup kept" test -f "$T/r/etc/sssd/sssd.conf.pre-patch"
run >/dev/null
eq "OSB-05: second run does not add it again" "$(grep -c '^ldap_user_certificate' "$T/r/etc/sssd/sssd.conf")" 1
fresh; printf '[sssd]\ndomains = corp\n' > "$T/r/etc/sssd/sssd.conf"; run >/dev/null
refute "OSB-05: no domain section means no change" grep -q ldap_user_certificate "$T/r/etc/sssd/sssd.conf"

# OSB-06: syslog group.
fresh; touch "$T/has-syslog"; run >/dev/null
check "OSB-06: chgrp syslog runs on /var/log when the group exists" grep -q "chgrp syslog $T/r/var/log" "$T/calls"
refute "OSB-06: nothing is installed when the group exists" grep -q apt-get "$T/calls"
fresh; run >/dev/null
check "OSB-06: rsyslog is installed when the group is missing" grep -q "apt-get install -y rsyslog" "$T/calls"

# OSB-20: auditd log_group root needs the audit directory at 0700.
fresh; printf 'log_group = root\nlog_file = /var/log/audit/audit.log\n' > "$T/r/etc/audit/auditd.conf"; chmod 0750 "$T/r/var/log/audit"; run >/dev/null
eq "OSB-20: the audit directory is tightened to 0700" "$(stat -c %a "$T/r/var/log/audit")" 700
fresh; printf 'log_group = adm\nlog_file = /var/log/audit/audit.log\n' > "$T/r/etc/audit/auditd.conf"; chmod 0750 "$T/r/var/log/audit"; run >/dev/null
eq "OSB-20: with another log_group it is left alone" "$(stat -c %a "$T/r/var/log/audit")" 750

# OSB-07: log-file drift.
fresh; echo a > "$T/r/var/log/a.log"; echo b > "$T/r/var/log/audit/b.log"; echo c > "$T/r/var/log/c.log"
chmod 0666 "$T/r/var/log/a.log"; chmod 0644 "$T/r/var/log/audit/b.log"; chmod 0640 "$T/r/var/log/c.log"; out="$(run)"
eq "OSB-07: a 0666 log becomes 0640 (u-x,g-wx,o-rwx)" "$(stat -c %a "$T/r/var/log/a.log")" 640
eq "OSB-07: a 0644 log in a subdirectory becomes 0640 or stricter" "$(stat -c %a "$T/r/var/log/audit/b.log" | grep -cE '^(600|640|400|440)$')" 1
eq "OSB-07: a 0640 log is untouched" "$(stat -c %a "$T/r/var/log/c.log")" 640
check "OSB-07: the number of files tightened is reported" grep -q "tightened 2 log file" <<<"$out"

# OSB-15: the AppArmor tools cannot import LibAppArmor under the default
# python3; another installed Python can. Detect and advise only: the exact
# command is printed and nothing is enforced.
fresh; mkdir -p "$T/py15" "$T/r/usr/bin"
printf '#!/bin/sh\necho "aa-enforce $*" >> "%s/calls"\n' "$T" > "$T/py15/aa-enforce"
printf '#!/bin/sh\ncase "$*" in --version) echo "Python 3.13.0";; *LibAppArmor*) exit 1;; esac\n' > "$T/py15/python3"
printf '#!/bin/sh\ncase "$*" in *LibAppArmor*) exit 0;; esac\necho "python3.12 $*" >> "%s/calls"\n' "$T" > "$T/r/usr/bin/python3.12"
printf '#!/bin/sh\nexit 1\n' > "$T/r/usr/bin/python3.12-config"
chmod +x "$T/py15/"* "$T/r/usr/bin/"*
out="$(PATH="$T/py15:$T/bin:$PATH" STIG_ROOT="$T/r" bash "$T/pp.sh" 2>&1)"
check "OSB-15: the import failure under the default python3 is reported" grep -q "OSB-15: aa-\* tools cannot import LibAppArmor under Python 3.13" <<<"$out"
check "OSB-15: the working interpreter and the exact command are printed" grep -qF "$T/r/usr/bin/python3.12 $T/py15/aa-enforce /etc/apparmor.d/*" <<<"$out"
refute "OSB-15: nothing is enforced (advise only)" grep -qE "aa-enforce|python3.12 " "$T/calls"
refute "OSB-15: the -config helper is never offered" grep -q "python3.12-config" <<<"$out"
fresh; out="$(PATH="$T/bin:$PATH" STIG_ROOT="$T/r" bash "$T/pp.sh" 2>&1)"
refute "OSB-15: silent when the AppArmor tools are absent or work" grep -q "OSB-15" <<<"$out"

# The script itself still parses and keeps the hook default-off.
check "stig-harden.sh passes bash -n" bash -n "$ROOT/scripts/stig-harden.sh"
# shellcheck disable=SC2016
check "STIG_ROOT defaults to the real system (empty)" grep -q 'local R="${STIG_ROOT:-}"' "$ROOT/scripts/stig-harden.sh"
tap_done
