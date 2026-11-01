#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# addon-units-guest.sh - runs INSIDE the throwaway guest (driven by
# run-addon-units-test.sh): every hardened temporary/ add-on unit under real
# systemd, doing its real job (TODO P2-2). The sandbox options in
# temporary/systemd/ are only proven by this: a unit that is too strict fails
# here, not on an operator's host. Prints "R ok NAME" / "R fail NAME" lines.
# Changes the guest freely (it is thrown away afterwards).
set -u
C=/etc/secure_sudo/addons
# shellcheck disable=SC2034  # L is used inside the eval'd checks
L=/var/log/secure_sudo/addons
pass=0; fail=0
r() { if eval "$2"; then echo "R ok $1"; pass=$((pass+1)); else echo "R fail $1"; fail=$((fail+1)); fi; }
# wait up to 60 s (TCG guests are slow) for a command to succeed
until_ok() { local _; for _ in $(seq 60); do eval "$1" && return 0; sleep 1; done; return 1; }
res() { systemctl show -p Result --value "$1"; }
runit() { systemctl start "$1"; sleep 1; }

# --- biosguard
secure-sudo-biosguard baseline >/dev/null
runit secure-sudo-biosguard.service
r "biosguard scan runs under its sandbox" '[ "$(res secure-sudo-biosguard.service)" = success ] && grep -q "fingerprint intact" $L/biosguard.log'

# --- bootguard: scan stages, the restore unit writes /boot
echo good > /boot/ss-test.txt
secure-sudo-bootguard baseline >/dev/null
echo evil > /boot/ss-test.txt
runit secure-sudo-bootguard.service
r "bootguard scan stages a restore (state dir writable)" '[ "$(res secure-sudo-bootguard.service)" = success ] && [ -e /var/lib/secure_sudo/addons/bootguard/PENDING ]'
r "... and the scan could not touch /boot itself" '[ "$(cat /boot/ss-test.txt)" = evil ]'
runit secure-sudo-bootguard-restore.service
r "bootguard-restore writes /boot under its sandbox" '[ "$(res secure-sudo-bootguard-restore.service)" = success ] && [ "$(cat /boot/ss-test.txt)" = good ] && [ ! -e /var/lib/secure_sudo/addons/bootguard/PENDING ]'
rm -f /boot/ss-test.txt; secure-sudo-bootguard refresh vmtest >/dev/null

# --- driverguard: enforce repairs a module file in /lib/modules
MD=/lib/modules/$(uname -r)/kernel/fs/nls
printf 'mode = enforce\nrotate = 1\ndriver_dir = %s\nbackup_root = /var/lib/secure_sudo/addons/driverguard/backups\n' "$MD" > $C/driverguard.conf
secure-sudo-driverguard baseline >/dev/null
M=$(find "$MD" -name '*.ko*' | head -1); cp "$M" /root/mod.orig; echo junk >> "$M"
runit secure-sudo-driverguard.service
r "driverguard enforce repairs $M under its sandbox" '[ "$(res secure-sudo-driverguard.service)" = success ] && cmp -s "$M" /root/mod.orig'

# --- locus
systemctl start secure-sudo-locus.service
until_ok 'grep -q "locus serving" $L/locus.log 2>/dev/null'
A=$(exec 3<>/dev/tcp/127.0.0.1/8787; echo "ALLOC procguard-quarantine" >&3; timeout 3 cat <&3)
r "locus serves an allocation under its sandbox ($A)" '[ "$(systemctl is-active secure-sudo-locus)" = active ] && echo "$A" | grep -q "^OK /var/lib/secure_sudo/addons/procguard/quarantine/"'
systemctl stop secure-sudo-locus

# --- gui
systemctl start secure-sudo-gui.service
gui_up() { [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8790/)" = 200 ]; }
r "the console serves its page under its unit" 'until_ok gui_up'
systemctl stop secure-sudo-gui

# --- procguard: enforce kills and removes a respawning /tmp implant
find /usr /opt -xdev -type f -perm -u+x 2>/dev/null > $C/procguard_allow.conf
for p in /proc/[0-9]*; do readlink "$p/exe" 2>/dev/null; done | grep ^/ | sed 's/ (deleted)$//' | sort -u >> $C/procguard_allow.conf
printf 'mode = enforce\ninterval = 1\nrespawn_threshold = 3\nrespawn_window = 60\nremove_on_infection = 1\nrotate = 1\nquarantine_root = /var/lib/secure_sudo/addons/procguard/quarantine\n' > $C/procguard.conf
cp "$(readlink -f "$(command -v sleep)")" /tmp/evil
systemctl start secure-sudo-procguard.service
until_ok 'grep -q "procguard started: mode=enforce" $L/procguard.log 2>/dev/null'
for _ in 1 2 3; do [ -e /tmp/evil ] || break; /tmp/evil 100 & p=$!; for _ in $(seq 30); do kill -0 $p 2>/dev/null || break; sleep 0.2; done; wait $p 2>/dev/null; done
sleep 2
r "procguard kills a /tmp implant under its sandbox" 'grep -q "killed pid .*(/tmp/evil)" $L/procguard.log'
r "... and removes it after 3 respawns, keeping a sample" '[ ! -e /tmp/evil ] && grep -q "INFECTION removed from disk: /tmp/evil" $L/procguard.log'
r "... while sshd and systemd are untouched" '[ "$(systemctl is-active ssh)" = active ] && [ "$(systemctl is-active secure-sudo-procguard)" = active ]'
systemctl stop secure-sudo-procguard
printf 'mode = monitor\n' > $C/procguard.conf

# --- tamperwatch: quarantine mode kills the writer of a protected file
echo protected > /etc/ss-prot.conf
printf 'mode = quarantine\nrotate = 1\nquarantine_root = /var/lib/secure_sudo/addons/tamperwatch/quarantine\n/etc/ss-prot.conf\n' > $C/tamperwatch.conf
systemctl start secure-sudo-tamperwatch.service
until_ok 'grep -q "files watched" $L/tamperwatch.log 2>/dev/null'
cp "$(readlink -f /bin/bash)" /tmp/wbash
/tmp/wbash -c 'echo x >> /etc/ss-prot.conf; sleep 20' & WP=$!; sleep 3
r "tamperwatch (fanotify) attributes and stops a writer under its sandbox" 'grep -q "killed tamperer pid $WP" $L/tamperwatch.log && ! kill -0 $WP 2>/dev/null'
r "... with its executable quarantined" '[ -n "$(find /var/lib/secure_sudo/addons/tamperwatch/quarantine -type f)" ]'
systemctl stop secure-sudo-tamperwatch; wait $WP 2>/dev/null
printf 'mode = log\n' > $C/tamperwatch.conf

# --- failure reporting: a bad config fails the unit, is reported, no restart loop
printf 'mode = enforec\n' > $C/procguard.conf
systemctl reset-failed secure-sudo-procguard 2>/dev/null
systemctl start secure-sudo-procguard.service
until_ok '[ "$(systemctl is-active secure-sudo-procguard)" = failed ]'
until_ok 'grep -q "ADD-ON FAILED: secure-sudo-procguard.service" $L/failure.log 2>/dev/null'
r "a bad config fails the daemon with status 78" '[ "$(systemctl show -p ExecMainStatus --value secure-sudo-procguard)" = 78 ] && [ "$(systemctl is-active secure-sudo-procguard)" = failed ]'
r "... which is not restarted" '[ "$(systemctl show -p NRestarts --value secure-sudo-procguard)" = 0 ]'
r "... and is reported CRITICAL by secure-sudo-addon-failure@" 'grep -q "CRIT .*ADD-ON FAILED: secure-sudo-procguard.service (result=exit-code, exited=78) - its configuration is invalid" $L/failure.log'
printf 'mode = monitor\n' > $C/procguard.conf

echo "# exposure of the installed units:"
systemd-analyze security --no-pager 2>/dev/null | grep secure-sudo | sed 's/^/# /'
echo "# $pass passed, $fail failed"
