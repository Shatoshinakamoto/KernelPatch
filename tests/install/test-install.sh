#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# test-install.sh - tests for install/install.sh (TODO P0-5): preflight
# changes nothing and blocks what cannot work, the file manifest, upgrades
# that keep the administrator's settings, uninstall that removes only what
# was installed and refuses while PAM uses the modules, recovery from an
# interrupted install, and the GRUB/Secure Boot helpers.
#
# Userspace goes into a scratch root (SS_ROOT); the kernel, bootloader and
# systemd steps are refused there and are tested in the distro VM instead
# (tests/vm/distro/). ROOT-ONLY: the whole suite (file ownership and modes).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
INST="$ROOT/install/install.sh"

if [ "$(id -u)" -ne 0 ]; then skip "ROOT-ONLY: install tests need root"; tap_done; exit 0; fi
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/root"
I() { SS_ROOT="$R" bash "$INST" "$@"; }
# The library, for the helpers: SS_INSTALL_LIB=1 sources without running main.
L() { SS_ROOT="$R" SS_INSTALL_LIB=1 bash -c '. "$0"; "$@"' "$INST" "$@"; }
# withenv VAR=value... -- command...: run command with those variables set
withenv() {
	local a=()
	while [ "$1" != -- ]; do a+=("$1"); shift; done; shift
	( for v in "${a[@]}"; do export "${v?}"; done; "$@" )
}

# A minimal target root: what a distro already has before we arrive.
mkroot() {
	rm -rf "$R"
	mkdir -p "$R"/usr/bin "$R"/usr/sbin "$R"/usr/libexec "$R"/usr/share/doc \
		"$R"/lib/systemd/system "$R"/lib/x86_64-linux-gnu/security "$R"/etc/pam.d \
		"$R"/boot "$R"/var/lib "$R"/var/backups
	printf 'auth\trequired\tpam_unix.so\n' > "$R/etc/pam.d/common-auth"
	printf '#%%PAM-1.0\n@include common-auth\n' > "$R/etc/pam.d/sudo"
	echo 'a distro tool that happens to share our name' > "$R/usr/bin/secure-sudo"
}
# Content snapshot of the root: every path with its type, mode and hash.
snap() {
	(cd "$R" && find . -mindepth 1 ! -path './var/backups/*' ! -path ./var/backups -printf '%y %m %p\n' | LC_ALL=C sort |
		while read -r y m p; do
			if [ "$y" = f ]; then echo "$y $m $p $(sha256sum "$p" | cut -c1-16)"; else echo "$y $m $p"; fi
		done)
}
has() { grep -qE -- "$1" "$T/out"; }
M="$R/var/lib/secure_sudo/install/manifest"

check "--help prints the commands" sh -c "bash '$INST' --help | grep -q 'install.sh uninstall'"
check "installer passes bash -n" bash -n "$INST"

# ---------------------------------------------------------------- staging
STAGE="$T/stage"
check "stage-userspace builds the userspace" sh -c "SS_ROOT='$R' bash '$INST' stage-userspace '$STAGE' >'$T/stage.log' 2>&1"
for f in usr/bin/secure-sudo usr/sbin/secure-sudod usr/bin/secure-sudo-otp usr/bin/secure-sudo-pheonixbox \
	lib/x86_64-linux-gnu/security/pam_secure_sudo.so lib/x86_64-linux-gnu/security/pam_secure_otp.so \
	usr/libexec/secure-sudo/apply-net.sh usr/libexec/secure-sudo/quarantine.sh usr/libexec/secure-sudo/contain.sh \
	usr/libexec/secure-sudo/oscap-results.py lib/systemd/system/secure-sudod.service \
	usr/libexec/secure-sudo/secure-sudo-attest usr/libexec/secure-sudo/attest-report.sh usr/bin/secure-sudo-attest-verify \
	usr/share/secure-sudo/defaults/secure-sudo.conf .secure-sudo-stage; do
	check "stage has $f" test -f "$STAGE/$f"
done

# -------------------------------------------------------------- preflight
mkroot
before="$(snap)"
I preflight userspace > "$T/out" 2>&1; rc=$?
check "preflight userspace passes on a supported root" test "$rc" -eq 0
check "preflight names the files it would install" has 'secure-sudod.service'
check "preflight says PAM is left alone" has 'pam +nothing'
I preflight userspace --prebuilt "$STAGE" > "$T/out" 2>&1; rc=$?
check "preflight userspace --prebuilt accepts a stage directory" sh -c "[ $rc -eq 0 ] && grep -qE 'prebuilt +$STAGE' '$T/out'"
I preflight userspace --prebuilt "$T" > "$T/out" 2>&1; rc=$?
check "preflight userspace --prebuilt blocks on a directory that is not a stage" sh -c "[ $rc -ne 0 ] && grep -q 'is not a stage-userspace directory' '$T/out'"
eq "preflight changed nothing in the root" "$(snap)" "$before"
check "preflight --dry-run is the same report" sh -c "SS_ROOT='$R' bash '$INST' --dry-run 2>&1 | grep -q 'nothing is changed'"
BUILD_ROOT="$T/nobuild/x" I preflight build-kernel > "$T/out" 2>&1
refute "preflight build-kernel did not create BUILD_ROOT" test -e "$T/nobuild"

printf 'ID=gentoo\nVERSION_ID=2.15\n' > "$T/os-gentoo"
SS_OS_RELEASE="$T/os-gentoo" I preflight userspace > "$T/out" 2>&1; rc=$?
check "unsupported distro is BLOCKED" sh -c "[ $rc -ne 0 ] && grep -q 'BLOCKED: gentoo' '$T/out'"
printf 'NAME="Fedora Linux"\nVERSION="40"\nID=fedora\nVERSION_ID=40\n' > "$T/os-fedora"
eq "os-release VERSION does not clobber the installer's version" \
	"$(SS_OS_RELEASE="$T/os-fedora" L eval 'detect_distro; echo "$FAMILY $SS_VERSION"')" \
	"fedora $(cat "$ROOT/VERSION")"

# Secure Boot: a self-built kernel must not be installed unsigned.
EV="$R/sys/firmware/efi/efivars"; mkdir -p "$EV"
printf '\x06\x00\x00\x00\x01' > "$EV/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
eq "secure boot state: enabled from efivars" "$(L secure_boot_state)" enabled
I preflight install-kernel > "$T/out" 2>&1; rc=$?
check "Secure Boot on without a MOK key blocks install-kernel" sh -c "[ $rc -ne 0 ] && grep -q 'BLOCKED: .*SS_SB_KEY' '$T/out'"
printf '\x06\x00\x00\x00\x00' > "$EV/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
eq "secure boot state: disabled from efivars" "$(L secure_boot_state)" disabled
I preflight install-kernel > "$T/out" 2>&1
refute "Secure Boot off: no Secure Boot block" has 'BLOCKED: .*SS_SB_KEY'
rm -rf "$R/sys"
eq "BIOS boot reports Secure Boot disabled" "$(L secure_boot_state)" disabled

refute_with "install-kernel refuses to run against SS_ROOT" "cannot run with SS_ROOT" I install-kernel "$T"
refute_with "rollback refuses to run against SS_ROOT" "cannot run with SS_ROOT" I rollback
refute_with "verify with nothing installed says so" "nothing is installed" I verify
refute_with "uninstall with nothing installed says so" "nothing is installed" I uninstall

# ----------------------------------------------------------------- install
mkroot
pristine="$(snap)"
check "userspace --prebuilt installs into the root" sh -c "SS_ROOT='$R' bash '$INST' userspace --prebuilt '$STAGE' >'$T/inst.log' 2>&1"
check "the manifest exists and is private" sh -c "[ -s '$M' ] && [ \"\$(stat -c %a '$R/var/lib/secure_sudo/install')\" = 700 ]"
nstage="$(cd "$STAGE" && find . -type f ! -name .secure-sudo-stage | wc -l)"
eq "every staged file is in the manifest" "$(grep -c '^F' "$M")" "$nstage"
check "manifest hashes match the installed files" sh -c "
	awk -F'\t' '\$1==\"F\" {print \$3 \"  $R\" \$2}' '$M' | sha256sum -c --quiet"
check "the CLI is the new one" cmp -s "$STAGE/usr/bin/secure-sudo" "$R/usr/bin/secure-sudo"
check "the foreign file it replaced was backed up" grep -q 'happens to share our name' "$R/var/lib/secure_sudo/install/backup/usr/bin/secure-sudo"
check "... and recorded as such" grep -qP '^B\t/usr/bin/secure-sudo\t' "$M"
check "configs created and recorded as C" sh -c "[ -f '$R/etc/secure_sudo/secure-sudo.conf' ] && grep -qP '^C\t/etc/secure_sudo/secure-sudo.conf\t' '$M'"
check "directories it created are recorded" sh -c "grep -qP '^D\t/etc/secure_sudo\t' '$M' && grep -qP '^D\t/usr/libexec/secure-sudo\t' '$M'"
refute "directories that already existed are not claimed" grep -qP '^D\t/usr/bin\t' "$M"
check "modes come from the stage" sh -c "[ \"\$(stat -c %a '$R/usr/sbin/secure-sudod')\" = 755 ] && [ \"\$(stat -c %a '$R/lib/x86_64-linux-gnu/security/pam_secure_sudo.so')\" = 644 ]"
check "no temporary files left behind" sh -c "! find '$R' -name '*.ss-new' | grep -q . && ! ls '$R/var/lib/secure_sudo/install/' | grep -q tmp"
refute "PAM was not touched" grep -q secure "$R/etc/pam.d/sudo"
check "the guidance points at docs/RECOVERY.md" grep -q 'docs/RECOVERY.md' "$T/inst.log"
I verify > "$T/out" 2>&1; rc=$?
check "verify passes after install" sh -c "[ $rc -eq 0 ] && grep -q 'verify: OK' '$T/out'"
echo tampered >> "$R/usr/libexec/secure-sudo/apply-net.sh"
I verify > "$T/out" 2>&1; rc=$?
check "verify fails on a changed file and names it" sh -c "[ $rc -ne 0 ] && grep -q 'apply-net.sh changed since install' '$T/out'"
cp "$STAGE/usr/libexec/secure-sudo/apply-net.sh" "$R/usr/libexec/secure-sudo/apply-net.sh"

# ----------------------------------------------------------------- upgrade
sed -i -E 's/^[[:space:]]*admin_gid[[:space:]]*=.*/admin_gid = 4242/' "$R/etc/secure_sudo/secure-sudo.conf"
grep -q '^admin_gid' "$R/etc/secure_sudo/secure-sudo.conf" || echo 'admin_gid = 4242' >> "$R/etc/secure_sudo/secure-sudo.conf"
# An older version shipped a helper this one does not.
echo 'old helper' > "$R/usr/libexec/secure-sudo/old-helper.sh"
printf 'F\t/usr/libexec/secure-sudo/old-helper.sh\t%s\n' "$(sha256sum "$R/usr/libexec/secure-sudo/old-helper.sh" | cut -d' ' -f1)" >> "$M"
echo 'local edit' > "$R/usr/libexec/secure-sudo/edited-old.sh"
printf 'F\t/usr/libexec/secure-sudo/edited-old.sh\t%s\n' 0000 >> "$M"
nb="$(grep -c '^B' "$M")"
I userspace --prebuilt "$STAGE" > "$T/out" 2>&1; rc=$?
check "reinstall (upgrade) succeeds" test "$rc" -eq 0
eq "upgrade makes no new backups of our own files" "$(grep -c '^B' "$M")" "$nb"
check "upgrade keeps the administrator's admin_gid" grep -q '^admin_gid = 4242' "$R/etc/secure_sudo/secure-sudo.conf"
check "... and says the detected groups differ" has 'yours is kept'
refute "an unchanged file the new version no longer ships is removed" test -e "$R/usr/libexec/secure-sudo/old-helper.sh"
check "a changed obsolete file is kept" test -e "$R/usr/libexec/secure-sudo/edited-old.sh"
eq "manifest has no duplicate entries" "$(cut -f1,2 "$M" | sort | uniq -d | wc -l)" 0

# --------------------------------------------------------------- uninstall
printf 'auth\trequired\tpam_secure_otp.so\n' >> "$R/etc/pam.d/sudo"
cp "$M" "$T/m.before"; b4="$(snap)"
I uninstall > "$T/out" 2>&1; rc=$?
check "uninstall refuses while PAM uses the modules" sh -c "[ $rc -ne 0 ] && grep -q 'PAM still uses' '$T/out'"
check "... and shows the line" has 'pam_secure_otp.so'
eq "... and changed nothing" "$(snap)" "$b4"
check "... not even the manifest" cmp -s "$M" "$T/m.before"

echo 'otp secret' > "$R/etc/secure_sudo/user-added.secret"
I uninstall --remove-pam-lines > "$T/out" 2>&1; rc=$?
check "uninstall --remove-pam-lines runs" test "$rc" -eq 0
refute "the secure_sudo PAM line is gone" grep -q pam_secure "$R/etc/pam.d/sudo"
check "the other PAM lines are untouched" grep -q '@include common-auth' "$R/etc/pam.d/sudo"
check "a copy of the old PAM file is kept" sh -c "grep -q pam_secure_otp '$R'/var/backups/secure_sudo-pam-*/sudo"
refute "installed binaries are removed" test -e "$R/usr/sbin/secure-sudod"
refute "PAM modules are removed" test -e "$R/lib/x86_64-linux-gnu/security/pam_secure_otp.so"
check "the foreign file we replaced is restored" grep -q 'happens to share our name' "$R/usr/bin/secure-sudo"
check "the changed config is kept, with a warning" sh -c "grep -q 4242 '$R/etc/secure_sudo/secure-sudo.conf' && grep -q 'kept /etc/secure_sudo/secure-sudo.conf' '$T/out'"
check "a file the admin added is never removed" test -f "$R/etc/secure_sudo/user-added.secret"
check "a changed installed file is kept" test -e "$R/usr/libexec/secure-sudo/edited-old.sh"
refute "empty directories we created are removed" test -e "$R/usr/share/secure-sudo"
check "pre-existing directories stay" test -d "$R/usr/libexec"
check "with things kept, the record stays for a second pass" test -s "$M"
I uninstall --purge > "$T/out" 2>&1; rc=$?
check "uninstall --purge finishes the job" test "$rc" -eq 0
refute "--purge removed /etc/secure_sudo" test -e "$R/etc/secure_sudo"

# Clean removal: install into a pristine root and take it out again.
mkroot
pristine="$(snap)"
I userspace --prebuilt "$STAGE" > /dev/null 2>&1
# What the running daemon and CLI leave in their state directory.
mkdir -p "$R/var/lib/secure_sudo/remote-queue" "$R/var/lib/secure_sudo/otp"
for f in daemon.health load.health event-cursor event-cursor.tmp \
	node_sea_auto.list node_sea_scan.cache node_sea_scan.cache.tmp.123 \
	manifest manifest.tmp manifest.prev; do
	echo state > "$R/var/lib/secure_sudo/$f"
done
I uninstall > "$T/out" 2>&1; rc=$?
check "install then uninstall succeeds" test "$rc" -eq 0
check "... and says everything is gone" has 'uninstall complete'
eq "install + uninstall leaves the root exactly as it was" "$(snap)" "$pristine"
refute "... including the daemon's heartbeat, cursor, load, node-scan and TimeVault state" test -e "$R/var/lib/secure_sudo"

# Events still queued for the remote collector are never thrown away.
mkroot
I userspace --prebuilt "$STAGE" > /dev/null 2>&1
mkdir -p "$R/var/lib/secure_sudo/remote-queue"
echo '{"sequence":7}' > "$R/var/lib/secure_sudo/remote-queue/0000000007"
I uninstall > "$T/out" 2>&1
check "uninstall keeps undelivered remote events" test -s "$R/var/lib/secure_sudo/remote-queue/0000000007"
check "... and says so" has 'kept /var/lib/secure_sudo/remote-queue'

# A configured OTP is never thrown away by uninstall (G3: its key may be
# sealed to the TPM; `otp disable` is the way to remove it).
mkroot
I userspace --prebuilt "$STAGE" > /dev/null 2>&1
mkdir -p "$R/var/lib/secure_sudo/otp"
echo sealed > "$R/var/lib/secure_sudo/otp/masterkey.tpm2"
I uninstall > "$T/out" 2>&1
check "uninstall keeps a configured OTP" test -s "$R/var/lib/secure_sudo/otp/masterkey.tpm2"
check "... and says how to remove it" has "kept /var/lib/secure_sudo/otp: OTP is still set up"

# An install that dies half-way can still be removed.
mkroot
pristine="$(snap)"
echo 'not a dir' > "$R/usr/share/secure-sudo"	# blocks a late file
pristine2="$(snap)"
I userspace --prebuilt "$STAGE" > "$T/out" 2>&1; rc=$?
check "an install that cannot place a file stops with an error" test "$rc" -ne 0
check "... after recording what it placed" sh -c "grep -c '^F' '$M' | grep -qv '^0$'"
I uninstall > "$T/out" 2>&1
eq "uninstall after the failed install restores the root" "$(snap)" "$pristine2"

# A program whose shared library is missing must stop the install before
# anything is wired to it.
cp -a "$STAGE" "$T/stage-badlib"
printf 'int f(void){return 0;}\n' > "$T/libf.c"; printf 'int f(void); int main(void){return f();}\n' > "$T/m.c"
gcc -shared -fPIC -o "$T/libssfake.so" "$T/libf.c" && gcc -o "$T/stage-badlib/usr/bin/secure-sudo-fake" "$T/m.c" -L"$T" -lssfake
rm -f "$T/libssfake.so"
mkroot
I userspace --prebuilt "$T/stage-badlib" > "$T/out" 2>&1; rc=$?
check "an installed program with a missing library fails the install" sh -c "[ $rc -ne 0 ] && grep -q 'cannot find shared libraries: */usr/bin/secure-sudo-fake(libssfake.so)' '$T/out'"
I uninstall > /dev/null 2>&1
check "... and is removed again by uninstall" sh -c "! test -e '$R/usr/bin/secure-sudo-fake'"
I userspace --prebuilt "$STAGE" > /dev/null 2>&1
I verify > "$T/out" 2>&1
check "verify checks shared libraries" has 'ok +shared libraries resolve'
I uninstall > /dev/null 2>&1

# ------------------------------------------------------------ boot helpers
mkdir -p "$R/boot/grub"
FIX="$HERE/fixtures/grub-ubuntu2404-cloud.cfg"   # a real Ubuntu 24.04 cloud image grub.cfg
cp "$FIX" "$R/boot/grub/grub.cfg"
U=59134bd0-a76f-4ea0-8e4a-770b2e1eafc2
eq "grub_entry: kernel inside the Advanced submenu" "$(L grub_entry 6.8.0-147-generic)" \
	"gnulinux-advanced-$U>gnulinux-6.8.0-147-generic-advanced-$U"
refute "grub_entry: a prefix of a release does not match" L grub_entry 6.8.0-14
refute "grub_entry: unknown release" L grub_entry 6.14.0-secure-sudo
check "boot_entry_present: the installed kernel" L boot_entry_present 6.8.0-147-generic
refute "boot_entry_present: not a prefix" L boot_entry_present 6.8.0-147
# The same menu after a secure_sudo kernel was added (what update-grub writes).
awk -v u="$U" '{print} /^submenu / {
	print "\tmenuentry '\''Ubuntu, with Linux 6.14.0-secure-sudo'\'' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option '\''gnulinux-6.14.0-secure-sudo-advanced-" u "'\'' {"
	print "\t\tlinux\t/vmlinuz-6.14.0-secure-sudo root=LABEL=cloudimg-rootfs ro"
	print "\t}"
	print "\tmenuentry '\''Ubuntu, with Linux 6.14.0-secure-sudo (recovery mode)'\'' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option '\''gnulinux-6.14.0-secure-sudo-recovery-" u "'\'' {"
	print "\t}" }' "$FIX" > "$R/boot/grub/grub.cfg"
eq "grub_entry: new kernel, normal entry (not recovery)" "$(L grub_entry 6.14.0-secure-sudo)" \
	"gnulinux-advanced-$U>gnulinux-6.14.0-secure-sudo-advanced-$U"
eq "grub_entry: the old kernel is still found" "$(L grub_entry 6.8.0-147-generic)" \
	"gnulinux-advanced-$U>gnulinux-6.8.0-147-generic-advanced-$U"
cp "$R/boot/grub/grub.cfg" "$T/sub.cfg"
# What update-grub writes with GRUB_DISABLE_SUBMENU=true: no "Ubuntu"
# (simple) entry, no submenu, every kernel at the top level.
awk '/^menuentry .*gnulinux-simple-/ {skip = 1; next} skip && /^}/ {skip = 0; next} skip {next}
	/^submenu / {insub = 1; next} insub && /^}/ {insub = 0; next} {if (insub) sub(/^\t/, ""); print}' \
	"$T/sub.cfg" > "$T/flat.cfg"
cp "$T/flat.cfg" "$R/boot/grub/grub.cfg"
eq "grub_entry: flat menu (GRUB_DISABLE_SUBMENU), new kernel" "$(L grub_entry 6.14.0-secure-sudo)" \
	"gnulinux-6.14.0-secure-sudo-advanced-$U"
eq "grub_entry: flat menu, the old kernel" "$(L grub_entry 6.8.0-147-generic)" "gnulinux-6.8.0-147-generic-advanced-$U"
# A GRUB superuser with --unrestricted entries, as the STIG VM run sets it
# (CLASS in /etc/grub.d/10_linux): the submenu line has no CLASS.
pw() { { echo 'set superusers="root"'; sed 's/--class os \$menuentry_id_option/--class os --unrestricted $menuentry_id_option/' "$1"; } > "$R/boot/grub/grub.cfg"; }
open_rc() { L grub_entry_open "$1" > /dev/null 2>&1; echo $?; }
SUB_E="gnulinux-advanced-$U>gnulinux-6.14.0-secure-sudo-advanced-$U"
FLAT_E="gnulinux-6.14.0-secure-sudo-advanced-$U"
pw "$T/sub.cfg"
check "grub_has_password: set superusers" L grub_has_password
eq "grub_entry_open: an entry inside the (restricted) Advanced submenu needs the password" "$(open_rc "$SUB_E")" 1
eq "grub_entry_open: the unrestricted top-level entry does not" "$(open_rc "gnulinux-simple-$U")" 0
eq "grub_entry_open: an unknown entry is reported as such" "$(open_rc "gnulinux-9.9-advanced-$U")" 2
pw "$T/flat.cfg"
eq "grub_entry_open: flat menu, the new kernel boots without the password" "$(open_rc "$FLAT_E")" 0
{ echo 'set superusers="root"'; cat "$T/flat.cfg"; } > "$R/boot/grub/grub.cfg"
eq "grub_entry_open: an entry without --unrestricted needs the password" "$(open_rc "$FLAT_E")" 1
cp "$T/flat.cfg" "$R/boot/grub/grub.cfg"
refute "grub_has_password: none set" L grub_has_password
# verify reports a default the password would hold at the menu.
mkdir -p "$R/var/lib/secure_sudo/install"
printf 'T\t6.14.0-secure-sudo\tcommitted\n' > "$M"
genv() { printf '# GRUB Environment Block\nsaved_entry=%s\n' "$1" > "$R/boot/grub/grubenv"; }
genv "$SUB_E"; pw "$T/sub.cfg"
I verify > "$T/out" 2>&1; rc=$?
check "verify fails when the default boot entry needs the GRUB password" sh -c "[ $rc -ne 0 ] && grep -q 'FAIL .*saved_entry needs it to boot' '$T/out'"
genv "$FLAT_E"; pw "$T/flat.cfg"
I verify > "$T/out" 2>&1; rc=$?
check "verify passes when it boots without the password" sh -c "[ $rc -eq 0 ] && grep -q 'ok .*saved_entry boots without it' '$T/out'"
cp "$T/flat.cfg" "$R/boot/grub/grub.cfg"
I verify > "$T/out" 2>&1
refute "verify says nothing about it with no GRUB password" has 'GRUB password'
# The trial boot: the drop-in an older version wrote (GRUB_DEFAULT=saved
# only) is replaced, the menu regenerated, and the flat entries armed.
mkdir -p "$T/grubbin" "$R/etc/default/grub.d"
cat > "$T/grubbin/update-grub" <<EOF2
#!/bin/sh
if grep -q '^GRUB_DISABLE_SUBMENU=true' '$R/etc/default/grub.d/99-secure-sudo.cfg'; then cp '$T/flat.cfg' '$R/boot/grub/grub.cfg'
else cp '$T/sub.cfg' '$R/boot/grub/grub.cfg'; fi
EOF2
for t in grub-set-default grub-reboot; do printf '#!/bin/sh\necho "%s $*" >> "$STUB_LOG"\n' "$t" > "$T/grubbin/$t"; done
chmod 0755 "$T/grubbin/"*
trial() { : > "$T/grub.log"; SS_ROOT="$R" SS_INSTALL_LIB=1 PATH="$T/grubbin:$PATH" STUB_LOG="$T/grub.log" bash -c '. "$0"; FAMILY=debian; "$@"' "$INST" arrange_trial_boot 6.14.0-secure-sudo 6.8.0-147-generic; }
printf '# Written by secure_sudo install.sh: keep the known-good kernel the\n# default and boot new kernels once (grub-reboot). Removed by uninstall.\nGRUB_DEFAULT=saved\n' > "$R/etc/default/grub.d/99-secure-sudo.cfg"
cp "$T/sub.cfg" "$R/boot/grub/grub.cfg"
printf 'F\t/etc/default/grub.d/99-secure-sudo.cfg\t%s\n' "$(sha256sum "$R/etc/default/grub.d/99-secure-sudo.cfg" | cut -d' ' -f1)" > "$M"
check "an older drop-in is stale (preflight plans to rewrite it)" sh -c "SS_ROOT='$R' SS_INSTALL_LIB=1 bash -c '. \"\$0\"; FAMILY=debian; grub_dropin_stale' '$INST'"
trial > "$T/out" 2>&1; rc=$?
check "trial boot after an older install succeeds" test "$rc" -eq 0
check "... the drop-in now lists every kernel at the top level" grep -qx 'GRUB_DISABLE_SUBMENU=true' "$R/etc/default/grub.d/99-secure-sudo.cfg"
check "... and still keeps GRUB_DEFAULT=saved" grep -qx 'GRUB_DEFAULT=saved' "$R/etc/default/grub.d/99-secure-sudo.cfg"
check "... its manifest hash is the new one" grep -qP "^F\t/etc/default/grub.d/99-secure-sudo.cfg\t$(sha256sum "$R/etc/default/grub.d/99-secure-sudo.cfg" | cut -d' ' -f1)\$" "$M"
check "... the known-good kernel is the default, by its top-level entry" grep -qx "grub-set-default gnulinux-6.8.0-147-generic-advanced-$U" "$T/grub.log"
check "... and the new kernel boots once, by its top-level entry" grep -qx "grub-reboot $FLAT_E" "$T/grub.log"
refute "a current drop-in is not stale" sh -c "SS_ROOT='$R' SS_INSTALL_LIB=1 bash -c '. \"\$0\"; grub_dropin_stale' '$INST'"
echo '# the administrator was here' >> "$R/etc/default/grub.d/99-secure-sudo.cfg"
cp "$R/etc/default/grub.d/99-secure-sudo.cfg" "$T/dropin.edited"
trial > "$T/out" 2>&1
check "a drop-in the administrator changed is left as it is" cmp -s "$T/dropin.edited" "$R/etc/default/grub.d/99-secure-sudo.cfg"
check "... with a warning" has '99-secure-sudo.cfg was changed since install.sh wrote it'
rm -rf "$R/etc/default/grub.d" "$R/boot/grub/grubenv" "$M"
printf "menuentry 'Top' \$menuentry_id_option 'gnulinux-5.0.0-x-advanced-$U' {\n\tlinux /vmlinuz-5.0.0-x\n}\n" > "$R/boot/grub/grub.cfg"
eq "grub_entry: a top-level entry has no submenu prefix" "$(L grub_entry 5.0.0-x)" "gnulinux-5.0.0-x-advanced-$U"
rm -f "$R/boot/grub/grub.cfg"; mkdir -p "$R/boot/loader/entries"
: > "$R/boot/loader/entries/0123abcd-6.14.0-secure-sudo.conf"
eq "grub_entry: BLS entry id" "$(L grub_entry 6.14.0-secure-sudo)" "0123abcd-6.14.0-secure-sudo"
check "boot_entry_present: BLS" L boot_entry_present 6.14.0-secure-sudo
mkdir -p "$R/etc/default/grub.d"
echo 'GRUB_DEFAULT=0' > "$R/etc/default/grub"
eq "grub_default reads /etc/default/grub" "$(L grub_default)" 0
echo 'GRUB_DEFAULT=saved' > "$R/etc/default/grub.d/99-secure-sudo.cfg"
eq "grub_default: grub.d drop-ins win, in order" "$(L grub_default)" saved

# ------------------------------------------------- pre-verified kernel tree
mkdir -p "$T/ktree"; echo 'VERSION = 6' > "$T/ktree/Makefile"
refute_with "SS_KERNEL_TREE without a provenance record is refused" "needs SS_KERNEL_TREE_PROVENANCE" \
	withenv SS_KERNEL_TREE="$T/ktree" BUILD_ROOT="$T/b" -- L use_kernel_tree
echo 'archive_sha256=abc' > "$T/prov"
refute_with "a provenance record without verified_by= is refused" "no verified_by" \
	withenv SS_KERNEL_TREE="$T/ktree" SS_KERNEL_TREE_PROVENANCE="$T/prov" BUILD_ROOT="$T/b" -- L use_kernel_tree
echo 'verified_by=test' >> "$T/prov"
check "a recorded tree is accepted" withenv SS_KERNEL_TREE="$T/ktree" SS_KERNEL_TREE_PROVENANCE="$T/prov" BUILD_ROOT="$T/b" -- L use_kernel_tree
check "... and its record becomes the build's kernel-source.txt" cmp -s "$T/prov" "$T/b/build-metadata/kernel-source.txt"

# Nothing shipped edits the shared kernel command line any more.
refute "installer no longer adds module.sig_enforce=1 to GRUB_CMDLINE_LINUX" \
	grep -qE '^[^#]*sed .*GRUB_CMDLINE_LINUX=.*sig_enforce' "$INST"

# Runtime packages on Debian, with stub dpkg/apt tools (no real package is
# touched). A fresh cloud image has no package lists: the distro VM test found
# that "apt-get install libqrencode4" then fails, so the lists are refreshed
# first when a package has no candidate.
mkdir -p "$T/apt"
cat > "$T/apt/dpkg" <<'EOF2'
#!/bin/sh
[ "$2" = libqrencode4 ] && exit 1; exit 0
EOF2
cat > "$T/apt/apt-cache" <<'EOF2'
#!/bin/sh
echo "$2:"; echo "  Installed: (none)"; echo "  Candidate: ${STUB_CANDIDATE:-(none)}"
EOF2
cat > "$T/apt/apt-get" <<'EOF2'
#!/bin/sh
echo "$*" >> "$STUB_LOG"; [ "$1" = install ] && [ -n "${STUB_FAIL:-}" ] && exit 100; exit 0
EOF2
chmod 0755 "$T/apt/"*
rdeps() { SS_ROOT="" SS_INSTALL_LIB=1 PATH="$T/apt:$PATH" STUB_LOG="$T/apt.log" bash -c '. "$0"; FAMILY=debian; "$@"' "$INST" "$@"; }
eq "runtime_missing lists only the missing package" "$(rdeps runtime_missing)" libqrencode4
: > "$T/apt.log"; rdeps install_runtime_deps > "$T/out" 2>&1
eq "no candidate yet: the package lists are refreshed, then it is installed" \
	"$(tr '\n' '|' < "$T/apt.log")" "update -q|install -y libqrencode4|"
: > "$T/apt.log"; withenv STUB_CANDIDATE=4.1.1-1build2 -- rdeps install_runtime_deps > "$T/out" 2>&1
eq "a known package is installed without a refresh" "$(tr '\n' '|' < "$T/apt.log")" "install -y libqrencode4|"
: > "$T/apt.log"
refute_with "a failed package install stops with a clear message" "could not install the runtime packages libqrencode4" \
	withenv STUB_FAIL=1 -- rdeps install_runtime_deps
# ---- G4: tpm-lockout against stand-in tpm2-tools (the TPM itself: VM run) ----
mkdir -p "$T/tpmbin"
: > "$T/tpm-dev"
cat > "$T/tpmbin/tpm2_getcap" <<'STUB'
#!/bin/sh
. "$TPM_STATE"
printf 'TPM2_PT_PERMANENT:\n  ownerAuthSet:              0\n  lockoutAuthSet:            %s\n  disableClear:              %s\n' "$lockout" "$clear"
STUB
cat > "$T/tpmbin/tpm2_changeauth" <<'STUB'
#!/bin/sh
echo "changeauth $*" >> "$TPM_LOG"
[ "$1" = -c ] && [ "$2" = lockout ] || exit 1
case "$3" in file:*) pw=$(cat "${3#file:}") ;; *) exit 1 ;; esac
printf 'lockout=1\nclear=0\npw=%s\n' "$pw" > "$TPM_STATE"
STUB
cat > "$T/tpmbin/tpm2_clearcontrol" <<'STUB'
#!/bin/sh
. "$TPM_STATE"
echo "clearcontrol $*" >> "$TPM_LOG"
[ "$4" = "file:${4#file:}" ] && [ "$(cat "${4#file:}")" = "$pw" ] || exit 1
printf 'lockout=1\nclear=1\npw=%s\n' "$pw" > "$TPM_STATE"
STUB
chmod 0755 "$T"/tpmbin/*
tpmL() { TPM_STATE="$T/tpm-state" TPM_LOG="$T/tpm.log" SS_TPM_DEV="$T/tpm-dev" \
	PATH="$T/tpmbin:$PATH" SS_INSTALL_LIB=1 bash -c '. "$0"; "$@"' "$INST" "$@"; }
if [ "$(id -u)" -eq 0 ]; then
	printf 'lockout=0\nclear=0\n' > "$T/tpm-state"; : > "$T/tpm.log"
	tpmL tpm_lockout > "$T/out" 2>&1; rc=$?
	pw=$(sed -n '/shown ONCE/,/^$/d; s/^      \([A-Za-z0-9]\{24,\}\)$/\1/p' "$T/out" | head -1)
	check "tpm-lockout sets a lockout password and disables clear" sh -c "[ $rc -eq 0 ] && grep -qx 'lockout=1' '$T/tpm-state' && grep -qx 'clear=1' '$T/tpm-state'"
	check "... shows the password once, the same one the TPM got" sh -c "[ -n '$pw' ] && grep -qx 'pw=$pw' '$T/tpm-state' && [ \$(grep -c '$pw' '$T/out') -eq 1 ]"
	refute "... and never puts it on a command line" grep -q "$pw" "$T/tpm.log"
	refute "... nor leaves its temporary file" sh -c "ls /run/ss-tpm-lockout.* 2>/dev/null | grep -q ."
	tpmL tpm_lockout > "$T/out" 2>&1
	check "a TPM whose lockout password is set is left alone" sh -c "grep -q 'already set; left as it is' '$T/out' && [ \$(grep -c changeauth '$T/tpm.log') -eq 1 ]"
	printf 'lockout=0\nclear=0\n' > "$T/tpm-state"
	SS_TPM_LOCKOUT=0 tpmL tpm_lockout > "$T/out" 2>&1
	check "SS_TPM_LOCKOUT=0 skips it" sh -c "grep -q 'skipped (SS_TPM_LOCKOUT=0)' '$T/out' && grep -qx 'lockout=0' '$T/tpm-state'"
	SS_TPM_DEV="$T/no-tpm" TPM_STATE="$T/tpm-state" PATH="$T/tpmbin:$PATH" SS_INSTALL_LIB=1 \
		bash -c '. "$0"; SS_TPM_DEV="$1"; tpm_lockout auto' "$INST" "$T/no-tpm" > "$T/out" 2>&1; rc=$?
	check "no TPM: \`all\` skips it quietly" sh -c "[ $rc -eq 0 ] && grep -q 'no TPM' '$T/out'"
else
	skip "tpm-lockout checks (need root for /run)"
fi
tap_done
