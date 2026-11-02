#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# install-temporary.sh - OPT-IN installer for the secure_sudo temporary/ add-ons
# (ProcGuard, DriverGuard, BiosGuard, BootGuard, Locus, tamperwatch, management
# GUI) plus the shared logging.
#
# These add-ons are NOT installed by the core install.sh. Run this only when you
# want them. It builds and installs the binaries, drops config TEMPLATES (never
# overwriting your edited configs), installs the systemd units, and creates the
# state/log directories - but it ENABLES NOTHING and KILLS NOTHING. Every
# enforcing behaviour is opt-in and starts in a safe mode. The next-steps notice
# at the end tells you exactly what to turn on and in what order.
#
# NOTE: run with `bash install-temporary.sh` (the project tree may be mounted
# noexec).
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
BINDIR="${BINDIR:-/usr/bin}"
UNITDIR="${UNITDIR:-/lib/systemd/system}"
CONFDIR="/etc/secure_sudo/addons"
STATEDIR="/var/lib/secure_sudo/addons"
LOGDIR="/var/log/secure_sudo/addons"

log() { printf '  [*] %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "install-temporary.sh: must run as root" >&2; exit 1; }

echo "secure_sudo temporary/ add-ons - installer"

# 1. Build + install each compiled add-on binary.
for d in procguard driverguard biosguard bootguard locus tamperwatch; do
	log "building $d"
	make -C "$SRC/$d" clean >/dev/null 2>&1 || true
	make -C "$SRC/$d" BINDIR="$BINDIR" >/dev/null
	make -C "$SRC/$d" BINDIR="$BINDIR" install >/dev/null
	make -C "$SRC/$d" clean >/dev/null 2>&1 || true
done

# 1a. Failure reporting: OnFailure= of every add-on unit runs this (P2-2).
log "building the add-on failure reporter"
make -C "$SRC/failure" clean >/dev/null 2>&1 || true
make -C "$SRC/failure" BINDIR=/usr/libexec/secure-sudo install >/dev/null
make -C "$SRC/failure" clean >/dev/null 2>&1 || true

# 1b. Management GUI (pure Python stdlib - script + page installed together).
log "installing management GUI"
make -C "$SRC/gui" >/dev/null
make -C "$SRC/gui" BINDIR="$BINDIR" install >/dev/null

# 2. Directories (root-only).
install -d -m0700 "$STATEDIR" "$LOGDIR"
mkdir -p "$CONFDIR"; chmod 0755 /etc/secure_sudo "$CONFDIR" 2>/dev/null || true

# 3. Config templates - never clobber an existing (edited) config.
log "installing config templates to $CONFDIR (existing files kept)"
for f in "$SRC"/config/*.conf; do
	base="$(basename "$f")"
	if [ -e "$CONFDIR/$base" ]; then
		log "keeping existing $base"
	else
		install -m0644 "$f" "$CONFDIR/$base"
	fi
done

# 3b. Package and kernel hooks: re-baseline BootGuard/DriverGuard after a
#     legitimate update, so it is not restored away as tampering. They do
#     nothing until a guard has a baseline.
log "installing package/kernel hooks (re-baseline after updates)"
install -D -m0755 "$SRC/hooks/addons-refresh" /usr/libexec/secure-sudo/addons-refresh
for d in /etc/kernel/postinst.d /etc/kernel/postrm.d; do
	[ -d "$d" ] && install -m0755 "$SRC/hooks/kernel-hook" "$d/zzz-secure-sudo-addons"
done
if [ -d /etc/kernel/install.d ] || command -v kernel-install >/dev/null 2>&1; then
	install -D -m0755 "$SRC/hooks/kernel-install.install" \
		/etc/kernel/install.d/99-secure-sudo-addons.install
fi
[ -d /etc/apt/apt.conf.d ] && install -m0644 "$SRC/hooks/apt.conf" /etc/apt/apt.conf.d/99secure-sudo-addons
[ -d /etc/dnf/libdnf5-plugins/actions.d ] &&
	install -m0644 "$SRC/hooks/dnf5.actions" /etc/dnf/libdnf5-plugins/actions.d/secure-sudo-addons.actions
[ -d /etc/dnf/plugins/post-transaction-actions.d ] &&
	install -m0644 "$SRC/hooks/dnf4.action" /etc/dnf/plugins/post-transaction-actions.d/secure-sudo-addons.action
true

# 3c. Every config is checked strictly: an add-on refuses to act on a config
#     with an unknown key, a bad value or an unsafe owner/mode (P2-2).
for b in procguard driverguard biosguard bootguard locus tamperwatch; do
	if ! "$BINDIR/secure-sudo-$b" check-config >/dev/null 2>&1; then
		log "WARNING: $b config has problems - run: secure-sudo-$b check-config"
	fi
done

# 4. systemd units.
if [ -d "$UNITDIR" ]; then
	log "installing systemd units to $UNITDIR"
	install -m0644 "$SRC"/systemd/*.service "$UNITDIR"/
	install -m0644 "$SRC"/systemd/*.timer   "$UNITDIR"/
	systemctl daemon-reload 2>/dev/null || true
fi

cat <<'NEXT'

Installed. NOTHING is enabled yet - every enforcing part is opt-in.

Every add-on has `check-config`; its acting commands refuse to run while its
config has an error. Each unit is sandboxed and resource-limited, and a unit
that fails is reported (CRITICAL log, off-box syslog, notify_cmd) by
secure-sudo-addon-failure@.service. Maturity: docs/ADDONS.md "Maturity".

Recommended order:

  Logging (optional off-box backup):
    edit /etc/secure_sudo/addons/logging.conf  (set remote_enabled=1 + a collector)

  Locus (optional - centralises the hourly rotating locations):
    edit /etc/secure_sudo/addons/locus.conf     (roots; keep GUI on 127.0.0.1)
    systemctl enable --now secure-sudo-locus
    # point guards at it: edit locus-client.conf (host/port)

  ProcGuard (START IN MONITOR):
    edit /etc/secure_sudo/addons/procguard_allow.conf   (add your allowed exes)
    secure-sudo-procguard scan        # monitor: logs what WOULD be killed
    # only after the allowlist is complete:
    #   set mode=enforce in procguard.conf, then
    #   systemctl enable --now secure-sudo-procguard

  DriverGuard:
    secure-sudo-driverguard baseline                 # hash + back up drivers
    systemctl enable --now secure-sudo-driverguard.timer   # hourly scan
    # set mode=enforce in driverguard.conf to auto-repair

  BootGuard:
    secure-sudo-bootguard baseline                   # hash + back up /boot
    systemctl enable secure-sudo-bootguard-restore   # apply staged restore at boot
    systemctl enable --now secure-sudo-bootguard.timer

  BiosGuard (DETECTION ONLY - logs + notifies, never reflashes):
    secure-sudo-biosguard baseline        # fingerprint DMI + ACPI tables
    systemctl enable --now secure-sudo-biosguard.timer
    # a detected change is logged CRITICAL + sent to notify_cmd (see logging.conf)

  tamperwatch (real-time "who tampered a protected file"):
    # watches the PheonixBox protected set in real time via fanotify
    systemctl enable --now secure-sudo-tamperwatch
    # mode=log (default) attributes only; set mode=quarantine to kill+compress

  Management GUI (view/configure everything from a local browser):
    systemctl enable --now secure-sudo-gui
    # then open http://127.0.0.1:8790/ ON THIS HOST (loopback only)
    # the access token is printed on start and stored 0600 at
    #   /var/lib/secure_sudo/addons/gui/token

Off-box log backup + notifications apply to every add-on above: set
remote_enabled=1 (collector) and/or notify_cmd in logging.conf.

See docs/ADDONS.md for the full description, the honesty notes on BIOS/boot, and
every command and setting.
NEXT
echo
echo "Done."
