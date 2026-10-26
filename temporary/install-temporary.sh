#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# install-temporary.sh - OPT-IN installer for the secure_sudo temporary/ add-ons
# (ProcGuard, DriverGuard, BiosGuard, BootGuard, Locus) plus the shared logging.
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

# 1. Build + install each add-on binary.
for d in procguard driverguard biosguard bootguard locus; do
	log "building $d"
	make -C "$SRC/$d" clean >/dev/null 2>&1 || true
	make -C "$SRC/$d" BINDIR="$BINDIR" >/dev/null
	make -C "$SRC/$d" BINDIR="$BINDIR" install >/dev/null
	make -C "$SRC/$d" clean >/dev/null 2>&1 || true
done

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

# 4. systemd units.
if [ -d "$UNITDIR" ]; then
	log "installing systemd units to $UNITDIR"
	install -m0644 "$SRC"/systemd/*.service "$UNITDIR"/
	install -m0644 "$SRC"/systemd/*.timer   "$UNITDIR"/
	systemctl daemon-reload 2>/dev/null || true
fi

cat <<'NEXT'

Installed. NOTHING is enabled yet - every enforcing part is opt-in.

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

  BiosGuard (detection; reflash is operator-only):
    # optionally set good_image=... in biosguard.conf first
    secure-sudo-biosguard baseline
    systemctl enable --now secure-sudo-biosguard.timer

See docs/ADDONS.md for the full description, the honesty notes on BIOS/boot, and
every command and setting.
NEXT
echo
echo "Done."
