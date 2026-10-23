#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# install-encrypted.sh - encrypted-source + Secure Boot variant of install.sh.
#
# It reuses the normal installer but adds two things the TODO/README ask for:
#   1. The source bundle ships ENCRYPTED (age). It is decrypted into a tmpfs
#      (RAM) mount, built there, and the plaintext never touches disk - the
#      tmpfs is unmounted (and thus wiped) at the end.
#   2. The resulting kernel and modules are SIGNED with an enrolled Machine
#      Owner Key (MOK) so the box can keep Secure Boot on, and optionally
#      assembled into a signed Unified Kernel Image (UKI).
#
# Prerequisites on the builder: age, mokutil, sbsigntool (sbsign/sbverify),
# and - for the UKI - systemd-ukify (or objcopy). The base install.sh deps are
# installed by install.sh itself.
#
# Inputs (environment):
#   SRC_AGE       path to secure_sudo-src.tar.age   (required)
#   AGE_IDENTITY  path to the age private key file   (required)
#   MOK_KEY       MOK private key (PEM)   [default: generate at /var/lib/secure_sudo/mok/MOK.key]
#   MOK_CRT       MOK certificate (DER)   [default: /var/lib/secure_sudo/mok/MOK.der]
#   MAKE_UKI      1 to also build+install a signed UKI       [default: 0]
#   ESP           EFI system partition mount point           [default: /boot/efi]
#
# Run as root. Enrolling a new MOK requires confirming at the MOK Manager
# screen on the NEXT reboot (you set a one-time password below).
set -euo pipefail

: "${SRC_AGE:?set SRC_AGE to the age-encrypted source bundle}"
: "${AGE_IDENTITY:?set AGE_IDENTITY to your age private key}"
MOK_DIR="/var/lib/secure_sudo/mok"
MOK_KEY="${MOK_KEY:-$MOK_DIR/MOK.key}"
MOK_CRT="${MOK_CRT:-$MOK_DIR/MOK.der}"
MAKE_UKI="${MAKE_UKI:-0}"
ESP="${ESP:-/boot/efi}"
KVER="${KVER:-6.12.48}"

log()  { printf '\033[1;32m[secure_sudo/enc]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[secure_sudo/enc]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
command -v age >/dev/null       || die "age not installed"
command -v mokutil >/dev/null   || die "mokutil not installed"
command -v sbsign >/dev/null    || die "sbsign (sbsigntool) not installed"

# --- 1. decrypt into tmpfs -------------------------------------------------
WORK="$(mktemp -d /run/secure_sudo-enc.XXXXXX)"
mount -t tmpfs -o size=8g,mode=0700 tmpfs "$WORK"
cleanup() { cd /; umount "$WORK" 2>/dev/null || true; rmdir "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

log "decrypting source into tmpfs $WORK"
age -d -i "$AGE_IDENTITY" "$SRC_AGE" | tar -x -C "$WORK"
SRC_TREE="$(find "$WORK" -maxdepth 2 -name install.sh -path '*/install/*' -printf '%h/..\n' | head -1)"
SRC_TREE="$(cd "$SRC_TREE" && pwd)"
[ -d "$SRC_TREE/kernel/security/secure_sudo" ] || die "decrypted tree missing LSM sources"

# --- 2. build via the normal installer (in tmpfs) -------------------------
log "building from encrypted source (BUILD_ROOT in tmpfs)"
KVER="$KVER" BUILD_ROOT="$WORK/build" "$SRC_TREE/install/install.sh"

# --- 3. MOK key (generate + enroll if absent) ------------------------------
mkdir -p "$MOK_DIR"; chmod 700 "$MOK_DIR"
if [ ! -f "$MOK_KEY" ] || [ ! -f "$MOK_CRT" ]; then
	log "generating a Machine Owner Key"
	openssl req -new -x509 -newkey rsa:2048 -keyout "$MOK_KEY" -out "$MOK_CRT.pem" \
		-nodes -days 3650 -subj "/CN=secure_sudo MOK/"
	openssl x509 -in "$MOK_CRT.pem" -outform DER -out "$MOK_CRT"
	chmod 600 "$MOK_KEY"
	log "enrolling MOK - you will set a one-time password; confirm it in the"
	log "MOK Manager screen on the next reboot."
	mokutil --import "$MOK_CRT"
fi

# --- 4. sign kernel image + modules ---------------------------------------
KIMG="/boot/vmlinuz-$KVER"
[ -f "$KIMG" ] || KIMG="$(ls -1 /boot/vmlinuz-"$KVER"* 2>/dev/null | head -1 || true)"
if [ -n "$KIMG" ] && [ -f "$KIMG" ]; then
	log "signing kernel image $KIMG"
	sbsign --key "$MOK_KEY" --cert "$MOK_CRT.pem" --output "$KIMG" "$KIMG"
fi

SIGN_FILE="$WORK/build/linux-$KVER/scripts/sign-file"
if [ -x "$SIGN_FILE" ]; then
	log "signing out-of-tree modules for $KVER"
	find "/lib/modules/$KVER" -name '*.ko' -print0 2>/dev/null | \
		while IFS= read -r -d '' ko; do
			"$SIGN_FILE" sha256 "$MOK_KEY" "$MOK_CRT" "$ko" || true
		done
fi

# --- 5. optional signed UKI ------------------------------------------------
if [ "$MAKE_UKI" = "1" ]; then
	if command -v ukify >/dev/null 2>&1; then
		log "assembling signed UKI"
		ukify build \
			--linux="$KIMG" \
			--initrd="/boot/initramfs-$KVER.img" \
			--cmdline="$(cat /proc/cmdline)" \
			--secureboot-private-key="$MOK_KEY" \
			--secureboot-certificate="$MOK_CRT.pem" \
			--output="$ESP/EFI/Linux/secure_sudo-$KVER.efi"
	else
		log "ukify not found; skipping UKI (kernel is still signed)"
	fi
fi

log "DONE. Reboot, confirm the MOK enrollment, and boot the new kernel."
log "Plaintext source in $WORK will be wiped on exit (tmpfs unmount)."
