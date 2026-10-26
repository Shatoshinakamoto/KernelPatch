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
# openssl, and - for the UKI - systemd-ukify. The base install.sh deps are
# installed by install.sh itself.
#
# Inputs (environment):
#   SRC_AGE       path to secure_sudo-src.tar.age   (required)
#   AGE_IDENTITY  path to the age private key file   (required)
#   MOK_KEY       MOK private key (PEM)   [default: generate at /var/lib/secure_sudo/mok/MOK.key]
#   MOK_CRT       MOK certificate (DER)   [default: /var/lib/secure_sudo/mok/MOK.der]
#   MAKE_UKI      1 to also build+install a signed UKI       [default: 0]
#   ESP           EFI system partition mount point           [default: /boot/efi]
#   ENC_TMPFS_SIZE size of the RAM build area                [default: 24g]
#   KVER          kernel version                             [default: install.sh's]
#
# Order matters with Secure Boot on: install.sh refuses to install a kernel
# signed with a key that is not enrolled yet (it would not boot). So the
# first run creates the MOK, asks mokutil to enroll it and stops; reboot,
# confirm it in MokManager, and run this again to build, sign and install.
#
# Run as root. The kernel goes through install.sh install-kernel: trial boot,
# rollback and uninstall work as for a normal install (docs/RECOVERY.md).
set -euo pipefail

: "${SRC_AGE:?set SRC_AGE to the age-encrypted source bundle}"
: "${AGE_IDENTITY:?set AGE_IDENTITY to your age private key}"
MOK_DIR="/var/lib/secure_sudo/mok"
MOK_KEY="${MOK_KEY:-$MOK_DIR/MOK.key}"
MOK_CRT="${MOK_CRT:-$MOK_DIR/MOK.der}"
MAKE_UKI="${MAKE_UKI:-0}"
ESP="${ESP:-/boot/efi}"
ENC_TMPFS_SIZE="${ENC_TMPFS_SIZE:-24g}"

log()  { printf '\033[1;32m[secure_sudo/enc]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[secure_sudo/enc]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
for t in age mokutil sbsign openssl; do command -v "$t" >/dev/null || die "$t not installed"; done

# --- 1. MOK first: create + enroll, or check it is enrolled ---------------
mkdir -p "$MOK_DIR"; chmod 700 "$MOK_DIR"
if [ ! -f "$MOK_KEY" ] || [ ! -f "$MOK_CRT" ]; then
	log "generating a Machine Owner Key"
	openssl req -new -x509 -newkey rsa:2048 -keyout "$MOK_KEY" -out "$MOK_CRT.pem" \
		-nodes -days 3650 -subj "/CN=secure_sudo MOK/"
	openssl x509 -in "$MOK_CRT.pem" -outform DER -out "$MOK_CRT"
	chmod 600 "$MOK_KEY"
fi
[ -f "$MOK_CRT.pem" ] || openssl x509 -inform DER -in "$MOK_CRT" -out "$MOK_CRT.pem"
if ! mokutil --test-key "$MOK_CRT" 2>/dev/null | grep -q 'already enrolled'; then
	if mokutil --sb-state 2>/dev/null | grep -q enabled; then
		log "enrolling the MOK: set a one-time password now, confirm it in the"
		log "MOK Manager screen on the next reboot, then run this script again."
		mokutil --import "$MOK_CRT"
		exit 0
	fi
	log "Secure Boot is off: building anyway; enroll $MOK_CRT before turning it on"
	mokutil --import "$MOK_CRT" || log "mokutil --import failed (no EFI?); enroll it later"
fi

# --- 2. decrypt into tmpfs -------------------------------------------------
WORK="$(mktemp -d /run/secure_sudo-enc.XXXXXX)"
mount -t tmpfs -o size="$ENC_TMPFS_SIZE",mode=0700 tmpfs "$WORK"
cleanup() { cd /; umount "$WORK" 2>/dev/null || true; rmdir "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

log "decrypting source into tmpfs $WORK"
age -d -i "$AGE_IDENTITY" "$SRC_AGE" | tar -x -C "$WORK"
SRC_TREE="$(find "$WORK" -maxdepth 2 -name install.sh -path '*/install/*' -printf '%h/..\n' | head -1)"
SRC_TREE="$(cd "$SRC_TREE" && pwd)"
[ -d "$SRC_TREE/kernel/security/secure_sudo" ] || die "decrypted tree missing LSM sources"

# --- 3. build, sign and install via the normal installer ------------------
# install.sh signs the kernel image with the MOK (sbsign + sbverify); the
# modules are signed with the per-build key and enforced (MODULE_SIG_FORCE).
log "building from encrypted source (BUILD_ROOT in tmpfs)"
env ${KVER:+KVER="$KVER"} BUILD_ROOT="$WORK/build" SS_SB_KEY="$MOK_KEY" SS_SB_CERT="$MOK_CRT.pem" \
	"$SRC_TREE/install/install.sh"
REL="$(sed -n 's/^K\t[^\t]*\t//p' /var/lib/secure_sudo/install/manifest | sort -u | tail -1)"
KIMG="/boot/vmlinuz-$REL"
[ -n "$REL" ] && [ -f "$KIMG" ] || die "could not find the installed kernel image (release '$REL')"

# --- 4. optional signed UKI ------------------------------------------------
if [ "$MAKE_UKI" = "1" ]; then
	INITRD="/boot/initrd.img-$REL"; [ -f "$INITRD" ] || INITRD="/boot/initramfs-$REL.img"
	if command -v ukify >/dev/null 2>&1; then
		log "assembling signed UKI"
		ukify build \
			--linux="$KIMG" \
			--initrd="$INITRD" \
			--cmdline="$(cat /proc/cmdline)" \
			--secureboot-private-key="$MOK_KEY" \
			--secureboot-certificate="$MOK_CRT.pem" \
			--output="$ESP/EFI/Linux/secure_sudo-$REL.efi"
	else
		log "ukify not found; skipping UKI (kernel is still signed)"
	fi
fi

log "DONE. Reboot to try $REL once; then: install.sh verify --commit"
log "Plaintext source in $WORK will be wiped on exit (tmpfs unmount)."
