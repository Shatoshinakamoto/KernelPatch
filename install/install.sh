#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# install.sh - build and install the secure_sudo patched kernel + userspace on
# Debian/Ubuntu, Fedora/RHEL, Arch and openSUSE (derivatives detected via
# ID_LIKE). One script, idempotent where it can be.
#
# This fixes the bugs the old build.sh/deploy.yml had:
#   * targets a real kernel (6.12 LTS), not the non-existent linux-5.15.0 URL;
#   * registers the LSM the right way (Kconfig + Makefile + CONFIG_LSM), not a
#     sed into security_init();
#   * builds in a root-owned dir, never world-writable /tmp;
#   * builds a removable distro PACKAGE (bindeb-pkg/binrpm-pkg) so the kernel
#     can be uninstalled and the old one stays in the boot menu;
#   * enforces module signing as a real kernel parameter.
#
# Run as root. Review it first: it compiles and installs a kernel.
set -euo pipefail

KVER="${KVER:-6.12.48}"            # kernel.org 6.12 LTS point release
KMAJOR="6"
JOBS="${JOBS:-$(nproc)}"
BUILD_ROOT="${BUILD_ROOT:-/usr/src/secure_sudo-build}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LSM_SRC="$ROOT/kernel/security/secure_sudo"
US_SRC="$ROOT/userspace"

log()  { printf '\033[1;32m[secure_sudo]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[secure_sudo]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[secure_sudo]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -d "$LSM_SRC" ] || die "LSM sources not found at $LSM_SRC"

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
FAMILY="" ; SECDIR="" ; PKG_TARGET=""
detect_distro() {
	. /etc/os-release
	local ids="${ID:-} ${ID_LIKE:-}"
	case " $ids " in
		*debian*|*ubuntu*)  FAMILY=debian ;;
		*fedora*|*rhel*|*centos*) FAMILY=fedora ;;
		*arch*)             FAMILY=arch ;;
		*suse*|*opensuse*)  FAMILY=suse ;;
		*) die "unsupported distro: ID=$ID ID_LIKE=${ID_LIKE:-}" ;;
	esac
	case "$FAMILY" in
		debian) SECDIR="/lib/$(uname -m)-linux-gnu/security"
			[ -d "$SECDIR" ] || SECDIR="/lib/security"
			PKG_TARGET="bindeb-pkg" ;;
		fedora) SECDIR="/usr/lib64/security"; PKG_TARGET="binrpm-pkg" ;;
		suse)   SECDIR="/usr/lib64/security"; PKG_TARGET="binrpm-pkg" ;;
		arch)   SECDIR="/usr/lib/security";   PKG_TARGET="" ;;
	esac
	log "distro family: $FAMILY (PAM dir $SECDIR)"
}

# ---------------------------------------------------------------------------
# Admin-group auto-detection
#
# Every group whose members can already become root through sudo should count
# as "sudo" for the LSM, otherwise those users would be treated as non-sudo.
# We collect: the well-known admin groups that exist on this box (sudo, wheel,
# admin), plus every %group (or %#gid) granted rights in /etc/sudoers and
# /etc/sudoers.d/*. Result is a comma-separated GID list, e.g. "27,10".
# ---------------------------------------------------------------------------
# Every admin group on the box (sudo/wheel/admin + sudoers %groups) as "27,10".
# Logic lives in scripts/ so it is shared with the installed tooling.
detect_admin_gids() {
	bash "$ROOT/scripts/detect-admin-gids.sh"
}

install_deps() {
	log "installing build dependencies"
	case "$FAMILY" in
	debian)
		apt-get update
		apt-get install -y build-essential fakeroot libncurses-dev bison flex \
			libssl-dev libelf-dev bc rsync kmod cpio dwarves zstd \
			libpam0g-dev libqrencode-dev zlib1g-dev nftables zip curl ca-certificates ;;
	fedora)
		dnf install -y gcc gcc-c++ make bison flex openssl-devel elfutils-libelf-devel \
			bc rsync kmod cpio dwarves zstd ncurses-devel rpm-build \
			pam-devel qrencode-devel zlib-devel nftables zip curl ;;
	suse)
		zypper --non-interactive install -y gcc gcc-c++ make bison flex libopenssl-devel \
			libelf-devel bc rsync kmod cpio zstd ncurses-devel rpm-build \
			pam-devel qrencode-devel zlib-devel nftables zip curl ;;
	arch)
		pacman -Sy --noconfirm --needed base-devel bc rsync kmod cpio zstd \
			openssl libelf pam qrencode zlib nftables zip curl ;;
	esac
}

# ---------------------------------------------------------------------------
# Kernel build
# ---------------------------------------------------------------------------
fetch_kernel() {
	mkdir -p "$BUILD_ROOT"; chmod 700 "$BUILD_ROOT"
	cd "$BUILD_ROOT"
	local tar="linux-$KVER.tar.xz"
	if [ ! -d "linux-$KVER" ]; then
		if [ ! -f "$tar" ]; then
			log "downloading kernel $KVER"
			curl -fL -o "$tar" \
			  "https://cdn.kernel.org/pub/linux/kernel/v${KMAJOR}.x/$tar"
		fi
		log "extracting $tar"
		tar xf "$tar"
	fi
}

graft_lsm() {
	local tree="$BUILD_ROOT/linux-$KVER"
	log "grafting secure_sudo into $tree/security"
	rm -rf "$tree/security/secure_sudo"
	cp -a "$LSM_SRC" "$tree/security/secure_sudo"

	# Register the Kconfig (idempotent).
	if ! grep -q 'security/secure_sudo/Kconfig' "$tree/security/Kconfig"; then
		# Insert just before the final endmenu of the Security options menu.
		sed -i 's|^endmenu|source "security/secure_sudo/Kconfig"\nendmenu|' \
			"$tree/security/Kconfig" || true
		grep -q 'security/secure_sudo/Kconfig' "$tree/security/Kconfig" \
			|| echo 'source "security/secure_sudo/Kconfig"' >> "$tree/security/Kconfig"
	fi

	# Register in the security Makefile (idempotent).
	if ! grep -q 'secure_sudo/' "$tree/security/Makefile"; then
		cat >> "$tree/security/Makefile" <<-'EOF'

		subdir-$(CONFIG_SECURITY_SECURE_SUDO) += secure_sudo
		obj-$(CONFIG_SECURITY_SECURE_SUDO)    += secure_sudo/
		EOF
	fi
}

configure_kernel() {
	local tree="$BUILD_ROOT/linux-$KVER"
	cd "$tree"
	log "configuring kernel"
	# Start from the running kernel's config if we can, else a sane default.
	if [ -f "/boot/config-$(uname -r)" ]; then
		cp "/boot/config-$(uname -r)" .config
	elif [ -f /proc/config.gz ]; then
		zcat /proc/config.gz > .config
	else
		make defconfig
	fi

	# Clear any distro signing keys that we can't reproduce; we sign ourselves.
	./scripts/config --disable SYSTEM_TRUSTED_KEYS || true
	./scripts/config --disable SYSTEM_REVOCATION_KEYS || true

	./scripts/config --enable SECURITY
	./scripts/config --enable SECURITY_NETWORK
	./scripts/config --enable SECURITY_SECURE_SUDO
	./scripts/config --enable MODULE_SIG
	./scripts/config --enable MODULE_SIG_ALL
	./scripts/config --enable TCG_TPM

	# Append secure_sudo to the active LSM list if not already there.
	local cur
	cur="$(./scripts/config --state CONFIG_LSM 2>/dev/null || true)"
	if [ -z "$cur" ] || [ "$cur" = "undef" ]; then
		cur="landlock,lockdown,yama,loadpin,safesetid,integrity,bpf"
	fi
	case ",$cur," in
		*,secure_sudo,*) : ;;
		*) cur="${cur%,bpf},secure_sudo,bpf"
		   case ",$cur," in *,secure_sudo,*) : ;; *) cur="$cur,secure_sudo" ;; esac ;;
	esac
	./scripts/config --set-str CONFIG_LSM "$cur"
	log "CONFIG_LSM = $cur"

	make olddefconfig
}

build_install_kernel() {
	local tree="$BUILD_ROOT/linux-$KVER"
	cd "$tree"
	log "building kernel (-j$JOBS); this takes a while"
	case "$FAMILY" in
	debian|fedora|suse)
		make -j"$JOBS" "$PKG_TARGET"
		log "installing kernel package(s)"
		case "$FAMILY" in
		debian) dpkg -i ../linux-image-*.deb ../linux-headers-*.deb 2>/dev/null || \
			dpkg -i ../linux-image-*.deb ;;
		fedora|suse) rpm -ivh --force "$HOME"/rpmbuild/RPMS/*/kernel-*.rpm 2>/dev/null || \
			find . -name 'kernel-*.rpm' -exec rpm -ivh --force {} + ;;
		esac ;;
	arch)
		make -j"$JOBS"
		make modules_install
		make install
		warn "Arch: update your bootloader entry to point at the new kernel in /boot." ;;
	esac
}

set_sig_enforce_cmdline() {
	# Make module signature enforcement a real kernel parameter (the old
	# modprobe.d option did nothing). Backs up before editing.
	local param="module.sig_enforce=1"
	if [ -f /etc/default/grub ]; then
		cp -n /etc/default/grub /etc/default/grub.secure_sudo.bak || true
		if ! grep -q "$param" /etc/default/grub; then
			sed -i "s/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"$param /" \
				/etc/default/grub || true
		fi
		if command -v update-grub >/dev/null 2>&1; then update-grub || true
		elif command -v grub2-mkconfig >/dev/null 2>&1; then
			grub2-mkconfig -o /boot/grub2/grub.cfg || \
			grub2-mkconfig -o /boot/efi/EFI/*/grub.cfg || true
		fi
	else
		warn "no /etc/default/grub; add '$param' to your kernel cmdline manually."
	fi
}

# ---------------------------------------------------------------------------
# Userspace
# ---------------------------------------------------------------------------
build_install_userspace() {
	log "building userspace (cli, pam, daemon, otp)"
	make -C "$US_SRC/cli" install
	make -C "$US_SRC/pam" SECDIR="$SECDIR" install
	make -C "$US_SRC/daemon" install
	make -C "$US_SRC/otp" install

	log "installing config to /etc/secure_sudo"
	mkdir -p /etc/secure_sudo
	for f in "$US_SRC"/config/*.conf; do
		local base; base="$(basename "$f")"
		[ -e "/etc/secure_sudo/$base" ] || install -m0644 "$f" "/etc/secure_sudo/$base"
	done

	# Generate the uid->home map for #4 from /etc/passwd (regular users with
	# a real home). Only create it if the admin hasn't written their own.
	if [ ! -s /etc/secure_sudo/home_map.conf ] || \
	   ! grep -qvE '^\s*(#|$)' /etc/secure_sudo/home_map.conf; then
		{
			echo "# generated from /etc/passwd by install.sh"
			getent passwd | awk -F: '$3>=1000 && $6 ~ /^\/home\// {print $3" "$6}'
		} > /etc/secure_sudo/home_map.conf
		log "generated home_map.conf for $(grep -cvE '^\s*(#|$)' /etc/secure_sudo/home_map.conf) user(s)"
	fi

	# Auto-detect every admin group so sudo-group users count as sudo.
	local gids; gids="$(detect_admin_gids)"
	if [ -n "$gids" ]; then
		sed -i "s/^admin_gid = .*/admin_gid = $gids/" /etc/secure_sudo/secure-sudo.conf
		log "admin_gid auto-detected: $gids"
	else
		warn "no admin groups found; only root will count as sudo (edit admin_gid in secure-sudo.conf)"
	fi

	# scripts/: standalone TimeVault allowlist tool + admin detector. The CLI
	# has both built in (secure-sudo vault-allow / detect-admins); these are
	# the dependency-free bash equivalents.
	install -D -m0755 "$ROOT/scripts/timevault-whitelist.sh" \
		/usr/libexec/secure-sudo/timevault-whitelist.sh
	install -D -m0755 "$ROOT/scripts/detect-admin-gids.sh" \
		/usr/libexec/secure-sudo/detect-admin-gids.sh

	mkdir -p /usr/share/doc/secure-sudo
	install -m0644 "$ROOT/kernel/security/secure_sudo/INTEGRATION.md" \
		/usr/share/doc/secure-sudo/INTEGRATION.md 2>/dev/null || true

	systemctl daemon-reload || true
	systemctl enable secure-sudod.service 2>/dev/null || \
		warn "could not enable secure-sudod.service (no systemd?)"
}

print_pam_guidance() {
	cat <<EOF

[secure_sudo] Userspace installed. PAM wiring is left to you ON PURPOSE so a
typo can't lock you out. To enable the cooldown feed and (optionally) OTP, add
to /etc/pam.d/sudo (and /etc/pam.d/su) around your existing auth lines:

    auth  [default=die]  pam_unix.so        # your existing verifier
    auth  required       pam_secure_sudo.so authfail
    auth  sufficient      pam_unix.so
    auth  required       pam_secure_sudo.so authsucc

For the rotating OTP password, run 'secure-sudo otp setup' first, test with
'secure-sudo otp verify', THEN add (keep a root shell open while testing):

    auth  required       pam_secure_otp.so

PAM modules are installed in: $SECDIR
EOF
}

main() {
	detect_distro
	install_deps
	fetch_kernel
	graft_lsm
	configure_kernel
	build_install_kernel
	set_sig_enforce_cmdline
	build_install_userspace
	secure-sudo load || warn "could not load policy yet (reboot into the new kernel first)"
	print_pam_guidance
	log "DONE. Reboot into the new kernel to activate the secure_sudo LSM."
}

main "$@"
