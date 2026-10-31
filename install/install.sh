#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# install.sh - build and install the secure_sudo patched kernel + userspace on
# Debian/Ubuntu, Fedora/RHEL, Arch and openSUSE (derivatives detected via
# ID_LIKE), and take it out again (TODO P0-5).
#
#   install.sh [all]            preflight, build the kernel from verified
#                               source, install it, install userspace, verify
#   install.sh preflight [WHAT] report what would happen; change nothing
#                               (also: install.sh --dry-run). WHAT: all,
#                               build-kernel, install-kernel, userspace
#                               [--prebuilt DIR]
#   install.sh build-kernel     fetch + verify + configure + build the kernel
#                               package(s) into $BUILD_ROOT/out/<release>/
#   install.sh install-kernel [DIR|PKG...]
#                               install built package(s), regenerate the boot
#                               menu, check it, and arrange a trial boot
#   install.sh userspace [--prebuilt DIR]
#                               build (or take DIR from stage-userspace) and
#                               install the CLI, daemon, PAM modules, OTP
#                               helper and PheonixBox, recording every file
#   install.sh stage-userspace DIR
#                               build userspace into DIR, for another machine
#   install.sh verify [--commit]
#                               check what is installed (and the running
#                               kernel, if it is ours); --commit makes a
#                               trial-booted kernel the default
#   install.sh rollback [--default]
#                               boot the kernel that ran before secure_sudo:
#                               next boot only, or from now on
#   install.sh uninstall [--remove-pam-lines] [--keep-kernel] [--purge]
#                               remove only what this script installed
#
# Safety rules this script keeps:
#   * kernel source is verified against its kernel.org signature before it is
#     extracted (scripts/verify-kernel-source.sh, TODO P0-4);
#   * the kernel is a removable distro PACKAGE named <version>-secure-sudo,
#     installed next to the running kernel, never over it;
#   * with GRUB, the running kernel stays the default and the new one is
#     booted ONCE (grub-reboot); a kernel that panics reboots after
#     SS_PANIC_TIMEOUT seconds into the previous kernel. "verify --commit"
#     makes it the default only after it booted and passed its checks;
#   * every file placed is recorded in /var/lib/secure_sudo/install/manifest
#     with its hash; files that were already there are backed up first.
#     uninstall removes only recorded files that are unchanged, restores the
#     backups, and refuses while PAM still references the modules;
#   * a failed step stops the run and says what is still intact; nothing
#     that changes what boots is ignored with "|| true".
#
# Run as root. Review it first: it compiles and installs a kernel.
# Recovery from every failure this can leave behind: docs/RECOVERY.md.
set -euo pipefail

KVER="${KVER:-6.12.114}"           # kernel.org 6.12 LTS point release
KMAJOR="6"
JOBS="${JOBS:-$(nproc)}"
BUILD_ROOT="${BUILD_ROOT:-/usr/src/secure_sudo-build}"
OUT_DIR="${OUT_DIR:-$BUILD_ROOT/out}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LSM_SRC="$ROOT/kernel/security/secure_sudo"
US_SRC="$ROOT/userspace"
SS_VERSION="$(cat "$ROOT/VERSION" 2>/dev/null || echo unknown)"
LOCALVERSION="-secure-sudo"

KEYDIR="${SS_KEYDIR:-$ROOT/install/keys}"
META_DIR="$BUILD_ROOT/build-metadata"

# SS_ROOT installs userspace into another root (the test suite uses it).
# Kernel, bootloader and systemd steps are never run against SS_ROOT.
SS_ROOT="${SS_ROOT:-}"
STATE="$SS_ROOT/var/lib/secure_sudo/install"
MANIFEST="$STATE/manifest"
BACKUP="$STATE/backup"
SS_TRIAL_BOOT="${SS_TRIAL_BOOT:-1}"
SS_PANIC_TIMEOUT="${SS_PANIC_TIMEOUT:-10}"
GRUB_DROPIN="/etc/default/grub.d/99-secure-sudo.cfg"
PAM_RE='^[[:space:]]*[^#[:space:]].*pam_secure_(sudo|otp)\.so'
BUILT_DIR=""

log()  { printf '\033[1;32m[secure_sudo]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[secure_sudo]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[secure_sudo]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
FAMILY="" ; SECDIR="" ; PKG_TARGET="" ; OS_ID="" ; OS_VER=""
detect_distro() {
	local osr="${SS_OS_RELEASE:-/etc/os-release}" r like
	# In a subshell: os-release sets VERSION, NAME, ... which must not leak.
	# shellcheck disable=SC1090
	r="$( [ -r "$osr" ] && . "$osr"; printf '%s|%s|%s' "${ID:-unknown}" "${VERSION_ID:-}" "${ID_LIKE:-}")"
	OS_ID="${r%%|*}"; r="${r#*|}"; OS_VER="${r%%|*}"; like="${r#*|}"
	case " $OS_ID $like " in
		*debian*|*ubuntu*)  FAMILY=debian ;;
		*fedora*|*rhel*|*centos*) FAMILY=fedora ;;
		*arch*)             FAMILY=arch ;;
		*suse*)  FAMILY=suse ;;		# also matches opensuse*
		*) FAMILY=""; return 1 ;;
	esac
	case "$FAMILY" in
		debian) SECDIR="/lib/$(uname -m)-linux-gnu/security"
			[ -d "$SS_ROOT$SECDIR" ] || [ -d "$SECDIR" ] || SECDIR="/lib/security"
			PKG_TARGET="bindeb-pkg" ;;
		fedora) SECDIR="/usr/lib64/security"; PKG_TARGET="binrpm-pkg" ;;
		suse)   SECDIR="/usr/lib64/security"; PKG_TARGET="binrpm-pkg" ;;
		arch)   SECDIR="/usr/lib/security";   PKG_TARGET="" ;;
	esac
}
need_distro() {
	detect_distro || die "unsupported distro: ID=$OS_ID (see install.sh preflight)"
	log "distro family: $FAMILY (PAM dir $SECDIR)"
}

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
			libpam0g-dev libqrencode-dev zlib1g-dev nftables zip curl ca-certificates \
			gnupg xz-utils debhelper ;;
	fedora)
		dnf install -y gcc gcc-c++ make bison flex openssl-devel elfutils-libelf-devel \
			bc rsync kmod cpio dwarves zstd ncurses-devel rpm-build \
			pam-devel qrencode-devel zlib-devel nftables zip curl gnupg2 xz ;;
	suse)
		zypper --non-interactive install -y gcc gcc-c++ make bison flex libopenssl-devel \
			libelf-devel bc rsync kmod cpio zstd ncurses-devel rpm-build \
			pam-devel qrencode-devel zlib-devel nftables zip curl gpg2 xz ;;
	arch)
		pacman -Sy --noconfirm --needed base-devel bc rsync kmod cpio zstd \
			openssl libelf pam qrencode zlib nftables zip curl gnupg xz ;;
	esac
}

# What the installed programs need at run time (libqrencode for the OTP
# helper's QR code, nft for the network modes, zip/unzip for TimeVault
# quarantine). Distro packages: installed if missing, never removed by
# uninstall (other software may use them).
runtime_missing() { # one package name per line
	local p
	case "$FAMILY" in
	debian) for p in libqrencode4 nftables zip unzip; do dpkg -s "$p" >/dev/null 2>&1 || echo "$p"; done ;;
	fedora) for p in qrencode-libs nftables zip unzip; do rpm -q "$p" >/dev/null 2>&1 || echo "$p"; done ;;
	suse)   for p in libqrencode4 nftables zip unzip; do rpm -q "$p" >/dev/null 2>&1 || echo "$p"; done ;;
	arch)   for p in qrencode nftables zip unzip; do pacman -Q "$p" >/dev/null 2>&1 || echo "$p"; done ;;
	esac
}
install_runtime_deps() {
	local p miss=()
	[ -z "$SS_ROOT" ] || return 0
	mapfile -t miss < <(runtime_missing)
	[ "${#miss[@]}" -gt 0 ] || return 0
	log "installing runtime packages: ${miss[*]}"
	case "$FAMILY" in
	debian)
		# A fresh image (cloud, container) may have no package lists yet.
		for p in "${miss[@]}"; do
			apt-cache policy "$p" 2>/dev/null | grep -q 'Candidate: [^(]' || { apt-get update -q || true; break; }
		done
		apt-get install -y "${miss[@]}" ;;
	fedora) dnf install -y "${miss[@]}" ;;
	suse)   zypper --non-interactive install -y "${miss[@]}" ;;
	arch)   pacman -S --noconfirm --needed "${miss[@]}" ;;
	esac || die "could not install the runtime packages ${miss[*]}; nothing else was changed"
}

# Every installed ELF file must find its shared libraries: a PAM module that
# cannot load fails the whole PAM stack it is in.
unresolved_libs() {
	local rel _ magic out=""
	while IFS=$'\t' read -r rel _; do
		magic=""; [ -f "$SS_ROOT$rel" ] && IFS= read -r -n4 magic < "$SS_ROOT$rel" 2>/dev/null
		[ "$magic" = $'\x7fELF' ] || continue
		if ldd "$SS_ROOT$rel" 2>/dev/null | grep -q 'not found'; then
			out="$out $rel($(ldd "$SS_ROOT$rel" | awk '/not found/ {print $1}' | tr '\n' ' ' | sed 's/ $//'))"
		fi
	done < <(m_list F)
	printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# The manifest: one line per thing this script put on the system,
#   <kind> TAB <path or name> TAB <value>
#   F file (value: sha256)        C config file created here (value: sha256)
#   B original backed up          D directory created here
#   K kernel package (value: release)   P kernel that booted before ours
#   S systemd unit enabled        T trial boot state (trial|committed)
#   V version installed
# Rewritten atomically after every change, so an interrupted run still knows
# everything it placed.
# ---------------------------------------------------------------------------
m_init() { mkdir -p "$STATE" "$BACKUP"; chmod 700 "$STATE"; touch "$MANIFEST"; }
m_get() { # kind key -> value
	[ -f "$MANIFEST" ] || return 1
	awk -F'\t' -v k="$1" -v p="$2" '$1==k && $2==p {v=$3; f=1} END {if (f) print v; exit !f}' "$MANIFEST"
}
m_list() { # kind -> "key TAB value" lines
	[ -f "$MANIFEST" ] || return 0
	awk -F'\t' -v k="$1" '$1==k {print $2 "\t" $3}' "$MANIFEST"
}
m_drop() { # kind key -> manifest without it, into the temp file
	if [ -f "$MANIFEST" ]; then
		awk -F'\t' -v k="$1" -v p="$2" '!($1==k && $2==p)' "$MANIFEST" > "$MANIFEST.tmp"
	else
		: > "$MANIFEST.tmp"
	fi
}
m_set() { m_drop "$1" "$2"; printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$MANIFEST.tmp"; mv -f "$MANIFEST.tmp" "$MANIFEST"; }
m_del() { m_drop "$1" "$2"; mv -f "$MANIFEST.tmp" "$MANIFEST"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

# Create the missing parents of $SS_ROOT/<rel> and record the ones we made.
make_parents() {
	local d missing=()
	d="$(dirname "$1")"
	while [ "$d" != / ] && [ "$d" != . ] && [ ! -d "$SS_ROOT$d" ]; do
		missing=("$d" "${missing[@]}"); d="$(dirname "$d")"
	done
	for d in "${missing[@]}"; do
		mkdir -m0755 "$SS_ROOT$d" || die "cannot create $SS_ROOT$d"
		m_set D "$d" 1
	done
}

# install_file SRC REL MODE [F|C]: place SRC at $SS_ROOT/REL atomically; back up
# whatever was there first unless it is ours.
install_file() {
	local src="$1" rel="$2" mode="$3" kind="${4:-F}" dst="$SS_ROOT$2"
	if { [ -e "$dst" ] || [ -L "$dst" ]; } && ! m_get F "$rel" >/dev/null &&
	   ! m_get C "$rel" >/dev/null && ! m_get B "$rel" >/dev/null; then
		mkdir -p "$BACKUP$(dirname "$rel")"
		cp -a "$dst" "$BACKUP$rel" || die "cannot back up $dst"
		m_set B "$rel" "$(sha "$dst")"
		log "backed up existing $rel"
	fi
	make_parents "$rel"
	{ install -m "$mode" "$src" "$dst.ss-new" && mv -f "$dst.ss-new" "$dst"; } ||
		die "cannot install $dst"
	m_set "$kind" "$rel" "$(sha "$dst")"
}

# ---------------------------------------------------------------------------
# Boot environment (shared by preflight, install-kernel, verify, uninstall)
# ---------------------------------------------------------------------------
boot_method() { if [ -d "$SS_ROOT/sys/firmware/efi" ]; then echo UEFI; else echo BIOS; fi; }

# enabled | disabled | unknown (BIOS boots report disabled)
secure_boot_state() {
	if [ "$(boot_method)" = BIOS ]; then echo disabled; return; fi
	local f
	f="$(find "$SS_ROOT/sys/firmware/efi/efivars" -maxdepth 1 -name 'SecureBoot-*' 2>/dev/null | head -1 || true)"
	if [ -n "$f" ]; then
		# 4 attribute bytes, then the value
		if [ "$(od -An -tu1 -j4 -N1 "$f" 2>/dev/null | tr -d ' ')" = 1 ]; then echo enabled; else echo disabled; fi
	elif [ -z "$SS_ROOT" ] && command -v mokutil >/dev/null 2>&1; then
		case "$(mokutil --sb-state 2>/dev/null)" in
			*enabled*) echo enabled ;; *disabled*) echo disabled ;; *) echo unknown ;;
		esac
	else
		echo unknown
	fi
}

# Is the certificate (PEM or DER) an enrolled MOK? mokutil wants DER.
mok_enrolled() {
	local der; der="$(mktemp)"
	openssl x509 -in "$1" -outform DER -out "$der" 2>/dev/null || cp "$1" "$der"
	if mokutil --test-key "$der" 2>/dev/null | grep -q 'already enrolled'; then rm -f "$der"; return 0; fi
	rm -f "$der"; return 1
}

grub_cfg() {
	local f
	for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
		[ -f "$SS_ROOT$f" ] && { echo "$SS_ROOT$f"; return 0; }
	done
	return 1
}
bootloader() {
	if grub_cfg >/dev/null; then echo grub
	elif [ -z "$SS_ROOT" ] && command -v bootctl >/dev/null 2>&1 && bootctl is-installed >/dev/null 2>&1; then echo systemd-boot
	else echo unknown; fi
}
grub_tool() { # reboot | set-default | editenv | mkconfig
	local t
	for t in "grub-$1" "grub2-$1"; do command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }; done
	return 1
}
# The effective GRUB_DEFAULT: /etc/default/grub, then grub.d/*.cfg in order.
grub_default() {
	(
		GRUB_DEFAULT=0
		# shellcheck disable=SC1090,SC1091
		[ -f "$SS_ROOT/etc/default/grub" ] && . "$SS_ROOT/etc/default/grub"
		for f in "$SS_ROOT"/etc/default/grub.d/*.cfg; do
			# shellcheck disable=SC1090
			[ -f "$f" ] && . "$f"
		done
		echo "$GRUB_DEFAULT"
	) 2>/dev/null
}

# grub_entry RELEASE: the menu path grub-reboot/grub-set-default take for the
# normal (non-recovery) entry of RELEASE: "submenu-id>entry-id", or a BLS id.
grub_entry() {
	local rel="$1" cfg bls
	bls="$(find "$SS_ROOT/boot/loader/entries" -maxdepth 1 -name "*-$rel.conf" 2>/dev/null | head -1 || true)"
	if [ -n "$bls" ]; then basename "$bls" .conf; return 0; fi
	cfg="$(grub_cfg)" || return 1
	awk -v rel="$rel" -v q="'" '
		function id(line,   i, rest, j) {
			i = index(line, "$menuentry_id_option ")
			if (!i) return ""
			rest = substr(line, i + 21)
			sub(/^ +/, "", rest)
			if (substr(rest, 1, 1) != q) return ""
			rest = substr(rest, 2); j = index(rest, q)
			return j ? substr(rest, 1, j - 1) : ""
		}
		/^[[:space:]]*submenu / { sub_id = id($0); insub = 1; next }
		/^}/ { insub = 0; next }
		/^[[:space:]]*menuentry / {
			e = id($0)
			if (index(e, "gnulinux-" rel "-advanced-") == 1) {
				print (insub && sub_id != "" ? sub_id ">" : "") e; found = 1; exit
			}
		}
		END { exit !found }' "$cfg"
}
# Is RELEASE in the generated boot menu?
boot_entry_present() {
	local rel="$1" cfg
	if find "$SS_ROOT/boot/loader/entries" -maxdepth 1 -name "*-$rel.conf" 2>/dev/null | grep -q .; then return 0; fi
	cfg="$(grub_cfg)" || return 1
	grep -qE "vmlinuz-${rel//./\\.}([[:space:]]|$)" "$cfg"
}
grub_next_entry() { local t; t="$(grub_tool editenv)" || return 1; "$t" - list 2>/dev/null | sed -n 's/^next_entry=//p'; }
# grub_env KEY: a value from the grubenv block next to grub.cfg (no tool, so
# it reads $SS_ROOT too).
grub_env() {
	local cfg; cfg="$(grub_cfg)" || return 0
	[ -f "$(dirname "$cfg")/grubenv" ] || return 0
	sed -n "s/^$1=//p" "$(dirname "$cfg")/grubenv"
}
# Does grub.cfg set a GRUB superuser (STIG grub2_password)? Then every entry
# and submenu without --unrestricted needs that password to boot.
grub_has_password() {
	local cfg; cfg="$(grub_cfg)" || return 1
	grep -q '^[[:space:]]*set superusers=' "$cfg"
}
# grub_entry_open ENTRY: can GRUB boot ENTRY ("submenu-id>entry-id" or
# "entry-id") without the password? 0 yes, 1 no (it or its submenu lacks
# --unrestricted), 2 not in grub.cfg.
grub_entry_open() {
	local cfg; cfg="$(grub_cfg)" || return 2
	awk -v want="$1" -v q="'" '
		function id(line,   i, rest, j) {
			i = index(line, "$menuentry_id_option ")
			if (!i) return ""
			rest = substr(line, i + 21)
			sub(/^ +/, "", rest)
			if (substr(rest, 1, 1) != q) return ""
			rest = substr(rest, 2); j = index(rest, q)
			return j ? substr(rest, 1, j - 1) : ""
		}
		function unr(line) { return line ~ /[[:space:]]--unrestricted[[:space:]]/ }
		BEGIN { n = split(want, p, ">"); r = 2 }
		/^[[:space:]]*submenu / { insub = 1; want_sub = (n == 2 && id($0) == p[1]); sub_open = unr($0); next }
		/^}/ { insub = 0; next }
		/^[[:space:]]*menuentry / {
			if (n == 1 && !insub && id($0) == p[1]) { r = !unr($0); exit }
			if (n == 2 && insub && want_sub && id($0) == p[2]) { r = !(sub_open && unr($0)); exit }
		}
		END { exit r }' "$cfg"
}
# The drop-in install.sh keeps on the Debian family (update-grub). Ubuntu's
# 10_linux writes its "Advanced options" submenu without the entries' CLASS,
# so without --unrestricted: with a GRUB password (STIG grub2_password) a
# default or one-shot entry inside it waits for the password at every boot.
# GRUB_DISABLE_SUBMENU puts every kernel at the top level instead.
grub_dropin_text() {
	printf '%s\n' \
		'# Written by secure_sudo install.sh: keep the known-good kernel the' \
		'# default and boot new kernels once (grub-reboot). Every kernel is at' \
		'# the top level of the menu, so a GRUB password (with --unrestricted' \
		'# entries) does not stop the boot at a submenu. Removed by uninstall.' \
		'GRUB_DEFAULT=saved' \
		'GRUB_DISABLE_SUBMENU=true'
}
# Is the drop-in missing or older than this version's?
grub_dropin_stale() {
	[ -f "$SS_ROOT$GRUB_DROPIN" ] || return 0
	[ "$(grub_dropin_text | sha256sum | cut -d' ' -f1)" != "$(sha "$SS_ROOT$GRUB_DROPIN")" ]
}

update_bootloader() {
	case "$(bootloader)" in
	grub)
		if command -v update-grub >/dev/null 2>&1; then
			update-grub || die "update-grub FAILED. grub-mkconfig only replaces grub.cfg when it succeeds, so the previous boot menu is unchanged; fix the error above and rerun."
		else
			local t; t="$(grub_tool mkconfig)" || die "no grub-mkconfig/grub2-mkconfig found"
			"$t" -o "$(grub_cfg)" || die "$t FAILED; the previous grub.cfg is unchanged; fix the error above and rerun."
		fi ;;
	systemd-boot)
		log "systemd-boot: entries are written by kernel-install; nothing to regenerate" ;;
	*)
		warn "unknown bootloader: add an entry for the new kernel yourself and keep the old one" ;;
	esac
}

running_ours() { m_list K | awk -F'\t' -v r="$(uname -r)" '$2==r {f=1} END {exit !f}'; }

# ---------------------------------------------------------------------------
# Preflight: report everything, change nothing.
# ---------------------------------------------------------------------------
PF_BLOCK=0
pf()  { printf '  %-16s %s\n' "$1" "$2"; }
pfb() { pf "$1" "BLOCKED: $2"; PF_BLOCK=$((PF_BLOCK + 1)); }
pfw() { pf "$1" "warning: $2"; }
free_mb() { # free MiB on the filesystem holding PATH (or its nearest parent)
	local d="$1"
	while [ ! -d "$d" ] && [ "$d" != / ]; do d="$(dirname "$d")"; done
	df -Pm "$d" 2>/dev/null | awk 'NR==2 {print $4}'
}

preflight() { # WHAT: all | build-kernel | install-kernel | userspace [--prebuilt DIR]
	local what="${1:-all}" t miss=() need=(sha256sum awk) sb bl gd prebuilt=""
	[ "${2:-}" = --prebuilt ] && prebuilt="${3:?--prebuilt DIR}"
	PF_BLOCK=0
	case "$what" in all|build-kernel|install-kernel|userspace) ;; *) die "preflight: unknown step $what" ;; esac
	echo "secure_sudo $SS_VERSION preflight ($what): nothing is changed"
	echo "system"
	if detect_distro; then pf distro "$OS_ID $OS_VER (family $FAMILY)"
	else pfb distro "$OS_ID $OS_VER is not a supported family (debian, fedora, suse, arch)"; fi
	case "$OS_ID $OS_VER" in "ubuntu 24.04") ;;
	*) pfw tested "only Ubuntu 24.04 has been installed and rolled back in a VM; others are untested" ;; esac
	[ "$(uname -m)" = x86_64 ] || pfw arch "$(uname -m): only x86_64 is built and tested"
	pf "running kernel" "$(uname -r)$(running_ours && echo ' (secure_sudo)')"
	if [ -s "$MANIFEST" ]; then pf installed "secure_sudo $(m_get V version || echo '?') (this run upgrades it)"
	else pf installed "nothing yet"; fi
	if [ "$(id -u)" -ne 0 ] && [ -z "$SS_ROOT" ]; then pfb user "not root"; fi

	echo "boot"
	pf "boot method" "$(boot_method)"
	bl="$(bootloader)"; pf bootloader "$bl"
	sb="$(secure_boot_state)"; pf "secure boot" "$sb"
	case "$what" in all|install-kernel)
		[ "$bl" = unknown ] && pfw bootloader "no GRUB or systemd-boot found; the new kernel will need a manual boot entry"
		if [ "$sb" = enabled ]; then
			if [ -z "${SS_SB_KEY:-}" ] || [ -z "${SS_SB_CERT:-}" ]; then
				pfb "secure boot" "a self-built kernel is not signed by a key shim trusts and would not boot; set SS_SB_KEY/SS_SB_CERT to an enrolled MOK key pair (docs/RECOVERY.md)"
			elif ! command -v sbsign >/dev/null 2>&1; then
				pfb "secure boot" "sbsign not installed (sbsigntool)"
			elif command -v mokutil >/dev/null 2>&1 && ! mok_enrolled "$SS_SB_CERT"; then
				pfb "secure boot" "$SS_SB_CERT is not enrolled: mokutil --import $SS_SB_CERT, reboot, enroll it, rerun"
			else
				pf "secure boot" "kernel will be signed with $SS_SB_CERT"
			fi
		fi
		if [ "$bl" = grub ]; then
			gd="$(grub_default)"
			if [ "$SS_TRIAL_BOOT" = 0 ]; then
				pfw "trial boot" "off (SS_TRIAL_BOOT=0): the new kernel becomes the default at once"
			elif [ "$gd" = saved ] || [ "$FAMILY" = debian ]; then
				pf "trial boot" "yes: $(uname -r) stays the default, the new kernel boots once"
			else
				pfw "trial boot" "GRUB_DEFAULT=$gd (not 'saved'): the new kernel becomes the default at once"
			fi
		fi
		t="$(free_mb "$SS_ROOT/boot")"
		if [ -n "$t" ] && [ "$t" -lt 200 ]; then pfb "/boot space" "${t} MB free, need 200"
		else pf "/boot space" "${t:-?} MB free"; fi
		if command -v dkms >/dev/null 2>&1 && dkms status 2>/dev/null | grep -q .; then
			pfw "dkms" "$(dkms status 2>/dev/null | wc -l) module(s); the new kernel enforces module signatures, so unsigned out-of-tree modules will not load there"
		fi ;;
	esac
	case "$what" in all|build-kernel)
		t="$(free_mb "$BUILD_ROOT")"
		if [ -n "$t" ] && [ "$t" -lt 20000 ]; then pfb "build space" "${t} MB free at $BUILD_ROOT, need about 20000"
		else pf "build space" "${t:-?} MB free at $BUILD_ROOT"; fi
		if [ -n "${SS_KERNEL_TREE:-}" ]; then
			pf "kernel source" "$SS_KERNEL_TREE (provenance: ${SS_KERNEL_TREE_PROVENANCE:-MISSING})"
			if [ ! -f "${SS_KERNEL_TREE_PROVENANCE:-/nonexistent}" ]; then pfb "kernel source" "SS_KERNEL_TREE needs SS_KERNEL_TREE_PROVENANCE"; fi
		else
			pf "kernel source" "linux-$KVER from cdn.kernel.org, verified against $KEYDIR before extraction"
		fi
		pf "base config" "${SS_BASE_CONFIG:-/boot/config-$(uname -r)}"
		if [ -n "${SS_LOCALMOD:-}" ]; then pfw "localmodconfig" "only modules listed in $SS_LOCALMOD are built"; fi ;;
	esac

	echo "tools"
	case "$what" in all|build-kernel) need+=(make gcc curl gpg bison flex bc) ;; userspace) [ -n "$prebuilt" ] || need+=(make gcc) ;; esac
	case "$what:$FAMILY" in
		all:debian|install-kernel:debian) need+=(dpkg dpkg-deb) ;;
		all:fedora|install-kernel:fedora|all:suse|install-kernel:suse) need+=(rpm) ;;
	esac
	for t in "${need[@]}"; do command -v "$t" >/dev/null 2>&1 || miss+=("$t"); done
	if [ "${#miss[@]}" -eq 0 ]; then pf missing none
	elif [ "$what" = all ]; then pf missing "${miss[*]} (installed by the dependency step)"
	else pfb missing "${miss[*]}"; fi

	echo "changes"
	case "$what" in all|build-kernel)
		pf kernel "build linux-$(if [ -n "${SS_KERNEL_TREE:-}" ]; then make -s -C "$SS_KERNEL_TREE" kernelversion 2>/dev/null; else echo "$KVER"; fi)$LOCALVERSION packages into $OUT_DIR (secure_sudo in CONFIG_LSM, module signatures enforced, reboot ${SS_PANIC_TIMEOUT}s after a panic)" ;;
	esac
	case "$what" in all|install-kernel)
		pf kernel "install it next to $(uname -r), which stays installed and in the boot menu"
		if [ "$FAMILY" = debian ] && [ "$SS_TRIAL_BOOT" != 0 ] && grub_dropin_stale; then
			pf bootloader "write $GRUB_DROPIN (GRUB_DEFAULT=saved, every kernel at the top level of the menu), regenerate the menu"
		else
			pf bootloader "regenerate the menu"
		fi ;;
	esac
	case "$what" in all|userspace)
		if [ -n "$prebuilt" ]; then
			if [ -f "$prebuilt/.secure-sudo-stage" ]; then pf prebuilt "$prebuilt (made by stage-userspace; nothing is compiled here)"
			else pfb prebuilt "$prebuilt is not a stage-userspace directory"; fi
		fi
		pf files "secure-sudo, secure-sudod, secure-sudo-otp, secure-sudo-pheonixbox, PAM modules in $SECDIR, /usr/libexec/secure-sudo/*, secure-sudod.service (enabled)"
		pf config "/etc/secure_sudo/*.conf where missing (existing files are kept)"
		if [ -z "$SS_ROOT" ]; then
			t="$(runtime_missing | tr '\n' ' ')"
			if [ -n "$t" ]; then pf packages "install ${t% } from the distro (left installed by uninstall)"
			else pf packages "runtime packages already installed"; fi
		fi
		pf pam "nothing: wiring PAM is left to you (guidance at the end)" ;;
	esac
	t="$(grep -lE "$PAM_RE" "$SS_ROOT"/etc/pam.d/* 2>/dev/null | tr '\n' ' ' || true)"
	if [ -n "$t" ]; then pf "pam uses it" "$t"; fi
	if [ "$PF_BLOCK" -eq 0 ]; then echo "preflight: OK"; else echo "preflight: $PF_BLOCK blocking problem(s)"; fi
	return "$PF_BLOCK"
}

# ---------------------------------------------------------------------------
# Kernel build
# ---------------------------------------------------------------------------
# The archive is verified against its kernel.org signature and the pinned
# signer list (install/keys/) BEFORE tar ever sees it; any failure stops the
# install (TODO P0-4). For offline installs point KERNEL_TARBALL and
# KERNEL_SIGNATURE at local copies; they are verified the same way.
KTREE=""
fetch_kernel() {
	mkdir -p "$BUILD_ROOT" "$META_DIR"; chmod 700 "$BUILD_ROOT"
	cd "$BUILD_ROOT"
	local name="linux-$KVER.tar.xz"
	local tar="${KERNEL_TARBALL:-$BUILD_ROOT/$name}"
	local sig="${KERNEL_SIGNATURE:-$BUILD_ROOT/linux-$KVER.tar.sign}"
	local url="https://cdn.kernel.org/pub/linux/kernel/v${KMAJOR}.x"
	if [ ! -f "$tar" ]; then
		log "downloading kernel $KVER"
		curl -fL --proto '=https' -o "$tar.part" "$url/$name" ||
			die "download of $name failed"
		mv "$tar.part" "$tar"
	fi
	if [ ! -f "$sig" ]; then
		log "downloading signature for $KVER"
		curl -fL --proto '=https' -o "$sig.part" "$url/linux-$KVER.tar.sign" ||
			die "no signature for $name; refusing to build unverified source"
		mv "$sig.part" "$sig"
	fi

	log "verifying $name against the pinned kernel.org signers"
	bash "$ROOT/scripts/verify-kernel-source.sh" --keys "$KEYDIR" --fetch-missing \
		--metadata "$META_DIR/kernel-source.txt" "$tar" "$sig" ||
		die "kernel source verification FAILED; nothing was extracted"

	local sha marker="$BUILD_ROOT/linux-$KVER/.secure_sudo-source-sha256"
	sha="$(sed -n 's/^archive_sha256=//p' "$META_DIR/kernel-source.txt")"
	if [ -d "linux-$KVER" ] && [ "$(cat "$marker" 2>/dev/null)" != "$sha" ]; then
		warn "existing linux-$KVER tree does not match the verified archive; re-extracting"
		rm -rf "linux-$KVER"
	fi
	if [ ! -d "linux-$KVER" ]; then
		log "extracting verified $name"
		tar --no-same-owner -xf "$tar" || die "extraction failed"
		[ -d "linux-$KVER" ] || die "archive did not contain linux-$KVER/"
		printf '%s\n' "$sha" > "$marker"
	fi
	KTREE="$BUILD_ROOT/linux-$KVER"
}

# A source tree verified some other way (an offline mirror, a distro source
# package checked through its signed archive). Its provenance record is
# required, and becomes the build's kernel-source.txt.
use_kernel_tree() {
	[ -f "$SS_KERNEL_TREE/Makefile" ] || die "SS_KERNEL_TREE=$SS_KERNEL_TREE is not a kernel tree"
	[ -s "${SS_KERNEL_TREE_PROVENANCE:-}" ] ||
		die "SS_KERNEL_TREE needs SS_KERNEL_TREE_PROVENANCE: a record of how the tree was verified"
	grep -q '^verified_by=' "$SS_KERNEL_TREE_PROVENANCE" ||
		die "$SS_KERNEL_TREE_PROVENANCE has no verified_by= line"
	mkdir -p "$BUILD_ROOT" "$META_DIR"; chmod 700 "$BUILD_ROOT"
	cp "$SS_KERNEL_TREE_PROVENANCE" "$META_DIR/kernel-source.txt"
	KTREE="$(cd "$SS_KERNEL_TREE" && pwd)"
	log "using pre-verified kernel tree $KTREE"
}

graft_lsm() {
	log "grafting secure_sudo into $KTREE/security"
	bash "$ROOT/ci/graft-lsm.sh" "$KTREE" || die "could not graft the LSM"
}

configure_kernel() {
	cd "$KTREE"
	log "configuring kernel"
	# Start from the running kernel's config if we can, else a sane default.
	if [ -n "${SS_BASE_CONFIG:-}" ]; then
		cp "$SS_BASE_CONFIG" .config
	elif [ -f "/boot/config-$(uname -r)" ]; then
		cp "/boot/config-$(uname -r)" .config
	elif [ -f /proc/config.gz ]; then
		zcat /proc/config.gz > .config
	else
		make defconfig
	fi

	# Clear any distro signing keys that we can't reproduce; we sign ourselves.
	./scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
	./scripts/config --set-str SYSTEM_REVOCATION_KEYS ""

	./scripts/config --enable SECURITY
	./scripts/config --enable SECURITY_NETWORK
	./scripts/config --enable SECURITY_SECURE_SUDO
	./scripts/config --enable MODULE_SIG
	./scripts/config --enable MODULE_SIG_ALL
	# Enforced in this kernel only, so the previous kernel boots exactly as
	# before (module.sig_enforce=1 on the shared GRUB command line, as <= 0.11
	# did, also stopped the old kernel's unsigned DKMS modules).
	./scripts/config --enable MODULE_SIG_FORCE
	./scripts/config --enable TCG_TPM
	./scripts/config --set-str LOCALVERSION "$LOCALVERSION"
	./scripts/config --disable LOCALVERSION_AUTO
	# A kernel that panics must come back, so a trial boot falls back to the
	# previous kernel instead of sitting on the panic screen.
	local pt; pt="$(./scripts/config --state PANIC_TIMEOUT)"
	if [ "$SS_PANIC_TIMEOUT" != 0 ] && { [ "$pt" = 0 ] || [ "$pt" = undef ]; }; then
		./scripts/config --set-val PANIC_TIMEOUT "$SS_PANIC_TIMEOUT"
	fi

	# Add secure_sudo to the active LSM list: just before bpf if bpf is
	# listed (so BPF-LSM programs still see the final decision), else last.
	local cur
	cur="$(./scripts/config --state CONFIG_LSM 2>/dev/null || true)"
	if [ -z "$cur" ] || [ "$cur" = "undef" ]; then
		cur="landlock,lockdown,yama,loadpin,safesetid,integrity,bpf"
	fi
	case ",$cur," in
		*,secure_sudo,*) : ;;
		*,bpf,*) cur="$(printf ',%s,' "$cur" | sed 's/,bpf,/,secure_sudo,bpf,/; s/^,//; s/,$//')" ;;
		*) cur="$cur,secure_sudo" ;;
	esac
	./scripts/config --set-str CONFIG_LSM "$cur"
	log "CONFIG_LSM = $cur"

	make olddefconfig
	if [ -n "${SS_LOCALMOD:-}" ]; then
		log "localmodconfig from $SS_LOCALMOD"
		{ yes '' || true; } | make LSMOD="$SS_LOCALMOD" localmodconfig >/dev/null	# yes dies of SIGPIPE
		# localmodconfig keeps only the modules loaded when the list was taken.
		# A host whose firewall is not up yet (a fresh install, before STIG
		# hardening turns ufw on) loses the netfilter modules: in the STIG VM,
		# ufw then could not start (no conntrack, nft_compat or xt matches).
		# The firewall stack ufw and secure_sudo's nft network modes use is
		# always kept. ufw 0.36 (Ubuntu 24.04) uses the matches conntrack,
		# addrtype, comment, hl, limit, multiport, recent and rt, and the
		# targets LOG and REJECT; one missing match fails the whole
		# ip(6)tables-restore and leaves ufw half-applied.
		local m
		for m in NETFILTER_ADVANCED NF_CONNTRACK NF_TABLES NF_TABLES_INET NF_TABLES_IPV4 \
			NF_TABLES_IPV6 NFT_CT NFT_LOG NFT_LIMIT NFT_REJECT NFT_COMPAT NETFILTER_XTABLES \
			NETFILTER_XT_MATCH_ADDRTYPE NETFILTER_XT_MATCH_COMMENT NETFILTER_XT_MATCH_CONNTRACK \
			NETFILTER_XT_MATCH_HL NETFILTER_XT_MATCH_LIMIT NETFILTER_XT_MATCH_MULTIPORT \
			NETFILTER_XT_MATCH_RECENT \
			NETFILTER_XT_TARGET_LOG NF_LOG_SYSLOG IP_NF_IPTABLES IP_NF_FILTER IP_NF_TARGET_REJECT \
			IP6_NF_IPTABLES IP6_NF_FILTER IP6_NF_TARGET_REJECT IP6_NF_MATCH_IPV6HEADER IP6_NF_MATCH_RT; do
			[ "$(./scripts/config --state "$m")" = y ] || ./scripts/config --module "$m"
		done
		make olddefconfig
		for m in NF_CONNTRACK NFT_COMPAT NETFILTER_XT_MATCH_CONNTRACK NETFILTER_XT_MATCH_HL \
			 NETFILTER_XT_MATCH_RECENT IP_NF_IPTABLES IP6_NF_IPTABLES; do
			grep -qE "^CONFIG_$m=[ym]$" .config || die "CONFIG_$m did not stick after localmodconfig (the firewall would not start)"
		done
	fi
	local want
	for want in CONFIG_SECURITY_SECURE_SUDO=y CONFIG_MODULE_SIG_FORCE=y "CONFIG_LOCALVERSION=\"$LOCALVERSION\""; do
		grep -qxF "$want" .config || die "$want did not stick after olddefconfig"
	done
	grep -q '^CONFIG_LSM=".*secure_sudo' .config || die "secure_sudo is not in CONFIG_LSM"
	cp .config "$META_DIR/kernel.config"
}

# Fixed build identity so a rebuild from the recorded inputs produces the same
# kernel (module signatures excepted: the signing key is generated per build).
reproducible_env() {
	local epoch
	epoch="$(sed -n 's/^signature_epoch=//p' "$META_DIR/kernel-source.txt" 2>/dev/null || true)"
	export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-${epoch:-0}}"
	export KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP:-@$SOURCE_DATE_EPOCH}"
	export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-secure_sudo}"
	export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-build}"
}

# Record the inputs needed to rebuild this kernel, plus an SPDX SBOM, next to
# the packages so they travel with them.
record_build_metadata() { # outdir
	local out="$1"
	{
		cat "$META_DIR/kernel-source.txt"
		echo "kernel_config_sha256=$(sha "$META_DIR/kernel.config")"
		echo "config_lsm=$(sed -n 's/^CONFIG_LSM=//p' "$META_DIR/kernel.config")"
		echo "secure_sudo_version=$SS_VERSION"
		echo "secure_sudo_tree_sha256=$(bash "$ROOT/scripts/gen-sbom.sh" --tree-hash)"
		echo "source_date_epoch=$SOURCE_DATE_EPOCH"
		echo "kbuild_build_timestamp=$KBUILD_BUILD_TIMESTAMP"
		echo "kbuild_build_user=$KBUILD_BUILD_USER"
		echo "kbuild_build_host=$KBUILD_BUILD_HOST"
		echo "kernel_release_built=$(cat "$KTREE/include/config/kernel.release" 2>/dev/null || echo unknown)"
		echo "cc=$(gcc --version | head -1)"
		echo "ld=$(ld --version | head -1)"
		echo "make=$(make --version | head -1)"
		echo "pahole=$(pahole --version 2>/dev/null || echo none)"
		echo "openssl=$(openssl version 2>/dev/null || echo none)"
		# shellcheck disable=SC1091
		echo "distro=$(. /etc/os-release; echo "$ID $VERSION_ID")"
	} > "$out/build-info.txt"
	cp "$META_DIR/kernel-source.txt" "$META_DIR/kernel.config" "$out/"
	bash "$ROOT/scripts/gen-sbom.sh" --build-info "$out/build-info.txt" \
		--out "$out/secure_sudo.spdx.json" || warn "SBOM generation failed"
	(cd "$out" && sha256sum -- * > "$META_DIR/SHA256SUMS" && mv "$META_DIR/SHA256SUMS" SHA256SUMS)
}

build_kernel() {
	cd "$KTREE"
	local rel out f
	log "building kernel (-j$JOBS); this takes a while"
	make -j"$JOBS" prepare >/dev/null
	rel="$(make -s kernelrelease)"
	out="$OUT_DIR/$rel"
	rm -rf "$out"; mkdir -p "$out"
	case "$FAMILY" in
	debian)
		make -j"$JOBS" "$PKG_TARGET" || die "kernel build failed"
		for f in "$KTREE"/../linux-image-"$rel"_*.deb "$KTREE"/../linux-headers-"$rel"_*.deb \
			 "$KTREE"/../linux-image-"$rel"-dbg_*.deb; do
			[ -f "$f" ] && mv "$f" "$out/"
		done ;;
	fedora|suse)
		make -j"$JOBS" "$PKG_TARGET" || die "kernel build failed"
		find "$KTREE/rpmbuild/RPMS" "$HOME/rpmbuild/RPMS" -name "kernel-*.rpm" \
			-newer "$KTREE/.config" -exec mv {} "$out/" \; 2>/dev/null ;;
	arch)
		make -j"$JOBS" || die "kernel build failed"
		echo "$KTREE" > "$out/ARCH-TREE" ;;
	esac
	[ -n "$(find "$out" -mindepth 1 -maxdepth 1)" ] || die "no kernel package was produced in $out"
	record_build_metadata "$out"
	log "kernel $rel built: $out"
	BUILT_DIR="$out"
}

# ---------------------------------------------------------------------------
# Kernel install
# ---------------------------------------------------------------------------
# Signed whenever a MOK pair is given (so Secure Boot can be switched on
# later), and required when Secure Boot is on (preflight blocks without it).
sign_kernel() { # release
	local img="/boot/vmlinuz-$1"
	if [ -z "${SS_SB_KEY:-}" ] || [ -z "${SS_SB_CERT:-}" ]; then
		[ "$(secure_boot_state)" != enabled ] || die "Secure Boot is on and no SS_SB_KEY/SS_SB_CERT: $img would not boot"
		return 0
	fi
	log "signing $img with $SS_SB_CERT"
	sbsign --key "$SS_SB_KEY" --cert "$SS_SB_CERT" --output "$img.signed" "$img" ||
		die "sbsign failed; $img is unsigned and would not boot with Secure Boot"
	mv -f "$img.signed" "$img"
	sbverify --cert "$SS_SB_CERT" "$img" >/dev/null || die "signature check of $img failed"
}

arrange_trial_boot() { # release previous
	local rel="$1" prev="$2" new_e prev_e
	[ "$(bootloader)" = grub ] || { warn "not GRUB: no trial boot; whether $rel boots by default is up to $(bootloader)"; return 0; }
	if [ "$SS_TRIAL_BOOT" = 0 ]; then
		log "SS_TRIAL_BOOT=0: the new kernel becomes the default as your distro decides"
		return 0
	fi
	if [ "$FAMILY" = debian ] && grub_dropin_stale; then
		local tmp want
		want="$(m_get F "$GRUB_DROPIN" 2>/dev/null || true)"
		if [ -f "$SS_ROOT$GRUB_DROPIN" ] && [ -n "$want" ] && [ "$(sha "$SS_ROOT$GRUB_DROPIN")" != "$want" ]; then
			warn "$GRUB_DROPIN was changed since install.sh wrote it; leaving it as it is"
		else
			# New, or the one an older version wrote (GRUB_DEFAULT=saved only).
			tmp="$(mktemp)"; grub_dropin_text > "$tmp"
			install_file "$tmp" "$GRUB_DROPIN" 0644; rm -f "$tmp"
			update_bootloader
		fi
	fi
	if [ "$(grub_default)" != saved ]; then
		warn "GRUB_DEFAULT is '$(grub_default)', not 'saved': no trial boot; the new kernel will boot by default"
		return 0
	fi
	new_e="$(grub_entry "$rel")" || die "no GRUB entry found for $rel after regenerating the menu"
	prev_e="$(grub_entry "$prev")" || die "no GRUB entry found for the running kernel $prev; refusing to continue without a known-good entry"
	"$(grub_tool set-default)" "$prev_e" || die "grub-set-default failed"
	"$(grub_tool reboot)" "$new_e" || die "grub-reboot failed"
	m_set T "$rel" trial
	log "trial boot armed: the next boot (only) runs $rel; $prev stays the default."
	log "after it boots, run: install.sh verify --commit"
}

install_kernel() { # [DIR|PKG...]
	local pkgs=() f p prev rel="" name
	[ -z "$SS_ROOT" ] || die "install-kernel cannot run with SS_ROOT"
	preflight install-kernel || die "preflight found blocking problems (above); nothing was changed"
	if [ $# -eq 0 ]; then
		set -- "${BUILT_DIR:-$(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1)}"
	fi
	for f in "$@"; do
		if [ -d "$f" ]; then
			if [ -f "$f/SHA256SUMS" ]; then
				(cd "$f" && sha256sum -c --quiet SHA256SUMS) || die "$f/SHA256SUMS does not match: refusing modified packages"
			fi
			for p in "$f"/*; do pkgs+=("$p"); done
		else pkgs+=("$f"); fi
	done
	m_init
	prev="$(uname -r)"		# it booted this system, so it boots
	running_ours || m_set P known-good "$prev"
	m_set V version "$SS_VERSION"
	case "$FAMILY" in
	debian)
		local debs=()
		for f in "${pkgs[@]}"; do
			case "$(basename "$f")" in
				linux-image-*-dbg_*.deb) ;;
				linux-image-*.deb|linux-headers-*.deb) debs+=("$f") ;;
			esac
		done
		[ "${#debs[@]}" -gt 0 ] || die "no linux-image/linux-headers .deb given"
		for f in "${debs[@]}"; do
			name="$(dpkg-deb -f "$f" Package)"
			case "$name" in linux-image-*) rel="${name#linux-image-}" ;; esac
		done
		[ -n "$rel" ] || die "no linux-image package among: ${debs[*]}"
		case "$rel" in *"$LOCALVERSION") ;; *) die "$rel is not a secure_sudo kernel (no $LOCALVERSION suffix)" ;; esac
		[ "$rel" != "$prev" ] || die "$rel is the running kernel; boot another kernel to replace it"
		for f in "${debs[@]}"; do m_set K "$(dpkg-deb -f "$f" Package)" "$rel"; done
		log "installing ${debs[*]##*/}"
		dpkg -i "${debs[@]}" ||
			die "dpkg -i FAILED. $prev is untouched and still the default. Finish or undo with: dpkg --configure -a  (or: install.sh uninstall)" ;;
	fedora|suse)
		local rpms=()
		for f in "${pkgs[@]}"; do
			case "$(basename "$f")" in kernel-headers-*) ;; kernel-*.rpm) rpms+=("$f") ;; esac
		done
		[ "${#rpms[@]}" -gt 0 ] || die "no kernel .rpm given"
		for f in "${rpms[@]}"; do
			if [ "$(rpm -qp --qf '%{NAME}' "$f")" = kernel ]; then
				rel="$(rpm -qpl "$f" | sed -n 's|^/lib/modules/\([^/]*\)/.*|\1|p' | head -1 || true)"
			fi
		done
		[ -n "$rel" ] || die "no kernel package among: ${rpms[*]}"
		[ "$rel" != "$prev" ] || die "$rel is the running kernel; boot another kernel to replace it"
		for f in "${rpms[@]}"; do m_set K "$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}' "$f")" "$rel"; done
		rpm -ivh "${rpms[@]}" || die "rpm -i FAILED. $prev is untouched. Clean up with: install.sh uninstall" ;;
	arch)
		local tree; tree="$(cat "$(dirname "${pkgs[0]}")/ARCH-TREE" 2>/dev/null)" || die "Arch installs need the build tree (ARCH-TREE)"
		rel="$(make -s -C "$tree" kernelrelease)"
		m_set K "arch:$rel" "$rel"
		make -C "$tree" modules_install || die "modules_install failed"
		install -m0644 "$tree/arch/x86/boot/bzImage" "/boot/vmlinuz-$rel"
		install -m0644 "$tree/System.map" "/boot/System.map-$rel"
		install -m0644 "$tree/.config" "/boot/config-$rel"
		mkinitcpio -k "$rel" -g "/boot/initramfs-$rel.img" || die "mkinitcpio failed"
		warn "Arch: add a boot entry for /boot/vmlinuz-$rel and keep the one for $prev" ;;
	esac
	sign_kernel "$rel"
	update_bootloader
	if [ "$(bootloader)" != unknown ]; then
		boot_entry_present "$rel" || die "the boot menu has no entry for $rel after regenerating it"
		boot_entry_present "$prev" || die "the boot menu LOST the running kernel $prev; do not reboot; see docs/RECOVERY.md"
		log "boot menu has $rel and the known-good $prev"
	fi
	arrange_trial_boot "$rel" "$prev"
	# The build record travels with the packages; keep it with the kernel.
	local d; d="$(dirname "${pkgs[0]}")"
	for f in build-info.txt kernel-source.txt kernel.config secure_sudo.spdx.json; do
		if [ -f "$d/$f" ]; then install_file "$d/$f" "/usr/share/doc/secure-sudo/build/$rel/$f" 0644; fi
	done
	return 0
}

# ---------------------------------------------------------------------------
# Userspace
# ---------------------------------------------------------------------------
stage_userspace() { # DIR
	local s f
	s="$(mkdir -p "$1" && cd "$1" && pwd)"
	log "building userspace into $s"
	make -C "$US_SRC/cli" DESTDIR="$s" install
	make -C "$US_SRC/pam" SECDIR="$SECDIR" DESTDIR="$s" install
	make -C "$US_SRC/daemon" DESTDIR="$s" install
	make -C "$US_SRC/otp" DESTDIR="$s" install
	make -C "$US_SRC/pheonixbox" DESTDIR="$s" install
	# scripts/: standalone TimeVault allowlist tool + admin detector. The CLI
	# has both built in (secure-sudo vault-allow / detect-admins); these are
	# the dependency-free bash equivalents.
	for f in timevault-whitelist.sh detect-admin-gids.sh stig-harden.sh oscap-results.py; do
		install -D -m0755 "$ROOT/scripts/$f" "$s/usr/libexec/secure-sudo/$f"
	done
	install -D -m0644 "$LSM_SRC/INTEGRATION.md" "$s/usr/share/doc/secure-sudo/INTEGRATION.md"
	for f in "$US_SRC"/config/*.conf; do
		install -D -m0644 "$f" "$s/usr/share/secure-sudo/defaults/$(basename "$f")"
	done
	printf 'secure_sudo_version=%s\nfamily=%s\nsecdir=%s\n' "$SS_VERSION" "$FAMILY" "$SECDIR" > "$s/.secure-sudo-stage"
}

install_userspace() { # [prebuilt-dir]
	local stage="${1:-}" tmp="" rel f old placed fresh=0
	m_init
	if [ -z "$stage" ]; then
		tmp="$(mktemp -d)"; stage="$tmp"
		stage_userspace "$stage"
	fi
	stage="$(cd "$stage" && pwd)"
	[ -f "$stage/.secure-sudo-stage" ] || die "$stage is not a stage-userspace directory"
	grep -qx "family=$FAMILY" "$stage/.secure-sudo-stage" ||
		die "$stage was built for $(sed -n 's/^family=//p' "$stage/.secure-sudo-stage"), this is $FAMILY"
	grep -qx "secure_sudo_version=$SS_VERSION" "$stage/.secure-sudo-stage" ||
		warn "$stage is $(sed -n 's/^secure_sudo_version=//p' "$stage/.secure-sudo-stage"), the installer is $SS_VERSION"
	install_runtime_deps
	old="$(m_get V version 2>/dev/null || true)"
	if [ -n "$old" ] && [ "$old" != "$SS_VERSION" ]; then log "upgrading userspace $old -> $SS_VERSION"; fi
	m_set V version "$SS_VERSION"

	log "installing userspace files (recorded in ${MANIFEST#"$SS_ROOT"})"
	placed="$(mktemp)"
	while IFS= read -r rel; do
		install_file "$stage$rel" "$rel" "$(stat -c %a "$stage$rel")"
		echo "$rel" >> "$placed"
	done < <(cd "$stage" && find . -type f ! -name .secure-sudo-stage | sed 's|^\.||' | LC_ALL=C sort)
	# Files an older version installed that this one no longer ships.
	while IFS=$'\t' read -r rel f; do
		case "$rel" in /usr/share/doc/secure-sudo/build/*|"$GRUB_DROPIN") continue ;; esac
		grep -qxF "$rel" "$placed" && continue
		if [ -f "$SS_ROOT$rel" ] && [ "$(sha "$SS_ROOT$rel")" = "$f" ]; then
			rm -f "$SS_ROOT$rel"; m_del F "$rel"; log "removed obsolete $rel"
		fi
	done < <(m_list F)
	rm -f "$placed"

	log "installing config to /etc/secure_sudo"
	make_parents /etc/secure_sudo/x
	for f in "$stage"/usr/share/secure-sudo/defaults/*.conf; do
		rel="/etc/secure_sudo/$(basename "$f")"
		if [ ! -e "$SS_ROOT$rel" ]; then
			install_file "$f" "$rel" 0644 C
			[ "$(basename "$f")" = secure-sudo.conf ] && fresh=1
		fi
	done

	# Generate the uid->home map for #4 from /etc/passwd (regular users with
	# a real home), but only into the shipped, still empty file.
	rel=/etc/secure_sudo/home_map.conf
	if [ -n "$(m_get C "$rel" 2>/dev/null)" ] && [ "$(sha "$SS_ROOT$rel")" = "$(m_get C "$rel")" ] &&
	   ! grep -qvE '^\s*(#|$)' "$SS_ROOT$rel"; then
		{
			echo "# generated from /etc/passwd by install.sh"
			getent passwd | awk -F: '$3>=1000 && $6 ~ /^\/home\// {print $3" "$6}'
		} > "$SS_ROOT$rel"
		m_set C "$rel" "$(sha "$SS_ROOT$rel")"
		log "generated home_map.conf for $(grep -cvE '^\s*(#|$)' "$SS_ROOT$rel") user(s)"
	fi

	# Admin groups: written only into a secure-sudo.conf this run created, so
	# an upgrade never overrides an administrator's admin_gid.
	local gids conf=/etc/secure_sudo/secure-sudo.conf cur
	gids="$(detect_admin_gids || true)"
	cur="$(sed -n -E 's/^[[:space:]]*admin_gid[[:space:]]*=[[:space:]]*//p' "$SS_ROOT$conf" | tail -1)"
	if [ "$fresh" = 1 ] && [ -n "$gids" ]; then
		if grep -qE '^[[:space:]]*admin_gid[[:space:]]*=' "$SS_ROOT$conf"; then
			sed -i -E "s|^[[:space:]]*admin_gid[[:space:]]*=.*|admin_gid = $gids|" "$SS_ROOT$conf"
		else
			printf 'admin_gid = %s\n' "$gids" >> "$SS_ROOT$conf"
		fi
		m_set C "$conf" "$(sha "$SS_ROOT$conf")"
		log "admin_gid auto-detected: $gids"
	elif [ -z "$gids" ]; then
		warn "no admin groups found; only root will count as sudo (edit admin_gid in secure-sudo.conf)"
	elif [ "$cur" != "$gids" ]; then
		warn "admin_gid is '$cur' in $conf but this box's admin groups are $gids (yours is kept; check it)"
	fi

	f="$(unresolved_libs)"
	[ -z "$f" ] || die "installed programs cannot find shared libraries:$f. Install the distro packages that provide them, then rerun. (Nothing is wired into PAM yet.)"

	if [ -z "$SS_ROOT" ]; then
		systemctl daemon-reload || warn "systemctl daemon-reload failed"
		if systemctl enable secure-sudod.service; then m_set S secure-sudod.service enabled
		else warn "could not enable secure-sudod.service (no systemd?)"; fi
	fi
	if [ -n "$tmp" ]; then rm -rf "$tmp"; fi
	return 0
}

print_pam_guidance() {
	cat <<EOF

[secure_sudo] Userspace installed. PAM wiring is left to you ON PURPOSE so a
mistake can't lock you out. Keep a root shell open while you test, and test
from a second terminal with: sudo -k; sudo true

Cooldown feed (#8): add ONE line as the first auth line of /etc/pam.d/sudo
and /etc/pam.d/su, above "@include common-auth" / "auth include system-auth":

    auth  optional  pam_secure_sudo.so

It never changes the result; it reports each failed or successful attempt.

Rotating OTP (#14), as a second factor: run 'secure-sudo otp setup', check a
code with 'secure-sudo otp verify', THEN add right after the password include:

    auth  required  pam_secure_otp.so

'secure-sudo lint' checks the order of these lines. PAM modules are in: $SECDIR
Recovery from a bad PAM change or policy: docs/RECOVERY.md
EOF
}

# Optional DISA STIG hardening. OFF unless the operator opts in, because it
# rewrites PAM/password/banner/audit policy and must be done deliberately.
#   STIG=scan       -> scan only, write reports (recommended first pass)
#   STIG=remediate  -> scan, apply the generated fixes, re-scan
# Either way reports land in /var/log/secure_sudo/stig/. See docs/STIG.md.
run_stig_hardening() {
	case "${STIG:-}" in
	scan)
		log "running STIG scan (STIG=scan); reports -> /var/log/secure_sudo/stig"
		bash "$ROOT/scripts/stig-harden.sh" --scan || warn "STIG scan returned non-zero" ;;
	remediate)
		log "running STIG scan+remediate (STIG=remediate)"
		bash "$ROOT/scripts/stig-harden.sh" --remediate --yes || warn "STIG remediation returned non-zero" ;;
	""|no|off|0)
		log "skipping STIG hardening (set STIG=scan or STIG=remediate to enable)" ;;
	*)
		warn "unknown STIG='$STIG' (use scan|remediate); skipping" ;;
	esac
}

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
V_FAIL=0
vok()   { printf '  ok      %s\n' "$*"; }
vbad()  { printf '  FAIL    %s\n' "$*"; V_FAIL=$((V_FAIL + 1)); }
vnote() { printf '  note    %s\n' "$*"; }

verify() { # [--commit]
	local commit=0 rel name want prev cfg st m s running="" n=0
	[ "${1:-}" = --commit ] && commit=1
	V_FAIL=0
	[ -s "$MANIFEST" ] || die "nothing is installed by this script (no ${MANIFEST#"$SS_ROOT"})"
	echo "secure_sudo verify ($(m_get V version || echo '?'))"
	echo "files"
	while IFS=$'\t' read -r name want; do
		n=$((n + 1))
		if [ ! -f "$SS_ROOT$name" ]; then vbad "$name missing"
		elif [ "$(sha "$SS_ROOT$name")" != "$want" ]; then vbad "$name changed since install"; fi
	done < <(m_list F)
	if [ "$V_FAIL" -eq 0 ]; then vok "$n installed files present and unchanged"; fi
	s="$(unresolved_libs)"
	if [ -z "$s" ]; then vok "shared libraries resolve"; else vbad "missing shared libraries:$s"; fi
	while IFS=$'\t' read -r name want; do
		[ -f "$SS_ROOT$name" ] || vbad "$name missing"
	done < <(m_list C)

	prev="$(m_get P known-good 2>/dev/null || true)"
	while IFS= read -r rel; do
		[ -n "$rel" ] || continue
		echo "kernel $rel"
		cfg="$SS_ROOT/boot/config-$rel"
		if [ ! -f "$SS_ROOT/boot/vmlinuz-$rel" ]; then vbad "/boot/vmlinuz-$rel missing"; continue; fi
		vok "/boot/vmlinuz-$rel"
		if [ -f "$cfg" ]; then
			if grep -qx 'CONFIG_SECURITY_SECURE_SUDO=y' "$cfg"; then vok "CONFIG_SECURITY_SECURE_SUDO=y"; else vbad "CONFIG_SECURITY_SECURE_SUDO not set"; fi
			if grep -q '^CONFIG_LSM=".*secure_sudo' "$cfg"; then vok "CONFIG_LSM has secure_sudo"; else vbad "secure_sudo missing from CONFIG_LSM"; fi
			if grep -qx 'CONFIG_MODULE_SIG_FORCE=y' "$cfg"; then vok "module signatures enforced (MODULE_SIG_FORCE)"; else vbad "CONFIG_MODULE_SIG_FORCE not set"; fi
		else
			vbad "/boot/config-$rel missing"
		fi
		if [ -f "$SS_ROOT/boot/initrd.img-$rel" ] || [ -f "$SS_ROOT/boot/initramfs-$rel.img" ]; then vok "initramfs"
		else vbad "no initramfs for $rel"; fi
		m="$(find "$SS_ROOT/lib/modules/$rel" -name '*.ko*' 2>/dev/null | head -1 || true)"
		if [ -n "$m" ]; then
			s="$(modinfo -F signer "$m" 2>/dev/null || true)"
			if [ -n "$s" ]; then vok "modules signed (signer: $s)"; else vbad "module ${m##*/} is unsigned"; fi
		fi
		if [ "$(bootloader)" = unknown ]; then vnote "unknown bootloader: check the boot entry yourself"
		elif boot_entry_present "$rel"; then vok "boot menu entry"
		else vbad "no boot menu entry"; fi
		st="$(secure_boot_state)"
		if command -v sbverify >/dev/null 2>&1; then
			if sbverify --list "$SS_ROOT/boot/vmlinuz-$rel" 2>/dev/null | grep -q '^signature 1'; then vok "kernel image is signed"
			elif [ "$st" = enabled ]; then vbad "Secure Boot is on and the kernel image is unsigned"
			else vnote "kernel image unsigned (Secure Boot is $st)"; fi
		elif [ "$st" = enabled ]; then vbad "Secure Boot is on and sbverify is missing: cannot check the image signature"
		fi
		if [ "$rel" = "$(uname -r)" ]; then running="$rel"; fi
	done < <(m_list K | cut -f2 | sort -u)

	if [ -n "$prev" ]; then
		echo "known-good kernel $prev"
		if [ "$(bootloader)" = unknown ]; then vnote "unknown bootloader: keep an entry for $prev"
		elif boot_entry_present "$prev"; then vok "still in the boot menu"
		else vbad "NOT in the boot menu"; fi
		if [ -f "$SS_ROOT/boot/vmlinuz-$prev" ]; then vok "/boot/vmlinuz-$prev"; else vbad "/boot/vmlinuz-$prev missing"; fi
	fi

	if [ -n "$running" ] && [ -z "$SS_ROOT" ]; then
		echo "running kernel $running"
		if grep -q secure_sudo /sys/kernel/security/lsm 2>/dev/null; then vok "active LSMs: $(cat /sys/kernel/security/lsm)"
		else vbad "secure_sudo is not an active LSM ($(cat /sys/kernel/security/lsm 2>/dev/null))"; fi
		if [ "$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null)" = Y ]; then vok "module.sig_enforce=Y"
		else vbad "module signatures not enforced"; fi
		st="$(sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null || true)"
		if [ -n "${SS_EXPECT_LOCKDOWN:-}" ]; then
			if [ "$st" = "$SS_EXPECT_LOCKDOWN" ]; then vok "lockdown=$st"; else vbad "lockdown=$st, expected $SS_EXPECT_LOCKDOWN"; fi
		else vnote "lockdown=${st:-unavailable} (set SS_EXPECT_LOCKDOWN to check it)"; fi
		if m_get F /usr/bin/secure-sudo >/dev/null; then
			if systemctl is-active --quiet secure-sudod.service; then vok "secure-sudod active"
			else vbad "secure-sudod not active ($(systemctl is-active secure-sudod.service 2>/dev/null || true))"; fi
			if secure-sudo lint -q >/dev/null 2>&1; then vok "secure-sudo lint: no errors"
			else vbad "secure-sudo lint reports errors (run: secure-sudo lint)"; fi
		else
			vnote "userspace not installed (install.sh userspace): the kernel runs its root-only defaults"
		fi
		st="$(systemctl is-system-running 2>/dev/null || true)"
		if [ "$st" = running ]; then vok "systemd: running"; else vnote "systemd: $st"; fi
	fi

	echo "boot plan"
	while IFS=$'\t' read -r rel st; do
		if [ "$st" = trial ] && [ "$rel" = "$(uname -r)" ]; then
			if [ "$commit" = 0 ]; then
				vnote "$rel trial boot is up; run 'install.sh verify --commit' to make it the default"
			elif [ "$V_FAIL" -ne 0 ]; then
				vbad "not committing $rel: fix the failures above (the next reboot returns to the previous default)"
			else
				"$(grub_tool set-default)" "$(grub_entry "$rel")" || die "grub-set-default failed"
				m_set T "$rel" committed
				vok "$rel is now the default boot entry; ${prev:-the previous kernel} stays in the menu"
			fi
		elif [ "$st" = trial ]; then
			if [ -n "$(grub_next_entry)" ]; then vnote "$rel is armed: the next boot tries it once"
			else vbad "the trial boot of $rel did not stay up (running $(uname -r)); see docs/RECOVERY.md"; fi
		elif [ "$st" = rolled-back ]; then
			vnote "$rel is installed but rolled back: ${prev:-the previous kernel} is the default"
		else
			vok "$rel is committed"
		fi
	done < <(m_list T)
	# A GRUB password stops unattended boots at any entry or submenu that is
	# not --unrestricted. BLS menus are built at boot: not checked here.
	if [ "$(bootloader)" = grub ] && [ -n "$(m_list T)" ] && grub_has_password &&
	   ! find "$SS_ROOT/boot/loader/entries" -maxdepth 1 -name '*.conf' 2>/dev/null | grep -q .; then
		for st in saved_entry next_entry; do
			m="$(grub_env "$st")"
			[ -n "$m" ] || continue
			s=0; grub_entry_open "$m" || s=$?
			case "$s" in
			0) vok "GRUB password set; $st boots without it ($m)" ;;
			1) vbad "GRUB password set and $st needs it to boot, so unattended boots wait at the menu ($m); see docs/RECOVERY.md section 1" ;;
			*) vnote "$st $m is not in $(grub_cfg): GRUB boots the first entry" ;;
			esac
		done
	fi
	if [ "$V_FAIL" -eq 0 ]; then echo "verify: OK"; else echo "verify: $V_FAIL problem(s)"; fi
	[ "$V_FAIL" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Rollback: boot the kernel that ran before secure_sudo, once (the default
# entry is untouched) or, with --default, from now on.
# ---------------------------------------------------------------------------
rollback() { # [--default]
	local prev e rel st
	[ -z "$SS_ROOT" ] || die "rollback cannot run with SS_ROOT"
	prev="$(m_get P known-good 2>/dev/null)" || die "no known-good kernel is recorded (nothing installed by this script?)"
	[ "$(bootloader)" = grub ] || die "not GRUB: pick $prev in your boot menu (docs/RECOVERY.md)"
	e="$(grub_entry "$prev")" || die "the boot menu has no entry for $prev; see docs/RECOVERY.md"
	if [ "${1:-}" = --default ]; then
		"$(grub_tool set-default)" "$e" || die "grub-set-default failed"
		while IFS=$'\t' read -r rel st; do m_set T "$rel" rolled-back; done < <(m_list T)
		log "$prev is the default again; reboot to use it"
	else
		"$(grub_tool reboot)" "$e" || die "grub-reboot failed"
		log "the next boot runs $prev (once); the default entry is unchanged"
	fi
}

# ---------------------------------------------------------------------------
# Uninstall: only what the manifest says we placed.
# ---------------------------------------------------------------------------
uninstall() {
	local rm_pam=0 keep_kernel=0 purge=0 a f rel want kept=0 ts t names=()
	for a in "$@"; do
		case "$a" in
		--remove-pam-lines) rm_pam=1 ;; --keep-kernel) keep_kernel=1 ;; --purge) purge=1 ;;
		*) die "uninstall: unknown option $a" ;;
		esac
	done
	[ -s "$MANIFEST" ] || die "nothing is installed by this script (no ${MANIFEST#"$SS_ROOT"})"
	ts="$(date +%Y%m%d-%H%M%S)"

	# 1. The kernel can only go when it is not the one running.
	if [ "$keep_kernel" = 0 ] && [ -n "$(m_list K)" ]; then
		[ -z "$SS_ROOT" ] || die "kernel removal cannot run with SS_ROOT (use --keep-kernel)"
		if running_ours; then
			die "the running kernel $(uname -r) is the secure_sudo one. Boot $(m_get P known-good || echo 'the previous kernel') first (docs/RECOVERY.md), or use --keep-kernel."
		fi
	fi

	# 2. PAM: a stack that names a missing "required" module fails every
	#    login and sudo, so its lines go first or nothing happens.
	mapfile -t PAMF < <(grep -lE "$PAM_RE" "$SS_ROOT"/etc/pam.d/* 2>/dev/null)
	if [ "${#PAMF[@]}" -gt 0 ]; then
		if [ "$rm_pam" = 0 ]; then
			grep -nE "$PAM_RE" "${PAMF[@]}" >&2
			die "PAM still uses the secure_sudo modules (above); removing them now would break sudo/login. Remove those lines (keep a root shell open), or rerun with --remove-pam-lines. Nothing was changed."
		fi
		local copies="/var/backups/secure_sudo-pam-$ts"
		mkdir -p "$SS_ROOT$copies"; chmod 700 "$SS_ROOT$copies"
		for f in "${PAMF[@]}"; do
			cp -a "$f" "$SS_ROOT$copies/" || die "could not copy $f; nothing was changed"
			sed -i -E "/$PAM_RE/d" "$f"
			log "removed the secure_sudo lines from ${f#"$SS_ROOT"} (the old file is in $copies)"
		done
	fi

	# 3. The service.
	if [ -z "$SS_ROOT" ] && m_get S secure-sudod.service >/dev/null; then
		systemctl disable --now secure-sudod.service || warn "could not disable secure-sudod.service"
		m_del S secure-sudod.service
	fi

	# 4. Files: remove ours if unchanged; restore what they replaced.
	while IFS=$'\t' read -r rel want; do
		if [ ! -e "$SS_ROOT$rel" ]; then m_del F "$rel"; continue; fi
		if [ "$(sha "$SS_ROOT$rel")" != "$want" ]; then
			warn "kept $rel: changed since install"; kept=$((kept + 1)); continue
		fi
		rm -f "$SS_ROOT$rel"; m_del F "$rel"
	done < <(m_list F)
	while IFS=$'\t' read -r rel want; do
		if [ ! -e "$SS_ROOT$rel" ]; then m_del C "$rel"; continue; fi
		if [ "$purge" = 0 ] && [ "$(sha "$SS_ROOT$rel")" != "$want" ]; then
			warn "kept $rel: you changed it (--purge removes it)"; kept=$((kept + 1)); continue
		fi
		rm -f "$SS_ROOT$rel"; m_del C "$rel"
	done < <(m_list C)
	while IFS=$'\t' read -r rel want; do
		if [ -e "$SS_ROOT$rel" ]; then
			warn "not restoring $rel: a file is in its place (the original is in ${BACKUP#"$SS_ROOT"}$rel)"
			kept=$((kept + 1)); continue
		fi
		make_parents "$rel"
		cp -a "$BACKUP$rel" "$SS_ROOT$rel" || die "could not restore $rel from ${BACKUP#"$SS_ROOT"}$rel"
		rm -f "$BACKUP$rel"; m_del B "$rel"; log "restored the original $rel"
	done < <(m_list B)

	# 5. Boot: the GRUB drop-in went with the files; clear the one-shot and
	#    saved entries we set, remove the kernel packages, rebuild the menu.
	if [ -z "$SS_ROOT" ] && [ -n "$(m_list T)" ]; then
		if t="$(grub_tool editenv)"; then "$t" - unset next_entry saved_entry || warn "could not clear grubenv"; fi
		while IFS=$'\t' read -r rel _; do m_del T "$rel"; done < <(m_list T)
	fi
	# Versions <= 0.11 put module.sig_enforce=1 on the shared command line.
	if [ -z "$SS_ROOT" ] && [ -f /etc/default/grub.secure_sudo.bak ] && grep -q 'module\.sig_enforce=1 ' /etc/default/grub; then
		sed -i 's/module\.sig_enforce=1 //' /etc/default/grub && rm -f /etc/default/grub.secure_sudo.bak
		log "removed the module.sig_enforce=1 an older install added to GRUB_CMDLINE_LINUX"
	fi
	if [ "$keep_kernel" = 0 ] && [ -z "$SS_ROOT" ]; then
		while IFS=$'\t' read -r f rel; do names+=("$f"); done < <(m_list K)
		if [ "${#names[@]}" -gt 0 ]; then
			log "removing kernel package(s): ${names[*]}"
			case "$FAMILY" in
			debian) dpkg --purge "${names[@]}" || die "dpkg --purge failed; what is left is recorded in $MANIFEST" ;;
			fedora|suse) rpm -e "${names[@]}" || die "rpm -e failed; what is left is recorded in $MANIFEST" ;;
			arch)
				for f in "${names[@]}"; do
					rel="${f#arch:}"
					rm -rf "/lib/modules/$rel"
					rm -f "/boot/vmlinuz-$rel" "/boot/System.map-$rel" "/boot/config-$rel" "/boot/initramfs-$rel.img"
				done ;;
			esac
			for f in "${names[@]}"; do m_del K "$f"; done
		fi
	fi
	if [ -z "$SS_ROOT" ]; then
		update_bootloader
		rel="$(m_get P known-good 2>/dev/null || true)"
		if [ -n "$rel" ] && [ "$(bootloader)" != unknown ] && ! boot_entry_present "$rel"; then
			warn "the boot menu has no entry for $rel; check it before rebooting"
		fi
	fi

	# 6. Directories we created, deepest first, if empty.
	while IFS=$'\t' read -r rel _; do
		if rmdir "$SS_ROOT$rel" 2>/dev/null || [ ! -e "$SS_ROOT$rel" ]; then m_del D "$rel"
		else warn "kept $rel: not empty"; kept=$((kept + 1)); fi
	done < <(m_list D | awk -F'\t' '{print length($1) "\t" $0}' | sort -rn | cut -f2-)

	if [ "$purge" = 1 ]; then
		rm -rf "$SS_ROOT/etc/secure_sudo" "$SS_ROOT/var/log/secure_sudo"
		log "purged /etc/secure_sudo and /var/log/secure_sudo"
	fi
	# 7. State the daemon and the CLI keep for themselves (heartbeat, last
	#    load result, event-stream position, and their temporary files). It
	#    is rebuilt on the next start and holds nothing an investigation
	#    needs; the logs and the quarantine do, and they stay. Events still
	#    queued for the remote collector stay too. The service is stopped
	#    (step 3), so nothing rewrites these behind us.
	local sd="$SS_ROOT/var/lib/secure_sudo" f
	for f in daemon.health daemon.health.tmp load.health event-cursor event-cursor.tmp; do
		rm -f -- "${sd:?}/$f"
	done
	rm -f -- "$sd"/load.health.tmp.??????
	if [ -d "$sd/remote-queue" ] && ! rmdir "$sd/remote-queue" 2>/dev/null; then
		warn "kept /var/lib/secure_sudo/remote-queue: events not yet delivered to the remote collector"
	fi
	if [ -d "$sd/quarantine" ]; then
		log "kept /var/lib/secure_sudo/quarantine (TimeVault evidence); delete it yourself when done"
	fi

	if [ "$kept" -eq 0 ] && [ -z "$(m_list K)" ]; then
		rm -rf "$STATE"; rmdir "$SS_ROOT/var/lib/secure_sudo" 2>/dev/null || true
		log "uninstall complete: everything this script installed is gone"
	else
		m_del V version; m_del P known-good
		log "uninstall done; $kept item(s) kept (above); the record stays in ${MANIFEST#"$SS_ROOT"}"
	fi
	return 0
}

# ---------------------------------------------------------------------------
main() {
	local cmd="${1:-all}"
	[ $# -gt 0 ] && shift
	case "$cmd" in
	--dry-run|-n) cmd=preflight; set -- all ;;
	-h|--help|help) sed -n '3,52p' "$0"; return 0 ;;
	esac
	case "$cmd" in
	preflight)
		preflight "${@:-all}" ;;
	stage-userspace)
		need_distro; stage_userspace "${1:?stage-userspace DIR}" ;;
	*)
		[ "$(id -u)" -eq 0 ] || die "must run as root"
		[ -d "$LSM_SRC" ] || die "LSM sources not found at $LSM_SRC"
		case "$cmd" in
		all)
			need_distro
			preflight all || die "preflight found blocking problems (above); nothing was changed"
			install_deps
			if [ -n "${SS_KERNEL_TREE:-}" ]; then use_kernel_tree; else fetch_kernel; fi
			graft_lsm; configure_kernel; reproducible_env; build_kernel
			install_kernel "$BUILT_DIR"
			install_userspace
			secure-sudo load || log "policy not loaded yet: it loads when the secure_sudo kernel boots"
			run_stig_hardening
			print_pam_guidance
			verify || true
			log "DONE. Reboot to try the secure_sudo kernel once, then: install.sh verify --commit" ;;
		build-kernel)
			need_distro
			preflight build-kernel || die "preflight found blocking problems (above)"
			if [ -n "${SS_KERNEL_TREE:-}" ]; then use_kernel_tree; else fetch_kernel; fi
			graft_lsm; configure_kernel; reproducible_env; build_kernel ;;
		install-kernel)
			need_distro; install_kernel "$@" ;;
		userspace)
			need_distro
			preflight userspace "$@" || die "preflight found blocking problems (above); nothing was changed"
			if [ "${1:-}" = --prebuilt ]; then install_userspace "${2:?--prebuilt DIR}"; else install_userspace; fi
			print_pam_guidance ;;
		verify)
			detect_distro || true; verify "$@" ;;
		uninstall)
			detect_distro || true; uninstall "$@" ;;
		rollback)
			detect_distro || true; rollback "$@" ;;
		*) die "unknown command '$cmd' (install.sh --help)" ;;
		esac ;;
	esac
}

# SS_INSTALL_LIB=1 lets the test suite source this file for its functions.
[ "${SS_INSTALL_LIB:-0}" = 1 ] || main "$@"
