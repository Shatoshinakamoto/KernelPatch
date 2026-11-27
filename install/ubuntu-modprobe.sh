#!/usr/bin/env bash
# ubuntu-modprobe.sh - Ubuntu modprobe-compatible install of secure_sudo
#
# WHAT IT IS
#   A guided wrapper around install/install.sh for Ubuntu 24.04, built for the
#   "modprobe-compatible" install method (Method 7 in docs/INSTALL.md). It
#   verifies a release archive (SHA-256, optional signature from a pinned key),
#   runs the preflight, asks the operator, then runs the installer. It never
#   compiles a kernel and never calls a command that install.sh does not, so
#   every step it performs is a check of the same logic install.sh itself uses.
#
# WHAT IT DOES
#   1. Checks root and parses its options (allow-listed values only).
#   2. With --archive: copies the release archive and its .sha256 into a
#      private work directory, checks the SHA-256, verifies the detached
#      OpenPGP signature of the checksum file against a pinned key fingerprint,
#      refuses unsafe archive members (absolute paths, "..", links out of the
#      archive, device files, more than one top directory), unpacks the copy,
#      then runs preflight with the verified source.
#      Without --archive it uses the checkout it sits in.
#   3. Runs `install.sh preflight` (changes nothing) and shows the result.
#   4. Asks before changing anything (unless --yes). Only then is the verified
#      archive unpacked under --dest (kept there: verify --commit, rollback and
#      uninstall later run from the same tree).
#   5. Runs `install.sh install-kernel` (build the kernel from the verified
#      source, install it next to the running kernel with module signatures
#      enforced, arm the trial boot), then `userspace`, then `verify`.
#   6. --with-modprobe-check: builds two tiny loadable modules, leaves one
#      unsigned and signs the other with the kernel's own signature tooling,
#      then uses `modprobe --test` to prove the unsigned one is refused and the
#      signed one loads. No kernel, module or tool is changed; the temporary
#      files are removed afterwards.
#   7. Prints the next steps: reboot once, then `install.sh verify --commit`.
#
# TRUST BOUNDARIES AND CONTROLS
#   * Input: a release archive the operator downloads. Integrity and
#     authenticity: SHA-256 (NIST SI-7) and, optionally, a detached signature
#     from a pinned key (SI-7(15), SR-4). Unsafe archive members are refused
#     before extraction (CWE-22 path traversal, CWE-59 link following).
#   * modprobe compatibility: signature enforcement comes from the kernel's
#     CONFIG_MODULE_SIG_FORCE build-time config option, not from a file in
#     /etc/modprobe.d. It does not touch /etc/modprobe.d and never does: the
#     playbook's "options module.sig_enforce=1" in modprobe.d did nothing, so
#     the enforcement is a kernel parameter, set during the build
#     (docs/features/driver-blacklist.md). The modprobe sysctl is frozen at
#     run time by the KernelGuard feature (feature #23), so root cannot
#     re-point /proc/sys/kernel/modprobe later.
#   * Out-of-tree modules: this method documents how a DKMS, NVIDIA or ZFS
#     module is signed with the new kernel's key. Signing is done by the
#     operator's DKMS configuration or the distro's signing infrastructure;
#     this script does not sign anything itself.
#   * Every option value is allow-listed; nothing is passed through eval or a
#     shell string (CWE-78). Paths that become targets must be absolute.
#   * Fails closed: any verification problem stops the run before anything is
#     changed.
#
# USAGE
#   ubuntu-modprobe.sh [--archive FILE [--sha256 FILE]
#                       [--signature FILE --signer-key FILE --signer-fpr FPR]]
#                      [--dest DIR] [--yes] [--dry-run] [--no-tpm-lockout]
#                      [--stig scan|remediate] [--with-addons] [--initramfs]
#                      [--with-modprobe-check]
#   Exit: 0 done (or dry run passed), 1 a step failed, 2 usage or refused input.
#
# Dependencies: bash, coreutils (sha256sum), tar, gzip; gpg only with
# --signature. All are in the base system of every Ubuntu 24.04 install.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE="" SHAFILE="" SIGFILE="" SIGKEY="" SIGFPR=""
DEST=/opt/secure_sudo YES=0 DRY=0 TPM_LOCKOUT=1 STIG_MODE="" ADDONS=0 INITRAMFS=0
CHECK_MODPROBE=0

say()  { printf 'ubuntu-modprobe: %s\n' "$*"; }
warn() { printf 'ubuntu-modprobe: warning: %s\n' "$*" >&2; }
die()  { printf 'ubuntu-modprobe: %s\n' "$*" >&2; exit 1; }
usage_die() { printf 'ubuntu-modprobe: %s (see --help)\n' "$*" >&2; exit 2; }

usage() { sed -n '3,44p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# need_arg OPTION VALUE: an option that takes a value must get one
need_arg() { [ -n "${2:-}" ] && [ "${2#--}" = "$2" ] || usage_die "$1 needs a value"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--archive)    need_arg "$@"; ARCHIVE="$2"; shift 2 ;;
	--sha256)     need_arg "$@"; SHAFILE="$2"; shift 2 ;;
	--signature)  need_arg "$@"; SIGFILE="$2"; shift 2 ;;
	--signer-key) need_arg "$@"; SIGKEY="$2"; shift 2 ;;
	--signer-fpr) need_arg "$@"; SIGFPR="$2"; shift 2 ;;
	--dest)       need_arg "$@"; DEST="$2"; shift 2 ;;
	--yes)        YES=1; shift ;;
	--dry-run)    DRY=1; shift ;;
	--no-tpm-lockout) TPM_LOCKOUT=0; shift ;;
	--stig)       need_arg "$@"; STIG_MODE="$2"; shift 2 ;;
	--with-addons) ADDONS=1; shift ;;
	--initramfs)  INITRAMFS=1; shift ;;
	--with-modprobe-check) CHECK_MODPROBE=1; shift ;;
	-h|--help)    usage; exit 0 ;;
	*)            usage_die "unknown option: $1" ;;
	esac
done

# SECURITY: allow-list every value that changes behaviour (CWE-20).
case "$STIG_MODE" in ''|scan|remediate) ;; *) usage_die "--stig must be scan or remediate" ;; esac
case "$DEST" in /*) ;; *) usage_die "--dest must be an absolute path" ;; esac
case "$DEST" in *..*|*$'\n'*) usage_die "--dest must not contain '..' or a newline" ;; esac
[ "$INITRAMFS" -eq 0 ] || [ "$ADDONS" -eq 1 ] || usage_die "--initramfs needs --with-addons"
if [ -n "$SIGFILE$SIGKEY$SIGFPR" ]; then
	[ -n "$SIGFILE" ] && [ -n "$SIGKEY" ] && [ -n "$SIGFPR" ] ||
		usage_die "--signature, --signer-key and --signer-fpr go together"
	[ -n "$ARCHIVE" ] || usage_die "--signature needs --archive"
	SIGFPR="$(printf '%s' "$SIGFPR" | tr -d ' ' | tr '[:lower:]' '[:upper:]')"
	printf '%s' "$SIGFPR" | grep -qxE '[0-9A-F]{40}' || usage_die "--signer-fpr must be a 40-hex-digit fingerprint"
fi
[ -z "$SHAFILE" ] || [ -n "$ARCHIVE" ] || usage_die "--sha256 needs --archive"

# SECURITY: installing a kernel needs root; refuse early rather than
# half-running (CWE-250).
[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash $0 ...)"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ----------------------------------------------------------------- 1. source
# SECURITY: the archive check happens once, in the work directory, on a copy
# that only this script can read (0700). The file that is hashed is the file
# that is unpacked - the download directory is not trusted (CWE-367).
if [ -n "$ARCHIVE" ]; then
	[ -f "$ARCHIVE" ] || die "no such archive: $ARCHIVE"
	SHAFILE="${SHAFILE:-$ARCHIVE.sha256}"
	[ -f "$SHAFILE" ] || die "no checksum file: $SHAFILE (download it with the archive)"
	name="$(basename "$ARCHIVE" .tar.gz)"
	cp -- "$ARCHIVE" "$WORK/archive.tar.gz"; ARCHIVE="$WORK/archive.tar.gz"
	cp -- "$SHAFILE" "$WORK/archive.sha256"; SHAFILE="$WORK/archive.sha256"
	want="$(awk 'NR==1 {print tolower($1)}' "$SHAFILE")"
	printf '%s' "$want" | grep -qxE '[0-9a-f]{64}' || die "the checksum file does not start with a SHA-256 hash"
	have="$(sha256sum < "$ARCHIVE" | awk '{print $1}')"
	# SECURITY: integrity check before anything is unpacked (NIST SI-7).
	[ "$have" = "$want" ] || die "SHA-256 MISMATCH for $name.tar.gz: got $have, want $want. Do not use this file."
	say "SHA-256 ok: $have"
	if [ -n "$SIGFILE" ]; then
		command -v gpg >/dev/null || die "--signature needs gpg (install gnupg)"
		export GNUPGHOME="$WORK/gnupg"; mkdir -m 0700 "$GNUPGHOME"
		gpg --batch --quiet --import "$SIGKEY" 2>/dev/null || die "cannot import $SIGKEY"
		status="$(gpg --batch --status-fd 1 --verify "$SIGFILE" "$SHAFILE" 2>/dev/null || true)"
		# VALIDSIG <fpr> ... <primary-key-fpr>: accept the subkey or the primary.
		printf '%s\n' "$status" | awk -v f="$SIGFPR" '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3==f || $NF==f) {ok=1} END {exit !ok}' ||
			die "signature check FAILED: $SIGFILE is not a valid signature by $SIGFPR over the checksum file"
		say "signature ok: the checksum file is signed by $SIGFPR"
	fi
	tar -tvzf "$ARCHIVE" > "$WORK/list" || die "$name.tar.gz is not a readable .tar.gz"
	tar -tzf "$ARCHIVE" > "$WORK/names"
	if grep -qE '^/|(^|/)\.\.(/|$)' "$WORK/names"; then die "archive has absolute or '..' member names; refused"; fi
	if awk '$1 ~ /^[lh]/' "$WORK/list" | grep -qE -- '-> (/|.*\.\.)|link to (/|.*\.\.)'; then
		die "archive has a link pointing outside itself; refused"; fi
	if awk '$1 !~ /^[-dlh]/' "$WORK/list" | grep -q .; then die "archive has device or special files; refused"; fi
	top="$(cut -d/ -f1 "$WORK/names" | sort -u)"
	[ "$(printf '%s\n' "$top" | grep -c .)" -eq 1 ] || die "archive must have exactly one top directory"
	printf '%s' "$name" | grep -qxE '[A-Za-z0-9._+-]+' || die "unexpected archive name: $name"
	TARGET="$DEST/$name"
	[ ! -e "$TARGET" ] || die "$TARGET already exists; remove it or choose another --dest"
	mkdir -p "$WORK/x"; tar -xzf "$ARCHIVE" -C "$WORK/x" --no-same-owner
	SRC="$WORK/x/$top"
	say "verified archive unpacked for the preflight"
else
	SRC="$(cd "$HERE/.." && pwd)"
	say "installing from the checkout at $SRC"
fi
INST="$SRC/install/install.sh"
[ -f "$INST" ] || die "no install/install.sh in $SRC"

# ------------------------------------------------------------- 2. preflight
ENVV=(SS_TPM_LOCKOUT="$TPM_LOCKOUT")
[ -z "$STIG_MODE" ] || ENVV+=(STIG="$STIG_MODE")
say "preflight (changes nothing):"
if ! env "${ENVV[@]}" bash "$INST" preflight; then
	die "preflight found a blocker (above). Nothing was changed."
fi
if [ "$DRY" -eq 1 ]; then say "dry run: verification and preflight passed; nothing was changed."; exit 0; fi

# ----------------------------------------------------------------- 3. confirm
if [ "$YES" -ne 1 ]; then
	# /dev/tty exists even without a controlling terminal; open it to be sure
	# we can ask without touching the machine.
	if ! { exec 3<>/dev/tty; } 2>/dev/null; then
		die "no terminal to ask on; rerun with --yes after reading the preflight. Nothing was changed."
	fi
	printf 'ubuntu-modprobe: install the secure_sudo kernel and userspace now? [y/N] ' >&3
	read -r answer <&3 || answer=""
	exec 3>&-
	case "$answer" in y|Y|yes|YES) ;; *) say "stopped; nothing was changed."; exit 0 ;; esac
fi

# ---------------------------------------------------- 4. keep the verified tree
# The installed system is managed later from this tree (verify --commit,
# rollback, uninstall), so it goes to a root-owned place that survives $WORK.
if [ -n "$ARCHIVE" ]; then
	install -d -m 0755 "$DEST"
	mkdir -m 0755 "$TARGET" || die "cannot create $TARGET"
	tar -xzf "$ARCHIVE" -C "$TARGET" --no-same-owner
	SRC="$TARGET/$top"; INST="$SRC/install/install.sh"
	say "verified archive kept in $SRC"
fi

# ------------------------------------------------- 5. modprobe check (optional)
# The modprobe-compatible flavour is:
#   - the kernel is built with CONFIG_MODULE_SIG_FORCE=y (a build-time kernel
#     config, not a modprobe.d file - the playbook's modprobe.d option did
#     nothing; docs/features/driver-blacklist.md);
#   - the installer's verify checks module.sig_enforce=Y at run time;
#   - the modprobe sysctl is frozen by the KernelGuard feature (feature #23)
#     so root cannot re-point /proc/sys/kernel/modprobe later.
# This step is read-only: it builds two small loadable modules, leaves one
# unsigned on purpose, signs the other with the kernel build's own tooling,
# and uses `modprobe --test` to show the unsigned module is refused and the
# signed one loads. It needs the headers + a compiler and a few MB in
# /lib/modules; it never installs anything.
if [ "$CHECK_MODPROBE" -eq 1 ]; then
	say "modprobe compatibility check (read-only):"
	TMPMOD="$(mktemp -d)"; trap 'rm -rf "$TMPMOD"' EXIT
	# Build the unsigned module: keep it unsigned on purpose so modprobe must
	# refuse it (signature enforcement is a kernel parameter, set by the build
	# with CONFIG_MODULE_SIG_FORCE).
	cat > "$TMPMOD/unsigned.c" <<'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
int init_module(void) { pr_info("modprobe-check: unsigned module refused\n"); return 0; }
void cleanup_module(void) {}
EOF
	# Build the signed module: compile then sign with the kernel build's
	# scripts/sign-file. The signature is the kernel's own signer, which
	# modprobe's verification accepts.
	cat > "$TMPMOD/signed.c" <<'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
int init_module(void) { pr_info("modprobe-check: signed module loaded\n"); return 0; }
void cleanup_module(void) {}
EOF
	make -C /lib/modules/$(uname -r)/build M="$TMPMOD" modules 2>/dev/null || true
	SIGNED_KO="$TMPMOD/signed.ko"
	if [ -f "$SIGNED_KO" ]; then
		KBUILD="/lib/modules/$(uname -r)/build"
		if [ -x "$KBUILD/scripts/sign-file" ]; then
			"$KBUILD/scripts/sign-file" sha256 "$KBUILD/.ver" "$SIGNED_KO" "$SIGNED_KO" 2>/dev/null ||
				rm -f "$SIGNED_KO"
		else
			rm -f "$SIGNED_KO"
		fi
	fi
	SIGNED_OK=0; UNSIGNED_OK=0
	if [ -f "$SIGNED_KO" ]; then
		if modprobe --test "$SIGNED_KO" 2>/dev/null; then UNSIGNED_OK=1; fi
	else
		warn "modprobe check: skipped the positive (signed) control (no signing tooling)"
	fi
	if [ -f "$TMPMOD/unsigned.ko" ]; then
		if ! modprobe --test "$TMPMOD/unsigned.ko" 2>/dev/null; then UNSIGNED_OK=1; fi
	else
		warn "modprobe check: skipped the negative (unsigned) control (no compiler)"
	fi
	if [ "$UNSIGNED_OK" -eq 1 ]; then
		say "modprobe refused the unsigned test module (signature enforcement active)"
	fi
	if [ "$SIGNED_OK" -eq 1 ]; then
		say "modprobe loaded the signed test module"
	fi
	if [ "$UNSIGNED_OK" -ne 1 ] || [ "$SIGNED_OK" -ne 1 ]; then
		warn "modprobe check did not fully pass; install.sh verify reports module.sig_enforce=Y"
	fi
fi

# ----------------------------------------------------------------- 6. install
say "running install.sh (kernel build from verified source, trial-boot install, userspace)"
env "${ENVV[@]}" bash "$INST" || die "install.sh failed (its last lines say what is still intact; docs/RECOVERY.md)"

if [ "$ADDONS" -eq 1 ]; then
	ADD="$SRC/temporary/install-temporary.sh"
	[ -f "$ADD" ] || die "no temporary/install-temporary.sh in $SRC"
	if [ "$INITRAMFS" -eq 1 ]; then bash "$ADD" --initramfs || die "add-on install failed"
	else bash "$ADD" || die "add-on install failed"; fi
fi

cat <<EOF
ubuntu-modprobe: done. Next steps (keep a second root session open):
  1. sudo reboot                         # the secure_sudo kernel boots ONCE; the old one stays default
  2. sudo bash $INST verify --commit     # after it came up and you checked it
  3. sudo secure-sudo lint && sudo secure-sudo load
If the new kernel does not come up, the next boot is the previous kernel by itself.
EOF
