#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# quick-install.sh - the guided one-command install of secure_sudo (kernel +
# userspace, optionally the add-ons) for a single machine. It wraps
# install/install.sh; it adds verification and a confirmation step, never new
# install logic. Full guide: docs/INSTALL.md. Command page:
# docs/commands/quick-install.md.
#
# WHAT IT DOES
#   1. Checks it runs as root and parses its options (allow-listed values).
#   2. With --archive: copies the release archive and its .sha256 file into a
#      private work directory, checks the SHA-256 and, if given, the detached
#      OpenPGP signature over the .sha256 file against a pinned signer
#      fingerprint; refuses archives with absolute paths, ".." members, links
#      pointing outside, special files or more than one top directory; unpacks
#      the copy in the work directory. Without --archive it uses the checkout
#      it sits in.
#   3. Runs `install.sh preflight` (changes nothing) and shows the result.
#   4. Asks before changing anything (unless --yes). Only then is the verified
#      archive unpacked under --dest (kept: verify --commit, rollback and
#      uninstall run from it later).
#   5. Runs `install.sh` (all: build from the signature-verified kernel.org
#      source, trial-boot install next to the running kernel, userspace, verify).
#   6. With --with-addons, runs temporary/install-temporary.sh (enables nothing).
#   7. Prints the next steps: reboot once, `install.sh verify --commit`.
#
# TRUST BOUNDARIES AND CONTROLS
#   * Input: a release archive downloaded by the operator. Integrity: SHA-256
#     (NIST SI-7) and, optionally, a detached signature from a pinned key
#     (SI-7(15), SR-4); unsafe archive members are refused before extraction
#     (CWE-22 path traversal, CWE-59 link following).
#   * No download-and-execute: this script never fetches code. The operator
#     downloads, the script verifies, then runs what was verified.
#   * Every option value is allow-listed; nothing is passed through eval or a
#     shell string (CWE-78). Paths must be absolute where they become targets.
#   * Fails closed: any verification problem stops before anything is changed.
#
# USAGE
#   quick-install.sh [--archive FILE [--sha256 FILE]
#                     [--signature FILE --signer-key FILE --signer-fpr FPR]]
#                    [--dest DIR] [--yes] [--dry-run] [--no-tpm-lockout]
#                    [--stig scan|remediate] [--with-addons] [--initramfs]
#   Exit: 0 done (or dry run passed), 1 a step failed, 2 usage or refused input.
#
# Dependencies: bash, coreutils (sha256sum), tar, gzip; gpg only with
# --signature. All are in the base system of every supported distribution.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE="" SHAFILE="" SIGFILE="" SIGKEY="" SIGFPR=""
DEST=/opt/secure_sudo YES=0 DRY=0 TPM_LOCKOUT=1 STIG_MODE="" ADDONS=0 INITRAMFS=0

say()  { printf 'quick-install: %s\n' "$*"; }
die()  { printf 'quick-install: %s\n' "$*" >&2; exit 1; }
usage_die() { printf 'quick-install: %s (see --help)\n' "$*" >&2; exit 2; }

usage() { sed -n '3,48p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

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

# SECURITY: installing a kernel needs root; refuse early rather than half-run.
[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash $0 ...)"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- 1. source
if [ -n "$ARCHIVE" ]; then
	[ -f "$ARCHIVE" ] || die "no such archive: $ARCHIVE"
	SHAFILE="${SHAFILE:-$ARCHIVE.sha256}"
	[ -f "$SHAFILE" ] || die "no checksum file: $SHAFILE (download it with the archive)"
	name="$(basename "$ARCHIVE" .tar.gz)"
	# SECURITY: work on a private copy (mktemp dir, 0700): the file that is
	# hashed is the file that is unpacked, even if the download directory is
	# writable by someone else (CWE-367).
	cp -- "$ARCHIVE" "$WORK/archive.tar.gz"; ARCHIVE="$WORK/archive.tar.gz"
	cp -- "$SHAFILE" "$WORK/archive.sha256"; SHAFILE="$WORK/archive.sha256"
	# The checksum file holds "<64 hex>  <name>". Only the hash is trusted;
	# the archive is hashed here, never looked up by the name in the file.
	want="$(awk 'NR==1 {print tolower($1)}' "$SHAFILE")"
	printf '%s' "$want" | grep -qxE '[0-9a-f]{64}' || die "the checksum file does not start with a SHA-256 hash"
	have="$(sha256sum < "$ARCHIVE" | awk '{print $1}')"
	# SECURITY: integrity check before anything is unpacked (NIST SI-7).
	[ "$have" = "$want" ] || die "SHA-256 MISMATCH for $name.tar.gz: got $have, want $want. Do not use this file."
	say "SHA-256 ok: $have"
	if [ -n "$SIGFILE" ]; then
		command -v gpg >/dev/null || die "--signature needs gpg (install gnupg)"
		# SECURITY: a throwaway keyring holding only the operator-supplied key;
		# the signature must come from the pinned fingerprint (SI-7(15)).
		export GNUPGHOME="$WORK/gnupg"; mkdir -m 0700 "$GNUPGHOME"
		gpg --batch --quiet --import "$SIGKEY" 2>/dev/null || die "cannot import $SIGKEY"
		status="$(gpg --batch --status-fd 1 --verify "$SIGFILE" "$SHAFILE" 2>/dev/null || true)"
		# VALIDSIG <fpr> ... <primary-key-fpr>: accept the subkey or the primary.
		printf '%s\n' "$status" | awk -v f="$SIGFPR" '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3==f || $NF==f) {ok=1} END {exit !ok}' ||
			die "signature check FAILED: $SIGFILE is not a valid signature by $SIGFPR over the checksum file"
		say "signature ok: the checksum file is signed by $SIGFPR"
	fi
	# SECURITY: inspect every member before extracting (CWE-22, CWE-59).
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
	# Unpacked into the private work directory first: the preflight runs from
	# there, and --dest is only written after the operator said yes, so a
	# refusal or a stop really leaves the machine unchanged.
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
	# /dev/tty exists even without a controlling terminal; only opening it tells.
	if ! { exec 3<>/dev/tty; } 2>/dev/null; then
		die "no terminal to ask on; rerun with --yes after reading the preflight. Nothing was changed."
	fi
	printf 'quick-install: install the secure_sudo kernel and userspace now? [y/N] ' >&3
	read -r answer <&3 || answer=""
	exec 3>&-
	case "$answer" in y|Y|yes|YES) ;; *) say "stopped; nothing was changed."; exit 0 ;; esac
fi

# ---------------------------------------------------- 4. keep the verified tree
# The installed system is managed later from this tree (verify --commit,
# rollback, uninstall), so it goes to a root-owned place that outlives $WORK.
if [ -n "$ARCHIVE" ]; then
	install -d -m 0755 "$DEST"
	mkdir -m 0755 "$TARGET" || die "cannot create $TARGET"
	tar -xzf "$ARCHIVE" -C "$TARGET" --no-same-owner
	SRC="$TARGET/$top"; INST="$SRC/install/install.sh"
	say "verified archive kept in $SRC"
fi

# ----------------------------------------------------------------- 5. install
say "running install.sh (kernel build from verified source, trial-boot install, userspace)"
env "${ENVV[@]}" bash "$INST" || die "install.sh failed (its last lines say what is still intact; docs/RECOVERY.md)"

if [ "$ADDONS" -eq 1 ]; then
	ADD="$SRC/temporary/install-temporary.sh"
	[ -f "$ADD" ] || die "no temporary/install-temporary.sh in $SRC"
	if [ "$INITRAMFS" -eq 1 ]; then bash "$ADD" --initramfs || die "add-on install failed"
	else bash "$ADD" || die "add-on install failed"; fi
fi

cat <<EOF
quick-install: done. Next steps (keep a second root session open):
  1. sudo reboot                         # the secure_sudo kernel boots ONCE; the old one stays default
  2. sudo bash $INST verify --commit     # after it came up and you checked it
  3. sudo secure-sudo lint && sudo secure-sudo load
If the new kernel does not come up, the next boot is the previous kernel by itself.
EOF
