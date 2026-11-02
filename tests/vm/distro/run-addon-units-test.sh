#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# run-addon-units-test.sh - the temporary/ add-ons under real systemd, in a
# throwaway distro VM (TODO P2-2).
#
# tests/userspace/test-addons.sh tests what each guard does; this tests that
# its hardened, resource-limited unit still lets it do it. On a fresh
# cloud-image guest it installs the add-ons with install-temporary.sh and runs
# addon-units-guest.sh there: every unit is started and must do its real job
# inside its sandbox (BootGuard's restore writing /boot, DriverGuard repairing
# a module, ProcGuard removing a /tmp implant, tamperwatch's fanotify, Locus
# and the console serving), and a config error must fail a unit with status
# 78, without a restart loop, reported by secure-sudo-addon-failure@.
# Output is TAP; the guest's output is kept in RESULTS.
#
# Usage: run-addon-units-test.sh IMAGE RESULTS-DIR
# The guest needs network access for apt (gcc, libssl-dev, zlib1g-dev).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
IMG="$(readlink -f "${1:?usage: $0 IMAGE RESULTS-DIR}")"
RES="${2:?RESULTS-DIR}"; mkdir -p "$RES"; RES="$(cd "$RES" && pwd)"
# The VM work dir holds the guest's disk and SSH key: never inside RESULTS.
W="$(mktemp -d "${TMPDIR:-/tmp}/ss-addon-vm.XXXXXX")"
VM="$HERE/vm.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"; bash "$VM" stop "$W" > /dev/null 2>&1; rm -rf "$W"' EXIT
G() { bash "$VM" ssh "$W" "$@"; }

if bash "$VM" up "$W" "$IMG" >> "$RES/vm.log" 2>&1; then ok "fresh guest boots from the verified image"
else not_ok "fresh guest boots"; tap_done; exit 1; fi
G 'cloud-init status --wait' > /dev/null 2>&1
(cd "$ROOT" && tar -czf "$work/addons.tgz" temporary tests/vm/distro/addon-units-guest.sh)
bash "$VM" put "$W" "$work/addons.tgz" /root/addons.tgz >> "$RES/vm.log" 2>&1
G 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq gcc make libssl-dev zlib1g-dev curl' \
	> "$RES/01-apt.log" 2>&1; rc=$?
check "the guest has a compiler and the add-ons' libraries" test "$rc" -eq 0
G 'rm -rf /root/a && mkdir /root/a && tar -xzf /root/addons.tgz -C /root/a && bash /root/a/temporary/install-temporary.sh' \
	> "$RES/02-install.log" 2>&1; rc=$?
check "install-temporary.sh installs every add-on and unit, enabling none" sh -c "
	[ $rc -eq 0 ] && grep -qF 'Done.' '$RES/02-install.log' && ! grep -q WARNING '$RES/02-install.log'"
en="$(G 'systemctl list-unit-files "secure-sudo-*" --no-legend | awk "\$2 == \"enabled\"" | wc -l' 2>/dev/null)"
eq "... none of them enabled" "${en:-x}" 0
G 'bash /root/a/tests/vm/distro/addon-units-guest.sh' > "$RES/03-units.log" 2>&1
n=0
while IFS= read -r line; do
	case "$line" in
	"R ok "*) ok "${line#R ok }"; n=$((n + 1)) ;;
	"R fail "*) not_ok "${line#R fail }"; n=$((n + 1)) ;;
	"# "*) echo "$line" ;;
	esac
done < "$RES/03-units.log"
check "the guest ran every unit check" test "$n" -ge 16
G 'journalctl --no-pager -u "secure-sudo-*"' > "$RES/04-journal.log" 2>&1
tap_done
