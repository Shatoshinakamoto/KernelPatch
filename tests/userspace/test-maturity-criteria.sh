#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# test-maturity-criteria.sh - the add-on promotion criteria the operator
# approved (TODO P2-2 part 4) are what ci/check-addon-maturity.py enforces:
# a beta needs a 14-day soak with every alert explained, a stable needs a
# 30-day enforcing period and a recovery drill on top. No root needed.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/tests/lib/tap.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

cat > "$T/t.py" <<'PY'
import copy, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("cm", sys.argv[1] + "/ci/check-addon-maturity.py")
cm = importlib.util.module_from_spec(spec); spec.loader.exec_module(cm)
c = json.load(open(sys.argv[1] + "/temporary/maturity.json"))["criteria"]
beta = {"approved_by": "Pheonix", "date": "2026-12-01", "host": "srv1",
        "soak_start": "2026-11-10", "soak_end": "2026-11-24",
        "alerts": [{"alert": "x killed", "explained": "allowlist gap, fixed"}]}
stable = {"approved_by": "Pheonix", "date": "2027-01-05", "host": "srv1",
          "enforce_start": "2026-12-02", "enforce_end": "2027-01-01", "alerts": [],
          "recovery_drill": {"date": "2027-01-02", "what": "restored a quarantined sample"}}
def p(level, pr): return cm.promotion_problems(level, c, pr)
def say(name, ok): print("R %s=%d" % (name, 1 if ok else 0))
say("criteria_ok", cm.criteria_problems(c) == [])
say("criteria_approved", c.get("approved_by") == "Pheonix" and c["beta"]["soak_days"] == 14
    and c["stable"]["enforce_days"] == 30)
say("beta_ok", p("beta", {"beta": beta}) == [])
b = copy.deepcopy(beta); b["soak_end"] = "2026-11-23"
say("short_soak", any("at least 14 days" in x for x in p("beta", {"beta": b})))
b = copy.deepcopy(beta); b["alerts"] = [{"alert": "y repaired"}]
say("unexplained", any("every alert" in x for x in p("beta", {"beta": b})))
b = copy.deepcopy(beta); del b["approved_by"]
say("no_approval", any("who approved" in x for x in p("beta", {"beta": b})))
say("stable_ok", p("stable", {"beta": beta, "stable": stable}) == [])
say("stable_needs_beta", any("no beta" in x for x in p("stable", {"stable": stable})))
s = copy.deepcopy(stable); s["enforce_end"] = "2026-12-20"
say("short_enforce", any("at least 30 days" in x for x in p("stable", {"beta": beta, "stable": s})))
s = copy.deepcopy(stable); del s["recovery_drill"]
say("no_drill", any("recovery drill" in x for x in p("stable", {"beta": beta, "stable": s})))
bad = copy.deepcopy(c); del bad["approved_by"]
say("unapproved_criteria", cm.criteria_problems(bad) != [])
PY
python3 -B "$T/t.py" "$ROOT" > "$T/out" 2>&1
r() { sed -n "s/^R $1=//p" "$T/out"; }
eq "the shipped criteria are approved and complete" "$(r criteria_ok)" 1
eq "... they are the ones the operator chose (14-day soak, 30 days enforcing)" "$(r criteria_approved)" 1
eq "a 14-day soak with every alert explained meets beta" "$(r beta_ok)" 1
eq "a 13-day soak does not" "$(r short_soak)" 1
eq "an alert without an explanation does not" "$(r unexplained)" 1
eq "a promotion nobody approved does not" "$(r no_approval)" 1
eq "beta plus 30 days enforcing and a recovery drill meets stable" "$(r stable_ok)" 1
eq "stable without a beta record does not" "$(r stable_needs_beta)" 1
eq "18 days enforcing does not" "$(r short_enforce)" 1
eq "stable without a recovery drill does not" "$(r no_drill)" 1
eq "criteria without the operator's approval fail the gate" "$(r unapproved_criteria)" 1
[ -s "$T/out" ] && grep -v '^R ' "$T/out" | sed 's/^/# /' | head -5
tap_done
