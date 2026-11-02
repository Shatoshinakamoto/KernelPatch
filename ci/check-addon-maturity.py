#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check-addon-maturity.py [ROOT] - hold the temporary/ add-ons to their
published maturity status (TODO P2-2).

temporary/maturity.json says, per add-on, what it does, its default mode, its
units and which maturity requirements are done or still open. This checks
that the tree agrees with it:

  - every add-on in temporary/ and every unit in temporary/systemd/ is listed;
  - each requirement is done, open or not applicable - never unaccounted;
  - "check-config" done: the source has the command and refuses bad configs;
  - every unit has OnFailure= reporting, MemoryMax=, TasksMax=,
    NoNewPrivileges=, no restart loop on a config error, a clean
    `systemd-analyze verify`, and a `systemd-analyze security` exposure at
    most its max_exposure;
  - the shipped config template's mode is the published default, and an
    acting default carries a note saying why that is safe;
  - the installer enables no unit;
  - docs/ADDONS.md has a maturity row and a threat model per add-on and the
    upgrade/rollback section;
  - the promotion criteria are operator-approved (who, when) and complete;
  - an add-on above "experimental" has no open item and a promotion record
    that meets them: who approved it and when, the soak host, a soak (and,
    for stable, an enforcing period) at least as long as the criteria say,
    every alert in it explained, and for stable a recorded recovery drill.

Needs systemd-analyze (systemd >= 250) unless SS_NO_SYSTEMD_ANALYZE=1.
Exit 0 if all pass. Prints one line per check, failures first.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.join(os.path.dirname(__file__), ".."))
TMP = os.path.join(ROOT, "temporary")
UNITS = os.path.join(TMP, "systemd")
CONFS = os.path.join(TMP, "config")
FAIL_UNIT = "secure-sudo-addon-failure@.service"
ACTING = {"enforce", "quarantine"}

bad, good = [], []


def check(ok, what):
    (good if ok else bad).append(what)
    return ok


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def unit_keys(text):
    """{section: {key: [values]}} of a unit file."""
    out, sec = {}, None
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln[0] in "#;":
            continue
        m = re.fullmatch(r"\[(\w+)\]", ln)
        if m:
            sec = out.setdefault(m.group(1), {})
            continue
        if "=" in ln and sec is not None:
            k, v = ln.split("=", 1)
            sec.setdefault(k.strip(), []).append(v.strip())
    return out


def conf_mode(name):
    p = os.path.join(CONFS, name)
    if not os.path.exists(p):
        return None
    for ln in read(p).splitlines():
        m = re.fullmatch(r"\s*mode\s*=\s*(\S+)\s*", ln)
        if m:
            return m.group(1)
    return None


def analyze_available():
    if os.environ.get("SS_NO_SYSTEMD_ANALYZE") == "1":
        return False
    return check(shutil.which("systemd-analyze") is not None,
                 "systemd-analyze is installed (or set SS_NO_SYSTEMD_ANALYZE=1)")


def exposure(unit_path):
    p = subprocess.run(["systemd-analyze", "security", "--offline=yes", "--no-pager",
                        unit_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
    m = re.search(r"Overall exposure level for \S+: ([0-9.]+)", p.stdout)
    return float(m.group(1)) if m else None


def verify_units(units):
    """systemd-analyze verify against a scratch root with stub executables,
    so it checks the files, not this machine. Returns its output."""
    with tempfile.TemporaryDirectory() as r:
        os.makedirs(os.path.join(r, "etc/systemd/system"))
        sysd = "/usr/lib/systemd/system"
        if os.path.isdir(sysd):
            shutil.copytree(sysd, os.path.join(r, "usr/lib/systemd/system"), symlinks=True)
        for u in os.listdir(UNITS):
            shutil.copy(os.path.join(UNITS, u), os.path.join(r, "etc/systemd/system", u))
            for ln in read(os.path.join(UNITS, u)).splitlines():
                m = re.match(r"\s*Exec\w+=[-@:+!]*(/\S+)", ln)
                if m:
                    exe = os.path.join(r, m.group(1).lstrip("/"))
                    os.makedirs(os.path.dirname(exe), exist_ok=True)
                    with open(exe, "w") as f:
                        f.write("#!/bin/sh\n")
                    os.chmod(exe, 0o755)
        names = [u.replace("@.service", "@check.service") for u in units]
        p = subprocess.run(["systemd-analyze", "verify", "--man=no", "--root=" + r] + names,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return (p.stdout.replace(r, "") + ("" if p.returncode == 0 else
                                           "exit %d" % p.returncode)).strip()


def _days(a, b):
    """Whole days from ISO date a to ISO date b, or None if either is bad."""
    try:
        return (date.fromisoformat(b) - date.fromisoformat(a)).days
    except (TypeError, ValueError):
        return None


def criteria_problems(c):
    """What is missing from the approved criteria (TODO P2-2 part 4)."""
    out = []
    if not (c.get("approved_by") and _days(c.get("date"), c.get("date")) == 0):
        out.append("the criteria record who approved them and the date (YYYY-MM-DD)")
    b, st = c.get("beta"), c.get("stable")
    if not isinstance(b, dict) or not isinstance(b.get("soak_days"), int) or b["soak_days"] < 1:
        out.append("beta has a soak_days of at least 1")
    if not isinstance(st, dict) or not isinstance(st.get("enforce_days"), int) or st["enforce_days"] < 1:
        out.append("stable has an enforce_days of at least 1")
    if isinstance(st, dict) and not st.get("recovery_drill"):
        out.append("stable requires a recovery drill")
    return out


def promotion_problems(level, c, pr):
    """Why the promotion record @pr does not meet criteria @c for @level."""
    out = []
    steps = ["beta"] if level == "beta" else ["beta", "stable"]
    for step in steps:
        r = pr.get(step)
        if not isinstance(r, dict):
            out.append("no %s promotion record" % step)
            continue
        if not (r.get("approved_by") and _days(r.get("date"), r.get("date")) == 0):
            out.append("%s: who approved it and when (YYYY-MM-DD)" % step)
        if not r.get("host"):
            out.append("%s: the host it ran on" % step)
        if step == "beta":
            d, need, what = _days(r.get("soak_start"), r.get("soak_end")), c["beta"]["soak_days"], "soak"
        else:
            d, need, what = (_days(r.get("enforce_start"), r.get("enforce_end")),
                             c["stable"]["enforce_days"], "enforcing period")
        if d is None or d < need:
            out.append("%s: a %s of at least %d days (start/end dates; got %s)" % (step, what, need, d))
        alerts = r.get("alerts")
        if not isinstance(alerts, list) or any(
                not (isinstance(a, dict) and a.get("alert") and a.get("explained")) for a in alerts):
            out.append("%s: every alert listed with its explanation (an empty list if none)" % step)
        if step == "stable":
            rd = r.get("recovery_drill")
            if not (isinstance(rd, dict) and _days(rd.get("date"), rd.get("date")) == 0 and rd.get("what")):
                out.append("stable: the recovery drill's date and what was undone")
    return out


def main():
    try:
        m = json.loads(read(os.path.join(TMP, "maturity.json")))
    except (OSError, ValueError) as e:
        print("FAIL temporary/maturity.json is readable JSON (%s)" % e)
        return 1
    levels, reqs, addons = m.get("levels", []), m.get("requirements", {}), m.get("addons", {})
    check(levels and levels[0] == "experimental", "the lowest maturity level is 'experimental'")
    crit = m.get("criteria", {})
    cp = criteria_problems(crit)
    check(not cp, "the promotion criteria are operator-approved and complete%s" %
          ("" if not cp else ": " + "; ".join(cp)))

    # every add-on directory and unit is listed
    listed_src = {a.get("source") for a in addons.values()}
    for d in sorted(os.listdir(TMP)):
        dp = os.path.join(TMP, d)
        if d == "common" or not os.path.isdir(dp) or not os.path.exists(os.path.join(dp, "Makefile")):
            continue
        check(any(s and s.startswith("temporary/%s/" % d) for s in listed_src),
              "temporary/%s/ is listed in maturity.json" % d)
    listed_units = {u for a in addons.values() for u in a.get("units", {})}
    for u in sorted(os.listdir(UNITS)):
        if u.endswith(".service"):
            check(u in listed_units, "%s belongs to an add-on in maturity.json" % u)

    docs = read(os.path.join(ROOT, "docs/ADDONS.md"))
    check(re.search(r"^## Upgrade and rollback\s*$", docs, re.M) is not None,
          "docs/ADDONS.md has the 'Upgrade and rollback' section")
    use_sa = analyze_available()
    if use_sa:
        out = verify_units(sorted(listed_units))
        check(out == "", "systemd-analyze verify is clean for every unit%s" %
              ("" if out == "" else ": " + out.replace("\n", "; ")[:400]))

    for name, a in sorted(addons.items()):
        lvl = a.get("level")
        check(lvl in levels, "%s: level %r is a known level" % (name, lvl))
        done, opn, na = set(a.get("done", [])), set(a.get("open", [])), set(a.get("na", []))
        check(not (done & opn), "%s: nothing is both done and open" % name)
        unknown = (done | opn | na) - set(reqs)
        check(not unknown, "%s: every requirement named is defined%s" %
              (name, " (unknown: %s)" % ", ".join(sorted(unknown)) if unknown else ""))
        missing = set(reqs) - (done | opn | na)
        check(not missing, "%s: every requirement is done, open or not applicable%s" %
              (name, " (unaccounted: %s)" % ", ".join(sorted(missing)) if missing else ""))
        src = os.path.join(ROOT, a.get("source", ""))
        if not check(os.path.isfile(src), "%s: source %s exists" % (name, a.get("source"))):
            continue
        s = read(src)
        if "check-config" in done:
            check("check-config" in s and ("ssc_refuse" in s or "refusing to start" in s
                                           or "refuse_bad_conf" in s),
                  "%s: has check-config and refuses to act on a bad config" % name)
        for c in a.get("configs", []):
            check(os.path.isfile(os.path.join(CONFS, c)), "%s: config template %s exists" % (name, c))
        mode = conf_mode(a["configs"][0]) if a.get("configs") else None
        if mode is not None:
            check(mode == a.get("default_mode"), "%s: the shipped mode (%s) is the published default (%s)"
                  % (name, mode, a.get("default_mode")))
        if a.get("default_mode") in ACTING:
            check(bool(a.get("default_mode_note")),
                  "%s: an acting default mode says why it is safe (default_mode_note)" % name)
        if lvl != "experimental":
            check(not opn, "%s: %s has no open requirement" % (name, lvl))
            if not cp:
                pp = promotion_problems(lvl, crit, a.get("promotion", {}))
                check(not pp, "%s: its promotion record meets the %s criteria%s" %
                      (name, lvl, "" if not pp else ": " + "; ".join(pp)))
        row = re.search(r"^\|\s*`?%s`?\s*\|([^\n]*)" % re.escape(name), docs, re.M)
        check(row is not None and lvl in row.group(1),
              "%s: docs/ADDONS.md maturity table lists it as %s" % (name, lvl))
        check(re.search(r"^#### .*\b%s\b" % re.escape(name), docs, re.M | re.I) is not None,
              "%s: docs/ADDONS.md has its threat model (#### ... %s)" % (name, name))

        for u, spec in sorted(a.get("units", {}).items()):
            up = os.path.join(UNITS, u)
            if not check(os.path.isfile(up), "%s: unit %s exists" % (name, u)):
                continue
            k = unit_keys(read(up))
            svc, un = k.get("Service", {}), k.get("Unit", {})
            if u != FAIL_UNIT:
                check("secure-sudo-addon-failure@%n.service" in un.get("OnFailure", []),
                      "%s: OnFailure= reports a failure" % u)
            for key in ("MemoryMax", "TasksMax"):
                check(key in svc, "%s: %s= is set" % (u, key))
            check(svc.get("NoNewPrivileges") == ["yes"], "%s: NoNewPrivileges=yes" % u)
            if "on-failure" in svc.get("Restart", []) or "always" in svc.get("Restart", []):
                check("78" in " ".join(svc.get("RestartPreventExitStatus", [])),
                      "%s: a config error (exit 78) does not restart-loop" % u)
            if use_sa:
                e = exposure(up)
                lim = float(spec.get("max_exposure", 4.0))
                check(e is not None and e <= lim, "%s: exposure %s <= %.1f" % (u, e, lim))

    inst = read(os.path.join(TMP, "install-temporary.sh"))
    body = inst.split("cat <<'NEXT'")[0]
    check(not re.search(r"^\s*[^#\n]*systemctl\s+(--now\s+)?enable", body, re.M),
          "install-temporary.sh enables no unit (every add-on stays opt-in)")

    for b in bad:
        print("FAIL " + b)
    for g in good:
        print("ok   " + g)
    print("add-on maturity: %d checks, %d failed" % (len(good) + len(bad), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
