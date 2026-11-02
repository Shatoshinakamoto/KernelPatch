#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""oscap-results.py - read OpenSCAP results by rule ID (TODO P0-2).

Reads an XCCDF/ARF results file (oscap xccdf eval --results/--results-arf)
or the console output of `oscap xccdf eval` ("Rule <id>" / "Result <r>").

  tally    FILE                 one line: pass=N fail=N ... (every result kind)
  rules    FILE [--not-pass]    "<result> <rule>" lines (short rule ids)
  skip-fix FIX REGEX            drop the fix blocks of matching rules from a
                                generated bash remediation; list them in
                                FIX.skipped
  gate     FILE --expect FILE [--mode release|diagnostic] [--crosscheck FILE]
                                the STIG regression gate, see below

The gate compares rule IDs, not totals. The expectation file lists, one per
line, "<result> <rule> <reason...>" for every rule allowed NOT to pass, e.g.
"fail encrypt_partitions OSB-12 ...". Release mode passes only if:
  - every failed rule is listed as an allowed fail (exactly the listed set),
  - there is no error and no unknown result at all,
  - every notchecked rule is listed (explained) - and it is still reported
    as needing manual review, never counted as a pass,
  - every other evaluated rule passed (or is notapplicable/notselected).
Diagnostic mode (containers) prints the same comparison, marks results the
expectation file tags "container-only" as environment noise, and exits 0
unless a rule fails that no line explains. Its output always says it is not
a release result.

Rules the scanner cannot evaluate on this platform (OSB-19) are listed as
"crosscheck <rule> <reason>". scripts/stig-harden.sh checks those itself and
writes "<result> <rule> <evidence>" lines next to each result file
(<name>.crosscheck, picked up automatically, or --crosscheck FILE). The gate
uses that result instead of the scanner's and says so; in release mode a
listed rule without one fails the gate.
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

PREFIX = "xccdf_org.ssgproject.content_rule_"
KINDS = ("pass", "fail", "error", "unknown", "notapplicable", "notchecked",
         "notselected", "informational", "fixed")
OK_KINDS = ("pass", "notapplicable", "notselected", "fixed")


def short(rule):
    return rule[len(PREFIX):] if rule.startswith(PREFIX) else rule


def load(path):
    """Return {short rule id: result}."""
    with open(path, "rb") as f:
        head = f.read(512).lstrip()
    out = {}
    if head.startswith(b"<"):
        for _, el in ET.iterparse(path, events=("end",)):
            if el.tag.rsplit("}", 1)[-1] != "rule-result":
                continue
            res = None
            for ch in el:
                if ch.tag.rsplit("}", 1)[-1] == "result":
                    res = (ch.text or "").strip()
            if el.get("idref") and res:
                out[short(el.get("idref"))] = res
            el.clear()
        return out
    rule = None
    # oscap's console output rewrites lines with "\r" (e.g. "Rule\r\t<id>"),
    # so read without newline translation and drop the carriage returns.
    with open(path, encoding="utf-8", errors="replace", newline="\n") as f:
        for line in f:
            line = line.replace("\r", "")
            m = re.match(r"^Rule\s+(\S+)", line)
            if m:
                rule = m.group(1)
                continue
            m = re.match(r"^Result\s+(\S+)", line)
            if m and rule:
                out[short(rule)] = m.group(1)
                rule = None
    return out


def tally(results):
    counts = {k: 0 for k in KINDS}
    for r in results.values():
        counts[r] = counts.get(r, 0) + 1
    return " ".join("%s=%d" % (k, v) for k, v in counts.items()
                    if v or k in ("pass", "fail", "error", "notchecked"))


def load_expect(path):
    """({rule: (result, reason, container_only)}, {rule: reason} to cross-check)"""
    exp, cross = {}, {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0] == "crosscheck":
                cross[short(parts[1])] = parts[2]
                continue
            if len(parts) < 3 or parts[0] not in KINDS:
                sys.exit("oscap-results: %s:%d: want '<result> <rule> <reason>'"
                         % (path, n))
            exp[short(parts[1])] = (parts[0], parts[2],
                                    "container-only" in parts[2])
    return exp, cross


def load_crosscheck(path):
    """{rule: (result, evidence)} from stig-harden.sh's independent checks"""
    out = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            parts = line.strip().split(None, 2)
            if not parts:
                continue
            if len(parts) < 2 or parts[0] not in KINDS:
                sys.exit("oscap-results: %s:%d: want '<result> <rule> <evidence>'"
                         % (path, n))
            out[short(parts[1])] = (parts[0], parts[2] if len(parts) > 2 else "")
    return out


def apply_crosscheck(results, checks, required, mode):
    """Replace the scanner's answer for cross-checked rules; return notes, problems."""
    notes, problems = [], []
    for rule, (res, why) in sorted(checks.items()):
        if rule not in results:
            continue
        was = results[rule]
        results[rule] = res
        if was == res:
            notes.append("%s %s: independent check agrees (%s)" % (res, rule, why))
        else:
            notes.append("%s %s: the scanner said %s; the independent check says %s (%s)"
                         % (res, rule, was, res, why))
    for rule, reason in sorted(required.items()):
        if rule in results and rule not in checks:
            msg = ("%s %s: the scanner cannot evaluate this rule (%s) and no "
                   "independent check was recorded" % (results[rule], rule, reason))
            (problems if mode == "release" else notes).append(msg)
    return notes, problems


def gate(results, exp, mode):
    problems, notes = [], []
    for rule, res in sorted(results.items()):
        if res in OK_KINDS:
            continue
        e = exp.get(rule)
        if e and e[0] == res:
            if e[2]:
                (notes if mode == "diagnostic" else problems).append(
                    "%s %s: container-only result (%s)%s" % (
                        res, rule, e[1],
                        "" if mode == "diagnostic" else
                        " - must not happen in the release VM"))
            elif res == "notchecked":
                notes.append("notchecked %s: MANUAL REVIEW NEEDED (%s)" % (rule, e[1]))
            else:
                notes.append("%s %s: allowed (%s)" % (res, rule, e[1]))
        elif e:
            problems.append("%s %s: expected %s (%s)" % (res, rule, e[0], e[1]))
        else:
            problems.append("%s %s: not explained by the expectation file" % (res, rule))
    for rule, e in sorted(exp.items()):
        if rule not in results and not e[2]:
            problems.append("%s %s: listed but not in the results (profile changed?)"
                            % (e[0], rule))
    if mode == "release":
        for k in ("error", "unknown"):
            if any(r == k for r in results.values()):
                problems.append("release gate: %s results are never allowed" % k)
    # de-duplicate, keep order
    seen, uniq = set(), []
    for p in problems:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq, notes


def skip_fix(fix, pattern):
    pat = re.compile(pattern)
    out, dropped, skip = [], [], False
    with open(fix, encoding="utf-8", errors="surrogateescape") as f:
        lines = f.readlines()
    for line in lines:
        m = re.match(r"# BEGIN fix \(.*\) for '([^']+)'", line)
        if m and pat.search(m.group(1)):
            skip = True
            dropped.append(m.group(1))
        if not skip:
            out.append(line)
        if skip and line.startswith("# END fix for"):
            skip = False
    if skip:
        sys.exit("oscap-results: %s: fix block for %s has no END marker; "
                 "not rewritten" % (fix, dropped[-1]))
    with open(fix, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.writelines(out)
    with open(fix + ".skipped", "w", encoding="utf-8") as f:
        f.write("".join(d + "\n" for d in dropped))
    return dropped


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd, args = argv[1], argv[2:]
    if cmd == "tally" and len(args) == 1:
        print(tally(load(args[0])))
    elif cmd == "rules" and args:
        res = load(args[0])
        for rule, r in sorted(res.items()):
            if "--not-pass" in args and r in OK_KINDS:
                continue
            print(r, rule)
    elif cmd == "skip-fix" and len(args) == 2:
        print(len(skip_fix(args[0], args[1])))
    elif cmd == "gate" and args:
        mode, expect, xfile = "release", None, None
        rest = args[1:]
        while rest:
            if rest[0] == "--mode" and len(rest) > 1 and rest[1] in ("release", "diagnostic"):
                mode, rest = rest[1], rest[2:]
            elif rest[0] == "--expect" and len(rest) > 1:
                expect, rest = rest[1], rest[2:]
            elif rest[0] == "--crosscheck" and len(rest) > 1:
                xfile, rest = rest[1], rest[2:]
            else:
                sys.exit("oscap-results: gate: bad argument %s" % rest[0])
        if not expect:
            sys.exit("oscap-results: gate needs --expect FILE")
        results = load(args[0])
        if not results:
            print("STIG gate (%s): FAIL - no rule results in %s" % (mode, args[0]))
            return 1
        exp, required = load_expect(expect)
        if xfile is None and os.path.exists(os.path.splitext(args[0])[0] + ".crosscheck"):
            xfile = os.path.splitext(args[0])[0] + ".crosscheck"
        checks = load_crosscheck(xfile) if xfile else {}
        scanner = tally(results)
        xnotes, xproblems = apply_crosscheck(results, checks, required, mode)
        problems, notes = gate(results, exp, mode)
        problems, notes = xproblems + problems, xnotes + notes
        label = "release" if mode == "release" else \
            "DIAGNOSTIC (not a release result)"
        print("STIG gate %s: %s" % (label, tally(results)))
        if checks:
            print("  scanner alone: %s; independent checks: %s" % (scanner, xfile))
        for n in notes:
            print("  note: " + n)
        for p in problems:
            print("  FAIL: " + p)
        print("STIG gate %s: %s" % (label, "FAIL" if problems else "pass"))
        return 1 if problems else 0
    else:
        sys.exit(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
