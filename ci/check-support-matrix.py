#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# check-support-matrix.py - the release-support matrix (docs/SUPPORT.md, TODO
# P3-1) must be current for the release being built. Fails when:
#   - the "Release:" line is missing or differs from VERSION;
#   - "Matrix reviewed:" is not a real date;
#   - a table row's status is not tested, compile-checked, expected or
#     unsupported;
#   - a tested or compile-checked row names no date (YYYY-MM-DD);
#   - the document lacks the kernels, distributions, boot methods, toolchain
#     and end-of-support sections.
# Usage: check-support-matrix.py ROOT   (prints "ok ..." / "FAIL ..." lines)
import datetime, os, re, sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
doc = os.path.join(root, "docs", "SUPPORT.md")
problems = []


def bad(msg):
    problems.append(msg)
    print("FAIL " + msg, file=sys.stderr)


try:
    text = open(doc, encoding="utf-8").read()
    version = open(os.path.join(root, "VERSION")).read().strip()
except OSError as e:
    print(f"FAIL cannot read {e.filename}: {e.strerror}", file=sys.stderr)
    sys.exit(1)

m = re.search(r"^Release:\s*(\S+)\s*$", text, re.M)
if not m:
    bad("docs/SUPPORT.md has no 'Release:' line")
elif m.group(1) != version:
    bad(f"docs/SUPPORT.md is for release {m.group(1)} but VERSION is {version}: update the matrix")
else:
    print(f"ok matrix is for release {version}")

m = re.search(r"^Matrix reviewed:\s*(\d{4}-\d\d-\d\d)\s*$", text, re.M)
try:
    datetime.date.fromisoformat(m.group(1)) if m else None
    if not m:
        raise ValueError
    print(f"ok matrix reviewed {m.group(1)}")
except ValueError:
    bad("docs/SUPPORT.md has no valid 'Matrix reviewed: YYYY-MM-DD' line")

STATUS = {"tested", "compile-checked", "expected", "unsupported"}
rows = 0
for n, line in enumerate(text.splitlines(), 1):
    if not line.startswith("|") or re.match(r"^\|\s*-", line):
        continue
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) < 3 or cells[1].lower() in ("status",):
        continue
    rows += 1
    st = cells[1]
    if st not in STATUS:
        bad(f"line {n}: status '{st}' is not one of {sorted(STATUS)}")
    elif st in ("tested", "compile-checked") and not re.search(r"\d{4}-\d\d-\d\d", cells[2]):
        bad(f"line {n}: a {st} row must name the date of its run")
if rows < 10:
    bad(f"only {rows} matrix rows found")
else:
    print(f"ok {rows} matrix rows checked")

for sect in ("## 1. Kernels", "## 2. Distributions", "## 3. Boot methods",
             "## 4. Toolchain", "## 5. End-of-support policy"):
    if sect not in text:
        bad(f"missing section '{sect}'")

sys.exit(1 if problems else 0)
