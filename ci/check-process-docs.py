#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# check-process-docs.py - the disclosure and maintenance process (SECURITY.md,
# docs/MAINTENANCE.md, TODO P3-3) must keep its parts: the reporting channel,
# the response targets, triage, the security-fix release steps, kernel/LTS
# tracking, dependency updates and the deprecation policy, and every file it
# points to must exist. Usage: check-process-docs.py ROOT
import os, re, sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
problems = []


def bad(msg):
    problems.append(msg)
    print("FAIL " + msg, file=sys.stderr)


def read(rel):
    try:
        return open(os.path.join(root, rel), encoding="utf-8").read()
    except OSError:
        bad(f"{rel} is missing")
        return ""


sec = read("SECURITY.md")
mnt = read("docs/MAINTENANCE.md")

for needle, why in (("## Reporting a vulnerability", "the reporting section"),
                    ("private vulnerability reporting", "the private channel"),
                    ("Acknowledge", "the acknowledge target"),
                    ("Triage", "the triage target"),
                    ("critical", "a critical-severity fix target"),
                    ("## Supported releases", "the supported-releases section"),
                    ("## Scope", "the scope section")):
    if sec and needle.lower() not in sec.lower():
        bad(f"SECURITY.md lacks {why}")
if sec and not re.search(r"\b\d+ days\b", sec):
    bad("SECURITY.md gives no response time in days")

for needle in ("## 1. Vulnerability triage", "## 2. Security-fix release process",
               "## 3. Kernel API and LTS tracking", "## 4. Dependency updates",
               "## 5. Deprecation policy", "## 6. Keeping the process testable"):
    if mnt and needle not in mnt:
        bad(f"docs/MAINTENANCE.md lacks '{needle}'")

# every relative link in the two documents resolves
for rel, text in (("SECURITY.md", sec), ("docs/MAINTENANCE.md", mnt)):
    base = os.path.dirname(os.path.join(root, rel))
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", text):
        if re.match(r"[a-z]+:", target):
            continue
        if not os.path.exists(os.path.normpath(os.path.join(base, target))):
            bad(f"{rel} links to {target}, which does not exist")

# the scripts and files the process names exist
for rel in ("ci/build-gate.sh", "ci/make-release.sh", "ci/release-epoch",
            "ci/lsm-compile-check.sh", "ci/check-support-matrix.py",
            "install/keys/release-signers.txt", "docs/SUPPORT.md", "docs/RECOVERY.md"):
    if not os.path.exists(os.path.join(root, rel)):
        bad(f"the process names {rel}, which does not exist")

if not problems:
    print("ok security and maintenance process documents are complete")
sys.exit(1 if problems else 0)
