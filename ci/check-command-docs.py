#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# check-command-docs.py - the per-command and per-feature pages (CLAUDE.MD
# section 5) must stay in step with the code:
#   - every `secure-sudo` subcommand the CLI dispatches has
#     docs/commands/secure-sudo-<name>.md;
#   - every script in scripts/, ci/ and userspace/daemon/helpers/, plus
#     tests/run-all.sh and temporary/install-temporary.sh, is named (by its
#     path) on some docs/commands/ page;
#   - every temporary/ add-on binary has docs/commands/<binary>.md;
#   - a page that copies a source file's header ("The script's own header is
#     the reference") still matches that header;
#   - every docs/features/ page has the eight required sections;
#   - every docs/commands/ and docs/features/ page is linked from
#     docs/README.md.
# Usage: check-command-docs.py ROOT. Prints "FAIL ..." lines to stderr and
# exits 1 on any problem.
import glob, os, re, sys

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


def header(rel):
    """The leading comment block of a script, as the command pages copy it."""
    lines = read(rel).splitlines()
    out, started = [], False
    for i, l in enumerate(lines):
        if i == 0 and l.startswith("#!"):
            continue
        s = l.strip()
        if re.match(r"^(#|//|\*|/\*|\*/)", s) or (s == "" and not started):
            if "SPDX-" in s:
                continue
            started = True
            out.append(re.sub(r"^(#!?|//|/\*+|\*/|\*)\s?", "", s))
        elif s.startswith('"""') and not started:
            body = s[3:]
            if body.endswith('"""'):
                out.append(body[:-3])
                break
            out.append(body)
            for l2 in lines[i + 1:]:
                if '"""' in l2:
                    out.append(l2.split('"""')[0])
                    break
                out.append(l2)
            break
        else:
            break
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


pages = {os.path.basename(p): open(p, encoding="utf-8").read()
         for p in glob.glob(os.path.join(root, "docs", "commands", "*.md"))}
alltext = "\n".join(pages.values())

# ---- CLI subcommands ---------------------------------------------------------
cli = read("userspace/cli/secure-sudo.c")
subs = sorted(set(re.findall(r'!strcmp\(argv\[1\], "([a-z-]+)"\)', cli)) - {"on", "off"})
if cli and not subs:
    bad("could not read the subcommands from userspace/cli/secure-sudo.c")
for s in subs:
    if f"secure-sudo-{s}.md" not in pages:
        bad(f"docs/commands/secure-sudo-{s}.md is missing (secure-sudo {s})")

# ---- scripts -------------------------------------------------------------------
scripts = []
for pat in ("scripts/*.sh", "scripts/*.py", "ci/*.sh", "ci/*.py",
            "userspace/daemon/helpers/*"):
    scripts += sorted(os.path.relpath(p, root) for p in glob.glob(os.path.join(root, pat)))
scripts += ["tests/run-all.sh", "temporary/install-temporary.sh"]
for s in scripts:
    if f"`{s}`" not in alltext and f"({'../../' + s})" not in alltext:
        bad(f"no docs/commands/ page names {s}")

# ---- add-on binaries -------------------------------------------------------------
for mk in sorted(glob.glob(os.path.join(root, "temporary", "*", "Makefile"))):
    m = re.search(r"^BIN\s*=\s*(\S+)", open(mk, encoding="utf-8").read(), re.M)
    if m and f"{m.group(1)}.md" not in pages:
        bad(f"docs/commands/{m.group(1)}.md is missing ({os.path.relpath(mk, root)})")

# ---- copied headers ------------------------------------------------------------
for name, text in sorted(pages.items()):
    if "The script's own header is the reference" not in text:
        continue
    src = re.search(r"\*\*Source:\*\* \[`([^`]+)`\]", text)
    block = re.search(r"```text\n(.*?)\n```", text, re.S)
    if not src or not block:
        bad(f"docs/commands/{name}: copied header page without a Source line or text block")
        continue
    if block.group(1) != header(src.group(1)):
        bad(f"docs/commands/{name}: the usage block differs from {src.group(1)}'s header")

# ---- feature pages ---------------------------------------------------------------
SECTIONS = ("Overview", "How it works", "How it is secure", "How to use it",
            "Dependencies", "Limitations and known risks", "Troubleshooting",
            "Test evidence")
for p in sorted(glob.glob(os.path.join(root, "docs", "features", "*.md"))):
    heads = re.findall(r"^## (.+?)\s*$", open(p, encoding="utf-8").read(), re.M)
    for s in SECTIONS:
        if s not in heads:
            bad(f"{os.path.relpath(p, root)}: no '## {s}' section")

# ---- index ---------------------------------------------------------------------
index = read("docs/README.md")
for sub in ("commands", "features"):
    for p in sorted(glob.glob(os.path.join(root, "docs", sub, "*.md"))):
        name = os.path.basename(p)
        if f"({sub}/{name})" not in index:
            bad(f"docs/README.md does not link {sub}/{name}")

if problems:
    print(f"check-command-docs: {len(problems)} problem(s)", file=sys.stderr)
    sys.exit(1)
print(f"check-command-docs: ok ({len(subs)} subcommands, {len(scripts)} scripts, "
      f"{len(pages)} command pages)")
