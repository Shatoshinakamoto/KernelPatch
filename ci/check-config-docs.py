#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# check-config-docs.py - the per-file configuration pages in
# docs/configuration/ (CLAUDE.MD section 5) must stay in step with the code:
#   - every kernel setting (ss_knobs in userspace/cli/policy.c) and every
#     daemon key (daemon_keys there) has exactly one row in
#     docs/configuration/secure-sudo-conf.md, and no row names a key the
#     code does not know;
#   - each kernel row's "Built-in default" matches ss_core.c;
#   - each row's "Shipped" column matches the template in userspace/config/
#     (the value, "(commented)" or "(absent)");
#   - net.conf rows match the template and apply-net.sh's defaults;
#   - every page in docs/configuration/ is linked from docs/README.md.
# Usage: check-config-docs.py ROOT. Prints "FAIL ..." lines to stderr and
# exits 1 on any problem.
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


def doc_rows(rel):
    """Rows of the table between the config-keys markers: {key: [cells]}."""
    text = read(rel)
    m = re.search(r"<!-- config-keys:begin -->(.*?)<!-- config-keys:end -->",
                  text, re.S)
    if text and not m:
        bad(f"{rel}: no <!-- config-keys:begin/end --> table")
        return {}
    rows = {}
    for line in (m.group(1).splitlines() if m else []):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        km = re.fullmatch(r"`([a-z_]+)`", cells[0]) if cells else None
        if not km:
            continue
        if km.group(1) in rows:
            bad(f"{rel}: key {km.group(1)} has two rows")
        rows[km.group(1)] = cells
    return rows


def template(rel):
    """{key: value} for set keys, {key: None} for commented-out keys."""
    vals = {}
    for line in read(rel).splitlines():
        m = re.match(r"^\s*([a-z_]+)\s*=\s*(.*?)\s*$", line)
        if m:
            vals[m.group(1)] = m.group(2)
            continue
        m = re.match(r"^\s*#\s*([a-z_]+)\s*=", line)
        if m and m.group(1) not in vals:
            vals[m.group(1)] = None
    return vals


def unq(cell):
    return cell.strip().strip("`")


def shipped_ok(rel, key, cell, tmpl):
    want = tmpl.get(key, "absent")
    if want == "absent":
        expect = "(absent)"
    elif want is None:
        expect = "(commented)"
    else:
        expect = want
    got = unq(cell)
    if expect == "" and got == "empty":
        return
    if got != expect:
        bad(f"{rel}: {key} Shipped is '{got}', the template has '{expect}'")


# ---- secure-sudo.conf ------------------------------------------------------
policy = read("userspace/cli/policy.c")
knobs = re.findall(r'^\s*\{\s*"([a-z_]+)",\s*"[a-z_]+",\s*K_[A-Z]+',
                   policy, re.M)
dm = re.search(r"daemon_keys\[\]\s*=\s*\{(.*?)NULL", policy, re.S)
dkeys = re.findall(r'"([a-z_]+)"', dm.group(1)) if dm else []
if policy and (not knobs or not dkeys):
    bad("could not read ss_knobs / daemon_keys from userspace/cli/policy.c")

page = "docs/configuration/secure-sudo-conf.md"
rows = doc_rows(page)
code_keys = set(knobs) | set(dkeys)
for k in sorted(code_keys - set(rows)):
    bad(f"{page}: no row for {k}")
for k in sorted(set(rows) - code_keys):
    bad(f"{page}: row {k} is not a key the code reads")

core = read("kernel/security/secure_sudo/ss_core.c")
kdef = {}
for k, v in re.findall(r"ss_cfg\.([a-z_]+)\s*=\s*([^;]+);", core):
    v = v.strip()
    kdef[k] = {"true": "1", "false": "0"}.get(v, v)
kdef.setdefault("admin_gid", "unset")
if kdef.get("net_mode") == "SS_NET_MONITOR":
    kdef["net_mode"] = "monitor"

tmpl = template("userspace/config/secure-sudo.conf")
for k, cells in rows.items():
    if len(cells) != 6:
        bad(f"{page}: row {k} has {len(cells)} columns, want 6")
        continue
    if k in knobs and k in kdef:
        got = unq(cells[4]).split("`")[0].split(" ")[0]
        if got != kdef[k]:
            bad(f"{page}: {k} Built-in default is '{got}', ss_core.c has '{kdef[k]}'")
    shipped_ok(page, k, cells[5], tmpl)
for k in sorted(set(tmpl) - code_keys - {"timevault_enabled"}):
    bad(f"userspace/config/secure-sudo.conf: {k} is not a key the code reads")

# ---- net.conf --------------------------------------------------------------
page = "docs/configuration/net-conf.md"
rows = doc_rows(page)
ntmpl = template("userspace/config/net.conf")
apply = read("userspace/daemon/helpers/apply-net.sh")
ndef = {k: v for k, v in
        re.findall(r"\$\(conf ([a-z_]+) '?([^')]*)'?\)", apply)}
for k in sorted(set(ndef) - set(rows)):
    bad(f"{page}: no row for {k} (apply-net.sh reads it)")
for k in sorted(set(rows) - set(ndef)):
    bad(f"{page}: row {k} is not a key apply-net.sh reads")
for k, cells in rows.items():
    if len(cells) != 5:
        bad(f"{page}: row {k} has {len(cells)} columns, want 5")
        continue
    if k in ndef:
        want = ndef[k] or "empty"
        if unq(cells[3]) != want:
            bad(f"{page}: {k} Default is '{unq(cells[3])}', apply-net.sh has '{want}'")
    shipped_ok(page, k, cells[4], ntmpl)

# ---- pheonixbox.conf -------------------------------------------------------
page = "docs/configuration/pheonixbox-conf.md"
rows = doc_rows(page)
if "trust" not in rows:
    bad(f"{page}: no row for trust")
else:
    shipped_ok(page, "trust", rows["trust"][4],
               template("userspace/config/pheonixbox.conf"))

# ---- index -----------------------------------------------------------------
index = read("docs/README.md")
cdir = os.path.join(root, "docs/configuration")
for name in sorted(os.listdir(cdir)) if os.path.isdir(cdir) else []:
    if name.endswith(".md") and f"(configuration/{name})" not in index:
        bad(f"docs/README.md does not link configuration/{name}")

if problems:
    print(f"check-config-docs: {len(problems)} problem(s)", file=sys.stderr)
    sys.exit(1)
print("check-config-docs: ok")
