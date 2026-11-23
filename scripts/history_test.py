#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
"""history_test.py - the shared recorder for the HistoryTest/ test archive.

Purpose
    Every test run (local suites, the build gate, VM runs on the owner's PC,
    manual checks) is archived under HistoryTest/runs/<run-id>/ so that anyone
    can review, verify and reproduce it (CLAUDE.MD section 9). This tool is
    the only writer: it creates run folders, redacts what it stores, hashes
    every file into a manifest chained to the previous run, and regenerates
    the index. It is a development record and is never shipped
    (scripts/gen-sbom.sh excludes HistoryTest/, so releases do not contain it).

Commands
    run        execute a command and archive it        (local runs)
    add        archive results received from elsewhere (PC/VM runs)
    note       append a dated note to a run            (append-only correction)
    invalidate mark a run invalid, with the reason
    index      regenerate INDEX.csv and the README table
    verify     check hashes, the manifest chain, redaction and the index

Trust boundaries and security controls
    * Inputs are test output and files supplied by the operator. They may
      contain secrets, personal data or internal addresses, so every text
      file is redacted before it is written (CWE-532, CWE-200, NIST AU-9):
      e-mail addresses, home-directory user names, this host's name, private
      IPv4 addresses (RFC 1918) and common token formats are replaced with
      placeholders. Binary files are refused, not stored.
    * Integrity (NIST AU-10): manifest.json lists the SHA-256 of every file
      in the run and the SHA-256 of the previous run's manifest; `verify`
      recomputes both. NOTES.md and INVALID are the only files that may be
      added after a run is sealed; they are append-only and hashed into
      notes.json chains of their own.
    * Commands are executed with an argument list, never through a shell
      (CWE-78). Run ids and areas are allow-listed ([a-z0-9-]) so they cannot
      escape HistoryTest/ (CWE-22).
    * Only the Python standard library is used (no third-party dependency to
      check for CVEs).
"""

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HT = os.environ.get("SS_HISTORYTEST_DIR", os.path.join(ROOT, "HistoryTest"))
RUNS = os.path.join(HT, "runs")
VERDICTS = ("pass", "fail", "partial", "invalid")
# Files that may change after a run is sealed (append-only, see note/invalidate).
MUTABLE = ("NOTES.md", "INVALID", "notes.json")
MAX_FILE = 5 * 1024 * 1024  # SECURITY: no model weights, images or caches (CLAUDE.MD 9 "Size")
TABLE_BEGIN = "<!-- history-test:index:begin -->"
TABLE_END = "<!-- history-test:index:end -->"

# --------------------------------------------------------------- redaction

_HOST = socket.gethostname() or ""
_REDACT = [
    # SECURITY: CWE-532/CWE-200 - personal data and credentials never stored.
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
    (re.compile(r"(/home/|/Users/|C:\\\\Users\\\\|C:\\Users\\)[^/\\\s]+"), r"\1<user>"),
    (re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}\b"), "<token>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<token>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "<private-key>"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b(\s*[=:]\s*)(?!<)\S+"), r"\1\2<redacted>"),
    # SECURITY: internal addresses (NIST SC-7 info leakage). RFC 1918 only;
    # loopback and the documentation ranges stay readable.
    (re.compile(r"\b10(?:\.\d{1,3}){3}\b"), "<private-ip>"),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b"), "<private-ip>"),
    (re.compile(r"\b192\.168(?:\.\d{1,3}){2}\b"), "<private-ip>"),
]


def redact(text):
    """Return text with personal data, secrets and internal addresses replaced.

    Security: applied to every stored text file (CWE-532, CWE-200, AU-9).
    """
    for rx, rep in _REDACT:
        text = rx.sub(rep, text)
    if len(_HOST) >= 3:
        text = re.sub(r"\b%s\b" % re.escape(_HOST), "<host>", text)
    return text


def needs_redaction(text):
    """True when text still contains something redact() would change."""
    return redact(text) != text


# ----------------------------------------------------------------- helpers

def die(msg, code=2):
    print("history_test: " + msg, file=sys.stderr)
    sys.exit(code)


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def slug(value, what):
    """Allow-list an identifier: lower-case letters, digits and '-' (CWE-22)."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", value or ""):
        die("bad %s %r: use a-z, 0-9 and '-' (max 41 chars)" % (what, value))
    return value


def run_dir(run_id):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{6}Z_[a-z0-9-]+_[0-9a-f]{7,12}(-\d+)?", run_id or ""):
        die("bad run id %r" % run_id)
    d = os.path.join(RUNS, run_id)
    if not os.path.isdir(d):
        die("no such run: %s" % run_id)
    return d


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text(path, text):
    """Write redacted UTF-8 text, mode 0644, creating parent dirs."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(redact(text))
    os.chmod(path, 0o644)


def git_commit():
    try:
        return subprocess.run(["git", "-C", ROOT, "rev-parse", "--short=7", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "0000000"


def all_runs():
    if not os.path.isdir(RUNS):
        return []
    return sorted(d for d in os.listdir(RUNS) if os.path.isfile(os.path.join(RUNS, d, "manifest.json")))


def load_manifest(run_id):
    with open(os.path.join(RUNS, run_id, "manifest.json"), encoding="utf-8") as f:
        return json.load(f)


def tap_counts(text):
    ok = len(re.findall(r"(?m)^ok \d+", text))
    bad = len(re.findall(r"(?m)^not ok \d+", text))
    skipped = len(re.findall(r"(?m)^ok \d+ - # SKIP", text))
    return ok, bad, skipped


def environment_md():
    """A redacted description of where the run happened (no host or user names)."""
    osr = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                osr[k] = v.strip('"')
    except OSError:
        pass
    return "\n".join([
        "# Environment",
        "",
        "- OS: %s %s" % (osr.get("NAME", platform.system()), osr.get("VERSION_ID", "")),
        "- Kernel: %s" % platform.release(),
        "- Machine: %s, %s CPUs" % (platform.machine(), os.cpu_count()),
        "- Python: %s" % platform.python_version(),
        "- Running as root: %s" % ("yes" if hasattr(os, "geteuid") and os.geteuid() == 0 else "no"),
        "- Recorded by: scripts/history_test.py",
        "",
    ])


def new_run(area, commit, when):
    """Create an empty run folder; returns (run_id, path).

    Run ids must sort in the order runs are sealed, because the manifest chain
    follows that order. Two runs archived in the same second could sort the
    other way round (by area name), so wait for the next second when the new
    id would not sort after every existing run.
    """
    slug(area, "area")
    existing = all_runs()
    while existing and "%s_%sZ" % (when.strftime("%Y-%m-%d"), when.strftime("%H%M%S")) <= existing[-1][:18]:
        time.sleep(0.2)
        when = now()
    if not re.fullmatch(r"[0-9a-f]{7,12}", commit):
        die("bad commit %r: 7 to 12 hex digits" % commit)
    base = "%s_%sZ_%s_%s" % (when.strftime("%Y-%m-%d"), when.strftime("%H%M%S"), area, commit[:7])
    rid, n = base, 1
    while os.path.exists(os.path.join(RUNS, rid)):
        n += 1
        rid = "%s-%d" % (base, n)
    d = os.path.join(RUNS, rid)
    for sub in ("results", "logs", "artifacts", "projects/input", "projects/output"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    return rid, d


def seal(rid, meta):
    """Hash every file of the run into manifest.json, chained to the previous run."""
    d = os.path.join(RUNS, rid)
    files = {}
    for top, _, names in os.walk(d):
        for name in sorted(names):
            p = os.path.join(top, name)
            rel = os.path.relpath(p, d)
            if rel in ("manifest.json",) + MUTABLE:
                continue
            files[rel] = sha256_file(p)
    prev = [r for r in all_runs() if r < rid]
    prev_id = prev[-1] if prev else None
    meta = dict(meta)
    meta.update({
        "run_id": rid,
        "schema": 1,
        "files": dict(sorted(files.items())),
        "previous_run": prev_id,
        "previous_manifest_sha256": sha256_file(os.path.join(RUNS, prev_id, "manifest.json")) if prev_id else None,
    })
    with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, sort_keys=True)
        f.write("\n")


RUN_MD = """# {title}

- **Run id:** `{rid}`
- **Area:** {area}
- **Commit:** `{commit}`
- **Date (UTC):** {date}
- **Where:** {where}
- **Verdict:** **{verdict}**

## What was tested and why
{what}

## How
{how}

## Results
{results}

## Failures
{failures}

## Reproduce
{reproduce}
"""


def read_opt(path_or_text):
    if path_or_text and os.path.isfile(path_or_text):
        with open(path_or_text, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    return (path_or_text or "").strip()


# ---------------------------------------------------------------- commands

def cmd_run(a):
    """Execute a test command (argument list, no shell) and archive it."""
    if not a.command:
        die("run: give the command after --")
    when = now()
    commit = a.commit or git_commit()
    rid, d = new_run(a.area, commit, when)
    # SECURITY: no shell (CWE-78); the timeout bounds a hung suite.
    try:
        p = subprocess.run(a.command, cwd=ROOT, capture_output=True, text=True,
                           timeout=a.timeout, errors="replace")
        out, err, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = "timed out after %ss\n" % a.timeout
        rc = 124
    except OSError as e:
        out, err, rc = "", str(e) + "\n", 127
    write_text(os.path.join(d, "logs", "stdout.log"), out)
    write_text(os.path.join(d, "logs", "stderr.log"), err)
    write_text(os.path.join(d, "command.txt"), " ".join(a.command) + "\n")
    write_text(os.path.join(d, "environment.md"), environment_md())
    ok, bad, skipped = tap_counts(out)
    write_text(os.path.join(d, "results", "tap-summary.txt"),
               "ok=%d not_ok=%d skipped=%d exit=%d\n" % (ok, bad, skipped, rc))
    verdict = "pass" if rc == 0 and bad == 0 else "fail"
    fails = "\n".join("- `%s`" % l for l in out.splitlines() if l.startswith("not ok")) or "None."
    write_text(os.path.join(d, "RUN.md"), RUN_MD.format(
        title=a.title or "Test run: %s" % a.area, rid=rid, area=a.area, commit=commit,
        date=when.isoformat(), where=a.where, verdict=verdict,
        what=read_opt(a.what) or "See the command.",
        how="`%s` (exit code %d)." % (" ".join(a.command), rc),
        results="%d ok, %d not ok, %d skipped (TAP lines in logs/stdout.log)." % (ok, bad, skipped),
        failures=fails,
        reproduce="From the repository root at commit `%s`:\n\n```\n%s\n```" % (commit, " ".join(a.command))))
    seal(rid, {"kind": "run", "area": a.area, "commit": commit, "verdict": verdict,
               "date": when.isoformat(), "where": a.where, "exit_code": rc,
               "tap": {"ok": ok, "not_ok": bad, "skipped": skipped}})
    cmd_index(a)
    print(rid)
    return 0 if verdict == "pass" else 1


def cmd_add(a):
    """Archive results that were produced elsewhere (e.g. the owner's PC)."""
    if a.verdict not in VERDICTS:
        die("verdict must be one of " + ", ".join(VERDICTS))
    when = dt.datetime.fromisoformat(a.date.replace("Z", "+00:00")) if a.date else now()
    # Check every input before anything is created, so a refused file never
    # leaves a half-written run behind.
    texts = []
    for src in a.file or []:
        if not os.path.isfile(src):
            die("no such file: " + src)
        if os.path.getsize(src) > MAX_FILE:
            die("too large to archive (record name and digest instead): " + src)
        with open(src, "rb") as f:
            raw = f.read()
        try:
            texts.append((os.path.basename(src), raw.decode("utf-8")))
        except UnicodeDecodeError:
            die("binary file refused (record its name and digest in RUN.md): " + src)
    # The run id carries the time it was archived, so ids sort in archive order
    # and the manifest chain only ever grows at the end (an earlier --date never
    # inserts a run before one that is already sealed). --date is the time the
    # run itself started; it goes in RUN.md, the manifest and the index.
    rid, d = new_run(a.area, a.commit, now())
    for name, text in texts:
        write_text(os.path.join(d, "results", name), text)
    summary = read_opt(a.results)
    ok, bad, skipped = tap_counts(summary)
    write_text(os.path.join(d, "command.txt"), read_opt(a.command_text) + "\n")
    write_text(os.path.join(d, "environment.md"), read_opt(a.environment) + "\n")
    write_text(os.path.join(d, "RUN.md"), RUN_MD.format(
        title=a.title, rid=rid, area=a.area, commit=a.commit, date=when.isoformat(),
        where=a.where, verdict=a.verdict, what=read_opt(a.what) or "-",
        how=read_opt(a.how) or "See command.txt.", results=summary or "See results/.",
        failures=read_opt(a.failures) or "None.", reproduce=read_opt(a.reproduce) or "See command.txt."))
    seal(rid, {"kind": "received", "area": a.area, "commit": a.commit, "verdict": a.verdict,
               "date": when.isoformat(), "where": a.where,
               "tap": {"ok": ok, "not_ok": bad, "skipped": skipped}})
    cmd_index(a)
    print(rid)
    return 0


def _append_note(d, kind, text):
    """Append a dated entry to NOTES.md and chain it in notes.json (append-only)."""
    when = now().isoformat()
    entry = "\n## %s - %s\n\n%s\n" % (when, kind, redact(text.strip()))
    notes = os.path.join(d, "NOTES.md")
    with open(notes, "a", encoding="utf-8") as f:
        if f.tell() == 0:
            f.write("# Notes (append-only)\n")
        f.write(entry)
    chain_path = os.path.join(d, "notes.json")
    chain = []
    if os.path.isfile(chain_path):
        with open(chain_path, encoding="utf-8") as f:
            chain = json.load(f)
    prev = chain[-1]["sha256"] if chain else None
    h = hashlib.sha256(((prev or "") + entry).encode("utf-8")).hexdigest()
    chain.append({"date": when, "kind": kind, "sha256": h})
    with open(chain_path, "w", encoding="utf-8") as f:
        json.dump(chain, f, indent=2)
        f.write("\n")


def cmd_note(a):
    _append_note(run_dir(a.run), "note", a.text)
    return 0


def cmd_invalidate(a):
    d = run_dir(a.run)
    if not a.reason.strip():
        die("invalidate needs a reason")
    _append_note(d, "invalidated", a.reason)
    with open(os.path.join(d, "INVALID"), "w", encoding="utf-8") as f:
        f.write(redact(a.reason.strip()) + "\n")
    cmd_index(a)
    return 0


def index_rows():
    rows = []
    for rid in all_runs():
        m = load_manifest(rid)
        verdict = "invalid" if os.path.exists(os.path.join(RUNS, rid, "INVALID")) else m.get("verdict", "")
        t = m.get("tap", {})
        rows.append([rid, m.get("date", ""), m.get("area", ""), m.get("commit", ""), verdict,
                     m.get("where", ""), t.get("ok", ""), t.get("not_ok", ""), t.get("skipped", "")])
    return rows


HEADER = ["run_id", "date", "area", "commit", "verdict", "where", "ok", "not_ok", "skipped"]


def render_index():
    rows = index_rows()
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(HEADER)
    w.writerows(rows)
    table = ["| Run | Date (UTC) | Area | Commit | Verdict | Where | ok / not ok / skipped |",
             "|---|---|---|---|---|---|---|"]
    for r in reversed(rows):
        table.append("| [`%s`](runs/%s/RUN.md) | %s | %s | `%s` | **%s** | %s | %s / %s / %s |"
                     % (r[0], r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]))
    return buf.getvalue(), "\n".join(table) + "\n"


def cmd_index(_a=None):
    csv_text, table = render_index()
    os.makedirs(HT, exist_ok=True)
    with open(os.path.join(HT, "INDEX.csv"), "w", encoding="utf-8") as f:
        f.write(csv_text)
    readme = os.path.join(HT, "README.md")
    if os.path.isfile(readme):
        with open(readme, encoding="utf-8") as f:
            s = f.read()
        if TABLE_BEGIN in s and TABLE_END in s:
            head, rest = s.split(TABLE_BEGIN, 1)
            _, tail = rest.split(TABLE_END, 1)
            with open(readme, "w", encoding="utf-8") as f:
                f.write(head + TABLE_BEGIN + "\n" + table + TABLE_END + tail)
    return 0


def cmd_verify(_a):
    """Recompute every hash and chain link, rescan for unredacted data, check the index."""
    problems = []
    prev_id, prev_sha = None, None
    for rid in all_runs():
        d = os.path.join(RUNS, rid)
        m = load_manifest(rid)
        if m.get("run_id") != rid:
            problems.append("%s: manifest run_id is %r" % (rid, m.get("run_id")))
        if m.get("previous_run") != prev_id or m.get("previous_manifest_sha256") != prev_sha:
            problems.append("%s: manifest chain broken (previous run %r)" % (rid, prev_id))
        listed = m.get("files", {})
        for rel, want in listed.items():
            p = os.path.join(d, rel)
            if not os.path.isfile(p):
                problems.append("%s: missing %s" % (rid, rel))
            elif sha256_file(p) != want:
                problems.append("%s: %s changed after the run was sealed" % (rid, rel))
        for top, _, names in os.walk(d):
            for name in names:
                p = os.path.join(top, name)
                rel = os.path.relpath(p, d)
                if rel not in listed and rel not in ("manifest.json",) + MUTABLE:
                    problems.append("%s: %s is not in the manifest" % (rid, rel))
                try:
                    with open(p, encoding="utf-8") as f:
                        if needs_redaction(f.read()):
                            problems.append("%s: %s contains data that must be redacted" % (rid, rel))
                except UnicodeDecodeError:
                    problems.append("%s: %s is binary" % (rid, rel))
        for need in ("RUN.md", "command.txt", "environment.md"):
            if need not in listed:
                problems.append("%s: %s is missing" % (rid, need))
        prev_id, prev_sha = rid, sha256_file(os.path.join(d, "manifest.json"))
    csv_text, _ = render_index()
    idx = os.path.join(HT, "INDEX.csv")
    if all_runs() and (not os.path.isfile(idx) or open(idx, encoding="utf-8").read() != csv_text):
        problems.append("INDEX.csv is out of date: run `python3 scripts/history_test.py index`")
    for p in problems:
        print("not ok - " + p, file=sys.stderr)
    print("history_test verify: %d runs, %d problems" % (len(all_runs()), len(problems)))
    return 1 if problems else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="history_test.py", description=__doc__.split("\n")[0])
    sp = ap.add_subparsers(dest="cmd", required=True)

    r = sp.add_parser("run", help="execute a command and archive it")
    r.add_argument("--area", required=True)
    r.add_argument("--commit")
    r.add_argument("--title")
    r.add_argument("--what", help="text or file: what is tested and why")
    r.add_argument("--where", default="local")
    r.add_argument("--timeout", type=int, default=3600)
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(fn=cmd_run)

    ad = sp.add_parser("add", help="archive results received from elsewhere")
    ad.add_argument("--area", required=True)
    ad.add_argument("--commit", required=True)
    ad.add_argument("--title", required=True)
    ad.add_argument("--verdict", required=True)
    ad.add_argument("--date", help="ISO 8601 UTC time the run started")
    ad.add_argument("--where", required=True)
    for k in ("what", "how", "results", "failures", "reproduce", "environment"):
        ad.add_argument("--" + k, help="text or file")
    ad.add_argument("--command-text", dest="command_text", required=True, help="text or file")
    ad.add_argument("--file", action="append", help="result file to archive (text, max 5 MB)")
    ad.set_defaults(fn=cmd_add)

    n = sp.add_parser("note", help="append a dated note to a run")
    n.add_argument("run")
    n.add_argument("--text", required=True)
    n.set_defaults(fn=cmd_note)

    iv = sp.add_parser("invalidate", help="mark a run invalid")
    iv.add_argument("run")
    iv.add_argument("--reason", required=True)
    iv.set_defaults(fn=cmd_invalidate)

    sp.add_parser("index", help="regenerate INDEX.csv and the README table").set_defaults(fn=cmd_index)
    sp.add_parser("verify", help="check hashes, chain, redaction and index").set_defaults(fn=cmd_verify)

    a = ap.parse_args(argv)
    if a.cmd == "run" and a.command and a.command[0] == "--":
        a.command = a.command[1:]
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
