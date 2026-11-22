#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
#
# gui-driver.py - drives a real secure-sudo-gui server over HTTP for
# tests/userspace/test-gui.sh (TODO P2-5). Prints "R ok NAME" / "R fail NAME".
# Usage: gui-driver.py PORT TOKEN WORKDIR
import http.client, json, os, subprocess, sys

port, tok, work = int(sys.argv[1]), sys.argv[2], sys.argv[3]


def req(method, path, host="127.0.0.1", token=tok, headers=None, body=None, ctype="application/json", raw_len=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", host)
    if token is not None:
        c.putheader("X-SS-Token", token)
    for k, v in (headers or {}).items():
        c.putheader(k, v)
    data = None
    if body is not None or raw_len is not None:
        if ctype:
            c.putheader("Content-Type", ctype)
        data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        c.putheader("Content-Length", str(len(data) if raw_len is None else raw_len))
    c.endheaders(data if data else None)
    r = c.getresponse()
    text = r.read().decode(errors="replace")
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    return r.status, doc, text, dict((k.lower(), v) for k, v in r.getheaders())


def r(name, cond):
    print(("R ok " if cond else "R fail ") + name, flush=True)


def cli(*args):
    p = subprocess.run(list(args), capture_output=True, text=True)
    return p.stdout


# ---- authentication, host, origin, type, size (read-only mode first) -------
r("no token: 401", req("GET", "/api/status", token=None)[0] == 401)
r("wrong token: 401", req("GET", "/api/status", token="x" * 48)[0] == 401)
r("another Host with the right token: 403 (DNS rebinding)", req("GET", "/api/status", host="evil.example")[0] == 403)
s, d, _, h = req("GET", "/api/status")
r("right token: 200", s == 200)
r("the page asks for no framing, no caching, no referrer, and has a CSP",
  h.get("x-frame-options") == "DENY" and h.get("cache-control") == "no-store"
  and h.get("referrer-policy") == "no-referrer" and "frame-ancestors 'none'" in h.get("content-security-policy", ""))
r("a cross-site Origin is refused even with the token (CSRF)",
  req("GET", "/api/status", headers={"Origin": "http://evil.example"})[0] == 403)
r("Origin: null is refused", req("GET", "/api/status", headers={"Origin": "null"})[0] == 403)
r("the console's own Origin is accepted",
  req("GET", "/api/status", headers={"Origin": f"http://127.0.0.1:{port}"})[0] == 200)
r("the page itself needs no token and holds none", req("GET", "/", token=None)[0] == 200 and tok not in req("GET", "/", token=None)[2])

# ---- read-only mode: every POST refused, nothing changed -------------------
r("status says the console is read-only", d.get("mode") == "read_only")
for path, body in (("/api/config", {"name": "bootguard", "content": "mode = monitor\n"}),
                   ("/api/setkey", {"name": "bootguard", "key": "mode", "value": "monitor"}),
                   ("/api/action", {"action": "quarantine_pid", "arg": "999999"}),
                   ("/api/action", {"action": "set_knob", "arg": "sudo_max_fails=9"})):
    s, d2, _, _ = req("POST", path, body=body)
    r(f"read-only: POST {path} is refused (403)", s == 403 and "read-only" in (d2 or {}).get("error", ""))
r("read-only: a refused POST without a token is still 401, not a hint", req("POST", "/api/action", token=None, body={})[0] == 401)
r("read-only: the config file was not written", not os.path.exists(os.path.join(work, "addons", "bootguard.conf")))

# ---- views: they say what the CLI and the kernel say -----------------------
s, d, _, _ = req("GET", "/api/status")
sysfs = {n: open(os.path.join(work, "sysfs", n)).read().strip() for n in sorted(os.listdir(os.path.join(work, "sysfs")))}
r("status: the knobs are exactly the kernel's sysfs values", d["knobs"] == sysfs)
bg = cli(os.path.join(work, "bin", "secure-sudo-bootguard"), "status").strip()
r("status: a guard's text is exactly what its own CLI prints", d["guards"]["bootguard"]["status"] == bg)
r("status: a guard that is not installed says so", d["guards"]["locus"] == {"installed": False, "status": "not installed"})

s, d, _, _ = req("GET", "/api/health")
want = json.loads(cli(os.path.join(work, "bin", "secure-sudo"), "health", "--json"))
r("health: is the CLI's own `health --json`", s == 200 and d["health"] == want)

s, d, _, _ = req("GET", "/api/eventloss")
r("event loss: the daemon's counters are shown", d["counters"].get("events_dropped") == 3 and d["counters"].get("alerts.dropped") == 2)
r("event loss: a counter that is not about loss is left out", "uptime_s" not in d["counters"])
r("event loss: event_gap records in the log are listed", d["gap_count"] == 1 and "event_gap" in d["gap_records"][0])

s, d, _, _ = req("GET", "/api/timeline?n=50")
rows = d["rows"]
times = [x["time"] for x in rows if x["time"]]
r("timeline: kernel and guard records are merged", {"kernel", "bootguard", "secure-sudod"} <= {x["source"] for x in rows})
r("timeline: sorted by time", times == sorted(times))
r("timeline: a guard CRIT line is critical", any(x["source"] == "bootguard" and x["severity"] == "critical" for x in rows))
r("timeline: a kernel deny is high", any(x["severity"] == "high" and "credential_change" in x["text"] for x in rows))
r("timeline: ?n= is bounded and checked", req("GET", "/api/timeline?n=abc")[0] == 400 and len(req("GET", "/api/timeline?n=1")[1]["rows"]) == 1)

s, d, _, _ = req("GET", "/api/policy?n=5")
want = [json.loads(x) for x in cli(os.path.join(work, "bin", "secure-sudo"), "history", "-n", "5", "--json").splitlines()]
r("policy changes: exactly the CLI history", d["rows"] == want and len(want) == 2)
r("policy changes: the hash-chain verdict is shown", d["chain"] == "intact")

s, d, _, _ = req("GET", "/api/evidence")
r("evidence: records and blob files are listed", len(d["records"]) == 2 and d["blobs"] and d["blobs"][0]["size"] > 0)
s, d, text, h = req("GET", "/api/evidence/export")
r("evidence export: a JSON download with every record", s == 200 and "attachment" in h.get("content-disposition", "") and len(d["records"]) == 2)
import hashlib
blob = os.path.join(work, "evidence", d["blobs"][0]["file"])
r("evidence export: blobs carry their SHA-256, never their content",
  d["blobs"][0]["sha256"] == hashlib.sha256(open(blob, "rb").read()).hexdigest() and "BLOBSECRET" not in text)
r("evidence: a symlink planted in the evidence tree is not followed", all("planted" not in b["file"] for b in d["blobs"]))

# ---- a token flood is throttled -------------------------------------------
codes = [req("GET", "/api/status", token="bad")[0] for _ in range(14)]
r("a flood of bad tokens is throttled (429)", 429 in codes and codes[0] == 401)
r("... and even the right token waits out the window", req("GET", "/api/status")[0] == 429)
print("R done", flush=True)
