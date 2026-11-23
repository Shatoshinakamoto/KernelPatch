# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
"""Cases for test-addon-log-tls.sh. argv: HARNESS TMPDIR. Prints TAP lines."""
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

harness, T = sys.argv[1], sys.argv[2]
LOG = os.path.join(T, "log", "tlstest.log")
CONF = os.path.join(T, "logging.conf")
n_fail = 0


def tap(good, name):
    global n_fail
    if not good:
        n_fail += 1
    print(("ok " if good else "not ok ") + name, flush=True)


def cert(name, san):
    c, k = os.path.join(T, name + ".pem"), os.path.join(T, name + "-key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", k, "-out", c, "-days", "1", "-subj", "/CN=collector",
                    "-addext", "subjectAltName=" + san],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return c, k


class Collector:
    """TLS syslog collector on 127.0.0.1 reading octet-framed lines.
    close_after: close each connection after that many frames."""

    def __init__(self, c, k, close_after=0, port=0):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(c, k)
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", port))
        self.ls.listen(4)
        self.ls.settimeout(0.2)
        self.port = self.ls.getsockname()[1]
        self.close_after = close_after
        self.frames, self.conns = [], 0
        self.stop = threading.Event()
        self.th = threading.Thread(target=self.run, daemon=True)
        self.th.start()

    def run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.ls.accept()
            except OSError:
                continue
            self.conns += 1
            conn.settimeout(5)
            try:
                with self.ctx.wrap_socket(conn, server_side=True) as tls:
                    got = 0
                    while True:
                        prefix = b""
                        while not prefix.endswith(b" "):
                            b = tls.recv(1)
                            if not b:
                                raise EOFError
                            prefix += b
                        size, msg = int(prefix[:-1]), b""
                        while len(msg) < size:
                            chunk = tls.recv(size - len(msg))
                            if not chunk:
                                raise EOFError
                            msg += chunk
                        self.frames.append(msg.decode())
                        got += 1
                        if self.close_after and got >= self.close_after:
                            break
            except (OSError, ssl.SSLError, EOFError, ValueError):
                pass

    def close(self):
        time.sleep(0.3)
        self.stop.set()
        self.th.join(5)
        self.ls.close()


def conf(host, port, ca, proto="tls"):
    with open(CONF, "w") as f:
        f.write(f"remote_enabled = 1\nremote_proto = {proto}\nremote_host = {host}\n"
                f"remote_port = {port}\nremote_ca_file = {ca}\n")
    os.chmod(CONF, 0o600)
    if os.path.exists(LOG):
        os.unlink(LOG)


def run(*lines):
    t0 = time.time()
    r = subprocess.run([harness, *lines], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=60)
    return r, time.time() - t0


def local():
    try:
        return open(LOG).read()
    except OSError:
        return ""


good_c, good_k = cert("collector", "DNS:localhost")
ip_c, ip_k = cert("collector-ip", "IP:127.0.0.1")
evil_c, evil_k = cert("untrusted", "DNS:localhost")
other_c, other_k = cert("other-name", "DNS:collector.invalid")
bad_ca = os.path.join(T, "not-a-ca.pem")
with open(bad_ca, "w") as f:
    f.write("this is not a certificate\n")

# check-config
conf("localhost", 6514, good_c)
r, _ = run("check")
tap(r.returncode == 0, "check-config accepts remote_proto = tls with a readable CA bundle")
conf("localhost", 6514, os.path.join(T, "missing.pem"))
r, _ = run("check")
tap(r.returncode == 1 and b"remote_ca_file" in r.stdout,
    "check-config rejects a missing remote_ca_file under tls")
conf("localhost", 6514, bad_ca)
r, _ = run("check")
tap(r.returncode == 1 and b"remote_ca_file" in r.stdout,
    "check-config rejects a remote_ca_file that holds no certificate")
conf("localhost", 6514, "relative/ca.pem")
r, _ = run("check")
tap(r.returncode == 1, "check-config rejects a relative remote_ca_file")
with open(CONF, "w") as f:
    f.write("remote_enabled = 1\nremote_proto = tls\nremote_host = localhost\n"
            "remote_ca_file = " + bad_ca + "\nremote_proto = tls\n")
os.chmod(CONF, 0o600)
r, _ = run("check")
tap(r.returncode == 1, "check-config still rejects a key set twice")

# delivery by host name
col = Collector(good_c, good_k)
conf("localhost", col.port, good_c)
r, _ = run("first line", "second line\nforged CRIT line")
col.close()
tap(col.conns == 1 and len(col.frames) == 2,
    f"two lines arrive over one verified TLS connection (conns={col.conns}, frames={len(col.frames)})")
tap(bool(col.frames) and col.frames[0].startswith("<108>1 ")
    and "secure_sudo-tlstest" in col.frames[0] and col.frames[0].endswith(" - first line"),
    "each line is an RFC 5424 record (PRI 108 = log audit + warning)")
tap(len(col.frames) == 2 and "\n" not in col.frames[1] and "\\x0a" in col.frames[1],
    "a newline in a message is escaped, not shipped as a second record")
tap("FAILED" not in local(), "no shipping failure is logged when the collector is healthy")

# delivery to an IP address (IP SAN)
col = Collector(ip_c, ip_k)
conf("127.0.0.1", col.port, ip_c)
run("by address")
col.close()
tap(len(col.frames) == 1, "an IP collector is verified against the certificate's IP SAN")

# untrusted certificate
col = Collector(evil_c, evil_k)
conf("localhost", col.port, good_c)
r, took = run("secret one", "secret two")
col.close()
tap(not col.frames, "a collector whose certificate is not from remote_ca_file gets nothing")
tap(local().count("remote log shipping FAILED") == 1 and "certificate" in local(),
    "the refusal is logged locally once, naming the certificate problem")
tap("secret one" in local() and "secret two" in local(),
    "lines are still written to the local log while shipping fails")

# host name mismatch: certificate for localhost, connecting by IP
col = Collector(good_c, good_k)
conf("127.0.0.1", col.port, good_c)
run("wrong host")
col.close()
tap(not col.frames and "FAILED" in local(),
    "a trusted certificate for another host name is refused")

# host name mismatch: trusted certificate for another DNS name
col = Collector(other_c, other_k)
conf("localhost", col.port, other_c)
run("wrong name")
col.close()
tap(not col.frames and "FAILED" in local(),
    "a trusted certificate naming another DNS host is refused")

# collector down: bounded delay, one local note
s = socket.socket()
s.bind(("127.0.0.1", 0))
dead = s.getsockname()[1]
s.close()
conf("localhost", dead, good_c)
r, took = run("a", "b", "c", "d", "e")
tap(took < 4 and local().count("remote log shipping FAILED") == 1,
    f"a dead collector costs one attempt per retry period, not one per line ({took:.1f} s)")

# collector comes up: retried after SSL_RETRY_SECS, recovery noted
conf("localhost", dead, good_c)
proc = subprocess.Popen([harness, "while down", "@sleep", "@sleep", "after recovery"])
time.sleep(0.3)
col = Collector(good_c, good_k, port=dead)
proc.wait(30)
col.close()
tap(any(f.endswith(" - after recovery") for f in col.frames)
    and "remote log shipping restored" in local(),
    "shipping resumes once the collector is back, and the recovery is logged")

# collector restarts: the next line reconnects instead of being lost
col = Collector(good_c, good_k, close_after=1)
conf("localhost", col.port, good_c)
run("before restart", "@sleep", "after restart")
col.close()
tap([f.rsplit(" - ", 1)[-1] for f in col.frames] == ["before restart", "after restart"]
    and col.conns == 2 and "FAILED" not in local(),
    f"a collector that closed the connection is reconnected without losing a line (conns={col.conns})")

# plain tcp still works (and now reconnects too)
plain = socket.socket()
plain.bind(("127.0.0.1", 0))
plain.listen(2)
plain.settimeout(5)
conf("127.0.0.1", plain.getsockname()[1], good_c, proto="tcp")
got = []


def tcp_serve():
    for _ in range(2):
        try:
            c, _ = plain.accept()
        except OSError:
            return
        data = c.recv(4096)
        got.append(data.decode(errors="replace"))
        c.close()


th = threading.Thread(target=tcp_serve, daemon=True)
th.start()
run("tcp one", "@sleep", "tcp two")
th.join(8)
plain.close()
tap(len(got) == 2 and got[0].split(" ", 1)[0].isdigit() and got[1].endswith("tcp two"),
    "remote_proto = tcp still ships octet-framed lines, reconnecting after a close")

sys.exit(0)
