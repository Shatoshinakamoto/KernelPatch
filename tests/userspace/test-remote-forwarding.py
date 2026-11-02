# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Johnathan Edward Brown
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


binary = sys.argv[1]


def receiver(cert, key, callback, frames=1):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(8)
    port = listener.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    received = []

    def serve():
        try:
            conn, _ = listener.accept()
            # every frame is read from this ONE accepted connection
            with context.wrap_socket(conn, server_side=True) as tls:
                for _ in range(frames):
                    prefix = bytearray()
                    while len(prefix) < 10 and not prefix.endswith(b" "):
                        byte = tls.recv(1)
                        if not byte:
                            return
                        prefix.extend(byte)
                    size = int(prefix[:-1])
                    message = bytearray()
                    while len(message) < size:
                        chunk = tls.recv(size - len(message))
                        if not chunk:
                            return
                        message.extend(chunk)
                    received.append(bytes(message))
        except (OSError, ssl.SSLError):
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    result = callback(port)
    thread.join(timeout=10)
    if thread.is_alive():
        raise RuntimeError("TLS test receiver did not stop")
    return result, received


with tempfile.TemporaryDirectory(prefix="secure-sudo-tls-") as temp:
    cert = os.path.join(temp, "collector.pem")
    key = os.path.join(temp, "collector-key.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    other_cert = os.path.join(temp, "untrusted.pem")
    other_key = os.path.join(temp, "untrusted-key.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", other_key, "-out", other_cert, "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def deliver(port, ca_file=cert):
        return subprocess.run(
            [binary, "send", "localhost", str(port), ca_file],
            timeout=10,
            check=False,
        ).returncode

    status, messages = receiver(cert, key, deliver)
    if status != 0 or len(messages) != 1 or b"<85>1 " not in messages[0]:
        raise RuntimeError("trusted TLS syslog delivery did not arrive")
    print("ok 1 - TLS verifies collector CA/hostname and delivers RFC 5425 frame")

    rotation_ca = os.path.join(temp, "rotation-ca.pem")
    rotation_next = os.path.join(temp, "rotation-ca.next")
    with open(rotation_ca, "wb") as target, open(cert, "rb") as source:
        target.write(source.read())
    old_status, old_messages = receiver(
        cert, key, lambda port: deliver(port, rotation_ca)
    )
    with open(rotation_next, "wb") as target:
        for ca in (cert, other_cert):
            with open(ca, "rb") as source:
                target.write(source.read())
    os.replace(rotation_next, rotation_ca)
    status, messages = receiver(
        other_cert, other_key, lambda port: deliver(port, rotation_ca)
    )
    if (old_status != 0 or len(old_messages) != 1 or status != 0 or
            len(messages) != 1):
        raise RuntimeError("TLS did not use the atomically rotated CA bundle")
    print("ok 2 - atomic CA-bundle rotation applies to the next TLS connection")

    if os.geteuid() == 0:
        def deliver_queued(port):
            return subprocess.run(
                [binary, "queue-deliver", "localhost", str(port), cert],
                timeout=10,
                check=False,
            ).returncode

        status, messages = receiver(cert, key, deliver_queued)
        if status != 0 or len(messages) != 1 or b"queue-delivery-test" not in messages[0]:
            raise RuntimeError("queued TLS event was not delivered and removed")
        print("ok 3 - persistent TLS queue drains after collector recovery")
    else:
        print("ok 3 - # SKIP persistent queue requires root-owned queue directory")

    def reject_hostname(port):
        return subprocess.run(
            [binary, "reject", "127.0.0.1", str(port), cert],
            timeout=10,
            check=False,
        ).returncode

    status, messages = receiver(cert, key, reject_hostname)
    if status != 0 or messages:
        raise RuntimeError("TLS accepted a certificate for the wrong host")
    print("ok 4 - TLS rejects a trusted certificate with the wrong hostname")

    def reject_untrusted(port):
        return subprocess.run(
            [binary, "reject", "localhost", str(port), other_cert],
            timeout=10,
            check=False,
        ).returncode

    status, messages = receiver(cert, key, reject_untrusted)
    if status != 0 or messages:
        raise RuntimeError("TLS accepted a certificate from an untrusted CA")
    print("ok 5 - TLS rejects a certificate issued by an untrusted CA")

    result = subprocess.run(
        [binary, "reject", "127.0.0.1", "1", os.path.join(temp, "missing-ca")],
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("TLS accepted a missing CA bundle")
    print("ok 6 - TLS refuses a missing CA bundle")

    result = subprocess.run([binary, "queue"], check=False)
    if result.returncode == 77:
        print("ok 7 - # SKIP bounded queue requires root-owned queue directory")
        print("ok 8 - # SKIP outage persistence requires root-owned queue directory")
    elif result.returncode != 0:
        raise RuntimeError("queue exhaustion/outage persistence test failed")
    else:
        result = subprocess.run([binary, "queue-verify"], check=False)
        if result.returncode != 0:
            raise RuntimeError("queued event did not persist across daemon process")
        print("ok 7 - queue exhaustion is counted and unsent events persist")
        print("ok 8 - outage retains queued event for a later retry")

    if os.geteuid() == 0:
        def deliver_batch(port):
            return subprocess.run(
                [binary, "queue-batch", "localhost", str(port), cert],
                timeout=20,
                check=False,
            ).returncode

        status, messages = receiver(cert, key, deliver_batch, frames=3)
        order = [m.rsplit(b" ", 1)[-1] for m in messages]
        if status != 0 or order != [b"batch-event-1", b"batch-event-2",
                                    b"batch-event-3"]:
            raise RuntimeError("queued events did not go out in order over "
                               "one connection: %r" % (messages,))
        print("ok 9 - a queue flush sends its events in order over one TLS "
              "connection")
        result = subprocess.run([binary, "queue-backoff"], check=False,
                                timeout=20)
        if result.returncode != 0:
            raise RuntimeError("events must only queue, and a failing "
                               "collector must be retried with backoff")
        print("ok 10 - events only queue; a failing collector is retried "
              "after 5 s, 10 s, ... not per event")
    else:
        print("ok 9 - # SKIP queue batch requires root-owned queue directory")
        print("ok 10 - # SKIP queue backoff requires root-owned queue directory")
    print("1..10")
