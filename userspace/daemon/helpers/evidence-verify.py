#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify an exported secure_sudo evidence bundle without trusting its contents."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile


MAX_MEMBER_SIZE = 2 * 1024 * 1024 * 1024
MAX_BUNDLE_SIZE = 8 * 1024 * 1024 * 1024


class VerificationError(Exception):
    pass


def extract_bundle(archive, destination):
    seen = set()
    total = 0

    try:
        bundle = tarfile.open(archive, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise VerificationError("cannot read gzip tar archive: {}".format(error))

    with bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            parts = tuple(part for part in path.parts if part not in ("", "."))
            if (path.is_absolute() or ".." in parts or "\\" in member.name or
                    len(member.name) > 4096):
                raise VerificationError("unsafe archive path: {!r}".format(member.name))
            if not parts:
                if member.isdir():
                    continue
                raise VerificationError("archive root is not a directory")
            if parts in seen:
                raise VerificationError("duplicate archive path: {!r}".format(member.name))
            seen.add(parts)
            target = destination.joinpath(*parts)

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise VerificationError("unsupported archive entry: {!r}".format(member.name))
            if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                raise VerificationError("archive member exceeds size limit: {!r}".format(member.name))
            total += member.size
            if total > MAX_BUNDLE_SIZE:
                raise VerificationError("archive exceeds total uncompressed size limit")

            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise VerificationError("cannot read archive member: {!r}".format(member.name))
            written = 0
            with source, target.open("xb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > member.size:
                        raise VerificationError("archive member exceeds declared size")
                    output.write(chunk)
            if written != member.size:
                raise VerificationError("truncated archive member: {!r}".format(member.name))


def safe_manifest_path(name):
    path = PurePosixPath(name)
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if path.is_absolute() or not parts or ".." in parts or "\\" in name:
        raise VerificationError("unsafe checksum path: {!r}".format(name))
    return parts


def verify_checksums(root):
    manifest_path = root / "SHA256SUMS"
    try:
        lines = manifest_path.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
    except OSError as error:
        raise VerificationError("missing checksum manifest: {}".format(error))

    verified = set()
    for line in lines:
        escaped = line.startswith("\\")
        if escaped:
            line = line[1:]
        match = re.fullmatch(r"([0-9a-fA-F]{64})  (.+)", line)
        if not match or escaped:
            raise VerificationError("unsupported checksum entry")
        parts = safe_manifest_path(match.group(2))
        relative = Path(*parts)
        if relative.as_posix() in verified:
            raise VerificationError("duplicate checksum entry: {}".format(relative))
        target = root.joinpath(*parts)
        if not target.is_file() or target.is_symlink():
            raise VerificationError("checksum target is missing or not a regular file")
        digest = hashlib.sha256()
        with target.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != match.group(1).lower():
            raise VerificationError("checksum mismatch: {}".format(relative))
        verified.add(relative.as_posix())

    excluded = {"SHA256SUMS", "bundle-manifest.sha256", "bundle-manifest.sig"}
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    } - excluded
    if actual != verified:
        raise VerificationError("checksum manifest does not cover exactly the bundle payload")
    return manifest_path


def verify_event_chain(root):
    logs_dir = root / "logs"
    logs = sorted(logs_dir.glob("*.log")) if logs_dir.is_dir() else []
    expected = bytearray()

    if not logs:
        chain = hashlib.sha256(b"secure_sudo-event-chain-v1\tno-logs\n").hexdigest()
        expected.extend(("no-logs\tFINAL\t{}\n".format(chain)).encode("ascii"))
    else:
        for logfile in logs:
            name = os.fsencode(logfile.name)
            chain = hashlib.sha256(
                b"secure_sudo-event-chain-v1\t" + name + b"\n"
            ).hexdigest()
            with logfile.open("rb") as source:
                for raw_line in source:
                    line = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
                    chain = hashlib.sha256(
                        chain.encode("ascii") + b"\t" + line + b"\n"
                    ).hexdigest()
                    expected.extend(name + b"\t" + chain.encode("ascii") + b"\n")
            expected.extend(name + b"\tFINAL\t" + chain.encode("ascii") + b"\n")

    chain_path = root / "event-chain.txt"
    try:
        actual = chain_path.read_bytes()
    except OSError as error:
        raise VerificationError("missing event-chain.txt: {}".format(error))
    if actual != expected:
        raise VerificationError("event chain does not match the exported logs")
    return actual


def verify_signature(public_key, message_path, signature_path):
    try:
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                "-inkey", str(public_key), "-in", str(message_path),
                "-sigfile", str(signature_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise VerificationError("cannot run openssl: {}".format(error))
    if result.returncode != 0:
        raise VerificationError("signature verification failed")


CHECKPOINT_LOG = re.compile(r"^[A-Za-z0-9._-]{1,64}\.log$")


def load_checkpoints(path):
    """log_checkpoint records as the collector received them.

    Each line may carry a syslog header in front of the JSON record, so the
    record is taken from the first "{" on the line. Lines that are not a
    secure-sudod log_checkpoint are ignored.
    """
    found = []
    try:
        with open(path, "rb") as source:
            for raw in source:
                start = raw.find(b"{")
                if start < 0 or b"log_checkpoint" not in raw:
                    continue
                try:
                    record = json.loads(raw[start:].decode("utf-8", "strict"))
                except (UnicodeDecodeError, ValueError):
                    continue
                if (not isinstance(record, dict) or
                        record.get("source") != "secure-sudod" or
                        record.get("event_type") != "log_checkpoint"):
                    continue
                log, lines, chain = (record.get("log"), record.get("lines"),
                                     record.get("chain"))
                if (not isinstance(log, str) or not CHECKPOINT_LOG.match(log) or
                        not isinstance(lines, int) or lines < 0 or
                        not isinstance(chain, str) or
                        not re.fullmatch(r"[0-9a-f]{64}", chain)):
                    raise VerificationError(
                        "malformed log_checkpoint record in {}".format(path))
                found.append((log, lines, chain))
    except OSError as error:
        raise VerificationError("cannot read checkpoints: {}".format(error))
    return found


def verify_checkpoints(chain, checkpoints):
    """Check off-host checkpoints against the bundle's per-line chain.

    `chain` is event-chain.txt, already proven to match the exported logs:
    for every log it lists the chain value after each line. A checkpoint
    (log, N, C) holds iff the value after line N of that log is C (or, for
    N = 0, the log's starting value). Returns a list of report lines.
    """
    after = {}
    for line in chain.decode("ascii").splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            after.setdefault(parts[0], []).append(parts[1])
    report, matched = [], 0
    for log, lines, value in checkpoints:
        if log not in after and lines > 0:
            report.append("checkpoint {} line {}: log not in this bundle".format(log, lines))
            continue
        values = after.get(log, [])
        if lines == 0:
            start = hashlib.sha256(
                b"secure_sudo-event-chain-v1\t" + log.encode("ascii") + b"\n"
            ).hexdigest()
            ok = value == start
        elif lines > len(values):
            raise VerificationError(
                "{} has {} lines but an off-host checkpoint covers {}: the "
                "log was truncated or replaced".format(log, len(values), lines))
        else:
            ok = values[lines - 1] == value
        if not ok:
            raise VerificationError(
                "{} does not match the off-host checkpoint at line {}: the "
                "log was changed after it was checkpointed".format(log, lines))
        matched += 1
    if checkpoints and not matched:
        raise VerificationError("no off-host checkpoint covers a log in this bundle")
    if matched:
        last = {}
        for log, lines, _ in checkpoints:
            if log in after:
                last[log] = max(last.get(log, 0), lines)
        for log in sorted(last):
            tail = len(after[log]) - last[log]
            report.append("{}: lines 1-{} match an off-host checkpoint; {} later "
                          "line(s) are not yet anchored".format(log, last[log], tail))
    return matched, report


# ---- G2: the TimeVault manifest's Merkle root ----
#
# RFC 6962 tree hash over the manifest's entries sorted by path (bytes):
# leaf = SHA-256(0x00 || path || 0x00 || hex hash), node = SHA-256(0x01 ||
# left || right), empty tree = SHA-256(""). secure-sudod computes the same.

TV_HEADER = b"# secure_sudo timevault manifest v2"
HEX64 = re.compile(rb"[0-9a-f]{64}")


def read_timevault_manifest(path):
    """Entries {path bytes: hex hash bytes} of a v2 (or v1) manifest."""
    try:
        data = Path(path).read_bytes()
    except OSError as error:
        raise VerificationError("cannot read TimeVault manifest: {}".format(error))
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    entries = {}
    v2 = bool(lines) and lines[0] == TV_HEADER
    for line in lines[1:] if v2 else lines:
        if v2:
            if len(line) < 66 or line[64:66] != b" /":
                raise VerificationError("malformed TimeVault manifest line")
            digest, raw, name, i = line[:64], line[65:], bytearray(), 0
            while i < len(raw):
                ch = raw[i:i + 1]
                if ch == b"\\":
                    nxt = raw[i + 1:i + 2]
                    if nxt not in (b"\\", b"n", b"r"):
                        raise VerificationError("bad escape in TimeVault manifest")
                    name += {b"\\": b"\\", b"n": b"\n", b"r": b"\r"}[nxt]
                    i += 2
                    continue
                name += ch
                i += 1
            name = bytes(name)
        else:
            name, _, digest = line.rpartition(b" ")
            if not name.startswith(b"/"):
                raise VerificationError("malformed TimeVault manifest line")
        if not HEX64.fullmatch(digest):
            raise VerificationError("malformed hash in TimeVault manifest")
        entries.setdefault(name, digest)
    return entries


def merkle_root(entries):
    leaves = [hashlib.sha256(b"\x00" + name + b"\x00" + entries[name]).digest()
              for name in sorted(entries)]

    def mth(items):
        if len(items) == 1:
            return items[0]
        k = 1
        while k * 2 < len(items):
            k *= 2
        return hashlib.sha256(b"\x01" + mth(items[:k]) + mth(items[k:])).digest()

    return (mth(leaves) if leaves else hashlib.sha256(b"").digest()).hex()


TV_TYPES = ("timevault_baseline", "timevault_merkle", "timevault_disengaged",
            "timevault_manifest_modified", "timevault_manifest_unreadable")


def load_timevault_records(path):
    """The daemon's timevault_* records, in the order the collector got them."""
    found = []
    try:
        with open(path, "rb") as source:
            for raw in source:
                start = raw.find(b"{")
                if start < 0 or b"timevault_" not in raw:
                    continue
                try:
                    record = json.loads(raw[start:].decode("utf-8", "strict"))
                except (UnicodeDecodeError, ValueError):
                    continue
                if (isinstance(record, dict) and
                        record.get("source") == "secure-sudod" and
                        record.get("event_type") in TV_TYPES):
                    found.append(record)
    except OSError as error:
        raise VerificationError("cannot read TimeVault records: {}".format(error))
    return found


def verify_timevault(records, manifest_entries=None):
    """Check the forwarded roots tell one consistent story.

    During an engagement the manifest never changes, so every root the
    daemon sends must equal the baseline's. A new baseline is legitimate
    only after a timevault_disengaged record (TimeVault is off again after
    a reboot). Returns (report lines, problems); any problem fails.
    """
    report, problems = [], []
    expected, open_engagement, seen = None, False, 0
    for rec in records:
        kind, root = rec.get("event_type"), rec.get("root")
        when = rec.get("realtime_ns", "?")
        if kind == "timevault_baseline":
            if open_engagement:
                problems.append(
                    "TimeVault took a new baseline at {} ({}) with no "
                    "disengage since the last one: the manifest was deleted "
                    "or replaced and the daemon restarted".format(
                        when, rec.get("reason")))
            expected, open_engagement = root, True
            seen += 1
        elif kind == "timevault_merkle":
            seen += 1
            if expected is None:
                expected, open_engagement = root, True
            elif root != expected:
                problems.append(
                    "TimeVault manifest root changed at {} ({}): {} -> {}; the "
                    "manifest was rewritten".format(when, rec.get("reason"),
                                                    expected, root))
                expected = root
        elif kind == "timevault_disengaged":
            if expected is not None and root not in (expected,):
                problems.append(
                    "TimeVault manifest set aside at {} has root {}, not {}".format(
                        when, root, expected))
            expected, open_engagement = None, False
        elif kind == "timevault_manifest_modified":
            report.append(
                "WARNING: the TimeVault manifest was changed on the host at {} "
                "(found root {}); the daemon {}".format(
                    when, rec.get("found_root"),
                    "put its copy back" if rec.get("restored") is True
                    else "could NOT put its copy back"))
            if rec.get("restored") is not True:
                problems.append("the TimeVault manifest could not be restored")
        elif kind == "timevault_manifest_unreadable":
            report.append("WARNING: the daemon could not read the TimeVault "
                          "manifest at {}: {}".format(when, rec.get("error")))
    if not seen:
        problems.append("no TimeVault root among the collector's records")
    elif expected:
        report.append("TimeVault: {} root record(s) agree; current root {}".format(
            seen, expected))
    if manifest_entries is not None:
        root = merkle_root(manifest_entries)
        if expected and root != expected:
            problems.append(
                "the bundle's TimeVault manifest has root {}, the collector "
                "holds {}: it was rewritten".format(root, expected))
        elif expected:
            report.append("TimeVault: the bundle's manifest ({} entries) matches "
                          "the off-host root".format(len(manifest_entries)))
    return report, problems


def verify_bundle(archive, trusted_key, checkpoints=None, timevault=None):
    with tempfile.TemporaryDirectory(prefix="secure-sudo-verify-") as temp:
        root = Path(temp)
        extract_bundle(archive, root)
        manifest_path = verify_checksums(root)
        chain = verify_event_chain(root)
        report = []
        if checkpoints is not None:
            _, report = verify_checkpoints(chain, checkpoints)
        if timevault is not None:
            tv_file = root / "live" / "timevault-manifest"
            entries = (read_timevault_manifest(tv_file)
                       if tv_file.is_file() else None)
            if entries is None:
                report.append("TimeVault: no manifest in this bundle "
                              "(TimeVault was not engaged)")
            tv_report, problems = verify_timevault(timevault, entries)
            report.extend(tv_report)
            if problems:
                raise VerificationError("; ".join(problems))

        manifest_hash_path = root / "bundle-manifest.sha256"
        manifest_signature = root / "bundle-manifest.sig"
        chain_signature = root / "event-chain.sig"
        if manifest_hash_path.exists() != manifest_signature.exists():
            raise VerificationError("incomplete bundle-manifest signature")
        if chain_signature.exists() != manifest_signature.exists():
            raise VerificationError("incomplete event-chain signature")
        if manifest_signature.exists():
            if not trusted_key:
                raise VerificationError("signed bundle requires --trusted-key")
            if not (root / "event-chain.pub").is_file():
                raise VerificationError("signed bundle is missing event-chain.pub")
            expected_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            recorded = manifest_hash_path.read_text(
                encoding="ascii", errors="strict"
            ).split()
            if not recorded or recorded[0] != expected_digest:
                raise VerificationError("signed checksum-manifest digest mismatch")
            final_lines = chain.decode("ascii").splitlines()
            if not final_lines or len(final_lines[-1].split("\t")) != 3:
                raise VerificationError("invalid final event-chain checkpoint")
            final_hash = final_lines[-1].split("\t")[2]
            with tempfile.NamedTemporaryFile(prefix="secure-sudo-final-") as final:
                final.write(final_hash.encode("ascii") + b"\n")
                final.flush()
                verify_signature(trusted_key, final.name, chain_signature)
            verify_signature(trusted_key, manifest_hash_path, manifest_signature)
        return report


def main():
    parser = argparse.ArgumentParser(
        description="verify checksums, event chains, and signatures in an evidence bundle"
    )
    parser.add_argument("archive", nargs="?",
                        help="evidence .tar.gz created by secure-sudo evidence-export")
    parser.add_argument("--trusted-key", help="trusted PEM public key for signed bundles")
    parser.add_argument(
        "--checkpoints",
        help="log_checkpoint records as received by the remote collector; "
             "each must match the bundle's logs")
    parser.add_argument(
        "--timevault",
        help="the collector's records (as for --checkpoints): every "
             "TimeVault Merkle root must agree, and the bundle's TimeVault "
             "manifest must hash to the last one")
    parser.add_argument(
        "--timevault-root", metavar="MANIFEST",
        help="print the Merkle root of a TimeVault manifest file and exit")
    args = parser.parse_args()

    if args.timevault_root:
        try:
            print(merkle_root(read_timevault_manifest(args.timevault_root)))
        except VerificationError as error:
            parser.exit(1, "secure-sudo evidence-verify: {}\n".format(error))
        return
    if not args.archive:
        parser.error("an evidence bundle is required")

    if args.trusted_key and not Path(args.trusted_key).is_file():
        parser.error("--trusted-key must name a readable public-key file")
    try:
        checkpoints = (load_checkpoints(args.checkpoints)
                       if args.checkpoints else None)
        timevault = (load_timevault_records(args.timevault)
                     if args.timevault else None)
        report = verify_bundle(args.archive, args.trusted_key, checkpoints,
                               timevault) or []
    except VerificationError as error:
        parser.exit(1, "secure-sudo evidence-verify: {}\n".format(error))
    for line in report:
        print("secure-sudo evidence-verify: " + line)
    print("secure-sudo evidence-verify: bundle integrity verified")


if __name__ == "__main__":
    main()
