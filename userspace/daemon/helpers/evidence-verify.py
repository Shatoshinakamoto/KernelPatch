#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify an exported secure_sudo evidence bundle without trusting its contents."""

import argparse
import hashlib
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


def verify_bundle(archive, trusted_key):
    with tempfile.TemporaryDirectory(prefix="secure-sudo-verify-") as temp:
        root = Path(temp)
        extract_bundle(archive, root)
        manifest_path = verify_checksums(root)
        chain = verify_event_chain(root)

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


def main():
    parser = argparse.ArgumentParser(
        description="verify checksums, event chains, and signatures in an evidence bundle"
    )
    parser.add_argument("archive", help="evidence .tar.gz created by secure-sudo evidence-export")
    parser.add_argument("--trusted-key", help="trusted PEM public key for signed bundles")
    args = parser.parse_args()

    if args.trusted_key and not Path(args.trusted_key).is_file():
        parser.error("--trusted-key must name a readable public-key file")
    try:
        verify_bundle(args.archive, args.trusted_key)
    except VerificationError as error:
        parser.exit(1, "secure-sudo evidence-verify: {}\n".format(error))
    print("secure-sudo evidence-verify: bundle integrity verified")


if __name__ == "__main__":
    main()
