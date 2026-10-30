#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Verify the reviewed controller artifact before any managed-host mutation."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


def verify(path, expected_sha256, revision):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("source SHA256 must be exactly 64 lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision must be exactly 40 lowercase hex characters")
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError("source archive must be a regular, non-symlink controller file")
    if source.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("source archive exceeds 128 MiB limit")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise ValueError("source archive SHA256 does not match reviewed artifact")
    with tarfile.open(source, "r:gz") as archive:
        if archive.pax_headers.get("comment") != revision:
            raise ValueError("archive must carry the requested git-archive commit provenance")
        names = set()
        total_size = 0
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or ".git" in name.parts:
                raise ValueError("unsafe source archive member path")
            if not member.isfile() and not member.isdir():
                raise ValueError("source archive must contain only regular files and directories")
            if member.mode & 0o7000:
                raise ValueError("source archive contains unsafe special permissions")
            canonical_name = str(name)
            if canonical_name in names:
                raise ValueError("source archive contains duplicate member paths")
            names.add(canonical_name)
            total_size += member.size
            if total_size > 256 * 1024 * 1024 or len(names) > 10000:
                raise ValueError("source archive exceeds extraction bounds")
        required = {
            "pyproject.toml", "config.example.toml",
            "src/oci_inference_proxy/__init__.py",
            "systemd/inference-proxy.service",
            "systemd/inference-proxy-purge.service",
            "systemd/inference-proxy-purge.timer",
        }
        if not required.issubset(names):
            raise ValueError("source archive lacks the expected inference-proxy package contract")
    return {"revision": revision, "sha256": digest, "members": len(names)}


if __name__ == "__main__":
    try:
        print(json.dumps(verify(*sys.argv[1:])))
    except (ValueError, OSError, tarfile.TarError) as exc:
        sys.exit(str(exc))
