#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fail-closed validation for an offline, root-owned OCI CLI wheel install."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat


NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.!+]*")
HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def safe_path(path, *, directory):
    """Require root-owned, non-writable-by-others real path and all ancestors."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("artifact path must be absolute")
    for part in (Path("/"), *reversed(list(path.parents)[:-1]), path):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(f"unsafe artifact path: {part}")
    info = path.stat()
    if directory and not stat.S_ISDIR(info.st_mode):
        raise ValueError("artifact directory differs")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise ValueError("artifact file differs")


def parse_lock(contents):
    """Accept only exact name/version lines followed by sha256 hash tokens.

    Direct URLs, editable installs, options, markers, and nested requirements
    are deliberately outside this runtime's supported lock format.
    """
    packages = {}
    current = None
    for raw in contents.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        continuation = line.endswith("\\")
        if continuation:
            line = line[:-1].strip()
        if current is None:
            pieces = line.split()
            if len(pieces) != 1 or "==" not in pieces[0]:
                raise ValueError("lock must contain only exact pinned names and hashes")
            name, version = pieces[0].split("==", 1)
            if not NAME.fullmatch(name) or not VERSION.fullmatch(version):
                raise ValueError("lock name or version differs")
            key = normalized(name)
            if key in packages:
                raise ValueError("duplicate locked package")
            if not continuation:
                raise ValueError("locked package lacks hash continuation")
            current = (key, version, set())
        else:
            found = HASH.fullmatch(line)
            if not found:
                raise ValueError("lock contains non-hash continuation")
            current[2].add(found.group(1))
            if not continuation:
                packages[current[0]] = (current[1], current[2])
                current = None
    if current is not None or packages.get("oci-cli", (None,))[0] != "3.84.0":
        raise ValueError("lock is incomplete or OCI CLI version differs")
    return packages


def verify_wheelhouse(wheelhouse, packages):
    seen = set()
    for wheel in Path(wheelhouse).iterdir():
        safe_path(wheel, directory=False)
        if wheel.suffix != ".whl":
            raise ValueError("wheelhouse contains a non-wheel file")
        parts = wheel.name[:-4].split("-")
        if len(parts) not in (5, 6):
            raise ValueError("wheel filename differs")
        package, version = normalized(parts[0]), parts[1]
        if package not in packages or packages[package][0] != version:
            raise ValueError("wheel is not an exact locked package/version")
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if digest not in packages[package][1]:
            raise ValueError("wheel digest differs from lock")
        seen.add(package)
    if seen != set(packages):
        raise ValueError("wheelhouse lacks a locked package")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--installer", required=True, type=Path)
    args = parser.parse_args()
    safe_path(args.installer, directory=False)
    safe_path(Path(__file__), directory=False)
    if args.installer.parent != Path(__file__).parent:
        raise ValueError("installer and preflight script directory differs")
    safe_path(args.runtime_root, directory=True)
    safe_path(args.lock, directory=False)
    safe_path(args.wheelhouse, directory=True)
    packages = parse_lock(args.lock.read_text(encoding="utf-8"))
    verify_wheelhouse(args.wheelhouse, packages)


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"OCI CLI runtime preflight failed: {error}")
