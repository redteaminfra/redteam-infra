# Copyright (c) 2026, Oracle and/or its affiliates.
"""Require an explicit hashed dependency closure without installer options."""
import hashlib
import re
from pathlib import Path
import sys


def verify(path, expected):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 1048576:
        raise ValueError("dependency lock must be a bounded regular file")
    data = p.read_bytes()
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("dependency lock checksum mismatch")
    packages = set()
    joined = data.decode().replace("\\\n", " ")
    for line in joined.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9_.+!-]+)(?:\s+--hash=sha256:[a-f0-9]{64})+", line)
        if not match:
            raise ValueError("lock requires exact versions and SHA256 hashes only")
        name = re.sub(r"[-_.]+", "-", match[1]).lower()
        if name in packages:
            raise ValueError("duplicate dependency")
        packages.add(name)
    if not {"jsonschema", "rfc8785", "setuptools", "wheel"} <= packages:
        raise ValueError("lock lacks application or build dependencies")
    return len(packages)


if __name__ == "__main__":
    try:
        print(verify(*sys.argv[1:]))
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))
