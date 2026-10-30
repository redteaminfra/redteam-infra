# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only retained-install fence; no secret or state contents are returned."""
import json
import os
from pathlib import Path
import re
import sys


def check(root, revision, source_digest, dependency_digest):
    root = Path(root)
    # Check every ancestor: a regular final path is insufficient behind a symlink.
    for path in reversed((root, *root.parents)):
        if path.is_symlink():
            raise ValueError("installation path contains a symlink")
        if path.exists() and (not path.is_dir() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022):
            raise ValueError("installation path must be root-owned and not group/world writable")
    expected = dict(revision=revision, sourceSha256=source_digest, dependencySha256=dependency_digest)
    receipt = root / ".installed-artifact.json"
    if not receipt.exists() and not receipt.is_symlink():
        receipt = root / ".artifact-intent.json"
    if receipt.is_symlink():
        raise ValueError("unsafe retained receipt")
    if receipt.exists():
        if not receipt.is_file() or receipt.stat().st_uid != 0 or receipt.stat().st_mode & 0o022:
            raise ValueError("unsafe retained receipt")
        if json.loads(receipt.read_text()) != expected:
            raise ValueError("source or dependency migration requires explicit upgrade")
    elif root.exists() and any(root.iterdir()):
        raise ValueError("nonempty unmanaged installation requires explicit recovery")
    for name in ("venv", "releases", "releases/" + revision):
        p = root / name
        if p.is_symlink() or (p.exists() and (not p.is_dir() or p.stat().st_uid != 0 or p.stat().st_mode & 0o022)):
            raise ValueError("unsafe retained installation directory")
    return expected


if __name__ == "__main__":
    try:
        print(json.dumps(check(*sys.argv[1:])))
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))
