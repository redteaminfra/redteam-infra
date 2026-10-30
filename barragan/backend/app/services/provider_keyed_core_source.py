# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, read-only source pin for the DevTest provider-keyed handoff."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_sketch import _source_files, _tracked_template_files


class ProviderKeyedCoreSourceError(ValueError):
    pass


def require_keyed_core_source(root: Path) -> dict[str, str]:
    """Pin the exact clean upstream template without copying or rendering it."""
    try:
        if (not isinstance(root, Path) or not root.is_absolute()
                or root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir()):
            raise ValueError

        def git(*args: str) -> str:
            result = subprocess.run(
                ["git", "--no-optional-locks", "-C", str(root), *args],
                capture_output=True, text=True, check=False, timeout=15,
            )
            if result.returncode:
                raise ValueError
            return result.stdout.strip()

        if (Path(git("rev-parse", "--show-toplevel")) != root
                or git("rev-parse", "HEAD") != _SOURCE_REVISION
                or git("status", "--porcelain=v1", "--untracked-files=all")
                or git("status", "--porcelain=v1", "--ignored", "--untracked-files=all",
                       "--", "external/sketch/digitalocean")):
            raise ValueError
        template = root / "external" / "sketch" / "digitalocean"
        if template.is_symlink() or not template.is_dir():
            raise ValueError
        inventory = _source_files(template, _tracked_template_files(root, "digitalocean"))
        digest = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
        if digest != _SOURCE_SHA256:
            raise ValueError
        return {"root": str(root), "revision": _SOURCE_REVISION, "templateSha256": digest}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise ProviderKeyedCoreSourceError("pinned provider-keyed source is unavailable or changed") from None
