# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only audit of the opt-in Linode UDP keyed source candidate.

This does not change Barragan's active deployment source pin. It lets an
offline ingress plan be evaluated against one exact candidate workspace.
"""

from __future__ import annotations

import hashlib
import json

from app.services.provider_keyed_sketch import (
    ProviderKeyedSketchError, ProviderKeyedWorkspace, SCHEMA,
    _source_files, _terraform_loadable,
)
from app.services.terraform_plan_gate import TerraformPlanGateError

_CANDIDATE_SOURCE_REVISION = "cae68e63b8495f0e6d31dfa4a991f4024f18e58b"
_CANDIDATE_SOURCE_SHA256 = "d0f3292ede53e09766f2710df3bc040410eaad24edd5f2f0d14b0dc8cf65d7ef"
_CANDIDATE_LOCK_SHA256 = "40e181997472ad02b0a68ef1b826c745f2d69c41426ab2a6d7000f9261399a49"


def require_candidate_linode_udp_workspace(workspace: ProviderKeyedWorkspace) -> None:
    """Require exact committed source, overlay, lock, and ownership marker."""
    if (not isinstance(workspace, ProviderKeyedWorkspace)
            or workspace.schema != SCHEMA or workspace.provider != "linode"
            or workspace.source_revision != _CANDIDATE_SOURCE_REVISION
            or workspace.source_sha256 != _CANDIDATE_SOURCE_SHA256):
        raise TerraformPlanGateError("Linode UDP candidate source is not audited")
    root = workspace.path
    try:
        marker = root / ".barragan-provider-keyed-state.json"
        if root.is_symlink() or marker.is_symlink() or not root.is_dir():
            raise ValueError("unsafe workspace")
        ownership = json.loads(marker.read_text(encoding="utf-8"))
        if not isinstance(ownership, dict) or any(
            ownership.get(key) != value for key, value in {
                "schema": SCHEMA,
                "engagement_id": root.parent.parent.parent.name,
                "provider": "linode",
                "provider_connection_id": workspace.provider_connection_id,
                "connection_fingerprint": workspace.connection_fingerprint,
                "source_revision": _CANDIDATE_SOURCE_REVISION,
            }.items()
        ):
            raise ValueError("ownership marker differs")
        source = ownership["source_files"]
        rendered = ownership["rendered_files"]
        if not isinstance(source, dict) or not isinstance(rendered, dict):
            raise ValueError("source inventory is missing")
        expected = dict(source)
        for target in ("providers.tf", "firewall.tf", ".terraform.lock.hcl"):
            expected[target] = source[f"barragan-v2/{target}"]
        digest = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        if (digest != _CANDIDATE_SOURCE_SHA256
                or source["barragan-v2/.terraform.lock.hcl"] != _CANDIDATE_LOCK_SHA256
                or rendered != expected
                or _source_files(root, tuple(rendered)) != rendered):
            raise ValueError("source files or rendered overlay differ")
        if any(
            path.relative_to(root).as_posix() not in rendered or path.is_symlink()
            for path in root.rglob("*")
            if _terraform_loadable(path.name) and (path.is_file() or path.is_symlink())
        ):
            raise ValueError("unreviewed Terraform source is present")
    except (OSError, ValueError, KeyError, TypeError, ProviderKeyedSketchError) as exc:
        raise TerraformPlanGateError("Linode UDP candidate workspace audit failed") from exc
