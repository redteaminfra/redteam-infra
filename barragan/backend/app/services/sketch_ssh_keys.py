# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.services.credentials import decrypt_secret_value, encrypt_secret_value
from app.services.engagements import get_engagement
from app.storage.sketch_ssh_key_repository import (
    SketchSshKeyRepository,
    SqlAlchemySketchSshKeyRepository,
    StoredSketchSshKey,
)
from app.storage.sketch_chain_repository import SketchChainRepository, SqlAlchemySketchChainRepository


class SketchSshKeyNotFoundError(ValueError):
    pass


class SketchSshKeyRotationError(ValueError):
    def __init__(self, errors: list[str], plan: dict[str, object] | None = None):
        super().__init__("sketch SSH key rotation failed")
        self.errors = errors
        self.plan = plan or {}


class SketchSshKeyRemovalError(ValueError):
    def __init__(self, errors: list[str], plan: dict[str, object] | None = None):
        super().__init__("sketch SSH key removal failed")
        self.errors = errors
        self.plan = plan or {}


SKETCH_SSH_KEY_ROTATION_CONFIRMATION = "rotate-sketch-key"
SKETCH_SSH_KEY_REMOVAL_CONFIRMATION = "remove-sketch-key"
ROTATION_SAFE_CHAIN_STATUSES = {"pending", "destroyed"}
REMOVAL_SAFE_CHAIN_STATUSES = {"destroyed"}


@dataclass(frozen=True)
class SketchSshKeyMetadata:
    engagement_id: str
    private_key_name: str
    public_key_name: str
    fingerprint: str
    retired_keys: list[dict[str, object]]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "engagementId": self.engagement_id,
            "privateKeyName": self.private_key_name,
            "publicKeyName": self.public_key_name,
            "fingerprint": self.fingerprint,
            "retiredKeys": self.retired_keys,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


@dataclass(frozen=True)
class SketchSshKeyMaterial:
    metadata: SketchSshKeyMetadata
    private_key: str
    public_key: str

    def to_dict(self) -> dict[str, object]:
        return {
            "key": self.metadata.to_dict(),
            "privateKey": self.private_key,
            "publicKey": self.public_key,
        }


def get_sketch_ssh_key_metadata(
    engagement_id: str,
    repository: SketchSshKeyRepository | None = None,
) -> SketchSshKeyMetadata | None:
    stored = (repository or SqlAlchemySketchSshKeyRepository()).get(engagement_id)
    return _metadata(stored) if stored else None


def ensure_sketch_ssh_key(
    engagement_id: str,
    repository: SketchSshKeyRepository | None = None,
) -> SketchSshKeyMetadata:
    repo = repository or SqlAlchemySketchSshKeyRepository()
    existing = repo.get(engagement_id)
    if existing is not None:
        return _metadata(existing)

    engagement = get_engagement(engagement_id)
    if engagement is None:
        raise SketchSshKeyNotFoundError("engagement not found")

    stored = repo.save(_new_stored_key(engagement_id, engagement.name))
    return _metadata(stored)


def preview_sketch_ssh_key_rotation(
    engagement_id: str,
    key_repository: SketchSshKeyRepository | None = None,
    chain_repository: SketchChainRepository | None = None,
) -> dict[str, object] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = key_repository or SqlAlchemySketchSshKeyRepository()
    current = repo.get(engagement_id)
    affected_chains = _affected_rotation_chains(engagement_id, chain_repository)
    blocked = bool(affected_chains)
    return {
        "engagementId": engagement_id,
        "status": "blocked" if blocked else "ready",
        "mutation": False,
        "currentKey": _metadata(current).to_dict() if current else None,
        "confirmation": SKETCH_SSH_KEY_ROTATION_CONFIRMATION,
        "requiresRepair": blocked,
        "affectedChains": affected_chains,
        "steps": _rotation_steps(blocked),
        "opsecBoundary": {
            "directSketchAccess": False,
            "middleAccess": "proxy jump only",
            "edgeAccess": "proxy to middle jump only",
        },
    }


def rotate_sketch_ssh_key(
    engagement_id: str,
    body: dict[str, object],
    key_repository: SketchSshKeyRepository | None = None,
    chain_repository: SketchChainRepository | None = None,
) -> dict[str, object] | None:
    if body.get("confirmation") != SKETCH_SSH_KEY_ROTATION_CONFIRMATION:
        raise SketchSshKeyRotationError([f'confirmation must equal "{SKETCH_SSH_KEY_ROTATION_CONFIRMATION}"'])
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = key_repository or SqlAlchemySketchSshKeyRepository()
    plan = preview_sketch_ssh_key_rotation(engagement_id, repo, chain_repository)
    if plan is None:
        return None
    if plan["requiresRepair"]:
        raise SketchSshKeyRotationError(
            [
                "sketch SSH key rotation is blocked while deployed, stopped, failed, or in-flight sketch chains may require repair"
            ],
            plan,
        )
    previous = repo.get(engagement_id)
    stored = repo.save(_new_stored_key(engagement_id, engagement.name, retired_keys=_retired_keys_with_previous(previous)))
    return {
        "key": _metadata(stored).to_dict(),
        "previousFingerprint": previous.fingerprint if previous else "",
        "rotation": {
            **plan,
            "status": "rotated",
            "mutation": True,
            "currentKey": _metadata(stored).to_dict(),
            "previousFingerprint": previous.fingerprint if previous else "",
        },
    }


def preview_sketch_ssh_key_removal(
    engagement_id: str,
    key_repository: SketchSshKeyRepository | None = None,
    chain_repository: SketchChainRepository | None = None,
    operations_overview: dict[str, object] | None = None,
) -> dict[str, object] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = key_repository or SqlAlchemySketchSshKeyRepository()
    current = repo.get(engagement_id)
    blockers = _removal_blockers(engagement_id, chain_repository, operations_overview)
    blocked = bool(blockers)
    return {
        "engagementId": engagement_id,
        "status": "blocked" if blocked else "ready",
        "mutation": False,
        "currentKey": _metadata(current).to_dict() if current else None,
        "confirmation": SKETCH_SSH_KEY_REMOVAL_CONFIRMATION,
        "requiresTeardown": blocked,
        "blockers": blockers,
        "steps": _removal_steps(blocked, current is not None),
        "opsecBoundary": {
            "directSketchAccess": False,
            "middleAccess": "proxy jump only",
            "edgeAccess": "proxy to middle jump only",
        },
    }


def remove_sketch_ssh_key(
    engagement_id: str,
    body: dict[str, object],
    key_repository: SketchSshKeyRepository | None = None,
    chain_repository: SketchChainRepository | None = None,
    operations_overview: dict[str, object] | None = None,
) -> dict[str, object] | None:
    if body.get("confirmation") != SKETCH_SSH_KEY_REMOVAL_CONFIRMATION:
        raise SketchSshKeyRemovalError([f'confirmation must equal "{SKETCH_SSH_KEY_REMOVAL_CONFIRMATION}"'])
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = key_repository or SqlAlchemySketchSshKeyRepository()
    plan = preview_sketch_ssh_key_removal(engagement_id, repo, chain_repository, operations_overview)
    if plan is None:
        return None
    if plan["requiresTeardown"]:
        raise SketchSshKeyRemovalError(
            ["sketch SSH key removal is blocked until engagement infrastructure is torn down"],
            plan,
        )
    removed = repo.delete(engagement_id)
    return {
        "removedKey": _metadata(removed).to_dict() if removed else None,
        "removal": {
            **plan,
            "status": "removed" if removed else "already_removed",
            "mutation": True,
            "currentKey": None,
            "removedFingerprint": removed.fingerprint if removed else "",
        },
    }


def retrieve_sketch_ssh_key(
    engagement_id: str,
    repository: SketchSshKeyRepository | None = None,
) -> SketchSshKeyMaterial | None:
    stored = (repository or SqlAlchemySketchSshKeyRepository()).get(engagement_id)
    if stored is None:
        return None
    return SketchSshKeyMaterial(
        metadata=_metadata(stored),
        private_key=decrypt_secret_value(stored.encrypted_private_key),
        public_key=decrypt_secret_value(stored.encrypted_public_key),
    )


def write_sketch_ssh_key_files(
    engagement_id: str,
    directory: Path,
    repository: SketchSshKeyRepository | None = None,
) -> tuple[str, str]:
    material = retrieve_sketch_ssh_key(engagement_id, repository)
    if material is None:
        ensure_sketch_ssh_key(engagement_id, repository)
        material = retrieve_sketch_ssh_key(engagement_id, repository)
    if material is None:
        raise SketchSshKeyNotFoundError("sketch SSH key not found")

    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / material.metadata.private_key_name
    public_path = directory / material.metadata.public_key_name
    private_path.write_text(material.private_key, encoding="utf-8")
    public_path.write_text(material.public_key, encoding="utf-8")
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)
    return str(private_path), str(public_path)


def write_existing_sketch_ssh_key_files(
    engagement_id: str,
    directory: Path,
    repository: SketchSshKeyRepository | None = None,
) -> tuple[str, str]:
    """Materialize the deployed infrastructure-admin identity for one run.

    This is deliberately retrieve-only.  Channel lifecycle operations must use
    the same infrastructure-admin key that provisioning installed on sketch
    hosts; creating a replacement key during an apply would strand those
    hosts.  The transport identity is separate and is only for ``sketchssh``
    forwarding.
    """
    material = retrieve_sketch_ssh_key(engagement_id, repository)
    if material is None:
        raise SketchSshKeyNotFoundError(
            "sketch infrastructure-admin SSH key not found; deploy the sketch chain before applying channels"
        )
    try:
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        private_path = directory / material.metadata.private_key_name
        public_path = directory / material.metadata.public_key_name
        private_path.write_text(material.private_key, encoding="utf-8")
        public_path.write_text(material.public_key, encoding="utf-8")
        os.chmod(private_path, 0o600)
        os.chmod(public_path, 0o644)
    except Exception:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return str(private_path), str(public_path)


def _new_stored_key(
    engagement_id: str,
    engagement_name: str,
    *,
    retired_keys: list[dict[str, object]] | None = None,
) -> StoredSketchSshKey:
    private_key, public_key = _generate_ed25519_pair()
    key_stem = _key_stem(engagement_name)
    return StoredSketchSshKey(
        engagement_id=engagement_id,
        private_key_name=f"{key_stem}-sketch",
        public_key_name=f"{key_stem}-sketch.pub",
        encrypted_private_key=encrypt_secret_value(private_key),
        encrypted_public_key=encrypt_secret_value(public_key),
        fingerprint=_fingerprint(public_key),
        retired_keys=list(retired_keys or []),
        created_at="",
        updated_at="",
    )


def _retired_keys_with_previous(previous: StoredSketchSshKey | None) -> list[dict[str, object]]:
    if previous is None:
        return []
    retired_keys = [_safe_retired_key(row) for row in previous.retired_keys]
    retired_keys.append(
        {
            "privateKeyName": previous.private_key_name,
            "publicKeyName": previous.public_key_name,
            "fingerprint": previous.fingerprint,
            "status": "retired",
            "reason": "rotated",
            "retiredAt": datetime.now(timezone.utc).isoformat(),
        }
    )
    return retired_keys


def _safe_retired_key(value: dict[str, Any]) -> dict[str, object]:
    return {
        "privateKeyName": str(value.get("privateKeyName") or ""),
        "publicKeyName": str(value.get("publicKeyName") or ""),
        "fingerprint": str(value.get("fingerprint") or ""),
        "status": str(value.get("status") or "retired"),
        "reason": str(value.get("reason") or "rotated"),
        "retiredAt": str(value.get("retiredAt") or ""),
    }


def _affected_rotation_chains(
    engagement_id: str,
    repository: SketchChainRepository | None,
) -> list[dict[str, object]]:
    chains = (repository or SqlAlchemySketchChainRepository()).list_for_engagement(engagement_id)
    affected = []
    for chain in chains:
        if chain.status in ROTATION_SAFE_CHAIN_STATUSES and not chain.nodes:
            continue
        affected.append(
            {
                "chainId": chain.chain_id,
                "assignedProxy": chain.assigned_proxy,
                "status": chain.status,
                "nodes": [
                    {
                        "hostname": str(node.get("hostname", "")),
                        "role": str(node.get("role", "")),
                        "provider": str(node.get("provider", "")),
                        "publicIp": str(node.get("publicIp", "")),
                    }
                    for node in chain.nodes
                    if isinstance(node, dict)
                ],
                "requiredAction": "reprovision_or_opsec_safe_repair",
            }
        )
    return affected


def _removal_blockers(
    engagement_id: str,
    chain_repository: SketchChainRepository | None,
    operations_overview: dict[str, object] | None,
) -> list[dict[str, object]]:
    overview = operations_overview
    if overview is None:
        from app.services.engagement_operations import get_operations_overview

        overview = get_operations_overview(engagement_id) or {}

    blockers: list[dict[str, object]] = []
    core_rows = overview.get("coreInfrastructure", []) if isinstance(overview, dict) else []
    sketch_rows = overview.get("sketchInfrastructure", []) if isinstance(overview, dict) else []
    if isinstance(core_rows, list) and core_rows:
        blockers.append(
            {
                "kind": "core_infrastructure",
                "count": len(core_rows),
                "detail": "Core homebase/proxy infrastructure is still recorded for this engagement.",
            }
        )
    active_sketch_rows = [
        row
        for row in sketch_rows
        if isinstance(row, dict)
        and str(row.get("status", "")).lower() not in REMOVAL_SAFE_CHAIN_STATUSES
        and (
            str(row.get("hostname", "")).strip() not in {"", "Not Deployed"}
            or str(row.get("publicIp", "")).strip() not in {"", "Not Deployed"}
        )
    ] if isinstance(sketch_rows, list) else []
    if active_sketch_rows:
        blockers.append(
            {
                "kind": "sketch_infrastructure",
                "count": len(active_sketch_rows),
                "detail": "Sketch middle/edge infrastructure is still recorded for this engagement.",
            }
        )

    chains = (chain_repository or SqlAlchemySketchChainRepository()).list_for_engagement(engagement_id)
    active_chains = [
        chain
        for chain in chains
        if chain.status not in REMOVAL_SAFE_CHAIN_STATUSES or chain.nodes
    ]
    for chain in active_chains:
        blockers.append(
            {
                "kind": "sketch_chain",
                "chainId": chain.chain_id,
                "assignedProxy": chain.assigned_proxy,
                "status": chain.status,
                "nodeCount": len(chain.nodes),
                "requiredAction": "tear_down_sketch_chain_first",
            }
        )
    return blockers


def _rotation_steps(blocked: bool) -> list[dict[str, object]]:
    if blocked:
        return [
            {
                "id": "inspect-affected-chains",
                "status": "blocked",
                "detail": "Existing sketch chains require reprovisioning or an OPSEC-safe repair path before key rotation.",
            },
            {
                "id": "preserve-current-key",
                "status": "pending",
                "detail": "Keep the current encrypted key active until affected chains are handled.",
            },
        ]
    return [
        {
            "id": "generate-new-keypair",
            "status": "ready",
            "detail": "Generate a new encrypted engagement-scoped keypair.",
        },
        {
            "id": "future-deployments-use-new-key",
            "status": "ready",
            "detail": "Future sketch deployments and outbound channel applies will use the rotated key.",
        },
    ]


def _removal_steps(blocked: bool, has_key: bool) -> list[dict[str, object]]:
    if blocked:
        return [
            {
                "id": "verify-teardown",
                "status": "blocked",
                "detail": "Tear down recorded core and sketch infrastructure before removing encrypted sketch key material.",
            },
            {
                "id": "preserve-current-key",
                "status": "pending",
                "detail": "Keep the current encrypted key active while any infrastructure may still need it.",
            },
        ]
    if not has_key:
        return [
            {
                "id": "nothing-to-remove",
                "status": "ready",
                "detail": "No encrypted sketch key material is stored for this engagement.",
            }
        ]
    return [
        {
            "id": "remove-encrypted-key",
            "status": "ready",
            "detail": "Delete Barragan's encrypted engagement sketch key material.",
        },
        {
            "id": "require-regeneration",
            "status": "ready",
            "detail": "A future sketch deployment must explicitly generate a new engagement key.",
        },
    ]


def _metadata(stored: StoredSketchSshKey) -> SketchSshKeyMetadata:
    return SketchSshKeyMetadata(
        engagement_id=stored.engagement_id,
        private_key_name=stored.private_key_name,
        public_key_name=stored.public_key_name,
        fingerprint=stored.fingerprint,
        retired_keys=[_safe_retired_key(row) for row in stored.retired_keys],
        created_at=stored.created_at,
        updated_at=stored.updated_at,
    )


def _generate_ed25519_pair() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")
    return private_key, public_key


def _key_stem(engagement_name: str) -> str:
    stem = re.sub(r"[^a-z0-9]+", "-", engagement_name.strip().lower()).strip("-")
    return stem or "engagement"


def _fingerprint(public_key: str) -> str:
    parts = public_key.split()
    if len(parts) < 2:
        return ""
    digest = hashlib.sha256(base64.b64decode(parts[1].encode("ascii"))).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
