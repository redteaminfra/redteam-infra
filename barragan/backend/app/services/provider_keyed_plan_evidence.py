# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure decoder for the retained provider plan after planned-state preflight.

The caller must first run ``preflight_planned_digitalocean_provider``. That
read-only gate proves one successful plan job/event, current reviewed intent,
and retained workspace files. This decoder only converts its exact event data
into typed, non-applying evidence for the later saved-plan boundary.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_saved_plan_runner import ProviderKeyedInitialPlanEvidence
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.services.provider_keyed_terraform_release import _REVIEWED_PATH, _REVIEWED_SHA256


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KEYS = frozenset({
    "coreJobId", "corePlanId", "revisionId", "providerConnectionId", "selectorTag",
    "sourceRevision", "planPath", "planSha256", "sourceSha256", "markerSha256",
    "topologySha256", "lockfileSha256", "inputSha256", "credentialSecretSha256",
    "credentialUpdatedAt", "terraformBinaryPath", "terraformBinarySha256", "terraformVersion",
    "adminPublicKeySha256", "adminPrivateKeyPath", "adminPublicKeyPath", "sshOutputDirectory",
})
_HASH_KEYS = (
    "planSha256", "sourceSha256", "markerSha256", "topologySha256", "lockfileSha256",
    "credentialSecretSha256", "terraformBinarySha256", "adminPublicKeySha256",
)


class ProviderKeyedPlanEvidenceError(ValueError):
    """Preflight evidence cannot be decoded into a safe saved-plan reference."""


@dataclass(frozen=True)
class DecodedProviderKeyedPlanEvidence:
    apply_evidence: ProviderKeyedInitialPlanEvidence
    admin_public_key_sha256: str


def decode_preflight_initial_plan_evidence(
    data: Mapping[str, object],
    workspace: ProviderKeyedWorkspace,
    *,
    expected_core_job_id: str,
    expected_core_plan_id: str,
    expected_revision_id: str,
    expected_connection_id: str,
    expected_selector_tag: str,
) -> DecodedProviderKeyedPlanEvidence:
    """Decode the *exact* evidence dict returned by planned-state preflight.

    This function performs no filesystem reads or mutations. It does not
    replace that preflight, a lease check, or the saved-plan apply gate.
    """
    try:
        if (not isinstance(data, dict) or set(data) != _KEYS
                or not isinstance(workspace, ProviderKeyedWorkspace)
                or not isinstance(workspace.path, Path)
                or any(type(value) is not str or not value for value in (
                    expected_core_job_id, expected_core_plan_id, expected_revision_id,
                    expected_connection_id, expected_selector_tag,
                ))):
            raise ValueError("shape")
        root = workspace.path
        fingerprint = hashlib.sha256(f"digitalocean\0{expected_connection_id}".encode()).hexdigest()
        if (not root.is_absolute() or ".." in root.parts
                or root.parent.name != "digitalocean" or root.parents[1].name != SCHEMA
                or root.name != fingerprint or workspace.connection_fingerprint != fingerprint
                or workspace.schema != SCHEMA or workspace.provider != "digitalocean"
                or workspace.provider_connection_id != expected_connection_id
                or workspace.source_revision != _SOURCE_REVISION
                or workspace.source_sha256 != _SOURCE_SHA256
                or workspace.state_path != root / "terraform.tfstate"
                or workspace.terraform_data_dir != root / ".terraform-data"):
            raise ValueError("workspace")
        if (data["coreJobId"] != expected_core_job_id
                or data["corePlanId"] != expected_core_plan_id
                or data["revisionId"] != expected_revision_id
                or data["providerConnectionId"] != expected_connection_id
                or data["selectorTag"] != expected_selector_tag
                or data["sourceRevision"] != _SOURCE_REVISION
                or data["sourceSha256"] != _SOURCE_SHA256
                or data["terraformVersion"] != "1.15.5"):
            raise ValueError("identity")
        if any(type(data[key]) is not str or not _HASH.fullmatch(data[key]) for key in _HASH_KEYS):
            raise ValueError("digest")
        if (data["terraformBinaryPath"] != str(_REVIEWED_PATH)
                or data["terraformBinarySha256"] != _REVIEWED_SHA256
                or type(data["credentialUpdatedAt"]) is not str
                or not data["credentialUpdatedAt"]):
            raise ValueError("release or credential")
        material = root.parents[1] / ".plan-material" / "digitalocean"
        plan = root / ".barragan-initial-full.tfplan"
        inputs = material / "inputs.json"
        if (data["planPath"] != str(plan)
                or data["adminPrivateKeyPath"] != str(material / "admin-private")
                or data["adminPublicKeyPath"] != str(material / "admin-public")
                or data["sshOutputDirectory"] != str(material / "ssh-output")):
            raise ValueError("path")
        manifest = data["inputSha256"]
        if (type(manifest) is not list or len(manifest) != 1
                or type(manifest[0]) is not list or len(manifest[0]) != 2
                or manifest[0][0] != str(inputs)
                or type(manifest[0][1]) is not str
                or not _HASH.fullmatch(manifest[0][1])):
            raise ValueError("input manifest")
        evidence = ProviderKeyedInitialPlanEvidence(
            plan_path=plan, plan_sha256=data["planSha256"],
            source_sha256=data["sourceSha256"], marker_sha256=data["markerSha256"],
            topology_sha256=data["topologySha256"], lockfile_sha256=data["lockfileSha256"],
            state_sha256=None, input_sha256=((str(inputs), manifest[0][1]),),
            credential_record_id=expected_connection_id,
            credential_secret_sha256=data["credentialSecretSha256"],
            credential_updated_at=data["credentialUpdatedAt"],
            terraform_version=data["terraformVersion"], terraform_binary_path=_REVIEWED_PATH,
            terraform_binary_sha256=data["terraformBinarySha256"],
        )
        return DecodedProviderKeyedPlanEvidence(evidence, data["adminPublicKeySha256"])
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise ProviderKeyedPlanEvidenceError("retained provider plan evidence is invalid") from exc
