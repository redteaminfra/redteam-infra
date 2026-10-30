# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bounded Homebase configuration and private source delivery for Inference Proxy.

No IAM API calls, token issuance, or inference requests belong in installation.
Only committed application files are archived; controller SCM credentials never
leave the controller.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Any

CAPABILITY_ID = "inference-proxy"
SOURCE_REVISION = "98838ad67f6e242f281fb2154185f23e07fe1fae"
SOURCE_ROOT_ENV = "BARRAGAN_INFERENCE_PROXY_SOURCE_ROOT"
CONFIGURATION_KEY = "inferenceProxyConfiguration"
SOURCE_KEY = "inferenceProxySource"


class InferenceProxyConfigurationError(ValueError):
    pass


def is_selected(overrides: dict[str, Any]) -> bool:
    return any(row.get("id") == CAPABILITY_ID and row.get("hostClass") == "homebase"
               for row in overrides.get("selectedOptionals", []) if isinstance(row, dict))


def normalize_configuration(value: Any, *, required: bool = False) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - {"region", "compartmentId", "port"}:
        raise InferenceProxyConfigurationError("Inference Proxy configuration must contain only region, compartmentId and port")
    region, compartment = value.get("region", ""), value.get("compartmentId", "")
    port = value.get("port", 8787)
    if not isinstance(region, str) or (region and not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", region)):
        raise InferenceProxyConfigurationError("Inference Proxy requires a valid OCI inference region")
    if not isinstance(compartment, str) or (compartment and not re.fullmatch(r"ocid1\.compartment\.[a-z0-9-]+\.[a-z0-9.-]+", compartment)):
        raise InferenceProxyConfigurationError("Inference Proxy requires a model compartment OCID")
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise InferenceProxyConfigurationError("Inference Proxy loopback port must be an integer from 1024 through 65535")
    if required and (not region or not compartment):
        raise InferenceProxyConfigurationError("Configure the Inference Proxy inference region and model compartment before selecting it")
    return {"region": region, "compartmentId": compartment, "port": port}


def public_state(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "configuration": normalize_configuration(metadata.get(CONFIGURATION_KEY)),
        "accessStatus": "not_verified",
        "policyGuidance": {
            "notes": [
                "Configure OCI instance-principal membership and model-compartment policies in OCI. Barragan does not modify IAM.",
                "Installation and local service health do not verify OCI model access or inference.",
                "Issue agent credentials locally with /opt/inference-proxy/venv/bin/inference-proxy-admin; protect the issued token.",
            ],
            "documentationUrl": "https://docs.oracle.com/en-us/iaas/Content/generative-ai/iam-policies.htm",
        },
    }


def _git(root: Path, *args: str, binary: bool = False) -> Any:
    try:
        result = subprocess.run(
            ["git", "--no-optional-locks", *args], cwd=root, capture_output=True,
            text=not binary, timeout=30, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InferenceProxyConfigurationError("Inference Proxy source could not be verified or archived on the controller") from exc
    return result.stdout


def _safe_artifact(root: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or not re.fullmatch(
        r"barragan/artifacts/inference-proxy-[0-9a-f]{40}-[0-9a-f]{64}\.tar\.gz", relative
    ):
        raise InferenceProxyConfigurationError("Inference Proxy source artifact path is invalid")
    root = root.resolve()
    target = root / rel
    for path in [target, *target.parents]:
        if path == root:
            break
        if path.is_symlink():
            raise InferenceProxyConfigurationError("Inference Proxy source artifact must not use symlinks")
    if root not in target.resolve().parents:
        raise InferenceProxyConfigurationError("Inference Proxy source artifact escapes the workspace")
    return target


def source_archive() -> bytes:
    configured = os.environ.get(SOURCE_ROOT_ENV, "").strip()
    if not configured:
        raise InferenceProxyConfigurationError(f"Controller administrator must configure {SOURCE_ROOT_ENV} with the pinned Inference Proxy checkout")
    root = Path(configured).resolve()
    if not root.is_dir():
        raise InferenceProxyConfigurationError("Configured Inference Proxy source checkout is unavailable")
    if Path(_git(root, "rev-parse", "--show-toplevel").strip()).resolve() != root:
        raise InferenceProxyConfigurationError("Inference Proxy source must be its own Git checkout")
    def verify() -> None:
        if _git(root, "rev-parse", "HEAD").strip() != SOURCE_REVISION:
            raise InferenceProxyConfigurationError(f"Inference Proxy source must be pinned at {SOURCE_REVISION}")
        if _git(root, "status", "--porcelain", "--untracked-files=all").strip():
            raise InferenceProxyConfigurationError("Inference Proxy source checkout must be clean")
    verify()
    archive = _git(root, "archive", "--format=tar.gz", SOURCE_REVISION, binary=True)
    verify()
    if len(archive) > 64 * 1024 * 1024:
        raise InferenceProxyConfigurationError("Inference Proxy source archive exceeds the allowed size")
    return archive


def prepare_source(workspace_root: Path, archive: bytes) -> dict[str, str]:
    digest = hashlib.sha256(archive).hexdigest()
    relative = f"barragan/artifacts/inference-proxy-{SOURCE_REVISION}-{digest}.tar.gz"
    target = _safe_artifact(workspace_root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise InferenceProxyConfigurationError("Retained Inference Proxy source artifact has changed")
    else:
        with target.open("xb") as output:
            output.write(archive)
        target.chmod(0o600)
    return {"revision": SOURCE_REVISION, "sha256": digest, "relativePath": relative}


def execution_inputs(workspace_root: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    configuration = normalize_configuration(metadata.get(CONFIGURATION_KEY), required=True)
    source = metadata.get(SOURCE_KEY)
    if not isinstance(source, dict) or source.get("revision") != SOURCE_REVISION or not re.fullmatch(r"[0-9a-f]{64}", str(source.get("sha256", ""))):
        raise InferenceProxyConfigurationError("Save Inference Proxy configuration to prepare its pinned source artifact")
    relative = source.get("relativePath", "")
    if not isinstance(relative, str):
        raise InferenceProxyConfigurationError("Inference Proxy source artifact path is invalid")
    path = _safe_artifact(workspace_root, relative)
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
        raise InferenceProxyConfigurationError("Inference Proxy source artifact is missing or changed; save and prepare the capability again")
    expected = f"barragan/artifacts/inference-proxy-{SOURCE_REVISION}-{source['sha256']}.tar.gz"
    if relative != expected:
        raise InferenceProxyConfigurationError("Inference Proxy source artifact identity does not match its digest")
    return {
        "configuration": configuration,
        "source": {"revision": SOURCE_REVISION, "sha256": source["sha256"], "relativePath": relative},
    }


def role_variables(inputs: dict[str, Any]) -> dict[str, Any]:
    config, source = inputs["configuration"], inputs["source"]
    return {
        "inference_proxy_region": config["region"],
        "inference_proxy_compartment_id": config["compartmentId"],
        "inference_proxy_port": config["port"],
        "inference_proxy_source_archive": "{{ playbook_dir }}/../" + source["relativePath"],
        "inference_proxy_source_sha256": source["sha256"],
        "inference_proxy_source_revision": source["revision"],
    }
