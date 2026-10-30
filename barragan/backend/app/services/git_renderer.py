# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.domain import DeploymentRevisionPlan
from app.integrations.provider_plans import (
    build_provider_plan_bundle,
    render_ansible_intent,
    render_terraform_intent,
)


RENDER_SCHEMA_VERSION = "barragan.render.v1"


@dataclass(frozen=True)
class RenderedArtifact:
    path: str
    sha256: str

    def to_dict(self) -> dict:
        return {"path": self.path, "sha256": self.sha256}


@dataclass(frozen=True)
class RenderResult:
    render_id: str
    revision_id: str
    root: str
    artifacts: list[RenderedArtifact]

    def to_dict(self) -> dict:
        return {
            "renderId": self.render_id,
            "revisionId": self.revision_id,
            "root": self.root,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }


def render_revision_plan(
    revision: DeploymentRevisionPlan,
    destination: Path,
    render_job_id: str = "job-local-render",
) -> RenderResult:
    body = revision.to_dict()
    engagement_slug = _slugify(revision.engagement_id)
    revision_dir = destination / "engagements" / engagement_slug / "revisions" / f"r{revision.revision_number:04d}"
    artifacts: list[RenderedArtifact] = []
    provider_plan = build_provider_plan_bundle(revision)
    validation_gates = body.get("validationGates", [])
    validation_summary = _validation_gate_summary(validation_gates)

    manifest = {
        "schema_version": RENDER_SCHEMA_VERSION,
        "render_job_id": render_job_id,
        "engagement_id": revision.engagement_id,
        "deployment_revision_id": revision.id,
        "revision_number": revision.revision_number,
        "revision_status": revision.status,
        "template_id": revision.template_id,
        "template_version": "0.1.0",
        "barragan_source": "local",
        "non_mutation_notice": "render-only; no provider, Terraform, Ansible, DNS, secret, or cloud mutation performed",
        "validation_gate_summary": validation_summary,
    }

    _write_artifact(revision_dir, "manifest.yaml", manifest, artifacts)
    _write_artifact(revision_dir, "topology.yaml", body["resolvedTopology"], artifacts)
    _write_artifact(revision_dir, "inputs.yaml", body["inputParameters"], artifacts)
    _write_artifact(
        revision_dir,
        "validation/gates.yaml",
        {"summary": validation_summary, "gates": validation_gates},
        artifacts,
    )
    _write_artifact(
        revision_dir,
        "terraform/core.tf.json",
        render_terraform_intent(provider_plan)["providers"]["oci"],
        artifacts,
    )
    _write_artifact(
        revision_dir,
        "terraform/sketch.tf.json",
        {
            "linode": render_terraform_intent(provider_plan)["providers"]["linode"],
            "digitalocean": render_terraform_intent(provider_plan)["providers"]["digitalocean"],
            "sketchChains": body["resolvedTopology"]["sketchChains"],
        },
        artifacts,
    )
    _write_artifact(
        revision_dir,
        "ansible/inventory.yaml",
        render_ansible_intent(revision, provider_plan)["inventory"],
        artifacts,
    )
    _write_artifact(
        revision_dir,
        "ansible/runbook.yaml",
        {"steps": render_ansible_intent(revision, provider_plan)["runbook"]},
        artifacts,
    )
    _write_artifact(revision_dir, "proxy/egress-profiles.yaml", body["resolvedTopology"]["egressProfiles"], artifacts)
    _write_artifact(
        revision_dir,
        "proxy/profile-files.yaml",
        _proxy_profile_file_manifest(body["resolvedTopology"]["egressProfiles"]),
        artifacts,
    )
    _write_artifact(revision_dir, "proxy/ingress-routes.yaml", body["resolvedTopology"]["ingressRoutes"], artifacts)
    _write_artifact(revision_dir, "proxy/proxy-stack.yaml", body["resolvedTopology"]["proxyStacks"], artifacts)
    _write_artifact(revision_dir, "proxy/reverse-channels.yaml", body["resolvedTopology"]["reverseChannels"], artifacts)
    _write_artifact(
        revision_dir,
        "access/core-users.yaml",
        {"mode": "intent-only", "users": [], "secretValuesRendered": False},
        artifacts,
    )
    _write_artifact(
        revision_dir,
        "access/sketch-management.yaml",
        {"mode": "intent-only", "users": ["sketch-management"], "namedOperatorsRendered": False},
        artifacts,
    )
    _write_artifact(
        revision_dir,
        f"jobs/{render_job_id}.yaml",
        {"job_id": render_job_id, "action": "render_git_artifacts", "mode": "local"},
        artifacts,
    )

    manifest_with_artifacts = {
        **manifest,
        "artifact_files": [artifact.to_dict() for artifact in artifacts if artifact.path != "manifest.yaml"],
    }
    _write_artifact(revision_dir, "manifest.yaml", manifest_with_artifacts, artifacts, replace=True)

    return RenderResult(
        render_id=f"render-{revision.id}",
        revision_id=revision.id,
        root=str(revision_dir),
        artifacts=sorted(_dedupe_artifacts(artifacts), key=lambda artifact: artifact.path),
    )


def _write_artifact(
    root: Path,
    relative_path: str,
    content: Any,
    artifacts: list[RenderedArtifact],
    replace: bool = False,
) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(content, indent=2, sort_keys=True)
    path.write_text(f"{encoded}\n", encoding="utf-8")
    artifact = RenderedArtifact(relative_path, hashlib.sha256(path.read_bytes()).hexdigest())
    if replace:
        artifacts[:] = [item for item in artifacts if item.path != relative_path]
    artifacts.append(artifact)


def _dedupe_artifacts(artifacts: list[RenderedArtifact]) -> list[RenderedArtifact]:
    by_path = {artifact.path: artifact for artifact in artifacts}
    return list(by_path.values())


def _validation_gate_summary(validation_gates: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(validation_gates),
        "passed": sum(1 for gate in validation_gates if gate.get("status") == "passed"),
        "failed": sum(1 for gate in validation_gates if gate.get("status") == "failed"),
        "blockers": sum(1 for gate in validation_gates if gate.get("severity") == "blocker"),
    }


def _proxy_profile_file_manifest(egress_profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "profileId": profile["id"],
            "name": profile["name"],
            "ownerProxy": profile["proxy"],
            "listenerPort": profile["details"]["listenerPort"],
            "backingSketchChainId": profile["sketchChainId"],
            "publicationPath": profile["details"]["publicationPath"],
            "fileName": profile["details"]["profileFile"],
            "source": "compiled-topology",
        }
        for profile in egress_profiles
    ]


def _slugify(value: str) -> str:
    cleaned = "".join(character if character.isalnum() else "-" for character in value.lower())
    return "-".join(part for part in cleaned.split("-") if part)
