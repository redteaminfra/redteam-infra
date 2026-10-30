# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bind a reviewed initial plan and successful apply to read-only attachment intent."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Mapping

from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentIntent,
    ExpectedDigitalOceanNode,
    _require_state_identity,
    _validate_intent,
)
from app.services.provider_keyed_initial_plan_gate import DigitalOceanNodeCreate
from app.services.provider_keyed_plan_evidence import decode_preflight_initial_plan_evidence
from app.services.provider_keyed_persisted_intent import ProviderKeyedPersistedIntent
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.storage.job_repository import StoredJobRun


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_APPLY_EVENT_KEYS = {"stateSha256", "selectorTag", "attachmentProofPending", "hostProofPending"}


class ProviderKeyedInitialAttachmentAdapterError(ValueError):
    """The retained apply cannot be bound to the reviewed attachment policy."""


def derive_digitalocean_initial_attachment_intent(
    reviewed_intent: ProviderKeyedPersistedIntent,
    workspace: ProviderKeyedWorkspace,
    raw_plan_evidence: Mapping[str, object],
    apply_job: StoredJobRun,
    *, expected_phase: str = "applied",
) -> DigitalOceanAttachmentIntent:
    """Read only retained state; never use provider inventory as expected policy."""
    try:
        if (not isinstance(reviewed_intent, ProviderKeyedPersistedIntent)
                or not isinstance(workspace, ProviderKeyedWorkspace)
                or not isinstance(apply_job, StoredJobRun)
                or workspace.schema != SCHEMA or workspace.provider != "digitalocean"
                or expected_phase not in {"applied", "destroy_started"}
                or workspace.provider_connection_id == ""
                or reviewed_intent.provider != "digitalocean"
                or reviewed_intent.firewall.selector_tag != reviewed_intent.selector_tag
                or not isinstance(reviewed_intent.nodes, dict) or not reviewed_intent.nodes
                or any(not isinstance(value, DigitalOceanNodeCreate)
                       or value.firewall_selector_tag != reviewed_intent.selector_tag
                       for value in reviewed_intent.nodes.values())):
            raise ValueError("reviewed intent")
        decoded = decode_preflight_initial_plan_evidence(
            raw_plan_evidence, workspace,
            expected_core_job_id=reviewed_intent.core_job_id,
            expected_core_plan_id=reviewed_intent.core_plan_id,
            expected_revision_id=reviewed_intent.revision_id,
            expected_connection_id=workspace.provider_connection_id,
            expected_selector_tag=reviewed_intent.selector_tag,
        )
        if (apply_job.id != _apply_job_id(reviewed_intent.core_job_id)
                or apply_job.action != "provider_keyed_initial_apply" or apply_job.status != "succeeded"
                or not apply_job.finished_at or apply_job.target_type != "engagement"
                or apply_job.target != f"engagement:{reviewed_intent.engagement_id}"
                or apply_job.target_id != reviewed_intent.engagement_id
                or apply_job.input != {
                    "engagementId": reviewed_intent.engagement_id,
                    "coreJobId": reviewed_intent.core_job_id,
                    "corePlanId": reviewed_intent.core_plan_id,
                    "planJobId": _plan_job_id(reviewed_intent.core_job_id), "mutation": True,
                }):
            raise ValueError("apply job identity")
        events = [event for event in apply_job.events
                  if event.message == "provider saved-plan apply completed; proof pending"]
        if (len(events) != 1 or events[0].level != "info" or set(events[0].data) != _APPLY_EVENT_KEYS
                or events[0].data["selectorTag"] != reviewed_intent.selector_tag
                or events[0].data["attachmentProofPending"] is not True
                or events[0].data["hostProofPending"] is not True
                or not isinstance(events[0].data["stateSha256"], str)
                or not _HASH.fullmatch(events[0].data["stateSha256"])):
            raise ValueError("apply evidence")
        state_sha256 = events[0].data["stateSha256"]
        path = workspace.state_path
        if (not isinstance(path, Path) or path != workspace.path / "terraform.tfstate"
                or path.is_symlink() or not path.is_file()
                or workspace.path.is_symlink() or workspace.path.resolve(strict=True) != workspace.path):
            raise ValueError("state path")
        raw_state = path.read_bytes()
        if hashlib.sha256(raw_state).hexdigest() != state_sha256:
            raise ValueError("state digest")
        state = json.loads(raw_state)
        actual = _provider_resources(state)
        expected = set(reviewed_intent.nodes) | {"digitalocean_firewall.firewall"}
        if set(actual) != expected:
            raise ValueError("provider resource addresses")
        firewall = actual["digitalocean_firewall.firewall"]
        if (not isinstance(firewall, dict) or firewall.get("name") != reviewed_intent.firewall.name
                or firewall.get("tags") != [reviewed_intent.selector_tag]):
            raise ValueError("firewall identity")
        nodes = []
        for address, expected_node in sorted(reviewed_intent.nodes.items()):
            value = actual[address]
            if (not isinstance(value, dict) or value.get("name") != expected_node.name
                    or value.get("region") != expected_node.region
                    or value.get("tags") != [reviewed_intent.selector_tag]):
                raise ValueError("node identity")
            nodes.append(ExpectedDigitalOceanNode(
                address=address, droplet_id=str(value["id"]), name=expected_node.name,
                region=expected_node.region, public_ipv4=value["ipv4_address"],
            ))
        attachment = DigitalOceanAttachmentIntent(
            state_sha256=state_sha256, firewall_id=firewall["id"],
            firewall_name=reviewed_intent.firewall.name,
            selector_tag=reviewed_intent.selector_tag,
            trusted_ssh_cidrs=reviewed_intent.firewall.trusted_ssh_cidrs,
            nodes=tuple(nodes),
            credential_record_id=decoded.apply_evidence.credential_record_id,
            credential_secret_sha256=decoded.apply_evidence.credential_secret_sha256,
            credential_updated_at=decoded.apply_evidence.credential_updated_at,
        )
        # Reuse the GET-only reconciler's exact state/phase verifier before any
        # provider request; it rejects sibling resources and changed tags.
        _validate_intent(workspace, attachment)
        _require_state_identity(workspace, attachment, expected_phase=expected_phase)
        return attachment
    except Exception:
        raise ProviderKeyedInitialAttachmentAdapterError("retained attachment identity differs from reviewed apply") from None


def _provider_resources(state: object) -> dict[str, dict]:
    if not isinstance(state, dict) or not isinstance(state.get("resources"), list):
        raise ValueError("state resources")
    result: dict[str, dict] = {}
    for resource in state["resources"]:
        if not isinstance(resource, dict) or not isinstance(resource.get("instances"), list):
            raise ValueError("state resource")
        base = f'{resource.get("type")}.{resource.get("name")}'
        if not base.startswith(("digitalocean_droplet.", "digitalocean_firewall.")):
            continue
        if resource.get("module") not in (None, ""):
            raise ValueError("provider resource is outside the reviewed root module")
        for instance in resource["instances"]:
            if not isinstance(instance, dict) or not isinstance(instance.get("attributes"), dict):
                raise ValueError("state instance")
            key = instance.get("index_key")
            address = f"{base}[{json.dumps(key)}]" if isinstance(key, str) else base
            if address in result:
                raise ValueError("duplicate provider resource")
            result[address] = instance["attributes"]
    return result


def _plan_job_id(core_job_id: str) -> str:
    return f"job-provider-keyed-initial-plan-{core_job_id.removeprefix('job-')}"


def _apply_job_id(core_job_id: str) -> str:
    return f"job-provider-keyed-initial-apply-{core_job_id.removeprefix('job-')}"
