# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only full-state destroy targets for one published DigitalOcean append.

This is input to the existing exact-delete plan gate, not command authority.
Credential, workspace and provider membership proof remain separate boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import asdict
import hashlib
import json
import os
import stat
from pathlib import Path

from app.services.provider_keyed_append_source import (
    _restore_chain, audit_published_provider_keyed_append_source,
)
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentIntent, ExpectedDigitalOceanNode,
    _require_state_identity, _validate_intent,
)
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_initial_teardown import (
    DigitalOceanTeardownIntent, _require_exact_state, _state_resources,
)
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.services.managed_host_image_continuity import managed_host_image_profile_named
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class ProviderKeyedAppendDestroyTargetsError(ValueError):
    """The reviewed five-node delete set is unavailable."""


@dataclass(frozen=True)
class PublishedAppendDestroyTargets:
    teardown_parent_id: str
    state_sha256: str
    resource_ids: dict[str, str]


@dataclass(frozen=True)
class PublishedAppendDestroyBinding:
    """Exact retained five-node source for the existing destroy plan/apply gates."""

    workspace: ProviderKeyedWorkspace
    intent: DigitalOceanTeardownIntent
    attachment: DigitalOceanAttachmentIntent
    input_path: Path
    input_sha256: str
    admin_public_key_sha256: str
    terraform_binary_path: Path
    terraform_binary_sha256: str
    marker_sha256: str
    topology_sha256: str
    lockfile_sha256: str


def bind_published_append_destroy(
    teardown_parent_id: str, *, environment: str = "devtest", state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    engagement_repository=None, credential_repository=None,
) -> PublishedAppendDestroyBinding:
    """Rebuild one expanded generation from saved publication, never provider inventory.

    The plan and apply children call this afresh before GO. A successful
    initial Apply receipt alone is deliberately insufficient for five nodes.
    """
    try:
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        engagements = engagement_repository or SqlAlchemyEngagementRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        source = load_keyed_teardown_source(
            teardown_parent_id, phase="pre_go", environment=environment,
            state_root=state_root, job_repository=jobs, plan_repository=plans,
            sketch_repository=chains,
        )
        if source.variant != "published_append":
            raise ValueError("one published append is required")
        parent = jobs.get(teardown_parent_id)
        expanded = audit_published_provider_keyed_append_source(
            source.core_job_id, environment=environment, state_root=state_root,
            engagement_repository=engagements, sketch_repository=chains,
            job_repository=jobs, plan_repository=plans,
        )
        if parent.input.get("publishedAppendSource") != json.loads(json.dumps(asdict(expanded))):
            raise ValueError("sealed append differs")
        scope = build_digitalocean_keyed_teardown_scope(
            source.engagement_id, source.core_job_id, environment=environment,
            state_root=state_root, allowed_teardown_parent_id=parent.id,
            engagement_repository=engagements, sketch_repository=chains,
            job_repository=jobs, plan_repository=plans,
            credential_repository=credentials,
        )
        if scope != parent.input["scopeSnapshot"]["providerScopes"][0]:
            raise ValueError("reviewed scope differs")
        append = jobs.get(expanded.append_job_id)
        append_plan = jobs.get(append.input["planJobId"])
        event = append_plan.events[-1].data
        from app.services.provider_keyed_append_plan_job import _PLAN_EVENT_KEYS
        if (append_plan.status != "succeeded" or set(event) != _PLAN_EVENT_KEYS
                or event["initialSource"] != parent.input["publishedSource"]
                or event["newEdgeAddress"] != expanded.new_edge_address
                or event["credentialRecordId"] != scope["providerConnectionId"]
                or event["sourceSha256"] != _SOURCE_SHA256):
            raise ValueError("reviewed append plan differs")
        rows = chains.list_for_engagement(source.engagement_id)
        previous = _restore_chain(event["selectedChain"])
        sibling = next(row for row in rows if row.chain_id != previous.chain_id)
        core = jobs.get(source.core_job_id)
        core_plan = plans.get(source.core_plan_id)
        engagement = engagements.get(source.engagement_id)
        profile = managed_host_image_profile_named(core_plan.evidence["managedHostImageProfile"])
        reviewed = compile_fresh_digitalocean_persisted_intent(
            engagement, rows, core, core_plan, profile,
            environment=environment, provider_state_exists=True,
            mode="materialized_read", reviewed_initial_chains=(previous, sibling),
        )
        workspace_root = Path(scope["workspace"])
        workspace = ProviderKeyedWorkspace(
            workspace_root, workspace_root / "terraform.tfstate",
            workspace_root / ".terraform-data", SCHEMA, "digitalocean",
            scope["providerConnectionId"], workspace_root.name,
            _SOURCE_REVISION, _SOURCE_SHA256,
        )
        raw = workspace.state_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expanded.state_sha256:
            raise ValueError("expanded state digest differs")
        values = _state_resources(json.loads(raw))
        ids = {item["address"]: item["id"] for item in scope["resources"]}
        if (len(ids) != 9 or len(values) != 9 or set(ids) != set(values)
                or set(reviewed.nodes) != {address for address in ids
                                            if address.startswith("digitalocean_droplet.")}
                or any(str(values[address].get("id")) != value
                       for address, value in ids.items())):
            raise ValueError("expanded resource IDs differ")
        digest, updated_at, _ = _credential_snapshot(scope["providerConnectionId"], credentials)
        if (event["credentialSecretSha256"], event["credentialUpdatedAt"]) != (digest, updated_at):
            raise ValueError("append provider credential changed")
        teardown = DigitalOceanTeardownIntent(
            reviewed.nodes, reviewed.firewall, ids, expanded.state_sha256,
            scope["providerConnectionId"], digest, updated_at,
        )
        _require_exact_state(workspace, teardown)
        projected = {node["terraformAddress"]: node for row in rows for node in row.nodes}
        attachment = DigitalOceanAttachmentIntent(
            expanded.state_sha256, ids["digitalocean_firewall.firewall"],
            reviewed.firewall.name, reviewed.selector_tag,
            reviewed.firewall.trusted_ssh_cidrs,
            tuple(ExpectedDigitalOceanNode(
                address, ids[address], node.name, node.region,
                projected[address]["publicIp"],
            ) for address, node in sorted(reviewed.nodes.items())),
            scope["providerConnectionId"], digest, updated_at,
        )
        _validate_intent(workspace, attachment)
        _require_state_identity(workspace, attachment, expected_phase="applied")
        input_path = workspace_root.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json"
        info = input_path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("retained append input is unsafe")
        input_digest = hashlib.sha256(input_path.read_bytes()).hexdigest()
        if event["inputSha256"] != [[str(input_path), input_digest]]:
            raise ValueError("retained append input differs")
        initial_plan = jobs.get(
            f"job-provider-keyed-initial-plan-{source.core_job_id.removeprefix('job-')}")
        initial_events = [row for row in initial_plan.events
                          if row.message == "reviewed provider plan saved"]
        if len(initial_events) != 1 or initial_plan.status != "succeeded":
            raise ValueError("initial reviewed key differs")
        public_key_digest = initial_events[0].data["adminPublicKeySha256"]
        marker_digest = hashlib.sha256((workspace_root / ".barragan-provider-keyed-state.json").read_bytes()).hexdigest()
        topology_digest = hashlib.sha256((workspace_root / ".barragan-topology.json").read_bytes()).hexdigest()
        lockfile_digest = hashlib.sha256((workspace_root / ".terraform.lock.hcl").read_bytes()).hexdigest()
        if (marker_digest != initial_events[0].data["markerSha256"]
                or topology_digest != event["topologySha256"]
                or lockfile_digest != event["lockfileSha256"]):
            raise ValueError("retained append workspace differs")
        binary = Path(event["terraformBinaryPath"])
        if (not binary.is_absolute() or binary.is_symlink()
                or hashlib.sha256(binary.read_bytes()).hexdigest()
                != event["terraformBinarySha256"]):
            raise ValueError("pinned Terraform differs")
        again = audit_published_provider_keyed_append_source(
            source.core_job_id, environment=environment, state_root=state_root,
            engagement_repository=engagements, sketch_repository=chains,
            job_repository=jobs, plan_repository=plans,
        )
        if again != expanded or jobs.get(parent.id) != parent:
            raise ValueError("appended source changed during read")
        return PublishedAppendDestroyBinding(
            workspace, teardown, attachment, input_path, input_digest,
            public_key_digest, binary, event["terraformBinarySha256"],
            marker_digest, topology_digest, lockfile_digest,
        )
    except Exception:
        raise ProviderKeyedAppendDestroyTargetsError(
            "reviewed appended destroy binding is unproved") from None


def read_published_append_destroy_targets(
    teardown_parent_id: str, *, environment: str = "devtest",
    state_root: Path | None = None, job_repository=None,
) -> PublishedAppendDestroyTargets:
    """Reprove the fenced parent and return every exact managed address/ID."""
    try:
        jobs = job_repository or SqlAlchemyJobRepository()
        source = load_keyed_teardown_source(
            teardown_parent_id, phase="pre_go", environment=environment,
            state_root=state_root, job_repository=jobs,
        )
        if source.variant != "published_append":
            raise ValueError("not an appended published source")
        parent = jobs.get(teardown_parent_id)
        scope = parent.input["scopeSnapshot"]["providerScopes"][0]
        current = build_digitalocean_keyed_teardown_scope(
            source.engagement_id, source.core_job_id, environment=environment,
            state_root=state_root, allowed_teardown_parent_id=teardown_parent_id,
            job_repository=jobs,
        )
        resources = current["resources"]
        ids = {item["address"]: item["id"] for item in resources}
        if (current != scope or len(ids) != len(resources) or len(ids) != 9
                or len([address for address in ids if address.startswith(
                    "digitalocean_droplet.")]) != 5
                or current["stateSha256"] != parent.input[
                    "publishedAppendSource"]["state_sha256"]):
            raise ValueError("expanded reviewed delete set differs")
        again = load_keyed_teardown_source(
            teardown_parent_id, phase="pre_go", environment=environment,
            state_root=state_root, job_repository=jobs,
        )
        if again != source or jobs.get(teardown_parent_id) != parent:
            raise ValueError("expanded delete source changed during read")
        return PublishedAppendDestroyTargets(
            teardown_parent_id, current["stateSha256"], ids,
        )
    except Exception:
        raise ProviderKeyedAppendDestroyTargetsError(
            "reviewed appended delete set is unproved") from None
