# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, complete provider scope for a keyed DevTest teardown preview.

This is review evidence, not permission to run a destroy plan. In particular,
local_file state IDs are local Terraform identities, not cloud resource IDs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_teardown import (
    DigitalOceanTeardownIntent, _SHARED, _require_exact_state, _state_resources,
)
from app.services.provider_keyed_postapply_preflight import read_applied_digitalocean_provider_for_teardown
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_runtime_preflight import _inert_aborted_intent
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class ProviderKeyedTeardownScopeError(ValueError):
    """A complete, independently reviewed provider scope was not proven."""


def build_digitalocean_keyed_teardown_scope(
    engagement_id: str, core_job_id: str, *,
    environment: str = "devtest", state_root: Path | None = None,
    allowed_teardown_parent_id: str | None = None,
    allowed_append_plan_parent_id: str | None = None,
    engagement_repository=None, sketch_repository=None, job_repository=None,
    plan_repository=None, credential_repository=None,
) -> dict:
    """Seal every managed state address and ID after a successful exact apply."""
    try:
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        if allowed_append_plan_parent_id is not None:
            if allowed_teardown_parent_id is not None:
                raise ValueError("concurrent append and teardown review")
            _require_unapplied_append_plan(engagement_id, allowed_append_plan_parent_id,
                                           job_repository,
                                           expected_core_job_id=core_job_id)
        elif (_has_provider_keyed_append(engagement_id, job_repository)
              and _reconciled_unapplied_append_state_sha(
                  engagement_id, job_repository,
                  expected_core_job_id=core_job_id) is None):
            return _build_published_append_scope(
                engagement_id, core_job_id, environment=environment,
                state_root=state_root, chains=chains, job_repository=job_repository,
                plan_repository=plan_repository, engagement_repository=engagement_repository,
                allowed_teardown_parent_id=allowed_teardown_parent_id,
            )
        rows = [row for row in chains.list_for_engagement(engagement_id)
                if not _inert_aborted_intent(row, engagement_id)]
        if len(rows) != 2:
            raise ValueError("reviewed chain count")
        if all(row.status == "pending" and not row.nodes for row in rows):
            mode = "applied_read"
        elif all(row.status in {"deploying", "deployed", "failed", "stopped", "tearing_down"}
                 and row.nodes for row in rows):
            mode = "materialized_read"
        else:
            raise ValueError("mixed or incomplete chain projection")
        intent, workspace, plan_evidence, apply_job = read_applied_digitalocean_provider_for_teardown(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root or _default_state_root(), mode=mode,
            allowed_teardown_parent_id=allowed_teardown_parent_id,
            engagement_repository=engagement_repository, sketch_repository=chains,
            job_repository=job_repository, plan_repository=plan_repository,
            credential_repository=credential_repository,
        )
        attachment = derive_digitalocean_initial_attachment_intent(intent, workspace, plan_evidence, apply_job)
        raw = workspace.state_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != attachment.state_sha256:
            raise ValueError("applied state changed")
        reconciled_sha = _reconciled_unapplied_append_state_sha(
            engagement_id, job_repository,
            allowed_active_parent_id=allowed_append_plan_parent_id,
            expected_core_job_id=core_job_id,
            expected_core_plan_id=intent.core_plan_id)
        from app.storage.job_repository import SqlAlchemyJobRepository
        related = (job_repository or SqlAlchemyJobRepository()).list_for_engagement(engagement_id)
        append_count = sum(job.action == "provider_keyed_edge_append" for job in related)
        if (append_count > (1 if allowed_append_plan_parent_id is not None else 0)
                and reconciled_sha is None):
            raise ValueError("unproved append history cannot use initial scope")
        if reconciled_sha is not None and reconciled_sha != attachment.state_sha256:
            raise ValueError("reconciled failed append changed retained state")
        state = json.loads(raw)
        actual = _state_resources(state)
        expected = set(intent.nodes) | _SHARED
        if set(actual) != expected:
            raise ValueError("full managed state differs")
        resource_ids = {address: attributes.get("id") for address, attributes in actual.items()}
        if any(type(value) is not str or not value or value != value.strip()
               for value in resource_ids.values()):
            raise ValueError("managed resource ID")
        teardown_intent = DigitalOceanTeardownIntent(
            intent.nodes, intent.firewall, resource_ids, attachment.state_sha256,
            attachment.credential_record_id, attachment.credential_secret_sha256,
            attachment.credential_updated_at,
        )
        _require_exact_state(workspace, teardown_intent)
        if (resource_ids["digitalocean_firewall.firewall"] != str(attachment.firewall_id)
                or {node.address: resource_ids[node.address] for node in attachment.nodes}
                != {node.address: str(node.droplet_id) for node in attachment.nodes}):
            raise ValueError("provider IDs differ from applied proof")
        if mode == "materialized_read":
            expected_nodes = {node.address: node for node in attachment.nodes}
            seen = set()
            routes = {route.chain_id: route for route in intent.chain_routes}
            for chain in rows:
                route = routes[chain.chain_id]
                selected = {f'digitalocean_droplet.middle["{route.middle_node}"]',
                            *(f'digitalocean_droplet.edge["{key}"]' for key in route.edge_nodes)}
                actual_addresses = set()
                for row in chain.nodes:
                    if type(row) is not dict:
                        raise ValueError("projected node row")
                    address = row.get("terraformAddress")
                    if address not in selected or address in seen:
                        raise ValueError("projected node address")
                    node = expected_nodes[address]
                    role = "middle" if address.startswith("digitalocean_droplet.middle[") else "edge"
                    if (row.get("chainId") != chain.chain_id or row.get("role") != role
                            or row.get("provider") != "digitalocean"
                            or row.get("providerInstanceId") != node.droplet_id
                            or row.get("hostname") != node.name
                            or row.get("region") != node.region
                            or row.get("publicIp") != node.public_ipv4
                            or row.get("assignedProxy") != route.assigned_proxy):
                        raise ValueError("projected node identity")
                    actual_addresses.add(address)
                    seen.add(address)
                if actual_addresses != selected:
                    raise ValueError("projected route incomplete")
            if seen != set(expected_nodes):
                raise ValueError("projected provider set incomplete")
        if hashlib.sha256(workspace.state_path.read_bytes()).hexdigest() != attachment.state_sha256:
            raise ValueError("applied state changed")
        if ([row for row in chains.list_for_engagement(engagement_id)
             if not _inert_aborted_intent(row, engagement_id)] != rows):
            raise ValueError("chain projection changed")
        def kind(address: str) -> str:
            if address.startswith("digitalocean_droplet."):
                return "droplet"
            if address == "digitalocean_firewall.firewall":
                return "firewall"
            if address == "digitalocean_ssh_key.key":
                return "ssh_key"
            if address in {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}:
                return "local_file"
            raise ValueError("unexpected managed address")
        return {
            "schema": "provider-keyed-v2", "provider": "digitalocean",
            "coreJobId": core_job_id, "corePlanId": intent.core_plan_id,
            "revisionId": intent.revision_id,
            "providerConnectionId": workspace.provider_connection_id,
            "workspace": str(workspace.path),
            "sourceRevision": workspace.source_revision,
            "selectorTag": intent.selector_tag,
            "stateSha256": attachment.state_sha256,
            "chainIds": [route.chain_id for route in intent.chain_routes],
            "chainFingerprints": {row.chain_id: sketch_chain_intent_fingerprint(row)
                                  for row in sorted(rows, key=lambda row: row.chain_id)},
            "resources": [
                {"address": address, "id": resource_ids[address], "kind": kind(address)}
                for address in sorted(resource_ids)
            ],
        }
    except Exception:
        raise ProviderKeyedTeardownScopeError("complete applied provider teardown scope is unavailable") from None


def _has_provider_keyed_append(engagement_id: str, repository) -> bool:
    from app.storage.job_repository import SqlAlchemyJobRepository

    jobs = repository or SqlAlchemyJobRepository()
    return any(job.action == "provider_keyed_edge_append"
               for job in jobs.list_for_engagement(engagement_id))


def _exact_no_go_apply_child(parent, related, jobs, *, fenced: bool = False):
    """Recognize only the reserved child that has no command/start history."""
    from app.services.provider_keyed_append_apply_job import _child_id
    from app.storage.job_repository import job_event_digest

    if (type(getattr(parent, "input", None)) is not dict
            or type(parent.input.get("applyReservationId")) is not str
            or len(parent.input["applyReservationId"]) != 32
            or type(parent.input.get("planJournalSha256")) is not str
            or parent.input.get("applyJobId") != _child_id(parent.id)):
        return None
    plan = jobs.get(parent.input.get("planJobId"))
    children = [job for job in related
                if job.action == "provider_keyed_edge_append_apply"
                and job.input.get("parentJobId") == parent.id]
    if (len(children) != 1 or any(job.action == "provider_keyed_edge_append_host_proof"
                                   and job.input.get("parentJobId") == parent.id
                                   for job in related)
            or plan is None or plan.action != "provider_keyed_edge_append_plan"
            or plan.status != "succeeded" or not plan.events
            or plan.events[-1].message != "reviewed append plan saved"
            or job_event_digest(plan.events) != parent.input["planJournalSha256"]):
        return None
    child = children[0]
    reserved = [event for event in parent.events
                if event.message == "provider append Apply reserved"]
    if (len(reserved) != 1 or reserved[0].data != {
            "planJournalSha256": parent.input["planJournalSha256"],
            "reservationId": parent.input["applyReservationId"]}):
        return None
    if (child.id != _child_id(parent.id) or child.target_id != parent.target_id
            or child.target != parent.target or child.target_type != "engagement"
            or child.action != "provider_keyed_edge_append_apply"
            or child.input != {
                "engagementId": parent.target_id, "parentJobId": parent.id,
                "coreJobId": parent.input.get("coreJobId"),
                "corePlanId": parent.input.get("corePlanId"),
                "planJobId": plan.id, "mutation": True,
            } or child.artifact_refs != [] or child.started_at is not None):
        return None
    expected = {"planJournalSha256": parent.input["planJournalSha256"],
                "reservationId": parent.input["applyReservationId"]}
    if (not child.events or child.events[0].sequence != 1
            or child.events[0].level != "info"
            or child.events[0].message != "provider append Apply child reserved"
            or child.events[0].data != expected):
        return None
    if not fenced:
        return child if (child.status == "queued" and child.finished_at is None
                         and len(child.events) == 1) else None
    if (child.status != "failed" or child.finished_at is None
            or len(child.events) != 2 or child.events[1].sequence != 2
            or child.events[1].level != "info"
            or child.events[1].message != "provider append Apply never started"
            or child.events[1].data != {
                "stateSha256": plan.events[-1].data.get("stateSha256"),
                "planJournalSha256": parent.input["planJournalSha256"],
            }):
        return None
    return child


def _reconciled_unapplied_append_state_sha(
    engagement_id: str, repository, *, allowed_active_parent_id: str | None = None,
    allowed_published_parent_id: str | None = None,
    expected_core_job_id: str | None = None, expected_core_plan_id: str | None = None,
) -> str | None:
    from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest

    jobs = repository or SqlAlchemyJobRepository()
    related = jobs.list_for_engagement(engagement_id)
    parents = [job for job in related if job.action == "provider_keyed_edge_append"]
    if (not parents or any(type(getattr(job, "input", None)) is not dict
                           for job in parents)
            or (allowed_active_parent_id is not None
                        and allowed_published_parent_id is not None)):
        return None
    excluded_id = allowed_active_parent_id or allowed_published_parent_id
    active = [job for job in parents if job.id == excluded_id]
    if excluded_id is not None and len(active) != 1:
        return None
    published = active[0] if allowed_published_parent_id is not None else None
    active_no_go = None
    if allowed_active_parent_id is not None:
        active_parent = active[0]
        if (active_parent.status == "failed"
                and active_parent.input.get("phase") in {"attention", "no_go_cleaning"}):
            active_no_go = _exact_no_go_apply_child(
                active_parent, related, jobs,
                fenced=active_parent.input["phase"] == "no_go_cleaning")
    permitted_applied_ids = ({published.input.get("applyJobId"),
                              published.input.get("hostProofJobId")}
                             if published is not None else set())
    if active_no_go is not None:
        permitted_applied_ids.add(active_no_go.id)
    historical = [job for job in parents if job.id != excluded_id]
    no_go_children = {parent.id: _exact_no_go_apply_child(parent, related, jobs, fenced=True)
                      for parent in historical
                      if parent.input.get("phase") == "unapplied_reconciled"}
    permitted_applied_ids.update(child.id for child in no_go_children.values()
                                 if child is not None)
    if any(job.action in {"provider_keyed_edge_append_apply",
                          "provider_keyed_edge_append_host_proof"}
           and (job.id not in permitted_applied_ids or
                (job.input.get("parentJobId") != allowed_published_parent_id
                 and (active_no_go is None or active_no_go.id != job.id)
                 and no_go_children.get(job.input.get("parentJobId")) != job))
           for job in related):
        return None
    if not historical:
        return None
    linked_ids = {job.input.get("planJobId") for job in parents}
    if (len(linked_ids) != len(parents)
            or any(job.action == "provider_keyed_edge_append_plan"
                   and job.id not in linked_ids for job in related)):
        return None
    values = set()
    child_ids = set()
    core_ids = set()
    plan_ids = set()
    for parent in historical:
        child = jobs.get(parent.input.get("planJobId"))
        terminal = parent.events[-1] if parent.events else None
        if (parent.target_id != engagement_id or parent.status != "failed"
                or parent.input.get("engagementId") != engagement_id
                or type(parent.input.get("coreJobId")) is not str
                or not parent.input["coreJobId"]
                or type(parent.input.get("corePlanId")) is not str
                or not parent.input["corePlanId"]
                or parent.input.get("phase") != "unapplied_reconciled"
                or not parent.finished_at or terminal is None
                or terminal.message != "append plan reconciled without mutation"
                or type(terminal.data) is not dict
                or set(terminal.data) not in ({"stateSha256"},
                        {"stateSha256", "noGoApplyChildJournalSha256"})
                or child is None or child.id in child_ids
                or child.action != "provider_keyed_edge_append_plan"
                or child.status not in {"failed", "succeeded"}
                or child.target_id != engagement_id
                or child.input.get("parentJobId") != parent.id
                or child.input.get("coreJobId") != parent.input.get("coreJobId")
                or child.input.get("mutation") is not False):
            return None
        child_ids.add(child.id)
        if "noGoApplyChildJournalSha256" in terminal.data:
            no_go = no_go_children.get(parent.id)
            fenced = [event for event in parent.events
                      if event.message == "provider append Apply no-GO fenced"]
            if (no_go is None or len(fenced) != 1
                    or fenced[0].data != {
                        "stateSha256": terminal.data["stateSha256"],
                        "applyChildJournalSha256": job_event_digest(no_go.events),
                    } or terminal.data["noGoApplyChildJournalSha256"] !=
                    job_event_digest(no_go.events)):
                return None
        elif no_go_children.get(parent.id) is not None:
            return None
        core_ids.add(parent.input.get("coreJobId"))
        plan_ids.add(parent.input.get("corePlanId"))
        value = terminal.data["stateSha256"]
        if (type(value) is not str or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)):
            return None
        values.add(value)
    if (len(values) != 1 or len(core_ids) != 1 or len(plan_ids) != 1
            or expected_core_job_id is not None and core_ids != {expected_core_job_id}
            or expected_core_plan_id is not None and plan_ids != {expected_core_plan_id}):
        return None
    return next(iter(values))


def _require_unapplied_append_plan(
    engagement_id: str, parent_id: str, repository, *,
    expected_core_job_id: str | None = None,
) -> None:
    """Allow an exact four-node read only while append has no apply history."""
    from app.storage.job_repository import SqlAlchemyJobRepository

    jobs = repository or SqlAlchemyJobRepository()
    related = jobs.list_for_engagement(engagement_id)
    parents = [job for job in related if job.action == "provider_keyed_edge_append"]
    active = [job for job in parents if job.id == parent_id]
    active_input = getattr(active[0], "input", None) if len(active) == 1 else None
    no_go_child = (_exact_no_go_apply_child(active[0], related, jobs,
        fenced=active_input.get("phase") == "no_go_cleaning")
        if type(active_input) is dict else None)
    historical_sha = (_reconciled_unapplied_append_state_sha(
        engagement_id, jobs, allowed_active_parent_id=parent_id,
        expected_core_job_id=active_input.get("coreJobId")
        if type(active_input) is dict else None,
        expected_core_plan_id=active_input.get("corePlanId")
        if type(active_input) is dict else None)
        if len(parents) > 1 else None)
    allowed_apply_ids = {no_go_child.id} if no_go_child is not None else set()
    if historical_sha is not None:
        for historical in parents:
            if historical.id != parent_id and historical.input.get("phase") == "unapplied_reconciled":
                child = _exact_no_go_apply_child(historical, related, jobs, fenced=True)
                if child is not None:
                    allowed_apply_ids.add(child.id)
    if (len(active) != 1 or active[0].target_id != engagement_id
            or (active[0].status not in {"queued", "running"}
                and not (active[0].status == "failed"
                         and type(active_input) is dict
                         and active_input.get("phase") in {"attention", "no_go_cleaning"}
                         and no_go_child is not None))
            or expected_core_job_id is not None
            and (type(getattr(active[0], "input", None)) is not dict
                 or active[0].input.get("coreJobId") != expected_core_job_id)
            or any(job.action == "provider_keyed_edge_append_host_proof"
                   or job.action == "provider_keyed_edge_append_apply"
                   and job.id not in allowed_apply_ids for job in related)
            or (len(parents) > 1 and historical_sha is None)):
        raise ValueError("append may have mutated the published generation")


def _build_published_append_scope(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path | None, chains, job_repository, plan_repository,
    engagement_repository, allowed_teardown_parent_id: str | None,
) -> dict:
    """Build the ordinary complete provider scope from the audited five-node state.

    The mutation dispatcher is intentionally unchanged; this read path does
    not authorize a destroy command or bypass the initial-only apply reader.
    """
    from app.services.provider_keyed_append_source import audit_published_provider_keyed_append_source
    from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION
    from app.storage.job_repository import SqlAlchemyJobRepository
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository

    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    source = audit_published_provider_keyed_append_source(
        core_job_id, environment=environment, state_root=state_root,
        engagement_repository=engagement_repository, sketch_repository=chains,
        job_repository=jobs, plan_repository=plans,
    )
    if source.initial_source.engagement_id != engagement_id:
        raise ValueError("expanded engagement differs")
    rows = chains.list_for_engagement(engagement_id)
    if len(rows) != 2 or {row.chain_id for row in rows} != set(source.initial_source.chain_ids):
        raise ValueError("expanded chain set differs")
    workspace = Path(rows[0].terraform_working_directory)
    if workspace != Path(rows[1].terraform_working_directory):
        raise ValueError("expanded workspace differs")
    raw = (workspace / "terraform.tfstate").read_bytes()
    if hashlib.sha256(raw).hexdigest() != source.state_sha256:
        raise ValueError("expanded state changed")
    resources = _state_resources(json.loads(raw))
    if len(resources) != 9:
        raise ValueError("expanded managed inventory differs")
    resource_ids = {address: str(value.get("id")) for address, value in resources.items()}
    if any(value in {"", "None"} for value in resource_ids.values()):
        raise ValueError("expanded resource ID is missing")
    initial = jobs.get(source.initial_source.initial_job_id)
    core_plan = plans.get(source.initial_source.core_plan_id)
    manifest = next(event.data for event in initial.events
                    if event.message == "provider host identity binding intended")
    if (core_plan is None or core_plan.revision_id != manifest.get("revisionId")
            or manifest.get("sourceRevision") != _SOURCE_REVISION
            or not isinstance(manifest.get("providerConnectionId"), str)
            or not manifest["providerConnectionId"]):
        raise ValueError("expanded source metadata differs")
    def kind(address: str) -> str:
        if address.startswith("digitalocean_droplet."):
            return "droplet"
        if address == "digitalocean_firewall.firewall":
            return "firewall"
        if address == "digitalocean_ssh_key.key":
            return "ssh_key"
        if address in {"local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"}:
            return "local_file"
        raise ValueError("unexpected expanded managed address")
    scope = {
        "schema": "provider-keyed-v2", "provider": "digitalocean",
        "coreJobId": core_job_id, "corePlanId": source.initial_source.core_plan_id,
        "revisionId": core_plan.revision_id,
        "providerConnectionId": manifest["providerConnectionId"],
        "workspace": str(workspace), "sourceRevision": manifest["sourceRevision"],
        "selectorTag": resources["digitalocean_firewall.firewall"]["tags"][0],
        "stateSha256": source.state_sha256,
        "chainIds": list(source.initial_source.chain_ids),
        "chainFingerprints": {row.chain_id: sketch_chain_intent_fingerprint(row)
                              for row in sorted(rows, key=lambda row: row.chain_id)},
        "resources": [{"address": address, "id": resource_ids[address], "kind": kind(address)}
                      for address in sorted(resources)],
    }
    if audit_published_provider_keyed_append_source(
        core_job_id, environment=environment, state_root=state_root,
        engagement_repository=engagement_repository, sketch_repository=chains,
        job_repository=jobs, plan_repository=plans,
    ) != source:
        raise ValueError("expanded source changed during scope read")
    if allowed_teardown_parent_id is not None:
        from dataclasses import asdict
        from app.services.engagement_teardown import (
            _fingerprint, _parent_id, _validated_parent_boundary,
            ENGAGEMENT_TEARDOWN_ACTION,
        )
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

        parent = jobs.get(allowed_teardown_parent_id)
        if (parent is None or parent.id != _parent_id(core_job_id)
                or parent.action != ENGAGEMENT_TEARDOWN_ACTION
                or parent.status != "queued" or parent.started_at is not None
                or parent.finished_at is not None or parent.input.get("phase") != "queued"
                or parent.input.get("mutation") is not True
                or parent.target_id != engagement_id
                or parent.input.get("publishedSource") != json.loads(json.dumps(
                    asdict(source.initial_source), sort_keys=True))
                or parent.input.get("publishedAppendSource") != json.loads(json.dumps(
                    asdict(source), sort_keys=True))
                or _db_lease_lookup(engagement_id) != (
                    source.initial_source.core_plan_id, "provider_keyed_teardown_fence")):
            raise ValueError("expanded reserved source differs")
        parent_core, snapshot = _validated_parent_boundary(parent, jobs)
        if (parent_core.id != core_job_id
                or snapshot.get("providerScopes") != [scope]
                or snapshot.get("providerScopeSha256") != _fingerprint({
                    "providerScopes": [scope]})
                or snapshot.get("dnsCleanupManifest", {}).get("appendJournalSha256")
                != source.append_journal_sha256
                or jobs.get(parent.id) != parent
                or _db_lease_lookup(engagement_id) != (
                    source.initial_source.core_plan_id, "provider_keyed_teardown_fence")):
            raise ValueError("expanded reserved scope differs")
    return scope
