# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, state-backed mixed host identity intent before any host contact.

This is a read-only boundary. A later one-shot bootstrap worker must rebind
this intent and reserve its own host-command journal before SSH or Ansible.
It is not a strict host proof or publication authority.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable, Mapping

from app.domain import JobEvent
from app.services.core_ssh import active_core_connection_details
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as _apply_child_id, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_coordinator import (
    _core_matches, recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_partial_apply_source import (
    ProviderApplyClassification, _state,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease, reviewed_mixed_chain_rows
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


ACTION = "provider_keyed_mixed_initial_host_binding"


def _same_inserted_job(saved: StoredJobRun, proposed: StoredJobRun) -> bool:
    """Compare an exact insert across SQLAlchemy SQLite's UTC suffix round-trip."""
    try:
        saved_at = datetime.fromisoformat(saved.created_at)
        expected_at = datetime.fromisoformat(proposed.created_at)
        if saved_at.tzinfo is None:
            saved_at = saved_at.replace(tzinfo=timezone.utc)
        return (saved_at.astimezone(timezone.utc) == expected_at
                and replace(saved, created_at=proposed.created_at) == proposed)
    except (AttributeError, TypeError, ValueError):
        return False


class MixedInitialHostBindingAttention(ValueError):
    """Exact mixed host identities or the inert checkpoint require review."""


@dataclass(frozen=True)
class ProviderHostObservation:
    """Fresh classified state supplied by a GET-only, fenced provider reader."""

    classification: ProviderApplyClassification
    state_json: bytes


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _binding_child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-host-binding-{core_job_id.removeprefix('job-')}"


def recognize_mixed_initial_host_binding(child: StoredJobRun, parent: StoredJobRun) -> dict:
    """Authenticate inert intent, never host-contact authority.

    A future worker must freshly reprove the complete provider state and node
    identity before using any address here for SSH or Ansible.
    """
    try:
        manifest = child.events[0].data["manifest"]
        digest = _digest(manifest)
        if (child.id != _binding_child_id(parent.input["coreJobId"])
                or child.action != ACTION or child.status != "queued"
                or child.target != f"engagement:{parent.target_id}"
                or child.target_type != "engagement" or child.target_id != parent.target_id
                or child.requested_by != parent.requested_by
                or child.started_at is not None or child.finished_at is not None
                or child.artifact_refs != [] or len(child.events) != 1
                or child.events[0] != JobEvent(1, "info", "mixed host binding reserved",
                                              {"manifestSha256": digest, "manifest": manifest})
                or child.input != {
                    "engagementId": parent.target_id,
                    "coreJobId": parent.input["coreJobId"],
                    "corePlanId": parent.input["corePlanId"],
                    "handoffJournalSha256": job_event_digest(parent.events),
                    "manifestSha256": digest, "mutation": False,
                }
                or manifest["schema"] != "mixed-initial-host-binding-v1"
                or manifest["engagementId"] != parent.target_id
                or manifest["coreJobId"] != parent.input["coreJobId"]
                or manifest["corePlanId"] != parent.input["corePlanId"]
                or manifest["handoffJournalSha256"] != job_event_digest(parent.events)
                or manifest["orderedProviders"] != parent.input["orderedProviders"]
                or manifest["chainIds"] != parent.input["chainIds"]
                or len(manifest["nodes"]) != 4):
            raise ValueError("mixed binding journal differs")
        return manifest
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
        raise MixedInitialHostBindingAttention("mixed host binding journal differs") from exc


def _public_ip(value: object) -> str:
    if type(value) is not str:
        raise ValueError("state node has no public IPv4")
    address = ipaddress.IPv4Address(value)
    if str(address) != value or not address.is_global:
        raise ValueError("state node public IPv4 is unusable")
    return value


def _linode_public_ip(value: object) -> str:
    # The Linode Terraform provider serializes ipv4 as a list, even when the
    # instance has one public address. More than one is ambiguous for the
    # reviewed management route; do not silently choose the first.
    if type(value) is not list or len(value) != 1:
        raise ValueError("Linode state must have exactly one public IPv4")
    return _public_ip(value[0])


def build_mixed_initial_host_binding(
    parent: StoredJobRun, core: StoredJobRun, active_core_id: str,
    children: Mapping[str, StoredJobRun], chains: Mapping[str, object],
    observations: Mapping[str, ProviderHostObservation],
) -> dict:
    """Bind both reviewed middle/edge pairs to exact retained state IDs/IPs."""
    try:
        handoff = recognize_mixed_initial_host_proof_handoff(
            parent, core, active_core_id, children)
        seal = validate_mixed_initial_apply_seal(parent)
        order, chain_ids = seal["orderedProviders"], seal["chainIds"]
        if (set(observations) != set(order) or set(chains) != set(chain_ids)
                or len(chains) != 2 or len(observations) != 2
                or core.input.get("pendingSketchChainIds") != chain_ids):
            raise ValueError("mixed binding coverage differs")
        nodes = []
        provider_states = []
        seen_ips = set()
        for index, provider in enumerate(order):
            child = children[provider]
            terminal = recognize_mixed_initial_apply_terminal(child, parent, provider)
            proof = terminal["proof"]
            observation = observations[provider]
            classification = observation.classification
            raw = observation.state_json
            policy = seal["reviewedPolicy"][provider]
            chain = chains[chain_ids[index]]
            if (type(observation) is not ProviderHostObservation
                    or type(raw) is not bytes or classification.provider != provider
                    or classification.kind != "full"
                    or classification.state_sha256 != proof["stateSha256"]
                    or classification.lineage != proof["lineage"]
                    or classification.serial != proof["serial"]
                    or dict(classification.resource_ids) != proof["resourceIds"]
                    or hashlib.sha256(raw).hexdigest() != classification.state_sha256
                    or chain.engagement_id != parent.target_id
                    or chain.chain_id != chain_ids[index]
                    or chain.status != "pending" or chain.burned or chain.nodes
                    or chain.deploy_job_id or chain.teardown_job_id
                    or chain.middle_provider != provider or chain.edge_provider != provider
                    or chain.edge_count != 1 or chain.assigned_proxy != policy["proxy_name"]
                    or len(chain.edge_intents) != 1
                    or chain.edge_intents[0] != {
                        "id": "edge-01", "provider": provider,
                        "region": chain.edge_region, "size": chain.edge_size,
                    }
                    or core.input["pendingSketchChainFingerprints"][chain.chain_id]
                    != sketch_chain_intent_fingerprint(chain)):
                raise ValueError("mixed state or pending chain differs")
            state, actual, cloud = _state(provider, policy, raw)
            if (state["lineage"] != classification.lineage
                    or state["serial"] != classification.serial
                    or cloud != dict(classification.resource_ids)):
                raise ValueError("mixed retained state differs from fresh proof")
            expected = (
                ("middle", policy["middle_key"]),
                ("edge", policy["edge_key"]),
            )
            if set(policy["nodes"]) != {
                    f'{"linode_instance" if provider == "linode" else "digitalocean_droplet"}.{role}["{key}"]'
                    for role, key in expected}:
                raise ValueError("mixed node address set differs")
            for role, key in expected:
                kind = "linode_instance" if provider == "linode" else "digitalocean_droplet"
                address = f'{kind}.{role}["{key}"]'
                expected_node = policy["nodes"][address]
                attrs = actual[address]
                name = expected_node["label" if provider == "linode" else "name"]
                public_ip = (_linode_public_ip(attrs["ipv4"]) if provider == "linode"
                             else _public_ip(attrs["ipv4_address"]))
                if (public_ip in seen_ips
                        or attrs["label" if provider == "linode" else "name"] != name
                        or attrs["region"] != expected_node["region"]
                        or (role == "middle" and chain.middle_region != expected_node["region"])):
                    raise ValueError("mixed node identity differs")
                if role == "edge" and chain.edge_region != expected_node["region"]:
                    raise ValueError("mixed edge region differs")
                if expected_node["node_type" if provider == "linode" else "size"] != (
                        chain.middle_size if role == "middle" else chain.edge_size):
                    raise ValueError("mixed node size differs")
                seen_ips.add(public_ip)
                nodes.append({
                    "chainId": chain.chain_id, "provider": provider, "role": role,
                    "hostname": name, "terraformAddress": address,
                    "providerInstanceId": cloud[address], "publicIp": public_ip,
                    "region": expected_node["region"], "assignedProxy": chain.assigned_proxy,
                })
            provider_states.append({
                "provider": provider, "stateSha256": classification.state_sha256,
                "lineage": classification.lineage, "serial": classification.serial,
                "terminalJournalSha256": terminal["terminalJournalSha256"],
            })
        if len(nodes) != 4 or len({row["hostname"] for row in nodes}) != 4:
            raise ValueError("mixed host identity is incomplete")
        return {
            "schema": "mixed-initial-host-binding-v1",
            "engagementId": parent.target_id, "coreJobId": core.id,
            "corePlanId": parent.input["corePlanId"],
            "handoffJournalSha256": job_event_digest(parent.events),
            "orderedProviders": list(order), "chainIds": list(chain_ids),
            "chainFingerprints": [core.input["pendingSketchChainFingerprints"][key]
                                  for key in chain_ids],
            "providerStates": provider_states, "nodes": nodes,
        }
    except (KeyError, TypeError, ValueError, AttributeError, ipaddress.AddressValueError) as exc:
        raise MixedInitialHostBindingAttention(
            "mixed host binding differs from reviewed provider states") from exc


def reserve_mixed_initial_host_binding(
    engagement_id: str, core_job_id: str, *, environment: str,
    fresh_observer: Callable[[StoredJobRun, str, Callable[[], str]], ProviderHostObservation],
    job_repository=None, sketch_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Reserve one inert binding record; no SSH, Ansible, or publication."""
    if environment != "devtest" or not engagement_id or not core_job_id:
        raise MixedInitialHostBindingAttention("mixed host binding is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        parent = jobs.get(_parent_id(core_job_id))
        core = jobs.get(core_job_id)
        if (parent is None or core is None or parent.target_id != engagement_id
                or parent.input.get("phase") != "awaiting_mixed_host_proof"):
            raise ValueError("mixed handoff is unavailable")
        seal = validate_mixed_initial_apply_seal(parent)
        order = seal["orderedProviders"]
        children = {provider: jobs.get(_apply_child_id(core_job_id, provider)) for provider in order}
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        if not _core_matches(parent, core, active_id):
            raise ValueError("active core differs")
        recognize_mixed_initial_host_proof_handoff(parent, core, active_id, children)
        _require_lease(lookup, engagement_id, parent.input["corePlanId"])
        child_id = _binding_child_id(core_job_id)
        existing = jobs.get(child_id)
        if existing is not None:
            recognize_mixed_initial_host_binding(existing, parent)
            return existing
        generation = _digest({"parent": job_event_digest(parent.events),
                              "children": [job_event_digest(children[p].events) for p in order]})

        def fence() -> str:
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            active, _ = active_core_connection_details(jobs, engagement_id)
            if (active != core.id or jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or any(jobs.get(children[p].id) != children[p] for p in order)
                    or jobs.get(child_id) is not None):
                raise ValueError("mixed host source changed during fresh observation")
            return generation

        observations = {}
        for provider in order:
            fence()
            observations[provider] = fresh_observer(parent, provider, fence)
            fence()
        durable = sketches.list_for_engagement(engagement_id)
        chains = {chain.chain_id: chain for chain in reviewed_mixed_chain_rows(
            durable, seal["chainIds"], engagement_id)}
        manifest = build_mixed_initial_host_binding(
            parent, core, core.id, children, chains, observations)
        fence()
        if sketches.list_for_engagement(engagement_id) != durable:
            raise ValueError("pending mixed chains changed")
        manifest_sha = _digest(manifest)
        child = StoredJobRun(
            id=child_id, action=ACTION, status="queued",
            target=f"engagement:{engagement_id}", target_type="engagement",
            target_id=engagement_id, requested_by=parent.requested_by,
            input={"engagementId": engagement_id, "coreJobId": core_job_id,
                   "corePlanId": parent.input["corePlanId"],
                   "handoffJournalSha256": job_event_digest(parent.events),
                   "manifestSha256": manifest_sha, "mutation": False},
            artifact_refs=[], created_at=datetime.now(timezone.utc).isoformat(),
            started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "mixed host binding reserved",
                             {"manifestSha256": manifest_sha, "manifest": manifest})],
        )
        saved = jobs.save_if_absent(child)
        if not _same_inserted_job(saved, child):
            raise ValueError("mixed host binding reservation raced")
        recognize_mixed_initial_host_binding(saved, parent)
        return saved
    except Exception as exc:
        raise MixedInitialHostBindingAttention(
            "mixed host binding needs exact reconciliation") from exc
