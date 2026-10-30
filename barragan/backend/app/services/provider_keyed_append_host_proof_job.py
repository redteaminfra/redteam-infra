# Copyright (c) 2026, Oracle and/or its affiliates.
"""Prove only the new DigitalOcean edge, then publish one expanded chain.

The deterministic child is a one-shot host-contact fence. Retained middle and
old edges are route hops only; Ansible's `--limit` selects the new edge alone.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.services.bootstrap_command_evidence import bootstrap_command_timing, without_bootstrap_timing
from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.managed_host_image_continuity import managed_host_image_profile_named
from app.services.provider_keyed_append_source import _decode_initial_source
from app.services.provider_keyed_append_apply_job import _completed_apply_child_receipt
from app.services.provider_keyed_append_host_collection import verify_append_edge_host_collection
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentIntent, ExpectedDigitalOceanNode,
    reconcile_digitalocean_initial_attachment,
)
from app.services.provider_keyed_gated_runner import GatedCommandTimeoutError, UnreapedGatedCommandError, run_gated_command
from app.services.provider_keyed_host_binding import _core_known_hosts, _digest_json
from app.services.provider_keyed_host_identity_probe import collect_digitalocean_edge_host_evidence
from app.services.provider_keyed_host_policy import Edge, Middle, Topology, render_sketch_host_policy
from app.services.provider_keyed_host_policy_interpreter import interpret_digitalocean_host_policy
from app.services.provider_keyed_host_surface_interpreter import (
    _key_digest, interpret_digitalocean_host_surface,
)
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256, _verify_audited_workspace
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot, _hash_file
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_bootstrap import SketchBootstrapSpec
from app.services.sketch_bootstrap_apply import (
    _core_hosts, _sketch_nodes, apply_sketch_bootstrap,
    BOOTSTRAP_COMMAND_TIMEOUT_SECONDS, BOOTSTRAP_TIMEOUT_MESSAGE, SketchBootstrapTimeoutError,
    require_pinned_sketch_ansible_source,
)
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.services.sketch_transport_ssh_keys import retrieve_sketch_transport_ssh_key
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_OWNER = f"provider-keyed-append-host-proof-{uuid4().hex}"
_SECONDS = 3600


class ProviderKeyedAppendHostProofError(ValueError):
    """The expanded generation cannot be published without reconciliation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(now: str) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=_SECONDS)).isoformat()


def _child_id(parent_id: str) -> str:
    return f"job-provider-keyed-append-host-proof-{parent_id.removeprefix('job-provider-keyed-append-')}"


def _sha(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _host_evidence_path(root: Path, parent_id: str) -> Path:
    return root / f".barragan-append-host-evidence-{hashlib.sha256(parent_id.encode()).hexdigest()[:20]}.json"


def _proof_context(jobs, engagement_id: str, selected):
    """Derive expected edge SSH policy and retained keys from active core/row."""
    middle = selected.nodes[0]
    policy = {"sketch_firewall_v2_enabled": True,
              "sketch_firewall_v2_ssh_sources": [f"{middle['publicIp']}/32"],
              "sketch_firewall_v2_rules": []}
    admin = retrieve_sketch_ssh_key(engagement_id)
    transport = retrieve_sketch_transport_ssh_key(engagement_id)
    if admin is None or transport is None:
        raise ValueError("retained sketch public identities are unavailable")
    return middle["publicIp"], policy, _key_digest(admin.public_key.strip() + "\n"), \
        _key_digest(transport.public_key.strip() + "\n")


def _completed_child_receipt(child, parent, apply_child, manifest_sha: str,
                             terminal_data: dict, evidence_path: Path,
                             *, selected, jobs) -> str:
    """Accept only the deterministic new-edge child, never rerun its commands."""
    if (child is None or child.status != "succeeded" or not child.finished_at
            or child.action != "provider_keyed_edge_append_host_proof"
            or child.input.get("parentJobId") != parent.id
            or child.input.get("applyJobId") != apply_child.id
            or child.input.get("mutation") is not False
            or not child.events or child.events[0].message != "strict append host proof reserved"
            or child.events[0].data != {"manifestSha256": manifest_sha}
            or child.events[-1].message != "strict append host proof completed"
            or set(child.events[-1].data) != set(terminal_data) | {
                "hostEvidenceSha256", "hostEvidencePath"}
            or any(child.events[-1].data[key] != value
                   for key, value in terminal_data.items())
            or not isinstance(child.events[-1].data["hostEvidenceSha256"], str)
            or len(child.events[-1].data["hostEvidenceSha256"]) != 64
            or child.events[-1].data["hostEvidencePath"] != str(evidence_path)):
        raise ValueError("strict append child completion differs")
    names = [event.message for event in child.events]
    milestones = (
        "strict append host proof reserved",
        "strict append host proof started",
        "provider append edge contact intended",
        "provider append bootstrap command intent fenced",
        "provider append bootstrap command started before GO",
        "provider append bootstrap command result fenced",
        "provider append root bootstrap start fenced",
        "provider append bootstrap command intent fenced",
        "provider append bootstrap command started before GO",
        "provider append bootstrap command result fenced",
        "provider append bootstrap command intent fenced",
        "provider append bootstrap command started before GO",
        "provider append bootstrap command result fenced",
        "provider append bootstrap command intent fenced",
        "provider append bootstrap command started before GO",
        "provider append bootstrap command result fenced",
        "provider append new edge bootstrap completed",
        "strict append host proof scratch intended",
        *(("strict append host proof command intended",
           "strict append host proof command started before GO",
           "strict append host proof command result fenced") * 4),
        "strict append host proof capture completed",
        "provider append expanded membership verified",
        "strict append host proof completed",
    )
    if (names != list(milestones)
            or [event.sequence for event in child.events]
               != list(range(1, len(child.events) + 1))
            or any(event.level != "info" for event in child.events)):
        raise ValueError("append host-proof milestone is absent or out of order")
    milestone_events = child.events[1:]
    new_address = terminal_data["newEdgeAddress"]
    new_id = terminal_data["newEdgeProviderId"]
    if (milestone_events[0].data != {"manifestSha256": manifest_sha}
            or milestone_events[1].data != {
                "newEdgeAddress": new_address, "newEdgeProviderId": new_id}
            or milestone_events[5].data != {
                "phase": "root_bootstrap", "sequence": 2,
                "newEdgeAddress": new_address}
            or milestone_events[15].data != {
                "newEdgeAddress": new_address, "newEdgeProviderId": new_id}
            or milestone_events[16].data.get("newEdgeAddress") != new_address
            or milestone_events[16].data.get("newEdgeProviderId") != new_id
            or not isinstance(milestone_events[16].data.get("scratchPath"), str)
            or not milestone_events[16].data["scratchPath"]):
        raise ValueError("append edge contact or bootstrap milestones differ")
    for phase, entries in (
        ("root_readiness", milestone_events[2:5]),
        ("root_bootstrap", milestone_events[6:9]),
        ("user_readiness", milestone_events[9:12]),
        ("transport_install", milestone_events[12:15]),
    ):
        intent, started, result = entries
        without_bootstrap_timing(result.data, success=True)
        invocation = intent.data.get("invocationId")
        sequence = ("root_readiness", "root_bootstrap", "user_readiness",
                    "transport_install").index(phase) + 1
        expected_common = {"phase": phase, "sequence": sequence,
                           "newEdgeAddress": new_address,
                           "invocationId": invocation}
        if (not invocation or intent.data.get("argvSha256") is None
                or re.fullmatch(r"[0-9a-f]{64}", intent.data["argvSha256"]) is None
                or intent.data != {**expected_common,
                                   "argvSha256": intent.data["argvSha256"]}
                or started.data.get("phase") != phase
                or result.data.get("phase") != phase
                or started.data.get("invocationId") != invocation
                or result.data.get("invocationId") != invocation
                or any(started.data.get(key) != value
                       for key, value in expected_common.items())
                or any(result.data.get(key) != value
                       for key, value in expected_common.items())
                or not all(started.data.get(key) for key in (
                    "bootId", "pid", "pgid", "startTicks"))
                or result.data.get("returnCode") != 0):
            raise ValueError("append edge-only bootstrap command differs")
    host_invocations = []
    for offset in range(17, 29, 3):
        host_intent, host_started, host_result = milestone_events[offset:offset + 3]
        host_common = {"newEdgeAddress": new_address,
                       "newEdgeProviderId": new_id,
                       "invocationId": host_intent.data.get("invocationId")}
        if (not host_common["invocationId"]
                or re.fullmatch(r"[0-9a-f]{64}",
                                str(host_intent.data.get("argvSha256"))) is None
                or host_intent.data != {**host_common,
                                        "argvSha256": host_intent.data["argvSha256"]}
                or any(host_started.data.get(key) != value
                       for key, value in host_common.items())
                or any(host_result.data.get(key) != value
                       for key, value in host_common.items())
                or not all(host_started.data.get(key) for key in (
                    "bootId", "pid", "pgid", "startTicks"))
                or host_result.data.get("returnCode") != 0):
            raise ValueError("append host probe command differs")
        host_invocations.append(host_common["invocationId"])
    if (len(set(host_invocations)) != 4
            or milestone_events[29].data != {
                "newEdgeAddress": terminal_data["newEdgeAddress"],
                "newEdgeProviderId": terminal_data["newEdgeProviderId"],
                "hostEvidenceSha256": child.events[-1].data["hostEvidenceSha256"],
                "hostEvidencePath": str(evidence_path),
            }
            or milestone_events[30].data.get("stateSha256") != terminal_data["stateSha256"]
            or not isinstance(milestone_events[30].data.get("providerIds"), list)
            or len(milestone_events[30].data["providerIds"]) != 5
            or len(set(milestone_events[30].data["providerIds"])) != 5
            or new_id not in milestone_events[30].data["providerIds"]):
        raise ValueError("append raw host or final provider proof differs")
    info = evidence_path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & 0o077
            or info.st_size <= 0 or info.st_size > 16 * 1024 * 1024
            or hashlib.sha256(evidence_path.read_bytes()).hexdigest() !=
               child.events[-1].data["hostEvidenceSha256"]):
        raise ValueError("append raw host artifact differs")
    predecessor, policy, admin_sha, transport_sha = _proof_context(
        jobs, parent.target_id, selected)
    collection = verify_append_edge_host_collection(
        evidence_path.read_bytes(), manifest_sha256=manifest_sha,
        chain_id=selected.chain_id,
        terraform_address=terminal_data["newEdgeAddress"],
        provider_instance_id=terminal_data["newEdgeProviderId"],
        public_ipv4=selected.nodes[2]["publicIp"],
        region=selected.nodes[2]["region"],
        hostname=selected.nodes[2]["hostname"], predecessor_ipv4=predecessor,
        expected_policy=policy, admin_key_sha256=admin_sha,
        transport_key_sha256=transport_sha)
    if host_invocations != [
        collection.identity.invocation_id,
        collection.firewall_before.invocation_id,
        collection.surface.invocation_id,
        collection.firewall_after.invocation_id,
    ]:
        raise ValueError("append host command/raw invocation binding differs")
    return job_event_digest(child.events)


def publish_reviewed_digitalocean_edge_append_host_proof(
    parent_id: str, *, environment: str = "devtest", state_root: Path,
    bootstrap_env, job_repository=None, plan_repository=None, sketch_repository=None,
    engagement_repository=None, credential_repository=None,
    lease_lookup=None, attachment_reconciler=reconcile_digitalocean_initial_attachment,
    bootstrap_helper=apply_sketch_bootstrap,
    edge_collector=collect_digitalocean_edge_host_evidence,
    gated_command_runner=run_gated_command,
) -> StoredJobRun:
    """Use retained Apply receipt and one new-edge command journal for publication."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    if (environment != "devtest" or parent is None or parent.status != "running"
            or parent.action != "provider_keyed_edge_append"
            or parent.input.get("phase") not in {
                "awaiting_host_proof", "host_proof_reserved", "awaiting_publication"}
            or parent.input.get("engagementId") != parent.target_id
            or (parent.input.get("phase") == "awaiting_host_proof"
                and jobs.get(_child_id(parent_id)) is not None)
            or (parent.input.get("phase") != "awaiting_host_proof"
                and parent.input.get("hostProofJobId") != _child_id(parent_id))
            or lookup(parent.target_id) != (parent.input.get("corePlanId"),
                                             "provider_keyed_edge_append")
            or not isinstance(bootstrap_env, dict)
            or type(bootstrap_env.get(TEMPLATE_ROOT_ENV)) is not str):
        raise ProviderKeyedAppendHostProofError("append host proof authority differs")
    try:
        plan_child = jobs.get(parent.input["planJobId"])
        apply_child = jobs.get(parent.input["applyJobId"])
        if (plan_child is None or apply_child is None
                or plan_child.action != "provider_keyed_edge_append_plan"
                or apply_child.action != "provider_keyed_edge_append_apply"
                or plan_child.status != "succeeded" or apply_child.status != "succeeded"
                or parent.input.get("planJournalSha256") != job_event_digest(plan_child.events)
                or parent.input.get("applyJournalSha256") != job_event_digest(apply_child.events)
                or apply_child.events[-1].message != "provider append apply completed"
                or set(apply_child.events[-1].data) != {
                    "stateSha256", "newEdgeAddress", "newEdgeProviderId",
                    "newEdgePublicIp", "providerMembershipVerified",
                } or apply_child.events[-1].data["providerMembershipVerified"] is not True
                or (parent.input["phase"] == "awaiting_host_proof" and (
                    parent.events[-1].message !=
                       "provider append apply completed; strict host proof pending"
                    or parent.events[-1].data != {
                        "stateSha256": apply_child.events[-1].data["stateSha256"],
                        "applyJournalSha256": job_event_digest(apply_child.events),
                    }))):
            raise ValueError("append Apply child receipt differs")
        receipt = plan_child.events[-1].data
        source = _decode_initial_source(receipt["initialSource"])
        if (receipt["initialSourceSha256"] != _fingerprint(asdict(source))
                or parent.input["initialSourceSha256"] != _fingerprint(asdict(source))
                or source.engagement_id != parent.target_id
                or source.core_job_id != parent.input["coreJobId"]):
            raise ValueError("initial publication history differs")
        initial = jobs.get(source.initial_job_id)
        core = jobs.get(source.core_job_id)
        if (initial is None or core is None
                or job_event_digest(initial.events) != source.initial_journal_sha256
                or job_event_digest(core.events) != source.core_journal_sha256):
            raise ValueError("initial child history differs")
        all_rows = chains.list_for_engagement(parent.target_id)
        rows = [row for row in all_rows if not _inert_aborted_intent(row, parent.target_id)]
        if (len(rows) != 2 or {row.chain_id for row in rows} != set(source.chain_ids)):
            raise ValueError("retained chain rows differ")
        _completed_apply_child_receipt(apply_child, parent,
            job_event_digest(plan_child.events), receipt,
            {str(node["providerInstanceId"])
             for row in rows for node in row.nodes})
        selected = next(row for row in rows if row.chain_id == parent.input["chainId"])
        other = next(row for row in rows if row.chain_id != selected.chain_id)
        if (receipt["selectedChain"] != selected.to_dict()
                or _fingerprint({row.chain_id: row.to_dict() for row in rows}) !=
                   source.chain_projection_sha256):
            raise ValueError("retained selected and sibling identities differ")
        root = Path(selected.terraform_working_directory)
        workspace = ProviderKeyedWorkspace(
            root, root / "terraform.tfstate", root / ".terraform-data", SCHEMA,
            "digitalocean", receipt["credentialRecordId"], root.name,
            _SOURCE_REVISION, _SOURCE_SHA256,
        )
        if (not root.is_absolute() or state_root not in root.parents
                or root != Path(other.terraform_working_directory)
                or _hash_file(workspace.state_path) != apply_child.events[-1].data["stateSha256"]
                or json.loads((root / ".barragan-apply-phase.json").read_text()) !=
                   {"schema": SCHEMA, "phase": "applied"}):
            raise ValueError("expanded workspace differs")
        _verify_audited_workspace(workspace)
        after_state = _state_resources(json.loads(workspace.state_path.read_bytes()))
        new_address = apply_child.events[-1].data["newEdgeAddress"]
        new_id = apply_child.events[-1].data["newEdgeProviderId"]
        new_ip = apply_child.events[-1].data["newEdgePublicIp"]
        old_nodes = {node["terraformAddress"]: node for row in rows for node in row.nodes}
        if (len(old_nodes) != 4 or len(after_state) != 9
                or set(after_state) != set(old_nodes) | {new_address} | {
                    "digitalocean_firewall.firewall", "digitalocean_ssh_key.key",
                    "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]",
                } or new_address in old_nodes or new_address != receipt["newEdgeAddress"]
                or str(after_state[new_address]["id"]) != new_id
                or after_state[new_address]["ipv4_address"] != new_ip
                or any(str(after_state[address].get("id")) != node["providerInstanceId"]
                       or after_state[address].get("ipv4_address") != node["publicIp"]
                       for address, node in old_nodes.items())
                or any(str(after_state[address].get("id")) != value
                       for address, value in receipt["retainedSharedIds"].items())):
            raise ValueError("five-node state or retained IDs differ")
        proposed = replace(selected, edge_count=2, edge_intents=[*selected.edge_intents, {
            "id": "edge-02", "provider": "digitalocean",
            "region": parent.input["region"], "size": parent.input["size"],
        }])
        core_plan = plans.get(parent.input["corePlanId"])
        profile = managed_host_image_profile_named(core_plan.evidence["managedHostImageProfile"])
        intent = compile_fresh_digitalocean_persisted_intent(
            engagements.get(parent.target_id),
            [proposed if row.chain_id == selected.chain_id else row for row in rows],
            core, core_plan, profile, environment=environment,
            provider_state_exists=True, mode="append_plan", reviewed_initial_chains=rows,
        )
        if (set(intent.nodes) != set(old_nodes) | {new_address}
                or after_state[new_address].get("name") != intent.nodes[new_address].name
                or after_state[new_address].get("region") != intent.nodes[new_address].region
                or after_state[new_address].get("size") != intent.nodes[new_address].size
                or after_state[new_address].get("image") != intent.nodes[new_address].image
                or after_state[new_address].get("tags") != [intent.selector_tag]):
            raise ValueError("new edge differs from reviewed intent")
        digest, updated, _ = _credential_snapshot(receipt["credentialRecordId"], credentials)
        if (digest, updated) != (receipt["credentialSecretSha256"],
                                 receipt["credentialUpdatedAt"]):
            raise ValueError("provider credential changed")
        attachment = DigitalOceanAttachmentIntent(
            apply_child.events[-1].data["stateSha256"],
            str(after_state["digitalocean_firewall.firewall"]["id"]),
            intent.firewall.name, intent.selector_tag, intent.firewall.trusted_ssh_cidrs,
            tuple(ExpectedDigitalOceanNode(
                address, str(after_state[address]["id"]), value.name, value.region,
                after_state[address]["ipv4_address"],
            ) for address, value in sorted(intent.nodes.items())),
            receipt["credentialRecordId"], digest, updated,
        )
        provider = attachment_reconciler(
            workspace, attachment, environment=environment,
            deployment_target="barragan-testing", credential_repository=credentials,
            max_attempts=12, poll_interval_seconds=10.0,
        )
        if (not provider.provider_membership_verified
                or provider.state_sha256 != attachment.state_sha256):
            raise ValueError("expanded provider membership differs")
        original_middle, original_edge = selected.nodes
        new_node = {
            "chainId": selected.chain_id, "role": "edge", "provider": "digitalocean",
            "hostname": intent.nodes[new_address].name, "terraformAddress": new_address,
            "providerInstanceId": new_id, "region": intent.nodes[new_address].region,
            "publicIp": new_ip, "assignedProxy": selected.assigned_proxy,
            "proxy": selected.assigned_proxy, "status": "deployed",
            "componentId": "edge-02", "edgeId": "edge-02", "edgeIndex": "2",
            "edgeCount": "2",
        }
        expanded = replace(proposed, nodes=[original_middle,
            {**original_edge, "edgeCount": "2"}, new_node], updated_at=_now())
        middle_ip = original_middle["publicIp"]
        selected_policy = render_sketch_host_policy(Topology(
            proxy_egress_ips={selected.assigned_proxy: intent.proxy_egress_ips[selected.assigned_proxy]},
            middles={original_middle["hostname"]: Middle(middle_ip, selected.assigned_proxy)},
            edges={node["hostname"]: Edge(node["publicIp"], original_middle["hostname"])
                   for node in expanded.nodes[1:]},
        ), ())
        homebase, proxy = _core_hosts(jobs, parent.target_id, selected.assigned_proxy,
                                      require_proxy_public_alias=True)
        middle, edges = _sketch_nodes(expanded, require_exact_roles=True)
        sketch_path = root / ".barragan-sketch-known-hosts"
        core_path, core_sha = _core_known_hosts(core)
        if (not sketch_path.is_file() or sketch_path.is_symlink()
                or not Path(core_path).is_file()):
            raise ValueError("retained route trust files differ")
        manifest = {
            "schema": SCHEMA, "engagementId": parent.target_id,
            "coreJobId": core.id, "corePlanId": parent.input["corePlanId"],
            "stateSha256": attachment.state_sha256,
            "initialSourceSha256": _fingerprint(asdict(source)),
            "newEdgeAddress": new_address, "newEdgeProviderId": new_id,
            "nodes": sorted(({
                "chainId": node["chainId"], "role": node["role"],
                "providerInstanceId": node["providerInstanceId"],
                "terraformAddress": node["terraformAddress"],
                "name": node["hostname"], "publicIp": node["publicIp"],
                "region": node["region"],
            } for row in (expanded, other) for node in row.nodes),
                key=lambda node: node["terraformAddress"]),
            "hostPolicies": [{"chainId": selected.chain_id,
                              "proxyEgressIp": proxy.host_key_alias,
                              "hosts": selected_policy}],
            "coreKnownHostsPath": core_path, "coreKnownHostsSha256": core_sha,
            "sketchKnownHostsPath": str(sketch_path),
        }
        if (len(manifest["nodes"]) != 5 or proxy.host_key_alias !=
                intent.proxy_egress_ips[selected.assigned_proxy]):
            raise ValueError("new edge route manifest differs")
        source_root = Path(bootstrap_env[TEMPLATE_ROOT_ENV])
        require_pinned_sketch_ansible_source(
            env=bootstrap_env, required_source_root=source_root,
            required_source_revision=workspace.source_revision,
        )
    except Exception:
        raise ProviderKeyedAppendHostProofError("append host proof preflight stopped") from None

    token = uuid4().hex
    claimed_at = _now()
    current_parent = jobs.claim_lease(
        parent.id, owner=_OWNER, token=token, claimed_at=claimed_at,
        expires_at=_later(claimed_at), eligible_statuses={"running"},
        eligible_phases={parent.input["phase"]},
    )
    if current_parent is None or (parent.input["phase"] == "awaiting_host_proof"
                                  and jobs.get(_child_id(parent.id)) is not None):
        raise ProviderKeyedAppendHostProofError("append host proof claim changed")
    child = None
    unreaped = False
    try:
        child = jobs.get(_child_id(parent.id))
        reserved_only = (parent.input["phase"] == "host_proof_reserved"
            and (child is None or (
                child.action == "provider_keyed_edge_append_host_proof"
                and child.status == "queued" and child.started_at is None
                and child.finished_at is None
                and child.target == parent.target
                and child.target_id == parent.target_id
                and child.requested_by == parent.input.get("applyRequestedBy", parent.requested_by)
                and child.input == {
                    "engagementId": parent.target_id, "parentJobId": parent.id,
                    "applyJobId": apply_child.id, "mutation": False}
                and len(child.events) == 1
                and child.events[0].sequence == 1
                and child.events[0].level == "info"
                and child.events[0].message == "strict append host proof reserved"
                and child.events[0].data == {
                    "manifestSha256": _digest_json(manifest)})))
        if reserved_only:
            if (parent.events[-1].message != "strict append host proof reserved"
                    or parent.events[-1].data != {
                        "manifestSha256": _digest_json(manifest)}):
                raise ValueError("unstarted append host proof reservation differs")
        elif parent.input["phase"] != "awaiting_host_proof":
            terminal_data = {
                "newEdgeAddress": new_address, "newEdgeProviderId": new_id,
                "stateSha256": attachment.state_sha256,
            }
            child_sha = _completed_child_receipt(
                child, parent, apply_child, _digest_json(manifest), terminal_data,
                _host_evidence_path(root, parent.id), selected=expanded, jobs=jobs)
            expected_seal = {
                "planJournalSha256": job_event_digest(plan_child.events),
                "applyJournalSha256": job_event_digest(apply_child.events),
                "hostProofJournalSha256": child_sha,
            }
            if parent.input["phase"] == "host_proof_reserved":
                if (parent.events[-1].message != "strict append host proof reserved"
                        or parent.events[-1].data != {
                            "manifestSha256": _digest_json(manifest)}):
                    raise ValueError("append host proof reservation differs")
                current_parent = jobs.save_if_leased(replace(
                    current_parent,
                    input={**current_parent.input, "phase": "awaiting_publication"},
                    events=[*current_parent.events, JobEvent(len(current_parent.events) + 1,
                        "info", "strict append host proof completed", expected_seal)]),
                    owner=_OWNER, token=token)
                if current_parent is None:
                    raise ValueError("append publication seal changed")
            elif (parent.events[-1].message != "strict append host proof completed"
                  or parent.events[-1].data != expected_seal):
                raise ValueError("append publication journal differs")
            chains.publish_provider_keyed_edge_append(
                parent=current_parent, before=selected, after=expanded, other=other,
                initial_source=source, state_sha256=attachment.state_sha256,
                expected_event_digest=job_event_digest(current_parent.events),
                claim_owner=_OWNER, claim_token=token, finished_at=_now(),
            )
            return jobs.get(parent.id)
        if parent.input["phase"] == "awaiting_host_proof":
            current_parent = jobs.save_if_leased(replace(
                current_parent,
                input={**current_parent.input, "phase": "host_proof_reserved",
                       "hostProofJobId": _child_id(parent.id)},
                events=[*current_parent.events, JobEvent(len(current_parent.events) + 1,
                    "info", "strict append host proof reserved", {
                        "manifestSha256": _digest_json(manifest)})]),
                owner=_OWNER, token=token)
            if current_parent is None:
                raise ValueError("append host-proof parent reservation lost")
        if child is None:
            child = StoredJobRun(
                _child_id(parent.id), "provider_keyed_edge_append_host_proof", "queued",
                parent.target, "engagement", parent.target_id,
                parent.input.get("applyRequestedBy", parent.requested_by),
                {"engagementId": parent.target_id, "parentJobId": parent.id,
                 "applyJobId": apply_child.id, "mutation": False}, [],
                _now(), None, None,
                [JobEvent(1, "info", "strict append host proof reserved", {
                    "manifestSha256": _digest_json(manifest)})],
            )
            inserted = jobs.save_if_absent(child)
            if (inserted is None
                    or datetime.fromisoformat(inserted.created_at).replace(
                        tzinfo=timezone.utc) != datetime.fromisoformat(child.created_at)
                    or replace(inserted, created_at=child.created_at) != child):
                raise ValueError("append host-proof child already exists")
            child = inserted
        child = jobs.claim_lease(child.id, owner=_OWNER, token=token,
                                 claimed_at=_now(), expires_at=_later(_now()),
                                 eligible_statuses={"queued"})
        if child is None:
            raise ValueError("append host-proof child claim changed")

        def fence():
            nonlocal current_parent, child
            if (lookup(parent.target_id) != (parent.input["corePlanId"], "provider_keyed_edge_append")
                    or chains.list_for_engagement(parent.target_id) != all_rows
                    or _hash_file(workspace.state_path) != attachment.state_sha256):
                raise ValueError("append host-proof source changed")
            now = _now()
            current_parent = jobs.renew_lease(current_parent.id, owner=_OWNER, token=token,
                                               heartbeat_at=now, expires_at=_later(now))
            if child.status in {"queued", "running"}:
                child = jobs.renew_lease(child.id, owner=_OWNER, token=token,
                                         heartbeat_at=now, expires_at=_later(now))
            if current_parent is None or child is None:
                raise ValueError("append host-proof claim changed")

        def record(message, data, *, terminal=None):
            nonlocal child
            fence()
            child = chains.append_provider_keyed_host_proof_event(
                child, JobEvent(len(child.events) + 1,
                    "error" if terminal == "failed" else "info", message, data),
                owner=_OWNER, token=token, started_at=child.started_at or _now(),
                terminal_status=terminal,
            )
            if child is None:
                raise ValueError("append host-proof journal changed")

        record("strict append host proof started", {"manifestSha256": _digest_json(manifest)})
        scratch = root / f".barragan-append-bootstrap-{uuid4().hex}"
        if scratch.exists() or scratch.is_symlink():
            raise ValueError("append bootstrap scratch already exists")
        contacted = False
        root_started = False
        command_sequence = 0

        def bootstrap_run(command, cwd, env):
            nonlocal contacted, root_started, command_sequence, unreaped
            if (cwd != scratch or command[-2:] != ["--limit", new_node["hostname"]]):
                raise ValueError("bootstrap command does not target only new edge")
            if any(str(part).endswith("wait_for_sketch_readiness.yml") for part in command):
                phase = "root_readiness"
            elif any(str(part).endswith("upstream-sketch-playbook.compat.yml") for part in command):
                phase = "root_bootstrap"
                if root_started:
                    raise ValueError("new-edge root bootstrap cannot replay")
                root_started = True
            elif any(str(part).endswith("wait_for_sketch_user_readiness.yml") for part in command):
                phase = "user_readiness"
            elif any(str(part).endswith("install_sketch_transport.yml") for part in command):
                phase = "transport_install"
            else:
                raise ValueError("new-edge bootstrap phase differs")
            if phase != "root_readiness" and not contacted:
                raise ValueError("new-edge first contact is unjournaled")
            if not contacted:
                record("provider append edge contact intended", {
                    "newEdgeAddress": new_address, "newEdgeProviderId": new_id})
                contacted = True
            command_sequence += 1
            fields = {"phase": phase, "sequence": command_sequence,
                      "newEdgeAddress": new_address}
            if phase == "root_bootstrap":
                record("provider append root bootstrap start fenced", fields)
            observed = {}

            def on_intent(value):
                record("provider append bootstrap command intent fenced", {
                    **fields, "invocationId": value.invocation_id,
                    "argvSha256": value.argv_sha256})
                observed["intent"] = value

            def on_started(value):
                if value.intent != observed.get("intent"):
                    raise ValueError("append bootstrap start differs")
                record("provider append bootstrap command started before GO", {
                    **fields, "invocationId": value.intent.invocation_id,
                    "bootId": value.identity.boot_id, "pid": value.identity.pid,
                    "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks})
                observed["started"] = value

            def on_result(value):
                if value.started != observed.get("started"):
                    raise ValueError("append bootstrap result differs")
                record("provider append bootstrap command result fenced", {
                    **fields, "invocationId": value.started.intent.invocation_id,
                    "returnCode": value.returncode,
                    "stdoutTruncated": value.stdout_truncated,
                    "stderrTruncated": value.stderr_truncated,
                    **bootstrap_command_timing(value)})
                observed["result"] = value

            try:
                outcome = gated_command_runner(
                    command, scratch_path=scratch, provider_keyed_v2=True,
                    execution_timeout_seconds=BOOTSTRAP_COMMAND_TIMEOUT_SECONDS,
                    env=dict(env), intent_callback=on_intent,
                    started_callback=on_started,
                    heartbeat_callback=lambda _value: fence(), result_callback=on_result,
                )
            except UnreapedGatedCommandError:
                unreaped = True
                raise
            if (observed.get("result") is None or outcome.started != observed.get("started")
                    or observed["result"].timed_out is not False
                    or outcome.returncode != observed["result"].returncode):
                raise ValueError("append bootstrap command journal incomplete")
            return subprocess.CompletedProcess(command, outcome.returncode,
                                               outcome.stdout, outcome.stderr)

        fence()
        bootstrap = bootstrap_helper(
            parent.target_id, expanded, repository=jobs, env=bootstrap_env,
            workspace_root=scratch, host_policies=selected_policy,
            proxy_egress_ip=proxy.host_key_alias,
            initial_sketch_known_hosts_path=sketch_path,
            pinned_core_known_hosts_path=Path(core_path),
            runner=bootstrap_run, required_source_root=source_root,
            required_source_revision=workspace.source_revision,
            only_edge_name=new_node["hostname"],
        )
        if (not contacted or not root_started or bootstrap.node_count != 1
                or bootstrap.root_returncode != 0 or bootstrap.user_readiness_returncode != 0
                or bootstrap.transport_returncode != 0):
            raise ValueError("one-edge bootstrap completion differs")
        record("provider append new edge bootstrap completed", {
            "newEdgeAddress": new_address, "newEdgeProviderId": new_id})
        admin = retrieve_sketch_ssh_key(parent.target_id)
        transport = retrieve_sketch_transport_ssh_key(parent.target_id)
        if admin is None or transport is None:
            raise ValueError("retained sketch identities are missing")
        unused = str(root / ".barragan-append-host-proof-unused")
        spec = SketchBootstrapSpec(
            homebase=homebase, proxy=proxy, middle=middle, edges=edges,
            admin_private_key_path=unused, admin_public_key_path=unused,
            transport_public_key_path=unused, ssh_config_path=unused,
            upstream_root_playbook_path=unused, host_policies=selected_policy,
            proxy_egress_ip=proxy.host_key_alias,
            initial_sketch_known_hosts_path=str(sketch_path),
            pinned_core_known_hosts_path=core_path,
        )
        route = {"homebasePublicIp": homebase.host, "homebaseUser": homebase.user,
                 "proxyPrivateIp": proxy.host, "proxyPublicIp": proxy.host_key_alias,
                 "proxyUser": proxy.user, "coreSshKeyPath": homebase.ssh_private_key_path}
        expected = next(node for node in attachment.nodes if node.address == new_address)
        probe_scratch = root / f".barragan-append-host-proof-{uuid4().hex}"
        probe_scratch.mkdir(mode=0o700)
        probe_scratch.chmod(0o700)
        fields = {"newEdgeAddress": new_address, "newEdgeProviderId": new_id}
        try:
            collected = edge_collector(
            manifest=manifest, manifest_sha256=_digest_json(manifest),
            chain_id=selected.chain_id, expected=expected, ssh_spec=spec,
            reviewed_core_route=route,
            sketch_known_hosts_sha256=hashlib.sha256(sketch_path.read_bytes()).hexdigest(),
            scratch_path=probe_scratch, fence=fence,
            scratch_intent_callback=lambda value: record(
                "strict append host proof scratch intended",
                {**fields, "scratchPath": value.scratch_path}),
            intent_callback=lambda value: record(
                "strict append host proof command intended",
                {**fields, "invocationId": value.invocation_id,
                 "argvSha256": value.argv_sha256}),
            started_callback=lambda value: record(
                "strict append host proof command started before GO",
                {**fields, "invocationId": value.intent.invocation_id,
                 "bootId": value.identity.boot_id, "pid": value.identity.pid,
                 "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks}),
            heartbeat_callback=lambda _value: fence(),
            result_callback=lambda value: record(
                "strict append host proof command result fenced",
                {**fields, "invocationId": value.started.intent.invocation_id,
                 "returnCode": value.returncode,
                 "stdoutBytes": value.stdout_bytes,
                 "stderrBytes": value.stderr_bytes,
                 "stdoutTruncated": value.stdout_truncated,
                 "stderrTruncated": value.stderr_truncated}),
            )
        except UnreapedGatedCommandError:
            unreaped = True
            raise
        identity = collected.identity
        if (identity.manifest_sha256 != _digest_json(manifest)
                or identity.chain_id != selected.chain_id
                or identity.terraform_address != new_address
                or identity.provider_instance_id != new_id
                or identity.public_ipv4 != new_ip):
            raise ValueError("new-edge raw host identity differs")
        host_policy = selected_policy[new_node["hostname"]]
        firewall = interpret_digitalocean_host_policy(
            collected, expected_identity=identity,
            expected_predecessor_ipv4=middle_ip, expected_policy=host_policy)
        surface = interpret_digitalocean_host_surface(
            collected, expected_identity=identity,
            expected_predecessor_ipv4=middle_ip, expected_role="edge",
            expected_admin_key_sha256=_key_digest(admin.public_key.strip() + "\n"),
            expected_transport_key_sha256=_key_digest(transport.public_key.strip() + "\n"),
            expected_policy=host_policy,
        )
        if (firewall.identity != identity or surface.identity != identity
                or surface.complete_ssh_policy is not True):
            raise ValueError("new-edge raw firewall or SSH proof differs")
        raw_bytes = json.dumps(asdict(collected), sort_keys=True,
                               separators=(",", ":")).encode()
        raw_sha = hashlib.sha256(raw_bytes).hexdigest()
        evidence_path = _host_evidence_path(root, parent.id)
        fd = os.open(evidence_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(raw_bytes)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("append host evidence write made no progress")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        directory_fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        record("strict append host proof capture completed", {
            **fields, "hostEvidenceSha256": raw_sha,
            "hostEvidencePath": str(evidence_path)})
        fence()
        final_provider = attachment_reconciler(
            workspace, attachment, environment=environment,
            deployment_target="barragan-testing", credential_repository=credentials,
            max_attempts=12, poll_interval_seconds=10.0,
        )
        if not final_provider.provider_membership_verified or final_provider.state_sha256 != attachment.state_sha256:
            raise ValueError("expanded provider membership changed during proof")
        record("provider append expanded membership verified", {
            "stateSha256": attachment.state_sha256,
            "providerIds": list(final_provider.verified_droplet_ids)})
        record("strict append host proof completed", {
            **fields, "stateSha256": attachment.state_sha256,
            "hostEvidenceSha256": raw_sha,
            "hostEvidencePath": str(evidence_path)}, terminal="succeeded")
        fence()
        current_parent = jobs.save_if_leased(replace(
            current_parent,
            input={**current_parent.input, "phase": "awaiting_publication"},
            events=[*current_parent.events, JobEvent(len(current_parent.events) + 1,
                "info", "strict append host proof completed", {
                    "planJournalSha256": job_event_digest(plan_child.events),
                    "applyJournalSha256": job_event_digest(apply_child.events),
                    "hostProofJournalSha256": job_event_digest(child.events),
                })]), owner=_OWNER, token=token)
        if current_parent is None:
            raise ValueError("append publication parent seal changed")
        chains.publish_provider_keyed_edge_append(
            parent=current_parent, before=selected, after=expanded, other=other,
            initial_source=source, state_sha256=attachment.state_sha256,
            expected_event_digest=job_event_digest(current_parent.events),
            claim_owner=_OWNER, claim_token=token, finished_at=_now(),
        )
        return jobs.get(parent.id)
    except Exception as exc:
        timed_out = isinstance(exc, (SketchBootstrapTimeoutError, GatedCommandTimeoutError))
        attention_message = (BOOTSTRAP_TIMEOUT_MESSAGE if timed_out else
                             "strict append host proof stopped; reconciliation required")
        attention_data = ({"bootstrap": "reconciliation_required", "timedOut": True}
                          if timed_out else {})
        if not unreaped:
            try:
                if child is not None and child.status in {"queued", "running"}:
                    latest = jobs.get(child.id)
                    if latest == child:
                        chains.append_provider_keyed_host_proof_event(
                            child, JobEvent(len(child.events) + 1, "error",
                                attention_message, attention_data),
                            owner=_OWNER, token=token, started_at=child.started_at or _now(),
                            terminal_status="failed",
                        )
                latest_parent = jobs.get(current_parent.id)
                if latest_parent == current_parent:
                    jobs.save_if_leased(replace(
                        current_parent, status="failed", finished_at=_now(),
                        input={**current_parent.input, "phase": "attention"},
                        events=[*current_parent.events, JobEvent(len(current_parent.events) + 1,
                            "error", attention_message, attention_data)]),
                        owner=_OWNER, token=token)
            except Exception:
                pass
        raise ProviderKeyedAppendHostProofError(
            BOOTSTRAP_TIMEOUT_MESSAGE if timed_out else
            "append host proof stopped; manual read-only reconciliation required") from None
