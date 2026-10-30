# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted five-node source audit before any teardown dispatcher is enabled."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sys
from types import SimpleNamespace
from copy import deepcopy
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.engagement_teardown import (
    _current_scope_snapshot, _parent_id, ENGAGEMENT_TEARDOWN_ACTION,
    EngagementTeardownValidationError,
)
from app.services.provider_keyed_append_source import (
    ProviderKeyedAppendSourceError, audit_published_provider_keyed_append_source,
)
from app.services.provider_keyed_append_host_proof_job import _host_evidence_path
from app.services.sketch_ssh_keys import ensure_sketch_ssh_key, retrieve_sketch_ssh_key
from app.services.sketch_transport_ssh_keys import (
    ensure_sketch_transport_ssh_key, retrieve_sketch_transport_ssh_key,
)
from app.services.provider_keyed_initial_plan_gate import _inbound, _outbound
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
from app.services.provider_keyed_teardown_scope import (
    ProviderKeyedTeardownScopeError, build_digitalocean_keyed_teardown_scope,
)
from app.services.provider_keyed_comprehensive_teardown import (
    ProviderKeyedComprehensiveTeardownError, run_provider_keyed_comprehensive_handoff,
    _child_id,
)
from app.services.provider_keyed_published_dispatch import (
    PublishedKeyedDispatchAttention, advance_published_keyed_terminal,
)
from app.services.provider_keyed_teardown_source import (
    ProviderKeyedTeardownSourceError, _read_published_post_destroy_boundary,
    load_keyed_teardown_source,
)
from app.services.provider_keyed_append_destroy_targets import (
    ProviderKeyedAppendDestroyTargetsError, bind_published_append_destroy,
    read_published_append_destroy_targets,
)
from app.services.provider_keyed_initial_teardown import (
    DigitalOceanTeardownPreview, ProviderKeyedTeardownPreviewError, _state_resources,
    require_exact_digitalocean_destroy_plan,
)
from app.services.provider_keyed_digitalocean_attachment import (
    require_digitalocean_pre_destroy_membership,
)
from app.services import provider_keyed_initial_destroy_plan_job as destroy_plan_service
from app.services import provider_keyed_initial_destroy_apply_job as destroy_apply_service
from app.services.provider_keyed_inspector_linode_cleanup import _published_terminal_binding
from app.services.provider_keyed_initial_destroy_apply_job import preflight_digitalocean_initial_destroy_apply
from app.services.provider_keyed_initial_destroy_apply import ProviderKeyedInitialDestroyApplyResult
from app.services.provider_keyed_destroy_absence_preflight import (
    reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.job_repository import StoredJobRun, PublishedKeyedTeardownReservationConflict
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_persisted_intent import _materialized_args
from provider_keyed_append_receipts import (
    reseal_completed_append_after_plan_change, strict_edge_raw_fixture,
)
from test_job_repository_keyed_provider_absent import ready_row, proof as ready_absence_proof


def _state_resource(address, attributes):
    kind, rest = address.split(".", 1)
    if "[" in rest:
        name, key = rest.split("[", 1)
        index = json.loads(key[:-1])
    else:
        name, index = rest, None
    instance = {"attributes": attributes}
    if index is not None:
        instance["index_key"] = index
    return {"mode": "managed", "type": kind, "name": name,
            "instances": [instance]}


def _case(client, tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", Fernet.generate_key().decode())
    now = datetime.now(timezone.utc).isoformat()
    engagement, initial, core, plan, profile = _materialized_args(regions=["sfo3", "sfo3"])
    workspace = tmp_path / "provider"
    workspace.mkdir()
    initial = [replace(row, status="deployed", terraform_working_directory=str(workspace),
                       deploy_job_id="job-provider-keyed-initial-core") for row in initial]
    engagement = SqlAlchemyEngagementRepository().save(engagement)
    ensure_sketch_ssh_key(engagement.id)
    ensure_sketch_transport_ssh_key(engagement.id)
    plan = SqlAlchemyDeploymentPlanRepository().save(plan)
    core = SqlAlchemyJobRepository().save(replace(
        core, input={**core.input, "workspaceDir": str(tmp_path / "core")},
        created_at=now, started_at=now, finished_at=now))
    chains = SqlAlchemySketchChainRepository()
    previous = [chains.save(row) for row in initial]
    baseline = compile_fresh_digitalocean_persisted_intent(
        engagement, previous, core, plan, profile, environment="devtest",
        provider_state_exists=True, mode="materialized_read")
    selected = previous[0]
    added = {**selected.nodes[1], "terraformAddress":
             'digitalocean_droplet.edge["sfo3-03"]', "hostname":
             "edge-m4t8q2z7-sfo3-03", "providerInstanceId": "99001",
             "publicIp": "8.8.1.9", "edgeId": "edge-02", "edgeIndex": "2",
             "componentId": "edge-02", "edgeCount": "2"}
    expanded = replace(selected, edge_count=2, updated_at=now,
        edge_intents=[*selected.edge_intents, {"id": "edge-02", "provider": "digitalocean",
            "region": "sfo3", "size": "s-1vcpu-1gb"}],
        nodes=[selected.nodes[0], {**selected.nodes[1], "edgeCount": "2"}, added])
    current_intent = compile_fresh_digitalocean_persisted_intent(
        engagement, [expanded, previous[1]], core, plan, profile,
        environment="devtest", provider_state_exists=True, mode="materialized_read",
        reviewed_initial_chains=previous)
    source_state = {"version": 4, "terraform_version": "1.15.5", "serial": 2,
        "lineage": "6e23087e-3164-4c54-bcc2-f056a484081d", "resources": []}
    projected = {node["terraformAddress"]: node for row in [expanded, previous[1]]
                 for node in row.nodes}
    for address, intent in current_intent.nodes.items():
        row = projected[address]
        source_state["resources"].append(_state_resource(address, {
            "id": row["providerInstanceId"], "name": intent.name,
            "image": intent.image, "size": intent.size, "region": intent.region,
            "tags": [intent.firewall_selector_tag], "ipv4_address": row["publicIp"],
        }))
    peers = sorted(f"{node['publicIp']}/32" for node in projected.values())
    ingress = [_inbound(proto, "1-65535", peers) for proto in ("icmp", "tcp", "udp")]
    ingress += [_inbound("tcp", port, ["0.0.0.0/0"])
                for port in current_intent.firewall.public_tcp_ports]
    ingress.append(_inbound("tcp", "22", list(current_intent.firewall.trusted_ssh_cidrs)))
    egress = [_outbound(proto, "" if proto == "icmp" else "1-65535", "0.0.0.0/0")
              for proto in ("tcp", "udp", "icmp")]
    source_state["resources"].append(_state_resource("digitalocean_firewall.firewall", {
        "id": "11111111-2222-4333-8444-555555555555", "name": current_intent.firewall.name,
        "tags": [current_intent.selector_tag], "droplet_ids": None,
        "inbound_rule": ingress, "outbound_rule": egress,
    }))
    for address, identity in (
        ("digitalocean_ssh_key.key", "88001"),
        ("local_file.ansible_inventory[0]", "inventory-id"),
        ("local_file.ssh_stanza[0]", "stanza-id"),
    ):
        source_state["resources"].append(_state_resource(address, {"id": identity}))
    raw = json.dumps(source_state, sort_keys=True).encode()
    (workspace / "terraform.tfstate").write_bytes(raw)
    state_sha = hashlib.sha256(raw).hexdigest()
    original_nodes = [node for row in previous for node in row.nodes]
    manifest = {"engagementId": engagement.id, "stateSha256": "4" * 64,
        "revisionId": plan.revision_id, "sourceRevision": _SOURCE_REVISION,
        "providerConnectionId": "connection-opaque",
        "nodes": sorted(({"chainId": node["chainId"], "role": node["role"],
            "providerInstanceId": node["providerInstanceId"],
            "terraformAddress": node["terraformAddress"], "name": node["hostname"],
            "publicIp": node["publicIp"], "region": node["region"]}
            for node in original_nodes), key=lambda node: node["terraformAddress"])}
    initial_job = SqlAlchemyJobRepository().save(replace(core,
        id="job-provider-keyed-initial-core", action="provider_keyed_initial",
        target=f"engagement:{engagement.id}", target_type="engagement", target_id=engagement.id,
        events=[JobEvent(1, "info", "provider host identity binding intended", manifest),
                JobEvent(2, "info", "provider two-chain host proof published",
                         {"stateSha256": manifest["stateSha256"],
                          "hostEvidenceSha256": "6" * 64,
                          "manifestSha256": hashlib.sha256(json.dumps(manifest,
                              sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                          "chainIds": [row.chain_id for row in previous]})]))
    SqlAlchemyJobRepository().save(replace(initial_job,
        id="job-provider-keyed-initial-apply-core", action="provider_keyed_initial_apply",
        events=[JobEvent(1, "info", "provider saved-plan apply completed; proof pending",
                         {"stateSha256": manifest["stateSha256"]})]))
    source = PublishedProviderKeyedSource(
        engagement.id, core.id, plan.id, initial_job.id,
        job_event_digest(initial_job.events), job_event_digest(core.events),
        "3" * 64, manifest["stateSha256"],
        hashlib.sha256(json.dumps(manifest, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest(),
        "6" * 64, tuple(row.chain_id for row in previous),
        _fingerprint({row.chain_id: row.to_dict() for row in previous}),
    )
    source_record = json.loads(json.dumps(asdict(source)))
    source_sha = _fingerprint(source_record)
    append_binary = "/usr/bin/terraform"
    append_plan_path = str(workspace / ".barragan-edge-append.tfplan")
    def argv_sha(phase):
        argv = [append_binary, *(["show", "-json", append_plan_path] if phase == "show"
                                else ["apply", "-input=false", "-lock=true", "-no-color",
                                      append_plan_path])]
        return hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
    evidence_path = _host_evidence_path(workspace, "job-append")
    raw = strict_edge_raw_fixture(monkeypatch,
        manifest_sha="7" * 64, chain_id=selected.chain_id,
        address=added["terraformAddress"], provider_id=added["providerInstanceId"],
        region=added["region"], public_ip=added["publicIp"],
        hostname=added["hostname"], middle_ip=selected.nodes[0]["publicIp"],
        admin_public_key=retrieve_sketch_ssh_key(engagement.id).public_key,
        transport_public_key=retrieve_sketch_transport_ssh_key(engagement.id).public_key)
    evidence_path.write_bytes(raw)
    evidence_path.chmod(0o600)
    raw_sha = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    manifest_sha = "7" * 64
    def events(entries):
        return [JobEvent(index, "info", message, data)
                for index, (message, data) in enumerate(entries, 1)]
    apply_entries = [
        ("provider append Apply child reserved", {"planJournalSha256": "PLAN_SHA",
            "reservationId": "f" * 32}),
        ("provider append Apply preflight started", {}),
        ("provider append key staging intended", {}),
    ]
    for phase in ("show", "apply"):
        if phase == "apply":
            apply_entries.extend([
                ("provider append retained membership verified", {
                    "stateSha256": manifest["stateSha256"],
                    "providerIds": [node["providerInstanceId"]
                                    for row in previous for node in row.nodes]}),
                ("provider append phase apply_started", {"stateSha256": manifest["stateSha256"]}),
            ])
        apply_entries.extend([
            ("provider append command intent fenced", {"phase": phase,
                "invocationId": phase, "argvSha256": argv_sha(phase)}),
            ("provider append command started before GO", {"phase": phase, "invocationId": phase,
                "bootId": "boot", "pid": 1, "pgid": 1, "startTicks": 1}),
            ("provider append command result fenced", {"phase": phase, "invocationId": phase,
                "returnCode": 0}),
        ])
    apply_entries.extend([
        ("provider append expanded membership verified", {"stateSha256": state_sha,
            "providerIds": [node["providerInstanceId"] for node in projected.values()]}),
        ("provider append apply completed", {
            "stateSha256": state_sha, "newEdgeAddress": added["terraformAddress"],
            "newEdgeProviderId": added["providerInstanceId"],
            "newEdgePublicIp": added["publicIp"], "providerMembershipVerified": True}),
    ])
    proof_entries = [
        ("strict append host proof reserved", {"manifestSha256": manifest_sha}),
        ("strict append host proof started", {"manifestSha256": manifest_sha}),
        ("provider append edge contact intended", {
            "newEdgeAddress": added["terraformAddress"],
            "newEdgeProviderId": added["providerInstanceId"]}),
    ]
    for sequence, phase in enumerate(("root_readiness", "root_bootstrap",
                                      "user_readiness", "transport_install"), 1):
        common = {"phase": phase, "sequence": sequence,
                  "newEdgeAddress": added["terraformAddress"],
                  "invocationId": phase}
        if phase == "root_bootstrap":
            proof_entries.append(("provider append root bootstrap start fenced", {
                "phase": phase, "sequence": sequence,
                "newEdgeAddress": added["terraformAddress"]}))
        proof_entries.extend([
            ("provider append bootstrap command intent fenced", {
                **common, "argvSha256": "a" * 64}),
            ("provider append bootstrap command started before GO", {
                **common, "bootId": "boot", "pid": sequence,
                "pgid": sequence, "startTicks": sequence}),
            ("provider append bootstrap command result fenced", {
                **common, "returnCode": 0}),
        ])
    proof_entries.extend([
        ("provider append new edge bootstrap completed", {
            "newEdgeAddress": added["terraformAddress"],
            "newEdgeProviderId": added["providerInstanceId"]}),
        ("strict append host proof scratch intended", {
            "newEdgeAddress": added["terraformAddress"],
            "newEdgeProviderId": added["providerInstanceId"],
            "scratchPath": str(workspace / ".test-proof-scratch")}),
    ])
    for index, invocation in enumerate(("identity", "before", "surface", "after"), 5):
        proof_entries.extend([
            ("strict append host proof command intended", {
                "newEdgeAddress": added["terraformAddress"],
                "newEdgeProviderId": added["providerInstanceId"],
                "invocationId": invocation, "argvSha256": "b" * 64}),
            ("strict append host proof command started before GO", {
                "newEdgeAddress": added["terraformAddress"],
                "newEdgeProviderId": added["providerInstanceId"],
                "invocationId": invocation, "bootId": "boot", "pid": index,
                "pgid": index, "startTicks": index}),
            ("strict append host proof command result fenced", {
                "newEdgeAddress": added["terraformAddress"],
                "newEdgeProviderId": added["providerInstanceId"],
                "invocationId": invocation, "returnCode": 0}),
        ])
    proof_entries.extend([
        ("strict append host proof capture completed", {
            "newEdgeAddress": added["terraformAddress"],
            "newEdgeProviderId": added["providerInstanceId"],
            "hostEvidenceSha256": raw_sha, "hostEvidencePath": str(evidence_path)}),
        ("provider append expanded membership verified", {
            "stateSha256": state_sha,
            "providerIds": [node["providerInstanceId"] for node in projected.values()]}),
        ("strict append host proof completed", {
            "newEdgeAddress": added["terraformAddress"],
            "newEdgeProviderId": added["providerInstanceId"],
            "stateSha256": state_sha, "hostEvidenceSha256": raw_sha,
            "hostEvidencePath": str(evidence_path)}),
    ])
    children = {}
    for kind, action, mutation, event in (
        ("plan", "provider_keyed_edge_append_plan", False,
         JobEvent(1, "info", "reviewed append plan saved", {
             "initialSourceSha256": source_sha, "initialSource": source_record,
             "retainedSharedIds": {
                 "digitalocean_firewall.firewall": "11111111-2222-4333-8444-555555555555",
                 "digitalocean_ssh_key.key": "88001",
             },
             "selectedChain": selected.to_dict(),
             "planPath": append_plan_path,
             "terraformBinaryPath": append_binary})),
        ("apply", "provider_keyed_edge_append_apply", True, None),
        ("hostProof", "provider_keyed_edge_append_host_proof", False,
         None),
    ):
        if kind == "apply":
            plan_sha = job_event_digest(children["plan"].events)
            apply_entries[0] = (apply_entries[0][0], {
                **apply_entries[0][1], "planJournalSha256": plan_sha})
        children[kind] = SqlAlchemyJobRepository().save(replace(initial_job,
            id=f"job-append-{kind}", action=action, status="succeeded",
            input={"parentJobId": "job-append", "mutation": mutation,
                   **({"applyJobId": "job-append-apply"} if kind == "hostProof" else {})},
            events=(events(apply_entries) if kind == "apply" else
                    events(proof_entries) if kind == "hostProof" else [event])))
    hashes = {f"{kind}JournalSha256": job_event_digest(child.events)
              for kind, child in children.items()}
    parent = SqlAlchemyJobRepository().save(replace(initial_job,
        id="job-append", action="provider_keyed_edge_append", status="succeeded",
        input={"engagementId": engagement.id, "chainId": selected.chain_id,
               "coreJobId": core.id, "corePlanId": plan.id,
               "phase": "completed", "initialSourceSha256": source_sha,
               "applyReservationId": "f" * 32,
               **{f"{kind}JobId": child.id for kind, child in children.items()},
               "mutation": True},
        events=[JobEvent(1, "info", "strict append host proof reserved", {
                    "manifestSha256": manifest_sha}),
                JobEvent(2, "info", "strict append host proof completed", hashes),
                JobEvent(3, "info", "provider one-edge append published", {
                    "initialSource": source_record, "stateSha256": state_sha})]))
    chains.save(expanded)
    return core.id, engagement.id, state_sha, added


def _pending_atomic_append_writer_case(client, tmp_path, monkeypatch, *, thin_child=None):
    """Persist the reviewed plan, complete children, claim, lease and prior rows."""
    from app.services.provider_keyed_append_plan_job import _PLAN_EVENT_KEYS
    from app.services.provider_keyed_append_source import _decode_initial_source
    core_id, engagement_id, state_sha, _ = _case(client, tmp_path, monkeypatch)
    jobs = SqlAlchemyJobRepository()
    chains = SqlAlchemySketchChainRepository()
    parent = jobs.get("job-append")
    plan = jobs.get(parent.input["planJobId"])
    apply = jobs.get(parent.input["applyJobId"])
    proof = jobs.get(parent.input["hostProofJobId"])
    after = next(row for row in chains.list_for_engagement(engagement_id)
                 if row.edge_count == 2)
    after = replace(after, nodes=[*after.nodes[:2],
                                  {**after.nodes[2], "status": "deployed"}])
    other = next(row for row in chains.list_for_engagement(engagement_id)
                 if row.chain_id != after.chain_id)
    selected = plan.events[-1].data["selectedChain"]
    before = replace(after, edge_count=1, edge_intents=after.edge_intents[:1],
        nodes=[after.nodes[0], {**after.nodes[1], "edgeCount": "1"}],
        updated_at=selected["updatedAt"])
    assert before.to_dict() == selected
    before = chains.save(before)
    source_record = parent.events[-1].data["initialSource"]
    initial_source = _decode_initial_source(source_record)
    receipt = {**plan.events[-1].data,
        "selectedChain": before.to_dict(),
        "newEdgeAddress": after.nodes[2]["terraformAddress"],
        "planSha256": "8" * 64, "stateSha256": initial_source.state_sha256,
        "topologySha256": "9" * 64, "sourceSha256": _SOURCE_SHA256,
        "lockfileSha256": "a" * 64,
        "inputSha256": [[str(Path(before.terraform_working_directory).parents[1] /
                             ".plan-material" / "digitalocean" /
                             "append-inputs.json"), "b" * 64]],
        "credentialRecordId": "credential-do", "credentialSecretSha256": "c" * 64,
        "credentialUpdatedAt": datetime.now(timezone.utc).isoformat(),
        "terraformBinarySha256": "d" * 64}
    assert set(receipt) == _PLAN_EVENT_KEYS
    plan = jobs.save(replace(plan, events=[replace(plan.events[-1], data=receipt)]))
    plan_sha = job_event_digest(plan.events)
    apply_events = [replace(apply.events[0], data={
        **apply.events[0].data, "planJournalSha256": plan_sha}), *apply.events[1:]]
    if thin_child == "apply":
        apply_events = [JobEvent(1, "info", "provider append apply completed",
                                 apply.events[-1].data)]
    apply = jobs.save(replace(apply, events=apply_events))
    if thin_child == "hostProof":
        proof = jobs.save(replace(proof, events=[
            proof.events[0], JobEvent(2, "info", "strict append host proof completed",
                                      proof.events[-1].data)]))
    digests = {f"{kind}JournalSha256": job_event_digest(child.events)
               for kind, child in (("plan", plan), ("apply", apply),
                                   ("hostProof", proof))}
    now = datetime.now(timezone.utc)
    parent = jobs.save(replace(parent, status="running", finished_at=None,
        input={**parent.input, "phase": "awaiting_publication",
               "planJournalSha256": plan_sha, "applyReservationId": "f" * 32,
               "claimOwner": "worker", "claimToken": "token",
               "claimClaimedAt": now.isoformat(),
               "claimExpiresAt": (now + timedelta(minutes=30)).isoformat()},
        events=[
            JobEvent(1, "info", "provider append plan ready for review", {
                "planJobId": plan.id, "planSha256": receipt["planSha256"]}),
            JobEvent(2, "info", "strict append host proof reserved", {
                "manifestSha256": "7" * 64}),
            JobEvent(3, "info", "strict append host proof completed", digests),
        ]))
    db.session.add(CoreMutationLeaseModel(
        engagement_id=engagement_id, owner_id=parent.input["corePlanId"],
        operation="provider_keyed_edge_append"))
    db.session.commit()
    assert parent.input["initialSourceSha256"] == _fingerprint(asdict(initial_source))
    assert after.nodes[1] == {**before.nodes[1], "edgeCount": "2"}
    assert after.nodes[2]["edgeCount"] == "2"
    assert len({node["terraformAddress"] for node in [*after.nodes, *other.nodes]}) == 5
    assert chains.get(engagement_id, before.chain_id) == before
    assert chains.get(engagement_id, other.chain_id) == other
    assert parent.events[-1].message == "strict append host proof completed"
    args = dict(parent=parent, before=before, after=after, other=other,
                initial_source=initial_source, state_sha256=state_sha,
                expected_event_digest=job_event_digest(parent.events),
                claim_owner="worker", claim_token="token", finished_at=now.isoformat())
    return chains, args


@pytest.mark.parametrize("wrong_owner", [False, True])
def test_atomic_append_writer_uses_core_plan_owned_lease(
        client, tmp_path, monkeypatch, wrong_owner):
    from app.storage.sketch_chain_repository import ProviderKeyedPublicationConflict

    with client.application.storage_context():
        chains, args = _pending_atomic_append_writer_case(client, tmp_path, monkeypatch)
        parent, before = args["parent"], args["before"]
        if wrong_owner:
            lease = db.session.get(CoreMutationLeaseModel, before.engagement_id)
            lease.owner_id = parent.id
            db.session.commit()
            with pytest.raises(ProviderKeyedPublicationConflict):
                chains.publish_provider_keyed_edge_append(**args)
            assert SqlAlchemyJobRepository().get(parent.id).status == "running"
            assert chains.get(before.engagement_id, before.chain_id) == before
        else:
            published = chains.publish_provider_keyed_edge_append(**args)
            assert published.edge_count == 2
            saved = SqlAlchemyJobRepository().get(parent.id)
            assert saved.status == "succeeded"
            assert saved.input["phase"] == "completed"
            assert db.session.get(CoreMutationLeaseModel, before.engagement_id) is None


@pytest.mark.parametrize("thin_child", ["apply", "hostProof"])
def test_atomic_append_writer_rejects_resealed_thin_child_journal(
        client, tmp_path, monkeypatch, thin_child):
    """The real writer must reach the strict child recognizer before publication."""
    from app.storage.sketch_chain_repository import ProviderKeyedPublicationConflict
    import app.services.provider_keyed_append_apply_job as apply_service
    import app.services.provider_keyed_append_host_proof_job as proof_service

    with client.application.storage_context():
        chains, args = _pending_atomic_append_writer_case(
            client, tmp_path, monkeypatch, thin_child=thin_child)
        parent = args["parent"]
        before = args["before"]
        engagement_id = before.engagement_id
        jobs = SqlAlchemyJobRepository()
        reached = []
        if thin_child == "apply":
            original = apply_service._completed_apply_child_receipt
            def recognizer(*args, **kwargs):
                reached.append("apply")
                return original(*args, **kwargs)
            monkeypatch.setattr(apply_service, "_completed_apply_child_receipt", recognizer)
        else:
            original = proof_service._completed_child_receipt
            def recognizer(*args, **kwargs):
                reached.append("hostProof")
                return original(*args, **kwargs)
            monkeypatch.setattr(proof_service, "_completed_child_receipt", recognizer)
        with pytest.raises(ProviderKeyedPublicationConflict):
            chains.publish_provider_keyed_edge_append(**args)
        assert reached == [thin_child]
        assert chains.get(engagement_id, before.chain_id) == before
        assert jobs.get(parent.id).status == "running"
        assert db.session.get(CoreMutationLeaseModel, engagement_id) is not None


def test_persisted_one_edge_source_reopens_and_rejects_node_drift(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, state_sha, added = _case(client, tmp_path, monkeypatch)
        source = audit_published_provider_keyed_append_source(
            core_id, state_root=tmp_path)
        assert source.state_sha256 == state_sha
        assert source.new_edge_address == added["terraformAddress"]
        chains = SqlAlchemySketchChainRepository()
        selected = next(row for row in chains.list_for_engagement(engagement_id)
                        if row.edge_count == 2)
        chains.save(replace(selected, nodes=[*selected.nodes[:2],
                                             {**selected.nodes[2], "providerInstanceId": "99999"}]))
        with pytest.raises(ProviderKeyedAppendSourceError):
            audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)


def test_published_append_audits_prior_reconciled_review_and_rejects_drift(
        client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, state_sha, _added = _case(client, tmp_path, monkeypatch)
        jobs = SqlAlchemyJobRepository()
        published = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        now = datetime.now(timezone.utc).isoformat()
        prior = StoredJobRun(
            "job-prior-append-review", "provider_keyed_edge_append", "failed",
            f"engagement:{engagement_id}", "engagement", engagement_id, "operator",
            {"engagementId": engagement_id, "coreJobId": core_id,
             "corePlanId": published.initial_source.core_plan_id,
             "planJobId": "job-prior-append-plan", "phase": "unapplied_reconciled"},
            [], now, now, now, [JobEvent(1, "info", "append plan reconciled without mutation",
                                    {"stateSha256": published.initial_source.state_sha256})],
        )
        child = StoredJobRun(
            "job-prior-append-plan", "provider_keyed_edge_append_plan", "failed",
            prior.target, "engagement", engagement_id, "operator",
            {"engagementId": engagement_id, "parentJobId": prior.id,
             "coreJobId": core_id, "mutation": False},
            [], now, now, now, [JobEvent(1, "error", "plan failed", {})],
        )
        jobs.save(prior)
        jobs.save(child)
        assert audit_published_provider_keyed_append_source(
            core_id, state_root=tmp_path) == published
        scope = build_digitalocean_keyed_teardown_scope(
            engagement_id, core_id, state_root=tmp_path)
        assert scope["stateSha256"] == state_sha
        jobs.save(replace(prior, events=[replace(prior.events[0],
            data={"stateSha256": "f" * 64})]))
        with pytest.raises(ProviderKeyedAppendSourceError):
            audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)


def test_published_append_audits_prior_attested_no_go_apply_and_teardown_scope(
        client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, state_sha, _added = _case(client, tmp_path, monkeypatch)
        jobs = SqlAlchemyJobRepository()
        published = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        now = datetime.now(timezone.utc).isoformat()
        prior_id = "job-provider-keyed-append-historical"
        plan_id = "job-provider-keyed-append-plan-historical"
        apply_id = "job-provider-keyed-append-apply-historical"
        target = f"engagement:{engagement_id}"
        reservation = "c" * 32
        original_sha = published.initial_source.state_sha256
        plan = jobs.save(StoredJobRun(plan_id, "provider_keyed_edge_append_plan",
            "succeeded", target, "engagement", engagement_id, "operator",
            {"engagementId": engagement_id, "parentJobId": prior_id,
             "coreJobId": core_id, "mutation": False}, [], now, now, now,
            [JobEvent(1, "info", "reviewed append plan saved",
                      {"stateSha256": original_sha, "planSha256": "b" * 64})]))
        plan_digest = job_event_digest(plan.events)
        child_events = [
            JobEvent(1, "info", "provider append Apply child reserved",
                     {"planJournalSha256": plan_digest, "reservationId": reservation}),
            JobEvent(2, "info", "provider append Apply never started",
                     {"stateSha256": original_sha,
                      "planJournalSha256": plan_digest}),
        ]
        jobs.save(StoredJobRun(apply_id, "provider_keyed_edge_append_apply",
            "failed", target, "engagement", engagement_id, "operator",
            {"engagementId": engagement_id, "parentJobId": prior_id,
             "coreJobId": core_id, "corePlanId": published.initial_source.core_plan_id,
             "planJobId": plan_id, "mutation": True}, [], now, None, now,
            child_events))
        jobs.save(StoredJobRun(prior_id, "provider_keyed_edge_append", "failed",
            target, "engagement", engagement_id, "operator",
            {"engagementId": engagement_id, "coreJobId": core_id,
             "corePlanId": published.initial_source.core_plan_id,
             "planJobId": plan_id, "applyJobId": apply_id,
             "planJournalSha256": plan_digest, "applyReservationId": reservation,
             "phase": "unapplied_reconciled"}, [], now, now, now, [
                JobEvent(1, "info", "provider append Apply reserved",
                         {"planJournalSha256": plan_digest,
                          "reservationId": reservation}),
                JobEvent(2, "info", "provider append Apply no-GO fenced",
                         {"stateSha256": original_sha,
                          "applyChildJournalSha256": job_event_digest(child_events)}),
                JobEvent(3, "info", "append plan reconciled without mutation",
                         {"stateSha256": original_sha,
                          "noGoApplyChildJournalSha256": job_event_digest(child_events)}),
            ]))
        assert audit_published_provider_keyed_append_source(
            core_id, state_root=tmp_path) == published
        assert build_digitalocean_keyed_teardown_scope(
            engagement_id, core_id, state_root=tmp_path)["stateSha256"] == state_sha


def test_expanded_scope_lists_all_five_nodes_and_four_shared_resources(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, state_sha, added = _case(client, tmp_path, monkeypatch)
        scope = build_digitalocean_keyed_teardown_scope(
            engagement_id, core_id, environment="devtest", state_root=tmp_path)
        assert scope["stateSha256"] == state_sha
        assert scope["schema"] == "provider-keyed-v2"
        assert len(scope["resources"]) == 9
        assert len([item for item in scope["resources"] if item["kind"] == "droplet"]) == 5
        assert {item["address"]: item["id"] for item in scope["resources"]}[
            added["terraformAddress"]] == added["providerInstanceId"]
        assert scope["chainIds"] == ["proxy01-sfo-01", "proxy02-sfo-01"]
        with pytest.raises(ProviderKeyedTeardownScopeError):
            build_digitalocean_keyed_teardown_scope(
                engagement_id, core_id, environment="devtest", state_root=tmp_path,
                allowed_teardown_parent_id="job-teardown")


def _reviewed_append_parent(core_id, engagement_id, tmp_path):
    jobs = SqlAlchemyJobRepository()
    core = jobs.get(core_id)
    snapshot = _current_scope_snapshot(
        core, jobs=jobs, chains=SqlAlchemySketchChainRepository(),
        resources=SqlAlchemyProviderResourceRepository(),
        domain_repository=SqlAlchemyDomainRepository(),
        inspector_state_reader=None, state_root=tmp_path,
    )
    now = datetime.now(timezone.utc).isoformat()
    proposal = StoredJobRun(
        id=_parent_id(core_id), action=ENGAGEMENT_TEARDOWN_ACTION,
        status="queued", target=f"engagement:{engagement_id}",
        target_type="engagement", target_id=engagement_id, requested_by="operator",
        input={"engagementId": engagement_id, "coreJobId": core_id,
               "scopeSnapshot": snapshot, "phase": "queued", "outcomes": {},
               "remainingOwnedResources": [], "mutation": True,
               "confirmation": "redacted"},
        artifact_refs=[], created_at=now, started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "engagement teardown queued",
                         {"snapshotId": snapshot["snapshotId"]})],
    )
    return jobs, proposal


def test_expanded_channel_free_preview_and_atomic_reservation(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, state_sha, _ = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        snapshot = proposal.input["scopeSnapshot"]
        assert snapshot["dnsCleanupManifest"]["schema"] == "provider-keyed-empty-dns-append-v1"
        assert snapshot["providerScopes"][0]["stateSha256"] == state_sha
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        saved = jobs.reserve_published_keyed_append_teardown_parent(
            proposal, reviewed_source=source, state_root=tmp_path)
        assert saved.status == "queued"
        assert saved.input["publishedAppendSource"]["append_journal_sha256"] == source.append_journal_sha256
        assert saved.input["scopeSnapshot"] == snapshot
        lease = db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=engagement_id).one()
        assert (lease.owner_id, lease.operation) == (source.initial_source.core_plan_id,
                                                      "provider_keyed_teardown_fence")
        restarted = SqlAlchemyJobRepository()
        assert restarted.reserve_published_keyed_append_teardown_parent(
            replace(proposal, created_at=datetime.now(timezone.utc).isoformat()),
            reviewed_source=source, state_root=tmp_path) == saved
        reserved_scope = build_digitalocean_keyed_teardown_scope(
            engagement_id, core_id, state_root=tmp_path,
            allowed_teardown_parent_id=saved.id)
        assert reserved_scope == snapshot["providerScopes"][0]
        loaded = load_keyed_teardown_source(
            saved.id, phase="pre_go", state_root=tmp_path)
        assert loaded.variant == "published_append"
        assert loaded.published_source_sha256 == _fingerprint(saved.input["publishedAppendSource"])
        handoff = run_provider_keyed_comprehensive_handoff(
            saved.id, environment="devtest", state_root=tmp_path)
        assert handoff.input["phase"] == "awaiting_inspector_preflight"
        with pytest.raises(PublishedKeyedDispatchAttention):
            advance_published_keyed_terminal(
                saved.id, environment="devtest", state_root=tmp_path,
                positive_control_ipv4="8.8.8.8")
        assert jobs.get(_child_id(core_id)) == handoff


def test_persisted_append_destroy_binding_reopens_and_rejects_input_drift(
    client, tmp_path, monkeypatch,
):
    """Rebind one five-node generation and its exact retained append input."""
    with client.application.storage_context():
        core_id, engagement_id, state_sha, added = _case(client, tmp_path, monkeypatch)
        jobs = SqlAlchemyJobRepository()
        workspace = tmp_path / "provider"
        material = workspace.parents[1] / ".plan-material" / "digitalocean"
        material.mkdir(parents=True)
        inputs = material / "append-inputs.json"
        inputs.write_bytes(b'{"reviewed":"one-edge"}')
        inputs.chmod(0o600)
        (workspace / ".barragan-apply-phase.json").write_text(
            '{"schema":"provider-keyed-v2","phase":"applied"}')
        (workspace / ".barragan-apply-phase.json").chmod(0o600)
        for name in (".barragan-provider-keyed-state.json", ".barragan-topology.json",
                     ".terraform.lock.hcl"):
            (workspace / name).write_text(name)
        # The fixture represents readable, non-writable-by-group Terraform
        # artifacts regardless of the host test user's umask.
        for name in ("terraform.tfstate", ".barragan-provider-keyed-state.json",
                     ".barragan-topology.json", ".terraform.lock.hcl"):
            (workspace / name).chmod(0o644)
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        public_key = "ssh-ed25519 fixture\n"
        initial_plan = replace(jobs.get("job-provider-keyed-initial-apply-core"),
            id="job-provider-keyed-initial-plan-core",
            action="provider_keyed_initial_plan",
            events=[JobEvent(1, "info", "reviewed provider plan saved", {
                "adminPublicKeySha256": hashlib.sha256(public_key.encode()).hexdigest(),
                "markerSha256": digest(workspace / ".barragan-provider-keyed-state.json"),
            })])
        jobs.save(initial_plan)
        append_plan = jobs.get("job-append-plan")
        prior = append_plan.events[-1].data
        receipt = {
            **prior,
            "newEdgeAddress": added["terraformAddress"],
            "planPath": str(workspace / ".barragan-edge-append.tfplan"),
            "planSha256": "b" * 64,
            "stateSha256": "4" * 64,
            "topologySha256": digest(workspace / ".barragan-topology.json"),
            "sourceSha256": _SOURCE_SHA256,
            "lockfileSha256": digest(workspace / ".terraform.lock.hcl"),
            "inputSha256": [[str(inputs), digest(inputs)]],
            "credentialRecordId": "connection-opaque",
            "credentialSecretSha256": "c" * 64,
            "credentialUpdatedAt": "2026-10-14T00:00:00+00:00",
            "terraformBinaryPath": str(Path(sys.executable).resolve()),
            "terraformBinarySha256": digest(Path(sys.executable).resolve()),
        }
        jobs.save(replace(append_plan, events=[JobEvent(1, "info", "reviewed append plan saved", receipt)]))
        reseal_completed_append_after_plan_change(jobs)
        monkeypatch.setattr(
            "app.services.provider_keyed_append_destroy_targets._credential_snapshot",
            lambda *_args: ("c" * 64, "2026-10-14T00:00:00+00:00", "sealed"),
        )
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        assert digest(inputs) == receipt["inputSha256"][0][1]
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        saved = jobs.reserve_published_keyed_append_teardown_parent(
            proposal, reviewed_source=source, state_root=tmp_path)
        assert digest(inputs) == receipt["inputSha256"][0][1]
        bound = bind_published_append_destroy(saved.id, state_root=tmp_path)
        assert len(bound.intent.resource_ids) == 9
        assert len(bound.attachment.nodes) == 5
        assert bound.intent.state_sha256 == state_sha
        assert bound.input_path == inputs
        monkeypatch.setattr(destroy_plan_service, "_default_state_root", lambda: tmp_path)
        monkeypatch.setattr(destroy_apply_service, "_default_state_root", lambda: tmp_path)
        monkeypatch.setattr("app.services.sketch_state_workspaces._default_state_root",
                            lambda: tmp_path)
        monkeypatch.setattr(destroy_plan_service, "retrieve_sketch_ssh_key",
                            lambda *_args: SimpleNamespace(public_key=public_key))
        binary = Path(sys.executable).resolve()
        release = lambda **_kw: SimpleNamespace(path=binary, sha256=digest(binary))
        command_number = 0
        state = json.loads((workspace / "terraform.tfstate").read_text())
        values = _state_resources(state)
        prior = [{"address": address, "mode": "managed", "values": deepcopy(attributes)}
                 for address, attributes in sorted(values.items())]
        destroy_json = json.dumps({
            "format_version": "1.2", "terraform_version": "1.15.5",
            "applyable": True, "complete": True, "errored": False,
            "prior_state": {"values": {"root_module": {"resources": prior}}},
            "planned_values": {"root_module": {}},
            "resource_changes": [{"address": item["address"], "change": {
                "actions": ["delete"], "before": deepcopy(item["values"]),
                "after": None, "after_unknown": {},
            }} for item in prior],
        })

        def gated(args, *, scratch_path, provider_keyed_v2, max_output_bytes, env,
                  intent_callback, started_callback, heartbeat_callback, result_callback):
            nonlocal command_number
            command_number += 1
            intent = CommandIntent(
                f"preview-{command_number}", str(scratch_path),
                hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest())
            intent_callback(intent)
            started = StartedCommand(intent, ProcessIdentity(
                "11111111-1111-4111-8111-111111111111", 1000 + command_number,
                1000 + command_number, command_number))
            started_callback(started)
            heartbeat_callback(started)
            output = ('{"terraform_version":"1.15.5"}' if args[1] == "version"
                      else destroy_json if args[1] == "show" else "")
            result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
            return CommandResult(started, 0, output, "", False, False)

        def preview(bound_workspace, intent, **options):
            assert bound_workspace.path == workspace
            assert len(intent.nodes) == 5 and len(intent.resource_ids) == 9
            assert options["var_files"] == [inputs]
            assert options["input_sha256"] == {inputs: digest(inputs)}
            assert options["expected_topology_path"] == inputs
            scratch = options["staging_path"]
            plan_file = workspace / ".barragan-initial-destroy.tfplan"
            run = options["command_runner"]
            run([str(binary), "version", "-json"], workspace, {})
            run([str(binary), "init", "-input=false", "-lockfile=readonly", "-no-color"],
                workspace, {})
            run([str(binary), "plan", "-destroy", "-input=false", "-lock=true", "-no-color",
                 f"-out={plan_file}", f"-var-file={scratch / 'input-0.json'}",
                 f"-var-file={scratch / 'credential.json'}"], workspace, {})
            plan_file.write_bytes(b"exact nine-resource destroy fixture")
            plan_file.chmod(0o600)
            shown = run([str(binary), "show", "-json", str(plan_file)], workspace, {})
            require_exact_digitalocean_destroy_plan(
                shown.stdout, expected_resource_ids=intent.resource_ids, state=state)
            return DigitalOceanTeardownPreview(
                plan_file, digest(plan_file), state_sha, _SOURCE_SHA256,
                digest(workspace / ".barragan-provider-keyed-state.json"),
                digest(workspace / ".terraform.lock.hcl"),
                digest(workspace / ".barragan-topology.json"),
                digest(workspace / ".barragan-apply-phase.json"),
                ((str(inputs), digest(inputs)),), "connection-opaque", "c" * 64,
                "2026-10-14T00:00:00+00:00", binary, digest(binary),
            )

        prior_stage = workspace / (".barragan-destroy-inputs-" + "a" * 32)
        instant = datetime.now(timezone.utc)
        old_preview = jobs.save(replace(jobs.get(core_id),
            id="job-provider-keyed-initial-destroy-plan-core",
            action="provider_keyed_initial_destroy_plan", status="failed",
            target=f"engagement:{engagement_id}", target_type="engagement",
            target_id=engagement_id, artifact_refs=[],
            input={"engagementId": engagement_id, "coreJobId": core_id,
                   "corePlanId": source.initial_source.core_plan_id,
                   "teardownParentId": saved.id,
                   "scopeSnapshotId": saved.input["scopeSnapshot"]["snapshotId"],
                   "providerScopeSha256": saved.input["scopeSnapshot"]["providerScopeSha256"],
                   "mutation": True},
            created_at=(instant - timedelta(minutes=4)).isoformat(),
            started_at=(instant - timedelta(minutes=3)).isoformat(),
            finished_at=(instant - timedelta(minutes=2)).isoformat(),
            events=[
                JobEvent(1, "info", "provider destroy preview queued", {}),
                JobEvent(2, "info", "provider destroy preview started", {}),
                JobEvent(3, "info", "provider destroy preview staging intended", {
                    "publicKeyPath": str(inputs.parent / "admin-public"),
                    "stagingPath": str(prior_stage),
                    "stagedInputPath": str(prior_stage / "input-0.json"),
                    "credentialPath": str(prior_stage / "credential.json"),
                    "planPath": str(workspace / ".barragan-initial-destroy.tfplan"),
                }),
                JobEvent(4, "error", "provider destroy preview stopped; reconciliation required",
                         {"failureStage": "other"}),
            ]))
        assert destroy_plan_service._precommand_failed_preview(
            old_preview, saved, jobs.get(core_id), saved.input["scopeSnapshot"],
            workspace, inputs)
        planned = destroy_plan_service.run_digitalocean_initial_destroy_plan_job(
            saved.id, environment="devtest", state_root=tmp_path,
            release_check=release, preview=preview, gated_command_runner=gated,
        )
        assert planned.status == "succeeded"
        assert planned.events[:4] == old_preview.events
        assert len(planned.events) == 19
        assert planned.events[-1].data["inputSha256"] == [[str(inputs), digest(inputs)]]
        # Exercise the actual provider membership veto with five current tagged
        # Droplets and the settled shared firewall; no network is opened.
        attachment = bound.attachment
        selector_path = f"/droplets?page=1&per_page=200&tag_name={attachment.selector_tag}"
        response_map = {
            selector_path: {"droplets": [{"id": int(node.droplet_id),
                                         "tags": [attachment.selector_tag]}
                                        for node in attachment.nodes],
                            "meta": {"total": 5}, "links": {}},
            "/droplets?page=1&per_page=200&type=gpus": {
                "droplets": [], "meta": {"total": 0}, "links": {}},
            f"/firewalls/{attachment.firewall_id}": {"firewall": {
                "id": attachment.firewall_id, "name": attachment.firewall_name,
                "tags": [attachment.selector_tag], "droplet_ids": [],
                "status": "succeeded", "pending_changes": [],
            }},
        }
        class Transport:
            def __init__(self):
                self.requests = []

            def request(self, origin, method, path, token):
                assert method == "GET" and token == "synthetic-token"
                self.requests.append(path)
                return deepcopy(response_map[path])

        transport = Transport()
        monkeypatch.setattr(
            "app.services.provider_keyed_digitalocean_attachment._credential_snapshot",
            lambda *_args: ("c" * 64, "2026-10-14T00:00:00+00:00", "sealed"),
        )
        monkeypatch.setattr(
            "app.services.provider_keyed_digitalocean_attachment.decrypt_secret_value",
            lambda *_args: "synthetic-token",
        )
        applied = preflight_digitalocean_initial_destroy_apply(
            saved.id, environment="devtest", state_root=tmp_path,
            membership_veto=require_digitalocean_pre_destroy_membership,
            membership_transport=transport,
        )
        assert len(applied.teardown_intent.resource_ids) == 9
        assert len(applied.attachment.nodes) == 5
        assert transport.requests == [selector_path,
            "/droplets?page=1&per_page=200&type=gpus",
            f"/firewalls/{attachment.firewall_id}"]
        response_map[selector_path]["droplets"].pop()
        with pytest.raises(ValueError):
            preflight_digitalocean_initial_destroy_apply(
                saved.id, environment="devtest", state_root=tmp_path,
                membership_veto=require_digitalocean_pre_destroy_membership,
                membership_transport=Transport(),
            )
        response_map[selector_path]["droplets"].append({
            "id": int(attachment.nodes[-1].droplet_id),
            "tags": [attachment.selector_tag],
        })
        commands = []

        def apply_gate(args, *, scratch_path, provider_keyed_v2, max_output_bytes, env,
                       intent_callback, started_callback, heartbeat_callback,
                       result_callback, **gate_options):
            phase = args[1]
            commands.append(phase)
            assert gate_options == ({"gate_timeout_seconds": 1200} if phase == "apply" else {})
            intent = CommandIntent(f"destroy-{phase}", str(scratch_path), hashlib.sha256(
                json.dumps(args, separators=(",", ":")).encode()).hexdigest())
            intent_callback(intent)
            started = StartedCommand(intent, ProcessIdentity(
                "11111111-1111-4111-8111-111111111111", 2000 + len(commands),
                2000 + len(commands), len(commands)))
            started_callback(started)
            heartbeat_callback(started)
            output = destroy_json if phase == "show" else ""
            result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
            return CommandResult(started, 0, output, "", False, False)

        def apply_once(bound_workspace, reviewed_preview, intent, *, command_runner,
                       phase_write_intent, **_kwargs):
            binary = str(reviewed_preview.terraform_binary_path)
            plan_path = str(reviewed_preview.plan_path)
            command_runner([binary, "show", "-json", plan_path], workspace, {})
            phase = workspace / ".barragan-apply-phase.json"
            phase_write_intent(phase, "destroy_started")
            phase.write_text('{"schema":"provider-keyed-v2","phase":"destroy_started"}')
            command_runner([binary, "apply", "-input=false", "-lock=true", "-no-color",
                            plan_path], workspace, {})
            phase_write_intent(phase, "destroy_applied")
            phase.write_text('{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
            (workspace / "terraform.tfstate").write_text(json.dumps({
                **state, "serial": state["serial"] + 1, "resources": [],
            }))
            return ProviderKeyedInitialDestroyApplyResult(digest(workspace / "terraform.tfstate"))

        dns_negative_checked = []
        def dns_checkpoint(snapshot, **_kwargs):
            from app.services.provider_keyed_dns_cleanup_checkpoint import (
                ProviderKeyedDnsCleanupCheckpointError,
                prove_provider_keyed_dns_cleanup_checkpoint,
            )
            if not dns_negative_checked:
                active = jobs.get(old_apply.id)
                foreign = replace(active, id="job-foreign-active", action="unrelated")
                shadow = SimpleNamespace(
                    get=jobs.get,
                    list_for_engagement=lambda engagement: [
                        *jobs.list_for_engagement(engagement), foreign],
                )
                with pytest.raises(ProviderKeyedDnsCleanupCheckpointError):
                    prove_provider_keyed_dns_cleanup_checkpoint(
                        snapshot, **{**_kwargs, "job_repository": shadow})
                dns_negative_checked.append(True)
            return prove_provider_keyed_dns_cleanup_checkpoint(snapshot, **_kwargs)

        inspector_checks = []
        def live_inspector_boundary(parent_id, **options):
            from app.services.provider_keyed_comprehensive_teardown import (
                _published_destroy_started_inspector_boundary,
            )
            assert parent_id == saved.id
            active = options["active_destroy_child"]()
            _published_destroy_started_inspector_boundary(
                jobs.get(saved.id), jobs.get(core_id), saved.input["scopeSnapshot"],
                active, jobs, state_root=tmp_path)
            if len(active.events) == 16:
                events = list(active.events)
                events[8] = replace(events[8], data={**events[8].data,
                                                     "failedJournalSha256": "0" * 64})
                drifted = replace(active, events=events)
                shadow = SimpleNamespace(get=lambda identifier: (
                    drifted if identifier == active.id else jobs.get(identifier)))
                with pytest.raises(ValueError):
                    _published_destroy_started_inspector_boundary(
                        jobs.get(saved.id), jobs.get(core_id), saved.input["scopeSnapshot"],
                        drifted, shadow, state_root=tmp_path)
            inspector_checks.append(parent_id)

        bound_apply = preflight_digitalocean_initial_destroy_apply(
            saved.id, environment="devtest", state_root=tmp_path,
            membership_veto=require_digitalocean_pre_destroy_membership,
            membership_transport=Transport(),
        )
        stopped_at = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        old_apply = jobs.save(StoredJobRun(
            id=f"job-provider-keyed-initial-destroy-apply-{core_id.removeprefix('job-')}",
            action="provider_keyed_initial_destroy_apply", status="failed",
            target=f"engagement:{engagement_id}", target_type="engagement",
            target_id=engagement_id, requested_by=saved.requested_by,
            input={"engagementId": engagement_id, "coreJobId": bound_apply.core_job_id,
                   "corePlanId": bound_apply.core_plan_id, "teardownParentId": saved.id,
                   "scopeSnapshotId": bound_apply.scope_snapshot_id,
                   "providerScopeSha256": bound_apply.provider_scope_sha256,
                   "destroyPlanJobId": bound_apply.preview_job_id,
                   "planSha256": bound_apply.preview.plan_sha256, "mutation": True},
            artifact_refs=[], created_at=stopped_at, started_at=stopped_at,
            finished_at=stopped_at, events=[
                JobEvent(1, "info", "provider destroy apply queued", {}),
                JobEvent(2, "info", "provider destroy apply started", {}),
                JobEvent(3, "error", "provider destroy apply stopped", {}),
            ],
        ))
        def rejected_rearm():
            before_child = jobs.get(old_apply.id)
            with pytest.raises(destroy_apply_service.ProviderKeyedInitialDestroyApplyJobError):
                destroy_apply_service.run_digitalocean_initial_destroy_apply_job(
                    saved.id, environment="devtest", state_root=tmp_path,
                    membership_veto=require_digitalocean_pre_destroy_membership,
                    membership_transport=Transport(), apply=apply_once,
                    gated_command_runner=apply_gate,
                    live_inspector_prover=live_inspector_boundary,
                    dns_checkpoint_prover=dns_checkpoint,
                )
            assert jobs.get(old_apply.id) == before_child and commands == []

        jobs.save(replace(old_apply, events=[*old_apply.events,
            JobEvent(4, "info", "unexpected", {})]))
        rejected_rearm()
        jobs.save(old_apply)
        # A second pre-command failure after the one permitted rearm has a
        # five-event history and deliberately needs reconciliation.
        jobs.save(replace(old_apply, events=[*old_apply.events,
            JobEvent(4, "info", destroy_apply_service._PRECOMMAND_APPLY_RECOVERY, {
                "failedJournalSha256": job_event_digest(old_apply.events),
                "failedFinishedAt": old_apply.finished_at}),
            JobEvent(5, "error", "provider destroy apply stopped", {})]))
        rejected_rearm()
        jobs.save(old_apply)
        original_parent = jobs.get(saved.id)
        jobs.save(replace(original_parent, input={**original_parent.input,
                                                 "phase": "drift"}))
        rejected_rearm()
        jobs.save(original_parent)
        append_source = jobs.get("job-append")
        jobs.save(replace(append_source, events=[*append_source.events,
            JobEvent(len(append_source.events) + 1, "info", "drift", {})]))
        rejected_rearm()
        jobs.save(append_source)
        lease = db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=engagement_id).one()
        lease_operation = lease.operation
        lease.operation = "unrelated"
        db.session.commit()
        rejected_rearm()
        lease.operation = lease_operation
        db.session.commit()
        for name, drifted in ((".barragan-initial-destroy.tfplan", b"other plan"),
                              (".barragan-apply-phase.json", b'{"phase":"other"}'),
                              ("terraform.tfstate", b"{}")):
            path = workspace / name
            original_bytes = path.read_bytes()
            path.write_bytes(drifted)
            rejected_rearm()
            path.write_bytes(original_bytes)
        with pytest.raises(destroy_apply_service.ProviderKeyedInitialDestroyApplyJobError):
            destroy_apply_service.run_digitalocean_initial_destroy_apply_job(
                saved.id, environment="devtest", state_root=tmp_path,
                membership_veto=require_digitalocean_pre_destroy_membership,
                membership_transport=Transport(), apply=apply_once,
                gated_command_runner=apply_gate,
                live_inspector_prover=live_inspector_boundary,
                dns_checkpoint_prover=lambda *_a, **_kw: (_ for _ in ()).throw(
                    ValueError("checkpoint unavailable")),
            )
        show_only = jobs.get(old_apply.id)
        assert show_only.status == "failed" and len(show_only.events) == 8
        assert commands == ["show"]
        assert digest(workspace / "terraform.tfstate") == state_sha
        assert json.loads((workspace / ".barragan-apply-phase.json").read_text())["phase"] == "applied"
        show_only = jobs.save(replace(
            show_only, finished_at=(datetime.now(timezone.utc) - timedelta(seconds=61)).isoformat()))
        commands.clear()
        def rejected_show_rearm(*, quiescent=True):
            before_child = jobs.get(show_only.id)
            with pytest.raises(destroy_apply_service.ProviderKeyedInitialDestroyApplyJobError):
                destroy_apply_service.run_digitalocean_initial_destroy_apply_job(
                    saved.id, environment="devtest", state_root=tmp_path,
                    membership_veto=require_digitalocean_pre_destroy_membership,
                    membership_transport=Transport(), apply=apply_once,
                    gated_command_runner=apply_gate,
                    live_inspector_prover=live_inspector_boundary,
                    dns_checkpoint_prover=dns_checkpoint,
                    process_quiescence=lambda *_identity: quiescent,
                )
            assert jobs.get(show_only.id) == before_child and commands == []

        rejected_show_rearm(quiescent=False)
        jobs.save(replace(show_only, events=[*show_only.events,
            JobEvent(9, "info", "provider destroy command intent fenced", {})]))
        rejected_show_rearm()
        jobs.save(show_only)
        for name, drifted in ((".barragan-initial-destroy.tfplan", b"other plan"),
                              (".barragan-apply-phase.json", b'{"phase":"destroy_started"}'),
                              ("terraform.tfstate", b"{}")):
            path = workspace / name
            original_bytes = path.read_bytes()
            path.write_bytes(drifted)
            rejected_show_rearm()
            path.write_bytes(original_bytes)
        quiescence_calls = []
        def prove_old_show_quiescent(*identity):
            quiescence_calls.append(identity)
            return True
        destroyed = destroy_apply_service.run_digitalocean_initial_destroy_apply_job(
            saved.id, environment="devtest", state_root=tmp_path,
            membership_veto=require_digitalocean_pre_destroy_membership,
            membership_transport=Transport(), apply=apply_once,
            gated_command_runner=apply_gate,
            live_inspector_prover=live_inspector_boundary,
            dns_checkpoint_prover=dns_checkpoint,
            process_quiescence=prove_old_show_quiescent,
        )
        assert destroyed.status == "succeeded" and commands == ["show", "apply"]
        assert dns_negative_checked == [True]
        assert inspector_checks == [saved.id]
        assert destroyed.id == old_apply.id and destroyed.events[:3] == old_apply.events
        assert destroyed.events[:8] == show_only.events
        assert len(destroyed.events) == 19
        assert destroyed.events[3].data["failedFinishedAt"] == old_apply.finished_at
        assert destroyed.events[8].data["failedFinishedAt"] == show_only.finished_at
        assert len(quiescence_calls) >= 2
        from app.services.provider_keyed_destroy_absence_preflight import _successful_journal
        assert _successful_journal(
            destroyed.events, str(binary), workspace / ".barragan-initial-destroy.tfplan",
            destroyed.id,
        ) == (17, 18)
        for event_index, replacement in (
            (8, replace(destroyed.events[8], data={
                **destroyed.events[8].data, "failedJournalSha256": "0" * 64})),
            (10, replace(destroyed.events[10], message="unexpected")),
        ):
            drifted_events = list(destroyed.events)
            drifted_events[event_index] = replacement
            with pytest.raises(ValueError):
                _successful_journal(
                    drifted_events, str(binary),
                    workspace / ".barragan-initial-destroy.tfplan", destroyed.id,
                )
        with pytest.raises(ValueError):
            _successful_journal(
                [*destroyed.events, JobEvent(20, "info", "unexpected", {})],
                str(binary), workspace / ".barragan-initial-destroy.tfplan", destroyed.id,
            )
        claimed_at = datetime.now(timezone.utc)
        assert jobs.rearm_exact_precommand_destroy_apply(
            old_apply, authority=lambda: True,
            owner="provider-keyed-destroy-apply-" + "a" * 32, token="b" * 32,
            claimed_at=claimed_at.isoformat(),
            expires_at=(claimed_at + timedelta(minutes=1)).isoformat(),
        ) is None
        with pytest.raises(destroy_apply_service.ProviderKeyedInitialDestroyApplyJobError):
            destroy_apply_service.run_digitalocean_initial_destroy_apply_job(
                saved.id, environment="devtest", state_root=tmp_path,
                membership_veto=require_digitalocean_pre_destroy_membership,
                membership_transport=Transport(), apply=apply_once,
                gated_command_runner=apply_gate,
                live_inspector_prover=live_inspector_boundary,
                dns_checkpoint_prover=dns_checkpoint,
            )
        assert commands == ["show", "apply"]
        inputs.write_bytes(b'{"reviewed":"changed"}')
        with pytest.raises(ProviderKeyedAppendDestroyTargetsError):
            bind_published_append_destroy(saved.id, state_root=tmp_path)
        inputs.write_bytes(b'{"reviewed":"one-edge"}')
        scope = saved.input["scopeSnapshot"]["providerScopes"][0]
        monkeypatch.setattr(
            "app.services.sketch_state_workspaces._default_state_root", lambda: tmp_path,
        )
        monkeypatch.setattr(
            "app.services.provider_keyed_destroy_absence_preflight._default_state_root",
            lambda: tmp_path,
        )
        credential_check = lambda *_args: (
            "c" * 64, "2026-10-14T00:00:00+00:00", "sealed")
        historical, _ = _read_published_post_destroy_boundary(
            saved.id, environment="devtest", state_root=tmp_path,
            job_repository=jobs, plan_repository=None, sketch_repository=None,
            credential_repository=None, lease_lookup=None, credential_check=credential_check,
        )
        assert historical.variant == "published_append"
        def empty_page(key, rows):
            return {key: rows, "meta": {"total": len(rows)}, "links": {}}
        response_map.update({
            "/droplets?page=1&per_page=200": empty_page("droplets", []),
            "/droplets?page=1&per_page=200&type=gpus": empty_page("droplets", []),
            "/firewalls?page=1&per_page=200": empty_page("firewalls", []),
            "/account/keys?page=1&per_page=200": empty_page("ssh_keys", []),
            "/tags?page=1&per_page=200": empty_page("tags", [{
                "name": attachment.selector_tag, "resources": {"count": 0},
            }]),
        })
        monkeypatch.setattr(
            "app.services.provider_keyed_digitalocean_absence._credential_snapshot",
            lambda *_args: ("c" * 64, "2026-10-14T00:00:00+00:00", "sealed"),
        )
        monkeypatch.setattr(
            "app.services.provider_keyed_digitalocean_absence.decrypt_secret_value",
            lambda *_args: "synthetic-token",
        )
        absent_get = Transport()
        absence = reconcile_successful_digitalocean_destroy_absence(
            saved.id, environment="devtest", state_root=tmp_path,
            credential_check=credential_check, transport=absent_get,
            max_attempts=1, sleeper=lambda *_args: None,
        )
        assert len(absence.verified_absent_droplet_ids) == 5
        assert len(absent_get.requests) == 5
        chains = SqlAlchemySketchChainRepository()
        before_rows = chains.list_for_engagement(engagement_id)
        prior_sha = _fingerprint({row.chain_id: row.to_dict() for row in before_rows})
        ready = ready_row()
        ready_input = {**ready.input, "engagementId": engagement_id,
            "coreJobId": core_id, "corePlanId": scope["corePlanId"],
            "teardownParentId": saved.id,
            "scopeSnapshotId": saved.input["scopeSnapshot"]["snapshotId"],
            "providerScopeSha256": saved.input["scopeSnapshot"]["providerScopeSha256"]}
        ready_events = list(ready.events)
        ready_events[0] = replace(ready_events[0], data={
            "snapshotId": ready_input["scopeSnapshotId"]})
        ready_events[3] = replace(ready_events[3], data={
            "corePlanId": ready_input["corePlanId"]})
        ready_events[4] = replace(ready_events[4], data={
            **ready_events[4].data,
            "scopeSnapshotId": ready_input["scopeSnapshotId"],
            "providerScopeSha256": ready_input["providerScopeSha256"],
            "sourceJournalSha256": job_event_digest(ready_events[:4]),
        })
        ready = jobs.save(replace(ready, id=_child_id(core_id),
            target=f"engagement:{engagement_id}", target_id=engagement_id,
            requested_by=saved.requested_by, input=ready_input,
            events=ready_events))
        ids = {row["address"]: row["id"] for row in scope["resources"]}
        publication = ready_absence_proof(ready)
        publication.update({
            "previewJobId": planned.id,
            "previewJournalSha256": job_event_digest(planned.events),
            "applyJobId": destroyed.id,
            "applyJournalSha256": job_event_digest(destroyed.events),
            "emptyStateSha256": absence.empty_state_sha256,
            "resourceIdsSha256": _fingerprint(ids),
            "verifiedAbsentDropletIds": list(absence.verified_absent_droplet_ids),
            "verifiedAbsentFirewallId": absence.verified_absent_firewall_id,
            "verifiedAbsentSshKeyId": absence.verified_absent_ssh_key_id,
            "selectorTagCleanupPending": absence.selector_tag_cleanup_pending,
        })
        provider_absent = jobs.publish_keyed_provider_absent_if_ready(
            ready, expected_event_digest=job_event_digest(ready.events),
            proof=publication, authority=lambda: None)
        assert provider_absent is not None
        now = datetime.now(timezone.utc)
        retirement_proof = {
            "scopeSnapshotId": ready_input["scopeSnapshotId"],
            "providerScopeSha256": ready_input["providerScopeSha256"],
            "sourceJournalSha256": job_event_digest(provider_absent.events),
            "applyJobId": destroyed.id,
            "resourceIdsSha256": _fingerprint(ids),
            "verifiedAbsentDropletIds": list(absence.verified_absent_droplet_ids),
            "verifiedAbsentFirewallId": absence.verified_absent_firewall_id,
            "verifiedAbsentSshKeyId": absence.verified_absent_ssh_key_id,
            "confirmationCompletedAt": now.isoformat(),
            "confirmationExpiresAt": (now + timedelta(seconds=30)).isoformat(),
        }
        retired_rows = chains.publish_provider_keyed_group_retired(
            coordinator=provider_absent, prior_chains=tuple(before_rows),
            prior_records=(), group_apply_job_id=destroyed.id,
            resource_ids=ids, proof=retirement_proof, authority=lambda: None,
            prior_chain_projection_sha256=prior_sha,
        )
        assert all(row.status == "destroyed" and row.nodes == [] for row in retired_rows)
        retired, _ = _read_published_post_destroy_boundary(
            saved.id, environment="devtest", state_root=tmp_path,
            job_repository=jobs, plan_repository=None, sketch_repository=None,
            credential_repository=None, lease_lookup=None, credential_check=credential_check,
            retired=True,
        )
        assert retired.variant == "published_append"
        binding = _published_terminal_binding(
            jobs.get(saved.id), jobs.get(_child_id(core_id)).events)
        assert binding["variant"] == "published_append"
        assert binding["appendJournalSha256"] == source.append_journal_sha256
        assert binding["initialJournalSha256"] == source.initial_source.initial_journal_sha256
        selected = next(row for row in chains.list_for_engagement(engagement_id)
                        if row.edge_count == 2)
        chains.save(replace(selected, edge_intents=[*selected.edge_intents[:1],
            {**selected.edge_intents[1], "region": "nyc3"}]))
        with pytest.raises(ValueError):
            _read_published_post_destroy_boundary(
                saved.id, environment="devtest", state_root=tmp_path,
                job_repository=jobs, plan_repository=None, sketch_repository=None,
                credential_repository=None, lease_lookup=None, credential_check=credential_check,
                retired=True,
            )


def test_expanded_reserved_source_rejects_sealed_drift_after_restart(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        saved = jobs.reserve_published_keyed_append_teardown_parent(
            proposal, reviewed_source=source, state_root=tmp_path)
        jobs.save(replace(saved, input={**saved.input,
            "publishedAppendSource": {**saved.input["publishedAppendSource"],
                                      "append_journal_sha256": "f" * 64}}))
        with pytest.raises(ProviderKeyedTeardownScopeError):
            build_digitalocean_keyed_teardown_scope(
                engagement_id, core_id, state_root=tmp_path,
                allowed_teardown_parent_id=saved.id)
        with pytest.raises(ProviderKeyedTeardownSourceError):
            load_keyed_teardown_source(saved.id, phase="pre_go", state_root=tmp_path)


def test_appended_targets_feed_existing_nine_resource_exact_delete_gate(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, added = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        saved = jobs.reserve_published_keyed_append_teardown_parent(
            proposal, reviewed_source=source, state_root=tmp_path)
        targets = read_published_append_destroy_targets(saved.id, state_root=tmp_path)
        assert targets.resource_ids[added["terraformAddress"]] == added["providerInstanceId"]
        assert len(targets.resource_ids) == 9
        workspace = tmp_path / "provider"
        state = json.loads((workspace / "terraform.tfstate").read_text())
        values = _state_resources(state)
        prior = [{"address": address, "mode": "managed", "values": deepcopy(attributes)}
                 for address, attributes in sorted(values.items())]
        changes = [{"address": item["address"], "change": {
            "actions": ["delete"], "before": deepcopy(item["values"]),
            "after": None, "after_unknown": {},
        }} for item in prior]
        plan = {"format_version": "1.2", "terraform_version": "1.15.5",
                "applyable": True, "complete": True, "errored": False,
                "prior_state": {"values": {"root_module": {"resources": prior}}},
                "planned_values": {"root_module": {}}, "resource_changes": changes}
        require_exact_digitalocean_destroy_plan(
            json.dumps(plan), expected_resource_ids=targets.resource_ids, state=state)
        plan["resource_changes"] = [item for item in changes
                                    if item["address"] != added["terraformAddress"]]
        with pytest.raises(ProviderKeyedTeardownPreviewError):
            require_exact_digitalocean_destroy_plan(
                json.dumps(plan), expected_resource_ids=targets.resource_ids, state=state)
        assert jobs.get("job-provider-keyed-initial-destroy-plan-core") is None


def test_appended_targets_reject_state_drift_after_reservation(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        saved = jobs.reserve_published_keyed_append_teardown_parent(
            proposal, reviewed_source=source, state_root=tmp_path)
        state_path = tmp_path / "provider" / "terraform.tfstate"
        state_path.write_bytes(state_path.read_bytes() + b"\n")
        with pytest.raises(ProviderKeyedAppendDestroyTargetsError):
            read_published_append_destroy_targets(saved.id, state_root=tmp_path)


@pytest.mark.parametrize("drift", ["lease", "status", "scope"])
def test_appended_targets_reject_fence_or_review_drift(client, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        saved = jobs.reserve_published_keyed_append_teardown_parent(
            proposal, reviewed_source=source, state_root=tmp_path)
        if drift == "lease":
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id=engagement_id).one()
            db.session.delete(lease)
            db.session.commit()
        elif drift == "status":
            jobs.save(replace(saved, status="failed", finished_at=datetime.now(timezone.utc).isoformat()))
        else:
            snapshot = deepcopy(saved.input["scopeSnapshot"])
            snapshot["providerScopes"][0]["resources"][0]["id"] = "other-owned-id"
            jobs.save(replace(saved, input={**saved.input, "scopeSnapshot": snapshot}))
        with pytest.raises(ProviderKeyedAppendDestroyTargetsError):
            read_published_append_destroy_targets(saved.id, state_root=tmp_path)


def test_expanded_reservation_rolls_back_if_reviewed_state_changes(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        selected = next(row for row in SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
                        if row.edge_count == 2)
        SqlAlchemySketchChainRepository().save(replace(selected, nodes=[*selected.nodes[:2],
            {**selected.nodes[2], "providerInstanceId": "99999"}]))
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_append_teardown_parent(
                proposal, reviewed_source=source, state_root=tmp_path)
        assert jobs.get(proposal.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=engagement_id).count() == 0


def test_expanded_preview_blocks_channel_work(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        core = SqlAlchemyJobRepository().get(core_id)
        SqlAlchemyJobRepository().save(replace(
            core, id="job-test-inbound", action="inbound_channel_create",
            target_id=engagement_id, target=f"engagement:{engagement_id}"))
        with pytest.raises(EngagementTeardownValidationError):
            _reviewed_append_parent(core_id, engagement_id, tmp_path)


def test_expanded_reservation_blocks_new_queued_engagement_job(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        core = jobs.get(core_id)
        jobs.save(replace(core, id="job-unrelated-queued", action="engagement_other_mutation",
                          status="queued", started_at=None, finished_at=None,
                          target_id=engagement_id, target=f"engagement:{engagement_id}"))
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_append_teardown_parent(
                proposal, reviewed_source=source, state_root=tmp_path)
        assert jobs.get(proposal.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=engagement_id).count() == 0


def test_expanded_reservation_blocks_append_journal_drift(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        append = jobs.get(source.append_job_id)
        jobs.save(replace(append, events=[*append.events,
            JobEvent(3, "info", "unexpected append event", {})]))
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_append_teardown_parent(
                proposal, reviewed_source=source, state_root=tmp_path)
        assert jobs.get(proposal.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=engagement_id).count() == 0


def test_expanded_scope_rejects_retained_node_id_drift(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        chains = SqlAlchemySketchChainRepository()
        selected = next(row for row in chains.list_for_engagement(engagement_id)
                        if row.edge_count == 2)
        chains.save(replace(selected, nodes=[{**selected.nodes[0],
            "providerInstanceId": "99888"}, *selected.nodes[1:]]))
        with pytest.raises(ProviderKeyedTeardownScopeError):
            build_digitalocean_keyed_teardown_scope(
                engagement_id, core_id, environment="devtest", state_root=tmp_path)


def test_persisted_source_rejects_untouched_sibling_drift(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        chains = SqlAlchemySketchChainRepository()
        sibling = next(row for row in chains.list_for_engagement(engagement_id)
                       if row.edge_count == 1)
        chains.save(replace(sibling, assigned_proxy="proxy01"))
        with pytest.raises(ProviderKeyedAppendSourceError):
            audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)


def test_persisted_source_rejects_extra_firewall_ingress_even_with_resealed_state(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, _, _, _ = _case(client, tmp_path, monkeypatch)
        state_path = tmp_path / "provider" / "terraform.tfstate"
        state = json.loads(state_path.read_text())
        firewall = next(row["instances"][0]["attributes"] for row in state["resources"]
                        if row["type"] == "digitalocean_firewall")
        firewall["inbound_rule"].append(_inbound("tcp", "9999", ["0.0.0.0/0"]))
        raw = json.dumps(state, sort_keys=True).encode()
        state_path.write_bytes(raw)
        state_sha = hashlib.sha256(raw).hexdigest()
        jobs = SqlAlchemyJobRepository()
        apply = jobs.get("job-append-apply")
        apply = jobs.save(replace(apply, events=[replace(apply.events[-1],
            data={"stateSha256": state_sha})]))
        parent = jobs.get("job-append")
        seal = replace(parent.events[0], data={**parent.events[0].data,
            "applyJournalSha256": job_event_digest(apply.events)})
        terminal = replace(parent.events[-1], data={**parent.events[-1].data,
            "stateSha256": state_sha})
        jobs.save(replace(parent, events=[seal, terminal]))
        with pytest.raises(ProviderKeyedAppendSourceError):
            audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)


@pytest.mark.parametrize("attachment_shape", ["missing", "empty_list"])
def test_persisted_source_requires_explicit_null_firewall_attachment_state(
    client, tmp_path, monkeypatch, attachment_shape,
):
    with client.application.storage_context():
        core_id, _, _, _ = _case(client, tmp_path, monkeypatch)
        state_path = tmp_path / "provider" / "terraform.tfstate"
        state = json.loads(state_path.read_text())
        firewall = next(row["instances"][0]["attributes"] for row in state["resources"]
                        if row["type"] == "digitalocean_firewall")
        if attachment_shape == "missing":
            firewall.pop("droplet_ids")
        else:
            firewall["droplet_ids"] = []
        raw = json.dumps(state, sort_keys=True).encode()
        state_path.write_bytes(raw)
        state_sha = hashlib.sha256(raw).hexdigest()
        jobs = SqlAlchemyJobRepository()
        apply = jobs.get("job-append-apply")
        apply = jobs.save(replace(apply, events=[replace(apply.events[-1],
            data={"stateSha256": state_sha})]))
        parent = jobs.get("job-append")
        seal = replace(parent.events[0], data={**parent.events[0].data,
            "applyJournalSha256": job_event_digest(apply.events)})
        terminal = replace(parent.events[-1], data={**parent.events[-1].data,
            "stateSha256": state_sha})
        jobs.save(replace(parent, events=[seal, terminal]))
        with pytest.raises(ProviderKeyedAppendSourceError):
            audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)


@pytest.mark.parametrize("kind,new_id", [
    ("digitalocean_firewall", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
    ("digitalocean_ssh_key", "other-key-id"),
])
def test_persisted_source_rejects_shared_provider_id_swap_with_resealed_state(
    client, tmp_path, monkeypatch, kind, new_id,
):
    with client.application.storage_context():
        core_id, engagement_id, _, _ = _case(client, tmp_path, monkeypatch)
        state_path = tmp_path / "provider" / "terraform.tfstate"
        state = json.loads(state_path.read_text())
        resource = next(row["instances"][0]["attributes"] for row in state["resources"]
                        if row["type"] == kind)
        resource["id"] = new_id
        raw = json.dumps(state, sort_keys=True).encode()
        state_path.write_bytes(raw)
        state_sha = hashlib.sha256(raw).hexdigest()
        jobs = SqlAlchemyJobRepository()
        apply = jobs.get("job-append-apply")
        apply = jobs.save(replace(apply, events=[replace(apply.events[-1],
            data={"stateSha256": state_sha})]))
        parent = jobs.get("job-append")
        jobs.save(replace(parent, events=[
            replace(parent.events[0], data={**parent.events[0].data,
                "applyJournalSha256": job_event_digest(apply.events)}),
            replace(parent.events[1], data={**parent.events[1].data,
                "stateSha256": state_sha}),
        ]))
        with pytest.raises(ProviderKeyedAppendSourceError):
            audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        with pytest.raises(ProviderKeyedTeardownScopeError):
            build_digitalocean_keyed_teardown_scope(
                engagement_id, core_id, environment="devtest", state_root=tmp_path)
