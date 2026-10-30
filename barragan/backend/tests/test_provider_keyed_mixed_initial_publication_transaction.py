# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted all-or-none boundary for the mixed initial publication writer."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import base64
import hashlib
import json

import pytest
from sqlalchemy import text

from app.domain import JobEvent
from app.services.provider_keyed_host_surface_interpreter import _key_digest
from app.services.provider_keyed_mixed_initial_host_binding import _digest as mixed_digest
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedHostRow, MixedInitialPublicationSource, MixedProviderState,
)
from app.storage.database import db
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel
from app.storage.sketch_chain_repository import ProviderKeyedPublicationConflict
from test_provider_keyed_chain_publication import _case


def _public_key(byte: int) -> str:
    blob = b"\0\0\0\x0bssh-ed25519\0\0\0 " + bytes([byte]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + "\n"


def _mixed_case(client, monkeypatch):
    repo, jobs, leases, old = _case(client)
    first, second = old["pending_chains"]
    first = repo.save(replace(
        first, middle_provider="linode", edge_provider="linode",
        edge_count=1, edge_intents=[{**first.edge_intents[0], "provider": "linode"}],
    ))
    second = repo.save(replace(second, edge_count=1,
                               edge_intents=second.edge_intents[:1]))
    pending = (first, second)
    first_projection, second_projection = old["projected_chains"]
    first_nodes = [
        {**node, "provider": "linode",
         "terraformAddress": node["terraformAddress"].replace(
             "digitalocean_droplet", "linode_instance"),
         "providerInstanceId": "linode-" + node["providerInstanceId"]}
        for node in first_projection.chain.nodes[:2]
    ]
    projections = (
        replace(first_projection, chain=replace(first, nodes=first_nodes)),
        replace(second_projection, chain=replace(second,
                nodes=second_projection.chain.nodes[:2])),
    )
    core = jobs.get("job-core")
    fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain)
                    for chain in pending}
    jobs.save(replace(core, input={**core.input,
        "pendingSketchChainFingerprints": fingerprints}))
    plan = DeploymentPlanModel.query.filter_by(id="plan-core").one()
    authorization = {"kind": "bounded-mixed-post-core-v1"}
    authorization["fingerprint"] = mixed_digest(authorization)
    plan.evidence = {**plan.evidence,
        "pendingSketchChainFingerprints": fingerprints,
        "sketchAuthorization": authorization}
    plan.review = {"reviewedConfiguration": {"sketchAuthorization": authorization}}
    db.session.commit()
    parent = old["parent"]
    events = [JobEvent(i, "info", f"mixed checkpoint {i}", {}) for i in range(1, 8)]
    now = datetime.now(timezone.utc)
    parent = jobs.save(replace(parent,
        action="provider_keyed_mixed_initial", events=events,
        input={"engagementId": first.engagement_id, "coreJobId": "job-core",
               "corePlanId": "plan-core", "revisionId": "rev-1",
               "reviewFingerprint": authorization["fingerprint"],
               "chainIds": [first.chain_id, second.chain_id],
               "orderedProviders": ["linode", "digitalocean"],
               "phase": "awaiting_mixed_host_proof", "mutation": True,
               "claimOwner": "mixed-writer", "claimToken": "token-a",
               "claimClaimedAt": (now - timedelta(minutes=1)).isoformat(),
               "claimExpiresAt": (now + timedelta(minutes=30)).isoformat()}))
    state_shas = {"linode": "1" * 64, "digitalocean": "2" * 64}
    states = []
    workspaces = {"linode": "/private/tmp/mixed-linode",
                  "digitalocean": "/private/tmp/mixed-digitalocean"}
    for provider in ("linode", "digitalocean"):
        child = jobs.save(StoredJobRun(
            id=f"job-provider-keyed-mixed-initial-apply-{provider}-core",
            action="provider_keyed_mixed_initial_apply_child", status="succeeded",
            target=parent.target, target_type="engagement", target_id=first.engagement_id,
            requested_by="operator", input={"provider": provider}, artifact_refs=[],
            created_at=parent.created_at, started_at=parent.started_at,
            finished_at=now.isoformat(),
            events=[JobEvent(1, "info", "provider applied", {})],
        ))
        states.append(MixedProviderState(provider, state_shas[provider], "lineage", 1,
                                         (("instance", provider + "-1"),),
                                         job_event_digest(child.events)))
    rows = tuple(MixedHostRow(
        chain_id=node["chainId"], provider=node["provider"], role=node["role"],
        hostname=node["hostname"], terraform_address=node["terraformAddress"],
        provider_instance_id=node["providerInstanceId"], public_ip=node["publicIp"],
        assigned_proxy=node["assignedProxy"],
    ) for projection in projections for node in projection.chain.nodes)
    bootstrap = jobs.save(StoredJobRun(
        id="job-provider-keyed-mixed-host-worker-core",
        action="provider_keyed_mixed_initial_host_worker", status="succeeded",
        target=parent.target, target_type="engagement", target_id=first.engagement_id,
        requested_by="operator", input={}, artifact_refs=[],
        created_at=parent.created_at, started_at=parent.started_at,
        finished_at=now.isoformat(), events=[JobEvent(1, "info", "bootstrap done", {})],
    ))
    jobs.save(StoredJobRun(
        id="job-provider-keyed-mixed-host-binding-core",
        action="provider_keyed_mixed_initial_host_binding", status="queued",
        target=parent.target, target_type="engagement", target_id=first.engagement_id,
        requested_by="operator", input={"manifestSha256": "b" * 64,
                                        "handoffJournalSha256": job_event_digest(events)},
        artifact_refs=[], created_at=parent.created_at, started_at=None,
        finished_at=None, events=[JobEvent(1, "info", "binding", {})],
    ))
    source = MixedInitialPublicationSource(
        first.engagement_id, "job-core", "plan-core", "rev-1", parent.id,
        ("linode", "digitalocean"), (first.chain_id, second.chain_id),
        job_event_digest(events), "b" * 64, job_event_digest(bootstrap.events),
        tuple(states), rows,
    )
    source_sha = hashlib.sha256(json.dumps(
        asdict(source), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    child = jobs.save(replace(old["proof_child"],
        action="provider_keyed_mixed_initial_strict_host_proof",
        input={"claimOwner": "mixed-writer", "claimToken": "token-a"},
        events=[JobEvent(1, "info", "mixed strict host proof completed",
                         {"sourceSha256": source_sha})]))
    receipt = SimpleNamespace(
        source=source, child_id=child.id, child_event_sha256=job_event_digest(child.events),
        host_evidence_sha256="d" * 64, claim_owner="mixed-writer", claim_token="token-a",
        admin_key_sha256=_key_digest(_public_key(1)),
        transport_key_sha256=_key_digest(_public_key(2)),
    )
    import app.services.provider_keyed_mixed_strict_host_receipt as proof
    import app.services.provider_keyed_mixed_initial_apply_child as apply
    import app.services.sketch_ssh_keys as admin_keys
    import app.services.sketch_transport_ssh_keys as transport_keys
    monkeypatch.setattr(proof, "validate_receipt_child", lambda *_: None)
    monkeypatch.setattr(admin_keys, "retrieve_sketch_ssh_key",
                        lambda _id: SimpleNamespace(public_key=_public_key(1)))
    monkeypatch.setattr(transport_keys, "retrieve_sketch_transport_ssh_key",
                        lambda _id: SimpleNamespace(public_key=_public_key(2)))
    monkeypatch.setattr(apply, "recognize_mixed_initial_apply_terminal",
                        lambda _child, _parent, provider: {
                            "planPath": workspaces[provider] + "/saved.tfplan",
                            "proof": {"stateSha256": state_shas[provider],
                                      "lineage": "lineage", "serial": 1,
                                      "resourceIds": {"instance": provider + "-1"}},
                        })
    return repo, jobs, leases, dict(
        parent=parent, proof_child=child, receipt=receipt, pending_chains=pending,
        projected_chains=projections, source=source, provider_workspaces=workspaces,
        expected_parent_event_digest=job_event_digest(events),
        expected_child_event_digest=job_event_digest(child.events),
        claim_owner="mixed-writer", claim_token="token-a", finished_at=now.isoformat(),
    )


def test_both_provider_workspaces_publish_atomically(client, monkeypatch):
    with client.application.storage_context():
        repo, jobs, leases, args = _mixed_case(client, monkeypatch)
        rows = repo.publish_provider_keyed_mixed_initial_chains(**args)
        assert [row.status for row in rows] == ["deployed", "deployed"]
        assert [row.terraform_working_directory for row in rows] == [
            args["provider_workspaces"]["linode"], args["provider_workspaces"]["digitalocean"]]
        assert jobs.get(args["parent"].id).input["phase"] == "completed"
        assert jobs.get(args["proof_child"].id).status == "succeeded"
        assert leases.acquire(args["source"].engagement_id, "next-plan", "prepare")


def test_second_provider_write_failure_rolls_back_jobs_chains_and_lease(client, monkeypatch):
    with client.application.storage_context():
        repo, jobs, leases, args = _mixed_case(client, monkeypatch)
        assert args["pending_chains"][1].chain_id == "proxy02-sfo-01"
        db.session.execute(text("""
            CREATE TRIGGER block_mixed_second BEFORE UPDATE ON sketch_chains
            WHEN NEW.chain_id = 'proxy02-sfo-01'
            BEGIN SELECT RAISE(ABORT, 'injected failure'); END
        """))
        db.session.commit()
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_mixed_initial_chains(**args)
        assert [row.status for row in repo.list_for_engagement(args["source"].engagement_id)] == [
            "pending", "pending"]
        assert jobs.get(args["parent"].id).status == "running"
        assert jobs.get(args["proof_child"].id).status == "running"
        assert CoreMutationLeaseModel.query.filter_by(
            engagement_id=args["source"].engagement_id,
            owner_id="plan-core", operation="provider_keyed_initial").one_or_none() is not None


def test_provider_workspace_swap_cannot_publish(client, monkeypatch):
    with client.application.storage_context():
        repo, jobs, _leases, args = _mixed_case(client, monkeypatch)
        paths = args["provider_workspaces"]
        args["provider_workspaces"] = {"linode": paths["digitalocean"],
                                       "digitalocean": paths["linode"]}
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_mixed_initial_chains(**args)
        assert jobs.get(args["parent"].id).status == "running"
        assert all(row.status == "pending" for row in
                   repo.list_for_engagement(args["source"].engagement_id))


@pytest.mark.parametrize("drift", ["parent_journal", "child_claim", "key", "review"])
def test_changed_generation_cannot_release_lease_or_publish(client, monkeypatch, drift):
    with client.application.storage_context():
        repo, jobs, _leases, args = _mixed_case(client, monkeypatch)
        if drift == "parent_journal":
            db.session.execute(text("""
                UPDATE job_events SET message = 'changed' WHERE job_id = :id AND sequence = 7
            """), {"id": args["parent"].id})
            db.session.commit()
        elif drift == "child_claim":
            db.session.execute(text("""
                UPDATE job_runs SET input = json_set(input, '$.claimToken', 'changed')
                WHERE id = :id
            """), {"id": args["proof_child"].id})
            db.session.commit()
        elif drift == "key":
            args["receipt"].transport_key_sha256 = "0" * 64
        else:
            plan = DeploymentPlanModel.query.filter_by(id="plan-core").one()
            plan.review = {"reviewedConfiguration": {"sketchAuthorization": {"changed": True}}}
            db.session.commit()
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_mixed_initial_chains(**args)
        assert all(row.status == "pending" for row in
                   repo.list_for_engagement(args["source"].engagement_id))
        assert jobs.get(args["parent"].id).status == "running"
        assert jobs.get(args["proof_child"].id).status == "running"
        assert CoreMutationLeaseModel.query.filter_by(
            engagement_id=args["source"].engagement_id,
            owner_id="plan-core", operation="provider_keyed_initial").one_or_none() is not None
