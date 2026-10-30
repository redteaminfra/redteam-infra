# Copyright (c) 2026, Oracle and/or its affiliates.
"""A one-edge publication is one SQLite transition, never a partial row edit."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_append_plan_job import _PLAN_EVENT_KEYS
from app.services.provider_keyed_initial_plan_gate import _SOURCE_SHA256
from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel, EngagementModel
from app.storage.sketch_chain_repository import (
    ProviderKeyedPublicationConflict, SqlAlchemySketchChainRepository, StoredSketchChain,
)


def _node(chain: str, role: str, identity: str, address: str, *, index: int = 1) -> dict:
    result = {
        "chainId": chain, "role": role, "provider": "digitalocean",
        "providerInstanceId": identity, "terraformAddress": address,
        "hostname": f"node-{identity}", "publicIp": f"203.0.113.{identity}",
        "region": "nyc3", "assignedProxy": "proxy01", "proxy": "proxy01",
        "status": "deployed", "componentId": "middle" if role == "middle" else f"edge-{index:02d}",
    }
    if role == "edge":
        result.update(edgeId=f"edge-{index:02d}", edgeIndex=str(index), edgeCount="1")
    return result


def _case(client):
    now = datetime.now(timezone.utc)
    started = (now - timedelta(minutes=1)).isoformat()
    finished = now.isoformat()
    expires = (now + timedelta(minutes=30)).isoformat()
    db.session.add(EngagementModel(
        id="eng-append", name="opaque", status="deployed", owner="operator",
        template_id="small-dev", active_revision="rev-1", input_parameters={},
        sketch_state_schema="provider-keyed-v2",
    ))
    db.session.commit()
    chains = SqlAlchemySketchChainRepository()
    before = chains.save(StoredSketchChain(
        chain_id="chain-01", engagement_id="eng-append", assigned_proxy="proxy01",
        middle_provider="digitalocean", middle_region="nyc3", middle_size="s-1vcpu-1gb",
        edge_provider="digitalocean", edge_region="nyc3", edge_size="s-1vcpu-1gb",
        status="deployed", burned=False, burned_note="", deploy_job_id="job-initial",
        teardown_job_id="", terraform_working_directory="/private/tmp/keyed-workspace",
        nodes=[_node("chain-01", "middle", "1", 'digitalocean_droplet.middle["middle_01"]'),
               _node("chain-01", "edge", "2", 'digitalocean_droplet.edge["nyc3-01"]')],
        created_at=started, updated_at=started, edge_count=1,
        edge_intents=[{"id": "edge-01", "provider": "digitalocean",
                       "region": "nyc3", "size": "s-1vcpu-1gb"}],
    ))
    other = chains.save(replace(before, chain_id="chain-02", nodes=[
        _node("chain-02", "middle", "3", 'digitalocean_droplet.middle["middle_02"]'),
        _node("chain-02", "edge", "4", 'digitalocean_droplet.edge["nyc3-02"]'),
    ]))
    after = replace(before, updated_at=finished, edge_count=2,
                    edge_intents=[*before.edge_intents, {
                        "id": "edge-02", "provider": "digitalocean",
                        "region": "nyc3", "size": "s-1vcpu-1gb",
                    }],
                    nodes=[before.nodes[0], {**before.nodes[1], "edgeCount": "2"},
                           {**_node("chain-01", "edge", "5",
                                     'digitalocean_droplet.edge["nyc3-03"]', index=2),
                            "edgeCount": "2"}])
    initial_source = PublishedProviderKeyedSource(
        "eng-append", "job-core", "plan-core", "job-initial",
        "1" * 64, "2" * 64, "3" * 64, "4" * 64,
        "5" * 64, "6" * 64, ("chain-01", "chain-02"), "7" * 64,
    )
    source_sha256 = _fingerprint(initial_source.__dict__)
    plan_receipt = {
        "initialSourceSha256": source_sha256,
        "initialSource": json.loads(json.dumps(initial_source.__dict__)),
        "retainedSharedIds": {
            "digitalocean_firewall.firewall": "11111111-2222-4333-8444-555555555555",
            "digitalocean_ssh_key.key": "789",
        },
        "selectedChain": before.to_dict(),
        "newEdgeAddress": after.nodes[2]["terraformAddress"],
        "planPath": str(Path(before.terraform_working_directory) / ".barragan-edge-append.tfplan"),
        "planSha256": "8" * 64,
        "stateSha256": initial_source.state_sha256,
        "topologySha256": "9" * 64,
        "sourceSha256": _SOURCE_SHA256,
        "lockfileSha256": "a" * 64,
        "inputSha256": [[str(Path(before.terraform_working_directory).parents[1]
                            / ".plan-material" / "digitalocean" / "append-inputs.json"),
                         "b" * 64]],
        "credentialRecordId": "credential-do",
        "credentialSecretSha256": "c" * 64,
        "credentialUpdatedAt": started,
        "terraformBinaryPath": "/usr/local/bin/terraform",
        "terraformBinarySha256": "d" * 64,
    }
    assert set(plan_receipt) == _PLAN_EVENT_KEYS
    jobs = SqlAlchemyJobRepository()
    child_digests = {}
    for kind, action, mutation in (
        ("plan", "provider_keyed_edge_append_plan", False),
        ("apply", "provider_keyed_edge_append_apply", True),
        ("hostProof", "provider_keyed_edge_append_host_proof", False),
    ):
        child = jobs.save(StoredJobRun(
            id=f"job-append-{kind}", action=action, status="succeeded",
            target="engagement:eng-append", target_type="engagement", target_id="eng-append",
            requested_by="operator", input={"parentJobId": "job-append", "mutation": mutation},
            artifact_refs=[], created_at=started, started_at=started, finished_at=finished,
            events=[JobEvent(1, "info", f"{kind} completed",
                             {"stateSha256": "b" * 64} if kind == "apply" else
                             plan_receipt if kind == "plan" else {})],
        ))
        child_digests[f"{kind}JournalSha256"] = job_event_digest(child.events)
    parent = jobs.save(StoredJobRun(
        id="job-append", action="provider_keyed_edge_append", status="running",
        target="engagement:eng-append", target_type="engagement", target_id="eng-append",
        requested_by="operator", input={
            "engagementId": "eng-append", "chainId": "chain-01", "phase": "awaiting_publication",
            "corePlanId": initial_source.core_plan_id,
            "initialSourceSha256": source_sha256,
            "mutation": True, "claimOwner": "worker", "claimToken": "token",
            "claimClaimedAt": started, "claimExpiresAt": expires,
            "planJobId": "job-append-plan", "applyJobId": "job-append-apply",
            "hostProofJobId": "job-append-hostProof",
            "planJournalSha256": child_digests["planJournalSha256"],
        }, artifact_refs=[], created_at=started, started_at=started, finished_at=None,
        events=[
            JobEvent(1, "info", "provider append plan ready for review", {
                "planJobId": "job-append-plan", "planSha256": plan_receipt["planSha256"],
            }),
            JobEvent(2, "info", "strict append host proof completed", child_digests),
        ],
    ))
    db.session.add(CoreMutationLeaseModel(engagement_id="eng-append",
                                          owner_id=initial_source.core_plan_id,
                                          operation="provider_keyed_edge_append"))
    db.session.commit()
    args = dict(parent=parent, before=before, after=after, other=other,
                initial_source=initial_source, state_sha256="b" * 64,
                expected_event_digest=job_event_digest(parent.events),
                claim_owner="worker", claim_token="token", finished_at=finished)
    return chains, args


def test_publish_appended_edge_and_receipt_atomically(client, tmp_path, monkeypatch):
    from test_provider_keyed_append_source import _pending_atomic_append_writer_case

    with client.application.storage_context():
        chains, args = _pending_atomic_append_writer_case(client, tmp_path, monkeypatch)
        result = chains.publish_provider_keyed_edge_append(**args)
        assert result.edge_count == 2
        assert result.edge_intents == args["after"].edge_intents
        assert [node["providerInstanceId"] for node in result.nodes] == [
            node["providerInstanceId"] for node in args["after"].nodes]
        assert chains.get(args["before"].engagement_id, args["other"].chain_id) == args["other"]
        saved = SqlAlchemyJobRepository().get("job-append")
        assert saved.status == "succeeded"
        assert saved.events[-1].message == "provider one-edge append published"
        assert saved.events[-1].data["stateSha256"] == args["state_sha256"]
        assert CoreMutationLeaseModel.query.get(args["before"].engagement_id) is None
        with pytest.raises(ProviderKeyedPublicationConflict):
            chains.publish_provider_keyed_edge_append(**args)


def test_two_operator_append_attributes_apply_and_host_proof_to_click_actor(
    client, tmp_path, monkeypatch,
):
    from test_provider_keyed_append_source import _pending_atomic_append_writer_case

    with client.application.storage_context():
        chains, args = _pending_atomic_append_writer_case(client, tmp_path, monkeypatch)
        jobs = SqlAlchemyJobRepository()
        parent = args["parent"]
        plan = jobs.get(parent.input["planJobId"])
        assert parent.requested_by == plan.requested_by
        jobs.save(replace(jobs.get(parent.input["applyJobId"]), requested_by="bob"))
        jobs.save(replace(jobs.get(parent.input["hostProofJobId"]), requested_by="bob"))
        at = datetime.now(timezone.utc).isoformat()
        approved = JobEvent(2, "info", "provider append Apply requested", {
            "planJobId": plan.id, "planSha256": plan.events[-1].data["planSha256"],
            "requestedBy": "bob", "requestedAt": at,
        })
        parent = jobs.save(replace(parent, input={
            **parent.input, "applyRequestedBy": "bob",
            "applyRequestedAt": at,
            "applyRequestedPlanSha256": plan.events[-1].data["planSha256"],
        }, events=[parent.events[0], approved, *[
            replace(event, sequence=event.sequence + 1)
            for event in parent.events[1:]]]))
        result = chains.publish_provider_keyed_edge_append(
            **{**args, "parent": parent,
               "expected_event_digest": job_event_digest(parent.events)})
        assert result.edge_count == 2
        assert jobs.get(parent.id).status == "succeeded"


def test_drift_vetoes_row_event_and_lease_release(client):
    with client.application.storage_context():
        chains, args = _case(client)
        chains.save(replace(args["other"], assigned_proxy="proxy02"))
        with pytest.raises(ProviderKeyedPublicationConflict):
            chains.publish_provider_keyed_edge_append(**args)
        assert chains.get("eng-append", "chain-01") == args["before"]
        assert SqlAlchemyJobRepository().get("job-append") == args["parent"]
        assert CoreMutationLeaseModel.query.get("eng-append") is not None


def test_retained_node_identity_change_is_rejected(client):
    with client.application.storage_context():
        chains, args = _case(client)
        bad = replace(args["after"], nodes=[
            {**args["after"].nodes[0], "providerInstanceId": "99"},
            *args["after"].nodes[1:],
        ])
        with pytest.raises(ProviderKeyedPublicationConflict):
            chains.publish_provider_keyed_edge_append(**{**args, "after": bad})
        assert chains.get("eng-append", "chain-01") == args["before"]


def test_retained_node_status_change_is_rejected(client):
    with client.application.storage_context():
        chains, args = _case(client)
        bad = replace(args["after"], nodes=[
            args["after"].nodes[0],
            {**args["after"].nodes[1], "status": "failed"},
            args["after"].nodes[2],
        ])
        with pytest.raises(ProviderKeyedPublicationConflict):
            chains.publish_provider_keyed_edge_append(**{**args, "after": bad})
        assert chains.get("eng-append", "chain-01") == args["before"]


def test_expired_claim_cannot_publish_with_backdated_finished_at(client):
    with client.application.storage_context():
        chains, args = _case(client)
        stale = replace(args["parent"], input={**args["parent"].input,
            "claimExpiresAt": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()})
        SqlAlchemyJobRepository().save(stale)
        with pytest.raises(ProviderKeyedPublicationConflict):
            chains.publish_provider_keyed_edge_append(**{**args, "parent": stale})
        assert chains.get("eng-append", "chain-01") == args["before"]


def test_failed_or_changed_apply_journal_cannot_publish(client):
    with client.application.storage_context():
        chains, args = _case(client)
        child = SqlAlchemyJobRepository().get("job-append-apply")
        SqlAlchemyJobRepository().save(replace(child, status="failed"))
        with pytest.raises(ProviderKeyedPublicationConflict):
            chains.publish_provider_keyed_edge_append(**args)
        assert chains.get("eng-append", "chain-01") == args["before"]
        assert CoreMutationLeaseModel.query.get("eng-append") is not None


@pytest.mark.parametrize("field,value", [
    ("newEdgeAddress", 'digitalocean_droplet.edge["nyc3-99"]'),
    ("planSha256", "0" * 64),
    ("sourceSha256", "0" * 64),
])
def test_changed_real_plan_receipt_cannot_publish_even_with_matching_parent_digest(
    client, field, value,
):
    with client.application.storage_context():
        chains, args = _case(client)
        jobs = SqlAlchemyJobRepository()
        plan = jobs.get("job-append-plan")
        event = replace(plan.events[-1], data={**plan.events[-1].data, field: value})
        changed_plan = jobs.save(replace(plan, events=[event]))
        parent = args["parent"]
        terminal = replace(parent.events[-1], data={**parent.events[-1].data,
            "planJournalSha256": job_event_digest(changed_plan.events)})
        changed_parent = jobs.save(replace(parent, events=[terminal]))
        with pytest.raises(ProviderKeyedPublicationConflict):
            chains.publish_provider_keyed_edge_append(**{
                **args, "parent": changed_parent,
                "expected_event_digest": job_event_digest(changed_parent.events),
            })
        assert chains.get("eng-append", "chain-01") == args["before"]
        assert chains.get("eng-append", "chain-02") == args["other"]
        assert jobs.get(parent.id) == changed_parent
        assert CoreMutationLeaseModel.query.get("eng-append") is not None
