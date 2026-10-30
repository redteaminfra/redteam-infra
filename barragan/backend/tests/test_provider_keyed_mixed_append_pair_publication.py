# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private paired publication updates both chains or neither one."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app.domain import JobEvent
from app.services.provider_keyed_mixed_append_pair_host_proof import SixNodeHostSource
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel, EngagementModel
from app.storage.sketch_chain_repository import (
    ProviderKeyedPublicationConflict, SqlAlchemySketchChainRepository,
    StoredSketchChain,
)


def _node(chain, provider, role, number, *, ordinal=1):
    row = {
        "chainId": chain, "provider": provider, "role": role,
        "hostname": f"host-{number}", "terraformAddress": f'{provider}_instance.{role}["{number}"]',
        "providerInstanceId": str(number), "publicIp": f"8.8.8.{number}",
        "region": "region-1", "status": "deployed", "componentId": (
            "middle" if role == "middle" else f"edge-{ordinal:02d}"),
        "assignedProxy": "proxy01", "proxy": "proxy01",
    }
    if role == "edge":
        row.update(edgeId=f"edge-{ordinal:02d}", edgeIndex=str(ordinal),
                   edgeCount=str(ordinal))
    return row


def _case(client, monkeypatch, order):
    now = datetime.now(timezone.utc)
    before_at = (now - timedelta(minutes=2)).isoformat()
    # save() stamps persisted rows after ``now``; the publication time follows.
    finished_at = (now + timedelta(seconds=10)).isoformat()
    expiry = (now + timedelta(minutes=30)).isoformat()
    engagement = "eng-six"
    parent_id = "job-provider-keyed-mixed-append-core"
    db.session.add(EngagementModel(
        id=engagement, name="opaque", status="deployed", owner="operator",
        template_id="small-dev", active_revision="rev-1", input_parameters={},
        sketch_state_schema="provider-keyed-v2"))
    db.session.commit()
    repo, jobs = SqlAlchemySketchChainRepository(), SqlAlchemyJobRepository()
    by_middle, after_by_middle = {}, {}
    for provider, number in (("linode", 1), ("digitalocean", 3)):
        chain_id = f"chain-{provider}"
        before = repo.save(StoredSketchChain(
            chain_id=chain_id, engagement_id=engagement, assigned_proxy="proxy01",
            middle_provider=provider, middle_region="region-1", middle_size="small",
            edge_provider=provider, edge_region="region-1", edge_size="small",
            status="deployed", burned=False, burned_note="",
            deploy_job_id="job-original", teardown_job_id="",
            terraform_working_directory=f"/private/tmp/{provider}-workspace",
            nodes=[_node(chain_id, provider, "middle", number),
                   _node(chain_id, provider, "edge", number + 1)],
            created_at=before_at, updated_at=before_at, edge_count=1,
            edge_intents=[{"id": "edge-01", "provider": provider,
                           "region": "region-1", "size": "small"}],
        ))
        by_middle[provider] = before
    after_by_middle["linode"] = replace(
        by_middle["linode"], edge_count=2, updated_at=finished_at,
        edge_intents=[*by_middle["linode"].edge_intents,
                      {"id": "edge-02", "provider": "digitalocean",
                       "region": "region-1", "size": "small"}],
        nodes=[by_middle["linode"].nodes[0],
               {**by_middle["linode"].nodes[1], "edgeCount": "2"},
               _node("chain-linode", "digitalocean", "edge", 5, ordinal=2)],
    )
    after_by_middle["digitalocean"] = replace(
        by_middle["digitalocean"], edge_count=2, updated_at=finished_at,
        edge_intents=[*by_middle["digitalocean"].edge_intents,
                      {"id": "edge-02", "provider": "linode",
                       "region": "region-1", "size": "small"}],
        nodes=[by_middle["digitalocean"].nodes[0],
               {**by_middle["digitalocean"].nodes[1], "edgeCount": "2"},
               _node("chain-digitalocean", "linode", "edge", 6, ordinal=2)],
    )
    chain_order = tuple("chain-digitalocean" if provider == "linode"
                        else "chain-linode" for provider in order)
    before = tuple(by_middle["digitalocean"] if provider == "linode"
                   else by_middle["linode"] for provider in order)
    after = tuple(after_by_middle["digitalocean"] if provider == "linode"
                  else after_by_middle["linode"] for provider in order)
    parent = jobs.save(StoredJobRun(
        id=parent_id, action="provider_keyed_mixed_append", status="running",
        target=f"engagement:{engagement}", target_type="engagement",
        target_id=engagement, requested_by="operator", input={
            "schema": "mixed-append-pair-parent-v1", "phase": "apply_sealed",
            "engagementId": engagement, "coreJobId": "job-core",
            "corePlanId": "plan-core", "providerOrder": list(order),
            "chainOrder": list(chain_order), "reviewSha256": "a" * 64,
            "mutation": True, "claimOwner": "writer", "claimToken": "token",
            "claimClaimedAt": before_at, "claimExpiresAt": expiry},
        artifact_refs=[], created_at=before_at, started_at=before_at,
        finished_at=None, events=[JobEvent(
            1, "info", "mixed append pair approved",
            {"reviewSha256": "a" * 64})],
    ))
    provider_children = {}
    for index, provider in enumerate(order):
        name = "first" if index == 0 else "second"
        child_id = (f"job-provider-keyed-mixed-append-apply-{name}-"
                    f"{parent_id.removeprefix('job-')}")
        prefix = f"mixed append {name}"
        events = [JobEvent(i, "info", f"{prefix} event {i}", {})
                  for i in range(1, 9)]
        events.append(JobEvent(9, "info", f"{prefix} exact poststate proved",
                               {"reviewSha256": "a" * 64}))
        events.append(JobEvent(10, "info", f"{prefix} provider Apply succeeded",
                               {"proofJournalSha256": job_event_digest(events)}))
        provider_children[provider] = jobs.save(StoredJobRun(
            child_id, "provider_keyed_mixed_append_apply_child" if index == 0
            else "provider_keyed_mixed_append_second_apply_child", "succeeded",
            parent.target, parent.target_type, parent.target_id, parent.requested_by,
            {}, [], before_at, before_at, finished_at, events,
        ))
    host = jobs.save(StoredJobRun(
        "job-provider-keyed-mixed-append-host-proof-core",
        "provider_keyed_mixed_append_pair_host_proof", "succeeded",
        parent.target, parent.target_type, parent.target_id, parent.requested_by,
        {}, [], before_at, before_at, finished_at,
        [JobEvent(1, "info", "six hosts proved", {})],
    ))
    db.session.add(CoreMutationLeaseModel(
        engagement_id=engagement, owner_id="plan-core",
        operation="provider_keyed_mixed_append"))
    db.session.commit()
    proof_digests = {provider: job_event_digest(child.events)
                     for provider, child in provider_children.items()}
    source = SixNodeHostSource(
        parent.id, engagement, "job-core", "plan-core", order, chain_order,
        before, after, tuple(chain.nodes[2]["terraformAddress"] for chain in after),
        tuple(proof_digests[provider] for provider in order),
        ("b" * 64, "c" * 64), ("/private/tmp/a", "/private/tmp/b"),
        ("rev-a", "rev-b"),
        ("8.8.8.7", "8.8.8.9"), "/private/tmp/core-known-hosts", "f" * 64,
    )
    receipt = SimpleNamespace(
        source_sha256=source.source_sha256,
        child_event_sha256=job_event_digest(host.events),
        claim_owner="writer", claim_token="token")
    import app.services.provider_keyed_mixed_append_pair_host_proof as host_module
    calls = []
    monkeypatch.setattr(host_module, "validate_six_host_receipt_child",
                        lambda _parent, _child, _receipt, *, source:
                        calls.append(source.source_sha256), raising=False)
    def local_fence(selected):
        assert selected is source
        calls.append(("local fence", db.session().in_transaction()))
        return selected.source_sha256

    args = dict(
        parent=parent, before_chains=before, after_chains=after,
        provider_proof_children=provider_children, host_proof_child=host,
        receipt=receipt,
        expected_parent_event_digest=job_event_digest(parent.events),
        expected_provider_event_digests=proof_digests,
        expected_host_event_digest=job_event_digest(host.events),
        claim_owner="writer", claim_token="token", finished_at=finished_at,
        fresh_source=lambda: calls.append(("fresh GET", db.session().in_transaction())) or source,
        local_fence=local_fence,
    )
    return repo, jobs, args, calls


@pytest.mark.parametrize('drift', [None, 'reversed', 'future', 'malformed', 'fresh_source'])
@pytest.mark.parametrize('order', [('digitalocean', 'linode'), ('linode', 'digitalocean')])
def test_sql_parent_start_projection_timestamp_is_compared_as_utc(client, monkeypatch, order, drift):
    from app.services.provider_keyed_mixed_append_six_source import project_mixed_append_six_chains
    with client.application.storage_context():
        repo, jobs, args, _ = _case(client, monkeypatch, order)
        parent = args['parent']
        intents, selected, requests, proofs = {}, {}, {}, {}
        for provider, before, after in zip(order, args['before_chains'], args['after_chains'], strict=True):
            node = after.nodes[2]
            middle_key = 'linode_middle' if provider == 'digitalocean' else 'digitalocean_middle'
            intents[provider] = {
                middle_key + '_address': before.nodes[0]['terraformAddress'],
                middle_key + '_id': before.nodes[0]['providerInstanceId'],
                'new_edge_address': node['terraformAddress'], 'new_edge': {
                    'name' if provider == 'digitalocean' else 'label': node['hostname'],
                    'size' if provider == 'digitalocean' else 'node_type': 'small',
                    'region': node['region']}}
            selected[provider] = before.nodes[0]['terraformAddress']
            requests[provider] = {'edgeRegion': node['region'],
                'edgeSize' if provider == 'digitalocean' else 'edgeType': 'small'}
            proofs[provider] = dict(provider=provider, newEdgeAddress=node['terraformAddress'],
                newEdgeProviderId=node['providerInstanceId'], newEdgePublicIp=node['publicIp'])
        # Exercise SQL's actual aware→naive conversion and the real projector.
        parent = jobs.save(replace(parent, started_at=datetime.now(timezone.utc).isoformat(),
            input={**parent.input, 'intents': intents, 'selectedMiddles': selected, 'reviewRequest': requests}))
        assert datetime.fromisoformat(parent.started_at).tzinfo is None
        after = project_mixed_append_six_chains(parent, args['before_chains'], proofs)
        assert all(chain.updated_at == parent.started_at for chain in after)
        if drift in ('reversed', 'future', 'malformed'):
            if drift == 'reversed':
                value = (datetime.fromisoformat(args['before_chains'][0].updated_at) - timedelta(seconds=1)).isoformat()
            elif drift == 'future':
                value = (datetime.fromisoformat(args['finished_at']) + timedelta(seconds=1)).replace(tzinfo=None).isoformat()
            else: value = 'not-a-time'
            after = (replace(after[0], updated_at=value), after[1])
        original = args['fresh_source']()
        source = replace(original, chains=after)
        digest = source.source_sha256
        receipt = SimpleNamespace(**{**vars(args['receipt']), 'source_sha256': digest})
        args.update(parent=parent, after_chains=after, receipt=receipt,
                    fresh_source=lambda: source, local_fence=lambda _: digest)
        if drift == 'fresh_source':
            args['fresh_source'] = lambda: replace(source, chains=(
                replace(after[0], updated_at=after[0].updated_at + '+00:00'), after[1]))
        if drift:
            with pytest.raises(ProviderKeyedPublicationConflict):
                repo.publish_provider_keyed_mixed_append_pair(**args)
            assert jobs.get(parent.id).status == 'running'
            assert tuple(repo.get(parent.target_id, row.chain_id) for row in args['before_chains']) == args['before_chains']
        else:
            repo.publish_provider_keyed_mixed_append_pair(**args)
            assert jobs.get(parent.id).status == 'succeeded'
        assert source.source_sha256 == digest
        assert tuple(chain.updated_at for chain in source.chains) == tuple(chain.updated_at for chain in after)


@pytest.mark.parametrize("order", [
    ("digitalocean", "linode"), ("linode", "digitalocean")])
def test_pair_publishes_once_after_fresh_source_under_writer_slot(client, monkeypatch, order):
    with client.application.storage_context():
        repo, jobs, args, calls = _case(client, monkeypatch, order)
        ghost = repo.save(replace(args["before_chains"][0], chain_id="old-aborted",
            status="aborted", burned=False, deploy_job_id="", teardown_job_id="",
            terraform_working_directory="", nodes=[]))
        db.session.rollback()
        rows = repo.publish_provider_keyed_mixed_append_pair(**args)
        assert repo.get("eng-six", ghost.chain_id) == ghost
        assert [row.edge_count for row in rows] == [2, 2]
        assert [row.nodes for row in rows] == [chain.nodes for chain in args["after_chains"]]
        assert jobs.get(args["parent"].id).status == "succeeded"
        assert jobs.get(args["parent"].id).input["phase"] == "completed"
        assert calls == [("fresh GET", False), ("local fence", True),
                         args["receipt"].source_sha256]
        published_event = jobs.get(args["parent"].id).events[-1]
        source = args["fresh_source"]()
        source_snapshot = json.loads(json.dumps(asdict(source)))
        assert published_event.message == "mixed append six-node generation published"
        assert published_event.data == {
            "sourceSha256": source.source_sha256,
            "source": source_snapshot,
            "hostProofJournalSha256": args["expected_host_event_digest"],
            "providerProofJournalSha256": args["expected_provider_event_digests"],
            "chainIds": list(source.chain_ids),
        }
        assert hashlib.sha256(json.dumps(
            published_event.data["source"], sort_keys=True,
            separators=(",", ":")).encode()).hexdigest() == source.source_sha256
        assert published_event.data["source"]["before_chains"] != (
            published_event.data["source"]["chains"])
        assert CoreMutationLeaseModel.query.get("eng-six") is None
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_mixed_append_pair(**args)


def test_second_row_failure_rolls_back_both_rows_parent_and_lease(client, monkeypatch):
    with client.application.storage_context():
        repo, jobs, args, _ = _case(client, monkeypatch,
                                   ("digitalocean", "linode"))
        db.session.execute(text("""
            CREATE TRIGGER block_second_six BEFORE UPDATE ON sketch_chains
            WHEN NEW.chain_id = 'chain-digitalocean'
            BEGIN SELECT RAISE(ABORT, 'injected failure'); END
        """))
        db.session.commit()
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_mixed_append_pair(**args)
        assert tuple(repo.get("eng-six", row.chain_id)
                     for row in args["before_chains"]) == args["before_chains"]
        assert jobs.get(args["parent"].id).status == "running"
        assert jobs.get(args["parent"].id).events == args["parent"].events
        assert CoreMutationLeaseModel.query.get("eng-six") is not None


@pytest.mark.parametrize("drift", [
    "parent", "provider", "host", "lease", "row", "source", "projection",
    "local"])
def test_drift_never_publishes_or_releases_lease(client, monkeypatch, drift):
    with client.application.storage_context():
        repo, jobs, args, _ = _case(client, monkeypatch,
                                   ("digitalocean", "linode"))
        if drift == "parent":
            db.session.execute(text("""
                UPDATE job_events SET message = 'changed' WHERE job_id = :id
            """), {"id": args["parent"].id})
            db.session.commit()
        elif drift == "provider":
            child = args["provider_proof_children"]["linode"]
            db.session.execute(text("""
                UPDATE job_events SET message = 'changed' WHERE job_id = :id
                AND sequence = 9
            """), {"id": child.id})
            db.session.commit()
        elif drift == "host":
            db.session.execute(text("""
                UPDATE job_events SET message = 'changed' WHERE job_id = :id
            """), {"id": args["host_proof_child"].id})
            db.session.commit()
        elif drift == "lease":
            lease = CoreMutationLeaseModel.query.get("eng-six")
            lease.operation = "changed"
            db.session.commit()
        elif drift == "row":
            db.session.execute(text("""
                UPDATE sketch_chains SET assigned_proxy = 'changed'
                WHERE chain_id = 'chain-linode'
            """))
            db.session.commit()
        elif drift == "source":
            source = args["fresh_source"]()
            args["fresh_source"] = lambda: replace(source,
                provider_proof_digests=("0" * 64, source.provider_proof_digests[1]))
        elif drift == "local":
            args["local_fence"] = lambda _source: "0" * 64
        else:
            after = list(args["after_chains"])
            after[0] = replace(after[0], nodes=[*after[0].nodes[:2],
                {**after[0].nodes[2], "providerInstanceId": "changed"}])
            args["after_chains"] = tuple(after)
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_mixed_append_pair(**args)
        assert [repo.get("eng-six", row.chain_id).edge_count
                for row in args["before_chains"]] == [1, 1]
        assert jobs.get(args["parent"].id).status == "running"
        if drift != "lease":
            assert CoreMutationLeaseModel.query.get("eng-six") is not None
