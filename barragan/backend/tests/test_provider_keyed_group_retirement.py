# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network atomic retirement of a shared keyed Sketch provider group."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import EngagementModel
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord,
)
from app.storage.sketch_chain_repository import (
    ProviderKeyedPublicationConflict, SqlAlchemySketchChainRepository, StoredSketchChain,
)
from test_job_repository_keyed_provider_absent import proof as absent_proof, ready_row


def case(client):
    now = datetime.now(timezone.utc)
    earlier = (now - timedelta(minutes=2)).isoformat()
    db.session.add(EngagementModel(id="eng-1", name="opaque", status="deployed",
        owner="operator", template_id="small-dev", active_revision="rev-1",
        input_parameters={}, sketch_state_schema="provider-keyed-v2"))
    db.session.commit()
    repo = SqlAlchemySketchChainRepository()
    chains = []
    ids = {}
    for index in (1, 2):
        middle = str(100 + index)
        edge = str(200 + index)
        ids[f'digitalocean_droplet.middle["chain-{index}"]'] = middle
        ids[f'digitalocean_droplet.edge["chain-{index}"]'] = edge
        chains.append(repo.save(StoredSketchChain(
            chain_id=f"chain-{index}", engagement_id="eng-1", assigned_proxy="proxy01",
            middle_provider="digitalocean", middle_region="nyc3", middle_size="s-1vcpu-1gb",
            edge_provider="digitalocean", edge_region="sfo3", edge_size="s-1vcpu-1gb",
            status="deployed", burned=False, burned_note="", deploy_job_id="job-initial",
            teardown_job_id="", terraform_working_directory="/private/tmp/retained-workspace",
            nodes=[{"providerInstanceId": middle}, {"providerInstanceId": edge}],
            created_at=earlier, updated_at=earlier, edge_count=1,
            edge_intents=[{"id": "edge-01", "provider": "digitalocean",
                           "region": "sfo3", "size": "s-1vcpu-1gb"}],
        )))
    ids["digitalocean_firewall.firewall"] = "11111111-1111-1111-1111-111111111111"
    ids["digitalocean_ssh_key.key"] = "789"
    ids["local_file.ansible_inventory[0]"] = "/private/inventory"
    ids["local_file.ssh_stanza[0]"] = "/private/ssh-stanza"
    jobs = SqlAlchemyJobRepository()
    ready = ready_row()
    ready = replace(ready, id="job-coordinator", input={**ready.input,
        "coreJobId": "job-core", "corePlanId": "plan-core",
        "teardownParentId": "job-parent"},
        events=[*ready.events[:3], replace(ready.events[3],
            data={"corePlanId": "plan-core"}), ready.events[4]])
    ready = replace(ready, events=[*ready.events[:4], replace(ready.events[4],
        data={**ready.events[4].data,
              "sourceJournalSha256": job_event_digest(ready.events[:4])})])
    absent = {**absent_proof(ready),
        "applyJobId": "job-provider-keyed-initial-destroy-apply-core",
        "resourceIdsSha256": _fingerprint(ids),
        "verifiedAbsentDropletIds": sorted(("101", "102", "201", "202")),
        "verifiedAbsentFirewallId": ids["digitalocean_firewall.firewall"],
        "verifiedAbsentSshKeyId": ids["digitalocean_ssh_key.key"],
        "observedAt": datetime.now(timezone.utc).isoformat()}
    child = jobs.save(replace(ready, input={**ready.input, "phase": "provider_absent"},
        events=[*ready.events, JobEvent(6, "info", "provider_absent", absent)]))
    jobs.save(StoredJobRun(
        id="job-provider-keyed-initial-destroy-apply-core",
        action="provider_keyed_initial_destroy_apply", status="succeeded",
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        requested_by="operator", input={"mutation": True}, artifact_refs=[],
        created_at=earlier, started_at=earlier, finished_at=earlier,
        events=[JobEvent(1, "info", "provider destroy apply succeeded", {})],
    ))
    completed = datetime.now(timezone.utc)
    proof = {
        "scopeSnapshotId": "a" * 64, "providerScopeSha256": "b" * 64,
        "sourceJournalSha256": job_event_digest(child.events),
        "applyJobId": "job-provider-keyed-initial-destroy-apply-core",
        "resourceIdsSha256": _fingerprint(ids),
        "verifiedAbsentDropletIds": sorted(("101", "201", "102", "202")),
        "verifiedAbsentFirewallId": ids["digitalocean_firewall.firewall"],
        "verifiedAbsentSshKeyId": ids["digitalocean_ssh_key.key"],
        "confirmationCompletedAt": completed.isoformat(),
        "confirmationExpiresAt": (completed + timedelta(seconds=30)).isoformat(),
    }
    return repo, jobs, child, tuple(chains), ids, proof


def publish(repo, child, chains, ids, proof, authority=lambda: None, records=()):
    return repo.publish_provider_keyed_group_retired(
        coordinator=child, prior_chains=chains, prior_records=records,
        group_apply_job_id=proof["applyJobId"], resource_ids=ids,
        proof=proof, authority=authority)


def test_group_retirement_updates_both_rows_once_preserving_desired_state(client):
    with client.application.storage_context():
        repo, jobs, child, chains, ids, proof = case(client)
        retired = publish(repo, child, chains, ids, proof)
        assert [row.status for row in retired] == ["destroyed", "destroyed"]
        for before, after in zip(chains, retired, strict=True):
            assert after.nodes == []
            assert after.teardown_job_id == proof["applyJobId"]
            assert after.deploy_job_id == before.deploy_job_id
            assert after.terraform_working_directory == before.terraform_working_directory
            assert after.edge_intents == before.edge_intents
            assert after.assigned_proxy == before.assigned_proxy
        saved = jobs.get(child.id)
        assert saved.input["phase"] == "group_retired"
        assert saved.events[-1].message == "keyed_provider_group_retired"
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, chains, ids, proof)
        assert jobs.get(child.id) == saved
        from app.services.sketch_chains import refresh_sketch_chain_from_job
        for row in retired:
            refreshed = refresh_sketch_chain_from_job(
                "eng-1", row.chain_id, repository=repo, job_repository=jobs)
            assert refreshed["sketchChain"]["status"] == "destroyed"
            assert refreshed["sketchChain"]["nodes"] == []
            assert repo.get("eng-1", row.chain_id) == row


def test_authority_crash_rolls_back_both_chains_and_event(client):
    with client.application.storage_context():
        repo, jobs, child, chains, ids, proof = case(client)
        with pytest.raises(RuntimeError, match="crash"):
            publish(repo, child, chains, ids, proof,
                    authority=lambda: (_ for _ in ()).throw(RuntimeError("crash")))
        assert jobs.get(child.id) == child
        assert tuple(repo.get("eng-1", row.chain_id) for row in chains) == chains
        assert all(row.status == "destroyed" for row in publish(
            repo, child, chains, ids, proof))


def test_chain_drift_vetoes_all_rows(client):
    with client.application.storage_context():
        repo, jobs, child, chains, ids, proof = case(client)
        repo.save(replace(chains[0], assigned_proxy="proxy02"))
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, chains, ids, proof)
        assert jobs.get(child.id) == child
        assert repo.get("eng-1", chains[1].chain_id) == chains[1]


def _record(*, record_id, resource_type, resource_id, owned, inspector=False):
    moment = datetime.now(timezone.utc).isoformat()
    metadata = {"barraganOwned": True} if owned else {}
    if inspector:
        metadata = {"barraganOwned": True, "role": "inspector"}
    return StoredProviderResourceRecord(
        id=record_id, engagement_id="eng-1", engagement_name="opaque",
        provider="digitalocean", resource_type=resource_type,
        resource_id=resource_id, name="opaque", region="nyc3",
        lifecycle_state="active", status="active",
        source="barragan" if owned else "provider_inventory", metadata=metadata,
        adoption_job_id="job-initial", adopted_at=moment, updated_at=moment,
    )


def test_owned_exact_record_retires_but_inspector_remains(client):
    with client.application.storage_context():
        repo, jobs, child, chains, ids, proof = case(client)
        resources = SqlAlchemyProviderResourceRepository()
        owned = resources.save(_record(record_id="owned-middle", resource_type="droplet",
                                       resource_id="101", owned=True))
        inspector = resources.save(_record(record_id="inspector", resource_type="inspector",
                                           resource_id="999", owned=True, inspector=True))
        rows = tuple(sorted((owned, inspector), key=lambda row: row.id))
        publish(repo, child, chains, ids, proof, records=rows)
        assert resources.get(owned.id).status == "destroyed"
        assert resources.get(inspector.id) == inspector
        assert jobs.get(child.id).events[-1].data["retiredRecordIds"] == [owned.id]


def test_unmanaged_record_blocks_group_retirement(client):
    with client.application.storage_context():
        repo, jobs, child, chains, ids, proof = case(client)
        resources = SqlAlchemyProviderResourceRepository()
        manual = resources.save(_record(record_id="manual", resource_type="droplet",
                                        resource_id="101", owned=False))
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, chains, ids, proof, records=(manual,))
        assert resources.get(manual.id) == manual
        assert jobs.get(child.id) == child
        assert tuple(repo.get("eng-1", row.chain_id) for row in chains) == chains


def test_repository_rejects_synthetic_or_corrupt_prior_absence(client):
    with client.application.storage_context():
        repo, jobs, child, chains, ids, proof = case(client)
        synthetic = replace(child, events=[JobEvent(1, "info", "ready", {}),
            JobEvent(2, "info", "provider_absent", {})])
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, synthetic, chains, ids, proof)
        corrupt = replace(child, events=[*child.events[:-1], replace(child.events[-1],
            data={**child.events[-1].data, "verifiedAbsentSshKeyId": "999"})])
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, corrupt, chains, ids, proof)
        assert jobs.get(child.id) == child
        assert tuple(repo.get("eng-1", row.chain_id) for row in chains) == chains

@pytest.mark.parametrize("active_extra", [False, True])
def test_retirement_preserves_only_inert_aborted_history(client, active_extra):
    with client.application.storage_context():
        repo, jobs, child, chains, ids, proof = case(client)
        ghost = repo.save(replace(chains[0], chain_id="old-aborted",
            status="deployed" if active_extra else "aborted", burned=False,
            deploy_job_id="", teardown_job_id="",
            terraform_working_directory="", nodes=[]))
        if active_extra:
            with pytest.raises(ProviderKeyedPublicationConflict):
                publish(repo, child, chains, ids, proof)
            assert tuple(repo.get("eng-1", row.chain_id) for row in chains) == chains
            assert jobs.get(child.id) == child
        else:
            retired = publish(repo, child, chains, ids, proof)
            assert all(row.status == "destroyed" for row in retired)
        assert repo.get("eng-1", ghost.chain_id) == ghost
