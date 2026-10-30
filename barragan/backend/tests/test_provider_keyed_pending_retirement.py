# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted, no-network pending keyed group retirement contract."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services import provider_keyed_pending_retirement as service
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.job_repository import job_event_digest
from app.storage.models import SketchChainModel
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord,
)
from app.storage.sketch_chain_repository import ProviderKeyedPublicationConflict
from test_provider_keyed_group_retirement import case
from test_job_repository_keyed_provider_absent import ready_row, proof as absent_proof
from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint


def pending_case(client):
    repo, jobs, child, original, ids, proof = case(client)
    rows = tuple(repo.save(replace(row, status="pending", nodes=[], deploy_job_id="",
                                   terraform_working_directory="")) for row in original)
    fingerprints = {row.chain_id: sketch_chain_intent_fingerprint(row) for row in rows}
    return repo, jobs, child, rows, ids, proof, fingerprints


def publish(repo, child, rows, ids, proof, fingerprints, *, records=(),
            all_rows=None, authority=lambda: None):
    return repo.publish_provider_keyed_pending_group_retired(
        coordinator=child, prior_chains=rows,
        prior_all_chains=tuple(rows if all_rows is None else all_rows),
        prior_records=records,
        group_apply_job_id=proof["applyJobId"], resource_ids=ids,
        chain_fingerprints=fingerprints, proof=proof, authority=authority,
        allowed_record_origins=frozenset({"job-provider-keyed-initial-apply-core"}),
    )


def test_pending_group_retirement_persists_both_rows_and_history(client):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        result = publish(repo, child, rows, ids, proof, fingerprints)
        assert len(result) == 2
        for before, after in zip(rows, result, strict=True):
            assert after.status == "destroyed"
            assert after.nodes == []
            assert after.deploy_job_id == ""
            assert after.teardown_job_id == proof["applyJobId"]
            assert after.edge_intents == before.edge_intents
            assert after.assigned_proxy == before.assigned_proxy
            assert sketch_chain_intent_fingerprint(after) == fingerprints[after.chain_id]
        saved = jobs.get(child.id)
        assert saved.input["phase"] == "pending_group_retired"
        assert saved.events[-1].message == "keyed_pending_provider_group_retired"
        assert saved.events[-1].data["chainFingerprints"] == fingerprints
        db.session.remove()  # A new ORM session must recognize committed rows.
        reopened = SqlAlchemyJobRepository().get(child.id)
        assert reopened.events[-1] == saved.events[-1]
        assert [repo.get("eng-1", row.chain_id).status for row in rows] == [
            "destroyed", "destroyed"]
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, rows, ids, proof, fingerprints)
        from app.services.sketch_chains import refresh_sketch_chain_from_job
        for after in result:
            assert refresh_sketch_chain_from_job(
                "eng-1", after.chain_id, repository=repo, job_repository=jobs,
            )["sketchChain"]["status"] == "destroyed"
            assert repo.get("eng-1", after.chain_id) == after


def test_pending_retirement_preserves_exact_inert_aborted_plan_row(client):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        abandoned = repo.save(replace(
            rows[0], chain_id="proxy01-aborted-plan-01", status="aborted",
            burned=False, burned_note="", nodes=[], deploy_job_id="",
            teardown_job_id="", terraform_working_directory="",
        ))
        retired = publish(repo, child, rows, ids, proof, fingerprints,
                          all_rows=(*rows, abandoned))
        assert [row.status for row in retired] == ["destroyed", "destroyed"]
        assert repo.get("eng-1", abandoned.chain_id) == abandoned
        assert jobs.get(child.id).events[-1].data["chainIds"] == sorted(
            row.chain_id for row in rows)


@pytest.mark.parametrize("drift", ["changed_aborted", "active_extra", "unlisted_extra"])
def test_pending_retirement_rejects_extra_row_drift_atomically(client, drift):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        abandoned = repo.save(replace(
            rows[0], chain_id="proxy01-aborted-plan-01", status="aborted",
            burned=False, burned_note="", nodes=[], deploy_job_id="",
            teardown_job_id="", terraform_working_directory="",
        ))
        snapshot = (*rows, abandoned)
        if drift == "changed_aborted":
            abandoned = repo.save(replace(abandoned, middle_size="s-2vcpu-2gb"))
        elif drift == "active_extra":
            abandoned = repo.save(replace(abandoned, status="pending"))
            snapshot = (*rows, abandoned)
        else:
            snapshot = rows
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, rows, ids, proof, fingerprints, all_rows=snapshot)
        assert jobs.get(child.id) == child
        assert tuple(repo.get("eng-1", row.chain_id) for row in rows) == rows
        assert repo.get("eng-1", abandoned.chain_id) == abandoned


def test_callback_failure_and_second_row_drift_roll_back_everything(client):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        with pytest.raises(RuntimeError, match="crash"):
            publish(repo, child, rows, ids, proof, fingerprints,
                    authority=lambda: (_ for _ in ()).throw(RuntimeError("crash")))
        assert jobs.get(child.id) == child
        assert tuple(repo.get("eng-1", row.chain_id) for row in rows) == rows
        second = rows[1]
        repo.save(replace(second, assigned_proxy="proxy02"))
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, rows, ids, proof, fingerprints)
        assert jobs.get(child.id) == child
        assert repo.get("eng-1", rows[0].chain_id) == rows[0]
        assert repo.get("eng-1", second.chain_id).status == "pending"


def test_unmanaged_or_wrong_origin_record_vetoes_all_rows(client):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        resources = SqlAlchemyProviderResourceRepository()
        now = datetime.now(timezone.utc).isoformat()
        base = StoredProviderResourceRecord(
            id="record-1", engagement_id="eng-1", engagement_name="opaque",
            provider="digitalocean", resource_type="droplet", resource_id="101",
            name="opaque", region="nyc3", lifecycle_state="active", status="active",
            source="provider_inventory", metadata={"barraganOwned": False},
            adoption_job_id="job-provider-keyed-initial-apply-core", adopted_at=now,
            updated_at=now,
        )
        unmanaged = resources.save(base)
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, rows, ids, proof, fingerprints, records=(unmanaged,))
        owned_wrong_origin = resources.save(replace(
            base, source="barragan", metadata={"barraganOwned": True},
            adoption_job_id="other-job"))
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, rows, ids, proof, fingerprints,
                    records=(owned_wrong_origin,))
        assert jobs.get(child.id) == child
        assert tuple(repo.get("eng-1", row.chain_id) for row in rows) == rows
        assert resources.get("record-1") == owned_wrong_origin


def test_exact_owned_record_retires_with_pending_group(client):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        resources = SqlAlchemyProviderResourceRepository()
        now = datetime.now(timezone.utc).isoformat()
        owned = resources.save(StoredProviderResourceRecord(
            id="record-1", engagement_id="eng-1", engagement_name="opaque",
            provider="digitalocean", resource_type="droplet", resource_id="101",
            name="opaque", region="nyc3", lifecycle_state="active", status="active",
            source="barragan", metadata={"barraganOwned": True},
            adoption_job_id="job-provider-keyed-initial-apply-core", adopted_at=now,
            updated_at=now,
        ))
        retired = publish(repo, child, rows, ids, proof, fingerprints, records=(owned,))
        assert [row.status for row in retired] == ["destroyed", "destroyed"]
        assert resources.get(owned.id).status == "destroyed"
        assert jobs.get(child.id).events[-1].data["retiredRecordIds"] == [owned.id]


def test_droplet_claiming_inspector_role_cannot_escape_pending_retirement(client):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        resources = SqlAlchemyProviderResourceRepository()
        now = datetime.now(timezone.utc).isoformat()
        forged = resources.save(StoredProviderResourceRecord(
            id="digitalocean:inspector:999", engagement_id="eng-1",
            engagement_name="opaque", provider="digitalocean", resource_type="droplet",
            resource_id="999", name="opaque", region="nyc3",
            lifecycle_state="active", status="active", source="barragan_inspector_job",
            metadata={"barraganOwned": True, "role": "inspector",
                      "inspectionJobId": "job-inspector"},
            adoption_job_id="job-inspector", adopted_at=now, updated_at=now,
        ))
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, rows, ids, proof, fingerprints, records=(forged,))
        assert resources.get(forged.id) == forged
        assert jobs.get(child.id) == child
        assert tuple(repo.get("eng-1", row.chain_id) for row in rows) == rows


def test_expired_exact_id_confirmation_does_not_retire(client):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        old = datetime.now(timezone.utc) - timedelta(minutes=2)
        stale = {**proof, "confirmationCompletedAt": old.isoformat(),
                 "confirmationExpiresAt": (old + timedelta(seconds=30)).isoformat()}
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, rows, ids, stale, fingerprints)
        assert jobs.get(child.id) == child
        assert tuple(repo.get("eng-1", row.chain_id) for row in rows) == rows


def test_transaction_detects_changed_row_after_snapshot_even_when_same_identity(client):
    with client.application.storage_context():
        repo, jobs, child, rows, ids, proof, fingerprints = pending_case(client)
        raw = db.session.query(SketchChainModel).filter_by(
            engagement_id="eng-1", chain_id=rows[1].chain_id).one()
        raw.middle_size = "s-2vcpu-2gb"
        db.session.commit()
        with pytest.raises(ProviderKeyedPublicationConflict):
            publish(repo, child, rows, ids, proof, fingerprints)
        assert jobs.get(child.id) == child
        assert repo.get("eng-1", rows[0].chain_id) == rows[0]


def test_service_requires_get_before_pending_commit_and_rechecks_drift(tmp_path, monkeypatch):
    from test_provider_keyed_group_retirement_service import setup

    parent, child, jobs, _chains, current, calls, opts, read = setup(tmp_path, monkeypatch)
    for row in current:
        row.status = "pending"
        row.nodes = []
        row.deploy_job_id = ""
        row.terraform_working_directory = ""
        row.engagement_id = "eng-1"
        row.assigned_proxy = "proxy01"
        row.middle_provider = row.edge_provider = "digitalocean"
        row.middle_region = "nyc3"
        row.edge_region = "sfo3"
        row.middle_size = row.edge_size = "s-1vcpu-1gb"
        row.edge_count = 1
        row.edge_intents = [{"id": "edge-01", "provider": "digitalocean",
                             "region": "sfo3", "size": "s-1vcpu-1gb"}]
    bound = read()
    bound.scope["chainFingerprints"] = {
        row.chain_id: sketch_chain_intent_fingerprint(row) for row in current}
    child = replace(child, input={**child.input, "coreJobId": bound.core.id,
                    "corePlanId": bound.core.input["corePlanId"],
                    "teardownParentId": parent.id,
                    "scopeSnapshotId": parent.input["scopeSnapshot"]["snapshotId"],
                    "providerScopeSha256": parent.input["scopeSnapshot"]["providerScopeSha256"]})
    jobs.rows[child.id] = child
    monkeypatch.setattr(service, "recognize_provider_keyed_destroy_absence",
                        lambda *_args, **_kwargs: jobs.get(child.id))
    monkeypatch.setattr(service, "_boundary", lambda *_args, **_kwargs: read())

    class PendingChains:
        publications = 0

        def list_for_engagement(self, _engagement_id):
            return list(current)

        def publish_provider_keyed_pending_group_retired(self, *, coordinator, authority, **kwargs):
            jobs.rows[coordinator.id] = replace(
                coordinator, input={**coordinator.input, "phase": "pending_group_retired"})
            try:
                authority()
            except Exception:
                jobs.rows[coordinator.id] = coordinator
                raise
            self.publications += 1
            return tuple(SimpleNamespace(**{**vars(row), "status": "destroyed",
                         "teardown_job_id": kwargs["group_apply_job_id"]})
                         for row in kwargs["prior_chains"])

    chains = PendingChains()
    opts["sketch_repository"] = chains
    rows = service.retire_pending_keyed_group_after_absence(parent.id, **opts)
    assert calls == ["GET"] and chains.publications == 1
    assert [row.status for row in rows] == ["destroyed", "destroyed"]
    assert all(row.deploy_job_id == "" for row in rows)

    # A second pending transition cannot re-arm the successful destroy.
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.retire_pending_keyed_group_after_absence(parent.id, **opts)
    assert calls == ["GET"] and chains.publications == 1

    jobs.rows[child.id] = child
    chains.publications = 0
    original_get = opts["absence_preflight"]

    def drift(*args, **kwargs):
        evidence = original_get(*args, **kwargs)
        current[1] = SimpleNamespace(**{**vars(current[1]), "edge_region": "nyc3"})
        return evidence

    opts["absence_preflight"] = drift
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.retire_pending_keyed_group_after_absence(parent.id, **opts)
    assert chains.publications == 0

    current[1] = SimpleNamespace(**{**vars(current[1]), "edge_region": "sfo3"})
    started = datetime.now(timezone.utc)
    instants = iter((started, started + timedelta(seconds=31)))
    opts["absence_preflight"] = original_get
    opts["now"] = lambda: next(instants)
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.retire_pending_keyed_group_after_absence(parent.id, **opts)
    assert chains.publications == 0


def test_restart_recognizer_accepts_only_same_historic_prefix(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    monkeypatch.setattr(service, "_default_state_root", lambda: root)
    original = ready_row()
    preview = SimpleNamespace(id="preview-1", events=[JobEvent(1, "info", "preview", {})])
    applied = SimpleNamespace(id="apply-1", events=[JobEvent(1, "info", "apply", {})])
    ids = {f'digitalocean_droplet.middle["{index}"]': str(100 + index)
           for index in (1, 2)}
    ids.update({f'digitalocean_droplet.edge["{index}"]': str(200 + index)
                for index in (1, 2)})
    ids["digitalocean_firewall.firewall"] = "11111111-1111-1111-1111-111111111111"
    ids["digitalocean_ssh_key.key"] = "789"
    intent = SimpleNamespace(resource_ids=ids, empty_state_sha256="3" * 64)
    absent = {**absent_proof(original),
              "previewJobId": preview.id,
              "previewJournalSha256": job_event_digest(preview.events),
              "applyJobId": applied.id,
              "applyJournalSha256": job_event_digest(applied.events),
              "resourceIdsSha256": _fingerprint(ids),
              "verifiedAbsentDropletIds": ["101", "102", "201", "202"],
              "verifiedAbsentFirewallId": ids["digitalocean_firewall.firewall"],
              "verifiedAbsentSshKeyId": ids["digitalocean_ssh_key.key"],
              "observedAt": datetime.now(timezone.utc).isoformat()}
    absent_child = replace(original, id=service._child_id("core-1"),
                           input={**original.input, "phase": "provider_absent"},
                           events=[*original.events, JobEvent(6, "info", "provider_absent", absent)])
    rows = []
    for index in (1, 2):
        rows.append(SimpleNamespace(
            chain_id=f"chain-{index}", status="destroyed", nodes=[], deploy_job_id="",
            teardown_job_id=applied.id, terraform_working_directory="",
            assigned_proxy="proxy01", middle_provider="digitalocean",
            middle_region="nyc3", middle_size="s-1vcpu-1gb",
            edge_provider="digitalocean", edge_region="sfo3", edge_size="s-1vcpu-1gb",
            edge_count=1, edge_intents=[{"id": "edge-01", "provider": "digitalocean",
                                        "region": "sfo3", "size": "s-1vcpu-1gb"}],
        ))
    fingerprints = {row.chain_id: sketch_chain_intent_fingerprint(row) for row in rows}
    scope = {"chainIds": [row.chain_id for row in rows],
             "chainFingerprints": fingerprints}
    parent = SimpleNamespace(id="parent-1", target_id="eng-1",
                             input={"scopeSnapshot": {"snapshotId": "a" * 64,
                                     "providerScopeSha256": "b" * 64}})
    bound = SimpleNamespace(parent=parent, core=SimpleNamespace(id="core-1",
        input={"corePlanId": "plan-1"}), preview_job=preview, apply_job=applied,
        scope=scope, intent=intent, chains=tuple(rows))
    monkeypatch.setattr(service, "_boundary", lambda *_args, **_kwargs: bound)
    completed = datetime.now(timezone.utc)
    event_data = {
        "scopeSnapshotId": "a" * 64,
        "providerScopeSha256": "b" * 64,
        "sourceJournalSha256": job_event_digest(absent_child.events),
        "applyJobId": applied.id, "resourceIdsSha256": _fingerprint(ids),
        "verifiedAbsentDropletIds": ["101", "102", "201", "202"],
        "verifiedAbsentFirewallId": ids["digitalocean_firewall.firewall"],
        "verifiedAbsentSshKeyId": ids["digitalocean_ssh_key.key"],
        "confirmationCompletedAt": completed.isoformat(),
        "confirmationExpiresAt": (completed + timedelta(seconds=30)).isoformat(),
        "chainIds": ["chain-1", "chain-2"],
        "chainFingerprints": fingerprints,
        "retiredRecordIds": [], "observedAt": datetime.now(timezone.utc).isoformat(),
    }
    retired_child = replace(absent_child,
        input={**absent_child.input, "phase": "pending_group_retired"},
        events=[*absent_child.events, JobEvent(7, "info",
                "keyed_pending_provider_group_retired", event_data)])

    class Jobs:
        row = retired_child

        def get(self, key):
            return self.row if key == self.row.id else None

        def list_for_engagement(self, _engagement_id):
            return [self.row]

    jobs = Jobs()
    resource_rows = []
    opts = dict(environment="devtest", state_root=root, job_repository=jobs,
                plan_repository=object(), sketch_repository=object(),
                credential_repository=object(),
                provider_resource_repository=SimpleNamespace(list_for_engagement=lambda _: resource_rows),
                lease_lookup=lambda _: ("plan-1", "provider_keyed_teardown_fence"))
    assert [row.chain_id for row in service.recognize_pending_keyed_group_retired(
        parent.id, **opts)] == ["chain-1", "chain-2"]
    jobs.row = replace(retired_child, events=[*retired_child.events[:-1], replace(
        retired_child.events[-1], data={**event_data,
                                        "chainFingerprints": {**fingerprints, "chain-2": "0" * 64}})])
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.recognize_pending_keyed_group_retired(parent.id, **opts)
    resource_rows[:] = [SimpleNamespace(
        id="owned-1", provider="digitalocean", resource_type="droplet",
        resource_id="101", status="destroyed", metadata={"barraganOwned": True},
        adoption_job_id="other-job", source="barragan")]
    jobs.row = replace(retired_child, events=[*retired_child.events[:-1], replace(
        retired_child.events[-1], data={**event_data, "retiredRecordIds": ["owned-1"]})])
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.recognize_pending_keyed_group_retired(parent.id, **opts)
    resource_rows[0].adoption_job_id = service._job_ids("core-1")[2]
    jobs.row = retired_child  # Omitted retired ID is also a changed projection.
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.recognize_pending_keyed_group_retired(parent.id, **opts)
    jobs.row = retired_child
    bound.chains = (rows[0], SimpleNamespace(**{**vars(rows[1]), "edge_region": "nyc3"}))
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.recognize_pending_keyed_group_retired(parent.id, **opts)
    bound.chains = tuple(rows)
    resource_rows.clear()
    resource_rows.append(SimpleNamespace(
        id="digitalocean:inspector:999", provider="digitalocean",
        resource_type="droplet", resource_id="999", status="active",
        metadata={"role": "inspector", "barraganOwned": True},
        adoption_job_id="job-inspector", source="barragan_inspector_job"))
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.recognize_pending_keyed_group_retired(parent.id, **opts)
