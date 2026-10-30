# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network tests of the dormant one-shot Inspector publication transaction."""

from dataclasses import replace
import copy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import text

from app.services import provider_keyed_inspector_readiness_publish as service
from app.services.provider_keyed_inspector_preparation_proof import InspectorSupportHostProof
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_inspector_preparation_proof import _run, _ssh_fake, _started
from test_provider_keyed_inspector_submit import setup as _inspector_setup
from app.services.provider_keyed_inspector_create_intent import ProviderKeyedInspectorCreateIntentError
from app.domain import JobEvent


def _capability(tmp_path, monkeypatch):
    state, parent, receipt, key, private, prepared = _started(tmp_path, monkeypatch)
    _ssh_fake(monkeypatch)
    capability = _run(state, parent, key, private, prepared)
    return state, parent, receipt, capability


def test_atomic_publication_and_no_replay(tmp_path, monkeypatch):
    state, parent, receipt, capability = _capability(tmp_path, monkeypatch)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        before = jobs.get(receipt.coordinator_job_id)
        host = service.publish_proved_keyed_inspector_readiness(
            capability, parent.target_id, environment="devtest")
        assert host.metadata["supportPreparedPackages"] == ["nmap"]
        assert host.metadata["rootLoginDisabled"] is True
        assert host.metadata["providerFirewall"].get("tag") is None
        current = SqlAlchemyObserverSettingsRepository().get(parent.target_id).current_host
        assert current == host.to_dict()
        rows = SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id)
        assert len(rows) == 2 and all(row.status == row.lifecycle_state == "active" for row in rows)
        after = jobs.get(receipt.coordinator_job_id)
        assert after.status == "running" and after.finished_at is None
        assert after.input["phase"] == "inspector_ready"
        assert after.input["claimOwner"] == "provider-keyed-inspector-ready-handoff"
        assert after.input["claimToken"] != before.input["claimToken"]
        assert len(after.events) == len(before.events) + 1
        assert jobs.save_if_leased(
            before, owner=before.input["claimOwner"],
            token=before.input["claimToken"],
        ) is None
        assert after.events[-1].data["selectedSourceSshPolicySha256"] == capability.evidence.ssh_policy_sha256
        assert SqlAlchemyJobRepository().get(parent.id).status == "queued"
        assert service.recognize_published_keyed_inspector_readiness(
            receipt.coordinator_job_id, parent.target_id, environment="devtest"
        ).status == "inspector_ready"
        with pytest.raises(service.InspectorReadinessPublicationAttention):
            service.publish_proved_keyed_inspector_readiness(
                capability, parent.target_id, environment="devtest")


def test_historical_publication_rejects_forged_retirement_suffix(tmp_path, monkeypatch):
    state, parent, receipt, capability = _capability(tmp_path, monkeypatch)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        service.publish_proved_keyed_inspector_readiness(
            capability, parent.target_id, environment="devtest")
        ready = jobs.get(receipt.coordinator_job_id)
        later = replace(
            ready, input={**ready.input, "phase": "pending_group_retired"},
            events=[*ready.events, JobEvent(len(ready.events) + 1, "info",
                                            "pending group retired", {})],
        )
        jobs.save(later)
        with pytest.raises(service.InspectorReadinessPublicationAttention):
            service.recognize_historical_keyed_inspector_readiness(
                receipt.coordinator_job_id, parent.target_id,
                environment="devtest", state_root=tmp_path)


def test_copied_capability_is_same_one_use_cell(tmp_path, monkeypatch):
    state, parent, _receipt, capability = _capability(tmp_path, monkeypatch)
    assert copy.copy(capability) is capability
    assert copy.deepcopy(capability) is capability
    with db.bind(state):
        service.publish_proved_keyed_inspector_readiness(
            copy.copy(capability), parent.target_id, environment="devtest")
        with pytest.raises(service.InspectorReadinessPublicationAttention):
            service.publish_proved_keyed_inspector_readiness(
                capability, parent.target_id, environment="devtest")


def test_concurrent_proof_consume_has_one_winner(tmp_path, monkeypatch):
    _state, _parent, _receipt, capability = _capability(tmp_path, monkeypatch)
    barrier = Barrier(2)

    def consume():
        barrier.wait()
        try:
            capability.consume_for_publication()
            return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _index: consume(), range(2))) == [False, True]


def test_plain_evidence_cannot_publish(tmp_path, monkeypatch):
    state, parent, _receipt, capability = _capability(tmp_path, monkeypatch)
    proof = replace(capability.evidence, status="support_host_proved_unpublished")
    assert type(proof) is InspectorSupportHostProof
    with db.bind(state):
        with pytest.raises(service.InspectorReadinessPublicationAttention):
            service.publish_proved_keyed_inspector_readiness(
                proof, parent.target_id, environment="devtest")
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id).current_host == {}


@pytest.mark.parametrize("drift", ["claim", "settings", "firewall"])
def test_drift_rolls_back_every_publication_row(tmp_path, monkeypatch, drift):
    state, parent, receipt, capability = _capability(tmp_path, monkeypatch)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        rows = SqlAlchemyProviderResourceRepository()
        settings_repo = SqlAlchemyObserverSettingsRepository()
        if drift == "claim":
            child = jobs.get(receipt.coordinator_job_id)
            jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))
        elif drift == "settings":
            settings = settings_repo.get(parent.target_id)
            settings_repo.save(replace(settings, current_host={"unexpected": True}))
        else:
            firewall = rows.get(capability.evidence.firewall_record_id)
            rows.save(replace(firewall, status="other"))
        before = jobs.get(receipt.coordinator_job_id)
        with pytest.raises(service.InspectorReadinessPublicationAttention):
            service.publish_proved_keyed_inspector_readiness(
                capability, parent.target_id, environment="devtest")
        after = jobs.get(receipt.coordinator_job_id)
        assert after == before
        assert rows.get(capability.evidence.host_record_id).status == "preparation_required"


def test_prod_veto_consumes_capability_without_publication(tmp_path, monkeypatch):
    state, parent, receipt, capability = _capability(tmp_path, monkeypatch)
    with db.bind(state):
        with pytest.raises(service.InspectorReadinessPublicationAttention):
            service.publish_proved_keyed_inspector_readiness(
                capability, parent.target_id, environment="prod")
        assert SqlAlchemyJobRepository().get(receipt.coordinator_job_id).status == "running"
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id).current_host == {}


def test_failure_after_host_update_rolls_back_all_rows(tmp_path, monkeypatch):
    state, parent, receipt, capability = _capability(tmp_path, monkeypatch)
    with db.bind(state):
        db.session.execute(text("""
            CREATE TRIGGER veto_inspector_firewall_ready
            BEFORE UPDATE OF status ON provider_resource_records
            WHEN OLD.id = 'linode:inspector-firewall:42'
            BEGIN SELECT RAISE(ABORT, 'test rollback'); END
        """))
        db.session.commit()
        before = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        with pytest.raises(service.InspectorReadinessPublicationAttention):
            service.publish_proved_keyed_inspector_readiness(
                capability, parent.target_id, environment="devtest")
        assert SqlAlchemyJobRepository().get(receipt.coordinator_job_id) == before
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id).current_host == {}
        rows = SqlAlchemyProviderResourceRepository()
        assert rows.get(capability.evidence.host_record_id).status == "preparation_required"
        assert rows.get(capability.evidence.firewall_record_id).status == "preparation_required"


def test_ready_recognizer_rejects_tampered_settings(tmp_path, monkeypatch):
    state, parent, receipt, capability = _capability(tmp_path, monkeypatch)
    with db.bind(state):
        service.publish_proved_keyed_inspector_readiness(
            capability, parent.target_id, environment="devtest")
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings = settings_repo.get(parent.target_id)
        settings_repo.save(replace(settings, current_host={**settings.current_host, "name": "wrong"}))
        with pytest.raises(service.InspectorReadinessPublicationAttention):
            service.recognize_published_keyed_inspector_readiness(
                receipt.coordinator_job_id, parent.target_id, environment="devtest")


def test_keyed_digitalocean_inspector_is_rejected_before_publication(tmp_path):
    with pytest.raises(ProviderKeyedInspectorCreateIntentError):
        _inspector_setup(tmp_path, "digitalocean")
