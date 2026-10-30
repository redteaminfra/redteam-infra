# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network one-shot Inspector preparation reservation tests."""

from dataclasses import replace
from copy import copy, deepcopy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from app.services.provider_keyed_inspector_prepare_intent import (
    InspectorPreparationCapability, InspectorPreparationIntentAttention,
    begin_keyed_inspector_preparation,
)
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_inspector_prepare_binder import _ready, Transport
from test_provider_keyed_inspector_provider_proof import linode_responses


def _begin(state, parent, receipt, key, private, transport=None):
    transport = transport or Transport(linode_responses())
    with db.bind(state):
        return begin_keyed_inspector_preparation(
            receipt.coordinator_job_id, parent.target_id, environment="devtest",
            key_identity_reader=lambda: (private, key[0]),
            key_pair_verifier=lambda _path, _fingerprint: None,
            binder_options={
                "decrypt_secret": lambda _ciphertext: "private-token",
                "transport_factory": lambda _provider: transport,
            },
        )


def test_fresh_binder_then_atomic_nonsecret_one_shot_intent(tmp_path):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    transport = Transport(linode_responses())
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        before_parent = jobs.get(parent.id)
        before_settings = SqlAlchemyObserverSettingsRepository().get(parent.target_id)
        before_rows = SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id)
    capability = _begin(state, parent, receipt, key, private, transport)
    assert isinstance(capability, InspectorPreparationCapability)
    assert "private-token" not in repr(capability)
    assert transport.calls
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        child = jobs.get(receipt.coordinator_job_id)
        assert child.input["phase"] == "inspector_prepare_started"
        assert child.events[-1].message == "inspector_prepare_started"
        assert child.events[-1].data["hostId"] == "123"
        assert child.events[-1].data["keyFingerprintSha256"] == key[0]
        assert "private-token" not in str(child.events[-1])
        assert jobs.get(parent.id) == before_parent
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id) == before_settings
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id) == before_rows
    consumed, journal = capability.consume_for_executor()
    assert consumed.host_prepare_authorized is False and len(journal) == 64
    with pytest.raises(InspectorPreparationIntentAttention):
        capability.consume_for_executor()
    with pytest.raises(InspectorPreparationIntentAttention):
        _begin(state, parent, receipt, key, private, Transport(linode_responses()))


@pytest.mark.parametrize("drift", ["key", "record", "claim", "lease"])
def test_precommit_drift_blocks_without_intent(tmp_path, drift):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        child = jobs.get(receipt.coordinator_job_id)
        if drift == "key":
            key[0] = "f" * 64
        elif drift == "record":
            resources = SqlAlchemyProviderResourceRepository()
            host = resources.get("linode:inspector:123")
            resources.save(replace(host, metadata={**host.metadata, "publicIp": "8.8.4.4"}))
        elif drift == "claim":
            jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))
        else:
            SqlAlchemyDeploymentPlanRepository().retag(
                parent.target_id, child.input["corePlanId"], "wrong-operation")
    with pytest.raises(InspectorPreparationIntentAttention):
        _begin(state, parent, receipt, key, private)
    with db.bind(state):
        child = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        assert child.input["phase"] == "inspector_owned_unprepared"
        assert child.events[-1].message == "inspector_owned_unprepared"


def test_event_append_failure_rolls_back_phase_and_no_capability(tmp_path, monkeypatch):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    from app.storage.models import JobEventModel
    with db.bind(state):
        original_flush = db.session.flush

        def fail_event_flush(*args, **kwargs):
            if any(isinstance(item, JobEventModel) and item.message == "inspector_prepare_started"
                   for item in db.session.new):
                raise RuntimeError("injected event failure")
            return original_flush(*args, **kwargs)

        monkeypatch.setattr(db.session, "flush", fail_event_flush)
        with pytest.raises(InspectorPreparationIntentAttention):
            _begin(state, parent, receipt, key, private)
        monkeypatch.undo()
        child = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        assert child.input["phase"] == "inspector_owned_unprepared"
        assert child.events[-1].message == "inspector_owned_unprepared"


def test_postcommit_crash_recovery_never_rearms(tmp_path):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    _begin(state, parent, receipt, key, private)
    transport = Transport(linode_responses())
    with pytest.raises(InspectorPreparationIntentAttention):
        _begin(state, parent, receipt, key, private, transport)
    assert transport.calls == []


def test_capability_copies_and_parallel_consumers_share_one_use(tmp_path):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    capability = _begin(state, parent, receipt, key, private)
    assert copy(capability) is capability and deepcopy(capability) is capability
    barrier = Barrier(3)

    def consume():
        barrier.wait()
        try:
            return capability.consume_for_executor()
        except InspectorPreparationIntentAttention:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(consume)
        second = pool.submit(consume)
        barrier.wait()
        results = [first.result(), second.result()]
    assert sum(result is not None for result in results) == 1
