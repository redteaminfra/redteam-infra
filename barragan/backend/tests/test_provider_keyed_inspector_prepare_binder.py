# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network persisted Inspector preparation binding tests."""

from dataclasses import replace
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import subprocess

import pytest

from app.services.provider_keyed_inspector_prepare_binder import (
    InspectorPreparationAttention, _verify_key_pair,
    bind_owned_keyed_inspector_for_preparation,
)
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_inspector_materialize import _case, _persist, _run
from test_provider_keyed_inspector_provider_proof import linode_responses


class Clock:
    def __init__(self):
        self.seconds = 0.0

    def monotonic(self):
        return self.seconds

    def sleep(self, seconds):
        self.seconds += seconds


class Transport:
    def __init__(self, responses, *, offline_once=False, after_get=None):
        self.responses = responses
        self.offline_once = offline_once
        self.after_get = after_get
        self.calls = []

    def request(self, method, path, token):
        assert method == "GET" and token == "private-token"
        self.calls.append(path)
        value = deepcopy(self.responses[path])
        if path == "/linode/instances/123" and self.offline_once:
            self.offline_once = False
            value["status"] = "offline"
        if self.after_get:
            self.after_get()
        return value


def _ready(tmp_path):
    state, source_jobs, parent, settings, credentials, key, receipt, submitted, proof = _case(tmp_path)
    _persist(state, source_jobs, parent, settings, credentials)
    _run(state, receipt, submitted, proof, key)
    private = tmp_path / "inspector-key"
    private.write_text("fake-private-key", encoding="ascii")
    private.chmod(0o600)
    return state, parent, receipt, submitted, key, private


def _bind(state, parent, receipt, key, private, transport, clock=None):
    clock = clock or Clock()
    with db.bind(state):
        return bind_owned_keyed_inspector_for_preparation(
            receipt.coordinator_job_id, parent.target_id, environment="devtest",
            key_identity_reader=lambda: (private, key[0]),
            key_pair_verifier=lambda _path, _digest: None,
            decrypt_secret=lambda _encrypted: "private-token",
            transport_factory=lambda _provider: transport,
            monotonic=clock.monotonic, sleep=clock.sleep,
        )


def test_persisted_binding_polls_offline_then_returns_non_authorizing_receipt(tmp_path):
    state, parent, receipt, submitted, key, private = _ready(tmp_path)
    transport = Transport(linode_responses(), offline_once=True)
    clock = Clock()
    with db.bind(state):
        before = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        before_rows = SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id)
    result = _bind(state, parent, receipt, key, private, transport, clock)
    assert result.status == "proved_unprepared" and result.host_prepare_authorized is False
    assert result.host_id == submitted.host_id and result.firewall_id == submitted.firewall_id
    assert result.public_ip == "1.1.1.1" and result.key_path == str(private)
    assert result.claim_token not in repr(result)
    assert datetime.fromisoformat(result.expires_at) <= datetime.now(timezone.utc) + timedelta(seconds=30)
    assert clock.seconds == 10 and transport.calls.count("/linode/instances/123") == 2
    with db.bind(state):
        assert SqlAlchemyJobRepository().get(receipt.coordinator_job_id) == before
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id) == before_rows


@pytest.mark.parametrize("drift", ["key", "record_ip", "record_id", "claim", "lease"])
def test_pre_get_drift_vetoes_without_provider_call(tmp_path, drift):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        child = jobs.get(receipt.coordinator_job_id)
        if drift == "key":
            key[0] = "f" * 64
        elif drift in {"record_ip", "record_id"}:
            resources = SqlAlchemyProviderResourceRepository()
            host = resources.get(f"linode:inspector:123")
            if drift == "record_ip":
                resources.save(replace(host, metadata={**host.metadata, "publicIp": "8.8.4.4"}))
            else:
                resources.save(replace(host, resource_id="999"))
        elif drift == "claim":
            jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))
        else:
            SqlAlchemyDeploymentPlanRepository().retag(
                parent.target_id, child.input["corePlanId"], "wrong-operation")
    transport = Transport(linode_responses())
    with pytest.raises(InspectorPreparationAttention):
        _bind(state, parent, receipt, key, private, transport)
    assert transport.calls == []


@pytest.mark.parametrize("drift_kind", ["record", "claim"])
def test_post_get_drift_vetoes_receipt(tmp_path, drift_kind):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    def drift():
        transport.after_get = None
        with db.bind(state):
            if drift_kind == "record":
                resources = SqlAlchemyProviderResourceRepository()
                host = resources.get("linode:inspector:123")
                resources.save(replace(host, metadata={**host.metadata, "publicIp": "8.8.4.4"}))
            else:
                jobs = SqlAlchemyJobRepository()
                child = jobs.get(receipt.coordinator_job_id)
                jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))
    transport = Transport(linode_responses(), after_get=drift)
    with pytest.raises(InspectorPreparationAttention):
        _bind(state, parent, receipt, key, private, transport)
    assert transport.calls == ["/linode/instances/123"]


def test_changed_provider_public_ip_is_hard_attention_without_write(tmp_path):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    responses = linode_responses()
    responses["/linode/instances/123"]["ipv4"] = ["8.8.4.4"]
    transport = Transport(responses)
    with db.bind(state):
        before = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        before_rows = SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id)
    with pytest.raises(InspectorPreparationAttention):
        _bind(state, parent, receipt, key, private, transport)
    assert transport.calls
    with db.bind(state):
        assert SqlAlchemyJobRepository().get(receipt.coordinator_job_id) == before
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id) == before_rows


def test_retained_private_must_match_pinned_public_without_key_generation(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    for path in (first, second):
        subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
            check=True, capture_output=True,
        )
    first_public = first.with_suffix(".pub")
    original = first_public.read_bytes()
    _verify_key_pair(str(first), hashlib.sha256(original.strip()).hexdigest())
    replacement = second.with_suffix(".pub").read_bytes()
    first_public.write_bytes(replacement)
    with pytest.raises(ValueError, match="keys differ"):
        _verify_key_pair(str(first), hashlib.sha256(replacement.strip()).hexdigest())


@pytest.mark.parametrize("missing", ["private", "public"])
def test_missing_retained_key_file_blocks_before_get(tmp_path, missing):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    if missing == "private":
        private.unlink()
        verifier = lambda _path, _digest: None
    else:
        verifier = _verify_key_pair
    transport = Transport(linode_responses())
    with db.bind(state), pytest.raises(InspectorPreparationAttention):
        bind_owned_keyed_inspector_for_preparation(
            receipt.coordinator_job_id, parent.target_id, environment="devtest",
            key_identity_reader=lambda: (private, key[0]),
            key_pair_verifier=verifier,
            decrypt_secret=lambda _encrypted: "private-token",
            transport_factory=lambda _provider: transport,
        )
    assert transport.calls == []


def test_permanent_offline_state_times_out_without_mutation(tmp_path):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)

    class Offline(Transport):
        def request(self, method, path, token):
            result = super().request(method, path, token)
            if path == "/linode/instances/123":
                result["status"] = "offline"
            return result

    transport = Offline(linode_responses())
    clock = Clock()
    with db.bind(state):
        before = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
    with pytest.raises(InspectorPreparationAttention):
        _bind(state, parent, receipt, key, private, transport, clock)
    assert 1 < transport.calls.count("/linode/instances/123") <= 12
    assert clock.seconds < 120
    with db.bind(state):
        assert SqlAlchemyJobRepository().get(receipt.coordinator_job_id) == before


def test_second_get_drift_stops_before_later_pages(tmp_path):
    state, parent, receipt, _submitted, key, private = _ready(tmp_path)
    calls = [0]

    def drift_after_second():
        calls[0] += 1
        if calls[0] == 2:
            with db.bind(state):
                jobs = SqlAlchemyJobRepository()
                child = jobs.get(receipt.coordinator_job_id)
                jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))

    transport = Transport(linode_responses(), after_get=drift_after_second)
    with pytest.raises(InspectorPreparationAttention):
        _bind(state, parent, receipt, key, private, transport)
    assert len(transport.calls) == 2
