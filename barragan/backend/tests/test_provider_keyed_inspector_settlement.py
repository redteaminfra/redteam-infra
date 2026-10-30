# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network bounded GET settlement of one already-submitted Inspector."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.services.observer_checks import ObserverHost
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderPending, InspectorProviderProof, InspectorProviderProofError,
)
from app.services.provider_keyed_inspector_settlement import (
    InspectorSettlementAttention, settle_submitted_keyed_inspector,
)
from app.services.provider_keyed_inspector_submit import submit_keyed_inspector_once
from test_provider_keyed_inspector_submit import FakeProvider, setup


class Clock:
    def __init__(self):
        self.seconds = 0.0
        self.origin = datetime.now(timezone.utc)
        self.sleeps = []

    def now(self):
        return self.origin + timedelta(seconds=self.seconds)

    def sleep(self, duration):
        self.sleeps.append(duration)
        self.seconds += duration


class NoNetworkTransport:
    def __init__(self):
        self.calls = []

    def request(self, method, path, token):
        self.calls.append((method, path))
        raise AssertionError("no fake provider GET response installed")


def case(tmp_path, provider="linode"):
    jobs, parent, plans, settings, credentials, key, receipt, submit_kw = setup(tmp_path, provider)
    submission = submit_keyed_inspector_once(
        receipt, provider_factory=lambda kind, source: FakeProvider(kind, source), **submit_kw,
    )
    clock = Clock()
    transport = NoNetworkTransport()
    kw = dict(
        environment="devtest", job_repository=jobs, plan_repository=plans,
        settings_repository=settings,
        provider_resource_repository=submit_kw["provider_resource_repository"],
        credential_repository=credentials, lease_lookup=submit_kw["lease_lookup"],
        key_fingerprint_reader=lambda: key[0], decrypt_secret=lambda ciphertext: "test-token",
        transport_factory=lambda kind: transport, now=clock.now,
        monotonic=lambda: clock.seconds, sleep=clock.sleep,
    )
    return jobs, parent, credentials, key, receipt, submission, clock, transport, kw


def evidence(submission):
    host = ObserverHost(submission.provider,
                        "instance" if submission.provider == "linode" else "droplet",
                        submission.host_id, submission.resource_name,
                        "us-east" if submission.provider == "linode" else "nyc3", "1.1.1.1")
    return InspectorProviderProof(host, submission.firewall_id, "8.8.8.8/32",
                                  submission.tag_name, False)


def test_pending_then_success_uses_bounded_get_passes_and_heartbeats(tmp_path):
    provider = "linode"  # Keyed-v2 Inspector creation currently requires Linode.
    jobs, _parent, _credentials, _key, receipt, submission, clock, transport, kw = case(tmp_path, provider)
    proof_calls = []
    heartbeats = []
    original = jobs.heartbeat_keyed_inspector_submission_if_running_claimed

    def heartbeat(*args, **kwargs):
        heartbeats.append(kwargs["expected_event_digest"])
        return original(*args, **kwargs)

    jobs.heartbeat_keyed_inspector_submission_if_running_claimed = heartbeat

    def proof(**arguments):
        proof_calls.append(arguments)
        assert arguments["token"] == "test-token"
        assert arguments["management_cidr"] == "8.8.8.8/32"
        if len(proof_calls) <= 2:
            raise InspectorProviderPending("settling")
        return evidence(submission)

    result = settle_submitted_keyed_inspector(receipt, submission, proof=proof, **kw)
    assert result.host.resource_id == submission.host_id
    assert len(proof_calls) == 3 and len(heartbeats) == 6
    assert clock.sleeps == [10.0, 10.0]
    assert transport.calls == []
    assert jobs.get(receipt.coordinator_job_id).events[-1].message == "inspector_create_stage"


def test_hard_policy_mismatch_stops_without_retry(tmp_path):
    jobs, _parent, _credentials, _key, receipt, submission, clock, _transport, kw = case(tmp_path)
    calls = []

    def proof(**_arguments):
        calls.append(1)
        raise InspectorProviderProofError("secret provider response")

    with pytest.raises(InspectorSettlementAttention) as caught:
        settle_submitted_keyed_inspector(receipt, submission, proof=proof, **kw)
    assert len(calls) == 1 and clock.sleeps == []
    assert "secret" not in str(caught.value)
    assert jobs.get(receipt.coordinator_job_id).status == "running"


@pytest.mark.parametrize("drift", ["credential", "key", "claim", "journal", "parent"])
def test_authority_drift_vetoes_before_get(drift, tmp_path):
    jobs, parent, credentials, key, receipt, submission, _clock, _transport, kw = case(tmp_path)
    child = jobs.get(receipt.coordinator_job_id)
    if drift == "credential":
        credentials.rows[0] = replace(credentials.rows[0], encrypted_secret="changed")
    elif drift == "key":
        key[0] = "f" * 64
    elif drift == "claim":
        jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))
    elif drift == "journal":
        events = list(child.events)
        events[-1] = replace(events[-1], data={**events[-1].data, "resourceId": "999"})
        jobs.save(replace(child, events=events))
    else:
        jobs.save(replace(parent, input={**parent.input, "phase": "attention"}))
    calls = []
    with pytest.raises(InspectorSettlementAttention):
        settle_submitted_keyed_inspector(
            receipt, submission, proof=lambda **k: calls.append(k), **kw,
        )
    assert calls == []


def test_post_get_drift_vetoes_success_and_no_provider_write(tmp_path):
    _jobs, _parent, credentials, _key, receipt, submission, _clock, _transport, kw = case(tmp_path)

    def proof(**_arguments):
        credentials.rows[0] = replace(credentials.rows[0], updated_at="2026-10-08T01:00:00+00:00")
        return evidence(submission)

    with pytest.raises(InspectorSettlementAttention):
        settle_submitted_keyed_inspector(receipt, submission, proof=proof, **kw)


def test_permanent_pending_times_out_without_replaying_create(tmp_path):
    jobs, _parent, _credentials, _key, receipt, submission, clock, _transport, kw = case(tmp_path)
    calls = []

    def proof(**_arguments):
        calls.append(1)
        raise InspectorProviderPending("settling")

    with pytest.raises(InspectorSettlementAttention):
        settle_submitted_keyed_inspector(receipt, submission, proof=proof, **kw)
    assert 1 < len(calls) <= 60
    assert clock.seconds <= 600 and all(seconds == 10 for seconds in clock.sleeps)
    assert jobs.get(receipt.coordinator_job_id).input["phase"] == "inspector_create_started"


def test_transport_rejects_provider_mutation_from_proof(tmp_path):
    _jobs, _parent, _credentials, _key, receipt, submission, _clock, transport, kw = case(tmp_path)

    def proof(**arguments):
        arguments["transport"].request("POST", "/droplets", "test-token", {})

    with pytest.raises(InspectorSettlementAttention):
        settle_submitted_keyed_inspector(receipt, submission, proof=proof, **kw)
    assert transport.calls == []


def test_slow_paginated_gets_hit_deadline_before_late_success(tmp_path):
    _jobs, _parent, _credentials, _key, receipt, submission, clock, _transport, kw = case(tmp_path)

    class SlowPages:
        def __init__(self):
            self.paths = []

        def request(self, method, path, token):
            assert method == "GET" and token == "test-token"
            self.paths.append(path)
            clock.seconds += 10  # the maximum default HTTP request timeout
            return {"page": len(self.paths)}

    pages = SlowPages()
    kw["transport_factory"] = lambda _provider: pages
    completed = []

    def proof(**arguments):
        for page in range(1, 100):
            arguments["transport"].request("GET", f"/droplets?page={page}", "test-token")
        completed.append(True)
        return evidence(submission)

    with pytest.raises(InspectorSettlementAttention):
        settle_submitted_keyed_inspector(receipt, submission, proof=proof, **kw)
    assert completed == []
    assert len(pages.paths) == 60
    assert clock.seconds == 600


def test_claim_loss_during_second_page_stops_further_gets(tmp_path):
    jobs, _parent, _credentials, _key, receipt, submission, _clock, _transport, kw = case(tmp_path)

    class ClaimChangingPages:
        def __init__(self):
            self.paths = []

        def request(self, method, path, token):
            self.paths.append(path)
            if len(self.paths) == 2:
                current = jobs.get(receipt.coordinator_job_id)
                jobs.save(replace(current, input={**current.input, "claimToken": "b" * 32}))
            return {}

    pages = ClaimChangingPages()
    kw["transport_factory"] = lambda _provider: pages

    def proof(**arguments):
        for page in range(1, 10):
            arguments["transport"].request("GET", f"/droplets?page={page}", "test-token")
        return evidence(submission)

    with pytest.raises(InspectorSettlementAttention):
        settle_submitted_keyed_inspector(receipt, submission, proof=proof, **kw)
    assert pages.paths == ["/droplets?page=1", "/droplets?page=2"]


def test_failed_get_still_runs_post_read_claim_fence(tmp_path):
    jobs, _parent, _credentials, _key, receipt, submission, _clock, _transport, kw = case(tmp_path)
    calls = []
    original = jobs.heartbeat_keyed_inspector_submission_if_running_claimed

    def heartbeat(*args, **kwargs):
        calls.append("heartbeat")
        return original(*args, **kwargs)

    jobs.heartbeat_keyed_inspector_submission_if_running_claimed = heartbeat

    class FailingGet:
        def request(self, method, path, token):
            calls.append("get")
            raise RuntimeError("private network detail")

    kw["transport_factory"] = lambda _provider: FailingGet()
    with pytest.raises(InspectorSettlementAttention) as caught:
        settle_submitted_keyed_inspector(
            receipt, submission,
            proof=lambda **arguments: arguments["transport"].request(
                "GET", "/droplets/123", "test-token"), **kw,
        )
    assert calls == ["heartbeat", "heartbeat", "get", "heartbeat", "heartbeat"]
    assert "private" not in str(caught.value)
