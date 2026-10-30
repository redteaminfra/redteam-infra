# Copyright (c) 2026, Oracle and/or its affiliates.
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.domain import JobEvent
from app.services.shared_proxy_stack import SharedProxyStackMutationConflict, reserve_shared_proxy_stack_mutation
from app.storage.job_repository import StoredJobRun


class _Repository:
    def __init__(self, jobs=()):
        self.jobs = list(jobs)

    def list(self):
        return list(self.jobs)

    def list_for_engagement(self, engagement_id):
        return [job for job in self.jobs if job.input.get("engagementId") == engagement_id]

    def save(self, job):
        self.jobs.append(job)
        return job


def _job(job_id, action, proxy_id):
    return StoredJobRun(
        id=job_id,
        action=action,
        status="running",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1", "proxyId": proxy_id},
        artifact_refs=[],
        created_at="2026-08-19T00:00:00+00:00",
        started_at="2026-08-19T00:00:00+00:00",
        finished_at=None,
        events=[JobEvent(1, "info", "started", {})],
    )


def test_reservation_normalizes_static_and_inbound_proxy_ids():
    repository = _Repository([_job("static", "web_static_service_apply", "proxy01")])
    candidate = _job("inbound", "inbound_channel_apply", "proxy01-engagement")

    try:
        reserve_shared_proxy_stack_mutation(repository, candidate, engagement_id="eng-1", proxy_id="proxy01-engagement")
    except SharedProxyStackMutationConflict as exc:
        assert exc.job.id == "static"
    else:
        raise AssertionError("expected a shared proxy stack mutation conflict")


def test_simultaneous_reservations_save_only_one_running_job():
    repository = _Repository()
    candidates = [
        _job("static", "web_static_service_apply", "proxy01"),
        _job("inbound", "inbound_channel_apply", "proxy01-engagement"),
    ]

    def reserve(job):
        try:
            reserve_shared_proxy_stack_mutation(repository, job, engagement_id="eng-1", proxy_id=job.input["proxyId"])
            return "saved"
        except SharedProxyStackMutationConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(reserve, candidates)) == ["conflict", "saved"]
    assert len(repository.jobs) == 1


def test_certificate_and_gate_mutations_share_the_same_proxy_lock():
    for certificate_action in (
        "certificate_asset_bind",
        "certificate_asset_unbind",
        "inbound_channel_certificate_issue",
        "inbound_channel_certificate_renew",
        "inbound_channel_certificate_revoke",
    ):
        repository = _Repository([_job("certificate", certificate_action, "proxy01-engagement")])
        candidate = _job("gate", "inbound_request_header_gate_apply", "proxy01")

        with pytest.raises(SharedProxyStackMutationConflict):
            reserve_shared_proxy_stack_mutation(repository, candidate, engagement_id="eng-1", proxy_id="proxy01")


def test_legacy_recognized_mutation_without_proxy_identity_blocks_conservatively():
    legacy = _job("legacy-certificate", "certificate_asset_bind", "")
    legacy = StoredJobRun(**{**legacy.__dict__, "input": {"engagementId": "eng-1"}})
    repository = _Repository([legacy])

    with pytest.raises(SharedProxyStackMutationConflict):
        reserve_shared_proxy_stack_mutation(
            repository,
            _job("gate", "inbound_request_header_gate_apply", "proxy02"),
            engagement_id="eng-1",
            proxy_id="proxy02",
        )


def test_legacy_certificate_selected_proxy_event_is_normalized():
    legacy = _job("legacy-certificate", "certificate_asset_bind", "")
    legacy = StoredJobRun(
        **{
            **legacy.__dict__,
            "input": {"engagementId": "eng-1"},
            "events": [JobEvent(1, "info", "started", {"selectedProxy": "proxy01-engagement"})],
        }
    )
    repository = _Repository([legacy])

    with pytest.raises(SharedProxyStackMutationConflict):
        reserve_shared_proxy_stack_mutation(
            repository,
            _job("gate", "inbound_request_header_gate_apply", "proxy01"),
            engagement_id="eng-1",
            proxy_id="proxy01",
        )
