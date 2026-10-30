# Copyright (c) 2026, Oracle and/or its affiliates.
"""The initial scope may be reread only before an append apply exists."""

from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_teardown_scope import (
    ProviderKeyedTeardownScopeError, _reconciled_unapplied_append_state_sha,
    _require_unapplied_append_plan, build_digitalocean_keyed_teardown_scope,
)


class Jobs:
    def __init__(self, jobs):
        self.jobs = jobs

    def list_for_engagement(self, _engagement_id):
        return self.jobs

    def get(self, job_id):
        return next((job for job in self.jobs if job.id == job_id), None)


def _job(action, job_id, status="queued", target_id="eng"):
    return SimpleNamespace(action=action, id=job_id, status=status, target_id=target_id)


def test_unapplied_append_parent_allows_initial_scope_recheck():
    jobs = Jobs([_job("provider_keyed_edge_append", "job-append", "running")])
    _require_unapplied_append_plan("eng", "job-append", jobs)


@pytest.mark.parametrize("extra", [
    [_job("provider_keyed_edge_append_apply", "job-apply")],
    [_job("provider_keyed_edge_append", "job-other")],
])
def test_unapplied_append_parent_rejects_ambiguous_history(extra):
    jobs = Jobs([_job("provider_keyed_edge_append", "job-append"), *extra])
    with pytest.raises(ValueError):
        _require_unapplied_append_plan("eng", "job-append", jobs)


@pytest.mark.parametrize("job", [
    _job("provider_keyed_edge_append", "job-other"),
    _job("provider_keyed_edge_append", "job-append", "succeeded"),
    _job("provider_keyed_edge_append", "job-append", target_id="other"),
])
def test_unapplied_append_parent_rejects_wrong_parent(job):
    with pytest.raises(ValueError):
        _require_unapplied_append_plan("eng", "job-append", Jobs([job]))


def test_foreign_core_reconciled_history_cannot_use_initial_teardown_scope(monkeypatch):
    parent = SimpleNamespace(
        id="job-prior", action="provider_keyed_edge_append", status="failed",
        target_id="eng", finished_at="2026-10-14T01:00:00+00:00",
        input={"engagementId": "eng", "coreJobId": "job-foreign",
               "corePlanId": "plan-foreign", "planJobId": "job-prior-plan",
               "phase": "unapplied_reconciled"},
        events=[JobEvent(1, "info", "append plan reconciled without mutation",
                         {"stateSha256": "a" * 64})],
    )
    child = SimpleNamespace(
        id="job-prior-plan", action="provider_keyed_edge_append_plan",
        status="failed", target_id="eng",
        input={"parentJobId": parent.id, "coreJobId": "job-foreign",
               "mutation": False},
    )
    jobs = Jobs([parent, child])
    assert _reconciled_unapplied_append_state_sha("eng", jobs) == "a" * 64
    assert _reconciled_unapplied_append_state_sha(
        "eng", jobs, expected_core_job_id="job-core") is None
    monkeypatch.setattr(
        "app.services.provider_keyed_teardown_scope._build_published_append_scope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("no publication")),
    )
    with pytest.raises(ProviderKeyedTeardownScopeError):
        build_digitalocean_keyed_teardown_scope(
            "eng", "job-core", sketch_repository=SimpleNamespace(),
            job_repository=jobs)


def test_active_retry_rejects_prior_core_tampered_after_reservation():
    prior = SimpleNamespace(
        id="job-prior", action="provider_keyed_edge_append", status="failed",
        target_id="eng", finished_at="2026-10-14T01:00:00+00:00",
        input={"engagementId": "eng", "coreJobId": "job-core",
               "corePlanId": "plan-core", "planJobId": "job-prior-plan",
               "phase": "unapplied_reconciled"},
        events=[JobEvent(1, "info", "append plan reconciled without mutation",
                         {"stateSha256": "a" * 64})],
    )
    child = SimpleNamespace(
        id="job-prior-plan", action="provider_keyed_edge_append_plan",
        status="failed", target_id="eng",
        input={"parentJobId": prior.id, "coreJobId": "job-core",
               "mutation": False},
    )
    active = SimpleNamespace(
        id="job-active", action="provider_keyed_edge_append", status="running",
        target_id="eng", input={"engagementId": "eng", "coreJobId": "job-core",
                                "corePlanId": "plan-core", "planJobId": "job-active-plan",
                                "phase": "planning"},
    )
    active_child = SimpleNamespace(
        id="job-active-plan", action="provider_keyed_edge_append_plan",
        status="queued", target_id="eng",
        input={"parentJobId": active.id, "coreJobId": "job-core",
               "mutation": False},
    )
    jobs = Jobs([prior, child, active, active_child])
    _require_unapplied_append_plan(
        "eng", active.id, jobs, expected_core_job_id="job-core")
    assert _reconciled_unapplied_append_state_sha(
        "eng", jobs, allowed_active_parent_id=active.id,
        expected_core_job_id="job-core", expected_core_plan_id="plan-core") == "a" * 64
    prior.input["coreJobId"] = child.input["coreJobId"] = "job-foreign"
    prior.input["corePlanId"] = "plan-foreign"
    with pytest.raises(ValueError):
        _require_unapplied_append_plan(
            "eng", active.id, jobs, expected_core_job_id="job-core")
    with pytest.raises(ProviderKeyedTeardownScopeError):
        build_digitalocean_keyed_teardown_scope(
            "eng", "job-core", allowed_append_plan_parent_id=active.id,
            sketch_repository=SimpleNamespace(), job_repository=jobs)
