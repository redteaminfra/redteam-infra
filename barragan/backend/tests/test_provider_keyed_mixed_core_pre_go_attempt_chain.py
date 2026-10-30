# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact repeated OCI pre-GO Apply starts are recoverable without GO replay."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_zero_apply_core_apply import (
    interrupted_apply_no_go_restartable,
)
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    canonical_mixed_core_apply_events,
)
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun,
    _mixed_core_no_go_attempts, _valid_mixed_core_apply_no_go_takeover,
    job_event_digest,
)
from app.storage.models import EngagementModel


def _intent(number, invocation):
    return JobEvent(number, "info", "core destroy command intent fenced", {
        "phase": "apply", "invocationId": invocation, "argvSha256": "a" * 64})


def _start(number, invocation, pid):
    return JobEvent(number, "info", "core destroy command started before GO", {
        "phase": "apply", "invocationId": invocation, "bootId": "boot",
        "pid": pid, "pgid": pid, "startTicks": pid})


def _original():
    return [
        JobEvent(1, "info", "mixed core destroy apply queued", {}),
        JobEvent(2, "info", "mixed core destroy apply started", {}),
        JobEvent(3, "info", "core destroy command intent fenced", {
            "phase": "show", "invocationId": "show", "argvSha256": "b" * 64}),
        JobEvent(4, "info", "core destroy command started before GO", {
            "phase": "show", "invocationId": "show", "bootId": "boot",
            "pid": 101, "pgid": 101, "startTicks": 101}),
        JobEvent(5, "info", "core destroy command result fenced", {
            "phase": "show", "invocationId": "show", "returnCode": 0,
            "stdoutBytes": 20, "stderrBytes": 0,
            "stdoutTruncated": False, "stderrTruncated": False}),
        JobEvent(6, "info", "core destroy prestate identity fenced", {}),
        _intent(7, "apply-1"), _start(8, "apply-1", 201),
    ]


def _child(events=None):
    expired = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
    return StoredJobRun(
        "job-core-apply", "provider_keyed_mixed_zero_apply_core_destroy_apply",
        "running", "engagement:eng-test", "engagement", "eng-test", "operator",
        {"teardownParentId": "job-parent", "coreJobId": "job-core",
         "corePlanId": "plan-core", "sourceSha256": "c" * 64,
         "previewJobId": "job-preview", "previewJournalSha256": "d" * 64,
         "planSha256": "e" * 64, "mutation": True,
         "claimOwner": "provider-keyed-mixed-core-destroy-old",
         "claimToken": "old-token-1234567890", "claimClaimedAt": expired,
         "claimExpiresAt": expired}, [],
        "2026-10-19T00:00:00+00:00", "2026-10-19T00:00:01+00:00", None,
        events or _original())


@pytest.fixture(params=["sqlite", "sqlalchemy"])
def jobs(request, tmp_path):
    if request.param == "sqlite":
        yield SqliteJobRepository(tmp_path / "attempt-chain.sqlite")
        return
    state = db.configure(f"sqlite:///{tmp_path / 'attempt-chain.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(
            id="eng-test", name="opaque-fixture", status="active",
            owner="operator", template_id="small"))
        db.session.commit()
        yield SqlAlchemyJobRepository()


def _take(jobs, child, number):
    at = datetime.now(timezone.utc).isoformat()
    later = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
    taken = jobs.take_over_mixed_core_apply_no_go(
        child, expected_event_digest=job_event_digest(child.events),
        owner=f"provider-keyed-mixed-core-destroy-new-{number}",
        token=f"new-token-{number}-1234567890", claimed_at=at, expires_at=later)
    assert taken is not None
    return taken


def test_repeated_pre_go_chain_cas_and_terminal_normalization(jobs):
    first = jobs.save(_child())
    second_claim = _take(jobs, first, 2)
    assert len(second_claim.events) == 9
    assert second_claim.events[-1].data["originalJournalSha256"] == job_event_digest(first.events)
    # The second gated process stopped before its started callback recorded GO.
    eleven = jobs.save(replace(second_claim, events=[
        *second_claim.events, _intent(10, "apply-2"), _start(11, "apply-2", 202)],
        input={**second_claim.input, "claimExpiresAt": first.input["claimExpiresAt"]}))
    assert [row["pid"] for row in _mixed_core_no_go_attempts(eleven.events)] == [201, 202]
    third_claim = _take(jobs, eleven, 3)
    assert len(third_claim.events) == 12
    assert third_claim.events[-1].data == {
        "originalJournalSha256": job_event_digest(eleven.events),
        "originalInvocationId": "apply-2"}
    assert jobs.take_over_mixed_core_apply_no_go(
        eleven, expected_event_digest=job_event_digest(eleven.events),
        owner="provider-keyed-mixed-core-destroy-loser",
        token="loser-token-1234567890",
        claimed_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()) is None
    fourteen = [*third_claim.events, _intent(13, "apply-3"), _start(14, "apply-3", 203)]
    assert [row["pid"] for row in _mixed_core_no_go_attempts(fourteen)] == [201, 202, 203]
    finished = [*fourteen,
        JobEvent(15, "info", "core destroy GO support rechecked", {}),
        JobEvent(16, "info", "core destroy command result fenced", {
            "phase": "apply", "invocationId": "apply-3"}),
        JobEvent(17, "info", "core destroy applied; provider absence pending", {})]
    normalized = canonical_mixed_core_apply_events(replace(third_claim, events=finished))
    assert len(normalized) == 11 and normalized[6].data["invocationId"] == "apply-3"
    with pytest.raises(ValueError):
        _mixed_core_no_go_attempts(finished)


@pytest.mark.parametrize("tamper", ["digest", "argv", "invocation", "go", "result"])
def test_recovered_prefix_rejects_foreign_or_uncertain_suffix(tamper):
    original = _original()
    marker = JobEvent(9, "info", "mixed core pre-GO Apply recovery claimed", {
        "originalJournalSha256": job_event_digest(original),
        "originalInvocationId": "apply-1"})
    events = [*original, marker, _intent(10, "apply-2"), _start(11, "apply-2", 202)]
    if tamper == "digest":
        events[8] = replace(marker, data={**marker.data, "originalJournalSha256": "f" * 64})
    elif tamper == "argv":
        events[9] = replace(events[9], data={**events[9].data, "argvSha256": "f" * 64})
    elif tamper == "invocation":
        events[9] = replace(events[9], data={**events[9].data, "invocationId": "apply-1"})
    elif tamper == "go":
        events.append(JobEvent(12, "info", "core destroy GO support rechecked", {}))
    else:
        events.append(JobEvent(12, "info", "core destroy command result fenced", {}))
    with pytest.raises(ValueError):
        _mixed_core_no_go_attempts(events)
    child = _child(events)
    at = datetime.now(timezone.utc).isoformat()
    assert not _valid_mixed_core_apply_no_go_takeover(
        child, expected_event_digest=job_event_digest(child.events),
        owner="provider-keyed-mixed-core-destroy-new",
        token="new-token-1234567890", claimed_at=at,
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat())


@pytest.mark.parametrize("published", [False, True])
def test_selector_requires_every_prior_process_quiescent(published):
    original = _original()
    events = [*original, JobEvent(9, "info", "mixed core pre-GO Apply recovery claimed", {
        "originalJournalSha256": job_event_digest(original),
        "originalInvocationId": "apply-1"}),
        _intent(10, "apply-2"), _start(11, "apply-2", 202)]
    preview = StoredJobRun(
        "job-preview", "preview", "succeeded", "engagement:eng-test",
        "engagement", "eng-test", "operator", {}, [], "now", "now", "now",
        [JobEvent(1, "info", "queued", {}), JobEvent(2, "info", "started", {}),
         JobEvent(3, "info", "sealed", {"planSha256": "e" * 64})])
    parent = StoredJobRun(
        "job-parent", ("provider_keyed_mixed_published_cleanup" if published
                       else "provider_keyed_mixed_interrupted_cleanup"),
        "queued", "engagement:eng-test", "engagement", "eng-test", "operator",
        {"corePlanId": "plan-core",
         "publishedSourceSha256" if published else "sourceSha256": "c" * 64},
        [], "now", None, None, [])
    child = _child(events)
    child = replace(child, id="job-provider-keyed-mixed-core-destroy-apply-core",
                    input={**child.input,
        "previewJournalSha256": job_event_digest(preview.events)})
    observed = []
    def quiet(identity):
        observed.append(identity["pid"])
        return True
    assert interrupted_apply_no_go_restartable(
        child, parent, preview, "job-core", published=published,
        process_quiescent=quiet, terraform_quiescent=lambda: True)
    assert observed == [201, 202]
    assert not interrupted_apply_no_go_restartable(
        child, parent, preview, "job-core", published=published,
        process_quiescent=lambda identity: identity["pid"] != 202,
        terraform_quiescent=lambda: True)
