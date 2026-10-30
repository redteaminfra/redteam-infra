# Copyright (c) 2026, Oracle and/or its affiliates.
"""Claim-fenced, append-only v2 apply job audit for both repository backends."""

from contextlib import contextmanager
from dataclasses import replace

import pytest

from app.domain import JobEvent
from app.storage import models as _models  # noqa: F401 - register tables
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun, job_event_digest,
)

NOW = "2026-10-08T00:00:00+00:00"
LATER = "2026-10-08T00:05:00+00:00"
DONE = "2026-10-08T00:02:00+00:00"
BASE = {"engagementId": "eng-1", "coreJobId": "core-1", "corePlanId": "plan-1",
        "planJobId": "plan-child-1", "mutation": True}


@contextmanager
def repository(kind, tmp_path):
    if kind == "sqlite":
        yield SqliteJobRepository(tmp_path / "claimed-apply.sqlite")
    else:
        state = db.configure("sqlite:///:memory:")
        with db.bind(state):
            db.create_all()
            yield SqlAlchemyJobRepository()


def job(*, action="provider_keyed_initial_apply", status="running"):
    return StoredJobRun(
        id="apply-1", action=action, status=status, target="engagement:eng-1",
        target_type="engagement", target_id="eng-1", requested_by="operator",
        input=dict(BASE), artifact_refs=[], created_at=NOW, started_at=NOW,
        finished_at=None, events=[JobEvent(1, "info", "queued", {}),
                                  JobEvent(2, "info", "started", {})],
    )


def claim(repo):
    return repo.claim_lease(
        "apply-1", owner="worker-a", token="token-a", claimed_at=NOW,
        expires_at=LATER, eligible_statuses={"running"},
    )


def append(repo, current, *, digest=None, owner="worker-a", token="token-a"):
    return repo.append_event_if_running_claimed(
        current, owner=owner, token=token,
        expected_event_digest=digest or job_event_digest(current.events),
        heartbeat_at="2026-10-08T00:01:00+00:00", expires_at=LATER,
        event=JobEvent(len(current.events) + 1, "info", "apply command intent fenced",
                       {"argvSha256": "a" * 64}),
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_expired_claim_replacement_can_append_with_new_heartbeat(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(job())
        old = claim(repo)
        assert old is not None
        assert repo.renew_lease(
            old.id, owner="worker-a", token="token-a",
            heartbeat_at="2026-10-08T00:04:00+00:00", expires_at=LATER) is not None
        new = repo.claim_lease(
            old.id, owner="worker-b", token="token-b",
            claimed_at="2026-10-08T00:06:00+00:00",
            expires_at="2026-10-08T00:11:00+00:00", eligible_statuses={"running"})
        assert new is not None
        assert new.input["claimClaimedAt"] == new.input["claimHeartbeatAt"] == "2026-10-08T00:06:00+00:00"
        event = JobEvent(len(new.events) + 1, "info", "apply resumed", {})
        assert repo.append_event_if_running_claimed(
            old, owner="worker-a", token="token-a",
            expected_event_digest=job_event_digest(old.events),
            heartbeat_at="2026-10-08T00:07:00+00:00",
            expires_at="2026-10-08T00:12:00+00:00", event=event) is None
        appended = repo.append_event_if_running_claimed(
            new, owner="worker-b", token="token-b",
            expected_event_digest=job_event_digest(new.events),
            heartbeat_at="2026-10-08T00:07:00+00:00",
            expires_at="2026-10-08T00:12:00+00:00", event=event)
        assert appended is not None
        assert appended.events[-1] == event


def finish(repo, current, *, status="succeeded", digest=None):
    return repo.finish_if_running_claimed(
        current, owner="worker-a", token="token-a",
        expected_event_digest=digest or job_event_digest(current.events),
        status=status, finished_at=DONE,
        event=JobEvent(len(current.events) + 1,
                       "info" if status == "succeeded" else "error",
                       "apply complete" if status == "succeeded" else "apply stopped", {}),
    )


def _raw_mutation_integer(repo, kind):
    if kind == "sqlite":
        with repo._connect() as connection:
            connection.execute("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = ?",
                               ("apply-1",))
    else:
        from sqlalchemy import text
        db.session.execute(text("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = :id"),
                           {"id": "apply-1"})
        db.session.commit()


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("terminal", ["succeeded", "failed"])
def test_append_then_finish_is_atomic_and_restores_exact_input(kind, terminal, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(job())
        current = claim(repo)
        assert current is not None
        after = append(repo, current)
        assert after is not None
        assert after.events[:2] == current.events
        assert after.input["claimHeartbeatAt"] == "2026-10-08T00:01:00+00:00"
        assert [event.sequence for event in after.events] == [1, 2, 3]
        done = finish(repo, after, status=terminal)
        assert done is not None and done.status == terminal
        assert done.input == BASE
        assert done.events[:3] == after.events
        assert [event.sequence for event in done.events] == [1, 2, 3, 4]
        assert "token-a" not in str(done.events)
        assert append(repo, after) is None
        assert finish(repo, after, status=terminal) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_stale_claim_or_same_count_journal_rewrite_cannot_append(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(job())
        current = claim(repo)
        assert append(repo, current, owner="other", token="other") is None
        assert append(repo, current, digest="0" * 64) is None
        mutated = replace(current, events=[JobEvent(1, "info", "rewritten", {}), current.events[1]])
        repo.save(mutated)  # Simulate an independently changed same-count journal.
        assert append(repo, current) is None
        assert finish(repo, current) is None
        retained = repo.get(current.id)
        assert retained.events[0].message == "rewritten"
        assert retained.status == "running" and retained.finished_at is None
        assert retained.input == mutated.input


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("operation", ["append", "finish"])
def test_raw_json_integer_mutation_cannot_match_boolean_snapshot(kind, operation, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(job())
        current = claim(repo)
        assert current.input["mutation"] is True
        _raw_mutation_integer(repo, kind)
        assert (append(repo, current) if operation == "append" else finish(repo, current)) is None
        retained = repo.get(current.id)
        assert retained.input["mutation"] == 1 and retained.input["mutation"] is not True
        assert retained.status == "running" and len(retained.events) == 2


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("drift", ["expired", "retrograde", "naive", "offset", "new_expiry"])
def test_invalid_or_expired_claim_time_cannot_append(kind, drift, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(job())
        current = claim(repo)
        inputs = dict(current.input)
        expires_at = LATER
        if drift == "expired":
            inputs["claimExpiresAt"] = "2026-10-08T00:01:00+00:00"
        elif drift == "retrograde":
            inputs["claimHeartbeatAt"] = "2026-10-08T00:03:00+00:00"
        elif drift == "naive":
            inputs["claimClaimedAt"] = "2026-10-08T00:00:00"
        elif drift == "offset":
            inputs["claimClaimedAt"] = "2026-10-08T01:00:00+01:00"
        else:
            expires_at = "2026-10-08T00:01:00+00:00"
        current = repo.save(replace(current, input=inputs))
        assert repo.append_event_if_running_claimed(
            current, owner="worker-a", token="token-a",
            expected_event_digest=job_event_digest(current.events),
            heartbeat_at="2026-10-08T00:01:00+00:00", expires_at=expires_at,
            event=JobEvent(3, "info", "intent", {}),
        ) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_finish_rejects_expired_or_retrograde_time(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(job())
        current = claim(repo)
        current = repo.save(replace(current, input={**current.input,
            "claimHeartbeatAt": "2026-10-08T00:03:00+00:00",
            "claimExpiresAt": "2026-10-08T00:04:00+00:00"}))
        assert finish(repo, current) is None  # Before the prior heartbeat.
        assert repo.finish_if_running_claimed(
            current, owner="worker-a", token="token-a",
            expected_event_digest=job_event_digest(current.events),
            status="failed", finished_at="2026-10-08T00:04:00+00:00",
            event=JobEvent(3, "error", "late", {}),
        ) is None  # At expiry, the claim has ended.
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_competing_claim_generation_and_recovery_terminal_writer(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(job())
        old = claim(repo)
        new = repo.claim_lease(
            "apply-1", owner="worker-b", token="token-b",
            claimed_at=LATER, expires_at="2026-10-08T00:10:00+00:00",
            eligible_statuses={"running"},
        )
        assert new is not None and new.input["claimToken"] == "token-b"
        assert append(repo, old) is None
        assert finish(repo, old) is None
        # A distinct recovery terminal writer wins before this worker can finish.
        repo.save(replace(new, status="failed", finished_at=LATER,
                          events=[*new.events, JobEvent(3, "error", "recovery terminal", {})]))
        assert repo.finish_if_running_claimed(
            new, owner="worker-b", token="token-b",
            expected_event_digest=job_event_digest(new.events), status="succeeded",
            finished_at=LATER, event=JobEvent(3, "info", "late success", {}),
        ) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_wrong_action_or_noncanonical_input_never_uses_claimed_apply_api(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        row = repo.save(job(action="other"))
        assert claim(repo) is not None
        current = repo.get(row.id)
        assert append(repo, current) is None
        assert finish(repo, current) is None
        row = repo.save(job())
        current = claim(repo)
        bad = replace(current, input={**current.input, "extra": "unexpected"})
        assert append(repo, bad) is None
        assert finish(repo, bad) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_one_edge_append_apply_uses_same_claimed_cas_journal(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        append_job = replace(job(action="provider_keyed_edge_append_apply"),
                             input={**BASE, "parentJobId": "append-parent-1"})
        repo.save(append_job)
        current = claim(repo)
        assert current is not None
        started = append(repo, current)
        assert started is not None and len(started.events) == 3
        assert append(repo, current) is None
        assert finish(repo, current) is None
        done = finish(repo, started)
        assert done is not None and done.status == "succeeded"
        assert done.input == append_job.input
        assert finish(repo, started) is None
        repo.save(append_job)
        malformed = claim(repo)
        malformed = replace(malformed, input={**malformed.input, "parentJobId": ""})
        assert append(repo, malformed) is None
        assert finish(repo, malformed) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_legacy_finish_if_running_is_unchanged(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = repo.save(job(action="legacy_apply"))
        done = repo.finish_if_running(current, status="succeeded", finished_at=LATER,
                                      event=JobEvent(3, "info", "legacy done", {}))
        assert done is not None and done.status == "succeeded"
        assert done.input == BASE
