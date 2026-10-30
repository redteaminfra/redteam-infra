# Copyright (c) 2026, Oracle and/or its affiliates.
"""Action-scoped claimed CAS for a dormant full-state destroy apply child."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import StoredJobRun, job_event_digest
from test_job_repository_claimed_apply import repository


NOW = datetime.now(timezone.utc)
CLAIMED = NOW.isoformat()
HEARTBEAT = (NOW + timedelta(seconds=1)).isoformat()
FINISHED = (NOW + timedelta(seconds=2)).isoformat()
EXPIRES = (NOW + timedelta(minutes=5)).isoformat()
BASE = {
    "engagementId": "eng-1", "coreJobId": "core-1", "corePlanId": "plan-1",
    "teardownParentId": "teardown-1", "scopeSnapshotId": "a" * 64,
    "providerScopeSha256": "b" * 64, "destroyPlanJobId": "destroy-plan-1",
    "planSha256": "c" * 64, "mutation": True,
}


def running(*, action="provider_keyed_initial_destroy_apply", inputs=None):
    return StoredJobRun(
        id="destroy-apply-1", action=action, status="running",
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        requested_by="operator", input=dict(BASE if inputs is None else inputs),
        artifact_refs=[], created_at=(NOW - timedelta(minutes=2)).isoformat(),
        started_at=(NOW - timedelta(minutes=1)).isoformat(), finished_at=None,
        events=[JobEvent(1, "info", "queued", {}), JobEvent(2, "info", "started", {})],
    )


def claim(repo, *, owner="worker-a", token="token-a", at=CLAIMED, expires=EXPIRES):
    return repo.claim_lease("destroy-apply-1", owner=owner, token=token,
                            claimed_at=at, expires_at=expires,
                            eligible_statuses={"running"})


def append(repo, row, *, digest=None, owner="worker-a", token="token-a", at=HEARTBEAT):
    return repo.append_destroy_apply_event_if_running_claimed(
        row, owner=owner, token=token,
        expected_event_digest=digest or job_event_digest(row.events),
        heartbeat_at=at, expires_at=EXPIRES,
        event=JobEvent(len(row.events) + 1, "info", "destroy command intent", {"phase": "show"}),
    )


def finish(repo, row, *, status="succeeded", digest=None, owner="worker-a",
           token="token-a", at=FINISHED, data=None):
    payload = ({"stateSha256": "d" * 64, "providerAbsenceProofPending": True}
               if status == "succeeded" else {}) if data is None else data
    return repo.finish_destroy_apply_if_running_claimed(
        row, owner=owner, token=token,
        expected_event_digest=digest or job_event_digest(row.events),
        status=status, finished_at=at,
        event=JobEvent(len(row.events) + 1, "info" if status == "succeeded" else "error",
                       "destroy apply completed" if status == "succeeded" else "destroy apply stopped", payload),
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_claimed_append_and_terminal_are_exact_and_single_use(kind, status, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        claimed = claim(repo)
        audited = append(repo, claimed)
        assert audited is not None and len(audited.events) == 3
        done = finish(repo, audited, status=status)
        assert done is not None and done.status == status
        assert done.input == BASE and done.artifact_refs == []
        assert [event.sequence for event in done.events] == [1, 2, 3, 4]
        assert finish(repo, audited, status=status) is None
        assert append(repo, audited) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("operation", ["append", "finish"])
def test_same_count_journal_rewrite_and_stale_generation_roll_back(kind, operation, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        old = claim(repo)
        rewritten = repo.save(replace(old, events=[JobEvent(1, "info", "rewritten", {}), old.events[1]]))
        assert (append(repo, old) if operation == "append" else finish(repo, old)) is None
        assert repo.get(old.id) == rewritten
        new = claim(repo, owner="worker-b", token="token-b", at=EXPIRES,
                    expires=(NOW + timedelta(minutes=10)).isoformat())
        assert new is not None
        assert (append(repo, rewritten) if operation == "append" else finish(repo, rewritten)) is None
        assert repo.get(old.id) == new


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("operation", ["append", "finish"])
def test_backdated_expired_claim_cannot_write(kind, operation, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        expired_at = (NOW - timedelta(seconds=10)).isoformat()
        current = claim(repo, at=(NOW - timedelta(seconds=30)).isoformat(), expires=expired_at)
        if operation == "append":
            result = repo.append_destroy_apply_event_if_running_claimed(
                current, owner="worker-a", token="token-a",
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=(NOW - timedelta(seconds=20)).isoformat(),
                expires_at=expired_at,
                event=JobEvent(3, "info", "forged old command", {}),
            )
        else:
            result = finish(repo, current, at=(NOW - timedelta(seconds=20)).isoformat())
        assert result is None and repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("bad", [
    {**BASE, "mutation": 1}, {**BASE, "extra": "unreviewed"},
    {**BASE, "planSha256": "short"}, {**BASE, "destroyPlanJobId": " other "},
])
def test_malformed_child_cannot_use_claimed_apply_cas(kind, bad, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running(inputs=bad))
        current = claim(repo)
        assert append(repo, current) is None
        assert finish(repo, current) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_success_requires_state_digest_and_pending_provider_absence(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        current = claim(repo)
        assert finish(repo, current, data={"stateSha256": "short", "providerAbsenceProofPending": True}) is None
        assert finish(repo, current, data={"stateSha256": "d" * 64, "providerAbsenceProofPending": False}) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_other_action_cannot_use_destroy_apply_cas(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running(action="provider_keyed_initial_destroy_plan"))
        current = claim(repo)
        assert append(repo, current) is None and finish(repo, current) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("operation", ["append", "finish"])
def test_raw_boolean_to_integer_drift_cannot_match_claim_snapshot(kind, operation, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        current = claim(repo)
        if kind == "sqlite":
            with repo._connect() as connection:
                connection.execute("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = ?",
                                   (current.id,))
        else:
            from sqlalchemy import text
            db.session.execute(text("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = :id"),
                               {"id": current.id})
            db.session.commit()
        assert (append(repo, current) if operation == "append" else finish(repo, current)) is None
        retained = repo.get(current.id)
        assert retained.input["mutation"] == 1 and retained.input["mutation"] is not True
        assert retained.status == "running" and retained.events == current.events
