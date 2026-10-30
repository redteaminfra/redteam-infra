# Copyright (c) 2026, Oracle and/or its affiliates.
"""Claim-fenced audit for the dormant provider-keyed destroy preview."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import job_event_digest
from test_job_repository_claimed_apply import repository
from test_job_repository_destroy_plan_finish import INPUT, PLAN, running


_NOW = datetime.now(timezone.utc)
CLAIMED = _NOW.isoformat()
HEARTBEAT = (_NOW + timedelta(seconds=1)).isoformat()
FINISHED = (_NOW + timedelta(seconds=2)).isoformat()
EXPIRES = (_NOW + timedelta(minutes=5)).isoformat()
NEXT_EXPIRES = (_NOW + timedelta(minutes=10)).isoformat()


def claim(repo, *, owner="worker-a", token="token-a", at=CLAIMED,
          expires=EXPIRES):
    return repo.claim_lease("destroy-plan-1", owner=owner, token=token,
                            claimed_at=at, expires_at=expires,
                            eligible_statuses={"running"})


def append(repo, row, *, digest=None, owner="worker-a", token="token-a",
           heartbeat=HEARTBEAT):
    return repo.append_destroy_preview_event_if_running_claimed(
        row, owner=owner, token=token,
        expected_event_digest=digest or job_event_digest(row.events),
        heartbeat_at=heartbeat, expires_at=EXPIRES,
        event=JobEvent(len(row.events) + 1, "info", "preview command intent", {"phase": "plan"}),
    )


def finish(repo, row, *, status="succeeded", digest=None, owner="worker-a",
           token="token-a", artifact=None, finished=FINISHED):
    return repo.finish_destroy_preview_if_running_claimed(
        row, owner=owner, token=token,
        expected_event_digest=digest or job_event_digest(row.events),
        status=status, finished_at=finished,
        event=JobEvent(len(row.events) + 1, "info" if status == "succeeded" else "error",
                       "preview finished", {}),
        artifact_ref=(PLAN if status == "succeeded" and artifact is None else artifact),
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_claim_append_finish_exact_input_and_artifact(kind, status, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        current = claim(repo)
        assert current is not None
        audited = append(repo, current)
        assert audited is not None and len(audited.events) == 3
        done = finish(repo, audited, status=status)
        assert done is not None and done.status == status
        assert done.input == INPUT
        assert done.artifact_refs == ([PLAN] if status == "succeeded" else [])
        assert [event.sequence for event in done.events] == [1, 2, 3, 4]
        assert append(repo, audited) is None
        assert finish(repo, audited, status=status) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("operation", ["append", "finish"])
def test_same_count_rewrite_rolls_back_claimed_operation(kind, operation, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        stale = claim(repo)
        rewritten = replace(stale, events=[JobEvent(1, "info", "rewritten", {}), stale.events[1]])
        repo.save(rewritten)
        result = append(repo, stale) if operation == "append" else finish(repo, stale)
        assert result is None
        assert repo.get(stale.id) == rewritten


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("operation", ["append", "finish"])
def test_competing_claim_generation_is_fenced(kind, operation, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        old = claim(repo)
        new = claim(repo, owner="worker-b", token="token-b", at=EXPIRES,
                    expires=NEXT_EXPIRES)
        assert new is not None
        assert (append(repo, old) if operation == "append" else finish(repo, old)) is None
        assert repo.get(old.id) == new


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("operation", ["append", "finish"])
def test_input_type_drift_is_fenced(kind, operation, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        stale = claim(repo)
        if kind == "sqlite":
            with repo._connect() as connection:
                connection.execute("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = ?",
                                   (stale.id,))
        else:
            from sqlalchemy import text
            db.session.execute(text("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = :id"),
                               {"id": stale.id})
            db.session.commit()
        assert (append(repo, stale) if operation == "append" else finish(repo, stale)) is None
        assert repo.get(stale.id).status == "running"


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_expired_claim_and_wrong_action_rejected(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(running())
        current = claim(repo)
        assert finish(repo, current, finished=EXPIRES) is None
        assert append(repo, current, heartbeat=EXPIRES) is None
        wrong = repo.save(replace(running(action="legacy_action"), id="destroy-plan-1"))
        claimed = claim(repo)
        assert append(repo, claimed) is None
        assert finish(repo, claimed) is None
        assert repo.get(wrong.id).status == "running"


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("operation", ["append", "finish"])
def test_forged_backdated_event_cannot_use_wall_clock_expired_claim(kind, operation, tmp_path):
    with repository(kind, tmp_path) as repo:
        original = repo.save(replace(
            running(), created_at=(_NOW - timedelta(minutes=21)).isoformat(),
            started_at=(_NOW - timedelta(minutes=20)).isoformat(),
        ))
        expired_claimed_at = (_NOW - timedelta(minutes=10)).isoformat()
        expired_at = (_NOW - timedelta(minutes=5)).isoformat()
        current = claim(repo, at=expired_claimed_at, expires=expired_at)
        assert current is not None
        backdated = (_NOW - timedelta(minutes=6)).isoformat()
        if operation == "append":
            result = repo.append_destroy_preview_event_if_running_claimed(
                current, owner="worker-a", token="token-a",
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=backdated, expires_at=expired_at,
                event=JobEvent(3, "info", "forged old intent", {}),
            )
        else:
            result = finish(repo, current, finished=backdated)
        assert result is None
        retained = repo.get(current.id)
        assert retained == current
        assert retained.events == original.events
        assert retained.artifact_refs == []
