# Copyright (c) 2026, Oracle and/or its affiliates.
"""Digest-fenced terminal CAS for the dormant keyed destroy-plan child."""

from dataclasses import replace

import pytest

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import StoredJobRun, job_event_digest
from test_job_repository_claimed_apply import repository


CREATED = "2026-10-08T00:00:00+00:00"
STARTED = "2026-10-08T00:01:00+00:00"
FINISHED = "2026-10-08T00:02:00+00:00"
PLAN = "/private/tmp/state/eng/provider-keyed-v2/digitalocean/hash/.barragan-initial-destroy.tfplan"
INPUT = {"engagementId": "eng-1", "coreJobId": "core-1", "corePlanId": "plan-1",
         "teardownParentId": "teardown-1", "scopeSnapshotId": "a" * 64,
         "providerScopeSha256": "b" * 64, "mutation": True}


def running(*, action="provider_keyed_initial_destroy_plan"):
    return StoredJobRun(
        id="destroy-plan-1", action=action, status="running",
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        requested_by="operator", input=dict(INPUT), artifact_refs=[],
        created_at=CREATED, started_at=STARTED, finished_at=None,
        events=[JobEvent(1, "info", "queued", {}), JobEvent(2, "info", "started", {})],
    )


def finish(repo, snapshot, *, status="succeeded", digest=None, sequence=None, artifact=None):
    return repo.finish_if_running_with_journal_digest(
        snapshot, expected_event_digest=digest or job_event_digest(snapshot.events),
        status=status, finished_at=FINISHED,
        event=JobEvent(sequence or len(snapshot.events) + 1,
                       "info" if status == "succeeded" else "error",
                       "destroy preview saved" if status == "succeeded" else "destroy preview stopped", {}),
        artifact_ref=PLAN if artifact is None and status == "succeeded" else artifact,
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_exact_terminal_cas_appends_event_and_artifact_atomically(kind, status, tmp_path):
    with repository(kind, tmp_path) as repo:
        original = repo.save(running())
        completed = finish(repo, original, status=status)
        assert completed is not None and completed.status == status
        assert completed.input == INPUT
        assert completed.artifact_refs == ([PLAN] if status == "succeeded" else [])
        assert [event.sequence for event in completed.events] == [1, 2, 3]
        assert finish(repo, original, status=status) is None
        assert repo.get(original.id) == completed


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_same_count_journal_rewrite_rolls_back_status_and_artifact(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        original = repo.save(running())
        rewritten = replace(original, events=[JobEvent(1, "info", "rewritten", {}), original.events[1]])
        repo.save(rewritten)
        assert finish(repo, original) is None
        assert repo.get(original.id) == rewritten
        assert repo.get(original.id).artifact_refs == []


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_stale_input_metadata_or_boolean_type_cannot_finish(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        original = repo.save(running())
        for altered in (
            replace(original, input={**original.input, "corePlanId": "other"}),
            replace(original, requested_by="other"),
            replace(original, target_id="other"),
        ):
            repo.save(altered)
            assert finish(repo, original) is None
            repo.save(original)
        if kind == "sqlite":
            with repo._connect() as connection:
                connection.execute("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = ?",
                                   (original.id,))
        else:
            from sqlalchemy import text
            db.session.execute(text("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = :id"),
                               {"id": original.id})
            db.session.commit()
        assert finish(repo, original) is None
        assert repo.get(original.id).status == "running"


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_bad_sequence_or_time_and_other_action_are_rejected_without_write(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        original = repo.save(running())
        assert finish(repo, original, sequence=7) is None
        assert finish(repo, original, digest="0" * 64) is None
        assert finish(repo, original, status="failed", artifact=PLAN) is None
        assert finish(repo, original, artifact="relative/plan.tfplan") is None
        assert repo.finish_if_running_with_journal_digest(
            original, expected_event_digest=job_event_digest(original.events),
            status="succeeded", finished_at=STARTED,
            event=JobEvent(3, "info", "invalid time", {}), artifact_ref=PLAN,
        ) is None
        assert repo.get(original.id) == original
        legacy = repo.save(replace(running(action="legacy_action"), id="legacy-1"))
        assert finish(repo, legacy) is None
        assert repo.finish_if_running(
            legacy, status="succeeded", finished_at=FINISHED,
            event=JobEvent(3, "info", "legacy complete", {}),
        ).status == "succeeded"


def test_two_sqlite_repository_instances_cannot_both_finish(tmp_path):
    from app.storage.job_repository import SqliteJobRepository

    database = tmp_path / "two-finishers.sqlite"
    first, second = SqliteJobRepository(database), SqliteJobRepository(database)
    original = first.save(running())
    stale = second.get(original.id)
    assert stale == original
    assert finish(first, original) is not None
    assert finish(second, stale) is None
    assert second.get(original.id).artifact_refs == [PLAN]


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("invalid_input", [
    {**INPUT, "mutation": "false"},
    {**INPUT, "mutation": 1},
    {**INPUT, "extra": "unreviewed"},
    {key: value for key, value in INPUT.items() if key != "providerScopeSha256"},
    {**INPUT, "scopeSnapshotId": "A" * 64},
    {**INPUT, "providerScopeSha256": "short"},
    {**INPUT, "teardownParentId": " parent "},
])
def test_malformed_child_input_never_finishes(kind, invalid_input, tmp_path):
    with repository(kind, tmp_path) as repo:
        malformed = repo.save(replace(running(), input=invalid_input))
        assert finish(repo, malformed) is None
        assert repo.get(malformed.id) == malformed
