# Copyright (c) 2026, Oracle and/or its affiliates.
"""Atomic provider apply-job transitions without altering reviewed input."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from app.domain import JobEvent
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun


def _queued() -> StoredJobRun:
    return StoredJobRun(
        id="apply-job", action="provider_keyed_initial_apply", status="queued",
        target="engagement:eng-opaque", target_type="engagement", target_id="eng-opaque",
        requested_by="operator", input={
            "engagementId": "eng-opaque", "coreJobId": "core-job", "corePlanId": "core-plan",
            "planJobId": "plan-job", "mutation": True,
        }, artifact_refs=[], created_at="2026-10-07T00:00:00+00:00",
        started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "job queued", {})],
    )


def _running(repo) -> StoredJobRun:
    queued = repo.save(_queued())
    running = repo.start_if_queued(
        queued, started_at="2026-10-07T00:01:00+00:00",
        event=JobEvent(2, "info", "start", {}),
    )
    assert running is not None
    return running


@pytest.mark.parametrize("backend", ["sqlalchemy", "sqlite"])
def test_exact_queued_job_can_be_started_only_once(client, tmp_path, backend):
    repo = (SqlAlchemyJobRepository() if backend == "sqlalchemy"
            else SqliteJobRepository(tmp_path / "jobs.sqlite"))
    queued = repo.save(_queued())
    start = JobEvent(2, "info", "provider saved-plan apply preflight started", {})

    claimed = repo.start_if_queued(queued, started_at="2026-10-07T00:01:00+00:00", event=start)

    assert claimed is not None
    assert claimed.status == "running"
    assert claimed.input == queued.input
    assert claimed.started_at is not None
    assert claimed.finished_at is None
    assert [(event.sequence, event.message) for event in claimed.events] == [
        (1, "job queued"), (2, "provider saved-plan apply preflight started"),
    ]
    assert repo.start_if_queued(queued, started_at="2026-10-07T00:02:00+00:00", event=start) is None
    assert len(repo.get(queued.id).events) == 2


@pytest.mark.parametrize("backend", ["sqlalchemy", "sqlite"])
@pytest.mark.parametrize("drift", ["action", "input", "started", "finished"])
def test_job_start_rejects_changed_record(client, tmp_path, backend, drift):
    repo = (SqlAlchemyJobRepository() if backend == "sqlalchemy"
            else SqliteJobRepository(tmp_path / "jobs.sqlite"))
    queued = repo.save(_queued())
    changes = {
        "action": {"action": "other"},
        "input": {"input": {**queued.input, "corePlanId": "other-plan"}},
        "started": {"started_at": "2026-10-07T00:00:30+00:00"},
        "finished": {"finished_at": "2026-10-07T00:00:30+00:00"},
    }
    repo.save(replace(queued, **changes[drift]))

    assert repo.start_if_queued(
        queued, started_at="2026-10-07T00:01:00+00:00",
        event=JobEvent(2, "info", "start", {}),
    ) is None
    retained = repo.get(queued.id)
    assert retained is not None and retained.status == "queued"
    assert [event.message for event in retained.events] == ["job queued"]


@pytest.mark.parametrize("backend", ["sqlalchemy", "sqlite"])
def test_job_start_rolls_back_status_if_event_history_advanced(client, tmp_path, backend):
    repo = (SqlAlchemyJobRepository() if backend == "sqlalchemy"
            else SqliteJobRepository(tmp_path / "jobs.sqlite"))
    queued = repo.save(_queued())
    repo.save(replace(queued, events=[*queued.events, JobEvent(2, "info", "another event", {})]))

    assert repo.start_if_queued(
        queued, started_at="2026-10-07T00:01:00+00:00",
        event=JobEvent(2, "info", "start", {}),
    ) is None

    retained = repo.get(queued.id)
    assert retained is not None and retained.status == "queued"
    assert retained.started_at is None
    assert [event.message for event in retained.events] == ["job queued", "another event"]


def test_two_sqlite_workers_race_for_one_start_event(tmp_path):
    database = tmp_path / "jobs.sqlite"
    first = SqliteJobRepository(database)
    second = SqliteJobRepository(database)
    queued = first.save(_queued())
    barrier = Barrier(2)

    def claim(repo):
        barrier.wait()
        return repo.start_if_queued(
            queued, started_at="2026-10-07T00:01:00+00:00",
            event=JobEvent(2, "info", "start", {}),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(claim, repo) for repo in (first, second)]
        results = [future.result() for future in futures]

    assert sum(result is not None for result in results) == 1
    retained = first.get(queued.id)
    assert retained is not None and retained.status == "running"
    assert retained.input == queued.input
    assert [event.message for event in retained.events] == ["job queued", "start"]


@pytest.mark.parametrize("backend", ["sqlalchemy", "sqlite"])
@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_exact_running_job_finishes_once_with_event(client, tmp_path, backend, status):
    repo = (SqlAlchemyJobRepository() if backend == "sqlalchemy"
            else SqliteJobRepository(tmp_path / "jobs.sqlite"))
    running = _running(repo)
    event = JobEvent(3, "info" if status == "succeeded" else "error", "terminal", {})

    finished = repo.finish_if_running(
        running, status=status, finished_at="2026-10-07T00:02:00+00:00", event=event,
    )

    assert finished is not None and finished.status == status
    assert finished.input == running.input
    assert finished.started_at == running.started_at
    assert finished.finished_at is not None
    assert [entry.message for entry in finished.events] == ["job queued", "start", "terminal"]
    assert repo.finish_if_running(
        running, status="failed" if status == "succeeded" else "succeeded",
        finished_at="2026-10-07T00:03:00+00:00", event=event,
    ) is None
    assert repo.get(running.id).status == status
    assert len(repo.get(running.id).events) == 3


@pytest.mark.parametrize("backend", ["sqlalchemy", "sqlite"])
@pytest.mark.parametrize("drift", ["action", "input", "started", "finished", "status"])
def test_job_finish_rejects_changed_running_record(client, tmp_path, backend, drift):
    repo = (SqlAlchemyJobRepository() if backend == "sqlalchemy"
            else SqliteJobRepository(tmp_path / "jobs.sqlite"))
    running = _running(repo)
    changes = {
        "action": {"action": "other"},
        "input": {"input": {**running.input, "corePlanId": "other-plan"}},
        "started": {"started_at": "2026-10-07T00:01:30+00:00"},
        "finished": {"finished_at": "2026-10-07T00:01:30+00:00"},
        "status": {"status": "reconciliation_required"},
    }
    repo.save(replace(running, **changes[drift]))

    assert repo.finish_if_running(
        running, status="succeeded", finished_at="2026-10-07T00:02:00+00:00",
        event=JobEvent(3, "info", "finish", {}),
    ) is None
    retained = repo.get(running.id)
    assert retained is not None and retained.status != "succeeded"
    assert [event.message for event in retained.events] == ["job queued", "start"]


@pytest.mark.parametrize("backend", ["sqlalchemy", "sqlite"])
def test_job_finish_rolls_back_status_if_event_history_advanced(client, tmp_path, backend):
    repo = (SqlAlchemyJobRepository() if backend == "sqlalchemy"
            else SqliteJobRepository(tmp_path / "jobs.sqlite"))
    running = _running(repo)
    repo.save(replace(running, events=[*running.events, JobEvent(3, "info", "another event", {})]))

    assert repo.finish_if_running(
        running, status="succeeded", finished_at="2026-10-07T00:02:00+00:00",
        event=JobEvent(3, "info", "finish", {}),
    ) is None

    retained = repo.get(running.id)
    assert retained is not None and retained.status == "running"
    assert retained.finished_at is None
    assert [event.message for event in retained.events] == ["job queued", "start", "another event"]


def test_two_sqlite_terminal_writers_cannot_overwrite_each_other(tmp_path):
    database = tmp_path / "jobs.sqlite"
    first = SqliteJobRepository(database)
    second = SqliteJobRepository(database)
    running = _running(first)
    barrier = Barrier(2)

    def finish(repo, status):
        barrier.wait()
        return repo.finish_if_running(
            running, status=status, finished_at="2026-10-07T00:02:00+00:00",
            event=JobEvent(3, "info", status, {}),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(finish, first, "succeeded"), pool.submit(finish, second, "failed")]
        results = [future.result() for future in futures]

    assert sum(result is not None for result in results) == 1
    winner = next(result for result in results if result is not None)
    retained = first.get(running.id)
    assert retained is not None and retained.status == winner.status
    assert retained.events[-1].message == winner.status
    assert len(retained.events) == 3
