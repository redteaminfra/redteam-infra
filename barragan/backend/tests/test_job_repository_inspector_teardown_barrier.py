# Copyright (c) 2026, Oracle and/or its affiliates.
"""Atomic Inspector lifecycle versus comprehensive teardown insert barrier."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.storage.job_repository import SqliteJobRepository, StoredJobRun
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.database import db
from app.storage import models as _models  # noqa: F401
from app.storage import job_repository as storage
from test_job_repository_claimed_apply import repository


NOW = "2026-10-08T00:00:00+00:00"
NORMAL = ("inspector_inspection", "inspector_readiness", "inspector_cleanup")


def initial(action, *, suffix="1", engagement="eng-1", status=None):
    parent = action == "engagement_comprehensive_teardown"
    status = status or ("queued" if parent else "running")
    return StoredJobRun(
        id=f"job-{action}-{suffix}", action=action, status=status,
        target=f"engagement:{engagement}", target_type="engagement", target_id=engagement,
        requested_by="operator", input={"engagementId": engagement}, artifact_refs=[],
        created_at=NOW, started_at=None if parent else NOW, finished_at=None,
        events=[JobEvent(1, "info", "created", {})],
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("normal_action", NORMAL)
@pytest.mark.parametrize("first", ["parent", "normal"])
def test_either_insert_order_has_only_one_active_side(kind, normal_action, first, tmp_path):
    with repository(kind, tmp_path) as repo:
        other = SqliteJobRepository(repo.database_path) if kind == "sqlite" else repo.__class__()
        parent = initial("engagement_comprehensive_teardown")
        normal = initial(normal_action)
        winner, loser = (parent, normal) if first == "parent" else (normal, parent)
        assert repo.insert_inspector_teardown_barrier(winner) is not None
        assert other.insert_inspector_teardown_barrier(loser) is None
        assert repo.get(winner.id) is not None and repo.get(loser.id) is None
        assert len(repo.get(winner.id).events) == 1


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_parent_same_id_idempotency_and_terminal_opponent(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        prior = initial("inspector_readiness")
        repo.save(replace(prior, status="succeeded", finished_at=NOW))
        parent = initial("engagement_comprehensive_teardown")
        saved = repo.insert_inspector_teardown_barrier(parent)
        assert saved is not None
        assert saved.created_at == parent.created_at
        assert saved.started_at == parent.started_at
        assert saved.events == parent.events
        second = repo.insert_inspector_teardown_barrier(replace(parent, requested_by="different"))
        assert second == saved
        assert second.requested_by == "operator"
        assert len(second.events) == 1
        assert repo.insert_inspector_teardown_barrier(initial("inspector_cleanup", engagement="eng-2")) is not None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_terminal_parent_does_not_block_and_normal_id_cannot_update(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        parent = initial("engagement_comprehensive_teardown")
        repo.save(replace(parent, status="succeeded", started_at=NOW, finished_at=NOW))
        normal = initial("inspector_inspection")
        assert repo.insert_inspector_teardown_barrier(normal) is not None
        assert repo.insert_inspector_teardown_barrier(replace(normal, input={"other": True})) is None
        assert repo.get(normal.id).input == {"engagementId": "eng-1"}


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_invalid_job_action_or_status_rejected(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        with pytest.raises(ValueError):
            repo.insert_inspector_teardown_barrier(initial("other"))
        with pytest.raises(ValueError):
            repo.insert_inspector_teardown_barrier(initial("inspector_cleanup", status="queued"))


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_new_insert_preserves_request_identity_override(kind, tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "current_request_identity", lambda: SimpleNamespace(username="authenticated-user"))
    with repository(kind, tmp_path) as repo:
        saved = repo.insert_inspector_teardown_barrier(initial("inspector_readiness"))
        assert saved is not None and saved.requested_by == "authenticated-user"
        assert repo.get(saved.id).requested_by == "authenticated-user"


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("same_parent", [False, True])
def test_separate_connection_simultaneous_insert_has_one_winner(kind, same_parent, tmp_path):
    path = tmp_path / "race.sqlite"
    if kind == "sqlite":
        SqliteJobRepository(path)
        state = None
    else:
        state = db.configure(f"sqlite:///{path}")
        with db.bind(state):
            db.create_all()
    barrier = Barrier(2)
    candidates = [initial("engagement_comprehensive_teardown"),
                  initial("engagement_comprehensive_teardown") if same_parent
                  else initial("inspector_inspection")]

    def attempt(candidate):
        if kind == "sqlite":
            repo = SqliteJobRepository(path)
            barrier.wait(timeout=5)
            return repo.insert_inspector_teardown_barrier(candidate)
        with db.bind(state):
            repo = SqlAlchemyJobRepository()
            barrier.wait(timeout=5)
            return repo.insert_inspector_teardown_barrier(candidate)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, candidates))
    assert sum(result is not None for result in results) == (2 if same_parent else 1)
    if same_parent:
        assert results[0] == results[1]
    if kind == "sqlite":
        retained = SqliteJobRepository(path).list_for_engagement("eng-1")
    else:
        with db.bind(state):
            retained = SqlAlchemyJobRepository().list_for_engagement("eng-1")
    assert len(retained) == 1 and len(retained[0].events) == 1
