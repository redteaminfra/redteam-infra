# Copyright (c) 2026, Oracle and/or its affiliates.
"""The second mixed-append child uses the same claimed append lease fence."""

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun, job_event_digest,
)
from app.storage.models import CoreMutationLeaseModel


ACTION = "provider_keyed_mixed_append_second_apply_child"


@contextmanager
def repository(kind, tmp_path):
    if kind == "sqlite":
        repo = SqliteJobRepository(tmp_path / "second-append.sqlite")
        with repo._connect() as connection:
            connection.execute(
                "CREATE TABLE core_mutation_leases ("
                "engagement_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, "
                "operation TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO core_mutation_leases (engagement_id, owner_id, operation) "
                "VALUES (?, ?, ?)",
                ("eng-opaque", "plan-core", "provider_keyed_mixed_append"),
            )
        yield repo
    else:
        state = db.configure("sqlite:///:memory:")
        with db.bind(state):
            db.create_all()
            db.session.add(CoreMutationLeaseModel(
                engagement_id="eng-opaque", owner_id="plan-core",
                operation="provider_keyed_mixed_append"))
            db.session.commit()
            yield SqlAlchemyJobRepository()


def row(at: str, *, provider_index: int = 1) -> StoredJobRun:
    return StoredJobRun(
        "job-second", ACTION, "running", "engagement:eng-opaque", "engagement",
        "eng-opaque", "operator",
        {"engagementId": "eng-opaque", "coreJobId": "job-core",
         "corePlanId": "plan-core", "appendParentId": "job-parent",
         "reviewSha256": "a" * 64, "provider": "linode",
         "providerIndex": provider_index, "mutation": True},
        [], at, at, None,
        [JobEvent(1, "info", "queued", {}), JobEvent(2, "info", "started", {})],
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_second_append_claimed_journal_and_lease(kind, tmp_path):
    at = datetime.now(timezone.utc)
    started = at.isoformat()
    heartbeat = (at + timedelta(seconds=1)).isoformat()
    expiry = (at + timedelta(minutes=2)).isoformat()
    with repository(kind, tmp_path) as repo:
        repo.save(row(started))
        current = repo.claim_lease(
            "job-second", owner="worker", token="token", claimed_at=started,
            expires_at=expiry, eligible_statuses={"running"})
        assert current is not None
        event = JobEvent(3, "info", "second command intended", {})
        appended = repo.append_event_if_running_claimed(
            current, owner="worker", token="token",
            expected_event_digest=job_event_digest(current.events),
            heartbeat_at=heartbeat, expires_at=expiry, event=event)
        assert appended is not None and appended.events[-1] == event
        assert repo.append_event_if_running_claimed(
            current, owner="worker", token="token",
            expected_event_digest=job_event_digest(current.events),
            heartbeat_at=heartbeat, expires_at=expiry, event=event) is None
        finished = repo.finish_if_running_claimed(
            appended, owner="worker", token="token",
            expected_event_digest=job_event_digest(appended.events),
            status="succeeded", finished_at=(at + timedelta(seconds=2)).isoformat(),
            event=JobEvent(4, "info", "second done", {}))
        assert finished is not None and finished.status == "succeeded"
        assert finished.input == row(started).input


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_second_append_wrong_index_or_lease_cannot_append(kind, tmp_path):
    at = datetime.now(timezone.utc)
    started = at.isoformat()
    expiry = (at + timedelta(minutes=2)).isoformat()
    with repository(kind, tmp_path) as repo:
        repo.save(row(started))
        current = repo.claim_lease(
            "job-second", owner="worker", token="token", claimed_at=started,
            expires_at=expiry, eligible_statuses={"running"})
        assert current is not None
        kwargs = dict(
            owner="worker", token="token",
            expected_event_digest=job_event_digest(current.events),
            heartbeat_at=(at + timedelta(seconds=1)).isoformat(),
            expires_at=expiry, event=JobEvent(3, "info", "intent", {}),
        )
        wrong = replace(current, input={**current.input, "providerIndex": 0})
        assert repo.append_event_if_running_claimed(wrong, **kwargs) is None
        if kind == "sqlite":
            with repo._connect() as connection:
                connection.execute("UPDATE core_mutation_leases SET operation = ?",
                                   ("provider_keyed_initial",))
        else:
            db.session.execute(text(
                "UPDATE core_mutation_leases SET operation = 'provider_keyed_initial'"))
            db.session.commit()
        assert repo.append_event_if_running_claimed(current, **kwargs) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_second_append_cannot_finish_after_lease_drift(kind, tmp_path):
    at = datetime.now(timezone.utc)
    started = at.isoformat()
    expiry = (at + timedelta(minutes=2)).isoformat()
    with repository(kind, tmp_path) as repo:
        repo.save(row(started))
        current = repo.claim_lease(
            "job-second", owner="worker", token="token", claimed_at=started,
            expires_at=expiry, eligible_statuses={"running"})
        assert current is not None
        if kind == "sqlite":
            with repo._connect() as connection:
                connection.execute("UPDATE core_mutation_leases SET operation = ?",
                                   ("provider_keyed_initial",))
        else:
            db.session.execute(text(
                "UPDATE core_mutation_leases SET operation = 'provider_keyed_initial'"))
            db.session.commit()
        assert repo.finish_if_running_claimed(
            current, owner="worker", token="token",
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=(at + timedelta(seconds=1)).isoformat(),
            event=JobEvent(3, "info", "second done", {})) is None
        assert repo.get(current.id).status == "running"
