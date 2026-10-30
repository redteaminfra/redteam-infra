# Copyright (c) 2026, Oracle and/or its affiliates.
"""Atomic terminal bootstrap claim handoff, with no runtime teardown dispatch."""

from contextlib import contextmanager
from dataclasses import replace

import pytest

from app.domain import JobEvent
from app.storage.database import db
from app.storage import models as _models  # noqa: F401 - register tables before create_all
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun, job_event_digest,
    handoff_claim_digest,
)


FINAL = "provider bootstrap completed; strict host proof pending"
NOW = "2026-10-08T00:00:00+00:00"
SCOPE_SHA256 = "a" * 64


@contextmanager
def _repository(kind, tmp_path):
    if kind == "sqlite":
        yield SqliteJobRepository(tmp_path / "handoff.sqlite")
    else:
        state = db.configure("sqlite:///:memory:")
        with db.bind(state):
            db.create_all()
            yield SqlAlchemyJobRepository()


def _job(*, phase="awaiting_strict_host_proof", action="provider_keyed_initial"):
    return StoredJobRun(
        id="parent", action=action, status="running", target="engagement:e1",
        target_type="engagement", target_id="e1", requested_by="test",
        input={"phase": phase, "claimOwner": "bootstrap", "claimToken": "old",
               "claimExpiresAt": NOW}, artifact_refs=[], created_at=NOW,
        started_at=NOW, finished_at=None,
        events=[JobEvent(1, "info", "parent started", {"chainId": "one"}),
                JobEvent(2, "info", FINAL, {"chainIds": ["one", "two"]})],
    )


def _fence(repository, original, **changes):
    arguments = dict(
        old_owner="bootstrap", old_token="old", new_owner="teardown",
        new_token="new", claimed_at=NOW, expires_at="2026-10-08T00:05:00+00:00",
        expected_event_count=len(original.events),
        expected_event_digest=job_event_digest(original.events),
        expected_final_message=FINAL,
        confirmed_scope_sha256=SCOPE_SHA256,
    )
    arguments.update(changes)
    return repository.fence_terminal_provider_bootstrap_handoff("parent", **arguments)


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_handoff_rotates_claim_and_fences_stale_writer(kind, tmp_path):
    with _repository(kind, tmp_path) as repository:
        original = repository.save(_job())
        winner = _fence(repository, original)
        assert winner is not None
        assert winner.input["phase"] == "teardown_handoff_pending"
        assert (winner.input["claimOwner"], winner.input["claimToken"]) == ("teardown", "new")
        assert len(winner.events) == 3
        assert winner.events[-1].message == "provider bootstrap claim fenced for teardown handoff"
        assert winner.events[-1].data == {
            "phase": "teardown_handoff_pending",
            "sourceEventSha256": job_event_digest(original.events),
            "scopeSnapshotSha256": SCOPE_SHA256,
            "handoffClaimSha256": handoff_claim_digest(
                owner="teardown", token="new", claimed_at=NOW,
                expires_at="2026-10-08T00:05:00+00:00"),
        }
        assert _fence(repository, original) is None
        assert repository.save_if_leased(replace(original, input=dict(original.input)), owner="bootstrap", token="old") is None
        assert repository.renew_lease("parent", owner="bootstrap", token="old",
                                      heartbeat_at=NOW, expires_at=NOW) is None
        assert repository.get("parent") == winner


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("drift", ["phase", "token", "count", "digest", "message", "earlier_event", "action", "scope_hash"])
def test_handoff_rejects_stale_or_ambiguous_snapshot(kind, tmp_path, drift):
    with _repository(kind, tmp_path) as repository:
        original = _job(phase="other" if drift == "phase" else "awaiting_strict_host_proof",
                        action="other" if drift == "action" else "provider_keyed_initial")
        if drift == "token":
            original = replace(original, input={**original.input, "claimToken": "different"})
        if drift == "earlier_event":
            original = replace(original, events=[JobEvent(1, "info", "changed", {}), original.events[1]])
        original = repository.save(original)
        expected = _job()
        kwargs = {}
        if drift == "count":
            kwargs["expected_event_count"] = 3
        if drift == "digest":
            kwargs["expected_event_digest"] = "0" * 64
        if drift == "message":
            kwargs["expected_final_message"] = "incorrect"
        if drift == "scope_hash":
            kwargs["confirmed_scope_sha256"] = "invalid"
        assert _fence(repository, expected, **kwargs) is None
        assert repository.get("parent") == original


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_handoff_rejects_same_claim_identity(kind, tmp_path):
    with _repository(kind, tmp_path) as repository:
        original = repository.save(_job())
        assert _fence(repository, original, new_owner="bootstrap", new_token="old") is None
        assert repository.get("parent") == original
