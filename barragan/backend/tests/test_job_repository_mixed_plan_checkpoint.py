# Copyright (c) 2026, Oracle and/or its affiliates.
"""Mixed two-provider checkpoint CAS on both persisted repository backends."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.storage import models as _models  # noqa: F401 - register tables
from app.storage.models import CoreMutationLeaseModel
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun, job_event_digest,
)


@contextmanager
def repository(kind, tmp_path):
    if kind == "sqlite":
        yield SqliteJobRepository(tmp_path / "mixed-parent.sqlite")
    else:
        state = db.configure("sqlite:///:memory:")
        with db.bind(state):
            db.create_all()
            db.session.add(CoreMutationLeaseModel(
                engagement_id="eng-1", owner_id="plan-1", operation="provider_keyed_initial"))
            db.session.commit()
            yield SqlAlchemyJobRepository()


def _job():
    now = datetime.now(timezone.utc)
    return StoredJobRun(
        "mixed-parent-1", "provider_keyed_mixed_initial", "queued", "engagement:eng-1",
        "engagement", "eng-1", "operator",
        {"engagementId": "eng-1", "coreJobId": "core-1", "corePlanId": "plan-1",
         "revisionId": "rev-1", "reviewFingerprint": "a" * 64,
         "chainIds": ["lin-1", "do-1"],
         "orderedProviders": ["linode", "digitalocean"], "phase": "queued",
         "mutation": True, "claimOwner": "worker", "claimToken": "token",
         "claimClaimedAt": now.isoformat(),
         "claimExpiresAt": (now + timedelta(minutes=10)).isoformat()},
        [], now.isoformat(), None, None,
        [JobEvent(1, "info", "mixed provider plans queued",
                  {"coreJobId": "core-1", "reviewFingerprint": "a" * 64})],
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_mixed_checkpoint_cas_is_append_only_and_rejects_stale_snapshot(kind, tmp_path):
    with repository(kind, tmp_path) as jobs:
        queued = jobs.save(_job())
        planning = JobEvent(2, "info", "mixed provider planning started", {})
        kwargs = dict(owner="worker", token="token", lease_owner="plan-1",
                      expected_event_digest=job_event_digest(queued.events),
                      next_phase="planning", event=planning)
        assert jobs.append_mixed_plan_phase_if_claimed(
            queued, **{**kwargs, "token": "other"}) is None
        assert jobs.append_mixed_plan_phase_if_claimed(
            queued, **{**kwargs, "expected_event_digest": "0" * 64}) is None
        active = jobs.append_mixed_plan_phase_if_claimed(queued, **kwargs)
        assert active.input["phase"] == "planning"
        assert [event.message for event in active.events] == [
            "mixed provider plans queued", "mixed provider planning started"]
        assert jobs.append_mixed_plan_phase_if_claimed(queued, **kwargs) is None
        first = JobEvent(3, "info", "first mixed provider plan saved",
                         {"provider": "linode", "chainId": "lin-1",
                          "receiptSha256": "b" * 64, "planSha256": "c" * 64,
                          "journalSha256": "d" * 64})
        next_kwargs = dict(owner="worker", token="token", lease_owner="plan-1",
                           expected_event_digest=job_event_digest(active.events),
                           next_phase="first_plan_saved", event=first)
        assert jobs.append_mixed_plan_phase_if_claimed(
            active, **{**next_kwargs, "event": JobEvent(3, "info", first.message,
                                                      {**first.data, "provider": "digitalocean"})}) is None
        saved = jobs.append_mixed_plan_phase_if_claimed(active, **next_kwargs)
        assert saved.input["phase"] == "first_plan_saved" and len(saved.events) == 3
        if kind == "sqlalchemy":
            db.session.query(CoreMutationLeaseModel).filter_by(engagement_id="eng-1").delete()
            db.session.commit()
            second = JobEvent(4, "info", "second mixed provider plan saved",
                              {"provider": "digitalocean", "chainId": "do-1",
                               "receiptSha256": "e" * 64, "planSha256": "f" * 64,
                               "journalSha256": "0" * 64})
            assert jobs.append_mixed_plan_phase_if_claimed(
                saved, owner="worker", token="token", lease_owner="plan-1",
                expected_event_digest=job_event_digest(saved.events),
                next_phase="second_plan_saved", event=second) is None
            assert jobs.get(saved.id).input["phase"] == "first_plan_saved"
