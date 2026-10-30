# Copyright (c) 2026, Oracle and/or its affiliates.
"""A POST and startup recovery cannot schedule two published coordinators."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event, Thread, current_thread
import sqlite3
import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.services.provider_keyed_mixed_published_dispatch_claim import (
    DispatchClaim, claim_published_mixed_dispatch, dispatch_claim_current,
    release_published_mixed_dispatch,
    run_claimed_published_mixed_dispatch,
    schedule_published_mixed_dispatch,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_mixed_published_teardown_collector import (
    PublishedMixedTeardownCollectionAttention,
    collect_published_mixed_initial_teardown,
)
from app.storage.job_repository import SqlAlchemyJobRepository
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_reservation import _persisted


def test_post_and_startup_race_for_one_durable_dispatch_claim(
        ready, tmp_path, monkeypatch):
    class DevTestConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'published-claim.sqlite3'}"

    app = create_app(DevTestConfig)
    with app.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        parent = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
    barrier = Barrier(2)
    scheduled = []

    def contend(name):
        with app.storage_context():
            barrier.wait()
            return schedule_published_mixed_dispatch(
                parent.id, environment="devtest",
                positive_control_ipv4="1.1.1.1", name=name,
                coordinator=lambda *_a, **_k: None,
                start_task=lambda _callback, *, name: scheduled.append(name),
                job_repository=SqlAlchemyJobRepository(),
                lease_lookup=_db_lease_lookup)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in
                   (pool.submit(contend, "POST"), pool.submit(contend, "startup"))]
    assert results.count(True) == 1
    assert len(scheduled) == 1
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        marker = next(row for row in jobs.list_for_engagement(parent.target_id)
                      if row.action == "provider_keyed_mixed_published_dispatch_claim")
        claim = DispatchClaim(
            parent.id, marker.id, marker.input["claimOwner"],
            marker.input["claimToken"])
        assert dispatch_claim_current(claim, job_repository=jobs)
        import app.services.provider_keyed_mixed_published_teardown_collector as collector_module
        monkeypatch.setattr(
            collector_module, "active_core_connection_details",
            lambda *_args: (collection.review.source.core_job_id, []))
        monkeypatch.setattr(
            collector_module, "_core_inspector_scope",
            lambda *_args, **_kwargs: collection.core_inspector_scope)
        def observed(_initial, provider, fence):
            at = datetime.now(timezone.utc)
            assert jobs.renew_lease(
                claim.marker_id, owner=claim.owner,
                token=claim.token, heartbeat_at=at.isoformat(),
                expires_at=(at + timedelta(minutes=2)).isoformat()) is not None
            fence()
            return collection.observations[provider]

        refreshed = collect_published_mixed_initial_teardown(
            collection.review.source.engagement_id,
            collection.review.source.core_job_id,
            job_repository=jobs, lease_lookup=_db_lease_lookup,
            allow_teardown_fence=True, fresh_observer=observed)
        assert refreshed.review == collection.review
        unrelated = jobs.save_if_absent(replace(marker, id=f"{marker.id}-other"))

        def drift_unrelated(_initial, provider, fence):
            jobs.save(replace(unrelated, input={**unrelated.input, "drift": True}))
            fence()
            return collection.observations[provider]

        with pytest.raises(PublishedMixedTeardownCollectionAttention):
            collect_published_mixed_initial_teardown(
                collection.review.source.engagement_id,
                collection.review.source.core_job_id,
                job_repository=jobs, lease_lookup=_db_lease_lookup,
                allow_teardown_fence=True, fresh_observer=drift_unrelated)
        assert claim_published_mixed_dispatch(
            parent.id, job_repository=jobs, lease_lookup=_db_lease_lookup) is None
        release_published_mixed_dispatch(claim, job_repository=jobs)
        resumed = claim_published_mixed_dispatch(
            parent.id, job_repository=jobs, lease_lookup=_db_lease_lookup)
        assert resumed is not None and resumed.token != claim.token
        release_published_mixed_dispatch(resumed, job_repository=jobs)

        with pytest.raises(RuntimeError, match="scheduler unavailable"):
            schedule_published_mixed_dispatch(
                parent.id, environment="devtest",
                positive_control_ipv4="1.1.1.1", name="POST",
                coordinator=lambda *_a, **_k: None,
                start_task=lambda *_a, **_k: (_ for _ in ()).throw(
                    RuntimeError("scheduler unavailable")),
                job_repository=jobs, lease_lookup=_db_lease_lookup)
        assert schedule_published_mixed_dispatch(
            parent.id, environment="devtest",
            positive_control_ipv4="1.1.1.1", name="retry",
            coordinator=lambda *_a, **_k: None,
            start_task=lambda _callback, *, name: scheduled.append(name),
            job_repository=jobs, lease_lookup=_db_lease_lookup)
        assert scheduled[-1] == "retry"


def _claimed_worker(ready, tmp_path, monkeypatch):
    class DevTestConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'heartbeat.sqlite3'}"

    app = create_app(DevTestConfig)
    with app.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        parent = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        claim = claim_published_mixed_dispatch(
            parent.id, job_repository=jobs, lease_lookup=_db_lease_lookup)
        assert claim is not None
        unrelated = jobs.save_if_absent(replace(parent, id="job-unrelated-heartbeat"))
    return app, parent, claim, unrelated


def test_sqlite_writer_contention_loses_dispatch_before_claim_expiry(
        ready, tmp_path, monkeypatch):
    from sqlalchemy import text
    from sqlalchemy.exc import OperationalError
    from app.storage.database import db
    import app.services.provider_keyed_mixed_published_dispatch_claim as dispatch

    app, parent, claim, unrelated = _claimed_worker(ready, tmp_path, monkeypatch)
    writer_ready, heartbeat_finished = Event(), Event()
    lock_failures, rollback_threads, thread_errors, provider_actions = [], [], [], []

    class ObservedThread(Thread):
        def run(self):
            try:
                super().run()
            finally:
                heartbeat_finished.set()

    class HeartbeatJobs(SqlAlchemyJobRepository):
        def renew_lease(self, *args, **kwargs):
            assert writer_ready.wait(5)
            # This setting belongs only to this heartbeat connection.
            db.session.execute(text("PRAGMA busy_timeout=1"))
            try:
                return super().renew_lease(*args, **kwargs)
            except OperationalError as error:
                assert isinstance(error.orig, sqlite3.OperationalError)
                lock_failures.append(type(error.orig))
                raise

    monkeypatch.setattr(dispatch, "Thread", ObservedThread)
    monkeypatch.setattr(dispatch, "SqlAlchemyJobRepository", HeartbeatJobs)
    monkeypatch.setattr("threading.excepthook", thread_errors.append)
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        marker_before = jobs.get(claim.marker_id)
        coordinator_session = db.session()
        session_type = type(coordinator_session)
        original_rollback = session_type.rollback

        def observed_rollback(session):
            if current_thread().name == "barragan-mixed-published-dispatch-heartbeat":
                assert session is not coordinator_session
                rollback_threads.append(current_thread().name)
                original_rollback(session)
            else:
                original_rollback(session)

        monkeypatch.setattr(session_type, "rollback", observed_rollback)

        def coordinator(_parent_id, *, dispatch_fence, **_kwargs):
            dispatch_fence()
            with sqlite3.connect(tmp_path / "heartbeat.sqlite3") as writer:
                writer.execute("BEGIN IMMEDIATE")
                writer_ready.set()
                assert heartbeat_finished.wait(5)
                writer.rollback()
            # The actual failed UPDATE did not alter or expire the claim.
            db.session.expire_all()
            assert jobs.get(claim.marker_id) == marker_before
            assert dispatch_claim_current(claim, job_repository=jobs)
            dispatch_fence()
            provider_actions.append("must not reach next provider action")
            return parent

        with pytest.raises(ValueError, match="dispatch claim changed"):
            run_claimed_published_mixed_dispatch(
                claim, environment="devtest", positive_control_ipv4="1.1.1.1",
                coordinator=coordinator, job_repository=jobs,
                heartbeat_seconds=0.001)
        assert lock_failures == [sqlite3.OperationalError]
        assert len(rollback_threads) == 1
        assert thread_errors == []
        assert provider_actions == []
        assert jobs.get(parent.id) == parent
        assert jobs.get(unrelated.id) == unrelated
        marker_after = jobs.get(claim.marker_id)
        assert marker_after.events == marker_before.events
        assert marker_after.input["claimOwner"] == claim.owner
        assert marker_after.input["claimToken"] == claim.token
        assert not dispatch_claim_current(claim, job_repository=jobs)


@pytest.mark.parametrize("ownership_lost", [False, True])
def test_heartbeat_renewal_and_none_ownership_loss(
        ready, tmp_path, monkeypatch, ownership_lost):
    from app.storage.database import db
    import app.services.provider_keyed_mixed_published_dispatch_claim as dispatch

    app, parent, claim, unrelated = _claimed_worker(ready, tmp_path, monkeypatch)
    renewed, heartbeat_finished = Event(), Event()
    saved_renewals, provider_actions = [], []

    class ObservedThread(Thread):
        def run(self):
            try:
                super().run()
            finally:
                heartbeat_finished.set()

    class HeartbeatJobs(SqlAlchemyJobRepository):
        def renew_lease(self, *args, **kwargs):
            if ownership_lost:
                return None
            result = super().renew_lease(*args, **kwargs)
            saved_renewals.append(result)
            renewed.set()
            return result

    monkeypatch.setattr(dispatch, "Thread", ObservedThread)
    monkeypatch.setattr(dispatch, "SqlAlchemyJobRepository", HeartbeatJobs)
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        marker_before = jobs.get(claim.marker_id)

        def coordinator(_parent_id, *, dispatch_fence, **_kwargs):
            dispatch_fence()
            assert (heartbeat_finished if ownership_lost else renewed).wait(5)
            db.session.expire_all()
            assert dispatch_claim_current(claim, job_repository=jobs)
            dispatch_fence()
            provider_actions.append("next coordinator phase")
            return parent

        if ownership_lost:
            with pytest.raises(ValueError, match="dispatch claim changed"):
                run_claimed_published_mixed_dispatch(
                    claim, environment="devtest", positive_control_ipv4="1.1.1.1",
                    coordinator=coordinator, job_repository=jobs,
                    heartbeat_seconds=0.001)
            assert saved_renewals == []
            assert provider_actions == []
        else:
            assert run_claimed_published_mixed_dispatch(
                claim, environment="devtest", positive_control_ipv4="1.1.1.1",
                coordinator=coordinator, job_repository=jobs,
                heartbeat_seconds=0.001) == parent
            assert saved_renewals and all(row is not None for row in saved_renewals)
            assert all(row.events == marker_before.events for row in saved_renewals)
            assert provider_actions == ["next coordinator phase"]
        assert heartbeat_finished.wait(5)
        assert jobs.get(parent.id) == parent
        assert jobs.get(unrelated.id) == unrelated
        assert jobs.get(claim.marker_id).events == marker_before.events


def test_lost_is_set_before_rollback_even_when_rollback_fails(
        ready, tmp_path, monkeypatch, caplog):
    from app.storage.database import db
    import app.services.provider_keyed_mixed_published_dispatch_claim as dispatch

    app, parent, claim, unrelated = _claimed_worker(ready, tmp_path, monkeypatch)
    coordinator_ready, heartbeat_finished = Event(), Event()
    fences, renewals, rollbacks, thread_errors = [], [], [], []

    class ObservedThread(Thread):
        def run(self):
            try:
                super().run()
            finally:
                heartbeat_finished.set()

    class FailedHeartbeatJobs(SqlAlchemyJobRepository):
        def renew_lease(self, *args, **kwargs):
            assert coordinator_ready.wait(5)
            renewals.append(True)
            raise RuntimeError("private renewal SQL parameters")

    monkeypatch.setattr(dispatch, "Thread", ObservedThread)
    monkeypatch.setattr(dispatch, "SqlAlchemyJobRepository", FailedHeartbeatJobs)
    monkeypatch.setattr("threading.excepthook", thread_errors.append)
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        coordinator_session = db.session()
        original_rollback = type(coordinator_session).rollback

        def failed_rollback(session):
            if current_thread().name == "barragan-mixed-published-dispatch-heartbeat":
                assert session is not coordinator_session
                # The lost flag must already reject before cleanup can fail.
                with pytest.raises(ValueError, match="dispatch claim changed"):
                    fences[0]()
                rollbacks.append(True)
                raise RuntimeError("private rollback SQL parameters")
            return original_rollback(session)

        monkeypatch.setattr(type(coordinator_session), "rollback", failed_rollback)

        def coordinator(_parent_id, *, dispatch_fence, **_kwargs):
            fences.append(dispatch_fence)
            coordinator_ready.set()
            assert heartbeat_finished.wait(5)
            assert dispatch_claim_current(claim, job_repository=jobs)
            dispatch_fence()
            pytest.fail("must not reach later coordinator action")

        with pytest.raises(ValueError, match="dispatch claim changed"):
            run_claimed_published_mixed_dispatch(
                claim, environment="devtest", positive_control_ipv4="1.1.1.1",
                coordinator=coordinator, job_repository=jobs,
                heartbeat_seconds=0.001)
        assert renewals == rollbacks == [True]
        assert thread_errors == []
        assert "private renewal" not in caplog.text
        assert "private rollback" not in caplog.text
        assert jobs.get(parent.id) == parent
        assert jobs.get(unrelated.id) == unrelated


def test_failed_worker_releases_claim_for_exact_restart(ready, tmp_path, monkeypatch):
    class DevTestConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'published-worker.sqlite3'}"

    app = create_app(DevTestConfig)
    with app.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        parent = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        claim = claim_published_mixed_dispatch(
            parent.id, job_repository=jobs, lease_lookup=_db_lease_lookup)
        assert claim is not None

        def fail_after_fence(_parent_id, *, dispatch_fence, **_kwargs):
            dispatch_fence()
            raise RuntimeError("worker interrupted before provider command")

        with pytest.raises(RuntimeError, match="worker interrupted"):
            run_claimed_published_mixed_dispatch(
                claim, environment="devtest", positive_control_ipv4="1.1.1.1",
                coordinator=fail_after_fence, job_repository=jobs,
                lease_lookup=_db_lease_lookup, heartbeat_seconds=0.01)
        resumed = claim_published_mixed_dispatch(
            parent.id, job_repository=jobs, lease_lookup=_db_lease_lookup)
        assert resumed is not None and resumed.token != claim.token
        release_published_mixed_dispatch(resumed, job_repository=jobs)
