# Copyright (c) 2026, Oracle and/or its affiliates.
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.jobs import (
    JobExecutionError,
    enqueue_job,
    get_job_run,
    list_job_runs,
    list_job_run_page,
    run_job,
)
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun


class JobRepositoryTests(unittest.TestCase):
    def test_summary_pages_are_ordered_counted_and_do_not_load_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            created = [
                enqueue_job(
                    action=f"action_{index}",
                    target_type="system",
                    target_id=str(index),
                    requested_by="operator@example.invalid",
                    input_data={},
                    repository=repository,
                )
                for index in range(3)
            ]
            repository._events = lambda _job_id: (_ for _ in ()).throw(AssertionError("summary query loaded events"))  # type: ignore[method-assign]

            page = list_job_run_page(limit=1, offset=1, repository=repository)

            self.assertEqual(page.total, 3)
            self.assertEqual(page.limit, 1)
            self.assertEqual(page.offset, 1)
            self.assertEqual([job.id for job in page.jobs], [created[1].id])
            self.assertTrue(page.to_dict()["pagination"]["hasMore"])

    def test_enqueue_detail_and_run_persist_job_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "barragan.sqlite3"
            repository = SqliteJobRepository(database_path)

            queued = enqueue_job(
                action="deploy_plan",
                target_type="revision",
                target_id="rev-test",
                requested_by="operator@example.invalid",
                input_data={"mode": "dry_run"},
                repository=repository,
            )

            self.assertEqual(queued.status, "queued")
            self.assertEqual(queued.events[0].message, "job queued")

            persisted_repository = SqliteJobRepository(database_path)
            summaries = list_job_runs(repository=persisted_repository)
            detail = get_job_run(queued.id, repository=persisted_repository)
            completed = run_job(queued.id, repository=persisted_repository)

            self.assertEqual([summary.id for summary in summaries], [queued.id])
            self.assertIsNotNone(detail)
            self.assertEqual(detail.input["mode"], "dry_run")
            self.assertEqual(completed.status, "succeeded")
            self.assertIn("dry-run:deploy_plan", completed.artifact_refs)
            self.assertEqual([event.sequence for event in completed.events], [1, 2, 3, 4])
            self.assertFalse(completed.events[2].data["mutation"])

    def test_run_records_failed_status_for_unsupported_action(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action="unsupported_action",
                target_type="system",
                target_id="manual",
                requested_by="operator@example.invalid",
                input_data={},
                repository=repository,
            )

            failed = run_job(queued.id, repository=repository)

            self.assertEqual(failed.status, "failed")
            self.assertEqual(failed.events[-1].level, "error")
            self.assertIn("unsupported plan-only action", failed.events[-1].message)

    def test_run_rejects_non_queued_job(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action="deploy_plan",
                target_type="revision",
                target_id="rev-test",
                requested_by="operator@example.invalid",
                input_data={},
                repository=repository,
            )
            run_job(queued.id, repository=repository)

            with self.assertRaises(JobExecutionError):
                run_job(queued.id, repository=repository)

    def test_list_for_engagement_filters_target_and_input_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            direct = enqueue_job(
                action="deploy_plan",
                target_type="engagement",
                target_id="eng-1",
                requested_by="operator@example.invalid",
                input_data={},
                repository=repository,
            )
            indirect = enqueue_job(
                action="deploy_plan",
                target_type="oci-compartment",
                target_id="barragan-testing",
                requested_by="operator@example.invalid",
                input_data={"engagementId": "eng-1"},
                repository=repository,
            )
            enqueue_job(
                action="deploy_plan",
                target_type="engagement",
                target_id="eng-2",
                requested_by="operator@example.invalid",
                input_data={},
                repository=repository,
            )

            selected = repository.list_for_engagement("eng-1")

            self.assertEqual({job.id for job in selected}, {direct.id, indirect.id})


def _lease_job(*, phase=None):
    return StoredJobRun(
        id="job-phase", action="provider_keyed_initial", status="running",
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        requested_by="operator", input={"engagementId": "eng-1", **({"phase": phase} if phase else {})},
        artifact_refs=[], created_at="2026-10-07T00:00:00+00:00",
        started_at="2026-10-07T00:00:01+00:00", finished_at=None,
        events=[JobEvent(1, "info", "started", {})],
    )


def _claim(repository, owner, *, phase=None, at="2026-10-07T00:01:00+00:00"):
    options = {"eligible_phases": phase} if phase is not None else {}
    return repository.claim_lease(
        "job-phase", owner=owner, token=f"token-{owner}", claimed_at=at,
        expires_at="2026-10-07T00:02:00+00:00" if owner == "a" else "2026-10-07T00:04:00+00:00",
        eligible_statuses={"running"}, **options,
    )


def test_two_sqlite_workers_claim_only_current_phase_with_atomic_cas(tmp_path):
    database_path = tmp_path / "phase-claim.sqlite"
    first = SqliteJobRepository(database_path)
    second = SqliteJobRepository(database_path)
    first.save(_lease_job(phase="attachment_pending"))

    claimed = _claim(first, "a", phase={"attachment_pending"})
    assert claimed is not None
    assert _claim(second, "b", phase={"attachment_pending"}) is None
    assert first.save_if_leased(
        replace(claimed, input={**claimed.input, "phase": "awaiting_host_proof"}),
        owner="a", token="token-a",
    ) is not None

    after_expiry = "2026-10-07T00:02:01+00:00"
    assert _claim(second, "b", phase={"attachment_pending"}, at=after_expiry) is None
    winner = _claim(second, "b", phase={"awaiting_host_proof"}, at=after_expiry)
    assert winner is not None
    assert winner.input["claimToken"] == "token-b"
    assert winner.input["phase"] == "awaiting_host_proof"


@pytest.mark.parametrize("invalid", [set(), {""}, {" pending"}, {"pending", 3}, "pending"])
def test_invalid_phase_allowlist_never_claims(tmp_path, invalid):
    repository = SqliteJobRepository(tmp_path / "phase-claim.sqlite")
    repository.save(_lease_job(phase="pending"))
    assert _claim(repository, "a", phase=invalid) is None
    assert "claimToken" not in repository.get("job-phase").input


def test_sqlalchemy_phase_claim_and_legacy_phase_free_callers():
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        repository = SqlAlchemyJobRepository()
        repository.save(_lease_job(phase="attachment_pending"))
        assert _claim(repository, "a", phase={"wrong_phase"}) is None
        assert _claim(repository, "a", phase=set()) is None
        assert _claim(repository, "a", phase={"attachment_pending"}) is not None
        repository.save(replace(_lease_job(), id="job-legacy"))
        assert repository.claim_lease(
            "job-legacy", owner="legacy", token="legacy-token",
            claimed_at="2026-10-07T00:01:00+00:00", expires_at="2026-10-07T00:02:00+00:00",
            eligible_statuses={"running"},
        ) is not None


if __name__ == "__main__":
    unittest.main()
