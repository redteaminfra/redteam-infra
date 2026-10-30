# Copyright (c) 2026, Oracle and/or its affiliates.
"""The SQLAlchemy append Apply child keeps its exact reservation across SQLite UTC normalization."""

from dataclasses import replace
from datetime import datetime, timezone

from app.domain import JobEvent
from app.services.provider_keyed_append_apply_job import _same_reserved_queued_child
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


def test_inserted_apply_child_is_exact_and_can_be_started(tmp_path):
    state = db.configure(f"sqlite:///{tmp_path / 'append-child.sqlite'}")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        created_at = datetime.now(timezone.utc).isoformat()
        child = StoredJobRun(
            "job-provider-keyed-append-apply-abc", "provider_keyed_edge_append_apply",
            "queued", "engagement:eng-abc", "engagement", "eng-abc", "operator",
            {"engagementId": "eng-abc", "parentJobId": "job-provider-keyed-append-abc",
             "coreJobId": "job-core", "corePlanId": "plan-core",
             "planJobId": "job-provider-keyed-append-plan-abc", "mutation": True},
            [], created_at, None, None,
            [JobEvent(1, "info", "provider append Apply child reserved", {
                "planJournalSha256": "a" * 64, "reservationId": "b" * 32,
            })],
        )
        stored = jobs.save_if_absent(child)
        assert stored != child  # SQLite returns a naive timestamp string.
        assert _same_reserved_queued_child(stored, child)
        assert not _same_reserved_queued_child(
            replace(stored, input={**stored.input, "parentJobId": "foreign"}), child)
        assert not _same_reserved_queued_child(
            replace(stored, events=[JobEvent(1, "info", "foreign", {})]), child)
        started = jobs.start_if_queued(stored, started_at=datetime.now(timezone.utc).isoformat(),
                                       event=JobEvent(2, "info", "provider append Apply preflight started", {}))
        assert started is not None
        assert started.status == "running"
        assert len(started.events) == 2
        # An existing reservation cannot masquerade as a newly inserted child.
        collided = jobs.save_if_absent(replace(child, requested_by="foreign"))
        assert collided == started
        assert not _same_reserved_queued_child(collided, child)
