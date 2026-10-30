# Copyright (c) 2026, Oracle and/or its affiliates.
"""A mixed destroy command can journal only while its teardown fence survives."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel


def test_claimed_mixed_destroy_writes_require_exact_teardown_lease():
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-opaque",
            operation="provider_keyed_initial"))
        db.session.commit()
        now = datetime.now(timezone.utc)
        at = now.isoformat()
        expiry = (now + timedelta(minutes=5)).isoformat()
        digest = "a" * 64
        base = {
            "engagementId": "eng-opaque", "coreJobId": "job-core",
            "corePlanId": "plan-opaque", "cleanupParentId": "job-cleanup",
            "cleanupJournalSha256": digest, "sourceSha256": digest,
            "planSetSha256": digest, "provider": "linode", "providerIndex": 0,
            "scopeSha256": digest, "beforeStateSha256": digest,
            "planPath": "/tmp/opaque.tfplan", "planSha256": digest,
            "showSha256": digest, "terraformPath": "/usr/bin/terraform",
            "terraformSha256": digest, "mutation": True,
        }
        job = StoredJobRun(
            "job-mixed-destroy", "provider_keyed_mixed_interrupted_destroy_apply",
            "running", "engagement:eng-opaque", "engagement", "eng-opaque",
            "operator", base, [], at, at, None,
            [JobEvent(1, "info", "queued", {}), JobEvent(2, "info", "started", {})])
        repo = SqlAlchemyJobRepository()
        repo.save(job)
        claimed = repo.claim_lease(job.id, owner="worker", token="token",
                                   claimed_at=at, expires_at=expiry,
                                   eligible_statuses={"running"})
        assert claimed is not None

        def append(row):
            return repo.append_event_if_running_claimed(
                row, owner="worker", token="token",
                expected_event_digest=job_event_digest(row.events),
                heartbeat_at=(now + timedelta(seconds=1)).isoformat(),
                expires_at=expiry,
                event=JobEvent(len(row.events) + 1, "info", "show proved", {}))

        assert append(claimed) is None
        assert len(repo.get(job.id).events) == 2
        db.session.execute(text("""UPDATE core_mutation_leases
            SET operation = 'provider_keyed_teardown_fence'
            WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        appended = append(claimed)
        assert appended is not None and len(appended.events) == 3
        db.session.execute(text("""UPDATE core_mutation_leases
            SET owner_id = 'wrong-plan' WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert repo.finish_if_running_claimed(
            appended, owner="worker", token="token",
            expected_event_digest=job_event_digest(appended.events),
            status="succeeded", finished_at=(now + timedelta(seconds=2)).isoformat(),
            event=JobEvent(4, "info", "finished", {})) is None
        assert repo.get(job.id).status == "running"
        db.session.execute(text("""UPDATE core_mutation_leases
            SET owner_id = 'plan-opaque' WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert repo.finish_if_running_claimed(
            appended, owner="worker", token="token",
            expected_event_digest=job_event_digest(appended.events),
            status="succeeded", finished_at=(now + timedelta(seconds=2)).isoformat(),
            event=JobEvent(4, "info", "finished", {})) is not None
