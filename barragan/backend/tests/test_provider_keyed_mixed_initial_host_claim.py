# Copyright (c) 2026, Oracle and/or its affiliates.
"""Mixed host contact journals require the selected core plan's active lease."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel


def test_claimed_mixed_host_contact_requires_exact_initial_lease():
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
        base = {
            "engagementId": "eng-opaque", "coreJobId": "job-core",
            "corePlanId": "plan-opaque", "mixedParentId": "job-mixed",
            "handoffJournalSha256": "a" * 64,
            "bindingJobId": "job-binding", "bindingManifestSha256": "b" * 64,
            "mutation": True,
        }
        job = StoredJobRun(
            "job-host", "provider_keyed_mixed_initial_host_worker", "running",
            "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
            base, [], at, at, None,
            [JobEvent(1, "info", "mixed host worker queued", {}),
             JobEvent(2, "info", "mixed host worker started", {})])
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
                event=JobEvent(len(row.events) + 1, "info", "mixed host contact intended", {}))

        db.session.execute(text("""UPDATE core_mutation_leases
            SET operation = 'provider_keyed_teardown_fence'
            WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert append(claimed) is None
        assert len(repo.get(job.id).events) == 2
        db.session.execute(text("""UPDATE core_mutation_leases
            SET operation = 'provider_keyed_initial', owner_id = 'wrong-plan'
            WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert append(claimed) is None
        db.session.execute(text("""UPDATE core_mutation_leases
            SET owner_id = 'plan-opaque' WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        appended = append(claimed)
        assert appended is not None and len(appended.events) == 3
        db.session.execute(text("""UPDATE core_mutation_leases
            SET operation = 'provider_keyed_teardown_fence'
            WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert repo.finish_if_running_claimed(
            appended, owner="worker", token="token",
            expected_event_digest=job_event_digest(appended.events),
            status="succeeded", finished_at=(now + timedelta(seconds=2)).isoformat(),
            event=JobEvent(4, "info", "mixed strict host proof completed", {})) is None
        assert repo.get(job.id).status == "running"


def test_claimed_mixed_strict_proof_read_requires_exact_initial_lease():
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
        base = {
            "engagementId": "eng-opaque", "coreJobId": "job-core",
            "corePlanId": "plan-opaque", "mixedParentId": "job-mixed",
            "handoffJournalSha256": "a" * 64, "bindingJobId": "job-binding",
            "bindingManifestSha256": "b" * 64, "bootstrapJobId": "job-bootstrap",
            "bootstrapJournalSha256": "c" * 64, "mutation": False,
        }
        job = StoredJobRun(
            "job-host-proof", "provider_keyed_mixed_initial_strict_host_proof", "running",
            "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
            base, [], at, at, None,
            [JobEvent(1, "info", "mixed strict host proof queued", {}),
             JobEvent(2, "info", "mixed strict host proof started", {})])
        repo = SqlAlchemyJobRepository()
        repo.save(job)
        claimed = repo.claim_lease(job.id, owner="worker", token="token",
                                   claimed_at=at, expires_at=expiry,
                                   eligible_statuses={"running"})
        assert claimed is not None
        event = JobEvent(3, "info", "mixed raw host read intended", {})
        def append():
            return repo.append_event_if_running_claimed(
                claimed, owner="worker", token="token",
                expected_event_digest=job_event_digest(claimed.events),
                heartbeat_at=(now + timedelta(seconds=1)).isoformat(),
                expires_at=expiry, event=event)
        db.session.execute(text("""UPDATE core_mutation_leases
            SET operation = 'provider_keyed_teardown_fence'
            WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert append() is None
        db.session.execute(text("""UPDATE core_mutation_leases
            SET operation = 'provider_keyed_initial'
            WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        appended = append()
        assert appended is not None and len(appended.events) == 3
        db.session.execute(text("""UPDATE core_mutation_leases
            SET owner_id = 'wrong-plan' WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert repo.finish_if_running_claimed(
            appended, owner="worker", token="token",
            expected_event_digest=job_event_digest(appended.events),
            status="succeeded", finished_at=(now + timedelta(seconds=2)).isoformat(),
            event=JobEvent(4, "info", "mixed strict host proof completed", {})) is None
