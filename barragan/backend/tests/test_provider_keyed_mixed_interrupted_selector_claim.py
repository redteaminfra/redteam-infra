# Copyright (c) 2026, Oracle and/or its affiliates.
"""A mixed selector DELETE can journal once under the exact teardown fence."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel


def test_mixed_selector_intent_and_finish_require_fence_and_exact_grammar():
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
            "schema": "mixed-interrupted-selector-retirement-v1",
            "engagementId": "eng-opaque", "coreJobId": "job-core",
            "corePlanId": "plan-opaque", "teardownParentId": "job-cleanup",
            "reviewSha256": digest, "planSetSha256": digest,
            "doScopeSha256": digest, "selectorTag": "opaque-tag",
            "providerConnectionId": "connection-opaque",
            "credentialSecretSha256": digest, "credentialUpdatedAt": at,
            "ociAbsenceJobId": "job-oci-absence",
            "ociAbsenceJournalSha256": digest,
            "inspectorNegativeJobId": "job-negative",
            "inspectorNegativeJournalSha256": digest, "mutation": True,
        }
        job = StoredJobRun(
            "job-selector", "provider_keyed_mixed_interrupted_selector_retirement",
            "running", "engagement:eng-opaque", "engagement", "eng-opaque",
            "operator", base, [], at, at, None,
            [JobEvent(1, "info", "mixed interrupted selector retirement queued", {}),
             JobEvent(2, "info", "mixed interrupted selector retirement started", {})])
        repo = SqlAlchemyJobRepository()
        repo.save(job)
        claimed = repo.claim_lease(job.id, owner="worker", token="token",
                                   claimed_at=at, expires_at=expiry,
                                   eligible_statuses={"running"})
        assert claimed is not None
        intent = JobEvent(3, "info", "mixed interrupted selector DELETE intended", {
            "selectorTag": "opaque-tag", "doScopeSha256": digest,
            "ociAbsenceJournalSha256": digest,
            "inspectorNegativeJournalSha256": digest})
        def append(event):
            return repo.append_mixed_interrupted_selector_retirement_event_if_running_claimed(
                claimed, owner="worker", token="token",
                expected_event_digest=job_event_digest(claimed.events),
                heartbeat_at=(now + timedelta(seconds=1)).isoformat(),
                expires_at=expiry, event=event)
        assert append(intent) is None
        db.session.execute(text("""UPDATE core_mutation_leases
            SET operation = 'provider_keyed_teardown_fence'
            WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert append(JobEvent(3, "info", intent.message,
                               {**intent.data, "doScopeSha256": "b" * 64})) is None
        appended = append(intent)
        assert appended is not None and len(appended.events) == 3
        terminal = JobEvent(4, "info", "mixed interrupted selector DELETE 204 received",
                            {"selectorTag": "opaque-tag", "httpStatus": 204})
        db.session.execute(text("""UPDATE core_mutation_leases
            SET owner_id = 'wrong-plan' WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert repo.finish_mixed_interrupted_selector_retirement_if_running_claimed(
            appended, owner="worker", token="token",
            expected_event_digest=job_event_digest(appended.events),
            finished_at=(now + timedelta(seconds=2)).isoformat(), event=terminal) is None
        db.session.execute(text("""UPDATE core_mutation_leases
            SET owner_id = 'plan-opaque' WHERE engagement_id = 'eng-opaque'"""))
        db.session.commit()
        assert repo.finish_mixed_interrupted_selector_retirement_if_running_claimed(
            appended, owner="worker", token="token",
            expected_event_digest=job_event_digest(appended.events),
            finished_at=(now + timedelta(seconds=2)).isoformat(), event=terminal) is not None
