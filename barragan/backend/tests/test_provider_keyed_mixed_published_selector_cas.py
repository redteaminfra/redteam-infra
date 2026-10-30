# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted published selector child uses teardown-fence CAS and one intent."""

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, StoredJobRun, job_event_digest,
)
from app.storage.models import CoreMutationLeaseModel, EngagementModel


SHA = "a" * 64
AT = "2026-10-19T00:00:00+00:00"
LATER = "2026-10-19T00:01:00+00:00"


def _base():
    return {
        "schema": "mixed-published-selector-retirement-v1",
        "engagementId": "eng-published-selector", "coreJobId": "job-core",
        "corePlanId": "plan-core", "teardownParentId": "job-teardown",
        "reviewSha256": SHA, "planSetSha256": SHA,
        "doScopeSha256": SHA, "selectorTag": "s01234567890123456789",
        "providerConnectionId": "connection-do", "credentialSecretSha256": SHA,
        "credentialUpdatedAt": AT, "ociAbsenceJobId": "job-oci-absence",
        "ociAbsenceJournalSha256": SHA,
        "inspectorNegativeJobId": "job-inspector-negative",
        "inspectorNegativeJournalSha256": SHA,
        "doAbsenceReceiptSha256": SHA,
        "publishedParentJournalSha256": SHA, "mutation": True,
    }


def _running():
    base = _base()
    return StoredJobRun(
        "job-published-selector", "provider_keyed_mixed_published_selector_retirement",
        "running", f"engagement:{base['engagementId']}", "engagement",
        base["engagementId"], "operator", base, [], AT, AT, None,
        [JobEvent(1, "info", "mixed published selector retirement queued", {}),
         JobEvent(2, "info", "mixed published selector retirement started", {})],
    )


def test_published_selector_intent_and_terminal_are_exact_claimed_cas(tmp_path):
    state = db.configure(f"sqlite:///{tmp_path / 'published-selector.sqlite'}")
    with db.bind(state):
        db.create_all()
        row = _running()
        db.session.add(EngagementModel(id=row.target_id, name="opaque-fixture",
                                       status="active", owner="operator", template_id="small"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=row.target_id, owner_id=row.input["corePlanId"],
            operation="provider_keyed_teardown_fence"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        jobs.save(row)
        claimed = jobs.claim_lease(row.id, owner="worker", token="token",
                                   claimed_at=AT, expires_at=LATER,
                                   eligible_statuses={"running"})
        assert claimed is not None
        intent = JobEvent(3, "info", "mixed published selector DELETE intended", {
            "selectorTag": row.input["selectorTag"],
            "doAbsenceReceiptSha256": SHA, "ociAbsenceJournalSha256": SHA,
            "inspectorNegativeJournalSha256": SHA})
        assert jobs.append_mixed_published_selector_retirement_event_if_running_claimed(
            claimed, owner="worker", token="token",
            expected_event_digest="0" * 64, heartbeat_at=AT,
            expires_at=LATER, event=intent) is None
        intended = jobs.append_mixed_published_selector_retirement_event_if_running_claimed(
            claimed, owner="worker", token="token",
            expected_event_digest=job_event_digest(claimed.events), heartbeat_at=AT,
            expires_at=LATER, event=intent)
        assert intended is not None and len(intended.events) == 3
        assert jobs.append_mixed_published_selector_retirement_event_if_running_claimed(
            claimed, owner="worker", token="token",
            expected_event_digest=job_event_digest(claimed.events), heartbeat_at=AT,
            expires_at=LATER, event=intent) is None
        terminal = JobEvent(4, "info", "mixed published selector DELETE 204 received",
                            {"selectorTag": row.input["selectorTag"], "httpStatus": 204})
        finished = jobs.finish_mixed_published_selector_retirement_if_running_claimed(
            intended, owner="worker", token="token",
            expected_event_digest=job_event_digest(intended.events),
            finished_at=AT, event=terminal)
        assert finished is not None and finished.status == "succeeded"


def test_published_selector_already_absent_is_a_no_write_terminal(tmp_path):
    state = db.configure(f"sqlite:///{tmp_path / 'published-selector-absent.sqlite'}")
    with db.bind(state):
        db.create_all()
        row = _running()
        db.session.add(EngagementModel(id=row.target_id, name="opaque-fixture",
                                       status="active", owner="operator", template_id="small"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=row.target_id, owner_id=row.input["corePlanId"],
            operation="provider_keyed_teardown_fence"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        jobs.save(row)
        claimed = jobs.claim_lease(row.id, owner="worker", token="token",
                                   claimed_at=AT, expires_at=LATER,
                                   eligible_statuses={"running"})
        assert claimed is not None
        terminal = JobEvent(3, "info", "mixed published selector already absent", {
            "selectorTag": row.input["selectorTag"], "exactGetStatus": 404})
        finished = jobs.finish_mixed_published_selector_retirement_if_running_claimed(
            claimed, owner="worker", token="token",
            expected_event_digest=job_event_digest(claimed.events),
            finished_at=AT, event=terminal)
        assert finished is not None and finished.status == "succeeded"
