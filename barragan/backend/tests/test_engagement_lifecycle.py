# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from app.domain import JobEvent
from app.services.engagement_lifecycle import reconcile_engagement_lifecycle, resolve_engagement_lifecycle
from app.storage.engagement_lifecycle_repository import StoredEngagementLifecycle, StoredEngagementLifecycleEvent
from app.storage.engagement_lifecycle_repository import SqlAlchemyEngagementLifecycleRepository
from app.storage.job_repository import StoredJobRun
from app.storage.provider_resource_repository import StoredProviderResourceRecord


class Jobs:
    def __init__(self, rows=()): self.rows = list(rows)
    def list_for_engagement(self, _engagement_id, *, limit=None): return self.rows[:limit]


class Providers:
    def __init__(self, rows=()): self.rows = list(rows)
    def list_for_engagement(self, _engagement_id): return self.rows


class Sketches:
    def __init__(self, rows=()): self.rows = list(rows)
    def list_for_engagement(self, _engagement_id): return self.rows


class Lifecycles:
    def __init__(self): self.current = None; self.events = []
    def get(self, _engagement_id): return self.current
    def save_transition(self, lifecycle, event):
        self.current = lifecycle
        saved = StoredEngagementLifecycleEvent(**{**event.__dict__, "id": len(self.events) + 1})
        self.events.append(saved)
        return lifecycle, saved
    def list_events(self, _engagement_id): return self.events


@dataclass
class Sketch:
    chain_id: str
    status: str


def job(
    status="succeeded", *, mutation=None, cleanup=None, teardown=False,
    extra_event_data=None, trailing_event_data=(),
):
    data = {}
    if mutation is not None: data["mutationStatus"] = mutation
    if cleanup is not None: data["finalCleanupStatus"] = cleanup
    data.update(extra_event_data or {})
    events = [JobEvent(1, "info", "operator teardown requested" if teardown else "core result", data)] if data or teardown else []
    events.extend(
        JobEvent(index, "info", "later core evidence", event_data)
        for index, event_data in enumerate(trailing_event_data, start=2)
    )
    return StoredJobRun(
        id="job-core", action="pilot_standard_rti_guarded_execute", status=status,
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        requested_by="operator", input={"engagementId": "eng-1"}, artifact_refs=[],
        created_at="2026-07-31T00:00:00+00:00", started_at=None, finished_at=None, events=events,
    )


def provider(status="tracked", *, owned=True):
    return StoredProviderResourceRecord(
        id="resource-1", engagement_id="eng-1", engagement_name="Example", provider="oci",
        resource_type="compute_instance", resource_id="ocid-redacted", name="opaque", region="region-1",
        lifecycle_state="active", status=status, source="barragan" if owned else "provider_inventory",
        metadata={} if owned else {"barraganOwned": False}, adoption_job_id="job-core",
        adopted_at="2026-07-31T00:00:00+00:00", updated_at="2026-07-31T00:00:00+00:00",
    )


def resolve(*jobs, providers=(), sketches=(), previous=None):
    return resolve_engagement_lifecycle(
        "eng-1", previous_state=previous, job_repository=Jobs(jobs),
        provider_resource_repository=Providers(providers), sketch_chain_repository=Sketches(sketches),
        use_runtime_repositories=False,
    )


def test_successful_retained_core_deployment_is_active():
    assert resolve(job(mutation="deployed", cleanup="pending_operator_teardown")).state == "active"


def test_running_deployment_and_teardown_are_distinct():
    assert resolve(job(status="running")).state == "deploying"
    assert resolve(job(status="running", teardown=True)).state == "tearing_down"


@pytest.mark.parametrize("action", [
    "provider_keyed_mixed_interrupted_cleanup",
    "provider_keyed_mixed_published_cleanup",
])
def test_mixed_cleanup_is_a_teardown_until_exact_terminal_proof(action):
    base = job(status="queued")
    interrupted = replace(
        base, id="job-mixed-cleanup",
        action=action,
        events=[JobEvent(1, "info", "mixed interrupted cleanup reserved", {})],
    )
    assert resolve(interrupted).state == "tearing_down"
    failed = replace(interrupted, status="failed")
    assert resolve(failed).state == "cleanup_required"
    verified = replace(
        interrupted, status="succeeded",
        events=[*interrupted.events,
                JobEvent(2, "info", "mixed interrupted cleanup completed",
                         {"finalCleanupStatus": "verified_clean"})],
    )
    assert resolve(verified).state == "destroyed"
    assert resolve(verified, providers=[provider()]).state == "cleanup_required"


def test_failed_non_mutating_deployment_stays_not_deployed_but_partial_mutation_requires_cleanup():
    assert resolve(job(status="failed")).state == "not_deployed"
    assert resolve(job(status="failed", mutation="preflight_failed", cleanup="not_started")).state == "not_deployed"
    assert resolve(job(status="failed", mutation="deployed", cleanup="pending_operator_teardown")).state == "cleanup_required"


def test_verified_teardown_requires_no_remaining_owned_evidence():
    clean = job(mutation="destroyed", cleanup="verified_clean", teardown=True)
    assert resolve(clean).state == "destroyed"
    assert resolve(clean, providers=[provider()]).state == "cleanup_required"


@pytest.mark.parametrize(
    ("mutation", "inspector_evidence"),
    [
        ("destroyed", {"inspectorTeardownVerification": {"ok": True}}),
        ("ansible_failed", {}),
    ],
    ids=["rt110-destroyed-and-inspector-verified", "rt7-ansible-failed-without-inspector-failure"],
)
def test_failed_legacy_pilot_with_verified_cleanup_and_no_remaining_resources_is_destroyed(
    mutation, inspector_evidence
):
    cleaned = job(
        status="failed",
        mutation=mutation,
        cleanup="verified_clean",
        extra_event_data=inspector_evidence,
    )

    assert resolve(cleaned).state == "destroyed"


@pytest.mark.parametrize("evidence_key", ["inspectorTeardownVerification", "inspectorCleanup"])
def test_failed_legacy_pilot_with_explicit_inspector_failure_requires_cleanup(evidence_key):
    inspector_failed = job(
        status="failed",
        cleanup="verified_clean",
        extra_event_data={evidence_key: {"ok": False}},
    )

    assert resolve(inspector_failed).state == "cleanup_required"


def test_failed_legacy_pilot_uses_latest_inspector_evidence():
    later_verified = job(
        status="failed",
        cleanup="verified_clean",
        extra_event_data={"inspectorCleanup": {"ok": False}},
        trailing_event_data=({"inspectorCleanup": {"ok": True}},),
    )
    later_failed = job(
        status="failed",
        cleanup="verified_clean",
        extra_event_data={"inspectorCleanup": {"ok": True}},
        trailing_event_data=({"inspectorCleanup": {"ok": False}},),
    )

    assert resolve(later_verified).state == "destroyed"
    assert resolve(later_failed).state == "cleanup_required"


def test_failed_legacy_pilot_verified_cleanup_ignores_unmanaged_provider_record():
    cleaned = job(status="failed", cleanup="verified_clean")

    assert resolve(cleaned, providers=[provider(owned=False)]).state == "destroyed"


def test_succeeded_verified_cleanup_preserves_legacy_failed_sketch_semantics():
    cleaned = job(status="succeeded", cleanup="verified_clean")

    assert resolve(cleaned, sketches=[Sketch("chain-failed", "failed")]).state == "destroyed"


@pytest.mark.parametrize(
    ("providers", "sketches"),
    [
        ([provider()], []),
        ([], [Sketch("chain-live", "deployed")]),
        ([], [Sketch("chain-tearing-down", "tearing_down")]),
        ([], [Sketch("chain-failed", "failed")]),
    ],
    ids=["active-owned-resource", "live-sketch", "tearing-down-sketch", "failed-sketch"],
)
def test_failed_legacy_pilot_verified_cleanup_keeps_remaining_resource_blockers(providers, sketches):
    cleaned = job(status="failed", cleanup="verified_clean")

    assert resolve(cleaned, providers=providers, sketches=sketches).state == "cleanup_required"


def test_orphaned_local_owned_evidence_requires_cleanup_without_provider_discovery():
    assert resolve(providers=[provider()]).state == "cleanup_required"
    assert resolve(sketches=[Sketch("chain-1", "failed")]).state == "cleanup_required"


def test_pending_sketch_configuration_does_not_imply_deployment():
    assert resolve(sketches=[Sketch("chain-1", "pending")]).state == "not_deployed"


def test_reconciliation_promotes_stale_planned_record_and_is_idempotent():
    repository = Lifecycles()
    args = dict(
        administrative_status="planned", lifecycle_repository=repository,
        job_repository=Jobs([job(mutation="deployed", cleanup="pending_operator_teardown")]),
        provider_resource_repository=Providers(), sketch_chain_repository=Sketches(),
        use_runtime_repositories=False,
    )
    first = reconcile_engagement_lifecycle("eng-1", **args)
    second = reconcile_engagement_lifecycle("eng-1", **args)

    assert first["current"]["state"] == "active"
    assert first["current"]["administrativeStatus"] == "planned"
    assert first["changed"] is True
    assert second["changed"] is False
    assert len(repository.events) == 1
    assert repository.events[0].reason == "operator_local_evidence_reconciliation"


def test_missing_evidence_after_active_history_fails_to_unknown():
    assert resolve(previous="active").state == "unknown"


def test_reconcile_api_is_local_auditable_and_idempotent(client):
    listed = client.get("/api/engagements?scope=all").get_json()["engagements"]
    summary = listed[0]
    engagement_id = summary["id"]
    first = client.post(f"/api/engagements/{engagement_id}/lifecycle/reconcile").get_json()["reconciliation"]
    second = client.post(f"/api/engagements/{engagement_id}/lifecycle/reconcile").get_json()["reconciliation"]
    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]

    assert first["current"]["administrativeStatus"] == summary["status"]
    assert summary["lifecycle"]["state"] == first["current"]["state"]
    assert first["changed"] is True
    assert second["changed"] is False
    assert operations["lifecycle"]["state"] == first["current"]["state"]


def test_lifecycle_projection_and_audit_roll_back_together(client, monkeypatch):
    from app.storage.database import db
    from app.storage.models import EngagementLifecycleEventModel, EngagementLifecycleModel

    engagement_id = client.get("/api/engagements?scope=all").get_json()["engagements"][0]["id"]
    lifecycle = StoredEngagementLifecycle(
        engagement_id=engagement_id,
        state="active",
        evidence_fingerprint="atomic-fingerprint",
        evidence=[{"kind": "core_job", "id": "job-atomic", "status": "succeeded"}],
        reconciled_at="2026-07-31T12:00:00+00:00",
    )
    event = StoredEngagementLifecycleEvent(
        id=None,
        engagement_id=engagement_id,
        previous_state="not_deployed",
        state="active",
        evidence_fingerprint="atomic-fingerprint",
        evidence=lifecycle.evidence,
        reason="atomicity_test",
        created_at="2026-07-31T12:00:00+00:00",
    )

    with client.application.storage_context():
        original_commit = db.session.commit
        rollback_calls = 0
        original_rollback = db.session.rollback

        def fail_commit():
            raise RuntimeError("simulated commit failure")

        def track_rollback():
            nonlocal rollback_calls
            rollback_calls += 1
            return original_rollback()

        monkeypatch.setattr(db.session, "commit", fail_commit)
        monkeypatch.setattr(db.session, "rollback", track_rollback)
        with pytest.raises(RuntimeError, match="simulated commit failure"):
            SqlAlchemyEngagementLifecycleRepository().save_transition(lifecycle, event)
        monkeypatch.setattr(db.session, "commit", original_commit)

        assert rollback_calls == 1
        assert EngagementLifecycleModel.query.filter_by(engagement_id=engagement_id).count() == 0
        assert EngagementLifecycleEventModel.query.filter_by(engagement_id=engagement_id).count() == 0

        SqlAlchemyEngagementLifecycleRepository().save_transition(lifecycle, event)
        assert EngagementLifecycleModel.query.filter_by(engagement_id=engagement_id).count() == 1
        assert EngagementLifecycleEventModel.query.filter_by(engagement_id=engagement_id).count() == 1


def test_runtime_schema_migrates_pending_customization_to_draft(client):
    from app.storage.database import db, ensure_database_schema
    from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
    from app.storage.models import EngagementModel

    with client.application.storage_context():
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id="eng-pending-legacy",
                name="Legacy pending row",
                status="pending_customization",
                owner="operator",
                template_id="",
                active_revision=None,
                input_parameters={},
            )
        )
        assert EngagementModel.query.get("eng-pending-legacy").status == "pending_customization"

        ensure_database_schema()
        db.session.expire_all()

        assert EngagementModel.query.get("eng-pending-legacy").status == "draft"
        assert SqlAlchemyEngagementRepository().get("eng-pending-legacy").status == "draft"
