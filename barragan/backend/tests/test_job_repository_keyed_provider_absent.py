# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private keyed provider-absence publication is one-shot and transaction fenced."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import time

import pytest

from app.domain import JobEvent
from app.storage.job_repository import job_event_digest
from test_job_repository_claimed_apply import repository
from test_job_repository_keyed_inspector_intent import row
from test_job_repository_keyed_retained_inspector import _ready_event


def ready_row():
    basic = row()
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    claimed = replace(basic, input={**basic.input,
        "claimOwner": "provider-keyed-retained-inspector-proof",
        "claimToken": "r" * 32, "claimClaimedAt": past,
        "claimHeartbeatAt": past, "claimExpiresAt": past})
    ready = _ready_event(claimed)
    return replace(claimed, input={**claimed.input, "phase": "inspector_ready",
        "claimOwner": "provider-keyed-retained-inspector-ready-handoff"},
        events=[*claimed.events, ready])


def proof(job):
    completed = datetime.now(timezone.utc)
    return {
        "scopeSnapshotId": job.input["scopeSnapshotId"],
        "providerScopeSha256": job.input["providerScopeSha256"],
        "readyJournalSha256": job_event_digest(job.events),
        "previewJobId": "preview-1", "previewJournalSha256": "1" * 64,
        "applyJobId": "apply-1", "applyJournalSha256": "2" * 64,
        "emptyStateSha256": "3" * 64, "resourceIdsSha256": "4" * 64,
        "verifiedAbsentDropletIds": ["123", "456"],
        "verifiedAbsentFirewallId": "11111111-1111-1111-1111-111111111111",
        "verifiedAbsentSshKeyId": "789", "selectorTagCleanupPending": True,
        "confirmationCompletedAt": completed.isoformat(),
        "confirmationExpiresAt": (completed + timedelta(seconds=30)).isoformat(),
    }


def publish(repo, job, *, evidence=None, authority=lambda: None):
    return repo.publish_keyed_provider_absent_if_ready(
        job, expected_event_digest=job_event_digest(job.events),
        proof=proof(job) if evidence is None else evidence, authority=authority)


def test_publishes_once_with_database_observation_time(tmp_path):
    with repository("sqlalchemy", tmp_path) as repo:
        original = ready_row()
        repo.save(original)
        published = publish(repo, original)
        assert published is not None
        assert published.input["phase"] == "provider_absent"
        assert published.status == "running"
        assert published.events[-1].message == "provider_absent"
        assert published.events[-1].data["readyJournalSha256"] == job_event_digest(original.events)
        observed = datetime.fromisoformat(published.events[-1].data["observedAt"])
        assert abs((datetime.now(timezone.utc) - observed).total_seconds()) < 10
        assert publish(repo, original) is None
        assert repo.get(original.id) == published


def test_authority_failure_rolls_back_phase_and_event(tmp_path):
    with repository("sqlalchemy", tmp_path) as repo:
        original = ready_row()
        repo.save(original)
        original = repo.get(original.id)
        with pytest.raises(ValueError, match="apply changed"):
            publish(repo, original, authority=lambda: (_ for _ in ()).throw(
                ValueError("apply changed")))
        assert repo.get(original.id) == original
        assert publish(repo, original) is not None


@pytest.mark.parametrize("mutation", [
    lambda job: replace(job, events=[*job.events[:-1],
                                    JobEvent(5, "info", "forged ready", {})]),
    lambda job: replace(job, input={**job.input, "phase": "attention"}),
    lambda job: replace(job, input={**job.input, "claimExpiresAt": (
        datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}),
])
def test_tamper_or_live_claim_vetoes_publication(tmp_path, mutation):
    with repository("sqlalchemy", tmp_path) as repo:
        original = ready_row()
        changed = mutation(original)
        repo.save(changed)
        changed = repo.get(changed.id)
        assert publish(repo, changed) is None
        assert repo.get(original.id) == changed


def test_same_count_journal_drift_and_concurrent_publication_cannot_duplicate(tmp_path):
    with repository("sqlalchemy", tmp_path) as repo:
        original = ready_row()
        repo.save(original)
        altered = replace(original, events=[*original.events[:-1],
            replace(original.events[-1], data={**original.events[-1].data,
                "publicIp": "8.8.4.4"})])
        repo.save(altered)
        assert publish(repo, original) is None
        repo.save(original)
        first = publish(repo, original)
        assert first is not None
        assert publish(repo, original) is None
        assert len(repo.get(original.id).events) == len(original.events) + 1


def test_standalone_sqlite_store_cannot_publish_without_cross_table_authority(tmp_path):
    with repository("sqlite", tmp_path) as repo:
        original = ready_row()
        repo.save(original)
        assert not hasattr(repo, "publish_keyed_provider_absent_if_ready")


def test_expired_confirmation_cannot_publish(tmp_path):
    with repository("sqlalchemy", tmp_path) as repo:
        original = ready_row()
        repo.save(original)
        original = repo.get(original.id)
        stale = proof(original)
        stale["confirmationCompletedAt"] = (
            datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        stale["confirmationExpiresAt"] = (
            datetime.now(timezone.utc) - timedelta(minutes=1, seconds=30)).isoformat()
        assert publish(repo, original, evidence=stale) is None
        assert repo.get(original.id) == original


def test_confirmation_expiring_during_authority_rolls_back(tmp_path):
    with repository("sqlalchemy", tmp_path) as repo:
        original = ready_row()
        repo.save(original)
        original = repo.get(original.id)
        short = proof(original)
        completed = datetime.now(timezone.utc)
        short["confirmationCompletedAt"] = completed.isoformat()
        short["confirmationExpiresAt"] = (completed + timedelta(seconds=1)).isoformat()
        assert publish(repo, original, evidence=short,
                       authority=lambda: time.sleep(1.2)) is None
        assert repo.get(original.id) == original
