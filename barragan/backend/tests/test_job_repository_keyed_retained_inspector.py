# Copyright (c) 2026, Oracle and/or its affiliates.
"""Four-event retained Inspector claim and one-shot readiness CAS."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.storage.job_repository import (
    inspector_claim_generation_digest, job_event_digest,
)
from test_job_repository_claimed_apply import repository
from test_job_repository_keyed_inspector_intent import row


OWNER = "provider-keyed-retained-inspector-proof"
TOKEN = "r" * 32


def _handoff(repo):
    repo.save(row())
    moment = datetime.now(timezone.utc) - timedelta(minutes=2)
    return repo.claim_lease(
        "coordinator-1", owner="provider-keyed-comprehensive-handoff",
        token="h" * 32, claimed_at=moment.isoformat(),
        expires_at=(moment + timedelta(minutes=1)).isoformat(),
        eligible_statuses={"running"}, eligible_phases={"awaiting_inspector_preflight"},
    )


def _transition(repo, current, mode, *, event=None, authority=None, token=TOKEN, digest=None):
    moment = datetime.now(timezone.utc)
    return repo.transition_retained_inspector_if_running(
        current, mode=mode, expected_event_digest=digest or job_event_digest(current.events),
        owner=OWNER, token=token, at=moment.isoformat(),
        expires_at=(moment + timedelta(minutes=4, seconds=50)).isoformat(),
        event=event, authority=authority,
    )


def _ready_event(current):
    data = {
        "scopeSnapshotId": current.input["scopeSnapshotId"],
        "providerScopeSha256": current.input["providerScopeSha256"],
        "sourceJournalSha256": job_event_digest(current.events),
        "hostRecordId": "linode:inspector:42", "firewallRecordId": "linode:inspector-firewall:7",
        "provider": "linode", "hostId": "42", "firewallId": "7", "publicIp": "8.8.8.8",
        "sourceCidr": "1.1.1.1/32", "credentialId": "cred-1",
        "credentialUpdatedAt": "2026-10-08T00:00:00+00:00",
        "credentialSha256": "a" * 64, "keyFingerprintSha256": "b" * 64,
        "providerProofSha256": "c" * 64, "sshPolicySha256": "d" * 64,
        "nmapVersionSha256": "e" * 64,
        "claimGenerationSha256": inspector_claim_generation_digest(
            token=current.input["claimToken"],
            claimed_at=current.input["claimClaimedAt"]),
    }
    return JobEvent(5, "info", "retained_inspector_ready", data)


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_expired_four_event_handoff_claims_and_heartbeats_without_rewrite(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        old = _handoff(repo)
        claimed = _transition(repo, old, "claim")
        assert claimed is not None and claimed.events == old.events
        assert claimed.input["claimOwner"] == OWNER
        assert _transition(repo, old, "claim") is None
        renewed = _transition(repo, claimed, "heartbeat")
        assert renewed is not None and renewed.events == old.events
        assert _transition(repo, claimed, "heartbeat") is None
        assert _transition(repo, renewed, "heartbeat", token="s" * 32) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_expiry_and_same_count_journal_drift_veto_without_partial_write(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        old = _handoff(repo)
        changed = replace(old, events=[*old.events[:2],
                                       replace(old.events[2], message="forged"), old.events[3]])
        repo.save(changed)
        assert _transition(repo, old, "claim") is None
        assert repo.get(old.id) == changed
        repo.save(old)
        expired = replace(old, input={**old.input,
            "claimExpiresAt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()})
        repo.save(expired)
        assert _transition(repo, expired, "claim") is None
        assert repo.get(old.id) == expired


def test_sqlalchemy_ready_event_is_atomic_and_authority_failure_rolls_back(tmp_path):
    with repository("sqlalchemy", tmp_path) as repo:
        claimed = _transition(repo, _handoff(repo), "claim")
        event = _ready_event(claimed)

        def drift():
            raise ValueError("record changed")

        with pytest.raises(ValueError, match="record changed"):
            _transition(repo, claimed, "ready", event=event, authority=drift)
        assert repo.get(claimed.id) == claimed
        ready = _transition(repo, claimed, "ready", event=event, authority=lambda: None)
        assert ready is not None and ready.status == "running"
        assert ready.input["phase"] == "inspector_ready"
        assert ready.input["claimOwner"] == "provider-keyed-retained-inspector-ready-handoff"
        assert ready.events == [*claimed.events, event]
        assert _transition(repo, claimed, "ready", event=event, authority=lambda: None) is None


def test_standalone_sqlite_ready_requires_cross_table_authority(tmp_path):
    with repository("sqlite", tmp_path) as repo:
        claimed = _transition(repo, _handoff(repo), "claim")
        assert _transition(repo, claimed, "ready", event=_ready_event(claimed),
                           authority=lambda: None) is None
        assert repo.get(claimed.id) == claimed


def test_ready_handoff_expiry_uses_database_clock_not_future_caller_time(tmp_path):
    with repository("sqlalchemy", tmp_path) as repo:
        claimed = _transition(repo, _handoff(repo), "claim")
        future = datetime.now(timezone.utc) + timedelta(minutes=1)
        ready = repo.transition_retained_inspector_if_running(
            claimed, mode="ready", expected_event_digest=job_event_digest(claimed.events),
            owner=OWNER, token=TOKEN, at=future.isoformat(),
            expires_at=(future + timedelta(minutes=4, seconds=50)).isoformat(),
            event=_ready_event(claimed), authority=lambda: None,
        )
        assert ready is not None
        assert datetime.fromisoformat(ready.input["claimExpiresAt"]) < future
        assert ready.input["claimClaimedAt"] == ready.input["claimHeartbeatAt"] == ready.input["claimExpiresAt"]
