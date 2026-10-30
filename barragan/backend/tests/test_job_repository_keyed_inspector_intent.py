# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot, claimed Inspector intent is journaled atomically in both stores."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import (
    StoredJobRun, _valid_claimed_apply_times, inspector_claim_generation_digest,
    job_event_digest,
)
from test_job_repository_claimed_apply import repository


SNAP = "a" * 64
SCOPE = "b" * 64
BASE = {
    "engagementId": "eng-1", "coreJobId": "core-1", "corePlanId": "plan-1",
    "teardownParentId": "parent-1", "scopeSnapshotId": SNAP,
    "providerScopeSha256": SCOPE, "mutation": True,
    "phase": "awaiting_inspector_preflight",
}
DATA = {
    "scopeSnapshotId": SNAP, "providerScopeSha256": SCOPE,
    "provider": "digitalocean", "region": "nyc3", "size": "s-1vcpu-1gb",
    "credentialAlias": "inspector-do", "credentialId": "credential-1",
    "credentialSha256": "e" * 64,
    "credentialUpdatedAt": "2026-10-08T00:00:00+00:00",
    "resourceName": "inspector-" + "c" * 32, "keyFingerprintSha256": "d" * 64,
    "managementSourceCidr": "8.8.8.8/32",
}
MESSAGES = [
    "keyed teardown coordinator queued", "keyed teardown coordinator started",
    "keyed teardown handoff intended",
    "keyed teardown handoff verified; Inspector preflight pending",
]


def row():
    now = datetime.now(timezone.utc)
    return StoredJobRun(
        id="coordinator-1", action="provider_keyed_comprehensive_teardown", status="running",
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        requested_by="operator", input=dict(BASE), artifact_refs=[],
        created_at=(now - timedelta(minutes=2)).isoformat(),
        started_at=(now - timedelta(minutes=1)).isoformat(), finished_at=None,
        events=[JobEvent(i, "info", message, data) for i, (message, data) in enumerate(zip(
            MESSAGES, [{"snapshotId": SNAP}, {}, {}, {"corePlanId": "plan-1"}], strict=True,
        ), 1)],
    )


def claim(repo, *, owner="provider-keyed-inspector-create", token="a" * 32, expired=False):
    now = datetime.now(timezone.utc)
    return repo.claim_lease(
        "coordinator-1", owner=owner, token=token,
        claimed_at=(now - timedelta(minutes=3) if expired else now - timedelta(seconds=3)).isoformat(),
        expires_at=(now - timedelta(minutes=2) if expired else now + timedelta(minutes=5)).isoformat(),
        eligible_statuses={"running"}, eligible_phases={"awaiting_inspector_preflight"},
    )


def append(repo, current, *, owner="provider-keyed-inspector-create", token="a" * 32, data=None,
           digest=None, heartbeat=None, event=None):
    now = datetime.now(timezone.utc)
    return repo.append_keyed_inspector_create_intent_if_running_claimed(
        current, owner=owner, token=token,
        expected_event_digest=digest or job_event_digest(current.events),
        heartbeat_at=heartbeat or now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        event=event or JobEvent(5, "info", "inspector_create_started", {
            **(DATA if data is None else data),
            "claimGenerationSha256": (DATA if data is None else data).get(
                "claimGenerationSha256", inspector_claim_generation_digest(
                    token=current.input.get("claimToken", ""),
                    claimed_at=current.input.get("claimClaimedAt", ""))),
        }),
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_one_shot_success_and_duplicate_veto(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(row())
        current = claim(repo)
        assert current is not None
        result = append(repo, current)
        assert result is not None
        assert result.input["phase"] == "inspector_create_started"
        assert result.events[:4] == current.events
        assert result.events[-1].data == {**DATA, "claimGenerationSha256":
            inspector_claim_generation_digest(token=current.input["claimToken"],
                                              claimed_at=current.input["claimClaimedAt"])}
        assert append(repo, current) is None
        assert append(repo, result) is None
        assert repo.get(result.id) == result


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_competing_claim_generation_veto(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(row())
        stale = claim(repo)
        next_claim = datetime.fromisoformat(stale.input["claimExpiresAt"]) + timedelta(seconds=1)
        rotated = repo.claim_lease(
            stale.id, owner="provider-keyed-inspector-create", token="b" * 32,
            claimed_at=next_claim.isoformat(),
            expires_at=(next_claim + timedelta(minutes=5)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"awaiting_inspector_preflight"},
        )
        assert rotated is not None
        assert append(repo, stale) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_same_count_journal_rewrite_rolls_back_phase_and_claim(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(row())
        current = claim(repo)
        rewritten = replace(current, events=[JobEvent(1, "info", "rewritten", {}), *current.events[1:]])
        repo.save(rewritten)
        assert append(repo, current) is None
        assert repo.get(current.id) == rewritten


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_handoff_owner_cannot_issue_inspector_intent(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(row())
        current = claim(repo, owner="provider-keyed-comprehensive-handoff")
        assert append(repo, current, owner="provider-keyed-comprehensive-handoff") is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_expired_claim_and_backdated_heartbeat_veto(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(row())
        current = claim(repo, expired=True)
        assert current is not None
        old = datetime.now(timezone.utc) - timedelta(minutes=2, seconds=30)
        # The caller's timestamps are internally valid; only the DB's current
        # time can reject an already-expired claim at the write boundary.
        assert _valid_claimed_apply_times(
            current, at=old.isoformat(),
            next_expiry=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        )
        assert append(repo, current, heartbeat=old.isoformat()) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("index", [0, 1, 2])
def test_malformed_earlier_handoff_journal_is_not_an_intent_predecessor(kind, index, tmp_path):
    with repository(kind, tmp_path) as repo:
        source = row()
        events = list(source.events)
        events[index] = JobEvent(index + 1, "info", "unexpected predecessor", {})
        repo.save(replace(source, events=events))
        current = claim(repo)
        assert current is not None
        assert append(repo, current) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("change", [
    lambda x: replace(x, action="legacy_action"),
    lambda x: replace(x, input={**x.input, "phase": "attention"}),
    lambda x: replace(x, input={**x.input, "mutation": "true"}),
    lambda x: replace(x, input={**x.input, "unexpected": "field"}),
])
def test_wrong_action_phase_or_input_veto(kind, change, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(change(row()))
        current = claim(repo)
        if current is None:
            current = repo.get("coordinator-1")
        assert append(repo, current) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("data", [
    {**DATA, "providerToken": "secret"},
    {**DATA, "resourceName": "inspector-prod-human-name"},
    {**DATA, "keyFingerprintSha256": "wrong"},
    {**DATA, "credentialUpdatedAt": "yesterday"},
    {**DATA, "managementSourceCidr": "10.0.0.1/32"},
    {**DATA, "managementSourceCidr": "224.0.0.1/32"},
    {**DATA, "managementSourceCidr": "8.8.8.0/24"},
])
def test_invalid_or_secretish_event_veto(kind, data, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(row())
        current = claim(repo)
        assert append(repo, current, data=data) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_raw_input_type_drift_veto(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(row())
        current = claim(repo)
        if kind == "sqlite":
            with repo._connect() as connection:
                connection.execute("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = ?",
                                   (current.id,))
        else:
            from sqlalchemy import text
            db.session.execute(text("UPDATE job_runs SET input = json_set(input, '$.mutation', 1) WHERE id = :id"),
                               {"id": current.id})
            db.session.commit()
        assert append(repo, current) is None
        assert repo.get(current.id).input["phase"] == "awaiting_inspector_preflight"
