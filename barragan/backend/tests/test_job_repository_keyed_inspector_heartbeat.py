# Copyright (c) 2026, Oracle and/or its affiliates.
"""Complete staged Inspector journals alone may receive a DB-clock heartbeat."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.storage.job_repository import (
    _valid_claimed_apply_times, _valid_completed_inspector_submission_heartbeat,
    inspector_claim_generation_digest,
    job_event_digest,
)
from test_job_repository_claimed_apply import repository
from test_job_repository_keyed_inspector_stage import complete, prepared


OWNER = "provider-keyed-inspector-create"
TOKEN = "a" * 32


def heartbeat(repo, current, *, digest=None, token=TOKEN, claimed_at=None, at=None):
    moment = at or datetime.now(timezone.utc)
    return repo.heartbeat_keyed_inspector_submission_if_running_claimed(
        current, owner=OWNER, token=token,
        claimed_at=claimed_at or current.input["claimClaimedAt"],
        expected_event_digest=digest or job_event_digest(current.events),
        heartbeat_at=moment.isoformat(),
        expires_at=(moment + timedelta(minutes=5)).isoformat(),
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_complete_journal_heartbeats_without_event_or_identity_change(kind, provider, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = complete(repo, prepared(repo, provider), provider)
        renewed = heartbeat(repo, current)
        assert renewed is not None
        assert renewed.events == current.events
        assert renewed.input["claimToken"] == current.input["claimToken"]
        assert renewed.input["claimClaimedAt"] == current.input["claimClaimedAt"]
        assert renewed.input["claimHeartbeatAt"] != current.input["claimHeartbeatAt"]
        assert heartbeat(repo, current) is None
        again = heartbeat(repo, renewed)
        assert again is not None and again.events == current.events


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_incomplete_or_tampered_journal_vetoes(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        incomplete = prepared(repo)
        assert heartbeat(repo, incomplete) is None
        current = complete(repo, incomplete, "digitalocean")
        rewritten = replace(current, events=[JobEvent(1, "info", "rewritten", {}), *current.events[1:]])
        repo.save(rewritten)
        assert heartbeat(repo, current) is None
        assert heartbeat(repo, rewritten) is None
        assert repo.get(current.id) == rewritten


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_wrong_action_phase_and_claim_generation_veto(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = complete(repo, prepared(repo, "linode"), "linode")
        assert heartbeat(repo, current, token="b" * 32) is None
        assert heartbeat(repo, current, claimed_at="2026-10-08T00:00:00+00:00") is None
        wrong = replace(current, action="other", input={**current.input, "phase": "other"})
        repo.save(wrong)
        assert heartbeat(repo, wrong) is None
        assert repo.get(current.id) == wrong


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_db_clock_expiry_vetoes_forged_backdated_heartbeat(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = complete(repo, prepared(repo, "linode"), "linode")
        old = datetime.now(timezone.utc) - timedelta(minutes=2)
        expired = replace(current, input={**current.input,
            "claimClaimedAt": (old - timedelta(minutes=1)).isoformat(),
            "claimHeartbeatAt": (old - timedelta(seconds=30)).isoformat(),
            "claimExpiresAt": (old + timedelta(seconds=30)).isoformat(),
        }, events=[*current.events[:4], replace(current.events[4], data={
            **current.events[4].data,
            "claimGenerationSha256": inspector_claim_generation_digest(
                token=TOKEN, claimed_at=(old - timedelta(minutes=1)).isoformat()),
        }), *current.events[5:]])
        repo.save(expired)
        assert _valid_completed_inspector_submission_heartbeat(
            expired, owner=OWNER, token=TOKEN,
            claimed_at=expired.input["claimClaimedAt"],
            expected_event_digest=job_event_digest(expired.events),
            heartbeat_at=old.isoformat(),
            expires_at=(old + timedelta(minutes=5)).isoformat(),
        )
        assert heartbeat(repo, expired, at=old) is None
        assert repo.get(current.id) == expired


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_valid_successor_claim_cannot_renew_original_submission(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = complete(repo, prepared(repo, "linode"), "linode")
        old_expiry = datetime.now(timezone.utc) - timedelta(minutes=1)
        old_claimed = old_expiry - timedelta(minutes=5)
        old_heartbeat = old_expiry - timedelta(seconds=30)
        original_intent = replace(current.events[4], data={
            **current.events[4].data,
            "claimGenerationSha256": inspector_claim_generation_digest(
                token=TOKEN, claimed_at=old_claimed.isoformat()),
        })
        historical = replace(current, input={**current.input,
            "claimClaimedAt": old_claimed.isoformat(),
            "claimHeartbeatAt": old_heartbeat.isoformat(),
            "claimExpiresAt": old_expiry.isoformat(),
        }, events=[*current.events[:4], original_intent, *current.events[5:]])
        repo.save(historical)
        now = datetime.now(timezone.utc)
        successor = repo.claim_lease(
            current.id, owner=OWNER, token="b" * 32,
            claimed_at=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"inspector_create_started"},
        )
        assert successor is not None and successor.input["claimToken"] == "b" * 32
        # Generic claim_lease preserves an old heartbeat. Make this successor
        # internally time-valid so only event 5's immutable generation can veto.
        successor = replace(successor, input={**successor.input,
            "claimHeartbeatAt": successor.input["claimClaimedAt"]})
        repo.save(successor)
        moment = datetime.now(timezone.utc)
        assert _valid_claimed_apply_times(
            successor, at=moment.isoformat(),
            next_expiry=(moment + timedelta(minutes=5)).isoformat(),
        )
        assert heartbeat(repo, successor, token="b" * 32) is None
        assert repo.get(current.id) == successor
