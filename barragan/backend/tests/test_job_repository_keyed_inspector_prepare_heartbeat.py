# Copyright (c) 2026, Oracle and/or its affiliates.
"""Only the sealed one-shot Inspector prepare journal can renew its claim."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.storage.job_repository import (
    _valid_keyed_inspector_prepare_heartbeat, job_event_digest,
)
from test_job_repository_claimed_apply import repository
from test_job_repository_keyed_inspector_stage import complete, prepared


OWNER = "provider-keyed-inspector-create"
TOKEN = "a" * 32


def _prepared_journal(repo, provider):
    current = complete(repo, prepared(repo, provider), provider)
    intent = current.events[4].data
    stages = current.events[5:]
    firewall_id = stages[1 if provider == "linode" else 3].data["resourceId"]
    host_id = stages[3 if provider == "linode" else 5].data["resourceId"]
    link_data = {
        "stageJournalSha256": job_event_digest(current.events),
        "proofSha256": "a" * 64,
        "hostRecordId": f"{provider}:inspector:{host_id}",
        "firewallRecordId": f"{provider}:inspector-firewall:{firewall_id}",
        "hostId": host_id, "firewallId": firewall_id, "provider": provider,
        "publicIp": "1.1.1.1", "scopeSnapshotId": current.input["scopeSnapshotId"],
        "cleanupRequired": True,
    }
    linked = [*current.events, JobEvent(len(current.events) + 1, "info",
                                        "inspector_owned_unprepared", link_data)]
    prepare_data = {
        "scopeSnapshotId": current.input["scopeSnapshotId"],
        "providerScopeSha256": current.input["providerScopeSha256"],
        "sourceJournalSha256": job_event_digest(linked),
        "provider": provider, "hostRecordId": link_data["hostRecordId"],
        "firewallRecordId": link_data["firewallRecordId"],
        "hostId": host_id, "firewallId": firewall_id,
        "publicIp": "1.1.1.1", "keyFingerprintSha256": intent["keyFingerprintSha256"],
    }
    result = replace(current, input={**current.input, "phase": "inspector_prepare_started"},
                     events=[*linked, JobEvent(len(linked) + 1, "info",
                                               "inspector_prepare_started", prepare_data)])
    return repo.save(result)


def _heartbeat(repo, current, *, token=TOKEN, claimed_at=None, digest=None,
               at=None, expiry=None):
    moment = at or datetime.now(timezone.utc)
    return repo.heartbeat_keyed_inspector_preparation_if_running_claimed(
        current, owner=OWNER, token=token,
        claimed_at=claimed_at or current.input["claimClaimedAt"],
        expected_event_digest=digest or job_event_digest(current.events),
        heartbeat_at=moment.isoformat(),
        expires_at=(expiry or moment + timedelta(minutes=4, seconds=50)).isoformat(),
    )


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_exact_prepare_journal_renews_only_input_and_one_writer(kind, provider, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = _prepared_journal(repo, provider)
        renewed = _heartbeat(repo, current)
        assert renewed is not None and renewed.events == current.events
        assert renewed.input["claimToken"] == current.input["claimToken"]
        assert renewed.input["claimClaimedAt"] == current.input["claimClaimedAt"]
        assert renewed.input["claimHeartbeatAt"] != current.input["claimHeartbeatAt"]
        assert _heartbeat(repo, current) is None
        assert _heartbeat(repo, renewed) is not None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_db_clock_vetoes_backdated_expired_claim_and_far_future_expiry(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = _prepared_journal(repo, "linode")
        now = datetime.now(timezone.utc)
        claimed = datetime.fromisoformat(current.input["claimClaimedAt"])
        expired = repo.save(replace(current, input={
            **current.input,
            "claimHeartbeatAt": (claimed + timedelta(seconds=1)).isoformat(),
            "claimExpiresAt": (claimed + timedelta(seconds=2)).isoformat(),
        }))
        backdated = claimed + timedelta(seconds=1, milliseconds=500)
        assert _valid_keyed_inspector_prepare_heartbeat(
            expired, owner=OWNER, token=TOKEN,
            claimed_at=expired.input["claimClaimedAt"],
            expected_event_digest=job_event_digest(expired.events),
            heartbeat_at=backdated.isoformat(),
            expires_at=(backdated + timedelta(minutes=5)).isoformat(),
        )
        assert _heartbeat(repo, expired, at=backdated) is None
        assert repo.get(current.id) == expired
        fresh = repo.save(current)
        future_heartbeat = now + timedelta(minutes=4)
        assert _heartbeat(repo, fresh, at=future_heartbeat,
                          expiry=future_heartbeat + timedelta(minutes=5)) is None
        assert repo.get(current.id) == fresh


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("drift", ["phase", "action", "token", "journal", "link", "intent"])
def test_stale_or_rewritten_generation_is_rejected_without_partial_update(kind, drift, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = _prepared_journal(repo, "digitalocean")
        if drift == "phase":
            changed = replace(current, input={**current.input, "phase": "other"})
        elif drift == "action":
            changed = replace(current, action="other")
        elif drift == "token":
            changed = replace(current, input={**current.input, "claimToken": "b" * 32})
        else:
            events = list(current.events)
            index = {"journal": 0, "link": -2, "intent": -1}[drift]
            events[index] = replace(events[index], data={**events[index].data, "extra": "drift"})
            changed = replace(current, events=events)
        repo.save(changed)
        assert _heartbeat(repo, current) is None
        assert _heartbeat(repo, changed, token="b" * 32 if drift == "token" else TOKEN) is None
        assert repo.get(current.id) == changed
