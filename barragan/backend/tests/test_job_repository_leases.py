# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import replace

from app.domain import JobEvent
from app.services import sketch_chains
from app.storage.job_repository import SqliteJobRepository, StoredJobRun


def test_lease_renewal_prevents_steal_after_original_five_minute_expiry(tmp_path):
    repository = SqliteJobRepository(tmp_path / "leases.sqlite")
    repository.save(_job())
    original = repository.claim_lease(
        "job-parent",
        owner="worker-a",
        token="token-a",
        claimed_at="2026-08-04T00:00:00+00:00",
        expires_at="2026-08-04T00:05:00+00:00",
        eligible_statuses={"queued", "running"},
    )
    assert original is not None

    renewed = repository.renew_lease(
        "job-parent",
        owner="worker-a",
        token="token-a",
        heartbeat_at="2026-08-04T00:04:30+00:00",
        expires_at="2026-08-04T00:09:30+00:00",
    )
    stolen = repository.claim_lease(
        "job-parent",
        owner="worker-b",
        token="token-b",
        claimed_at="2026-08-04T00:05:01+00:00",
        expires_at="2026-08-04T00:10:01+00:00",
        eligible_statuses={"queued", "running"},
    )

    assert renewed is not None
    assert stolen is None
    assert repository.get("job-parent").input["claimToken"] == "token-a"


def test_stale_owner_cannot_write_terminal_state_after_lease_is_stolen(tmp_path):
    repository = SqliteJobRepository(tmp_path / "leases.sqlite")
    repository.save(_job())
    owned = repository.claim_lease(
        "job-parent",
        owner="worker-a",
        token="token-a",
        claimed_at="2026-08-04T00:00:00+00:00",
        expires_at="2026-08-04T00:05:00+00:00",
        eligible_statuses={"queued", "running"},
    )
    assert owned is not None
    stolen = repository.claim_lease(
        "job-parent",
        owner="worker-b",
        token="token-b",
        claimed_at="2026-08-04T00:05:01+00:00",
        expires_at="2026-08-04T00:10:01+00:00",
        eligible_statuses={"queued", "running"},
    )
    assert stolen is not None

    stale_final = repository.save_if_leased(
        replace(owned, status="succeeded", finished_at="2026-08-04T00:05:02+00:00"),
        owner="worker-a",
        token="token-a",
    )

    assert stale_final is None
    durable = repository.get("job-parent")
    assert durable.status == "queued"
    assert durable.input["claimToken"] == "token-b"


def test_reclaimed_expired_lease_starts_new_heartbeat_generation(tmp_path):
    repository = SqliteJobRepository(tmp_path / "leases.sqlite")
    repository.save(_job())
    old = repository.claim_lease(
        "job-parent", owner="worker-a", token="token-a",
        claimed_at="2026-08-04T00:00:00+00:00",
        expires_at="2026-08-04T00:05:00+00:00", eligible_statuses={"queued"})
    assert old is not None
    assert repository.renew_lease(
        "job-parent", owner="worker-a", token="token-a",
        heartbeat_at="2026-08-04T00:04:00+00:00",
        expires_at="2026-08-04T00:05:00+00:00") is not None
    new = repository.claim_lease(
        "job-parent", owner="worker-b", token="token-b",
        claimed_at="2026-08-04T00:06:00+00:00",
        expires_at="2026-08-04T00:11:00+00:00", eligible_statuses={"queued"})
    assert new is not None
    assert new.input["claimClaimedAt"] == new.input["claimHeartbeatAt"] == "2026-08-04T00:06:00+00:00"


def test_blocking_child_work_keeps_outbound_parent_lease_alive(tmp_path, monkeypatch):
    repository = SqliteJobRepository(tmp_path / "leases.sqlite")
    repository.save(_job())
    owned = repository.claim_lease(
        "job-parent",
        owner=sketch_chains._outbound_auto_configuration_owner,
        token="token-a",
        claimed_at="2026-08-04T00:00:00+00:00",
        expires_at="2026-08-04T00:05:00+00:00",
        eligible_statuses={"queued", "running"},
    )
    assert owned is not None
    monkeypatch.setattr(sketch_chains, "OUTBOUND_AUTO_HEARTBEAT_SECONDS", 0.01)

    with sketch_chains._outbound_auto_lease_heartbeat(repository, "job-parent", "token-a"):
        assert sketch_chains.threading.Event().wait(0.04) is False

    durable = repository.get("job-parent")
    assert durable.input["claimHeartbeatAt"] != "2026-08-04T00:00:00+00:00"
    assert durable.input["claimExpiresAt"] > durable.input["claimHeartbeatAt"]


def _job() -> StoredJobRun:
    return StoredJobRun(
        id="job-parent",
        action="outbound_channel_auto_configuration",
        status="queued",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1", "chainId": "chain-1", "deployJobId": "job-deploy"},
        artifact_refs=[],
        created_at="2026-08-04T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "queued", {})],
    )
