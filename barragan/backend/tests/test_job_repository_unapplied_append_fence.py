# Copyright (c) 2026, Oracle and/or its affiliates.
"""A transferred teardown writer fence also stops late harmless bookkeeping."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from test_job_repository_mixed_append_second import repository, row


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("action", ["provider_keyed_mixed_append",
    "provider_keyed_mixed_append_apply_child", "provider_keyed_mixed_append_second_apply_child"])
@pytest.mark.parametrize("operation", ["reserve", "start", "claim", "renew"])
def test_stale_append_snapshot_cannot_write_after_teardown_fence(kind, action, operation, tmp_path):
    at = datetime.now(timezone.utc)
    before = (at - timedelta(minutes=10)).isoformat()
    now, later = at.isoformat(), (at + timedelta(minutes=2)).isoformat()
    with repository(kind, tmp_path) as jobs:
        stale = replace(row(before), id="job-stale", action=action)
        if operation in {"reserve", "start"}:
            stale = replace(stale, status="queued", started_at=None,
                events=[JobEvent(1, "info", "queued", {})])
        if operation == "renew":
            stale = replace(stale, input={**stale.input, "claimOwner": "old",
                "claimToken": "old-token", "claimExpiresAt": before})
        if operation != "reserve":
            jobs.save(stale)
            stale = jobs.get(stale.id)  # The caller holds this pre-transfer snapshot.
        if kind == "sqlite":
            with jobs._connect() as connection:
                changed = connection.execute("UPDATE core_mutation_leases SET operation = ? WHERE engagement_id = ?",
                    ("provider_keyed_teardown_fence", "eng-opaque"))
                assert changed.rowcount == 1
        else:
            db.session.query(CoreMutationLeaseModel).filter_by(engagement_id="eng-opaque").update(
                {"operation": "provider_keyed_teardown_fence"}, synchronize_session=False)
            db.session.commit()
        if operation == "reserve":
            with pytest.raises(ValueError, match="lost its mutation lease"):
                jobs.save_if_absent(stale)
            assert jobs.get(stale.id) is None
        elif operation == "start":
            assert jobs.start_if_queued(stale, started_at=now, event=JobEvent(2, "info", "started", {})) is None
        elif operation == "claim":
            assert jobs.claim_lease(stale.id, owner="new", token="new-token", claimed_at=now,
                expires_at=later, eligible_statuses={"running"}) is None
        else:
            assert jobs.renew_lease(stale.id, owner="old", token="old-token",
                heartbeat_at=now, expires_at=later) is None
        if operation != "reserve":
            assert jobs.get(stale.id) == stale
