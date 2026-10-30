# Copyright (c) 2026, Oracle and/or its affiliates.
"""One reviewed operator confirmation reserves the exact published parent."""

import pytest
from dataclasses import replace

from app.services.provider_keyed_mixed_published_dispatch import (
    PublishedMixedDispatchAttention, preview_published_mixed_cleanup,
    start_published_mixed_cleanup,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.engagement_teardown import engagement_teardown_in_progress
from app.services.provider_keyed_mixed_published_public import (
    recover_published_mixed_dispatches,
)
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_reservation import _persisted


def test_published_preview_and_start_reserve_one_exact_parent(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        _exercise(ready, tmp_path, monkeypatch)


def _exercise(ready, tmp_path, monkeypatch):
    jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
    core = jobs.get(collection.review.source.core_job_id)
    calls = []

    def collect(*_args, **_kwargs):
        calls.append("collect")
        return collection

    preview = preview_published_mixed_cleanup(
        core, environment="devtest", job_repository=jobs,
        lease_lookup=lambda *_: None, collector=collect)
    assert preview["startAvailable"] is True
    assert preview["blockers"] == []
    assert preview["parentJobId"] is None
    assert preview["orderedScope"][0]["items"] == list(collection.review.provider_scopes)
    assert preview["confirmationPhrase"] == "teardown-opaque-fixture"
    with pytest.raises(PublishedMixedDispatchAttention):
        start_published_mixed_cleanup(
            core, {"snapshotId": "wrong", "confirmation": preview["confirmationPhrase"]},
            environment="devtest", job_repository=jobs,
            lease_lookup=lambda *_: None, collector=collect)
    assert jobs.get(proposal.id) is None
    saved = start_published_mixed_cleanup(
        core, {"snapshotId": preview["snapshotId"],
               "confirmation": preview["confirmationPhrase"]},
        environment="devtest", job_repository=jobs,
        lease_lookup=_db_lease_lookup,
        collector=collect)
    assert saved.id == proposal.id
    assert saved.status == "queued"
    assert engagement_teardown_in_progress(
        collection.review.source.engagement_id, repository=jobs) == saved
    assert len(calls) == 3
    scheduled = []
    assert recover_published_mixed_dispatches(
        environment="devtest", schedule=scheduled.append,
        job_repository=jobs, lease_lookup=_db_lease_lookup) == [saved.id]
    assert scheduled == [saved.id]
    assert recover_published_mixed_dispatches(
        environment="devtest", schedule=scheduled.append,
        job_repository=jobs, lease_lookup=lambda *_: None) == []
    lease = _db_lease_lookup
    pending = preview_published_mixed_cleanup(
        core, environment="devtest", job_repository=jobs,
        lease_lookup=lease,
        collector=lambda *_a, **_k: pytest.fail("full/full source recollected"))
    assert pending["snapshotId"] == preview["snapshotId"]
    assert pending["parentJobId"] == saved.id
    assert pending["startAvailable"] is False
    assert start_published_mixed_cleanup(
        core, {"snapshotId": pending["snapshotId"],
               "confirmation": pending["confirmationPhrase"]},
        environment="devtest", job_repository=jobs, lease_lookup=lease,
        collector=lambda *_a, **_k: pytest.fail("full/full source recollected")) == saved
    with pytest.raises(PublishedMixedDispatchAttention):
        preview_published_mixed_cleanup(
            core, environment="devtest", job_repository=jobs,
            lease_lookup=lambda *_: None,
            collector=lambda *_a, **_k: pytest.fail("full/full source recollected"))
    completed = replace(saved, status="succeeded")
    original_get = jobs.get
    monkeypatch.setattr(jobs, "get", lambda identifier: (
        completed if identifier == saved.id else original_get(identifier)))
    from app.services import provider_keyed_mixed_published_terminal as terminal
    monkeypatch.setattr(terminal, "recognize_published_mixed_terminal",
                        lambda *_a, **_k: completed)
    complete_preview = preview_published_mixed_cleanup(
        core, environment="devtest", job_repository=jobs,
        lease_lookup=lambda *_: None,
        collector=lambda *_a, **_k: pytest.fail("full/full source recollected"))
    assert complete_preview["startAvailable"] is False
    assert complete_preview["blockers"] == ["teardown complete"]
    assert start_published_mixed_cleanup(
        core, {}, environment="devtest", job_repository=jobs,
        lease_lookup=lambda *_: None,
        collector=lambda *_a, **_k: pytest.fail("full/full source recollected")) == completed
