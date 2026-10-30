# Copyright (c) 2026, Oracle and/or its affiliates.
"""Engagement query contract for the service tests' in-memory job repositories."""

from dataclasses import replace

import pytest

from app.domain import JobEvent
from app.services.core_ssh import active_core_connection_details
from app.storage.job_repository import StoredJobRun
from test_backflips_service import _FakeJobRepository as BackflipsJobRepository
from test_legacy_homebase_role_service import _FakeJobRepository as LegacyRoleJobRepository
from test_outbound_channel_apply import _FakeJobRepository as OutboundJobRepository


@pytest.fixture(params=[BackflipsJobRepository, LegacyRoleJobRepository, OutboundJobRepository],
                ids=["backflips", "legacy-role", "outbound"])
def repository_class(request):
    return request.param


def _job(identifier, **overrides):
    return replace(StoredJobRun(
        id=identifier, action="pilot_standard_rti_guarded_execute", status="succeeded",
        target="oci-compartment:testing", target_type="oci_compartment", target_id="compartment-test",
        requested_by="fixture", input={}, artifact_refs=[], created_at="2026-10-28T12:00:00Z",
        started_at="2026-10-28T12:00:01Z", finished_at="2026-10-28T12:01:00Z", events=[],
    ), **overrides)


def test_scoped_query_matches_all_production_identity_columns_and_respects_limit(repository_class):
    jobs = [
        _job("foreign", input={"engagementId": "eng-other"}),
        _job("input-match", input={"engagementId": "eng-selected"}),
        _job("target-match", target="engagement:eng-selected"),
        _job("target-id-match", target_id="eng-selected"),
    ]
    repository = repository_class(jobs)
    assert [job.id for job in repository.list_for_engagement("eng-selected")] == [
        "input-match", "target-match", "target-id-match"
    ]
    assert repository.list_for_engagement("eng-selected", limit=1) == [jobs[1]]
    assert repository.list_for_engagement("eng-selected", limit=0) == []
    assert repository.list_for_engagement("eng-absent") == []
    assert repository.list() == jobs


def test_active_core_reader_cannot_select_foreign_connection_details(repository_class):
    def connection(hostname):
        return [JobEvent(1, "info", "connection details", {"connectionDetails": [{"role": "homebase", "displayName": hostname}]})]
    repository = repository_class([
        _job("newer-foreign-core", input={"engagementId": "eng-other"}, events=connection("other-homebase")),
        _job("selected-channel", action="outbound_channel_apply", input={"engagementId": "eng-selected"},
             events=connection("channel-snapshot")),
        _job("selected-core", input={"engagementId": "eng-selected"}, events=connection("selected-homebase")),
    ])
    assert active_core_connection_details(repository, "eng-selected") == (
        "selected-core", [{"role": "homebase", "displayName": "selected-homebase"}]
    )
    assert active_core_connection_details(repository, "eng-absent") == ("", [])


def test_scoped_query_sorts_newest_first_before_limit_with_stable_ties(repository_class):
    jobs = [
        _job("old", target_id="eng-selected", created_at="2026-10-27T12:00:00Z"),
        _job("new-first", target_id="eng-selected", created_at="2026-10-28T14:00:00Z"),
        _job("middle", target_id="eng-selected", created_at="2026-10-28T13:00:00Z"),
        _job("new-second", target_id="eng-selected", created_at="2026-10-28T14:00:00Z"),
        _job("foreign-newest", target_id="eng-other", created_at="2026-10-28T15:00:00Z"),
    ]
    repository = repository_class(jobs)
    assert [job.id for job in repository.list_for_engagement("eng-selected")] == [
        "new-first", "new-second", "middle", "old"
    ]
    assert repository.list_for_engagement("eng-selected", limit=1) == [jobs[1]]
    assert repository.list_for_engagement("eng-selected", limit=2) == [jobs[1], jobs[3]]
    assert repository.list() == jobs


def test_active_core_reader_selects_newest_generation_after_save(repository_class):
    def core(identifier, created_at):
        return _job(
            identifier, created_at=created_at, input={"engagementId": "eng-selected"},
            events=[JobEvent(1, "info", "connection details", {
                "connectionDetails": [{"role": "homebase", "displayName": identifier}]
            })],
        )
    old = core("old-generation", "2026-10-27T12:00:00Z")
    new = core("new-generation", "2026-10-28T12:00:00Z")
    repository = repository_class([old])
    repository.save(new)
    assert active_core_connection_details(repository, "eng-selected") == (
        "new-generation", [{"role": "homebase", "displayName": "new-generation"}]
    )
    # Updating the older row must not make it the newest deployment generation.
    repository.save(old)
    assert active_core_connection_details(repository, "eng-selected")[0] == "new-generation"
