# Copyright (c) 2026, Oracle and/or its affiliates.
"""A finished published teardown supersedes core status only in Operations."""
from dataclasses import replace

import pytest

from app.domain import JobEvent
from test_teardown_progress_projection import _case, _overview


def _terminal_case(tmp_path):
    repo, core, parent, marker, child = _case(tmp_path)
    core = replace(core, events=[JobEvent(1, "info", "core deployed", {
        "finalCleanupStatus": "pending_operator_teardown",
        "mutationStatus": "deployed",
        "connectionDetails": [
            {"role": "homebase", "displayName": "homebase-original-name", "sshAlias": "homebase-original-name", "publicIp": "8.8.8.8"},
            {"role": "proxy", "displayName": "proxy01-original-name", "sshAlias": "proxy01-original-name", "publicIp": "9.9.9.9"},
        ],
    })])
    parent = replace(parent, status="succeeded", finished_at="2026-10-26T23:00:00Z",
        input={**parent.input, "remainingOwnedResources": []}, events=[
            *parent.events, JobEvent(2, "info", "published mixed teardown complete", {
                "state": "destroyed", "finalCleanupStatus": "verified_clean"})])
    for row in (core, parent, replace(marker, status="succeeded"), replace(child, status="succeeded")):
        repo.save(row)
    return repo, core, parent


def test_completed_published_cleanup_projects_historical_core_without_rewriting_it(tmp_path):
    repo, core, parent = _terminal_case(tmp_path)
    before = repo.get(core.id)
    result = _overview(repo)
    assert result["lifecycle"]["state"] == "destroyed"
    assert result["teardownJob"]["recoveryState"] == "complete"
    assert len(result["coreInfrastructure"]) == 2
    for host in result["coreInfrastructure"]:
        assert host["status"] == host["lifecycleState"] == "destroyed"
        assert host["lastKnown"] is True
        assert host["health"]["status"] == "destroyed"
        assert host["health"]["source"] == "cleanup verification"
    assert result["healthSummary"]["status"] == "destroyed"
    assert result["healthSummary"]["activeHostCount"] == 0
    assert [row["publicIp"] for row in result["coreInfrastructure"]] == ["8.8.8.8", "9.9.9.9"]
    assert result["coreJob"]["status"] == "succeeded"
    assert repo.get(core.id) == before
    assert repo.get(core.id).events[0].data["finalCleanupStatus"] == "pending_operator_teardown"
    assert repo.get(parent.id) == parent


@pytest.mark.parametrize("drift", ["running", "failed", "unfinished", "remaining", "missing-state", "wrong-plan", "ambiguous", "new-core"])
def test_unproved_or_other_generation_cleanup_does_not_retire_core_projection(tmp_path, drift):
    repo, core, parent = _terminal_case(tmp_path)
    if drift in {"running", "failed"}:
        repo.save(replace(parent, status=drift))
    elif drift == "unfinished":
        repo.save(replace(parent, finished_at=None))
    elif drift == "remaining":
        repo.save(replace(parent, input={**parent.input, "remainingOwnedResources": ["unproved"]}))
    elif drift == "missing-state":
        repo.save(replace(parent, events=[*parent.events[:-1], replace(parent.events[-1], data={"finalCleanupStatus": "verified_clean"})]))
    elif drift == "wrong-plan":
        repo.save(replace(core, input={**core.input, "corePlanId": "plan-other"}))
    elif drift == "ambiguous":
        repo.save(replace(parent, id="job-other-cleanup", action="engagement_comprehensive_teardown"))
    else:
        repo.save(replace(core, id="job-new-core", created_at="2026-10-27T00:00:00Z",
            input={**core.input, "corePlanId": "plan-new"}))
    result = _overview(repo)
    assert len(result["coreInfrastructure"]) == 2
    assert all(row["lifecycleState"] == "active" and row["lastKnown"] is False for row in result["coreInfrastructure"])
    assert result["healthSummary"]["activeHostCount"] == 2
