# Copyright (c) 2026, Oracle and/or its affiliates.
"""Actual six-node checkpoint shape feeds Operations and cleanup-parent GETs."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.engagement_operations import _mixed_published_progress
from app.services.provider_keyed_mixed_published_teardown_checkpoint import propose_published_mixed_initial_cleanup
from app.services.provider_keyed_mixed_published_dispatch_claim import _marker
from test_provider_keyed_mixed_published_six_workflow import _persist, _owned_dns_setup


def produced_case(client, tmp_path, monkeypatch, *, reverse=False, unpublished=False):
    # This producer composes real saved six-node source, policies, owned bindings,
    # manifest and checkpoint. Provider/host observation inputs stay offline.
    zone = None if unpublished else _owned_dns_setup(tmp_path, monkeypatch)
    jobs, _, _, core, collection = _persist(client, tmp_path, monkeypatch, reverse,
        before_collect=zone.seed if zone else None, unpublished=unpublished)
    parent = propose_published_mixed_initial_cleanup(collection.review,
        collection.core_inspector_scope, "Opaque", requested_by="operator")
    assert set(parent.input["publishedSource"]) == {"six_node_source", "parent_job_id", "provider_states"}
    assert len(collection.review.source.host_rows) == 6
    if zone:
        assert parent.input["bindingManifest"]["bindingCount"] > 0
        assert parent.input["bindingManifest"]["domains"]
    return jobs, core, parent, collection.review.source.ordered_providers


def running_display(jobs, parent, *, phase="plans_sealed", status="queued", child=False):
    # Status/phase changes are display scenarios, not provider command authorization.
    parent = jobs.save(replace(parent, status=status, input={**parent.input, "phase": phase}))
    now = datetime.now(timezone.utc)
    marker = _marker(parent)
    marker = jobs.save(replace(marker, status="running", started_at=now.isoformat(),
        input={**marker.input, "claimOwner": "mixed-published-dispatch-" + "a" * 32,
               "claimToken": "b" * 32, "claimClaimedAt": (now - timedelta(seconds=5)).isoformat(),
               "claimHeartbeatAt": now.isoformat(), "claimExpiresAt": (now + timedelta(minutes=2)).isoformat()},
        events=[*marker.events, JobEvent(2, "info", "published mixed dispatch started", {})]))
    active = None
    if child:
        provider = parent.input["orderedProviders"][0]
        active = jobs.save(replace(parent,
            id=f"job-provider-keyed-mixed-published-destroy-{parent.input['coreJobId'].removeprefix('job-')}-{provider}",
            action="provider_keyed_mixed_published_destroy_apply", status="running",
            input={"cleanupParentId": parent.id, "coreJobId": parent.input["coreJobId"]},
            events=[JobEvent(1, "info", "provider command started", {})]))
    return parent, marker, active


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("phase,child", [("awaiting_both_destroy_plans", False), ("plans_sealed", False), ("plans_sealed", True)])
def test_real_bound_six_checkpoint_operations_and_actual_detail_get(client, tmp_path, monkeypatch, reverse, phase, child):
    with client.application.storage_context():
        jobs, core, parent, order = produced_case(client, tmp_path, monkeypatch, reverse=reverse)
        parent, marker, active = running_display(jobs, parent, phase=phase, child=child)
        original = deepcopy(parent.input)
    operations = client.get(f"/api/engagements/{parent.target_id}/operations?includeProviderFindings=false")
    assert operations.status_code == 200
    view = operations.json()["operations"]
    assert view["teardownSelection"] == {"state": "exact"}
    assert view["teardownJob"]["id"] == parent.id and view["teardownJob"]["status"] == "queued"
    expected = "destroy_plans" if phase == "awaiting_both_destroy_plans" else f"{order[0]}_absence"
    assert view["teardownJob"]["phase"] == expected
    assert view["teardownJob"]["recoveryState"] == "in_progress"
    assert view["teardownJob"]["progress"] == {"completed": 0 if expected == "destroy_plans" else 1, "total": 9}
    assert view["teardownJob"]["dispatch"]["claimState"] == "live"
    detail = client.get('/api/orchestrator/barragan-testing/pilot-standard-rti/runs/' + parent.id)
    assert detail.status_code == 200
    shown = detail.json()["job"]
    assert shown["id"] == parent.id and shown["phase"] == expected
    assert shown["dispatch"]["heartbeatAt"] == marker.input["claimHeartbeatAt"]
    assert (shown["activeChild"]["id"] if shown["activeChild"] else None) == (active.id if active else None)
    # Core detail remains the core job; only the parent endpoint augments teardown.
    core_detail = client.get('/api/orchestrator/barragan-testing/pilot-standard-rti/runs/' + core.id)
    assert core_detail.status_code == 200 and core_detail.json()["job"]["id"] == core.id
    assert "dispatch" not in core_detail.json()["job"] and "activeChild" not in core_detail.json()["job"]
    with client.application.storage_context():
        assert jobs.get(parent.id).input == original
    export = os.environ.get("BARRAGAN_TEST_EXPORT_SIX_DISPLAY")
    if export:
        Path(export).write_text(json.dumps({"id": parent.id, "status": parent.status,
            "targetType": parent.target_type, "targetId": parent.target_id,
            "input": {key: parent.input[key] for key in ("sourceKind", "publishedSource", "engagementId",
                "coreJobId", "corePlanId", "publishedParentId", "orderedProviders")}}, indent=2))


@pytest.mark.parametrize("drift", ["unknown-kind", "mixed-shape", "wrong-core", "wrong-plan", "wrong-engagement", "order", "missing-state"])
def test_real_six_checkpoint_display_rejects_malformed_or_crossed_source(client, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, _, parent, _ = produced_case(client, tmp_path, monkeypatch)
        body = deepcopy(parent.input)
        nested = body["publishedSource"]["six_node_source"]
        if drift == "unknown-kind": body["sourceKind"] = "unknown-v1"
        elif drift == "mixed-shape": body["publishedSource"]["ordered_providers"] = body["orderedProviders"]
        elif drift == "wrong-core": nested["core_job_id"] = "job-alien"
        elif drift == "wrong-plan": nested["core_plan_id"] = "plan-alien"
        elif drift == "wrong-engagement": nested["engagement_id"] = "eng-alien"
        elif drift == "order": nested["provider_order"] = list(reversed(nested["provider_order"]))
        else: body["publishedSource"]["provider_states"].pop()
        changed = jobs.save(replace(parent, input=body))
        assert _mixed_published_progress(changed, [changed]) == ("attention", {"completed": 0, "total": 9})
    view = client.get(f"/api/engagements/{parent.target_id}/operations?includeProviderFindings=false").json()["operations"]
    assert view["teardownSelection"] == {"state": "unavailable"} and view["teardownJob"] is None


def test_real_unpublished_six_checkpoint_uses_same_nested_read_shape(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, _, parent, _ = produced_case(client, tmp_path, monkeypatch, unpublished=True)
        jobs.save(parent)
        assert parent.input["sourceKind"] == "unpublished-six-node-cleanup-v1"
        assert _mixed_published_progress(parent, [parent]) == ("destroy_plans", {"completed": 0, "total": 9})


def test_real_six_terminal_detail_and_operations_remain_historical(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, core, parent, _ = produced_case(client, tmp_path, monkeypatch)
        parent = jobs.save(replace(parent, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
            input={**parent.input, "phase": "lifecycle_reconciliation"}, events=[*parent.events,
                JobEvent(2, "info", "published mixed teardown complete", {"finalCleanupStatus": "verified_clean"})]))
    view = client.get(f"/api/engagements/{parent.target_id}/operations?includeProviderFindings=false").json()["operations"]
    assert view["teardownSelection"] == {"state": "exact"}
    assert view["teardownJob"]["phase"] == "complete" and view["teardownJob"]["recoveryState"] == "complete"
    detail = client.get('/api/orchestrator/barragan-testing/pilot-standard-rti/runs/' + parent.id).json()["job"]
    assert detail["id"] == parent.id and detail["phase"] == "complete" and detail["status"] == "succeeded"
