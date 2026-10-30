# Copyright (c) 2026, Oracle and/or its affiliates.
"""A retained Inspector may be reread during one exact published pre-GO child."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_comprehensive_teardown as service
from app.services import sketch_state_workspaces
from app.storage.job_repository import StoredJobRun, job_event_digest


def _case(tmp_path, monkeypatch, *, existing=None):
    monkeypatch.setattr(sketch_state_workspaces, "_default_state_root", lambda: tmp_path)
    workspace = (tmp_path / "keyed" if existing is None else
                 Path(existing[2]["providerScopes"][0]["workspace"]))
    workspace.mkdir(exist_ok=True)
    state = workspace / "terraform.tfstate"
    if existing is None:
        state.write_text('{"lineage":"stable"}')
    state_sha = hashlib.sha256(state.read_bytes()).hexdigest()
    marker = workspace / ".barragan-apply-phase.json"
    marker.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "destroy_started"}))
    if existing is None:
        core = SimpleNamespace(id="job-core", input={"corePlanId": "plan-1"})
        scope = {"workspace": str(workspace), "stateSha256": state_sha,
                 "selectorTag": "selector-1", "providerConnectionId": "credential-1",
                 "resources": [{"address": "digitalocean_ssh_key.key", "id": "1"}]}
        snapshot = {"snapshotId": "a" * 64, "providerScopeSha256": "b" * 64,
                    "providerScopes": [scope], "dnsCleanupManifest": {
                        "manifestSha256": "sha256:" + "f" * 64}}
        parent = SimpleNamespace(
            id="job-engagement-teardown-core", target_id="engagement-1",
            requested_by="operator", input={"publishedSource": {
                "scope_sha256": service._fingerprint(scope), "state_sha256": state_sha}},
        )
    else:
        parent, core, snapshot = existing
        assert snapshot["providerScopes"][0]["stateSha256"] == state_sha
    stamp = datetime.now(timezone.utc)
    prestate = {
        "coreJobId": core.id, "corePlanId": core.input["corePlanId"],
        "scopeSnapshotId": snapshot["snapshotId"],
        "providerScopeSha256": snapshot["providerScopeSha256"],
        "preDestroyStateSha256": state_sha,
        "stateLineage": "lineage-1", "preDestroySerial": 1,
        "resourceIds": {row["address"]: row["id"] for row in snapshot["providerScopes"][0]["resources"]},
        "selectorTag": snapshot["providerScopes"][0]["selectorTag"],
        "credentialRecordId": snapshot["providerScopes"][0]["providerConnectionId"],
        "credentialSecretSha256": "d" * 64,
        "credentialUpdatedAt": "2026-10-13T00:00:00+00:00",
        "dnsCleanupManifestSha256": snapshot["dnsCleanupManifest"]["manifestSha256"],
        "dnsCleanupHandoffJournalSha256": "e" * 64,
        "dnsCleanupCheckpointSha256": "f" * 64,
    }
    prestate["resourceIdsSha256"] = service._fingerprint(prestate["resourceIds"])
    events = [
        JobEvent(1, "info", "provider destroy apply queued", {}),
        JobEvent(2, "info", "provider destroy apply started", {}),
        JobEvent(3, "info", "provider destroy command intent fenced",
                 {"phase": "show", "invocationId": "show"}),
        JobEvent(4, "info", "provider destroy command started before GO",
                 {"phase": "show", "invocationId": "show"}),
        JobEvent(5, "info", "provider destroy command result fenced",
                 {"phase": "show", "invocationId": "show", "returnCode": 0}),
        JobEvent(6, "info", "provider destroy prestate identity fenced", prestate),
        JobEvent(7, "info", "provider destroy phase write intended",
                 {"phase": "destroy_started", "path": str(marker)}),
        JobEvent(8, "info", "provider destroy command intent fenced",
                 {"phase": "apply", "invocationId": "apply"}),
        JobEvent(9, "info", "provider destroy command started before GO",
                 {"phase": "apply", "invocationId": "apply"}),
    ]
    child = StoredJobRun(
        id=f"job-provider-keyed-initial-destroy-apply-{core.id.removeprefix('job-')}",
        action="provider_keyed_initial_destroy_apply", status="running",
        target=f"engagement:{parent.target_id}", target_type="engagement",
        target_id=parent.target_id, requested_by=parent.requested_by,
        input={
            "engagementId": parent.target_id, "coreJobId": core.id,
            "corePlanId": core.input["corePlanId"], "teardownParentId": parent.id,
            "scopeSnapshotId": snapshot["snapshotId"],
            "providerScopeSha256": snapshot["providerScopeSha256"],
            "destroyPlanJobId": f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}",
            "planSha256": "c" * 64, "mutation": True,
            "claimOwner": "provider-keyed-destroy-apply-" + "d" * 32,
            "claimToken": "e" * 32, "claimClaimedAt": stamp.isoformat(),
            "claimHeartbeatAt": stamp.isoformat(),
            "claimExpiresAt": (stamp + timedelta(minutes=20)).isoformat(),
        },
        artifact_refs=[], created_at=stamp.isoformat(),
        started_at=stamp.isoformat(), finished_at=None, events=events,
    )
    preview = SimpleNamespace(
        id=f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}",
        status="succeeded",
        events=[SimpleNamespace(data={"planSha256": "c" * 64,
                                      "credentialSecretSha256": "d" * 64,
                                      "credentialUpdatedAt": "2026-10-13T00:00:00+00:00"})])
    jobs = SimpleNamespace(get=lambda job_id: (
        child if job_id == child.id else preview if job_id == preview.id else None))
    return parent, core, snapshot, child, jobs, state, marker


def test_exact_published_destroy_started_child_is_readable(tmp_path, monkeypatch):
    parent, core, snapshot, child, jobs, _state, _marker = _case(tmp_path, monkeypatch)
    service._published_destroy_started_inspector_boundary(
        parent, core, snapshot, child, jobs, state_root=tmp_path)


@pytest.mark.parametrize("drift", [None, "journal", "schema", "published", "child"])
def test_exact_failed_prebinding_destroy_started_child_requires_pending_source(
    tmp_path, monkeypatch, drift,
):
    parent, core, snapshot, child, jobs, _state, _marker = _case(tmp_path, monkeypatch)
    initial = SimpleNamespace(status="failed", events=[JobEvent(1, "error", "failed", {})])
    manifest = {**snapshot["dnsCleanupManifest"],
                "schema": "provider-keyed-empty-dns-prebinding-v1",
                "initialJournalSha256": job_event_digest(initial.events)}
    snapshot["dnsCleanupManifest"] = manifest
    parent.input = {}
    original_get = jobs.get
    from app.services.provider_keyed_initial_continuation import _job_ids
    initial_id = _job_ids(core.id)[0]
    child = replace(child, events=[
        replace(event, data={**event.data,
                             "dnsCleanupManifestSha256": manifest["manifestSha256"]})
        if event.sequence == 6 else event for event in child.events
    ])
    jobs.get = lambda job_id: (initial if job_id == initial_id else
                               child if job_id == child.id else original_get(job_id))
    if drift == "journal":
        manifest["initialJournalSha256"] = "0" * 64
    elif drift == "schema":
        manifest["schema"] = "unexpected"
    elif drift == "published":
        parent.input = {"publishedSource": {}}
    elif drift == "child":
        child = replace(child, events=child.events[:-1])
    if drift is None:
        service._published_destroy_started_inspector_boundary(
            parent, core, snapshot, child, jobs, state_root=tmp_path,
            failed_prebinding=True)
    else:
        with pytest.raises(ValueError):
            service._published_destroy_started_inspector_boundary(
                parent, core, snapshot, child, jobs, state_root=tmp_path,
                failed_prebinding=True)


@pytest.mark.parametrize("drift", [
    "unpublished", "source_seal", "wrong_child", "event", "state",
    "state_symlink", "marker", "claim", "preview_hash",
])
def test_destroy_started_exception_rejects_drift(tmp_path, monkeypatch, drift):
    parent, core, snapshot, child, jobs, state, marker = _case(tmp_path, monkeypatch)
    if drift == "unpublished":
        parent.input = {}
    elif drift == "source_seal":
        parent.input = {"publishedSource": {**parent.input["publishedSource"],
                                            "scope_sha256": "0" * 64}}
    elif drift == "wrong_child":
        child = replace(child, id="job-provider-keyed-initial-destroy-apply-other")
    elif drift == "event":
        events = list(child.events)
        events[-1] = replace(events[-1], message="provider destroy command result fenced")
        child = replace(child, events=events)
    elif drift == "state":
        state.write_text('{"lineage":"changed"}')
    elif drift == "state_symlink":
        prior = state.with_suffix(".original")
        state.rename(prior)
        state.symlink_to(prior)
    elif drift == "marker":
        marker.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "applied"}))
    elif drift == "preview_hash":
        original_get = jobs.get
        preview = original_get(child.input["destroyPlanJobId"])
        preview.events[-1].data["planSha256"] = "0" * 64
    else:
        child = replace(child, input={**child.input, "claimExpiresAt": (
            datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()})
    original_get = jobs.get
    jobs.get = lambda job_id: child if job_id == child.id else original_get(job_id)
    with pytest.raises(ValueError):
        service._published_destroy_started_inspector_boundary(
            parent, core, snapshot, child, jobs, state_root=tmp_path)
