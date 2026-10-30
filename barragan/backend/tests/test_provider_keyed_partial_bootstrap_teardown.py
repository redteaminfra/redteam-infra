# Copyright (c) 2026, Oracle and/or its affiliates.
"""A failed root command may be retired only after its exact audit has settled."""

from dataclasses import replace
import shutil

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_teardown_quiescence as audit
from app.services.provider_keyed_host_binding import _digest_json
from test_provider_keyed_teardown_quiescence import _completed


def _partial(tmp_path, monkeypatch, *, diagnosed=False):
    jobs, parent, root, scope = _completed(tmp_path)
    monkeypatch.setattr(audit, "_recorded_group_active", lambda _data: False)
    manifest = next(event.data for event in parent.events
                    if event.message == "provider host identity binding intended")
    nodes = [next(node for node in manifest["nodes"]
                  if node["chainId"] == chain_id and node["role"] == role)
             for chain_id in scope["chainIds"] for role in ("middle", "edge")]
    manifest = {**manifest, "nodes": nodes}
    scope["resources"] = [
        {"address": node["terraformAddress"], "id": node["providerInstanceId"]}
        for node in nodes
    ]
    prior = [
        "provider continuation job queued", "provider plan child starting",
        "provider plan child queued", "provider plan child succeeded",
        "provider apply preflight passed", "provider apply child queued",
        "provider attachment proof started",
    ]
    events = [JobEvent(index, "info", message,
                       {"creationToken": "a" * 32} if index == 1 else {})
              for index, message in enumerate(prior, 1)]
    attachment = next(event.data for event in parent.events
                      if event.message == "provider attachment proven; host proof pending")
    events.append(JobEvent(8, "info", "provider attachment proven; host proof pending",
                           attachment))
    host_events = [event for event in parent.events
                   if event.message in {
                       "provider host identity binding intended", "provider host identity bound",
                       audit._PREPARED, audit._CONTACT, audit._INTENT, audit._STARTED,
                       audit._RESULT, audit._ROOT,
                   }][:11]
    for event in host_events:
        data = (manifest if event.message == "provider host identity binding intended"
                else {**event.data, "manifestSha256": _digest_json(manifest)}
                if event.message in {"provider host identity bound", audit._PREPARED}
                else event.data)
        events.append(JobEvent(len(events) + 1, event.level, event.message, data))
    assert len(events) == 19
    # This fixture completed both chains; the partial run never creates the
    # reserved second scratch directory.
    shutil.rmtree(events[10].data["scratchPaths"][1])
    events[18] = replace(events[18], data={**events[18].data, "returnCode": 2})
    detail = "upstream sketch bootstrap failed (exit 2): redacted task failed"
    terminal = JobEvent(20, "error",
        "provider bootstrap stopped; manual read-only reconciliation required"
        + ("; " + detail[:240] if diagnosed else ""),
        {"failureDetail": detail} if diagnosed else {})
    failed = replace(parent, status="failed", finished_at="2026-10-14T12:00:00+00:00",
        input={**parent.input, "phase": "attention",
               "claimExpiresAt": "2026-10-14T12:00:00+00:00"},
        events=[*events, terminal])
    jobs.save(failed)
    return jobs, failed, root, scope


@pytest.mark.parametrize("diagnosed", [False, True])
def test_exact_partial_root_failure_requires_settled_claim_and_keys(
    tmp_path, monkeypatch, diagnosed,
):
    jobs, failed, root, scope = _partial(tmp_path, monkeypatch, diagnosed=diagnosed)

    def check():
        return audit._exact_partial_root_failure(
            jobs.get(failed.id), jobs.get(failed.id).events,
            scope, root, jobs, "job-core")

    assert check()
    jobs.save(replace(failed, input={**failed.input,
                                    "claimExpiresAt": "2099-01-01T00:00:00+00:00"}))
    assert not check()
    jobs.save(failed)
    monkeypatch.setattr(audit, "_recorded_group_active", lambda _data: True)
    assert not check()
    monkeypatch.setattr(audit, "_recorded_group_active", lambda _data: False)
    scratch = root / failed.events[10].data["scratchPaths"][0].rsplit("/", 1)[-1]
    (scratch / "keys").mkdir()
    assert not check()
    (scratch / "keys").rmdir()
    assert check()


def test_partial_root_failure_rejects_journal_or_identity_drift(tmp_path, monkeypatch):
    jobs, failed, root, scope = _partial(tmp_path, monkeypatch)

    def check():
        current = jobs.get(failed.id)
        return audit._exact_partial_root_failure(
            current, current.events, scope, root, jobs, "job-core")

    assert check()
    for event in (
        replace(failed.events[18], data={**failed.events[18].data, "returnCode": 0}),
        replace(failed.events[18], data={**failed.events[18].data, "invocationId": "other"}),
        replace(failed.events[18], message="command result unrecorded"),
    ):
        jobs.save(replace(failed, events=[*failed.events[:18], event, failed.events[-1]]))
        assert not check()
    jobs.save(replace(failed, events=[*failed.events, JobEvent(
        21, "info", "unreviewed later host command", {})]))
    assert not check()
    jobs.save(failed)
    assert check()
    scope["resources"][0]["id"] = "unreviewed-instance"
    assert not check()
