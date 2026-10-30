# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact, claim-only takeover of an interrupted pre-GO DO destroy child."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from app.domain import JobEvent
from app.storage import models  # noqa: F401 - register tables before create_all
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun, job_event_digest,
)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _child():
    now = datetime.now(timezone.utc)
    old_expiry = (now - timedelta(minutes=1)).isoformat()
    ids = {f"digitalocean_droplet.middle[\"m{i}\"]": str(i) for i in range(1, 3)}
    ids.update({f"digitalocean_droplet.edge[\"e{i}\"]": str(i + 2) for i in range(1, 3)})
    ids["digitalocean_firewall.firewall"] = "f" * 36
    ids["digitalocean_ssh_key.key"] = "5"
    ids["local_file.ansible_inventory[0]"] = "local-1"
    ids["local_file.ssh_stanza[0]"] = "local-2"
    inputs = {
        "engagementId": "eng-test", "coreJobId": "job-core", "corePlanId": "plan-core",
        "teardownParentId": "job-parent", "scopeSnapshotId": "a" * 64,
        "providerScopeSha256": "b" * 64, "destroyPlanJobId": "job-preview",
        "planSha256": "c" * 64, "mutation": True,
        "claimOwner": "provider-keyed-destroy-apply-old", "claimToken": "d" * 32,
        "claimClaimedAt": (now - timedelta(minutes=2)).isoformat(),
        "claimExpiresAt": old_expiry,
    }
    pre = {
        "coreJobId": inputs["coreJobId"], "corePlanId": inputs["corePlanId"],
        "scopeSnapshotId": inputs["scopeSnapshotId"],
        "providerScopeSha256": inputs["providerScopeSha256"],
        "preDestroyStateSha256": "e" * 64,
        "stateLineage": "14d532bf-6147-4639-8dbc-92d17ec9fe8b",
        "preDestroySerial": 1, "resourceIds": ids,
        "resourceIdsSha256": _digest(ids), "selectorTag": "barragantest",
        "credentialRecordId": "credential-do", "credentialSecretSha256": "0" * 64,
        "credentialUpdatedAt": "2026-10-12T00:00:00+00:00",
        "dnsCleanupManifestSha256": "sha256:" + "1" * 64,
        "dnsCleanupHandoffJournalSha256": "2" * 64,
        "dnsCleanupCheckpointSha256": "3" * 64,
    }
    def intent(phase, invocation):
        return {"phase": phase, "invocationId": invocation, "argvSha256": "4" * 64}
    def started(phase, invocation, pid):
        return {"phase": phase, "invocationId": invocation, "bootId": "boot",
                "pid": pid, "pgid": pid, "startTicks": 12345}
    messages = [
        ("provider destroy apply queued", {}),
        ("provider destroy apply started", {}),
        ("provider destroy command intent fenced", intent("show", "show-1")),
        ("provider destroy command started before GO", started("show", "show-1", 101)),
        ("provider destroy command result fenced", {
            "phase": "show", "invocationId": "show-1", "returnCode": 0,
            "stdoutBytes": 10, "stderrBytes": 0,
            "stdoutTruncated": False, "stderrTruncated": False,
        }),
        ("provider destroy prestate identity fenced", pre),
        ("provider destroy phase write intended", {
            "phase": "destroy_started", "path": "/tmp/work/.barragan-apply-phase.json",
        }),
        ("provider destroy command intent fenced", intent("apply", "apply-1")),
        ("provider destroy command started before GO", started("apply", "apply-1", 102)),
    ]
    return StoredJobRun(
        id="job-provider-keyed-initial-destroy-apply-core", action="provider_keyed_initial_destroy_apply",
        status="running", target="engagement:eng-test", target_type="engagement",
        target_id="eng-test", requested_by="operator", input=inputs,
        artifact_refs=[], created_at=(now - timedelta(minutes=3)).isoformat(),
        started_at=(now - timedelta(minutes=2)).isoformat(), finished_at=None,
        events=[JobEvent(index, "info", message, data)
                for index, (message, data) in enumerate(messages, 1)],
    )


def test_incident_prestate_distinguishes_eight_state_addresses_from_six_cloud_ids():
    ids = _child().events[5].data["resourceIds"]
    assert len(ids) == 8
    assert len([address for address in ids if address.startswith("digitalocean_")]) == 6
    assert set(address for address in ids if address.startswith("local_file.")) == {
        "local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]",
    }
    assert _child().events[5].data["dnsCleanupManifestSha256"] == "sha256:" + "1" * 64


def _kwargs(row):
    now = datetime.now(timezone.utc)
    return {
        "expected_event_digest": job_event_digest(row.events),
        "owner": "provider-keyed-destroy-recovery-new", "token": "f" * 32,
        "claimed_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
    }


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_exact_nine_event_takeover_is_one_time_claim_only(tmp_path, backend):
    row = _child()
    if backend == "sqlite":
        jobs = SqliteJobRepository(tmp_path / "takeover.sqlite")
        scope = None
    else:
        scope = db.bind(db.configure(f"sqlite:///{tmp_path / 'takeover-sa.sqlite'}"))
        scope.__enter__()
        db.create_all()
        jobs = SqlAlchemyJobRepository()
    try:
        original = jobs.save(row)
        before_events = original.events
        taken = jobs.take_over_initial_destroy_apply_pre_go(original, **_kwargs(original))
        assert taken is not None and taken.input["claimOwner"] == "provider-keyed-destroy-recovery-new"
        assert taken.events == before_events and taken.status == "running"
        assert jobs.take_over_initial_destroy_apply_pre_go(original, **_kwargs(original)) is None
        assert jobs.get(row.id) == taken
    finally:
        if scope is not None:
            scope.__exit__(None, None, None)


@pytest.mark.parametrize("tamper", [
    "short", "extra", "result", "phase", "prestate", "invocation", "pid",
    "expiry", "claim_time", "wrong_owner", "digest", "input", "bare_manifest",
])
def test_takeover_rejects_ambiguous_journal_or_claim(tmp_path, tamper):
    jobs = SqliteJobRepository(tmp_path / "negative.sqlite")
    row = _child()
    kwargs = _kwargs(row)
    events = list(row.events)
    if tamper == "short":
        events.pop()
    elif tamper == "extra":
        events.append(JobEvent(10, "info", "provider destroy command result fenced", {}))
    elif tamper == "result":
        events[4] = replace(events[4], data={**events[4].data, "returnCode": 1})
    elif tamper == "phase":
        events[6] = replace(events[6], data={**events[6].data, "phase": "destroy_applied"})
    elif tamper == "prestate":
        events[5] = replace(events[5], data={**events[5].data, "resourceIdsSha256": "9" * 64})
    elif tamper == "bare_manifest":
        events[5] = replace(events[5], data={
            **events[5].data, "dnsCleanupManifestSha256": "1" * 64,
        })
    elif tamper == "invocation":
        events[8] = replace(events[8], data={**events[8].data, "invocationId": "show-1"})
    elif tamper == "pid":
        events[8] = replace(events[8], data={**events[8].data, "pgid": 999})
    elif tamper == "expiry":
        row = replace(row, input={**row.input, "claimExpiresAt": kwargs["expires_at"]})
    elif tamper == "claim_time":
        kwargs["claimed_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    elif tamper == "wrong_owner":
        kwargs["owner"] = "other"
    elif tamper == "digest":
        kwargs["expected_event_digest"] = "9" * 64
    elif tamper == "input":
        row = replace(row, input={**row.input, "extra": True})
    row = replace(row, events=events)
    stored = jobs.save(row)
    assert jobs.take_over_initial_destroy_apply_pre_go(stored, **kwargs) is None
    assert jobs.get(row.id) == stored


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("drift", ["journal", "input"])
def test_takeover_cas_rejects_stale_read_after_journal_or_input_change(tmp_path, backend, drift):
    if backend == "sqlite":
        jobs = SqliteJobRepository(tmp_path / "stale.sqlite")
        scope = None
    else:
        scope = db.bind(db.configure(f"sqlite:///{tmp_path / 'stale-sa.sqlite'}"))
        scope.__enter__()
        db.create_all()
        jobs = SqlAlchemyJobRepository()
    try:
        original = jobs.save(_child())
        if drift == "journal":
            revised = replace(original, events=[*original.events, JobEvent(
                10, "error", "late worker reported uncertainty", {})])
        else:
            revised = replace(original, input={
                **original.input,
                "claimHeartbeatAt": (datetime.now(timezone.utc) - timedelta(seconds=20)).isoformat(),
            })
        jobs.save(revised)
        assert jobs.take_over_initial_destroy_apply_pre_go(original, **_kwargs(original)) is None
        assert jobs.get(original.id) == revised
    finally:
        if scope is not None:
            scope.__exit__(None, None, None)
