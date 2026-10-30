# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted private selector DELETE, restart, and fail-closed visibility."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_selector_retirement as service
from app.storage.job_repository import SqliteJobRepository, StoredJobRun, job_event_digest


def _row(identifier, action, engagement, *, status="succeeded", events=None, inputs=None):
    now = datetime.now(timezone.utc).isoformat()
    return StoredJobRun(
        identifier, action, status, f"engagement:{engagement}", "engagement", engagement,
        "operator", inputs or {}, [], now, now if status != "queued" else None,
        now if status == "succeeded" else None,
        events or [JobEvent(1, "info", "fixture", {})],
    )


class Catalog:
    def __init__(self, selector):
        self.selector = selector
        self.null_volume = False
        self.database_reads = 0
        self.firewall_reference = False
        self.tag_present = True
        self.calls = []

    def request(self, base, method, path, token):
        assert base == service._ORIGIN and method == "GET" and token == "fake-token"
        self.calls.append(path)
        if path == f"/tags/{self.selector}":
            assert self.tag_present
            return {"tag": {"name": self.selector, "resources": {"count": 0}}}
        endpoint = path.split("?", 1)[0]
        key = endpoint.removeprefix("/")
        if key == "databases":
            self.database_reads += 1
            raise PermissionError("database:read unavailable")
        if key == "snapshots":
            rows = []
        elif key == "volumes" and self.null_volume:
            rows = [{"id": "vol-1", "tags": None}]
        elif key == "firewalls" and self.firewall_reference:
            rows = [{"id": "fw-1", "tags": [], "inbound_rules": [
                {"sources": {"tags": [self.selector]}}], "outbound_rules": []}]
        elif key == "firewalls":
            rows = []
        elif key == "tags" and self.tag_present:
            rows = [{"id": "tag-1", "name": self.selector}]
        else:
            rows = []
        return {key: rows, "meta": {"total": len(rows)}, "links": {"pages": {}}}


class Deleter:
    def __init__(self, catalog):
        self.catalog = catalog
        self.calls = 0
        self.fail_after_delete = False

    def delete_tag(self, token, selector):
        assert token == "fake-token" and selector == self.catalog.selector
        self.calls += 1
        self.catalog.tag_present = False
        if self.fail_after_delete:
            raise TimeoutError("lost response")
        return service.DeleteResponse(204, b"")

    def get_tag_status(self, token, selector):
        assert token == "fake-token" and selector == self.catalog.selector
        return 404 if not self.catalog.tag_present else 200


def _case(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    engagement = "eng-" + "1" * 32
    core_id = "job-core-" + "2" * 32
    selector = "s" + hashlib.sha256(engagement.encode()).hexdigest()[:20]
    parent = jobs.save(_row("job-parent", "engagement_comprehensive_teardown", engagement,
                            status="queued", inputs={"scopeSnapshot": {
                                "snapshotId": "a" * 64, "providerScopeSha256": "b" * 64}}))
    core = jobs.save(_row(core_id, "pilot_standard_rti_guarded_execute", engagement,
                          inputs={"corePlanId": "plan-core"}))
    initial_id, plan_id, apply_id = service._job_ids(core_id)
    initial = jobs.save(_row(initial_id, "provider_keyed_initial", engagement))
    plan = jobs.save(_row(plan_id, "provider_keyed_initial_plan", engagement,
                          events=[JobEvent(1, "info", "reviewed provider plan saved", {
                              "coreJobId": core.id, "corePlanId": "plan-core",
                              "providerConnectionId": "cred-1", "selectorTag": selector,
                              "sourceSha256": "e" * 64,
                              "credentialSecretSha256": "f" * 64,
                              "credentialUpdatedAt": "2026-10-09T00:00:00+00:00",
                              "planSha256": "c" * 64, "planPath": "/tmp/plan",
                              "terraformBinaryPath": "/usr/bin/terraform",
                              "terraformBinarySha256": "d" * 64})]))
    applied = jobs.save(_row(apply_id, "provider_keyed_initial_apply", engagement))
    absent = jobs.save(_row(
        f"job-provider-keyed-core-destroy-absence-{core_id.removeprefix('job-')}-attempt-01",
        service.CORE_ABSENCE_ACTION, engagement,
        inputs={"teardownParentId": parent.id, "coreJobId": core.id,
                "scopeSnapshotId": "a" * 64},
        events=[JobEvent(1, "info", "core destroy exact absence proved", {})]))
    before = SimpleNamespace(
        parent=parent, core=core, workspace=SimpleNamespace(source_sha256="e" * 64),
        intent=SimpleNamespace(selector_tag=selector, credential_record_id="cred-1",
                               credential_secret_sha256="f" * 64,
                               credential_updated_at="2026-10-09T00:00:00+00:00"),
    )
    monkeypatch.setattr(service, "_default_state_root", lambda: tmp_path)
    monkeypatch.setattr(service, "_read_success_boundary", lambda *args, **kwargs: before)
    monkeypatch.setattr(service, "_require_destroy_fence", lambda *args: None)
    monkeypatch.setattr(service, "_credential_snapshot", lambda *args: (
        "f" * 64, "2026-10-09T00:00:00+00:00", "encrypted"))
    monkeypatch.setattr(service, "require_initial_selector_absence_provenance",
                        lambda *args, **kwargs: None)
    catalog = Catalog(selector)
    deleter = Deleter(catalog)
    options = dict(environment="devtest", state_root=tmp_path, job_repository=jobs,
                   plan_repository=SimpleNamespace(), sketch_repository=SimpleNamespace(),
                   credential_repository=SimpleNamespace(),
                   lease_lookup=lambda engagement_id: ("plan-core", service._FENCE),
                   retired_recognizer=lambda *args, **kwargs: (),
                   core_absence_recognizer=lambda *args, **kwargs: absent,
                   catalog_transport=catalog, delete_transport=deleter,
                   decrypt_secret=lambda value: "fake-token")
    return jobs, parent, catalog, deleter, options


def test_persisted_exact_204_and_restart_never_replays(tmp_path, monkeypatch):
    jobs, parent, catalog, deleter, options = _case(tmp_path, monkeypatch)
    result = service.retire_pending_digitalocean_selector(parent.id, **options)
    assert result.status == "succeeded"
    assert [event.message for event in result.events[-2:]] == [
        "selector DELETE intended", "selector DELETE 204 received"]
    assert deleter.calls == 1
    assert catalog.database_reads == 0
    options["job_repository"] = SqliteJobRepository(jobs.database_path)
    with pytest.raises(service.SelectorRetirementAttention):
        service.retire_pending_digitalocean_selector(parent.id, **options)
    assert deleter.calls == 1


def test_ambiguous_delete_reconciles_absence_only_after_claim_expiry(tmp_path, monkeypatch):
    jobs, parent, catalog, deleter, options = _case(tmp_path, monkeypatch)
    deleter.fail_after_delete = True
    with pytest.raises(service.SelectorRetirementAttention):
        service.retire_pending_digitalocean_selector(parent.id, **options)
    assert deleter.calls == 1
    child = jobs.get(f"job-provider-keyed-selector-retirement-{'core-' + '2' * 32}")
    assert child.events[-1].message == "selector DELETE intended"
    assert child.status == "running"
    jobs.save(replace(child, input={**child.input, "claimExpiresAt":
                                   (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}))
    options["job_repository"] = SqliteJobRepository(jobs.database_path)
    reconciled = service.retire_pending_digitalocean_selector(parent.id, **options)
    assert reconciled.status == "succeeded"
    assert reconciled.events[-1].message == "selector absence reconciled"
    assert deleter.calls == 1


def test_pre_intent_visibility_failure_can_restart_after_claim_expiry(tmp_path, monkeypatch):
    jobs, parent, catalog, deleter, options = _case(tmp_path, monkeypatch)
    catalog.null_volume = True
    with pytest.raises(service.SelectorRetirementAttention):
        service.retire_pending_digitalocean_selector(parent.id, **options)
    assert deleter.calls == 0
    child_id = f"job-provider-keyed-selector-retirement-{'core-' + '2' * 32}"
    prior = jobs.get(child_id)
    assert [event.message for event in prior.events] == [
        "selector retirement queued", "selector retirement started"]
    jobs.save(replace(prior, input={**prior.input, "claimExpiresAt":
                                    (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}))
    catalog.null_volume = False
    options["job_repository"] = SqliteJobRepository(jobs.database_path)
    resumed = service.retire_pending_digitalocean_selector(parent.id, **options)
    assert resumed.status == "succeeded"
    assert len([event for event in resumed.events
                if event.message == "selector DELETE intended"]) == 1
    assert deleter.calls == 1


@pytest.mark.parametrize("published", [False, True])
def test_sqlite_intent_cas_rejects_stale_writer(tmp_path, monkeypatch, published):
    jobs, parent, catalog, deleter, options = _case(tmp_path, monkeypatch)
    catalog.null_volume = True
    with pytest.raises(service.SelectorRetirementAttention):
        service.retire_pending_digitalocean_selector(parent.id, **options)
    child_id = f"job-provider-keyed-selector-retirement-{'core-' + '2' * 32}"
    current = jobs.get(child_id)
    if published:
        current = jobs.save(replace(current, input={**current.input,
            "inspectorNegativeJobId": (
                f"job-provider-keyed-inspector-negative-{current.input['coreJobId'].removeprefix('job-')}"),
            "inspectorNegativeJournalSha256": "a" * 64,
        }))
    data = {"selectorTag": current.input["selectorTag"],
            "scopeSnapshotId": current.input["scopeSnapshotId"],
            "initialApplyJournalSha256": current.input["initialApplyJournalSha256"],
            "coreAbsenceJournalSha256": current.input["coreAbsenceJournalSha256"]}
    if published:
        data.update({"inspectorNegativeJobId": current.input["inspectorNegativeJobId"],
                     "inspectorNegativeJournalSha256": current.input[
                         "inspectorNegativeJournalSha256"]})
    event = JobEvent(3, "info", "selector DELETE intended", data)
    at = datetime.now(timezone.utc).isoformat()
    kwargs = dict(owner=current.input["claimOwner"], token=current.input["claimToken"],
                  expected_event_digest=job_event_digest(current.events), heartbeat_at=at,
                  expires_at=(datetime.fromisoformat(at) + timedelta(seconds=60)).isoformat(),
                  event=event)
    saved = jobs.append_selector_retirement_event_if_running_claimed(current, **kwargs)
    assert saved is not None and saved.events[-1] == event
    assert jobs.append_selector_retirement_event_if_running_claimed(current, **kwargs) is None
    assert SqliteJobRepository(jobs.database_path).get(child_id) == saved
    assert deleter.calls == 0


@pytest.mark.parametrize("problem", ["null_volume", "firewall_reference"])
def test_incomplete_visibility_fails_before_delete(tmp_path, monkeypatch, problem):
    jobs, parent, catalog, deleter, options = _case(tmp_path, monkeypatch)
    setattr(catalog, problem, True)
    with pytest.raises(service.SelectorRetirementAttention):
        service.retire_pending_digitalocean_selector(parent.id, **options)
    assert deleter.calls == 0
    children = [job for job in jobs.list_for_engagement(parent.target_id) if job.action == service.ACTION]
    assert len(children) == 1 and len(children[0].events) == 2
