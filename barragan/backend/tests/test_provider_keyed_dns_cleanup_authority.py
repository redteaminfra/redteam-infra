# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only DNS authority binds saved teardown and bootstrap journals."""

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_dns_cleanup_authority as authority
from app.services.provider_keyed_host_binding import _digest_json
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import EngagementModel
from test_provider_keyed_dns_cleanup_binding import _fixture


class Jobs:
    def __init__(self, rows):
        self.rows = {row.id: row for row in rows}

    def get(self, job_id):
        return self.rows.get(job_id)


class Domains:
    def __init__(self, engagement_id):
        self.asset = SimpleNamespace(registrar="namecheap")
        self.assignment = SimpleNamespace(id=7, status="active", engagement_id=engagement_id)

    def get_asset(self, _domain_id):
        return self.asset

    def list_assignments(self, *, domain_id):
        return [self.assignment]


def _case(monkeypatch):
    scope, manifest = _fixture()
    scope["coreJobId"] = "job-core"
    scope_hash = _digest_json({"providerScopes": [scope]})
    snapshot = {"snapshotId": "s" * 64, "providerScopeSha256": scope_hash,
                "providerScopes": [scope]}
    parent = SimpleNamespace(id="parent", target_id="eng-1", input={"scopeSnapshot": snapshot},
                             events=[JobEvent(1, "info", "queued", {})])
    core = SimpleNamespace(id="job-core")
    initial_id = authority._job_ids(core.id)[0]
    initial = SimpleNamespace(id=initial_id, target_id="eng-1", events=[
        JobEvent(1, "info", "provider host identity binding intended", manifest),
        JobEvent(2, "info", "provider host identity bound", {
            "manifestSha256": _digest_json(manifest), "hostProofPending": True}),
    ])
    group = SimpleNamespace(id=authority._child_id(core.id), target_id="eng-1",
                            events=[JobEvent(1, "info", "keyed_provider_group_retired", {})])
    jobs = Jobs([parent, initial, group])
    domains = Domains("eng-1")
    bound = SimpleNamespace(parent=parent, core=core)
    calls = []

    def read(_id, **_kwargs):
        calls.append("read")
        return bound

    def recognize(_id, **_kwargs):
        calls.append("recognize")
        return ()

    monkeypatch.setattr(authority, "_read_success_boundary", read)
    monkeypatch.setattr(authority, "recognize_provider_keyed_group_retired", recognize)
    options = dict(environment="devtest", state_root=Path("/unused"),
                   job_repository=jobs, plan_repository=object(), sketch_repository=object(),
                   credential_repository=object(), provider_resource_repository=object(),
                   domain_repository=domains, lease_lookup=lambda _id: None)
    return jobs, domains, calls, options


def test_loader_binds_persisted_events_and_rereads(monkeypatch):
    jobs, _domains, calls, options = _case(monkeypatch)
    result = authority.load_keyed_dns_cleanup_authority("parent", "domain", **options)
    assert result.edge_public_ips == ("1.1.1.1", "8.8.8.8")
    assert result.assignment_id == 7
    assert result.initial_job_id in jobs.rows
    assert calls == ["read", "recognize", "read", "recognize"]
    with pytest.raises(FrozenInstanceError):
        result.assignment_id = 8


@pytest.mark.parametrize("missing", ["provider host identity binding intended",
                                    "provider host identity bound"])
def test_missing_persisted_host_event_fails_closed(monkeypatch, missing):
    jobs, _domains, _calls, options = _case(monkeypatch)
    initial = jobs.get(authority._job_ids("job-core")[0])
    initial.events[:] = [row for row in initial.events if row.message != missing]
    with pytest.raises(authority.ProviderKeyedDnsCleanupAuthorityError):
        authority.load_keyed_dns_cleanup_authority("parent", "domain", **options)


def test_forged_or_changed_persisted_journal_fails_closed(monkeypatch):
    jobs, _domains, _calls, options = _case(monkeypatch)
    initial = jobs.get(authority._job_ids("job-core")[0])
    initial.events[1] = JobEvent(2, "info", "provider host identity bound", {
        "manifestSha256": "0" * 64, "hostProofPending": True})
    with pytest.raises(authority.ProviderKeyedDnsCleanupAuthorityError):
        authority.load_keyed_dns_cleanup_authority("parent", "domain", **options)


def test_assignment_or_authority_drift_between_reads_fails(monkeypatch):
    _jobs, domains, _calls, options = _case(monkeypatch)
    original = domains.list_assignments
    reads = 0

    def drift(*, domain_id):
        nonlocal reads
        rows = original(domain_id=domain_id)
        reads += 1
        if reads == 1:
            domains.assignment = SimpleNamespace(id=8, status="active", engagement_id="eng-1")
        return rows

    domains.list_assignments = drift
    with pytest.raises(authority.ProviderKeyedDnsCleanupAuthorityError):
        authority.load_keyed_dns_cleanup_authority("parent", "domain", **options)


def test_loader_reads_saved_sqlite_journals_not_supplied_events(client, monkeypatch):
    jobs, _domains, _calls, options = _case(monkeypatch)
    now = datetime.now(timezone.utc).isoformat()
    with client.application.storage_context():
        db.session.add(EngagementModel(id="eng-1", name="opaque", status="deployed",
            owner="operator", template_id="small-dev", active_revision="rev-1",
            input_parameters={}, sketch_state_schema="provider-keyed-v2"))
        db.session.commit()
        saved = SqlAlchemyJobRepository()
        rows = [*jobs.rows.values(), SimpleNamespace(id="job-core", input={}, events=[
            JobEvent(1, "info", "core applied", {})])]
        for row in rows:
            saved.save(StoredJobRun(
                id=row.id, action="persisted-proof", status="running",
                target="engagement:eng-1", target_type="engagement", target_id="eng-1",
                requested_by="operator", input=getattr(row, "input", {}),
                artifact_refs=[], created_at=now, started_at=now, finished_at=None,
                events=row.events,
            ))
        options["job_repository"] = saved
        # The strict boundary and retirement readers have dedicated persisted
        # repository suites; this test covers the loader's saved-job lookup.
        monkeypatch.setattr(authority, "_read_success_boundary", lambda *_a, **_kw:
            SimpleNamespace(parent=saved.get("parent"), core=saved.get("job-core")))
        result = authority.load_keyed_dns_cleanup_authority("parent", "domain", **options)
        assert result.initial_journal_sha256
        assert result.group_journal_sha256
        original_get = saved.get
        group_id = authority._child_id("job-core")
        mutated = False

        def change_after_first_group_read(job_id):
            nonlocal mutated
            row = original_get(job_id)
            if job_id == group_id and not mutated:
                mutated = True
                saved.save(replace(row, events=[*row.events,
                    JobEvent(2, "info", "unexpected later event", {})]))
            return row

        saved.get = change_after_first_group_read
        with pytest.raises(authority.ProviderKeyedDnsCleanupAuthorityError):
            authority.load_keyed_dns_cleanup_authority("parent", "domain", **options)
        saved.get = original_get
        group = saved.get(group_id)
        saved.save(replace(group, events=group.events[:-1]))
        initial_id = authority._job_ids("job-core")[0]
        stored = saved.get(initial_id)
        saved.save(StoredJobRun(**{**vars(stored), "events": stored.events[:-1]}))
        with pytest.raises(authority.ProviderKeyedDnsCleanupAuthorityError):
            authority.load_keyed_dns_cleanup_authority("parent", "domain", **options)
