# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import urllib.parse
import threading
import json
import sqlite3
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app import create_app
from app.core.config import TestConfig
from app.integrations.namecheap import NamecheapDnsClient, NamecheapError, NamecheapHost, NamecheapMutationBlockedError, NamecheapReadOnlyClient
from app.services.credentials import CredentialValidationError, resolve_credential_secret, test_master_key as credential_test_master_key
from app.services.engagement_dns import (
    _eligible_edge_targets, preview_owned_dns_cleanup, recover_engagement_dns_apply,
    recover_interrupted_engagement_dns_applies, reserve_private_keyed_owned_dns_cleanup,
    recover_interrupted_keyed_owned_dns_cleanups,
    run_private_keyed_owned_dns_cleanup, recover_private_keyed_owned_dns_cleanup,
    set_dns01_challenge,
    start_engagement_dns_apply,
)
from app.storage.database import db
from app.storage.domain_repository import SqlAlchemyDomainRepository, StoredDomainDnsSnapshot
from app.storage.domain_repository import DomainAssignmentFenceError
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import EngagementModel
from app.services.domains import assign_domain, release_domain, confirmation_token, DomainValidationError


def _assignment_fence_parent(engagement_id, *, keyed=True, status="queued", append=False):
    if append:
        from app.storage.models import CoreMutationLeaseModel
        db.session.add(CoreMutationLeaseModel(engagement_id=engagement_id,
            owner_id="plan-core", operation="provider_keyed_mixed_append"))
        db.session.commit()
        return
    now = datetime.now(timezone.utc).isoformat()
    return SqlAlchemyJobRepository().save(StoredJobRun(
        id=f"job-assignment-fence-{engagement_id}",
        action="engagement_comprehensive_teardown", status=status,
        target=f"engagement:{engagement_id}", target_type="engagement",
        target_id=engagement_id, requested_by="operator",
        input={"scopeSnapshot": ({"providerScopes": [{"provider": "digitalocean"}]}
                                 if keyed else {"chains": []})},
        artifact_refs=[], created_at=now,
        started_at=now if status == "running" else None,
        finished_at=None, events=[JobEvent(1, "info", "engagement teardown queued", {})],
    ))


def _second_domain_engagement():
    db.session.add(EngagementModel(id="eng-second", name="Second", status="deployed",
        owner="operator", template_id="small-dev", active_revision="rev-1",
        input_parameters={}, sketch_state_schema="provider-keyed-v2"))
    db.session.commit()


@pytest.mark.parametrize("append", [False, True])
@pytest.mark.parametrize("status", ["queued", "running"])
def test_keyed_parent_fences_new_assignment_and_direct_repository_bypass(
        domain_client, monkeypatch, status, append):
    app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client",
                        lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]
    with app.storage_context():
        repo = SqlAlchemyDomainRepository()
        _assignment_fence_parent("eng-of02-dev", status=status, append=append)
        with pytest.raises(DomainValidationError):
            assign_domain(domain_id, {"engagementId": "eng-of02-dev"})
        now = datetime.now(timezone.utc).isoformat()
        from app.storage.domain_repository import StoredDomainAssignment
        with pytest.raises(DomainAssignmentFenceError):
            repo.save_assignment(StoredDomainAssignment(None, domain_id,
                "eng-of02-dev", "Example", "rti", "active", "", "operator", "",
                now, None))
        assert repo.list_assignments(domain_id=domain_id) == []
    response = client.post(f"/api/domains/{domain_id}/assign",
                           json={"engagementId": "eng-of02-dev"})
    assert response.status_code == 400
    if append:
        assert "unavailable during paired edge append" in str(response.get_json()["errors"])


@pytest.mark.parametrize("append", [False, True])
@pytest.mark.parametrize("fenced_side", ["old", "new"])
def test_keyed_parent_fences_transfer_without_releasing_old_assignment(
        domain_client, monkeypatch, fenced_side, append):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    with app.storage_context():
        _second_domain_engagement()
        repo = SqlAlchemyDomainRepository()
        asset = repo.get_asset(domain_id)
        old = repo.list_assignments(domain_id=domain_id)[0]
        _assignment_fence_parent("eng-of02-dev" if fenced_side == "old" else "eng-second", append=append)
        with pytest.raises(DomainValidationError):
            assign_domain(domain_id, {"engagementId": "eng-second",
                "confirmationToken": confirmation_token(asset.domain_name)})
        rows = repo.list_assignments(domain_id=domain_id)
        assert len(rows) == 1 and rows[0] == old and rows[0].status == "active"


@pytest.mark.parametrize("append", [False, True])
def test_keyed_parent_fences_release_and_direct_repository_release(
        domain_client, monkeypatch, append):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    with app.storage_context():
        repo = SqlAlchemyDomainRepository()
        old = repo.list_assignments(domain_id=domain_id)[0]
        asset_updated_at = repo.get_asset(domain_id).updated_at
        _assignment_fence_parent("eng-of02-dev", append=append)
        with pytest.raises(DomainValidationError):
            release_domain(domain_id, {})
        with pytest.raises(DomainAssignmentFenceError):
            repo.save_assignment(replace(old, status="released",
                released_at=datetime.now(timezone.utc).isoformat()))
        assert repo.list_assignments(domain_id=domain_id) == [old]
        assert repo.get_asset(domain_id).updated_at == asset_updated_at


def test_split_v1_parent_does_not_fence_assignment_changes(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    with app.storage_context():
        repo = SqlAlchemyDomainRepository()
        asset_updated_at = repo.get_asset(domain_id).updated_at
        _assignment_fence_parent("eng-of02-dev", keyed=False)
        released = release_domain(domain_id, {})
        assert released["releasedAssignments"][0]["status"] == "released"
        assigned = assign_domain(domain_id, {"engagementId": "eng-of02-dev"})
        assert assigned["assignment"]["status"] == "active"
        assert repo.get_asset(domain_id).updated_at == asset_updated_at


@pytest.mark.parametrize("append", [False, True])
def test_assignment_waits_for_other_connection_keyed_parent_writer(
        tmp_path, monkeypatch, append):
    database_path = tmp_path / "assignment-race.sqlite"

    class FileConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{database_path}"

    monkeypatch.setenv("BARRAGAN_DNS01_LOCK_DIR", str(tmp_path / "dns-locks"))
    app = create_app(FileConfig)
    client = app.test_client()
    domain_id = _assigned_domain_id(client, monkeypatch)
    with app.storage_context():
        old = SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id)[0]
        db.session.remove()
    writer = sqlite3.connect(database_path, timeout=10)
    writer.execute("BEGIN IMMEDIATE")
    if append:
        writer.execute("INSERT INTO core_mutation_leases (engagement_id, owner_id, operation, acquired_at) "
            "VALUES (?, ?, ?, ?)", ("eng-of02-dev", "plan-core", "provider_keyed_mixed_append",
                                     datetime.now(timezone.utc).isoformat()))
    else:
        writer.execute(
            "INSERT INTO job_runs (id, action, status, target, target_type, target_id, "
            "requested_by, input, artifact_refs, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("job-racing-keyed-parent", "engagement_comprehensive_teardown", "queued",
             "engagement:eng-of02-dev", "engagement", "eng-of02-dev", "operator",
             json.dumps({"scopeSnapshot": {"providerScopes": [{"provider": "digitalocean"}]}}),
             "[]", datetime.now(timezone.utc).isoformat()),
        )
    started, done = threading.Event(), threading.Event()
    outcomes = []

    def release_after_writer():
        with app.storage_context():
            started.set()
            try:
                SqlAlchemyDomainRepository().save_assignment(replace(
                    old, status="released", released_at=datetime.now(timezone.utc).isoformat()))
                outcomes.append("released")
            except DomainAssignmentFenceError:
                outcomes.append("fenced")
            finally:
                done.set()

    worker = threading.Thread(target=release_after_writer)
    worker.start()
    assert started.wait(2)
    time.sleep(0.1)
    assert not done.is_set()
    writer.commit()
    writer.close()
    worker.join(5)
    assert not worker.is_alive() and outcomes == ["fenced"]
    with app.storage_context():
        assert SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id) == [old]
        db.session.remove()
        db.engine.dispose()
from app.services.provider_keyed_dns_cleanup_authority import ProviderKeyedDnsCleanupAuthority


def _private_dns_authority(domain_id, assignment_id, *, edge_ips=("8.8.8.8",)):
    return ProviderKeyedDnsCleanupAuthority(
        engagement_id="eng-of02-dev", domain_id=domain_id,
        assignment_id=assignment_id, teardown_parent_id="job-parent",
        core_job_id="job-core", initial_job_id="job-initial", group_job_id="job-group",
        scope_snapshot_id="a" * 64, provider_scope_sha256="b" * 64,
        parent_journal_sha256="c" * 64, initial_journal_sha256="d" * 64,
        group_journal_sha256="e" * 64, binding_sha256="f" * 64,
        edge_public_ips=edge_ips,
    )


def test_private_keyed_dns_reservation_is_deterministic_and_read_only(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([FakeNamecheapHost("manual", "A", "1.1.1.1", ttl="600")])
    with app.storage_context():
        assignment = SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id)[0]
        proof = _private_dns_authority(domain_id, assignment.id)
        monkeypatch.setattr("app.services.engagement_dns.load_keyed_dns_cleanup_authority",
                            lambda *_a, **_kw: proof)
        preview = preview_owned_dns_cleanup("eng-of02-dev", domain_id,
                                            ["8.8.8.8"], adapter=adapter)
        first = reserve_private_keyed_owned_dns_cleanup(
            "job-parent", domain_id, reviewed_preview=preview,
            environment="devtest", state_root=tmp_path,
            adapter=adapter)
        second = reserve_private_keyed_owned_dns_cleanup(
            "job-parent", domain_id, reviewed_preview=preview,
            environment="devtest", state_root=tmp_path,
            adapter=adapter)
        assert first.id == second.id and second.status == "queued"
        assert second.input["mutation"] is False
        adapter.hosts[0] = FakeNamecheapHost("manual", "A", "9.9.9.9", ttl="600")
        changed = preview_owned_dns_cleanup("eng-of02-dev", domain_id,
                                            ["8.8.8.8"], adapter=adapter)
        with pytest.raises(Exception):
            reserve_private_keyed_owned_dns_cleanup(
                "job-parent", domain_id, reviewed_preview=changed,
                environment="devtest", state_root=tmp_path, adapter=adapter)
        assert adapter.set_calls == []
        assert SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id)[0].status == "active"


def test_private_keyed_dns_reservation_rejects_authority_or_zone_drift(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([FakeNamecheapHost("manual", "A", "1.1.1.1", ttl="600")])
    with app.storage_context():
        assignment = SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id)[0]
        proof = _private_dns_authority(domain_id, assignment.id)
        monkeypatch.setattr("app.services.engagement_dns.load_keyed_dns_cleanup_authority",
                            lambda *_a, **_kw: proof)
        preview = preview_owned_dns_cleanup("eng-of02-dev", domain_id,
                                            ["8.8.8.8"], adapter=adapter)
        adapter.hosts.append(FakeNamecheapHost("later", "TXT", "new", ttl="600"))
        with pytest.raises(Exception):
            reserve_private_keyed_owned_dns_cleanup(
                "job-parent", domain_id, reviewed_preview=preview,
                environment="devtest", state_root=tmp_path, adapter=adapter)
        adapter.hosts.pop()
        monkeypatch.setattr("app.services.engagement_dns.load_keyed_dns_cleanup_authority",
                            lambda *_a, **_kw: replace(proof, assignment_id=999))
        with pytest.raises(Exception):
            reserve_private_keyed_owned_dns_cleanup(
                "job-parent", domain_id, reviewed_preview=preview,
                environment="devtest", state_root=tmp_path, adapter=adapter)
        assert adapter.set_calls == []
        assert not [job for job in SqlAlchemyJobRepository().list_for_engagement(
            "eng-of02-dev") if job.action == "engagement_dns_owned_cleanup"]


def test_private_keyed_dns_reservation_accepts_numeric_sorted_multi_edge_authority(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([FakeNamecheapHost("manual", "A", "1.1.1.1", ttl="600")])
    with app.storage_context():
        assignment = SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id)[0]
        proof = _private_dns_authority(
            domain_id, assignment.id, edge_ips=("8.8.8.8", "11.11.11.11"))
        monkeypatch.setattr("app.services.engagement_dns.load_keyed_dns_cleanup_authority",
                            lambda *_a, **_kw: proof)
        preview = preview_owned_dns_cleanup("eng-of02-dev", domain_id,
                                            list(proof.edge_public_ips), adapter=adapter)
        assert preview["oldEdgeIps"] == ["11.11.11.11", "8.8.8.8"]
        reserved = reserve_private_keyed_owned_dns_cleanup(
            "job-parent", domain_id, reviewed_preview=preview,
            environment="devtest", state_root=tmp_path, adapter=adapter)
        assert reserved.status == "queued" and adapter.set_calls == []


def test_private_keyed_dns_reservation_records_owned_mutation_without_writing(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([FakeNamecheapHost("manual", "TXT", "manual", ttl="600")])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client",
                        lambda alias=None: adapter)
    desired = [
        {"name": "manual", "type": "TXT", "address": "manual", "ttl": "600"},
        {"name": "edge", "type": "A", "address": "8.8.8.8", "ttl": "600"},
    ]
    planned = client.post("/api/engagements/eng-of02-dev/dns/preview",
                          json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired,
        "currentFingerprint": planned["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "succeeded" and len(adapter.set_calls) == 1
    with app.storage_context():
        repo = SqlAlchemyDomainRepository()
        assignment = repo.list_assignments(domain_id=domain_id)[0]
        proof = _private_dns_authority(domain_id, assignment.id)
        monkeypatch.setattr("app.services.engagement_dns.load_keyed_dns_cleanup_authority",
                            lambda *_a, **_kw: proof)
        preview = preview_owned_dns_cleanup("eng-of02-dev", domain_id,
                                            ["8.8.8.8"], adapter=adapter)
        reserved = reserve_private_keyed_owned_dns_cleanup(
            "job-parent", domain_id, reviewed_preview=preview,
            environment="devtest", state_root=tmp_path, adapter=adapter)
        assert reserved.input["mutation"] is True
        assert len(reserved.input["previewPlan"]["ownedRecords"]) == 1
        assert len(repo.list_record_ownership(domain_id, active_only=True)) == 1
        assert len(adapter.set_calls) == 1


def _private_keyed_go_case(app, client, monkeypatch, *, owned):
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([FakeNamecheapHost("manual", "TXT", "manual", ttl="600")])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client",
                        lambda alias=None: adapter)
    if owned:
        desired = [
            {"name": "manual", "type": "TXT", "address": "manual", "ttl": "600"},
            {"name": "edge", "type": "A", "address": "8.8.8.8", "ttl": "600"},
        ]
        planned = client.post("/api/engagements/eng-of02-dev/dns/preview",
            json={"domainId": domain_id, "records": desired}).get_json()["preview"]
        applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
            "domainId": domain_id, "records": desired,
            "currentFingerprint": planned["currentFingerprint"],
        }).get_json()
        assert applied["job"]["status"] == "succeeded"
    with app.storage_context():
        assignment = SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id)[0]
        proof = _private_dns_authority(domain_id, assignment.id)
        monkeypatch.setattr("app.services.engagement_dns.load_keyed_dns_cleanup_authority",
                            lambda *_a, **_kw: proof)
        preview = preview_owned_dns_cleanup("eng-of02-dev", domain_id,
                                            ["8.8.8.8"], adapter=adapter)
    return domain_id, adapter, preview


@pytest.mark.parametrize("owned", [False, True])
def test_private_keyed_dns_go_completes_exact_cleanup_once(
        domain_client, monkeypatch, tmp_path, owned):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=owned)
    before_calls = len(adapter.set_calls)
    with app.storage_context():
        done = run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
            reviewed_preview=preview, environment="devtest", state_root=tmp_path,
            adapter=adapter)
        assert done.status == "succeeded"
        assert len(adapter.set_calls) == before_calls + int(owned)
        assert SqlAlchemyDomainRepository().list_record_ownership(
            domain_id, active_only=True) == []
        assert SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id)[0].status == "active"
        with pytest.raises(Exception):
            run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
                reviewed_preview=preview, environment="devtest", state_root=tmp_path,
                adapter=adapter)
        assert len(adapter.set_calls) == before_calls + int(owned)


def test_private_keyed_dns_go_ignores_transient_host_id(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    assert all("hostId" not in row["record"] for row in preview["ownedRecords"])
    adapter.hosts = [replace(row, host_id=f"new-host-{index}")
                     for index, row in enumerate(adapter.hosts)]
    with app.storage_context():
        done = run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
            reviewed_preview=preview, environment="devtest", state_root=tmp_path,
            adapter=adapter)
        assert done.status == "succeeded" and len(adapter.set_calls) == 2



def test_private_keyed_dns_go_blocks_content_drift_with_stable_host_id(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    adapter.hosts = [replace(row, address="9.9.9.9") if row.name == "edge" else row
                     for row in adapter.hosts]
    with app.storage_context():
        with pytest.raises(Exception):
            run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
                reviewed_preview=preview, environment="devtest", state_root=tmp_path,
                adapter=adapter)
        assert len(adapter.set_calls) == 1
        assert len(SqlAlchemyDomainRepository().list_record_ownership(
            domain_id, active_only=True)) == 1


def test_private_keyed_dns_go_accepted_crash_recovers_get_only(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    from app.services import engagement_dns
    original = engagement_dns._publish_private_keyed_owned_dns_cleanup
    calls = 0

    def crash_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated process interruption")
        return original(*args, **kwargs)

    monkeypatch.setattr(engagement_dns, "_publish_private_keyed_owned_dns_cleanup", crash_once)
    with app.storage_context():
        with pytest.raises(Exception):
            run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
                reviewed_preview=preview, environment="devtest", state_root=tmp_path,
                adapter=adapter)
        job = next(row for row in SqlAlchemyJobRepository().list_for_engagement(
            "eng-of02-dev") if row.action == "engagement_dns_owned_cleanup")
        assert job.status == "running"
        assert job.events[-1].message == "owned DNS setHosts accepted"
        done = recover_private_keyed_owned_dns_cleanup(job.id, environment="devtest",
            state_root=tmp_path, adapter=adapter)
        assert done.status == "succeeded" and len(adapter.set_calls) == 2


def test_private_keyed_dns_go_uncertain_intent_never_replays(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    monkeypatch.setattr("app.services.engagement_dns.DNS_READBACK_DELAY_SECONDS", 0)

    def uncertain(_domain, _hosts):
        adapter.set_calls.append([])
        raise NamecheapError("uncertain")

    adapter.set_hosts = uncertain
    with app.storage_context():
        pending = run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
            reviewed_preview=preview, environment="devtest", state_root=tmp_path,
            adapter=adapter)
        assert pending.status == "running"
        uncertain_job = recover_private_keyed_owned_dns_cleanup(pending.id,
            environment="devtest", state_root=tmp_path, adapter=adapter)
        assert uncertain_job.status == "running" and len(adapter.set_calls) == 2
        assert not any(event.message == "owned DNS setHosts accepted"
                       for event in uncertain_job.events)
        assert len(SqlAlchemyDomainRepository().list_record_ownership(
            domain_id, active_only=True)) == 1


def test_private_keyed_dns_go_accepted_before_crash_recovers_from_get_only(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    original = adapter.set_hosts

    def accept_then_crash(domain, hosts):
        original(domain, hosts)
        raise KeyboardInterrupt("process interrupted after provider acceptance")

    adapter.set_hosts = accept_then_crash
    with app.storage_context():
        with pytest.raises(KeyboardInterrupt):
            run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
                reviewed_preview=preview, environment="devtest", state_root=tmp_path,
                adapter=adapter)
        pending = next(row for row in SqlAlchemyJobRepository().list_for_engagement(
            "eng-of02-dev") if row.action == "engagement_dns_owned_cleanup")
        assert pending.status == "running" and len(pending.events) == 2
        recovered = recover_private_keyed_owned_dns_cleanup(pending.id,
            environment="devtest", state_root=tmp_path, adapter=adapter)
        assert recovered.status == "succeeded"
        assert any(event.message == "owned DNS setHosts accepted" and
                   event.data.get("recoveredByProviderReadback") is True
                   for event in recovered.events)
        assert len(adapter.set_calls) == 2
        assert SqlAlchemyDomainRepository().list_record_ownership(
            domain_id, active_only=True) == []


def test_private_keyed_dns_go_provider_error_after_acceptance_get_recovers_immediately(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    original = adapter.set_hosts

    def accept_then_error(domain, hosts):
        original(domain, hosts)
        raise NamecheapError("response lost after acceptance")

    adapter.set_hosts = accept_then_error
    with app.storage_context():
        done = run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
            reviewed_preview=preview, environment="devtest", state_root=tmp_path,
            adapter=adapter)
        assert done.status == "succeeded" and len(adapter.set_calls) == 2
        assert any(row.message == "owned DNS setHosts accepted" and
                   row.data.get("recoveredByProviderReadback") is True
                   for row in done.events)


def test_private_keyed_dns_go_authority_drift_after_acceptance_keeps_receipts(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    from app.services import engagement_dns
    original = engagement_dns._publish_private_keyed_owned_dns_cleanup
    with app.storage_context():
        assignment = SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id)[0]
        proof = _private_dns_authority(domain_id, assignment.id)

        def drift_after_acceptance(*args, **kwargs):
            monkeypatch.setattr(engagement_dns, "load_keyed_dns_cleanup_authority",
                lambda *_a, **_kw: replace(proof, binding_sha256="0" * 64))
            return original(*args, **kwargs)

        monkeypatch.setattr(engagement_dns, "_publish_private_keyed_owned_dns_cleanup",
                            drift_after_acceptance)
        with pytest.raises(Exception):
            run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
                reviewed_preview=preview, environment="devtest", state_root=tmp_path,
                adapter=adapter)
        pending = next(row for row in SqlAlchemyJobRepository().list_for_engagement(
            "eng-of02-dev") if row.action == "engagement_dns_owned_cleanup")
        assert pending.status == "running"
        assert pending.events[-1].message == "owned DNS setHosts accepted"
        assert len(SqlAlchemyDomainRepository().list_record_ownership(
            domain_id, active_only=True)) == 1
        assert len(adapter.set_calls) == 2


def test_private_keyed_dns_go_authority_drift_inside_writer_rolls_back(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    original = SqlAlchemyDomainRepository.complete_keyed_owned_dns_cleanup

    def drift_in_writer(self, **kwargs):
        read_authority = kwargs["authority"]

        def drift():
            return {**read_authority(), "binding_sha256": "0" * 64}

        return original(self, **{**kwargs, "authority": drift})

    monkeypatch.setattr(SqlAlchemyDomainRepository,
                        "complete_keyed_owned_dns_cleanup", drift_in_writer)
    with app.storage_context():
        with pytest.raises(Exception):
            run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
                reviewed_preview=preview, environment="devtest", state_root=tmp_path,
                adapter=adapter)
        pending = next(row for row in SqlAlchemyJobRepository().list_for_engagement(
            "eng-of02-dev") if row.action == "engagement_dns_owned_cleanup")
        assert pending.status == "running"
        assert pending.events[-1].message == "owned DNS setHosts accepted"
        assert len(SqlAlchemyDomainRepository().list_record_ownership(
            domain_id, active_only=True)) == 1
        assert len(adapter.set_calls) == 2


def test_private_keyed_dns_go_accepted_but_stale_readback_never_replays(
        domain_client, monkeypatch, tmp_path):
    app, client = domain_client
    domain_id, adapter, preview = _private_keyed_go_case(app, client, monkeypatch,
                                                           owned=True)
    monkeypatch.setattr("app.services.engagement_dns.DNS_READBACK_DELAY_SECONDS", 0)

    def accepted_without_change(_domain, _hosts):
        adapter.set_calls.append([])
        return True

    adapter.set_hosts = accepted_without_change
    with app.storage_context():
        pending = run_private_keyed_owned_dns_cleanup("job-parent", domain_id,
            reviewed_preview=preview, environment="devtest", state_root=tmp_path,
            adapter=adapter)
        assert pending.status == "running"
        assert len(adapter.set_calls) == 2
        assert len(SqlAlchemyDomainRepository().list_record_ownership(
            domain_id, active_only=True)) == 1
        reread = recover_private_keyed_owned_dns_cleanup(pending.id,
            environment="devtest", state_root=tmp_path, adapter=adapter)
        assert reread.status == "running" and len(adapter.set_calls) == 2
        for _ in range(2):
            reread = recover_private_keyed_owned_dns_cleanup(pending.id,
                environment="devtest", state_root=tmp_path, adapter=adapter)
        assert sum(row.message == "owned DNS readback pending" for row in reread.events) == 12
        adapter.hosts = [FakeNamecheapHost("manual", "TXT", "manual", ttl="600")]
        from app.services import engagement_dns, sketch_state_workspaces
        monkeypatch.setattr(sketch_state_workspaces, "_default_state_root", lambda: tmp_path)
        monkeypatch.setattr(engagement_dns, "DNS_KEYED_CLEANUP_STARTUP_GRACE_SECONDS", 0)
        tasks = []
        assert recover_interrupted_keyed_owned_dns_cleanups(
            environment="devtest", state_root=tmp_path, schedule=tasks.append,
            job_repository=SqlAlchemyJobRepository()) == 1
        tasks[0]()
        late = SqlAlchemyJobRepository().get(pending.id)
        assert late.status == "succeeded" and len(adapter.set_calls) == 2


def test_private_keyed_dns_startup_selects_running_intent_and_waits_before_get(
        monkeypatch, tmp_path):
    from app.services import engagement_dns
    from app.services import sketch_state_workspaces
    monkeypatch.setattr(sketch_state_workspaces, "_default_state_root", lambda: tmp_path)
    now = datetime.now(timezone.utc).isoformat()
    intent = JobEvent(2, "info", "owned DNS setHosts intended", {})
    accepted = JobEvent(3, "info", "owned DNS setHosts accepted", {})
    pending = JobEvent(4, "info", "owned DNS readback pending", {"attempt": 1})
    rows = [
        SimpleNamespace(id="eligible", action="engagement_dns_owned_cleanup",
            status="running", input={"teardownParentId": "parent", "domainId": "domain"},
            events=[intent, accepted], created_at=now, started_at=now),
        SimpleNamespace(id="exhausted", action="engagement_dns_owned_cleanup",
            status="running", input={"teardownParentId": "parent", "domainId": "domain"},
            events=[intent, accepted, *[pending] * 12], created_at=now, started_at=now),
        SimpleNamespace(id="queued", action="engagement_dns_owned_cleanup",
            status="queued", input={"teardownParentId": "parent", "domainId": "domain"},
            events=[], created_at=now, started_at=None),
    ]

    class Jobs:
        def list(self):
            return rows

        def get(self, job_id):
            return next((row for row in rows if row.id == job_id), None)

    tasks = []
    waits = []
    recovered = []
    monkeypatch.setattr(engagement_dns.time, "sleep", waits.append)
    monkeypatch.setattr(engagement_dns, "recover_private_keyed_owned_dns_cleanup",
        lambda job_id, **kwargs: recovered.append((job_id, kwargs["state_root"])))
    assert recover_interrupted_keyed_owned_dns_cleanups(
        environment="prod", state_root=tmp_path, schedule=tasks.append,
        job_repository=Jobs()) == 0
    assert recover_interrupted_keyed_owned_dns_cleanups(
        environment="devtest", state_root=tmp_path, schedule=tasks.append,
        job_repository=Jobs()) == 2
    assert len(tasks) == 1 and recovered == []
    tasks[0]()
    assert len(waits) == 2 and all(0 < wait <= 60 for wait in waits)
    assert recovered == [("eligible", tmp_path), ("exhausted", tmp_path)]


def test_private_keyed_dns_startup_rechecks_status_after_schedule(monkeypatch, tmp_path):
    from app.services import engagement_dns, sketch_state_workspaces
    monkeypatch.setattr(sketch_state_workspaces, "_default_state_root", lambda: tmp_path)
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    row = SimpleNamespace(id="eligible", action="engagement_dns_owned_cleanup",
        status="running", input={"teardownParentId": "parent", "domainId": "domain"},
        events=[JobEvent(2, "info", "owned DNS setHosts intended", {})],
        created_at=old, started_at=old)

    class Jobs:
        def list(self):
            return [row]

        def get(self, _job_id):
            return row

    tasks = []
    recovered = []
    monkeypatch.setattr(engagement_dns, "recover_private_keyed_owned_dns_cleanup",
                        lambda *args, **kwargs: recovered.append(args))
    assert recover_interrupted_keyed_owned_dns_cleanups(
        environment="devtest", state_root=tmp_path, schedule=tasks.append,
        job_repository=Jobs()) == 1
    row.status = "succeeded"
    tasks[0]()
    assert recovered == []


@pytest.fixture()
def domain_client(monkeypatch, tmp_path):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())
    monkeypatch.setenv("BARRAGAN_DNS01_LOCK_DIR", str(tmp_path / "dns-locks"))
    app = create_app(TestConfig)
    yield app, app.test_client()
    with app.storage_context():
        db.session.remove()
        db.engine.dispose()


@dataclass(frozen=True)
class FakeNamecheapDomain:
    name: str
    created: str = "2026-01-01"
    expires: str = "2027-01-01"
    auto_renew: bool = True
    status: str = "active"
    metadata: dict | None = None


@dataclass(frozen=True)
class FakeNamecheapHost:
    name: str
    record_type: str
    address: str
    ttl: str = "1800"
    mx_pref: str = ""
    host_id: str = ""


class FakeNamecheapAdapter:
    def get_domains(self):
        return [
            FakeNamecheapDomain("Example.COM", metadata={"source": "fake"}),
            FakeNamecheapDomain("xn--bcher-kva.example", metadata={"source": "fake"}),
        ]

    def get_hosts(self, domain_name: str):
        return [FakeNamecheapHost("@", "A", "203.0.113.10", host_id="12"), FakeNamecheapHost("www", "CNAME", domain_name)]


class ExternalDnsNamecheapAdapter:
    def __init__(self):
        self.host_calls: list[str] = []

    def get_domains(self):
        return [FakeNamecheapDomain("External-DNS.example", metadata={"isOurDNS": False})]

    def get_hosts(self, domain_name: str):
        self.host_calls.append(domain_name)
        raise AssertionError("external DNS domains should not fetch Namecheap hosts")


class PerDomainHostFailureNamecheapAdapter:
    def get_domains(self):
        return [
            FakeNamecheapDomain("Healthy.example", metadata={"isOurDNS": True}),
            FakeNamecheapDomain("External.example", metadata={"isOurDNS": True}),
        ]

    def get_hosts(self, domain_name: str):
        if domain_name == "external.example":
            raise NamecheapError("Namecheap request failed for ApiKey=super-secret-api-key")
        return [FakeNamecheapHost("@", "A", "203.0.113.20", host_id="healthy-host")]


class FakeNamecheapTransport:
    def __init__(self, responses: list[str]):
        self.responses = responses
        self.urls: list[str] = []
        self.posts: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, timeout: int) -> str:
        self.urls.append(url)
        return self._next_response()

    def post(self, url: str, data: dict[str, str], timeout: int) -> str:
        self.posts.append((url, data))
        return self._next_response()

    def _next_response(self) -> str:
        index = len(self.urls) + len(self.posts) - 1
        return self.responses[index]


class FakeDnsAdapter:
    def __init__(self, hosts: list[FakeNamecheapHost]):
        self.hosts = list(hosts)
        self.set_calls: list[list[dict[str, str]]] = []

    def get_hosts(self, domain_name: str):
        return list(self.hosts)

    def set_hosts(self, domain_name: str, hosts: list[NamecheapHost]) -> bool:
        self.set_calls.append([host.to_dict() for host in hosts])
        self.hosts = [
            FakeNamecheapHost(
                name=host.name,
                record_type=host.record_type,
                address=host.address,
                ttl=host.ttl,
                mx_pref=host.mx_pref,
            )
            for host in hosts
        ]
        return True


class FailingDnsAdapter(FakeDnsAdapter):
    def get_hosts(self, domain_name: str):
        raise NamecheapError("Namecheap request failed for ApiKey=super-secret-api-key")


def _query(url: str) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def _get_list_response(domain_nodes: str, *, current_page: int, total_items: int, page_size: int = 100) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="OK">
  <Errors />
  <CommandResponse Type="namecheap.domains.getList">
    <DomainGetListResult>{domain_nodes}</DomainGetListResult>
    <Paging>
      <TotalItems>{total_items}</TotalItems>
      <CurrentPage>{current_page}</CurrentPage>
      <PageSize>{page_size}</PageSize>
    </Paging>
  </CommandResponse>
</ApiResponse>"""


def _domain_node(index: int, *, is_our_dns: str = "false") -> str:
    return (
        f'<Domain ID="{index}" Name="domain{index}.com" User="owner" Created="02/15/2026" '
        f'Expires="02/15/2027" IsExpired="false" IsLocked="false" AutoRenew="true" '
        f'WhoisGuard="ENABLED" IsPremium="false" IsOurDNS="{is_our_dns}" />'
    )


def _set_hosts_response(domain_name: str = "example.com", success: str = "true") -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="OK">
  <Errors />
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="{domain_name}" IsSuccess="{success}" />
  </CommandResponse>
</ApiResponse>"""


def _assigned_domain_id(client, monkeypatch) -> str:
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]
    response = client.post(f"/api/domains/{domain_id}/assign", json={"engagementId": "eng-of02-dev", "purposeTags": ["rti"]})
    assert response.status_code == 200
    return domain_id


def test_namecheap_credential_shape_is_supported_and_redacted(domain_client):
    app, client = domain_client

    response = client.post(
        "/api/credentials",
        json={"provider": "namecheap", "alias": "namecheap-default", "secret": "api-user:super-secret-api-key", "isDefault": True},
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["credential"]["provider"] == "namecheap"
    assert body["credential"]["isDefault"] is True
    assert "super-secret-api-key" not in str(body)
    assert "secret" not in body["credential"]

    with app.storage_context():
        assert resolve_credential_secret("namecheap", "namecheap-default") == "api-user:super-secret-api-key"


def test_namecheap_sync_caches_domains_hosts_and_redacts_job_input(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())

    response = client.post("/api/domains/sync/namecheap", json={"credentialAlias": "namecheap-default", "includeHosts": True})
    body = response.get_json()

    assert response.status_code == 201
    assert body["domainsSynced"] == 2
    assert body["hostSnapshots"] == 2
    assert body["job"]["action"] == "namecheap_domain_sync"
    assert body["job"]["status"] == "succeeded"
    assert "api-key" not in str(body).lower()
    assert "namecheap.domains.dns.setHosts" not in str(body)

    grouped = client.get("/api/domains").get_json()["domains"]
    waiting = grouped["waiting_to_be_used"]
    assert [domain["domainName"] for domain in waiting] == ["example.com", "xn--bcher-kva.example"]
    assert waiting[0]["dnsSummary"]["recordCount"] == 2
    assert waiting[0]["dnsSummary"]["recordsPreview"][0] == {
        "name": "@",
        "type": "A",
        "address": "203.0.113.10",
        "ttl": "1800",
    }
    assert waiting[0]["dnsSummary"]["source"] == "provider_snapshot"

    domain_id = waiting[0]["id"]
    detail = client.get(f"/api/domains/{domain_id}").get_json()["domain"]
    assert detail["domainName"] == "example.com"
    assert detail["catalogState"] == "auto"
    assert detail["assignments"] == []

    hosts = client.get(f"/api/domains/{domain_id}/hosts").get_json()["hosts"]
    assert hosts["readOnly"] is True
    assert hosts["source"] == "provider_snapshot"
    assert hosts["hosts"][0]["type"] == "A"
    assert hosts["hosts"][0]["hostId"] == "12"


def test_domain_catalog_state_moves_inactive_domain_between_inventory_buckets(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]

    historical_response = client.patch(
        f"/api/domains/{domain_id}/catalog-state",
        json={"catalogState": "used_in_past_engagements"},
    )

    assert historical_response.status_code == 200
    assert historical_response.get_json()["domain"]["catalogState"] == "used_in_past_engagements"
    grouped = client.get("/api/domains").get_json()["domains"]
    assert [domain["id"] for domain in grouped["used_in_past_engagements"]] == [domain_id]
    assert domain_id not in [domain["id"] for domain in grouped["waiting_to_be_used"]]

    waiting_response = client.patch(
        f"/api/domains/{domain_id}/catalog-state",
        json={"catalogState": "waiting_to_be_used"},
    )

    assert waiting_response.status_code == 200
    grouped = client.get("/api/domains").get_json()["domains"]
    assert domain_id in [domain["id"] for domain in grouped["waiting_to_be_used"]]


def test_domain_catalog_state_rejects_invalid_value(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]

    response = client.patch(f"/api/domains/{domain_id}/catalog-state", json={"catalogState": "archive-later"})

    assert response.status_code == 400
    assert response.get_json()["errors"] == [
        "catalogState must be auto, currently_being_used, waiting_to_be_used, or used_in_past_engagements"
    ]


def test_domain_catalog_state_cannot_hide_active_assignment(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]
    client.post(f"/api/domains/{domain_id}/assign", json={"engagementId": "eng-of02-dev", "purposeTags": ["rti"]})

    response = client.patch(f"/api/domains/{domain_id}/catalog-state", json={"catalogState": "waiting_to_be_used"})

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["catalogState cannot hide active use: active assignment"]


def test_domain_catalog_state_cannot_hide_active_barragan_dns(domain_client, monkeypatch):
    app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]
    timestamp = "2026-06-17T00:00:00+00:00"

    with app.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-dns-active",
                action="engagement_dns_apply",
                status="succeeded",
                target="engagement:eng-of02-dev",
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator",
                input={},
                artifact_refs=[],
                created_at=timestamp,
                started_at=timestamp,
                finished_at=timestamp,
                events=[JobEvent(1, "info", "DNS applied", {})],
            )
        )
        SqlAlchemyDomainRepository().save_snapshot(
            StoredDomainDnsSnapshot(
                id=None,
                domain_id=domain_id,
                provider="namecheap",
                hosts=[{"name": "@", "type": "A", "address": "198.51.100.10", "ttl": "600"}],
                source="provider_snapshot",
                sync_job_id="job-dns-active",
                fetched_at=timestamp,
            )
        )

    grouped = client.get("/api/domains").get_json()["domains"]
    assert [domain["id"] for domain in grouped["currently_being_used"]] == [domain_id]

    response = client.patch(f"/api/domains/{domain_id}/catalog-state", json={"catalogState": "used_in_past_engagements"})

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["catalogState cannot hide active use: active Barragan-managed DNS"]


def test_namecheap_sync_skips_get_hosts_for_external_dns_domains(domain_client, monkeypatch):
    _app, client = domain_client
    adapter = ExternalDnsNamecheapAdapter()
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: adapter)

    response = client.post("/api/domains/sync/namecheap", json={"includeHosts": True})
    body = response.get_json()

    assert response.status_code == 201
    assert body["domainsSynced"] == 1
    assert body["hostSnapshots"] == 1
    assert body["job"]["status"] == "succeeded"
    assert adapter.host_calls == []

    domain = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]
    hosts = client.get(f"/api/domains/{domain['id']}/hosts").get_json()["hosts"]
    assert hosts["readOnly"] is True
    assert hosts["source"] == "external_dns_provider"
    assert hosts["hosts"] == []


def test_namecheap_sync_records_get_hosts_failure_without_failing_sync(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: PerDomainHostFailureNamecheapAdapter())

    response = client.post("/api/domains/sync/namecheap", json={"includeHosts": True})
    body = response.get_json()

    assert response.status_code == 201
    assert body["job"]["status"] == "succeeded"
    assert body["domainsSynced"] == 2
    assert body["hostSnapshots"] == 2
    assert "super-secret-api-key" not in str(body)
    assert "ApiKey" not in str(body)
    domains = {
        domain["domainName"]: domain["id"]
        for domain in client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"]
    }
    warning_events = [event for event in body["job"]["events"] if event["level"] == "warning"]
    assert warning_events == [
        {
            "sequence": 2,
            "level": "warning",
            "message": "Namecheap DNS host snapshot warnings recorded",
            "data": {
                "warningCount": 1,
                "warnings": [
                    {
                        "domainId": domains["external.example"],
                        "source": "provider_snapshot_error",
                        "reason": "namecheap_get_hosts_unavailable",
                    }
                ],
            },
        }
    ]

    failed_hosts = client.get(f"/api/domains/{domains['external.example']}/hosts").get_json()["hosts"]
    healthy_hosts = client.get(f"/api/domains/{domains['healthy.example']}/hosts").get_json()["hosts"]
    assert failed_hosts["source"] == "provider_snapshot_error"
    assert failed_hosts["hosts"] == []
    assert healthy_hosts["source"] == "provider_snapshot"
    assert healthy_hosts["hosts"][0]["hostId"] == "healthy-host"


def test_domain_assignment_release_history_and_engagement_read(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]

    assign_response = client.post(
        f"/api/domains/{domain_id}/assign",
        json={"engagementId": "eng-of02-dev", "purposeTags": [" Email ", "rti", "email", "", "RTI"], "notes": "mail warmup"},
    )
    assert assign_response.status_code == 200
    assignment = assign_response.get_json()["assignment"]
    assert assignment["purpose"] == "email, rti"
    assert assignment["purposeTags"] == ["email", "rti"]

    grouped = client.get("/api/domains").get_json()["domains"]
    assert grouped["currently_being_used"][0]["id"] == domain_id
    assert grouped["currently_being_used"][0]["purpose"] == "email, rti"
    assert grouped["currently_being_used"][0]["purposeTags"] == ["email", "rti"]
    engagement_domains = client.get("/api/engagements/eng-of02-dev/domains").get_json()["domains"]
    assert engagement_domains[0]["id"] == domain_id
    assert engagement_domains[0]["purposeTags"] == ["email", "rti"]

    release_response = client.post(f"/api/domains/{domain_id}/release", json={"releasedBy": "operator"})
    assert release_response.status_code == 200
    assert release_response.get_json()["releasedAssignments"][0]["status"] == "released"
    assert release_response.get_json()["releasedAssignments"][0]["purposeTags"] == ["email", "rti"]

    detail = client.get(f"/api/domains/{domain_id}").get_json()["domain"]
    assert detail["assignments"][0]["status"] == "released"
    assert detail["assignments"][0]["purposeTags"] == ["email", "rti"]
    grouped_after_release = client.get("/api/domains").get_json()["domains"]
    assert grouped_after_release["used_in_past_engagements"][0]["id"] == domain_id
    engagement_domains_after_release = client.get("/api/engagements/eng-of02-dev/domains").get_json()["domains"]
    assert engagement_domains_after_release == []
    assert client.get("/api/domains/purposes").get_json()["purposes"] == ["email", "rti"]


def test_domain_release_with_dns_records_moves_to_historical_bucket(domain_client, monkeypatch):
    app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]
    client.post(f"/api/domains/{domain_id}/assign", json={"engagementId": "eng-of02-dev", "purposeTags": ["website"]})
    timestamp = "2026-06-28T00:00:00+00:00"

    with app.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-dns-release",
                action="engagement_dns_apply",
                status="succeeded",
                target="engagement:eng-of02-dev",
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator",
                input={},
                artifact_refs=[],
                created_at=timestamp,
                started_at=timestamp,
                finished_at=timestamp,
                events=[JobEvent(1, "info", "DNS applied", {})],
            )
        )
        SqlAlchemyDomainRepository().save_snapshot(
            StoredDomainDnsSnapshot(
                id=None,
                domain_id=domain_id,
                provider="namecheap",
                hosts=[{"name": "@", "type": "A", "address": "198.51.100.44", "ttl": "600"}],
                source="provider_snapshot",
                sync_job_id="job-dns-release",
                fetched_at=timestamp,
            )
        )

    release_response = client.post(f"/api/domains/{domain_id}/release", json={"releasedBy": "operator"})

    assert release_response.status_code == 200
    released_domain = release_response.get_json()["domain"]
    assert released_domain["bucket"] == "used_in_past_engagements"
    assert released_domain["dnsSummary"]["recordCount"] == 1
    grouped_after_release = client.get("/api/domains").get_json()["domains"]
    assert [domain["id"] for domain in grouped_after_release["currently_being_used"]] == []
    assert [domain["id"] for domain in grouped_after_release["used_in_past_engagements"]] == [domain_id]


def test_domain_assignment_purpose_can_be_updated(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]
    client.post(f"/api/domains/{domain_id}/assign", json={"engagementId": "eng-of02-dev", "purposeTags": ["rti"]})

    update_response = client.patch(
        f"/api/domains/{domain_id}/assignment",
        json={"purposeTags": [" Email ", "rti", "email", "", "RTI"]},
    )

    assert update_response.status_code == 200
    body = update_response.get_json()
    assert body["assignments"][0]["purpose"] == "email, rti"
    assert body["assignments"][0]["purposeTags"] == ["email", "rti"]
    assert body["domain"]["purpose"] == "email, rti"
    assert body["domain"]["purposeTags"] == ["email", "rti"]

    grouped = client.get("/api/domains").get_json()["domains"]
    assert grouped["currently_being_used"][0]["purposeTags"] == ["email", "rti"]
    engagement_domains = client.get("/api/engagements/eng-of02-dev/domains").get_json()["domains"]
    assert engagement_domains[0]["purposeTags"] == ["email", "rti"]
    assert client.get("/api/domains/purposes").get_json()["purposes"] == ["email", "rti"]


def test_domain_assignment_purpose_update_requires_active_assignment(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]

    response = client.patch(f"/api/domains/{domain_id}/assignment", json={"purposeTags": ["rti"]})

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["domain has no active assignment"]


def test_legacy_domain_assignment_purpose_is_returned_as_tags(domain_client, monkeypatch):
    app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    waiting_domains = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"]
    domain_id = waiting_domains[0]["id"]
    request_legacy_domain_id = waiting_domains[1]["id"]

    legacy_request = client.post(
        f"/api/domains/{request_legacy_domain_id}/assign",
        json={"engagementId": "eng-of02-dev", "purpose": " Campaign Mail "},
    )
    assert legacy_request.status_code == 200
    assert legacy_request.get_json()["assignment"]["purposeTags"] == ["campaign mail"]

    with app.storage_context():
        from app.storage.models import DomainAssignmentModel

        db.session.add(
            DomainAssignmentModel(
                domain_id=domain_id,
                engagement_id="eng-of02-dev",
                engagement_name="of02-dev reference",
                purpose=" Legacy Mail ",
                purpose_tags=[],
                status="active",
                notes="old row",
                assigned_by="operator",
                assigned_at=datetime(2026, 6, 14, tzinfo=timezone.utc),
            )
        )
        db.session.commit()

    detail = client.get(f"/api/domains/{domain_id}").get_json()["domain"]
    assert detail["purpose"] == "legacy mail"
    assert detail["purposeTags"] == ["legacy mail"]
    assert detail["assignments"][0]["purpose"] == "legacy mail"
    assert detail["assignments"][0]["purposeTags"] == ["legacy mail"]
    assert client.get("/api/domains/purposes").get_json()["purposes"] == ["campaign mail", "legacy mail"]


def test_reassignment_and_risky_assignment_require_confirmation(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]
    second_engagement = client.post("/api/engagements", json={"name": "ZY01", "owner": "operator"}).get_json()["engagement"]

    client.post(f"/api/domains/{domain_id}/assign", json={"engagementId": "eng-of02-dev", "purposeTags": ["rti"]})
    conflict = client.post(
        f"/api/domains/{domain_id}/assign",
        json={"engagementId": second_engagement["id"], "purposeTags": ["Staging", "rti", "staging"]},
    )
    assert conflict.status_code == 409
    token = conflict.get_json()["confirmationRequired"]["token"]
    assert token == "ASSIGN example.com"

    confirmed = client.post(
        f"/api/domains/{domain_id}/assign",
        json={"engagementId": second_engagement["id"], "purposeTags": ["Staging", "rti", "staging"], "confirmationToken": token},
    )
    assert confirmed.status_code == 200
    assignments = confirmed.get_json()["domain"]["assignments"]
    assert assignments[0]["engagementId"] == second_engagement["id"]
    assert assignments[0]["purposeTags"] == ["staging", "rti"]
    assert any(assignment["status"] == "released" for assignment in assignments)

    client.post(f"/api/domains/{domain_id}/release", json={})
    risk_response = client.patch(f"/api/domains/{domain_id}/risk", json={"riskStatus": "burned", "riskFlags": ["detected"]})
    assert risk_response.status_code == 200
    risky_assign = client.post(f"/api/domains/{domain_id}/assign", json={"engagementId": second_engagement["id"], "purposeTags": ["email"]})
    assert risky_assign.status_code == 409
    assert "domain risk status is burned" in risky_assign.get_json()["confirmationRequired"]["reasons"]


def test_namecheap_client_blocks_mutation_commands():
    client = NamecheapReadOnlyClient("api-user", "super-secret-api-key", transport=object())

    with pytest.raises(NamecheapMutationBlockedError) as excinfo:
        client.request("namecheap.domains.dns.setHosts", {"SLD": "example", "TLD": "com"})

    assert "setHosts" in str(excinfo.value)
    assert "super-secret-api-key" not in str(excinfo.value)


def test_namecheap_dns_client_sends_indexed_set_hosts_without_enabling_readonly_mutations():
    transport = FakeNamecheapTransport([_set_hosts_response()])
    client = NamecheapDnsClient("api-user", "super-secret-api-key", transport=transport)

    assert client.set_hosts(
        "example.com",
        [
            NamecheapHost("@", "A", "203.0.113.10", "600", ""),
            NamecheapHost("mail", "MX", "mail.example.com.", "600", "10"),
        ],
    ) is True

    assert transport.urls == []
    assert len(transport.posts) == 1
    url, form = transport.posts[0]
    assert url == "https://api.namecheap.com/xml.response"
    assert form["Command"] == "namecheap.domains.dns.setHosts"
    assert form["SLD"] == "example"
    assert form["TLD"] == "com"
    assert form["HostName1"] == "@"
    assert form["RecordType1"] == "A"
    assert form["Address1"] == "203.0.113.10"
    assert form["TTL1"] == "600"
    assert form["HostName2"] == "mail"
    assert form["RecordType2"] == "MX"
    assert form["MXPref2"] == "10"
    assert "super-secret-api-key" not in url


def test_namecheap_client_fetches_all_domain_pages_and_captures_metadata():
    first_page = "".join(_domain_node(index, is_our_dns="true" if index == 1 else "false") for index in range(1, 101))
    second_page = _domain_node(101)
    transport = FakeNamecheapTransport(
        [
            _get_list_response(first_page, current_page=1, total_items=101),
            _get_list_response(second_page, current_page=2, total_items=101),
        ]
    )
    client = NamecheapReadOnlyClient("api-user", "super-secret-api-key", transport=transport)

    domains = client.get_domains()

    assert len(domains) == 101
    assert [domain.name for domain in domains[:2]] == ["domain1.com", "domain2.com"]
    assert domains[0].metadata["isOurDNS"] is True
    assert domains[0].metadata["namecheapId"] == "1"
    assert len(transport.urls) == 2
    first_query = _query(transport.urls[0])
    second_query = _query(transport.urls[1])
    assert first_query["Command"] == ["namecheap.domains.getList"]
    assert first_query["Page"] == ["1"]
    assert first_query["PageSize"] == ["100"]
    assert second_query["Page"] == ["2"]
    assert second_query["PageSize"] == ["100"]
    assert "namecheap.domains.dns.setHosts" not in str(transport.urls)
    assert "super-secret-api-key" not in str(domains)


def test_engagement_dns_apply_submits_complete_host_list_and_stores_snapshot(domain_client, monkeypatch):
    _app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter(
        [
            FakeNamecheapHost("@", "A", "203.0.113.1", ttl="1800", host_id="h1"),
            FakeNamecheapHost("www", "CNAME", "old.example.", ttl="1800", host_id="h2"),
        ]
    )
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)

    desired_records = [
        {"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600"},
        {"name": "www", "type": "CNAME", "address": "old.example.", "ttl": "1800"},
    ]
    preview_response = client.post(
        "/api/engagements/eng-of02-dev/dns/preview",
        json={"domainId": domain_id, "records": desired_records},
    )
    preview = preview_response.get_json()["preview"]

    assert preview_response.status_code == 201
    assert preview["diff"]["updated"][0]["before"]["address"] == "203.0.113.1"
    assert preview["diff"]["unchanged"][0]["name"] == "www"

    apply_response = client.post(
        "/api/engagements/eng-of02-dev/dns/apply",
        json={"domainId": domain_id, "records": desired_records, "currentFingerprint": preview["currentFingerprint"]},
    )
    body = apply_response.get_json()

    assert apply_response.status_code == 202
    assert body["job"]["status"] == "succeeded"
    assert len(adapter.set_calls) == 1
    assert adapter.set_calls[0] == [
        {"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600", "mxPref": ""},
        {"name": "www", "type": "CNAME", "address": "old.example.", "ttl": "1800", "mxPref": ""},
    ]
    hosts = client.get(f"/api/domains/{domain_id}/hosts").get_json()["hosts"]
    assert hosts["syncJobId"] == body["job"]["id"]
    assert hosts["hosts"][0]["address"] == "198.51.100.30"
    assert hosts["hosts"][1]["address"] == "old.example."


def test_dns_ownership_only_claims_new_unique_name_type_after_verified_full_zone(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([
        FakeNamecheapHost("@", "A", "203.0.113.1", host_id="manual-a"),
        FakeNamecheapHost("mail", "MX", "mx.example.net.", mx_pref="10", host_id="manual-mx"),
        FakeNamecheapHost("note", "TXT", "manual-value", host_id="manual-txt"),
    ])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [
        {"name": "@", "type": "A", "address": "203.0.113.2", "ttl": "1800"},
        {"name": "mail", "type": "MX", "address": "mx.example.net.", "mxPref": "10", "ttl": "1800"},
        {"name": "note", "type": "TXT", "address": "manual-value", "ttl": "1800"},
        {"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"},
        {"name": "multi", "type": "A", "address": "198.51.100.11", "ttl": "600"},
        {"name": "multi", "type": "A", "address": "198.51.100.12", "ttl": "600"},
    ]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "succeeded"
    assert len(adapter.set_calls) == 1
    with app.storage_context():
        owned = SqlAlchemyDomainRepository().list_record_ownership(domain_id)
        assert [(row.record["name"], row.record["address"]) for row in owned] == [("new", "198.51.100.10")]
        assert owned[0].creating_job_id == applied["job"]["id"]
        assert owned[0].assignment_id > 0 and owned[0].snapshot_id > 0


def test_owned_dns_cleanup_preview_proves_exact_rows_without_provider_write(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([FakeNamecheapHost("note", "TXT", "manual", ttl="600")])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [
        {"name": "note", "type": "TXT", "address": "manual", "ttl": "600"},
        {"name": "edge", "type": "A", "address": "198.51.100.10", "ttl": "600"},
        {"name": "alias", "type": "CNAME", "address": "edge.example.com.", "ttl": "600"},
    ]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "succeeded"
    with app.storage_context():
        cleanup = preview_owned_dns_cleanup("eng-of02-dev", domain_id, ["198.51.100.10"], adapter=adapter)
    assert cleanup["blockers"] == []
    assert {row["record"]["name"] for row in cleanup["ownedRecords"]} == {"edge", "alias"}
    assert cleanup["zoneFingerprint"].startswith("sha256:")
    assert cleanup["planSha256"].startswith("sha256:")
    assert len(adapter.set_calls) == 1


def test_owned_dns_cleanup_preview_blocks_unowned_old_ip_and_dependent_alias(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([
        FakeNamecheapHost("manual", "A", "198.51.100.20", ttl="600"),
        FakeNamecheapHost("outside", "CNAME", "edge.example.com.", ttl="600"),
    ])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [
        {"name": "manual", "type": "A", "address": "198.51.100.20", "ttl": "600"},
        {"name": "outside", "type": "CNAME", "address": "edge.example.com.", "ttl": "600"},
        {"name": "edge", "type": "A", "address": "198.51.100.10", "ttl": "600"},
    ]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "succeeded"
    with app.storage_context():
        cleanup = preview_owned_dns_cleanup("eng-of02-dev", domain_id,
                                            ["198.51.100.10", "198.51.100.20"], adapter=adapter)
    assert len(cleanup["ownedRecords"]) == 1
    assert any("unowned A" in blocker for blocker in cleanup["blockers"])
    assert any("depends on an owned name" in blocker for blocker in cleanup["blockers"])
    assert len(adapter.set_calls) == 1


def test_later_dns_edit_transfers_unique_owned_tuple_to_verified_replacement(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    first = [{"name": "edge", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    first_preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": first}).get_json()["preview"]
    assert client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": first, "currentFingerprint": first_preview["currentFingerprint"],
    }).get_json()["job"]["status"] == "succeeded"
    replacement = [{"name": "edge", "type": "A", "address": "198.51.100.30", "ttl": "600"}]
    second_preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": replacement}).get_json()["preview"]
    assert client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": replacement, "currentFingerprint": second_preview["currentFingerprint"],
    }).get_json()["job"]["status"] == "succeeded"
    with app.storage_context():
        repo = SqlAlchemyDomainRepository()
        active = repo.list_record_ownership(domain_id, active_only=True)
        assert len(active) == 1 and active[0].record["address"] == "198.51.100.30"
        history = repo.list_record_ownership(domain_id)
        assert len(history) == 2 and history[0].retired_at is not None
        cleanup = preview_owned_dns_cleanup("eng-of02-dev", domain_id, ["198.51.100.30"], adapter=adapter)
    assert len(cleanup["ownedRecords"]) == 1
    assert cleanup["blockers"] == []
    assert len(adapter.set_calls) == 2


def test_dns_apply_refuses_foreign_active_ownership_after_assignment_transfer(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    first = [{"name": "edge", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": first}).get_json()["preview"]
    assert client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": first, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()["job"]["status"] == "succeeded"
    with app.storage_context():
        repo = SqlAlchemyDomainRepository()
        old = repo.list_assignments(domain_id=domain_id, engagement_id="eng-of02-dev")[0]
        repo.save_assignment(replace(old, status="released"))
        repo.save_assignment(replace(old, id=None, status="active"))
    replacement = [{"name": "edge", "type": "A", "address": "198.51.100.30", "ttl": "600"}]
    second_preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": replacement}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": replacement, "currentFingerprint": second_preview["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "failed"
    with app.storage_context():
        active = SqlAlchemyDomainRepository().list_record_ownership(domain_id, active_only=True)
        assert len(active) == 1 and active[0].assignment_id == old.id
    assert len(adapter.set_calls) == 1


def test_dns_ownership_accepts_provider_name_case_and_host_id_normalization(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    original_get = adapter.get_hosts
    def normalized_get(domain_name):
        rows = original_get(domain_name)
        return [FakeNamecheapHost(row.name.upper(), row.record_type, row.address,
                                  ttl=row.ttl, host_id="provider-host-7") for row in rows]
    adapter.get_hosts = normalized_get
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "succeeded"
    with app.storage_context():
        owned = SqlAlchemyDomainRepository().list_record_ownership(domain_id)
        assert len(owned) == 1
        assert owned[0].record["name"] == "NEW"
        assert owned[0].record["hostId"] == "provider-host-7"


def test_domain_release_waits_for_dns_zone_lock(monkeypatch, tmp_path):
    from app.services.domains import release_domain
    from app.services.engagement_dns import _dns01_domain_lock

    monkeypatch.setenv("BARRAGAN_DNS01_LOCK_DIR", str(tmp_path / "dns-locks"))
    entered = threading.Event()
    monkeypatch.setattr("app.services.domains._release_domain_locked",
                        lambda *_args, **_kwargs: entered.set())
    thread = threading.Thread(target=lambda: release_domain("domain-lock-test", {}))
    with _dns01_domain_lock("domain-lock-test"):
        thread.start()
        assert not entered.wait(0.1)
    thread.join(timeout=1)
    assert entered.is_set()


def test_dns_crash_after_intent_never_replays_or_claims_ownership(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    def uncertain_set(domain_name, hosts):
        adapter.set_calls.append([host.to_dict() for host in hosts])
        raise TimeoutError("provider response lost")
    adapter.set_hosts = uncertain_set
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "failed"
    assert "uncertain" in applied["job"]["events"][-1]["message"]
    with app.storage_context():
        assert recover_engagement_dns_apply(applied["job"]["id"], adapter=adapter).status == "failed"
        assert SqlAlchemyDomainRepository().list_record_ownership(domain_id) == []
    assert len(adapter.set_calls) == 1


def test_dns_restart_before_accepted_marks_uncertain_without_replaying(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    def interrupted_set(domain_name, hosts):
        adapter.set_calls.append([host.to_dict() for host in hosts])
        raise KeyboardInterrupt("process stopped during provider call")
    adapter.set_hosts = interrupted_set
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    tasks = []
    with app.storage_context():
        started = start_engagement_dns_apply("eng-of02-dev", {
            "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
        }, adapter=adapter, background_runner=tasks.append)
        with pytest.raises(KeyboardInterrupt):
            tasks[0]()
        assert SqlAlchemyJobRepository().get(started["job"]["id"]).status == "running"
        recovered = recover_engagement_dns_apply(started["job"]["id"], adapter=adapter)
        assert recovered.status == "failed"
        assert "uncertain" in recovered.events[-1].message
        assert SqlAlchemyDomainRepository().list_record_ownership(domain_id) == []
    assert len(adapter.set_calls) == 1


def test_dns_startup_recovery_fences_original_worker_before_provider_go(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    monkeypatch.setattr("app.services.engagement_dns.DNS_PREINTENT_STARTUP_GRACE_SECONDS", 0)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    original_tasks = []
    startup_tasks = []
    with app.storage_context():
        started = start_engagement_dns_apply("eng-of02-dev", {
            "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
        }, adapter=adapter, background_runner=original_tasks.append)
        assert recover_interrupted_engagement_dns_applies(schedule=startup_tasks.append) == 1
        startup_tasks[0]()
        assert SqlAlchemyJobRepository().get(started["job"]["id"]).status == "failed"
        original_tasks[0]()
        assert SqlAlchemyJobRepository().get(started["job"]["id"]).status == "failed"
        assert SqlAlchemyDomainRepository().list_record_ownership(domain_id) == []
    assert adapter.set_calls == []


def test_dns_startup_recovery_uses_bounded_workers_without_dropping_jobs(monkeypatch):
    timestamp = "2026-10-08T00:00:00+00:00"
    rows = [StoredJobRun(
        id=f"job-dns-batch-{index}", action="engagement_dns_apply", status="running",
        target="engagement:eng-of02-dev", target_type="engagement", target_id="eng-of02-dev",
        requested_by="operator", input={"domainId": "domain-1"}, artifact_refs=[],
        created_at=timestamp, started_at=timestamp, finished_at=None,
        events=[JobEvent(1, "info", "engagement DNS apply started", {})]
        + ([JobEvent(2, "info", "Namecheap DNS setHosts intended", {})] if index in {9, 10} else [])
        + ([JobEvent(3, "info", "Namecheap DNS setHosts accepted", {})] if index == 9 else []),
    ) for index in range(11)]
    class Jobs:
        def list(self):
            return rows
        def get(self, job_id):
            return next((row for row in rows if row.id == job_id), None)
    seen = []
    monkeypatch.setattr("app.services.engagement_dns._recover_dns_apply_after_startup_grace",
                        lambda job_id, _jobs: seen.append(job_id))
    tasks = []
    assert recover_interrupted_engagement_dns_applies(schedule=tasks.append, job_repository=Jobs()) == 1
    assert len(tasks) == 1
    tasks[0]()
    assert seen[:2] == ["job-dns-batch-9", "job-dns-batch-10"]
    assert sorted(seen) == sorted(row.id for row in rows)


def test_dns_startup_dispatcher_continues_after_one_job_fails(monkeypatch):
    timestamp = "2026-10-08T00:00:00+00:00"
    rows = [StoredJobRun(
        id=f"job-dns-isolation-{index}", action="engagement_dns_apply", status="running",
        target="engagement:eng-of02-dev", target_type="engagement", target_id="eng-of02-dev",
        requested_by="operator", input={"domainId": "domain-1"}, artifact_refs=[],
        created_at=timestamp, started_at=timestamp, finished_at=None,
        events=[JobEvent(1, "info", "engagement DNS apply started", {})],
    ) for index in range(2)]
    class Jobs:
        def list(self):
            return rows
        def get(self, job_id):
            return next((row for row in rows if row.id == job_id), None)
    seen = []
    def attempt(job_id, _jobs):
        seen.append(job_id)
        if job_id == rows[0].id:
            raise ValueError("bad timestamp")
    monkeypatch.setattr("app.services.engagement_dns._recover_dns_apply_after_startup_grace", attempt)
    tasks = []
    recover_interrupted_engagement_dns_applies(schedule=tasks.append, job_repository=Jobs())
    tasks[0]()
    assert seen == [row.id for row in rows]


def test_dns_accepted_marker_commit_failure_never_claims_or_replays(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    original_save = SqlAlchemyJobRepository.save
    def fail_accepted_save(self, job):
        if any(event.message == "Namecheap DNS setHosts accepted" for event in job.events):
            raise RuntimeError("accepted marker write failed")
        return original_save(self, job)
    monkeypatch.setattr(SqlAlchemyJobRepository, "save", fail_accepted_save)
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()
    monkeypatch.setattr(SqlAlchemyJobRepository, "save", original_save)
    assert applied["job"]["status"] == "running"
    with app.storage_context():
        recovered = recover_engagement_dns_apply(applied["job"]["id"], adapter=adapter)
        assert recovered.status == "failed"
        assert "uncertain" in recovered.events[-1].message
        assert SqlAlchemyDomainRepository().list_record_ownership(domain_id) == []
    assert len(adapter.set_calls) == 1


def test_dns_accepted_recovery_uses_get_only_and_waits_for_matching_zone(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    tasks = []
    with app.storage_context():
        started = start_engagement_dns_apply("eng-of02-dev", {
            "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
        }, adapter=adapter, background_runner=tasks.append)
        from app.services import engagement_dns
        original_verify = engagement_dns._verify_accepted_dns_apply
        monkeypatch.setattr(engagement_dns, "_verify_accepted_dns_apply",
                            lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt("worker stopped")))
        with pytest.raises(KeyboardInterrupt):
            tasks[0]()
        monkeypatch.setattr(engagement_dns, "_verify_accepted_dns_apply", original_verify)
        job_id = started["job"]["id"]
        repo = SqlAlchemyDomainRepository()
        assert repo.list_record_ownership(domain_id) == []
        pending_job = SqlAlchemyJobRepository().get(job_id)
        assert pending_job.status == "running"
        assert pending_job.events[-1].message == "Namecheap DNS setHosts accepted"
        accepted_sequence = next(event.sequence for event in pending_job.events
                                 if event.message == "Namecheap DNS setHosts accepted")
        assignment_id = repo.list_assignments(domain_id=domain_id, engagement_id="eng-of02-dev")[0].id
        with pytest.raises(ValueError, match="owned records differ"):
            repo.complete_dns_apply(
                snapshot=StoredDomainDnsSnapshot(
                    id=None, domain_id=domain_id, provider="namecheap",
                    hosts=[{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600", "mxPref": ""}],
                    source="provider_snapshot", sync_job_id=pending_job.id,
                    fetched_at="2026-10-08T00:00:00+00:00",
                ),
                assignment_id=assignment_id, engagement_id="eng-of02-dev",
                job_id=pending_job.id, owned_records=[], accepted_sequence=accepted_sequence,
                fresh_fingerprint=pending_job.events[accepted_sequence - 1].data["submittedFingerprint"],
            )
        assert repo.list_record_ownership(domain_id) == []
        assert repo.list_snapshots(domain_id) == []
        startup_tasks = []
        assert recover_interrupted_engagement_dns_applies(schedule=startup_tasks.append) == 1
        assert recover_interrupted_engagement_dns_applies(schedule=startup_tasks.append) == 1
        startup_tasks[0]()
        startup_tasks[1]()
        assert SqlAlchemyJobRepository().get(job_id).status == "succeeded"
        assert len(repo.list_record_ownership(domain_id)) == 1
    assert len(adapter.set_calls) == 1


def test_dns_delayed_provider_readback_converges_without_replaying_sethosts(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns.DNS_READBACK_DELAY_SECONDS", 0)
    original_get = adapter.get_hosts
    reads = 0
    def delayed_get(domain_name):
        nonlocal reads
        reads += 1
        if reads in {3, 4, 5, 6}:
            return []
        return original_get(domain_name)
    adapter.get_hosts = delayed_get
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "succeeded"
    assert sum(event["message"] == "Namecheap DNS readback pending" for event in applied["job"]["events"]) == 4
    with app.storage_context():
        assert len(SqlAlchemyDomainRepository().list_record_ownership(domain_id)) == 1
    assert len(adapter.set_calls) == 1


def test_dns_assignment_change_before_go_blocks_provider_write(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    tasks = []
    with app.storage_context():
        started = start_engagement_dns_apply("eng-of02-dev", {
            "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
        }, adapter=adapter, background_runner=tasks.append)
        assignment = SqlAlchemyDomainRepository().list_assignments(domain_id=domain_id, engagement_id="eng-of02-dev")[0]
        SqlAlchemyDomainRepository().save_assignment(replace(assignment, status="released"))
        tasks[0]()
        assert SqlAlchemyJobRepository().get(started["job"]["id"]).status == "failed"
        assert SqlAlchemyDomainRepository().list_record_ownership(domain_id) == []
    assert adapter.set_calls == []


def test_dns_post_write_mismatch_stays_unowned_and_recovery_is_get_only(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns.DNS_READBACK_DELAY_SECONDS", 0)
    original_get = adapter.get_hosts
    reads = 0
    def counting_get(domain_name):
        nonlocal reads
        reads += 1
        return original_get(domain_name)
    adapter.get_hosts = counting_get
    original_set = adapter.set_hosts
    def modified_set(domain_name, hosts):
        original_set(domain_name, hosts)
        adapter.hosts = [FakeNamecheapHost("new", "A", "198.51.100.99", ttl="600")]
        return True
    adapter.set_hosts = modified_set
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    applied = client.post("/api/engagements/eng-of02-dev/dns/apply", json={
        "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
    }).get_json()
    assert applied["job"]["status"] == "failed"
    assert "manual review" in applied["job"]["events"][-1]["message"]
    with app.storage_context():
        assert recover_engagement_dns_apply(applied["job"]["id"], adapter=adapter).status == "failed"
        assert SqlAlchemyDomainRepository().list_record_ownership(domain_id) == []
    assert len(adapter.set_calls) == 1
    assert reads == 14  # preview, GO, then twelve bounded GET-only readbacks


def test_dns_assignment_transfer_after_accepted_cannot_publish_ownership(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired = [{"name": "new", "type": "A", "address": "198.51.100.10", "ttl": "600"}]
    preview = client.post("/api/engagements/eng-of02-dev/dns/preview", json={"domainId": domain_id, "records": desired}).get_json()["preview"]
    tasks = []
    with app.storage_context():
        started = start_engagement_dns_apply("eng-of02-dev", {
            "domainId": domain_id, "records": desired, "currentFingerprint": preview["currentFingerprint"],
        }, adapter=adapter, background_runner=tasks.append)
        from app.services import engagement_dns
        original_verify = engagement_dns._verify_accepted_dns_apply
        monkeypatch.setattr(engagement_dns, "_verify_accepted_dns_apply",
                            lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt("worker stopped")))
        with pytest.raises(KeyboardInterrupt):
            tasks[0]()
        monkeypatch.setattr(engagement_dns, "_verify_accepted_dns_apply", original_verify)
        repo = SqlAlchemyDomainRepository()
        assignment = repo.list_assignments(domain_id=domain_id, engagement_id="eng-of02-dev")[0]
        repo.save_assignment(replace(assignment, status="released"))
        assert recover_engagement_dns_apply(started["job"]["id"], adapter=adapter).status == "failed"
        assert repo.list_record_ownership(domain_id) == []
    assert len(adapter.set_calls) == 1


def test_engagement_dns_preview_ignores_non_mx_mxpref_noise(domain_client, monkeypatch):
    _app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter(
        [
            FakeNamecheapHost("www", "A", "198.51.100.30", ttl="300", mx_pref="10", host_id="h1"),
            FakeNamecheapHost("token", "TXT", "random-value", ttl="300", mx_pref="10", host_id="h2"),
        ]
    )
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)

    response = client.post(
        "/api/engagements/eng-of02-dev/dns/preview",
        json={
            "domainId": domain_id,
            "records": [
                {"name": "token", "type": "TXT", "address": "random-value", "ttl": "300"},
            ],
        },
    )

    preview = response.get_json()["preview"]
    assert response.status_code == 201
    assert preview["diff"]["updated"] == []
    assert preview["diff"]["unchanged"] == [{"name": "token", "type": "TXT", "address": "random-value", "ttl": "300", "mxPref": ""}]
    assert preview["diff"]["removed"][0]["name"] == "www"


def test_dns01_challenge_adds_and_removes_exact_txt_while_preserving_records(domain_client, monkeypatch):
    app, client = domain_client
    _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([
        FakeNamecheapHost("@", "A", "203.0.113.10", ttl="600"),
        FakeNamecheapHost("_acme-challenge", "TXT", "another-concurrent-value", ttl="60"),
        FakeNamecheapHost("@", "NS", "dns1.example.", ttl="1800"),
    ])

    with app.storage_context():
        added = set_dns01_challenge(
            "eng-of02-dev",
            "example.com",
            "ephemeral-validation-value",
            present=True,
            adapter=adapter,
        )
        removed = set_dns01_challenge(
            "eng-of02-dev",
            "example.com",
            "ephemeral-validation-value",
            present=False,
            adapter=adapter,
        )

    assert added["recordName"] == "_acme-challenge"
    assert "ephemeral-validation-value" not in str(added)
    assert removed["present"] is False
    assert adapter.set_calls[0] == [
        {"name": "@", "type": "A", "address": "203.0.113.10", "ttl": "600", "mxPref": ""},
        {"name": "_acme-challenge", "type": "TXT", "address": "another-concurrent-value", "ttl": "60", "mxPref": ""},
        {"name": "@", "type": "NS", "address": "dns1.example.", "ttl": "1800", "mxPref": ""},
        {"name": "_acme-challenge", "type": "TXT", "address": "ephemeral-validation-value", "ttl": "60", "mxPref": ""},
    ]
    assert [host.address for host in adapter.hosts] == ["203.0.113.10", "another-concurrent-value", "dns1.example."]


def test_dns01_propagation_requires_each_authoritative_nameserver(monkeypatch):
    from app.services.engagement_dns import wait_for_dns01_challenge

    class NsAnswer:
        def __init__(self, target):
            self.target = target

    class AddressAnswer:
        def __init__(self, address):
            self.address = address

    class TxtAnswer:
        strings = (b"validation-value",)

    class FakeResolver:
        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []

        def resolve(self, name, record_type, lifetime=10):
            if record_type == "NS":
                return [NsAnswer("ns1.example.net."), NsAnswer("ns2.example.net.")]
            if record_type == "A":
                return [AddressAnswer("192.0.2.1" if name.startswith("ns1") else "192.0.2.2")]
            assert self.nameservers in (["192.0.2.1"], ["192.0.2.2"])
            return [TxtAnswer()]

    monkeypatch.setattr("app.services.engagement_dns.dns.resolver.Resolver", FakeResolver)

    result = wait_for_dns01_challenge(
        "www.example.com",
        "validation-value",
        zone="example.com",
        timeout_seconds=1,
        poll_seconds=1,
    )

    assert result["propagated"] is True
    assert result["authoritativeServerCount"] == 2


def test_engagement_dns_apply_preserves_unsupported_provider_records(domain_client, monkeypatch):
    _app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter(
        [
            FakeNamecheapHost("@", "A", "203.0.113.1", ttl="1800", host_id="h1"),
            FakeNamecheapHost("@", "CAA", "0 issue \"letsencrypt.org\"", ttl="1800", host_id="caa1"),
        ]
    )
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)

    desired_records = [{"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600"}]
    preview_response = client.post(
        "/api/engagements/eng-of02-dev/dns/preview",
        json={"domainId": domain_id, "records": desired_records},
    )
    preview = preview_response.get_json()["preview"]

    assert preview_response.status_code == 201
    assert preview["desiredRecords"] == [
        {"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600", "mxPref": ""},
        {"name": "@", "type": "CAA", "address": "0 issue \"letsencrypt.org\"", "ttl": "1800", "mxPref": ""},
    ]
    assert preview["diff"]["unchanged"] == [
        {"name": "@", "type": "CAA", "address": "0 issue \"letsencrypt.org\"", "ttl": "1800", "mxPref": ""}
    ]

    apply_response = client.post(
        "/api/engagements/eng-of02-dev/dns/apply",
        json={"domainId": domain_id, "records": desired_records, "currentFingerprint": preview["currentFingerprint"]},
    )

    assert apply_response.status_code == 202
    assert apply_response.get_json()["job"]["status"] == "succeeded"
    assert adapter.set_calls[0] == [
        {"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600", "mxPref": ""},
        {"name": "@", "type": "CAA", "address": "0 issue \"letsencrypt.org\"", "ttl": "1800", "mxPref": ""},
    ]


def test_engagement_dns_apply_can_return_running_background_job(domain_client, monkeypatch):
    app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([FakeNamecheapHost("@", "A", "203.0.113.1", ttl="600", host_id="h1")])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired_records = [{"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600"}]
    preview = client.post(
        "/api/engagements/eng-of02-dev/dns/preview",
        json={"domainId": domain_id, "records": desired_records},
    ).get_json()["preview"]

    with app.storage_context():
        result = start_engagement_dns_apply(
            "eng-of02-dev",
            {"domainId": domain_id, "records": desired_records, "currentFingerprint": preview["currentFingerprint"]},
            adapter=adapter,
            background_runner=lambda _task: None,
        )

    assert result is not None
    assert result["status"] == "running"
    assert result["job"]["action"] == "engagement_dns_apply"
    assert adapter.set_calls == []


def test_engagement_dns_apply_credential_setup_failure_does_not_leave_running_job(domain_client, monkeypatch):
    _app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)

    def fail_dns_client(alias=None):
        raise CredentialValidationError(["no active default namecheap credential configured"])

    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", fail_dns_client)

    response = client.post(
        "/api/engagements/eng-of02-dev/dns/apply",
        json={
            "domainId": domain_id,
            "records": [{"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600"}],
            "currentFingerprint": "sha256:preview",
        },
    )

    assert response.status_code == 400
    assert "no active default namecheap credential configured" in response.get_json()["errors"]
    dns_jobs = [
        job
        for job in client.get("/api/jobs").get_json()["jobs"]
        if job["action"] == "engagement_dns_apply"
    ]
    assert dns_jobs == []


def test_engagement_dns_edge_targets_exclude_inactive_and_burned_edges():
    overview = {
        "sketchInfrastructure": [
            {"role": "edge", "hostname": "edge-ready", "publicIp": "198.51.100.10", "status": "ready", "chainId": "chain-ready"},
            {"role": "edge", "hostname": "edge-deployed", "publicIp": "198.51.100.11", "status": "deployed", "chainId": "chain-deployed"},
            {"role": "edge", "hostname": "edge-stopped", "publicIp": "198.51.100.12", "status": "stopped", "chainId": "chain-stopped"},
            {"role": "edge", "hostname": "edge-failed", "publicIp": "198.51.100.13", "status": "failed", "chainId": "chain-failed"},
            {"role": "edge", "hostname": "edge-pending", "publicIp": "198.51.100.14", "status": "pending", "chainId": "chain-pending"},
            {"role": "edge", "hostname": "edge-burned", "publicIp": "198.51.100.15", "status": "ready", "chainId": "chain-burned", "burned": True},
            {"role": "middle", "hostname": "middle-ready", "publicIp": "198.51.100.16", "status": "ready", "chainId": "chain-middle"},
        ]
    }

    targets = _eligible_edge_targets(overview)

    assert [target["hostname"] for target in targets] == ["edge-ready", "edge-deployed"]


def test_engagement_dns_apply_rejects_stale_preview_fingerprint(domain_client, monkeypatch):
    _app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter([FakeNamecheapHost("@", "A", "203.0.113.1", ttl="600", host_id="h1")])
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)

    desired_records = [{"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600"}]
    preview = client.post(
        "/api/engagements/eng-of02-dev/dns/preview",
        json={"domainId": domain_id, "records": desired_records},
    ).get_json()["preview"]
    adapter.hosts = [FakeNamecheapHost("@", "A", "203.0.113.99", ttl="600", host_id="h1")]

    apply_response = client.post(
        "/api/engagements/eng-of02-dev/dns/apply",
        json={"domainId": domain_id, "records": desired_records, "currentFingerprint": preview["currentFingerprint"]},
    )
    body = apply_response.get_json()

    assert apply_response.status_code == 202
    assert body["job"]["status"] == "failed"
    assert adapter.set_calls == []
    assert "state changed after preview" in body["job"]["events"][-1]["message"]
    assert body["job"]["events"][-1]["data"]["mutation"] is False


def test_engagement_dns_apply_can_add_update_and_remove_ns_records(domain_client, monkeypatch):
    _app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    adapter = FakeDnsAdapter(
        [
            FakeNamecheapHost("delegated", "NS", "old-ns.example.net.", ttl="600", host_id="ns1"),
            FakeNamecheapHost("obsolete", "NS", "ns1.obsolete.example.net.", ttl="600", host_id="ns2"),
        ]
    )
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: adapter)
    desired_records = [
        {"name": "delegated", "type": "NS", "address": "ns1.delegated.example.net.", "ttl": "300"},
        {"name": "delegated", "type": "NS", "address": "ns2.delegated.example.net.", "ttl": "300"},
    ]

    preview_response = client.post(
        "/api/engagements/eng-of02-dev/dns/preview",
        json={"domainId": domain_id, "records": desired_records},
    )
    preview = preview_response.get_json()["preview"]

    assert preview_response.status_code == 201
    assert [row["address"] for row in preview["diff"]["added"]] == ["ns2.delegated.example.net."]
    assert preview["diff"]["updated"] == [
        {
            "before": {"name": "delegated", "type": "NS", "address": "old-ns.example.net.", "ttl": "600", "mxPref": "", "hostId": "ns1"},
            "after": {"name": "delegated", "type": "NS", "address": "ns1.delegated.example.net.", "ttl": "300", "mxPref": ""},
        }
    ]
    assert [row["name"] for row in preview["diff"]["removed"]] == ["obsolete"]

    apply_response = client.post(
        "/api/engagements/eng-of02-dev/dns/apply",
        json={"domainId": domain_id, "records": desired_records, "currentFingerprint": preview["currentFingerprint"]},
    )

    assert apply_response.status_code == 202
    assert apply_response.get_json()["job"]["status"] == "succeeded"
    assert adapter.set_calls == [[
        {"name": "delegated", "type": "NS", "address": "ns1.delegated.example.net.", "ttl": "300", "mxPref": ""},
        {"name": "delegated", "type": "NS", "address": "ns2.delegated.example.net.", "ttl": "300", "mxPref": ""},
    ]]


def test_engagement_dns_requires_active_domain_assignment(domain_client, monkeypatch):
    _app, client = domain_client
    monkeypatch.setattr("app.services.domains._namecheap_client", lambda alias=None: FakeNamecheapAdapter())
    client.post("/api/domains/sync/namecheap", json={"includeHosts": False})
    domain_id = client.get("/api/domains").get_json()["domains"]["waiting_to_be_used"][0]["id"]
    monkeypatch.setattr("app.services.engagement_dns._namecheap_dns_client", lambda alias=None: FakeDnsAdapter([]))

    response = client.post(
        "/api/engagements/eng-of02-dev/dns/preview",
        json={"domainId": domain_id, "records": [{"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600"}]},
    )

    assert response.status_code == 400
    assert "actively assigned" in response.get_json()["errors"][0]


def test_engagement_dns_apply_redacts_namecheap_secret_errors(domain_client, monkeypatch):
    _app, client = domain_client
    domain_id = _assigned_domain_id(client, monkeypatch)
    monkeypatch.setattr(
        "app.services.engagement_dns._namecheap_dns_client",
        lambda alias=None: FailingDnsAdapter([FakeNamecheapHost("@", "A", "203.0.113.1")]),
    )

    response = client.post(
        "/api/engagements/eng-of02-dev/dns/apply",
        json={
            "domainId": domain_id,
            "records": [{"name": "@", "type": "A", "address": "198.51.100.30", "ttl": "600"}],
            "currentFingerprint": "sha256:preview",
        },
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["job"]["status"] == "failed"
    assert "super-secret-api-key" not in str(body)
    assert "ApiKey" not in str(body)
    assert "redacted sensitive details" in body["job"]["events"][-1]["message"]


def test_namecheap_client_captures_dns_host_ids_without_mutation():
    transport = FakeNamecheapTransport(
        [
            """<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="OK">
  <Errors />
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
      <Host HostId="12" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>"""
        ]
    )
    client = NamecheapReadOnlyClient("api-user", "super-secret-api-key", transport=transport)

    hosts = client.get_hosts("example.com")

    assert hosts[0].to_dict() == {
        "name": "@",
        "type": "A",
        "address": "1.2.3.4",
        "ttl": "1800",
        "mxPref": "10",
        "hostId": "12",
    }
    query = _query(transport.urls[0])
    assert query["Command"] == ["namecheap.domains.dns.getHosts"]
    assert query["SLD"] == ["example"]
    assert query["TLD"] == ["com"]
    assert "namecheap.domains.dns.setHosts" not in transport.urls[0]


def test_namecheap_transport_errors_are_redacted():
    class ExplodingTransport:
        def get(self, url: str, timeout: int) -> str:
            raise RuntimeError(f"transport failed for {url}")

    client = NamecheapReadOnlyClient("api-user", "super-secret-api-key", transport=ExplodingTransport())

    with pytest.raises(Exception) as excinfo:
        client.get_domains()

    message = str(excinfo.value)
    assert "super-secret-api-key" not in message
    assert "ApiKey" not in message
    assert "api.namecheap.com" not in message
