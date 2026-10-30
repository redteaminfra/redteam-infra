# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-read, persisted pre-destroy DNS manifest proof."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_dns_cleanup_manifest import (
    ProviderKeyedDnsCleanupManifestError, build_provider_keyed_dns_cleanup_manifest,
)
from app.services.provider_keyed_host_binding import _digest_json
from app.storage.domain_repository import (
    StoredDomainDnsRecordOwnership, StoredDomainDnsSnapshot,
)
from test_provider_keyed_dns_cleanup_binding import _fixture


class Jobs:
    def __init__(self, rows):
        self.rows = {row.id: row for row in rows}

    def get(self, job_id):
        return self.rows.get(job_id)

    def list_for_engagement(self, engagement_id):
        return [row for row in self.rows.values()
                if ((row.id == "job-core" and engagement_id == "eng-1")
                    or getattr(row, "target_id", None) == engagement_id)]


class Domains:
    def __init__(self, count, *, owned=False):
        self.assets = {}
        self.assignments = []
        self.snapshots = {}
        self.receipts = {}
        self.frozen = []
        for index in range(count):
            domain_id = f"domain-{index + 1}"
            name = f"zone-{index + 1}.example"
            assignment = SimpleNamespace(id=index + 1, domain_id=domain_id,
                engagement_id="eng-1", status="active")
            self.assignments.append(assignment)
            self.assets[domain_id] = SimpleNamespace(id=domain_id, domain_name=name,
                                                      registrar="namecheap")
            self.frozen.append({"domainId": domain_id, "assignmentId": index + 1,
                                "domainName": name, "registrar": "namecheap"})
            self.snapshots[domain_id] = []
            self.receipts[domain_id] = []
            if owned:
                record = {"name": "www", "type": "A", "address": "8.8.8.8",
                          "ttl": "600", "mxPref": ""}
                self.snapshots[domain_id] = [StoredDomainDnsSnapshot(
                    id=100 + index, domain_id=domain_id, provider="namecheap",
                    hosts=[record], source="provider", sync_job_id=f"dns-{index + 1}",
                    fetched_at="2026-10-08T00:00:00+00:00")]
                self.receipts[domain_id] = [StoredDomainDnsRecordOwnership(
                    id=200 + index, domain_id=domain_id, assignment_id=index + 1,
                    engagement_id="eng-1", creating_job_id=f"dns-{index + 1}",
                    snapshot_id=100 + index, record=record, retired_at=None)]

    def list_assignments(self, domain_id=None, engagement_id=None):
        if domain_id is not None:
            return [row for row in self.assignments if row.domain_id == domain_id]
        if engagement_id is not None:
            return [row for row in self.assignments if row.engagement_id == engagement_id]
        return list(self.assignments)

    def get_asset(self, domain_id):
        return self.assets.get(domain_id)

    def list_snapshots(self, domain_id):
        return self.snapshots[domain_id]

    def list_record_ownership(self, domain_id, *, active_only=False):
        return self.receipts[domain_id]


class Adapter:
    def __init__(self, domains, *, owned=False):
        self.zones = {}
        self.calls = []
        for asset in domains.assets.values():
            records = [
                {"name": "@", "type": "MX", "address": "mail.example",
                 "ttl": "1800", "mxPref": "10"},
                {"name": "note", "type": "TXT", "address": "manual value",
                 "ttl": "600"},
            ]
            if owned:
                records.insert(0, {"name": "www", "type": "A", "address": "8.8.8.8",
                                   "ttl": "600"})
            self.zones[asset.domain_name] = records

    def get_hosts(self, domain_name):
        self.calls.append(domain_name)
        return deepcopy(self.zones[domain_name])

    def set_hosts(self, _domain_name, _hosts):
        pytest.fail("read-only manifest called setHosts")


def _case(count=1, *, owned=False):
    scope, host_manifest = _fixture()
    domains = Domains(count, owned=owned)
    core = SimpleNamespace(id="job-core", action="pilot_standard_rti_guarded_execute",
                           status="succeeded", input={"engagementId": "eng-1",
                               "corePlanId": "plan-1", "sketchStateSchema": "provider-keyed-v2"})
    initial = SimpleNamespace(id="job-provider-keyed-initial-core",
        action="provider_keyed_initial", target_id="eng-1",
        input={"coreJobId": core.id, "corePlanId": "plan-1"}, events=[
            JobEvent(1, "info", "provider host identity binding intended", host_manifest),
            JobEvent(2, "info", "provider host identity bound", {
                "manifestSha256": _digest_json(host_manifest), "hostProofPending": True}),
        ])
    sources = [SimpleNamespace(id=f"dns-{index + 1}", action="engagement_dns_apply",
        status="succeeded", target_id="eng-1", input={"domainId": f"domain-{index + 1}"},
        events=[JobEvent(1, "info", "Namecheap DNS setHosts completed with full desired host list",
                         {"snapshotId": 100 + index})]) for index in range(count)] if owned else []
    jobs = Jobs([core, initial, *sources])
    snapshot = {"engagementId": "eng-1", "coreJobId": core.id,
                "providerScopes": [scope],
                "providerScopeSha256": _digest_json({"providerScopes": [scope]}),
                "domainAssignments": domains.frozen}
    adapter = Adapter(domains, owned=owned)
    return snapshot, jobs, domains, adapter


@pytest.mark.parametrize("count", [0, 1, 2])
def test_manifest_seals_complete_sorted_domain_set_from_one_read_each(count):
    snapshot, jobs, domains, adapter = _case(count, owned=True)
    result = build_provider_keyed_dns_cleanup_manifest(
        snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    assert [row["domainId"] for row in result["domains"]] == [
        row["domainId"] for row in domains.frozen]
    assert len(adapter.calls) == count
    assert result["manifestSha256"].startswith("sha256:")
    assert result["domainAssignments"] == domains.frozen
    for row in result["domains"]:
        assert row["ownedReceiptIds"] == [200 + int(row["domainId"].split("-")[1]) - 1]
        assert row["maxOwnedTtl"] == 600
        assert row["preservedRecordCount"] == 2
        assert row["preservedRecordsSha256"].startswith("sha256:")
        assert "manual value" not in str(row)
        assert row["blockers"] == []
    assert result == build_provider_keyed_dns_cleanup_manifest(
        snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)


def test_reconciled_unapplied_append_uses_four_node_dns_manifest_and_fails_closed():
    snapshot, jobs, domains, adapter = _case(1, owned=True)
    retained_sha = snapshot["providerScopes"][0]["stateSha256"]
    parent = SimpleNamespace(
        id="job-append", action="provider_keyed_edge_append", status="failed",
        target_id="eng-1", finished_at="2026-10-14T01:00:00+00:00",
        input={"engagementId": "eng-1", "coreJobId": "job-core", "corePlanId": "plan-1",
               "phase": "unapplied_reconciled", "planJobId": "job-append-plan"},
        events=[JobEvent(1, "info", "append plan reconciled without mutation", {
            "stateSha256": retained_sha})],
    )
    child = SimpleNamespace(
        id="job-append-plan", action="provider_keyed_edge_append_plan",
        status="failed", target_id="eng-1",
        input={"parentJobId": parent.id, "coreJobId": "job-core", "mutation": False},
    )
    jobs.rows[parent.id], jobs.rows[child.id] = parent, child
    result = build_provider_keyed_dns_cleanup_manifest(
        snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    assert result["schema"] != "provider-keyed-empty-dns-append-v1"
    assert len(result["domains"]) == 1
    parent.events[-1] = JobEvent(1, "info", "append plan reconciled without mutation", {
        "stateSha256": "0" * 64})
    with pytest.raises(ProviderKeyedDnsCleanupManifestError):
        build_provider_keyed_dns_cleanup_manifest(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    parent.events[-1] = JobEvent(1, "info", "append plan reconciled without mutation", {
        "stateSha256": retained_sha})
    jobs.rows["job-append-apply"] = SimpleNamespace(
        id="job-append-apply", action="provider_keyed_edge_append_apply",
        target_id="eng-1", status="failed")
    with pytest.raises(ProviderKeyedDnsCleanupManifestError):
        build_provider_keyed_dns_cleanup_manifest(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)


def test_unowned_old_edge_ip_in_second_domain_blocks_complete_manifest():
    snapshot, jobs, domains, adapter = _case(2)
    adapter.zones["zone-2.example"].append(
        {"name": "old", "type": "A", "address": "1.1.1.1", "ttl": "600"})
    with pytest.raises(ProviderKeyedDnsCleanupManifestError):
        build_provider_keyed_dns_cleanup_manifest(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    assert adapter.calls == ["zone-1.example", "zone-2.example"]


def test_manual_only_zone_has_no_deletion_receipts_and_preserves_every_record():
    snapshot, jobs, domains, adapter = _case(1)
    result = build_provider_keyed_dns_cleanup_manifest(
        snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    row = result["domains"][0]
    assert row["ownedReceiptIds"] == []
    assert row["maxOwnedTtl"] == 0
    assert row["preservedRecordCount"] == 2
    assert "manual value" not in str(result)
    assert adapter.calls == ["zone-1.example"]


def test_duplicate_owned_tuple_is_ambiguous_and_cannot_enter_manifest():
    snapshot, jobs, domains, adapter = _case(1, owned=True)
    adapter.zones["zone-1.example"].append(deepcopy(adapter.zones["zone-1.example"][0]))
    with pytest.raises(ProviderKeyedDnsCleanupManifestError):
        build_provider_keyed_dns_cleanup_manifest(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)


def test_missing_persisted_initial_binding_is_not_substituted_from_caller():
    snapshot, jobs, domains, adapter = _case(1)
    jobs.rows.pop("job-provider-keyed-initial-core")
    with pytest.raises(ProviderKeyedDnsCleanupManifestError):
        build_provider_keyed_dns_cleanup_manifest(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    assert adapter.calls == []


def test_manifest_freezes_caller_rows_and_fails_if_binding_changes_during_zone_read():
    snapshot, jobs, domains, adapter = _case()
    frozen = build_provider_keyed_dns_cleanup_manifest(
        snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    snapshot["domainAssignments"][0]["domainName"] = "changed.example"
    assert frozen["domainAssignments"][0]["domainName"] == "zone-1.example"

    snapshot, jobs, domains, adapter = _case()
    original_get = adapter.get_hosts

    def change_initial_journal(domain_name):
        rows = original_get(domain_name)
        initial = jobs.rows["job-provider-keyed-initial-core"]
        initial.events.append(JobEvent(3, "info", "unexpected host binding change", {}))
        return rows

    adapter.get_hosts = change_initial_journal
    with pytest.raises(ProviderKeyedDnsCleanupManifestError):
        build_provider_keyed_dns_cleanup_manifest(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)


def test_assignment_change_during_zone_read_blocks_manifest():
    snapshot, jobs, domains, adapter = _case()
    original_get = adapter.get_hosts

    def change_assignment(domain_name):
        rows = original_get(domain_name)
        domains.assignments[0] = SimpleNamespace(id=9, domain_id="domain-1",
            engagement_id="eng-1", status="active")
        return rows

    adapter.get_hosts = change_assignment
    with pytest.raises(ProviderKeyedDnsCleanupManifestError):
        build_provider_keyed_dns_cleanup_manifest(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)


@pytest.mark.parametrize("drift", ["missing_asset", "assignment", "registrar", "binding", "type"])
def test_manifest_rejects_missing_or_changed_provenance(drift):
    snapshot, jobs, domains, adapter = _case()
    if drift == "missing_asset":
        domains.assets.clear()
    elif drift == "assignment":
        domains.assignments[0] = SimpleNamespace(id=9, domain_id="domain-1",
            engagement_id="eng-1", status="active")
    elif drift == "registrar":
        domains.assets["domain-1"].registrar = "other"
    elif drift == "binding":
        jobs.rows["job-provider-keyed-initial-core"].events[1] = JobEvent(
            2, "info", "provider host identity bound", {
                "manifestSha256": "0" * 64, "hostProofPending": True})
    else:
        adapter.zones["zone-1.example"].append(
            {"name": "unknown", "type": "CAA", "address": "0 issue example", "ttl": "600"})
    with pytest.raises(ProviderKeyedDnsCleanupManifestError):
        build_provider_keyed_dns_cleanup_manifest(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
