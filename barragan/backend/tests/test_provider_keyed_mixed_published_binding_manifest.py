# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact, inert DNS and binding preview for mixed six-node teardown."""

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_append_pair_host_proof import validate_six_node_host_source
from app.services.provider_keyed_mixed_published_binding_manifest import (
    MixedPublishedBindingManifestAttention, _digest,
    build_mixed_published_binding_manifest as _build_manifest,
)
from app.services.provider_keyed_mixed_initial_host_binding import _digest as _scope_digest
from app.services.provider_keyed_mixed_published_six_scope import (
    PublishedMixedSixScope, build_mixed_published_six_teardown_scope,
)
from app.storage.domain_repository import (
    StoredDomainAssignment, StoredDomainDnsRecordOwnership, StoredDomainDnsSnapshot,
)
from app.storage.job_repository import SqliteJobRepository, StoredJobRun
from test_provider_keyed_mixed_append_pair_host_proof import _source
from test_provider_keyed_mixed_published_six_scope import _case as _real_scope_case


_EMPTY = {kind: () for kind in ("channels", "domains", "certificates", "sites")}


def build_mixed_published_binding_manifest(source, scope, **kwargs):
    """Use the fake engagement-scoped ownership table for focused reads."""
    domains = kwargs["domain_repository"]
    kwargs.setdefault("host_routes_reader", lambda *_args: ())
    kwargs.setdefault("dns_ownership_reader", lambda engagement_id: [
        row for row in domains.ownership if row.engagement_id == engagement_id])
    return _build_manifest(source, scope, **kwargs)


def _case(*, reverse=False, bindings=None):
    source = _source()
    if reverse:
        source = replace(source,
            provider_order=tuple(reversed(source.provider_order)),
            chain_ids=tuple(reversed(source.chain_ids)),
            before_chains=tuple(reversed(source.before_chains)),
            chains=tuple(reversed(source.chains)),
            new_edge_addresses=tuple(reversed(source.new_edge_addresses)),
            provider_proof_digests=tuple(reversed(source.provider_proof_digests)),
            state_sha256s=tuple(reversed(source.state_sha256s)),
            workspace_paths=tuple(reversed(source.workspace_paths)),
            source_revisions=tuple(reversed(source.source_revisions)),
            proxy_egress_ips=tuple(reversed(source.proxy_egress_ips)))
    validate_six_node_host_source(source)
    rows = bindings or _EMPTY
    scope = PublishedMixedSixScope(
        source.source_sha256, "append-sha",
        _scope_digest({"schema": "mixed-published-six-bindings-v1", "bindings": rows}),
        sum(len(value) for value in rows.values()), ({}, {}),
    )
    return source, scope, lambda _engagement_id: rows


def test_accepts_scope_built_from_exact_six_node_publication():
    source, options = _real_scope_case()
    scope = build_mixed_published_six_teardown_scope(source, **options)
    manifest = build_mixed_published_binding_manifest(
        source, scope, domain_repository=_Domains(), job_repository=object(),
        binding_inventory=lambda _id: options["live_bindings"],
    )
    assert manifest["bindingsSha256"] == scope.bindings_sha256
    assert manifest["bindingCount"] == scope.binding_count == 4


class _Domains:
    def __init__(self, assignment=None, *, foreign=None, ownership=None, snapshot=None):
        self.assignment = assignment
        self.foreign = foreign
        self.ownership = ownership or []
        self.snapshot = snapshot

    def list_assignments(self, domain_id=None, engagement_id=None):
        rows = [row for row in (self.assignment, self.foreign) if row is not None]
        if domain_id:
            rows = [row for row in rows if row.domain_id == domain_id]
        if engagement_id:
            rows = [row for row in rows if row.engagement_id == engagement_id]
        return rows

    def get_asset(self, domain_id):
        return (SimpleNamespace(id="domain-1", domain_name="one.example",
                                registrar="namecheap")
                if domain_id == "domain-1" else None)

    def list_record_ownership(self, domain_id, *, active_only=False):
        return [row for row in self.ownership if row.domain_id == domain_id
                and (not active_only or row.retired_at is None)]

    def list_snapshots(self, domain_id):
        return [self.snapshot] if domain_id == "domain-1" and self.snapshot else []


class _Zone:
    def __init__(self, records):
        self.records = records
        self.reads = 0

    def get_hosts(self, domain_name):
        assert domain_name == "one.example"
        self.reads += 1
        return list(self.records)

    def set_hosts(self, *_args):
        raise AssertionError("read-only preview must not write DNS")


def _assignment(engagement_id="eng-test", assignment_id=1):
    return StoredDomainAssignment(
        assignment_id, "domain-1", engagement_id, "test", "test", "active",
        "", "operator", "", "2026-10-19T00:00:00+00:00", None,
    )


def _owned_setup(tmp_path, monkeypatch):
    monkeypatch.setenv("BARRAGAN_DNS01_LOCK_DIR", str(tmp_path / "dns-locks"))
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    owned = {"name": "nb", "type": "A", "address": "198.51.100.21",
             "ttl": "600", "mxPref": ""}
    job = StoredJobRun(
        "job-dns-1", "engagement_dns_apply", "succeeded", "engagement:eng-test",
        "engagement", "eng-test", "operator", {"domainId": "domain-1"}, [],
        "2026-10-19T00:00:00+00:00", "2026-10-19T00:00:00+00:00",
        "2026-10-19T00:00:01+00:00", [JobEvent(
            1, "info", "Namecheap DNS setHosts completed with full desired host list",
            {"snapshotId": 1})],
    )
    jobs.save(job)
    snapshot = StoredDomainDnsSnapshot(
        1, "domain-1", "namecheap", [owned], "provider", job.id,
        "2026-10-19T00:00:01+00:00",
    )
    receipt = StoredDomainDnsRecordOwnership(
        11, "domain-1", 1, "eng-test", job.id, 1, owned, None,
    )
    return jobs, _Domains(_assignment(), ownership=[receipt], snapshot=snapshot), owned


@pytest.mark.parametrize("reverse", [False, True])
def test_empty_inventory_and_assignments_are_exact_and_recheckable(reverse):
    source, scope, inventory = _case(reverse=reverse)
    result = build_mixed_published_binding_manifest(
        source, scope, domain_repository=_Domains(), job_repository=object(),
        binding_inventory=inventory,
    )
    assert result["domains"] == result["domainAssignments"] == []
    assert len(result["edgeTargets"]) == len(result["edgePublicIps"]) == 4
    assert {row["provider"] for row in result["edgeTargets"]} == {"linode", "digitalocean"}
    assert result == build_mixed_published_binding_manifest(
        source, scope, domain_repository=_Domains(), job_repository=object(),
        binding_inventory=inventory, expected_manifest=result,
    )


def test_owned_record_only_and_manual_record_preserved(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    zone = _Zone([owned, {"name": "manual", "type": "TXT", "address": "keep",
                         "ttl": "600", "mxPref": ""}])
    manifest = build_mixed_published_binding_manifest(
        source, scope, domain_repository=domains, job_repository=jobs,
        dns_adapter=zone, binding_inventory=inventory,
    )
    assert zone.reads == 1
    assert manifest["domains"][0]["ownedRecords"] == [
        {"ownershipId": 11, "record": owned}]
    assert "manual" not in str(manifest["domains"][0]["ownedRecords"])
    assert manifest["domains"][0]["ownedRecordsSha256"] == _digest(
        manifest["domains"][0]["ownedRecords"])
    assert build_mixed_published_binding_manifest(
        source, scope, domain_repository=domains, job_repository=jobs,
        dns_adapter=zone, binding_inventory=inventory,
        expected_manifest=manifest) == manifest


def test_provider_record_case_is_canonicalized_without_losing_receipt(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    mixed_case = {**owned, "name": "NB"}
    domains.ownership = [replace(domains.ownership[0], record=mixed_case)]
    domains.snapshot = replace(domains.snapshot, hosts=[mixed_case])
    manifest = build_mixed_published_binding_manifest(
        source, scope, domain_repository=domains, job_repository=jobs,
        dns_adapter=_Zone([mixed_case]), binding_inventory=inventory,
    )
    assert manifest["domains"][0]["ownedRecords"] == [
        {"ownershipId": 11, "record": owned}]


@pytest.mark.parametrize("changed_zone", [
    [{"name": "nb", "type": "A", "address": "198.51.100.21", "ttl": "600", "mxPref": ""},
     {"name": "alias", "type": "CNAME", "address": "nb.one.example", "ttl": "600", "mxPref": ""}],
    [{"name": "nb", "type": "A", "address": "198.51.100.21", "ttl": "600", "mxPref": ""},
     {"name": "manual", "type": "A", "address": "198.51.100.22", "ttl": "600", "mxPref": ""}],
])
def test_unowned_dependent_or_old_edge_target_blocks(tmp_path, monkeypatch, changed_zone):
    source, scope, inventory = _case()
    jobs, domains, _ = _owned_setup(tmp_path, monkeypatch)
    with pytest.raises(MixedPublishedBindingManifestAttention):
        build_mixed_published_binding_manifest(
            source, scope, domain_repository=domains, job_repository=jobs,
            dns_adapter=_Zone(changed_zone), binding_inventory=inventory,
        )


def test_foreign_active_assignment_blocks(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    domains.foreign = _assignment("another-engagement", 2)
    with pytest.raises(MixedPublishedBindingManifestAttention):
        build_mixed_published_binding_manifest(
            source, scope, domain_repository=domains, job_repository=jobs,
            dns_adapter=_Zone([owned]), binding_inventory=inventory,
        )


def test_released_domain_with_active_owned_record_blocks(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    domains.assignment = replace(
        domains.assignment, status="released",
        released_at="2026-10-19T00:01:00+00:00")
    with pytest.raises(MixedPublishedBindingManifestAttention):
        build_mixed_published_binding_manifest(
            source, scope, domain_repository=domains, job_repository=jobs,
            dns_adapter=_Zone([owned]), binding_inventory=inventory,
        )


def test_persisted_released_assignment_with_active_owned_row_blocks(tmp_path):
    from app.storage.database import db
    from app.storage.domain_repository import SqlAlchemyDomainRepository
    from app.storage.models import (
        DomainAssetModel, DomainAssignmentModel, DomainDnsRecordOwnershipModel,
        DomainDnsSnapshotModel, EngagementModel, JobRunModel,
    )

    source, scope, inventory = _case()
    state = db.configure(f"sqlite:///{tmp_path / 'released-ownership.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(
            id="eng-test", name="Test", status="deployed", owner="operator",
            template_id="small-dev", input_parameters={},
            sketch_state_schema="provider-keyed-v2"))
        db.session.add(DomainAssetModel(
            id="domain-1", domain_name="one.example", registrar="namecheap"))
        db.session.add(JobRunModel(
            id="job-dns-1", action="engagement_dns_apply", status="succeeded",
            target="engagement:eng-test", target_type="engagement",
            target_id="eng-test", requested_by="operator", input={"domainId": "domain-1"},
            artifact_refs=[]))
        db.session.flush()
        assignment = DomainAssignmentModel(
            domain_id="domain-1", engagement_id="eng-test", engagement_name="Test",
            status="released", released_at=datetime.now(timezone.utc))
        snapshot = DomainDnsSnapshotModel(
            domain_id="domain-1", provider="namecheap", hosts=[],
            sync_job_id="job-dns-1")
        db.session.add_all([assignment, snapshot])
        db.session.flush()
        db.session.add(DomainDnsRecordOwnershipModel(
            domain_id="domain-1", assignment_id=assignment.id,
            engagement_id="eng-test", creating_job_id="job-dns-1",
            snapshot_id=snapshot.id,
            record={"name": "nb", "type": "A", "address": "198.51.100.21",
                    "ttl": "600", "mxPref": ""}))
        db.session.commit()
        from app.services.engagement_teardown import _active_keyed_domain_assignments
        from app.services.provider_keyed_mixed_append_live_bindings import _owned_dns_rows

        assert _active_keyed_domain_assignments(
            "eng-test", SqlAlchemyDomainRepository()) == []
        assert len([row for row in _owned_dns_rows("eng-test")
                    if row.retired_at is None]) == 1
        with pytest.raises(MixedPublishedBindingManifestAttention):
            _build_manifest(
                source, scope, domain_repository=SqlAlchemyDomainRepository(),
                job_repository=object(), binding_inventory=inventory,
            )


def test_released_domain_with_only_retired_historical_ownership_is_empty(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    domains.assignment = replace(
        domains.assignment, status="released",
        released_at="2026-10-19T00:01:00+00:00")
    domains.ownership = [replace(
        domains.ownership[0], retired_at="2026-10-19T00:01:00+00:00")]
    result = build_mixed_published_binding_manifest(
        source, scope, domain_repository=domains, job_repository=jobs,
        dns_adapter=_Zone([owned]), binding_inventory=inventory,
    )
    assert result["domainAssignments"] == result["domains"] == []


def test_new_active_ownership_during_zone_read_blocks(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    reads = 0

    def ownership(_engagement_id):
        nonlocal reads
        reads += 1
        if reads == 1:
            return list(domains.ownership)
        return [*domains.ownership, replace(domains.ownership[0], id=12)]

    with pytest.raises(MixedPublishedBindingManifestAttention):
        build_mixed_published_binding_manifest(
            source, scope, domain_repository=domains, job_repository=jobs,
            dns_adapter=_Zone([owned]), binding_inventory=inventory,
            dns_ownership_reader=ownership,
        )
    assert reads == 2


def test_ownership_reader_target_must_match_preview_receipt(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    conflicting = replace(domains.ownership[0], record={
        **owned, "address": "198.51.100.22"})
    with pytest.raises(MixedPublishedBindingManifestAttention):
        build_mixed_published_binding_manifest(
            source, scope, domain_repository=domains, job_repository=jobs,
            dns_adapter=_Zone([owned]), binding_inventory=inventory,
            dns_ownership_reader=lambda _id: [conflicting],
        )


def test_binding_change_during_zone_read_blocks(tmp_path, monkeypatch):
    source, scope, _ = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    reads = 0

    def inventory(_id):
        nonlocal reads
        reads += 1
        if reads == 1:
            return _EMPTY
        return {**_EMPTY, "sites": (("service", "site-1", "hash"),)}

    with pytest.raises(MixedPublishedBindingManifestAttention):
        build_mixed_published_binding_manifest(
            source, scope, domain_repository=domains, job_repository=jobs,
            dns_adapter=_Zone([owned]), binding_inventory=inventory,
        )
    assert reads == 2


def test_assignment_ownership_zone_edges_and_bindings_drift_veto(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    zone = _Zone([owned])
    expected = build_mixed_published_binding_manifest(
        source, scope, domain_repository=domains, job_repository=jobs,
        dns_adapter=zone, binding_inventory=inventory,
    )
    for change in ("assignment", "ownership", "ownership_target", "zone", "edges", "bindings"):
        changed_domains = _Domains(domains.assignment, ownership=list(domains.ownership),
                                   snapshot=domains.snapshot)
        changed_source, changed_scope = source, scope
        changed_zone, changed_inventory = _Zone([owned]), inventory
        if change == "assignment":
            changed_domains.assignment = _assignment(assignment_id=3)
        elif change == "ownership":
            changed_domains.ownership = [replace(domains.ownership[0], id=12)]
        elif change == "ownership_target":
            changed_domains.ownership = [replace(
                domains.ownership[0], record={**owned, "address": "198.51.100.22"})]
        elif change == "zone":
            changed_zone = _Zone([owned, {"name": "manual", "type": "TXT",
                                          "address": "new", "ttl": "600", "mxPref": ""}])
        elif change == "edges":
            new_chain = replace(source.chains[0], nodes=[*source.chains[0].nodes[:2],
                {**source.chains[0].nodes[2], "publicIp": "8.8.2.23"}])
            changed_source = replace(source, chains=(new_chain, source.chains[1]))
            changed_scope = replace(scope, source_sha256=changed_source.source_sha256)
        else:
            changed_inventory = lambda _id: {**_EMPTY, "sites": (("service", "s1", "hash"),)}
        with pytest.raises(MixedPublishedBindingManifestAttention):
            build_mixed_published_binding_manifest(
                changed_source, changed_scope, domain_repository=changed_domains,
                job_repository=jobs, dns_adapter=changed_zone,
                binding_inventory=changed_inventory, expected_manifest=expected,
            )
