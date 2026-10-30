# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
from copy import deepcopy
from datetime import datetime, timezone

import pytest
from types import SimpleNamespace

from app.domain import JobEvent
from app.services import engagement_teardown
from app.services import provider_keyed_teardown_scope
from app.services.observer_checks import InspectorAddressCollisionError
from app.services.engagement_lifecycle import resolve_engagement_lifecycle
from app.storage.job_repository import SqliteJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


class ChainRepository:
    def __init__(self, chains: list[StoredSketchChain]):
        self.chains = {(chain.engagement_id, chain.chain_id): chain for chain in chains}

    def list_for_engagement(self, engagement_id: str):
        return [chain for (owner, _), chain in self.chains.items() if owner == engagement_id]

    def get(self, engagement_id: str, chain_id: str):
        return self.chains.get((engagement_id, chain_id))

    def save(self, chain: StoredSketchChain):
        self.chains[(chain.engagement_id, chain.chain_id)] = chain
        return chain


class ResourceRepository:
    def __init__(self, records=None):
        self.records = list(records or [])

    def list_for_engagement(self, engagement_id: str):
        return [record for record in self.records if record.engagement_id == engagement_id]

    def save(self, record):
        self.records = [existing for existing in self.records if existing.id != record.id] + [record]
        return record


class DomainRepository:
    def __init__(self, assignments=(), assets=(), extra_active=()):
        self.assignments = list(assignments)
        self.assets = {asset.id: asset for asset in assets}
        self.extra_active = list(extra_active)

    def list_assignments(self, domain_id=None, engagement_id=None):
        rows = [*self.assignments, *self.extra_active]
        if domain_id is not None:
            return [row for row in rows if row.domain_id == domain_id]
        if engagement_id is not None:
            return [row for row in self.assignments if row.engagement_id == engagement_id]
        return rows

    def get_asset(self, domain_id):
        return self.assets.get(domain_id)

    def list_snapshots(self, _domain_id):
        return []

    def list_record_ownership(self, _domain_id, *, active_only=False):
        return []


def _domain_assignment(identifier=1, domain_id="domain-1", engagement_id="eng-1"):
    return SimpleNamespace(id=identifier, domain_id=domain_id, engagement_id=engagement_id,
                           status="active")


def _domain_asset(domain_id="domain-1", name="alpha.example", registrar="namecheap"):
    return SimpleNamespace(id=domain_id, domain_name=name, registrar=registrar)


def _keyed_review_scope(core_id="job-core-1"):
    return {
        "schema": "provider-keyed-v2", "provider": "digitalocean",
        "coreJobId": core_id, "corePlanId": "plan-opaque", "revisionId": "revision-opaque",
        "providerConnectionId": "connection-opaque", "workspace": "/private/provider-workspace",
        "sourceRevision": "a" * 40, "selectorTag": "opaque-selector",
        "stateSha256": "b" * 64, "chainIds": ["chain-a", "chain-b"],
        "chainFingerprints": {"chain-a": "c" * 64, "chain-b": "d" * 64},
        "resources": [
            {"address": 'digitalocean_droplet.edge["sea-01"]', "id": "101", "kind": "droplet"},
            {"address": "digitalocean_firewall.firewall", "id": "fw-opaque", "kind": "firewall"},
            {"address": "digitalocean_ssh_key.key", "id": "key-opaque", "kind": "ssh_key"},
            {"address": "local_file.ansible_inventory[0]", "id": "/private/inventory", "kind": "local_file"},
            {"address": "local_file.ssh_stanza[0]", "id": "/private/stanza", "kind": "local_file"},
        ],
    }


def _save_keyed_core_with_host_binding(jobs, monkeypatch):
    from app.services import provider_keyed_dns_cleanup_manifest
    from app.services.provider_keyed_host_binding import _digest_json
    from app.services.provider_keyed_initial_continuation import _job_ids

    class ManualZone:
        def get_hosts(self, _domain_name):
            return [{"name": "note", "type": "TXT", "address": "private sentinel",
                     "ttl": "600"}]

        def set_hosts(self, *_args):
            pytest.fail("read-only teardown preview called setHosts")

    monkeypatch.setattr(provider_keyed_dns_cleanup_manifest, "_namecheap_dns_client",
                        lambda: ManualZone())
    scope = _keyed_review_scope()
    core = replace(core_job(), input={**core_job().input,
        "sketchStateSchema": "provider-keyed-v2", "corePlanId": scope["corePlanId"]})
    jobs.save(core)
    manifest = {"schema": "provider-keyed-v2", "engagementId": "eng-1",
        **{key: scope[key] for key in ("coreJobId", "corePlanId", "revisionId",
                                     "stateSha256", "sourceRevision", "providerConnectionId")},
        "chainFingerprints": [{"chainId": chain_id, "fingerprint": scope["chainFingerprints"][chain_id]}
                              for chain_id in scope["chainIds"]],
        "nodes": [{"terraformAddress": scope["resources"][0]["address"],
                   "providerInstanceId": "101", "role": "edge",
                   "chainId": "chain-a", "publicIp": "8.8.8.8"}],
    }
    initial = replace(core, id=_job_ids(core.id)[0], action="provider_keyed_initial",
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        status="running", finished_at=None,
        input={"coreJobId": core.id, "corePlanId": scope["corePlanId"]},
        events=[JobEvent(1, "info", "provider host identity binding intended", manifest),
                JobEvent(2, "info", "provider host identity bound",
                         {"manifestSha256": _digest_json(manifest), "hostProofPending": True})])
    jobs.save(initial)
    return core


def core_job(*, status="succeeded", events=None):
    now = datetime.now(timezone.utc).isoformat()
    return StoredJobRun(
        id="job-core-1",
        action="pilot_standard_rti_guarded_execute",
        status=status,
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="example_operator_three",
        input={"engagementId": "eng-1", "engagementName": "Cleanup Test", "workspaceDir": "/tmp/workspace", "proxyCount": 2},
        artifact_refs=[],
        created_at=now,
        started_at=now,
        finished_at=now if status not in {"queued", "running"} else None,
        events=list(events or [JobEvent(1, "info", "deployment complete", {"finalCleanupStatus": "pending_operator_teardown", "mutationStatus": "deployed"})]),
    )


def failed_comprehensive_teardown(job_id="job-teardown-failed", *, cleanup="cleanup_not_verified"):
    now = datetime.now(timezone.utc).isoformat()
    scope = {
        "engagementId": "eng-1", "engagementName": "Cleanup Test", "coreJobId": "job-core-1",
        "snapshotId": "snapshot-1", "confirmationPhrase": "teardown-Cleanup-Test",
        "chains": [], "ownedProviderRecordIds": [], "excludedUnmanagedProviderRecords": [],
        "core": {"jobId": "job-core-1", "workspace": "/tmp/workspace", "proxyCount": 2},
        "publicVerificationTargets": [],
        "inspector": {"tracked": False, "ownedProviderRecordIds": [], "recordOwners": {}, "verificationTargetCount": 0},
    }
    return StoredJobRun(
        id=job_id, action="engagement_comprehensive_teardown", status="failed",
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        requested_by="example_operator_three", input={"engagementId": "eng-1", "coreJobId": "job-core-1", "scopeSnapshot": scope},
        artifact_refs=[], created_at=now, started_at=now, finished_at=now,
        events=[JobEvent(1, "error", "engagement teardown requires cleanup", {"finalCleanupStatus": cleanup})],
    )


@pytest.mark.parametrize("cleanup", ["cleanup_not_verified", "verified_clean"])
def test_core_creation_fence_requires_exact_failed_parent_recovery(tmp_path, cleanup):
    jobs = SqliteJobRepository(tmp_path / "core-creation-fence.sqlite")
    parent = failed_comprehensive_teardown(cleanup=cleanup)
    jobs.save(parent)

    with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
        engagement_teardown.assert_core_creation_allowed("eng-1", repository=jobs)

    assert exc.value.errors == [
        "engagement cleanup recovery is required through comprehensive teardown "
        "job-teardown-failed before creating core infrastructure"
    ]


def test_core_creation_fence_uses_newest_comprehensive_parent(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "core-creation-newest.sqlite")
    older = replace(failed_comprehensive_teardown("job-old"), created_at="2026-01-01T00:00:00+00:00")
    recovered = replace(
        failed_comprehensive_teardown("job-recovered", cleanup="verified_clean"),
        status="succeeded", created_at="2026-01-02T00:00:00+00:00",
        input={**failed_comprehensive_teardown().input, "remainingOwnedResources": []},
        events=[JobEvent(1, "info", "engagement lifecycle reconciled", {
            "state": "destroyed", "finalCleanupStatus": "verified_clean",
        })],
    )
    jobs.save(older)
    jobs.save(recovered)

    engagement_teardown.assert_core_creation_allowed("eng-1", repository=jobs, lifecycle_state="destroyed")


def test_core_creation_fence_rejects_succeeded_incomplete_parent(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "core-creation-incomplete.sqlite")
    jobs.save(replace(failed_comprehensive_teardown(), status="succeeded"))

    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown.assert_core_creation_allowed("eng-1", repository=jobs, lifecycle_state="cleanup_required")


@pytest.mark.parametrize("state", ["cleanup_required", "tearing_down"])
def test_core_creation_fence_rejects_recovery_lifecycle_without_parent(tmp_path, state):
    jobs = SqliteJobRepository(tmp_path / f"core-creation-{state}.sqlite")

    with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
        engagement_teardown.assert_core_creation_allowed("eng-1", repository=jobs, lifecycle_state=state)

    assert "comprehensive teardown missing" in exc.value.errors[0]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda parent: replace(parent, input={}),
        lambda parent: replace(parent, input={**parent.input, "scopeSnapshot": []}),
        lambda parent: replace(parent, target_id="eng-other"),
        lambda parent: replace(parent, input={**parent.input, "coreJobId": ""}),
        lambda parent: replace(parent, input={**parent.input, "scopeSnapshot": {**parent.input["scopeSnapshot"], "snapshotId": ""}}),
    ],
)
def test_malformed_comprehensive_parent_is_blocked_and_preview_fails_controlled(tmp_path, mutation):
    jobs = SqliteJobRepository(tmp_path / "malformed-parent.sqlite")
    jobs.save(core_job())
    parent = mutation(failed_comprehensive_teardown())
    jobs.save(parent)

    assert engagement_teardown.comprehensive_teardown_recovery_state(parent) == "blocked"
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
        engagement_teardown.preview_engagement_teardown(parent.id, job_repository=jobs)
    assert exc.value.errors == ["comprehensive teardown recovery boundary is invalid"]


@pytest.mark.parametrize("core_value", [
    None,
    replace(core_job(), action="infra_orientation_refresh"),
    replace(core_job(), input={"engagementId": "eng-other"}),
])
def test_parent_preview_requires_exact_same_engagement_guarded_core(tmp_path, core_value):
    jobs = SqliteJobRepository(tmp_path / "wrong-core.sqlite")
    if core_value is not None:
        jobs.save(core_value)
    parent = failed_comprehensive_teardown()
    jobs.save(parent)

    with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
        engagement_teardown.preview_engagement_teardown(parent.id, job_repository=jobs)
    assert exc.value.errors == ["comprehensive teardown recovery core boundary is invalid"]


def test_parent_preview_accepts_provider_targeted_core_job_bound_by_input_engagement(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "provider-target-core.sqlite")
    jobs.save(replace(
        core_job(),
        target="oci-compartment:barragan-testing",
        target_type="oci_compartment",
        target_id="ocid1.compartment.oc1..reviewedfixture",
    ))
    parent = failed_comprehensive_teardown()
    jobs.save(parent)

    preview = engagement_teardown.preview_engagement_teardown(
        parent.id,
        job_repository=jobs,
        sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository(),
    )

    assert preview["parentJobId"] == parent.id
    assert preview["snapshotId"] == parent.input["scopeSnapshot"]["snapshotId"]


@pytest.mark.parametrize(
    "path,value",
    [
        (("chains",), [{"chainId": "chain-1"}]),
        (("ownedProviderRecordIds",), ["record-1", "record-1"]),
        (("ownedProviderRecordIds",), [" record-1"]),
        (("excludedUnmanagedProviderRecords",), ["manual-1 "]),
        (("publicVerificationTargets",), [{"id": "tcp-1", "type": "tcp-forbidden", "host": "198.51.100.1", "port": True}]),
        (("publicVerificationTargets",), [{"id": " tcp-1", "type": "tcp-forbidden", "host": "198.51.100.1", "port": 22}]),
        (("publicVerificationTargets",), [{"id": "tcp-1", "type": "tcp-forbidden", "host": " 198.51.100.1", "port": 22}]),
        (("publicVerificationTargets",), [{"id": "dns-1", "type": "dns-absent", "host": "Example.COM", "expectedIp": "198.51.100.1"}]),
        (("publicVerificationTargets",), [{"id": "dns-1", "type": "dns-absent", "host": "example.com", "expectedIp": " 198.51.100.1"}]),
        (("publicVerificationTargets",), [
            {"id": "dns-1", "type": "dns-absent", "host": "example.com", "expectedIp": "198.51.100.1"},
            {"id": "dns-2", "type": "dns-absent", "host": "example.com", "expectedIp": "198.51.100.1"},
        ]),
        (("publicVerificationTargets",), [{"id": "tcp-1", "type": "tcp-forbidden", "host": "198.51.100.1", "port": 22, "unexpected": "x"}]),
        (("chains",), [{
            "chainId": "chain-1", "assignedProxy": "proxy01", "status": "deployed", "deployJobId": "job-1",
            "alreadyClean": False, "outboundChannelIds": [], "middle": {"provider": "linode", "region": "us-east"},
            "edges": [
                {"id": "edge-1", "provider": "linode", "region": "us-east"},
                {"id": "edge-1", "provider": "linode", "region": "us-west"},
            ],
        }]),
        (("chains",), [{
            "chainId": " chain-1", "assignedProxy": "proxy01", "status": "deployed", "deployJobId": "job-1",
            "alreadyClean": False, "outboundChannelIds": [], "middle": {"provider": "linode", "region": "us-east"},
            "edges": [{"id": "edge-1", "provider": "linode", "region": "us-east"}],
        }]),
        (("chains",), [{
            "chainId": "chain-1", "assignedProxy": "proxy01", "status": "deployed", "deployJobId": "job-1",
            "alreadyClean": False, "outboundChannelIds": [" channel-1"], "middle": {"provider": "linode", "region": "us-east"},
            "edges": [{"id": "edge-1", "provider": "linode", "region": "us-east"}],
        }]),
        (("chains",), [{
            "chainId": "chain-1", "assignedProxy": "proxy01", "status": "deployed", "deployJobId": "job-1",
            "alreadyClean": False, "outboundChannelIds": [], "middle": {"provider": " linode", "region": "us-east"},
            "edges": [{"id": "edge-1", "provider": "linode", "region": "us-east"}],
        }]),
        (("chains",), [{
            "chainId": "chain-1", "assignedProxy": "proxy01", "status": "deployed", "deployJobId": "job-1",
            "alreadyClean": False, "outboundChannelIds": [], "middle": {"provider": "linode", "region": "us-east"},
            "edges": [{"id": " edge-1", "provider": "linode", "region": "us-east"}],
        }]),
        (("inspector", "verificationTargetCount"), 1),
        (("inspector", "tracked"), "false"),
        (("inspector", "recordOwners"), {"record-1": False}),
        (("inspector", "ownedProviderRecordIds"), [" inspector-1"]),
        (("inspector", "recordOwners"), {" inspector-1": "job-inspector"}),
        (("inspector", "recordOwners"), {"inspector-1": " job-inspector"}),
        (("core", "proxyCount"), True),
        (("core", "workspace"), None),
    ],
)
def test_nested_malformed_snapshot_blocks_preview_and_start_before_dispatch(tmp_path, path, value):
    jobs = SqliteJobRepository(tmp_path / "nested-malformed.sqlite")
    jobs.save(core_job())
    parent = failed_comprehensive_teardown()
    parent_input = deepcopy(parent.input)
    node = parent_input["scopeSnapshot"]
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    parent = replace(parent, input=parent_input)
    jobs.save(parent)
    dispatches = []

    assert engagement_teardown.comprehensive_teardown_recovery_state(parent) == "blocked"
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown.preview_engagement_teardown(parent.id, job_repository=jobs)
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown.start_engagement_teardown(
            parent.id, {"confirmation": "anything", "snapshotId": "anything"},
            job_repository=jobs, chain_dispatcher=lambda *_args: dispatches.append("chain"),
            core_dispatcher=lambda *_args: dispatches.append("core"),
            inspector_preflight=lambda *_args: dispatches.append("inspector"),
        )
    assert dispatches == []


def test_valid_public_target_inventory_is_preserved_one_for_one_by_canonicalization():
    targets = [
        {"id": "tcp-1", "type": "tcp-forbidden", "host": "198.51.100.1", "port": 22, "targetGroup": "sketch-public-management"},
        {"id": "dns-1", "type": "dns-absent", "host": "example.com", "expectedIp": "198.51.100.1"},
    ]
    assert engagement_teardown._valid_public_targets(targets)
    assert len(engagement_teardown.canonical_teardown_targets(targets)) == len(targets)


@pytest.mark.parametrize(
    "path,value",
    [
        (("chainId",), "chain-1 "),
        (("assignedProxy",), " proxy01"),
        (("deployJobId",), "job-1 "),
        (("outboundChannelIds",), ["channel-1 "]),
        (("middle", "provider"), " linode"),
        (("middle", "region"), "us-east "),
        (("edges", 0, "id"), " edge-1"),
        (("edges", 0, "provider"), "linode "),
        (("edges", 0, "region"), " us-east"),
    ],
)
def test_snapshot_chain_identity_strings_must_be_canonical(path, value):
    chain = {
        "chainId": "chain-1", "assignedProxy": "proxy01", "status": "deployed", "deployJobId": "job-1",
        "alreadyClean": False, "outboundChannelIds": ["channel-1"],
        "middle": {"provider": "linode", "region": "us-east"},
        "edges": [{"id": "edge-1", "provider": "linode", "region": "us-east"}],
    }
    node = chain
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value

    assert engagement_teardown._valid_snapshot_chains([chain]) is False


def test_snapshot_chain_requires_deploy_job_id_and_accepts_pending_empty_sentinel():
    chain_row = {
        "chainId": "chain-1", "assignedProxy": "proxy01", "status": "pending", "deployJobId": "",
        "alreadyClean": True, "outboundChannelIds": [],
        "middle": {"provider": "linode", "region": "us-east"},
        "edges": [{"id": "edge-1", "provider": "linode", "region": "us-east"}],
    }
    assert engagement_teardown._valid_snapshot_chains([chain_row]) is True
    del chain_row["deployJobId"]
    assert engagement_teardown._valid_snapshot_chains([chain_row]) is False


def chain(chain_id: str, proxy: str, *, status="deployed"):
    now = datetime.now(timezone.utc).isoformat()
    return StoredSketchChain(
        chain_id=chain_id,
        engagement_id="eng-1",
        assigned_proxy=proxy,
        middle_provider="linode",
        middle_region="us-east",
        middle_size="g6-standard-1",
        edge_provider="digitalocean",
        edge_region="sfo3",
        edge_size="s-1vcpu-1gb",
        edge_count=2,
        edge_intents=[
            {"id": "edge-01", "provider": "digitalocean", "region": "sfo3"},
            {"id": "edge-02", "provider": "digitalocean", "region": "nyc3"},
        ],
        status=status,
        burned=False,
        burned_note="",
        deploy_job_id=f"job-deploy-{chain_id}",
        teardown_job_id="",
        terraform_working_directory=f"/tmp/{chain_id}",
        nodes=[{"role": "middle"}, {"role": "edge"}, {"role": "edge"}],
        created_at=now,
        updated_at=now,
    )


def clean_core(job: StoredJobRun) -> StoredJobRun:
    return replace(
        job,
        status="succeeded",
        finished_at=datetime.now(timezone.utc).isoformat(),
        events=job.events
        + [
            JobEvent(len(job.events) + 1, "info", "operator teardown requested", {}),
            JobEvent(
                len(job.events) + 2,
                "info",
                "pilot Standard RTI teardown finished",
                {
                    "finalCleanupStatus": "verified_clean",
                    "coreCleanupStatus": "verified_clean",
                    "ok": True,
                    "mutationStatus": "destroyed",
                    "verificationTargetSha256": engagement_teardown.teardown_target_sha256([]),
                    "inspectorTeardownVerification": {"ok": True, "targetCount": 0, "targets": [], "inspectorHost": {}},
                    "inspectorCleanup": {"ok": True, "cleanupVerified": True, "currentHostCleared": True, "inspectorHost": {}},
                },
            )
        ],
    )


PUBLIC_TEARDOWN_TARGET = {
    "id": "edge-public-management",
    "type": "tcp-forbidden",
    "host": "203.0.113.50",
    "port": 22,
    "targetGroup": "sketch-public-management",
}


def test_teardown_target_digest_is_order_independent():
    dns = {"id": "dns:old.example", "type": "dns-absent", "host": "old.example", "expectedIp": "203.0.113.50"}
    assert engagement_teardown.teardown_target_sha256([PUBLIC_TEARDOWN_TARGET, dns]) == \
        engagement_teardown.teardown_target_sha256([dns, PUBLIC_TEARDOWN_TARGET])


def public_core_job() -> StoredJobRun:
    return core_job(
        events=[JobEvent(1, "info", "deployment complete", {"publicVerificationTargets": [PUBLIC_TEARDOWN_TARGET]})]
    )


def clean_public_core(job: StoredJobRun) -> StoredJobRun:
    host = {"provider": "linode", "resourceType": "instance", "resourceId": "inspector-1"}
    return replace(
        job,
        status="succeeded",
        finished_at=datetime.now(timezone.utc).isoformat(),
        events=job.events
        + [
            JobEvent(len(job.events) + 1, "info", "operator teardown requested", {}),
            JobEvent(
                len(job.events) + 2,
                "info",
                "pilot Standard RTI teardown finished",
                {
                    "finalCleanupStatus": "verified_clean",
                    "coreCleanupStatus": "verified_clean",
                    "ok": True,
                    "mutationStatus": "destroyed",
                    "verificationTargetSha256": engagement_teardown.teardown_target_sha256([PUBLIC_TEARDOWN_TARGET]),
                    "inspectorTeardownVerification": {
                        "ok": True,
                        "targetCount": 1,
                        "targets": [PUBLIC_TEARDOWN_TARGET],
                        "inspectorHost": host,
                    },
                    "inspectorCleanup": {"ok": True, "cleanupVerified": True, "currentHostCleared": True, "inspectorHost": host},
                },
            )
        ],
    )


def test_zero_target_completion_accepts_cleanup_of_retained_inspector():
    host = {"provider": "linode", "resourceType": "instance", "resourceId": "retained"}
    job = core_job(events=[JobEvent(1, "info", "operator teardown requested", {}), JobEvent(2, "info", "pilot Standard RTI teardown finished", {
        "ok": True, "coreCleanupStatus": "verified_clean",
        "mutationStatus": "destroyed", "finalCleanupStatus": "verified_clean",
        "verificationTargetSha256": engagement_teardown.teardown_target_sha256([]),
        "inspectorTeardownVerification": {"ok": True, "targetCount": 0, "targets": [], "inspectorHost": {}},
        "inspectorCleanup": {"ok": True, "cleanupVerified": True, "currentHostCleared": True, "inspectorHost": host},
    })])
    assert engagement_teardown._core_verified(job, [])


def test_core_verified_rejects_malformed_or_conflicting_newest_attempt_evidence():
    valid = clean_public_core(public_core_job())
    terminal = valid.events[-1]
    cases = [
        replace(valid, status="failed"),
        replace(valid, events=[terminal]),
        replace(valid, events=[*valid.events[:-1], replace(terminal, level="error")]),
        replace(valid, events=[*valid.events[:-1], replace(terminal, data={**terminal.data, "ok": False})]),
        replace(valid, events=[*valid.events[:-1], replace(terminal, data={**terminal.data, "inspectorTeardownVerification": {**terminal.data["inspectorTeardownVerification"], "targetCount": True}})]),
        replace(valid, events=[*valid.events[:-1], replace(terminal, data={**terminal.data, "inspectorTeardownVerification": {**terminal.data["inspectorTeardownVerification"], "targets": {"bad": "value"}}})]),
        replace(valid, events=[*valid.events[:-1], replace(terminal, data={**terminal.data, "inspectorTeardownVerification": {**terminal.data["inspectorTeardownVerification"], "targets": ["bad"]}})]),
        replace(valid, events=[*valid.events, replace(terminal, sequence=terminal.sequence + 1)]),
        replace(valid, events=[*valid.events, JobEvent(terminal.sequence + 1, "info", "operator teardown requested", {})]),
        replace(valid, events=[*valid.events[:-1], replace(terminal, data={
            **terminal.data,
            "inspectorTeardownVerification": {**terminal.data["inspectorTeardownVerification"], "inspectorHost": {}},
            "inspectorCleanup": {**terminal.data["inspectorCleanup"], "inspectorHost": {}},
        })]),
        replace(valid, events=[*valid.events[:-1], replace(terminal, data={
            **terminal.data,
            "inspectorCleanup": {**terminal.data["inspectorCleanup"], "inspectorHost": {
                "provider": "linode", "resourceType": "instance", "resourceId": "different",
            }},
        })]),
    ]
    assert all(not engagement_teardown._core_verified(candidate, [PUBLIC_TEARDOWN_TARGET]) for candidate in cases)


@pytest.fixture()
def repositories(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    jobs.save(core_job())
    chains = ChainRepository([chain("proxy01-chain", "proxy01"), chain("proxy02-chain", "proxy02")])
    resources = ResourceRepository()
    monkeypatch.setattr(
        engagement_teardown,
        "reconcile_engagement_lifecycle",
        lambda *_args, **_kwargs: {"current": {"state": "destroyed"}},
    )
    return jobs, chains, resources


def test_preview_is_ordered_and_snapshots_two_mixed_multi_edge_chains(repositories):
    jobs, chains, resources = repositories
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )

    assert preview is not None
    assert preview["confirmationPhrase"] == "teardown-cleanup-test"
    assert [row["id"] for row in preview["orderedScope"]] == [
        "outbound", "sketch", "core", "inspector-verify", "inspector-cleanup"
    ]
    sketch_rows = preview["orderedScope"][1]["items"]
    assert [row["assignedProxy"] for row in sketch_rows] == ["proxy01", "proxy02"]
    assert all(len(row["edges"]) == 2 for row in sketch_rows)
    assert preview["snapshotId"]


def test_active_inspector_insert_barrier_vetoes_teardown_before_dispatch(repositories):
    jobs, chains, resources = repositories
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains,
        provider_resource_repository=resources,
    )
    now = datetime.now(timezone.utc).isoformat()
    jobs.save(StoredJobRun(
        id="job-active-inspector", action="inspector_readiness", status="running",
        target="engagement:eng-1", target_type="engagement", target_id="eng-1",
        requested_by="operator", input={}, artifact_refs=[], created_at=now,
        started_at=now, finished_at=None,
        events=[JobEvent(1, "info", "readiness started", {})],
    ))
    dispatched = []
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown.start_engagement_teardown(
            "job-core-1",
            {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
            job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
            chain_dispatcher=lambda *_: dispatched.append("chain"),
            outbound_dispatcher=lambda *_: dispatched.append("outbound"),
            core_dispatcher=lambda *_: dispatched.append("core"),
            background_runner=lambda task: task(),
        )
    assert dispatched == []
    assert jobs.get("job-engagement-teardown-core-1") is None


def test_parent_cleans_sketch_before_core_and_finishes_verified(repositories):
    jobs, chains, resources = repositories
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    calls = []

    def dispatch_chain(engagement_id, chain_id, _body):
        calls.append(f"chain:{chain_id}")
        current = chains.get(engagement_id, chain_id)
        chains.save(replace(current, status="destroyed", nodes=[]))
        return {"chain": chains.get(engagement_id, chain_id).to_dict(), "job": None}

    def dispatch_core(core_id, _targets):
        calls.append("core")
        jobs.save(clean_core(jobs.get(core_id)))

    parent = engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        chain_dispatcher=dispatch_chain,
        outbound_dispatcher=lambda _engagement_id, chain_id, _requested_by: calls.append(f"outbound:{chain_id}"),
        core_dispatcher=dispatch_core,
        background_runner=lambda task: task(),
        wait=lambda _seconds: None,
    )

    assert calls == ["outbound:proxy01-chain", "outbound:proxy02-chain", "chain:proxy01-chain", "chain:proxy02-chain", "core"]
    assert parent.status == "succeeded"
    assert parent.input["remainingOwnedResources"] == []
    assert parent.events[-1].data["finalCleanupStatus"] == "verified_clean"


def test_chain_failure_stops_before_core_and_names_remaining_resource(repositories):
    jobs, chains, resources = repositories
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    core_calls = []

    def fail_chain(_engagement_id, chain_id, _body):
        raise RuntimeError(f"failed {chain_id}")

    parent = engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        chain_dispatcher=fail_chain,
        outbound_dispatcher=lambda *_args: None,
        core_dispatcher=lambda core_id, _targets: core_calls.append(core_id),
        background_runner=lambda task: task(),
    )

    assert parent.status == "failed"
    assert core_calls == []
    assert parent.input["remainingOwnedResources"] == ["sketch_chain:proxy01-chain"]


def test_public_target_inspector_preflight_completes_before_destructive_cleanup(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "preflight.sqlite")
    jobs.save(public_core_job())
    chains = ChainRepository([chain("proxy01-chain", "proxy01")])
    resources = ResourceRepository()
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: {"current": {"state": "destroyed"}})
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    calls = []

    def dispatch_chain(engagement_id, chain_id, _body):
        calls.append(f"chain:{chain_id}")
        current = chains.get(engagement_id, chain_id)
        chains.save(replace(current, status="destroyed", nodes=[]))
        return {"chain": chains.get(engagement_id, chain_id).to_dict(), "job": None}

    def dispatch_core(core_id, targets):
        calls.append("core")
        assert targets == [PUBLIC_TEARDOWN_TARGET]
        jobs.save(clean_public_core(jobs.get(core_id)))

    parent = engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        inspector_preflight=lambda *_args: calls.append("inspector-preflight") or {
            "ok": True,
            "status": "created_prepared",
            "inspectorHost": {"resourceId": "inspector-1"},
        },
        outbound_dispatcher=lambda _engagement_id, chain_id, _requested_by: calls.append(f"outbound:{chain_id}"),
        chain_dispatcher=dispatch_chain,
        core_dispatcher=dispatch_core,
        background_runner=lambda task: task(),
        wait=lambda _seconds: None,
    )

    assert parent.status == "succeeded"
    assert calls == ["inspector-preflight", "outbound:proxy01-chain", "chain:proxy01-chain", "core"]


def test_parent_collision_failure_retains_inspector_and_dispatches_nothing(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "collision-parent.sqlite")
    jobs.save(public_core_job())
    chains = ChainRepository([chain("proxy01-chain", "proxy01")])
    retained = SimpleNamespace(
        id="linode:inspector:retained", engagement_id="eng-1", status="active",
        resource_type="inspector_instance", adoption_job_id="job-original",
        metadata={"barraganOwned": True, "role": "inspector"},
    )
    resources = ResourceRepository([retained])
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: {"current": {"state": "cleanup_required"}})
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
    )
    calls = []
    parent = engagement_teardown.start_engagement_teardown(
        "job-core-1", {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        inspector_preflight=lambda *_args: (_ for _ in ()).throw(InspectorAddressCollisionError([PUBLIC_TEARDOWN_TARGET["id"]])),
        outbound_dispatcher=lambda *_args: calls.append("outbound"),
        chain_dispatcher=lambda *_args: calls.append("chain"), core_dispatcher=lambda *_args: calls.append("core"),
        background_runner=lambda task: task(),
    )
    assert parent.status == "failed"
    assert calls == []
    assert resources.records[0].status == "active"
    assert parent.input["scopeSnapshot"]["publicVerificationTargets"] == [PUBLIC_TEARDOWN_TARGET]
    outcome = parent.input["outcomes"]["inspectorPreflight"]
    assert outcome["failureClass"] == "retired_target_address_reuse"
    assert outcome["nextAction"] == "Run dedicated Inspector Cleanup, then explicitly retry teardown"


def test_unconfirmed_active_targets_fail_before_any_teardown_mutation(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "scope-boundary.sqlite")
    jobs.save(public_core_job())
    chains = ChainRepository([chain("proxy01-chain", "proxy01")])
    resources = ResourceRepository()
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: {"current": {"state": "cleanup_required"}})
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    tasks = []
    calls = []
    engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        inspector_preflight=lambda *_args: calls.append("inspector"),
        outbound_dispatcher=lambda *_args: calls.append("outbound"),
        chain_dispatcher=lambda *_args: calls.append("chain"),
        core_dispatcher=lambda *_args: calls.append("core"),
        background_runner=tasks.append,
    )
    chains.chains[("eng-1", "new-chain")] = chain("new-chain", "proxy02")
    resources.records.append(
        SimpleNamespace(
            id="owned-new", engagement_id="eng-1", status="active", metadata={"barraganOwned": True}
        )
    )

    tasks[0]()

    parent = jobs.get("job-engagement-teardown-core-1")
    assert parent.status == "failed"
    assert calls == []
    assert parent.input["remainingOwnedResources"] == [
        "unconfirmed_sketch_chain:new-chain",
        "unconfirmed_owned_provider_resource:owned-new",
    ]


def test_concurrent_inspector_is_not_absorbed_into_confirmed_cleanup(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "concurrent-inspector.sqlite")
    jobs.save(public_core_job())
    chains = ChainRepository([chain("proxy01-chain", "proxy01")])
    resources = ResourceRepository()
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: {"current": {"state": "cleanup_required"}})
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    calls = []

    def concurrent_preflight(*_args):
        resources.save(
            SimpleNamespace(
                id="linode:inspector:foreign",
                engagement_id="eng-1",
                status="active",
                metadata={"barraganOwned": True, "role": "inspector"},
                resource_type="inspector_instance",
                adoption_job_id="job-other-inspection",
            )
        )
        return {"ok": True, "status": "created_prepared", "inspectorHost": {"resourceId": "foreign"}}

    parent = engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        inspector_preflight=concurrent_preflight,
        outbound_dispatcher=lambda *_args: calls.append("outbound"),
        chain_dispatcher=lambda *_args: calls.append("chain"),
        core_dispatcher=lambda *_args: calls.append("core"),
        background_runner=lambda task: task(),
    )

    assert parent.status == "failed"
    assert calls == []
    assert parent.input["remainingOwnedResources"] == [
        "unconfirmed_owned_provider_resource:linode:inspector:foreign"
    ]


def test_failed_inspector_preflight_is_retryable_without_broadening_confirmed_scope(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "preflight-retry.sqlite")
    jobs.save(public_core_job())
    chains = ChainRepository([chain("proxy01-chain", "proxy01")])
    original_resource = SimpleNamespace(
        id="owned-original", engagement_id="eng-1", status="active", metadata={"barraganOwned": True}
    )
    resources = ResourceRepository([original_resource])
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: {"current": {"state": "cleanup_required"}})
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    destructive_calls = []
    body = {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]}

    failed = engagement_teardown.start_engagement_teardown(
        "job-core-1",
        body,
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        inspector_preflight=lambda *_args: (_ for _ in ()).throw(RuntimeError("preparation failed")),
        outbound_dispatcher=lambda *_args: destructive_calls.append("outbound"),
        chain_dispatcher=lambda *_args: destructive_calls.append("chain"),
        core_dispatcher=lambda *_args: destructive_calls.append("core"),
        background_runner=lambda task: task(),
    )

    assert failed.status == "failed"
    assert failed.input["phase"] == "cleanup_required"
    assert destructive_calls == []

    chains.chains[("eng-1", "new-chain")] = chain("new-chain", "proxy02")
    resources.records.append(
        SimpleNamespace(
            id="owned-new", engagement_id="eng-1", status="active", metadata={"barraganOwned": True}
        )
    )
    jobs.save(
        replace(
            jobs.get("job-core-1"),
            events=jobs.get("job-core-1").events
            + [
                JobEvent(
                    2,
                    "info",
                    "late endpoint",
                    {"publicVerificationTargets": [{**PUBLIC_TEARDOWN_TARGET, "id": "late", "host": "203.0.113.51"}]},
                )
            ],
        )
    )
    tasks = []
    current_preview = engagement_teardown.preview_engagement_teardown(
        failed.id,
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        inspector_state_reader=lambda _engagement_id: {"tracked": True, "reusable": True, "status": "running"},
    )
    retried = engagement_teardown.start_engagement_teardown(
        failed.id,
        {"confirmation": current_preview["confirmationPhrase"], "snapshotId": current_preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        inspector_state_reader=lambda _engagement_id: {"tracked": True, "reusable": True, "status": "running"},
        background_runner=tasks.append,
    )

    scope = retried.input["scopeSnapshot"]
    assert retried.status == "queued"
    assert retried.finished_at is None
    assert [row["chainId"] for row in scope["chains"]] == ["proxy01-chain"]
    assert scope["ownedProviderRecordIds"] == ["owned-original"]
    assert scope["publicVerificationTargets"] == [PUBLIC_TEARDOWN_TARGET]
    assert scope["inspector"]["tracked"] is True
    assert len(tasks) == 1


def test_duplicate_start_reuses_live_parent_claim(repositories):
    jobs, chains, resources = repositories
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    queued = []
    body = {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]}
    first = engagement_teardown.start_engagement_teardown(
        "job-core-1", body, job_repository=jobs, sketch_repository=chains,
        provider_resource_repository=resources, background_runner=queued.append,
    )
    first_token = first.input["claimToken"]
    second = engagement_teardown.start_engagement_teardown(
        "job-core-1", body, job_repository=jobs, sketch_repository=chains,
        provider_resource_repository=resources, background_runner=queued.append,
    )

    assert first.id == second.id
    assert second.input["claimToken"] == first_token
    assert len(queued) == 1


@pytest.mark.parametrize("stale_expiry", ["2000-01-01T00:00:00+00:00", "not-a-date", None])
def test_recovery_reclaims_expired_foreign_parent_claim_and_launches_fresh_worker(repositories, stale_expiry):
    jobs, chains, resources = repositories
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1",
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
    )
    abandoned_tasks = []
    queued = engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        background_runner=abandoned_tasks.append,
    )
    assert queued is not None and len(abandoned_tasks) == 1

    leases, prefix = engagement_teardown._core_mutation_leases(jobs)
    lease_key = f"{prefix}eng-1"
    leases.release(lease_key, str(queued.input["claimToken"]))
    jobs.save(
        replace(
            queued,
            input={
                **queued.input,
                "claimOwner": "foreign-runtime",
                "claimToken": "foreign-expired-token",
                "claimExpiresAt": stale_expiry,
            },
        )
    )

    fresh_tasks = []
    recovered = engagement_teardown.recover_engagement_teardowns(
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        background_runner=fresh_tasks.append,
    )
    reclaimed = jobs.get(queued.id)

    assert recovered == [queued.id]
    assert len(fresh_tasks) == 1
    assert reclaimed is not None
    assert reclaimed.input["claimOwner"] == engagement_teardown._owner
    assert reclaimed.input["claimToken"] != "foreign-expired-token"
    assert engagement_teardown._lease_owned(
        reclaimed,
        engagement_teardown._owner,
        str(reclaimed.input["claimToken"]),
    )
    with pytest.raises(engagement_teardown.DeploymentPlanConflictError):
        leases.acquire(lease_key, "parallel-owner", "teardown")
    leases.release(lease_key, str(reclaimed.input["claimToken"]))


def test_teardown_holds_shared_core_lease_until_worker_finishes(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "lease.sqlite")
    jobs.save(clean_core(core_job()))
    chains = ChainRepository([])
    resources = ResourceRepository()
    monkeypatch.setattr(
        engagement_teardown,
        "reconcile_engagement_lifecycle",
        lambda *_args, **_kwargs: {"current": {"state": "destroyed"}},
    )
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    queued = []

    engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        background_runner=queued.append,
    )

    leases, prefix = engagement_teardown._core_mutation_leases(jobs)
    lease_key = f"{prefix}eng-1"
    with pytest.raises(engagement_teardown.DeploymentPlanConflictError):
        leases.acquire(lease_key, "parallel-plan", "prepare")
    queued[0]()
    leases.acquire(lease_key, "after-teardown", "prepare")
    leases.release(lease_key, "after-teardown")


def test_default_comprehensive_chain_dispatcher_can_use_its_own_core_lease(client, monkeypatch):
    from app.services import sketch_chains
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    with client.application.storage_context():
        chains = SqlAlchemySketchChainRepository()
        owned_chain = replace(
            chain("chain-owned-by-teardown", "proxy01", status="deployed"),
            engagement_id="eng-of02-dev",
        )
        chains.save(owned_chain)
        provider_job = SimpleNamespace(
            id="job-authorized-child-teardown",
            status="running",
            to_dict=lambda: {"id": "job-authorized-child-teardown", "status": "running"},
        )
        monkeypatch.setattr(sketch_chains, "start_guarded_linode_sketch_teardown", lambda *_a, **_k: provider_job)
        monkeypatch.setattr(sketch_chains, "_start_sketch_teardown_sequence", lambda *_a, **_k: None)
        leases = SqlAlchemyDeploymentPlanRepository()
        leases.acquire("eng-of02-dev", "job-comprehensive-owner", "apply")
        try:
            with pytest.raises(sketch_chains.SketchChainValidationError) as wrong_operation:
                sketch_chains.ensure_sketch_chain_teardown(
                    "eng-of02-dev",
                    owned_chain.chain_id,
                    {"confirmation": f"teardown-{owned_chain.chain_id}"},
                    repository=chains,
                    core_mutation_lease_owner="job-comprehensive-owner",
                )
            assert "temporarily locked" in wrong_operation.value.errors[0]
        finally:
            leases.release("eng-of02-dev", "job-comprehensive-owner")

        leases.acquire("eng-of02-dev", "job-comprehensive-owner", "teardown")
        try:
            with pytest.raises(sketch_chains.SketchChainValidationError) as public_error:
                sketch_chains.ensure_sketch_chain_teardown(
                    "eng-of02-dev",
                    owned_chain.chain_id,
                    {"confirmation": f"teardown-{owned_chain.chain_id}"},
                    repository=chains,
                )
            assert "temporarily locked" in public_error.value.errors[0]

            with pytest.raises(sketch_chains.SketchChainValidationError) as wrong_owner:
                sketch_chains.ensure_sketch_chain_teardown(
                    "eng-of02-dev",
                    owned_chain.chain_id,
                    {"confirmation": f"teardown-{owned_chain.chain_id}"},
                    repository=chains,
                    core_mutation_lease_owner="wrong-owner",
                )
            assert "temporarily locked" in wrong_owner.value.errors[0]

            result = engagement_teardown._default_chain_dispatcher(
                "eng-of02-dev",
                owned_chain.chain_id,
                {"confirmation": f"teardown-{owned_chain.chain_id}"},
                core_mutation_lease_owner="job-comprehensive-owner",
            )
            assert result is not None
            assert result["chain"]["status"] == "tearing_down"
            assert result["job"]["id"] == "job-authorized-child-teardown"
        finally:
            leases.release("eng-of02-dev", "job-comprehensive-owner")


def test_server_rejects_stale_snapshot_and_wrong_confirmation(repositories):
    jobs, chains, resources = repositories
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown.start_engagement_teardown(
            "job-core-1", {"confirmation": preview["confirmationPhrase"]},
            job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        )
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown.start_engagement_teardown(
            "job-core-1", {"confirmation": "wrong", "snapshotId": preview["snapshotId"]},
            job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        )
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown.start_engagement_teardown(
            "job-core-1", {"confirmation": preview["confirmationPhrase"], "snapshotId": "stale"},
            job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        )


def test_failed_parent_core_retry_preserves_confirmed_targets_while_refreshing_state(repositories):
    jobs, chains, resources = repositories
    original_preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    queued = []
    engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": original_preview["confirmationPhrase"], "snapshotId": original_preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        background_runner=queued.append,
    )
    parent_id = "job-engagement-teardown-core-1"
    parent = jobs.get(parent_id)
    jobs.save(replace(
        parent,
        status="failed",
        finished_at=datetime.now(timezone.utc).isoformat(),
        input={**parent.input, "claimExpiresAt": "2000-01-01T00:00:00+00:00"},
    ))
    core = jobs.get("job-core-1")
    jobs.save(replace(core, events=core.events + [
        JobEvent(len(core.events) + 1, "info", "new core endpoint", {
            "connectionDetails": [{"role": "homebase", "publicIp": "203.0.113.10"}],
        }),
    ]))
    fresh_preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    assert fresh_preview["snapshotId"] == original_preview["snapshotId"]

    engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": fresh_preview["confirmationPhrase"], "snapshotId": fresh_preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        background_runner=queued.append,
    )

    assert jobs.get(parent_id).input["scopeSnapshot"]["snapshotId"] == original_preview["snapshotId"]
    assert jobs.get(parent_id).input["scopeSnapshot"]["publicVerificationTargets"] == []


def test_direct_failed_parent_retry_keeps_its_persisted_snapshot(repositories):
    jobs, chains, resources = repositories
    original_preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    queued = []
    engagement_teardown.start_engagement_teardown(
        "job-core-1",
        {"confirmation": original_preview["confirmationPhrase"], "snapshotId": original_preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        background_runner=queued.append,
    )
    parent_id = "job-engagement-teardown-core-1"
    parent = jobs.get(parent_id)
    jobs.save(replace(
        parent,
        status="failed",
        finished_at=datetime.now(timezone.utc).isoformat(),
        input={**parent.input, "claimExpiresAt": "2000-01-01T00:00:00+00:00"},
    ))
    core = jobs.get("job-core-1")
    jobs.save(replace(core, events=core.events + [
        JobEvent(len(core.events) + 1, "info", "new core endpoint", {
            "connectionDetails": [{"role": "homebase", "publicIp": "203.0.113.10"}],
        }),
    ]))
    direct_preview = engagement_teardown.preview_engagement_teardown(
        parent_id, job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    assert direct_preview["snapshotId"] == original_preview["snapshotId"]

    engagement_teardown.start_engagement_teardown(
        parent_id,
        {"confirmation": direct_preview["confirmationPhrase"], "snapshotId": direct_preview["snapshotId"]},
        job_repository=jobs,
        sketch_repository=chains,
        provider_resource_repository=resources,
        background_runner=queued.append,
    )

    assert jobs.get(parent_id).input["scopeSnapshot"]["snapshotId"] == original_preview["snapshotId"]


def test_interrupted_chain_teardown_resumes_same_persisted_child(tmp_path, monkeypatch):
    from app.services import sketch_chains

    # This test exercises recovery for a legacy chain, so supply the split-v1
    # engagement identity required by the dispatch guard.
    monkeypatch.setattr(sketch_chains, "get_engagement", lambda _id: SimpleNamespace(sketch_state_schema="split-v1"))
    jobs = SqliteJobRepository(tmp_path / "resume.sqlite")
    recorded = replace(chain("proxy01-chain", "proxy01"), status="tearing_down", teardown_job_id="job-teardown-1")
    chains = ChainRepository([recorded])
    now = datetime.now(timezone.utc).isoformat()
    jobs.save(
        StoredJobRun(
            id="job-teardown-1",
            action="linode_sketch_teardown",
            status="running",
            target="engagement:eng-1",
            target_type="engagement",
            target_id="eng-1",
            requested_by="example_operator_three",
            input={"engagementId": "eng-1"},
            artifact_refs=[],
            created_at=now,
            started_at=now,
            finished_at=None,
            events=[],
        )
    )
    captured = {}
    resumed = []

    def capture_sequence(_engagement_id, _chain, child_id, provider_tasks, **_kwargs):
        captured["childId"] = child_id
        captured["providerTasks"] = provider_tasks

    monkeypatch.setattr(sketch_chains, "_start_sketch_teardown_sequence", capture_sequence)
    monkeypatch.setattr(sketch_chains, "resume_guarded_linode_sketch_teardown", lambda child_id, **_kwargs: resumed.append(child_id) or jobs.get(child_id).to_detail())

    result = sketch_chains.ensure_sketch_chain_teardown(
        "eng-1",
        "proxy01-chain",
        {"confirmation": "teardown-proxy01-chain"},
        repository=chains,
        job_repository=jobs,
    )
    assert result["job"]["id"] == "job-teardown-1"
    assert captured == {}
    assert resumed == []


def test_comprehensive_parent_has_lifecycle_precedence(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "lifecycle.sqlite")
    core = jobs.save(clean_core(core_job()))
    now = datetime.now(timezone.utc).isoformat()
    parent = jobs.save(
        StoredJobRun(
            id="job-engagement-teardown-core-1",
            action=engagement_teardown.ENGAGEMENT_TEARDOWN_ACTION,
            status="running",
            target="engagement:eng-1",
            target_type="engagement",
            target_id="eng-1",
            requested_by="example_operator_three",
            input={"engagementId": "eng-1", "remainingOwnedResources": []},
            artifact_refs=[],
            created_at=now,
            started_at=now,
            finished_at=None,
            events=[JobEvent(1, "info", "engagement teardown queued", {})],
        )
    )
    empty_chains = ChainRepository([])
    empty_resources = ResourceRepository()
    assert resolve_engagement_lifecycle(
        "eng-1", job_repository=jobs, sketch_chain_repository=empty_chains,
        provider_resource_repository=empty_resources, use_runtime_repositories=False,
    ).state == "tearing_down"

    jobs.save(replace(parent, status="failed", finished_at=now, events=parent.events + [JobEvent(2, "error", "engagement teardown requires cleanup", {"finalCleanupStatus": "cleanup_not_verified"})]))
    assert resolve_engagement_lifecycle(
        "eng-1", job_repository=jobs, sketch_chain_repository=empty_chains,
        provider_resource_repository=empty_resources, use_runtime_repositories=False,
    ).state == "cleanup_required"

    finalizing = replace(
        parent,
        status="running",
        input={**parent.input, "phase": "lifecycle_reconciliation"},
        events=parent.events + [JobEvent(2, "info", "engagement cleanup verified", {"finalCleanupStatus": "verified_clean"})],
    )
    jobs.save(finalizing)
    assert resolve_engagement_lifecycle(
        "eng-1", job_repository=jobs, sketch_chain_repository=empty_chains,
        provider_resource_repository=empty_resources, use_runtime_repositories=False,
    ).state == "destroyed"

    jobs.save(replace(finalizing, status="succeeded", finished_at=now))
    assert resolve_engagement_lifecycle(
        "eng-1", job_repository=jobs, sketch_chain_repository=empty_chains,
        provider_resource_repository=empty_resources, use_runtime_repositories=False,
    ).state == "destroyed"


def test_pending_chain_is_aborted_and_immediately_verified_clean(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "pending.sqlite")
    jobs.save(core_job())
    pending = replace(chain("proxy01-pending", "proxy01"), status="pending", deploy_job_id="", nodes=[])
    chains = ChainRepository([pending])
    resources = ResourceRepository()
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: {"current": {"state": "destroyed"}})
    preview = engagement_teardown.preview_engagement_teardown("job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources)

    def cancel(engagement_id, chain_id, _body):
        current = chains.get(engagement_id, chain_id)
        aborted = chains.save(replace(current, status="aborted"))
        return {"chain": aborted.to_dict(), "job": None}

    parent = engagement_teardown.start_engagement_teardown(
        "job-core-1", {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        chain_dispatcher=cancel, outbound_dispatcher=lambda *_a: pytest.fail("pending chain has no outbound cleanup"),
        core_dispatcher=lambda core_id, _targets: jobs.save(clean_core(jobs.get(core_id))),
        background_runner=lambda task: task(), wait=lambda _seconds: pytest.fail("pending chain must not wait"),
    )
    assert parent.status == "succeeded"
    assert chains.get("eng-1", "proxy01-pending").status == "aborted"


def test_preview_generated_pending_chain_remains_recoverable_after_later_core_failure(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "pending-recovery.sqlite")
    jobs.save(core_job())
    pending = replace(chain("proxy01-pending", "proxy01"), status="pending", deploy_job_id="", nodes=[])
    chains = ChainRepository([pending])
    resources = ResourceRepository()
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: {"current": {"state": "destroyed"}})
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
    )
    chain_calls: list[str] = []

    def cancel(engagement_id, chain_id, _body):
        chain_calls.append(chain_id)
        current = chains.get(engagement_id, chain_id)
        aborted = chains.save(replace(current, status="aborted"))
        return {"chain": aborted.to_dict(), "job": None}

    failed = engagement_teardown.start_engagement_teardown(
        "job-core-1", {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        chain_dispatcher=cancel, outbound_dispatcher=lambda *_a: pytest.fail("pending chain has no outbound cleanup"),
        core_dispatcher=lambda *_a: None, background_runner=lambda task: task(),
        wait=lambda _seconds: pytest.fail("pending chain must not wait"),
    )
    assert failed.status == "failed"
    assert engagement_teardown.comprehensive_teardown_recovery_state(failed) == "recoverable"
    assert failed.input["scopeSnapshot"]["chains"][0]["deployJobId"] == ""
    assert chain_calls == ["proxy01-pending"]

    retry_preview = engagement_teardown.preview_engagement_teardown(
        failed.id, job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
    )
    retried = engagement_teardown.start_engagement_teardown(
        failed.id,
        {"confirmation": retry_preview["confirmationPhrase"], "snapshotId": retry_preview["snapshotId"]},
        job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        chain_dispatcher=lambda *_a: pytest.fail("already-clean pending chain must not redispatch"),
        outbound_dispatcher=lambda *_a: pytest.fail("already-clean pending chain must not rerun outbound cleanup"),
        core_dispatcher=lambda core_id, _targets: jobs.save(clean_core(jobs.get(core_id))),
        background_runner=lambda task: task(), wait=lambda _seconds: pytest.fail("retry must not wait"),
    )
    assert retried.status == "succeeded"
    assert chain_calls == ["proxy01-pending"]


def test_snapshot_collects_engagement_wide_targets_and_excludes_unmanaged_records(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "targets.sqlite")
    core = core_job(events=[JobEvent(1, "info", "core", {"connectionDetails": [{"publicIp": "203.0.113.10"}]})])
    jobs.save(core)
    jobs.save(replace(core, id="job-channel", action="inbound_channel_apply", events=[JobEvent(1, "info", "channel", {"inboundChannels": [{"chainId": "c1", "domain": "site.example", "externalPort": 443}]})]))
    jobs.save(replace(
        core,
        id="job-outbound",
        action="mixed_provider_sketch_deploy",
        events=[JobEvent(1, "info", "outbound", {"outboundChannels": [
            {
                "channelId": "edge-01",
                "domain": "proxy01-sfo3-01-edge-01",
                "port": "3333",
                "validation": {"expectedPublicIp": "198.51.100.20"},
            },
            {"channelId": "placeholder", "domain": "Not Deployed", "port": "3334"},
            {"channelId": "bad-ip", "domain": "bad-.example", "validation": {"expectedPublicIp": "Not Deployed"}},
            {"channelId": "empty-label", "domain": "proxy01..example.com"},
            {"channelId": "ip-as-domain", "domain": "203.0.113.21"},
        ]})],
    ))
    managed = SimpleNamespace(id="owned-1", status="active", metadata={"barraganOwned": True}, engagement_id="eng-1")
    unmanaged = SimpleNamespace(id="manual-1", status="active", metadata={}, engagement_id="eng-1")
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository([managed, unmanaged]),
    )
    parent_tasks = []
    engagement_teardown.start_engagement_teardown(
        "job-core-1", {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs, sketch_repository=ChainRepository([]), provider_resource_repository=ResourceRepository([managed, unmanaged]),
        background_runner=parent_tasks.append,
    )
    parent = jobs.get("job-engagement-teardown-core-1")
    snapshot = parent.input["scopeSnapshot"]
    assert snapshot["ownedProviderRecordIds"] == ["owned-1"]
    assert snapshot["excludedUnmanagedProviderRecords"] == ["manual-1"]
    assert {target["host"] for target in snapshot["publicVerificationTargets"]} == {
        "203.0.113.10", "site.example", "198.51.100.20"
    }
    assert len(snapshot["publicVerificationTargets"]) == 3
    dns_target = next(target for target in snapshot["publicVerificationTargets"] if target["host"] == "site.example")
    assert dns_target == {
        "id": "dns:site.example",
        "type": "dns-absent",
        "host": "site.example",
    }
    edge_target = next(target for target in snapshot["publicVerificationTargets"] if target["host"] == "198.51.100.20")
    assert edge_target == {
        "id": "edge-01:management",
        "type": "tcp-forbidden",
        "host": "198.51.100.20",
        "port": 22,
        "targetGroup": "sketch-public-management",
    }
    assert all(
        target["host"] not in {
            "Not Deployed",
            "proxy01-sfo3-01-edge-01",
            "bad-.example",
            "proxy01..example.com",
            "203.0.113.21",
        }
        for target in snapshot["publicVerificationTargets"]
    )

    from app.services.guarded_test_deployment import _retired_public_endpoint_targets
    explicit_core = replace(core, input={**core.input, "engagementTeardownVerificationTargets": snapshot["publicVerificationTargets"]})
    assert _retired_public_endpoint_targets(explicit_core) == snapshot["publicVerificationTargets"]

    from app.services.observer_checks import _teardown_target
    sanitized = [_teardown_target(target) for target in snapshot["publicVerificationTargets"]]
    assert all(target["type"] in {"tcp-forbidden", "dns-absent"} for target in sanitized)
    verified = replace(
        clean_core(core),
        events=clean_core(core).events
        + [JobEvent(99, "info", "exact Inspector result", {"inspectorTeardownVerification": {"ok": True, "targetCount": len(sanitized), "targets": sanitized}, "inspectorCleanup": {"ok": True}})],
    )
    assert not engagement_teardown._core_verified(verified, snapshot["publicVerificationTargets"])
    dropped = replace(verified, events=verified.events + [JobEvent(100, "info", "dropped target", {"inspectorTeardownVerification": {"ok": True, "targetCount": len(sanitized) - 1, "targets": sanitized[:-1]}, "inspectorCleanup": {"ok": True}})])
    assert not engagement_teardown._core_verified(dropped, snapshot["publicVerificationTargets"])


def test_legacy_core_targets_are_semantically_deduplicated_and_enriched(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "legacy-core-targets.sqlite")
    jobs.save(core_job(events=[
        JobEvent(1, "info", "legacy targets", {"publicVerificationTargets": [
            {"id": "tcp:64.181.246.3:22", "type": "tcp-forbidden", "host": "64.181.246.3", "port": 22},
            {"id": "tcp:163.192.44.56:22", "type": "tcp-forbidden", "host": "163.192.44.56", "port": 22},
        ]}),
        JobEvent(2, "info", "core connections", {"connectionDetails": [
            {"role": "homebase", "publicIp": "64.181.246.3"},
            {"role": "proxy", "publicIp": "163.192.44.56"},
        ]}),
    ]))

    targets = engagement_teardown._known_public_targets_for_engagement(jobs, "eng-1")

    assert targets == [
        {
            "id": "tcp:64.181.246.3:22",
            "type": "tcp-forbidden",
            "host": "64.181.246.3",
            "port": 22,
            "targetGroup": "core-public-management",
        },
        {
            "id": "tcp:163.192.44.56:22",
            "type": "tcp-forbidden",
            "host": "163.192.44.56",
            "port": 22,
            "targetGroup": "core-public-management",
        },
    ]


@pytest.mark.parametrize("groups", [
    ("core-public-management", "sketch-public-management"),
    ("sketch-public-management", "core-public-management"),
])
def test_conflicting_target_groups_fail_closed_regardless_of_event_order(tmp_path, groups):
    jobs = SqliteJobRepository(tmp_path / f"conflicting-target-groups-{groups[0]}.sqlite")
    jobs.save(core_job(events=[
        JobEvent(1, "info", "first target", {"publicVerificationTargets": [{
            "id": "first",
            "type": "tcp-forbidden",
            "host": "198.51.100.20",
            "port": 22,
            "targetGroup": groups[0],
        }]}),
        JobEvent(2, "info", "conflicting target", {"publicVerificationTargets": [{
            "id": "second",
            "type": "tcp-forbidden",
            "host": "198.51.100.20",
            "port": "22",
            "targetGroup": groups[1],
        }]}),
    ]))

    targets = engagement_teardown._known_public_targets_for_engagement(jobs, "eng-1")

    assert len(targets) == 1
    assert targets[0]["targetGroup"] == "sketch-public-management"


def test_public_target_semantic_identity_keeps_different_ports_and_types(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "distinct-target-identities.sqlite")
    jobs.save(core_job(events=[JobEvent(1, "info", "distinct targets", {"publicVerificationTargets": [
        {"id": "ssh", "type": "tcp-forbidden", "host": "edge.example.com", "port": 22},
        {"id": "https", "type": "tcp-forbidden", "host": "edge.example.com", "port": 443},
        {"id": "dns", "type": "dns-absent", "host": "edge.example.com"},
    ]})]))

    targets = engagement_teardown._known_public_targets_for_engagement(jobs, "eng-1")

    assert [(target["type"], target.get("port")) for target in targets] == [
        ("tcp-forbidden", 22),
        ("tcp-forbidden", 443),
        ("dns-absent", None),
    ]


@pytest.mark.parametrize("unspecified_first", [True, False])
def test_same_dns_name_retains_distinct_old_edge_ips_with_exact_inspector_evidence(tmp_path, unspecified_first):
    jobs = SqliteJobRepository(tmp_path / "dns-multiple-old-ips.sqlite")
    explicit = [
        {"id": "same-channel", "type": "dns-absent", "host": "edge.example.com", "expectedIp": "198.51.100.10"},
        {"id": "other-channel", "type": "dns-absent", "host": "edge.example.com", "expectedIp": "198.51.100.20"},
        {"id": "duplicate", "type": "dns-absent", "host": "edge.example.com", "expectedIp": "198.51.100.10"},
    ]
    legacy = {"id": "legacy-hostname", "type": "dns-absent", "host": "edge.example.com"}
    values = [legacy, *explicit] if unspecified_first else [*explicit, legacy]
    jobs.save(core_job(events=[JobEvent(1, "info", "two old A records", {"publicVerificationTargets": values})]))
    baseline_jobs = SqliteJobRepository(tmp_path / "dns-explicit-only.sqlite")
    baseline_jobs.save(core_job(events=[JobEvent(1, "info", "two old A records", {"publicVerificationTargets": explicit})]))

    targets = engagement_teardown._known_public_targets_for_engagement(jobs, "eng-1")
    baseline = engagement_teardown._known_public_targets_for_engagement(baseline_jobs, "eng-1")
    assert targets == baseline
    assert len(targets) == 4
    assert engagement_teardown.teardown_target_sha256(targets) == engagement_teardown.teardown_target_sha256(baseline)
    dns_targets = [target for target in targets if target["type"] == "dns-absent"]
    assert dns_targets == [
        {"id": "dns:edge.example.com:198.51.100.10", "type": "dns-absent", "host": "edge.example.com", "expectedIp": "198.51.100.10"},
        {"id": "dns:edge.example.com:198.51.100.20", "type": "dns-absent", "host": "edge.example.com", "expectedIp": "198.51.100.20"},
    ]
    assert engagement_teardown._valid_public_targets(targets)
    base = clean_core(core_job())
    terminal = base.events[-1]
    inspector = {"provider": "linode", "resourceType": "instance", "resourceId": "inspector-1"}
    data = {
        **terminal.data,
        "verificationTargetSha256": engagement_teardown.teardown_target_sha256(targets),
        "inspectorTeardownVerification": {
            "ok": True, "targetCount": len(targets), "targets": targets, "inspectorHost": inspector,
        },
        "inspectorCleanup": {"ok": True, "cleanupVerified": True, "currentHostCleared": True, "inspectorHost": inspector},
    }
    verified = replace(base, events=[*base.events[:-1], replace(terminal, data=data)])
    assert engagement_teardown._core_verified(verified, targets)
    missing_one_dns = [target for target in targets if target != dns_targets[1]]
    forged = replace(verified, events=[*verified.events[:-1], replace(verified.events[-1], data={
        **data, "inspectorTeardownVerification": {**data["inspectorTeardownVerification"], "targets": missing_one_dns},
    })])
    assert not engagement_teardown._core_verified(forged, targets)


def test_combined_inbound_row_uses_distinct_dns_and_tcp_target_ids(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "combined-inbound-target.sqlite")
    jobs.save(core_job(events=[JobEvent(1, "info", "inbound channel", {"inboundChannels": [
        {"id": "channel-1", "domain": "edge.example.com", "publicIp": "198.51.100.10", "externalPort": 443},
    ]})]))

    targets = engagement_teardown._known_public_targets_for_engagement(jobs, "eng-1")
    assert targets == [
        {"id": "dns:edge.example.com:198.51.100.10", "type": "dns-absent",
         "host": "edge.example.com", "expectedIp": "198.51.100.10"},
        {"id": "tcp:198.51.100.10:443", "type": "tcp-forbidden",
         "host": "198.51.100.10", "port": 443},
    ]
    assert engagement_teardown._valid_public_targets(targets)


def test_public_target_host_validation_rejects_placeholders_and_malformed_names():
    assert engagement_teardown._normalized_ip("203.0.113.20") == "203.0.113.20"
    assert engagement_teardown._normalized_ip("Not Deployed") == ""
    assert engagement_teardown._looks_like_public_dns_name("edge.example.com")
    assert not engagement_teardown._looks_like_public_dns_name("203.0.113.20")
    assert not engagement_teardown._looks_like_public_dns_name("bad-.example")
    assert not engagement_teardown._looks_like_public_dns_name("proxy01..example.com")


def test_preview_tracks_retained_inspector_from_active_owned_provider_record(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "inspector-preview.sqlite")
    jobs.save(core_job())
    retained_inspector = SimpleNamespace(
        id="linode:inspector:123",
        status="active",
        source="barragan_inspector_job",
        metadata={"barraganOwned": True, "role": "inspector"},
        resource_type="inspector_instance",
        engagement_id="eng-1",
    )

    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1",
        job_repository=jobs,
        sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository([retained_inspector]),
    )

    inspector_scope = next(row for row in preview["orderedScope"] if row["id"] == "inspector-cleanup")
    assert inspector_scope["items"] == [
        {
            "tracked": True,
            "ownedProviderRecordIds": ["linode:inspector:123"],
            "verificationTargetCount": 0,
        }
    ]


def test_lifecycle_reconcile_exception_fails_parent(repositories, monkeypatch):
    jobs, chains, resources = repositories
    for current in chains.list_for_engagement("eng-1"):
        chains.save(replace(current, status="destroyed", nodes=[]))
    preview = engagement_teardown.preview_engagement_teardown("job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources)
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("db unavailable")))
    parent = engagement_teardown.start_engagement_teardown(
        "job-core-1", {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        outbound_dispatcher=lambda *_a: None,
        core_dispatcher=lambda core_id, _targets: jobs.save(clean_core(jobs.get(core_id))),
        background_runner=lambda task: task(), wait=lambda _s: None,
    )
    assert parent.status == "failed"
    assert parent.input["remainingOwnedResources"] == ["engagement_lifecycle"]


def test_recovery_observes_running_core_without_duplicate_dispatch(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "running-core.sqlite")
    jobs.save(core_job())
    chains = ChainRepository([])
    resources = ResourceRepository()
    monkeypatch.setattr(engagement_teardown, "reconcile_engagement_lifecycle", lambda *_a, **_k: {"current": {"state": "destroyed"}})
    preview = engagement_teardown.preview_engagement_teardown("job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources)
    tasks = []
    engagement_teardown.start_engagement_teardown(
        "job-core-1", {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        background_runner=tasks.append,
    )
    parent = jobs.get("job-engagement-teardown-core-1")
    jobs.save(replace(parent, input={**parent.input, "outcomes": {"core": {"state": "running", "jobId": "job-core-1"}}}))
    jobs.save(replace(jobs.get("job-core-1"), status="running", finished_at=None))
    dispatched = []
    waits = 0

    def finish_on_wait(_seconds):
        nonlocal waits
        waits += 1
        jobs.save(clean_core(jobs.get("job-core-1")))

    # Reclaim the expired parent through an explicit retry and observe the
    # already-running core child instead of dispatching another destroy.
    expired = jobs.get(parent.id)
    jobs.save(replace(expired, status="failed", input={**expired.input, "claimExpiresAt": "2000-01-01T00:00:00+00:00"}))
    engagement_teardown.start_engagement_teardown(
        parent.id, {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        core_dispatcher=lambda *_args: dispatched.append("core"), background_runner=lambda task: task(), wait=finish_on_wait,
    )
    assert dispatched == []
    assert waits == 1
    assert jobs.get(parent.id).status == "succeeded"


def test_lifecycle_finalizing_ignores_unmanaged_but_blocks_managed_provider_record(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "owned-lifecycle.sqlite")
    now = datetime.now(timezone.utc).isoformat()
    jobs.save(clean_core(core_job()))
    jobs.save(StoredJobRun(
        id="job-engagement-teardown-core-1", action=engagement_teardown.ENGAGEMENT_TEARDOWN_ACTION,
        status="running", target="engagement:eng-1", target_type="engagement", target_id="eng-1", requested_by="example_operator_three",
        input={"engagementId": "eng-1", "phase": "lifecycle_reconciliation", "remainingOwnedResources": []},
        artifact_refs=[], created_at=now, started_at=now, finished_at=None,
        events=[JobEvent(1, "info", "resource gates", {"finalCleanupStatus": "verified_clean"})],
    ))
    unmanaged = SimpleNamespace(id="manual", engagement_id="eng-1", status="active", metadata={}, provider="oci", resource_type="instance")
    managed = SimpleNamespace(id="owned", engagement_id="eng-1", status="active", metadata={"barraganOwned": True}, provider="oci", resource_type="instance")
    assert resolve_engagement_lifecycle(
        "eng-1", job_repository=jobs, sketch_chain_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository([unmanaged]), use_runtime_repositories=False,
    ).state == "destroyed"
    assert resolve_engagement_lifecycle(
        "eng-1", job_repository=jobs, sketch_chain_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository([managed]), use_runtime_repositories=False,
    ).state == "cleanup_required"


def test_synchronous_child_heartbeat_renews_before_and_after_dispatch(monkeypatch):
    renewals = []
    sentinel = SimpleNamespace()
    monkeypatch.setattr(engagement_teardown, "_renew", lambda *_args: renewals.append("renew") or sentinel)
    result = engagement_teardown._run_with_lease_heartbeat(
        lambda: "done", jobs=SimpleNamespace(), parent_id="job-parent", owner="runtime", token="token"
    )
    assert result == "done"
    assert len(renewals) >= 2


def test_heartbeat_timeout_never_calls_operation(monkeypatch):
    import time

    called = []
    monkeypatch.setattr(engagement_teardown, "HEARTBEAT_START_TIMEOUT_SECONDS", 0.005)
    monkeypatch.setattr(engagement_teardown, "_renew", lambda *_args: time.sleep(0.05) or SimpleNamespace())
    with pytest.raises(engagement_teardown.EngagementTeardownLeaseLost):
        engagement_teardown._run_with_lease_heartbeat(
            lambda: called.append("operation"), jobs=SimpleNamespace(), parent_id="job-parent", owner="old", token="old-token"
        )
    assert called == []


def test_post_operation_lease_loss_takes_precedence_over_child_error(monkeypatch):
    renewals = iter([SimpleNamespace(), None])
    monkeypatch.setattr(engagement_teardown, "_renew", lambda *_args: next(renewals))

    with pytest.raises(engagement_teardown.EngagementTeardownLeaseLost):
        engagement_teardown._run_with_lease_heartbeat(
            lambda: (_ for _ in ()).throw(RuntimeError("child failed")),
            jobs=SimpleNamespace(),
            parent_id="job-parent",
            owner="old",
            token="old-token",
        )


def test_post_dispatch_lease_loss_causes_no_failure_or_stale_parent_write(repositories, monkeypatch):
    jobs, chains, resources = repositories
    preview = engagement_teardown.preview_engagement_teardown(
        "job-core-1", job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources
    )
    monkeypatch.setattr(
        engagement_teardown,
        "_run_with_lease_heartbeat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(engagement_teardown.EngagementTeardownLeaseLost("reclaimed")),
    )
    parent = engagement_teardown.start_engagement_teardown(
        "job-core-1", {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
        job_repository=jobs, sketch_repository=chains, provider_resource_repository=resources,
        outbound_dispatcher=lambda *_args: None, background_runner=lambda task: task(),
    )
    assert parent.status == "running"
    assert all(event.message != "engagement teardown requires cleanup" for event in parent.events)


def test_mutation_services_reject_while_teardown_active(monkeypatch):
    from app.services import certificate_manager, guarded_test_deployment, inspector_scheduler, observer_checks

    def reject(*_args, **_kwargs):
        raise engagement_teardown.EngagementTeardownValidationError(["teardown active"])

    monkeypatch.setattr(engagement_teardown, "assert_engagement_mutation_allowed", reject)
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        guarded_test_deployment.run_guarded_pilot_standard_rti({"engagementId": "eng-1"})
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        observer_checks.start_inspection("eng-1", {})
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        certificate_manager.start_certificate_renew("eng-1", "cert-1", {})
    assert inspector_scheduler._inspection_mutation_allowed("eng-1") is False


def test_legacy_ownership_predicate_and_explicit_false_override():
    from app.storage.provider_resource_repository import is_barragan_owned_record

    assert is_barragan_owned_record(SimpleNamespace(metadata={}, source="barragan"))
    assert is_barragan_owned_record(SimpleNamespace(metadata={}, source="barragan-inspector"))
    assert is_barragan_owned_record(SimpleNamespace(metadata={}, source="barragan_inspector_job"))
    assert is_barragan_owned_record(SimpleNamespace(metadata={}, source="barragan_observer_job"))
    assert is_barragan_owned_record(SimpleNamespace(metadata={}, source="observer_job"))
    assert not is_barragan_owned_record(SimpleNamespace(metadata={"barraganOwned": False}, source="barragan"))
    assert not is_barragan_owned_record(SimpleNamespace(metadata={}, source="provider_inventory"))


def test_keyed_preview_seals_one_shared_provider_scope_and_blocks_start(tmp_path, monkeypatch):
    from test_provider_keyed_persisted_intent import _inputs

    jobs = SqliteJobRepository(tmp_path / "keyed-preview.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    pending = [replace(chain, engagement_id="eng-1") for chain in _inputs()[1]]
    preview = engagement_teardown.preview_engagement_teardown(
        core.id, job_repository=jobs, sketch_repository=ChainRepository(pending),
        provider_resource_repository=ResourceRepository(), domain_repository=DomainRepository(),
        inspector_state_reader=lambda _id: {},
    )
    assert preview is not None
    provider = [step for step in preview["orderedScope"] if step["id"] == "provider-keyed"]
    assert len(provider) == 1 and provider[0]["items"] == [_keyed_review_scope()]
    sketch = [step for step in preview["orderedScope"] if step["id"] == "sketch"][0]
    assert "review only" in sketch["label"]
    assert len(sketch["items"]) == 2 and all(row["alreadyClean"] is False for row in sketch["items"])
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
        engagement_teardown.start_engagement_teardown(
            core.id, {"confirmation": preview["confirmationPhrase"],
                      "snapshotId": preview["snapshotId"]}, job_repository=jobs,
            sketch_repository=ChainRepository([]), provider_resource_repository=ResourceRepository(),
        )
    assert "keyed provider teardown execution" in exc.value.errors[0]
    assert jobs.get(engagement_teardown._parent_id(core.id)) is None


def test_keyed_preview_is_blocked_when_applied_scope_is_incomplete(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "keyed-incomplete.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    def reject(*_args, **_kwargs):
        raise provider_keyed_teardown_scope.ProviderKeyedTeardownScopeError("incomplete")
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope", reject)
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
        engagement_teardown.preview_engagement_teardown(
            core.id, job_repository=jobs, sketch_repository=ChainRepository([]),
            provider_resource_repository=ResourceRepository(), domain_repository=DomainRepository(),
            inspector_state_reader=lambda _id: {},
        )
    assert "complete applied keyed provider scope" in exc.value.errors[0]


def test_keyed_recovery_skips_existing_parent_without_dispatch(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "keyed-recovery.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    parent = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
                     status="queued", finished_at=None,
                     input={**failed_comprehensive_teardown().input,
                            "scopeSnapshot": {**failed_comprehensive_teardown().input["scopeSnapshot"],
                                              "providerScopes": [_keyed_review_scope()]}})
    jobs.save(parent)
    assert engagement_teardown.recover_engagement_teardowns(
        job_repository=jobs, sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository(),
        chain_dispatcher=lambda *_a: pytest.fail("legacy chain destroy dispatched"),
    ) == []
    assert jobs.get(parent.id).status == "queued"


def test_keyed_scope_change_requires_new_snapshot():
    assert engagement_teardown._valid_provider_scopes([_keyed_review_scope()], "job-core-1")
    snapshot = {"providerScopes": [_keyed_review_scope()], "chains": [],
                "ownedProviderRecordIds": [], "inspector": {"ownedProviderRecordIds": [],
                                                               "recordOwners": {}}}
    changed = deepcopy(snapshot)
    changed["providerScopes"][0]["resources"][0]["id"] = "changed"
    assert "provider_scope_changed" in engagement_teardown._unconfirmed_destructive_targets(
        snapshot, changed, teardown_job_id="job-parent")
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown._refresh_confirmed_scope_snapshot(snapshot, changed)


def test_keyed_parent_refresh_preserves_confirmed_id_as_chain_status_changes(tmp_path, monkeypatch):
    from test_provider_keyed_persisted_intent import _inputs

    jobs = SqliteJobRepository(tmp_path / "keyed-refresh.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    pending = [replace(chain, engagement_id="eng-1") for chain in _inputs()[1]]
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository(pending), resources=ResourceRepository(),
        domain_repository=DomainRepository())
    current = deepcopy(snapshot)
    current["chains"][0]["status"] = "failed"
    current["chains"][0]["alreadyClean"] = False
    current["inspector"]["tracked"] = True
    refreshed = engagement_teardown._refresh_confirmed_scope_snapshot(snapshot, current)
    assert refreshed["snapshotId"] == snapshot["snapshotId"]
    assert refreshed["providerScopes"] == snapshot["providerScopes"]
    assert refreshed["providerScopeSha256"] == snapshot["providerScopeSha256"]
    assert refreshed["chains"][0]["status"] == "failed"
    parent = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
                     input={**failed_comprehensive_teardown().input, "scopeSnapshot": refreshed})
    jobs.save(parent)
    assert engagement_teardown._validated_parent_boundary(parent, jobs)[1] == refreshed
    tampered = replace(parent, input={**parent.input, "scopeSnapshot": {
        **refreshed, "providerScopes": [{**refreshed["providerScopes"][0], "selectorTag": "changed"}]}})
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown._validated_parent_boundary(tampered, jobs)
    drifted = deepcopy(current)
    drifted["providerScopes"][0]["resources"][0]["id"] = "wrong"
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown._refresh_confirmed_scope_snapshot(refreshed, drifted)


@pytest.mark.parametrize("assignments,assets,expected", [
    ([], [], []),
    ([_domain_assignment(2, "domain-2"), _domain_assignment(1)],
     [_domain_asset("domain-2", "zeta.example"), _domain_asset()],
     [{"domainId": "domain-1", "assignmentId": 1, "domainName": "alpha.example", "registrar": "namecheap"},
      {"domainId": "domain-2", "assignmentId": 2, "domainName": "zeta.example", "registrar": "namecheap"}]),
])
def test_keyed_preview_freezes_and_shows_exact_active_dns_assignments(
    tmp_path, monkeypatch, assignments, assets, expected,
):
    jobs = SqliteJobRepository(tmp_path / "keyed-dns-preview.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    preview = engagement_teardown.preview_engagement_teardown(
        core.id, job_repository=jobs, sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository(),
        domain_repository=DomainRepository(assignments, assets), inspector_state_reader=lambda _id: {},
    )
    dns = next(row for row in preview["orderedScope"] if row["id"] == "dns-assignments")
    assert dns["count"] == len(expected)
    assert dns["items"] == ([{"domainId": row["domainId"],
                              "domainName": row["domainName"],
                              "assignmentId": row["assignmentId"],
                              "ownedRecordCount": 0, "preservedRecordCount": 1,
                              "maxOwnedTtl": 0, "blockers": []}
                             for row in expected] or [{"assignedDomainCount": 0}])
    assert "private sentinel" not in str(preview)
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository([]), resources=ResourceRepository(),
        domain_repository=DomainRepository(assignments, assets),
    )
    assert snapshot["domainAssignments"] == expected
    assert snapshot["snapshotId"] == engagement_teardown._fingerprint(
        {key: value for key, value in snapshot.items() if key != "snapshotId"})


@pytest.mark.parametrize("domain_repo", [
    DomainRepository([_domain_assignment()], []),
    DomainRepository([_domain_assignment(), _domain_assignment(1, "domain-2")],
                     [_domain_asset(), _domain_asset("domain-2", "zeta.example")]),
    DomainRepository([_domain_assignment(), _domain_assignment(2)], [_domain_asset()]),
    DomainRepository([_domain_assignment()], [_domain_asset(registrar="other")]),
    DomainRepository([_domain_assignment()], [_domain_asset()],
                     [_domain_assignment(2, engagement_id="other")]),
])
def test_keyed_preview_blocks_missing_or_ambiguous_dns_assignment(
    tmp_path, monkeypatch, domain_repo,
):
    jobs = SqliteJobRepository(tmp_path / "keyed-dns-invalid.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError, match="validation failed") as exc:
        engagement_teardown.preview_engagement_teardown(
            core.id, job_repository=jobs, sketch_repository=ChainRepository([]),
            provider_resource_repository=ResourceRepository(), domain_repository=domain_repo,
            inspector_state_reader=lambda _id: {},
        )
    assert "active keyed DNS assignments" in exc.value.errors[0]


def test_keyed_confirmation_rejects_assignment_drift_after_preview(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "keyed-dns-drift.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    initial = DomainRepository([_domain_assignment()], [_domain_asset()])
    preview = engagement_teardown.preview_engagement_teardown(
        core.id, job_repository=jobs, sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository(), domain_repository=initial,
        inspector_state_reader=lambda _id: {},
    )
    changed = DomainRepository([_domain_assignment(2)], [_domain_asset()])
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
        engagement_teardown.start_engagement_teardown(
            core.id, {"confirmation": preview["confirmationPhrase"], "snapshotId": preview["snapshotId"]},
            job_repository=jobs, sketch_repository=ChainRepository([]),
            provider_resource_repository=ResourceRepository(), domain_repository=changed,
            inspector_state_reader=lambda _id: {},
            provider_keyed_coordinator=lambda *_a: pytest.fail("keyed GO reached"),
            provider_keyed_environment="devtest",
        )
    assert "scope changed" in exc.value.errors[0]
    assert jobs.get(engagement_teardown._parent_id(core.id)) is None


def test_keyed_parent_boundary_rejects_missing_frozen_dns_inventory(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "keyed-dns-parent.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository([]), resources=ResourceRepository(),
        domain_repository=DomainRepository(),
    )
    snapshot.pop("domainAssignments")
    snapshot["snapshotId"] = engagement_teardown._fingerprint(
        {key: value for key, value in snapshot.items() if key != "snapshotId"})
    parent = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
                     input={**failed_comprehensive_teardown().input, "scopeSnapshot": snapshot})
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        engagement_teardown._validated_parent_boundary(parent, jobs)


def test_keyed_dns_manifest_validator_accepts_numeric_edge_order_and_sealed_plan():
    from app.services.provider_keyed_dns_cleanup_manifest import build_provider_keyed_dns_cleanup_manifest
    from app.services.provider_keyed_host_binding import _digest_json
    from test_provider_keyed_dns_cleanup_manifest import _case

    scope, jobs, domains, adapter = _case(1)
    initial = jobs.get("job-provider-keyed-initial-core")
    host = initial.events[0].data
    host["nodes"][0]["publicIp"] = "11.11.11.11"
    host["nodes"][1]["publicIp"] = "8.8.8.8"
    initial.events[1] = JobEvent(2, "info", "provider host identity bound",
                                  {"manifestSha256": _digest_json(host), "hostProofPending": True})
    scope["dnsCleanupManifest"] = build_provider_keyed_dns_cleanup_manifest(
        scope, job_repository=jobs, domain_repository=domains, adapter=adapter)
    entry = scope["dnsCleanupManifest"]["domains"][0]
    assert entry["oldEdgeIps"] == ["8.8.8.8", "11.11.11.11"]
    assert entry["cleanupPlanSha256"].startswith("sha256:")
    assert "cleanupPlan" not in entry
    assert engagement_teardown._valid_keyed_dns_cleanup_manifest(scope)


def test_keyed_parent_boundary_rejects_missing_or_forged_dns_manifest(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "keyed-dns-manifest-boundary.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    repo = DomainRepository([_domain_assignment()], [_domain_asset()])
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository([]), resources=ResourceRepository(),
        domain_repository=repo)
    parent = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
        input={**failed_comprehensive_teardown().input, "scopeSnapshot": snapshot})
    assert engagement_teardown._parent_boundary_fields(parent) is not None

    missing = deepcopy(snapshot)
    missing.pop("dnsCleanupManifest")
    missing["snapshotId"] = engagement_teardown._fingerprint(
        {key: value for key, value in missing.items() if key != "snapshotId"})
    assert engagement_teardown._parent_boundary_fields(replace(parent,
        input={**parent.input, "scopeSnapshot": missing})) is None

    forged = deepcopy(snapshot)
    entry = forged["dnsCleanupManifest"]["domains"][0]
    entry["preservedRecordCount"] = -1
    entry["entrySha256"] = "sha256:" + engagement_teardown._fingerprint(
        {key: value for key, value in entry.items() if key != "entrySha256"})
    manifest = forged["dnsCleanupManifest"]
    manifest["manifestSha256"] = "sha256:" + engagement_teardown._fingerprint(
        {key: value for key, value in manifest.items() if key != "manifestSha256"})
    forged["snapshotId"] = engagement_teardown._fingerprint(
        {key: value for key, value in forged.items() if key != "snapshotId"})
    assert engagement_teardown._parent_boundary_fields(replace(parent,
        input={**parent.input, "scopeSnapshot": forged})) is None


def test_keyed_confirmation_rejects_changed_namecheap_zone_after_preview(tmp_path, monkeypatch):
    from app.services import provider_keyed_dns_cleanup_manifest

    jobs = SqliteJobRepository(tmp_path / "keyed-dns-zone-drift.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    repo = DomainRepository([_domain_assignment()], [_domain_asset()])
    preview = engagement_teardown.preview_engagement_teardown(
        core.id, job_repository=jobs, sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository(), domain_repository=repo,
        inspector_state_reader=lambda _id: {},
    )

    class ChangedZone:
        def get_hosts(self, _domain_name):
            return [{"name": "note", "type": "TXT", "address": "different private value",
                     "ttl": "600"}]

        def set_hosts(self, *_args):
            pytest.fail("confirmation called setHosts")

    monkeypatch.setattr(provider_keyed_dns_cleanup_manifest, "_namecheap_dns_client",
                        lambda: ChangedZone())
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
        engagement_teardown.start_engagement_teardown(
            core.id, {"confirmation": preview["confirmationPhrase"],
                      "snapshotId": preview["snapshotId"]},
            job_repository=jobs, sketch_repository=ChainRepository([]),
            provider_resource_repository=ResourceRepository(), domain_repository=repo,
            inspector_state_reader=lambda _id: {},
            provider_keyed_coordinator=lambda *_a: pytest.fail("keyed GO reached"),
            provider_keyed_environment="devtest",
        )
    assert "scope changed" in exc.value.errors[0]
    assert jobs.get(engagement_teardown._parent_id(core.id)) is None


def test_confirmed_queued_keyed_parent_preview_uses_sealed_manifest_without_namecheap(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "keyed-dns-sealed-preview.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    repo = DomainRepository([_domain_assignment()], [_domain_asset()])
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository([]), resources=ResourceRepository(),
        domain_repository=repo)
    parent = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
        status="queued", finished_at=None,
        input={**failed_comprehensive_teardown().input, "scopeSnapshot": snapshot})
    jobs.save(parent)
    monkeypatch.setattr(engagement_teardown, "_current_scope_snapshot",
                        lambda *_a, **_kw: pytest.fail("queued parent rebuilt DNS manifest"))
    preview = engagement_teardown.preview_engagement_teardown(
        parent.id, job_repository=jobs, sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository(), domain_repository=repo,
        inspector_state_reader=lambda _id: {},
    )
    assert preview["snapshotId"] == snapshot["snapshotId"]
    assert "private sentinel" not in str(preview)


@pytest.mark.parametrize("status", ["queued", "running"])
@pytest.mark.parametrize("selected_parent", [False, True])
def test_repeat_keyed_start_uses_sealed_parent_without_provider_reads(
        tmp_path, monkeypatch, status, selected_parent):
    jobs = SqliteJobRepository(tmp_path / f"keyed-repeat-{status}-{selected_parent}.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    repo = DomainRepository([_domain_assignment()], [_domain_asset()])
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository([]), resources=ResourceRepository(),
        domain_repository=repo)
    events = [JobEvent(1, "info", "engagement teardown queued",
                       {"snapshotId": snapshot["snapshotId"]})]
    if status == "running":
        events.append(JobEvent(2, "info", "keyed coordinator in progress", {}))
    parent = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
        status=status, started_at=core.started_at if status == "running" else None,
        finished_at=None,
        input={**failed_comprehensive_teardown().input, "scopeSnapshot": snapshot,
               "phase": "provider_cleanup" if status == "running" else "queued",
               "mutation": True}, events=events)
    jobs.save(parent)
    monkeypatch.setattr(engagement_teardown, "_current_scope_snapshot",
                        lambda *_a, **_kw: pytest.fail("repeat keyed start rebuilt retired scope"))
    calls = []
    selected = parent.id if selected_parent else core.id
    result = engagement_teardown.start_engagement_teardown(
        selected, {"confirmation": snapshot["confirmationPhrase"],
                   "snapshotId": snapshot["snapshotId"]},
        job_repository=jobs, sketch_repository=ChainRepository([]),
        provider_resource_repository=ResourceRepository(), domain_repository=repo,
        inspector_state_reader=lambda _id: {},
        provider_keyed_coordinator=lambda parent_id: calls.append(parent_id),
        provider_keyed_environment="devtest",
    )
    assert result == parent
    assert calls == ([parent.id] if status == "queued" else [])


def test_completed_keyed_parent_preview_and_start_use_sealed_scope_after_dns_removal(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "keyed-dns-completed-preview.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    repo = DomainRepository([_domain_assignment()], [_domain_asset()])
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository([]), resources=ResourceRepository(),
        domain_repository=repo)
    done = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
        status="succeeded", input={**failed_comprehensive_teardown().input,
                                   "scopeSnapshot": snapshot})
    jobs.save(done)
    monkeypatch.setattr(engagement_teardown, "_current_scope_snapshot",
                        lambda *_a, **_kw: pytest.fail("completed teardown rebuilt provider/DNS scope"))
    for selected in (done.id, core.id):
        preview = engagement_teardown.preview_engagement_teardown(
            selected, job_repository=jobs, sketch_repository=ChainRepository([]),
            provider_resource_repository=ResourceRepository(), domain_repository=repo,
            inspector_state_reader=lambda _id: {},
        )
        assert preview["snapshotId"] == snapshot["snapshotId"]
        returned = engagement_teardown.start_engagement_teardown(
            selected, {"confirmation": preview["confirmationPhrase"],
                       "snapshotId": preview["snapshotId"]},
            job_repository=jobs, sketch_repository=ChainRepository([]),
            provider_resource_repository=ResourceRepository(), domain_repository=repo,
            inspector_state_reader=lambda _id: {},
            provider_keyed_coordinator=lambda *_a: pytest.fail("completed GO reached"),
            provider_keyed_environment="devtest",
        )
        assert returned == done


def test_failed_keyed_parent_requires_recovery_before_any_fresh_provider_read(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "keyed-dns-failed-recovery.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    repo = DomainRepository([_domain_assignment()], [_domain_asset()])
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository([]), resources=ResourceRepository(),
        domain_repository=repo)
    failed = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
        input={**failed_comprehensive_teardown().input, "scopeSnapshot": snapshot})
    jobs.save(failed)
    monkeypatch.setattr(engagement_teardown, "_current_scope_snapshot",
                        lambda *_a, **_kw: pytest.fail("failed keyed parent reread deleted DNS"))
    for selected in (failed.id, core.id):
        preview = engagement_teardown.preview_engagement_teardown(
            selected, job_repository=jobs, sketch_repository=ChainRepository([]),
            provider_resource_repository=ResourceRepository(), domain_repository=repo,
            inspector_state_reader=lambda _id: {},
        )
        assert preview["snapshotId"] == snapshot["snapshotId"]
        with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
            engagement_teardown.start_engagement_teardown(
                selected, {"confirmation": preview["confirmationPhrase"],
                           "snapshotId": preview["snapshotId"]},
                job_repository=jobs, sketch_repository=ChainRepository([]),
                provider_resource_repository=ResourceRepository(), domain_repository=repo,
                inspector_state_reader=lambda _id: {},
                provider_keyed_coordinator=lambda *_a: pytest.fail("failed keyed GO reached"),
                provider_keyed_environment="devtest",
            )
        assert "phase-specific recovery" in exc.value.errors[0]
    assert jobs.get(failed.id) == failed


def test_keyed_parent_job_detail_api_does_not_expose_raw_dns_content(client, tmp_path, monkeypatch):
    import json
    from app.storage.job_repository import SqlAlchemyJobRepository

    jobs = SqliteJobRepository(tmp_path / "keyed-dns-api-review.sqlite")
    core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
    monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: _keyed_review_scope())
    snapshot = engagement_teardown._scope_snapshot(
        core, jobs=jobs, chains=ChainRepository([]), resources=ResourceRepository(),
        domain_repository=DomainRepository([_domain_assignment()], [_domain_asset()]))
    parent = replace(failed_comprehensive_teardown(engagement_teardown._parent_id(core.id)),
        input={**failed_comprehensive_teardown().input, "scopeSnapshot": snapshot})
    assert "private sentinel" not in str(parent.input)
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(parent)
    response = client.get(f"/api/jobs/{parent.id}")
    assert response.status_code == 200
    body = json.dumps(response.get_json())
    assert "private sentinel" not in body
    entry = response.get_json()["job"]["input"]["scopeSnapshot"]["dnsCleanupManifest"]["domains"][0]
    assert "preservedRecords" not in entry and "cleanupPlan" not in entry


def _real_keyed_dns_barrier_fixture(tmp_path, monkeypatch):
    from app.storage.database import db
    from app.storage.models import DomainAssetModel, DomainAssignmentModel, EngagementModel
    from app.storage.job_repository import SqlAlchemyJobRepository

    state = db.configure(f"sqlite:///{tmp_path / 'keyed-domain-fence.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(
            id="eng-1", name="Cleanup Test", status="deployed", owner="example_operator_three",
            template_id="small-dev", input_parameters={}, sketch_state_schema="provider-keyed-v2",
        ))
        db.session.add(DomainAssetModel(id="domain-1", domain_name="alpha.example", registrar="namecheap"))
        db.session.add(DomainAssignmentModel(
            domain_id="domain-1", engagement_id="eng-1", engagement_name="Cleanup Test",
            purpose="other", status="active", assigned_by="example_operator_three",
            assigned_at=datetime.now(timezone.utc),
        ))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        core = _save_keyed_core_with_host_binding(jobs, monkeypatch)
        monkeypatch.setattr(provider_keyed_teardown_scope, "build_digitalocean_keyed_teardown_scope",
                            lambda *_a, **_kw: _keyed_review_scope())
        preview = engagement_teardown.preview_engagement_teardown(
            core.id, job_repository=jobs, sketch_repository=ChainRepository([]),
            provider_resource_repository=ResourceRepository(), inspector_state_reader=lambda _id: {},
        )
    return state, jobs, core, preview


@pytest.mark.parametrize("drift", ["released", "missing_asset", "other_active", "registrar"])
def test_real_sqlite_parent_insert_fence_rolls_back_late_dns_drift(tmp_path, monkeypatch, drift):
    from sqlalchemy import text
    from app.storage.database import db
    from app.storage.models import DomainAssignmentModel, DomainAssetModel, JobEventModel

    state, jobs, core, preview = _real_keyed_dns_barrier_fixture(tmp_path, monkeypatch)
    with db.bind(state):
        original = jobs.insert_inspector_teardown_barrier

        def drift_before_writer_slot(candidate):
            if drift == "released":
                db.session.query(DomainAssignmentModel).filter_by(domain_id="domain-1").update(
                    {"status": "released"})
            elif drift == "missing_asset":
                db.session.execute(text("DELETE FROM domain_assets WHERE id = 'domain-1'"))
            elif drift == "other_active":
                db.session.add(DomainAssignmentModel(
                    domain_id="domain-1", engagement_id="eng-2", engagement_name="Other",
                    purpose="other", status="active", assigned_by="other",
                    assigned_at=datetime.now(timezone.utc),
                ))
            else:
                db.session.query(DomainAssetModel).filter_by(id="domain-1").update(
                    {"registrar": "other"})
            db.session.commit()
            return original(candidate)

        monkeypatch.setattr(jobs, "insert_inspector_teardown_barrier", drift_before_writer_slot)
        with pytest.raises(engagement_teardown.EngagementTeardownValidationError) as exc:
            engagement_teardown.start_engagement_teardown(
                core.id, {"confirmation": preview["confirmationPhrase"],
                          "snapshotId": preview["snapshotId"]},
                job_repository=jobs, sketch_repository=ChainRepository([]),
                provider_resource_repository=ResourceRepository(), inspector_state_reader=lambda _id: {},
                provider_keyed_coordinator=lambda *_a: pytest.fail("keyed GO reached"),
                provider_keyed_environment="devtest",
            )
        assert "review the current cleanup scope" in exc.value.errors[0]
        assert jobs.get(engagement_teardown._parent_id(core.id)) is None
        assert db.session.query(JobEventModel).filter_by(
            job_id=engagement_teardown._parent_id(core.id)).count() == 0


def test_real_sqlite_parent_insert_holds_writer_slot_through_dns_inventory_read(tmp_path, monkeypatch):
    import sqlite3
    from threading import Event, Thread

    from app.storage.database import db
    from app.storage.models import DomainAssignmentModel

    state, jobs, core, preview = _real_keyed_dns_barrier_fixture(tmp_path, monkeypatch)
    writer_started = Event()
    writer_finished = Event()
    writer_errors = []
    writer_thread = None
    original = engagement_teardown._active_keyed_domain_assignments
    read_count = 0

    def concurrent_release():
        try:
            with sqlite3.connect(tmp_path / "keyed-domain-fence.sqlite", timeout=3) as connection:
                writer_started.set()
                connection.execute(
                    "UPDATE domain_assignments SET status = 'released' WHERE domain_id = ?",
                    ("domain-1",),
                )
                connection.commit()
        except Exception as exc:
            writer_errors.append(exc)
        finally:
            writer_finished.set()

    def read_while_other_writer_waits(engagement_id, repository):
        nonlocal read_count, writer_thread
        read_count += 1
        if read_count == 1:
            return original(engagement_id, repository)
        writer_thread = Thread(target=concurrent_release, daemon=True)
        writer_thread.start()
        assert writer_started.wait(1)
        assert not writer_finished.wait(0.1), "assignment writer passed the parent INSERT lock"
        return original(engagement_id, repository)

    monkeypatch.setattr(engagement_teardown, "_active_keyed_domain_assignments",
                        read_while_other_writer_waits)
    try:
        with db.bind(state):
            result = engagement_teardown.start_engagement_teardown(
                core.id, {"confirmation": preview["confirmationPhrase"],
                          "snapshotId": preview["snapshotId"]},
                job_repository=jobs, sketch_repository=ChainRepository([]),
                provider_resource_repository=ResourceRepository(), inspector_state_reader=lambda _id: {},
                provider_keyed_coordinator=lambda _id: None,
                provider_keyed_environment="devtest",
            )
            assert result.id == engagement_teardown._parent_id(core.id)
            assert result.status == "queued"
            assert jobs.get(result.id) == result
        assert writer_finished.wait(3)
        assert writer_errors == []
        assert read_count == 2
        with db.bind(state):
            assert db.session.query(DomainAssignmentModel).filter_by(
                domain_id="domain-1", status="released",
            ).count() == 1
    finally:
        if writer_thread is not None:
            writer_thread.join(timeout=3)
