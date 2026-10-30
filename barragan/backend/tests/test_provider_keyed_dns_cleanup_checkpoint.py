# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fresh, read-only DNS proof immediately ahead of keyed destroy intent."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_dns_cleanup_checkpoint as checkpoint_service
from app.services.engagement_teardown import ENGAGEMENT_TEARDOWN_ACTION, _fingerprint
from app.services.provider_keyed_dns_cleanup_checkpoint import (
    ProviderKeyedDnsCleanupCheckpointError, prove_provider_keyed_dns_cleanup_checkpoint,
)
from app.services.provider_keyed_dns_cleanup_manifest import build_provider_keyed_dns_cleanup_manifest
from app.services.provider_keyed_host_binding import _digest_json
from app.storage.job_repository import job_event_digest
from test_provider_keyed_dns_cleanup_manifest import _case


def _confirmed(count=1):
    snapshot, jobs, domains, adapter = _case(count, owned=True)
    snapshot["dnsCleanupManifest"] = build_provider_keyed_dns_cleanup_manifest(
        snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    snapshot["snapshotId"] = _fingerprint(snapshot)
    initial = jobs.get(snapshot["dnsCleanupManifest"]["initialJobId"])
    prefix = job_event_digest(initial.events)
    initial.input["phase"] = "teardown_handoff_pending"
    initial.events.append(JobEvent(len(initial.events) + 1, "info",
        "provider bootstrap claim fenced for teardown handoff", {
            "phase": "teardown_handoff_pending", "sourceEventSha256": prefix,
            "scopeSnapshotSha256": _fingerprint(snapshot),
            "handoffClaimSha256": "a" * 64,
        }))
    adapter.calls.clear()
    return snapshot, jobs, domains, adapter


def _published(monkeypatch, count):
    snapshot, jobs, domains, adapter = _case(count, owned=True)
    scope = snapshot["providerScopes"][0]
    scope["workspace"] = "/tmp/published-dns-workspace"
    snapshot["providerScopeSha256"] = _digest_json({"providerScopes": [scope]})
    core = jobs.get(snapshot["coreJobId"])
    core.events = [JobEvent(1, "info", "core complete", {})]
    initial = jobs.get("job-provider-keyed-initial-core")
    initial.status = "succeeded"
    initial.input["phase"] = "completed"
    initial.events.append(JobEvent(3, "info", "provider two-chain host proof published", {}))
    snapshot["dnsCleanupManifest"] = build_provider_keyed_dns_cleanup_manifest(
        snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    snapshot["snapshotId"] = _fingerprint(snapshot)
    sealed = {
        "engagement_id": "eng-1", "core_job_id": core.id,
        "core_plan_id": "plan-1", "initial_job_id": initial.id,
        "initial_journal_sha256": job_event_digest(initial.events),
        "core_journal_sha256": job_event_digest(core.events),
        "scope_sha256": _fingerprint(scope), "state_sha256": scope["stateSha256"],
        "manifest_sha256": "a" * 64, "published_host_evidence_sha256": "b" * 64,
        "chain_ids": scope["chainIds"], "chain_projection_sha256": "c" * 64,
    }
    parent = SimpleNamespace(id="job-engagement-teardown-core",
        action=ENGAGEMENT_TEARDOWN_ACTION, status="queued",
        target_id="eng-1", input={"phase": "queued", "scopeSnapshot": deepcopy(snapshot),
                                    "publishedSource": sealed})
    jobs.rows[parent.id] = parent
    monkeypatch.setattr(checkpoint_service, "audit_published_provider_keyed_bootstrap",
        lambda *_args, **_kwargs: SimpleNamespace(parent_job_id=initial.id,
            chain_ids=tuple(scope["chainIds"]), manifest_sha256="a" * 64))
    adapter.calls.clear()
    return snapshot, jobs, domains, adapter


@pytest.mark.parametrize("count", [0, 1, 2])
def test_published_checkpoint_reproves_full_journal_and_fresh_zones(monkeypatch, count):
    snapshot, jobs, domains, adapter = _published(monkeypatch, count)
    result = prove_provider_keyed_dns_cleanup_checkpoint(
        snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)
    assert result["dnsCleanupHandoffJournalSha256"] == job_event_digest(
        jobs.get("job-provider-keyed-initial-core").events)
    assert adapter.calls == [row["domainName"] for row in snapshot["domainAssignments"]]


@pytest.mark.parametrize("drift", ["zone", "receipt", "journal", "sealed", "parent", "status"])
def test_published_checkpoint_rejects_drift(monkeypatch, drift):
    snapshot, jobs, domains, adapter = _published(monkeypatch, 1)
    initial = jobs.get("job-provider-keyed-initial-core")
    parent = jobs.get("job-engagement-teardown-core")
    if drift == "zone":
        adapter.zones["zone-1.example"][0]["address"] = "9.9.9.9"
    elif drift == "receipt":
        domains.receipts["domain-1"].clear()
    elif drift == "journal":
        initial.events.append(JobEvent(4, "info", "unexpected", {}))
    elif drift == "sealed":
        parent.input["publishedSource"]["initial_journal_sha256"] = "0" * 64
    elif drift == "parent":
        parent.input["scopeSnapshot"]["snapshotId"] = "0" * 64
    else:
        initial.status = "running"
    with pytest.raises(ProviderKeyedDnsCleanupCheckpointError):
        prove_provider_keyed_dns_cleanup_checkpoint(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)


@pytest.mark.parametrize("count", [0, 1, 2])
def test_checkpoint_reproves_all_frozen_domains_without_provider_write(count):
    snapshot, jobs, domains, adapter = _confirmed(count)
    checks = []
    result = prove_provider_keyed_dns_cleanup_checkpoint(
        snapshot, job_repository=jobs, domain_repository=domains,
        adapter=adapter, fence=lambda: checks.append("fenced"))
    assert result["dnsCleanupManifestSha256"] == snapshot["dnsCleanupManifest"]["manifestSha256"]
    assert result["dnsCleanupCheckpointSha256"] == _fingerprint({
        "scopeSnapshotId": snapshot["snapshotId"],
        "dnsCleanupManifestSha256": result["dnsCleanupManifestSha256"],
        "dnsCleanupHandoffJournalSha256": result["dnsCleanupHandoffJournalSha256"],
    })
    assert adapter.calls == [row["domainName"] for row in snapshot["domainAssignments"]]
    assert len(checks) >= count * 2 + 2


def test_checkpoint_uses_default_domain_repository_for_normal_handoff(monkeypatch):
    snapshot, jobs, domains, adapter = _confirmed(0)
    monkeypatch.setattr(checkpoint_service, "SqlAlchemyDomainRepository", lambda: domains)
    result = prove_provider_keyed_dns_cleanup_checkpoint(
        snapshot, job_repository=jobs, adapter=adapter,
    )
    assert result["dnsCleanupManifestSha256"] == snapshot["dnsCleanupManifest"]["manifestSha256"]
    assert adapter.calls == []


@pytest.mark.parametrize("drift", [
    "zone", "receipt", "assignment", "binding", "handoff", "forged_manifest",
])
def test_checkpoint_rejects_drift_or_forged_parent_digest(drift):
    snapshot, jobs, domains, adapter = _confirmed(1)
    initial = jobs.get(snapshot["dnsCleanupManifest"]["initialJobId"])
    if drift == "zone":
        adapter.zones["zone-1.example"][0]["address"] = "9.9.9.9"
    elif drift == "receipt":
        domains.receipts["domain-1"].clear()
    elif drift == "assignment":
        domains.assignments[0].id = 9
    elif drift == "binding":
        initial.events[0] = JobEvent(1, "info", initial.events[0].message, {})
    elif drift == "handoff":
        initial.events[-1].data["sourceEventSha256"] = "0" * 64
    else:
        forged = deepcopy(snapshot["dnsCleanupManifest"])
        forged["domains"][0]["ownedRecordsSha256"] = "sha256:" + "f" * 64
        forged["domains"][0]["entrySha256"] = "sha256:" + _fingerprint({
            key: value for key, value in forged["domains"][0].items()
            if key != "entrySha256"})
        forged["manifestSha256"] = "sha256:" + _fingerprint({
            key: value for key, value in forged.items() if key != "manifestSha256"})
        snapshot["dnsCleanupManifest"] = forged
        snapshot["snapshotId"] = _fingerprint({
            key: value for key, value in snapshot.items() if key != "snapshotId"})
        initial.events[-1].data["scopeSnapshotSha256"] = _fingerprint(snapshot)
    with pytest.raises(ProviderKeyedDnsCleanupCheckpointError):
        prove_provider_keyed_dns_cleanup_checkpoint(
            snapshot, job_repository=jobs, domain_repository=domains, adapter=adapter)


def test_checkpoint_fence_loss_after_namecheap_read_prevents_proof():
    snapshot, jobs, domains, adapter = _confirmed(1)
    calls = 0
    def fence():
        nonlocal calls
        calls += 1
        if calls == 3:
            raise ValueError("lease expired")
    with pytest.raises(ProviderKeyedDnsCleanupCheckpointError):
        prove_provider_keyed_dns_cleanup_checkpoint(
            snapshot, job_repository=jobs, domain_repository=domains,
            adapter=adapter, fence=fence)
    assert adapter.calls == ["zone-1.example"]
