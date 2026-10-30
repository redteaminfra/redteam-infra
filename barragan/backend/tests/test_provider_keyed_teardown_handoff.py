# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network terminal handoff from audited bootstrap to a retained core lease."""

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import engagement_teardown as teardown
from app.services import provider_keyed_teardown_handoff as handoff
from app.storage.job_repository import handoff_claim_digest
from test_provider_keyed_teardown_quiescence import _completed


class LeasePlans:
    def __init__(self, plan):
        self.plan = plan
        self.lease = (plan.id, "provider_keyed_initial")
        self.calls = []
        self.reject = False

    def get(self, plan_id):
        return self.plan if plan_id == self.plan.id else None

    def retag_if_operation(self, engagement_id, owner_id, old, new):
        self.calls.append((engagement_id, owner_id, old, new))
        if self.reject or self.lease != (owner_id, old):
            raise ValueError("stale lease")
        self.lease = (owner_id, new)


def _fixture(tmp_path):
    jobs, bootstrap_parent, workspace, seed_scope = _completed(tmp_path)
    core = jobs.get("job-core")
    engagement_id = core.input["engagementId"]
    plan_id = core.input["corePlanId"]
    resources = [
        {"address": address, "id": str(index), "kind": kind}
        for index, (address, kind) in enumerate(sorted([
            ('digitalocean_ssh_key.key', 'ssh_key'),
            ('digitalocean_firewall.firewall', 'firewall'),
            ('local_file.ansible_inventory[0]', 'local_file'),
            ('local_file.ssh_stanza[0]', 'local_file'),
            ('digitalocean_droplet.middle["m1"]', 'droplet'),
        ]), 1)
    ]
    scope = {
        **seed_scope, "provider": "digitalocean", "revisionId": "revision-1",
        "selectorTag": "opaque-selector", "resources": resources,
    }
    snapshot = {
        "engagementId": engagement_id, "coreJobId": core.id,
        "confirmationPhrase": "destroy test",
        "engagementName": "test", "chains": [], "ownedProviderRecordIds": [],
        "excludedUnmanagedProviderRecords": [],
        "core": {"jobId": core.id, "workspace": str(workspace), "proxyCount": 2},
        "publicVerificationTargets": [],
        "domainAssignments": [],
        "inspector": {"tracked": False, "ownedProviderRecordIds": [],
                      "recordOwners": {}, "verificationTargetCount": 0},
        "providerScopes": [scope],
        "providerScopeSha256": teardown._fingerprint({"providerScopes": [scope]}),
    }
    dns_manifest = {
        "schema": "provider-keyed-dns-cleanup-manifest-v1",
        "engagementId": engagement_id, "coreJobId": core.id,
        "providerScopeSha256": snapshot["providerScopeSha256"],
        "bindingSha256": "a" * 64,
        "initialJobId": f"job-provider-keyed-initial-{core.id.removeprefix('job-')}",
        "initialJournalSha256": "b" * 64,
        "domainAssignments": [], "domains": [],
    }
    dns_manifest["manifestSha256"] = "sha256:" + teardown._fingerprint(dns_manifest)
    snapshot["dnsCleanupManifest"] = dns_manifest
    snapshot["snapshotId"] = teardown._fingerprint(snapshot)
    queued = jobs.save(replace(
        bootstrap_parent, id=teardown._parent_id(core.id),
        action=teardown.ENGAGEMENT_TEARDOWN_ACTION, status="queued",
        started_at=None, finished_at=None,
        input={"engagementId": engagement_id, "coreJobId": core.id,
               "scopeSnapshot": snapshot, "phase": "queued", "mutation": True,
               "outcomes": {}, "remainingOwnedResources": [], "confirmation": "redacted"},
        events=[JobEvent(1, "info", "engagement teardown queued",
                         {"snapshotId": snapshot["snapshotId"]})],
    ))
    plans = LeasePlans(SimpleNamespace(id=plan_id, engagement_id=engagement_id,
                                      status="applied", apply_job_id=core.id))
    options = dict(
        environment="devtest", job_repository=jobs, plan_repository=plans,
        lease_lookup=lambda _engagement: plans.lease,
        scope_builder=lambda *_a, **_kw: scope,
        now=lambda: datetime(2026, 10, 8, tzinfo=timezone.utc),
        token_factory=lambda: "a" * 32,
    )
    return jobs, bootstrap_parent, queued, scope, plans, options


def test_terminal_handoff_retains_same_lease_and_fences_bootstrap(tmp_path):
    jobs, old_parent, queued, scope, plans, options = _fixture(tmp_path)
    fenced = handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    assert fenced.input["phase"] == "teardown_handoff_pending"
    assert fenced.input["claimOwner"] == handoff._HANDOFF_OWNER
    assert fenced.input["claimToken"] != old_parent.input["claimToken"]
    assert fenced.events[-1].data == {
        "phase": "teardown_handoff_pending",
        "sourceEventSha256": handoff.job_event_digest(old_parent.events),
        "scopeSnapshotSha256": teardown._fingerprint(queued.input["scopeSnapshot"]),
        "handoffClaimSha256": handoff_claim_digest(
            owner=fenced.input["claimOwner"], token=fenced.input["claimToken"],
            claimed_at=fenced.input["claimClaimedAt"],
            expires_at=fenced.input["claimExpiresAt"],
        ),
    }
    assert plans.calls == [(queued.target_id, scope["corePlanId"],
                            "provider_keyed_initial", "provider_keyed_teardown_fence")]
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
    assert jobs.save_if_leased(old_parent, owner=old_parent.input["claimOwner"],
                               token=old_parent.input["claimToken"]) is None
    assert jobs.get(queued.id) == queued


@pytest.mark.parametrize("drift", ["queued_status", "scope", "snapshot_field", "core_plan", "lease", "parent_phase"])
def test_stale_boundary_fails_before_handoff(tmp_path, drift):
    jobs, parent, queued, scope, plans, options = _fixture(tmp_path)
    if drift == "queued_status":
        jobs.save(replace(queued, status="running"))
    elif drift == "scope":
        options["scope_builder"] = lambda *_a, **_kw: {**scope, "selectorTag": "changed"}
    elif drift == "snapshot_field":
        changed = {**queued.input["scopeSnapshot"], "engagementName": "after-confirmation-change"}
        jobs.save(replace(queued, input={**queued.input, "scopeSnapshot": changed}))
    elif drift == "core_plan":
        plans.plan.status = "failed"
    elif drift == "lease":
        plans.lease = (plans.plan.id, "unrelated")
    else:
        jobs.save(replace(parent, input={**parent.input, "phase": "bootstrap_root_started"}))
    with pytest.raises(handoff.ProviderKeyedTeardownHandoffError):
        handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    assert plans.calls == []
    assert jobs.get(parent.id).input["phase"] != "teardown_handoff_pending"


def test_cas_race_does_not_retag(tmp_path):
    jobs, parent, queued, _scope, plans, options = _fixture(tmp_path)
    original = jobs.fence_terminal_provider_bootstrap_handoff
    def lost(*args, **kwargs):
        jobs.save(replace(parent, input={**parent.input, "phase": "attention"}))
        return original(*args, **kwargs)
    jobs.fence_terminal_provider_bootstrap_handoff = lost
    with pytest.raises(handoff.ProviderKeyedTeardownHandoffError):
        handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    assert plans.calls == []
    assert plans.lease == (plans.plan.id, "provider_keyed_initial")


def test_teardown_scope_race_after_cas_leaves_pending_without_retag(tmp_path):
    jobs, parent, queued, _scope, plans, options = _fixture(tmp_path)
    original = jobs.fence_terminal_provider_bootstrap_handoff
    def drift(*args, **kwargs):
        result = original(*args, **kwargs)
        changed = {**queued.input["scopeSnapshot"], "engagementName": "changed"}
        jobs.save(replace(queued, input={**queued.input, "scopeSnapshot": changed}))
        return result
    jobs.fence_terminal_provider_bootstrap_handoff = drift
    with pytest.raises(handoff.ProviderKeyedTeardownHandoffError):
        handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    assert jobs.get(parent.id).input["phase"] == "teardown_handoff_pending"
    assert plans.calls == []
    assert plans.lease == (plans.plan.id, "provider_keyed_initial")


def test_final_reread_detects_drift_after_retag(tmp_path):
    jobs, parent, queued, _scope, plans, options = _fixture(tmp_path)
    original = plans.retag_if_operation
    def retag_then_drift(*args):
        original(*args)
        changed = {**queued.input["scopeSnapshot"], "engagementName": "late-change"}
        jobs.save(replace(queued, input={**queued.input, "scopeSnapshot": changed}))
    plans.retag_if_operation = retag_then_drift
    with pytest.raises(handoff.ProviderKeyedTeardownHandoffError):
        handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    assert jobs.get(parent.id).input["phase"] == "teardown_handoff_pending"
    assert plans.lease == (plans.plan.id, "provider_keyed_teardown_fence")


def test_retag_failure_leaves_pending_and_safe_retry_retags_once(tmp_path):
    jobs, parent, queued, _scope, plans, options = _fixture(tmp_path)
    plans.reject = True
    with pytest.raises(handoff.ProviderKeyedTeardownHandoffError):
        handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    pending = jobs.get(parent.id)
    assert pending.input["phase"] == "teardown_handoff_pending"
    assert pending.events[-1].data["sourceEventSha256"] == handoff.job_event_digest(parent.events)
    assert plans.lease == (plans.plan.id, "provider_keyed_initial")
    assert jobs.get(queued.id) == queued
    plans.reject = False
    recovered = handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    assert recovered == pending
    assert len(plans.calls) == 2
    assert plans.lease == (plans.plan.id, "provider_keyed_teardown_fence")
    assert jobs.get(parent.id) == pending
    with pytest.raises(handoff.ProviderKeyedTeardownHandoffError):
        handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    assert len(plans.calls) == 2


@pytest.mark.parametrize("drift", ["scope", "source_event", "handoff_event", "new_event", "scratch", "lease", "core", "claim_token", "claim_claimed_at", "claim_expires_at"])
def test_pending_retry_rejects_drift_without_retag(tmp_path, drift):
    jobs, parent, queued, scope, plans, options = _fixture(tmp_path)
    plans.reject = True
    with pytest.raises(handoff.ProviderKeyedTeardownHandoffError):
        handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    pending = jobs.get(parent.id)
    plans.reject = False
    if drift == "scope":
        changed = {**queued.input["scopeSnapshot"], "engagementName": "changed"}
        jobs.save(replace(queued, input={**queued.input, "scopeSnapshot": changed}))
    elif drift == "source_event":
        events = list(pending.events)
        events[0] = replace(events[0], message="changed source event")
        jobs.save(replace(pending, events=events))
    elif drift == "handoff_event":
        events = list(pending.events)
        events[-1] = replace(events[-1], data={**events[-1].data, "scopeSnapshotSha256": "0" * 64})
        jobs.save(replace(pending, events=events))
    elif drift == "new_event":
        jobs.save(replace(pending, events=[*pending.events,
            JobEvent(len(pending.events) + 1, "info", "unexpected later event", {})]))
    elif drift == "scratch":
        preparation = next(event for event in pending.events
                           if event.message == "provider bootstrap preparation fenced")
        (handoff.Path(preparation.data["scratchPaths"][0]) / "keys").mkdir()
    elif drift == "lease":
        plans.lease = (plans.plan.id, "other_operation")
    elif drift in {"claim_token", "claim_claimed_at", "claim_expires_at"}:
        key = {"claim_token": "claimToken", "claim_claimed_at": "claimClaimedAt",
               "claim_expires_at": "claimExpiresAt"}[drift]
        jobs.save(replace(pending, input={**pending.input, key: "same-owner-rotated"}))
    else:
        core = jobs.get(scope["coreJobId"])
        jobs.save(replace(core, input={**core.input, "pendingSketchChainIds": ["changed"]}))
    with pytest.raises(handoff.ProviderKeyedTeardownHandoffError):
        handoff.handoff_terminal_provider_keyed_teardown(queued.id, **options)
    assert len(plans.calls) == 1
    assert jobs.get(parent.id).input["phase"] == "teardown_handoff_pending"
