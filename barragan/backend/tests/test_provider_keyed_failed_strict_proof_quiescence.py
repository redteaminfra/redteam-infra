# Copyright (c) 2026, Oracle and/or its affiliates.
"""A fully captured but rejected strict host proof is a distinct teardown source."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_teardown_quiescence as audit
from app.services.engagement_teardown import _fingerprint
from app.storage.job_repository import _PROVIDER_ABSENT_PROOF_KEYS, job_event_digest
from test_provider_keyed_teardown_quiescence import _completed


def test_failed_strict_proof_reuses_complete_bootstrap_prefix(tmp_path, monkeypatch):
    jobs, parent, root, scope = _completed(tmp_path)
    monkeypatch.setattr(audit, "_recorded_group_active", lambda _data: False)
    failed = replace(parent, status="failed", finished_at="2026-10-12T00:00:00+00:00",
                     input={**parent.input, "phase": "attention"},
                     events=[*parent.events, JobEvent(len(parent.events) + 1, "error",
                        "strict host proof stopped; reconciliation required", {})])
    jobs.save(failed)
    proof = audit._audit_bootstrap(
        "job-core", confirmed_scope=scope, workspace_root=root,
        job_repository=jobs, pending_scope_sha256=None, failed_host_proof=True)
    assert proof.command_count == 8
    assert proof.chain_ids == tuple(scope["chainIds"])
    jobs.save(replace(failed, events=[*failed.events, JobEvent(
        len(failed.events) + 1, "info", "unreviewed host replay", {})]))
    with pytest.raises(audit.ProviderKeyedTeardownQuiescenceError):
        audit._audit_bootstrap(
            "job-core", confirmed_scope=scope, workspace_root=root,
            job_repository=jobs, pending_scope_sha256=None, failed_host_proof=True)


def _failed_child_fixture(root: Path):
    ids = ("chain-a", "chain-b")
    nodes = []
    rows = []
    for index, chain_id in enumerate(ids):
        persisted = []
        for role in ("middle", "edge"):
            name = f"{role}-{index}"
            address = f"digitalocean_droplet.{name}"
            instance = str(100 + len(nodes))
            nodes.append({"chainId": chain_id, "role": role, "name": name,
                          "terraformAddress": address, "providerInstanceId": instance})
            persisted.append({"role": role, "hostname": name,
                              "terraformAddress": address, "providerInstanceId": instance})
        rows.append(SimpleNamespace(chain_id=chain_id, status="pending", deploy_job_id="",
                                    teardown_job_id="", burned=False, nodes=[], edge_count=1))
    digest = "a" * 64
    core = SimpleNamespace(input={"engagementId": "eng-test", "corePlanId": "plan-test",
                                  "pendingSketchChainFingerprints": {key: key for key in ids}},
                           requested_by="test")
    parent = SimpleNamespace(id="job-provider-keyed-initial-core",
                             events=[JobEvent(1, "info", "provider host identity binding intended",
                                              {"nodes": nodes})])
    bootstrap = audit.ProviderKeyedBootstrapQuiescenceEvidence(
        parent.id, digest, ids, 8, ())
    events = [JobEvent(1, "info", "strict host proof reserved", {"manifestSha256": digest}),
              JobEvent(2, "info", "strict host proof started", {"manifestSha256": digest})]
    for node in nodes:
        fields = {"hostname": node["name"], "terraformAddress": node["terraformAddress"],
                  "providerInstanceId": node["providerInstanceId"]}
        scratch = root / f".barragan-strict-host-proof-{len(events):032x}"
        events.append(JobEvent(len(events) + 1, "info", "strict host proof scratch intended",
                               {**fields, "scratchPath": str(scratch)}))
        for _ in range(4):
            invocation = f"invocation-{len(events)}"
            events.extend([
                JobEvent(len(events) + 1, "info", "strict host proof command intended",
                         {**fields, "invocationId": invocation, "scratchPath": str(scratch),
                          "argvSha256": "b" * 64}),
                JobEvent(len(events) + 2, "info", "strict host proof command started before GO",
                         {**fields, "invocationId": invocation,
                          "bootId": "11111111-1111-4111-8111-111111111111",
                          "pid": 1000 + len(events), "pgid": 1000 + len(events),
                          "startTicks": len(events)}),
                JobEvent(len(events) + 3, "info", "strict host proof command result fenced",
                         {**fields, "invocationId": invocation, "returnCode": 0,
                          "stdoutBytes": 1, "stderrBytes": 0,
                          "stdoutTruncated": False, "stderrTruncated": False}),
            ])
        events.append(JobEvent(len(events) + 1, "info", "strict host proof capture completed",
                               fields))
    events.append(JobEvent(len(events) + 1, "error",
                           "strict host proof stopped; reconciliation required", {}))
    assert len(events) == 59
    child = SimpleNamespace(
        id="job-provider-keyed-initial-host-proof-core",
        action="provider_keyed_initial_host_proof", status="failed",
        started_at="2026-10-12T00:00:00+00:00", finished_at="2026-10-12T00:01:00+00:00",
        target_type="engagement", target="engagement:eng-test", target_id="eng-test",
        requested_by="test", artifact_refs=[], input={
            "engagementId": "eng-test", "coreJobId": "job-core", "corePlanId": "plan-test",
            "parentJobId": parent.id, "manifestSha256": digest, "mutation": False,
        }, events=events)
    jobs = SimpleNamespace(get=lambda key: child if key == child.id else None)
    sketches = SimpleNamespace(list_for_engagement=lambda _engagement: rows)
    return core, parent, bootstrap, child, jobs, sketches


def test_failed_strict_proof_requires_complete_child_and_no_scratch(tmp_path, monkeypatch):
    root = tmp_path / "provider"
    root.mkdir(mode=0o700)
    core, parent, bootstrap, child, jobs, sketches = _failed_child_fixture(root)
    monkeypatch.setattr(audit, "_recorded_group_active", lambda _data: False)
    from app.services import post_core_sketch_continuation
    monkeypatch.setattr(post_core_sketch_continuation, "sketch_chain_intent_fingerprint",
                        lambda row: row.chain_id)
    def check():
        audit._audit_failed_strict_host_child(
            "job-core", core, parent, bootstrap, root, jobs, sketch_repository=sketches)
    check()
    scratch = Path(child.events[2].data["scratchPath"])
    scratch.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        check()
    scratch.rmdir()
    original = child.events
    child.events = original[:-2] + [original[-1]]
    with pytest.raises(ValueError):
        check()
    child.events = original
    bad = list(original)
    bad[5] = replace(bad[5], data={**bad[5].data, "returnCode": 1})
    child.events = bad
    with pytest.raises(ValueError):
        check()
    child.events = original
    rows = sketches.list_for_engagement("eng-test")
    rows[0].status = "deployed"
    with pytest.raises(ValueError):
        check()
    rows[0].status = "pending"
    monkeypatch.setattr(audit, "_recorded_group_active", lambda _data: True)
    with pytest.raises(ValueError):
        check()


def test_retired_failed_strict_proof_requires_sealed_event_and_exact_rows(
        tmp_path, monkeypatch):
    root = tmp_path / "provider"
    root.mkdir(mode=0o700)
    original_core, parent, bootstrap, host_child, _jobs, sketches = _failed_child_fixture(root)
    core = SimpleNamespace(id="job-core", **vars(original_core))
    rows = sketches.list_for_engagement("eng-test")
    destroyed = SimpleNamespace(id="job-provider-keyed-initial-destroy-apply-core",
                                status="succeeded")
    for row in rows:
        row.status = "destroyed"
        row.teardown_job_id = destroyed.id
        row.terraform_working_directory = ""
    resource_ids = {
        "digitalocean_droplet.middle_1": "101",
        "digitalocean_droplet.edge_1": "102",
        "digitalocean_droplet.middle_2": "103",
        "digitalocean_droplet.edge_2": "104",
        "digitalocean_firewall.firewall": "firewall-1",
        "digitalocean_ssh_key.key": "key-1",
    }
    scope = {
        "chainIds": list(bootstrap.chain_ids),
        "chainFingerprints": {chain_id: chain_id for chain_id in bootstrap.chain_ids},
        "resources": [{"address": key, "id": value} for key, value in resource_ids.items()],
    }
    snapshot = {"snapshotId": "a" * 64, "providerScopeSha256": "b" * 64}
    teardown = SimpleNamespace(id="job-engagement-teardown-core", requested_by="test",
                               input={"scopeSnapshot": snapshot})
    event_prefix = [JobEvent(index, "info", f"coordinator record {index}", {})
                    for index in range(1, 6)]
    absence = {key: "fixture" for key in _PROVIDER_ABSENT_PROOF_KEYS}
    absence.update({"applyJobId": destroyed.id,
                    "resourceIdsSha256": _fingerprint(resource_ids),
                    "observedAt": "2026-10-12T00:00:01+00:00"})
    event_prefix.append(JobEvent(6, "info", "provider_absent", absence))
    receipt = {
        "scopeSnapshotId": snapshot["snapshotId"],
        "providerScopeSha256": snapshot["providerScopeSha256"],
        "sourceJournalSha256": job_event_digest(event_prefix),
        "applyJobId": destroyed.id,
        "resourceIdsSha256": _fingerprint(resource_ids),
        "verifiedAbsentDropletIds": ["101", "102", "103", "104"],
        "verifiedAbsentFirewallId": "firewall-1",
        "verifiedAbsentSshKeyId": "key-1",
        "confirmationCompletedAt": "2026-10-12T00:00:00+00:00",
        "confirmationExpiresAt": "2026-10-12T00:00:30+00:00",
        "chainIds": sorted(bootstrap.chain_ids),
        "chainFingerprints": {key: key for key in sorted(bootstrap.chain_ids)},
        "retiredRecordIds": [],
        "observedAt": "2026-10-12T00:00:01+00:00",
    }
    coordinator = SimpleNamespace(
        id="job-provider-keyed-comprehensive-teardown-core",
        action="provider_keyed_comprehensive_teardown", status="running",
        finished_at=None, target_type="engagement", target_id="eng-test",
        target="engagement:eng-test", requested_by="test",
        input={"coreJobId": core.id, "corePlanId": core.input["corePlanId"],
               "teardownParentId": teardown.id,
               "scopeSnapshotId": snapshot["snapshotId"],
               "providerScopeSha256": snapshot["providerScopeSha256"]},
        events=[*event_prefix, JobEvent(7, "info",
                                     "keyed_pending_provider_group_retired", receipt)],
    )
    by_id = {host_child.id: host_child, coordinator.id: coordinator}
    jobs = SimpleNamespace(get=by_id.get)
    monkeypatch.setattr(audit, "_recorded_group_active", lambda _data: False)
    monkeypatch.setattr(audit, "replace", lambda row, **changes: SimpleNamespace(
        **{**vars(row), **changes}))
    monkeypatch.setattr("app.storage.job_repository._valid_provider_absent_handoff",
                        lambda *_args: True)
    monkeypatch.setattr("app.services.post_core_sketch_continuation.sketch_chain_intent_fingerprint",
                        lambda row: row.chain_id)

    def check():
        audit._audit_failed_strict_host_child(
            core.id, core, parent, bootstrap, root, jobs, sketch_repository=sketches,
            confirmed_scope=scope, teardown=teardown, destroyed=destroyed)

    check()
    original = coordinator.events
    coordinator.events = original[:-1]
    with pytest.raises(ValueError):
        check()
    coordinator.events = [*original[:-1], replace(original[-1], data={
        **receipt, "sourceJournalSha256": "0" * 64})]
    with pytest.raises(ValueError):
        check()
    coordinator.events = original
    rows[0].teardown_job_id = "another-destroy"
    with pytest.raises(ValueError):
        check()
    rows[0].teardown_job_id = destroyed.id
    original_host_events = host_child.events
    host_child.events = original_host_events[:-2] + [original_host_events[-1]]
    with pytest.raises(ValueError):
        check()
    host_child.events = original_host_events
    check()
