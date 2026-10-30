# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted first-provider proof never replays Apply or accepts uncertain state."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_append_first_poststate import (
    MixedAppendFirstPoststateAttention,
)
import app.services.provider_keyed_mixed_append_first_proof_job as service
from app.services.provider_keyed_mixed_append_pair_apply_child import (
    ACTION as APPLY_ACTION, _base as apply_base, _child_id as apply_child_id,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
from app.services.provider_keyed_mixed_append_pair_parent import _digest, _plan_child_id
from app.services.provider_keyed_mixed_initial_apply_child import _child_id as initial_child_id
from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_parent_id
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_append_first_poststate import _case


def _ready(provider):
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-one", owner_id="plan-core",
            operation="provider_keyed_mixed_append"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        now = datetime.now(timezone.utc).isoformat()
        prior = _case(provider)
        receipt_sha = "e" * 64
        parent = StoredJobRun(
            "job-pair", "provider_keyed_mixed_append", "running",
            "engagement:eng-one", "engagement", "eng-one", "operator",
            {"schema": "mixed-append-pair-parent-v1", "phase": "apply_sealed",
             "coreJobId": "job-core", "corePlanId": "plan-core",
             "reviewSha256": "a" * 64,
             "providerOrder": [provider, "linode" if provider == "digitalocean" else "digitalocean"],
             "receiptSha256": {provider: receipt_sha}},
            [], now, now, None, [JobEvent(1, "info", "mixed append pair approved",
                                          {"reviewSha256": "a" * 64})])
        jobs.save(parent)
        parent = jobs.get(parent.id)
        messages = [
            ("mixed append first Apply queued", {}),
            ("mixed append first Apply started", {}),
            ("mixed append first Apply command intended", {
                "invocationId": "one", "argvSha256": "d" * 64,
                "planSha256": "b" * 64, "planPath": "/saved.tfplan",
                "terraformPath": "/terraform", "terraformSha256": "c" * 64}),
            ("mixed append first Apply command started before GO", {
                "invocationId": "one", "bootId": "boot", "pid": 123,
                "pgid": 123, "startTicks": 99}),
            ("mixed append first phase apply_started", {"commandStartSequence": 4}),
            ("mixed append first Apply command result fenced", {
                "invocationId": "one", "returnCode": 0,
                "stdoutBytes": 0, "stderrBytes": 0,
                "stdoutTruncated": False, "stderrTruncated": False}),
            ("mixed append first phase applied", {"commandResultSequence": 6}),
            ("mixed append first awaiting exact poststate proof", {"commandResultSequence": 6}),
        ]
        child = StoredJobRun(
            apply_child_id(parent.id), APPLY_ACTION, "running", parent.target,
            parent.target_type, parent.target_id, parent.requested_by,
            apply_base(parent), [], now, now, None,
            [JobEvent(index, "info", message, data)
             for index, (message, data) in enumerate(messages, 1)])
        jobs.save(child)
        receipt = {"provider": provider, "engagementId": "eng-one",
                   "coreJobId": "job-core", "planSha256": "b" * 64,
                   "terraformBinarySha256": "c" * 64,
                   "predecessorStateSha256": hashlib.sha256(
                       prior["predecessor_state"]).hexdigest()}
        source = service._ApprovedFirstSource(
            object(), prior["intent"], receipt, receipt_sha,
            prior["predecessor_state"], prior["reviewed_show_json"])
    return state, jobs, parent, child, prior, source


def _options(jobs, parent, source, snapshots, *, sleeper=lambda _: None):
    values = iter(snapshots)
    return dict(
        parent_id=parent.id, environment="devtest", job_repository=jobs,
        lease_lookup=lambda engagement: (
            (row.owner_id, row.operation) if (
                row := db.session.get(CoreMutationLeaseModel, engagement)) else None),
        source_loader=lambda selected, repository, release: source,
        snapshot_collector=lambda **kwargs: next(values),
        process_quiescent=lambda _: True,
        max_observation_attempts=len(snapshots),
        poll_interval_seconds=0, sleeper=sleeper,
    )


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_first_provider_proof_persists_exact_event_then_terminal(provider):
    state, jobs, parent, child, prior, source = _ready(provider)
    with db.bind(state):
        terminal = service.prove_and_finish_first_mixed_append_apply(
            **_options(jobs, parent, source, [prior["snapshot"]]))
        assert terminal.status == "succeeded"
        assert [event.sequence for event in terminal.events] == list(range(1, 11))
        assert terminal.events[8].data["provider"] == provider
        assert terminal.events[8].data["newEdgeAddress"] == prior["intent"].new_edge_address
        assert jobs.get(child.id) == terminal
        # A repeat recognizes the terminal event; it does not read the provider
        # or issue another command.
        again = service.prove_and_finish_first_mixed_append_apply(
            **_options(jobs, parent, source, []))
        assert again == terminal


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_observed_attachment_settling_renews_claim(provider):
    state, jobs, parent, _, prior, source = _ready(provider)
    snapshot = prior["snapshot"]
    if provider == "digitalocean":
        incomplete = replace(snapshot, selector_resources_count=2)
    else:
        incomplete = replace(snapshot, linode_firewall_attached_node_ids=("1001", "1002"))
    sleeps = []
    with db.bind(state):
        terminal = service.prove_and_finish_first_mixed_append_apply(
            **_options(jobs, parent, source, [incomplete, snapshot],
                       sleeper=lambda value: sleeps.append(value)))
        assert terminal.status == "succeeded"
        assert sleeps == [0]


def test_crash_after_proof_event_reobserves_before_terminal(monkeypatch):
    state, jobs, parent, child, prior, source = _ready("linode")
    with db.bind(state):
        finish = jobs.finish_if_running_claimed
        monkeypatch.setattr(jobs, "finish_if_running_claimed", lambda *a, **k: None)
        with pytest.raises(service.MixedAppendFirstProofJobAttention):
            service.prove_and_finish_first_mixed_append_apply(
                **_options(jobs, parent, source, [prior["snapshot"]]))
        persisted = jobs.get(child.id)
        assert persisted.status == "running" and len(persisted.events) == 9
        monkeypatch.setattr(jobs, "finish_if_running_claimed", finish)
        terminal = service.prove_and_finish_first_mixed_append_apply(
            **_options(jobs, parent, source, [prior["snapshot"]]),
            claim_owner=persisted.input["claimOwner"],
            claim_token=persisted.input["claimToken"])
        assert terminal.status == "succeeded" and len(terminal.events) == 10


def test_terminal_replay_rejects_changed_proof_payload():
    state, jobs, parent, child, prior, source = _ready("digitalocean")
    with db.bind(state):
        terminal = service.prove_and_finish_first_mixed_append_apply(
            **_options(jobs, parent, source, [prior["snapshot"]]))
        altered = list(terminal.events)
        altered[8] = replace(altered[8], data={**altered[8].data,
                                                "newEdgeProviderId": "different"})
        jobs.save(replace(terminal, events=altered))
        with pytest.raises(service.MixedAppendFirstProofJobAttention):
            service.prove_and_finish_first_mixed_append_apply(
                **_options(jobs, parent, source, []))


def test_active_other_claim_blocks_proof_before_inventory():
    state, jobs, parent, child, prior, source = _ready("digitalocean")
    with db.bind(state):
        now = datetime.now(timezone.utc).isoformat()
        claimed = jobs.claim_lease(
            child.id, owner="other", token="other-token", claimed_at=now,
            expires_at=(datetime.fromisoformat(now) + timedelta(minutes=5)).isoformat(),
            eligible_statuses={"running"})
        assert claimed is not None
        reads = []
        options = _options(jobs, parent, source, [prior["snapshot"]])
        options["snapshot_collector"] = lambda **kwargs: reads.append(1)
        with pytest.raises(service.MixedAppendFirstProofJobAttention):
            service.prove_and_finish_first_mixed_append_apply(**options)
        assert reads == []


@pytest.mark.parametrize("drift", ["uncertain_result", "poststate", "lease"])
def test_uncertain_or_drift_never_records_proof(drift):
    state, jobs, parent, child, prior, source = _ready("digitalocean")
    with db.bind(state):
        if drift == "uncertain_result":
            events = list(child.events)
            events[5] = replace(events[5], data={**events[5].data, "returnCode": 1})
            jobs.save(replace(child, events=events))
        elif drift == "lease":
            db.session.get(CoreMutationLeaseModel, parent.target_id).operation = "other"
            db.session.commit()
        else:
            prior["snapshot"] = replace(prior["snapshot"], state_sha256="f" * 64)
        with pytest.raises(service.MixedAppendFirstProofJobAttention):
            service.prove_and_finish_first_mixed_append_apply(
                **_options(jobs, parent, source, [prior["snapshot"]]))
        assert len(jobs.get(child.id).events) == 8


def test_approved_source_rejects_predecessor_snapshot_tamper_after_apply(tmp_path, monkeypatch):
    """Live terraform.tfstate has changed, but saved predecessor must stay exact."""
    prior = _case("digitalocean")
    intent = prior["intent"]
    root = tmp_path / "workspace"
    root.mkdir()
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", "digitalocean", "cred-id", "fingerprint",
        "revision", "source-sha")

    def write(name, value):
        path = root / name
        path.write_bytes(value)
        path.chmod(0o600)
        return hashlib.sha256(value).hexdigest()

    predecessor_sha = write(_name("digitalocean", "predecessor.tfstate"),
                            prior["predecessor_state"])
    show_sha = write(_name("digitalocean", "show.json"), prior["reviewed_show_json"])
    plan_sha = write(_name("digitalocean", "saved.tfplan"), b"saved plan")
    input_sha = write(_name("digitalocean", "inputs.json"),
                      json.dumps(intent.nonsecret_varfile).encode())
    marker_sha = write(".barragan-provider-keyed-state.json", b"marker")
    topology_sha = write(".barragan-topology.json", b"topology")
    lock_sha = write(".terraform.lock.hcl", b"lock")
    release = tmp_path / "terraform"
    release.write_bytes(b"terraform")
    release_sha = hashlib.sha256(release.read_bytes()).hexdigest()
    receipt = {
        "schema": "mixed-append-saved-plan-receipt-v1",
        "provider": "digitalocean", "engagementId": "eng-one",
        "coreJobId": "job-core", "chainId": intent.chain_id,
        "newEdgeAddress": intent.new_edge_address,
        "predecessorStateSha256": predecessor_sha,
        "showJsonSha256": show_sha, "planSha256": plan_sha,
        "inputSha256": input_sha, "sourceMarkerSha256": marker_sha,
        "topologySha256": topology_sha, "lockfileSha256": lock_sha,
        "sourceRevision": "revision", "sourceSha256": "source-sha",
        "credentialRecordId": "cred-id", "terraformBinarySha256": release_sha,
        "journalSha256": "a" * 64,
    }
    receipt_sha = write(_name("digitalocean", "plan-receipt.json"),
                        json.dumps(receipt).encode())
    manifest = {"historical": "binding"}
    now = datetime.now(timezone.utc).isoformat()
    parent = StoredJobRun(
        "job-pair", "provider_keyed_mixed_append", "running",
        "engagement:eng-one", "engagement", "eng-one", "operator",
        {"schema": "mixed-append-pair-parent-v1", "phase": "apply_sealed",
         "engagementId": "eng-one", "coreJobId": "job-core",
         "providerOrder": ["digitalocean", "linode"],
         "reviewSha256": "b" * 64, "requestSha256": "c" * 64,
         "bindingManifestSha256": _digest(manifest),
         "receiptSha256": {"digitalocean": receipt_sha},
         "intents": {"digitalocean": asdict(intent)},
         "reviewedInputs": {"digitalocean": intent.nonsecret_varfile}},
        [], now, now, None, [JobEvent(1, "info", "mixed append pair approved", {
            "reviewSha256": "b" * 64, "planChildId": _plan_child_id("job-pair")})])
    plan_child = replace(parent, id=_plan_child_id(parent.id), status="succeeded",
                         input={"requestSha256": "c" * 64},
                         events=[JobEvent(1, "info", "mixed append pair plan reviewed",
                                          {"reviewSha256": "b" * 64})])
    rows = {
        plan_child.id: plan_child,
        initial_parent_id("job-core"): parent,
        _binding_child_id("job-core"): parent,
        initial_child_id("job-core", "digitalocean"): parent,
    }
    jobs = SimpleNamespace(get=rows.get)
    monkeypatch.setattr(service, "recognize_mixed_initial_host_binding", lambda *_: manifest)
    monkeypatch.setattr(service, "recognize_mixed_initial_apply_terminal", lambda *_: {})
    monkeypatch.setattr(service, "_prior_workspace", lambda *_: workspace)
    monkeypatch.setattr(service, "_journal_complete", lambda *_: None)
    check = lambda **_: SimpleNamespace(path=release, sha256=release_sha)
    selected = service._load_approved_first_source(parent, jobs, check)
    assert selected.predecessor_state == prior["predecessor_state"]
    (root / _name("digitalocean", "predecessor.tfstate")).write_bytes(b"changed")
    with pytest.raises(ValueError, match="approved artifact"):
        service._load_approved_first_source(parent, jobs, check)
