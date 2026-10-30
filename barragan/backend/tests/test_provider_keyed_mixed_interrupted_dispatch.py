# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private mixed cleanup reserves both provider scopes before sealing plans."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_interrupted_dispatch as service
from app.services.provider_keyed_mixed_interrupted_dispatch import (
    _core_inspector_scope as exact_core_inspector_scope,
)
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    recognize_mixed_interrupted_cleanup_checkpoint,
    recognize_mixed_interrupted_sealed_plans, propose_mixed_interrupted_cleanup, _canonical,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
    bind_mixed_interrupted_destroy_plans,
)
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedProviderScope, MixedInterruptedReview,
)
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_initial_teardown import _state_resources
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_initial_apply_proof import _state_and_rows
from test_provider_keyed_mixed_initial_bootstrap import _inputs as _bootstrap_inputs
from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
from app.services.provider_keyed_mixed_partial_apply_inventory import MixedPartialApplyInventorySnapshot
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel
import app.services.sketch_state_workspaces as state_workspaces


def exact_core_inspector_fixture_scope(core, **_kwargs):
    proxy_count = core.input.get("proxyCount", 1)
    return {"jobId": core.id, "planId": core.input["corePlanId"],
            "stateSha256": "a" * 64, "inventorySha256": "b" * 64,
            "proxyCount": proxy_count,
            "targets": [{"id": f"target-{index}"}
                        for index in range(proxy_count + 1)],
            "ownedInspectorRecordIds": ["inspector-instance", "inspector-firewall"]}


@pytest.fixture(autouse=True)
def exact_core_inspector_fixture(monkeypatch):
    """The mixed Apply fixture does not create an OCI state or Inspector host."""
    monkeypatch.setattr(service, "_core_inspector_scope",
                        exact_core_inspector_fixture_scope)


def test_exact_core_inspector_scope_uses_shared_readers_and_fails_on_drift(
        ready, monkeypatch, tmp_path):
    from types import SimpleNamespace
    import app.services.provider_keyed_mixed_zero_apply_teardown_source as source
    import app.services.provider_keyed_mixed_zero_apply_inspector_negative as negative

    jobs = ready.case.jobs
    core = jobs.get(ready.parent.input["coreJobId"])
    plan = SimpleNamespace(id=core.input["corePlanId"],
                           engagement_id=core.input["engagementId"],
                           evidence={"target": {"name": "barragan-testing"},
                                     "proxyCount": 1})
    plans = SimpleNamespace(get=lambda _id: plan)
    resources = SimpleNamespace()
    inventory = SimpleNamespace(raw_state_sha256="a" * 64,
                                inventory_sha256="b" * 64)
    calls = {"inventory": 0, "inspector": 0}

    def read_inventory(*_args):
        calls["inventory"] += 1
        return inventory

    def read_inspector(*_args):
        calls["inspector"] += 1
        return ("inspector-firewall", "inspector-instance")

    monkeypatch.setattr(source, "_core_inventory", read_inventory)
    monkeypatch.setattr(source, "_owned_inspector_records", read_inspector)
    monkeypatch.setattr(negative, "_targets", lambda *_args: [
        {"id": "tcp:8.8.8.8:22"}, {"id": "tcp:8.8.4.4:22"}])
    scope = exact_core_inspector_scope(
        core, jobs=jobs, core_state_root=tmp_path,
        plan_repository=plans, provider_resource_repository=resources)
    assert scope["proxyCount"] == 1
    assert len(scope["targets"]) == 2
    assert scope["ownedInspectorRecordIds"] == [
        "inspector-firewall", "inspector-instance"]
    assert calls == {"inventory": 2, "inspector": 2}

    monkeypatch.setattr(source, "_owned_inspector_records",
                        lambda *_args: ("inspector-instance",))
    with pytest.raises(ValueError, match="reviewed core or Inspector changed"):
        exact_core_inspector_scope(
            core, jobs=jobs, core_state_root=tmp_path,
            plan_repository=plans, provider_resource_repository=resources)


def test_saved_scope_survives_terminal_preview_without_retained_resources(
        ready, monkeypatch):
    from app.services.provider_keyed_mixed_interrupted_cleanup import (
        propose_mixed_interrupted_cleanup,
    )
    import app.services.provider_keyed_mixed_interrupted_terminal as terminal

    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    initial, jobs = ready.parent, ready.case.jobs
    core = jobs.get(initial.input["coreJobId"])
    def collector(_parent, provider, _workspace, *, fence, **_kwargs):
        return _snapshot(provider, generation=fence())
    arguments = dict(environment="devtest", state_root=ready.case.state_root,
                     job_repository=jobs, lease_lookup=ready.args["lease_lookup"],
                     process_quiescent=lambda _: True, snapshot_collector=collector)
    preview = service.preview_mixed_interrupted_cleanup(core, **arguments)
    review, *_ = service._fresh_review(
        initial, jobs=jobs, lookup=ready.args["lease_lookup"],
        state_root=ready.case.state_root, quiescent=lambda _: True,
        snapshot_collector=collector, credential_repository=None,
        linode_transport=None, digitalocean_transport=None)
    scope = exact_core_inspector_fixture_scope(core)
    queued = propose_mixed_interrupted_cleanup(
        initial, review, requested_by="operator", review_scope=scope)
    finished = replace(queued, status="succeeded")
    jobs.save(finished)
    monkeypatch.setattr(terminal, "recognize_mixed_interrupted_terminal",
                        lambda *_args, **_kwargs: finished)
    monkeypatch.setattr(terminal, "_historical_parent", lambda _parent: queued)
    monkeypatch.setattr(service, "_core_inspector_scope",
                        lambda *_args, **_kwargs: pytest.fail("retired resources must not be read"))
    result = service.preview_mixed_interrupted_cleanup(
        finished, **{**arguments,
                     "lease_lookup": lambda _: None})
    assert result["snapshotId"] == preview["snapshotId"]
    assert result["orderedScope"][1]["items"][0]["proxyCount"] == 1
    assert result["orderedScope"][3]["items"][0]["tracked"] is True


def test_changed_core_or_inspector_scope_invalidates_operator_confirmation(
        ready, monkeypatch):
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    initial, jobs = ready.parent, ready.case.jobs
    core = jobs.get(initial.input["coreJobId"])
    def collector(_parent, provider, _workspace, *, fence, **_kwargs):
        return _snapshot(provider, generation=fence())
    arguments = dict(environment="devtest", state_root=ready.case.state_root,
                     job_repository=jobs, lease_lookup=ready.args["lease_lookup"],
                     process_quiescent=lambda _: True, snapshot_collector=collector)
    preview = service.preview_mixed_interrupted_cleanup(core, **arguments)
    changed = exact_core_inspector_fixture_scope(core)
    changed["ownedInspectorRecordIds"] = ["new-inspector-instance", "inspector-firewall"]
    monkeypatch.setattr(service, "_core_inspector_scope", lambda *_args, **_kwargs: changed)
    with pytest.raises(service.MixedInterruptedDispatchAttention,
                       match="review changed"):
        service.start_mixed_interrupted_cleanup(
            core, {"snapshotId": preview["snapshotId"],
                   "confirmation": preview["confirmationPhrase"]}, **arguments)
    assert jobs.get(service.cleanup_parent_id(core.id)) is None


def test_confirmed_scope_is_saved_in_cleanup_parent(ready, monkeypatch):
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    initial, jobs = ready.parent, ready.case.jobs
    core = jobs.get(initial.input["coreJobId"])
    def collector(_parent, provider, _workspace, *, fence, **_kwargs):
        return _snapshot(provider, generation=fence())
    arguments = dict(environment="devtest", state_root=ready.case.state_root,
                     job_repository=jobs, lease_lookup=ready.args["lease_lookup"],
                     process_quiescent=lambda _: True, snapshot_collector=collector)
    monkeypatch.setattr(jobs, "reserve_mixed_interrupted_cleanup_parent",
                        lambda proposal, **_kwargs: jobs.save(proposal), raising=False)
    preview = service.preview_mixed_interrupted_cleanup(core, **arguments)
    parent = service.start_mixed_interrupted_cleanup(
        core, {"snapshotId": preview["snapshotId"],
               "confirmation": preview["confirmationPhrase"]}, **arguments)
    assert jobs.get(parent.id) == parent
    assert parent.input["reviewScope"] == exact_core_inspector_fixture_scope(core)
    assert parent.input["reviewScopeSha256"]
    assert service.preview_mixed_interrupted_cleanup(
        parent, **{**arguments,
                   "lease_lookup": lambda _: (initial.input["corePlanId"],
                                              "provider_keyed_teardown_fence")})[
                                                  "snapshotId"] == preview["snapshotId"]


def test_both_orders_reserve_then_seal_without_provider_write(ready, monkeypatch):
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    initial = ready.parent
    jobs = ready.case.jobs
    order = tuple(initial.input["orderedProviders"])
    records = []

    def collector(parent, provider, workspace, *, fence, **kwargs):
        assert parent == initial and workspace.provider == provider
        assert kwargs["process_quiescent"]() is True
        records.append(("GET", provider))
        return _snapshot(provider, generation=fence())

    def reserve(proposal, *, initial, review, snapshots_by_provider,
                process_quiescent, state_root, review_generation, host_rows):
        assert review_generation and state_root == ready.case.state_root
        assert host_rows is None
        assert set(snapshots_by_provider) == set(order)
        recognize_mixed_interrupted_cleanup_checkpoint(proposal, initial, review)
        jobs.save(proposal)
        records.append(("reserve", tuple(review.ordered_providers)))
        return proposal

    monkeypatch.setattr(jobs, "reserve_mixed_interrupted_cleanup_parent", reserve, raising=False)
    parent = service.reserve_mixed_interrupted_cleanup(
        initial.target_id, initial.input["coreJobId"], requested_by="operator",
        environment="devtest", state_root=ready.case.state_root,
        job_repository=jobs, lease_lookup=ready.args["lease_lookup"],
        process_quiescent=lambda identity: True, snapshot_collector=collector)
    assert records == [("GET", order[0]), ("GET", order[1]), ("reserve", order)]
    assert parent.input["phase"] == "awaiting_both_destroy_plans"
    alternate = ready.case.state_root.parent / "alternate-state-root"
    alternate.mkdir()
    with pytest.raises(service.MixedInterruptedDispatchAttention, match="configured DevTest state root"):
        service.seal_mixed_interrupted_cleanup_plans(
            initial.target_id, initial.input["coreJobId"],
            plan_paths={provider: None for provider in order},
            show_json={provider: None for provider in order}, environment="devtest",
            state_root=alternate, job_repository=jobs,
            lease_lookup=lambda _: (initial.input["corePlanId"], "provider_keyed_teardown_fence"))

    def seal(saved, *, initial, review, plan_set, before_states, plan_paths, show_json, state_root):
        assert state_root == ready.case.state_root
        assert saved == parent and isinstance(review, MixedInterruptedReview)
        assert all(value is None for value in before_states.values())
        assert all(value is None for value in plan_paths.values())
        assert all(value is None for value in show_json.values())
        from dataclasses import asdict
        sealed = replace(parent, input={**parent.input, "phase": "plans_sealed"},
                         events=parent.events + [JobEvent(2, "info", "both mixed destroy plans sealed",
                              {"planSet": _canonical(asdict(plan_set)),
                               "planSetSha256": plan_set.plan_set_sha256})])
        recognize_mixed_interrupted_sealed_plans(sealed, initial, review, plan_set)
        jobs.save(sealed)
        records.append(("seal", tuple(plan_set.ordered_providers)))
        return sealed

    monkeypatch.setattr(jobs, "seal_mixed_interrupted_destroy_plans", seal, raising=False)
    sealed = service.seal_mixed_interrupted_cleanup_plans(
        initial.target_id, initial.input["coreJobId"],
        plan_paths={provider: None for provider in order},
        show_json={provider: None for provider in order}, environment="devtest",
        state_root=ready.case.state_root, job_repository=jobs,
        lease_lookup=lambda _: (initial.input["corePlanId"], "provider_keyed_teardown_fence"))
    assert sealed.input["phase"] == "plans_sealed"
    assert records[-1] == ("seal", order)
    seen = list(records)
    assert service.reserve_mixed_interrupted_cleanup(
        initial.target_id, initial.input["coreJobId"], requested_by="operator",
        environment="devtest", state_root=ready.case.state_root,
        job_repository=jobs,
        lease_lookup=lambda _: (initial.input["corePlanId"], "provider_keyed_teardown_fence"),
        process_quiescent=lambda identity: True,
        snapshot_collector=lambda *a, **k: pytest.fail("duplicate must not repeat GET")) == sealed
    with pytest.raises(service.MixedInterruptedDispatchAttention):
        service.reserve_mixed_interrupted_cleanup(
            initial.target_id, initial.input["coreJobId"], requested_by="operator",
            environment="devtest", state_root=ready.case.state_root,
            job_repository=jobs, expected_snapshot_id="0" * 64,
            lease_lookup=lambda _: (initial.input["corePlanId"],
                                    "provider_keyed_teardown_fence"),
            snapshot_collector=lambda *a, **k: pytest.fail("duplicate must not repeat GET"))
    assert service.seal_mixed_interrupted_cleanup_plans(
        initial.target_id, initial.input["coreJobId"],
        plan_paths={provider: None for provider in order},
        show_json={provider: None for provider in order}, environment="devtest",
        state_root=ready.case.state_root, job_repository=jobs,
        lease_lookup=lambda _: (initial.input["corePlanId"], "provider_keyed_teardown_fence")) == sealed
    assert records == seen


def test_review_fence_drift_blocks_reservation(ready, monkeypatch):
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    initial = ready.parent
    jobs = ready.case.jobs
    calls = []

    def collector(parent, provider, workspace, *, fence, **kwargs):
        calls.append(provider)
        if len(calls) == 2:
            changed = replace(initial, events=initial.events + [JobEvent(
                len(initial.events) + 1, "info", "unreviewed change", {})])
            jobs.save(changed)
        return _snapshot(provider, generation=fence())

    with pytest.raises(service.MixedInterruptedDispatchAttention):
        service.reserve_mixed_interrupted_cleanup(
            initial.target_id, initial.input["coreJobId"], requested_by="operator",
            environment="devtest", state_root=ready.case.state_root,
            job_repository=jobs, lease_lookup=ready.args["lease_lookup"],
            process_quiescent=lambda identity: True, snapshot_collector=collector)
    assert len(calls) == 2


def test_reviewed_snapshot_must_match_fresh_provider_classification(ready, monkeypatch):
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    initial = ready.parent
    calls = []

    def collector(_parent, provider, _workspace, *, fence, **_kwargs):
        calls.append(provider)
        return _snapshot(provider, generation=fence())

    with pytest.raises(service.MixedInterruptedDispatchAttention):
        service.reserve_mixed_interrupted_cleanup(
            initial.target_id, initial.input["coreJobId"], requested_by="operator",
            environment="devtest", state_root=ready.case.state_root,
            job_repository=ready.case.jobs, lease_lookup=ready.args["lease_lookup"],
            process_quiescent=lambda _identity: True,
            snapshot_collector=collector, expected_snapshot_id="0" * 64)
    assert calls == list(initial.input["orderedProviders"])
    assert ready.case.jobs.get(service.cleanup_parent_id(initial.input["coreJobId"])) is None


def test_preview_snapshot_id_is_stable_across_read_only_collections(ready, monkeypatch):
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    initial = ready.parent
    core = ready.case.jobs.get(initial.input["coreJobId"])
    calls = []

    def collector(_parent, provider, _workspace, *, fence, **_kwargs):
        calls.append((provider, fence()))
        return _snapshot(provider, generation=fence())

    arguments = dict(environment="devtest", state_root=ready.case.state_root,
                     job_repository=ready.case.jobs,
                     lease_lookup=ready.args["lease_lookup"],
                     process_quiescent=lambda _identity: True,
                     snapshot_collector=collector)
    first = service.preview_mixed_interrupted_cleanup(core, **arguments)
    second = service.preview_mixed_interrupted_cleanup(core, **arguments)
    assert first["snapshotId"] == second["snapshotId"]
    assert first["parentJobId"] is None
    assert len({nonce for _, nonce in calls}) == 2
    monkeypatch.setattr(ready.case.jobs, "reserve_mixed_interrupted_cleanup_parent",
                        lambda proposal, **_kwargs: ready.case.jobs.save(proposal),
                        raising=False)
    parent = service.reserve_mixed_interrupted_cleanup(
        initial.target_id, initial.input["coreJobId"], requested_by="operator",
        expected_snapshot_id=first["snapshotId"], **arguments)
    assert parent.input["phase"] == "awaiting_both_destroy_plans"


def test_state_backed_0644_plan_duplicate_is_historical_checkpoint(ready, monkeypatch):
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    initial = ready.parent
    first, second = initial.input["orderedProviders"]
    policy = initial.events[5].data["reviewedPolicy"][first]
    state, _, _, _ = _state_and_rows(first, policy)
    raw = json.dumps(state).encode()
    _, attributes, cloud = _state(first, policy, raw)
    first_scope = MixedInterruptedProviderScope(
        first, "full", "b" * 64, hashlib.sha256(raw).hexdigest(),
        state["lineage"], state["serial"], tuple(sorted(cloud.items())),
        "c" * 64, "d" * 64, policy.get("selector_tag"), first == "digitalocean")
    second_scope = service.review_mixed_interrupted_source(
        initial, {provider: None for provider in (first, second)},
        {provider: _snapshot(provider) for provider in (first, second)},
        fence=lambda: "stable", process_quiescent=lambda identity: True).scopes[1]
    payload = {"engagementId": initial.target_id, "coreJobId": initial.input["coreJobId"],
               "sealJournalSha256": job_event_digest(initial.events[:6]),
               "orderedProviders": (first, second),
               "scopes": [first_scope.__dict__, second_scope.__dict__]}
    review = MixedInterruptedReview(
        initial.target_id, initial.input["coreJobId"], payload["sealJournalSha256"],
        (first, second), (first_scope, second_scope),
        hashlib.sha256(json.dumps(payload, sort_keys=True,
                                  separators=(",", ":")).encode()).hexdigest())
    workspace = service._workspace(initial, first, ready.case.state_root)
    workspace.state_path.write_bytes(raw)
    path = workspace.path / f".barragan-mixed-interrupted-destroy-{first}.tfplan"
    path.write_bytes(b"readable-reviewed-plan")
    path.chmod(0o644)
    shown = {"format_version": "1.2", "terraform_version": "1.15.5",
             "applyable": True, "complete": True, "errored": False,
             "resource_changes": [{"address": address, "change": {
                 "actions": ["delete"], "before": attrs, "after": None,
                 "after_unknown": {}}} for address, attrs in attributes.items()],
             "prior_state": {"values": {"root_module": {"resources": [
                 {"address": address, "mode": "managed", "values": attrs}
                 for address, attrs in attributes.items()]}}},
             "output_changes": {}, "planned_values": {"root_module": {}}}
    shown_json = json.dumps(shown)
    plans = bind_mixed_interrupted_destroy_plans(
        initial, review, {first: raw, second: None},
        {first: path, second: None}, {first: shown_json, second: None},
        fence=lambda: "stable")
    parent = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
    sealed = replace(parent, input={**parent.input, "phase": "plans_sealed"},
                     events=parent.events + [JobEvent(2, "info", "both mixed destroy plans sealed",
                          {"planSet": _canonical(__import__("dataclasses").asdict(plans)),
                           "planSetSha256": plans.plan_set_sha256})])
    ready.case.jobs.save(sealed)
    # A completed destroy may already have changed the retained state. The
    # duplicate only recognizes historical sealed artifacts; it does not GO.
    workspace.state_path.unlink()
    assert service.seal_mixed_interrupted_cleanup_plans(
        initial.target_id, initial.input["coreJobId"],
        plan_paths={first: path, second: None},
        show_json={first: shown_json, second: None}, environment="devtest",
        state_root=ready.case.state_root, job_repository=ready.case.jobs,
        lease_lookup=lambda _: (initial.input["corePlanId"],
                                "provider_keyed_teardown_fence")) == sealed


def _full_host_snapshot(parent, provider, raw, generation):
    state = json.loads(raw)
    rows, nodes = [], []
    for resource in state["resources"]:
        kind = ("node" if resource["type"] in {"linode_instance", "digitalocean_droplet"}
                else "firewall" if resource["type"] in {
                    "linode_firewall", "digitalocean_firewall"} else
                "ssh_key" if resource["type"] == "digitalocean_ssh_key" else None)
        if kind is None:
            continue
        for instance in resource["instances"]:
            attrs = instance["attributes"]
            row = {"kind": kind, "id": attrs["id"],
                   "name": attrs.get("label", attrs.get("name")),
                   "tags": attrs.get("tags", [])}
            if kind == "ssh_key":
                row["public_key"] = attrs["public_key"]
            rows.append(row)
            if kind == "node":
                nodes.append(str(attrs["id"]))
    rows = tuple(rows)
    phase = "applied"
    sha = hashlib.sha256(raw).hexdigest()
    attached = tuple(sorted(nodes))
    linode_attached = attached if provider == "linode" else None
    selector_exists = True if provider == "digitalocean" else None
    selector_count = len(nodes) if provider == "digitalocean" else None
    selector_attached = attached if provider == "digitalocean" else None
    digest = hashlib.sha256(json.dumps({
        "provider": provider, "stateSha256": sha, "phase": phase,
        "inventory": rows, "linodeAttachments": linode_attached,
        "selectorExists": selector_exists, "selectorCount": selector_count,
        "selectorAttachments": selector_attached, "fence": generation,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return MixedPartialApplyInventorySnapshot(
        provider, raw, sha, phase, rows, linode_attached,
        selector_exists, selector_count, selector_attached, digest)


@pytest.mark.parametrize("drift", [
    None, "no-worker", "no-binding", "binding-without-worker", "binding-appears-slot",
    "queued-worker", "expired-precontact", "failed-intent",
    "failed-result", "failed-between-chains", "expired-started", "running-worker",
    "uncertain-worker", "writer-slot", "writer-slot-prefix", "process-drift",
    "live-process", "live-prefix-process",
], ids=[
    "completed", "absent-worker", "absent-binding-and-worker",
    "worker-without-binding", "binding-appears-before-reserve", "queued",
    "expired-before-contact", "failed-intent-only",
    "failed-command-result", "failed-between-chains", "expired-started-no-result",
    "active-worker", "incomplete-journal",
    "changed-before-reserve", "changed-prefix-before-reserve",
    "process-changed-before-reserve", "live-process", "live-prefix-process",
])
def test_persisted_completed_host_GET_POST_reservation_both_orders(
        ready, client, tmp_path, monkeypatch, drift):
    initial, binding, bootstrap_args, _calls, _ = _bootstrap_inputs(ready, tmp_path)
    worker = run_mixed_initial_bootstrap(**bootstrap_args)
    if drift in {"queued-worker", "expired-precontact", "failed-intent", "failed-result",
                 "failed-between-chains", "expired-started", "running-worker",
                 "writer-slot-prefix", "live-prefix-process"}:
        events = worker.events
        if drift == "queued-worker":
            worker = replace(worker, status="queued", started_at=None, finished_at=None,
                             events=events[:1])
        elif drift == "failed-intent":
            end = next(i for i, event in enumerate(events, 1)
                       if event.message == "mixed bootstrap command intended")
            worker = replace(worker, status="failed", events=events[:end])
        elif drift == "failed-result":
            end = next(i for i, event in enumerate(events, 1)
                       if event.message == "mixed bootstrap command result fenced")
            failure = replace(events[end - 1], data={**events[end - 1].data, "returnCode": 1})
            worker = replace(worker, status="failed", events=events[:end - 1] + [failure])
        elif drift == "failed-between-chains":
            end = next(i for i, event in enumerate(events, 1)
                       if event.message == "mixed chain bootstrap completed")
            worker = replace(worker, status="failed", events=events[:end])
        else:
            end = (2 if drift == "expired-precontact" else
                   next(i for i, event in enumerate(events, 1)
                        if event.message == "mixed bootstrap command started before GO"))
            expired = (datetime.now(timezone.utc) + timedelta(
                minutes=2 if drift == "running-worker" else -2)).isoformat()
            claimed = (datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat()
            worker = replace(worker, status="running", finished_at=None, events=events[:end],
                             input={**worker.input, "claimOwner": "mixed-host-bootstrap-fixture",
                                    "claimToken": "a" * 32, "claimClaimedAt": claimed,
                                    "claimHeartbeatAt": claimed, "claimExpiresAt": expired})
    monkeypatch.setattr(state_workspaces, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    raw_states = {}
    for provider in initial.input["orderedProviders"]:
        raw = bootstrap_args["fresh_observer"](initial, provider, lambda: "stable").state_json
        workspace = service._workspace(initial, provider, ready.case.state_root)
        workspace.state_path.write_bytes(raw)
        (workspace.path / ".barragan-apply-phase.json").write_text(json.dumps({
            "schema": "provider-keyed-v2", "phase": "applied"}))
        raw_states[provider] = raw
    with client.application.storage_context():
        db.session.add(EngagementModel(
            id="eng-opaque", name="opaque-fixture", status="deployed",
            owner="operator", template_id="small", input_parameters={}))
        db.session.add(DeploymentPlanModel(
            id="plan-1", engagement_id="eng-opaque", revision_id="rev-1",
            status="applied", stage="applied", apply_job_id="job-core"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-1",
            operation="provider_keyed_initial"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        for row in ready.case.jobs.list():
            if row.id == binding.id and drift in {
                    "no-binding", "binding-without-worker", "binding-appears-slot"}:
                continue
            if row.id == worker.id:
                if drift in {"no-worker", "no-binding", "binding-appears-slot"}:
                    continue
                row = worker
            when = "2026-10-15T00:00:00+00:00"
            jobs.save(replace(
                row, created_at=when if row.created_at == "now" else row.created_at,
                started_at=when if row.started_at == "now" else row.started_at,
                finished_at=when if row.finished_at == "now" else row.finished_at))
        core = jobs.get("job-core")
        worker = jobs.get(worker.id)
        assert service.is_mixed_interrupted_request(core, jobs=jobs)

        def collector(_parent, provider, _workspace, *, fence, **_kwargs):
            return _full_host_snapshot(initial, provider, raw_states[provider], fence())

        arguments = dict(environment="devtest", state_root=ready.case.state_root,
                         job_repository=jobs,
                         process_quiescent=lambda _identity: drift not in {
                             "live-process", "live-prefix-process"},
                         snapshot_collector=collector)
        if drift == "uncertain-worker":
            jobs.save(replace(worker, events=worker.events[:-2] + worker.events[-1:]))
        if drift in ("running-worker", "uncertain-worker", "live-process",
                     "live-prefix-process", "binding-without-worker"):
            assert service.is_mixed_interrupted_request(core, jobs=jobs)
            with pytest.raises(service.MixedInterruptedDispatchAttention):
                service.preview_mixed_interrupted_cleanup(core, **arguments)
        else:
            preview = service.preview_mixed_interrupted_cleanup(core, **arguments)
            assert [item["provider"] for item in preview["orderedScope"][0]["items"]] == (
                initial.input["orderedProviders"])
            if drift in {"writer-slot", "writer-slot-prefix"}:
                original_reserve = jobs.reserve_mixed_interrupted_cleanup_parent

                def changed_worker(*a, **kw):
                    changed = (replace(worker, events=worker.events[:-1])
                               if drift == "writer-slot-prefix" else
                               replace(worker, status="running", finished_at=None))
                    jobs.save(changed)
                    return original_reserve(*a, **kw)

                monkeypatch.setattr(jobs, "reserve_mixed_interrupted_cleanup_parent", changed_worker)
            if drift == "binding-appears-slot":
                original_reserve = jobs.reserve_mixed_interrupted_cleanup_parent

                def changed_binding(*a, **kw):
                    jobs.save(binding)
                    return original_reserve(*a, **kw)

                monkeypatch.setattr(jobs, "reserve_mixed_interrupted_cleanup_parent", changed_binding)
            if drift == "process-drift":
                original_reserve = jobs.reserve_mixed_interrupted_cleanup_parent

                def changed_process(*a, **kw):
                    kw["process_quiescent"] = lambda _identity: False
                    return original_reserve(*a, **kw)

                monkeypatch.setattr(jobs, "reserve_mixed_interrupted_cleanup_parent", changed_process)
            body = {"snapshotId": preview["snapshotId"],
                    "confirmation": preview["confirmationPhrase"]}
            if drift in ("writer-slot", "writer-slot-prefix", "process-drift",
                         "binding-appears-slot"):
                with pytest.raises(service.MixedInterruptedDispatchAttention):
                    service.start_mixed_interrupted_cleanup(core, body, **arguments)
            else:
                saved = service.start_mixed_interrupted_cleanup(core, body, **arguments)
                assert saved.action == "provider_keyed_mixed_interrupted_cleanup"
                assert saved.input["phase"] == "awaiting_both_destroy_plans"
        assert db.session.get(CoreMutationLeaseModel, "eng-opaque").operation == (
            "provider_keyed_initial" if drift in {
                "running-worker", "uncertain-worker", "writer-slot",
                "writer-slot-prefix", "process-drift", "live-process",
                "live-prefix-process", "binding-without-worker",
                "binding-appears-slot"} else "provider_keyed_teardown_fence")
