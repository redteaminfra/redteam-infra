# Copyright (c) 2026, Oracle and/or its affiliates.
"""The paired Review child is durable and separate from operator Apply."""

from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

import pytest

import app.services.provider_keyed_mixed_append_review_runtime as runtime
from app.services.provider_keyed_mixed_append_plan_context import MixedAppendPlanChoices
from app.services.provider_keyed_mixed_append_published_source import PublishedMixedAppendSource
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_append_pair_parent import _setup
from test_provider_keyed_mixed_append_pair_plan_worker import fixture as pair_fixture


def _request(kwargs):
    do, linode = kwargs["digitalocean_intent"], kwargs["linode_intent"]
    return {
        "digitalocean": {"selectedChainId": do.chain_id,
                         "edgeRegion": do.new_edge.region,
                         "edgeSize": do.new_edge.size,
                         "edgeImage": do.new_edge.image,
                         "selectorTag": do.new_edge.firewall_selector_tag},
        "linode": {"selectedChainId": linode.chain_id,
                   "edgeRegion": linode.new_edge.region,
                   "edgeType": linode.new_edge.node_type,
                   "edgeImage": linode.new_edge.image,
                   "engagementTag": linode.new_edge.tag},
    }


@pytest.mark.parametrize("order", [("digitalocean", "linode"),
                                   ("linode", "digitalocean")])
def test_review_produces_one_terminal_digest_without_apply(tmp_path, monkeypatch, order):
    kwargs, _, _ = pair_fixture(tmp_path, monkeypatch)
    source = kwargs["source"]
    published = PublishedMixedAppendSource(
        source, tuple((p, row.path) for p, row in kwargs["workspaces"].items()),
        0, "d" * 64, "e" * 64)
    request = _request(kwargs)
    chain_order = tuple(request[p]["selectedChainId"] for p in order)
    state, jobs = _setup(source.engagement_id, source.core_job_id, source.core_plan_id)
    choices = {p: {key: request[p][key] for key in (
        "selectedChainId", "edgeRegion", "edgeSize" if p == "digitalocean" else "edgeType")}
        for p in request}
    monkeypatch.setattr(runtime, "derive_mixed_append_review_request", lambda *_a, **_k:
                        MixedAppendPlanChoices(request, order, chain_order, source.core_plan_id))
    context = SimpleNamespace(source=source, producer_kwargs=lambda: {})
    monkeypatch.setattr(runtime, "collect_mixed_append_pair_plan_context", lambda *_a, **_k: context)
    produced = []
    monkeypatch.setattr(runtime, "_RENEW_INTERVAL", timedelta(0))
    def produce(**options):
        assert options["lease_lookup"](source.engagement_id) == (
            source.core_plan_id, "provider_keyed_mixed_append")
        assert jobs.get(parent.id).input["claimHeartbeatAt"]
        produced.append(True)
        return SimpleNamespace(engagement_id=source.engagement_id,
                               core_job_id=source.core_job_id,
                               provider_order=order, chain_order=chain_order,
                               new_edge_addresses=("example.edge-one", "example.edge-two"),
                               saved_plan_sha256=("b" * 64, "c" * 64),
                               review_sha256="a" * 64)
    monkeypatch.setattr(runtime, "produce_mixed_append_pair_plan_review", produce)
    monkeypatch.setattr(runtime.pair, "_collect_published", lambda *_a: published)
    def lease(engagement):
        row = db.session.get(CoreMutationLeaseModel, engagement)
        return (row.owner_id, row.operation) if row else None
    with db.bind(state):
        parent = runtime.begin_mixed_append_review(
            source.engagement_id, source.core_job_id, choices, "operator", job_repository=jobs)
        assert runtime.begin_mixed_append_review(
            source.engagement_id, source.core_job_id, choices, "operator",
            job_repository=jobs).id == parent.id
        child = runtime.run_mixed_append_review(
            parent.id, job_repository=jobs, lease_lookup=lease)
        digest = runtime.pair.mixed_append_approval_sha256("a" * 64, published)
        assert child.status == "succeeded"
        assert child.events[-1].data == {"reviewSha256": digest}
        assert child.events[-1].message == "mixed append pair plan reviewed"
        assert runtime.mixed_append_review_status(
            source.engagement_id, source.core_job_id, job_repository=jobs) == (
                jobs.get(parent.id), child)
        assert jobs.get(parent.id).input["phase"] == "planning"
        summary = jobs.get(parent.id).input["reviewSummary"]
        assert summary["providerOrder"] == list(order)
        assert [row["savedPlanSha256"] for row in summary["plans"]] == ["b" * 64, "c" * 64]
        assert summary["outcome"] == "add one edge per provider; retain all existing nodes"
        assert "claimToken" not in jobs.get(parent.id).input
        assert runtime.run_mixed_append_review(
            parent.id, job_repository=jobs, lease_lookup=lease) == child
        assert len(produced) == 1


def test_startup_recovery_selects_only_queued_or_expired_review(tmp_path, monkeypatch):
    kwargs, _, _ = pair_fixture(tmp_path, monkeypatch)
    source = kwargs["source"]
    request = _request(kwargs)
    order = ("digitalocean", "linode")
    state, jobs = _setup(source.engagement_id, source.core_job_id, source.core_plan_id)
    with db.bind(state):
        parent = runtime.pair.reserve_mixed_append_pair(
            source.engagement_id, source.core_job_id, source.core_plan_id,
            requested_by="operator", reviewed_request=request, provider_order=order,
            chain_order=tuple(request[p]["selectedChainId"] for p in order),
            job_repository=jobs)
        scheduled = []
        assert runtime.recover_mixed_append_reviews(
            environment="prod", schedule=scheduled.append,
            job_repository=jobs) == []
        assert runtime.recover_mixed_append_reviews(
            environment="devtest", schedule=scheduled.append,
            job_repository=jobs) == [parent.id]
        assert len(scheduled) == 1
        running = jobs.start_if_queued(parent, started_at=runtime._now(), event=runtime.JobEvent(
            2, "info", "mixed append pair planning started", {}))
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        claimed = jobs.claim_lease(
            running.id, owner="worker", token="token", claimed_at=runtime._now(),
            expires_at=future.isoformat(), eligible_statuses={"running"},
            eligible_phases={"planning"})
        child = jobs.get(runtime.pair._plan_child_id(parent.id))
        jobs.start_if_queued(child, started_at=runtime._now(), event=runtime.JobEvent(
            2, "info", "mixed append pair plan started", {}))
        scheduled.clear()
        assert runtime.recover_mixed_append_reviews(
            environment="devtest", schedule=scheduled.append,
            job_repository=jobs) == []
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        reclaimed = jobs.claim_lease(
            claimed.id, owner="worker", token="token", claimed_at=runtime._now(),
            expires_at=past.isoformat(), eligible_statuses={"running"},
            eligible_phases={"planning"})
        assert reclaimed is not None
        assert runtime.recover_mixed_append_reviews(
            environment="devtest", schedule=scheduled.append,
            job_repository=jobs) == [parent.id]
        assert len(scheduled) == 1


def test_failed_plan_is_visible_and_not_replayed(tmp_path, monkeypatch):
    kwargs, _, _ = pair_fixture(tmp_path, monkeypatch)
    source = kwargs["source"]
    request = _request(kwargs)
    order = ("digitalocean", "linode")
    state, jobs = _setup(source.engagement_id, source.core_job_id, source.core_plan_id)
    monkeypatch.setattr(runtime, "collect_mixed_append_pair_plan_context", lambda *_a, **_k:
                        SimpleNamespace(producer_kwargs=lambda: {}))
    calls = []
    def fail(**_kwargs):
        calls.append(True)
        raise ValueError("uncertain plan command")
    monkeypatch.setattr(runtime, "produce_mixed_append_pair_plan_review", fail)
    def lease(engagement):
        row = db.session.get(CoreMutationLeaseModel, engagement)
        return (row.owner_id, row.operation) if row else None
    with db.bind(state):
        parent = runtime.pair.reserve_mixed_append_pair(
            source.engagement_id, source.core_job_id, source.core_plan_id,
            requested_by="operator", reviewed_request=request,
            provider_order=order,
            chain_order=tuple(request[p]["selectedChainId"] for p in order),
            job_repository=jobs)
        with pytest.raises(runtime.MixedAppendReviewAttention):
            runtime.run_mixed_append_review(
                parent.id, job_repository=jobs, lease_lookup=lease)
        child = jobs.get(runtime.pair._plan_child_id(parent.id))
        assert child.status == "failed"
        assert child.events[-1].data == {}
        with pytest.raises(runtime.MixedAppendReviewAttention):
            runtime.run_mixed_append_review(
                parent.id, job_repository=jobs, lease_lookup=lease)
        assert calls == [True]


def _failed_unstaged_review(tmp_path, monkeypatch):
    from dataclasses import replace
    import json
    kwargs, _, _ = pair_fixture(tmp_path, monkeypatch)
    source, request = kwargs["source"], _request(kwargs)
    state, jobs = _setup(source.engagement_id, source.core_job_id, source.core_plan_id)
    for workspace in kwargs["workspaces"].values():
        for path in workspace.path.glob(".barragan-mixed-append-*"):
            path.unlink()
    topologies = {p: {"schema": "provider-keyed-v2", "regional_high_water": {}} for p in kwargs["workspaces"]}
    for provider, workspace in kwargs["workspaces"].items():
        workspace.state_path.write_bytes(kwargs["provider_states"][provider])
        (workspace.path / ".barragan-topology.json").write_text(json.dumps(topologies[provider]))
        (workspace.path.parents[1] / "regional-ordinals.json").write_text("{}")
    context = SimpleNamespace(source=source, workspaces=kwargs["workspaces"],
        provider_states=kwargs["provider_states"], original_topologies=topologies,
        original_regional_high_water={}, producer_kwargs=lambda: {})
    with db.bind(state):
        parent = runtime.pair.reserve_mixed_append_pair(source.engagement_id, source.core_job_id,
            source.core_plan_id, requested_by="operator", reviewed_request=request,
            provider_order=source.ordered_providers, chain_order=source.chain_ids, job_repository=jobs)
        def fail(*_a, **_k):
            raise ValueError("pre-context failure")
        monkeypatch.setattr(runtime, "collect_mixed_append_pair_plan_context", fail)
        with pytest.raises(runtime.MixedAppendReviewAttention):
            runtime.run_mixed_append_review(parent.id, job_repository=jobs)
        parent = jobs.get(parent.id)
        child = jobs.get(runtime.pair._plan_child_id(parent.id))
    monkeypatch.setattr(runtime, "collect_mixed_append_pair_plan_context", lambda *_a, **_k: context)
    return state, jobs, parent, child, context, kwargs


def test_explicit_precommand_retry_preserves_history_lease_and_uses_normal_worker(tmp_path, monkeypatch):
    state, jobs, parent, child, context, kwargs = _failed_unstaged_review(tmp_path, monkeypatch)
    published = PublishedMixedAppendSource(context.source,
        tuple((p, w.path) for p, w in context.workspaces.items()), 0, "d" * 64, "e" * 64)
    monkeypatch.setattr(runtime.pair, "_collect_published", lambda *_: published)
    monkeypatch.setattr(runtime, "produce_mixed_append_pair_plan_review", lambda **_: SimpleNamespace(
        engagement_id=parent.target_id, core_job_id=parent.input["coreJobId"],
        provider_order=tuple(parent.input["providerOrder"]), chain_order=tuple(parent.input["chainOrder"]),
        new_edge_addresses=("example.first", "example.second"), saved_plan_sha256=("b"*64, "c"*64),
        review_sha256="a"*64))
    with db.bind(state):
        choices = runtime.mixed_append_retry_choices(parent, child, jobs=jobs)
        result = runtime.begin_mixed_append_review(parent.target_id, parent.input["coreJobId"],
            choices, parent.requested_by, job_repository=jobs)
        assert result == parent
        queued = jobs.get(child.id)
        assert queued.id == child.id and queued.status == "queued"
        assert queued.events[:3] == child.events and queued.finished_at is None
        assert queued.events[-1].message == "mixed append pair Review retry requested"
        assert runtime.begin_mixed_append_review(parent.target_id, parent.input["coreJobId"],
            choices, parent.requested_by, job_repository=jobs) == parent
        assert len(jobs.get(child.id).events) == 4
        assert runtime._db_lease_lookup(parent.target_id) == (parent.input["corePlanId"], runtime.pair._OPERATION)
        done = runtime.run_mixed_append_review(parent.id, job_repository=jobs)
        assert done.status == "succeeded" and done.events[:4] == queued.events
        assert done.events[-1].message == "mixed append pair plan reviewed"


@pytest.mark.parametrize("drift", ["artifact", "symlink", "state", "topology", "ledger", "lease", "claim", "apply"])
def test_precommand_retry_refuses_staging_and_source_drift(tmp_path, monkeypatch, drift):
    from dataclasses import replace
    state, jobs, parent, child, context, kwargs = _failed_unstaged_review(tmp_path, monkeypatch)
    workspace = next(iter(context.workspaces.values()))
    with db.bind(state):
        if drift in {"artifact", "symlink"}:
            path = workspace.path / ".barragan-mixed-append-digitalocean-plan-journal.jsonl"
            path.symlink_to(tmp_path / "absent") if drift == "symlink" else path.write_text("intent")
        elif drift == "state": workspace.state_path.write_bytes(b"changed")
        elif drift == "topology": (workspace.path / ".barragan-topology.json").write_text('{"schema":"provider-keyed-v2","changed":true}')
        elif drift == "ledger": (workspace.path.parents[1] / "regional-ordinals.json").write_text('{"changed":1}')
        elif drift == "lease":
            db.session.get(CoreMutationLeaseModel, parent.target_id).operation = "other"
            db.session.commit()
        elif drift == "claim": parent = jobs.save(replace(parent, input={**parent.input, "claimOwner": "live"}))
        else:
            from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id
            jobs.save(replace(child, id=_child_id(parent.id), action="provider_keyed_mixed_append_first_apply"))
        with pytest.raises((runtime.MixedAppendReviewAttention, ValueError)):
            runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
        assert jobs.get(child.id) == child


def test_repeated_precontext_failure_remains_explicitly_retryable(tmp_path, monkeypatch):
    state, jobs, parent, child, context, _ = _failed_unstaged_review(tmp_path, monkeypatch)
    with db.bind(state):
        runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
        def fail(*_a, **_k): raise ValueError("still pre-context")
        monkeypatch.setattr(runtime, "collect_mixed_append_pair_plan_context", fail)
        with pytest.raises(runtime.MixedAppendReviewAttention):
            runtime.run_mixed_append_review(parent.id, job_repository=jobs)
        parent, child = jobs.get(parent.id), jobs.get(child.id)
        assert len(child.events) == 6
        assert runtime.mixed_append_retry_choices(parent, child, jobs=jobs) is not None
        monkeypatch.setattr(runtime, "collect_mixed_append_pair_plan_context", lambda *_a, **_k: context)
        runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
        assert jobs.get(child.id).status == "queued"


@pytest.mark.parametrize("changed", ["parent", "child", "artifact"])
def test_retry_writer_rechecks_exact_rows_and_local_artifact_fence(tmp_path, monkeypatch, changed):
    from dataclasses import replace
    state, jobs, parent, child, context, _ = _failed_unstaged_review(tmp_path, monkeypatch)
    original = jobs.retry_precommand_mixed_append_review
    def race(p, c, **kwargs):
        if changed == "parent": jobs.save(replace(p, input={**p.input, "changed": True}))
        elif changed == "child": jobs.save(replace(c, input={**c.input, "changed": True}))
        else:
            next(iter(context.workspaces.values())).path.joinpath(".barragan-mixed-append-raced-plan.lock").touch()
        return original(p, c, **kwargs)
    monkeypatch.setattr(jobs, "retry_precommand_mixed_append_review", race)
    with db.bind(state):
        with pytest.raises(ValueError):
            runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
        assert jobs.get(child.id).status == "failed"


def _stage_precommand_retry(tmp_path, monkeypatch, *, corrected=False):
    import json
    state, jobs, parent, child, context, kwargs = _failed_unstaged_review(tmp_path, monkeypatch)
    context.reviewed_provider_order = tuple(parent.input["providerOrder"])
    context.binding_manifest = kwargs["binding_manifest"]
    proposed = {provider: {**topology, "edge_groups": {"added": True}}
                for provider, topology in context.original_topologies.items()}
    ledger = {"reserved-region": 2}
    inputs = {provider: {"unchanged": provider, "ssh_pub_key_path": "/canonical/public",
        "ssh_priv_key_path": "/canonical/private", "ssh_config_path": "/canonical/config"}
        for provider in context.workspaces}
    context.approval_kwargs = lambda: {"digitalocean_intent": kwargs["digitalocean_intent"],
        "linode_intent": kwargs["linode_intent"], "reviewed_inputs": inputs}
    import app.services.provider_keyed_mixed_append_reservation as reservations
    monkeypatch.setattr(reservations, "propose_mixed_external_append_reservations", lambda **_: SimpleNamespace(
        reservations=[SimpleNamespace(provider=p, proposed_topology=value) for p, value in proposed.items()],
        proposed_high_water=ledger))
    for provider, workspace in context.workspaces.items():
        (workspace.path / ".barragan-topology.json").write_text(json.dumps(proposed[provider]))
        (workspace.path.parents[1] / "regional-ordinals.json").write_text(json.dumps(ledger))
        for suffix, blob in (("predecessor.tfstate", context.provider_states[provider]), ("plan.lock", b"")):
            path = workspace.path / f".barragan-mixed-append-{provider}-{suffix}"
            path.write_bytes(blob)
            path.chmod(0o600)
    first = context.reviewed_provider_order[0]
    variables = inputs[first] if corrected else {"unchanged": first}
    path = context.workspaces[first].path / f".barragan-mixed-append-{first}-inputs.json"
    path.write_text(json.dumps(variables, sort_keys=True) + "\n")
    path.chmod(0o600)
    return state, jobs, parent, child, context


@pytest.mark.parametrize("corrected", [False, True])
def test_retry_retains_exact_precommand_staging_and_releases_both_locks(tmp_path, monkeypatch, corrected):
    import fcntl
    state, jobs, parent, child, context = _stage_precommand_retry(tmp_path, monkeypatch, corrected=corrected)
    before = {path: path.read_bytes() for workspace in context.workspaces.values()
              for path in workspace.path.glob(".barragan-mixed-append-*")}
    with db.bind(state):
        runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
        assert jobs.get(child.id).status == "queued"
        assert jobs.get(child.id).events[:len(child.events)] == child.events
        assert {path: path.read_bytes() for path in before} == before
        for provider, workspace in context.workspaces.items():
            with (workspace.path / f".barragan-mixed-append-{provider}-plan.lock").open("r+b") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.parametrize("drift", ["zero-journal", "secret", "unknown", "missing-predecessor",
    "changed-predecessor", "topology", "ledger", "input", "mode", "symlink-lock", "active-lock", "second-input"])
def test_staged_precommand_retry_rejects_every_unproved_boundary(tmp_path, monkeypatch, drift):
    import json
    import fcntl
    state, jobs, parent, child, context = _stage_precommand_retry(tmp_path, monkeypatch)
    first, second = context.reviewed_provider_order
    workspace = context.workspaces[first]
    prefix = f".barragan-mixed-append-{first}-"
    held = None
    if drift in {"zero-journal", "secret", "unknown"}:
        suffix = {"zero-journal": "plan-journal.jsonl", "secret": "secret.json", "unknown": "unrecognized"}[drift]
        (workspace.path / (prefix + suffix)).write_bytes(b"")
    elif drift == "missing-predecessor": (workspace.path / (prefix + "predecessor.tfstate")).unlink()
    elif drift == "changed-predecessor": (workspace.path / (prefix + "predecessor.tfstate")).write_bytes(b"changed")
    elif drift == "topology": (workspace.path / ".barragan-topology.json").write_text('{"schema":"provider-keyed-v2"}')
    elif drift == "ledger": (workspace.path.parents[1] / "regional-ordinals.json").write_text("{}")
    elif drift == "input": (workspace.path / (prefix + "inputs.json")).write_text('{"unchanged":"foreign"}\n')
    elif drift == "mode": (workspace.path / (prefix + "predecessor.tfstate")).chmod(0o644)
    elif drift == "symlink-lock":
        path = workspace.path / (prefix + "plan.lock")
        path.unlink()
        path.symlink_to(tmp_path / "missing")
    elif drift == "active-lock":
        held = (workspace.path / (prefix + "plan.lock")).open("r+b")
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:
        path = context.workspaces[second].path / f".barragan-mixed-append-{second}-inputs.json"
        path.write_text(json.dumps({"unchanged": second}, sort_keys=True) + "\n")
        path.chmod(0o600)
    try:
        with db.bind(state):
            with pytest.raises(ValueError):
                runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
            assert jobs.get(child.id) == child
    finally:
        if held: held.close()


def _completed_pair_retry(tmp_path, monkeypatch):
    import json
    from test_provider_keyed_mixed_append_pair_plan_producer import fixture
    from app.services import provider_keyed_mixed_append_pair_plan_producer as producer
    kwargs, calls, _ = fixture(tmp_path, monkeypatch)
    producer.produce_mixed_append_pair_plan_review(**kwargs)
    approved = {"digitalocean_intent": producer.compile_mixed_digitalocean_on_linode_append_intent(),
        "linode_intent": producer.compile_mixed_linode_on_digitalocean_append_intent(),
        "digitalocean_firewall": kwargs["digitalocean_firewall"]}
    approved["reviewed_inputs"] = {p: approved[p + "_intent"].nonsecret_varfile for p in kwargs["workspaces"]}
    context = SimpleNamespace(**{key: kwargs[key] for key in (
        "source", "workspaces", "provider_states", "admin_public_key", "admin_private_key")})
    monkeypatch.setattr(producer, "SqlAlchemyCredentialRepository", lambda: kwargs["credential_repository"])
    monkeypatch.setattr(producer, "require_devtest_terraform_release", kwargs["release_check"])
    monkeypatch.setattr(producer, "_process_quiescent", lambda *_: True)
    # Actual failure shape: first receipt cleaned, second complete show awaiting its receipt.
    root = context.workspaces["digitalocean"].path
    (root / ".barragan-mixed-append-digitalocean-plan-receipt.json").unlink()
    secret = root / ".barragan-mixed-append-digitalocean-secret.json"
    secret.write_bytes(producer._secret_bytes("digitalocean", "test-token")); secret.chmod(0o600)
    public, private = producer._admin_material_paths(context.workspaces["digitalocean"], approved["reviewed_inputs"]["digitalocean"])
    for path, value in ((public, context.admin_public_key), (private, context.admin_private_key)):
        path.write_text(value); path.chmod(0o600)
    return context, approved, calls


def test_completed_retry_readonly_proof_accepts_receipt_and_missing_receipt(tmp_path, monkeypatch):
    context, approved, calls = _completed_pair_retry(tmp_path, monkeypatch)
    before = {path: path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    proof = runtime._completed_retry_files(context, approved)
    assert len(calls) == 8
    assert proof["digitalocean"] and proof["linode"]
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize("drift", ["journal", "missing-show", "receipt", "input", "secret", "admin", "gate", "live-process"])
def test_completed_retry_readonly_proof_rejects_drift(tmp_path, monkeypatch, drift):
    from app.services import provider_keyed_mixed_append_pair_plan_producer as producer
    context, approved, calls = _completed_pair_retry(tmp_path, monkeypatch)
    root = context.workspaces["digitalocean"].path
    path = lambda suffix: root / (".barragan-mixed-append-digitalocean-" + suffix)
    if drift == "journal": path("plan-journal.jsonl").write_bytes(b"")
    elif drift == "missing-show": path("show.json").unlink()
    elif drift == "receipt":
        receipt = context.workspaces["linode"].path / ".barragan-mixed-append-linode-plan-receipt.json"
        receipt.write_text('{}')
    elif drift == "input": path("inputs.json").write_text('{}')
    elif drift == "secret": path("secret.json").write_text('{}')
    elif drift == "admin":
        public, _ = producer._admin_material_paths(context.workspaces["digitalocean"], approved["reviewed_inputs"]["digitalocean"])
        public.write_text('changed')
    elif drift == "gate":
        def reject(*_a, **_k): raise ValueError("policy differs")
        monkeypatch.setattr(producer, "_full_gate", reject)
    else: monkeypatch.setattr(producer, "_process_quiescent", lambda *_: False)
    with pytest.raises((ValueError, FileNotFoundError)):
        runtime._completed_retry_files(context, approved)
    assert len(calls) == 8


def test_completed_retry_cas_event_fences_worker_and_cannot_downgrade(tmp_path, monkeypatch):
    state, jobs, parent, child, context = _stage_precommand_retry(tmp_path, monkeypatch)
    from app.domain import JobEvent
    from dataclasses import replace
    with db.bind(state):
        jobs.retry_precommand_mixed_append_review(parent, child, recheck=lambda: None,
            requested_at=runtime._now(), completed_plans_only=True)
        queued = jobs.get(child.id)
        assert queued.events[-1].data == {"completedPlansOnly": True}
        seen = []
        def fail(**options):
            seen.append(options.get("completed_plans_only"))
            raise ValueError("missing completed artifacts: no command")
        monkeypatch.setattr(runtime, "produce_mixed_append_pair_plan_review", fail)
        with pytest.raises(runtime.MixedAppendReviewAttention):
            runtime.run_mixed_append_review(parent.id, job_repository=jobs)
        assert seen == [True]
        parent, child = jobs.get(parent.id), jobs.get(child.id)
        assert runtime.mixed_append_retry_choices(parent, child, jobs=jobs) is not None
        with pytest.raises(runtime.MixedAppendReviewAttention, match="completed append plans are missing"):
            runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)


@pytest.mark.parametrize("race", [False, True])
def test_completed_retry_guard_records_server_mode_and_rechecks_artifacts(tmp_path, monkeypatch, race):
    state, jobs, parent, child, context = _stage_precommand_retry(tmp_path, monkeypatch, corrected=True)
    files = {"authority": {}}
    for provider, workspace in context.workspaces.items():
        files[provider] = {}
        for suffix, blob in (("inputs.json", b"canonical"), ("plan-journal.jsonl", b"completed")):
            path = workspace.path / f".barragan-mixed-append-{provider}-{suffix}"
            path.write_bytes(blob); path.chmod(0o600)
            files[provider][path] = blob
    monkeypatch.setattr(runtime, "_completed_retry_files", lambda *_: files)
    original = jobs.retry_precommand_mixed_append_review
    def writer(p, c, **options):
        assert options["completed_plans_only"] is True
        if race:
            next(iter(files["digitalocean"])).write_bytes(b"changed")
        return original(p, c, **options)
    monkeypatch.setattr(jobs, "retry_precommand_mixed_append_review", writer)
    with db.bind(state):
        if race:
            with pytest.raises(runtime.MixedAppendReviewAttention):
                runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
            assert jobs.get(child.id) == child
        else:
            runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
            assert jobs.get(child.id).events[-1].data == {"completedPlansOnly": True}


def _completed_first_review(tmp_path, monkeypatch, order):
    """Real SQL failed Review + producer's exact completed-first journal.

    Initial publication, pure plan gates and Terraform commands are explicit
    offline witnesses; retry file/lock/CAS/journal and receipt paths are real.
    """
    import json
    from test_provider_keyed_mixed_append_pair_plan_producer import fixture
    from app.services import provider_keyed_mixed_append_pair_plan_producer as producer
    from app.services import provider_keyed_mixed_append_reservation as reservation
    kwargs, calls, runner = fixture(tmp_path, monkeypatch)
    kwargs['reviewed_provider_order'] = order
    approved = {p + '_intent': getattr(producer, 'compile_mixed_' + (
        'digitalocean_on_linode_append_intent' if p == 'digitalocean' else 'linode_on_digitalocean_append_intent'))()
        for p in order}
    approved['digitalocean_firewall'] = kwargs['digitalocean_firewall']
    approved['reviewed_inputs'] = {p: approved[p + '_intent'].nonsecret_varfile for p in order}
    kwargs['reviewed_chain_order'] = tuple(approved[p + '_intent'].chain_id for p in order)
    real_gate = producer._full_gate
    def fail_first(provider, *_a, **_k):
        assert provider == order[0]
        raise ValueError('saved first full plan needs corrected semantic gate')
    monkeypatch.setattr(producer, '_full_gate', fail_first)
    with pytest.raises(producer.MixedAppendPairPlanProductionAttention):
        producer.produce_mixed_append_pair_plan_review(**kwargs)
    monkeypatch.setattr(producer, '_full_gate', real_gate)
    source = kwargs['source']
    topologies = {p: {**json.loads((w.path / '.barragan-topology.json').read_bytes()), 'schema': 'provider-keyed-v2'} for p, w in kwargs['workspaces'].items()}
    for p, w in kwargs['workspaces'].items(): (w.path / '.barragan-topology.json').write_text(json.dumps(topologies[p]))
    ordinal = next(iter(kwargs['workspaces'].values())).path.parents[1] / 'regional-ordinals.json'
    ordinal.write_text('{}')
    proposal = SimpleNamespace(reservations=tuple(SimpleNamespace(provider=p, proposed_topology=topologies[p]) for p in order),
                               proposed_high_water={})
    monkeypatch.setattr(reservation, 'propose_mixed_external_append_reservations', lambda **_: proposal)
    monkeypatch.setattr(producer, 'propose_mixed_external_append_reservations', lambda **_: proposal)
    monkeypatch.setattr(producer, 'reserve_mixed_external_provider_topologies', lambda *_: topologies)
    monkeypatch.setattr(producer, 'read_provider_topology', lambda w: topologies[w.provider])
    monkeypatch.setattr(producer, 'SqlAlchemyCredentialRepository', lambda: kwargs['credential_repository'])
    monkeypatch.setattr(producer, 'require_devtest_terraform_release', kwargs['release_check'])
    monkeypatch.setattr(producer, '_process_quiescent', lambda *_: True)
    context = SimpleNamespace(**{k: kwargs[k] for k in ('source', 'workspaces', 'provider_states', 'admin_public_key', 'admin_private_key')},
        original_topologies=topologies, original_regional_high_water={}, reviewed_provider_order=order,
        binding_manifest=kwargs['binding_manifest'], approval_kwargs=lambda: approved,
        producer_kwargs=lambda: {**{k: v for k, v in kwargs.items() if k != 'lease_lookup'}, 'lease_owner': source.core_plan_id})
    state, jobs = _setup(source.engagement_id, source.core_job_id, source.core_plan_id)
    with db.bind(state):
        parent = runtime.pair.reserve_mixed_append_pair(source.engagement_id, source.core_job_id, source.core_plan_id,
            requested_by='operator', reviewed_request=_request(approved), provider_order=order,
            chain_order=kwargs['reviewed_chain_order'], job_repository=jobs)
        def fail_context(*_a, **_k): raise ValueError('completed first needs reconciliation')
        monkeypatch.setattr(runtime, 'collect_mixed_append_pair_plan_context', fail_context)
        with pytest.raises(runtime.MixedAppendReviewAttention): runtime.run_mixed_append_review(parent.id, job_repository=jobs)
        parent, child = jobs.get(parent.id), jobs.get(runtime.pair._plan_child_id(parent.id))
    monkeypatch.setattr(runtime, 'collect_mixed_append_pair_plan_context', lambda *_a, **_k: context)
    published = PublishedMixedAppendSource(source, tuple((p, w.path) for p, w in context.workspaces.items()), 0, 'd'*64, 'e'*64)
    monkeypatch.setattr(runtime.pair, '_collect_published', lambda *_: published)
    return state, jobs, parent, child, context, kwargs, calls, runner


@pytest.mark.parametrize('order', [('linode', 'digitalocean'), ('digitalocean', 'linode')])
def test_completed_first_retry_sql_worker_reopens_first_and_only_plans_second(tmp_path, monkeypatch, order):
    state, jobs, parent, child, context, kwargs, calls, runner = _completed_first_review(tmp_path, monkeypatch, order)
    first, second = order
    journal = context.workspaces[first].path / f'.barragan-mixed-append-{first}-plan-journal.jsonl'
    original = journal.read_bytes()
    def second_only(argv, **options):
        assert options['scratch_path'].parent.name == second, 'completed first command replayed'
        return runner(argv, **options)
    kwargs['gated_command_runner'] = second_only
    with db.bind(state):
        choices = runtime.mixed_append_retry_choices(parent, child, jobs=jobs)
        runtime.begin_mixed_append_review(parent.target_id, parent.input['coreJobId'], choices, 'operator', job_repository=jobs)
        queued = jobs.get(child.id)
        assert queued.events[-1].data == {'completedFirstProvider': first}
        assert queued.events[:3] == child.events
        succeeded = runtime.run_mixed_append_review(parent.id, job_repository=jobs)
        assert succeeded.status == 'succeeded'
        assert jobs.get(parent.id).input['reviewSummary']['providerOrder'] == list(order)
    assert journal.read_bytes() == original
    assert calls == [(first, phase) for phase in ('version', 'init', 'plan', 'show')] + [
        (second, phase) for phase in ('version', 'init', 'plan', 'show')]


@pytest.mark.parametrize('drift', ['first_journal_missing', 'first_journal_empty', 'second_journal', 'second_inputs',
                                  'second_plan', 'first_show', 'state', 'lock_active'])
def test_completed_first_retry_rejects_changed_files_and_never_commands(tmp_path, monkeypatch, drift):
    from app.services import provider_keyed_mixed_append_pair_plan_producer as producer
    import fcntl
    state, jobs, parent, child, context, kwargs, calls, _ = _completed_first_review(tmp_path, monkeypatch, ('linode', 'digitalocean'))
    first, second = context.reviewed_provider_order
    with db.bind(state):
        runtime.retry_precommand_mixed_append_review(parent, child, jobs=jobs)
        assert jobs.get(child.id).events[-1].data == {'completedFirstProvider': first}
        root = context.workspaces[first if drift.startswith('first') else second].path
        prefix = f'.barragan-mixed-append-{first if drift.startswith("first") else second}-'
        held = None
        if drift == 'first_journal_missing': (root / (prefix + 'plan-journal.jsonl')).unlink()
        elif drift == 'first_journal_empty': (root / (prefix + 'plan-journal.jsonl')).write_bytes(b'')
        elif drift == 'first_show': (root / (prefix + 'show.json')).write_bytes(b'changed')
        elif drift.startswith('second_'):
            suffix = {'second_journal': 'plan-journal.jsonl', 'second_inputs': 'inputs.json', 'second_plan': 'saved.tfplan'}[drift]
            path = root / (prefix + suffix); path.write_bytes(b'changed'); path.chmod(0o600)
        elif drift == 'state': context.workspaces[first].state_path.write_bytes(b'changed')
        else:
            held = (root / (prefix + 'plan.lock')).open('r+b'); fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        kwargs['gated_command_runner'] = lambda *_a, **_k: pytest.fail('changed retry ran a command')
        try:
            with pytest.raises(runtime.MixedAppendReviewAttention): runtime.run_mixed_append_review(parent.id, job_repository=jobs)
        finally:
            if held: held.close()
        assert calls == [(first, phase) for phase in ('version', 'init', 'plan', 'show')]
        if drift == 'first_journal_missing':
            with pytest.raises(runtime.MixedAppendReviewAttention, match='completed append plans are missing'):
                runtime.retry_precommand_mixed_append_review(jobs.get(parent.id), jobs.get(child.id), jobs=jobs)


@pytest.mark.parametrize('marker', [{'completedPlansOnly': 1}, {'completedFirstProvider': True},
                                   {'completedFirstProvider': 'digitalocean', 'extra': True}])
def test_retry_history_rejects_untyped_or_extra_mode_fields(tmp_path, monkeypatch, marker):
    from dataclasses import replace
    from app.domain import JobEvent
    state, jobs, parent, child, context = _stage_precommand_retry(tmp_path, monkeypatch)
    with db.bind(state):
        invalid = replace(child, events=[*child.events,
            JobEvent(4, 'info', 'mixed append pair Review retry requested', marker),
            JobEvent(5, 'info', 'mixed append pair plan started', {}),
            JobEvent(6, 'error', 'mixed append pair plan needs reconciliation', {})])
        assert runtime.mixed_append_retry_choices(parent, invalid, jobs=jobs) is None
