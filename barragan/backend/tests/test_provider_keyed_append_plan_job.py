# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted reservation for a single non-applying edge review."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_append_plan_job import (
    ProviderKeyedAppendPlanJobError, begin_published_digitalocean_edge_append_plan,
    run_published_digitalocean_edge_append_plan,
    reconcile_reviewed_digitalocean_edge_append_plan,
    discard_reviewed_digitalocean_edge_append_plan,
    reconcile_interrupted_digitalocean_edge_append_plan,
    cancel_unscheduled_digitalocean_edge_append_plan,
    reconcile_failed_artifact_free_edge_append_plan,
    cancel_unscheduled_digitalocean_edge_append_plan,
)
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_published_teardown_source import audit_published_provider_keyed_source
from app.services.provider_keyed_append_plan_runner import (
    ProviderKeyedAppendPlanEvidence, ProviderKeyedAppendPlanPreparationError,
)
from app.services.provider_keyed_initial_plan_gate import _SOURCE_SHA256
from app.services.provider_keyed_initial_plan_gate import DigitalOceanNodeCreate
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.storage.job_repository import SqliteJobRepository, job_event_digest
from app.storage.database import db
from app.storage.deployment_plan_repository import DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import DeploymentPlanModel, EngagementModel
from app.domain import JobEvent
from test_provider_keyed_published_teardown_source import _case


class Chains:
    def __init__(self, rows):
        self.rows = rows

    def list_for_engagement(self, engagement_id):
        return [row for row in self.rows if row.engagement_id == engagement_id]

    def get(self, engagement_id, chain_id):
        return next((row for row in self.rows if row.engagement_id == engagement_id
                     and row.chain_id == chain_id), None)


class Plans:
    def __init__(self, plan, state, jobs):
        self.plan = plan
        self.state = state
        self.jobs = jobs

    def get(self, _plan_id):
        return self.plan

    def reserve_provider_keyed_append_plan(self, parent, child):
        if self.state["lease"] is not None:
            return False
        self.state["lease"] = (parent.input["corePlanId"], "provider_keyed_edge_append")
        self.jobs.save_if_absent(parent)
        self.jobs.save_if_absent(child)
        return True

    def close_unapplied_provider_keyed_append_plan(self, parent, child, *, state_sha256):
        if self.state["lease"] != (parent.input["corePlanId"], "provider_keyed_edge_append"):
            raise ValueError("lease differs")
        assert self.jobs.get(parent.id) == parent and self.jobs.get(child.id) == child
        terminal = JobEvent(len(parent.events) + 1, "info",
            "append plan reconciled without mutation", {"stateSha256": state_sha256})
        closed = self.jobs.save(replace(parent, status="failed",
            input={**parent.input, "phase": "unapplied_reconciled"},
            finished_at=datetime.now(timezone.utc).isoformat(),
            events=[*parent.events, terminal]))
        self.state["lease"] = None
        return closed


def _reservation(tmp_path, monkeypatch, *, retained_state=None):
    jobs, _initial, _manifest, rows, state, options = _case(tmp_path)
    source = audit_published_provider_keyed_source("job-core", **options)
    if retained_state is not None:
        path = Path(rows[0].terraform_working_directory) / "terraform.tfstate"
        path.write_text(json.dumps(retained_state, sort_keys=True))
        source = replace(source, state_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    for index, row in enumerate(rows):
        rows[index] = replace(row, edge_count=1, nodes=row.nodes[:2], edge_intents=[{
            "id": "edge-01", "provider": "digitalocean", "region": row.edge_region,
            "size": row.edge_size,
        }])
    chains = Chains(rows)
    plans = Plans(state["plan"], state, jobs)

    def audit(core_job_id, **kwargs):
        assert core_job_id == "job-core"
        expected = kwargs.get("expected_mutation_lease")
        assert state["lease"] == expected
        if expected is not None:
            assert kwargs.get("allowed_append_plan_parent_id")
        return source

    monkeypatch.setattr("app.services.provider_keyed_append_plan_job.audit_published_provider_keyed_source", audit)
    kwargs = dict(requested_by="operator", job_repository=jobs,
                  plan_repository=plans, sketch_repository=chains,
                  lease_lookup=lambda _engagement: state["lease"])
    return jobs, rows, state, kwargs


def test_append_plan_reservation_persists_parent_child_and_keeps_rows(tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    before = list(rows)
    assert (rows[0].status, rows[0].burned, rows[0].edge_count,
            len(rows[0].nodes), rows[0].edge_intents) == (
        "deployed", False, 1, 2, [{"id": "edge-01", "provider": "digitalocean",
                                     "region": rows[0].edge_region, "size": rows[0].edge_size}])
    parent, child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    assert state["lease"] == (parent.input["corePlanId"], "provider_keyed_edge_append")
    assert parent.input["planJobId"] == child.id
    assert child.status == "queued" and child.input["mutation"] is False
    assert jobs.get(parent.id) == parent and jobs.get(child.id) == child
    assert SqliteJobRepository(tmp_path / "jobs.sqlite").get(child.id) == child
    assert rows == before
    with pytest.raises(ProviderKeyedAppendPlanJobError):
        begin_published_digitalocean_edge_append_plan(
            "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)


def test_reconciled_unapplied_append_can_be_reviewed_again_without_changing_rows(
        tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    before = list(rows)
    first, _child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    closed = cancel_unscheduled_digitalocean_edge_append_plan(first.id, **{
        key: kwargs[key] for key in ("job_repository", "plan_repository", "sketch_repository",
                                    "lease_lookup")})
    assert closed.input["phase"] == "unapplied_reconciled"
    assert state["lease"] is None
    second, second_child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    assert second.id != first.id and second_child.id != first.input["planJobId"]
    assert jobs.get(first.id) == closed
    assert rows == before
    assert state["lease"] == (second.input["corePlanId"], "provider_keyed_edge_append")
    second_closed = cancel_unscheduled_digitalocean_edge_append_plan(second.id, **{
        key: kwargs[key] for key in ("job_repository", "plan_repository", "sketch_repository",
                                    "lease_lookup")})
    third, _ = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    assert {first.id, second.id, third.id} == {job.id for job in jobs.list_for_engagement(
        first.target_id) if job.action == "provider_keyed_edge_append"}
    assert jobs.get(first.id) == closed and jobs.get(second.id) == second_closed
    assert rows == before


def test_persisted_no_go_apply_history_can_review_and_reconcile_next_plan(
        tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    first, plan = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    sha = first.input["initialSource"]["state_sha256"]
    now = datetime.now(timezone.utc).isoformat()
    plan = jobs.save(replace(plan, status="succeeded", started_at=now, finished_at=now,
        events=[*plan.events, JobEvent(2, "info", "reviewed append plan saved", {
            "stateSha256": sha, "planSha256": "a" * 64,
        })]))
    plan_digest = job_event_digest(plan.events)
    apply_id = "job-provider-keyed-append-apply-" + first.id.removeprefix(
        "job-provider-keyed-append-")
    reserved = JobEvent(1, "info", "provider append Apply child reserved", {
        "planJournalSha256": plan_digest, "reservationId": "b" * 32})
    no_go = JobEvent(2, "info", "provider append Apply never started", {
        "stateSha256": sha, "planJournalSha256": plan_digest})
    apply = jobs.save(StoredJobRun(apply_id, "provider_keyed_edge_append_apply",
        "failed", first.target, "engagement", first.target_id, "operator", {
            "engagementId": first.target_id, "parentJobId": first.id,
            "coreJobId": "job-core", "corePlanId": first.input["corePlanId"],
            "planJobId": plan.id, "mutation": True,
        }, [], now, None, now, [reserved, no_go]))
    first = jobs.save(replace(first, status="failed", finished_at=now,
        input={**first.input, "phase": "unapplied_reconciled",
               "applyJobId": apply.id, "applyReservationId": "b" * 32,
               "planJournalSha256": plan_digest, "applyRequestedPlanSha256": "a" * 64},
        events=[*first.events,
            JobEvent(2, "info", "provider append Apply reserved", {
                "planJournalSha256": plan_digest, "reservationId": "b" * 32}),
            JobEvent(3, "info", "provider append Apply no-GO fenced", {
                "stateSha256": sha,
                "applyChildJournalSha256": job_event_digest(apply.events)}),
            JobEvent(4, "info", "append plan reconciled without mutation", {
                "stateSha256": sha,
                "noGoApplyChildJournalSha256": job_event_digest(apply.events)}),
        ]))
    state["lease"] = None
    second, second_plan = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    assert second.id != first.id and state["lease"] is not None
    from app.services.provider_keyed_teardown_scope import _require_unapplied_append_plan
    _require_unapplied_append_plan(
        second.target_id, second.id, jobs, expected_core_job_id="job-core")
    from app.asgi import _append_unscheduled_review_cancel_state
    assert _append_unscheduled_review_cancel_state(
        second, second_plan, jobs, lease=state["lease"],
        now=datetime.now(timezone.utc)) == "waiting"
    assert _append_unscheduled_review_cancel_state(
        second, second_plan, jobs, lease=state["lease"],
        now=datetime.now(timezone.utc) + timedelta(minutes=2)) == "ready"
    closed = cancel_unscheduled_digitalocean_edge_append_plan(second.id, **{
        key: kwargs[key] for key in ("job_repository", "plan_repository",
                                 "sketch_repository", "lease_lookup")})
    assert closed.input["phase"] == "unapplied_reconciled"
    assert state["lease"] is None
    assert _append_unscheduled_review_cancel_state(
        jobs.get(second.id), jobs.get(second_plan.id), jobs, lease=state["lease"],
        now=datetime.now(timezone.utc) + timedelta(minutes=2)) == ""
    # The same original generation stays intact after both no-mutation closes.
    assert all(row.edge_count == 1 and len(row.nodes) == 2 for row in rows)
    jobs.save(replace(apply, events=[reserved, replace(no_go, data={
        "stateSha256": "f" * 64, "planJournalSha256": plan_digest})]))
    with pytest.raises(ProviderKeyedAppendPlanJobError):
        begin_published_digitalocean_edge_append_plan(
            "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)


@pytest.mark.parametrize("tamper", ["state", "apply", "parent", "orphan_plan"])
def test_reconciled_append_retry_rejects_ambiguous_history(tmp_path, monkeypatch, tamper):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    first, _child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    closed = cancel_unscheduled_digitalocean_edge_append_plan(first.id, **{
        key: kwargs[key] for key in ("job_repository", "plan_repository", "sketch_repository",
                                    "lease_lookup")})
    if tamper == "state":
        jobs.save(replace(closed, events=[*closed.events[:-1], replace(
            closed.events[-1], data={"stateSha256": "f" * 64})]))
    elif tamper == "apply":
        now = datetime.now(timezone.utc).isoformat()
        jobs.save(StoredJobRun("job-unreviewed-apply", "provider_keyed_edge_append_apply",
            "failed", closed.target, "engagement", closed.target_id, "operator",
            {"parentJobId": closed.id}, [], now, now, now, []))
    elif tamper == "parent":
        jobs.save(replace(closed, status="running", finished_at=None))
    else:
        now = datetime.now(timezone.utc).isoformat()
        jobs.save(StoredJobRun("job-orphan-plan", "provider_keyed_edge_append_plan",
            "failed", closed.target, "engagement", closed.target_id, "operator",
            {"parentJobId": "missing"}, [], now, now, now, []))
    with pytest.raises(ProviderKeyedAppendPlanJobError):
        begin_published_digitalocean_edge_append_plan(
            "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    assert state["lease"] is None


def test_reconciled_append_retry_requires_owned_plan_artifacts_absent(tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    first, _child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    cancel_unscheduled_digitalocean_edge_append_plan(first.id, **{
        key: kwargs[key] for key in ("job_repository", "plan_repository", "sketch_repository",
                                    "lease_lookup")})
    residue = Path(rows[0].terraform_working_directory) / ".barragan-edge-append.tfplan"
    residue.write_bytes(b"unexpected")
    with pytest.raises(ProviderKeyedAppendPlanJobError, match="artifacts remain"):
        begin_published_digitalocean_edge_append_plan(
            "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    assert state["lease"] is None


def test_append_plan_reservation_does_not_write_on_unavailable_lease(tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    state["lease"] = ("other", "other")
    with pytest.raises(Exception):
        begin_published_digitalocean_edge_append_plan(
            "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    assert not [job for job in jobs.list_for_engagement(rows[0].engagement_id)
                if job.action == "provider_keyed_edge_append"]


def test_unscheduled_queued_append_is_fenced_and_releases_no_apply_lease(tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    parent, child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    closed = cancel_unscheduled_digitalocean_edge_append_plan(parent.id,
        job_repository=jobs, plan_repository=kwargs["plan_repository"],
        sketch_repository=kwargs["sketch_repository"], lease_lookup=kwargs["lease_lookup"])
    assert closed.status == "failed" and closed.input["phase"] == "unapplied_reconciled"
    assert jobs.get(child.id).status == "failed" and state["lease"] is None
    assert jobs.start_if_queued(child, started_at=datetime.now(timezone.utc).isoformat(),
        event=JobEvent(2, "info", "late worker started", {})) is None


def test_plan_worker_persists_failure_before_any_provider_or_terraform_command(tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    parent, child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    calls = []

    def reject_initial_state(*_args, **_kwargs):
        calls.append("state")
        raise ValueError("retained initial state unavailable")

    monkeypatch.setattr(
        "app.services.provider_keyed_append_plan_job.read_applied_digitalocean_provider_for_teardown",
        reject_initial_state)
    with pytest.raises(ProviderKeyedAppendPlanJobError):
        run_published_digitalocean_edge_append_plan(
            child.id, job_repository=jobs, plan_repository=kwargs["plan_repository"],
            sketch_repository=kwargs["sketch_repository"],
            lease_lookup=kwargs["lease_lookup"],
            attachment_membership=lambda *_a, **_k: pytest.fail("provider GET must not run"),
            plan_runner=lambda *_a, **_k: pytest.fail("Terraform must not run"),
        )
    assert calls == ["state"]
    persisted = SqliteJobRepository(tmp_path / "jobs.sqlite").get(child.id)
    assert persisted.status == "failed"
    assert persisted.events[-1].message == "provider append plan preparation failed"
    assert persisted.events[-1].data == {"stage": "preparation"}
    assert jobs.get(parent.id).status == "running"
    assert state["lease"] == (parent.input["corePlanId"], "provider_keyed_edge_append")
    from app.services.provider_keyed_append_plan_job import (
        reconcile_failed_artifact_free_edge_append_plan,
    )
    closed = reconcile_failed_artifact_free_edge_append_plan(
        parent.id, job_repository=jobs, plan_repository=kwargs["plan_repository"],
        sketch_repository=kwargs["sketch_repository"],
        lease_lookup=kwargs["lease_lookup"])
    assert closed.status == "failed" and closed.input["phase"] == "unapplied_reconciled"
    assert state["lease"] is None
    from app.services.provider_keyed_teardown_scope import _reconciled_unapplied_append_state_sha
    assert _reconciled_unapplied_append_state_sha(parent.target_id, jobs)


def test_plan_worker_persists_allowlisted_saved_gate_reason(tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    _parent, child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    reason_code = "resource_omitted"
    def reject(*_args, **_kwargs):
        raise ProviderKeyedAppendPlanPreparationError("saved_plan_gate", reason_code)
    monkeypatch.setattr(
        "app.services.provider_keyed_append_plan_job.read_applied_digitalocean_provider_for_teardown",
        reject)
    with pytest.raises(ProviderKeyedAppendPlanJobError):
        run_published_digitalocean_edge_append_plan(
            child.id, job_repository=jobs, plan_repository=kwargs["plan_repository"],
            sketch_repository=kwargs["sketch_repository"],
            lease_lookup=kwargs["lease_lookup"],
            attachment_membership=lambda *_a, **_k: pytest.fail("provider GET must not run"),
            plan_runner=lambda *_a, **_k: pytest.fail("Terraform must not run"),
        )
    persisted = SqliteJobRepository(tmp_path / "jobs.sqlite").get(child.id)
    assert persisted.status == "failed"
    assert persisted.events[-1].data == {"stage": "saved_plan_gate", "reasonCode": reason_code}


def test_truncated_plan_receipt_cannot_be_promoted_after_restart(tmp_path, monkeypatch):
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch)
    parent, child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    import app.services.provider_keyed_append_plan_job as service
    source = service.audit_published_provider_keyed_source("job-core",
        expected_mutation_lease=state["lease"], allowed_append_plan_parent_id=parent.id)
    path = Path(rows[0].terraform_working_directory) / ".barragan-edge-append.tfplan"
    path.write_bytes(b"opaque reviewed binary plan")
    path.chmod(0o600)
    running = jobs.start_if_queued(child, started_at=datetime.now(timezone.utc).isoformat(),
        event=JobEvent(len(child.events) + 1, "info", "started", {}))
    assert running is not None
    saved = jobs.finish_if_running(running, status="succeeded",
        finished_at=datetime.now(timezone.utc).isoformat(),
        event=JobEvent(len(running.events) + 1, "info", "reviewed append plan saved", {
            "initialSource": json.loads(json.dumps(asdict(source))),
            "initialSourceSha256": _fingerprint(asdict(source)),
            "selectedChain": rows[0].to_dict(),
            "stateSha256": source.state_sha256,
            "planPath": str(path),
            "planSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }))
    assert saved is not None and jobs.get(parent.id).input["phase"] == "planning"
    reopened = SqliteJobRepository(tmp_path / "jobs.sqlite")
    options = {**kwargs, "job_repository": reopened}
    with pytest.raises(ProviderKeyedAppendPlanJobError):
        reconcile_reviewed_digitalocean_edge_append_plan(parent.id, **{
            key: options[key] for key in ("job_repository", "plan_repository", "sketch_repository", "lease_lookup")})
    assert reopened.get(parent.id).input["phase"] == "planning"


def test_plan_worker_saves_one_review_without_changing_published_rows(tmp_path, monkeypatch):
    original_jobs, _parent, _manifest, original_rows, _state, _options = _case(tmp_path / "source")
    state_resources = []
    for row in original_rows:
        for node in row.nodes[:2]:
            address = node["terraformAddress"]
            kind, rest = address.split(".", 1)
            name, key = rest.split("[", 1)
            state_resources.append({"mode": "managed", "type": kind, "name": name,
                "instances": [{"index_key": json.loads(key[:-1]),
                    "attributes": {"id": node["providerInstanceId"]}}]})
    for kind, name, identity in (("digitalocean_firewall", "firewall", "firewall-id"),
                                 ("digitalocean_ssh_key", "key", "key-id")):
        state_resources.append({"mode": "managed", "type": kind, "name": name,
                                "instances": [{"attributes": {"id": identity}}]})
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch,
        retained_state={"resources": state_resources})
    old_root = Path(rows[0].terraform_working_directory)
    canonical_root = tmp_path / "state" / "provider-keyed-v2" / "digitalocean" / "fingerprint"
    canonical_root.parent.mkdir(parents=True)
    old_root.rename(canonical_root)
    canonical_root.chmod(0o700)
    for index, row in enumerate(rows):
        rows[index] = replace(row, terraform_working_directory=str(canonical_root))
    del original_jobs
    parent, child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    retained = list(rows)
    import app.services.provider_keyed_append_plan_job as service
    source = service.audit_published_provider_keyed_source("job-core",
        expected_mutation_lease=state["lease"], allowed_append_plan_parent_id=parent.id)
    root = Path(rows[0].terraform_working_directory)
    (root / ".barragan-provider-keyed-state.json").write_text(json.dumps({
        "provider_connection_id": "connection-id"}))
    (root / ".barragan-topology.json").write_text(json.dumps({"schema": "provider-keyed-v2",
        "middles": {"one": {}}, "edge_groups": {}}))
    (root / ".terraform.lock.hcl").write_text("pinned lock")
    (root / ".barragan-initial-full-plan.lock").write_bytes(b"")
    (root / ".barragan-initial-full-plan.lock").chmod(0o600)
    (root.parents[1] / ".regional-ordinals.lock").write_bytes(b"")
    (root.parents[1] / ".regional-ordinals.lock").chmod(0o600)
    (root.parents[1] / ".plan-material" / "digitalocean").mkdir(parents=True, mode=0o700,
        exist_ok=True)
    workspace = ProviderKeyedWorkspace(root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", "digitalocean", "connection-id", "fingerprint", "a" * 40,
        _SOURCE_SHA256)
    new_address = 'digitalocean_droplet.edge["sfo3-99"]'
    new_node = DigitalOceanNodeCreate("new-edge", "image", "size", "sfo3", "selector")
    intent = SimpleNamespace(nodes={**{node["terraformAddress"]: new_node
        for row in rows for node in row.nodes}, new_address: new_node},
        firewall=object(), nonsecret_varfile={"middles": {}, "edge_groups": {}},
        topology={"middles": {}, "edge_groups": {}}, engagement_name="opaque")
    calls = []
    monkeypatch.setattr(service, "read_applied_digitalocean_provider_for_teardown",
        lambda *_a, **_k: (None, workspace, None, None))
    monkeypatch.setattr(service, "derive_digitalocean_initial_attachment_intent",
        lambda *_a: SimpleNamespace(state_sha256=source.state_sha256))
    monkeypatch.setattr(service, "compile_fresh_digitalocean_persisted_intent",
        lambda *_a, **_k: intent)
    monkeypatch.setattr(service, "managed_host_image_profile_named", lambda _name: object())
    monkeypatch.setattr(service, "retrieve_sketch_ssh_key", lambda *_a:
        SimpleNamespace(private_key="PRIVATE", public_key="PUBLIC"))
    monkeypatch.setattr(service, "_expected_inventory", lambda *_a: "reviewed inventory")
    terraform = tmp_path / "terraform"
    terraform.write_text("pinned binary")
    monkeypatch.setattr(service, "require_devtest_terraform_release", lambda **_k:
        SimpleNamespace(path=terraform, sha256=hashlib.sha256(terraform.read_bytes()).hexdigest()))
    monkeypatch.setattr(service, "_credential_snapshot", lambda *_a: ("e" * 64, "updated", "encrypted"))
    kwargs["plan_repository"].plan.evidence["managedHostImageProfile"] = "test"

    def saved_plan(*_args, **params):
        calls.append(params["new_edge_address"])
        plan = root / ".barragan-edge-append.tfplan"
        plan.write_bytes(b"reviewed binary plan")
        plan.chmod(0o600)
        return ProviderKeyedAppendPlanEvidence(plan, hashlib.sha256(plan.read_bytes()).hexdigest(),
            source.state_sha256, hashlib.sha256((root / ".barragan-topology.json").read_bytes()).hexdigest(),
            _SOURCE_SHA256, hashlib.sha256((root / ".terraform.lock.hcl").read_bytes()).hexdigest(),
            ((str(params["var_files"][0]), next(iter(params["input_sha256"].values()))),),
            "connection-id", "e" * 64, "updated", terraform,
            hashlib.sha256(terraform.read_bytes()).hexdigest())

    finished = run_published_digitalocean_edge_append_plan(
        child.id, job_repository=jobs, plan_repository=kwargs["plan_repository"],
        sketch_repository=kwargs["sketch_repository"],
        engagement_repository=SimpleNamespace(get=lambda _id: object()),
        lease_lookup=kwargs["lease_lookup"],
        attachment_membership=lambda *_a, **_k: calls.append("provider GET"),
        plan_runner=saved_plan)
    assert calls == ["provider GET", new_address]
    assert finished.status == "succeeded"
    assert jobs.get(parent.id).input["phase"] == "awaiting_apply"
    assert rows == retained
    assert not (root.parents[1] / ".plan-material" / "digitalocean" / "admin-private").exists()
    published = jobs.get(parent.id)
    jobs.save(replace(published, input={key: value for key, value in published.input.items()
        if key != "planJournalSha256"} | {"phase": "planning"},
        events=published.events[:-1]))
    reopened = SqliteJobRepository(tmp_path / "jobs.sqlite")
    repaired = reconcile_reviewed_digitalocean_edge_append_plan(parent.id,
        job_repository=reopened, plan_repository=kwargs["plan_repository"],
        sketch_repository=kwargs["sketch_repository"],
        lease_lookup=kwargs["lease_lookup"])
    assert repaired.input["phase"] == "awaiting_apply"
    terraform.write_text("tampered binary")
    with pytest.raises(ProviderKeyedAppendPlanJobError):
        reconcile_reviewed_digitalocean_edge_append_plan(parent.id,
            job_repository=reopened, plan_repository=kwargs["plan_repository"],
            sketch_repository=kwargs["sketch_repository"],
            lease_lookup=kwargs["lease_lookup"])
    terraform.write_text("pinned binary")
    plans = kwargs["plan_repository"]
    committed_close = plans.close_unapplied_provider_keyed_append_plan
    def interrupted_close(*_args, **_kwargs):
        raise RuntimeError("simulated crash before atomic close")
    plans.close_unapplied_provider_keyed_append_plan = interrupted_close
    with pytest.raises(RuntimeError, match="simulated crash"):
        discard_reviewed_digitalocean_edge_append_plan(
            parent.id, job_repository=reopened, plan_repository=plans,
            sketch_repository=kwargs["sketch_repository"], lease_lookup=kwargs["lease_lookup"])
    assert jobs.get(parent.id).input["phase"] == "discarding"
    assert state["lease"] == (parent.input["corePlanId"], "provider_keyed_edge_append")
    assert not (root / ".barragan-edge-append.tfplan").exists()
    plans.close_unapplied_provider_keyed_append_plan = committed_close
    closed = discard_reviewed_digitalocean_edge_append_plan(
        parent.id, job_repository=reopened, plan_repository=plans,
        sketch_repository=kwargs["sketch_repository"], lease_lookup=kwargs["lease_lookup"])
    assert closed.status == "failed" and closed.input["phase"] == "unapplied_reconciled"
    assert state["lease"] is None and rows == retained
    assert not (root / ".barragan-edge-append.tfplan").exists()
    assert not (root.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json").exists()


def test_sqlalchemy_append_reservation_commits_both_jobs_and_lease_together(tmp_path):
    state = db.configure(f"sqlite:///{tmp_path / 'append-reserve.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(id="eng-a", name="opaque", status="deployed",
            owner="operator", template_id="dev", input_parameters={}))
        db.session.add(DeploymentPlanModel(id="plan-a", engagement_id="eng-a",
            revision_id="rev-a", status="applied", stage="applied", review={},
            evidence={}, is_current=False, apply_job_id="job-core", error=""))
        db.session.commit()
        now = datetime.now(timezone.utc).isoformat()
        parent = StoredJobRun("job-append", "provider_keyed_edge_append", "running",
            "engagement:eng-a", "engagement", "eng-a", "operator",
            {"engagementId": "eng-a", "corePlanId": "plan-a", "coreJobId": "job-core",
             "planJobId": "job-plan", "phase": "planning"},
            [], now, now, None, [JobEvent(1, "info", "reserved", {})])
        child = StoredJobRun("job-plan", "provider_keyed_edge_append_plan", "queued",
            parent.target, "engagement", "eng-a", "operator",
            {"parentJobId": parent.id, "coreJobId": "job-core", "mutation": False},
            [], now, None, None, [JobEvent(1, "info", "queued", {})])
        plans = SqlAlchemyDeploymentPlanRepository()
        assert plans.reserve_provider_keyed_append_plan(parent, child)
        jobs = SqlAlchemyJobRepository()
        assert jobs.get(parent.id).input == parent.input
        assert jobs.get(child.id).input == child.input
        assert jobs.get(parent.id).events == parent.events
        assert jobs.get(child.id).events == child.events
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        assert _db_lease_lookup("eng-a") == ("plan-a", "provider_keyed_edge_append")
        with pytest.raises(DeploymentPlanConflictError):
            plans.reserve_provider_keyed_append_plan(replace(parent, id="job-other"), child)
        assert jobs.get("job-other") is None
        assert _db_lease_lookup("eng-a") == ("plan-a", "provider_keyed_edge_append")
        queued = jobs.get(child.id)
        running = jobs.start_if_queued(queued, started_at=now,
            event=JobEvent(2, "info", "started", {}))
        failed = jobs.finish_if_running(running, status="failed", finished_at=now,
            event=JobEvent(3, "error", "plan failed", {}))
        closed = plans.close_unapplied_provider_keyed_append_plan(
            jobs.get(parent.id), failed, state_sha256="a" * 64)
        assert closed.status == "failed" and closed.input["phase"] == "unapplied_reconciled"
        assert closed.events[-1].message == "append plan reconciled without mutation"
        assert _db_lease_lookup("eng-a") is None
        retry_parent = replace(parent, id="job-append-retry",
            input={**parent.input, "planJobId": "job-plan-retry",
                   "initialSource": {"state_sha256": "a" * 64}})
        retry_child = replace(child, id="job-plan-retry",
            input={**child.input, "parentJobId": retry_parent.id})
        assert plans.reserve_provider_keyed_append_plan(retry_parent, retry_child)
        assert jobs.get(closed.id) == closed
        assert jobs.get(retry_parent.id).input == retry_parent.input
        assert _db_lease_lookup("eng-a") == ("plan-a", "provider_keyed_edge_append")
        assert plans.close_unapplied_provider_keyed_append_plan(
            jobs.get(retry_parent.id), jobs.finish_if_running(
                jobs.start_if_queued(jobs.get(retry_child.id), started_at=now,
                    event=JobEvent(2, "info", "started", {})),
                status="failed", finished_at=now,
                event=JobEvent(3, "error", "plan failed", {})),
            state_sha256="a" * 64).input["phase"] == "unapplied_reconciled"
        assert _db_lease_lookup("eng-a") is None
        db.session.add(EngagementModel(id="eng-b", name="opaque-b", status="deployed",
            owner="operator", template_id="dev", input_parameters={}))
        db.session.add(DeploymentPlanModel(id="plan-b", engagement_id="eng-b",
            revision_id="rev-b", status="applied", stage="applied", review={},
            evidence={}, is_current=False, apply_job_id="job-core-b", error=""))
        db.session.commit()
        reviewed_parent = replace(parent, id="job-append-b", target="engagement:eng-b",
            target_id="eng-b", input={"corePlanId": "plan-b", "coreJobId": "job-core-b",
                "planJobId": "job-plan-b", "phase": "planning"})
        reviewed_child = replace(child, id="job-plan-b", target=reviewed_parent.target,
            target_id="eng-b",
            input={"parentJobId": reviewed_parent.id, "coreJobId": "job-core-b"})
        assert plans.reserve_provider_keyed_append_plan(reviewed_parent, reviewed_child)
        jobs.save(replace(reviewed_parent, input={**reviewed_parent.input, "phase": "discarding"}))
        jobs.save(replace(reviewed_child, status="succeeded", started_at=now, finished_at=now))
        reviewed_close = plans.close_unapplied_provider_keyed_append_plan(
            jobs.get(reviewed_parent.id), jobs.get(reviewed_child.id), state_sha256="b" * 64)
        assert reviewed_close.status == "failed"
        assert reviewed_close.events[-1].data == {"stateSha256": "b" * 64}
        assert _db_lease_lookup("eng-b") is None


def test_expired_append_worker_residue_is_fenced_and_reconciled_after_restart(tmp_path, monkeypatch):
    from app.asgi import _append_failed_review_discard_state
    jobs, rows, state, kwargs = _reservation(tmp_path, monkeypatch,
        retained_state={"resources": []})
    old_root = Path(rows[0].terraform_working_directory)
    root = tmp_path / "state" / "provider-keyed-v2" / "digitalocean" / "fingerprint"
    root.parent.mkdir(parents=True)
    old_root.rename(root)
    root.chmod(0o700)
    for index, row in enumerate(rows):
        rows[index] = replace(row, terraform_working_directory=str(root))
    parent, child = begin_published_digitalocean_edge_append_plan(
        "job-core", rows[0].chain_id, rows[0].edge_region, rows[0].edge_size, **kwargs)
    (root / ".barragan-initial-full-plan.lock").write_bytes(b"")
    (root / ".barragan-initial-full-plan.lock").chmod(0o600)
    (root.parents[1] / ".regional-ordinals.lock").write_bytes(b"")
    (root.parents[1] / ".regional-ordinals.lock").chmod(0o600)
    material = root.parents[1] / ".plan-material" / "digitalocean"
    material.mkdir(parents=True, mode=0o700)
    for name, content in (("admin-private", "PRIVATE"), ("admin-public", "PUBLIC"),
                          ("append-inputs.json", "{}")):
        path = material / name
        path.write_text(content)
        path.chmod(0o600)
    plan = root / ".barragan-edge-append.tfplan"
    plan.write_bytes(b"partial plan")
    plan.chmod(0o600)
    stage = root / ".barragan-append-inputs-abcdefgh"
    stage.mkdir(mode=0o700)
    (stage / "credential.json").write_text("secret")
    (stage / "credential.json").chmod(0o600)
    child = jobs.start_if_queued(child, started_at=datetime.now(timezone.utc).isoformat(),
        event=JobEvent(2, "info", "provider append plan preflight started", {}))
    assert child is not None
    now = datetime.now(timezone.utc)
    jobs.claim_lease(parent.id, owner="provider_keyed_append_plan", token="worker",
        claimed_at=now.isoformat(), expires_at=(now.replace(year=now.year + 1)).isoformat(),
        eligible_statuses={"running"}, eligible_phases={"planning"})
    def discard_state():
        return _append_failed_review_discard_state(
            jobs.get(parent.id), jobs.get(child.id),
            jobs.list_for_engagement(parent.target_id), jobs,
            lease=state["lease"], now=datetime.now(timezone.utc))
    assert discard_state() == ""
    cleanup = dict(job_repository=jobs, plan_repository=kwargs["plan_repository"],
        sketch_repository=kwargs["sketch_repository"], lease_lookup=kwargs["lease_lookup"],
        ssh_key_repository=SimpleNamespace())
    monkeypatch.setattr("app.services.provider_keyed_append_plan_job.retrieve_sketch_ssh_key",
        lambda *_a: SimpleNamespace(private_key="PRIVATE", public_key="PUBLIC"))
    with pytest.raises(ProviderKeyedAppendPlanJobError, match="still be running"):
        reconcile_interrupted_digitalocean_edge_append_plan(parent.id, **cleanup)
    assert plan.exists() and jobs.get(child.id).status == "running"
    jobs.save(replace(jobs.get(parent.id), input={**jobs.get(parent.id).input,
        "claimExpiresAt": (now.replace(year=now.year - 1)).isoformat()}))
    assert discard_state() == ""
    assert hashlib.sha256((root / "terraform.tfstate").read_bytes()).hexdigest() == parent.input["initialSource"]["state_sha256"]
    (material / "admin-public").write_text("TAMPERED")
    with pytest.raises(ProviderKeyedAppendPlanJobError, match="key residue differs"):
        reconcile_interrupted_digitalocean_edge_append_plan(parent.id, **cleanup)
    assert plan.exists() and state["lease"] is not None
    (material / "admin-public").write_text("PUBLIC")
    plans = kwargs["plan_repository"]
    close = plans.close_unapplied_provider_keyed_append_plan
    plans.close_unapplied_provider_keyed_append_plan = lambda *_a, **_k: (_ for _ in ()).throw(
        RuntimeError("simulated restart"))
    with pytest.raises(RuntimeError, match="simulated restart"):
        reconcile_interrupted_digitalocean_edge_append_plan(parent.id, **cleanup)
    assert jobs.get(child.id).status == "failed" and not plan.exists() and not stage.exists()
    assert jobs.get(parent.id).status == "running" and state["lease"] is not None
    assert discard_state() == "waiting"
    jobs.save(replace(jobs.get(parent.id), input={**jobs.get(parent.id).input,
        "claimExpiresAt": (now.replace(year=now.year - 1)).isoformat()}))
    assert discard_state() == "ready"
    plans.close_unapplied_provider_keyed_append_plan = close
    closed = reconcile_interrupted_digitalocean_edge_append_plan(parent.id, **cleanup)
    assert closed.status == "failed" and closed.input["phase"] == "unapplied_reconciled"
    assert state["lease"] is None
