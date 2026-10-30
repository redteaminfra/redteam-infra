# Copyright (c) 2026, Oracle and/or its affiliates.
"""A queued Apply child is fenced before the append lease can be released."""

from dataclasses import replace
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from contextlib import nullcontext
import hashlib
import json
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.storage.database import db
from app.storage.deployment_plan_repository import (
    DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository,
)
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel
from app.services.provider_keyed_teardown_scope import (
    _exact_no_go_apply_child, _reconciled_unapplied_append_state_sha,
)
from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_append_plan_job import (
    ProviderKeyedAppendPlanJobError, reconcile_no_go_digitalocean_edge_append_apply,
)


def _job(id, action, status, input, events, *, now, started=None, finished=None):
    return StoredJobRun(id, action, status, "engagement:eng-a", "engagement", "eng-a",
                        "operator", input, [], now, started, finished, events)


def _case(tmp_path, *, expiry_delta=-60):
    state = db.configure(f"sqlite:///{tmp_path / 'no-go.sqlite'}")
    binding = db.bind(state)
    binding.__enter__()
    db.create_all()
    db.session.add(EngagementModel(id="eng-a", name="opaque", status="deployed",
        owner="operator", template_id="dev", input_parameters={},
        sketch_state_schema="provider-keyed-v2"))
    db.session.add(DeploymentPlanModel(id="plan-core", engagement_id="eng-a",
        revision_id="rev-a", status="applied", stage="applied", review={},
        evidence={}, is_current=False, apply_job_id="job-core", error=""))
    db.session.add(CoreMutationLeaseModel(engagement_id="eng-a",
        owner_id="plan-core", operation="provider_keyed_edge_append"))
    db.session.commit()
    jobs = SqlAlchemyJobRepository()
    now = datetime.now(timezone.utc).isoformat()
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=expiry_delta)).isoformat()
    sha = "a" * 64
    plan = jobs.save(_job("job-plan", "provider_keyed_edge_append_plan", "succeeded",
        {"engagementId": "eng-a", "parentJobId": "job-provider-keyed-append-case",
         "coreJobId": "job-core", "mutation": False},
        [JobEvent(1, "info", "reviewed append plan saved", {
            "stateSha256": sha, "planSha256": "b" * 64})],
        now=now, started=now, finished=now))
    parent_id = "job-provider-keyed-append-case"
    digest = job_event_digest(plan.events)
    parent = jobs.save(_job(parent_id, "provider_keyed_edge_append", "failed", {
        "engagementId": "eng-a", "coreJobId": "job-core", "corePlanId": "plan-core",
        "planJobId": plan.id, "applyJobId": "job-provider-keyed-append-apply-case",
        "planJournalSha256": digest, "applyReservationId": "c" * 32,
        "phase": "attention", "claimExpiresAt": expiry,
    }, [JobEvent(1, "info", "provider append Apply reserved", {
        "planJournalSha256": digest, "reservationId": "c" * 32}),
        JobEvent(2, "error", "provider append Apply stopped; reconciliation required", {})],
        now=now, started=now, finished=now))
    child = jobs.save(_job("job-provider-keyed-append-apply-case",
        "provider_keyed_edge_append_apply", "queued", {
            "engagementId": "eng-a", "parentJobId": parent_id, "coreJobId": "job-core",
            "corePlanId": "plan-core", "planJobId": plan.id, "mutation": True,
        }, [JobEvent(1, "info", "provider append Apply child reserved", {
            "planJournalSha256": digest, "reservationId": "c" * 32})], now=now))
    return binding, jobs, SqlAlchemyDeploymentPlanRepository(), parent, plan, child, sha


@pytest.mark.parametrize("change", ["exact", "started", "foreign_child", "wrong_phase"])
def test_historical_failed_review_allows_only_exact_active_no_go_child(tmp_path, change):
    binding, jobs, _plans, parent, _plan, child, sha = _case(tmp_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        old = jobs.save(_job("job-provider-keyed-append-plan-old",
            "provider_keyed_edge_append_plan", "failed", {
                "engagementId": "eng-a", "parentJobId": "job-provider-keyed-append-old",
                "coreJobId": "job-core", "mutation": False,
            }, [JobEvent(1, "error", "provider append plan preparation failed", {})],
            now=now, started=now, finished=now))
        jobs.save(_job("job-provider-keyed-append-old", "provider_keyed_edge_append",
            "failed", {"engagementId": "eng-a", "coreJobId": "job-core",
                       "corePlanId": "plan-core", "planJobId": old.id,
                       "phase": "unapplied_reconciled"},
            [JobEvent(1, "info", "append plan reconciled without mutation",
                      {"stateSha256": sha})],
            now=now, started=now, finished=now))
        if change == "started":
            jobs.save(replace(child, started_at=now))
        elif change == "foreign_child":
            jobs.save(replace(child, input={**child.input, "parentJobId": "foreign"}))
        elif change == "wrong_phase":
            jobs.save(replace(parent, input={**parent.input, "phase": "running"}))
        actual = _reconciled_unapplied_append_state_sha(
            "eng-a", jobs, allowed_active_parent_id=parent.id,
            expected_core_job_id="job-core", expected_core_plan_id="plan-core")
        assert actual == sha if change == "exact" else actual is None
    finally:
        binding.__exit__(None, None, None)


def test_no_go_two_stage_atomic_close_and_history(tmp_path):
    binding, jobs, plans, parent, plan, child, sha = _case(tmp_path)
    try:
        assert _exact_no_go_apply_child(parent, jobs.list_for_engagement("eng-a"), jobs) == child
        fenced = plans.fence_no_go_provider_keyed_append_apply(
            parent, plan, child, state_sha256=sha)
        stopped = jobs.get(child.id)
        assert stopped.status == "failed" and stopped.started_at is None
        assert stopped.events[-1].message == "provider append Apply never started"
        assert fenced.input["phase"] == "no_go_cleaning"
        assert db.session.get(CoreMutationLeaseModel, "eng-a") is not None
        assert jobs.start_if_queued(child, started_at=datetime.now(timezone.utc).isoformat(),
                                   event=JobEvent(2, "info", "start", {})) is None
        # A fresh repository after a process restart can finish the same fence.
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        fenced, stopped, plan = jobs.get(parent.id), jobs.get(child.id), jobs.get(plan.id)
        closed = plans.close_no_go_provider_keyed_append_apply(
            fenced, plan, stopped, state_sha256=sha)
        assert closed.input["phase"] == "unapplied_reconciled"
        assert db.session.get(CoreMutationLeaseModel, "eng-a") is None
        assert _reconciled_unapplied_append_state_sha("eng-a", jobs,
            expected_core_job_id="job-core", expected_core_plan_id="plan-core") == sha
        with pytest.raises(DeploymentPlanConflictError):
            plans.close_no_go_provider_keyed_append_apply(fenced, plan, stopped,
                                                           state_sha256=sha)
    finally:
        binding.__exit__(None, None, None)


def test_historical_no_go_remains_valid_after_later_published_append(tmp_path):
    binding, jobs, plans, parent, plan, child, sha = _case(tmp_path)
    try:
        fenced = plans.fence_no_go_provider_keyed_append_apply(
            parent, plan, child, state_sha256=sha)
        plans.close_no_go_provider_keyed_append_apply(
            fenced, plan, jobs.get(child.id), state_sha256=sha)
        now = datetime.now(timezone.utc).isoformat()
        published_id = "job-append-published"
        published = jobs.save(_job(published_id, "provider_keyed_edge_append", "succeeded", {
            "engagementId": "eng-a", "coreJobId": "job-core", "corePlanId": "plan-core",
            "planJobId": "job-plan-published", "applyJobId": "job-apply-published",
            "hostProofJobId": "job-proof-published", "phase": "published",
        }, [JobEvent(1, "info", "published", {})], now=now, started=now,
            finished=now))
        jobs.save(_job("job-plan-published", "provider_keyed_edge_append_plan",
            "succeeded", {"engagementId": "eng-a", "parentJobId": published_id,
                          "coreJobId": "job-core", "mutation": False},
            [JobEvent(1, "info", "reviewed append plan saved", {})],
            now=now, started=now, finished=now))
        for job_id, action in (("job-apply-published", "provider_keyed_edge_append_apply"),
                               ("job-proof-published", "provider_keyed_edge_append_host_proof")):
            jobs.save(_job(job_id, action, "succeeded", {
                "engagementId": "eng-a", "parentJobId": published_id,
                "coreJobId": "job-core", "mutation": action.endswith("_apply"),
            }, [JobEvent(1, "info", "completed", {})],
                now=now, started=now, finished=now))
        assert _reconciled_unapplied_append_state_sha(
            "eng-a", jobs, allowed_published_parent_id=published.id,
            expected_core_job_id="job-core", expected_core_plan_id="plan-core") == sha
        jobs.save(_job("job-foreign-apply", "provider_keyed_edge_append_apply",
            "succeeded", {"engagementId": "eng-a", "parentJobId": "foreign"},
            [JobEvent(1, "info", "foreign", {})], now=now,
            started=now, finished=now))
        assert _reconciled_unapplied_append_state_sha(
            "eng-a", jobs, allowed_published_parent_id=published.id,
            expected_core_job_id="job-core", expected_core_plan_id="plan-core") is None
    finally:
        binding.__exit__(None, None, None)


@pytest.mark.parametrize("foreign_apply", [False, True])
def test_sqlite_close_after_historical_no_go_apply_is_exact(tmp_path, foreign_apply):
    binding, jobs, plans, parent, plan, child, sha = _case(tmp_path)
    try:
        fenced = plans.fence_no_go_provider_keyed_append_apply(
            parent, plan, child, state_sha256=sha)
        plans.close_no_go_provider_keyed_append_apply(
            fenced, plan, jobs.get(child.id), state_sha256=sha)
        db.session.add(CoreMutationLeaseModel(engagement_id="eng-a",
            owner_id="plan-core", operation="provider_keyed_edge_append"))
        db.session.commit()
        now = datetime.now(timezone.utc).isoformat()
        new_plan = jobs.save(_job("job-plan-next", "provider_keyed_edge_append_plan",
            "failed", {"engagementId": "eng-a", "parentJobId": "job-append-next",
                       "coreJobId": "job-core", "mutation": False},
            [JobEvent(1, "info", "provider append plan queued", {}),
             JobEvent(2, "error", "append plan worker was not scheduled", {})],
            now=now, finished=now))
        new_parent = jobs.save(_job("job-append-next", "provider_keyed_edge_append",
            "running", {"engagementId": "eng-a", "coreJobId": "job-core",
                        "corePlanId": "plan-core", "planJobId": new_plan.id,
                        "initialSource": {"state_sha256": sha}, "phase": "planning"},
            [JobEvent(1, "info", "provider append review reserved", {})],
            now=now, started=now))
        if foreign_apply:
            jobs.save(_job("job-foreign-apply", "provider_keyed_edge_append_apply",
                "queued", {"engagementId": "eng-a", "parentJobId": "foreign"},
                [JobEvent(1, "info", "foreign", {})], now=now))
            with pytest.raises(DeploymentPlanConflictError):
                plans.close_unapplied_provider_keyed_append_plan(
                    new_parent, new_plan, state_sha256=sha)
            assert db.session.get(CoreMutationLeaseModel, "eng-a") is not None
            assert jobs.get(new_parent.id).status == "running"
        else:
            closed = plans.close_unapplied_provider_keyed_append_plan(
                new_parent, new_plan, state_sha256=sha)
            assert closed.input["phase"] == "unapplied_reconciled"
            assert db.session.get(CoreMutationLeaseModel, "eng-a") is None
    finally:
        binding.__exit__(None, None, None)


@pytest.mark.parametrize("foreign_apply", [False, True])
def test_sqlite_apply_approval_after_historical_no_go_is_exact(tmp_path, foreign_apply):
    binding, jobs, plans, parent, plan, child, sha = _case(tmp_path)
    try:
        fenced = plans.fence_no_go_provider_keyed_append_apply(
            parent, plan, child, state_sha256=sha)
        plans.close_no_go_provider_keyed_append_apply(
            fenced, plan, jobs.get(child.id), state_sha256=sha)
        db.session.add(CoreMutationLeaseModel(engagement_id="eng-a",
            owner_id="plan-core", operation="provider_keyed_edge_append"))
        db.session.commit()
        now = datetime.now(timezone.utc).isoformat()
        saved_hash = "d" * 64
        next_plan = jobs.save(_job("job-plan-next", "provider_keyed_edge_append_plan",
            "succeeded", {"engagementId": "eng-a", "parentJobId": "job-append-next",
                          "coreJobId": "job-core", "mutation": False},
            [JobEvent(1, "info", "reviewed append plan saved",
                      {"planSha256": saved_hash})],
            now=now, started=now, finished=now))
        next_parent = jobs.save(_job("job-append-next", "provider_keyed_edge_append",
            "running", {"engagementId": "eng-a", "coreJobId": "job-core",
                        "corePlanId": "plan-core", "planJobId": next_plan.id,
                        "initialSource": {"state_sha256": sha},
                        "planJournalSha256": job_event_digest(next_plan.events),
                        "phase": "awaiting_apply"},
            [JobEvent(1, "info", "provider append plan ready for review",
                      {"planJobId": next_plan.id, "planSha256": saved_hash})],
            now=now, started=now))
        if foreign_apply:
            jobs.save(_job("job-foreign-apply", "provider_keyed_edge_append_apply",
                "queued", {"engagementId": "eng-a", "parentJobId": "foreign"},
                [JobEvent(1, "info", "foreign", {})], now=now))
        approved = jobs.approve_provider_keyed_edge_append_apply(
            next_parent, next_plan, plan_sha256=saved_hash,
            requested_by="operator", requested_at=now)
        if foreign_apply:
            assert approved is None
            assert jobs.get(next_parent.id) == next_parent
        else:
            assert approved is not None
            assert approved.input["applyRequestedPlanSha256"] == saved_hash
            assert [event.message for event in approved.events].count(
                "provider append Apply requested") == 1
            assert jobs.approve_provider_keyed_edge_append_apply(
                next_parent, next_plan, plan_sha256=saved_hash,
                requested_by="operator", requested_at=now) is None
    finally:
        binding.__exit__(None, None, None)


@pytest.mark.parametrize("change", [
    "extra_event", "foreign_input", "live_claim", "wrong_state", "forged_receipt",
])
def test_no_go_fence_rejects_unsafe_history(tmp_path, change):
    binding, jobs, plans, parent, plan, child, sha = _case(tmp_path,
        expiry_delta=60 if change == "live_claim" else -60)
    try:
        if change == "extra_event":
            child = jobs.save(replace(child, events=[*child.events,
                JobEvent(2, "info", "provider append command intent fenced", {})]))
        elif change == "foreign_input":
            child = jobs.save(replace(child, input={**child.input, "parentJobId": "foreign"}))
        elif change == "forged_receipt":
            child = jobs.save(replace(child, events=[JobEvent(1, "info",
                "provider append Apply child reserved", {
                    "planJournalSha256": "f" * 64, "reservationId": "c" * 32,
                })]))
        with pytest.raises(DeploymentPlanConflictError):
            plans.fence_no_go_provider_keyed_append_apply(parent, plan, child,
                state_sha256="f" * 64 if change == "wrong_state" else sha)
        assert db.session.get(CoreMutationLeaseModel, "eng-a") is not None
        assert jobs.get(parent.id).input["phase"] == "attention"
    finally:
        binding.__exit__(None, None, None)


@pytest.mark.parametrize("restart_state", ["complete", "partially_removed", "state_changed"])
def test_no_go_cleaning_resumes_after_restart_with_verified_artifacts(
        tmp_path, monkeypatch, restart_state):
    binding, jobs, plans, parent, plan, child, sha = _case(tmp_path)
    try:
        root = tmp_path / "state" / "provider-keyed-v2" / "digitalocean" / "connection"
        root.mkdir(parents=True)
        material = root.parents[1] / ".plan-material" / "digitalocean"
        material.mkdir(parents=True)
        plan_path = root / ".barragan-edge-append.tfplan"
        varfile = material / "append-inputs.json"
        plan_path.write_bytes(b"owned saved plan")
        varfile.write_bytes(b"owned reviewed inputs")
        plan_path.chmod(0o600)
        varfile.chmod(0o600)
        (root / "terraform.tfstate").write_bytes(b"original state")
        (root / ".barragan-apply-phase.json").write_text(json.dumps({"phase": "applied"}))
        source = PublishedProviderKeyedSource(
            "eng-a", "job-core", "plan-core", "job-initial",
            "1" * 64, "2" * 64, "3" * 64, sha, "4" * 64,
            "5" * 64, ("chain-a", "chain-b"), "6" * 64,
        )
        plan = jobs.save(replace(plan, events=[JobEvent(1, "info",
            "reviewed append plan saved", {
                "stateSha256": sha,
                "planSha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
                "planPath": str(plan_path),
                "inputSha256": [[str(varfile), hashlib.sha256(varfile.read_bytes()).hexdigest()]],
            })]))
        digest = job_event_digest(plan.events)
        requested_at = datetime.now(timezone.utc).isoformat()
        parent = jobs.save(replace(parent, input={**parent.input,
            "chainId": "chain-a", "initialSource": json.loads(json.dumps(asdict(source))),
            "initialSourceSha256": _fingerprint(asdict(source)),
            "planJournalSha256": digest,
            "applyRequestedPlanSha256": plan.events[-1].data["planSha256"],
            "applyRequestedBy": "operator", "applyRequestedAt": requested_at,
        }, events=[
            JobEvent(1, "info", "provider append Apply requested", {
                "planJobId": plan.id, "planSha256": plan.events[-1].data["planSha256"],
                "requestedBy": "operator", "requestedAt": requested_at}),
            JobEvent(2, "info", "provider append Apply reserved", {
                "planJournalSha256": digest, "reservationId": "c" * 32}),
            JobEvent(3, "error", "provider append Apply stopped; reconciliation required", {}),
        ]))
        child = jobs.save(replace(child, events=[JobEvent(1, "info",
            "provider append Apply child reserved", {
                "planJournalSha256": digest, "reservationId": "c" * 32,
            })]))
        fenced = plans.fence_no_go_provider_keyed_append_apply(
            parent, plan, child, state_sha256=sha)
        assert fenced.input["phase"] == "no_go_cleaning"
        if restart_state == "partially_removed":
            plan_path.unlink()
        if restart_state == "state_changed":
            (root / "terraform.tfstate").write_bytes(b"changed state")
        # Simulate a process restart after the child was fenced but before close.
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        chain = SimpleNamespace(chain_id="chain-a", terraform_working_directory=str(root))
        chains = SimpleNamespace(get=lambda eng, cid: chain if (eng, cid) ==
                                 ("eng-a", "chain-a") else None)
        monkeypatch.setattr("app.services.provider_keyed_append_plan_job._append_cleanup_locks",
                            lambda _root: nullcontext())
        monkeypatch.setattr("app.services.provider_keyed_append_plan_job.audit_published_provider_keyed_source",
                            lambda *_args, **_kwargs: source)
        monkeypatch.setattr("app.services.provider_keyed_append_plan_job._hash_file",
            lambda path: sha if path == root / "terraform.tfstate"
                and path.read_bytes() == b"original state" else
                hashlib.sha256(path.read_bytes()).hexdigest())
        def resume():
            return reconcile_no_go_digitalocean_edge_append_apply(
                parent.id, state_root=tmp_path / "state", job_repository=jobs,
                plan_repository=plans, sketch_repository=chains,
                lease_lookup=lambda _eng: ("plan-core", "provider_keyed_edge_append")
                    if db.session.get(CoreMutationLeaseModel, "eng-a") else None)
        if restart_state == "state_changed":
            with pytest.raises(ProviderKeyedAppendPlanJobError):
                resume()
            assert db.session.get(CoreMutationLeaseModel, "eng-a") is not None
            assert plan_path.exists() and varfile.exists()
            return
        result = resume()
        assert result.input["phase"] == "unapplied_reconciled"
        assert db.session.get(CoreMutationLeaseModel, "eng-a") is None
        assert not plan_path.exists() and not varfile.exists()
        assert jobs.get(child.id).started_at is None
    finally:
        binding.__exit__(None, None, None)
