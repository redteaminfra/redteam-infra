# Copyright (c) 2026, Oracle and/or its affiliates.
"""A reviewed append remains inert until one durable authenticated Apply click."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_append_dispatch import (
    advance_approved_digitalocean_edge_append,
    recover_approved_digitalocean_edge_appends,
)
from app.services.provider_keyed_append_plan_job import (
    ProviderKeyedAppendPlanJobError,
    discard_reviewed_digitalocean_edge_append_plan,
)
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import (
    CoreMutationLeaseModel, DeploymentPlanModel, EngagementModel,
)


def test_sqlalchemy_approval_is_one_click_and_startup_only_resumes_approved(tmp_path, monkeypatch):
    state = db.configure(f"sqlite:///{tmp_path / 'append-click.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(
            id="eng-a", name="opaque", status="deployed", owner="alice",
            template_id="dev", input_parameters={}, sketch_state_schema="provider-keyed-v2",
        ))
        db.session.add(DeploymentPlanModel(
            id="plan-a", engagement_id="eng-a", revision_id="rev-a", status="applied",
            stage="applied", review={}, evidence={}, is_current=False,
            apply_job_id="job-core", error="",
        ))
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-a", owner_id="plan-a",
            operation="provider_keyed_edge_append",
        ))
        db.session.commit()
        now = datetime.now(timezone.utc).isoformat()
        jobs = SqlAlchemyJobRepository()
        plan = jobs.save(StoredJobRun(
            "job-plan", "provider_keyed_edge_append_plan", "succeeded",
            "engagement:eng-a", "engagement", "eng-a", "alice",
            {"parentJobId": "job-append", "mutation": False}, [], now, now, now,
            [JobEvent(1, "info", "reviewed append plan saved", {
                "planSha256": "a" * 64,
            })],
        ))
        parent = jobs.save(StoredJobRun(
            "job-append", "provider_keyed_edge_append", "running",
            "engagement:eng-a", "engagement", "eng-a", "alice",
            {"engagementId": "eng-a", "corePlanId": "plan-a", "coreJobId": "job-core",
             "chainId": "chain-a", "planJobId": plan.id, "phase": "awaiting_apply",
             "planJournalSha256": job_event_digest(plan.events)},
            [], now, now, None,
            [JobEvent(1, "info", "provider append plan ready for review", {
                "planJobId": plan.id, "planSha256": "a" * 64,
            })],
        ))
        scheduled = []
        assert recover_approved_digitalocean_edge_appends(
            environment="devtest", rollout_enabled=True, schedule=scheduled.append,
            job_repository=jobs) == []
        # A discard writer claiming first prevents the click from overwriting it.
        claimed = jobs.claim_lease(parent.id, owner="provider_keyed_append_discard",
            token="discard-claim", claimed_at=now,
            expires_at=(datetime.fromisoformat(now) + timedelta(minutes=5)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"awaiting_apply"})
        assert claimed is not None
        assert jobs.approve_provider_keyed_edge_append_apply(
            parent, plan, plan_sha256="a" * 64,
            requested_by="bob", requested_at=now) is None
        parent = jobs.save_if_leased(replace(claimed, input={
            key: value for key, value in claimed.input.items()
            if not key.startswith("claim")}),
            owner="provider_keyed_append_discard", token="discard-claim")
        assert parent is not None
        assert jobs.approve_provider_keyed_edge_append_apply(
            parent, plan, plan_sha256="b" * 64,
            requested_by="bob", requested_at=now) is None
        approved = jobs.approve_provider_keyed_edge_append_apply(
            parent, plan, plan_sha256="a" * 64,
            requested_by="bob", requested_at=now)
        assert approved is not None
        assert approved.requested_by == "alice"  # Retained plan actor.
        assert approved.input["applyRequestedBy"] == "bob"
        assert approved.events[-1].message == "provider append Apply requested"
        assert approved.events[-1].data["requestedBy"] == "bob"
        assert jobs.approve_provider_keyed_edge_append_apply(
            parent, plan, plan_sha256="a" * 64,
            requested_by="bob", requested_at=now) is None
        assert recover_approved_digitalocean_edge_appends(
            environment="devtest", rollout_enabled=True, schedule=scheduled.append,
            job_repository=jobs) == [parent.id]
        assert len(scheduled) == 1
        with pytest.raises(ProviderKeyedAppendPlanJobError, match="cannot be discarded"):
            discard_reviewed_digitalocean_edge_append_plan(
                parent.id, job_repository=jobs)
        pin = {"root": str(tmp_path), "revision": "pinned"}
        jobs.save(StoredJobRun(
            "job-core", "pilot_standard_rti_guarded_execute", "succeeded",
            "engagement:eng-a", "engagement", "eng-a", "alice",
            {"engagementId": "eng-a", "providerKeyedSourcePin": pin},
            [], now, now, now, [],
        ))
        monkeypatch.setattr(
            "app.services.guarded_test_deployment._require_configured_keyed_source",
            lambda expected: expected,
        )
        calls = []
        def apply(parent_id, **_kw):
            calls.append(("apply", parent_id))
            current = jobs.get(parent_id)
            assert current.input["applyRequestedBy"] == "bob"
            return jobs.save(replace(current, input={
                **current.input, "phase": "awaiting_host_proof",
            }))
        def prove(parent_id, **kw):
            calls.append(("proof", parent_id))
            assert kw["bootstrap_env"]["BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT"] == str(tmp_path)
            current = jobs.get(parent_id)
            return jobs.save(replace(current, status="succeeded", finished_at=now,
                                     input={**current.input, "phase": "completed"}))
        # A started or uncertain child is never routed back through Apply.
        reserved = jobs.save(replace(jobs.get(parent.id), input={
            **jobs.get(parent.id).input, "phase": "apply_reserved",
        }))
        with pytest.raises(ValueError, match="uncertain"):
            advance_approved_digitalocean_edge_append(
                parent.id, rollout_enabled=True, job_repository=jobs,
                reconcile_apply=lambda *_a, **_kw: (_ for _ in ()).throw(
                    ValueError("uncertain child")), apply=apply, prove=prove)
        assert calls == []
        jobs.save(replace(reserved, input={**reserved.input, "phase": "awaiting_apply"}))
        completed = advance_approved_digitalocean_edge_append(
            parent.id, rollout_enabled=True, job_repository=jobs,
            apply=apply, prove=prove)
        assert completed.status == "succeeded"
        assert calls == [("apply", parent.id), ("proof", parent.id)]
        assert advance_approved_digitalocean_edge_append(
            parent.id, rollout_enabled=True, job_repository=jobs,
            apply=apply, prove=prove).status == "succeeded"
        assert len(calls) == 2
