# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant initial continuation uses reviewed identities and never replays apply."""

from dataclasses import replace
from pathlib import Path
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.domain.deployment_plan import DeploymentPlan
from app.integrations.oci_deployment_targets import BARRAGAN_TESTING_TARGET
from app.services import provider_keyed_initial_continuation as service
from app.services.provider_keyed_digitalocean_attachment import DigitalOceanAttachmentStillSettling
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun


class Jobs:
    def __init__(self, core):
        self.rows = {core.id: core}
        self.calls = []

    def get(self, job_id):
        return self.rows.get(job_id)

    def save_if_absent(self, job):
        self.calls.append(("save_if_absent", job.id))
        self.rows.setdefault(job.id, job)
        return self.rows[job.id]

    def claim_lease(self, job_id, *, owner, token, claimed_at, expires_at, eligible_statuses):
        current = self.rows[job_id]
        if current.status not in eligible_statuses or current.input.get("claimToken"):
            return None
        claimed = replace(current, input={**current.input, "claimOwner": owner,
                                          "claimToken": token, "claimExpiresAt": expires_at})
        self.rows[job_id] = claimed
        return claimed

    def renew_lease(self, job_id, *, owner, token, heartbeat_at, expires_at):
        current = self.rows[job_id]
        if current.input.get("claimOwner") != owner or current.input.get("claimToken") != token:
            return None
        return current

    def save_if_leased(self, job, *, owner, token):
        current = self.rows[job.id]
        if current.input.get("claimOwner") != owner or current.input.get("claimToken") != token:
            return None
        self.calls.append(("phase", job.input["phase"]))
        self.rows[job.id] = job
        return job


def _core(*, schema="provider-keyed-v2", eligible=False):
    return StoredJobRun(
        id="job-core-opaque", action=service.CORE_ACTION, status="succeeded",
        target=f"oci-compartment:{BARRAGAN_TESTING_TARGET.name}", target_type="oci_compartment",
        target_id=BARRAGAN_TESTING_TARGET.compartment_id,
        requested_by="operator", input={
            "engagementId": "eng-opaque", "corePlanId": "plan-opaque",
            "sketchStateSchema": schema, "postCoreSketchContinuationEligible": eligible,
            "pendingSketchChainIds": ["chain-a", "chain-b"],
            "pendingSketchChainFingerprints": {"chain-a": "a" * 64, "chain-b": "b" * 64},
        }, artifact_refs=[], created_at="2026-10-07T00:00:00+00:00",
        started_at="2026-10-07T00:00:01+00:00", finished_at="2026-10-07T00:01:00+00:00",
        events=[JobEvent(1, "info", "core completed", {})],
    )


def _inputs(core):
    engagement = SimpleNamespace(
        id="eng-opaque", sketch_state_schema=core.input["sketchStateSchema"],
        input_parameters={"deploymentTarget": BARRAGAN_TESTING_TARGET.name},
    )
    plan = SimpleNamespace(
        id="plan-opaque", engagement_id="eng-opaque", status="applied", apply_job_id=core.id,
        evidence={"sketchStateSchema": core.input["sketchStateSchema"],
                  "pendingSketchChainIds": core.input["pendingSketchChainIds"],
                  "pendingSketchChainFingerprints": core.input["pendingSketchChainFingerprints"]},
    )
    return SimpleNamespace(get=lambda _id: engagement), SimpleNamespace(get=lambda _id: plan)


def _run(core, jobs, *, plan_runner, preflight, apply_runner, lease_lookup=None,
         attachment_intent_builder=None, attachment_reconciler=None):
    engagement_repo, plan_repo = _inputs(core)
    attachment = SimpleNamespace(state_sha256="a" * 64, firewall_id="firewall-opaque",
                                 nodes=(SimpleNamespace(droplet_id="101"),))
    evidence = SimpleNamespace(provider_membership_verified=True, host_policy_verified=False,
                               state_sha256=attachment.state_sha256, firewall_id=attachment.firewall_id,
                               verified_droplet_ids=("101",), attempts=2)
    return service.start_fresh_digitalocean_initial_continuation(
        core.id, environment="devtest", state_root=Path("/tmp/state"), template_root=Path("/tmp/upstream"),
        job_repository=jobs, engagement_repository=engagement_repo, plan_repository=plan_repo,
        lease_lookup=lease_lookup or (lambda _id: ("plan-opaque", "provider_keyed_initial")),
        plan_runner=plan_runner, planned_preflight=preflight, apply_runner=apply_runner,
        attachment_intent_builder=attachment_intent_builder or (lambda *_args: attachment),
        attachment_reconciler=attachment_reconciler or (lambda *_args, **_kwargs: evidence),
    )


def test_real_shape_v2_core_plans_and_applies_once_with_preflight_before_apply_row():
    core = _core(eligible=False)
    jobs = Jobs(core)
    calls = []

    def plan(job_id, **kwargs):
        calls.append("plan")
        assert kwargs["lease_owner"] == "plan-opaque"
        assert jobs.get(job_id).input == {"engagementId": "eng-opaque", "coreJobId": core.id, "mutation": False}
        result = replace(jobs.get(job_id), status="succeeded", finished_at="2026-10-07T00:02:00+00:00")
        jobs.rows[job_id] = result
        return result

    def preflight(engagement_id, core_id, plan_id, **kwargs):
        calls.append("preflight")
        assert (engagement_id, core_id, plan_id) == ("eng-opaque", core.id, service._job_ids(core.id)[1])
        assert kwargs["lease_owner"] == "plan-opaque"
        assert jobs.get(service._job_ids(core.id)[2]) is None
        return (SimpleNamespace(), SimpleNamespace(), {})

    def apply(job_id, **kwargs):
        calls.append("apply")
        assert jobs.get(job_id).input == {
            "engagementId": "eng-opaque", "coreJobId": core.id, "corePlanId": "plan-opaque",
            "planJobId": service._job_ids(core.id)[1], "mutation": True,
        }
        result = replace(jobs.get(job_id), status="succeeded", finished_at="2026-10-07T00:03:00+00:00")
        jobs.rows[job_id] = result
        return result

    def attachment_reconciler(*_args, **kwargs):
        calls.append("attachment")
        assert kwargs["max_attempts"] == 12
        return SimpleNamespace(provider_membership_verified=True, host_policy_verified=False,
                               state_sha256="a" * 64, firewall_id="firewall-opaque",
                               verified_droplet_ids=("101",), attempts=2)

    result = _run(core, jobs, plan_runner=plan, preflight=preflight, apply_runner=apply,
                  attachment_reconciler=attachment_reconciler)
    assert calls == ["plan", "preflight", "apply", "attachment"]
    assert result.status == "running"
    assert result.input["phase"] == "awaiting_host_proof"
    assert datetime.fromisoformat(result.input["claimExpiresAt"]) <= datetime.now(timezone.utc)
    assert result.events[-1].data["providerMembershipVerified"] is True
    assert result.events[-1].data["hostProofPending"] is True
    assert result.finished_at is None
    assert result.input["planJobId"] == service._job_ids(core.id)[1]
    assert result.input["applyJobId"] == service._job_ids(core.id)[2]
    assert _run(core, jobs, plan_runner=plan, preflight=preflight, apply_runner=apply,
                attachment_reconciler=attachment_reconciler) == result
    assert calls == ["plan", "preflight", "apply", "attachment"]


def test_awaiting_host_proof_handoff_is_immediately_claimable_by_new_owner(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "handoff.sqlite")
    core = _core()
    parent_id, plan_id, apply_id = service._job_ids(core.id)
    parent = service._new_job(
        parent_id, service.ACTION, core, "eng-opaque",
        {"engagementId": "eng-opaque", "coreJobId": core.id, "corePlanId": "plan-opaque",
         "planJobId": plan_id, "applyJobId": apply_id, "phase": "queued", "mutation": True},
    )
    jobs.save(parent)
    claimed = jobs.claim_lease(
        parent_id, owner=service._CLAIM_OWNER, token="first-token",
        claimed_at=service._now(), expires_at=service._expiry(service._now()),
        eligible_statuses={"queued"},
    )
    assert claimed is not None
    advanced = service._advance(jobs, claimed, "first-token", "awaiting_host_proof", "proof complete")
    assert advanced.input["claimExpiresAt"] <= service._now()
    successor = jobs.claim_lease(
        parent_id, owner="host-binder", token="second-token", claimed_at=service._now(),
        expires_at=service._expiry(service._now()), eligible_statuses={"running"},
        eligible_phases={"awaiting_host_proof"},
    )
    assert successor is not None and successor.input["claimToken"] == "second-token"
    assert jobs.save_if_leased(advanced, owner=service._CLAIM_OWNER, token="first-token") is None


@pytest.mark.parametrize("failure", ["plan", "preflight", "apply"])
def test_child_failure_stops_with_redacted_attention_and_no_replay(failure):
    core = _core()
    jobs = Jobs(core)
    calls = []

    def plan(job_id, **kwargs):
        calls.append("plan")
        if failure == "plan":
            raise ValueError("secret provider detail")
        result = replace(jobs.get(job_id), status="succeeded")
        jobs.rows[job_id] = result
        return result

    def preflight(*args, **kwargs):
        calls.append("preflight")
        if failure == "preflight":
            raise ValueError("secret provider detail")
        return (SimpleNamespace(), SimpleNamespace(), {})

    def apply(job_id, **kwargs):
        calls.append("apply")
        raise ValueError("secret provider detail")

    result = _run(core, jobs, plan_runner=plan, preflight=preflight, apply_runner=apply)
    assert result.status == "failed" and result.input["phase"] == "attention"
    assert "secret provider detail" not in str(result.events)
    if failure != "apply":
        assert jobs.get(service._job_ids(core.id)[2]) is None
    assert _run(core, jobs, plan_runner=plan, preflight=preflight, apply_runner=apply) == result
    expected_calls = {"plan": ["plan"], "preflight": ["plan", "preflight"],
                      "apply": ["plan", "preflight", "apply"]}
    assert calls == expected_calls[failure]


@pytest.mark.parametrize("outcome", ["timeout", "mismatch"])
def test_attachment_settling_or_mismatch_never_replays_apply(outcome):
    core = _core()
    jobs = Jobs(core)
    calls = []

    def plan(job_id, **_kwargs):
        calls.append("plan")
        result = replace(jobs.get(job_id), status="succeeded")
        jobs.rows[job_id] = result
        return result

    def apply(job_id, **_kwargs):
        calls.append("apply")
        result = replace(jobs.get(job_id), status="succeeded")
        jobs.rows[job_id] = result
        return result

    def attachment(*_args, **_kwargs):
        calls.append("attachment")
        if outcome == "timeout":
            raise DigitalOceanAttachmentStillSettling("secret provider timeout detail")
        return SimpleNamespace(provider_membership_verified=False, host_policy_verified=False,
                               state_sha256="a" * 64, firewall_id="firewall-opaque",
                               verified_droplet_ids=("101",), attempts=12)

    kwargs = dict(plan_runner=plan, preflight=lambda *_a, **_kw: (object(), object(), {}),
                  apply_runner=apply, attachment_reconciler=attachment)
    result = _run(core, jobs, **kwargs)
    if outcome == "timeout":
        assert result.status == "running" and result.input["phase"] == "attachment_pending"
        assert result.events[-1].data == {"attachmentProofPending": True, "hostProofPending": True}
        assert result.finished_at is None
        assert result.input["attachmentRecheckCount"] == 0
        assert result.input["claimExpiresAt"] == result.input["nextAttachmentCheckAt"]
    else:
        assert result.status == "failed" and result.input["phase"] == "attention"
    assert "secret provider timeout detail" not in str(result.events)
    assert _run(core, jobs, **kwargs) == result
    assert calls == ["plan", "apply", "attachment"]


@pytest.mark.parametrize("case", ["wrong_lease", "v1", "snapshot_drift"])
def test_preclaim_rejects_lease_v1_and_reviewed_snapshot_drift(case):
    core = _core(schema="split-v1", eligible=True) if case == "v1" else _core()
    jobs = Jobs(core)
    engagement_repo, plan_repo = _inputs(core)
    if case == "snapshot_drift":
        plan_repo.get("plan-opaque").evidence["pendingSketchChainFingerprints"] = {"chain-a": "different"}
    with pytest.raises(service.ProviderKeyedInitialContinuationError):
        service.start_fresh_digitalocean_initial_continuation(
            core.id, environment="devtest", state_root=Path("/tmp/state"), template_root=Path("/tmp/upstream"),
            job_repository=jobs, engagement_repository=engagement_repo, plan_repository=plan_repo,
            lease_lookup=lambda _id: ("other-plan", "provider_keyed_initial") if case == "wrong_lease" else ("plan-opaque", "provider_keyed_initial"),
            plan_runner=lambda *_a, **_kw: pytest.fail("plan must not run"),
            planned_preflight=lambda *_a, **_kw: pytest.fail("preflight must not run"),
            apply_runner=lambda *_a, **_kw: pytest.fail("apply must not run"),
        )
    assert jobs.calls == []


def test_real_sqlalchemy_job_claim_progress_and_child_round_trip():
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        core = jobs.save(_core())
        plans = SqlAlchemyDeploymentPlanRepository()
        plans.save(DeploymentPlan(
            id="plan-opaque", engagement_id="eng-opaque", revision_id="revision-opaque",
            status="applied", stage="applied", apply_job_id=core.id,
            evidence={"sketchStateSchema": "provider-keyed-v2",
                      "pendingSketchChainIds": core.input["pendingSketchChainIds"],
                      "pendingSketchChainFingerprints": core.input["pendingSketchChainFingerprints"]},
        ))
        assert plans.get("plan-opaque").evidence["pendingSketchChainIds"] == ["chain-a", "chain-b"]
        parent = jobs.save_if_absent(service._new_job(
            service._job_ids(core.id)[0], service.ACTION, core, "eng-opaque",
            {"engagementId": "eng-opaque", "coreJobId": core.id, "corePlanId": "plan-opaque",
             "planJobId": service._job_ids(core.id)[1], "applyJobId": service._job_ids(core.id)[2],
             "phase": "queued", "mutation": True},
        ))
        now = service._now()
        claimed = jobs.claim_lease(parent.id, owner=service._CLAIM_OWNER, token="token", claimed_at=now,
                                   expires_at=service._expiry(now), eligible_statuses={"queued"})
        assert claimed is not None
        advanced = service._advance(jobs, claimed, "token", "planning", "plan started")
        assert jobs.get(parent.id) == advanced and advanced.input["phase"] == "planning"
        assert service._same_parent(advanced, core, "eng-opaque", "plan-opaque",
                                    service._job_ids(core.id)[1], service._job_ids(core.id)[2])
        assert jobs.claim_lease(parent.id, owner="other", token="other", claimed_at=now,
                                expires_at=service._expiry(now), eligible_statuses={"queued"}) is None
        child = service._new_job(service._job_ids(core.id)[1], service.PLAN_ACTION, core, "eng-opaque",
                                 {"engagementId": "eng-opaque", "coreJobId": core.id, "mutation": False})
        assert service._save_new_child(jobs, child) == jobs.get(child.id)
        with pytest.raises(service.ProviderKeyedInitialContinuationError, match="already has an audit record"):
            service._save_new_child(jobs, child)
