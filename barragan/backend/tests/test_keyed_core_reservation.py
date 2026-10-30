# Copyright (c) 2026, Oracle and/or its affiliates.
"""The internal v2 core worker cannot outrun its durable plan/job binding."""

from dataclasses import replace
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.domain import JobEvent
from app.domain.deployment_plan import DeploymentPlan
from app.integrations.oci_deployment_targets import BARRAGAN_TESTING_TARGET
from app.services.core_deployment_plans import recover_interrupted_core_deployment_plans
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
from app.services.provider_keyed_initial_dispatch import (
    ProviderKeyedInitialDispatchError, dispatch_fresh_keyed_initial,
    advance_fresh_keyed_initial_phases, recover_fresh_keyed_initial_dispatches, _recover_one,
)
from app.services.guarded_test_deployment import (
    GuardedDeploymentConfirmationError, _execute_guarded_pilot_standard_rti_run,
    start_guarded_pilot_standard_rti_run,
)
from app.services.jobs import get_job_run
from app.storage.database import db
from app.storage.deployment_plan_repository import DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import CoreMutationLeaseModel, EngagementModel, JobEventModel, JobRunModel


IDS = ["chain-one", "chain-two"]
FINGERPRINTS = {"chain-one": "a" * 64, "chain-two": "b" * 64}
TARGET = BARRAGAN_TESTING_TARGET


def _evidence():
    return {
        "sketchStateSchema": "provider-keyed-v2", "pendingSketchChainIds": IDS,
        "pendingSketchChainFingerprints": FINGERPRINTS,
        "sketchAuthorization": {"source": {"revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256}},
        "runDirectory": "/private/tmp/queued-keyed-core",
        "target": {"name": TARGET.name, "region": TARGET.region,
                   "compartmentId": TARGET.compartment_id, "auth": TARGET.auth},
    }


def _setup(engagement_id: str, plan_id: str):
    db.session.add(EngagementModel(
        id=engagement_id, name="Disposable", status="planned", owner="test",
        template_id="standard-rti", input_parameters={}, sketch_state_schema="provider-keyed-v2",
    ))
    db.session.commit()
    plans = SqlAlchemyDeploymentPlanRepository()
    plans.save(DeploymentPlan(
        plan_id, engagement_id, "revision", "applying", "terraform_apply",
        evidence=_evidence(),
    ))
    plans.acquire(engagement_id, plan_id, "apply")
    return plans


def _queued(job_id: str, engagement_id: str, plan_id: str) -> StoredJobRun:
    now = datetime.now(timezone.utc).isoformat()
    return StoredJobRun(
        id=job_id, action="pilot_standard_rti_guarded_execute", status="queued",
        target=f"oci-compartment:{TARGET.name}", target_type="oci_compartment",
        target_id=TARGET.compartment_id, requested_by="tester",
        input={
            "engagementId": engagement_id, "corePlanId": plan_id,
            "sketchStateSchema": "provider-keyed-v2",
            "pendingSketchChainIds": IDS, "pendingSketchChainFingerprints": FINGERPRINTS,
            "workspace": "barragan-pilot-standard-rti",
            "workspaceDir": "/private/tmp/queued-keyed-core",
            "target": TARGET.to_dict(),
            "providerKeyedSourcePin": {"root": "/private/pinned-source", "revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256},
            "corePlanEvidenceSha256": hashlib.sha256(json.dumps(_evidence(), sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        },
        artifact_refs=[], created_at=now, started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "pilot Standard RTI run queued", {
            "workspace": "barragan-pilot-standard-rti", "workspaceDir": "/private/tmp/queued-keyed-core",
            "target": TARGET.name, "region": TARGET.region,
        })],
    )


def _reserve(plans, job):
    return plans.reserve_keyed_core_apply_job(
        job, expected_evidence=plans.get(job.input["corePlanId"]).evidence,
        expected_revision_id="revision",
    )


def _mixed_evidence(*, linode_first: bool):
    evidence = deepcopy(_evidence())
    chain_order = IDS if linode_first else list(reversed(IDS))
    evidence["pendingSketchChainIds"] = chain_order
    scopes = []
    for provider, chain_id in (("digitalocean", IDS[1] if linode_first else IDS[0]),
                               ("linode", IDS[0] if linode_first else IDS[1])):
        scopes.append({
            "provider": provider,
            "source": {"revision": _SOURCE_REVISION,
                       "templateSha256": (_SOURCE_SHA256 if provider == "digitalocean"
                                          else "c" * 64)},
            "chain": {"id": chain_id, "fingerprint": FINGERPRINTS[chain_id]},
        })
    evidence["sketchAuthorization"] = {
        "kind": "bounded-mixed-post-core-v1", "providerScopes": scopes,
    }
    evidence.update({
        "terraformStatePath": "/private/tmp/mixed-core.tfstate",
        "terraformDataDir": "/private/tmp/mixed-core-data",
        "terraformStateLocator": "private",
    })
    return evidence


def _setup_mixed(engagement_id: str, plan_id: str, *, linode_first: bool):
    plans = _setup(engagement_id, plan_id)
    evidence = _mixed_evidence(linode_first=linode_first)
    plans.save(replace(plans.get(plan_id), evidence=evidence))
    return plans, evidence


def _successful_keyed_core(engagement_id: str, plan_id: str, *, authorized: bool = True):
    plans = _setup(engagement_id, plan_id)
    queued = _queued(f"job-{engagement_id}", engagement_id, plan_id)
    _reserve(plans, queued)
    jobs = SqlAlchemyJobRepository()
    retained = jobs.get(queued.id)
    success = jobs.save(replace(
        retained, status="succeeded", started_at=retained.created_at,
        finished_at=retained.created_at,
        input={**retained.input, "postCoreSketchContinuationEligible": False,
               "providerKeyedDispatchAuthorized": authorized},
        events=retained.events + [JobEvent(2, "info", "pilot Standard RTI run finished", {
            "ok": True, "mutationStatus": "deployed", "ansibleStatus": "validated",
            "finalCleanupStatus": "pending_operator_teardown",
        })],
    ))
    plans.complete_apply(replace(plans.get(plan_id), status="applied", stage="applied"),
                         next_operation="provider_keyed_initial")
    return jobs, plans, success


def test_keyed_dispatch_requires_exact_absent_or_inert_parent(client, tmp_path):
    jobs, plans, core = _successful_keyed_core("eng-keyed-dispatch", "dpl-keyed-dispatch")
    called = []
    pin = core.input["providerKeyedSourcePin"]
    with patch("app.services.provider_keyed_initial_dispatch._default_state_root", return_value=tmp_path), patch(
        "app.services.guarded_test_deployment._require_configured_keyed_source", return_value=pin,
    ):
        result = dispatch_fresh_keyed_initial(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            preflight=lambda *args, **kwargs: called.append("preflight"),
            continuation=lambda *args, **kwargs: called.append("continuation") or "started",
        )
        assert result == "started"
        assert called == ["preflight", "continuation"]
        called.clear()
        (tmp_path / core.input["engagementId"]).mkdir()
        with pytest.raises(ProviderKeyedInitialDispatchError, match="workspace"):
            dispatch_fresh_keyed_initial(
                core.id, environment="devtest", rollout_enabled=True,
                job_repository=jobs, plan_repository=plans,
                preflight=lambda *args, **kwargs: called.append("preflight"),
                continuation=lambda *args, **kwargs: called.append("continuation"),
            )
        assert called == []


def test_later_rollout_cannot_dispatch_old_unauthed_core(client):
    jobs, plans, core = _successful_keyed_core(
        "eng-keyed-old-off", "dpl-keyed-old-off", authorized=False,
    )
    scheduled = []
    assert recover_fresh_keyed_initial_dispatches(
        environment="devtest", rollout_enabled=True,
        schedule=lambda task: scheduled.append(task),
    ) == []
    assert scheduled == []
    with pytest.raises(ProviderKeyedInitialDispatchError):
        dispatch_fresh_keyed_initial(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            preflight=lambda *args, **kwargs: pytest.fail("preflight called"),
            continuation=lambda *args, **kwargs: pytest.fail("provider called"),
        )


@pytest.mark.parametrize("running", [False, True])
def test_startup_leaves_live_claimed_parent_untouched(client, running):
    from app.services.provider_keyed_initial_continuation import _job_ids, _new_job

    jobs, plans, core = _successful_keyed_core("eng-keyed-live-parent", "dpl-keyed-live-parent")
    parent_id, plan_child_id, apply_child_id = _job_ids(core.id)
    parent = _new_job(parent_id, "provider_keyed_initial", core, core.input["engagementId"], {
        "engagementId": core.input["engagementId"], "coreJobId": core.id,
        "corePlanId": core.input["corePlanId"], "planJobId": plan_child_id,
        "applyJobId": apply_child_id, "phase": "queued", "mutation": True,
    })
    jobs.save(parent)
    claimed = jobs.claim_lease(
        parent.id, owner="live-worker", token="live-token",
        claimed_at=datetime.now(timezone.utc).isoformat(),
        expires_at="2999-01-01T00:00:00+00:00", eligible_statuses={"queued"},
    )
    assert claimed is not None
    if running:
        claimed = jobs.save(replace(
            claimed, status="running", started_at=datetime.now(timezone.utc).isoformat(),
            input={**claimed.input, "phase": "planning"},
        ))
    with patch("app.services.provider_keyed_initial_dispatch.dispatch_fresh_keyed_initial") as dispatch:
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    dispatch.assert_not_called()
    assert jobs.get(parent.id) == claimed
    assert plans.get(core.input["corePlanId"]).stage == "applied"


def test_recovery_race_claimed_queued_parent_does_not_mark_false_attention(client):
    from app.services.provider_keyed_initial_continuation import _job_ids, _new_job

    jobs, plans, core = _successful_keyed_core("eng-keyed-claim-race", "dpl-keyed-claim-race")
    parent_id, plan_child_id, apply_child_id = _job_ids(core.id)
    parent = jobs.save(_new_job(
        parent_id, "provider_keyed_initial", core, core.input["engagementId"], {
            "engagementId": core.input["engagementId"], "coreJobId": core.id,
            "corePlanId": core.input["corePlanId"], "planJobId": plan_child_id,
            "applyJobId": apply_child_id, "phase": "queued", "mutation": True,
        },
    ))

    def racing_dispatch(*args, **kwargs):
        assert jobs.claim_lease(
            parent.id, owner="other-worker", token="other-token",
            claimed_at=datetime.now(timezone.utc).isoformat(),
            expires_at="2999-01-01T00:00:00+00:00", eligible_statuses={"queued"},
        ) is not None
        raise ProviderKeyedInitialDispatchError("claim raced")

    with patch("app.services.provider_keyed_initial_dispatch.dispatch_fresh_keyed_initial",
               side_effect=racing_dispatch):
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    assert jobs.get(parent.id).input["claimToken"] == "other-token"
    assert plans.get(core.input["corePlanId"]).stage == "applied"


def _running_keyed_parent(jobs, core, phase, *, next_check=None):
    from app.services.provider_keyed_initial_continuation import _job_ids, _new_job

    parent_id, plan_child_id, apply_child_id = _job_ids(core.id)
    values = {
        "engagementId": core.input["engagementId"], "coreJobId": core.id,
        "corePlanId": core.input["corePlanId"], "planJobId": plan_child_id,
        "applyJobId": apply_child_id, "phase": phase, "mutation": True,
    }
    if next_check is not None:
        values.update({"nextAttachmentCheckAt": next_check, "attachmentRecheckCount": 0,
                       "claimExpiresAt": next_check})
    parent = _new_job(parent_id, "provider_keyed_initial", core, core.input["engagementId"], values)
    return jobs.save(replace(parent, status="running", started_at=parent.created_at))


def test_phase_controller_advances_attachment_binding_and_bootstrap_without_public_gate(client, tmp_path):
    jobs, plans, core = _successful_keyed_core("eng-keyed-phase", "dpl-keyed-phase")
    due = "2026-10-08T00:00:30+00:00"
    parent = _running_keyed_parent(jobs, core, "attachment_pending", next_check=due)
    now = [datetime.fromisoformat("2026-10-08T00:00:00+00:00")]
    calls = []

    def wait(seconds):
        calls.append(("wait", seconds))
        now[0] = now[0] + __import__("datetime").timedelta(seconds=seconds)

    def advance(phase):
        current = jobs.get(parent.id)
        changed = jobs.save(replace(current, input={**current.input, "phase": phase,
            **({} if phase == "attachment_pending" else {"claimExpiresAt": now[0].isoformat()})}))
        return changed

    def recheck(*args, **kwargs):
        calls.append("recheck")
        assert now[0] >= datetime.fromisoformat(due)
        return advance("awaiting_host_proof")

    def bind(*args, **kwargs):
        calls.append("bind")
        return advance("host_identity_bound")

    def bootstrap(*args, **kwargs):
        calls.append("bootstrap")
        assert kwargs["bootstrap_env"]["BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT"] == core.input["providerKeyedSourcePin"]["root"]
        return advance("awaiting_strict_host_proof")

    with patch("app.services.provider_keyed_initial_dispatch._default_state_root", return_value=tmp_path), patch(
        "app.services.guarded_test_deployment._require_configured_keyed_source",
        return_value=core.input["providerKeyedSourcePin"],
    ):
        final = advance_fresh_keyed_initial_phases(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans, recheck=recheck,
            bind=bind, bootstrap=bootstrap, wait=wait, clock=lambda: now[0],
        )
    assert final.input["phase"] == "awaiting_strict_host_proof"
    assert calls == [("wait", 30.0), "recheck", "bind", "bootstrap"]
    assert plans.get(core.input["corePlanId"]).status == "applied"


@pytest.mark.parametrize("phase", ["bootstrap_preparing", "bootstrap_contacted", "bootstrap_root_started",
                                    "bootstrap_chain_completed", "awaiting_strict_host_proof", "attention"])
def test_phase_controller_never_replays_one_shot_bootstrap_phases(client, phase):
    jobs, plans, core = _successful_keyed_core(f"eng-keyed-stop-{phase}", f"dpl-keyed-stop-{phase}")
    parent = _running_keyed_parent(jobs, core, phase)
    assert advance_fresh_keyed_initial_phases(
        core.id, environment="devtest", rollout_enabled=True,
        job_repository=jobs, plan_repository=plans,
        dispatch=lambda *_a, **_k: pytest.fail("dispatch replay"),
        recheck=lambda *_a, **_k: pytest.fail("GET replay"),
        bind=lambda *_a, **_k: pytest.fail("binding replay"),
        bootstrap=lambda *_a, **_k: pytest.fail("bootstrap replay"),
    ) == parent


def test_strict_proof_runs_only_in_live_loop_after_completed_bootstrap(client, tmp_path):
    jobs, plans, core = _successful_keyed_core("eng-keyed-proof-loop", "dpl-keyed-proof-loop")
    parent = _running_keyed_parent(jobs, core, "host_identity_bound")
    calls = []

    def bootstrap(*_args, **_kwargs):
        current = jobs.get(parent.id)
        return jobs.save(replace(current, input={**current.input,
            "phase": "awaiting_strict_host_proof"}, events=[*current.events,
            JobEvent(len(current.events) + 1, "info",
                     "provider bootstrap completed; strict host proof pending", {})]))

    def publish(*_args, **_kwargs):
        calls.append("proof")
        current = jobs.get(parent.id)
        return jobs.save(replace(current, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
                                 input={**current.input, "phase": "completed"}))

    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               return_value=core.input["providerKeyedSourcePin"]), patch(
        "app.services.provider_keyed_initial_dispatch._default_state_root", return_value=tmp_path,
    ):
        result = advance_fresh_keyed_initial_phases(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            bootstrap=bootstrap, publish_host_proof=publish,
        )
        assert result.status == "succeeded" and calls == ["proof"]
        # A later dispatch/restart never repeats the one-shot contact.
        assert advance_fresh_keyed_initial_phases(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            publish_host_proof=lambda *_a, **_k: pytest.fail("proof replay"),
        ).status == "succeeded"


def test_restart_marks_expired_strict_host_phase_attention_without_contact(client):
    jobs, plans, core = _successful_keyed_core("eng-keyed-proof-restart", "dpl-keyed-proof-restart")
    parent = _running_keyed_parent(jobs, core, "awaiting_strict_host_proof")
    with patch("app.services.provider_keyed_initial_dispatch.publish_initial_digitalocean_host_proof") as proof:
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    proof.assert_not_called()
    assert jobs.get(parent.id).status == "running"
    assert plans.get(core.input["corePlanId"]).stage == "provider_keyed_initial_attention"


def test_phase_controller_refuses_source_drift_before_bootstrap(client):
    jobs, plans, core = _successful_keyed_core("eng-keyed-boot-drift", "dpl-keyed-boot-drift")
    _running_keyed_parent(jobs, core, "host_identity_bound")
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               side_effect=ValueError("private source path")):
        with pytest.raises(ProviderKeyedInitialDispatchError, match="pinned keyed source"):
            advance_fresh_keyed_initial_phases(
                core.id, environment="devtest", rollout_enabled=True,
                job_repository=jobs, plan_repository=plans,
                bootstrap=lambda *_a, **_k: pytest.fail("host contact"),
            )


def test_phase_controller_gate_off_does_not_read_or_dispatch(client):
    assert advance_fresh_keyed_initial_phases(
        "old-v2-core", environment="devtest", rollout_enabled=False,
        job_repository=object(), plan_repository=object(),
        dispatch=lambda *_a, **_k: pytest.fail("dispatch"),
    ) is None


def test_startup_resumes_safe_bound_phase_but_not_bootstrap_command_phase(client, tmp_path):
    jobs, plans, core = _successful_keyed_core("eng-keyed-resume-bound", "dpl-keyed-resume-bound")
    parent = _running_keyed_parent(jobs, core, "host_identity_bound")
    calls = []

    def bootstrap(*args, **kwargs):
        calls.append("bootstrap")
        current = jobs.get(parent.id)
        return jobs.save(replace(current, input={**current.input, "phase": "bootstrap_preparing"}))

    with patch("app.services.provider_keyed_initial_dispatch._default_state_root", return_value=tmp_path), patch(
        "app.services.guarded_test_deployment._require_configured_keyed_source",
        return_value=core.input["providerKeyedSourcePin"],
    ), patch("app.services.provider_keyed_initial_dispatch.bootstrap_initial_digitalocean_chains",
             side_effect=bootstrap):
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    assert calls == ["bootstrap"]
    assert jobs.get(parent.id).input["phase"] == "bootstrap_preparing"
    assert plans.get(core.input["corePlanId"]).stage == "applied"


def test_due_attachment_with_live_claim_is_not_rechecked(client, tmp_path):
    jobs, plans, core = _successful_keyed_core("eng-keyed-live-get", "dpl-keyed-live-get")
    parent = _running_keyed_parent(jobs, core, "attachment_pending",
                                   next_check="2026-10-08T00:00:00+00:00")
    current = jobs.get(parent.id)
    jobs.save(replace(current, input={**current.input, "claimExpiresAt": "2999-01-01T00:00:00+00:00"}))
    waited = []

    def wait(seconds):
        waited.append(seconds)
        current = jobs.get(parent.id)
        jobs.save(replace(current, input={**current.input, "phase": "bootstrap_contacted"}))

    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               return_value=core.input["providerKeyedSourcePin"]), patch(
        "app.services.provider_keyed_initial_dispatch._default_state_root", return_value=tmp_path,
    ):
        result = advance_fresh_keyed_initial_phases(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            recheck=lambda *_a, **_k: pytest.fail("competing GET recheck"),
            clock=lambda: datetime.fromisoformat("2026-10-08T00:01:00+00:00"),
            wait=wait,
        )
    assert result.input["phase"] == "bootstrap_contacted"
    assert waited == [300.0]


def test_restart_waits_for_safe_claim_expiry_then_bootstraps(client, tmp_path):
    jobs, plans, core = _successful_keyed_core("eng-keyed-expired-bound", "dpl-keyed-expired-bound")
    parent = _running_keyed_parent(jobs, core, "host_identity_bound")
    now = [datetime.fromisoformat("2026-10-08T00:00:00+00:00")]
    current = jobs.get(parent.id)
    jobs.save(replace(current, input={**current.input, "claimExpiresAt": "2026-10-08T00:00:40+00:00"}))
    calls = []

    def wait(seconds):
        calls.append(("wait", seconds))
        now[0] += __import__("datetime").timedelta(seconds=seconds)

    def bootstrap(*args, **kwargs):
        calls.append("bootstrap")
        current = jobs.get(parent.id)
        return jobs.save(replace(current, input={**current.input, "phase": "awaiting_strict_host_proof"}))

    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               return_value=core.input["providerKeyedSourcePin"]), patch(
        "app.services.provider_keyed_initial_dispatch._default_state_root", return_value=tmp_path,
    ):
        result = advance_fresh_keyed_initial_phases(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            bootstrap=bootstrap, wait=wait, clock=lambda: now[0],
        )
    assert result.input["phase"] == "awaiting_strict_host_proof"
    assert calls == [("wait", 40.0), "bootstrap"]


def test_long_attachment_settling_does_not_strand_one_click_controller(client, tmp_path):
    jobs, plans, core = _successful_keyed_core("eng-keyed-long-settle", "dpl-keyed-long-settle")
    now = [datetime.fromisoformat("2026-10-08T00:00:00+00:00")]
    parent = _running_keyed_parent(jobs, core, "attachment_pending", next_check=now[0].isoformat())
    attempts = []

    def wait(seconds):
        now[0] += __import__("datetime").timedelta(seconds=seconds)

    def recheck(*args, **kwargs):
        attempts.append(1)
        current = jobs.get(parent.id)
        if len(attempts) <= 49:
            due = (now[0] + __import__("datetime").timedelta(seconds=30)).isoformat()
            return jobs.save(replace(current, input={**current.input, "nextAttachmentCheckAt": due,
                                                      "claimExpiresAt": due}))
        return jobs.save(replace(current, input={**current.input, "phase": "awaiting_strict_host_proof"}))

    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               return_value=core.input["providerKeyedSourcePin"]), patch(
        "app.services.provider_keyed_initial_dispatch._default_state_root", return_value=tmp_path,
    ):
        result = advance_fresh_keyed_initial_phases(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            recheck=recheck, wait=wait, clock=lambda: now[0],
        )
    assert len(attempts) == 50
    assert result.input["phase"] == "awaiting_strict_host_proof"


def test_expired_pending_parent_with_missing_due_gets_visible_attention(client):
    jobs, plans, core = _successful_keyed_core("eng-keyed-bad-due", "dpl-keyed-bad-due")
    parent = _running_keyed_parent(jobs, core, "attachment_pending")
    retained = jobs.get(parent.id)
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               return_value=core.input["providerKeyedSourcePin"]), patch(
        "app.services.provider_keyed_initial_dispatch.recheck_digitalocean_initial_attachment",
        side_effect=AssertionError("GET must not run"),
    ):
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    assert jobs.get(parent.id) == retained
    assert plans.get(core.input["corePlanId"]).stage == "provider_keyed_initial_attention"
    assert CoreMutationLeaseModel.query.filter_by(engagement_id=core.input["engagementId"]).count() == 1


def test_running_safe_phase_source_drift_marks_attention_without_replay(client):
    jobs, plans, core = _successful_keyed_core("eng-keyed-source-attn", "dpl-keyed-source-attn")
    parent = _running_keyed_parent(jobs, core, "host_identity_bound")
    retained = jobs.get(parent.id)
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               side_effect=ValueError("private source path")), patch(
        "app.services.provider_keyed_initial_dispatch.bootstrap_initial_digitalocean_chains",
        side_effect=AssertionError("no host contact"),
    ):
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    assert jobs.get(parent.id) == retained
    assert plans.get(core.input["corePlanId"]).stage == "provider_keyed_initial_attention"
    assert CoreMutationLeaseModel.query.filter_by(engagement_id=core.input["engagementId"]).count() == 1
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               return_value=core.input["providerKeyedSourcePin"]), patch(
        "app.services.provider_keyed_initial_dispatch.bootstrap_initial_digitalocean_chains",
        side_effect=AssertionError("attention must not replay bootstrap"),
    ):
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    assert plans.get(core.input["corePlanId"]).stage == "provider_keyed_initial_attention"


def test_running_safe_phase_lease_drift_marks_attention_without_contact(client):
    jobs, plans, core = _successful_keyed_core("eng-keyed-lease-attn", "dpl-keyed-lease-attn")
    parent = _running_keyed_parent(jobs, core, "host_identity_bound")
    lease = CoreMutationLeaseModel.query.filter_by(engagement_id=core.input["engagementId"]).one()
    lease.operation = "other_operation"
    db.session.commit()
    with patch("app.services.provider_keyed_initial_dispatch.bootstrap_initial_digitalocean_chains",
               side_effect=AssertionError("no host contact")):
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    assert jobs.get(parent.id).input["phase"] == "host_identity_bound"
    assert plans.get(core.input["corePlanId"]).stage == "provider_keyed_initial_attention"
    assert CoreMutationLeaseModel.query.filter_by(engagement_id=core.input["engagementId"]).one().operation == "other_operation"


def test_running_safe_phase_with_live_claim_is_not_marked_attention(client):
    jobs, plans, core = _successful_keyed_core("eng-keyed-live-drift", "dpl-keyed-live-drift")
    parent = _running_keyed_parent(jobs, core, "host_identity_bound")
    retained = jobs.get(parent.id)
    jobs.save(replace(retained, input={**retained.input, "claimOwner": "live", "claimToken": "token",
                                       "claimClaimedAt": datetime.now(timezone.utc).isoformat(),
                                       "claimExpiresAt": "2999-01-01T00:00:00+00:00"}))
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               side_effect=ValueError("private source path")), patch(
        "app.services.provider_keyed_initial_dispatch.bootstrap_initial_digitalocean_chains",
        side_effect=AssertionError("no host contact"),
    ):
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    assert jobs.get(parent.id).input["claimToken"] == "token"
    assert plans.get(core.input["corePlanId"]).stage == "applied"


@pytest.mark.parametrize("status,bad_input", [
    ("running", None), ("running", []), ("running", {}),
    ("queued", None), ("queued", []),
])
def test_malformed_parent_input_gets_attention_without_provider_call(client, status, bad_input):
    jobs, plans, core = _successful_keyed_core(
        f"eng-keyed-malformed-{status}-{type(bad_input).__name__}",
        f"dpl-keyed-malformed-{status}-{type(bad_input).__name__}",
    )
    parent = _running_keyed_parent(jobs, core, "attachment_pending")
    current = jobs.get(parent.id)
    jobs.save(replace(current, status=status, started_at=current.started_at if status == "running" else None,
                      input=bad_input))
    with patch("app.services.provider_keyed_initial_dispatch.recheck_digitalocean_initial_attachment",
               side_effect=AssertionError("no provider GET")):
        _recover_one(core.id, environment="devtest", rollout_enabled=True)
    assert plans.get(core.input["corePlanId"]).stage == "provider_keyed_initial_attention"


def test_reservation_is_atomic_and_duplicate_cannot_leave_orphan(client):
    engagement_id, plan_id = "eng-keyed-reserve", "dpl-keyed-reserve"
    plans = _setup(engagement_id, plan_id)
    first = _queued("job-keyed-first", engagement_id, plan_id)
    second = replace(first, id="job-keyed-second")

    with patch("app.core.request_identity.current_request_identity",
               return_value=SimpleNamespace(username="authenticated-user")):
        _reserve(plans, first)
    assert plans.get(plan_id).apply_job_id == first.id
    retained = SqlAlchemyJobRepository().get(first.id)
    assert retained is not None
    assert retained.id == first.id and retained.input == first.input
    assert retained.events == first.events
    assert retained.requested_by == "authenticated-user"
    public = get_job_run(first.id, repository=SqlAlchemyJobRepository())
    assert public is not None
    assert "providerKeyedSourcePin" not in public.input
    assert "corePlanEvidenceSha256" not in public.input
    assert datetime.fromisoformat(retained.created_at) == datetime.fromisoformat(first.created_at).replace(tzinfo=None)
    with pytest.raises(DeploymentPlanConflictError):
        _reserve(plans, second)
    assert JobRunModel.query.get(second.id) is None
    assert JobEventModel.query.filter_by(job_id=second.id).count() == 0
    assert plans.get(plan_id).apply_job_id == first.id


@pytest.mark.parametrize("linode_first", [True, False])
def test_real_core_start_reserves_reviewed_mixed_plan_once(client, linode_first):
    engagement_id = f"eng-keyed-mixed-start-{linode_first}"
    plan_id = f"dpl-keyed-mixed-start-{linode_first}"
    plans, evidence = _setup_mixed(engagement_id, plan_id,
                                   linode_first=linode_first)
    engagement = SimpleNamespace(id=engagement_id, name="Disposable",
                                 template_id="small-dev-infra", input_parameters={})
    pin = {"root": "/private/pinned-source", "revision": _SOURCE_REVISION,
           "templateSha256": _SOURCE_SHA256}
    scheduled = []
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               return_value=pin), patch(
        "app.services.guarded_test_deployment._required_engagement",
        return_value=engagement,
    ), patch("app.services.guarded_test_deployment._target_for_engagement",
             return_value=TARGET), patch(
        "app.services.guarded_test_deployment._validate_guarded_pilot_request",
    ):
        started = start_guarded_pilot_standard_rti_run(
            {"engagementId": engagement_id, "sshSourceCidrs": ["198.51.100.1/32"]},
            prepared_core_run=evidence, core_plan_id=plan_id,
            core_plan_revision_id="revision",
            background_runner=lambda task: scheduled.append(task),
        )
    assert len(scheduled) == 1
    assert plans.get(plan_id).apply_job_id == started.id
    assert JobRunModel.query.filter_by(id=started.id).count() == 1
    assert JobEventModel.query.filter_by(job_id=started.id).count() >= 1
    assert started.status == "running"


@pytest.mark.parametrize("linode_first", [True, False])
def test_mixed_reservation_rejects_source_scope_and_lease_drift(client, linode_first):
    engagement_id = f"eng-keyed-mixed-veto-{linode_first}"
    plan_id = f"dpl-keyed-mixed-veto-{linode_first}"
    plans, evidence = _setup_mixed(engagement_id, plan_id,
                                   linode_first=linode_first)
    job = _queued(f"job-mixed-veto-{linode_first}", engagement_id, plan_id)
    job = replace(job, input={**job.input,
        "pendingSketchChainIds": evidence["pendingSketchChainIds"],
        "corePlanEvidenceSha256": hashlib.sha256(json.dumps(
            evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    })
    bad_pin = replace(job, input={**job.input, "providerKeyedSourcePin": {
        **job.input["providerKeyedSourcePin"], "templateSha256": "0" * 64,
    }})
    with pytest.raises(DeploymentPlanConflictError):
        _reserve(plans, bad_pin)
    assert JobRunModel.query.get(job.id) is None
    assert plans.get(plan_id).apply_job_id == ""

    malformed = deepcopy(evidence)
    malformed["sketchAuthorization"]["providerScopes"][1]["provider"] = "digitalocean"
    plans.save(replace(plans.get(plan_id), evidence=malformed))
    malformed_job = replace(job, input={**job.input,
        "corePlanEvidenceSha256": hashlib.sha256(json.dumps(
            malformed, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    })
    with pytest.raises(DeploymentPlanConflictError):
        _reserve(plans, malformed_job)
    assert JobRunModel.query.get(job.id) is None
    assert plans.get(plan_id).apply_job_id == ""

    malformed = deepcopy(evidence)
    malformed["pendingSketchChainIds"] = [[], IDS[1]]
    plans.save(replace(plans.get(plan_id), evidence=malformed))
    malformed_job = replace(job, input={**job.input,
        "pendingSketchChainIds": malformed["pendingSketchChainIds"],
        "corePlanEvidenceSha256": hashlib.sha256(json.dumps(
            malformed, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    })
    with pytest.raises(DeploymentPlanConflictError):
        _reserve(plans, malformed_job)
    assert JobRunModel.query.get(job.id) is None
    assert plans.get(plan_id).apply_job_id == ""

    plans.save(replace(plans.get(plan_id), evidence=evidence))
    CoreMutationLeaseModel.query.filter_by(engagement_id=engagement_id).delete()
    db.session.commit()
    with pytest.raises(DeploymentPlanConflictError):
        _reserve(plans, job)
    assert JobRunModel.query.get(job.id) is None
    assert JobEventModel.query.filter_by(job_id=job.id).count() == 0
    assert plans.get(plan_id).apply_job_id == ""


def test_reserving_same_job_id_twice_is_a_typed_conflict(client):
    engagement_id, plan_id = "eng-keyed-same-id", "dpl-keyed-same-id"
    plans = _setup(engagement_id, plan_id)
    job = _queued("job-keyed-same-id", engagement_id, plan_id)

    _reserve(plans, job)
    with pytest.raises(DeploymentPlanConflictError):
        _reserve(plans, job)

    assert plans.get(plan_id).apply_job_id == job.id
    assert JobRunModel.query.filter_by(id=job.id).count() == 1
    assert JobEventModel.query.filter_by(job_id=job.id).count() == 1


def test_reservation_failure_rolls_back_job_event_and_plan(client):
    engagement_id, plan_id = "eng-keyed-veto", "dpl-keyed-veto"
    plans = _setup(engagement_id, plan_id)
    job = _queued("job-keyed-veto", engagement_id, plan_id)
    CoreMutationLeaseModel.query.filter_by(engagement_id=engagement_id).delete()
    db.session.commit()
    with pytest.raises(DeploymentPlanConflictError):
        _reserve(plans, job)
    assert JobRunModel.query.get(job.id) is None
    assert JobEventModel.query.filter_by(job_id=job.id).count() == 0
    assert plans.get(plan_id).apply_job_id == ""


def test_reviewed_evidence_or_target_drift_cannot_bind(client):
    engagement_id, plan_id = "eng-keyed-drift", "dpl-keyed-drift"
    plans = _setup(engagement_id, plan_id)
    original = dict(plans.get(plan_id).evidence)
    plans.save(replace(plans.get(plan_id), evidence={**original, "digitaloceanImage": "changed"}))
    job = _queued("job-keyed-drift", engagement_id, plan_id)
    with pytest.raises(DeploymentPlanConflictError):
        plans.reserve_keyed_core_apply_job(
            job, expected_evidence=original, expected_revision_id="revision",
        )
    assert JobRunModel.query.get(job.id) is None
    assert plans.get(plan_id).apply_job_id == ""

    wrong_target = replace(job, target_id="another-compartment")
    with pytest.raises(DeploymentPlanConflictError):
        _reserve(plans, wrong_target)
    assert JobRunModel.query.get(job.id) is None
    assert JobEventModel.query.filter_by(job_id=job.id).count() == 0


def test_synchronous_runner_observes_bound_job_before_launch(client, tmp_path):
    engagement_id, plan_id = "eng-keyed-fast", "dpl-keyed-fast"
    plans = _setup(engagement_id, plan_id)
    jobs = SqlAlchemyJobRepository()
    observed = []
    engagement = SimpleNamespace(
        id=engagement_id, name="Disposable", template_id="standard-rti", input_parameters={},
    )
    prepared = {
        "sketchStateSchema": "provider-keyed-v2", "pendingSketchChainIds": IDS,
        "pendingSketchChainFingerprints": FINGERPRINTS,
        "runDirectory": str(tmp_path / "core"), "terraformStatePath": str(tmp_path / "core.tfstate"),
        "terraformDataDir": str(tmp_path / "terraform-data"), "terraformStateLocator": "private",
    }
    prepared.update(plans.get(plan_id).evidence)
    plans.save(replace(plans.get(plan_id), evidence=prepared))

    def synchronous_runner(task):
        bound_id = plans.get(plan_id).apply_job_id
        assert bound_id
        assert jobs.get(bound_id).status == "running"
        observed.append(bound_id)
        task()

    with patch("app.services.guarded_test_deployment._require_configured_keyed_source", return_value={
        "root": "/private/pinned-source", "revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
    }), patch("app.services.guarded_test_deployment._required_engagement", return_value=engagement), patch(
        "app.services.guarded_test_deployment._target_for_engagement", return_value=TARGET,
    ), patch("app.services.guarded_test_deployment._validate_guarded_pilot_request"):
        started = start_guarded_pilot_standard_rti_run(
            {"engagementId": engagement_id, "sshSourceCidrs": ["198.51.100.1/32"]},
            repository=jobs, prepared_core_run=prepared, core_plan_id=plan_id,
            core_plan_revision_id="revision",
            background_runner=synchronous_runner,
            executor=lambda _workspace, **_kwargs: {
                "ok": False, "mutationStatus": "preflight_failed",
                "ansibleStatus": "not_started", "finalCleanupStatus": "not_started",
            },
        )
    assert observed == [started.id]
    assert "providerKeyedSourcePin" not in started.input
    assert "corePlanEvidenceSha256" not in started.input
    assert "providerKeyedDispatchAuthorized" not in started.input
    assert jobs.get(started.id).input["providerKeyedSourcePin"]["root"] == "/private/pinned-source"
    assert jobs.get(started.id).status == "failed"
    assert plans.get(plan_id).status == "reconciliation_required"


def test_keyed_source_drift_at_apply_command_start_prevents_go(client, tmp_path):
    engagement_id, plan_id = "eng-keyed-source-go", "dpl-keyed-source-go"
    plans = _setup(engagement_id, plan_id)
    jobs = SqlAlchemyJobRepository()
    engagement = SimpleNamespace(
        id=engagement_id, name="Disposable", template_id="standard-rti", input_parameters={},
    )
    prepared = {
        **plans.get(plan_id).evidence,
        "terraformStatePath": str(tmp_path / "core.tfstate"),
        "terraformDataDir": str(tmp_path / "terraform-data"),
        "terraformStateLocator": "private",
    }
    plans.save(replace(plans.get(plan_id), evidence=prepared))
    go = []

    def executor(_workspace, **kwargs):
        kwargs["progress_callback"]({
            "message": "infrastructure command started",
            "data": {"eventKind": "command_started", "step": "terraform_apply"},
        })
        go.append(True)
        return {"ok": True}

    pin = {"root": "/private/pinned-source", "revision": _SOURCE_REVISION,
           "templateSha256": _SOURCE_SHA256}
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source",
               side_effect=[pin, GuardedDeploymentConfirmationError("pinned source changed")]), patch(
        "app.services.guarded_test_deployment._required_engagement", return_value=engagement,
    ), patch("app.services.guarded_test_deployment._target_for_engagement", return_value=TARGET), patch(
        "app.services.guarded_test_deployment._validate_guarded_pilot_request",
    ):
        start_guarded_pilot_standard_rti_run(
            {"engagementId": engagement_id, "sshSourceCidrs": ["198.51.100.1/32"]},
            repository=jobs, prepared_core_run=prepared, core_plan_id=plan_id,
            core_plan_revision_id="revision", background_runner=lambda task: task(), executor=executor,
        )
    assert go == []
    assert plans.get(plan_id).status == "reconciliation_required"
    lease = CoreMutationLeaseModel.query.get(engagement_id)
    assert lease is not None and (lease.owner_id, lease.operation) == (plan_id, "apply")


@pytest.mark.parametrize("changed", ["planPath", "terraformStatePath", "sshPrivateKeyPath"])
def test_saved_core_artifact_drift_at_real_command_started_prevents_runner(client, tmp_path, changed):
    from app.integrations.pilot_standard_rti import _run_guarded_command

    engagement_id, plan_id = f"eng-go-{changed}", f"dpl-go-{changed}"
    plans = _setup(engagement_id, plan_id)
    jobs = SqlAlchemyJobRepository()
    engagement = SimpleNamespace(
        id=engagement_id, name="Disposable", template_id="standard-rti", input_parameters={},
    )
    prepared = {
        **plans.get(plan_id).evidence,
        "terraformStatePath": str(tmp_path / "core.tfstate"),
        "terraformDataDir": str(tmp_path / "terraform-data"),
        "terraformStateLocator": "private",
    }
    plans.save(replace(plans.get(plan_id), evidence=prepared))
    artifact = tmp_path / changed
    artifact.write_bytes(b"reviewed")
    launched = []

    def verify(plan):
        assert plan.apply_job_id
        if artifact.read_bytes() != b"reviewed":
            raise GuardedDeploymentConfirmationError("reviewed artifact changed")

    def executor(workspace, **kwargs):
        artifact.write_bytes(b"changed")
        _run_guarded_command(
            ["/bin/echo", "apply"], workspace,
            lambda *args, **kw: launched.append(True),
            step="terraform_apply", progress_callback=kwargs["progress_callback"],
        )
        return {"ok": True}

    pin = {"root": "/private/pinned-source", "revision": _SOURCE_REVISION,
           "templateSha256": _SOURCE_SHA256}
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source", return_value=pin), patch(
        "app.services.core_deployment_plans._verify_plan_evidence", side_effect=verify,
    ), patch("app.services.guarded_test_deployment._required_engagement", return_value=engagement), patch(
        "app.services.guarded_test_deployment._target_for_engagement", return_value=TARGET,
    ), patch("app.services.guarded_test_deployment._validate_guarded_pilot_request"):
        start_guarded_pilot_standard_rti_run(
            {"engagementId": engagement_id, "sshSourceCidrs": ["198.51.100.1/32"]},
            repository=jobs, prepared_core_run=prepared, core_plan_id=plan_id,
            core_plan_revision_id="revision", background_runner=lambda task: task(), executor=executor,
        )
    assert launched == []
    assert plans.get(plan_id).status == "reconciliation_required"


@pytest.mark.parametrize("enabled", [False, True])
def test_actual_worker_success_atomically_retags_lease(client, enabled):
    engagement_id, plan_id = "eng-worker-success", "dpl-worker-success"
    plans = _setup(engagement_id, plan_id)
    jobs = SqlAlchemyJobRepository()
    queued = _queued("job-worker-success", engagement_id, plan_id)
    _reserve(plans, queued)
    running = jobs.save(replace(
        jobs.get(queued.id), status="running", started_at=datetime.now(timezone.utc).isoformat(),
        events=[*queued.events, JobEvent(2, "info", "pilot Standard RTI run started", {})],
    ))
    result = {
        "ok": True, "deploymentMode": "hold_for_review", "mutationStatus": "deployed",
        "ansibleStatus": "validated", "finalCleanupStatus": "pending_operator_teardown",
    }
    dispatched = []
    seal = {"schema": "applied-oci-core-state-v1", "corePlanEvidenceSha256": running.input["corePlanEvidenceSha256"],
            "rawStateSha256": "a" * 64, "inventorySha256": "b" * 64,
            "lineage": "11111111-1111-4111-8111-111111111111", "serial": 1, "resourceCount": 1}
    with patch("app.services.guarded_test_deployment._runtime_environment", return_value="devtest"), patch(
        "app.services.guarded_test_deployment.runtime_value", return_value=enabled,
    ), patch("app.services.provider_keyed_initial_dispatch._recover_one",
             side_effect=lambda *args, **kwargs: dispatched.append((args, kwargs))), patch(
        "app.services.guarded_test_deployment.ensure_continuous_inspector_ready", return_value={"ready": True},
    ), patch("app.services.guarded_test_deployment.try_enqueue_infra_orientation_refresh"), patch(
        "app.storage.deployment_plan_repository._read_keyed_core_state_seal", return_value=seal,
    ):
        _execute_guarded_pilot_standard_rti_run(
            running.id, {"engagementId": engagement_id, "target": TARGET.to_dict(),
                         "corePlanId": plan_id, "proxyCount": 1},
            Path("/private/tmp/queued-keyed-core"), executor=lambda *args, **kwargs: result,
            repository=jobs,
        )
    stored = jobs.get(running.id)
    assert stored.status == "succeeded"
    assert stored.events[-2].message == "applied OCI core state sealed"
    assert stored.events[-2].data == seal
    assert stored.input["providerKeyedDispatchAuthorized"] is enabled
    assert plans.get(plan_id).status == "applied"
    lease = CoreMutationLeaseModel.query.get(engagement_id)
    assert lease is not None and (lease.owner_id, lease.operation) == (plan_id, "provider_keyed_initial")
    assert len(dispatched) == int(enabled)


def test_losing_reservation_never_launches_runner(client, tmp_path):
    engagement_id, plan_id = "eng-keyed-loser", "dpl-keyed-loser"
    plans = _setup(engagement_id, plan_id)
    _reserve(plans, _queued("job-already-reserved", engagement_id, plan_id))
    called = []
    engagement = SimpleNamespace(
        id=engagement_id, name="Disposable", template_id="standard-rti", input_parameters={},
    )
    prepared = {
        "sketchStateSchema": "provider-keyed-v2", "pendingSketchChainIds": IDS,
        "pendingSketchChainFingerprints": FINGERPRINTS,
        "runDirectory": str(tmp_path / "core"), "terraformStatePath": str(tmp_path / "core.tfstate"),
        "terraformDataDir": str(tmp_path / "terraform-data"), "terraformStateLocator": "private",
    }
    prepared.update(plans.get(plan_id).evidence)
    plans.save(replace(plans.get(plan_id), evidence=prepared))
    with patch("app.services.guarded_test_deployment._require_configured_keyed_source", return_value={
        "root": "/private/pinned-source", "revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
    }), patch("app.services.guarded_test_deployment._required_engagement", return_value=engagement), patch(
        "app.services.guarded_test_deployment._target_for_engagement", return_value=TARGET,
    ), patch("app.services.guarded_test_deployment._validate_guarded_pilot_request"), patch(
        "app.services.guarded_test_deployment._validate_core_recreate_guard",
    ):
        with pytest.raises(DeploymentPlanConflictError):
            start_guarded_pilot_standard_rti_run(
                {"engagementId": engagement_id, "sshSourceCidrs": ["198.51.100.1/32"]},
                repository=SqlAlchemyJobRepository(), prepared_core_run=prepared, core_plan_id=plan_id,
                core_plan_revision_id="revision",
                background_runner=lambda task: called.append(task),
            )
    assert called == []
    assert [row.id for row in SqlAlchemyJobRepository().list_for_engagement(engagement_id)] == ["job-already-reserved"]


@pytest.mark.parametrize("failure_point", ["get", "running_save", "runner"])
def test_post_reservation_failure_keeps_plan_and_lease_fenced(client, tmp_path, failure_point):
    engagement_id = f"eng-keyed-{failure_point}"
    plan_id = f"dpl-keyed-{failure_point}"
    plans = _setup(engagement_id, plan_id)
    prepared = {
        **plans.get(plan_id).evidence,
        "runDirectory": str(tmp_path / "core"),
        "terraformStatePath": str(tmp_path / "core.tfstate"),
        "terraformDataDir": str(tmp_path / "terraform-data"),
        "terraformStateLocator": "private",
    }
    plans.save(replace(plans.get(plan_id), evidence=prepared))
    engagement = SimpleNamespace(
        id=engagement_id, name="Disposable", template_id="standard-rti", input_parameters={},
    )
    launch_calls = []

    class FailingRepository(SqlAlchemyJobRepository):
        def get(self, job_id):
            if failure_point == "get" and job_id.startswith("job-"):
                raise RuntimeError("injected job read failure")
            return super().get(job_id)

        def save(self, job):
            if failure_point == "running_save" and job.status == "running":
                raise RuntimeError("injected running write failure")
            return super().save(job)

    def runner(task):
        launch_calls.append(True)
        raise RuntimeError("injected launch failure")

    with patch("app.services.guarded_test_deployment._require_configured_keyed_source", return_value={
        "root": "/private/pinned-source", "revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
    }), patch("app.services.guarded_test_deployment._required_engagement", return_value=engagement), patch(
        "app.services.guarded_test_deployment._target_for_engagement", return_value=TARGET,
    ), patch("app.services.guarded_test_deployment._validate_guarded_pilot_request"):
        with pytest.raises(RuntimeError):
            start_guarded_pilot_standard_rti_run(
                {"engagementId": engagement_id, "sshSourceCidrs": ["198.51.100.1/32"]},
                repository=FailingRepository(), prepared_core_run=prepared, core_plan_id=plan_id,
                core_plan_revision_id="revision", background_runner=runner,
            )
    current = plans.get(plan_id)
    assert current.status == "reconciliation_required"
    assert current.apply_job_id
    lease = CoreMutationLeaseModel.query.get(engagement_id)
    assert lease is not None and (lease.owner_id, lease.operation) == (plan_id, "apply")
    assert len(SqlAlchemyJobRepository().list_for_engagement(engagement_id)) == 1
    assert launch_calls == ([True] if failure_point == "runner" else [])


def test_two_sqlite_connections_cannot_reserve_two_core_jobs(tmp_path):
    state = db.configure(f"sqlite:///{tmp_path / 'reservation-race.sqlite'}")
    with db.bind(state):
        db.create_all()
        _setup("eng-keyed-race", "dpl-keyed-race")
    barrier = Barrier(2)

    def attempt(job_id):
        with db.bind(state):
            barrier.wait(timeout=5)
            try:
                _reserve(SqlAlchemyDeploymentPlanRepository(),
                         _queued(job_id, "eng-keyed-race", "dpl-keyed-race"))
                return True
            except DeploymentPlanConflictError:
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ("job-race-one", "job-race-two")))
    assert results.count(True) == 1
    with db.bind(state):
        plan = SqlAlchemyDeploymentPlanRepository().get("dpl-keyed-race")
        jobs = SqlAlchemyJobRepository().list_for_engagement("eng-keyed-race")
        assert [job.id for job in jobs] == [plan.apply_job_id]
        assert len(jobs[0].events) == 1


def test_startup_recovery_retains_bound_keyed_apply_fence(client):
    engagement_id, plan_id = "eng-keyed-crash", "dpl-keyed-crash"
    plans = _setup(engagement_id, plan_id)
    job = _queued("job-keyed-crash", engagement_id, plan_id)
    _reserve(plans, job)

    recover_interrupted_core_deployment_plans()

    assert plans.get(plan_id).status == "reconciliation_required"
    assert plans.get(plan_id).apply_job_id == job.id
    lease = CoreMutationLeaseModel.query.get(engagement_id)
    assert lease is not None and (lease.owner_id, lease.operation) == (plan_id, "apply")
    with pytest.raises(DeploymentPlanConflictError):
        plans.acquire(engagement_id, "dpl-next", "apply")


def test_core_success_and_provider_lease_handoff_are_one_transaction(client):
    engagement_id, plan_id = "eng-keyed-success", "dpl-keyed-success"
    plans = _setup(engagement_id, plan_id)
    jobs = SqlAlchemyJobRepository()
    queued = _queued("job-keyed-success", engagement_id, plan_id)
    _reserve(plans, queued)
    running = jobs.save(replace(
        jobs.get(queued.id), status="running", started_at=datetime.now(timezone.utc).isoformat(),
        events=[*queued.events, JobEvent(2, "info", "pilot Standard RTI run started", {})],
    ))
    seal = {"schema": "applied-oci-core-state-v1", "corePlanEvidenceSha256": running.input["corePlanEvidenceSha256"],
            "rawStateSha256": "a" * 64, "inventorySha256": "b" * 64,
            "lineage": "11111111-1111-4111-8111-111111111111", "serial": 1, "resourceCount": 1}
    success = replace(
        running, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
        input={**running.input, "inspectorReadiness": {"ready": True},
               "postCoreSketchContinuationEligible": False,
               "providerKeyedDispatchAuthorized": False},
        events=[*running.events, JobEvent(3, "info", "applied OCI core state sealed", seal),
                JobEvent(4, "info", "pilot Standard RTI run finished", {
            "ok": True, "mutationStatus": "deployed", "ansibleStatus": "validated",
            "finalCleanupStatus": "pending_operator_teardown",
        })],
    )
    with patch("app.storage.deployment_plan_repository._read_keyed_core_state_seal", return_value=seal):
        plans.finish_keyed_core_success(success)
    assert jobs.get(queued.id).status == "succeeded"
    assert plans.get(plan_id).status == "applied"
    lease = CoreMutationLeaseModel.query.get(engagement_id)
    assert lease is not None and lease.operation == "provider_keyed_initial"

    with pytest.raises(DeploymentPlanConflictError):
        plans.finish_keyed_core_success(success)
    assert len(jobs.get(queued.id).events) == 4


def test_rejected_core_success_rolls_back_all_three_rows(client):
    engagement_id, plan_id = "eng-keyed-bad-success", "dpl-keyed-bad-success"
    plans = _setup(engagement_id, plan_id)
    jobs = SqlAlchemyJobRepository()
    queued = _queued("job-keyed-bad-success", engagement_id, plan_id)
    _reserve(plans, queued)
    running = jobs.save(replace(
        jobs.get(queued.id), status="running", started_at=datetime.now(timezone.utc).isoformat(),
        events=[*queued.events, JobEvent(2, "info", "pilot Standard RTI run started", {})],
    ))
    forged = replace(
        running, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
        input={**running.input, "inspectorReadiness": {"ready": True},
               "postCoreSketchContinuationEligible": False,
               "providerKeyedDispatchAuthorized": False},
        events=[*running.events, JobEvent(3, "info", "pilot Standard RTI run finished", {
            "ok": True, "mutationStatus": "partial", "ansibleStatus": "validated",
            "finalCleanupStatus": "pending_operator_teardown",
        })],
    )
    with pytest.raises(DeploymentPlanConflictError):
        plans.finish_keyed_core_success(forged)
    assert jobs.get(queued.id) == running
    assert plans.get(plan_id).status == "applying"
    lease = CoreMutationLeaseModel.query.get(engagement_id)
    assert lease is not None and lease.operation == "apply"
