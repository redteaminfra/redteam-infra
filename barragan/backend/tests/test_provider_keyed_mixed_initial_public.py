# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-cloud checks for the mixed one-Deploy public boundary."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.asgi import _keyed_core_plan_deploy_eligible
from app.core.config import TestConfig
from app.services import core_deployment_plans, guarded_test_deployment
from app.services.provider_keyed_mixed_initial_public import (
    MixedInitialPublicAttention, advance_reviewed_mixed_initial,
    advance_reviewed_mixed_initial_host, advance_reviewed_mixed_initial_proof,
    prove_selector_absent_before_mixed_apply, recover_reviewed_mixed_initial_dispatches,
)
from app.services.provider_keyed_initial_dispatch import recover_fresh_keyed_initial_dispatches
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from dataclasses import replace
from datetime import datetime, timezone
from app.domain import JobEvent
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_coordinator import _inputs
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_initial_bootstrap import _inputs as _bootstrap_inputs
from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
from app.services.provider_keyed_mixed_initial_host_binding import reserve_mixed_initial_host_binding
from app.services.core_deployment_plans import CoreDeploymentPlanError
from app.services.provider_keyed_cleanup_visibility import ProviderKeyedCleanupVisibilityError


class DevTest(TestConfig):
    ENVIRONMENT = "devtest"
    PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = True
    PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "4.2.2.2"


def _plan():
    scopes = [{"provider": provider, "providerConnectionId": f"cred-{provider}"}
              for provider in ("digitalocean", "linode")]
    return SimpleNamespace(
        id="plan-mixed", engagement_id="eng-mixed", revision_id="rev-mixed",
        status="ready", stage="ready", apply_job_id=None,
        evidence={"sketchStateSchema": "provider-keyed-v2",
                  "managedHostImageProfile": "ubuntu-24.04",
                  "target": {"name": "barragan-testing"},
                  "sketchAuthorization": {"kind": "bounded-mixed-post-core-v1",
                                          "providerScopes": scopes},
                  "keyedProviderCredentialSnapshots": {
                      provider: {"encryptedSecretSha256": "a" * 64,
                                 "updatedAt": "2026-10-15T00:00:00+00:00"}
                      for provider in ("digitalocean", "linode")}},
        review={"reviewedConfiguration": {
                    "templateId": "small-dev-infra",
                    "core": {"homebases": 1, "proxies": 1, "elkEnabled": False}},
                "counts": {"add": 4, "replace": 0, "remove": 0}},
    )


def test_mixed_ui_eligibility_is_exact_and_do_only_branch_is_not_used(monkeypatch):
    plan = _plan()
    engagement = SimpleNamespace(sketch_state_schema="provider-keyed-v2",
                                 active_revision=plan.revision_id)
    monkeypatch.setattr("app.asgi.get_engagement", lambda _id: engagement)
    monkeypatch.setattr(guarded_test_deployment, "_target_for_engagement",
                        lambda _engagement: SimpleNamespace(name="barragan-testing"))
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda: {"root": "/approved"})
    monkeypatch.setattr(core_deployment_plans, "_verify_plan_evidence", lambda _plan: None)
    assert _keyed_core_plan_deploy_eligible(DevTest, plan)
    for mutate in (
        lambda row: row.review["reviewedConfiguration"]["core"].update({"proxies": 2}),
        lambda row: row.evidence["keyedProviderCredentialSnapshots"].pop("linode"),
        lambda row: row.evidence["sketchAuthorization"]["providerScopes"][1].update({"provider": "digitalocean"}),
        lambda row: row.review["counts"].update({"replace": 1}),
        lambda row: row.evidence["target"].update({"name": "other"}),
    ):
        altered = deepcopy(plan)
        mutate(altered)
        assert not _keyed_core_plan_deploy_eligible(DevTest, altered)
    assert not _keyed_core_plan_deploy_eligible(
        type("Production", (DevTest,), {"ENVIRONMENT": "production"}), plan)


def test_mixed_dispatch_joins_plans_seal_and_handoff_in_one_call(monkeypatch, tmp_path):
    plan = _plan()
    plan.status = plan.stage = "applied"
    plan.apply_job_id = "job-core"
    pin = {"root": str(tmp_path), "revision": "pinned"}
    core = SimpleNamespace(id="job-core", status="succeeded",
                           action="pilot_standard_rti_guarded_execute",
                           events=[SimpleNamespace(message="pilot Standard RTI run finished",
                               data={"ok": True, "mutationStatus": "deployed",
                                     "ansibleStatus": "validated",
                                     "finalCleanupStatus": "pending_operator_teardown"})],
                           input={"engagementId": "eng-mixed", "corePlanId": plan.id,
                                  "sketchStateSchema": "provider-keyed-v2",
                                  "providerKeyedDispatchAuthorized": True,
                                  "providerKeyedSourcePin": pin})
    jobs = SimpleNamespace(get=lambda job_id: core if job_id == core.id else None)
    plans = SimpleNamespace(get=lambda plan_id: plan if plan_id == plan.id else None)
    monkeypatch.setattr("app.services.provider_keyed_runtime_preflight._db_lease_lookup",
                        lambda _id: (plan.id, "provider_keyed_initial"))
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda supplied: supplied)
    monkeypatch.setattr("app.services.provider_keyed_mixed_initial_public._default_state_root",
                        lambda: tmp_path)
    material = SimpleNamespace(private_key="private", public_key="public")
    monkeypatch.setattr("app.services.provider_keyed_mixed_initial_public.retrieve_sketch_ssh_key",
                        lambda _id: material)
    monkeypatch.setattr("app.services.provider_keyed_mixed_initial_public.retrieve_sketch_transport_ssh_key",
                        lambda _id: material)
    calls = []

    def prepare(core_id, **kwargs):
        calls.append(("prepare", core_id, kwargs["lease_owner"]))

    def seal(core_id, **kwargs):
        calls.append(("seal", core_id, kwargs["lease_owner"]))

    def continue_deploy(engagement_id, core_id, **kwargs):
        calls.append(("continue", core_id, kwargs["selector_absence_prover"] is not None))
        assert engagement_id == "eng-mixed"
        return "awaiting_mixed_host_proof"

    assert advance_reviewed_mixed_initial(
        core.id, environment="devtest", rollout_enabled=True,
        job_repository=jobs, plan_repository=plans,
        plan_builder=prepare, seal_builder=seal, continuation=continue_deploy,
        host_continuation=lambda core_id, **_kw: calls.append(("host", core_id)) or "bootstrapped",
    ) == "bootstrapped"
    assert calls == [("prepare", core.id, plan.id),
                     ("seal", core.id, plan.id), ("continue", core.id, True),
                     ("host", core.id)]
    calls.clear()
    handoff = SimpleNamespace(input={"phase": "awaiting_mixed_host_proof"})
    jobs.get = lambda job_id: core if job_id == core.id else (
        handoff if job_id == "job-provider-keyed-mixed-initial-core" else None)
    assert advance_reviewed_mixed_initial(
        core.id, environment="devtest", rollout_enabled=True,
        job_repository=jobs, plan_repository=plans,
        plan_builder=prepare, seal_builder=seal, continuation=continue_deploy,
        host_continuation=lambda core_id, **_kw: calls.append(("host", core_id)) or "bootstrapped",
    ) == "bootstrapped"
    assert calls == [("host", core.id)]
    calls.clear()
    core.events[0].data["ansibleStatus"] = "failed"
    with pytest.raises(MixedInitialPublicAttention):
        advance_reviewed_mixed_initial(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            plan_builder=prepare, seal_builder=seal, continuation=continue_deploy)
    assert calls == []


@pytest.mark.parametrize("preadmin", [False, True], ids=["both-missing", "transport-missing"])
def test_persisted_mixed_handoff_creates_and_reuses_both_keys_before_planning(
        ready, tmp_path, monkeypatch, preadmin):
    """A fresh mixed core gets durable keys once, in either reviewed order."""
    from app.services import provider_keyed_mixed_initial_public as public
    from app.services import sketch_ssh_keys, sketch_transport_ssh_keys
    from app.services.sketch_ssh_keys import ensure_sketch_ssh_key
    from app.services.credentials import test_master_key
    from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository
    from app.storage.sketch_transport_ssh_key_repository import SqlAlchemySketchTransportSshKeyRepository

    original = ready.case.records["core_job"]
    now = datetime.now(timezone.utc).isoformat()
    core = replace(original, created_at=now, started_at=now, finished_at=now,
        input={**original.input, "providerKeyedDispatchAuthorized": True,
               "providerKeyedSourcePin": {"root": str(ready.case.state_root),
                                          "revision": "fixture"}},
        events=[*original.events, JobEvent(len(original.events) + 1, "info",
            "pilot Standard RTI run finished", {
                "ok": True, "mutationStatus": "deployed", "ansibleStatus": "validated",
                "finalCleanupStatus": "pending_operator_teardown"})])
    plan = replace(ready.case.records["core_plan"], stage="applied")
    state = db.configure(f"sqlite:///{tmp_path / 'mixed-key-handoff.sqlite'}")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        jobs.save(core)
        plans.save(plan)
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-1",
            operation="provider_keyed_initial"))
        db.session.commit()
        monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", test_master_key())
        engagement = SimpleNamespace(name="opaque")
        monkeypatch.setattr(sketch_ssh_keys, "get_engagement", lambda _id: engagement)
        monkeypatch.setattr(sketch_transport_ssh_keys, "get_engagement", lambda _id: engagement)
        monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                            lambda pin: pin)
        monkeypatch.setattr(public, "_default_state_root", lambda: ready.case.state_root)
        admin_repo = SqlAlchemySketchSshKeyRepository()
        transport_repo = SqlAlchemySketchTransportSshKeyRepository()
        if preadmin:
            ensure_sketch_ssh_key("eng-opaque")
        initial_admin = admin_repo.get("eng-opaque")
        assert (initial_admin is not None) is preadmin
        assert transport_repo.get("eng-opaque") is None
        calls = []

        def prepare(_core_id, **_kwargs):
            admin = admin_repo.get("eng-opaque")
            transport = transport_repo.get("eng-opaque")
            assert admin is not None and transport is not None
            calls.append((admin.fingerprint, transport.fingerprint))

        def finish(_core_id, **_kwargs):
            return "handoff"

        kwargs = dict(environment="devtest", rollout_enabled=True,
                      job_repository=jobs, plan_repository=plans,
                      plan_builder=prepare, seal_builder=finish,
                      continuation=lambda *_a, **_kw: "handoff",
                      host_continuation=finish)
        assert advance_reviewed_mixed_initial(core.id, **kwargs) == "handoff"
        first = calls[-1]
        assert first[0] != first[1]
        if initial_admin is not None:
            assert first[0] == initial_admin.fingerprint
        assert advance_reviewed_mixed_initial(core.id, **kwargs) == "handoff"
        assert calls == [first, first]
        assert admin_repo.get("eng-opaque").fingerprint == first[0]
        assert transport_repo.get("eng-opaque").fingerprint == first[1]


def test_mixed_key_creation_stops_on_source_or_lease_drift(monkeypatch, tmp_path):
    from app.services import provider_keyed_mixed_initial_public as public

    plan = _plan()
    plan.status = plan.stage = "applied"
    plan.apply_job_id = "job-core"
    pin = {"root": str(tmp_path), "revision": "pinned"}
    core = SimpleNamespace(id="job-core", status="succeeded",
        action="pilot_standard_rti_guarded_execute",
        input={"engagementId": "eng-mixed", "corePlanId": plan.id,
               "sketchStateSchema": "provider-keyed-v2",
               "providerKeyedDispatchAuthorized": True, "providerKeyedSourcePin": pin},
        events=[SimpleNamespace(message="pilot Standard RTI run finished",
            data={"ok": True, "mutationStatus": "deployed", "ansibleStatus": "validated",
                  "finalCleanupStatus": "pending_operator_teardown"})])
    jobs = SimpleNamespace(get=lambda job_id: core if job_id == core.id else None)
    plans = SimpleNamespace(get=lambda _id: plan)
    lease = {"value": (plan.id, "provider_keyed_initial")}
    monkeypatch.setattr("app.services.provider_keyed_runtime_preflight._db_lease_lookup",
                        lambda _id: lease["value"])
    source = {"value": pin}
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda _pin: source["value"])
    created = []
    monkeypatch.setattr(public, "ensure_sketch_ssh_key", lambda _id: created.append("admin"))
    monkeypatch.setattr(public, "ensure_sketch_transport_ssh_key",
                        lambda _id: created.append("transport"))
    monkeypatch.setattr(public, "retrieve_sketch_ssh_key", lambda _id: None)
    monkeypatch.setattr(public, "retrieve_sketch_transport_ssh_key", lambda _id: None)
    source["value"] = {"root": "/changed", "revision": "pinned"}
    with pytest.raises(MixedInitialPublicAttention, match="source pin differs"):
        advance_reviewed_mixed_initial(core.id, environment="devtest", rollout_enabled=True,
                                       job_repository=jobs, plan_repository=plans)
    assert created == []
    source["value"] = pin
    lease["value"] = (plan.id, "provider_keyed_teardown_fence")
    with pytest.raises(MixedInitialPublicAttention, match="core or lease differs"):
        advance_reviewed_mixed_initial(core.id, environment="devtest", rollout_enabled=True,
                                       job_repository=jobs, plan_repository=plans)
    assert created == []


def test_handoff_reserves_binding_then_bootstraps_with_pinned_source(monkeypatch, tmp_path):
    plan = _plan()
    plan.status = plan.stage = "applied"
    plan.apply_job_id = "job-core"
    pin = {"root": str(tmp_path), "revision": "pinned"}
    core = SimpleNamespace(
        id="job-core", action="pilot_standard_rti_guarded_execute", status="succeeded",
        input={"engagementId": "eng-mixed", "corePlanId": plan.id,
               "sketchStateSchema": "provider-keyed-v2",
               "providerKeyedDispatchAuthorized": True, "providerKeyedSourcePin": pin},
        events=[SimpleNamespace(message="pilot Standard RTI run finished",
                                data={"ok": True, "mutationStatus": "deployed",
                                      "ansibleStatus": "validated",
                                      "finalCleanupStatus": "pending_operator_teardown"})],
    )
    parent = SimpleNamespace(
        action="provider_keyed_mixed_initial", target_id="eng-mixed",
        status="running", finished_at=None,
        input={"engagementId": "eng-mixed", "coreJobId": core.id,
               "corePlanId": plan.id, "phase": "awaiting_mixed_host_proof"},
    )
    rows = {core.id: core, "job-provider-keyed-mixed-initial-core": parent}
    jobs = SimpleNamespace(get=rows.get)
    plans = SimpleNamespace(get=lambda plan_id: plan if plan_id == plan.id else None)
    monkeypatch.setattr("app.services.provider_keyed_runtime_preflight._db_lease_lookup",
                        lambda _id: (plan.id, "provider_keyed_initial"))
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda supplied: supplied)
    monkeypatch.setattr("app.services.provider_keyed_mixed_initial_public.barragan_subprocess_env",
                        lambda: {"ORIGINAL": "yes"})
    calls = []
    observer = lambda *_args: None

    def reserve(engagement_id, core_id, **kwargs):
        calls.append(("binding", engagement_id, core_id, kwargs["fresh_observer"]))

    def bootstrap(engagement_id, core_id, **kwargs):
        calls.append(("bootstrap", engagement_id, core_id, kwargs["fresh_observer"]))
        assert kwargs["bootstrap_env"]["ORIGINAL"] == "yes"
        assert kwargs["bootstrap_env"]["BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT"] == pin["root"]
        return "bootstrap-worker"

    assert advance_reviewed_mixed_initial_host(
        core.id, environment="devtest", rollout_enabled=True,
        job_repository=jobs, plan_repository=plans, fresh_observer=observer,
        binding_reserver=reserve, bootstrap_runner=bootstrap) == "bootstrap-worker"
    assert calls == [("binding", "eng-mixed", core.id, observer),
                     ("bootstrap", "eng-mixed", core.id, observer)]
    rows["job-provider-keyed-mixed-host-worker-core"] = object()
    with pytest.raises(MixedInitialPublicAttention, match="no host command may be replayed"):
        advance_reviewed_mixed_initial_host(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans, fresh_observer=observer,
            binding_reserver=reserve, bootstrap_runner=bootstrap)
    assert len(calls) == 2
    rows.pop("job-provider-keyed-mixed-host-worker-core")
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda _supplied: {"root": "/different", "revision": "pinned"})
    with pytest.raises(MixedInitialPublicAttention, match="source pin differs"):
        advance_reviewed_mixed_initial_host(
            core.id, environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans, fresh_observer=observer,
            binding_reserver=reserve, bootstrap_runner=bootstrap)
    assert len(calls) == 2


def test_startup_routes_mixed_only_to_mixed_recovery(monkeypatch):
    row = _plan()
    row.status = row.stage = "applied"
    row.apply_job_id = "job-core"
    core = SimpleNamespace(status="succeeded", input={"providerKeyedDispatchAuthorized": True})

    class Query:
        def filter_by(self, **_kwargs):
            return self

        def all(self):
            return [row]

    monkeypatch.setattr("app.storage.models.DeploymentPlanModel",
                        SimpleNamespace(query=Query()))
    held = {"value": (row.id, "provider_keyed_initial")}
    parent = {"value": None}
    worker = {"value": None}
    jobs = SimpleNamespace(get=lambda job_id: (
        core if job_id == "job-core" else
        worker["value"] if job_id == "job-provider-keyed-mixed-host-worker-core" else
        parent["value"] if job_id == "job-provider-keyed-mixed-initial-core" else None))
    monkeypatch.setattr("app.services.provider_keyed_initial_dispatch.SqlAlchemyJobRepository",
                        lambda: jobs)
    monkeypatch.setattr("app.services.provider_keyed_mixed_initial_public.SqlAlchemyJobRepository",
                        lambda: jobs)
    monkeypatch.setattr("app.services.provider_keyed_runtime_preflight._db_lease_lookup",
                        lambda _id: held["value"])
    core.input.update({"engagementId": row.engagement_id, "corePlanId": row.id})
    old_tasks, mixed_tasks = [], []
    assert recover_fresh_keyed_initial_dispatches(
        environment="devtest", rollout_enabled=True,
        schedule=old_tasks.append) == []
    assert recover_reviewed_mixed_initial_dispatches(
        environment="devtest", rollout_enabled=True,
        schedule=mixed_tasks.append) == ["job-core"]
    assert old_tasks == [] and len(mixed_tasks) == 1
    parent["value"] = SimpleNamespace(action="provider_keyed_mixed_initial",
        target=f"engagement:{row.engagement_id}", target_type="engagement",
        target_id=row.engagement_id, input={"engagementId": row.engagement_id,
                                             "coreJobId": "job-core", "corePlanId": row.id,
                                             "phase": "awaiting_mixed_host_proof"},
        status="running", finished_at=None)
    assert recover_reviewed_mixed_initial_dispatches(
        environment="devtest", rollout_enabled=True, schedule=mixed_tasks.append) == ["job-core"]
    worker["value"] = object()
    assert recover_reviewed_mixed_initial_dispatches(
        environment="devtest", rollout_enabled=True, schedule=mixed_tasks.append) == []
    worker["value"] = SimpleNamespace(status="succeeded", finished_at="2026-10-19T00:00:00+00:00")
    assert recover_reviewed_mixed_initial_dispatches(
        environment="devtest", rollout_enabled=True, schedule=mixed_tasks.append) == ["job-core"]
    assert len(mixed_tasks) == 3
    original_get = jobs.get
    jobs.get = lambda job_id: object() if job_id == "job-provider-keyed-mixed-strict-host-proof-core" else original_get(job_id)
    assert recover_reviewed_mixed_initial_dispatches(
        environment="devtest", rollout_enabled=True, schedule=mixed_tasks.append) == []
    jobs.get = original_get
    worker["value"] = None
    parent["value"].input["phase"] = "apply_sealed"
    held["value"] = (row.id, "provider_keyed_teardown_fence")
    assert recover_reviewed_mixed_initial_dispatches(
        environment="devtest", rollout_enabled=True, schedule=mixed_tasks.append) == []
    held["value"] = (row.id, "provider_keyed_initial")
    assert recover_reviewed_mixed_initial_dispatches(
        environment="devtest", rollout_enabled=True,
        schedule=mixed_tasks.append) == ["job-core"]


def test_completed_bootstrap_continues_to_proof_without_second_deploy(monkeypatch, tmp_path):
    plan = _plan()
    plan.status = plan.stage = "applied"
    plan.apply_job_id = "job-core"
    core = SimpleNamespace(
        id="job-core", status="succeeded", action="pilot_standard_rti_guarded_execute",
        input={"engagementId": "eng-mixed", "corePlanId": plan.id,
               "providerKeyedDispatchAuthorized": True,
               "sketchStateSchema": "provider-keyed-v2",
               "providerKeyedSourcePin": {"root": str(tmp_path), "revision": "pinned"}},
        events=[SimpleNamespace(message="pilot Standard RTI run finished", data={
            "ok": True, "mutationStatus": "deployed", "ansibleStatus": "validated",
            "finalCleanupStatus": "pending_operator_teardown"})],
    )
    parent = SimpleNamespace(
        action="provider_keyed_mixed_initial", status="running", finished_at=None,
        target_id="eng-mixed", input={"phase": "awaiting_mixed_host_proof",
            "engagementId": "eng-mixed", "coreJobId": core.id, "corePlanId": plan.id},
    )
    worker = SimpleNamespace(status="succeeded", finished_at="2026-10-19T00:00:00+00:00")
    rows = {core.id: core, "job-provider-keyed-mixed-initial-core": parent}
    jobs = SimpleNamespace(get=rows.get)
    plans = SimpleNamespace(get=lambda plan_id: plan if plan_id == plan.id else None)
    monkeypatch.setattr("app.services.provider_keyed_runtime_preflight._db_lease_lookup",
                        lambda _id: (plan.id, "provider_keyed_initial"))
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda supplied: supplied)
    calls = []

    def prove(engagement_id, core_id, **_kwargs):
        calls.append((engagement_id, core_id))
        return "published"

    def bootstrap(*_args, **_kwargs):
        rows["job-provider-keyed-mixed-host-worker-core"] = worker
        return worker

    assert advance_reviewed_mixed_initial(
        core.id, environment="devtest", rollout_enabled=True,
        job_repository=jobs, plan_repository=plans,
        host_continuation=bootstrap,
        proof_continuation=lambda *args, **kwargs:
            advance_reviewed_mixed_initial_proof(*args, **kwargs, proof_runner=prove)) == "published"
    assert advance_reviewed_mixed_initial_proof(
        core.id, environment="devtest", rollout_enabled=True,
        job_repository=jobs, plan_repository=plans, proof_runner=prove) == "published"
    assert advance_reviewed_mixed_initial(
        core.id, environment="devtest", rollout_enabled=True,
        job_repository=jobs, plan_repository=plans, proof_continuation=lambda *args, **kwargs:
            advance_reviewed_mixed_initial_proof(*args, **kwargs, proof_runner=prove)) == "published"
    assert calls == [("eng-mixed", core.id)] * 3


def test_sqlalchemy_core_completion_two_children_handoff_and_startup_no_replay(
        ready, tmp_path, monkeypatch):
    """Persist public dispatch evidence; all provider/OCI boundaries are fixtures."""
    from app.services import provider_keyed_mixed_initial_public as public
    from app.services import provider_keyed_mixed_initial_deploy_continuation as private
    from app.services.credentials import test_master_key
    from app.storage.engagement_repository import SqlAlchemyEngagementRepository
    from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository
    from app.storage.sketch_transport_ssh_key_repository import SqlAlchemySketchTransportSshKeyRepository

    _core, children, _fresh, _ = _inputs(ready)
    original = ready.case.records["core_job"]
    at = datetime.now(timezone.utc).isoformat()
    core = replace(original,
        created_at=at, started_at=at, finished_at=at,
        input={**original.input, "providerKeyedDispatchAuthorized": True,
               "providerKeyedSourcePin": {"root": str(ready.case.state_root),
                                          "revision": "fixture"}},
        events=[*original.events, JobEvent(2, "info", "pilot Standard RTI run finished", {
            "ok": True, "mutationStatus": "deployed", "ansibleStatus": "validated",
            "finalCleanupStatus": "pending_operator_teardown"})])
    plan = replace(ready.case.records["core_plan"], stage="applied")
    state = db.configure(f"sqlite:///{tmp_path / 'mixed-public.sqlite'}")
    with db.bind(state):
        db.create_all()
        SqlAlchemyEngagementRepository().save(ready.case.records["engagement"])
        monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", test_master_key())
        plans = SqlAlchemyDeploymentPlanRepository()
        plans.save(plan)
        jobs = SqlAlchemyJobRepository()
        jobs.save(core)
        jobs.save(ready.parent)
        for child in children.values():
            jobs.save(child)
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-1",
            operation="provider_keyed_initial"))
        db.session.commit()
        monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                            lambda pin: pin)
        monkeypatch.setattr(public, "_default_state_root", lambda: ready.case.state_root)
        monkeypatch.setattr(public, "prepare_or_reuse_mixed_initial_plans",
                            lambda *_a, **_kw: jobs.get(ready.parent.id))
        monkeypatch.setattr(public, "seal_mixed_initial_apply",
                            lambda *_a, **_kw: jobs.get(ready.parent.id))
        def continue_to_handoff(engagement_id, core_id, **kwargs):
            first_provider = ready.parent.input["orderedProviders"][0]
            proof = children[first_provider].events[-2].data
            def first_fresh(_parent, _child, fence):
                fence()
                return ProviderApplyClassification(
                    first_provider, "full", proof["stateSha256"],
                    proof["lineage"], proof["serial"],
                    tuple(proof["resourceIds"].items()))
            return private.advance_mixed_initial_deploy_to_host_proof(
                engagement_id, core_id, **kwargs,
                fresh_first_prover=first_fresh,
                apply_runner=lambda *_a, **_kw: pytest.fail("provider Apply replayed"),
                proof_finisher=lambda *_a, **_kw: pytest.fail("proof replayed"))
        monkeypatch.setattr(public, "advance_mixed_initial_deploy_to_host_proof",
                            continue_to_handoff)
        host_calls = []
        def reserve_host_once(*_args, **_kwargs):
            host_calls.append("host")
            jobs.save(replace(core, id="job-provider-keyed-mixed-host-worker-core",
                              action="provider_keyed_mixed_initial_host_worker",
                              status="queued", finished_at=None, events=[]))
        monkeypatch.setattr(public, "advance_reviewed_mixed_initial_host", reserve_host_once)
        startup_tasks = []
        assert recover_reviewed_mixed_initial_dispatches(
            environment="devtest", rollout_enabled=True,
            schedule=startup_tasks.append) == [core.id]
        guarded_test_deployment._route_keyed_core_after_success(core)
        admin = SqlAlchemySketchSshKeyRepository().get("eng-opaque")
        transport = SqlAlchemySketchTransportSshKeyRepository().get("eng-opaque")
        assert admin is not None and transport is not None
        assert admin.fingerprint != transport.fingerprint
        checkpoint = jobs.get(ready.parent.id)
        assert checkpoint.input["phase"] == "awaiting_mixed_host_proof"
        assert host_calls == ["host"]
        assert len(checkpoint.events) == 7
        assert {row.status for row in (jobs.get(child.id) for child in children.values())} == {"succeeded"}
        # The startup worker was queued concurrently with core completion. It
        # sees the terminal checkpoint and cannot create another provider intent.
        with pytest.raises(MixedInitialPublicAttention, match="no host command may be replayed"):
            startup_tasks[0]()
        assert SqlAlchemySketchSshKeyRepository().get("eng-opaque").fingerprint == admin.fingerprint
        assert SqlAlchemySketchTransportSshKeyRepository().get("eng-opaque").fingerprint == transport.fingerprint
        assert host_calls == ["host"]
        assert jobs.get(ready.parent.id) == checkpoint
        assert recover_reviewed_mixed_initial_dispatches(
            environment="devtest", rollout_enabled=True,
            schedule=startup_tasks.append) == []


@pytest.mark.parametrize("timing_receipt", [False, True], ids=["interim-audit", "timing-audit"])
@pytest.mark.parametrize("prebind", [False, True], ids=["fresh-binding", "restart-after-binding"])
def test_sqlalchemy_handoff_reuses_inert_binding_and_runs_one_claimed_bootstrap(
        ready, tmp_path, monkeypatch, prebind, timing_receipt):
    """Both reviewed orders cross the public handoff without any real host contact."""
    from app.services import provider_keyed_mixed_initial_public as public

    checkpoint, _binding, args, calls, _state = _bootstrap_inputs(ready, tmp_path)
    original = ready.case.jobs.get("job-core")
    now = datetime.now(timezone.utc).isoformat()
    core = replace(original,
        created_at=now, started_at=now,
        input={**original.input, "providerKeyedDispatchAuthorized": True,
               "providerKeyedSourcePin": {
                   "root": str(ready.case.args["template_root"]), "revision": "fixture"}},
        events=[*original.events, JobEvent(len(original.events) + 1, "info",
            "pilot Standard RTI run finished", {
                "ok": True, "mutationStatus": "deployed", "ansibleStatus": "validated",
                "finalCleanupStatus": "pending_operator_teardown"})],
        finished_at=now)
    plan = replace(ready.case.records["core_plan"], stage="applied")
    state = db.configure(f"sqlite:///{tmp_path / 'mixed-host-public.sqlite'}")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        plans = SqlAlchemyDeploymentPlanRepository()
        sketches = SqlAlchemySketchChainRepository()
        plans.save(plan)
        jobs.save(core)
        jobs.save(checkpoint)
        for provider in checkpoint.input["orderedProviders"]:
            child_id = f"job-provider-keyed-mixed-initial-apply-{provider}-core"
            jobs.save(ready.case.jobs.get(child_id))
        for chain in ready.case.records["chains"]:
            sketches.save(chain)
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-1",
            operation="provider_keyed_initial"))
        db.session.commit()
        monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                            lambda pin: pin)
        observer = args["fresh_observer"]

        def reserve(*call_args, **kwargs):
            return reserve_mixed_initial_host_binding(
                *call_args, **kwargs, sketch_repository=sketches)

        gate = args["gated_command_runner"]
        def receipt_gate(command, **kwargs):
            callback = kwargs["result_callback"]
            if not timing_receipt:
                kwargs["result_callback"] = lambda value: callback(replace(
                    value, execution_timeout_seconds=None, command_elapsed_seconds=None))
            return gate(command, **kwargs)

        def bootstrap(*call_args, **kwargs):
            return run_mixed_initial_bootstrap(
                *call_args, **kwargs, sketch_repository=sketches,
                bootstrap_helper=args["bootstrap_helper"],
                gated_command_runner=receipt_gate,
                source_verifier=args["source_verifier"],
                core_known_hosts_reader=args["core_known_hosts_reader"],
                sketch_known_hosts_initializer=args["sketch_known_hosts_initializer"])

        # Both a fresh handoff and a restart after an inert reservation reach
        # the same one-shot worker without contacting a real host.
        if prebind:
            reserve("eng-opaque", "job-core", environment="devtest",
                    fresh_observer=observer, job_repository=jobs)
        finished = advance_reviewed_mixed_initial_host(
            "job-core", environment="devtest", rollout_enabled=True,
            job_repository=jobs, plan_repository=plans,
            fresh_observer=observer, binding_reserver=reserve,
            bootstrap_runner=bootstrap)
        assert finished.status == "succeeded"
        assert jobs.get("job-provider-keyed-mixed-host-binding-core").status == "queued"
        assert [value for kind, value in calls if kind == "chain"] == checkpoint.input["orderedProviders"]
        assert len([value for kind, value in calls if kind == "intent"]) == 8
        assert jobs.get(finished.id).events == finished.events
        with pytest.raises(MixedInitialPublicAttention, match="no host command may be replayed"):
            advance_reviewed_mixed_initial_host(
                "job-core", environment="devtest", rollout_enabled=True,
                job_repository=jobs, plan_repository=plans,
                fresh_observer=observer, binding_reserver=reserve,
                bootstrap_runner=bootstrap)
        assert len([value for kind, value in calls if kind == "intent"]) == 8


def test_mixed_core_starter_preflights_do_scope_before_reserving(monkeypatch):
    plan = _plan()
    plan.evidence["sshSourceCidrs"] = ["203.0.113.0/24"]
    plan.evidence["sketchAuthorization"]["providerScopes"][0]["chain"] = {
        "middle": {"region": "sfo3", "size": "s-1vcpu-1gb"},
        "edges": [{"region": "nyc3", "size": "s-1vcpu-1gb"}],
    }
    engagement = SimpleNamespace(sketch_state_schema="provider-keyed-v2",
                                 active_revision=plan.revision_id)
    reserved = []

    class Plans:
        def begin_private_keyed_core_apply(self, row):
            reserved.append(row.id)

        def get(self, _id):
            return plan

    monkeypatch.setattr(core_deployment_plans, "runtime_value",
                        lambda key, default=None: "devtest" if key == "ENVIRONMENT" else "4.2.2.2")
    monkeypatch.setattr(core_deployment_plans, "get_engagement", lambda _id: engagement)
    monkeypatch.setattr(core_deployment_plans, "get_core_deployment_plan", lambda *_args, **_kw: plan)
    monkeypatch.setattr(core_deployment_plans, "_verify_plan_evidence", lambda _plan: None)
    monkeypatch.setattr(core_deployment_plans, "SqlAlchemyDeploymentPlanRepository", Plans)
    monkeypatch.setattr(guarded_test_deployment, "_target_for_engagement",
                        lambda _engagement: SimpleNamespace(name="barragan-testing"))
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda: {"root": "/approved"})
    monkeypatch.setattr(guarded_test_deployment, "start_guarded_pilot_standard_rti_run",
                        lambda *_args, **_kw: "core-worker")
    monkeypatch.setattr("app.services.engagement_teardown.assert_core_creation_allowed",
                        lambda _id: None)
    monkeypatch.setattr("app.services.provider_keyed_saved_plan_runner._credential_snapshot",
                        lambda _id, _repo: ("a" * 64, "2026-10-15T00:00:00+00:00", "encrypted"))
    monkeypatch.setattr("app.services.credentials.decrypt_secret_value", lambda _secret: "token")
    observed = []
    monkeypatch.setattr("app.services.provider_keyed_cleanup_visibility.require_digitalocean_cleanup_visibility",
                        lambda connection, snapshot, **_kw:
                        observed.append((connection, snapshot)) or ("droplets",))
    monkeypatch.setattr("app.services.provider_catalog.require_selected_digitalocean_region_sizes",
                        lambda token, selections, **_kw:
                        observed.append((token, selections)))
    returned_plan, worker = core_deployment_plans._begin_private_devtest_keyed_core_plan_apply(
        plan.engagement_id, plan.id)
    assert returned_plan is plan and worker == "core-worker"
    assert reserved == [plan.id]
    assert observed[0][0] == "cred-digitalocean"
    assert observed[1] == ("token", [("sfo3", "s-1vcpu-1gb"),
                                     ("nyc3", "s-1vcpu-1gb")])

    reserved.clear()
    monkeypatch.setattr("app.services.provider_keyed_cleanup_visibility.require_digitalocean_cleanup_visibility",
                        lambda *_args, **_kw: (_ for _ in ()).throw(
                            ProviderKeyedCleanupVisibilityError("unavailable")))
    with pytest.raises(CoreDeploymentPlanError):
        core_deployment_plans._begin_private_devtest_keyed_core_plan_apply(
            plan.engagement_id, plan.id)
    assert reserved == []


def _page(key, rows):
    return {key: rows, "meta": {"total": len(rows)}, "links": {"pages": {}}}


def test_selector_absence_uses_fenced_complete_gets_and_never_posts():
    class Catalog:
        def __init__(self):
            self.paths = []

        def request(self, _origin, method, path, token):
            assert method == "GET" and token == "ephemeral-token"
            self.paths.append(path)
            key = path.split("?", 1)[0].removeprefix("/")
            return _page(key, [])

    source = SimpleNamespace(selector_tag="barragan-selector-abc",
                             selector_token="ephemeral-token",
                             receipt_sha256="a" * 64, plan_sha256="b" * 64)
    catalog = Catalog()
    renewals = []
    digest = prove_selector_absent_before_mixed_apply(
        source, lambda: renewals.append(True), transport=catalog)
    assert len(digest) == 64
    assert len(catalog.paths) == 5
    assert len(renewals) >= 2 * len(catalog.paths)
    assert any("type=gpus" in path for path in catalog.paths)


@pytest.mark.parametrize("key,rows", [
    ("tags", [{"name": "BARRAGAN-SELECTOR-ABC"}]),
    ("droplets", [{"id": 17, "tags": ["barragan-selector-abc"]}]),
    ("firewalls", [{"id": "fw", "tags": ["barragan-selector-abc"],
                    "inbound_rules": [], "outbound_rules": []}]),
])
def test_selector_occupied_blocks_before_post(key, rows):
    class Catalog:
        def request(self, _origin, _method, path, _token):
            kind = path.split("?", 1)[0].removeprefix("/")
            return _page(kind, rows if kind == key else [])

    source = SimpleNamespace(selector_tag="barragan-selector-abc",
                             selector_token="ephemeral-token",
                             receipt_sha256="a" * 64, plan_sha256="b" * 64)
    with pytest.raises(MixedInitialPublicAttention, match="absence is unproved"):
        prove_selector_absent_before_mixed_apply(source, lambda: None, transport=Catalog())


def test_selector_second_page_and_firewall_rule_are_checked():
    class Catalog:
        def __init__(self, *, rule=False):
            self.rule = rule
            self.paths = []

        def request(self, _origin, _method, path, _token):
            self.paths.append(path)
            if path == "/tags?page=1&per_page=200":
                return {"tags": [{"name": "other"}], "meta": {"total": 2},
                        "links": {"pages": {"next":
                            "https://api.digitalocean.com/v2/tags?page=2&per_page=200"}}}
            if path == "/tags?page=2&per_page=200":
                return {"tags": [{"name": "BARRAGAN-SELECTOR-ABC"}],
                        "meta": {"total": 2}, "links": {"pages": {}}}
            kind = path.split("?", 1)[0].removeprefix("/")
            if self.rule and kind == "firewalls":
                return _page("firewalls", [{"id": "fw", "tags": [],
                    "inbound_rules": [{"sources": {"tags": ["barragan-selector-abc"]}}],
                    "outbound_rules": []}])
            return _page(kind, [])

    source = SimpleNamespace(selector_tag="barragan-selector-abc",
                             selector_token="ephemeral-token",
                             receipt_sha256="a" * 64, plan_sha256="b" * 64)
    catalog = Catalog()
    with pytest.raises(MixedInitialPublicAttention, match="absence is unproved"):
        prove_selector_absent_before_mixed_apply(source, lambda: None, transport=catalog)
    assert "/tags?page=2&per_page=200" in catalog.paths

    class RuleCatalog(Catalog):
        def request(self, origin, method, path, token):
            if path.startswith("/tags?"):
                return _page("tags", [])
            return super().request(origin, method, path, token)

    with pytest.raises(MixedInitialPublicAttention, match="absence is unproved"):
        prove_selector_absent_before_mixed_apply(source, lambda: None,
                                                transport=RuleCatalog(rule=True))
