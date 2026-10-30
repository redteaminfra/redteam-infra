# Copyright (c) 2026, Oracle and/or its affiliates.
"""The normal reviewed Deploy route opens only for the disposable keyed diagnostic."""

from copy import deepcopy
from types import SimpleNamespace

from app.asgi import _keyed_core_plan_deploy_eligible, create_app
from app.core.config import TestConfig
from app.services import core_deployment_plans, guarded_test_deployment
from app.core.runtime import runtime_context
from app.storage.job_repository import SqlAlchemyJobRepository


def _plan():
    authorization = {
        "provider": "digitalocean", "providerConnectionId": "credential-selected",
        "source": {"revision": "pinned-revision", "templateSha256": "a" * 64},
        "chains": [
            {"middle": {"provider": "digitalocean"},
             "edges": [{"provider": "digitalocean"}]},
            {"middle": {"provider": "digitalocean"},
             "edges": [{"provider": "digitalocean"}]},
        ],
    }
    return SimpleNamespace(
        id="plan-disposable", engagement_id="eng-disposable", revision_id="revision-current",
        status="ready", stage="ready", apply_job_id=None,
        evidence={
            "sketchStateSchema": "provider-keyed-v2", "managedHostImageProfile": "ubuntu-24.04",
            "sketchAuthorization": authorization,
            "keyedProviderCredentialSnapshot": {"encryptedSecretSha256": "b" * 64,
                                                 "updatedAt": "2026-10-10T00:00:00+00:00"},
            "target": {"name": "barragan-testing"},
        },
        review={"postCoreScope": {"chainCount": 2},
                "counts": {"add": 4, "update": 0, "replace": 0, "remove": 0}},
        to_dict=lambda: {"id": "plan-disposable", "status": "ready"},
    )


def test_keyed_readiness_requires_exact_devtest_plan_and_server_control(monkeypatch):
    class DevTest(TestConfig):
        ENVIRONMENT = "devtest"
        PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = True
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "4.2.2.2"

    plan = _plan()
    engagement = SimpleNamespace(sketch_state_schema="provider-keyed-v2",
                                 active_revision=plan.revision_id)
    monkeypatch.setattr("app.asgi.get_engagement", lambda _id: engagement)
    monkeypatch.setattr(guarded_test_deployment, "_target_for_engagement",
                        lambda _engagement: SimpleNamespace(name="barragan-testing"))
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda: {"revision": "pinned-revision", "templateSha256": "a" * 64})
    monkeypatch.setattr(core_deployment_plans, "_verify_plan_evidence", lambda _plan: None)

    assert _keyed_core_plan_deploy_eligible(DevTest, plan)
    for config_change in (
        {"ENVIRONMENT": "production"},
        {"PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED": False},
        {"PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4": ""},
        {"PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4": "192.0.2.1"},
    ):
        variant = type("Variant", (DevTest,), config_change)
        assert not _keyed_core_plan_deploy_eligible(variant, plan)
    for mutation in (
        lambda row: row.evidence.update({"managedHostImageProfile": "ubuntu-22.04"}),
        lambda row: row.evidence["sketchAuthorization"]["chains"][1]["middle"].update({"provider": "linode"}),
        lambda row: row.evidence["target"].update({"name": "another-target"}),
        lambda row: row.review["postCoreScope"].update({"chainCount": 3}),
    ):
        changed = deepcopy(plan)
        mutation(changed)
        assert not _keyed_core_plan_deploy_eligible(DevTest, changed)


def test_normal_apply_route_requires_confirmation_before_private_keyed_starter(tmp_path, monkeypatch):
    class DevTest(TestConfig):
        ENVIRONMENT = "devtest"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'apply.sqlite'}"
        PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = True
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "4.2.2.2"

    monkeypatch.setattr("app.services.provider_keyed_initial_dispatch.recover_fresh_keyed_initial_dispatches",
                        lambda **_kw: [])
    app = create_app(DevTest)
    plan = _plan()
    monkeypatch.setattr("app.asgi.get_core_deployment_plan", lambda _eng, _plan: plan)
    eligible = {"value": False}
    monkeypatch.setattr("app.asgi._keyed_core_plan_deploy_eligible",
                        lambda _cfg, _plan: eligible["value"])
    started = []

    def starter(engagement_id, plan_id):
        started.append((engagement_id, plan_id))
        applying = deepcopy(plan)
        applying.status = "applying"
        job = SimpleNamespace(to_dict=lambda: {"id": "job-disposable", "status": "queued"})
        return applying, job

    monkeypatch.setattr(core_deployment_plans, "_begin_private_devtest_keyed_core_plan_apply", starter)
    path = "/api/engagements/eng-disposable/deployment-plans/plan-disposable/apply"
    unavailable = app.test_client().post(path, json={"confirmMutation": "mutate-barragan-testing"})
    assert unavailable.status_code == 400 and started == []
    eligible["value"] = True
    rejected = app.test_client().post(path, json={"confirmMutation": "wrong"})
    assert rejected.status_code == 400 and started == []
    accepted = app.test_client().post(path, json={"confirmMutation": "mutate-barragan-testing"})
    assert accepted.status_code == 201
    assert accepted.json()["job"]["id"] == "job-disposable"
    assert started == [("eng-disposable", "plan-disposable")]
    # This route test launches no worker and creates no core job or lease.
    with runtime_context(app.state.runtime):
        assert SqlAlchemyJobRepository().list_for_engagement("eng-disposable") == []
