# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest append review and one guarded Apply action redact private material."""

from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

from app.asgi import create_app
from app.core.config import TestConfig
from app.domain import JobEvent


def test_append_review_routes_are_devtest_only_and_redact_saved_evidence(tmp_path, monkeypatch):
    class DevTest(TestConfig):
        ENVIRONMENT = "devtest"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'append-api.sqlite'}"
        START_SCHEDULERS = False

    class Local(DevTest):
        ENVIRONMENT = "local"

    class ApplyEnabled(DevTest):
        PROVIDER_KEYED_EDGE_APPEND_APPLY_ENABLED = True

    import app.services.provider_keyed_append_plan_job as service
    import app.storage.job_repository as jobs_module
    import app.storage.sketch_chain_repository as chains_module
    import app.storage.engagement_repository as engagements_module
    import app.core.runtime as runtime
    import app.services.provider_keyed_append_dispatch as dispatch

    chain = SimpleNamespace(status="deployed", burned=False,
        middle_provider="digitalocean", edge_provider="digitalocean",
        edge_count=1, nodes=[{}, {}], edge_region="sfo3", edge_size="s-1vcpu-1gb",
        deploy_job_id="job-initial")
    initial = SimpleNamespace(action="provider_keyed_initial", status="succeeded",
        target_id="eng-a", input={"engagementId": "eng-a", "coreJobId": "job-core"})
    parent = SimpleNamespace(id="job-append", action="provider_keyed_edge_append", status="running",
        target_id="eng-a", input={"chainId": "chain-a", "planJobId": "job-plan", "phase": "awaiting_apply"})
    child = SimpleNamespace(id="job-plan", action="provider_keyed_edge_append_plan",
        status="succeeded", target_id="eng-a", input={"parentJobId": "job-append"},
        events=[JobEvent(
        1, "info", "reviewed append plan saved", {
            "newEdgeAddress": 'digitalocean_droplet.edge["sfo3-03"]',
            "planSha256": "a" * 64, "planPath": "/private/secret/plan",
            "credentialSecretSha256": "b" * 64,
        })])
    rows = []
    class Chains:
        def get(self, engagement_id, chain_id):
            return chain if (engagement_id, chain_id) == ("eng-a", "chain-a") else None
    class Jobs:
        def list(self):
            return rows
        def list_for_engagement(self, _engagement_id):
            return rows
        def get(self, job_id):
            return child if job_id == child.id else initial if job_id == "job-initial" else None
    monkeypatch.setattr(chains_module, "SqlAlchemySketchChainRepository", Chains)
    engagement = SimpleNamespace(input_parameters={}, sketch_state_schema="provider-keyed-v2")
    monkeypatch.setattr(engagements_module, "SqlAlchemyEngagementRepository",
        lambda: SimpleNamespace(get=lambda _id: engagement))
    monkeypatch.setattr(jobs_module, "SqlAlchemyJobRepository", Jobs)
    monkeypatch.setattr("app.asgi.assert_engagement_mutation_allowed", lambda _id: None)
    scheduled = []
    monkeypatch.setattr(runtime, "start_runtime_task", lambda task, *, name: scheduled.append((task, name)))
    monkeypatch.setattr(service, "begin_published_digitalocean_edge_append_plan",
        lambda core, chain_id, region, size, **_kw: (rows.append(parent) or parent, child))
    discarded = []
    monkeypatch.setattr(service, "discard_reviewed_digitalocean_edge_append_plan",
        lambda parent_id, **_kw: discarded.append(parent_id))
    cancelled = []
    monkeypatch.setattr(service, "cancel_unscheduled_digitalocean_edge_append_plan",
        lambda parent_id, **_kw: cancelled.append(parent_id))

    prod = create_app(Local).test_client()
    path = "/api/engagements/eng-a/sketch-chains/chain-a/edges/append/plan"
    assert prod.get(path).json() == {"review": {"available": False, "status": "unavailable"}}
    assert prod.post(path, json={}).status_code == 404
    assert prod.post(f"{path}/discard", json={}).status_code == 404
    assert prod.post(f"{path}/apply", json={"planSha256": "a" * 64}).status_code == 404

    client = create_app(DevTest).test_client()
    scheduled.clear()
    assert client.get(path).json()["review"]["status"] == "ready"
    assert rows == [] and scheduled == []
    engagement.sketch_state_schema = "split-v1"
    assert client.get(path).json()["review"]["available"] is False
    assert client.post(path, json={}).status_code == 409
    engagement.sketch_state_schema = "provider-keyed-v2"
    engagement.input_parameters = {"deploymentTarget": "some-other-compartment"}
    assert client.post(path, json={"requestedBy": "spoofed"}).status_code == 409
    engagement.input_parameters = {}
    requested = []
    monkeypatch.setattr(service, "begin_published_digitalocean_edge_append_plan",
        lambda core, chain_id, region, size, **kw: (requested.append((core, kw["requested_by"]))
                                           or rows.append(parent) or parent, child))
    created = client.post(path, json={"coreJobId": "spoofed", "requestedBy": "spoofed"})
    assert created.status_code == 202 and len(scheduled) == 1
    assert requested == [("job-core", "devtest-operator")]
    review = client.get(path).json()["review"]
    assert review["status"] == "awaiting_apply"
    assert review["planSha256"] == "a" * 64
    assert "planPath" not in review and "credential" not in str(review).lower()
    assert client.post(f"{path}/apply", json={"planSha256": "a" * 64}).status_code == 404
    assert create_app(ApplyEnabled).test_client().post(
        f"{path}/apply", json={"planSha256": "a" * 64}).status_code == 409
    enabled_app = create_app(ApplyEnabled)
    @enabled_app.middleware("http")
    async def test_operator(request, call_next):
        request.state.identity = SimpleNamespace(username="bob")
        return await call_next(request)
    enabled = enabled_app.test_client()
    engagement.sketch_state_schema = "split-v1"
    assert enabled.post(f"{path}/apply", json={"planSha256": "a" * 64}).status_code == 409
    engagement.sketch_state_schema = "provider-keyed-v2"
    assert enabled.post(f"{path}/apply", json={"planSha256": "b" * 64}).status_code == 409
    approved = []
    def approve(parent_id, **kw):
        approved.append((parent_id, kw["expected_plan_sha256"], kw["requested_by"]))
        parent.input["applyRequestedPlanSha256"] = kw["expected_plan_sha256"]
        return parent
    monkeypatch.setattr(dispatch, "approve_reviewed_digitalocean_edge_append", approve)
    monkeypatch.setattr(dispatch, "advance_approved_digitalocean_edge_append", lambda *_a, **_kw: None)
    before_apply = len(scheduled)
    applied = enabled.post(f"{path}/apply", json={"planSha256": "a" * 64})
    assert applied.status_code == 202
    assert approved == [(parent.id, "a" * 64, "bob")]
    assert len(scheduled) == before_apply + 1
    assert applied.json()["review"]["applyRequested"] is True
    assert enabled.post(f"{path}/apply", json={"planSha256": "a" * 64}).status_code == 409
    assert len(scheduled) == before_apply + 1
    parent.input.pop("applyRequestedPlanSha256")
    assert client.post(f"{path}/discard", json={}).status_code == 200
    assert discarded == [parent.id]
    from app.services import provider_keyed_runtime_preflight as preflight
    monkeypatch.setattr(preflight, "_db_lease_lookup",
        lambda _id: ("plan-a", "provider_keyed_edge_append"))
    parent.input.update(phase="planning", engagementId="eng-a", corePlanId="plan-a",
        claimOwner="provider_keyed_append_plan", claimExpiresAt=(
            datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    child.status = "failed"
    assert client.get(path).json()["review"]["failedReviewDiscardState"] == "waiting"
    parent.input["claimOwner"] = "provider_keyed_append_cleanup"
    assert client.get(path).json()["review"]["failedReviewDiscardState"] == "waiting"
    assert client.post(f"{path}/discard", json={}).status_code == 409
    assert discarded == [parent.id]
    parent.input["claimExpiresAt"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    assert client.get(path).json()["review"]["failedReviewDiscardState"] == "ready"
    recovered = []
    monkeypatch.setattr(service, "reconcile_interrupted_digitalocean_edge_append_plan",
        lambda parent_id, **_kw: recovered.append(parent_id))
    assert client.post(f"{path}/discard", json={}).status_code == 200
    assert recovered == [parent.id] and discarded == [parent.id]
    assert client.get(path).status_code == 200
    import app.services.provider_keyed_append_publication_recovery as publication
    parent.status = "failed"
    parent.input["phase"] = "attention"
    child.status = "succeeded"
    monkeypatch.setattr(publication, "publication_recovery_state",
        lambda *_a, **_kw: "waiting")
    assert enabled.get(path).json()["review"]["publicationRecoveryState"] == "waiting"
    recovery_path = f"{path}/recover-publication"
    assert prod.post(recovery_path, json={}).status_code == 404
    before_recovery = len(scheduled)
    assert enabled.post(recovery_path, json={}).status_code == 409
    assert len(scheduled) == before_recovery
    monkeypatch.setattr(publication, "publication_recovery_state",
        lambda *_a, **_kw: "ready")
    resumed = []
    monkeypatch.setattr(publication, "rearm_sealed_append_publication",
        lambda parent_id, **_kw: (resumed.append(parent_id) or parent))
    response = enabled.post(recovery_path, json={})
    assert response.status_code == 202
    assert resumed == [parent.id] and len(scheduled) == before_recovery + 1
    rows.clear()
    monkeypatch.setattr(runtime, "start_runtime_task",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("scheduler offline")))
    unavailable = client.post(path, json={})
    assert unavailable.status_code == 503
    assert unavailable.json()["review"]["parentJobId"] == parent.id
    assert cancelled == [parent.id]


def test_append_review_route_retries_reconciled_history_and_discards_only_new_parent(
        tmp_path, monkeypatch):
    class DevTest(TestConfig):
        ENVIRONMENT = "devtest"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'append-retry-api.sqlite'}"
        START_SCHEDULERS = False

    import app.services.provider_keyed_append_plan_job as service
    import app.storage.job_repository as jobs_module
    import app.storage.sketch_chain_repository as chains_module
    import app.storage.engagement_repository as engagements_module
    import app.core.runtime as runtime

    now = datetime.now(timezone.utc).isoformat()
    old_parent = SimpleNamespace(
        id="job-old", action="provider_keyed_edge_append", status="failed",
        target_id="eng-a", finished_at=now,
        input={"engagementId": "eng-a", "coreJobId": "job-core",
               "corePlanId": "plan-core", "chainId": "chain-a",
               "planJobId": "job-old-plan", "phase": "unapplied_reconciled"},
        events=[JobEvent(1, "info", "append plan reconciled without mutation",
                         {"stateSha256": "a" * 64})],
    )
    old_child = SimpleNamespace(
        id="job-old-plan", action="provider_keyed_edge_append_plan", status="failed",
        target_id="eng-a", input={"parentJobId": old_parent.id,
                                   "coreJobId": "job-core", "mutation": False},
        events=[JobEvent(1, "error", "review failed", {})],
    )
    new_parent = SimpleNamespace(
        id="job-new", action="provider_keyed_edge_append", status="running",
        target_id="eng-a", input={"engagementId": "eng-a", "coreJobId": "job-core",
                              "corePlanId": "plan-core", "chainId": "chain-a",
                              "planJobId": "job-new-plan", "phase": "planning"},
    )
    new_child = SimpleNamespace(
        id="job-new-plan", action="provider_keyed_edge_append_plan", status="queued",
        target_id="eng-a", input={"parentJobId": new_parent.id,
                                   "coreJobId": "job-core", "mutation": False},
        events=[],
    )
    initial = SimpleNamespace(
        id="job-initial", action="provider_keyed_initial", status="succeeded",
        target_id="eng-a", input={"engagementId": "eng-a", "coreJobId": "job-core"},
    )
    rows = [old_parent, old_child]
    class Jobs:
        def list_for_engagement(self, _engagement_id):
            return rows
        def get(self, job_id):
            return next((row for row in [*rows, initial] if row.id == job_id), None)
    chain = SimpleNamespace(
        status="deployed", burned=False, middle_provider="digitalocean",
        edge_provider="digitalocean", edge_count=1, nodes=[{}, {}],
        edge_region="sfo3", edge_size="s-1vcpu-1gb", deploy_job_id=initial.id,
    )
    monkeypatch.setattr(jobs_module, "SqlAlchemyJobRepository", Jobs)
    monkeypatch.setattr(chains_module, "SqlAlchemySketchChainRepository",
        lambda: SimpleNamespace(get=lambda _eng, _chain: chain))
    monkeypatch.setattr(engagements_module, "SqlAlchemyEngagementRepository",
        lambda: SimpleNamespace(get=lambda _eng: SimpleNamespace(
            input_parameters={}, sketch_state_schema="provider-keyed-v2")))
    monkeypatch.setattr("app.asgi.assert_engagement_mutation_allowed", lambda _eng: None)
    scheduled = []
    monkeypatch.setattr(runtime, "start_runtime_task",
        lambda task, *, name: scheduled.append(name))
    monkeypatch.setattr(service, "begin_published_digitalocean_edge_append_plan",
        lambda *_args, **_kwargs: (rows.extend([new_parent, new_child]) or
                                   (new_parent, new_child)))
    discarded = []
    monkeypatch.setattr(service, "discard_reviewed_digitalocean_edge_append_plan",
        lambda parent_id, **_kwargs: discarded.append(parent_id))
    client = create_app(DevTest).test_client()
    scheduled.clear()
    path = "/api/engagements/eng-a/sketch-chains/chain-a/edges/append/plan"
    ready = client.get(path).json()["review"]
    assert (ready["available"], ready["status"], ready["parentJobId"]) == (
        True, "ready", "")
    created = client.post(path, json={})
    assert created.status_code == 202 and len(scheduled) == 1
    assert created.json()["review"]["parentJobId"] == new_parent.id
    assert client.get(path).json()["review"]["status"] == "planning"
    new_parent.created_at = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    new_parent.events = [JobEvent(1, "info", "provider append review reserved", {})]
    new_child.events = [JobEvent(1, "info", "provider append plan queued", {})]
    monkeypatch.setattr(
        "app.services.provider_keyed_runtime_preflight._db_lease_lookup",
        lambda _eng: ("plan-core", "provider_keyed_edge_append"))
    cancelled = []
    monkeypatch.setattr(service, "cancel_unscheduled_digitalocean_edge_append_plan",
        lambda parent_id, **_kwargs: cancelled.append(parent_id))
    assert client.get(path).json()["review"]["unscheduledReviewCancelState"] == "ready"
    assert client.post(f"{path}/discard", json={}).status_code == 200
    assert cancelled == [new_parent.id]
    new_parent.input["phase"] = "awaiting_apply"
    new_child.status = "succeeded"
    assert client.post(f"{path}/discard", json={}).status_code == 200
    assert discarded == [new_parent.id]
    assert rows[:2] == [old_parent, old_child]
