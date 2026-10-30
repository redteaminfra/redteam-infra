# Copyright (c) 2026, Oracle and/or its affiliates.
"""Paired Review accepts only edge choices and redacts private plan material."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.domain import JobEvent
from app.storage.sketch_chain_repository import StoredSketchChain


@pytest.mark.parametrize("inert_history", [False, True])
def test_mixed_append_review_is_devtest_only_and_schedules_one_pair(tmp_path, monkeypatch, inert_history):
    class DevTest(TestConfig):
        ENVIRONMENT = "devtest"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'mixed-append-api.sqlite'}"
        START_SCHEDULERS = False

    class Local(DevTest):
        ENVIRONMENT = "local"

    import app.services.provider_keyed_mixed_append_review_runtime as review_service
    import app.storage.sketch_chain_repository as chains_module
    import app.storage.engagement_repository as engagements_module
    import app.storage.job_repository as jobs_module
    import app.core.runtime as runtime

    initial = SimpleNamespace(action="provider_keyed_mixed_initial", status="succeeded",
        target_id="eng-a", input={"phase": "completed", "coreJobId": "job-core",
                                  "chainIds": ["chain-digitalocean", "chain-linode"]})
    records = {"job-initial": initial}
    chains = [StoredSketchChain(
        chain_id=f"chain-{provider}", engagement_id="eng-a", assigned_proxy="proxy01",
        middle_provider=provider, middle_region="nyc3" if provider == "digitalocean" else "us-east",
        middle_size="small", edge_provider=provider,
        edge_region="nyc3" if provider == "digitalocean" else "us-east", edge_size="small",
        status="deployed", burned=False, burned_note="", nodes=[{}, {}], edge_count=1,
        deploy_job_id="job-initial", teardown_job_id="", terraform_working_directory="/workspace",
        created_at="", updated_at="") for provider in ("digitalocean", "linode")]
    ghost = replace(chains[0], chain_id="old-default", status="aborted",
        deploy_job_id="", terraform_working_directory="", nodes=[])
    if inert_history:
        chains.insert(0, ghost)
    monkeypatch.setattr(chains_module, "SqlAlchemySketchChainRepository",
        lambda: SimpleNamespace(list_for_engagement=lambda _id: chains))
    engagement = SimpleNamespace(input_parameters={}, sketch_state_schema="provider-keyed-v2")
    monkeypatch.setattr(engagements_module, "SqlAlchemyEngagementRepository",
        lambda: SimpleNamespace(get=lambda _id: engagement))
    monkeypatch.setattr(jobs_module, "SqlAlchemyJobRepository",
        lambda: SimpleNamespace(get=lambda job_id: records.get(job_id),
                                list_by_actions_and_statuses=lambda **_kwargs: []))
    monkeypatch.setattr("app.asgi.assert_engagement_mutation_allowed", lambda _id: None)
    scheduled = []
    monkeypatch.setattr(runtime, "start_runtime_task",
        lambda task, *, name: scheduled.append(name))
    monkeypatch.setattr("app.services.provider_keyed_runtime_preflight._db_lease_lookup",
        lambda _: ("plan-core", "provider_keyed_mixed_append"))
    saved = []
    parent = SimpleNamespace(id="job-provider-keyed-mixed-append-core", status="queued", target_id="eng-a",
        input={"phase": "planning", "corePlanId": "plan-core"})
    child = SimpleNamespace(id="job-plan", status="queued", events=[])
    monkeypatch.setattr(review_service, "mixed_append_review_status",
        lambda *_args, **_kwargs: (parent, child) if saved else None)
    monkeypatch.setattr(review_service, "begin_mixed_append_review",
        lambda engagement_id, core_job_id, choices, requested_by: (
            saved.append((engagement_id, core_job_id, choices, requested_by)) or parent))

    path = "/api/engagements/eng-a/sketch/mixed-append/review"
    prod = create_app(Local).test_client()
    assert prod.get(path).json() == {"review": {"available": False, "status": "unavailable"}}
    assert prod.post(path, json={"choices": {}}).status_code == 409

    client = create_app(DevTest).test_client()
    assert client.get(path).json() == {"review": {"available": True, "status": "ready"}}
    scheduled.clear()
    active_extra = replace(ghost, chain_id="unreviewed-active", status="pending")
    chains.append(active_extra)
    assert client.get(path).json() == {"review": {"available": False, "status": "unavailable"}}
    assert client.post(path, json={"choices": {}}).status_code == 409
    assert saved == [] and scheduled == []
    chains.remove(active_extra)
    assert client.get(path).json() == {"review": {"available": True, "status": "ready"}}
    if inert_history:
        assert chains[0] is ghost and ghost.status == "aborted" and not ghost.nodes
    choices = {"digitalocean": {"selectedChainId": "chain-linode", "edgeRegion": "sfo3",
                                "edgeSize": "s-1vcpu-1gb"},
               "linode": {"selectedChainId": "chain-do", "edgeRegion": "us-east",
                          "edgeType": "g6-nanode-1"}}
    assert client.post(path, json={"choices": choices, "coreJobId": "spoofed"}).status_code == 409
    scheduled.clear()
    response = client.post(path, json={"choices": choices})
    assert response.status_code == 202
    assert saved == [("eng-a", "job-core", choices, "devtest-operator")]
    assert scheduled == ["barragan-mixed-append-review"]
    child.status = "failed"
    monkeypatch.setattr(review_service, "mixed_append_retry_choices",
        lambda p, c, **_kwargs: choices if c.status == "failed" else None)
    failed = client.get(path).json()["review"]
    assert failed["retryAvailable"] is True and failed["retryChoices"] == choices
    assert failed["applyAvailable"] is False
    def retry(engagement_id, core_job_id, submitted, requested_by):
        assert submitted == choices
        child.status = "queued"
        return parent
    monkeypatch.setattr(review_service, "begin_mixed_append_review", retry)
    scheduled.clear()
    assert client.post(path, json={"choices": choices}).status_code == 202
    assert scheduled == ["barragan-mixed-append-review"]
    assert client.get(path).json()["review"]["retryAvailable"] is False
    child.status = "succeeded"
    child.events = [JobEvent(1, "info", "mixed append pair plan reviewed",
                             {"reviewSha256": "a" * 64})]
    parent.status = "running"
    parent.input["reviewSummary"] = {"schema": "mixed-append-pair-review-summary-v1",
        "providerOrder": ["digitalocean", "linode"], "plans": [],
        "outcome": "add one edge per provider; retain all existing nodes"}
    detail = client.get(path).json()["review"]
    assert detail["applyAvailable"] is True
    assert detail["reviewSha256"] == "a" * 64
    assert "secret" not in str(detail).lower()

    import app.services.provider_keyed_mixed_append_plan_context as context_service
    import app.services.provider_keyed_mixed_append_pair_parent as parent_service
    approvals = []
    monkeypatch.setattr(context_service, "collect_mixed_append_pair_plan_context",
        lambda parent_id: SimpleNamespace(approval_kwargs=lambda: {"source": "server-owned"}))
    monkeypatch.setattr(parent_service, "approve_mixed_append_pair",
        lambda parent_id, **kwargs: approvals.append((parent_id, kwargs)))
    scheduled.clear()
    apply_path = "/api/engagements/eng-a/sketch/mixed-append/apply"
    assert client.post(apply_path, json={"reviewSha256": "b" * 64}).status_code == 409
    assert client.post(apply_path, json={"reviewSha256": "a" * 64,
                                         "coreJobId": "spoofed"}).status_code == 409
    assert approvals == []
    response = client.post(apply_path, json={"reviewSha256": "a" * 64})
    assert response.status_code == 202
    assert approvals == [(parent.id, {"expected_review_sha256": "a" * 64,
                                      "source": "server-owned"})]
    assert scheduled == ["barragan-mixed-append-apply"]

    from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id
    parent.input["phase"] = "apply_sealed"
    records[_child_id(parent.id)] = SimpleNamespace(status="failed")
    stopped = client.get(path).json()["review"]
    assert stopped["attention"] is True
    assert stopped["applyAvailable"] is False
    assert stopped["applyStage"] == "applying first provider"

    # Same approved review now exposes a distinct proof-only action, never a
    # second approval or client-supplied mode/claim.
    import app.services.provider_keyed_mixed_append_apply_runtime as apply_runtime
    claimed=[];dispatched=[];tasks=[]
    monkeypatch.setattr(apply_runtime,'mixed_append_proof_resume_available',lambda *_a,**_k:True)
    def claim(p,*,jobs):
        claimed.append(p.id)
        if len(claimed)>1:raise ValueError('claim already held')
        return ('server-owner','server-token')
    monkeypatch.setattr(apply_runtime,'claim_mixed_append_proof_resume',claim)
    monkeypatch.setattr(apply_runtime,'run_mixed_append_apply',lambda *a,**k:dispatched.append((a,k)))
    monkeypatch.setattr(runtime,'start_runtime_task',lambda task,*,name:tasks.append(task))
    parent.input['reviewSha256']='a'*64
    detail=client.get(path).json()['review']
    assert detail['proofResumeAvailable'] and detail['attention'] and not detail['applyAvailable']
    assert client.post(apply_path,json={'reviewSha256':'b'*64}).status_code==409
    assert client.post(apply_path,json={'reviewSha256':'a'*64,'proofResumeOnly':True}).status_code==409
    assert claimed==[]
    assert client.post(apply_path,json={'reviewSha256':'a'*64}).status_code==202
    assert approvals==[(parent.id,{'expected_review_sha256':'a'*64,'source':'server-owned'})]
    assert len(tasks)==1
    assert client.post(apply_path,json={'reviewSha256':'a'*64}).status_code==409
    assert len(tasks)==1
    tasks[0]()
    assert dispatched==[((parent.id,),{'proof_resume_only':True,'proof_resume_claim':('server-owner','server-token')})]


    # An exact stopped rc1 classification is projected without rewriting stored jobs.
    import app.services.provider_keyed_mixed_failed_second_append as failed_second
    monkeypatch.setattr(failed_second, "stopped_second_failure_attention", lambda *_: True)
    original_status = parent.status
    original_input = dict(parent.input)
    stopped = client.get(path).json()["review"]
    assert stopped["status"] == "attention" and stopped["attention"] is True
    assert stopped["applyStage"] == "provider Apply failed; cleanup review required"
    assert stopped["proofResumeAvailable"] is False and stopped["retryAvailable"] is False
    assert stopped["applyAvailable"] is False
    assert parent.status == original_status and parent.input == original_input

    monkeypatch.setattr(failed_second, "stopped_second_failure_attention", lambda *_: False)
    # A sealed pair without a command intent is an Apply retry, not proof resume.
    from app.services.provider_keyed_mixed_append_availability import MixedAppendAvailabilityAttention
    import app.services.provider_keyed_mixed_append_availability as availability
    records.pop(_child_id(parent.id))
    monkeypatch.setattr(apply_runtime, "mixed_append_pristine_apply_available", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(apply_runtime, "mixed_append_proof_resume_available", lambda *_args, **_kwargs: False)
    tasks.clear(); dispatched.clear()
    checked = []
    def catalog_blocked(*args, **kwargs):
        checked.append("catalog")
        raise MixedAppendAvailabilityAttention("DigitalOcean region unavailable; no append started")
    monkeypatch.setattr(availability, "require_reviewed_mixed_append_availability", catalog_blocked)
    detail = client.get(path).json()["review"]
    assert detail["applyAvailable"] and detail["applyStage"] == "approved; no provider command started"
    rejected = client.post(apply_path, json={"reviewSha256": "a" * 64})
    assert rejected.status_code == 409 and "no append started" in rejected.json()["error"]
    assert tasks == [] and checked == ["catalog"]
    monkeypatch.setattr(availability, "require_reviewed_mixed_append_availability", lambda *args, **kwargs: checked.append("catalog"))
    assert client.post(apply_path, json={"reviewSha256": "a" * 64}).status_code == 202
    assert len(tasks) == 1 and len(approvals) == 1
    tasks[0]()
    assert dispatched == [((parent.id,), {})]
