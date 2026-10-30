# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted mixed append reservation, approval and duplicate-click safety."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_initial_plan_gate import DigitalOceanInitialFirewallIntent
from app.services.provider_keyed_mixed_append_pair_parent import (
    MixedAppendPairParentAttention, _parent_id, _plan_child_id,
    approve_mixed_append_pair, mixed_append_approval_sha256,
    mixed_append_review_summary,
    reserve_mixed_append_pair,
)
import app.services.provider_keyed_mixed_append_pair_parent as parent_service
from app.services.provider_keyed_mixed_append_pair_plan_worker import (
    reopen_mixed_append_pair_plan_review,
)
from app.services.provider_keyed_mixed_append_published_source import PublishedMixedAppendSource
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import (
    CoreMutationLeaseModel, DeploymentPlanModel, JobEventModel, JobRunModel,
    SketchChainModel,
)
from test_provider_keyed_mixed_append_pair_plan_worker import fixture as pair_fixture


def _setup(engagement_id="eng-one", core_job_id="job-core", core_plan_id="plan-core"):
    state = db.configure("sqlite:///:memory:")
    jobs = SqlAlchemyJobRepository()
    with db.bind(state):
        db.create_all()
        db.session.add(DeploymentPlanModel(
            id=core_plan_id, engagement_id=engagement_id, revision_id="revision",
            status="applied", stage="applied", apply_job_id=core_job_id,
            review={}, evidence={}, is_current=False))
        db.session.commit()
        at = datetime.now(timezone.utc).isoformat()
        jobs.save(StoredJobRun(
            core_job_id, "pilot_standard_rti_guarded_execute", "succeeded",
            f"engagement:{engagement_id}", "engagement", engagement_id,
            "operator", {"engagementId": engagement_id, "corePlanId": core_plan_id},
            [], at, at, at, [JobEvent(1, "info", "core deployed", {})]))
        jobs.save(StoredJobRun(
            f"job-provider-keyed-mixed-initial-{core_job_id.removeprefix('job-')}",
            "provider_keyed_mixed_initial", "succeeded",
            f"engagement:{engagement_id}", "engagement", engagement_id,
            "operator", {"coreJobId": core_job_id, "corePlanId": core_plan_id,
                         "chainIds": ["chain-do", "chain-linode"],
                         "orderedProviders": ["digitalocean", "linode"],
                         "phase": "completed"},
            [], at, at, at,
            [JobEvent(1, "info", "mixed two-provider host proof published",
                      {"chainIds": ["chain-do", "chain-linode"]})]))
        for chain_id, provider in (("chain-do", "digitalocean"),
                                   ("chain-linode", "linode")):
            db.session.add(SketchChainModel(
                engagement_id=engagement_id, chain_id=chain_id,
                assigned_proxy="proxy01", middle_provider=provider,
                middle_region="region", middle_size="small",
                edge_provider=provider, edge_region="region", edge_size="small",
                edge_count=1, status="deployed", burned=False,
                deploy_job_id=f"job-provider-keyed-mixed-initial-{core_job_id.removeprefix('job-')}",
                nodes=[{"role": role, "provider": provider} for role in ("middle", "edge")],
            ))
        db.session.commit()
    return state, jobs


def _reserve(jobs, engagement_id="eng-one", core_job_id="job-core",
             core_plan_id="plan-core", request=None):
    return reserve_mixed_append_pair(
        engagement_id, core_job_id, core_plan_id, requested_by="operator",
        reviewed_request=request or {
            "digitalocean": {"selectedChainId": "chain-linode", "edgeRegion": "nyc3",
                             "edgeSize": "small", "edgeImage": "image", "selectorTag": "tag"},
            "linode": {"selectedChainId": "chain-do", "edgeRegion": "us-east",
                       "edgeType": "small", "edgeImage": "image",
                       "engagementTag": "tag"}},
        provider_order=("digitalocean", "linode"),
        chain_order=("chain-do", "chain-linode"), job_repository=jobs)


def complete_review(jobs, parent, review_sha, seal):
    """Persist the background Review terminal before testing Apply approval."""
    at = datetime.now(timezone.utc)
    started = jobs.start_if_queued(parent, started_at=at.isoformat(), event=JobEvent(
        2, "info", "mixed append pair planning started", {}))
    claimed = jobs.claim_lease(
        started.id, owner="test-plan", token="test-token", claimed_at=at.isoformat(),
        expires_at=(at + timedelta(hours=1)).isoformat(),
        eligible_statuses={"running"}, eligible_phases={"planning"})
    child = jobs.get(_plan_child_id(parent.id))
    running = jobs.start_if_queued(child, started_at=at.isoformat(), event=JobEvent(
        2, "info", "mixed append pair plan started", {}))
    summary = mixed_append_review_summary(parent, seal)
    return jobs.finish_mixed_append_review(
        claimed, running, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
        event=JobEvent(3, "info", "mixed append pair plan reviewed",
                       {"reviewSha256": review_sha}), review_summary=summary)


def _save_aborted_history(**changes):
    values = dict(engagement_id="eng-one", chain_id="old-default", assigned_proxy="proxy01",
                  middle_provider="digitalocean", middle_region="sfo3", middle_size="small",
                  edge_provider="digitalocean", edge_region="sfo3", edge_size="small",
                  edge_count=1, status="aborted", burned=False, deploy_job_id="",
                  teardown_job_id="", terraform_working_directory="", nodes=[])
    values.update(changes)
    row = SketchChainModel(**values)
    db.session.add(row)
    db.session.commit()
    return row.id


@pytest.mark.parametrize("inert_history", [False, True])
def test_atomic_reservation_and_duplicate_click_survive_repository_reopen(inert_history):
    state, jobs = _setup()
    with db.bind(state):
        ghost_id = _save_aborted_history() if inert_history else None
        parent = _reserve(jobs)
        lease = db.session.get(CoreMutationLeaseModel, "eng-one")
        assert lease.operation == "provider_keyed_mixed_append"
        assert jobs.get(_plan_child_id(parent.id)).status == "queued"
        assert _reserve(SqlAlchemyJobRepository()).id == parent.id
        if inert_history:
            ghost = db.session.get(SketchChainModel, ghost_id)
            assert ghost.status == "aborted" and not ghost.nodes
            assert not ghost.deploy_job_id and not ghost.terraform_working_directory
            assert db.session.query(SketchChainModel).filter_by(engagement_id="eng-one").count() == 3
        changed_request = {key: dict(value) for key, value in parent.input["reviewRequest"].items()}
        changed_request["digitalocean"]["edgeRegion"] = "sfo3"
        with pytest.raises(MixedAppendPairParentAttention):
            _reserve(jobs, request=changed_request)
        assert jobs.get(parent.id).input["requestSha256"] == parent.input["requestSha256"]
        # A stale initial lease after publication must not be consumed.
        lease.operation = "provider_keyed_initial"
        db.session.commit()
        with pytest.raises(MixedAppendPairParentAttention):
            _reserve(jobs, request=changed_request)
        assert db.session.get(CoreMutationLeaseModel, "eng-one").operation == (
            "provider_keyed_initial")


@pytest.mark.parametrize("changes", [
    {"status": "pending"}, {"burned": True}, {"deploy_job_id": "job-old"},
    {"teardown_job_id": "job-old"}, {"terraform_working_directory": "/old"},
    {"nodes": [{"role": "edge", "providerInstanceId": "owned"}]},
])
def test_reservation_rejects_noninert_extra_without_leasing_or_reserving(changes):
    state, jobs = _setup()
    with db.bind(state):
        _save_aborted_history(**changes)
        with pytest.raises(MixedAppendPairParentAttention):
            _reserve(jobs)
        assert db.session.get(CoreMutationLeaseModel, "eng-one") is None
        assert jobs.get(_parent_id("job-core")) is None
        assert jobs.get(_plan_child_id(_parent_id("job-core"))) is None
        assert db.session.query(SketchChainModel).filter_by(engagement_id="eng-one").count() == 3


def test_failed_reservation_rolls_back_lease_and_both_jobs():
    state, jobs = _setup()
    with db.bind(state):
        with pytest.raises(MixedAppendPairParentAttention):
            _reserve(jobs, core_plan_id="wrong-plan")
        assert db.session.get(CoreMutationLeaseModel, "eng-one") is None
        assert jobs.get(_parent_id("job-core")) is None
        assert jobs.get(_plan_child_id(_parent_id("job-core"))) is None


def test_reservation_requires_lease_free_published_generation():
    state, jobs = _setup()
    with db.bind(state):
        published_id = "job-provider-keyed-mixed-initial-core"
        publication = db.session.query(JobEventModel).filter_by(
            job_id=published_id).one()
        db.session.delete(publication)
        db.session.commit()
        with pytest.raises(MixedAppendPairParentAttention):
            _reserve(jobs)
        assert db.session.get(CoreMutationLeaseModel, "eng-one") is None
        assert jobs.get(_parent_id("job-core")) is None
        db.session.add(JobEventModel(
            job_id=published_id, sequence=1, level="info",
            message="mixed two-provider host proof published",
            data={"chainIds": ["chain-do", "chain-linode"]}))
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-one", owner_id="plan-core",
            operation="provider_keyed_initial"))
        db.session.commit()
        with pytest.raises(MixedAppendPairParentAttention):
            _reserve(jobs)
        assert db.session.get(CoreMutationLeaseModel, "eng-one").operation == (
            "provider_keyed_initial")
        assert jobs.get(_parent_id("job-core")) is None


def test_reservation_rejects_missing_or_changed_published_chain_row():
    state, jobs = _setup()
    with db.bind(state):
        row = db.session.query(SketchChainModel).filter_by(
            engagement_id="eng-one", chain_id="chain-linode").one()
        db.session.delete(row)
        db.session.commit()
        with pytest.raises(MixedAppendPairParentAttention):
            _reserve(jobs)
        assert db.session.get(CoreMutationLeaseModel, "eng-one") is None
        assert jobs.get(_parent_id("job-core")) is None


@pytest.mark.parametrize("drift", ["none", "bindings", "receipt", "review", "summary"])
@pytest.mark.parametrize("inert_history", [False, True])
def test_approval_seals_exact_pair_once_after_restart(tmp_path, monkeypatch, drift, inert_history):
    kwargs, records, _ = pair_fixture(tmp_path, monkeypatch)
    seal = reopen_mixed_append_pair_plan_review(**kwargs)
    pair_plan_sha = seal.review_sha256
    source = kwargs["source"]
    do, linode = kwargs["digitalocean_intent"], kwargs["linode_intent"]
    request = {
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
    state, jobs = _setup(source.engagement_id, source.core_job_id, source.core_plan_id)
    with db.bind(state):
        if inert_history:
            _save_aborted_history(engagement_id=source.engagement_id)
        parent = reserve_mixed_append_pair(
            source.engagement_id, source.core_job_id, source.core_plan_id,
            requested_by="operator",
            reviewed_request=request,
            provider_order=kwargs["reviewed_provider_order"],
            chain_order=kwargs["reviewed_chain_order"], job_repository=jobs)
        published = PublishedMixedAppendSource(
            source, tuple((p, row.path) for p, row in kwargs["workspaces"].items()),
            0, "d" * 64, "e" * 64)
        expected_review = mixed_append_approval_sha256(pair_plan_sha, published)
        complete_review(jobs, parent, expected_review, seal)
        if drift == "summary":
            row = db.session.get(JobRunModel, parent.id)
            altered = dict(row.input)
            altered_summary = dict(altered["reviewSummary"])
            altered_plans = [dict(plan) for plan in altered_summary["plans"]]
            altered_plans[0]["edgeRegion"] = "different-region"
            altered_summary["plans"] = altered_plans
            row.input = {**altered, "reviewSummary": altered_summary}
            db.session.commit()
        observed = replace(published, live_bindings_sha256="f" * 64) if drift == "bindings" else published
        if drift == "receipt":
            path = (kwargs["workspaces"]["digitalocean"].path
                    / ".barragan-mixed-append-digitalocean-plan-receipt.json")
            receipt = json.loads(path.read_text())
            receipt["planSha256"] = "0" * 64
            path.write_text(json.dumps(receipt))
        monkeypatch.setattr(parent_service, "_collect_published",
                            lambda engagement, core, jobs, lookup: observed)
        firewall = DigitalOceanInitialFirewallIntent(
            "name", "tag", ("22",), (), ("192.0.2.1/32",))
        options = dict(
            expected_review_sha256="0" * 64 if drift == "review" else expected_review,
            binding_manifest=kwargs["binding_manifest"],
            digitalocean_intent=kwargs["digitalocean_intent"],
            linode_intent=kwargs["linode_intent"],
            workspaces=kwargs["workspaces"],
            provider_states=kwargs["provider_states"],
            reviewed_inputs=kwargs["reviewed_inputs"],
            digitalocean_firewall=firewall, job_repository=jobs,
            credential_repository=kwargs["credential_repository"],
            lease_lookup=lambda engagement: (
                (row.owner_id, row.operation) if (
                    row := db.session.get(CoreMutationLeaseModel, engagement)) else None),
            release_check=kwargs["release_check"],
        )
        if drift != "none":
            with pytest.raises(MixedAppendPairParentAttention):
                approve_mixed_append_pair(parent.id, **options)
            assert jobs.get(parent.id).input["phase"] == "planning"
            assert jobs.get(_plan_child_id(parent.id)).status == "succeeded"
            return
        approved = approve_mixed_append_pair(parent.id, **options)
        assert approved.input["phase"] == "apply_sealed"
        assert approved.input["reviewSha256"]
        assert approved.input["pairPlanSha256"] == pair_plan_sha
        assert approved.input["bindingManifestSha256"] == source.binding_manifest_sha256
        assert approved.input["receiptSha256"].keys() == {"digitalocean", "linode"}
        reviewed_child = jobs.get(_plan_child_id(parent.id))
        assert reviewed_child.status == "succeeded"
        assert len(reviewed_child.events) == 3
        assert reviewed_child.events[-1].data == {"reviewSha256": expected_review}
        assert approve_mixed_append_pair(parent.id, **options) == approved
        assert jobs.get(_plan_child_id(parent.id)) == reviewed_child
        assert len(jobs.get(parent.id).events) == 3
        with pytest.raises(MixedAppendPairParentAttention):
            approve_mixed_append_pair(parent.id, **{
                **options, "expected_review_sha256": "0" * 64})
        assert "claimToken" not in approved.input
        at = datetime.now(timezone.utc)
        host_claim = jobs.claim_lease(
            approved.id, owner="mixed-append-host-proof", token="host-token",
            claimed_at=at.isoformat(),
            expires_at=(at + timedelta(minutes=20)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"apply_sealed"})
        assert host_claim is not None
        assert host_claim.input["claimOwner"] == "mixed-append-host-proof"
        assert db.session.get(CoreMutationLeaseModel, source.engagement_id).operation == (
            "provider_keyed_mixed_append")


@pytest.fixture(autouse=True)
def isolate_purchase_catalog(monkeypatch):
    monkeypatch.setattr(parent_service, "require_reviewed_mixed_append_availability", lambda *args, **kwargs: None)


def test_catalog_rejection_precedes_approval_claim_and_seal(monkeypatch):
    from types import SimpleNamespace
    from app.services.provider_keyed_mixed_append_availability import MixedAppendAvailabilityAttention
    state, jobs = _setup()
    with db.bind(state):
        parent = _reserve(jobs)
        summary_seal = SimpleNamespace(new_edge_addresses=("new-do", "new-li"),
            saved_plan_sha256=("d" * 64, "e" * 64))
        complete_review(jobs, parent, "a" * 64, summary_seal)
        before = jobs.get(parent.id)
        def unavailable(*args, **kwargs):
            raise MixedAppendAvailabilityAttention("DigitalOcean availability unavailable; no append started")
        monkeypatch.setattr(parent_service, "require_reviewed_mixed_append_availability", unavailable)
        with pytest.raises(MixedAppendPairParentAttention, match="no append started"):
            approve_mixed_append_pair(parent.id, expected_review_sha256="a" * 64,
                binding_manifest={}, digitalocean_intent=None, linode_intent=None,
                workspaces={}, provider_states={}, reviewed_inputs={}, digitalocean_firewall=None,
                job_repository=jobs)
        assert jobs.get(parent.id) == before
        assert before.input["phase"] == "planning"
        assert not before.input.get("claimToken")


def test_binding_racing_fresh_review_rolls_back_atomic_reservation():
    from app.services.provider_keyed_mixed_append_availability import require_no_independent_mixed_append_bindings
    from app.storage.models import DomainAssignmentModel, DomainAssetModel
    state, jobs = _setup()
    with db.bind(state):
        # The first eligibility read succeeds, then an independently owned
        # binding commits before reservation obtains the writer slot.
        require_no_independent_mixed_append_bindings("eng-one", jobs=jobs)
        db.session.add(DomainAssetModel(id="domain-owned", domain_name="owned.example.test"))
        db.session.add(DomainAssignmentModel(domain_id="domain-owned", engagement_id="eng-one"))
        db.session.commit()
        with pytest.raises(MixedAppendPairParentAttention):
            _reserve(jobs)
        assert jobs.get(_parent_id("job-core")) is None
        assert jobs.get(_plan_child_id(_parent_id("job-core"))) is None
        assert db.session.get(CoreMutationLeaseModel, "eng-one") is None
