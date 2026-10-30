# Copyright (c) 2026, Oracle and/or its affiliates.
"""SQLite writer reserves both published provider scopes and fence atomically."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from app.services.provider_keyed_mixed_published_teardown_authority import (
    review_published_mixed_initial_teardown,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup,
)
from app.services.provider_keyed_mixed_published_destroy_plan import (
    bind_published_mixed_initial_destroy_plans,
)
from app.services.provider_keyed_mixed_published_absence import (
    prove_published_mixed_provider_absence,
    propose_published_mixed_first_absence_event,
)
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
from app.services.provider_keyed_mixed_published_teardown_collector import (
    PublishedMixedTeardownCollection,
)
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel, EngagementModel
from app.storage.models import EngagementServiceModel
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_authority import _case
from test_provider_keyed_mixed_published_teardown_checkpoint import _core_scope
from test_provider_keyed_mixed_published_absence import _awaiting, _empty_snapshot
from app.storage.job_repository import job_event_digest


def _persisted(ready, tmp_path, monkeypatch):
    source, args, persisted = _case(ready, tmp_path)
    review = review_published_mixed_initial_teardown(**args)
    scope = _core_scope(review)
    import app.services.core_ssh as core_ssh
    import app.services.provider_keyed_mixed_interrupted_dispatch as dispatch
    monkeypatch.setattr(core_ssh, "active_core_connection_details",
                        lambda jobs, engagement: (source.core_job_id, []))
    monkeypatch.setattr(dispatch, "_core_inspector_scope",
                        lambda core, **kwargs: scope)
    db.session.add(EngagementModel(
        id=source.engagement_id, name="Opaque", status="deployed",
        owner="operator", template_id="small", input_parameters={}))
    db.session.commit()
    jobs = SqlAlchemyJobRepository()
    for row in ready.case.jobs.list():
        when = "2026-10-15T00:00:00+00:00"
        jobs.save(replace(
            row,
            created_at=when if row.created_at == "now" else row.created_at,
            started_at=when if row.started_at == "now" else row.started_at,
            finished_at=when if row.finished_at == "now" else row.finished_at,
        ))
    SqlAlchemyDeploymentPlanRepository().save(args["plan"])
    sketches = SqlAlchemySketchChainRepository()
    for row in persisted().values():
        sketches.save(row)
    # Persisted inert history must survive both SQL reserve and seal rechecks.
    first = next(iter(persisted().values()))
    sketches.save(replace(first, chain_id="old-aborted", status="aborted",
        burned=False, deploy_job_id="", teardown_job_id="",
        terraform_working_directory="", nodes=[]))
    for provider, workspace in args["workspaces"].items():
        workspace.mkdir(parents=True, exist_ok=True)
        workspace.joinpath("terraform.tfstate").write_bytes(
            args["observations"][provider].state_json)
    collection = PublishedMixedTeardownCollection(
        review, scope, args["observations"], args["workspaces"])
    proposal = propose_published_mixed_initial_cleanup(
        review, scope, "Opaque", requested_by="operator")
    return jobs, collection, proposal


def _attested_plans(jobs, collection, tmp_path, *, with_shows=False):
    source = collection.review.source
    initial = jobs.get(source.parent_job_id)
    from app.services.provider_keyed_mixed_published_teardown_authority import published_review_policy
    policies = {p: published_review_policy(collection.review, initial, p) for p in source.ordered_providers}
    states, paths, shows = {}, {}, {}
    for provider in source.ordered_providers:
        workspace = collection.workspaces[provider]
        raw = collection.observations[provider].state_json
        _parsed, actual, _cloud = _state(provider, policies[provider], raw)
        path = workspace / f".barragan-mixed-published-destroy-{provider}.tfplan"
        path.write_bytes(f"saved-{provider}-plan".encode())
        lock = workspace / f".barragan-{provider}-plan.lock"
        lock.write_bytes(b"")
        lock.chmod(0o600)
        changes = [{"address": address, "change": {
            "actions": ["delete"], "before": attrs, "after": None,
            "after_unknown": {}}} for address, attrs in actual.items()]
        shows[provider] = json.dumps({
            "format_version": "1.2", "terraform_version": "1.15.5",
            "applyable": True, "complete": True, "errored": False,
            "resource_changes": changes,
            "prior_state": {"values": {"root_module": {"resources": [
                {"address": address, "mode": "managed", "values": attrs}
                for address, attrs in actual.items()]}}},
            "output_changes": {}, "planned_values": {"root_module": {}},
        })
        states[provider], paths[provider] = raw, path
    binary = tmp_path / "terraform-test"
    binary.write_bytes(b"pinned Terraform executable fixture")
    binary.chmod(0o755)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    by_path = {path: shows[provider] for provider, path in paths.items()}
    plan_set = bind_published_mixed_initial_destroy_plans(
        initial, collection.review, states, paths, shows,
        fence=lambda: "reserved-generation", terraform_path=binary,
        expected_terraform_sha256=digest,
        release_validator=lambda: ProviderKeyedTerraformRelease(
            binary, digest, "1.15.5", "linux_amd64"),
        show_runner=lambda command, cwd: by_path[Path(command[-1])],
    )
    return ((plan_set, states, paths, binary, shows) if with_shows
            else (plan_set, states, paths, binary))


def test_published_mixed_reservation_acquires_new_fence_and_restarts_same_parent(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        assert db.session.get(CoreMutationLeaseModel,
                              collection.review.source.engagement_id) is None
        saved = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        assert saved.id == proposal.id
        lease = db.session.get(CoreMutationLeaseModel,
                               collection.review.source.engagement_id)
        assert (lease.owner_id, lease.operation) == (
            collection.review.source.core_plan_id,
            "provider_keyed_teardown_fence")
        assert jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"]) == saved


def test_published_mixed_reservation_vetoes_changed_state_without_parent_or_lease(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        provider = collection.review.source.ordered_providers[0]
        path = collection.workspaces[provider] / "terraform.tfstate"
        path.write_bytes(path.read_bytes() + b" ")
        with pytest.raises(ValueError, match="requires exact review"):
            jobs.reserve_published_mixed_initial_cleanup_parent(
                proposal, collection=collection,
                expected_snapshot_id=proposal.input["reviewSnapshotId"])
        assert jobs.get(proposal.id) is None
        assert db.session.get(CoreMutationLeaseModel,
                              collection.review.source.engagement_id) is None


@pytest.mark.parametrize("drift", ["state", "binding"])
def test_published_mixed_duplicate_reservation_rechecks_durable_source(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        if drift == "state":
            provider = collection.review.source.ordered_providers[0]
            path = collection.workspaces[provider] / "terraform.tfstate"
            path.write_bytes(path.read_bytes() + b" ")
        else:
            db.session.add(EngagementServiceModel(
                engagement_id=collection.review.source.engagement_id,
                service_id="drift", service_type="test", name="drift",
                proxy_id="proxy", status="pending", config={},
                apply_job_id=""))
            db.session.commit()
        with pytest.raises(ValueError, match="requires exact review"):
            jobs.reserve_published_mixed_initial_cleanup_parent(
                proposal, collection=collection,
                expected_snapshot_id=proposal.input["reviewSnapshotId"])


def test_published_mixed_seals_both_attested_plans_atomically(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        plan_set, states, _paths, _binary = _attested_plans(
            jobs, collection, tmp_path)
        sealed = jobs.seal_published_mixed_initial_destroy_plans(
            queued, collection=collection, plan_set=plan_set,
            before_states=states)
        assert sealed.input["phase"] == "plans_sealed"
        assert sealed.input["planSetSha256"] == plan_set.plan_set_sha256
        assert len(sealed.events) == 2


@pytest.mark.parametrize("drift", ["plan", "state", "binding", "binary"])
def test_published_mixed_seal_rolls_back_drift(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        plan_set, states, paths, binary = _attested_plans(
            jobs, collection, tmp_path)
        provider = collection.review.source.ordered_providers[0]
        if drift == "plan":
            paths[provider].write_bytes(b"changed-plan")
        elif drift == "state":
            path = collection.workspaces[provider] / "terraform.tfstate"
            path.write_bytes(path.read_bytes() + b" ")
        elif drift == "binary":
            binary.write_bytes(b"changed-binary")
        else:
            db.session.add(EngagementServiceModel(
                engagement_id=collection.review.source.engagement_id,
                service_id="drift", service_type="test", name="drift",
                proxy_id="proxy", status="pending", config={},
                apply_job_id=""))
            db.session.commit()
        with pytest.raises(ValueError, match="require fresh seal"):
            jobs.seal_published_mixed_initial_destroy_plans(
                queued, collection=collection, plan_set=plan_set,
                before_states=states)
        assert jobs.get(queued.id) == queued


@pytest.mark.parametrize("lose_lease", [False, True])
def test_published_mixed_first_absence_receipt_persists_only_under_claim_and_fence(
        client, ready, tmp_path, monkeypatch, lose_lease):
    with client.application.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        plans, states, _paths, _binary = _attested_plans(jobs, collection, tmp_path)
        parent = jobs.seal_published_mixed_initial_destroy_plans(
            queued, collection=collection, plan_set=plans, before_states=states)
        first = collection.review.source.ordered_providers[0]
        child = jobs.save(_awaiting(parent, collection.review, plans,
                                    collection.core_inspector_scope, first))
        now = datetime.now(timezone.utc)
        at = now.isoformat()
        expiry = (now + timedelta(seconds=120)).isoformat()
        claimed = jobs.claim_lease(
            child.id, owner="worker", token="opaque-token", claimed_at=at,
            expires_at=expiry, eligible_statuses={"running"})
        assert claimed is not None
        receipt = prove_published_mixed_provider_absence(
            jobs.get(collection.review.source.parent_job_id), parent,
            collection.review, plans, first, claimed,
            _empty_snapshot(plans.plans[0]),
            collection.core_inspector_scope, "Opaque",
            fence=lambda: "stable", process_quiescent=lambda identity: True)
        event = propose_published_mixed_first_absence_event(claimed, receipt)
        if lose_lease:
            db.session.delete(db.session.get(
                CoreMutationLeaseModel, collection.review.source.engagement_id))
            db.session.commit()
        saved = jobs.finish_if_running_claimed(
            claimed, owner="worker", token="opaque-token",
            expected_event_digest=job_event_digest(claimed.events),
            status="succeeded", finished_at=(now + timedelta(seconds=1)).isoformat(),
            event=event)
        if lose_lease:
            assert saved is None
            assert jobs.get(claimed.id).events == claimed.events
            return
        assert saved is not None
        assert saved.status == "succeeded"
        assert "claimOwner" not in saved.input
        assert saved.events[-1].data["receiptSha256"] == receipt.receipt_sha256
        assert jobs.finish_if_running_claimed(
            claimed, owner="worker", token="opaque-token",
            expected_event_digest=job_event_digest(claimed.events),
            status="succeeded", finished_at=(now + timedelta(seconds=2)).isoformat(),
            event=event) is None
        assert jobs.get(saved.id) == saved
