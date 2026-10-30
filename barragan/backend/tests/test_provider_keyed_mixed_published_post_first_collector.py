# Copyright (c) 2026, Oracle and/or its affiliates.
"""Restart after provider 1 rereads saved rows and fresh two-provider facts."""

from dataclasses import replace
import json

import pytest

from app.services.provider_keyed_mixed_published_absence import (
    prove_published_mixed_provider_absence,
    propose_published_mixed_first_absence_event,
)
from app.services.provider_keyed_mixed_published_post_first_collector import (
    PublishedMixedPostFirstCollectionAttention,
    collect_published_mixed_post_first_transition,
)
from app.storage.database import db
from app.storage.models import EngagementServiceModel
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_published_absence import _awaiting
from test_provider_keyed_mixed_published_teardown_reservation import (
    _attested_plans, _persisted,
)


@pytest.mark.parametrize("drift", [None, "historical", "binding", "lease",
                                   "second_state", "first_absence",
                                   "first_during_get"])
def test_post_first_collector_requires_persisted_receipt_and_fresh_source(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        plans, states, _paths, _binary = _attested_plans(jobs, collection, tmp_path)
        cleanup = jobs.seal_published_mixed_initial_destroy_plans(
            queued, collection=collection, plan_set=plans, before_states=states)
        review = collection.review
        first, second = review.source.ordered_providers
        generation = f"{cleanup.id}:{plans.plan_set_sha256}"
        post = json.dumps({
            "version": 4, "terraform_version": "1.15.5",
            "lineage": plans.plans[0].state_lineage,
            "serial": plans.plans[0].state_serial + 1,
            "resources": [],
        }).encode()
        snapshot = _snapshot(first, tag=first == "digitalocean",
                             phase="destroy_applied", state=post,
                             generation=generation)
        child = _awaiting(cleanup, review, plans,
                          collection.core_inspector_scope, first)
        initial = jobs.get(review.source.parent_job_id)
        receipt = prove_published_mixed_provider_absence(
            initial, cleanup, review, plans, first, child,
            snapshot, collection.core_inspector_scope, "Opaque",
            fence=lambda: generation, process_quiescent=lambda identity: True)
        child = replace(child, status="succeeded",
                        finished_at=child.started_at, events=[
            *child.events,
            propose_published_mixed_first_absence_event(child, receipt)])
        jobs.save(child)
        workspace = collection.workspaces[first]
        workspace.joinpath("terraform.tfstate").write_bytes(post)
        workspace.joinpath(".barragan-apply-phase.json").write_text(json.dumps({
            "schema": "provider-keyed-v2", "phase": "destroy_applied"}))
        import app.services.provider_keyed_mixed_published_post_first_collector as module
        monkeypatch.setattr(module, "active_core_connection_details",
                            lambda jobs, engagement: (review.source.core_job_id, []))
        monkeypatch.setattr(module, "_core_inspector_scope",
                            lambda core, **kwargs: collection.core_inspector_scope)
        def fresh_first(parent, provider, workspace, **kwargs):
            if drift == "first_during_get":
                jobs.save(replace(child, input={**child.input, "drift": True}))
            return snapshot
        monkeypatch.setattr(module, "collect_provider_inventory_snapshot", fresh_first)
        monkeypatch.setattr(module, "prove_mixed_initial_prior_provider_fresh",
                            lambda parent, child, workspace, **kwargs:
                            collection.observations[second].classification)
        if drift == "historical":
            row = jobs.get(review.source.core_job_id)
            jobs.save(replace(row, input={**row.input, "drift": True}))
        elif drift == "binding":
            db.session.add(EngagementServiceModel(
                engagement_id=review.source.engagement_id,
                service_id="drift", service_type="test", name="drift",
                proxy_id="proxy", status="pending", config={},
                apply_job_id=""))
            db.session.commit()
        elif drift == "lease":
            from app.storage.models import CoreMutationLeaseModel
            db.session.delete(db.session.get(CoreMutationLeaseModel,
                                             review.source.engagement_id))
            db.session.commit()
        elif drift == "second_state":
            path = collection.workspaces[second] / "terraform.tfstate"
            path.write_bytes(path.read_bytes() + b" ")
        elif drift == "first_absence":
            snapshot = replace(snapshot, phase="apply")
        call = lambda: collect_published_mixed_post_first_transition(
            cleanup.id, job_repository=jobs,
            process_quiescent=lambda identity: True)
        if drift is None:
            result = call()
            assert result.transition.first_absence.receipt_sha256 == receipt.receipt_sha256
            assert result.transition.second_provider == second
        else:
            with pytest.raises(PublishedMixedPostFirstCollectionAttention):
                call()
