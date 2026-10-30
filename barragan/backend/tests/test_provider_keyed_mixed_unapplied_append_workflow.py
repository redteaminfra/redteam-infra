# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted no-Apply reservation uses the existing two-provider destroy path."""
from dataclasses import asdict, replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_published_teardown_collector as collector
from app.services import provider_keyed_mixed_unapplied_append_teardown as noapply
from app.services import provider_keyed_mixed_failed_append_teardown as failure
from app.services.provider_keyed_mixed_append_pair_plan_worker import _canonical, _name
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup, saved_published_mixed_initial_review,
)
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_reservation import _persisted, _attested_plans
from test_provider_keyed_mixed_unapplied_append_teardown import rows


def collection_for_no_apply(ready, tmp_path, monkeypatch, phase):
    jobs, original, _ = _persisted(ready, tmp_path, monkeypatch)
    source = original.review.source
    parent, plan, _, _ = rows(source.core_job_id, source.core_plan_id,
        source.engagement_id, phase=phase)
    jobs.save(parent)
    jobs.save(plan)
    for provider, path in original.workspaces.items():
        (path / _name(provider, "predecessor.tfstate")).write_bytes(original.observations[provider].state_json)
        (path / _name(provider, "predecessor.tfstate")).chmod(0o600)
        (path / ".barragan-apply-phase.json").write_text('{"schema":"provider-keyed-v2","phase":"applied"}')
    binary = tmp_path / "retained-append-terraform"
    binary.write_bytes(b"unchanged reviewed binary")
    # The source/plan-authentication suite exercises the real plan reopener.
    # Here the injected read-only witness composes with real SQLite fencing,
    # snapshot decoding, destroy-plan sealing and both absence transitions.
    monkeypatch.setattr(noapply, "_artifacts", lambda *_: {})
    def witness(review, initial, append, *, jobs, **kwargs):
        return {"kind": noapply.KIND, "appendParentId": append.id, "failedProvider": None,
            "source": json.loads(json.dumps(asdict(review.source))), "evidence": {
                "rowsSha256": noapply._rows_digest(append, jobs), "artifacts": {},
                "reviewSha256": "a" * 64, "initialSha256": _canonical(asdict(initial)),
                "terraform": {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}}}
    monkeypatch.setattr(noapply, "build_no_apply_recovery", witness)
    monkeypatch.setattr(failure, "fresh_failed_append_observation", lambda _initial, _append, provider, *args, **kwargs: original.observations[provider])
    monkeypatch.setattr(collector, "active_core_connection_details", lambda *_: (source.core_job_id, []))
    monkeypatch.setattr(collector, "_core_inspector_scope", lambda *args, **kwargs: original.core_inspector_scope)
    db.session.add(CoreMutationLeaseModel(engagement_id=source.engagement_id,
        owner_id=source.core_plan_id, operation="provider_keyed_mixed_append"))
    db.session.commit()
    return jobs, collector.collect_published_mixed_initial_teardown(source.engagement_id,
        source.core_job_id, job_repository=jobs)


def historical(review, jobs):
    from app.services.provider_keyed_mixed_published_teardown_authority import historical_published_mixed_rows_sha256
    from app.services.provider_keyed_mixed_initial_apply_child import _child_id
    from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
    from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
    from app.services.provider_keyed_mixed_strict_host_receipt import child_id
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
    source = review.source
    return historical_published_mixed_rows_sha256(parent=jobs.get(source.parent_job_id),
        core=jobs.get(source.core_job_id), plan=SqlAlchemyDeploymentPlanRepository().get(source.core_plan_id),
        binding=jobs.get(_binding_child_id(source.core_job_id)), bootstrap=jobs.get(_worker_id(source.core_job_id)),
        proof_child=jobs.get(child_id(source.core_job_id)),
        apply_children={p: jobs.get(_child_id(source.core_job_id, p)) for p in source.ordered_providers},
        chains={row.chain_id: row for row in SqlAlchemySketchChainRepository().list_for_engagement(source.engagement_id)
                if row.chain_id in source.chain_ids},
        failed_append_recovery=review.failed_append_recovery, jobs=jobs)


@pytest.mark.parametrize("phase", ["planning", "apply_sealed"])
def test_no_apply_review_reservation_restart_and_both_absence_transitions(client, ready, tmp_path, monkeypatch, phase):
    from app.services.provider_keyed_mixed_published_absence import (
        prove_published_mixed_provider_absence, propose_published_mixed_first_absence_event,
    )
    from app.services.provider_keyed_mixed_published_second_transition import review_published_mixed_second_transition
    from test_provider_keyed_mixed_published_absence import _awaiting, _empty_snapshot
    with client.application.storage_context():
        jobs, collection = collection_for_no_apply(ready, tmp_path, monkeypatch, phase)
        review, scope = collection.review, collection.core_inspector_scope
        assert sum(row["kind"] in {"instance", "droplet"} for provider in review.provider_scopes for row in provider["resources"]) == 4
        proposal = propose_published_mixed_initial_cleanup(review, scope, "Opaque", requested_by="operator")
        parent = jobs.reserve_published_mixed_initial_cleanup_parent(proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        assert saved_published_mixed_initial_review(parent) == review
        lease = db.session.get(CoreMutationLeaseModel, review.source.engagement_id)
        assert lease.operation == "provider_keyed_teardown_fence"
        plans, states, *_ = _attested_plans(jobs, collection, tmp_path)
        parent = jobs.seal_published_mixed_initial_destroy_plans(parent, collection=collection,
            plan_set=plans, before_states=states)
        initial = jobs.get(review.source.parent_job_id)
        first, second = review.source.ordered_providers
        first_child = _awaiting(parent, review, plans, scope, first)
        snapshot = _empty_snapshot(plans.plans[0])
        receipt = prove_published_mixed_provider_absence(initial, parent, review, plans, first,
            first_child, snapshot, scope, "Opaque", fence=lambda: "stable", process_quiescent=lambda _: True)
        first_child = jobs.save(replace(first_child, status="succeeded", finished_at=first_child.started_at,
            events=[*first_child.events, propose_published_mixed_first_absence_event(first_child, receipt)]))
        collection.workspaces[first].joinpath("terraform.tfstate").write_bytes(snapshot.state_json)
        collection.workspaces[first].joinpath(".barragan-apply-phase.json").write_text('{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
        assert historical(review, jobs) == review.historical_rows_sha256
        transition = review_published_mixed_second_transition(initial, parent, review, plans,
            first_child, snapshot, collection.observations[second], scope, "Opaque",
            fence=lambda: "stable", process_quiescent=lambda _: True,
            historical_source_unchanged=lambda: historical(review, jobs) == review.historical_rows_sha256,
            fresh_core_inspector_scope=lambda: scope,
            fresh_empty_bindings=lambda: {kind: () for kind in ("channels", "domains", "certificates", "sites")})
        assert transition.second_state_sha256 == plans.plans[1].before_state_sha256
        second_child = _awaiting(parent, review, plans, scope, second, prior=receipt.receipt_sha256)
        second_snapshot = _empty_snapshot(plans.plans[1])
        second_receipt = prove_published_mixed_provider_absence(initial, parent, review, plans, second,
            second_child, second_snapshot, scope, "Opaque", fence=lambda: "stable", process_quiescent=lambda _: True)
        assert second_receipt.provider == second
        collection.workspaces[second].joinpath("terraform.tfstate").write_bytes(second_snapshot.state_json)
        assert historical(review, jobs) == review.historical_rows_sha256


def test_no_apply_confirmation_rejects_a_racing_command_intent(client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection = collection_for_no_apply(ready, tmp_path, monkeypatch, "apply_sealed")
        review, scope = collection.review, collection.core_inspector_scope
        proposal = propose_published_mixed_initial_cleanup(review, scope, "Opaque", requested_by="operator")
        append = jobs.get(review.failed_append_recovery["appendParentId"])
        jobs.save(replace(append, id=noapply.first_id(append.id), action="provider_keyed_mixed_append_apply_child",
            events=[*append.events, __import__('app.domain', fromlist=['JobEvent']).JobEvent(4, "info", "command intended", {})]))
        with pytest.raises(ValueError):
            jobs.reserve_published_mixed_initial_cleanup_parent(proposal, collection=collection,
                expected_snapshot_id=proposal.input["reviewSnapshotId"])
        assert jobs.get(proposal.id) is None
        assert db.session.get(CoreMutationLeaseModel, review.source.engagement_id).operation == "provider_keyed_mixed_append"


@pytest.mark.parametrize("operation", ["reserve", "start", "claim", "renew", "parent_claim", "parent_renew"])
def test_teardown_writer_fences_late_pristine_bookkeeping(client, ready, tmp_path, monkeypatch, operation):
    from app.domain import JobEvent
    from app.services.provider_keyed_mixed_append_pair_apply_child import _base
    from datetime import datetime, timedelta, timezone
    with client.application.storage_context():
        jobs, collection = collection_for_no_apply(ready, tmp_path, monkeypatch, "apply_sealed")
        append = jobs.get(collection.review.failed_append_recovery["appendParentId"])
        at = "2026-10-19T00:00:00+00:00"
        later = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
        first = replace(append, id=noapply.first_id(append.id), action="provider_keyed_mixed_append_apply_child",
            status="queued", started_at=None, input=_base(append),
            events=[JobEvent(1, "info", "mixed append first Apply queued", {})])
        if operation not in {"reserve", "parent_claim", "parent_renew"}:
            if operation in {"claim", "renew"}:
                first = replace(first, status="running", started_at=at, events=[*first.events,
                    JobEvent(2, "info", "mixed append first Apply started", {})],
                    input={**first.input, "claimOwner": "old", "claimToken": "old-token",
                           "claimExpiresAt": at})
            jobs.save(first)
        elif operation == "parent_renew":
            append = jobs.save(replace(append, input={**append.input,
                "claimOwner": "old", "claimToken": "old-token", "claimExpiresAt": at}))
        # Refresh the authenticated snapshot before transferring the writer fence.
        source = collection.review.source
        collection = collector.collect_published_mixed_initial_teardown(source.engagement_id,
            source.core_job_id, job_repository=jobs)
        proposal = propose_published_mixed_initial_cleanup(collection.review,
            collection.core_inspector_scope, "Opaque", requested_by="operator")
        jobs.reserve_published_mixed_initial_cleanup_parent(proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        from app.services.provider_keyed_mixed_append_apply_runtime import mixed_append_pristine_apply_available
        assert not mixed_append_pristine_apply_available(jobs.get(append.id), jobs=jobs)
        before_parent = jobs.get(append.id)
        before_child = jobs.get(first.id)
        if operation == "reserve":
            with pytest.raises(ValueError, match="lost its mutation lease"):
                jobs.save_if_absent(first)
        elif operation == "start":
            assert jobs.start_if_queued(first, started_at=later,
                event=JobEvent(2, "info", "mixed append first Apply started", {})) is None
        elif operation in {"claim", "parent_claim"}:
            identifier = append.id if operation == "parent_claim" else first.id
            assert jobs.claim_lease(identifier, owner="late", token="late-token",
                claimed_at=later, expires_at=later, eligible_statuses={"running"}) is None
        else:
            identifier = append.id if operation == "parent_renew" else first.id
            assert jobs.renew_lease(identifier, owner="old", token="old-token",
                heartbeat_at=later, expires_at=later) is None
        assert jobs.get(append.id) == before_parent
        assert jobs.get(first.id) == before_child
