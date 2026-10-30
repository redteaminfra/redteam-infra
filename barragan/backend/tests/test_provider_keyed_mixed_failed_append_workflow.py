# Copyright (c) 2026, Oracle and/or its affiliates.
"""Existing four-cloud teardown uses a separately proved failed append receipt."""
from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_published_teardown_collector as collector
from app.services import provider_keyed_mixed_failed_append_teardown as failure
from app.services.provider_keyed_mixed_append_pair_parent import _parent_id as append_id
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _canonical
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup, saved_published_mixed_initial_review)
from app.services.provider_keyed_mixed_published_teardown_authority import published_review_states
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_reservation import _persisted, _attested_plans


def _failed_collection(ready, tmp_path, monkeypatch, failed_index):
    jobs, original, _ = _persisted(ready, tmp_path, monkeypatch)
    source = original.review.source
    first = source.ordered_providers[failed_index]
    core = jobs.get(source.core_job_id)
    parent = jobs.save(replace(core, id=append_id(core.id), action="provider_keyed_mixed_append",
        status="running", finished_at=None, input={"phase": "apply_sealed", "providerOrder":
            [first, next(p for p in source.ordered_providers if p != first)],
            "historicalRowsSha256": original.review.historical_rows_sha256,
            "liveBindingsSha256": _canonical({"schema": "mixed-append-live-bindings-v1", "bindings": {k: () for k in ("channels", "domains", "certificates", "sites")}})}))
    from app.services.provider_keyed_mixed_append_live_bindings import collect_mixed_append_live_bindings
    parent = jobs.save(replace(parent, input={**parent.input, "liveBindingsSha256": _canonical({
        "schema": "mixed-append-live-bindings-v1", "bindings": collect_mixed_append_live_bindings(
            source.engagement_id, job_repository=jobs)})}))
    observed = dict(original.observations)
    for provider, path in original.workspaces.items():
        (path / _name(provider, "predecessor.tfstate")).write_bytes(observed[provider].state_json)
        (path / _name(provider, "predecessor.tfstate")).chmod(0o600)
        (path / ".barragan-apply-phase.json").write_text(json.dumps({
            "schema": "provider-keyed-v2", "phase": "apply_started" if provider == first else "applied"}))
        if provider == first:
            raw = json.loads(observed[provider].state_json)
            raw["serial"] += 3
            raw["resources"] = [row for row in raw["resources"] if row["type"] != "local_file"]
            blob = json.dumps(raw).encode()
            (path / "terraform.tfstate").write_bytes(blob)
            old = observed[provider].classification
            observed[provider] = ProviderHostObservation(replace(old,
                state_sha256=__import__('hashlib').sha256(blob).hexdigest(), serial=raw["serial"]), blob)
            (path / _name(provider, "show.json")).write_text(json.dumps({"resource_changes": [
                {"address": address, "change": {"actions": ["delete"]}} for address in failure._LOCAL]}))
            (path / _name(provider, "show.json")).chmod(0o600)
    # Separate exact journal/artifact tests cover this readonly witness; orchestration is real SQL.
    monkeypatch.setattr(failure, "immutable_failure_evidence", lambda *_a, **_k: {"exact": "saved-failure"})
    monkeypatch.setattr(collector, "active_core_connection_details", lambda *_: (source.core_job_id, []))
    monkeypatch.setattr(collector, "_core_inspector_scope", lambda *_a, **_k: original.core_inspector_scope)
    monkeypatch.setattr(failure, "fresh_failed_append_observation", lambda _i, _a, p, *_args, **_kwargs: observed[p])
    db.session.add(CoreMutationLeaseModel(engagement_id=source.engagement_id,
        owner_id=source.core_plan_id, operation="provider_keyed_mixed_append"))
    db.session.commit()
    value = collector.collect_published_mixed_initial_teardown(source.engagement_id, source.core_job_id,
        job_repository=jobs)
    return jobs, value


@pytest.mark.parametrize("failed_index", [0, 1])
def test_failed_append_review_start_current_plan_scope_and_restart(client, ready, tmp_path, monkeypatch, failed_index):
    with client.application.storage_context():
        jobs, collection = _failed_collection(ready, tmp_path, monkeypatch, failed_index)
        review = collection.review
        original_state = review.source.provider_states[failed_index]
        assert published_review_states(review)[failed_index].serial == original_state.serial + 3
        assert sum(len(row["resources"]) for row in review.provider_scopes) == 10
        proposal = propose_published_mixed_initial_cleanup(review, collection.core_inspector_scope, "Opaque", requested_by="operator")
        parent = jobs.reserve_published_mixed_initial_cleanup_parent(proposal,
            collection=collection, expected_snapshot_id=proposal.input["reviewSnapshotId"])
        assert saved_published_mixed_initial_review(parent) == review
        lease = db.session.get(CoreMutationLeaseModel, review.source.engagement_id)
        assert lease.operation == "provider_keyed_teardown_fence"
        plans, states, *_ = _attested_plans(jobs, collection, tmp_path)
        assert plans.plans[failed_index].state_serial == original_state.serial + 3
        sealed = jobs.seal_published_mixed_initial_destroy_plans(parent,
            collection=collection, plan_set=plans, before_states=states)
        assert saved_published_mixed_initial_review(sealed) == review
        assert review.source.provider_states[failed_index] == original_state


def _history(review, jobs):
    from app.services.provider_keyed_mixed_published_teardown_authority import historical_published_mixed_rows_sha256
    from app.services.provider_keyed_mixed_initial_apply_child import _child_id
    from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
    from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
    from app.services.provider_keyed_mixed_strict_host_receipt import child_id
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
    source = review.source
    return historical_published_mixed_rows_sha256(parent=jobs.get(source.parent_job_id),
        core=jobs.get(source.core_job_id), plan=SqlAlchemyDeploymentPlanRepository().get(source.core_plan_id),
        binding=jobs.get(_binding_child_id(source.core_job_id)), bootstrap=jobs.get(_worker_id(source.core_job_id)),
        proof_child=jobs.get(child_id(source.core_job_id)),
        apply_children={p: jobs.get(_child_id(source.core_job_id, p)) for p in source.ordered_providers},
        chains={row.chain_id: row for row in SqlAlchemySketchChainRepository().list_for_engagement(source.engagement_id)},
        failed_append_recovery=review.failed_append_recovery, jobs=jobs)


@pytest.mark.parametrize("failed_index", [0, 1])
def test_failed_append_history_and_real_second_transition_after_first_destroy(client, ready, tmp_path, monkeypatch, failed_index):
    from app.services.provider_keyed_mixed_published_absence import prove_published_mixed_provider_absence, propose_published_mixed_first_absence_event
    from app.services.provider_keyed_mixed_published_second_transition import review_published_mixed_second_transition
    from test_provider_keyed_mixed_published_absence import _awaiting, _empty_snapshot
    with client.application.storage_context():
        jobs, collection = _failed_collection(ready, tmp_path, monkeypatch, failed_index)
        review, scope = collection.review, collection.core_inspector_scope
        queued = propose_published_mixed_initial_cleanup(review, scope, "Opaque", requested_by="operator")
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(queued, collection=collection,
            expected_snapshot_id=queued.input["reviewSnapshotId"])
        plans, states, *_ = _attested_plans(jobs, collection, tmp_path)
        parent = jobs.seal_published_mixed_initial_destroy_plans(queued, collection=collection,
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
        collection.workspaces[first].joinpath(".barragan-apply-phase.json").write_text(
            '{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
        assert _history(review, jobs) == review.historical_rows_sha256
        transition = review_published_mixed_second_transition(initial, parent, review, plans,
            first_child, snapshot, collection.observations[second], scope, "Opaque",
            fence=lambda: "stable", process_quiescent=lambda _: True,
            historical_source_unchanged=lambda: _history(review, jobs) == review.historical_rows_sha256,
            fresh_core_inspector_scope=lambda: scope,
            fresh_empty_bindings=lambda: {kind: () for kind in ("channels", "domains", "certificates", "sites")})
        assert transition.second_state_sha256 == plans.plans[1].before_state_sha256
        # Same immutable source remains valid when both providers are gone.
        collection.workspaces[second].joinpath("terraform.tfstate").write_bytes(_empty_snapshot(plans.plans[1]).state_json)
        collection.workspaces[second].joinpath(".barragan-apply-phase.json").write_text(
            '{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
        assert _history(review, jobs) == review.historical_rows_sha256


def test_failed_provider_apply_started_is_accepted_at_both_existing_destroy_go_fences(client, ready, tmp_path, monkeypatch):
    from app.services import provider_keyed_mixed_published_first_destroy_go as worker
    from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
    from test_provider_keyed_mixed_published_first_destroy_go import _fake_runner
    import hashlib
    with client.application.storage_context():
        jobs, collection = _failed_collection(ready, tmp_path, monkeypatch, 0)
        review, scope = collection.review, collection.core_inspector_scope
        queued = propose_published_mixed_initial_cleanup(review, scope, "Opaque", requested_by="operator")
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(queued, collection=collection,
            expected_snapshot_id=queued.input["reviewSnapshotId"])
        plans, states, _, binary, shows = _attested_plans(jobs, collection, tmp_path, with_shows=True)
        parent = jobs.seal_published_mixed_initial_destroy_plans(queued, collection=collection,
            plan_set=plans, before_states=states)
        provider = review.source.ordered_providers[0]
        root = collection.workspaces[provider]
        (root / ".terraform-data").mkdir(exist_ok=True)
        calls = []
        monkeypatch.setattr(worker, "collect_published_mixed_initial_teardown", lambda *_a, **_k: collection)
        child = worker.run_published_mixed_first_provider_destroy(parent.id, environment="devtest", job_repository=jobs,
            lease_lookup=lambda _: (review.source.core_plan_id, "provider_keyed_teardown_fence"),
            credential_repository=ready.case.args["credential_repository"],
            show_runner=lambda *_: shows[provider], release_validator=lambda **_: ProviderKeyedTerraformRelease(
                binary, hashlib.sha256(binary.read_bytes()).hexdigest(), "1.15.5", "linux_amd64"),
            gated_command_runner=_fake_runner(provider, root, calls))
        assert child.events[-1].message == "published mixed provider awaiting exact absence"
        assert len(calls) == 1
