# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted no-write first absence handoff and rc0 recovery."""

from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest
from sqlalchemy import text

from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_published_first_absence_worker import (
    PublishedMixedFirstAbsenceAttention, finish_published_mixed_first_absence,
    reconcile_published_mixed_first_result,
)
from app.services.provider_keyed_mixed_published_first_destroy_go import run_published_mixed_first_provider_destroy
from app.services.provider_keyed_mixed_published_first_destroy_go import run_published_mixed_second_provider_destroy
from app.services.provider_keyed_mixed_published_second_absence_worker import (
    PublishedMixedSecondAbsenceAttention, finish_published_mixed_second_absence,
    reconcile_published_mixed_second_result,
)
from app.services.provider_keyed_mixed_published_tail_authority import (
    PublishedMixedTailAuthorityAttention, audit_published_mixed_tail_authority,
)
from app.services.provider_keyed_oci_core_state import (
    OciCoreStateInventory, OciCoreStateResource,
)
from app.services.provider_keyed_mixed_published_destroy_child import child_id
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.database import db
from app.storage.models import EngagementServiceModel
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_published_first_destroy_go import _fake_runner, _sealed
import app.services.provider_keyed_mixed_published_first_absence_worker as absence
import app.services.provider_keyed_mixed_published_first_destroy_go as go_module
import app.services.provider_keyed_mixed_published_post_first_collector as post_first
import app.services.provider_keyed_mixed_published_tail_authority as tail


def _worker(ready, collection, monkeypatch):
    source = collection.review.source
    monkeypatch.setattr(absence, "active_core_connection_details",
                        lambda jobs, engagement: (source.core_job_id, []))
    monkeypatch.setattr(absence, "_core_inspector_scope",
                        lambda core, **kwargs: collection.core_inspector_scope)
    lease = lambda engagement: (source.core_plan_id,
                                "provider_keyed_teardown_fence")
    return dict(
        job_repository=SqlAlchemyJobRepository(), lease_lookup=lease,
        process_quiescent=lambda identity: True,
        credential_repository=ready.case.args["credential_repository"],
    )


def _snapshot_after(plan, generation):
    raw = json.dumps({
        "version": 4, "terraform_version": "1.15.5",
        "lineage": plan.state_lineage, "serial": plan.state_serial + 1,
        "resources": [],
    }).encode()
    return _snapshot(plan.provider, tag=plan.provider == "digitalocean",
                     phase="destroy_applied", state=raw, generation=generation)


def test_first_absence_takes_distinct_claim_after_exact_provider_get(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, plans, first, root, go = _sealed(
            ready, tmp_path, monkeypatch)
        calls = []
        go["gated_command_runner"] = _fake_runner(first, root, calls)
        handed_off = run_published_mixed_first_provider_destroy(parent.id, **go)
        assert datetime.fromisoformat(handed_off.input["claimExpiresAt"]) <= (
            datetime.now(timezone.utc))
        kwargs = _worker(ready, collection, monkeypatch)
        kwargs["job_repository"] = jobs
        snapshots = []
        claims = []
        original_claim = jobs.claim_lease

        def claim(*args, **kw):
            claims.append(kw["owner"])
            return original_claim(*args, **kw)

        monkeypatch.setattr(jobs, "claim_lease", claim)

        def collect(initial, provider, workspace, *, fence, **kwargs):
            snapshots.append(provider)
            assert kwargs["phase_mode"] == "destroy_applied"
            return _snapshot_after(plans.plans[0], fence())

        kwargs["snapshot_collector"] = collect
        terminal = finish_published_mixed_first_absence(parent.id, **kwargs)
        assert terminal.status == "succeeded"
        assert len(terminal.events) == 8
        assert "claimOwner" not in terminal.input
        assert terminal.events[7].data["receipt"]["provider"] == first
        assert calls and snapshots == [first]
        assert len(claims) == 1
        assert claims[0] != handed_off.input["claimOwner"]
        assert finish_published_mixed_first_absence(parent.id, **kwargs) == terminal
        assert snapshots == [first]


def test_rc0_result_restarts_without_command_replay_then_finishes_absence(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, plans, first, root, go = _sealed(
            ready, tmp_path, monkeypatch)

        def stop_after_result(command, *, scratch_path, intent_callback,
                              started_callback, result_callback, **kwargs):
            intent = CommandIntent("once", str(root), hashlib.sha256(json.dumps(
                command, separators=(",", ":")).encode()).hexdigest())
            intent_callback(intent)
            started = StartedCommand(intent, ProcessIdentity("boot", 234, 234, 1))
            started_callback(started)
            path = root / "terraform.tfstate"
            before = json.loads(path.read_text())
            path.write_text(json.dumps({
                **before, "serial": before["serial"] + 1, "resources": []}))
            result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
            raise RuntimeError("worker stopped after durable rc0 result")

        go["gated_command_runner"] = stop_after_result
        with pytest.raises(Exception):
            run_published_mixed_first_provider_destroy(parent.id, **go)
        child = jobs.get(child_id(collection.review.source.core_job_id, first))
        assert len(child.events) == 6
        assert json.loads((root / ".barragan-apply-phase.json").read_text())[
            "phase"] == "destroy_started"
        kwargs = _worker(ready, collection, monkeypatch)
        db.session.execute(text("""
            UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', :past)
            WHERE id = :child_id
        """), {"past": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
               "child_id": child.id})
        db.session.commit()
        recovered = reconcile_published_mixed_first_result(parent.id, **{
            key: value for key, value in kwargs.items() if key != "credential_repository"})
        assert len(recovered.events) == 7
        assert json.loads((root / ".barragan-apply-phase.json").read_text())[
            "phase"] == "destroy_applied"
        assert reconcile_published_mixed_first_result(parent.id, **{
            key: value for key, value in kwargs.items() if key != "credential_repository"}) == recovered
        kwargs["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
            _snapshot_after(plans.plans[0], fence()))
        finished = finish_published_mixed_first_absence(parent.id, **kwargs)
        assert finished.status == "succeeded"
        assert len(finished.events) == 8


def test_nonzero_result_cannot_advance_to_absence(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, _plans, first, root, go = _sealed(
            ready, tmp_path, monkeypatch)

        def nonzero(command, *, intent_callback, started_callback,
                    result_callback, **kwargs):
            intent = CommandIntent("once", str(root), hashlib.sha256(json.dumps(
                command, separators=(",", ":")).encode()).hexdigest())
            intent_callback(intent)
            started = StartedCommand(intent, ProcessIdentity("boot", 234, 234, 1))
            started_callback(started)
            result_callback(CommandAuditResult(started, 1, 0, 0, False, False))
            raise RuntimeError("nonzero command")

        go["gated_command_runner"] = nonzero
        with pytest.raises(Exception):
            run_published_mixed_first_provider_destroy(parent.id, **go)
        child = jobs.get(child_id(collection.review.source.core_job_id, first))
        assert len(child.events) == 6
        kwargs = _worker(ready, collection, monkeypatch)
        with pytest.raises(PublishedMixedFirstAbsenceAttention):
            reconcile_published_mixed_first_result(parent.id, **{
                key: value for key, value in kwargs.items()
                if key != "credential_repository"})


def test_expired_first_claim_is_stolen_only_for_exact_absence(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, plans, first, root, go = _sealed(
            ready, tmp_path, monkeypatch)
        go["gated_command_runner"] = _fake_runner(first, root, [])
        child = run_published_mixed_first_provider_destroy(parent.id, **go)
        at = datetime.now(timezone.utc)
        competing = jobs.claim_lease(
            child.id, owner="other-live-worker", token="other-token",
            claimed_at=at.isoformat(),
            expires_at=(at + timedelta(minutes=10)).isoformat(),
            eligible_statuses={"running"})
        assert competing is not None
        kwargs = _worker(ready, collection, monkeypatch)
        kwargs["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
            _snapshot_after(plans.plans[0], fence()))
        with pytest.raises(PublishedMixedFirstAbsenceAttention):
            finish_published_mixed_first_absence(parent.id, **kwargs)
        db.session.execute(text("""
            UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', :past)
            WHERE id = :child_id
        """), {"past": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
               "child_id": child.id})
        db.session.commit()

        def collect(initial, provider, workspace, *, fence, **kw):
            assert jobs.get(child.id).input["claimOwner"] == "other-live-worker"
            return _snapshot_after(plans.plans[0], fence())

        kwargs["snapshot_collector"] = collect
        finished = finish_published_mixed_first_absence(parent.id, **kwargs)
        assert finished.status == "succeeded"
        assert len(finished.events) == 8
        assert "claimOwner" not in finished.input


def test_binding_drift_during_first_absence_get_vetoes_finish(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, plans, first, root, go = _sealed(
            ready, tmp_path, monkeypatch)
        go["gated_command_runner"] = _fake_runner(first, root, [])
        child = run_published_mixed_first_provider_destroy(parent.id, **go)
        kwargs = _worker(ready, collection, monkeypatch)

        def collect(initial, provider, workspace, *, fence, **kw):
            generation = fence()
            db.session.add(EngagementServiceModel(
                engagement_id=collection.review.source.engagement_id,
                service_id="drift", service_type="test", name="drift",
                proxy_id="proxy", status="pending", config={}, apply_job_id=""))
            db.session.commit()
            return _snapshot_after(plans.plans[0], generation)

        kwargs["snapshot_collector"] = collect
        with pytest.raises(PublishedMixedFirstAbsenceAttention):
            finish_published_mixed_first_absence(parent.id, **kwargs)
        assert jobs.get(child.id).events == child.events


def test_second_provider_go_requires_terminal_first_receipt_and_fresh_transition(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, plans, first, first_root, go = _sealed(
            ready, tmp_path, monkeypatch)
        order = collection.review.source.ordered_providers
        second = order[1]
        second_root = collection.workspaces[second]
        (second_root / ".terraform-data").mkdir(exist_ok=True)
        (second_root / ".barragan-apply-phase.json").write_text(json.dumps({
            "schema": "provider-keyed-v2", "phase": "applied"}))
        calls = []
        go["gated_command_runner"] = _fake_runner(first, first_root, calls)
        run_published_mixed_first_provider_destroy(parent.id, **go)

        def no_second_without_receipt(*args, **kwargs):
            calls.append("unreviewed GO")

        go["gated_command_runner"] = no_second_without_receipt
        with pytest.raises(Exception):
            run_published_mixed_second_provider_destroy(parent.id, **go)
        assert calls == [tuple([
            plans.plans[0].terraform_path, "apply", "-input=false",
            "-lock=true", "-no-color", plans.plans[0].plan_path])]

        kwargs = _worker(ready, collection, monkeypatch)
        kwargs["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
            _snapshot_after(plans.plans[0], fence()))
        finished = finish_published_mixed_first_absence(parent.id, **kwargs)

        monkeypatch.setattr(post_first, "active_core_connection_details",
                            lambda jobs, engagement: (
                                collection.review.source.core_job_id, []))
        monkeypatch.setattr(post_first, "_core_inspector_scope",
                            lambda core, **kw: collection.core_inspector_scope)
        monkeypatch.setattr(post_first, "collect_provider_inventory_snapshot",
                            lambda initial, provider, workspace, *, fence, **kw:
                            _snapshot_after(plans.plans[0], fence()))
        monkeypatch.setattr(post_first, "prove_mixed_initial_prior_provider_fresh",
                            lambda initial, child, workspace, **kw:
                            collection.observations[second].classification)
        real_post = post_first.collect_published_mixed_post_first_transition
        monkeypatch.setattr(go_module, "collect_published_mixed_post_first_transition",
                            lambda cleanup_id, **kw: real_post(
                                cleanup_id, process_quiescent=lambda identity: True,
                                **kw))
        # The exact shown JSON is already stored as the sealed plan digest;
        # reconstruct the fixture's deterministic show for the second plan.
        from app.services.provider_keyed_mixed_partial_apply_source import _state
        policy = jobs.get(collection.review.source.parent_job_id).events[5].data[
            "reviewedPolicy"][second]
        _, actual, _ = _state(second, policy,
                              collection.observations[second].state_json)
        shown = json.dumps({
            "format_version": "1.2", "terraform_version": "1.15.5",
            "applyable": True, "complete": True, "errored": False,
            "resource_changes": [{"address": address, "change": {
                "actions": ["delete"], "before": attrs, "after": None,
                "after_unknown": {}}} for address, attrs in actual.items()],
            "prior_state": {"values": {"root_module": {"resources": [
                {"address": address, "mode": "managed", "values": attrs}
                for address, attrs in actual.items()]}}},
            "output_changes": {}, "planned_values": {"root_module": {}},
        })
        assert hashlib.sha256(shown.encode()).hexdigest() == plans.plans[1].show_json_sha256
        go["show_runner"] = lambda command, cwd: shown
        go["gated_command_runner"] = _fake_runner(second, second_root, calls)
        child = run_published_mixed_second_provider_destroy(parent.id, **go)
        assert len(child.events) == 7
        assert child.input["providerIndex"] == 1
        assert child.input["priorAbsenceReceiptSha256"] == (
            finished.events[7].data["receiptSha256"])
        assert len(calls) == 2
        kwargs["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
            _snapshot_after(plans.plans[order.index(provider)], fence()))
        second_terminal = finish_published_mixed_second_absence(parent.id, **kwargs)
        assert second_terminal.status == "succeeded"
        assert len(second_terminal.events) == 8
        assert second_terminal.events[7].data["receipt"]["provider"] == second
        assert finish_published_mixed_second_absence(parent.id, **kwargs) == second_terminal


def _prepared_second(ready, tmp_path, monkeypatch):
    jobs, collection, parent, plans, first, first_root, go = _sealed(
        ready, tmp_path, monkeypatch)
    second = collection.review.source.ordered_providers[1]
    second_root = collection.workspaces[second]
    (second_root / ".terraform-data").mkdir(exist_ok=True)
    (second_root / ".barragan-apply-phase.json").write_text(json.dumps({
        "schema": "provider-keyed-v2", "phase": "applied"}))
    go["gated_command_runner"] = _fake_runner(first, first_root, [])
    run_published_mixed_first_provider_destroy(parent.id, **go)
    kwargs = _worker(ready, collection, monkeypatch)
    kwargs["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
        _snapshot_after(plans.plans[0], fence()))
    finish_published_mixed_first_absence(parent.id, **kwargs)
    monkeypatch.setattr(post_first, "active_core_connection_details",
                        lambda jobs, engagement: (
                            collection.review.source.core_job_id, []))
    monkeypatch.setattr(post_first, "_core_inspector_scope",
                        lambda core, **kw: collection.core_inspector_scope)
    monkeypatch.setattr(post_first, "collect_provider_inventory_snapshot",
                        lambda initial, provider, workspace, *, fence, **kw:
                        _snapshot_after(plans.plans[0], fence()))
    monkeypatch.setattr(post_first, "prove_mixed_initial_prior_provider_fresh",
                        lambda initial, child, workspace, **kw:
                        collection.observations[second].classification)
    real_post = post_first.collect_published_mixed_post_first_transition
    monkeypatch.setattr(go_module, "collect_published_mixed_post_first_transition",
                        lambda cleanup_id, **kw: real_post(
                            cleanup_id, process_quiescent=lambda identity: True,
                            **kw))
    from app.services.provider_keyed_mixed_partial_apply_source import _state
    policy = jobs.get(collection.review.source.parent_job_id).events[5].data[
        "reviewedPolicy"][second]
    _, actual, _ = _state(second, policy,
                          collection.observations[second].state_json)
    shown = json.dumps({
        "format_version": "1.2", "terraform_version": "1.15.5",
        "applyable": True, "complete": True, "errored": False,
        "resource_changes": [{"address": address, "change": {
            "actions": ["delete"], "before": attrs, "after": None,
            "after_unknown": {}}} for address, attrs in actual.items()],
        "prior_state": {"values": {"root_module": {"resources": [
            {"address": address, "mode": "managed", "values": attrs}
            for address, attrs in actual.items()]}}},
        "output_changes": {}, "planned_values": {"root_module": {}},
    })
    assert hashlib.sha256(shown.encode()).hexdigest() == plans.plans[1].show_json_sha256
    go["show_runner"] = lambda command, cwd: shown
    return jobs, collection, parent, plans, second, second_root, go


@pytest.mark.parametrize("drift_stage", ["intent", "go"])
def test_second_go_vetoes_fresh_transition_drift_at_command_gate(
        client, ready, tmp_path, monkeypatch, drift_stage):
    with client.application.storage_context():
        jobs, collection, parent, plans, second, root, go = _prepared_second(
            ready, tmp_path, monkeypatch)
        real_collect = go_module.collect_published_mixed_post_first_transition
        reads = []

        def drifting(*args, **kwargs):
            reads.append(1)
            result = real_collect(*args, **kwargs)
            threshold = 4 if drift_stage == "intent" else 5
            if len(reads) >= threshold:
                from dataclasses import replace
                return replace(result, transition=replace(
                    result.transition, second_state_sha256="0" * 64))
            return result

        monkeypatch.setattr(go_module,
                            "collect_published_mixed_post_first_transition",
                            drifting)
        calls = []
        go["gated_command_runner"] = _fake_runner(second, root, calls)
        with pytest.raises(Exception):
            run_published_mixed_second_provider_destroy(parent.id, **go)
        assert len(calls) == 1  # Runner entered, but no GO/state mutation.
        assert (root / "terraform.tfstate").read_bytes() == (
            collection.observations[second].state_json)
        assert json.loads((root / ".barragan-apply-phase.json").read_text())[
            "phase"] == "applied"


def test_second_uncertain_intent_never_replays(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, plans, second, root, go = _prepared_second(
            ready, tmp_path, monkeypatch)
        calls = []

        def stopped(command, *, intent_callback, **kwargs):
            calls.append("runner")
            intent_callback(CommandIntent("once", str(root), hashlib.sha256(
                json.dumps(command, separators=(",", ":")).encode()).hexdigest()))
            raise RuntimeError("stop after second durable intent")

        go["gated_command_runner"] = stopped
        for _ in range(2):
            with pytest.raises(Exception):
                run_published_mixed_second_provider_destroy(parent.id, **go)
        assert calls == ["runner"]
        child = jobs.get(child_id(collection.review.source.core_job_id, second))
        assert len(child.events) == 4


def test_second_rc0_result_restarts_without_replaying_command(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, plans, second, root, go = _prepared_second(
            ready, tmp_path, monkeypatch)

        def stop_after_result(command, *, intent_callback, started_callback,
                              result_callback, **kwargs):
            intent = CommandIntent("once", str(root), hashlib.sha256(json.dumps(
                command, separators=(",", ":")).encode()).hexdigest())
            intent_callback(intent)
            started = StartedCommand(intent, ProcessIdentity("boot", 234, 234, 1))
            started_callback(started)
            path = root / "terraform.tfstate"
            state = json.loads(path.read_text())
            path.write_text(json.dumps({
                **state, "serial": state["serial"] + 1, "resources": []}))
            result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
            raise RuntimeError("stopped after second rc0 result")

        go["gated_command_runner"] = stop_after_result
        with pytest.raises(Exception):
            run_published_mixed_second_provider_destroy(parent.id, **go)
        child = jobs.get(child_id(collection.review.source.core_job_id, second))
        assert len(child.events) == 6
        db.session.execute(text("""
            UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', :past)
            WHERE id = :child_id
        """), {"past": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
               "child_id": child.id})
        db.session.commit()
        kwargs = _worker(ready, collection, monkeypatch)
        recovered = reconcile_published_mixed_second_result(parent.id, **{
            key: value for key, value in kwargs.items()
            if key != "credential_repository"})
        assert len(recovered.events) == 7
        assert json.loads((root / ".barragan-apply-phase.json").read_text())[
            "phase"] == "destroy_applied"
        kwargs["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
            _snapshot_after(plans.plans[
                collection.review.source.ordered_providers.index(provider)], fence()))
        finished = finish_published_mixed_second_absence(parent.id, **kwargs)
        assert len(finished.events) == 8
        assert finished.status == "succeeded"


@pytest.mark.parametrize("drift", ["first_child", "core", "binding"])
def test_second_absence_vetoes_source_drift_during_two_provider_gets(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, collection, parent, plans, second, root, go = _prepared_second(
            ready, tmp_path, monkeypatch)
        go["gated_command_runner"] = _fake_runner(second, root, [])
        child = run_published_mixed_second_provider_destroy(parent.id, **go)
        kwargs = _worker(ready, collection, monkeypatch)
        order = collection.review.source.ordered_providers

        def collect(initial, provider, workspace, *, fence, **kw):
            generation = fence()
            if ((drift == "first_child" and provider == order[0])
                    or (drift in {"core", "binding"} and provider == order[1])):
                if drift == "binding":
                    db.session.add(EngagementServiceModel(
                        engagement_id=collection.review.source.engagement_id,
                        service_id="drift", service_type="test", name="drift",
                        proxy_id="proxy", status="pending", config={},
                        apply_job_id=""))
                    db.session.commit()
                else:
                    target_id = (child_id(collection.review.source.core_job_id,
                                          order[0]) if drift == "first_child"
                                 else collection.review.source.core_job_id)
                    original = jobs.get(target_id)
                    from dataclasses import replace
                    jobs.save(replace(original, input={**original.input,
                                                       "drift": True}))
            return _snapshot_after(plans.plans[order.index(provider)], generation)

        kwargs["snapshot_collector"] = collect
        with pytest.raises(PublishedMixedSecondAbsenceAttention):
            finish_published_mixed_second_absence(parent.id, **kwargs)
        assert jobs.get(child.id).events == child.events


@pytest.mark.parametrize("drift", [None, "inspector", "core"])
def test_published_tail_reopens_both_terminal_receipts_and_core_inspector(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, collection, parent, plans, second, root, go = _prepared_second(
            ready, tmp_path, monkeypatch)
        go["gated_command_runner"] = _fake_runner(second, root, [])
        run_published_mixed_second_provider_destroy(parent.id, **go)
        kwargs = _worker(ready, collection, monkeypatch)
        order = collection.review.source.ordered_providers
        kwargs["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
            _snapshot_after(plans.plans[order.index(provider)], fence()))
        finish_published_mixed_second_absence(parent.id, **kwargs)
        monkeypatch.setattr(tail, "_default_state_root",
                            lambda: ready.case.state_root)
        inventory = OciCoreStateInventory(
            "a" * 64, "b" * 64, "123e4567-e89b-12d3-a456-426614174000", 1,
            (OciCoreStateResource("oci_core_instance.homebase",
                                  "ocid1.instance.oc1.fixture", None),))
        calls = {"core": 0, "inspector": 0}

        def core_reader(core, plan, root):
            calls["core"] += 1
            from dataclasses import replace
            return (replace(inventory, raw_state_sha256="0" * 64)
                    if drift == "core" and calls["core"] == 2 else inventory)

        def inspector_reader(engagement, repo, resources):
            calls["inspector"] += 1
            return (("changed-host", "inspector-firewall")
                    if drift == "inspector" and calls["inspector"] == 2
                    else ("inspector-host", "inspector-firewall"))

        options = dict(
            environment="devtest", job_repository=jobs,
            lease_lookup=kwargs["lease_lookup"],
            process_quiescent=lambda identity: True,
            credential_repository=ready.case.args["credential_repository"],
            inventory_collector=kwargs["snapshot_collector"],
            core_inventory_reader=core_reader,
            inspector_record_reader=inspector_reader)
        if drift is None:
            authority = audit_published_mixed_tail_authority(parent.id, **options)
            assert tuple(row.provider for row in authority.provider_receipts) == order
            assert authority.core_state_sha256 == inventory.raw_state_sha256
            assert authority.owned_inspector_record_ids == (
                "inspector-host", "inspector-firewall")
        else:
            with pytest.raises(PublishedMixedTailAuthorityAttention):
                audit_published_mixed_tail_authority(parent.id, **options)
