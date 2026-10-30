# Copyright (c) 2026, Oracle and/or its affiliates.
"""Both-provider terminal receipts remain read-only and fail closed."""

from dataclasses import asdict, replace
import hashlib
import json

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as initial_child_id, run_mixed_initial_provider_apply,
)
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    _canonical, propose_mixed_interrupted_cleanup,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
    bind_mixed_interrupted_destroy_plans,
)
from app.services.provider_keyed_mixed_interrupted_destroy_source import bind_mixed_interrupted_destroy_show
from app.services.provider_keyed_mixed_interrupted_destroy_child import (
    _digest as command_digest, propose_mixed_interrupted_destroy_child,
)
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import (
    MixedInterruptedPostSketchAbsenceAttention,
    prove_mixed_interrupted_provider_absence,
    prove_mixed_interrupted_post_sketch_absence,
)
from app.services.provider_keyed_mixed_interrupted_source import (
    review_mixed_interrupted_source, _digest as review_digest,
)
from app.storage.job_repository import StoredJobRun, job_event_digest
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_interrupted_destroy_source import saved, _release
from test_provider_keyed_mixed_initial_apply_proof import _state_and_rows
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_mixed_interrupted_source import MixedInterruptedProviderScope


def _sealed(initial, review):
    order = review.ordered_providers
    plans = bind_mixed_interrupted_destroy_plans(
        initial, review, {provider: None for provider in order},
        {provider: None for provider in order},
        {provider: None for provider in order}, fence=lambda: "stable")
    parent = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
    parent = replace(parent, input={**parent.input, "phase": "plans_sealed"},
                     events=parent.events + [JobEvent(2, "info", "both mixed destroy plans sealed",
                          {"planSet": _canonical(asdict(plans)),
                           "planSetSha256": plans.plan_set_sha256})])
    return parent, plans


def test_both_orders_unstarted_prove_exact_empty_provider_receipts(ready):
    initial = ready.parent
    order = tuple(initial.input["orderedProviders"])
    snapshots = {provider: _snapshot(provider) for provider in order}
    children = {provider: None for provider in order}
    review = review_mixed_interrupted_source(
        initial, children, snapshots, fence=lambda: "stable",
        process_quiescent=lambda identity: True)
    parent, plans = _sealed(initial, review)
    proof = prove_mixed_interrupted_post_sketch_absence(
        initial, parent, review, plans, children, children, snapshots,
        fence=lambda: "stable", process_quiescent=lambda identity: True)
    assert proof.ordered_providers == order
    assert [receipt.scope_kind for receipt in proof.receipts] == ["unstarted", "unstarted"]
    assert all(receipt.destroy_child_id is None and receipt.verified_absent_ids == ()
               for receipt in proof.receipts)
    assert len(proof.checkpoint_sha256) == 64
    first = order[0]
    assert prove_mixed_interrupted_provider_absence(
        initial, parent, review, plans, first, None, None, snapshots[first],
        fence=lambda: "stable", process_quiescent=lambda identity: True) == proof.receipts[0]
    changed = {**snapshots, order[0]: _snapshot(order[0], generation="changed")}
    with pytest.raises(MixedInterruptedPostSketchAbsenceAttention):
        prove_mixed_interrupted_post_sketch_absence(
            initial, parent, review, plans, children, children, changed,
            fence=lambda: "stable", process_quiescent=lambda identity: True)


@pytest.mark.parametrize("case", [False], indirect=True)
def test_tag_only_keeps_selector_retirement_pending_without_delete(ready):
    initial = ready.parent
    assert initial.input["orderedProviders"][0] == "digitalocean"
    def stop_before_command(*args, **kwargs):
        raise RuntimeError("stopped before destroy source")
    with pytest.raises(RuntimeError, match="stopped before destroy source"):
        run_mixed_initial_provider_apply(
            provider="digitalocean",
            **{**ready.args, "gated_command_runner": stop_before_command})
    child = ready.case.jobs.get(initial_child_id("job-core", "digitalocean"))
    order = tuple(initial.input["orderedProviders"])
    original = {"digitalocean": child, "linode": None}
    snapshots = {"digitalocean": _snapshot("digitalocean", tag=True),
                 "linode": _snapshot("linode")}
    review = review_mixed_interrupted_source(
        initial, original, snapshots, fence=lambda: "stable",
        process_quiescent=lambda identity: True)
    parent, plans = _sealed(initial, review)
    proof = prove_mixed_interrupted_post_sketch_absence(
        initial, parent, review, plans, original,
        {provider: None for provider in order}, snapshots,
        fence=lambda: "stable", process_quiescent=lambda identity: True)
    assert proof.receipts[0].scope_kind == "tag_only"
    assert proof.receipts[0].selector_retirement_pending is True
    assert proof.receipts[0].destroy_child_id is None
    absent_tag = {**snapshots, "digitalocean": _snapshot("digitalocean", tag=False)}
    with pytest.raises(MixedInterruptedPostSketchAbsenceAttention):
        prove_mixed_interrupted_post_sketch_absence(
            initial, parent, review, plans, original,
            {provider: None for provider in order}, absent_tag,
            fence=lambda: "stable", process_quiescent=lambda identity: True)


def _state_backed_case(saved, *, both=False):
    initial, _, review, _, provider, before, binary, shown, plan_path = saved
    other = review.ordered_providers[1]
    original = StoredJobRun(
        "original-apply", "provider_keyed_mixed_initial_apply_child", "running",
        initial.target, "engagement", initial.target_id, initial.requested_by,
        {}, [], "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00", None,
        [JobEvent(1, "info", "original Apply journal retained", {})])
    scope = replace(review.scopes[0], child_journal_sha256=job_event_digest(original.events))
    scopes = (scope, review.scopes[1])
    before_by_provider = {provider: before, other: None}
    path_by_provider = {provider: plan_path, other: None}
    show_by_provider = {provider: shown, other: None}
    binary_by_provider = {provider: binary, other: None}
    originals = {provider: original, other: None}
    if both:
        policy = initial.events[5].data["reviewedPolicy"][other]
        state, _, _, _ = _state_and_rows(other, policy)
        second_before = json.dumps(state).encode()
        _, actual, cloud = _state(other, policy, second_before)
        second_original = replace(original, id="original-apply-other")
        second_scope = MixedInterruptedProviderScope(
            other, "full", job_event_digest(second_original.events),
            hashlib.sha256(second_before).hexdigest(), state["lineage"], state["serial"],
            tuple(sorted(cloud.items())), "c" * 64, "d" * 64,
            policy.get("selector_tag"), other == "digitalocean")
        scopes = (scope, second_scope)
        originals[other] = second_original
        workspace = next((plan_path.parents[2] / other).iterdir())
        workspace.joinpath("terraform.tfstate").write_bytes(second_before)
        lock = workspace / f".barragan-{other}-plan.lock"
        lock.write_bytes(b"")
        lock.chmod(0o600)
        second_binary = workspace / "terraform-test"
        second_binary.write_bytes(binary.read_bytes())
        second_binary.chmod(0o755)
        second_path = workspace / f".barragan-mixed-interrupted-destroy-{other}.tfplan"
        second_path.write_bytes(b"reviewed-binary-plan-other")
        changes = [{"address": address, "change": {"actions": ["delete"],
                    "before": attrs, "after": None, "after_unknown": {}}}
                   for address, attrs in actual.items()]
        second_shown = json.dumps({
            "format_version": "1.2", "terraform_version": "1.15.5",
            "applyable": True, "complete": True, "errored": False,
            "resource_changes": changes,
            "prior_state": {"values": {"root_module": {"resources": [
                {"address": address, "mode": "managed", "values": attrs}
                for address, attrs in actual.items()]}}},
            "output_changes": {}, "planned_values": {"root_module": {}}})
        before_by_provider[other] = second_before
        path_by_provider[other] = second_path
        show_by_provider[other] = second_shown
        binary_by_provider[other] = second_binary
    payload = {"engagementId": initial.target_id, "coreJobId": review.core_job_id,
               "sealJournalSha256": review.seal_journal_sha256,
               "orderedProviders": review.ordered_providers,
               "scopes": [item.__dict__ for item in scopes]}
    review = replace(review, scopes=scopes, review_sha256=review_digest(payload))
    plans = bind_mixed_interrupted_destroy_plans(
        initial, review, before_by_provider,
        path_by_provider, show_by_provider,
        fence=lambda: "stable")
    cleanup = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
    cleanup = replace(cleanup, input={**cleanup.input, "phase": "plans_sealed"},
                      events=cleanup.events + [JobEvent(2, "info", "both mixed destroy plans sealed",
                           {"planSet": _canonical(asdict(plans)),
                            "planSetSha256": plans.plan_set_sha256})])
    def destroy_child(which, raw, shown_json, prior_receipt=None):
        executable = binary_by_provider[which]
        bound = bind_mixed_interrupted_destroy_show(
            initial, cleanup, review, plans, which, raw, executable,
            hashlib.sha256(executable.read_bytes()).hexdigest(),
            show_runner=lambda command, cwd: shown_json, fence=lambda: "stable",
            release_validator=lambda: _release(executable))
        child = propose_mixed_interrupted_destroy_child(initial, cleanup, review, plans, bound)
        show_data = {
            "showSha256": bound.show_sha256, "planSha256": bound.plan_sha256,
            "terraformSha256": bound.terraform_sha256,
            "beforeStateSha256": bound.before_state_sha256,
            "showArgvSha256": bound.argv_sha256}
        if prior_receipt is not None:
            show_data.update({
                "priorAbsenceObservationSha256": prior_receipt.observation_sha256,
                "priorAbsenceReceiptSha256": hashlib.sha256(json.dumps(
                    asdict(prior_receipt), sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest()})
        prefix = child.events + [
        JobEvent(2, "info", "mixed provider destroy started", {}),
        JobEvent(3, "info", "mixed provider destroy show proved", show_data)]
        intent = JobEvent(4, "info", "mixed provider destroy command intended", {
        "invocationId": "once", "argvSha256": command_digest((
            bound.terraform_path, "apply", "-input=false", "-lock=true",
            "-no-color", bound.plan_path)),
        "showJournalSha256": job_event_digest(prefix),
        "beforeStateSha256": bound.before_state_sha256,
        "planSha256": bound.plan_sha256})
        tail = [intent,
            JobEvent(5, "info", "mixed provider destroy command started before GO", {
                "invocationId": "once", "bootId": "boot", "pid": 10,
                "pgid": 10, "startTicks": 1}),
            JobEvent(6, "info", "mixed provider phase destroy_started",
                     {"commandStartSequence": 5}),
            JobEvent(7, "info", "mixed provider destroy result fenced", {
                "invocationId": "once", "returnCode": 0, "stdoutBytes": 0,
                "stderrBytes": 0, "stdoutTruncated": False, "stderrTruncated": False}),
            JobEvent(8, "info", "mixed provider phase destroy_applied",
                     {"commandResultSequence": 7}),
            JobEvent(9, "info", "mixed provider awaiting exact absence",
                     {"commandResultSequence": 7})]
        return replace(child, status="running", started_at="2026-10-15T00:00:00+00:00",
                       events=prefix + tail)
    destroys = {}
    snapshots = {}
    first_receipt = None
    for which in review.ordered_providers:
        raw = before_by_provider[which]
        if raw is None:
            destroys[which] = None
            snapshots[which] = _snapshot(which)
            continue
        destroys[which] = destroy_child(which, raw, show_by_provider[which], first_receipt)
        prior = json.loads(raw)
        after = json.dumps({"version": 4, "terraform_version": "1.15.5",
                            "lineage": prior["lineage"], "serial": prior["serial"] + 1,
                            "resources": []}).encode()
        snapshots[which] = _snapshot(which, tag=which == "digitalocean",
                                     phase="destroy_applied", state=after)
        if first_receipt is None:
            first_receipt = prove_mixed_interrupted_provider_absence(
                initial, cleanup, review, plans, which, originals[which],
                destroys[which], snapshots[which], fence=lambda: "stable",
                process_quiescent=lambda identity: True)
    return initial, cleanup, review, plans, originals, destroys, snapshots


def test_state_backed_exact_rc0_poststate_and_provider_absence(saved):
    initial, cleanup, review, plans, originals, destroys, snapshots = _state_backed_case(saved)
    provider, other = review.ordered_providers
    child = destroys[provider]
    scope = review.scopes[0]
    prior = json.loads(saved[5])
    proof = prove_mixed_interrupted_post_sketch_absence(
        initial, cleanup, review, plans, originals, destroys, snapshots,
        fence=lambda: "stable", process_quiescent=lambda identity: True)
    receipt = proof.receipts[0]
    assert receipt.destroy_child_id == child.id
    assert receipt.before_state_sha256 == scope.state_sha256
    assert receipt.after_serial == prior["serial"] + 1
    assert receipt.verified_absent_ids == tuple(sorted({identifier for _, identifier in scope.resource_ids}))
    assert prove_mixed_interrupted_provider_absence(
        initial, cleanup, review, plans, provider, originals[provider], child,
        snapshots[provider], fence=lambda: "stable",
        process_quiescent=lambda identity: True) == receipt
    with pytest.raises(MixedInterruptedPostSketchAbsenceAttention):
        prove_mixed_interrupted_post_sketch_absence(
            initial, cleanup, review, plans, originals,
            {provider: replace(child, events=child.events[:-1]), other: None}, snapshots,
            fence=lambda: "stable", process_quiescent=lambda identity: True)
    with pytest.raises(MixedInterruptedPostSketchAbsenceAttention):
        prove_mixed_interrupted_post_sketch_absence(
            initial, cleanup, review, plans, originals, destroys, snapshots,
            fence=lambda: "stable", process_quiescent=lambda identity: False)


def _prove(case):
    return prove_mixed_interrupted_post_sketch_absence(
        *case, fence=lambda: "stable", process_quiescent=lambda identity: True)


def _changed_snapshot(snapshot, **changes):
    changed = replace(snapshot, **changes)
    summary = {"provider": changed.provider, "stateSha256": changed.state_sha256,
               "phase": changed.phase, "inventory": changed.inventory,
               "linodeAttachments": changed.linode_firewall_attached_node_ids,
               "selectorExists": changed.selector_tag_exists,
               "selectorCount": changed.selector_resources_count,
               "selectorAttachments": changed.selector_attached_node_ids,
               "fence": "stable"}
    return replace(changed, observation_sha256=hashlib.sha256(json.dumps(
        summary, sort_keys=True, separators=(",", ":")).encode()).hexdigest())


def test_both_state_backed_providers_require_exact_absence(saved):
    case = _state_backed_case(saved, both=True)
    initial, cleanup, review, plans, originals, destroys, snapshots = case
    proof = _prove(case)
    assert tuple(receipt.scope_kind for receipt in proof.receipts) == ("full", "full")
    assert all(receipt.destroy_child_id and receipt.verified_absent_ids
               for receipt in proof.receipts)
    assert proof.receipts[0].provider != proof.receipts[1].provider
    for provider in review.ordered_providers:
        snapshot = snapshots[provider]
        original_state = json.loads(snapshot.state_json)
        for changed_state in (
            {**original_state, "resources": [{"mode": "managed", "type": "unexpected"}]},
            {**original_state, "lineage": "11111111-1111-4111-8111-111111111111"},
            {**original_state, "serial": review.scopes[
                review.ordered_providers.index(provider)].serial},
        ):
            raw = json.dumps(changed_state).encode()
            changed = _changed_snapshot(snapshot, state_json=raw,
                                        state_sha256=hashlib.sha256(raw).hexdigest())
            with pytest.raises(MixedInterruptedPostSketchAbsenceAttention):
                _prove((initial, cleanup, review, plans, originals, destroys,
                        {**snapshots, provider: changed}))
    digitalocean = snapshots["digitalocean"]
    attached = _changed_snapshot(digitalocean, selector_resources_count=1,
                                 selector_attached_node_ids=("999",))
    with pytest.raises(MixedInterruptedPostSketchAbsenceAttention):
        _prove((initial, cleanup, review, plans, originals, destroys,
                {**snapshots, "digitalocean": attached}))


def test_failed_absent_requires_no_destroy_child_and_no_provider_residue(ready):
    initial = ready.parent
    provider, other = initial.input["orderedProviders"]
    original_runner = ready.args["gated_command_runner"]

    def failed(command, **kwargs):
        try:
            original_runner(command, **kwargs)
        finally:
            (kwargs["scratch_path"] / "terraform.tfstate").unlink(missing_ok=True)
        raise RuntimeError("Apply failed after result")

    with pytest.raises(RuntimeError, match="Apply failed"):
        run_mixed_initial_provider_apply(
            provider=provider, **{**ready.args, "gated_command_runner": failed})
    child = ready.case.jobs.get(initial_child_id("job-core", provider))
    rows = list(child.events)
    rows[-1] = replace(rows[-1], data={**rows[-1].data, "returnCode": 1})
    child = replace(child, events=rows)
    originals = {provider: child, other: None}
    snapshots = {provider: _snapshot(provider, tag=provider == "digitalocean",
                                     phase="apply_started"), other: _snapshot(other)}
    review = review_mixed_interrupted_source(
        initial, originals, snapshots, fence=lambda: "stable",
        process_quiescent=lambda identity: True)
    assert review.scopes[0].kind == "failed_absent"
    cleanup, plans = _sealed(initial, review)
    destroys = {provider: None, other: None}
    case = (initial, cleanup, review, plans, originals, destroys, snapshots)
    assert _prove(case).receipts[0].verified_absent_ids == ()
    with pytest.raises(MixedInterruptedPostSketchAbsenceAttention):
        _prove((initial, cleanup, review, plans, originals,
                {**destroys, provider: child}, snapshots))
    residue = _changed_snapshot(snapshots[provider], inventory=(
        {"kind": "node", "id": "999", "name": "unreviewed-owned", "tags": [
            initial.events[5].data["reviewedPolicy"][provider].get(
                "selector_tag", initial.events[5].data["reviewedPolicy"][provider].get(
                    "engagement_name"))]},))
    with pytest.raises(MixedInterruptedPostSketchAbsenceAttention):
        _prove((initial, cleanup, review, plans, originals, destroys,
                {**snapshots, provider: residue}))
