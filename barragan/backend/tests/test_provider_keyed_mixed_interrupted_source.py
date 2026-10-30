# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline mixed interruption authority; no provider writes or Terraform."""

from dataclasses import replace
from types import SimpleNamespace
import hashlib
import json

import pytest

from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, run_mixed_initial_provider_apply,
)
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedProviderScope, MixedInterruptedReview,
    MixedInterruptedSourceAttention, review_mixed_interrupted_source,
    review_mixed_interrupted_provider_source,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
    MixedInterruptedDestroyPlanAttention, bind_mixed_interrupted_destroy_plans,
)
from app.services.provider_keyed_mixed_interrupted_absence import (
    MixedInterruptedAbsenceAttention, inspect_mixed_interrupted_provider_absence,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_mixed_partial_apply_inventory import MixedPartialApplyInventorySnapshot
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
import app.services.provider_keyed_mixed_partial_apply_inventory as collector
import app.services.provider_keyed_mixed_initial_apply_proof as proof_service
from app.services.provider_keyed_mixed_partial_apply_source import classify_sealed_provider_apply, ApplyObservation
from app.services.provider_keyed_mixed_initial_apply_child import recognize_mixed_initial_apply_result
from app.services.provider_keyed_mixed_initial_apply_proof import prove_and_finish_mixed_initial_apply
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_initial_apply_proof import _state_and_rows


def _collected(ready, provider, state, nodes_rows, firewall, node_ids, monkeypatch,
               *, phase):
    source = ready.args["source_session"](ready.parent, provider, lambda: None).__enter__()
    workspace = source.workspace
    workspace.state_path.write_text(json.dumps(state))
    (workspace.path / ".barragan-apply-phase.json").write_text(json.dumps({
        "schema": "provider-keyed-v2", "phase": phase}))
    policy = ready.parent.events[5].data["reviewedPolicy"][provider]
    monkeypatch.setattr(collector, "_verify_linode_workspace", lambda workspace: None)
    monkeypatch.setattr(collector, "_verify_audited_workspace", lambda workspace: None)

    class LinodeTransport:
        def request(self, method, endpoint, token):
            assert method == "GET"
            if endpoint.startswith("/linode/instances?"):
                data = nodes_rows
            elif endpoint.startswith("/networking/firewalls?"):
                data = [firewall]
            elif endpoint.startswith("/networking/firewalls/301/devices?"):
                data = [{"id": index + 1, "entity": {"id": int(identifier),
                         "type": "linode"}} for index, identifier in enumerate(node_ids)]
            else:
                raise AssertionError(endpoint)
            return {"data": data, "page": 1, "pages": 1, "results": len(data)}

    class DoTransport:
        def request(self, origin, method, endpoint, token):
            assert method == "GET"
            if endpoint.startswith("/droplets?"):
                key, data = "droplets", ([] if "type=gpus" in endpoint else nodes_rows)
            elif endpoint.startswith("/firewalls?"):
                key, data = "firewalls", [firewall]
            elif endpoint.startswith("/account/keys?"):
                key, data = "ssh_keys", [{"id": 401, "name": policy["ssh_key_name"],
                                           "public_key": policy["admin_public_key"]}]
            elif endpoint.startswith("/tags?"):
                key, data = "tags", [{"name": policy["selector_tag"],
                                       "resources": {"count": len(node_ids)}}]
            else:
                raise AssertionError(endpoint)
            return {key: data, "meta": {"total": len(data)}, "links": {"pages": {}}}

    transports = {"linode_transport": LinodeTransport(),
                  "digitalocean_transport": DoTransport()}
    snapshot = collect_provider_inventory_snapshot(
        ready.parent, provider, workspace, fence=lambda: "stable",
        process_quiescent=lambda: True,
        credential_repository=ready.case.args["credential_repository"],
        decrypt_secret=lambda secret: secret, **transports)
    return workspace, snapshot, transports


def _snapshot(provider, *, tag=False, phase=None, state=None, inventory=(), generation="stable"):
    state_sha = hashlib.sha256(state).hexdigest() if state is not None else None
    linode_attached = () if provider == "linode" else None
    selector_exists = tag if provider == "digitalocean" else None
    selector_count = 0 if provider == "digitalocean" else None
    selector_attached = () if provider == "digitalocean" else None
    inventory = tuple(inventory)
    summary = {"provider": provider, "stateSha256": state_sha,
               "phase": phase, "inventory": inventory,
               "linodeAttachments": linode_attached,
               "selectorExists": selector_exists, "selectorCount": selector_count,
               "selectorAttachments": selector_attached, "fence": generation}
    digest = hashlib.sha256(json.dumps(summary, sort_keys=True,
                                       separators=(",", ":")).encode()).hexdigest()
    return MixedPartialApplyInventorySnapshot(
        provider, state, state_sha, phase, inventory,
        linode_attached, selector_exists, selector_count, selector_attached, digest)


def _empty_review(ready, *, children=None, snapshots=None):
    order = ready.parent.input["orderedProviders"]
    children = children or {provider: None for provider in order}
    snapshots = snapshots or {provider: _snapshot(provider) for provider in order}
    return review_mixed_interrupted_source(
        ready.parent, children, snapshots,
        fence=lambda: "stable", process_quiescent=lambda identity: True)


def test_both_orders_unstarted_require_two_absence_scopes_and_no_plans(ready):
    review = _empty_review(ready)
    assert [scope.kind for scope in review.scopes] == ["unstarted", "unstarted"]
    order = review.ordered_providers
    plans = bind_mixed_interrupted_destroy_plans(
        ready.parent, review, {provider: None for provider in order},
        {provider: None for provider in order}, {provider: None for provider in order},
        fence=lambda: "one-teardown-generation")
    assert [plan.plan_path for plan in plans.plans] == [None, None]
    assert plans.review_sha256 == review.review_sha256
    for provider, expected in zip(order, review.scopes, strict=True):
        assert review_mixed_interrupted_provider_source(
            ready.parent, provider, None, _snapshot(provider),
            fence=lambda: "stable", process_quiescent=lambda identity: True) == expected
    for scope in review.scopes:
        snapshot = _snapshot(scope.provider)
        absence = inspect_mixed_interrupted_provider_absence(
            ready.parent, review, scope, None, None, snapshot, fence=lambda: "stable")
        assert absence.verified_absent_ids == ()
        assert absence.after_state_sha256 is None


@pytest.mark.parametrize("case", [False], indirect=True)
def test_do_tag_only_requires_exact_201_visibility_and_no_apply_intent(ready):
    assert ready.parent.input["orderedProviders"][0] == "digitalocean"
    def stop_before_command(*args, **kwargs):
        raise RuntimeError("stopped before command intent")
    with pytest.raises(RuntimeError, match="before command"):
        run_mixed_initial_provider_apply(
            provider="digitalocean", **{**ready.args, "gated_command_runner": stop_before_command})
    child = ready.case.jobs.get(_child_id("job-core", "digitalocean"))
    assert child.events[-1].message == "mixed selector exclusive visibility proved"
    children = {"digitalocean": child, "linode": None}
    snapshots = {"digitalocean": _snapshot("digitalocean", tag=True),
                 "linode": _snapshot("linode")}
    review = _empty_review(ready, children=children, snapshots=snapshots)
    assert review.scopes[0].kind == "tag_only"
    assert review_mixed_interrupted_provider_source(
        ready.parent, "digitalocean", child, snapshots["digitalocean"],
        fence=lambda: "stable", process_quiescent=lambda identity: True) == review.scopes[0]
    assert review.scopes[0].selector_retirement_pending is True
    absence = inspect_mixed_interrupted_provider_absence(
        ready.parent, review, review.scopes[0], None, None,
        snapshots["digitalocean"], fence=lambda: "stable")
    assert absence.selector_retirement_pending is True
    tampered = list(child.events)
    tampered[-2] = replace(tampered[-2], data={"selectorTag": child.events[-2].data["selectorTag"],
                                                "httpStatus": 200})
    children["digitalocean"] = replace(child, events=tampered)
    with pytest.raises(MixedInterruptedSourceAttention):
        _empty_review(ready, children=children, snapshots=snapshots)


def test_failed_empty_requires_fenced_nonzero_result_and_no_orphans(ready):
    provider = ready.parent.input["orderedProviders"][0]
    original = ready.args["gated_command_runner"]
    def failed(command, **kwargs):
        # Exercise the real journal callbacks but prevent retained state.
        try:
            original(command, **kwargs)
        finally:
            (kwargs["scratch_path"] / "terraform.tfstate").unlink(missing_ok=True)
        raise RuntimeError("provider Apply failed after result")
    with pytest.raises(RuntimeError, match="Apply failed"):
        run_mixed_initial_provider_apply(provider=provider,
                                         **{**ready.args, "gated_command_runner": failed})
    child = ready.case.jobs.get(_child_id("job-core", provider))
    rows = list(child.events)
    rows[-1] = replace(rows[-1], data={**rows[-1].data, "returnCode": 1})
    child = replace(child, events=rows)
    other = ready.parent.input["orderedProviders"][1]
    children = {provider: child, other: None}
    snapshots = {provider: _snapshot(provider, tag=provider == "digitalocean",
                                     phase="apply_started"),
                 other: _snapshot(other)}
    review = _empty_review(ready, children=children, snapshots=snapshots)
    assert review.scopes[0].kind == "failed_absent"
    absent = inspect_mixed_interrupted_provider_absence(
        ready.parent, review, review.scopes[0], None, None, snapshots[provider],
        fence=lambda: "stable")
    assert absent.before_state_sha256 is None
    assert absent.verified_absent_ids == ()
    snapshots[provider] = _snapshot(provider, tag=provider == "digitalocean",
                                     phase="apply_started", inventory=({"kind": "node",
                                         "id": "999", "name": "unexpected", "tags": [
                                             (ready.parent.events[5].data["reviewedPolicy"][provider][
                                                 "selector_tag"] if provider == "digitalocean" else
                                              ready.parent.events[5].data["reviewedPolicy"][provider][
                                                 "engagement_name"])]},))
    with pytest.raises(MixedInterruptedSourceAttention):
        _empty_review(ready, children=children, snapshots=snapshots)


def test_no_state_review_rejects_plan_or_changed_fence(ready):
    review = _empty_review(ready)
    order = review.ordered_providers
    with pytest.raises(MixedInterruptedDestroyPlanAttention):
        bind_mixed_interrupted_destroy_plans(
            ready.parent, review, {provider: None for provider in order},
            {provider: None for provider in order},
            {provider: "unexpected show" for provider in order}, fence=lambda: "stable")
    count = iter(("first", "second"))
    with pytest.raises(MixedInterruptedSourceAttention):
        review_mixed_interrupted_source(
            ready.parent, {provider: None for provider in order},
            {provider: _snapshot(provider, generation="first") for provider in order},
            fence=lambda: next(count), process_quiescent=lambda identity: True)


def test_exact_delete_plan_binds_state_backed_ids_before_any_go(ready):
    first, second = ready.parent.input["orderedProviders"]
    policy = ready.parent.events[5].data["reviewedPolicy"][first]
    state, _, _, _ = _state_and_rows(first, policy)
    raw = json.dumps(state).encode()
    _, attributes, cloud = _state(first, policy, raw)
    first_scope = MixedInterruptedProviderScope(
        first, "full", "b" * 64, hashlib.sha256(raw).hexdigest(),
        state["lineage"], state["serial"], tuple(sorted(cloud.items())),
        "c" * 64, "d" * 64, policy.get("selector_tag"), first == "digitalocean")
    second_scope = _empty_review(ready).scopes[1]
    order = (first, second)
    payload = {"engagementId": ready.parent.target_id,
               "coreJobId": ready.parent.input["coreJobId"],
               "sealJournalSha256": __import__("app.storage.job_repository", fromlist=[
                   "job_event_digest"]).job_event_digest(ready.parent.events[:6]),
               "orderedProviders": order,
               "scopes": [first_scope.__dict__, second_scope.__dict__]}
    review = MixedInterruptedReview(
        ready.parent.target_id, ready.parent.input["coreJobId"],
        payload["sealJournalSha256"], order, (first_scope, second_scope),
        hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    workspace = next((ready.case.state_root / "eng-opaque" / "provider-keyed-v2" / first).iterdir())
    path = workspace / f".barragan-mixed-interrupted-destroy-{first}.tfplan"
    path.write_bytes(b"reviewed-binary-plan")
    path.chmod(0o600)
    changes = [{"address": address, "change": {"actions": ["delete"],
                "before": attrs, "after": None, "after_unknown": {}}}
               for address, attrs in attributes.items()]
    shown = {"format_version": "1.2", "terraform_version": "1.15.5",
             "applyable": True, "complete": True, "errored": False,
             "resource_changes": changes,
             "prior_state": {"values": {"root_module": {"resources": [
                 {"address": address, "mode": "managed", "values": attrs}
                 for address, attrs in attributes.items()]}}},
             "output_changes": {}, "planned_values": {"root_module": {}}}
    args = (ready.parent, review, {first: raw, second: None},
            {first: path, second: None}, {first: json.dumps(shown), second: None})
    plans = bind_mixed_interrupted_destroy_plans(*args, fence=lambda: "stable")
    assert plans.plans[0].resource_ids == tuple(sorted(
        (address, str(attrs["id"])) for address, attrs in attributes.items()))
    assert plans.plans[1].plan_path is None
    after = {**state, "serial": state["serial"] + 1, "resources": []}
    after_raw = json.dumps(after).encode()
    snapshot = _snapshot(first, tag=first == "digitalocean",
                         phase="destroy_applied", state=after_raw)
    absence = inspect_mixed_interrupted_provider_absence(
        ready.parent, review, first_scope, raw, after_raw, snapshot,
        fence=lambda: "stable")
    assert absence.verified_absent_ids == tuple(sorted(cloud.values()))
    assert absence.after_serial == state["serial"] + 1
    with pytest.raises(MixedInterruptedAbsenceAttention):
        inspect_mixed_interrupted_provider_absence(
            ready.parent, review, first_scope, raw,
            json.dumps({**after, "serial": state["serial"]}).encode(), snapshot,
            fence=lambda: "stable")
    shown["resource_changes"][0]["change"]["actions"] = ["create"]
    with pytest.raises(MixedInterruptedDestroyPlanAttention):
        bind_mixed_interrupted_destroy_plans(
            *args[:4], {first: json.dumps(shown), second: None}, fence=lambda: "stable")


@pytest.mark.parametrize("outcome", ["failed_partial", "full_terminal"])
def test_persisted_child_and_fresh_collector_feed_exact_destroy_plan(
        ready, monkeypatch, outcome):
    provider, other = ready.parent.input["orderedProviders"]
    if outcome == "failed_partial":
        original = ready.args["gated_command_runner"]
        def failed(command, **kwargs):
            callback = kwargs["result_callback"]
            kwargs["result_callback"] = lambda value: callback(replace(value, returncode=1))
            return replace(original(command, **kwargs), returncode=1)
        with pytest.raises(Exception):
            run_mixed_initial_provider_apply(provider=provider,
                                             **{**ready.args, "gated_command_runner": failed})
    else:
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    child = ready.case.jobs.get(_child_id("job-core", provider))
    policy = ready.parent.events[5].data["reviewedPolicy"][provider]
    state, nodes_rows, firewall, node_ids = _state_and_rows(provider, policy)
    if outcome == "failed_partial":
        state["resources"] = [row for row in state["resources"]
                              if not (row["type"] == "local_file" and row["name"] == "ssh_stanza")]
    workspace, snapshot, _ = _collected(
        ready, provider, state, nodes_rows, firewall, node_ids, monkeypatch,
        phase="apply_started" if outcome == "failed_partial" else "applied")
    observation = ApplyObservation(
        "failed" if outcome == "failed_partial" else "succeeded", True, True,
        snapshot.phase, snapshot.state_json, True, snapshot.inventory,
        snapshot.selector_tag_exists, snapshot.selector_attached_node_ids,
        snapshot.linode_firewall_attached_node_ids, snapshot.selector_resources_count)
    classification = classify_sealed_provider_apply(ready.parent, provider, observation)
    assert classification.kind == ("partial" if outcome == "failed_partial" else "full")
    if outcome == "full_terminal":
        monkeypatch.setattr(proof_service, "collect_provider_inventory_snapshot",
                            lambda *args, **kwargs: snapshot)
        child = prove_and_finish_mixed_initial_apply(
            "eng-opaque", "job-core", provider, workspace, environment="devtest",
            job_repository=ready.case.jobs, lease_lookup=ready.case.args["lease_lookup"],
            credential_repository=ready.case.args["credential_repository"],
            process_quiescent=lambda identity: True,
            claim_owner=child.input["claimOwner"], claim_token=child.input["claimToken"])
        assert child.status == "succeeded"
    snapshots = {provider: snapshot, other: _snapshot(other)}
    children = {provider: child, other: None}
    review = _empty_review(ready, children=children, snapshots=snapshots)
    assert review.scopes[0].kind == classification.kind
    raw = workspace.state_path.read_bytes()
    attributes = _state_resources(state)
    shown = {"format_version": "1.2", "terraform_version": "1.15.5",
             "applyable": True, "complete": True, "errored": False,
             "resource_changes": [{"address": address, "change": {
                 "actions": ["delete"], "before": attrs, "after": None,
                 "after_unknown": {}}} for address, attrs in attributes.items()],
             "prior_state": {"values": {"root_module": {"resources": [
                 {"address": address, "mode": "managed", "values": attrs}
                 for address, attrs in attributes.items()]}}},
             "output_changes": {}, "planned_values": {"root_module": {}}}
    plan_path = workspace.path / f".barragan-mixed-interrupted-destroy-{provider}.tfplan"
    plan_path.write_bytes(b"offline-reviewed-plan")
    plan_path.chmod(0o644)
    plans = bind_mixed_interrupted_destroy_plans(
        ready.parent, review, {provider: raw, other: None},
        {provider: plan_path, other: None},
        {provider: json.dumps(shown), other: None}, fence=lambda: "stable")
    assert plans.plans[0].before_state_sha256 == review.scopes[0].state_sha256
    assert plans.plans[1].plan_path is None


def test_missing_result_or_active_process_never_yields_destroy_scope(ready):
    provider, other = ready.parent.input["orderedProviders"]
    child = run_mixed_initial_provider_apply(provider=provider, **ready.args)
    rows = list(child.events)
    rows = rows[:next(index for index, row in enumerate(rows)
                      if row.message == "mixed provider Apply command result fenced")]
    child = replace(child, events=rows)
    snapshots = {provider: _snapshot(provider, phase="apply_started"),
                 other: _snapshot(other)}
    with pytest.raises(MixedInterruptedSourceAttention):
        _empty_review(ready, children={provider: child, other: None}, snapshots=snapshots)
    # Even a complete result cannot authorize a destroy while its PID/group lives.
    child = ready.case.jobs.get(_child_id("job-core", provider))
    with pytest.raises(MixedInterruptedSourceAttention):
        review_mixed_interrupted_source(
            ready.parent, {provider: child, other: None}, snapshots,
            fence=lambda: "stable", process_quiescent=lambda identity: False)
