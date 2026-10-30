# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private read-only interrupted tail handoff; no OCI or provider GO."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_mixed_interrupted_tail_authority as service
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as apply_child_id, run_mixed_initial_provider_apply,
)
from app.services.provider_keyed_mixed_interrupted_source import review_mixed_interrupted_source
from app.services.provider_keyed_oci_core_state import OciCoreStateInventory, OciCoreStateResource
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_post_sketch_absence import _sealed
from test_provider_keyed_mixed_interrupted_source import _snapshot


@pytest.fixture
def authority_case(ready, monkeypatch):
    initial = ready.parent
    order = tuple(initial.input["orderedProviders"])
    snapshots = {provider: _snapshot(provider, generation="generation") for provider in order}
    review = review_mixed_interrupted_source(
        initial, {provider: None for provider in order}, snapshots,
        fence=lambda: "generation", process_quiescent=lambda identity: True)
    cleanup, plans = _sealed(initial, review)
    generation = job_event_digest(cleanup.events) + ":" + plans.plan_set_sha256
    snapshots = {provider: _snapshot(provider, generation=generation) for provider in order}
    core = replace(ready.case.records["core_job"], status="succeeded")
    plan = replace(ready.case.records["core_plan"], status="applied", apply_job_id=core.id)
    jobs = {initial.id: initial, cleanup.id: cleanup, core.id: core}
    lease = {"value": (plan.id, "provider_keyed_teardown_fence")}
    calls = []
    inventory = OciCoreStateInventory(
        "a" * 64, "b" * 64, "123e4567-e89b-12d3-a456-426614174000", 1,
        (OciCoreStateResource("oci_core_instance.homebase", "ocid1.instance.oc1.fixture", None),))
    monkeypatch.setattr(service, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(service, "DEFAULT_TERRAFORM_STATE_ROOT", ready.case.state_root)

    def collect(parent, provider, workspace, *, fence, process_quiescent,
                credential_repository, phase_mode):
        assert parent == initial and workspace.provider == provider
        assert phase_mode == "apply" and process_quiescent() is True
        calls.append(provider)
        assert fence()
        return snapshots[provider]

    options = dict(environment="devtest", state_root=ready.case.state_root,
                   core_state_root=ready.case.state_root,
                   process_quiescent=lambda identity: True,
                   job_repository=SimpleNamespace(get=jobs.get),
                   plan_repository=SimpleNamespace(get=lambda _: plan),
                   provider_resource_repository=object(),
                   lease_lookup=lambda _: lease["value"],
                   inventory_collector=collect,
                   core_inventory_reader=lambda actual_core, actual_plan, root: inventory,
                   inspector_record_reader=lambda engagement, repo, resources:
                       ("inspector-host", "inspector-firewall"))
    return SimpleNamespace(initial=initial, cleanup=cleanup, review=review,
                           plans=plans, options=options, jobs=jobs, lease=lease,
                           snapshots=snapshots, calls=calls, inventory=inventory)


def test_both_provider_orders_recollect_and_bind_core_inspector(authority_case):
    item = authority_case
    result = service.audit_mixed_interrupted_tail_authority(
        item.initial, item.cleanup, item.review, item.plans, **item.options)
    assert item.calls == list(item.review.ordered_providers)
    assert result.post_sketch_absence.ordered_providers == item.review.ordered_providers
    assert result.core_state_sha256 == item.inventory.raw_state_sha256
    assert result.owned_inspector_record_ids == ("inspector-host", "inspector-firewall")
    assert result.selector_retirement_pending is False


def test_stale_parent_or_lease_and_bad_second_inventory_fail_closed(authority_case):
    item = authority_case
    item.lease["value"] = ("other-plan", "provider_keyed_teardown_fence")
    with pytest.raises(service.MixedInterruptedTailAuthorityAttention):
        service.audit_mixed_interrupted_tail_authority(
            item.initial, item.cleanup, item.review, item.plans, **item.options)
    item.lease["value"] = (item.cleanup.input["corePlanId"], "provider_keyed_teardown_fence")
    item.jobs[item.cleanup.id] = replace(item.cleanup, input={
        **item.cleanup.input, "sourceSha256": "0" * 64})
    with pytest.raises(service.MixedInterruptedTailAuthorityAttention):
        service.audit_mixed_interrupted_tail_authority(
            item.initial, item.cleanup, item.review, item.plans, **item.options)
    item.jobs[item.cleanup.id] = item.cleanup
    second = item.review.ordered_providers[1]
    original = item.options["inventory_collector"]
    item.options["inventory_collector"] = lambda *a, **k: (
        replace(item.snapshots[second], observation_sha256="0" * 64)
        if a[1] == second else original(*a, **k))
    with pytest.raises(service.MixedInterruptedTailAuthorityAttention):
        service.audit_mixed_interrupted_tail_authority(
            item.initial, item.cleanup, item.review, item.plans, **item.options)


@pytest.mark.parametrize("case", [False], indirect=True)
def test_tag_only_selector_is_explicitly_pending_for_later_retirement(ready, authority_case):
    item = authority_case
    initial = item.initial
    assert initial.input["orderedProviders"][0] == "digitalocean"

    def stop(*args, **kwargs):
        raise RuntimeError("stopped before Apply")

    with pytest.raises(RuntimeError, match="stopped before Apply"):
        run_mixed_initial_provider_apply(
            provider="digitalocean",
            **{**ready.args, "gated_command_runner": stop})
    child = ready.case.jobs.get(apply_child_id("job-core", "digitalocean"))
    order = tuple(initial.input["orderedProviders"])
    review_snapshots = {"digitalocean": _snapshot("digitalocean", tag=True,
                                                   generation="stable"),
                        "linode": _snapshot("linode", generation="stable")}
    review = review_mixed_interrupted_source(
        initial, {"digitalocean": child, "linode": None}, review_snapshots,
        fence=lambda: "stable", process_quiescent=lambda identity: True)
    cleanup, plans = _sealed(initial, review)
    generation = job_event_digest(cleanup.events) + ":" + plans.plan_set_sha256
    snapshots = {"digitalocean": _snapshot("digitalocean", tag=True,
                                            generation=generation),
                 "linode": _snapshot("linode", generation=generation)}
    item.jobs.pop(item.cleanup.id)
    item.jobs[cleanup.id] = cleanup
    item.jobs[child.id] = child
    options = {**item.options,
               "inventory_collector": lambda parent, provider, workspace, **kwargs:
                   snapshots[provider]}
    result = service.audit_mixed_interrupted_tail_authority(
        initial, cleanup, review, plans, **options)
    assert result.selector_retirement_pending is True
    assert result.post_sketch_absence.receipts[0].selector_retirement_pending is True


def test_lease_change_during_second_complete_inventory_rejects_authority(authority_case):
    item = authority_case
    original = item.options["inventory_collector"]
    second = item.review.ordered_providers[1]

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[1] == second:
            item.lease["value"] = ("other-plan", "provider_keyed_teardown_fence")
        return result

    with pytest.raises(service.MixedInterruptedTailAuthorityAttention):
        service.audit_mixed_interrupted_tail_authority(
            item.initial, item.cleanup, item.review, item.plans,
            **{**item.options, "inventory_collector": changed})
