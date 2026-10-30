# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-cloud saved binary/plan show proof for mixed interrupted teardown."""

from dataclasses import asdict, replace
import hashlib
import json

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    propose_mixed_interrupted_cleanup,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import bind_mixed_interrupted_destroy_plans
from app.services.provider_keyed_mixed_interrupted_destroy_source import (
    MixedInterruptedDestroySourceAttention, bind_mixed_interrupted_destroy_show,
)
from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedProviderScope, MixedInterruptedReview,
)
from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_apply_proof import _state_and_rows
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _empty_review


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _release(binary):
    return ProviderKeyedTerraformRelease(
        binary, hashlib.sha256(binary.read_bytes()).hexdigest(), "1.15.5", "linux_amd64")


@pytest.fixture
def saved(ready):
    first, second = ready.parent.input["orderedProviders"]
    policy = ready.parent.events[5].data["reviewedPolicy"][first]
    state, _, _, _ = _state_and_rows(first, policy)
    raw = json.dumps(state).encode()
    _, actual, cloud = _state(first, policy, raw)
    first_scope = MixedInterruptedProviderScope(
        first, "full", "b" * 64, hashlib.sha256(raw).hexdigest(),
        state["lineage"], state["serial"], tuple(sorted(cloud.items())),
        "c" * 64, "d" * 64, policy.get("selector_tag"), first == "digitalocean")
    second_scope = _empty_review(ready).scopes[1]
    order = (first, second)
    prefix_sha = job_event_digest(ready.parent.events[:6])
    review = MixedInterruptedReview(
        ready.parent.target_id, ready.parent.input["coreJobId"], prefix_sha,
        order, (first_scope, second_scope),
        _digest({"engagementId": ready.parent.target_id,
                 "coreJobId": ready.parent.input["coreJobId"],
                 "sealJournalSha256": prefix_sha, "orderedProviders": order,
                 "scopes": [first_scope.__dict__, second_scope.__dict__]}))
    workspace = next((ready.case.state_root / "eng-opaque" / "provider-keyed-v2" / first).iterdir())
    workspace.joinpath("terraform.tfstate").write_bytes(raw)
    plan_path = workspace / f".barragan-mixed-interrupted-destroy-{first}.tfplan"
    plan_path.write_bytes(b"reviewed-binary-plan")
    lock_path = workspace / f".barragan-{first}-plan.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)
    changes = [{"address": address, "change": {"actions": ["delete"],
                "before": attrs, "after": None, "after_unknown": {}}}
               for address, attrs in actual.items()]
    shown = json.dumps({"format_version": "1.2", "terraform_version": "1.15.5",
                        "applyable": True, "complete": True, "errored": False,
                        "resource_changes": changes,
                        "prior_state": {"values": {"root_module": {"resources": [
                            {"address": address, "mode": "managed", "values": attrs}
                            for address, attrs in actual.items()]}}},
                        "output_changes": {}, "planned_values": {"root_module": {}}})
    plans = bind_mixed_interrupted_destroy_plans(
        ready.parent, review, {first: raw, second: None},
        {first: plan_path, second: None}, {first: shown, second: None},
        fence=lambda: "teardown-generation")
    queued = propose_mixed_interrupted_cleanup(ready.parent, review, requested_by="operator")
    cleanup = replace(
        queued, input={**queued.input, "phase": "plans_sealed"},
        events=queued.events + [JobEvent(2, "info", "both mixed destroy plans sealed",
                                        {"planSet": json.loads(json.dumps(asdict(plans))),
                                         "planSetSha256": plans.plan_set_sha256})])
    binary = workspace / "terraform-test"
    binary.write_bytes(b"pinned terraform executable fixture")
    binary.chmod(0o755)
    return ready.parent, cleanup, review, plans, first, raw, binary, shown, plan_path


def test_both_orders_bind_exact_binary_plan_and_show(saved):
    initial, cleanup, review, plans, provider, raw, binary, shown, plan_path = saved
    calls = []
    def show(command, cwd):
        calls.append((command, cwd))
        return shown
    bound = bind_mixed_interrupted_destroy_show(
        initial, cleanup, review, plans, provider, raw, binary,
        hashlib.sha256(binary.read_bytes()).hexdigest(), show_runner=show,
        fence=lambda: "same-generation", release_validator=lambda: _release(binary))
    assert calls == [((str(binary), "show", "-json", str(plan_path)), plan_path.parent)]
    assert bound.plan_sha256 == plans.plans[0].plan_sha256
    assert bound.argv_sha256 == _digest(list(calls[0][0]))


def test_wrong_binary_or_changed_plan_or_wrong_show_stops_before_go(saved):
    initial, cleanup, review, plans, provider, raw, binary, shown, plan_path = saved
    original = hashlib.sha256(binary.read_bytes()).hexdigest()
    def prove(*, expected=original, result=shown):
        return bind_mixed_interrupted_destroy_show(
            initial, cleanup, review, plans, provider, raw, binary,
            expected, show_runner=lambda command, cwd: result,
            fence=lambda: "same-generation", release_validator=lambda: _release(binary))
    with pytest.raises(MixedInterruptedDestroySourceAttention):
        prove(expected="0" * 64)
    with pytest.raises(MixedInterruptedDestroySourceAttention):
        prove(result=shown + " ")
    plan_path.write_bytes(b"changed saved plan")
    with pytest.raises(MixedInterruptedDestroySourceAttention):
        prove()


def test_wrong_executable_with_its_own_matching_hash_is_rejected(saved):
    initial, cleanup, review, plans, provider, raw, binary, shown, _ = saved
    reviewed = _release(binary)
    other = binary.parent / "unreviewed-terraform"
    other.write_bytes(b"different executable with a matching caller hash")
    other.chmod(0o755)
    with pytest.raises(MixedInterruptedDestroySourceAttention):
        bind_mixed_interrupted_destroy_show(
            initial, cleanup, review, plans, provider, raw, other,
            hashlib.sha256(other.read_bytes()).hexdigest(),
            show_runner=lambda command, cwd: shown,
            fence=lambda: "same-generation", release_validator=lambda: reviewed)
