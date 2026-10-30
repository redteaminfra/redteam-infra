# Copyright (c) 2026, Oracle and/or its affiliates.
"""Both published-provider plans must delete exactly their retained state."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from app.services.provider_keyed_mixed_partial_apply_source import _state
from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
from app.services.provider_keyed_mixed_published_destroy_plan import (
    PublishedMixedDestroyPlanAttention, bind_published_mixed_initial_destroy_plans,
)
from app.services.provider_keyed_mixed_published_teardown_authority import (
    review_published_mixed_initial_teardown,
)
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_authority import _case


def _saved(ready, tmp_path, *, with_observations=False):
    source, args, _persisted = _case(ready, tmp_path)
    review = review_published_mixed_initial_teardown(**args)
    parent = args["parent"]
    policies = parent.events[5].data["reviewedPolicy"]
    states, paths, shows = {}, {}, {}
    for provider, scope in zip(source.ordered_providers,
                               review.provider_scopes, strict=True):
        raw = args["observations"][provider].state_json
        _parsed, actual, _cloud = _state(provider, policies[provider], raw)
        path = Path(scope["workspace"]) / f".barragan-mixed-published-destroy-{provider}.tfplan"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"saved-{provider}-plan".encode())
        path.parent.joinpath("terraform.tfstate").write_bytes(raw)
        lock = path.parent / f".barragan-{provider}-plan.lock"
        lock.write_bytes(b"")
        lock.chmod(0o600)
        changes = [{"address": address, "change": {
            "actions": ["delete"], "before": attrs, "after": None,
            "after_unknown": {}}} for address, attrs in actual.items()]
        shown = json.dumps({
            "format_version": "1.2", "terraform_version": "1.15.5",
            "applyable": True, "complete": True, "errored": False,
            "resource_changes": changes,
            "prior_state": {"values": {"root_module": {"resources": [
                {"address": address, "mode": "managed", "values": attrs}
                for address, attrs in actual.items()]}}},
            "output_changes": {}, "planned_values": {"root_module": {}},
        })
        states[provider], paths[provider], shows[provider] = raw, path, shown
    result = review, parent, states, paths, shows
    return (*result, args["observations"]) if with_observations else result


def _bind(parent, review, states, paths, shows, tmp_path, *, fence,
          show_runner=None):
    binary = tmp_path / "terraform-test"
    binary.write_bytes(b"pinned Terraform executable fixture")
    binary.chmod(0o755)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    by_path = {path: shows[provider] for provider, path in paths.items()
               if provider in shows}
    return bind_published_mixed_initial_destroy_plans(
        parent, review, states, paths, shows, fence=fence,
        terraform_path=binary, expected_terraform_sha256=digest,
        release_validator=lambda: ProviderKeyedTerraformRelease(
            binary, digest, "1.15.5", "linux_amd64"),
        show_runner=show_runner or (lambda command, cwd: by_path[Path(command[-1])]),
    )


def test_both_provider_orders_require_both_saved_exact_delete_plans(client, ready, tmp_path):
    with client.application.storage_context():
        review, parent, states, paths, shows = _saved(ready, tmp_path)
        calls = []
        def fence():
            calls.append("read")
            return "same-generation"
        plans = _bind(parent, review, states, paths, shows, tmp_path, fence=fence)
        assert tuple(plan.provider for plan in plans.plans) == review.source.ordered_providers
        assert all(plan.plan_sha256 and plan.show_json_sha256 for plan in plans.plans)
        assert len(calls) >= 3
        assert _bind(parent, review, states, paths, shows, tmp_path,
                     fence=lambda: "same-generation") == plans


@pytest.mark.parametrize("drift", [
    "missing_second", "changed_state", "wrong_plan", "changed_plan",
    "non_delete", "changed_fence", "changed_parent", "changed_scope",
    "unattested_show", "changed_binary_during_show", "reordered_four_chains",
])
def test_plan_set_vetoes_partial_or_drifted_source(client, ready, tmp_path, drift):
    with client.application.storage_context():
        review, parent, states, paths, shows = _saved(ready, tmp_path)
        provider = review.source.ordered_providers[0]
        if drift == "missing_second":
            shows.pop(review.source.ordered_providers[1])
        elif drift == "changed_state":
            states[provider] += b" "
        elif drift == "wrong_plan":
            paths[provider] = paths[provider].with_name("foreign.tfplan")
            paths[provider].write_bytes(b"foreign")
        elif drift == "changed_plan":
            paths[provider].unlink()
        elif drift == "non_delete":
            payload = json.loads(shows[provider])
            payload["resource_changes"][0]["change"]["actions"] = ["update"]
            shows[provider] = json.dumps(payload)
        elif drift == "reordered_four_chains":
            review = replace(review, source=replace(review.source,
                chain_ids=tuple(reversed(review.source.chain_ids))))
        elif drift == "changed_parent":
            parent = replace(parent, events=parent.events[:-1])
        elif drift == "changed_scope":
            first = dict(review.provider_scopes[0])
            first["stateSha256"] = "0" * 64
            review = replace(review, provider_scopes=(first, review.provider_scopes[1]))
        attested = (lambda command, cwd: "different-show") if drift == "unattested_show" else None
        if drift == "changed_binary_during_show":
            def change_binary(command, cwd):
                Path(command[0]).write_bytes(b"changed executable")
                return shows[provider]
            attested = change_binary
        counter = iter(("first", "second", "second"))
        fence = (lambda: next(counter)) if drift == "changed_fence" else (lambda: "stable")
        with pytest.raises(PublishedMixedDestroyPlanAttention):
            _bind(parent, review, states, paths, shows, tmp_path,
                  fence=fence, show_runner=attested)
