# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published mixed GO reattests one exact saved plan under its file lock."""

from dataclasses import replace
from pathlib import Path

import pytest

from app.services.provider_keyed_mixed_published_destroy_source import (
    PublishedMixedDestroySourceAttention, attest_published_mixed_destroy_show,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup, propose_published_mixed_plans_sealed,
)
from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_destroy_plan import _bind, _saved
from test_provider_keyed_mixed_published_teardown_checkpoint import _core_scope


@pytest.mark.parametrize("drift", [None, "plan", "show", "binary", "state",
                                   "fence", "historical"])
def test_selected_published_plan_is_reshown_before_go(
        client, ready, tmp_path, drift):
    with client.application.storage_context():
        review, initial, states, paths, shows = _saved(ready, tmp_path)
        plans = _bind(initial, review, states, paths, shows, tmp_path,
                      fence=lambda: "same")
        scope = _core_scope(review)
        queued = propose_published_mixed_initial_cleanup(
            review, scope, "Opaque", requested_by="operator")
        parent = propose_published_mixed_plans_sealed(
            queued, review, plans, scope, "Opaque")
        provider = review.source.ordered_providers[0]
        plan = plans.plans[0]
        binary = Path(plan.terraform_path)
        if drift == "plan":
            paths[provider].write_bytes(b"different-plan")
        elif drift == "binary":
            binary.write_bytes(b"different-executable")
        elif drift == "state":
            paths[provider].parent.joinpath("terraform.tfstate").write_bytes(b"different-state")
        elif drift == "historical":
            initial = replace(initial, events=[*initial.events[:-1], replace(
                initial.events[-1], data={**initial.events[-1].data,
                                         "sourceSha256": "0" * 64})])
        observed = []
        values = iter(("same", "changed"))
        fence = (lambda: next(values)) if drift == "fence" else (lambda: "same")
        shown = ("different-show" if drift == "show" else shows[provider])
        def show_runner(command, cwd):
            observed.append((command, cwd))
            return shown
        def continuation(attested):
            observed.append(("attested", attested.plan_sha256))
            return "under-lock"
        call = lambda: attest_published_mixed_destroy_show(
            initial, parent, review, plans, provider, states[provider],
            scope, "Opaque", fence=fence, show_runner=show_runner,
            release_validator=lambda: ProviderKeyedTerraformRelease(
                binary, plan.terraform_sha256, "1.15.5", "linux_amd64"),
            on_attested=continuation)
        if drift is None:
            assert call() == "under-lock"
            assert observed == [((str(binary), "show", "-json", plan.plan_path),
                                 paths[provider].parent),
                                ("attested", plan.plan_sha256)]
        else:
            with pytest.raises(PublishedMixedDestroySourceAttention):
                call()
            assert ("attested", plan.plan_sha256) not in observed
