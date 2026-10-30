# Copyright (c) 2026, Oracle and/or its affiliates.
"""One published plan worker seals both providers before any destroy GO."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_reservation import (
    _attested_plans, _persisted,
)
import app.services.provider_keyed_mixed_published_plan_worker as worker


@pytest.mark.parametrize("drift", [False, True])
def test_published_plan_worker_seals_both_in_reviewed_order_or_stops_on_drift(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(
            proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        plan_set, states, paths, binary, shows = _attested_plans(
            jobs, collection, tmp_path, with_shows=True)
        monkeypatch.setattr(worker, "_default_state_root", lambda: ready.case.state_root)
        monkeypatch.setattr(worker, "DEFAULT_TERRAFORM_STATE_ROOT", tmp_path / "oci")
        monkeypatch.setattr(worker, "_workspace", lambda initial, provider, root:
                            SimpleNamespace(path=collection.workspaces[provider]))
        monkeypatch.setattr(worker, "bind_published_mixed_initial_destroy_plans",
                            lambda *args, **kwargs: plan_set)
        calls = []

        def produce(provider, scope, initial, workspace, *, source_recheck, **kwargs):
            calls.append(provider)
            assert kwargs["plan_variant"] == "published"
            assert scope.kind == "full"
            if drift and len(calls) == 1:
                jobs.save(replace(queued, input={**queued.input, "drift": True}))
            source_recheck()
            return paths[provider], shows[provider]

        monkeypatch.setattr(worker, "_produce_state_backed_plan", produce)
        release = ProviderKeyedTerraformRelease(
            binary, plan_set.plans[0].terraform_sha256, "1.15.5", "linux_amd64")
        options = dict(
            environment="devtest", state_root=ready.case.state_root,
            core_state_root=tmp_path / "oci", job_repository=jobs,
            lease_lookup=lambda _eng: (queued.input["corePlanId"],
                                       "provider_keyed_teardown_fence"),
            collector=lambda *_a, **_k: collection,
            release_validator=lambda **_k: release)
        if drift:
            with pytest.raises(worker.PublishedMixedPlanWorkerAttention):
                worker.prepare_published_mixed_destroy_plans(queued.id, **options)
            assert calls == [collection.review.source.ordered_providers[0]]
            return
        sealed = worker.prepare_published_mixed_destroy_plans(queued.id, **options)
        assert sealed.input["phase"] == "plans_sealed"
        assert calls == list(collection.review.source.ordered_providers)
        assert worker.prepare_published_mixed_destroy_plans(
            queued.id, **options) == sealed
        assert calls == list(collection.review.source.ordered_providers)
