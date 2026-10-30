# Copyright (c) 2026, Oracle and/or its affiliates.
"""Historical published provider receipts remain usable after OCI goes empty."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_mixed_published_destroy_child import child_id
from app.services.provider_keyed_mixed_published_first_destroy_go import (
    run_published_mixed_second_provider_destroy,
)
from app.services.provider_keyed_mixed_published_post_oci_source import (
    PublishedMixedPostOciSourceAttention, audit_published_mixed_post_oci_source,
)
from app.services.provider_keyed_mixed_published_second_absence_worker import (
    finish_published_mixed_second_absence,
)
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_first_absence_worker import (
    _prepared_second, _snapshot_after, _worker,
)
from test_provider_keyed_mixed_published_first_destroy_go import _fake_runner


def _post_oci(client, ready, tmp_path, monkeypatch):
    jobs, collection, parent, plans, second, root, go = _prepared_second(
        ready, tmp_path, monkeypatch)
    go["gated_command_runner"] = _fake_runner(second, root, [])
    run_published_mixed_second_provider_destroy(parent.id, **go)
    worker = _worker(ready, collection, monkeypatch)
    order = collection.review.source.ordered_providers
    worker["snapshot_collector"] = lambda initial, provider, workspace, *, fence, **kw: (
        _snapshot_after(plans.plans[order.index(provider)], fence()))
    finish_published_mixed_second_absence(parent.id, **worker)
    source = collection.review.source
    options = dict(
        active_core_reader=lambda _jobs, engagement: (source.core_job_id, []),
        inspector_record_reader=lambda *args: tuple(parent.input[
            "reviewScope"]["ownedInspectorRecordIds"]),
    )
    return (jobs, parent, jobs.get(source.parent_job_id),
            jobs.get(source.core_job_id),
            SqlAlchemyDeploymentPlanRepository().get(source.core_plan_id),
            worker["lease_lookup"], options, source)


@pytest.mark.parametrize("drift", [None, "first_child", "second_child", "lease"])
def test_post_oci_source_reopens_both_terminal_receipts_without_core_state(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, parent, initial, core, plan, lookup, options, source = _post_oci(
            client, ready, tmp_path, monkeypatch)
        if drift in {"first_child", "second_child"}:
            provider = source.ordered_providers[0 if drift == "first_child" else 1]
            child = jobs.get(child_id(source.core_job_id, provider))
            jobs.save(replace(child, input={**child.input, "drift": True}))
        elif drift == "lease":
            lookup = lambda engagement: (source.core_plan_id, "provider_keyed_initial")
        args = (parent, initial, core, plan, jobs, lookup)
        if drift is None:
            result = audit_published_mixed_post_oci_source(*args, **options)
            assert result.core_state_sha256 == parent.input["reviewScope"]["stateSha256"]
            assert len(result.provider_child_journal_sha256) == 2
            assert len(result.provider_absence_receipt_sha256) == 2
        else:
            with pytest.raises(PublishedMixedPostOciSourceAttention):
                audit_published_mixed_post_oci_source(*args, **options)
