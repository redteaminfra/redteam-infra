# Copyright (c) 2026, Oracle and/or its affiliates.
"""The runtime collector reopens persisted publication before any destroy."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_mixed_published_teardown_collector import (
    PublishedMixedTeardownCollectionAttention,
    _empty_owned_bindings,
    collect_published_mixed_initial_teardown,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_authority import _case


class Plans:
    def __init__(self, plan):
        self.plan = plan

    def get(self, identifier):
        return self.plan if identifier == self.plan.id else None


def _collect(ready, tmp_path, monkeypatch, *, observer=None, inventory=None,
             lease=None, allow_fence=False):
    source, args, _ = _case(ready, tmp_path)
    import app.services.provider_keyed_mixed_published_teardown_collector as module
    monkeypatch.setattr(module, "active_core_connection_details",
                        lambda jobs, engagement: (source.core_job_id, []))
    monkeypatch.setattr(module, "_core_inspector_scope",
                        lambda core, **kwargs: {"jobId": core.id, "inspector": "exact"})
    records = {"value": args["live_bindings"]}
    kwargs = dict(
        job_repository=ready.case.jobs, plan_repository=Plans(args["plan"]),
        sketch_repository=SqlAlchemySketchChainRepository(),
        domain_repository=object(), provider_resource_repository=object(),
        lease_lookup=lambda engagement: lease,
        fresh_observer=observer or (
            lambda parent, provider, fence: args["observations"][provider]),
        binding_inventory=inventory or (
            lambda engagement, jobs, domains: records["value"]),
        allow_teardown_fence=allow_fence,
    )
    return source, args, records, kwargs


def test_collector_reads_published_provider_order(client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, args, _, kwargs = _collect(ready, tmp_path, monkeypatch)
        result = collect_published_mixed_initial_teardown(
            source.engagement_id, source.core_job_id, **kwargs)
        assert result.review.source == source
        assert tuple(row["provider"] for row in result.review.provider_scopes) == source.ordered_providers
        assert result.core_inspector_scope == {"jobId": source.core_job_id, "inspector": "exact"}
        assert set(result.observations) == set(source.ordered_providers)
        assert set(result.workspaces) == set(source.ordered_providers)


def test_collector_fences_binding_change_during_provider_read(client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, args, records, kwargs = _collect(ready, tmp_path, monkeypatch)
        def observe(parent, provider, fence):
            records["value"] = {**records["value"], "domains": ("late-binding",)}
            return args["observations"][provider]
        kwargs["fresh_observer"] = observe
        with pytest.raises(PublishedMixedTeardownCollectionAttention):
            collect_published_mixed_initial_teardown(source.engagement_id,
                                                     source.core_job_id, **kwargs)


def test_collector_rejects_unfenced_lease(client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, _, _, kwargs = _collect(
            ready, tmp_path, monkeypatch,
            lease=("another-owner", "provider_keyed_initial"))
        with pytest.raises(PublishedMixedTeardownCollectionAttention):
            collect_published_mixed_initial_teardown(source.engagement_id,
                                                     source.core_job_id, **kwargs)


def test_empty_owned_binding_inventory_checks_persisted_action_history(client, ready):
    with client.application.storage_context():
        engagement = ready.case.records["core_plan"].engagement_id
        jobs = ready.case.jobs
        class Domains:
            def list_assignments(self, *, engagement_id):
                return []
        domains = Domains()
        assert _empty_owned_bindings(engagement, jobs, domains) == {
            key: () for key in ("channels", "domains", "certificates", "sites")}
        original = jobs.list_for_engagement
        jobs.list_for_engagement = lambda identifier: [
            *original(identifier),
            replace(original(identifier)[0], action="engagement_channels_update"),
        ]
        with pytest.raises(ValueError, match="independently owned bindings"):
            _empty_owned_bindings(engagement, jobs, domains)


@pytest.mark.parametrize("drift", [None, "nodes", "during_read"])
def test_collector_selects_reviewed_pair_and_fences_complete_history(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        source, args, _, kwargs = _collect(ready, tmp_path, monkeypatch)
        sketches = kwargs["sketch_repository"]
        first = sketches.list_for_engagement(source.engagement_id)[0]
        ghost = sketches.save(replace(first, chain_id="old-aborted", status="aborted",
            burned=False, deploy_job_id="", teardown_job_id="",
            terraform_working_directory="", nodes=[]))
        if drift == "nodes":
            sketches.save(replace(ghost, nodes=[{"providerInstanceId": "alien"}]))
        if drift == "during_read":
            def observer(parent, provider, fence):
                sketches.save(replace(ghost, burned_note="history changed"))
                return args["observations"][provider]
            kwargs["fresh_observer"] = observer
        if drift is not None:
            with pytest.raises(PublishedMixedTeardownCollectionAttention):
                collect_published_mixed_initial_teardown(source.engagement_id,
                    source.core_job_id, **kwargs)
        else:
            result = collect_published_mixed_initial_teardown(source.engagement_id,
                source.core_job_id, **kwargs)
            assert result.review.source == source
            assert sketches.get(source.engagement_id, ghost.chain_id) == ghost
