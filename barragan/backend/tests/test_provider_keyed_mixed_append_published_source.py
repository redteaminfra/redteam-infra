# Copyright (c) 2026, Oracle and/or its affiliates.
"""Append source reuses the published proof while allowing live bindings."""

import pytest

from app.services.provider_keyed_mixed_append_published_source import (
    PublishedMixedAppendSourceAttention, collect_published_mixed_append_source,
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


def _options(ready, tmp_path, monkeypatch):
    source, args, _ = _case(ready, tmp_path)
    import app.services.provider_keyed_mixed_append_published_source as module
    monkeypatch.setattr(module, "active_core_connection_details",
                        lambda jobs, engagement: (source.core_job_id, []))
    bindings = {"channels": ("channel-opaque",), "domains": (),
                "certificates": (), "sites": ()}
    calls = []
    def observe(parent, provider, fence):
        calls.append(provider)
        fence()
        return args["observations"][provider]
    options = dict(
        binding_inventory=lambda: bindings,
        job_repository=ready.case.jobs,
        plan_repository=Plans(args["plan"]),
        sketch_repository=SqlAlchemySketchChainRepository(),
        lease_lookup=lambda engagement: (
            args["plan"].id, "provider_keyed_mixed_append"),
        fresh_observer=observe,
    )
    return source, args, bindings, calls, options


def test_selected_source_accepts_append_lease_and_live_bindings(
    client, ready, tmp_path, monkeypatch,
):
    with client.application.storage_context():
        source, args, bindings, calls, options = _options(ready, tmp_path, monkeypatch)
        # A global scan is neither needed nor permitted by this source reader.
        ready.case.jobs.list = lambda: (_ for _ in ()).throw(
            AssertionError("global job history scanned"))
        result = collect_published_mixed_append_source(
            source.engagement_id, source.core_job_id, **options)
        assert result.source == source
        assert result.live_binding_count == 1
        assert result.source.binding_manifest_sha256 == source.binding_manifest_sha256
        assert tuple(provider for provider, _ in result.workspaces) == source.ordered_providers
        assert calls == list(source.ordered_providers)


def test_binding_change_during_provider_get_fails_closed(
    client, ready, tmp_path, monkeypatch,
):
    with client.application.storage_context():
        source, args, bindings, _, options = _options(ready, tmp_path, monkeypatch)
        def observe(parent, provider, fence):
            bindings["channels"] = ("late-channel",)
            return args["observations"][provider]
        options["fresh_observer"] = observe
        with pytest.raises(PublishedMixedAppendSourceAttention):
            collect_published_mixed_append_source(
                source.engagement_id, source.core_job_id, **options)


def test_equal_count_binding_swap_changes_source_digest(
    client, ready, tmp_path, monkeypatch,
):
    with client.application.storage_context():
        source, _, bindings, _, options = _options(ready, tmp_path, monkeypatch)
        before = collect_published_mixed_append_source(
            source.engagement_id, source.core_job_id, **options)
        bindings["channels"] = ("different-opaque-channel",)
        after = collect_published_mixed_append_source(
            source.engagement_id, source.core_job_id, **options)
        assert before.live_binding_count == after.live_binding_count == 1
        assert before.source == after.source
        assert before.live_bindings_sha256 != after.live_bindings_sha256
        assert before != after
        assert "channel-opaque" not in repr(before)


def test_wrong_append_lease_fails_before_provider_get(
    client, ready, tmp_path, monkeypatch,
):
    with client.application.storage_context():
        source, _, _, calls, options = _options(ready, tmp_path, monkeypatch)
        options["lease_lookup"] = lambda engagement: (
            options["plan_repository"].plan.id, "provider_keyed_initial")
        with pytest.raises(PublishedMixedAppendSourceAttention):
            collect_published_mixed_append_source(
                source.engagement_id, source.core_job_id, **options)
        assert calls == []
