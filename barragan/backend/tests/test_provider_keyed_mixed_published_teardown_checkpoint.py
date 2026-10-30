# Copyright (c) 2026, Oracle and/or its affiliates.
"""A published mixed cleanup checkpoint binds both providers but grants no GO."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_mixed_published_teardown_authority import (
    review_published_mixed_initial_teardown,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup,
    recognize_published_mixed_initial_checkpoint,
    saved_published_mixed_initial_review,
)
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_authority import _case


def _core_scope(review):
    return {
        "jobId": review.source.core_job_id,
        "planId": review.source.core_plan_id,
        "stateSha256": "a" * 64,
        "inventorySha256": "b" * 64,
        "proxyCount": 1,
        "targets": [{"id": f"tcp:{ip}:22", "type": "tcp-forbidden", "host": ip,
                     "port": 22, "targetGroup": "core-public-management"}
                    for ip in ("8.8.8.8", "9.9.9.9")],
        "ownedInspectorRecordIds": ["inspector-instance", "inspector-firewall"],
    }


def test_published_checkpoint_binds_both_scopes_and_exact_review(client, ready, tmp_path):
    with client.application.storage_context():
        source, args, _persisted = _case(ready, tmp_path)
        review = review_published_mixed_initial_teardown(**args)
        scope = _core_scope(review)
        proposed = propose_published_mixed_initial_cleanup(
            review, scope, "Opaque", requested_by="operator")
        assert proposed.input["orderedProviders"] == list(source.ordered_providers)
        assert [row["provider"] for row in proposed.input["providerScopes"]] == list(
            source.ordered_providers)
        assert proposed.input["phase"] == "awaiting_both_destroy_plans"
        assert len(proposed.events) == 1
        assert saved_published_mixed_initial_review(proposed) == review
        assert recognize_published_mixed_initial_checkpoint(
            proposed, review, scope, "Opaque") == proposed
        with pytest.raises(ValueError):
            recognize_published_mixed_initial_checkpoint(
                replace(proposed, input={**proposed.input,
                                         "providerScopes": proposed.input["providerScopes"][:1]}),
                review, scope, "Opaque")
        with pytest.raises(ValueError):
            recognize_published_mixed_initial_checkpoint(
                replace(proposed, events=[*proposed.events, proposed.events[0]]),
                review, scope, "Opaque")
        with pytest.raises(ValueError):
            recognize_published_mixed_initial_checkpoint(
                proposed, review, {**scope, "stateSha256": "c" * 64}, "Opaque")
        tampered = {**proposed.input["publishedSource"],
                    "host_rows": [*proposed.input["publishedSource"]["host_rows"]]}
        tampered["host_rows"][0] = {**tampered["host_rows"][0],
                                     "public_ip": "198.51.100.23"}
        with pytest.raises(ValueError, match="exact checkpoint"):
            saved_published_mixed_initial_review(replace(
                proposed, input={**proposed.input, "publishedSource": tampered}))


def test_published_checkpoint_vetoes_six_node_or_binding_drift(client, ready, tmp_path):
    with client.application.storage_context():
        _source, args, _persisted = _case(ready, tmp_path)
        review = review_published_mixed_initial_teardown(**args)
        scope = _core_scope(review)
        with pytest.raises(Exception):
            propose_published_mixed_initial_cleanup(
                replace(review, live_binding_count=1), scope, "Opaque",
                requested_by="operator")
        with pytest.raises(Exception):
            propose_published_mixed_initial_cleanup(
                replace(review, provider_scopes=review.provider_scopes[:1]),
                scope, "Opaque", requested_by="operator")
