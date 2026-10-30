# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline mixed publication source is exact but never publishes a chain."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_mixed_initial_apply_child import _child_id
from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedInitialPublicationSourceAttention, recognize_mixed_initial_publication_source,
)
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_bootstrap import _inputs
from test_provider_keyed_mixed_initial_plan_parent import case


def _source(ready, tmp_path):
    parent, binding, args, _calls, _state = _inputs(ready, tmp_path)
    worker = run_mixed_initial_bootstrap(**args)
    order = parent.input["orderedProviders"]
    observations = {provider: args["fresh_observer"](parent, provider, lambda: None)
                    for provider in order}
    chains = {chain.chain_id: chain for chain in
              args["sketch_repository"].list_for_engagement(parent.target_id)}
    return dict(parent=parent, core=ready.case.jobs.get("job-core"),
                plan=replace(ready.case.records["core_plan"], stage="applied"),
                children={provider: ready.case.jobs.get(_child_id("job-core", provider))
                          for provider in order}, binding=binding, host_worker=worker,
                active_core_id="job-core", lease=ready.case.lease["value"],
                chains=chains, observations=observations,
                process_quiescent=lambda _identity: True)


@pytest.mark.parametrize("receipt_shape", ["old", "interim", "timing"])
def test_both_orders_produce_immutable_four_host_source(ready, tmp_path, receipt_shape):
    kwargs = _source(ready, tmp_path)
    worker = kwargs["host_worker"]
    fields = {"executionTimeoutSeconds", "commandElapsedSeconds", "timedOut"}
    if receipt_shape != "timing":
        excluded = fields if receipt_shape == "old" else fields - {"timedOut"}
        kwargs["host_worker"] = replace(worker, events=[
            replace(event, data={key: value for key, value in event.data.items() if key not in excluded})
            if event.message == "mixed bootstrap command result fenced" else event
            for event in worker.events
        ])
    source = recognize_mixed_initial_publication_source(**kwargs)
    assert source.ordered_providers == tuple(kwargs["parent"].input["orderedProviders"])
    assert source.chain_ids == tuple(kwargs["parent"].input["chainIds"])
    assert [row.role for row in source.host_rows] == ["middle", "edge", "middle", "edge"]
    assert [row.provider for row in source.host_rows] == [
        source.ordered_providers[0], source.ordered_providers[0],
        source.ordered_providers[1], source.ordered_providers[1]]
    assert len(source.provider_states) == 2
    assert all(len(row.state_sha256) == 64 and row.resource_ids for row in source.provider_states)
    assert all(chain.status == "pending" and not chain.nodes for chain in kwargs["chains"].values())
    with pytest.raises(AttributeError):
        source.host_rows = ()


@pytest.mark.parametrize("drift", [
    "lease", "active_core", "revision", "plan_fingerprint", "plan_scope",
    "duplicate_provider",
    "chain_generation", "crossed_children", "state_bytes", "binding", "worker",
    "pending_chain", "missing_state", "core_plan", "worker_process",
])
def test_drift_fails_closed(ready, tmp_path, drift):
    kwargs = _source(ready, tmp_path)
    parent = kwargs["parent"]
    if drift == "lease":
        kwargs["lease"] = ("other-plan", "provider_keyed_initial")
    elif drift == "active_core":
        kwargs["active_core_id"] = "job-other"
    elif drift == "revision":
        kwargs["plan"] = replace(kwargs["plan"], revision_id="rev-other")
    elif drift == "plan_fingerprint":
        evidence = {**kwargs["plan"].evidence,
                    "sketchAuthorization": {**kwargs["plan"].evidence["sketchAuthorization"],
                                             "fingerprint": "0" * 64}}
        kwargs["plan"] = replace(kwargs["plan"], evidence=evidence)
    elif drift == "plan_scope":
        auth = {**kwargs["plan"].evidence["sketchAuthorization"],
                "providerScopes": [{"provider": "unreviewed"}]}
        kwargs["plan"] = replace(kwargs["plan"], evidence={
            **kwargs["plan"].evidence, "sketchAuthorization": auth})
    elif drift == "duplicate_provider":
        kwargs["children"] = {"linode": next(iter(kwargs["children"].values()))}
    elif drift == "chain_generation":
        evidence = {**kwargs["plan"].evidence,
                    "pendingSketchChainIds": list(reversed(parent.input["chainIds"]))}
        kwargs["plan"] = replace(kwargs["plan"], evidence=evidence)
    elif drift == "crossed_children":
        first, second = parent.input["orderedProviders"]
        kwargs["children"] = {first: kwargs["children"][second],
                              second: kwargs["children"][first]}
    elif drift == "state_bytes":
        provider = parent.input["orderedProviders"][0]
        observed = kwargs["observations"][provider]
        kwargs["observations"][provider] = replace(observed, state_json=observed.state_json + b" ")
    elif drift == "binding":
        kwargs["binding"] = replace(kwargs["binding"], input={
            **kwargs["binding"].input, "manifestSha256": "0" * 64})
    elif drift == "worker":
        kwargs["host_worker"] = replace(kwargs["host_worker"], status="running")
    elif drift == "pending_chain":
        chain_id = parent.input["chainIds"][0]
        kwargs["chains"][chain_id] = replace(kwargs["chains"][chain_id], status="deployed")
    elif drift == "missing_state":
        kwargs["observations"].pop(parent.input["orderedProviders"][0])
    elif drift == "core_plan":
        kwargs["plan"] = replace(kwargs["plan"], apply_job_id="job-other")
    elif drift == "worker_process":
        kwargs["process_quiescent"] = lambda _identity: False
    with pytest.raises(MixedInitialPublicationSourceAttention):
        recognize_mixed_initial_publication_source(**kwargs)
