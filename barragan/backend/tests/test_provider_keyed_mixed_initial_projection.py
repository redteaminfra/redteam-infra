# Copyright (c) 2026, Oracle and/or its affiliates.
"""Mixed route projection uses exact provider binding and selected proxy."""

from copy import deepcopy

import pytest

from app.services.provider_keyed_mixed_initial_host_binding import build_mixed_initial_host_binding
from app.services.provider_keyed_mixed_initial_projection import (
    MixedInitialProjectionError, project_mixed_initial_chains,
)
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_host_binding import _prepared
from test_provider_keyed_mixed_initial_plan_parent import case


def test_mixed_projection_has_two_isolated_management_routes(ready):
    checkpoint, children, chains, observations = _prepared(ready)
    core = ready.case.records["core_job"]
    manifest = build_mixed_initial_host_binding(
        checkpoint, core, core.id, children, chains, observations)
    policy = checkpoint.events[5].data["reviewedPolicy"]
    projected = project_mixed_initial_chains(manifest, chains, policy)
    assert [item.chain.chain_id for item in projected] == checkpoint.input["chainIds"]
    assert [item.chain.middle_provider for item in projected] == checkpoint.input["orderedProviders"]
    assert all(len(item.chain.nodes) == 2 and len(item.host_policies) == 2 for item in projected)
    for item in projected:
        middle, edge = item.chain.nodes
        assert middle["role"] == "middle" and edge["role"] == "edge"
        assert item.host_policies[middle["hostname"]]["sketch_firewall_v2_ssh_sources"] == [
            item.proxy_egress_ip + "/32"]
        assert item.host_policies[edge["hostname"]]["sketch_firewall_v2_ssh_sources"] == [
            middle["publicIp"] + "/32"]


def test_mixed_projection_rejects_cross_chain_node(ready):
    checkpoint, children, chains, observations = _prepared(ready)
    core = ready.case.records["core_job"]
    manifest = build_mixed_initial_host_binding(
        checkpoint, core, core.id, children, chains, observations)
    changed = deepcopy(manifest)
    changed["nodes"][0]["chainId"] = changed["chainIds"][1]
    with pytest.raises(MixedInitialProjectionError):
        project_mixed_initial_chains(changed, chains, checkpoint.events[5].data["reviewedPolicy"])
