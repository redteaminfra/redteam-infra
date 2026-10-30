# Copyright (c) 2026, Oracle and/or its affiliates.
"""Mixed host binding is exact, private, and has no host contact."""

from dataclasses import replace
import hashlib
import json
from uuid import uuid4

import pytest

from app.services.provider_keyed_mixed_initial_apply_child import _child_id
from app.services.provider_keyed_mixed_initial_coordinator import (
    prepare_or_reuse_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    MixedInitialHostBindingAttention, ProviderHostObservation, _linode_public_ip,
    build_mixed_initial_host_binding, recognize_mixed_initial_host_binding,
    reserve_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
from test_provider_keyed_mixed_initial_apply_child import _terminal_first, ready
from test_provider_keyed_mixed_initial_coordinator import _finish_second
from test_provider_keyed_mixed_initial_plan_parent import case


def _resource(address, attributes):
    kind, rest = address.split(".", 1)
    name, _, suffix = rest.partition("[")
    instance = {"attributes": attributes}
    if suffix:
        instance["index_key"] = json.loads("[" + suffix)[0]
    return {"mode": "managed", "type": kind, "name": name, "instances": [instance]}


def _state(parent, provider, number):
    policy = parent.events[5].data["reviewedPolicy"][provider]
    resources = []
    cloud = {}
    nodes = []
    for index, (address, expected) in enumerate(sorted(policy["nodes"].items())):
        identifier = str(number * 100 + index + 1)
        name = expected["label" if provider == "linode" else "name"]
        ip = ["9.9.9.9", "1.1.1.1", "4.2.2.2", "1.0.0.1"][number * 2 + index]
        attrs = {
            "id": identifier, "tags": [expected["tag" if provider == "linode" else "firewall_selector_tag"]],
            "label" if provider == "linode" else "name": name,
            "image": expected["image"], "region": expected["region"],
            "type" if provider == "linode" else "size": expected["node_type" if provider == "linode" else "size"],
            "ipv4" if provider == "linode" else "ipv4_address": [ip] if provider == "linode" else ip,
        }
        resources.append(_resource(address, attrs))
        cloud[address] = identifier
        nodes.append(identifier)
    if provider == "linode":
        shared = {
            "linode_firewall.firewall": {
                "id": "900", "label": "fw-" + policy["engagement_name"] + "-firewall",
                "tags": [policy["engagement_name"]]},
            "random_password.root_password": {"id": "random"},
        }
    else:
        shared = {
            "digitalocean_firewall.firewall": {
                "id": "901", "name": policy["firewall"]["name"],
                "tags": [policy["firewall"]["selector_tag"]]},
            "digitalocean_ssh_key.key": {
                "id": "902", "name": policy["ssh_key_name"], "tags": [],
                "public_key": policy["admin_public_key"]},
        }
    for address, attrs in shared.items():
        resources.append(_resource(address, attrs))
        if not address.startswith("random_password"):
            cloud[address] = str(attrs["id"])
    for address in ("local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"):
        resources.append(_resource(address, {"id": address}))
    raw = json.dumps({"version": 4, "terraform_version": "1.15.5",
                      "lineage": str(uuid4()), "serial": 1, "resources": resources},
                     sort_keys=True).encode()
    return raw, cloud, nodes


def _prepared(ready):
    order = ready.parent.input["orderedProviders"]
    first = _terminal_first(ready)
    _finish_second(ready, first)
    observations = {}
    for index, provider in enumerate(order):
        child = ready.case.jobs.get(_child_id("job-core", provider))
        raw, cloud, node_ids = _state(ready.parent, provider, index)
        proof = {**child.events[-2].data,
                 "stateSha256": hashlib.sha256(raw).hexdigest(),
                 "lineage": json.loads(raw)["lineage"], "resourceIds": dict(sorted(cloud.items())),
                 "inventoryCount": len(cloud),
                 "selectorResourcesCount": len(node_ids) if provider == "digitalocean" else None,
                 "selectorAttachedNodeIds": sorted(node_ids) if provider == "digitalocean" else None,
                 "linodeFirewallAttachedNodeIds": sorted(node_ids) if provider == "linode" else None}
        events = [*child.events[:-2], replace(child.events[-2], data=proof), child.events[-1]]
        ready.case.jobs.save(replace(child, events=events))
        observations[provider] = ProviderHostObservation(
            ProviderApplyClassification(provider, "full", proof["stateSha256"],
                                        proof["lineage"], 1, tuple(sorted(cloud.items()))), raw)
    first_provider = order[0]
    def fresh(parent, child, fence):
        fence()
        return observations[first_provider].classification
    checkpoint = prepare_or_reuse_mixed_initial_host_proof_handoff(
        "eng-opaque", "job-core", environment="devtest", fresh_first_prover=fresh,
        job_repository=ready.case.jobs, lease_lookup=ready.case.args["lease_lookup"])
    children = {provider: ready.case.jobs.get(_child_id("job-core", provider)) for provider in order}
    chains = {chain.chain_id: chain for chain in ready.case.records["chains"]}
    return checkpoint, children, chains, observations


def test_exact_four_node_binding_for_both_reviewed_orders(ready):
    checkpoint, children, chains, observations = _prepared(ready)
    core = ready.case.records["core_job"]
    manifest = build_mixed_initial_host_binding(
        checkpoint, core, core.id, children, chains, observations)
    assert manifest["orderedProviders"] == checkpoint.input["orderedProviders"]
    assert len(manifest["nodes"]) == 4
    assert {row["role"] for row in manifest["nodes"]} == {"middle", "edge"}
    assert {row["provider"] for row in manifest["nodes"]} == {"linode", "digitalocean"}
    assert {row["providerInstanceId"] for row in manifest["nodes"]} <= {
        identifier for observation in observations.values()
        for _, identifier in observation.classification.resource_ids}


def test_changed_ip_or_state_hash_rejects_binding(ready):
    checkpoint, children, chains, observations = _prepared(ready)
    core = ready.case.records["core_job"]
    provider = checkpoint.input["orderedProviders"][0]
    raw = observations[provider].state_json.replace(b"9.9.9.9", b"9.9.9.10")
    changed = {**observations, provider: replace(observations[provider], state_json=raw)}
    with pytest.raises(MixedInitialHostBindingAttention):
        build_mixed_initial_host_binding(checkpoint, core, core.id, children, chains, changed)


@pytest.mark.parametrize("value", [[], ["8.8.8.8", "9.9.9.9"],
                                   ["127.0.0.1"], ["not-an-ip"], "8.8.8.8", [None]])
def test_linode_public_ip_requires_one_usable_address(value):
    with pytest.raises(ValueError):
        _linode_public_ip(value)
    assert _linode_public_ip(["8.8.8.8"]) == "8.8.8.8"


@pytest.mark.parametrize("inert_history", [False, True])
def test_inert_reservation_is_single_and_no_host_callback(ready, inert_history):
    checkpoint, children, chains, observations = _prepared(ready)
    if inert_history:
        ghost = replace(next(iter(chains.values())), chain_id="old-default", status="aborted",
            deploy_job_id="", teardown_job_id="", terraform_working_directory="", nodes=[])
        chains[ghost.chain_id] = ghost
    seen = []
    def observer(parent, provider, fence):
        seen.append(provider)
        fence()
        return observations[provider]
    args = dict(engagement_id="eng-opaque", core_job_id="job-core", environment="devtest",
                fresh_observer=observer, job_repository=ready.case.jobs,
                sketch_repository=type("Sketches", (), {"list_for_engagement":
                    lambda self, engagement_id: list(chains.values())})(),
                lease_lookup=ready.case.args["lease_lookup"])
    child = reserve_mixed_initial_host_binding(**args)
    assert child.status == "queued" and child.input["mutation"] is False
    assert child.events[0].data["manifest"]["nodes"]
    assert recognize_mixed_initial_host_binding(child, checkpoint) == child.events[0].data["manifest"]
    assert seen == checkpoint.input["orderedProviders"]
    assert reserve_mixed_initial_host_binding(
        **{**args, "fresh_observer": lambda *_: pytest.fail("duplicate provider read")}) == child
    forged = replace(child, events=[replace(child.events[0], data={
        **child.events[0].data, "manifestSha256": "0" * 64})])
    with pytest.raises(MixedInitialHostBindingAttention):
        recognize_mixed_initial_host_binding(forged, checkpoint)
