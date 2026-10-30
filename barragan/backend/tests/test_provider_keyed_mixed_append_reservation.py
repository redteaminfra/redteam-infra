# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure external-middle reservation contract; no filesystem or Terraform."""

from dataclasses import replace
from copy import deepcopy

import pytest

from app.services.provider_keyed_mixed_append_reservation import (
    MixedAppendReservationAttention, _digest,
    propose_mixed_external_append_reservations,
)
from app.services.provider_keyed_mixed_initial_publication_source import (
    MixedInitialPublicationSource, MixedProviderState,
)
from test_provider_keyed_mixed_append_pair_plan import inputs


def sample():
    do, linode, _ = inputs()
    do_topology = {
        "schema": "provider-keyed-v2",
        "middles": {"middle_01": {"region": "nyc3", "ordinal": 1}},
        "edge_groups": {"original_nyc3": {
            "region": "nyc3", "middle_node": "middle_01", "ordinals": [1]}},
        "regional_high_water": {"nyc3": 1},
    }
    linode_topology = {
        "schema": "provider-keyed-v2",
        "middles": {"middle_02": {"region": "us-sea", "ordinal": 2}},
        "edge_groups": {"original_us_sea": {
            "region": "us-sea", "middle_node": "middle_02", "ordinals": [1]}},
        "regional_high_water": {"nyc3": 1, "us-sea": 1},
    }
    do = replace(do, nonsecret_varfile={
        "middles": do_topology["middles"],
        "edge_groups": {**do_topology["edge_groups"], "external_nyc3": {
            "region": "nyc3", "middle_node": "middle_02", "ordinals": [2]}},
        "external_middle_nodes": ["middle_02"],
    })
    linode = replace(linode, nonsecret_varfile={
        "middles": linode_topology["middles"],
        "edge_groups": {**linode_topology["edge_groups"], "external_us_sea": {
            "region": "us-sea", "middle_node": "middle_01", "ordinals": [2]}},
        "external_middle_nodes": ["middle_01"],
    })
    nodes = [
        {"chainId": "chain-do", "provider": "digitalocean", "role": "middle",
         "terraformAddress": 'digitalocean_droplet.middle["middle_01"]',
         "providerInstanceId": "101", "region": "nyc3"},
        {"chainId": "chain-do", "provider": "digitalocean", "role": "edge",
         "terraformAddress": 'digitalocean_droplet.edge["nyc3-01"]',
         "providerInstanceId": "102", "region": "nyc3"},
        {"chainId": "chain-linode", "provider": "linode", "role": "middle",
         "terraformAddress": 'linode_instance.middle["middle_02"]',
         "providerInstanceId": "201", "region": "us-sea"},
        {"chainId": "chain-linode", "provider": "linode", "role": "edge",
         "terraformAddress": 'linode_instance.edge["us-sea-01"]',
         "providerInstanceId": "202", "region": "us-sea"},
    ]
    manifest = {"schema": "mixed-initial-host-binding-v1",
                "engagementId": do.engagement_id, "coreJobId": do.core_job_id,
                "nodes": nodes}
    source = MixedInitialPublicationSource(
        do.engagement_id, do.core_job_id, "plan-1", "revision-1", "job-1",
        ("digitalocean", "linode"), ("chain-do", "chain-linode"),
        "1" * 64, _digest(manifest), "2" * 64,
        (MixedProviderState("digitalocean", "a" * 64, "do-lineage", 1,
                            do.retained_digitalocean_ids, "3" * 64),
         MixedProviderState("linode", "b" * 64, "linode-lineage", 1,
                            do.retained_linode_ids, "4" * 64)), ())
    return dict(source=source, binding_manifest=manifest, digitalocean_intent=do,
                linode_intent=linode,
                current_topologies={"digitalocean": do_topology, "linode": linode_topology},
                regional_high_water={"nyc3": 1, "us-sea": 1},
                reviewed_provider_order=("digitalocean", "linode"))


def test_external_middle_proposal_is_deterministic_and_nonmutating():
    kwargs = sample()
    before = deepcopy(kwargs)
    first = propose_mixed_external_append_reservations(**kwargs)
    assert first == propose_mixed_external_append_reservations(**kwargs)
    assert kwargs == before
    assert first.proposed_high_water == {"nyc3": 2, "us-sea": 2}
    assert tuple(row.foreign_middle_provider for row in first.reservations) == (
        "linode", "digitalocean")
    assert first.reservations[0].proposed_topology["external_middles"] == {
        "middle_02": {"provider": "linode", "chain_id": "chain-linode",
                      "terraform_address": 'linode_instance.middle["middle_02"]',
                      "provider_instance_id": "201"}}


@pytest.mark.parametrize("tamper", ["selected", "state", "ordinal", "old_group", "ledger", "source"])
def test_crossed_or_stale_reservation_fails_closed(tamper):
    kwargs = sample()
    if tamper == "selected":
        kwargs["digitalocean_intent"] = replace(kwargs["digitalocean_intent"],
                                                  linode_middle_id="202")
    elif tamper == "state":
        kwargs["linode_intent"] = replace(kwargs["linode_intent"],
                                          linode_state_sha256="9" * 64)
    elif tamper == "ordinal":
        kwargs["digitalocean_intent"] = replace(kwargs["digitalocean_intent"],
                                                  new_edge_ordinal=3)
    elif tamper == "old_group":
        kwargs["current_topologies"]["digitalocean"]["edge_groups"]["original_nyc3"]["ordinals"] = [2]
    elif tamper == "ledger":
        kwargs["regional_high_water"]["nyc3"] = 3
    else:
        kwargs["binding_manifest"]["nodes"][2]["providerInstanceId"] = "999"
    with pytest.raises(MixedAppendReservationAttention):
        propose_mixed_external_append_reservations(**kwargs)


def test_same_region_pair_must_allocate_distinct_engagement_ordinals():
    kwargs = sample()
    linode = kwargs["linode_intent"]
    kwargs["linode_intent"] = replace(
        linode, new_edge_address='linode_instance.edge["nyc3-02"]',
        nonsecret_varfile={**linode.nonsecret_varfile,
                           "edge_groups": {**kwargs["current_topologies"]["linode"]["edge_groups"],
                                           "external_nyc3": {"region": "nyc3",
                                                             "middle_node": "middle_01",
                                                             "ordinals": [2]}}})
    with pytest.raises(MixedAppendReservationAttention):
        propose_mixed_external_append_reservations(**kwargs)


def test_same_region_pair_allocates_sequential_engagement_ordinals():
    kwargs = sample()
    linode = kwargs["linode_intent"]
    kwargs["linode_intent"] = replace(
        linode, new_edge_address='linode_instance.edge["nyc3-03"]',
        new_edge_ordinal=3,
        new_edge=replace(linode.new_edge, region="nyc3"),
        nonsecret_varfile={**linode.nonsecret_varfile,
                           "edge_groups": {**kwargs["current_topologies"]["linode"]["edge_groups"],
                                           "external_nyc3": {"region": "nyc3",
                                                             "middle_node": "middle_01",
                                                             "ordinals": [3]}}})
    proposal = propose_mixed_external_append_reservations(**kwargs)
    assert [row.edge_ordinal for row in proposal.reservations] == [2, 3]
    assert proposal.proposed_high_water == {"nyc3": 3, "us-sea": 1}


@pytest.mark.parametrize('drift', [None, 'cloud_id', 'missing_cloud_id', 'unknown_extra'])
def test_reservation_binds_cloud_publication_to_full_retained_ids(drift):
    kwargs = sample()
    source = kwargs['source']
    states = tuple(replace(row, resource_ids=tuple((a, v) for a, v in row.resource_ids
        if not a.startswith(('local_file.', 'random_password.')))) for row in source.provider_states)
    kwargs['source'] = replace(source, provider_states=states)
    if drift == 'cloud_id':
        row = states[0]
        kwargs['source'] = replace(source, provider_states=(replace(row,
            resource_ids=((*row.resource_ids[:-1], (row.resource_ids[-1][0], 'foreign')))), states[1]))
    elif drift == 'missing_cloud_id':
        row = states[0]
        kwargs['source'] = replace(source, provider_states=(replace(row, resource_ids=row.resource_ids[1:]), states[1]))
    elif drift == 'unknown_extra':
        for name in ('digitalocean_intent', 'linode_intent'):
            intent = kwargs[name]
            kwargs[name] = replace(intent, retained_digitalocean_ids=(*intent.retained_digitalocean_ids,
                ('digitalocean_droplet.foreign', 'foreign')))
    if drift:
        with pytest.raises(MixedAppendReservationAttention):
            propose_mixed_external_append_reservations(**kwargs)
    else:
        proposal = propose_mixed_external_append_reservations(**kwargs)
        assert len(proposal.reservations) == 2
