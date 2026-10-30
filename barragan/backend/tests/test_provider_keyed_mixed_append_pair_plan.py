# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pure paired pre-Apply plan seal regressions; no Terraform or provider calls."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_initial_plan_gate import DigitalOceanNodeCreate
from app.services.provider_keyed_linode_initial_plan_gate import LinodeNodeCreate
from app.services.provider_keyed_mixed_append_intent import (
    MixedDigitalOceanOnLinodeAppendIntent, _SHARED_DO, _SHARED_LINODE,
)
from app.services.provider_keyed_mixed_append_linode_intent import (
    MixedLinodeOnDigitalOceanAppendIntent,
)
from app.services.provider_keyed_mixed_append_pair_plan import (
    MixedAppendPairPlanError, seal_mixed_append_pair_plan,
)


DO_MIDDLE = 'digitalocean_droplet.middle["middle_01"]'
LINODE_MIDDLE = 'linode_instance.middle["middle_02"]'
DO_NEW = 'digitalocean_droplet.edge["nyc3-02"]'
LINODE_NEW = 'linode_instance.edge["us-sea-02"]'
DO_IDS = tuple(sorted({
    **{address: str(n) for n, address in enumerate(sorted(_SHARED_DO), 10)},
    DO_MIDDLE: "101", 'digitalocean_droplet.edge["nyc3-01"]': "102",
}.items()))
LINODE_IDS = tuple(sorted({
    **{address: str(n) for n, address in enumerate(sorted(_SHARED_LINODE), 20)},
    LINODE_MIDDLE: "201", 'linode_instance.edge["us-sea-01"]': "202",
}.items()))


def inputs():
    common = dict(
        engagement_id="eng-example", core_job_id="core-example",
        digitalocean_state_sha256="a" * 64, linode_state_sha256="b" * 64,
        retained_digitalocean_ids=DO_IDS, retained_linode_ids=LINODE_IDS,
        prior_trusted_ssh_cidrs=("203.0.113.1/32",),
        trusted_ssh_cidrs=("203.0.113.1/32", "203.0.113.2/32"),
        new_edge_ordinal=2, nonsecret_varfile={},
    )
    do = MixedDigitalOceanOnLinodeAppendIntent(
        **common, chain_id="chain-linode", linode_middle_address=LINODE_MIDDLE,
        linode_middle_id="201", new_edge_address=DO_NEW,
        new_edge=DigitalOceanNodeCreate("edge-example-nyc3-02", "ubuntu", "s-1vcpu-1gb", "nyc3", "tag"),
    )
    linode = MixedLinodeOnDigitalOceanAppendIntent(
        **common, chain_id="chain-do", digitalocean_middle_address=DO_MIDDLE,
        digitalocean_middle_id="101", new_edge_address=LINODE_NEW,
        new_edge=LinodeNodeCreate("edge-example-us-sea-02", "ubuntu", "g6-nanode-1", "us-sea", "tag", ("ssh-ed25519 example",)),
    )
    def receipt(provider, chain, state, edge, plan):
        return {
            "provider": provider, "engagementId": "eng-example", "coreJobId": "core-example",
            "chainId": chain, "predecessorStateSha256": state, "newEdgeAddress": edge,
            "planSha256": plan * 64, "showJsonSha256": "e" * 64,
            "sourceRevision": "pinned-source-commit", "sourceSha256": "f" * 64,
            "credentialRecordId": f"credential-{provider}",
            "credentialSecretSha256": "9" * 64, "credentialUpdatedAt": "2026-10-19T00:00:00Z",
        }
    receipts = (
        receipt("digitalocean", "chain-linode", "a" * 64, DO_NEW, "c"),
        receipt("linode", "chain-do", "b" * 64, LINODE_NEW, "d"),
    )
    return do, linode, receipts


def seal(do, linode, receipts, *, providers=("digitalocean", "linode"),
         chains=("chain-linode", "chain-do")):
    return seal_mixed_append_pair_plan(
        do, linode, receipts, reviewed_provider_order=providers,
        reviewed_chain_order=chains)


def test_pair_seal_is_deterministic_and_ordered():
    do, linode, receipts = inputs()
    first = seal(do, linode, receipts)
    assert first == seal(do, linode, tuple(dict(row) for row in receipts))
    assert first.saved_plan_sha256 == ("c" * 64, "d" * 64)
    assert first.new_edge_addresses == (DO_NEW, LINODE_NEW)
    reverse = seal(do, linode, receipts[::-1],
                   providers=("linode", "digitalocean"),
                   chains=("chain-do", "chain-linode"))
    assert reverse.review_sha256 != first.review_sha256
    assert reverse.saved_plan_sha256 == first.saved_plan_sha256[::-1]
    with pytest.raises(MixedAppendPairPlanError):
        seal(do, linode, receipts, chains=("chain-do", "chain-linode"))


def test_pair_seal_allows_same_numeric_instance_id_in_different_providers():
    do, linode, receipts = inputs()
    overlapping = tuple(sorted((address, "201" if address == DO_MIDDLE else value)
                               for address, value in DO_IDS))
    do = replace(do, retained_digitalocean_ids=overlapping)
    linode = replace(linode, retained_digitalocean_ids=overlapping,
                     digitalocean_middle_id="201")
    assert seal(do, linode, receipts).new_edge_addresses == (DO_NEW, LINODE_NEW)


@pytest.mark.parametrize("mutation", [
    lambda d, l, r: (d, replace(l, digitalocean_state_sha256="8" * 64), r),
    lambda d, l, r: (d, replace(l, retained_linode_ids=LINODE_IDS[:-1]), r),
    lambda d, l, r: (replace(d, linode_middle_id="202"), l, r),
    lambda d, l, r: (d, replace(l, digitalocean_middle_id="102"), r),
    lambda d, l, r: (d, replace(l, chain_id=d.chain_id), r),
    lambda d, l, r: (replace(d, new_edge_address='digitalocean_droplet.edge["nyc3-01"]'), l, r),
    lambda d, l, r: (d, l, r[::-1]),
    lambda d, l, r: (d, l, ({**r[0], "predecessorStateSha256": "b" * 64}, r[1])),
    lambda d, l, r: (d, l, ({**r[0], "chainId": r[1]["chainId"]}, r[1])),
    lambda d, l, r: (d, l, ({**r[0], "newEdgeAddress": r[1]["newEdgeAddress"]}, r[1])),
    lambda d, l, r: (d, l, ({**r[0], "planSha256": r[1]["planSha256"]}, r[1])),
    lambda d, l, r: (d, l, ({**r[0], "credentialRecordId": ""}, r[1])),
    lambda d, l, r: (d, l, ({**r[0], "coreJobId": "other-core"}, r[1])),
    lambda d, l, r: (d, l, ({**r[0], "sourceRevision": ""}, r[1])),
    lambda d, l, r: (d, l, ({**r[0], "showJsonSha256": "bad"}, r[1])),
    lambda d, l, r: (d, l, ({**r[0], "unreviewed": "extra"}, r[1])),
])
def test_stale_or_crossed_pair_fails_closed(mutation):
    with pytest.raises(MixedAppendPairPlanError):
        seal(*mutation(*inputs()))
