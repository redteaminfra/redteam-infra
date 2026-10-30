# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import replace

import pytest

from app.domain.deployment_plan import DeploymentPlan
from app.domain.job import JobEvent
from app.integrations.managed_host_images import MANAGED_HOST_IMAGE_PROFILES, ManagedHostImageProfile
from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.integrations.pilot_standard_rti import pilot_names
from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentEvidence, DigitalOceanAttachmentIntent, ExpectedDigitalOceanNode,
)
from app.services.provider_keyed_persisted_intent import (
    ProviderKeyedPersistedIntentError,
    compile_fresh_digitalocean_persisted_intent,
)
from app.storage.engagement_repository import StoredEngagement
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.database import db
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository, StoredSketchChain


def _chain(identifier, proxy, regions):
    return StoredSketchChain(
        chain_id=identifier, engagement_id="eng-opaque", assigned_proxy=proxy,
        middle_provider="digitalocean", middle_region="nyc3",
        middle_size="s-1vcpu-1gb", edge_provider="digitalocean",
        edge_region=regions[0], edge_size="s-1vcpu-1gb", status="pending",
        burned=False, burned_note="", deploy_job_id="", teardown_job_id="",
        terraform_working_directory="", nodes=[], created_at="", updated_at="",
        edge_count=len(regions), edge_intents=[
            {"id": f"edge-{index:02d}", "provider": "digitalocean", "region": region,
             "size": "s-1vcpu-1gb"} for index, region in enumerate(regions, 1)
        ],
    )


def _inputs():
    target = normalized_oci_deployment_target("barragan-testing")
    engagement = StoredEngagement(
        id="eng-opaque", name="m4t8q2z7", status="deployed",
        owner="operator", template_id="small-dev", active_revision="rev-1",
        input_parameters={"deploymentTarget": target},
        sketch_state_schema="provider-keyed-v2",
    )
    chains = [
        _chain("proxy01-sfo-01", "proxy01", ["sfo3", "nyc3", "sfo3"]),
        _chain("proxy02-sfo-01", "proxy02", ["sfo3", "sfo3"]),
    ]
    ids = [chain.chain_id for chain in chains]
    fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain) for chain in chains}
    evidence = {
        "sketchStateSchema": "provider-keyed-v2", "managedHostImageProfile": "ubuntu-22.04",
        "digitaloceanImage": "ubuntu-22-04-x64",
        "target": target, "pendingSketchChainIds": ids,
        "pendingSketchChainFingerprints": fingerprints, "sshSourceCidrs": ["203.0.113.10/32"],
    }
    job = StoredJobRun(
        id="job-core", action="pilot_standard_rti_guarded_execute", status="succeeded",
        target="", target_type="", target_id="", requested_by="operator",
        input={"engagementId": engagement.id, "engagementName": engagement.name,
               "sketchStateSchema": "provider-keyed-v2", "postCoreSketchContinuationEligible": False,
               "corePlanId": "plan-core", "target": target,
               "proxyCount": 2,
               "pendingSketchChainIds": ids, "pendingSketchChainFingerprints": fingerprints,
               "sshSourceCidrs": ["203.0.113.10/32"]},
        artifact_refs=[], created_at="", started_at="", finished_at="", events=[JobEvent(
            1, "info", "core deployed", {"mutationStatus": "deployed", "connectionDetails": [
                {"role": "proxy", "displayName": pilot_names(engagement.name).proxy_name,
                 "sshAlias": pilot_names(engagement.name).proxy_name, "publicIp": "8.8.8.8"},
                {"role": "proxy", "displayName": pilot_names(engagement.name).proxy02_name,
                 "sshAlias": pilot_names(engagement.name).proxy02_name, "publicIp": "9.9.9.9"},
            ]},
        )],
    )
    plan = DeploymentPlan("plan-core", engagement.id, "rev-1", "applied", "applied",
                          evidence=evidence, apply_job_id=job.id)
    return engagement, chains, job, plan, MANAGED_HOST_IMAGE_PROFILES["ubuntu-22.04"]


def _compile(*args, **kwargs):
    return compile_fresh_digitalocean_persisted_intent(*args, environment="devtest", **kwargs)


def test_compiles_two_chains_with_engagement_wide_regional_ordinals_and_opaque_labels():
    args = _inputs()
    result = _compile(*args)
    assert result.topology["middles"] == {
        "middle_01": {"region": "nyc3", "ordinal": 1},
        "middle_02": {"region": "nyc3", "ordinal": 2},
    }
    assert result.chain_routes[0].assigned_proxy == "proxy01"
    assert result.chain_routes[0].edge_nodes == ("sfo3-01", "nyc3-01", "sfo3-02")
    assert result.chain_routes[1].edge_nodes == ("sfo3-03", "sfo3-04")
    assert set(result.nodes) == {
        'digitalocean_droplet.middle["middle_01"]',
        'digitalocean_droplet.middle["middle_02"]',
        *(f'digitalocean_droplet.edge["{name}"]'
          for name in ("nyc3-01", "sfo3-01", "sfo3-02", "sfo3-03", "sfo3-04")),
    }
    assert result.firewall.public_tcp_ports == ("80", "443", "2222")
    assert result.firewall.public_udp_ports == ()
    assert result.firewall.trusted_ssh_cidrs == ("8.8.8.8/32", "9.9.9.9/32")
    assert result.proxy_egress_ips == {"proxy01": "8.8.8.8", "proxy02": "9.9.9.9"}
    assert result.nonsecret_varfile["allowed_tcp_ports"] == ["22", "80", "443", "2222"]
    assert result.nonsecret_varfile["docean_image"] == "ubuntu-22-04-x64"
    assert result.engagement_name == "m4t8q2z7"
    assert result.nodes['digitalocean_droplet.middle["middle_01"]'].name == "middle01-m4t8q2z7"
    assert "do_pat" not in result.nonsecret_varfile
    assert _compile(args[0], list(reversed(args[1])), *args[2:]).topology == result.topology


def test_applied_read_reconstructs_same_reviewed_intent_only_with_retained_state():
    args = _inputs()
    fresh = _compile(*args)
    assert _compile(*args, mode="applied_read", provider_state_exists=True) == fresh
    with pytest.raises(ProviderKeyedPersistedIntentError, match="state presence"):
        _compile(*args, mode="applied_read", provider_state_exists=False)


def _materialized_args(status="deployed", regions=None):
    engagement, chains, job, plan, profile = _inputs()
    if regions is not None:
        chains = [replace(chain, edge_count=1, edge_region=region,
                          edge_intents=[{"id": "edge-01", "provider": "digitalocean",
                                         "region": region, "size": "s-1vcpu-1gb"}])
                  for chain, region in zip(chains, regions, strict=True)]
        fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain) for chain in chains}
        job = replace(job, input={**job.input, "pendingSketchChainFingerprints": fingerprints})
        plan = replace(plan, evidence={**plan.evidence,
                                       "pendingSketchChainFingerprints": fingerprints})
    reviewed = _compile(engagement, chains, job, plan, profile)
    projected = []
    next_id = 10000
    for ordinal, route in enumerate(reviewed.chain_routes, 1):
        chain = next(value for value in chains if value.chain_id == route.chain_id)
        rows = []
        keys = [route.middle_node, *route.edge_nodes]
        for index, key in enumerate(keys):
            next_id += 1
            role = "middle" if index == 0 else "edge"
            address = f'digitalocean_droplet.{role}["{key}"]'
            expected = reviewed.nodes[address]
            component = "middle" if index == 0 else f"edge-{index:02d}"
            row = {
                "chainId": chain.chain_id, "role": role, "provider": "digitalocean",
                "hostname": expected.name, "terraformAddress": address,
                "providerInstanceId": str(next_id), "region": expected.region,
                "publicIp": f"8.8.{ordinal}.{index + 1}",
                "assignedProxy": route.assigned_proxy, "proxy": route.assigned_proxy,
                "componentId": component, "status": "pending",
            }
            if index == 0:
                row["middleOrdinal"] = ordinal
            else:
                row.update({"edgeId": component, "edgeIndex": str(index),
                            "edgeCount": str(len(route.edge_nodes))})
            rows.append(row)
        projected.append(replace(chain, status=status, nodes=rows,
                                 terraform_working_directory="/retained/provider-root"))
    return engagement, projected, job, plan, profile


@pytest.mark.parametrize("status", ["deployed", "deploying", "reconciling", "failed",
                                      "stopping", "stopped", "starting", "tearing_down"])
def test_materialized_read_reconstructs_exact_provider_intent_across_real_lifecycle_states(status):
    args = _materialized_args(status)
    expected = _compile(*_inputs())
    assert _compile(*args, mode="materialized_read", provider_state_exists=True) == expected
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(*args, mode="applied_read", provider_state_exists=True)
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(*args)


@pytest.mark.parametrize("status", ["pending", "destroyed", "aborted"])
def test_materialized_read_rejects_nonmaterialized_or_terminal_rows(status):
    args = _materialized_args(status)
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(*args, mode="materialized_read", provider_state_exists=True)


def test_materialized_read_requires_retained_state_and_unchanged_reviewed_intent():
    engagement, chains, job, plan, profile = _materialized_args("failed")
    with pytest.raises(ProviderKeyedPersistedIntentError, match="state presence"):
        _compile(engagement, chains, job, plan, profile, mode="materialized_read")
    changed = replace(chains[0], assigned_proxy="proxy02")
    with pytest.raises(ProviderKeyedPersistedIntentError, match="reviewed core intent"):
        _compile(engagement, [changed, chains[1]], job, plan, profile,
                 mode="materialized_read", provider_state_exists=True)


def test_expanded_read_keeps_core_review_of_original_two_chains():
    engagement, initial, job, plan, profile = _materialized_args(regions=["sfo3", "sfo3"])
    selected = initial[0]
    new_edge = {**selected.nodes[-1], "edgeId": "edge-02", "edgeIndex": "2",
                "componentId": "edge-02", "edgeCount": "2",
                "terraformAddress": 'digitalocean_droplet.edge["nyc3-01"]',
                "providerInstanceId": "90001", "hostname": "edge-m4t8q2z7-nyc3-01",
                "publicIp": "8.8.1.9", "region": "nyc3"}
    expanded = replace(selected, edge_count=2,
        edge_intents=[*selected.edge_intents, {
            "id": "edge-02", "provider": "digitalocean", "region": "nyc3",
            "size": "s-1vcpu-1gb",
        }],
        nodes=[selected.nodes[0], *({**row, "edgeCount": "2"}
                                   for row in selected.nodes[1:]), new_edge],
        updated_at="later")
    result = _compile(engagement, [expanded, initial[1]], job, plan, profile,
                      mode="materialized_read", provider_state_exists=True,
                      reviewed_initial_chains=initial)
    assert len(result.nodes) == 5
    assert result.chain_routes[0].edge_nodes[-1] == "nyc3-01"
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(engagement, [replace(expanded, assigned_proxy="proxy02"), initial[1]],
                 job, plan, profile, mode="materialized_read", provider_state_exists=True,
                 reviewed_initial_chains=initial)


def test_first_chain_append_uses_engagement_wide_next_ordinal():
    engagement, initial, job, plan, profile = _materialized_args(regions=["sfo3", "sfo3"])
    old_addresses = [node["terraformAddress"] for row in initial for node in row.nodes]
    selected = initial[0]
    new_edge = {**selected.nodes[1], "edgeId": "edge-02", "edgeIndex": "2",
                "componentId": "edge-02", "edgeCount": "2",
                "terraformAddress": 'digitalocean_droplet.edge["sfo3-03"]',
                "providerInstanceId": "90001", "hostname": "edge-m4t8q2z7-sfo3-03",
                "publicIp": "8.8.1.9"}
    expanded = replace(selected, edge_count=2,
        edge_intents=[*selected.edge_intents, {
            "id": "edge-02", "provider": "digitalocean", "region": "sfo3",
            "size": "s-1vcpu-1gb",
        }],
        nodes=[selected.nodes[0], {**selected.nodes[1], "edgeCount": "2"}, new_edge],
        updated_at="later")
    intent = _compile(engagement, [expanded, initial[1]], job, plan, profile,
                      mode="materialized_read", provider_state_exists=True,
                      reviewed_initial_chains=initial)
    assert intent.chain_routes[0].edge_nodes == ("sfo3-01", "sfo3-03")
    assert intent.chain_routes[1].edge_nodes == ("sfo3-02",)
    assert set(old_addresses) < set(intent.nodes)
    assert set(intent.nodes) - set(old_addresses) == {
        'digitalocean_droplet.edge["sfo3-03"]'}


def test_append_plan_compiles_fifth_edge_without_materializing_or_rekeying_rows():
    engagement, initial, job, plan, profile = _materialized_args(regions=["sfo3", "sfo3"])
    selected = initial[0]
    proposed = replace(selected, edge_count=2,
        edge_intents=[*selected.edge_intents, {
            "id": "edge-02", "provider": "digitalocean", "region": "sfo3",
            "size": "s-1vcpu-1gb",
        }])
    intent = _compile(engagement, [proposed, initial[1]], job, plan, profile,
                      mode="append_plan", provider_state_exists=True,
                      reviewed_initial_chains=initial)
    assert intent.chain_routes[0].edge_nodes == ("sfo3-01", "sfo3-03")
    assert intent.chain_routes[1].edge_nodes == ("sfo3-02",)
    assert set(intent.nodes) - {node["terraformAddress"] for row in initial for node in row.nodes} == {
        'digitalocean_droplet.edge["sfo3-03"]'}
    assert selected.nodes == proposed.nodes
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(engagement, [replace(proposed, nodes=[]), initial[1]], job, plan, profile,
                 mode="append_plan", provider_state_exists=True,
                 reviewed_initial_chains=initial)


def test_materialized_read_keeps_provider_intent_through_lifecycle_bookkeeping():
    engagement, chains, job, plan, profile = _materialized_args("failed")
    changed = replace(chains[0], burned=True, burned_note="retired after proof failure",
                      deploy_job_id="chain-lifecycle-job", teardown_job_id="teardown-job")
    assert _compile(engagement, [changed, chains[1]], job, plan, profile,
                    mode="materialized_read", provider_state_exists=True) == _compile(*_inputs())


@pytest.mark.parametrize("change", [
    lambda rows: [],
    lambda rows: list(reversed(rows)),
    lambda rows: [{**rows[0], "hostname": "wrong"}, *rows[1:]],
    lambda rows: [{**rows[0], "providerInstanceId": rows[1]["providerInstanceId"]}, *rows[1:]],
    lambda rows: [{**rows[0], "publicIp": "127.0.0.1"}, *rows[1:]],
    lambda rows: [{**rows[0], "publicIp": 134744073}, *rows[1:]],
    lambda rows: [{**rows[0], "middleOrdinal": True}, *rows[1:]],
    lambda rows: [rows[0], {**rows[1], "edgeIndex": "99"}, *rows[2:]],
])
def test_materialized_read_rejects_incoherent_local_projection(change):
    engagement, chains, job, plan, profile = _materialized_args()
    changed = replace(chains[0], nodes=change(chains[0].nodes))
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(engagement, [changed, chains[1]], job, plan, profile,
                 mode="materialized_read", provider_state_exists=True)


def test_materialized_read_rejects_cross_chain_duplicate_provider_identity():
    engagement, chains, job, plan, profile = _materialized_args()
    duplicate = {**chains[1].nodes[0],
                 "providerInstanceId": chains[0].nodes[0]["providerInstanceId"]}
    changed = replace(chains[1], nodes=[duplicate, *chains[1].nodes[1:]])
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(engagement, [chains[0], changed], job, plan, profile,
                 mode="materialized_read", provider_state_exists=True)


def test_projected_rows_survive_repository_round_trip_and_recompile_reviewed_intent():
    engagement, chains, job, plan, profile = _inputs()
    fresh = _compile(engagement, chains, job, plan, profile)
    nodes = tuple(
        ExpectedDigitalOceanNode(address, str(index), expected.name, expected.region,
                                   f"198.51.100.{index}")
        for index, (address, expected) in enumerate(sorted(fresh.nodes.items()), 101)
    )
    attachment = DigitalOceanAttachmentIntent(
        state_sha256="a" * 64, firewall_id="11111111-2222-4333-8444-555555555555",
        firewall_name=fresh.firewall.name, selector_tag=fresh.selector_tag,
        trusted_ssh_cidrs=fresh.firewall.trusted_ssh_cidrs, nodes=nodes,
        credential_record_id="connection-opaque", credential_secret_sha256="b" * 64,
        credential_updated_at="2026-10-07T00:00:00+00:00",
    )
    proof = DigitalOceanAttachmentEvidence(
        state_sha256=attachment.state_sha256, firewall_id=attachment.firewall_id,
        verified_droplet_ids=tuple(sorted(node.droplet_id for node in nodes)), attempts=2,
    )
    projected = project_digitalocean_initial_chains(fresh, attachment, proof, chains)
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        SqlAlchemyEngagementRepository().save(engagement)
        repository = SqlAlchemySketchChainRepository()
        for chain in chains:
            repository.save(chain)
        for index, item in enumerate(projected):
            materialized = replace(item.chain, status="deployed" if index == 0 else "failed",
                                   terraform_working_directory="/retained/provider-root")
            assert repository.save_if_matches(
                materialized, expected_status="pending", expected_deploy_job_id="",
                expected_teardown_job_id="",
            ) is not None
        db.session.remove()  # Reload the JSON rows through a new ORM session.
        loaded = repository.list_for_engagement(engagement.id)
        assert [row.status for row in loaded] == ["deployed", "failed"]
        assert [row.nodes for row in loaded] == [item.chain.nodes for item in projected]
        assert _compile(engagement, loaded, job, plan, profile,
                        mode="materialized_read", provider_state_exists=True) == fresh


def test_reviewed_chain_order_controls_ordinals_even_when_supplied_rows_are_reversed():
    engagement, chains, job, plan, profile = _inputs()
    reviewed_ids = list(reversed(plan.evidence["pendingSketchChainIds"]))
    plan = replace(plan, evidence={**plan.evidence, "pendingSketchChainIds": reviewed_ids})
    job = replace(job, input={**job.input, "pendingSketchChainIds": reviewed_ids})
    result = _compile(engagement, list(reversed(chains)), job, plan, profile)
    assert result.chain_routes[0].chain_id == chains[1].chain_id
    assert result.chain_routes[0].middle_node == "middle_01"
    assert result.chain_routes[0].edge_nodes == ("sfo3-01", "sfo3-02")
    assert result.chain_routes[1].edge_nodes == ("sfo3-03", "nyc3-01", "sfo3-04")


def test_sketch_ssh_uses_selected_proxy_ips_not_oci_operator_sources():
    engagement, chains, job, plan, profile = _inputs()
    core_sources = ["160.34.86.0/23"]
    job = replace(job, input={**job.input, "sshSourceCidrs": core_sources})
    plan = replace(plan, evidence={**plan.evidence, "sshSourceCidrs": core_sources})
    result = _compile(engagement, chains, job, plan, profile)
    assert result.firewall.trusted_ssh_cidrs == ("8.8.8.8/32", "9.9.9.9/32")
    assert result.nonsecret_varfile["trusted_ssh_cidrs"] == ["8.8.8.8/32", "9.9.9.9/32"]


def test_unused_core_proxy_is_not_an_ssh_source():
    engagement, chains, job, plan, profile = _inputs()
    first = chains[0]
    second = replace(chains[1], assigned_proxy="proxy01")
    reviewed = {chain.chain_id: sketch_chain_intent_fingerprint(chain) for chain in (first, second)}
    job = replace(job, input={**job.input, "pendingSketchChainFingerprints": reviewed})
    plan = replace(plan, evidence={**plan.evidence, "pendingSketchChainFingerprints": reviewed})
    result = _compile(engagement, [first, second], job, plan, profile)
    assert result.proxy_egress_ips == {"proxy01": "8.8.8.8"}
    assert result.firewall.trusted_ssh_cidrs == ("8.8.8.8/32",)


@pytest.mark.parametrize("details", [
    lambda rows: rows[:1],
    lambda rows: [*rows, rows[1]],
    lambda rows: [rows[0], {**rows[1], "publicIp": "10.0.0.2"}],
    lambda rows: [rows[0], {**rows[1], "publicIp": rows[0]["publicIp"]}],
])
def test_rejects_missing_ambiguous_or_nonpublic_proxy_source(details):
    engagement, chains, job, plan, profile = _inputs()
    event = job.events[0]
    job = replace(job, events=[replace(event, data={
        **event.data, "connectionDetails": details(event.data["connectionDetails"]),
    })])
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(engagement, chains, job, plan, profile)


def test_later_empty_core_connection_snapshot_fails_closed():
    engagement, chains, job, plan, profile = _inputs()
    job = replace(job, events=[*job.events, JobEvent(
        2, "info", "core detail changed", {"connectionDetails": []},
    )])
    with pytest.raises(ProviderKeyedPersistedIntentError, match="details are missing"):
        _compile(engagement, chains, job, plan, profile)


@pytest.mark.parametrize("mutate", [
    lambda a: (replace(a[0], sketch_state_schema="split-v1"), *a[1:]),
    lambda a: (replace(a[0], active_revision="rev-changed"), *a[1:]),
    lambda a: (replace(a[0], name="changed-name"), *a[1:]),
    lambda a: (replace(a[0], input_parameters={"deploymentTarget": {"name": "production"}}), *a[1:]),
    lambda a: (replace(a[0], input_parameters={"deploymentTarget": {**a[0].input_parameters["deploymentTarget"], "region": "wrong-region"}}), *a[1:]),
    lambda a: (a[0], [replace(a[1][0], middle_provider="linode"), a[1][1]], *a[2:]),
    lambda a: (a[0], [replace(a[1][0], edge_size="s-2vcpu-2gb"), a[1][1]], *a[2:]),
    lambda a: (a[0], [replace(a[1][0], nodes=[{"id": "existing"}]), a[1][1]], *a[2:]),
    lambda a: (a[0], [replace(a[1][0], edge_intents=[{**a[1][0].edge_intents[0], "id": "edge-99"}, *a[1][0].edge_intents[1:]]), a[1][1]], *a[2:]),
    lambda a: (a[0], a[1], replace(a[2], input={**a[2].input, "pendingSketchChainFingerprints": {}}), *a[3:]),
    lambda a: (a[0], a[1], replace(a[2], input={**a[2].input, "sketchStateSchema": "split-v1"}), *a[3:]),
    lambda a: (a[0], a[1], replace(a[2], input={**a[2].input, "postCoreSketchContinuationEligible": True}), *a[3:]),
    lambda a: (a[0], a[1], replace(a[2], input={**a[2].input, "target": {**a[2].input["target"], "compartmentId": "wrong"}}), *a[3:]),
    lambda a: (a[0], a[1], replace(a[2], input={**a[2].input, "proxyCount": 1}), *a[3:]),
    lambda a: (a[0], a[1], a[2], replace(a[3], apply_job_id="other-job"), a[4]),
    lambda a: (a[0], a[1], a[2], replace(a[3], evidence={**a[3].evidence, "digitaloceanImage": "ubuntu-24-04-x64"}), a[4]),
    lambda a: (a[0], a[1], a[2], replace(a[3], evidence={**a[3].evidence, "pendingSketchChainIds": [a[1][0].chain_id] * 2}), a[4]),
    lambda a: (a[0], a[1], a[2], a[3], ManagedHostImageProfile("ubuntu-22.04", "22.04", "linode/ubuntu22.04", "ubuntu-24-04-x64")),
])
def test_rejects_unreviewed_or_nonfresh_input(mutate):
    with pytest.raises(ProviderKeyedPersistedIntentError):
        _compile(*mutate(_inputs()))


def test_rejects_state_and_contradictory_caller_topology():
    args = _inputs()
    with pytest.raises(ProviderKeyedPersistedIntentError, match="no provider state"):
        _compile(*args, provider_state_exists=True)
    with pytest.raises(ProviderKeyedPersistedIntentError, match="contradicts"):
        _compile(*args, proposed_topology={"middles": {}})


def test_uses_same_existing_slug_rule_as_core_without_adding_name_policy():
    args = _inputs()
    named = replace(args[0], name="My Engagement")
    renamed = pilot_names(named.name)
    event = args[2].events[0]
    details = [
        {**row, "displayName": renamed.proxy_name if index == 0 else renamed.proxy02_name,
         "sshAlias": renamed.proxy_name if index == 0 else renamed.proxy02_name}
        for index, row in enumerate(event.data["connectionDetails"])
    ]
    job = replace(
        args[2], input={**args[2].input, "engagementName": named.name},
        events=[replace(event, data={**event.data, "connectionDetails": details})],
    )
    result = _compile(named, args[1], job, *args[3:])
    assert result.engagement_name == "my-engagement"
    assert result.nodes['digitalocean_droplet.middle["middle_01"]'].name == "middle01-my-engagement"
