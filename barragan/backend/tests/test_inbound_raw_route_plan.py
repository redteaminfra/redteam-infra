# Copyright (c) 2026, Oracle and/or its affiliates.
from copy import deepcopy

import pytest

from app.services.inbound_raw_route_plan import (
    InboundRawRoutePlanError,
    apply_plan_to_channel,
    is_backflips_route,
    legacy_raw_route_resolution,
    plan_new_raw_route,
    validate_persisted_raw_route_plan,
)


def test_tcp_and_udp_use_same_deterministic_pool_with_transport_isolation():
    tcp = _channel("tcp", external=24561)
    tcp_plan = plan_new_raw_route(tcp, [])
    tcp_saved = apply_plan_to_channel(tcp, tcp_plan)
    udp = _channel("udp", external=34561)
    udp_plan = plan_new_raw_route(udp, [tcp_saved])

    assert tcp_plan["middleRelay"]["port"] == 8000
    assert tcp_plan["proxyRelay"]["port"] == 8000
    assert udp_plan["middleRelay"]["port"] == 8000
    assert tcp_plan["transport"] == "tcp"
    assert udp_plan["transport"] == "udp"
    assert len(tcp_plan["routeFingerprint"]) == 64
    assert len(tcp_plan["infrastructureFingerprint"]) == 64


def test_same_transport_reuses_number_only_for_different_exact_components_and_hosts():
    first = apply_plan_to_channel(_channel("tcp"), plan_new_raw_route(_channel("tcp"), []))
    sibling = _channel("tcp", external=24562)
    assert plan_new_raw_route(sibling, [first])["middleRelay"]["port"] == 8001

    other = _channel("tcp", external=24562)
    other.update({
        "edge": "edge-two",
        "edgeComponentId": "edge-component-two",
        "middle": "middle-two",
        "middleComponentId": "middle-component-two",
        "proxy": "proxy02-demo",
        "chainId": "proxy02-chain",
    })
    assert plan_new_raw_route(other, [first])["middleRelay"]["port"] == 8000


def test_middle_and_proxy_pools_allocate_independently_when_availability_is_asymmetric():
    occupied_middle = _channel("tcp", external=25000)
    occupied_middle.update({
        "middleRelayPort": "8000", "proxyRelayPort": "8000", "relayPort": "8000",
        "proxy": "proxy02-demo", "chainId": "proxy02-chain",
    })

    plan = plan_new_raw_route(_channel("tcp", external=25001), [occupied_middle])

    assert plan["middleRelay"]["port"] == 8001
    assert plan["proxyRelay"]["port"] == 8000


def test_pool_exhaustion_and_public_socket_collision_fail_deterministically():
    active = []
    for offset, port in enumerate(range(8000, 8081)):
        row = _channel("tcp", external=30000 + offset)
        row.update({"relayPort": str(port), "middleRelayPort": str(port), "proxyRelayPort": str(port)})
        active.append(row)
    with pytest.raises(InboundRawRoutePlanError, match="planning failed") as exc:
        plan_new_raw_route(_channel("tcp", external=40000), active)
    assert "No TCP relay port" in exc.value.errors[0]

    first = apply_plan_to_channel(_channel("udp"), plan_new_raw_route(_channel("udp"), []))
    with pytest.raises(InboundRawRoutePlanError) as collision:
        plan_new_raw_route(_channel("udp"), [first])
    assert "already exists or is applying" in collision.value.errors[0]


def test_persisted_plan_is_authoritative_and_tampering_fails_closed():
    channel = _channel("tcp")
    plan = plan_new_raw_route(channel, [])
    saved = apply_plan_to_channel(channel, plan)
    assert validate_persisted_raw_route_plan(saved, plan) == plan

    scalar_tampered = {**saved, "relayPort": "8077"}
    with pytest.raises(InboundRawRoutePlanError):
        validate_persisted_raw_route_plan(scalar_tampered, plan)

    tampered = deepcopy(plan)
    tampered["middleRelay"]["port"] = 8002
    with pytest.raises(InboundRawRoutePlanError) as exc:
        validate_persisted_raw_route_plan(saved, tampered)
    assert any("fingerprint" in error for error in exc.value.errors)


@pytest.mark.parametrize("forgery", ["port22", "allocation", "infrastructureFingerprint", "routeFingerprint"])
def test_persisted_plan_rejects_forged_ports_metadata_and_fingerprints(forgery):
    channel = _channel("tcp")
    plan = plan_new_raw_route(channel, [], _infrastructure())
    saved = apply_plan_to_channel(channel, plan)
    tampered = deepcopy(plan)
    if forgery == "port22":
        tampered["proxyRelay"]["port"] = 22
        saved["proxyRelayPort"] = "22"
        saved["relayPort"] = "22"
    elif forgery == "allocation":
        tampered["allocation"]["pool"] = "1-65535"
    elif forgery == "infrastructureFingerprint":
        tampered["infrastructureFingerprint"] = "0" * 64
    else:
        tampered["routeFingerprint"] = "0" * 64

    with pytest.raises(InboundRawRoutePlanError):
        validate_persisted_raw_route_plan(saved, tampered, infrastructure=_infrastructure())


def test_infrastructure_recreation_invalidates_saved_plan_even_with_same_logical_names():
    channel = _channel("tcp")
    original = _infrastructure()
    plan = plan_new_raw_route(channel, [], original)
    saved = apply_plan_to_channel(channel, plan)
    recreated = deepcopy(original)
    recreated["sketchInfrastructure"][0]["providerResourceId"] = "edge-resource-recreated"

    with pytest.raises(InboundRawRoutePlanError) as exc:
        validate_persisted_raw_route_plan(saved, plan, infrastructure=recreated)
    assert "recreated or changed" in exc.value.errors[0]


def test_removed_route_plan_cannot_recover_after_sibling_reuses_released_claim():
    channel = _channel("tcp")
    plan = plan_new_raw_route(channel, [], _infrastructure())
    removed = {**apply_plan_to_channel(channel, plan), "status": "Removed"}
    sibling = {**_channel("tcp", external=25000), "channelId": "sibling", "status": "Validated"}
    sibling.update({"middleRelayPort": "8000", "proxyRelayPort": "8000", "relayPort": "8000"})

    with pytest.raises(InboundRawRoutePlanError) as exc:
        plan_new_raw_route(removed, [removed, sibling], _infrastructure())
    assert "conflicts" in exc.value.errors[0]


def test_legacy_routes_preserve_explicit_or_historical_fallback_without_migration():
    explicit = {**_channel("tcp"), "relayPort": "8042"}
    fallback_tcp = _channel("tcp")
    fallback_udp = _channel("udp", external=34561, internal=23461)

    assert legacy_raw_route_resolution(explicit) == {
        "schemaVersion": 0,
        "provenance": "legacy-explicit-pinned",
        "transport": "tcp",
        "middleRelayPort": "8042",
        "proxyRelayPort": "8042",
        "migrationRequired": True,
    }
    distinct = {**_channel("tcp"), "middleRelayPort": "8041", "proxyRelayPort": "8042"}
    assert legacy_raw_route_resolution(distinct)["middleRelayPort"] == "8041"
    assert legacy_raw_route_resolution(distinct)["proxyRelayPort"] == "8042"
    assert legacy_raw_route_resolution(fallback_tcp)["middleRelayPort"] == fallback_tcp["externalPort"]
    assert legacy_raw_route_resolution(fallback_udp)["proxyRelayPort"] == fallback_udp["internalPort"]


def test_http_and_identity_marked_backflips_are_outside_the_allocator():
    web = {**_channel("tcp"), "mode": "http-openresty", "protocol": "HTTP"}
    assert plan_new_raw_route(web, []) == {}

    for field, identity in (
        ("serviceId", "barragan.backflips-v2"),
        ("capabilityId", "backflips-v2"),
        ("service", "SSH Backflips"),
        ("purpose", "backflips"),
    ):
        marked = {**_channel("tcp", external=4444, internal=3333), field: identity}
        with pytest.raises(InboundRawRoutePlanError, match="inbound raw route planning failed"):
            plan_new_raw_route(marked, [])

    marked_udp = {**_channel("udp", external=4444, internal=3333), "service": "SSH Backflips"}
    assert is_backflips_route(marked_udp) is False
    with pytest.raises(InboundRawRoutePlanError):
        plan_new_raw_route(marked_udp, [])


def test_port_2222_is_available_to_temporary_raw_routes_without_backflips_ownership():
    tcp_plan = plan_new_raw_route(_channel("tcp", external=2222, internal=3333), [])
    udp_plan = plan_new_raw_route(_channel("udp", external=2222, internal=3333), [])

    assert tcp_plan["public"]["port"] == 2222
    assert udp_plan["public"]["port"] == 2222


def test_backflips_public_socket_ownership_is_transport_and_edge_specific():
    owner = {
        **_channel("tcp", external=2222, internal=2222),
        "mode": "backflips",
        "serviceId": "barragan.backflips-v2",
        "status": "Validated",
    }
    ordinary_tcp = _channel("tcp", external=2222, internal=3333)
    with pytest.raises(InboundRawRoutePlanError) as collision:
        plan_new_raw_route(ordinary_tcp, [owner])
    assert "already owns edge-one:2222/tcp" in collision.value.errors[0]

    ordinary_udp = _channel("udp", external=2222, internal=3333)
    assert plan_new_raw_route(ordinary_udp, [owner])["public"]["port"] == 2222

    other_edge_owner = {
        **owner,
        "edge": "edge-two",
        "edgeComponentId": "edge-component-two",
    }
    assert plan_new_raw_route(ordinary_tcp, [other_edge_owner])["public"]["port"] == 2222


@pytest.mark.parametrize(
    "forgery",
    [
        "bool-version", "string-port", "missing-scalar", "empty-scalar",
        "padded-scalar", "whitespace-host", "typed-revision",
    ],
)
def test_persisted_plan_schema_rejects_coercible_and_noncanonical_types(forgery):
    channel = _channel("tcp")
    plan = plan_new_raw_route(channel, [], _infrastructure())
    saved = apply_plan_to_channel(channel, plan)
    tampered_plan = deepcopy(plan)
    tampered_channel = dict(saved)
    if forgery == "bool-version":
        tampered_plan["schemaVersion"] = True
    elif forgery == "string-port":
        tampered_plan["middleRelay"]["port"] = "8000"
    elif forgery == "missing-scalar":
        tampered_channel.pop("middleRelayPort")
    elif forgery == "empty-scalar":
        tampered_channel["middleRelayPort"] = "   "
    elif forgery == "padded-scalar":
        tampered_channel["proxyRelayPort"] = " 8000 "
    elif forgery == "whitespace-host":
        tampered_channel["edge"] = "   "
    else:
        tampered_plan["infrastructureRevision"]["edge"]["providerResourceId"] = 123

    with pytest.raises(InboundRawRoutePlanError):
        validate_persisted_raw_route_plan(tampered_channel, tampered_plan, infrastructure=_infrastructure())


def _channel(transport: str, *, external: int = 24561, internal: int = 23461):
    return {
        "channelId": f"route-{transport}-{external}",
        "domain": "N/A",
        "protocol": transport.upper(),
        "mode": f"{transport}-forward",
        "externalPort": str(external),
        "edge": "edge-one",
        "edgeComponentId": "edge-component-one",
        "middle": "middle-one",
        "middleComponentId": "middle-component-one",
        "chainId": "proxy01-chain",
        "proxy": "proxy01-demo",
        "terminatesOn": "homebase-demo",
        "internalPort": str(internal),
        "status": "Pending Apply",
    }


def _infrastructure():
    return {
        "sketchInfrastructure": [
            {
                "hostname": "edge-one", "componentId": "edge-component-one", "provider": "linode",
                "providerResourceId": "edge-resource-one", "deploymentJobId": "job-chain-one",
                "workspaceRevision": "workspace-chain-one", "publicIp": "203.0.113.10",
            },
            {
                "hostname": "middle-one", "componentId": "middle-component-one", "provider": "linode",
                "providerResourceId": "middle-resource-one", "deploymentJobId": "job-chain-one",
                "workspaceRevision": "workspace-chain-one", "publicIp": "203.0.113.11",
            },
        ],
        "coreInfrastructure": [
            {
                "hostname": "proxy01-demo", "hostId": "proxy01", "provider": "oci",
                "providerResourceId": "proxy-resource-one", "deploymentJobId": "job-core-one",
                "workspaceRevision": "workspace-core-one", "publicIp": "203.0.113.12", "privateIp": "192.168.2.11",
            },
            {
                "hostname": "homebase-demo", "hostId": "homebase", "provider": "oci",
                "providerResourceId": "homebase-resource-one", "deploymentJobId": "job-core-one",
                "workspaceRevision": "workspace-core-one", "publicIp": "203.0.113.13", "privateIp": "192.168.1.10",
            },
        ],
    }


@pytest.mark.parametrize("planned", [False, True])
@pytest.mark.parametrize("chain", ["other-chain", "", None])
def test_repeated_sketch_ids_require_two_known_distinct_chains(planned, chain):
    first = _channel("udp", external=53)
    if planned:
        first = apply_plan_to_channel(first, plan_new_raw_route(first, []))
        first["rawRoutePlan"]["infrastructureRevision"]["chainId"] = chain
    else:
        first.update(chainId=chain, middleRelayPort="8000", proxyRelayPort="8000")
    candidate = {**_channel("udp", external=53), "edge": "edge-two", "middle": "middle-two"}
    if chain:
        plan = plan_new_raw_route(candidate, [first])
        assert plan["middleRelay"]["port"] == 8000
        assert plan["proxyRelay"]["port"] == 8001
        from app.services.inbound_raw_route_plan import assert_raw_route_plan_available
        assert_raw_route_plan_available(plan, [first])
    else:
        with pytest.raises(InboundRawRoutePlanError):
            plan_new_raw_route(candidate, [first])


@pytest.mark.parametrize("planned", [False, True])
@pytest.mark.parametrize("drift", ["same-host-new-id", "same-chain-alias"])
def test_physical_host_or_same_chain_component_keeps_public_claim(planned, drift):
    first = _channel("udp", external=53)
    if planned:
        first = apply_plan_to_channel(first, plan_new_raw_route(first, []))
    candidate = {**_channel("udp", external=53), "chainId": "other-chain"}
    if drift == "same-host-new-id":
        candidate.update(edgeComponentId="renamed-edge", middleComponentId="renamed-middle")
    else:
        candidate.update(chainId=first["chainId"], edge="edge-alias", middle="middle-alias")
    with pytest.raises(InboundRawRoutePlanError):
        plan_new_raw_route(candidate, [first])


@pytest.mark.parametrize("planned,proxy_drift", [(False, "alias"), (True, "alias"), (True, "id")])
def test_shared_proxy_claim_survives_alias_or_id_drift(planned, proxy_drift):
    first = _channel("udp", external=53)
    first.update(middleRelayPort="8000", proxyRelayPort="8000")
    if planned:
        first = apply_plan_to_channel(first, plan_new_raw_route(first, []))
        if proxy_drift == "id":
            first["rawRoutePlan"]["proxyRelay"]["hostId"] = "renamed"
    candidate = {**_channel("udp", external=54), "chainId": "other-chain",
                 "edge": "edge-two", "middle": "middle-two"}
    if proxy_drift == "alias":
        candidate["proxy"] = "proxy01-alias"
    plan = plan_new_raw_route(candidate, [first])
    assert plan["middleRelay"]["port"] == 8000
    assert plan["proxyRelay"]["port"] == 8001


def test_saved_availability_keeps_claims_protocol_exclusion_and_inactive_semantics():
    from app.services.inbound_raw_route_plan import assert_raw_route_plan_available
    row = _channel("udp", external=53)
    plan = plan_new_raw_route(row, [])
    saved = apply_plan_to_channel(row, plan)
    with pytest.raises(InboundRawRoutePlanError):
        assert_raw_route_plan_available(plan, [saved])
    assert_raw_route_plan_available(plan, [saved], exclude_channel_id=row["channelId"])
    assert_raw_route_plan_available(plan, [{**saved, "status": "Removed"}])
    tcp = _channel("tcp", external=53)
    assert plan_new_raw_route(tcp, [saved])["proxyRelay"]["port"] == 8000
    legacy = {**row, "chainId": "", "edge": "legacy-edge", "middle": "legacy-middle",
              "edgeComponentId": "different-edge", "middleComponentId": "different-middle"}
    assert plan_new_raw_route(row, [legacy])["middleRelay"]["port"] == 8000


@pytest.mark.parametrize("planned", [False, True])
@pytest.mark.parametrize("drift", ["same-host-new-id", "same-chain-alias", "unknown-chain"])
def test_saved_middle_relay_is_not_freed_by_identity_ambiguity(planned, drift):
    from app.services.inbound_raw_route_plan import assert_raw_route_plan_available
    existing = _channel("udp", external=54)
    existing.update(middleRelayPort="8000", proxyRelayPort="8007")
    if planned:
        existing = apply_plan_to_channel(existing, plan_new_raw_route(existing, []))
    candidate = {**_channel("udp", external=53), "edge": "edge-two",
                 "edgeComponentId": "edge-two", "proxy": "proxy02-demo"}
    if drift == "same-host-new-id":
        candidate.update(chainId="other-chain", middleComponentId="renamed-middle")
    elif drift == "same-chain-alias":
        candidate["middle"] = "middle-alias"
    else:
        candidate["middle"] = "middle-two"
        if planned:
            existing["rawRoutePlan"]["infrastructureRevision"].pop("chainId")
        else:
            existing.pop("chainId")
    independently_reviewed = plan_new_raw_route(candidate, [])
    with pytest.raises(InboundRawRoutePlanError) as exc:
        assert_raw_route_plan_available(independently_reviewed, [existing])
    assert "middle" in exc.value.errors[0]
    assert plan_new_raw_route(candidate, [existing])["middleRelay"]["port"] == 8001
