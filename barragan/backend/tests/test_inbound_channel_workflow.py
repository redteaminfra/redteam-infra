# Copyright (c) 2026, Oracle and/or its affiliates.
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.services.inbound_channel_apply import InboundChannelApplyValidationError
from app.services.inbound_channel_batch import _preflight_batch
from app.services.inbound_channel_workflow import (
    InboundChannelWorkflowValidationError,
    create_and_apply_inbound_channel,
    derive_inbound_channel,
    recover_inbound_channel,
)


def test_derive_inbound_channel_locks_route_to_selected_edge_chain():
    channel = derive_inbound_channel(
        "ZY01",
        _overview(),
        {
            "edge": "edge-zy01-us-sea-01",
            "protocol": "HTTPS",
            "externalPort": "443",
            "terminatesOn": "homebase-zy01",
            "internalPort": "7443",
            "domain": "c2.example.invalid",
            "purpose": "Mythic ingress",
        },
    )

    assert channel["channelId"] == "edge-zy01-us-sea-01-443-to-proxy01-443-c2-example-invalid"
    assert channel["protocol"] == "HTTPS"
    assert channel["mode"] == "https-openresty"
    assert channel["edge"] == "edge-zy01-us-sea-01"
    assert channel["edgeComponentId"] == "edge-sea-01"
    assert channel["middle"] == "middle01-zy01"
    assert channel["middleComponentId"] == "middle-01"
    assert channel["chainId"] == "proxy01-chain-001"
    assert channel["proxy"] == "proxy01-zy01"
    assert channel["terminatesOn"] == "proxy01-zy01"
    assert channel["internalPort"] == "443"
    assert channel["backendPort"] == "7443"
    assert channel["serviceType"] == "web-http-backend"
    assert channel["serviceId"].startswith("http-site-")
    assert channel["service"] == "OpenResty"
    assert channel["validationProfile"] == {
        "type": "manual",
        "label": "Bind TLS certificate, then validate HTTPS from Inspector",
    }
    assert channel["status"] == "Pending Apply"


def test_derive_inbound_channel_allows_same_proxy_termination():
    channel = derive_inbound_channel(
        "ZY01",
        _overview(),
        {
            "edge": "edge-zy01-us-sea-01",
            "mode": "tcp-forward",
            "externalPort": "2223",
            "terminatesOn": "proxy01",
            "internalPort": "8001",
        },
    )

    assert channel["channelId"] == "edge-zy01-us-sea-01-2223-to-proxy01-8001"
    assert channel["proxy"] == "proxy01-zy01"
    assert channel["terminatesOn"] == "proxy01-zy01"
    assert channel["service"] == "Inbound service"


def test_derive_http_openresty_defaults_standard_port_route_and_http_validation():
    channel = derive_inbound_channel(
        "ZY01",
        _overview(),
        {
            "edge": "edge-zy01-us-sea-01",
            "protocol": "HTTP",
            "mode": "http-openresty",
            "externalPort": "80",
            "terminatesOn": "homebase",
            "internalPort": "9999",
            "domain": "upload.example.invalid",
            "service": "File service",
        },
    )

    assert channel["mode"] == "http-openresty"
    assert channel["protocol"] == "HTTP"
    assert channel["terminatesOn"] == "homebase-zy01"
    assert channel["validationProfile"]["type"] == "http"
    assert "Host: upload.example.invalid" in channel["validationProfile"]["requestText"]
    assert channel["validationProfile"]["expectedResponse"] == "HTTP status below 500"


def test_derive_gosus_https_creates_a_typed_proxy_site_identity():
    channel = derive_inbound_channel(
        "ZY01",
        _overview(),
        {
            "edge": "edge-zy01-us-sea-01",
            "protocol": "HTTPS",
            "mode": "https-openresty",
            "externalPort": "443",
            "terminatesOn": "homebase",
            "internalPort": "9999",
            "domain": "files.example.invalid",
            "service": "Go Simple Upload Server",
            "purpose": "HTTPS uploads",
        },
    )

    assert channel["terminatesOn"] == "proxy01-zy01"
    assert channel["internalPort"] == "443"
    assert channel["backendPort"] == "9999"
    assert channel["serviceType"] == "web-http-backend"
    assert channel["serviceId"].startswith("http-site-")
    assert channel["channelId"].endswith("files-example-invalid")
    assert channel["validationProfile"]["type"] == "manual"


def test_derive_inbound_channels_allow_two_https_edges_on_same_middle_and_proxy():
    overview = _overview()
    overview["sketchInfrastructure"].append(
        {
                "chainId": "proxy01-chain-001",
                "hostname": "edge-zy01-us-sea-02",
                "componentId": "edge-sea-02",
                "provider": "linode",
                    "role": "edge",
                    "proxy": "proxy01",
                    "assignedProxyId": "proxy01",
                    "status": "deployed",
        }
    )
    first = derive_inbound_channel(
        "ZY01",
        overview,
        {
            "edge": "edge-zy01-us-sea-01",
            "protocol": "HTTPS",
            "externalPort": "443",
            "terminatesOn": "proxy01",
            "internalPort": "443",
            "domain": "www.example.invalid",
        },
    )
    second = derive_inbound_channel(
        "ZY01",
        overview,
        {
            "edge": "edge-zy01-us-sea-02",
            "protocol": "HTTPS",
            "externalPort": "443",
            "terminatesOn": "proxy01",
            "internalPort": "443",
            "domain": "noop.example.invalid",
        },
    )

    assert first["channelId"] == "edge-zy01-us-sea-01-443-to-proxy01-443"
    assert second["channelId"] == "edge-zy01-us-sea-02-443-to-proxy01-443"
    assert first["middle"] == "middle01-zy01"
    assert second["middle"] == "middle01-zy01"
    assert first["edgeComponentId"] == "edge-sea-01"
    assert second["edgeComponentId"] == "edge-sea-02"
    assert first["middleComponentId"] == second["middleComponentId"] == "middle-01"
    assert first["mode"] == "https-openresty"
    assert second["mode"] == "https-openresty"


@pytest.mark.parametrize("mutation", ["missing-edge-component", "duplicate-edge", "duplicate-middle"])
def test_derive_inbound_channel_fails_closed_when_route_identity_is_incomplete_or_ambiguous(mutation):
    overview = deepcopy(_overview())
    if mutation == "missing-edge-component":
        overview["sketchInfrastructure"][1].pop("componentId")
    elif mutation == "duplicate-edge":
        overview["sketchInfrastructure"].append(dict(overview["sketchInfrastructure"][1]))
    else:
        overview["sketchInfrastructure"].append(dict(overview["sketchInfrastructure"][0]))

    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel(
            "ZY01",
            overview,
            {
                "edge": "edge-zy01-us-sea-01",
                "mode": "tcp-forward",
                "externalPort": "2222",
                "terminatesOn": "proxy01",
                "internalPort": "8001",
            },
        )


@pytest.mark.parametrize("reverse_rows", [False, True])
def test_derive_inbound_channel_selects_exact_second_duplicate_hostname_component(reverse_rows):
    overview = _overview()
    duplicate_name = "edge-shared-name"
    overview["sketchInfrastructure"][1]["hostname"] = duplicate_name
    overview["sketchInfrastructure"][3]["hostname"] = duplicate_name
    if reverse_rows:
        overview["sketchInfrastructure"] = list(reversed(overview["sketchInfrastructure"]))

    channel = derive_inbound_channel(
        "ZY01",
        overview,
        {
            "edge": duplicate_name,
            "chainId": "proxy02-chain-001",
            "edgeComponentId": "edge-ash-02",
            "protocol": "TCP",
            "externalPort": "8443",
            "terminatesOn": "proxy02",
            "internalPort": "9443",
        },
    )

    assert channel["edge"] == duplicate_name
    assert channel["chainId"] == "proxy02-chain-001"
    assert channel["edgeComponentId"] == "edge-ash-02"
    assert channel["middle"] == "middle02-zy01"
    assert channel["middleComponentId"] == "middle-02"
    assert channel["proxy"] == "proxy02-zy01"


@pytest.mark.parametrize("mutation", ["partial-chain", "partial-component", "stale", "mismatch", "duplicate"])
def test_exact_edge_selection_rejects_partial_stale_mismatched_or_duplicate_identity(mutation):
    overview = _overview()
    body = {
        "edge": "edge-zy01-us-sea-01",
        "chainId": "proxy01-chain-001",
        "edgeComponentId": "edge-sea-01",
        "mode": "tcp-forward",
        "externalPort": "8443",
        "terminatesOn": "proxy01",
        "internalPort": "9443",
    }
    if mutation == "partial-chain":
        body.pop("edgeComponentId")
    elif mutation == "partial-component":
        body.pop("chainId")
    elif mutation == "stale":
        overview["sketchInfrastructure"] = [
            row for row in overview["sketchInfrastructure"] if row.get("componentId") != "edge-sea-01"
        ]
    elif mutation == "mismatch":
        body["chainId"] = "proxy02-chain-001"
    else:
        overview["sketchInfrastructure"].append(dict(overview["sketchInfrastructure"][1]))

    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel("ZY01", overview, body)


@pytest.mark.parametrize(
    "role,status",
    [
        (role, status)
        for role in ("edge", "middle")
        for status in (
            None, "unknown", "pending", "deploying", "reconciling", "stopping",
            "stopped", "starting", "tearing_down", "destroyed", "failed", "aborted",
        )
    ],
)
def test_exact_edge_selection_requires_durable_deployed_state(role, status):
    overview = _overview()
    row = next(item for item in overview["sketchInfrastructure"] if item["chainId"] == "proxy01-chain-001" and item["role"] == role)
    if status is None:
        row.pop("status")
    else:
        row["status"] = status

    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel("ZY01", overview, {
            "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
            "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
            "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
        })


@pytest.mark.parametrize("mutation", ["missing-edge", "missing-middle", "conflict", "duplicate-proxy"])
def test_exact_edge_selection_requires_consistent_unique_proxy_attachment(mutation):
    overview = _overview()
    edge = overview["sketchInfrastructure"][1]
    middle = overview["sketchInfrastructure"][0]
    if mutation == "missing-edge":
        edge.pop("proxy")
    elif mutation == "missing-middle":
        middle.pop("proxy")
    elif mutation == "conflict":
        middle["proxy"] = "proxy02"
    else:
        overview["coreInfrastructure"].append(dict(overview["coreInfrastructure"][1]))

    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel("ZY01", overview, {
            "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
            "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
            "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
        })


def test_proxy_identity_uses_semantic_route_id_and_exact_of02_style_core_evidence():
    overview = _overview()
    core = overview["coreInfrastructure"][1]
    core.update({
        "hostId": "proxy01", "logicalName": "proxy01",
        "hostname": "proxy01-of02-prod", "expectedHostname": "proxy01-of02-prod",
    })

    channel = derive_inbound_channel("of02-prod", overview, {
        "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
        "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
        "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
    })

    assert channel["proxy"] == "proxy01-of02-prod"


@pytest.mark.parametrize("middle_proxy", [
    "proxy02", "proxy01-of02-prod", "proxy01-of02-prod.infra.redteam",
    "proxy01.infra.redteam", "proxy01-other", "proxy010",
])
def test_route_proxy_identity_rejects_nonsemantic_aliases_and_distinct_ids(middle_proxy):
    overview = _overview()
    overview["sketchInfrastructure"][0]["proxy"] = middle_proxy
    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel("ZY01", overview, {
            "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
            "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
            "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
        })


def test_proxy_identity_rejects_duplicate_semantic_core_rows():
    overview = _overview()
    overview["coreInfrastructure"].append(dict(overview["coreInfrastructure"][1]))
    with pytest.raises(InboundChannelWorkflowValidationError, match="validation failed") as exc:
        derive_inbound_channel("ZY01", overview, {
            "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
            "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
            "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
        })
    assert "not found uniquely" in exc.value.errors[0]


@pytest.mark.parametrize("mutation", [
    "missing-host-id", "missing-logical-name", "mismatched-hostname", "fqdn-hostname", "duplicate", "duplicate-reversed",
])
def test_homebase_requires_one_exact_projected_semantic_identity(mutation):
    overview = _overview()
    homebase = overview["coreInfrastructure"][0]
    if mutation == "missing-host-id":
        homebase.pop("hostId")
    elif mutation == "missing-logical-name":
        homebase.pop("logicalName")
    elif mutation == "mismatched-hostname":
        homebase["expectedHostname"] = "homebase-other"
    elif mutation == "fqdn-hostname":
        homebase["hostname"] = homebase["expectedHostname"] = "homebase-zy01.infra.redteam"
    else:
        overview["coreInfrastructure"].append(dict(homebase))
        if mutation == "duplicate-reversed":
            overview["coreInfrastructure"].reverse()

    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel("RENAMED", overview, {
            "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
            "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
            "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
        })


def test_homebase_termination_rejects_hostname_prefix_alias():
    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel("ZY01", _overview(), {
            "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
            "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
            "externalPort": "8443", "terminatesOn": "homebase-attacker", "internalPort": "9443",
        })


@pytest.mark.parametrize("mutation", ["missing-logical", "wrong-hostname", "fqdn-hostname", "wrong-host-id"])
def test_proxy_identity_rejects_malformed_present_core_evidence(mutation):
    overview = _overview()
    core = overview["coreInfrastructure"][1]
    if mutation == "missing-logical":
        core.pop("logicalName")
    elif mutation == "wrong-hostname":
        core["hostname"] = "proxy01-other"
    elif mutation == "fqdn-hostname":
        core["hostname"] = core["expectedHostname"] = "proxy01-zy01.infra.redteam"
    else:
        core["hostId"] = core["logicalName"] = "proxy02"
    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel("ZY01", overview, {
            "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
            "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
            "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
        })


def test_core_identity_without_immutable_deployment_projection_fails_closed_even_after_rename():
    overview = _overview()
    core = overview["coreInfrastructure"][1]
    for key in ("hostId", "logicalName", "expectedHostname"):
        core.pop(key)
    with pytest.raises(InboundChannelWorkflowValidationError):
        derive_inbound_channel("renamed-engagement", overview, {
            "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
            "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
            "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
        })


def test_legacy_hostname_selection_is_absence_only_and_requires_unique_component():
    overview = _overview()
    overview["sketchInfrastructure"][3]["hostname"] = overview["sketchInfrastructure"][1]["hostname"]
    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        derive_inbound_channel(
            "ZY01",
            overview,
            {
                "edge": "edge-zy01-us-sea-01", "mode": "tcp-forward",
                "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
            },
        )
    assert "uniquely" in exc.value.errors[0]


def test_batch_preflight_rejects_one_stale_component_without_reserving_valid_rows():
    overview = _overview()
    overview["inboundChannels"] = []
    base = {
        "edge": "edge-zy01-us-sea-01", "chainId": "proxy01-chain-001",
        "edgeComponentId": "edge-sea-01", "mode": "tcp-forward",
        "externalPort": "8443", "terminatesOn": "proxy01", "internalPort": "9443",
    }
    stale = {
        **base, "chainId": "proxy02-chain-001", "edgeComponentId": "missing-component",
        "edge": "edge-zy01-us-ash-02", "externalPort": "8444", "terminatesOn": "proxy02",
    }

    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        _preflight_batch("ZY01", overview, [base, stale])

    assert any(error.startswith("row 2:") for error in exc.value.errors)
    assert overview["inboundChannels"] == []


def test_derive_inbound_channel_preserves_service_bound_tcp_validation_profile():
    channel = derive_inbound_channel(
        "ZY01",
        _overview(),
        {
            "edge": "edge-zy01-us-sea-01",
            "protocol": "TCP",
            "mode": "tcp-forward",
            "externalPort": "8080",
            "terminatesOn": "proxy01",
            "internalPort": "18080",
            "domain": "ff10.example.invalid",
            "service": "Static Web",
            "purpose": "campaign web traffic",
            "validationProfile": {
                "type": "tcp-send-receive",
                "label": "Static web HTTP check",
                "requestText": "GET / HTTP/1.1\r\nHost: ff10.example.invalid\r\n\r\n",
                "expectedResponse": "hola ff10",
            },
        },
    )

    assert channel["service"] == "Static Web"
    assert channel["terminatesOn"] == "proxy01-zy01"
    assert channel["internalPort"] == "18080"
    assert channel["validationProfile"] == {
        "type": "tcp-send-receive",
        "label": "Static web HTTP check",
        "requestText": "GET / HTTP/1.1\r\nHost: ff10.example.invalid\r\n\r\n",
        "expectedResponse": "hola ff10",
    }


def test_derive_static_web_https_stops_at_shared_proxy_front():
    overview = {
        **_overview(),
        "servicePlacements": [
            {
                "serviceId": "web-ff10",
                "serviceType": "web-static",
                "service": "Static Web",
                "status": "Configured",
                "hostId": "proxy01",
                "port": "18081",
                "protocol": "TCP",
            }
        ],
    }

    channel = derive_inbound_channel(
        "ZY01",
        overview,
        {
            "edge": "edge-zy01-us-sea-01",
            "mode": "https-openresty",
            "externalPort": "443",
            "serviceId": "web-ff10",
            "domain": "ff10.example.invalid",
        },
    )

    assert channel["channelId"] == "edge-zy01-us-sea-01-443-to-proxy01-443"
    assert channel["terminatesOn"] == "proxy01-zy01"
    assert channel["internalPort"] == "443"
    assert channel["serviceId"] == "web-ff10"
    assert channel["validationProfile"] == {
        "type": "tcp-connect",
        "label": "TLS-unbound route check",
    }


def test_derive_static_web_http_stops_at_shared_proxy_front():
    overview = {
        **_overview(),
        "servicePlacements": [
            {
                "serviceId": "web-ff10",
                "serviceType": "web-static",
                "service": "Static Web",
                "status": "Configured",
                "hostId": "proxy01",
                "port": "8081",
                "protocol": "HTTP",
            }
        ],
    }

    channel = derive_inbound_channel(
        "ZY01",
        overview,
        {
            "edge": "edge-zy01-us-sea-01",
            "mode": "http-openresty",
            "externalPort": "80",
            "serviceId": "web-ff10",
            "domain": "ff10.example.invalid",
        },
    )

    assert channel["channelId"] == "edge-zy01-us-sea-01-80-to-proxy01-80-ff10-example-invalid"
    assert channel["terminatesOn"] == "proxy01-zy01"
    assert channel["internalPort"] == "80"
    assert channel["serviceId"] == "web-ff10"
    assert channel["validationProfile"] == {
        "type": "http",
        "label": "HTTP route check",
        "requestText": "GET / HTTP/1.1\r\nHost: ff10.example.invalid\r\nConnection: close\r\n\r\n",
        "expectedResponse": "HTTP status below 500",
    }


def test_derive_inbound_channel_inherits_generic_service_binding_defaults():
    overview = {
        **_overview(),
        "servicePlacements": [
            {
                "serviceId": "generic-c2",
                "serviceType": "generic",
                "service": "custom c2",
                "status": "Active",
                "hostId": "proxy01",
                "port": "18090",
                "protocol": "tcp",
                "purpose": "operator-managed c2 listener",
                "validationProfile": {"type": "tcp-connect", "label": "TCP reachability"},
            }
        ],
    }

    channel = derive_inbound_channel(
        "ZY01",
        overview,
        {
            "edge": "edge-zy01-us-sea-01",
            "externalPort": "8443",
            "serviceId": "generic-c2",
        },
    )

    assert channel["serviceId"] == "generic-c2"
    assert channel["serviceType"] == "generic"
    assert channel["service"] == "custom c2"
    assert channel["protocol"] == "TCP"
    assert channel["terminatesOn"] == "proxy01-zy01"
    assert channel["internalPort"] == "18090"
    assert channel["purpose"] == "operator-managed c2 listener"
    assert channel["validationProfile"] == {"type": "tcp-connect", "label": "TCP reachability"}


def test_derive_inbound_channel_rejects_disabled_service_binding():
    overview = {
        **_overview(),
        "servicePlacements": [
            {
                "serviceId": "generic-old",
                "serviceType": "generic",
                "service": "old listener",
                "status": "Disabled",
                "hostId": "proxy01",
                "port": "18090",
                "protocol": "tcp",
            }
        ],
    }

    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        derive_inbound_channel(
            "ZY01",
            overview,
            {
                "edge": "edge-zy01-us-sea-01",
                "externalPort": "8443",
                "serviceId": "generic-old",
            },
        )

    assert exc.value.errors == ["service generic-old is Disabled and cannot receive a new inbound channel"]


def test_derive_inbound_channel_blocks_generic_backflips_proxy_socket_collision():
    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        derive_inbound_channel(
            "ZY01",
            _overview(),
            {
                "edge": "edge-zy01-us-sea-01",
                "mode": "tcp-forward",
                "externalPort": "2222",
                "terminatesOn": "proxy01",
                "internalPort": "2222",
                "purpose": "ssh backflips",
            },
        )

    assert "SSH Backflips owns proxy01-zy01:2222" in exc.value.errors[0]
    assert "generic inbound channel cannot also bind" in exc.value.errors[0]
    assert "SSH Backflips capability configuration" in exc.value.errors[0]


def test_derive_inbound_channel_allows_temporary_tcp_2222_without_backflips_identity():
    channel = derive_inbound_channel(
        "ZY01",
        _overview(),
        {
            "edge": "edge-zy01-us-sea-01",
            "mode": "tcp-forward",
            "externalPort": "2222",
            "terminatesOn": "proxy01",
            "internalPort": "2222",
            "purpose": "temporary TCP validation",
        },
    )

    assert channel["externalPort"] == "2222"
    assert channel["rawRoutePlan"]["public"]["port"] == 2222
    assert channel["proxyRelayPort"] == "8000"


def test_derive_inbound_channel_blocks_cross_proxy_termination():
    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        derive_inbound_channel(
            "ZY01",
            _overview(),
            {
                "edge": "edge-zy01-us-sea-01",
                "externalPort": "443",
                "terminatesOn": "proxy02-zy01",
                "internalPort": "8001",
            },
        )

    assert "can terminate only on proxy01-zy01 or homebase-zy01" in exc.value.errors[0]


def test_derive_inbound_channel_defaults_udp_validation_profile():
    channel = derive_inbound_channel(
        "ZY01",
        _overview(),
        {
            "edge": "edge-zy01-us-ash-02",
            "protocol": "UDP",
            "externalPort": "53",
            "terminatesOn": "homebase",
            "internalPort": "18080",
        },
    )

    assert channel["mode"] == "udp-forward"
    assert channel["proxy"] == "proxy02-zy01"
    assert channel["middle"] == "middle02-zy01"
    assert channel["relayPort"] == "8000"
    assert channel["middleRelayPort"] == "8000"
    assert channel["proxyRelayPort"] == "8000"
    assert channel["validationProfile"] == {
        "type": "udp-send-receive",
        "label": "UDP route check",
        "requestText": "PING",
        "expectedResponse": "FF0000",
    }


def test_derive_raw_tcp_persists_canonical_hidden_route_plan():
    channel = derive_inbound_channel(
        "ZY01",
        _overview(),
        {
            "edge": "edge-zy01-us-sea-01",
            "protocol": "TCP",
            "externalPort": "24561",
            "relayPort": "24561",
            "terminatesOn": "homebase",
            "internalPort": "23461",
        },
    )

    assert channel["relayPort"] == "8000"
    assert channel["middleRelayPort"] == "8000"
    assert channel["proxyRelayPort"] == "8000"
    assert channel["rawRoutePlan"]["transport"] == "tcp"
    assert channel["rawRoutePlan"]["public"] == {
        "host": "edge-zy01-us-sea-01",
        "componentId": "edge-sea-01",
        "port": 24561,
    }
    assert channel["rawRoutePlan"]["allocation"]["provenance"] == "allocated-lowest-available"


def test_derive_inbound_channel_allocates_non_conflicting_udp_relay_on_shared_middle_or_proxy():
    overview = _overview()
    overview["inboundChannels"] = [
        {
            "channelId": "existing",
            "protocol": "UDP",
            "mode": "udp-forward",
            "relayPort": "8000",
            "middle": "middle01-zy01",
            "proxy": "proxy01-zy01",
            "status": "Validated",
        }
    ]
    channel = derive_inbound_channel(
        "ZY01",
        overview,
        {
            "edge": "edge-zy01-us-sea-01",
            "protocol": "UDP",
            "externalPort": "53",
            "relayPort": "53",
            "terminatesOn": "homebase",
            "internalPort": "53053",
        },
    )

    assert channel["relayPort"] == "8001"
    assert channel["middleRelayPort"] == "8001"
    assert channel["proxyRelayPort"] == "8001"


def test_derive_inbound_channel_rejects_exhausted_udp_relay_pool():
    overview = _overview()
    overview["inboundChannels"] = [
        {
            "channelId": f"existing-{port}",
            "protocol": "UDP",
            "relayPort": str(port),
            "middle": "middle02-zy01",
            "proxy": "proxy02-zy01",
            "status": "Validated",
        }
        for port in range(8000, 8081)
    ]

    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        derive_inbound_channel(
            "ZY01",
            overview,
            {
                "edge": "edge-zy01-us-ash-02",
                "protocol": "UDP",
                "externalPort": "53",
                "terminatesOn": "homebase",
                "internalPort": "53053",
            },
        )
    assert "No UDP relay port is available in 8000-8080" in exc.value.errors[0]


def test_derive_inbound_channel_rejects_static_web_service_on_udp():
    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        derive_inbound_channel(
            "ZY01",
            _overview(),
            {
                "edge": "edge-zy01-us-ash-02",
                "protocol": "UDP",
                "mode": "udp-forward",
                "externalPort": "8054",
                "terminatesOn": "proxy02",
                "internalPort": "18054",
                "service": "Static Web",
                "validationProfile": {
                    "type": "udp-send-receive",
                    "label": "UDP send/expect",
                    "requestText": "GET / HTTP/1.1\r\nHost: stale.example.invalid\r\n\r\n",
                    "expectedResponse": "<html",
                },
            },
        )

    assert exc.value.errors == ["Static Web service bindings require TCP or HTTPS inbound channels"]


def test_concurrent_udp_creates_claim_distinct_relays_and_reject_duplicate(monkeypatch):
    recorded_channels = []

    def fake_operations(_engagement_id):
        return {**_overview(), "inboundChannels": list(recorded_channels)}

    def fake_apply(_engagement_id, channel_id, **kwargs):
        recorded_channels.append(kwargs["channel"])
        return {"job": {"id": f"job-{channel_id}", "status": "running", "events": []}, "status": "Pending Apply"}

    monkeypatch.setattr("app.services.inbound_channel_workflow.get_engagement", lambda _engagement_id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_operations_overview", fake_operations)
    monkeypatch.setattr("app.services.inbound_channel_workflow.start_inbound_channel_apply", fake_apply)
    monkeypatch.setattr("app.services.inbound_channel_workflow.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    def create(external_port):
        return create_and_apply_inbound_channel("eng-zy01", {
            "edge": "edge-zy01-us-sea-01", "protocol": "UDP", "externalPort": external_port,
            "terminatesOn": "homebase", "internalPort": f"53{external_port}",
        })

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, ("53", "54")))
    assert {result["channel"]["relayPort"] for result in results} == {"8000", "8001"}
    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        create("53")
    assert "already exists or is applying" in exc.value.errors[0]


def test_udp_create_accepts_domainless_manual_listener(monkeypatch):
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_engagement", lambda _engagement_id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_operations_overview", lambda _engagement_id: _overview())
    monkeypatch.setattr("app.services.inbound_channel_workflow.start_inbound_channel_apply", lambda *_args, **kwargs: {"job": {"id": "job-udp", "status": "running", "events": []}, "status": "Pending Apply"})

    created = create_and_apply_inbound_channel("eng-zy01", {
        "edge": "edge-zy01-us-sea-01", "protocol": "UDP", "externalPort": "53",
        "terminatesOn": "homebase", "internalPort": "53053",
    })

    assert created["channel"]["domain"] == "N/A"
    assert created["channel"]["relayPort"] == "8000"


def test_http_openresty_create_allows_distinct_hosts_on_shared_chain(monkeypatch):
    recorded_channels = []

    def operations(_engagement_id):
        return {**_overview(), "inboundChannels": list(recorded_channels)}

    def apply(_engagement_id, channel_id, **kwargs):
        recorded_channels.append(kwargs["channel"])
        return {"job": {"id": f"job-{channel_id}", "status": "running", "events": []}, "status": "Pending Apply"}

    monkeypatch.setattr("app.services.inbound_channel_workflow.get_engagement", lambda _engagement_id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_operations_overview", operations)
    monkeypatch.setattr("app.services.inbound_channel_workflow.start_inbound_channel_apply", apply)
    monkeypatch.setattr("app.services.inbound_channel_workflow.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    def create(domain):
        return create_and_apply_inbound_channel("eng-zy01", {
            "edge": "edge-zy01-us-sea-01", "protocol": "HTTP", "mode": "http-openresty", "externalPort": "80",
            "terminatesOn": "homebase", "internalPort": "9999", "domain": domain, "service": "File service",
        })

    first = create("one.example.invalid")["channel"]
    second = create("two.example.invalid")["channel"]

    assert first["channelId"] != second["channelId"]
    assert first["externalPort"] == second["externalPort"] == "80"


def test_create_and_recover_inbound_channel_request_automatic_validation(monkeypatch):
    calls = []
    recorded_channels = []

    def fake_operations(_engagement_id):
        return {**_overview(), "inboundChannels": recorded_channels}

    def fake_update(_engagement_id, body):
        recorded_channels[:] = body.get("inboundChannels", [])
        return {**_overview(), "inboundChannels": recorded_channels}

    def fake_apply(engagement_id, channel_id, **kwargs):
        calls.append({"engagementId": engagement_id, "channelId": channel_id, **kwargs})
        if isinstance(kwargs.get("channel"), dict):
            recorded_channels[:] = [kwargs["channel"]]
        return {
            "job": {
                "id": f"job-{len(calls)}",
                "action": "inbound_channel_apply",
                "status": "running",
                "events": [],
            },
            "status": "Pending Apply",
        }

    monkeypatch.setattr("app.services.inbound_channel_workflow.get_engagement", lambda _engagement_id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_operations_overview", fake_operations)
    monkeypatch.setattr("app.services.inbound_channel_workflow.update_operations_overview", fake_update)
    monkeypatch.setattr("app.services.inbound_channel_workflow.start_inbound_channel_apply", fake_apply)
    monkeypatch.setattr("app.services.inbound_channel_workflow.preflight_inbound_channel_apply", lambda _name, _overview, channel: channel)

    created = create_and_apply_inbound_channel(
        "eng-zy01",
        {
            "edge": "edge-zy01-us-sea-01",
            "protocol": "HTTP",
            "mode": "http-openresty",
            "externalPort": "80",
            "terminatesOn": "homebase",
            "internalPort": "9999",
            "domain": "upload.example.invalid",
            "service": "File service",
        },
    )
    created_channel_id = created["channel"]["channelId"]
    recorded_channels[0] = {**recorded_channels[0], "status": "Removed"}

    recovered = recover_inbound_channel("eng-zy01", created_channel_id)

    assert recovered["channel"]["channelId"] == created_channel_id
    assert recovered["channel"]["mode"] == "http-openresty"
    assert recovered["channel"]["validationProfile"]["expectedResponse"] == "HTTP status below 500"
    assert [call["channelId"] for call in calls] == [created_channel_id, created_channel_id]
    assert all(call["auto_validate"] is True for call in calls)


def test_removed_raw_route_recovery_fails_before_apply_after_sibling_reuses_relay(monkeypatch):
    overview = _overview()
    removed = derive_inbound_channel(
        "ZY01",
        overview,
        {
            "edge": "edge-zy01-us-sea-01", "protocol": "TCP", "externalPort": "24561",
            "terminatesOn": "homebase", "internalPort": "23461",
        },
    )
    removed["status"] = "Removed"
    sibling = {
        **removed,
        "channelId": "sibling-route",
        "externalPort": "24562",
        "status": "Validated",
        "rawRoutePlan": None,
    }
    overview["inboundChannels"] = [removed, sibling]
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_operations_overview", lambda _id: overview)
    monkeypatch.setattr(
        "app.services.inbound_channel_workflow.start_inbound_channel_apply",
        lambda *_args, **_kwargs: pytest.fail("conflicting recovery must not start apply"),
    )

    with pytest.raises(InboundChannelWorkflowValidationError) as exc:
        recover_inbound_channel("eng-zy01", removed["channelId"])

    assert "conflicts" in exc.value.errors[0]


def test_create_and_apply_preflight_failure_records_no_active_channel_or_apply_job(monkeypatch):
    updates = []
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_engagement", lambda _id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr("app.services.inbound_channel_workflow.get_operations_overview", lambda _id: _overview())
    monkeypatch.setattr("app.services.inbound_channel_workflow.update_operations_overview", lambda _id, body: updates.append(body))
    monkeypatch.setattr(
        "app.services.inbound_channel_workflow.preflight_inbound_channel_apply",
        lambda *_args: (_ for _ in ()).throw(InboundChannelApplyValidationError(["blocked before mutation"])),
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_workflow.start_inbound_channel_apply",
        lambda *_args, **_kwargs: pytest.fail("apply job must not start"),
    )

    with pytest.raises(InboundChannelApplyValidationError) as exc:
        create_and_apply_inbound_channel(
            "eng-zy01",
            {
                "edge": "edge-zy01-us-ash-02",
                "protocol": "UDP",
                "externalPort": "53",
                "terminatesOn": "homebase",
                "internalPort": "53053",
            },
        )

    assert updates == []
    assert exc.value.errors == ["blocked before mutation"]


def _overview():
    return {
        "coreInfrastructure": [
            {"hostname": "homebase-zy01", "expectedHostname": "homebase-zy01", "hostId": "homebase", "logicalName": "homebase", "role": "homebase", "publicIp": "203.0.113.10", "privateIp": "192.168.0.10"},
            {"hostname": "proxy01-zy01", "expectedHostname": "proxy01-zy01", "hostId": "proxy01", "logicalName": "proxy01", "role": "proxy", "publicIp": "203.0.113.11", "privateIp": "192.168.2.11"},
            {"hostname": "proxy02-zy01", "expectedHostname": "proxy02-zy01", "hostId": "proxy02", "logicalName": "proxy02", "role": "proxy", "publicIp": "203.0.113.12", "privateIp": "192.168.2.12"},
        ],
        "sketchInfrastructure": [
            {
                "chainId": "proxy01-chain-001",
                "hostname": "middle01-zy01",
                "componentId": "middle-01",
                "provider": "linode",
                "role": "middle",
                "proxy": "proxy01",
                "assignedProxyId": "proxy01",
                "publicIp": "198.51.100.10",
                "status": "deployed",
            },
            {
                "chainId": "proxy01-chain-001",
                "hostname": "edge-zy01-us-sea-01",
                "componentId": "edge-sea-01",
                "provider": "linode",
                "role": "edge",
                "proxy": "proxy01",
                "assignedProxyId": "proxy01",
                "publicIp": "198.51.100.11",
                "status": "deployed",
            },
            {
                "chainId": "proxy02-chain-001",
                "hostname": "middle02-zy01",
                "componentId": "middle-02",
                "provider": "digitalocean",
                "role": "middle",
                "proxy": "proxy02",
                "assignedProxyId": "proxy02",
                "publicIp": "198.51.100.20",
                "status": "deployed",
            },
            {
                "chainId": "proxy02-chain-001",
                "hostname": "edge-zy01-us-ash-02",
                "componentId": "edge-ash-02",
                "provider": "digitalocean",
                "role": "edge",
                "proxy": "proxy02",
                "assignedProxyId": "proxy02",
                "publicIp": "198.51.100.21",
                "status": "deployed",
            },
        ],
    }
