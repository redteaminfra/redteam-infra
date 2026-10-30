# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import re
from typing import Any

from app.integrations.oci_deployment_targets import (
    OciDeploymentTargetError,
    normalized_oci_deployment_target,
)

from app.domain import (
    NodeGroupSpec,
    ServiceProfileSpec,
    TemplateDetail,
    TemplateParameter,
    TemplateSummary,
    TemplateValidationResult,
)


SKETCH_PROVIDERS = {"linode", "digitalocean"}
PROXY_IDS = {"proxy01", "proxy02"}
SINGLE_PROXY_TEMPLATE_IDS = frozenset({"dev-infra", "small-dev-infra"})
DEFAULT_PROXY_SOCKS_PORT = 1080
CREDENTIAL_ALIAS_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{1,78}[a-z0-9]")
PROVIDER_DEFAULTS = {
    "linode": {
        "region": "us-sea",
        "size": "g6-nanode-1",
    },
    "digitalocean": {
        "region": "sfo3",
        "size": "s-1vcpu-1gb",
    },
}
PROVIDER_REGION_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{1,31}")
PROVIDER_SIZE_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{1,78}[a-z0-9]")


STANDARD_RTI_TEMPLATE = TemplateDetail(
    summary=TemplateSummary(
        id="standard-rti",
        name="Standard RTI",
        version="0.1.0",
        description="Opinionated RTI baseline with OCI core infrastructure and one or more sketch chains.",
        default_node_groups=["homebase", "proxy", "middle", "edge"],
        supported_providers=["oci", "linode", "digitalocean"],
    ),
    parameters=[
        TemplateParameter(
            name="engagementName",
            label="Engagement name",
            kind="string",
            required=True,
            description="Operator-visible engagement name.",
        ),
        TemplateParameter(
            name="proxyCount",
            label="Proxy count",
            kind="integer",
            required=True,
            default=2,
            description="Standard RTI starts with two OCI proxies.",
        ),
        TemplateParameter(
            name="elkEnabled",
            label="Enable ELK",
            kind="boolean",
            required=False,
            default=False,
            description="Optional OCI ELK node.",
        ),
        TemplateParameter(
            name="sketchChains",
            label="Sketch chains",
            kind="array",
            required=True,
            description="One or more proxy -> middle -> edge chains.",
        ),
        TemplateParameter(
            name="egressProfiles",
            label="Egress profiles",
            kind="array",
            required=True,
            description="Named operator SOCKS profiles published on homebase.",
        ),
        TemplateParameter(
            name="ingressRoutes",
            label="Ingress routes",
            kind="array",
            required=True,
            description="Domain-backed edge -> middle -> proxy -> backend routes.",
        ),
        TemplateParameter(
            name="reverseChannels",
            label="Reverse channels",
            kind="array",
            required=False,
            description="Optional Backflip or reverse SSH channels for supported services.",
        ),
    ],
    node_groups=[
        NodeGroupSpec("homebase", "oci", 1, True, "192.168.0.0/24"),
        NodeGroupSpec("proxy", "oci", 2, True, "192.168.2.0/24"),
        NodeGroupSpec("elk", "oci", 1, False, "192.168.1.0/24", False),
        NodeGroupSpec("middle", "linode|digitalocean", 1, True),
        NodeGroupSpec("edge", "linode|digitalocean", 1, True),
    ],
    service_profiles=[
        ServiceProfileSpec("homebase", "Homebase", "homebase"),
        ServiceProfileSpec("proxy-stack", "Proxy Stack", "proxy", requires_ingress_route=True),
        ServiceProfileSpec(
            "sketch-egress",
            "Sketch-backed Egress",
            "proxy",
            publishes_egress_profile=True,
        ),
        ServiceProfileSpec(
            "reverse-channel",
            "Reverse Channel",
            "proxy",
            requires_ingress_route=True,
            requires_reverse_channel=True,
        ),
    ],
    provider_constraints={
        "coreProvider": "oci",
        "sketchProviders": sorted(SKETCH_PROVIDERS),
        "mixedProviderSketchChains": True,
        "namedOperatorsOnSketch": False,
    },
    route_defaults={
        "defaultProxySocksPort": DEFAULT_PROXY_SOCKS_PORT,
        "requiredIngressPorts": [80, 443, 2222],
        "minimumIngressRoutes": 1,
        "minimumEgressProfiles": 1,
        "egressProfilePublicationRoots": ["/opt/proxy01", "/opt/proxy02"],
        "egressProfileListenerPortRequired": True,
    },
    reverse_channel_defaults={
        "minimumReverseChannels": 0,
        "defaultRemotePort": 2222,
        "supportedKinds": ["backflip", "reverse-ssh"],
    },
)

DEV_INFRA_TEMPLATE = TemplateDetail(
    summary=TemplateSummary(
        id="dev-infra",
        name="Dev Infra",
        version="0.1.0",
        description="Smaller RTI development shape with one OCI homebase, one OCI proxy, and sketch chains as needed.",
        default_node_groups=["homebase", "proxy", "middle", "edge"],
        supported_providers=["oci", "linode", "digitalocean"],
    ),
    parameters=[
        TemplateParameter(
            name="engagementName",
            label="Engagement name",
            kind="string",
            required=True,
            description="Operator-visible engagement name.",
        ),
        TemplateParameter(
            name="proxyCount",
            label="Proxy count",
            kind="integer",
            required=True,
            default=1,
            description="Dev Infra starts with one OCI proxy.",
        ),
        TemplateParameter(
            name="elkEnabled",
            label="Enable ELK",
            kind="boolean",
            required=False,
            default=False,
            description="Optional OCI ELK node.",
        ),
        TemplateParameter(
            name="sketchChains",
            label="Sketch chains",
            kind="array",
            required=False,
            description="Optional proxy -> middle -> edge chains.",
        ),
        TemplateParameter(
            name="egressProfiles",
            label="Egress profiles",
            kind="array",
            required=False,
            description="Named operator SOCKS profiles published on homebase.",
        ),
        TemplateParameter(
            name="ingressRoutes",
            label="Ingress routes",
            kind="array",
            required=False,
            description="Domain-backed edge -> middle -> proxy -> backend routes.",
        ),
        TemplateParameter(
            name="reverseChannels",
            label="Reverse channels",
            kind="array",
            required=False,
            description="Optional Backflip or reverse SSH channels for supported services.",
        ),
    ],
    node_groups=[
        NodeGroupSpec("homebase", "oci", 1, True, "192.168.0.0/24"),
        NodeGroupSpec("proxy", "oci", 1, True, "192.168.2.0/24"),
        NodeGroupSpec("elk", "oci", 1, False, "192.168.1.0/24", False),
        NodeGroupSpec("middle", "linode|digitalocean", 0, False),
        NodeGroupSpec("edge", "linode|digitalocean", 0, False),
    ],
    service_profiles=STANDARD_RTI_TEMPLATE.service_profiles,
    provider_constraints=STANDARD_RTI_TEMPLATE.provider_constraints,
    route_defaults={
        **STANDARD_RTI_TEMPLATE.route_defaults,
        "minimumIngressRoutes": 0,
        "minimumEgressProfiles": 0,
        "egressProfilePublicationRoots": ["/opt/proxy01"],
    },
    reverse_channel_defaults=STANDARD_RTI_TEMPLATE.reverse_channel_defaults,
)

SMALL_DEV_INFRA_TEMPLATE = TemplateDetail(
    summary=TemplateSummary(
        id="small-dev-infra",
        name="Small Dev Infra",
        version="0.1.0",
        description="Disposable low-capacity RTI development shape with one OCI homebase and one OCI proxy.",
        default_node_groups=["homebase", "proxy", "middle", "edge"],
        supported_providers=["oci", "linode", "digitalocean"],
    ),
    parameters=[parameter for parameter in DEV_INFRA_TEMPLATE.parameters if parameter.name != "elkEnabled"],
    node_groups=[group for group in DEV_INFRA_TEMPLATE.node_groups if group.role != "elk"],
    service_profiles=DEV_INFRA_TEMPLATE.service_profiles,
    provider_constraints=DEV_INFRA_TEMPLATE.provider_constraints,
    route_defaults=DEV_INFRA_TEMPLATE.route_defaults,
    reverse_channel_defaults=DEV_INFRA_TEMPLATE.reverse_channel_defaults,
)

TEMPLATES = {
    STANDARD_RTI_TEMPLATE.summary.id: STANDARD_RTI_TEMPLATE,
    DEV_INFRA_TEMPLATE.summary.id: DEV_INFRA_TEMPLATE,
    SMALL_DEV_INFRA_TEMPLATE.summary.id: SMALL_DEV_INFRA_TEMPLATE,
}


def is_single_proxy_template(template_id: str) -> bool:
    return template_id in SINGLE_PROXY_TEMPLATE_IDS


def template_allows_elk(template_id: str) -> bool:
    return template_id != "small-dev-infra"


def list_templates() -> list[TemplateSummary]:
    return [template.summary for template in TEMPLATES.values()]


def get_template(template_id: str) -> TemplateDetail | None:
    return TEMPLATES.get(template_id)


def validate_template_input(template_id: str, input_parameters: dict[str, Any]) -> TemplateValidationResult:
    template = get_template(template_id)
    if template is None:
        return TemplateValidationResult(False, [f"unknown template: {template_id}"], {})

    target_errors: list[str] = []
    deployment_target = None
    if "deploymentTarget" in input_parameters:
        try:
            deployment_target = normalized_oci_deployment_target(input_parameters.get("deploymentTarget"))
        except OciDeploymentTargetError as exc:
            target_errors.append(str(exc))
    normalized = _normalize_template_input(template_id, input_parameters, deployment_target=deployment_target)
    errors = [*target_errors, *_validate_template_input(template_id, normalized)]
    return TemplateValidationResult(len(errors) == 0, errors, normalized)


def _normalize_template_input(
    template_id: str,
    input_parameters: dict[str, Any],
    *,
    deployment_target: dict[str, str] | None,
) -> dict[str, Any]:
    default_proxy_count = 1 if is_single_proxy_template(template_id) else 2
    normalized = {
        "engagementName": str(input_parameters.get("engagementName", "")).strip(),
        "proxyCount": input_parameters.get("proxyCount", default_proxy_count),
        "elkEnabled": bool(input_parameters.get("elkEnabled", False)),
        "sketchChains": _normalize_sketch_chains(list(input_parameters.get("sketchChains", []))),
        "egressProfiles": list(input_parameters.get("egressProfiles", [])),
        "ingressRoutes": list(input_parameters.get("ingressRoutes", [])),
        "reverseChannels": list(input_parameters.get("reverseChannels", [])),
    }
    if deployment_target is not None:
        normalized["deploymentTarget"] = deployment_target
    return normalized


def _normalize_sketch_chains(sketch_chains: list[Any]) -> list[Any]:
    normalized: list[Any] = []
    for chain in sketch_chains:
        if not isinstance(chain, dict):
            normalized.append(chain)
            continue
        middle_provider = chain.get("middleProvider")
        raw_edges = chain.get("edges")
        edge_provider = chain.get("edgeProvider")
        middle_defaults = PROVIDER_DEFAULTS.get(str(middle_provider), {})
        edge_defaults = PROVIDER_DEFAULTS.get(str(edge_provider), {})
        item = {
                **chain,
                "middleRegion": str(chain.get("middleRegion") or middle_defaults.get("region", "")).strip(),
                "edgeRegion": str(chain.get("edgeRegion") or edge_defaults.get("region", "")).strip(),
                "middleSize": str(chain.get("middleSize") or middle_defaults.get("size", "")).strip(),
                "edgeSize": str(chain.get("edgeSize") or edge_defaults.get("size", "")).strip(),
                "edgeCount": _normalize_edge_count(chain.get("edgeCount")),
            }
        if isinstance(raw_edges, list) and raw_edges:
            edges = []
            for index, edge in enumerate(raw_edges, start=1):
                edge = edge if isinstance(edge, dict) else {}
                provider = str(edge.get("provider") or edge_provider or "").strip()
                defaults = PROVIDER_DEFAULTS.get(provider, {})
                edges.append({
                    "id": str(edge.get("id") or f"edge-{index:02d}").strip(),
                    "provider": provider,
                    "region": str(edge.get("region") or defaults.get("region", "")).strip(),
                    "size": str(edge.get("size") or defaults.get("size", "")).strip(),
                })
            item.update(edges=edges, edgeProvider=edges[0]["provider"], edgeRegion=edges[0]["region"], edgeSize=edges[0]["size"], edgeCount=len(edges))
        normalized.append(item)
    return normalized


def _validate_template_input(template_id: str, parameters: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if not parameters["engagementName"]:
        errors.append("engagementName is required")

    if template_id == "standard-rti" and parameters["proxyCount"] != 2:
        errors.append("standard-rti requires exactly 2 OCI proxies")
    if is_single_proxy_template(template_id) and parameters["proxyCount"] != 1:
        errors.append(f"{template_id} requires exactly 1 OCI proxy")
    if not template_allows_elk(template_id) and parameters["elkEnabled"]:
        errors.append("small-dev-infra does not support an ELK node")
    allowed_proxies = {"proxy01"} if is_single_proxy_template(template_id) else PROXY_IDS

    sketch_chains = parameters["sketchChains"]
    if template_id == "standard-rti" and len(sketch_chains) < 1:
        errors.append("at least one sketch chain is required")

    chain_ids = set()
    chain_proxy_by_id = {}
    for index, chain in enumerate(sketch_chains):
        prefix = f"sketchChains[{index}]"
        if not isinstance(chain, dict):
            errors.append(f"{prefix} must be an object")
            continue

        chain_id = str(chain.get("id", "")).strip()
        if not chain_id:
            errors.append(f"{prefix}.id is required")
        elif chain_id in chain_ids:
            errors.append(f"{prefix}.id must be unique")
        chain_ids.add(chain_id)

        assigned_proxy = chain.get("assignedProxy")
        if assigned_proxy not in allowed_proxies:
            errors.append(f"{prefix}.assignedProxy must be one of {sorted(allowed_proxies)}")
        elif chain_id:
            chain_proxy_by_id[chain_id] = assigned_proxy

        _validate_sketch_provider(errors, prefix, "middleProvider", chain.get("middleProvider"))
        _validate_sketch_provider(errors, prefix, "edgeProvider", chain.get("edgeProvider"))
        _validate_provider_region(errors, prefix, "middleRegion", chain.get("middleRegion"))
        _validate_provider_region(errors, prefix, "edgeRegion", chain.get("edgeRegion"))
        _validate_provider_size(errors, prefix, "middleSize", chain.get("middleSize"))
        _validate_provider_size(errors, prefix, "edgeSize", chain.get("edgeSize"))
        edge_count = chain.get("edgeCount")
        if not isinstance(edge_count, int) or edge_count < 1 or edge_count > 10:
            errors.append(f"{prefix}.edgeCount must be an integer from 1 to 10")
        _validate_credential_alias(errors, prefix, "middleCredentialAlias", chain.get("middleCredentialAlias"))
        _validate_credential_alias(errors, prefix, "edgeCredentialAlias", chain.get("edgeCredentialAlias"))
        if "edges" in chain:
            edges = chain.get("edges")
            if not isinstance(edges, list) or not 1 <= len(edges) <= 10:
                errors.append(f"{prefix}.edges must contain 1 to 10 edge intents")
            elif isinstance(edges, list):
                for edge_index, edge in enumerate(edges, start=1):
                    edge_prefix = f"{prefix}.edges[{edge_index - 1}]"
                    if not isinstance(edge, dict):
                        errors.append(f"{edge_prefix} must be an object")
                        continue
                    if edge.get("id") != f"edge-{edge_index:02d}":
                        errors.append(f"{edge_prefix}.id must equal edge-{edge_index:02d}")
                    _validate_sketch_provider(errors, edge_prefix, "provider", edge.get("provider"))
                    _validate_provider_region(errors, edge_prefix, "region", edge.get("region"))
                    _validate_provider_size(errors, edge_prefix, "size", edge.get("size"))

    _validate_egress_profiles(
        errors,
        parameters["egressProfiles"],
        chain_ids=chain_ids,
        chain_proxy_by_id=chain_proxy_by_id,
        minimum=1 if template_id == "standard-rti" else 0,
    )
    _validate_route_collection(
        errors,
        "ingressRoutes",
        parameters["ingressRoutes"],
        minimum=1 if template_id == "standard-rti" else 0,
        chain_ids=chain_ids,
    )
    _validate_route_collection(
        errors,
        "reverseChannels",
        parameters["reverseChannels"],
        minimum=0,
        chain_ids=chain_ids,
    )

    return errors


def _validate_sketch_provider(errors: list[str], prefix: str, field_name: str, value: Any) -> None:
    if value not in SKETCH_PROVIDERS:
        errors.append(f"{prefix}.{field_name} must be one of {sorted(SKETCH_PROVIDERS)}")


def _normalize_edge_count(value: Any) -> int:
    try:
        edge_count = 1 if value in (None, "") else int(value)
    except (TypeError, ValueError):
        return 0
    return edge_count


def _validate_credential_alias(errors: list[str], prefix: str, field_name: str, value: Any) -> None:
    if value in (None, ""):
        return
    if not isinstance(value, str) or not CREDENTIAL_ALIAS_PATTERN.fullmatch(value.strip().lower()):
        errors.append(f"{prefix}.{field_name} must be a valid credential alias")


def _validate_provider_region(errors: list[str], prefix: str, field_name: str, value: Any) -> None:
    if not isinstance(value, str) or not PROVIDER_REGION_PATTERN.fullmatch(value.strip().lower()):
        errors.append(f"{prefix}.{field_name} must be a valid provider region")


def _validate_provider_size(errors: list[str], prefix: str, field_name: str, value: Any) -> None:
    if not isinstance(value, str) or not PROVIDER_SIZE_PATTERN.fullmatch(value.strip().lower()):
        errors.append(f"{prefix}.{field_name} must be a valid provider size")


def _validate_route_collection(
    errors: list[str],
    field_name: str,
    values: list[Any],
    minimum: int,
    chain_ids: set[str],
) -> None:
    if len(values) < minimum:
        errors.append(f"{field_name} requires at least {minimum} item")
        return

    for index, item in enumerate(values):
        prefix = f"{field_name}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue

        item_name = str(item.get("name", "")).strip()
        if not item_name:
            errors.append(f"{prefix}.name is required")

        sketch_chain_id = str(item.get("sketchChainId", "")).strip()
        if sketch_chain_id not in chain_ids:
            errors.append(f"{prefix}.sketchChainId must reference a declared sketch chain")


def _validate_egress_profiles(
    errors: list[str],
    values: list[Any],
    chain_ids: set[str],
    chain_proxy_by_id: dict[str, str],
    minimum: int,
) -> None:
    if len(values) < minimum:
        errors.append(f"egressProfiles requires at least {minimum} item")
        return

    seen_ports: set[tuple[str, int]] = set()
    seen_names: set[tuple[str, str]] = set()
    for index, item in enumerate(values):
        prefix = f"egressProfiles[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue

        item_name = str(item.get("name", "")).strip()
        if not item_name:
            errors.append(f"{prefix}.name is required")

        sketch_chain_id = str(item.get("sketchChainId", "")).strip()
        if sketch_chain_id not in chain_ids:
            errors.append(f"{prefix}.sketchChainId must reference a declared sketch chain")

        listener_port = item.get("listenerPort")
        if isinstance(listener_port, bool) or not isinstance(listener_port, int):
            errors.append(f"{prefix}.listenerPort is required and must be an integer")
            continue

        if listener_port < 1024 or listener_port > 65535:
            errors.append(f"{prefix}.listenerPort must be between 1024 and 65535")

        if listener_port == DEFAULT_PROXY_SOCKS_PORT:
            errors.append(f"{prefix}.listenerPort must not use reserved default proxy SOCKS port {DEFAULT_PROXY_SOCKS_PORT}")

        owner_proxy = chain_proxy_by_id.get(sketch_chain_id)
        if owner_proxy is None:
            continue

        port_key = (owner_proxy, listener_port)
        if port_key in seen_ports:
            errors.append(f"{prefix}.listenerPort must be unique for {owner_proxy}")
        seen_ports.add(port_key)

        if item_name:
            name_key = (owner_proxy, item_name)
            if name_key in seen_names:
                errors.append(f"{prefix}.name must be unique for {owner_proxy}")
            seen_names.add(name_key)
