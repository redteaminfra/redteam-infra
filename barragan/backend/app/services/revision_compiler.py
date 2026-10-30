# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from typing import Any

from app.domain import (
    DeploymentRevisionPlan,
    NodeGroupPlan,
    ProxyStackPlan,
    RevisionValidationGate,
    RoutePlan,
    SketchChainPlan,
)
from app.services.catalog import (
    PROVIDER_DEFAULTS,
    is_single_proxy_template,
    validate_template_input,
)


class RevisionCompileError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("revision compile failed")
        self.errors = errors


def compile_standard_rti_revision(
    engagement_id: str,
    input_parameters: dict[str, Any],
    revision_number: int = 1,
    template_id: str = "standard-rti",
) -> DeploymentRevisionPlan:
    validation = validate_template_input(template_id, input_parameters)
    if not validation.valid:
        raise RevisionCompileError(validation.errors)

    normalized = validation.normalized
    node_groups = _compile_node_groups(normalized)
    sketch_chains = _compile_sketch_chains(normalized)
    egress_profiles = _compile_route_plans(normalized["egressProfiles"], sketch_chains, "egress")
    ingress_routes = _compile_route_plans(normalized["ingressRoutes"], sketch_chains, "ingress")
    reverse_channels = _compile_route_plans(normalized["reverseChannels"], sketch_chains, "reverse-channel")
    proxy_stacks = _compile_proxy_stacks(ingress_routes)
    run_intent = _compile_run_intent()
    validation_gates = _compile_validation_gates(
        template_id,
        node_groups,
        sketch_chains,
        egress_profiles,
        ingress_routes,
        reverse_channels,
        run_intent,
    )

    return DeploymentRevisionPlan(
        id=f"rev-{engagement_id}-{revision_number:04d}",
        engagement_id=engagement_id,
        revision_number=revision_number,
        status="compiled",
        template_id=template_id,
        input_parameters=normalized,
        node_groups=node_groups,
        sketch_chains=sketch_chains,
        egress_profiles=egress_profiles,
        ingress_routes=ingress_routes,
        proxy_stacks=proxy_stacks,
        reverse_channels=reverse_channels,
        run_intent=run_intent,
        validation_gates=validation_gates,
    )


def deployment_revision_from_dict(body: dict[str, Any]) -> DeploymentRevisionPlan:
    topology = body["resolvedTopology"]
    return DeploymentRevisionPlan(
        id=body["id"],
        engagement_id=body["engagementId"],
        revision_number=body["revisionNumber"],
        status=body["status"],
        template_id=body["templateId"],
        input_parameters=body["inputParameters"],
        node_groups=[
            NodeGroupPlan(
                id=node_group["id"],
                role=node_group["role"],
                provider=node_group["provider"],
                count=node_group["count"],
                subnet=node_group.get("subnet"),
            )
            for node_group in topology["nodeGroups"]
        ],
        sketch_chains=[
            SketchChainPlan(
                id=chain["id"],
                assigned_proxy=chain["assignedProxy"],
                middle_provider=chain["middleProvider"],
                edge_provider=chain["edgeProvider"],
                management_path=chain["managementPath"],
                middle_region=_chain_value(chain, "middleRegion", chain["middleProvider"], "region"),
                edge_region=_chain_value(chain, "edgeRegion", chain["edgeProvider"], "region"),
                middle_size=_chain_value(chain, "middleSize", chain["middleProvider"], "size"),
                edge_size=_chain_value(chain, "edgeSize", chain["edgeProvider"], "size"),
                edge_count=int(chain.get("edgeCount") or 1),
                edges=list(chain.get("edges") or _legacy_edges(chain)),
                middle_credential_alias=chain.get("middleCredentialAlias"),
                edge_credential_alias=chain.get("edgeCredentialAlias"),
            )
            for chain in topology["sketchChains"]
        ],
        egress_profiles=[_route_plan_from_dict(route) for route in topology["egressProfiles"]],
        ingress_routes=[_route_plan_from_dict(route) for route in topology["ingressRoutes"]],
        proxy_stacks=[
            ProxyStackPlan(
                proxy=stack["proxy"],
                ingress_route_ids=stack["ingressRouteIds"],
                domains=stack["domains"],
            )
            for stack in topology["proxyStacks"]
        ],
        reverse_channels=[_route_plan_from_dict(route) for route in topology["reverseChannels"]],
        run_intent=body["runIntent"],
        validation_gates=[
            RevisionValidationGate(
                id=gate["id"],
                label=gate["label"],
                status=gate["status"],
                severity=gate["severity"],
                message=gate["message"],
            )
            for gate in body.get("validationGates", [])
        ],
    )


def _route_plan_from_dict(body: dict[str, Any]) -> RoutePlan:
    return RoutePlan(
        id=body["id"],
        name=body["name"],
        sketch_chain_id=body["sketchChainId"],
        proxy=body["proxy"],
        kind=body["kind"],
        details=body["details"],
    )


def _chain_value(chain: dict[str, Any], key: str, provider: str, default_key: str) -> str:
    value = str(chain.get(key) or "").strip()
    if value:
        return value
    return PROVIDER_DEFAULTS.get(provider, {}).get(default_key, "")


def _compile_node_groups(parameters: dict[str, Any]) -> list[NodeGroupPlan]:
    node_groups = [
        NodeGroupPlan("homebase", "homebase", "oci", 1, "192.168.0.0/24"),
        NodeGroupPlan("proxy", "proxy", "oci", parameters.get("proxyCount", 2), "192.168.2.0/24"),
    ]
    if parameters["elkEnabled"]:
        node_groups.append(NodeGroupPlan("elk", "elk", "oci", 1, "192.168.1.0/24"))

    for chain in parameters["sketchChains"]:
        chain_id = chain["id"]
        edges = chain.get("edges")
        node_groups.extend(
            [
                NodeGroupPlan(f"middle-{chain_id}", "middle", chain["middleProvider"], 1),
                *([
                    NodeGroupPlan(f"edge-{chain_id}-{edge['id']}", "edge", edge["provider"], 1)
                    for edge in edges
                ] if edges else [NodeGroupPlan(f"edge-{chain_id}", "edge", chain["edgeProvider"], chain.get("edgeCount", 1))]),
            ]
        )

    return node_groups


def _compile_sketch_chains(parameters: dict[str, Any]) -> list[SketchChainPlan]:
    return [
        SketchChainPlan(
            id=chain["id"],
            assigned_proxy=chain["assignedProxy"],
            middle_provider=chain["middleProvider"],
            edge_provider=chain["edgeProvider"],
            management_path=[
                "barragan",
                "homebase",
                chain["assignedProxy"],
                f"middle-{chain['id']}",
                f"edge-{chain['id']}",
            ],
            middle_region=chain["middleRegion"],
            edge_region=chain["edgeRegion"],
            middle_size=chain["middleSize"],
            edge_size=chain["edgeSize"],
            edge_count=chain.get("edgeCount", 1),
            edges=list(chain.get("edges") or _legacy_edges(chain)),
            middle_credential_alias=chain.get("middleCredentialAlias"),
            edge_credential_alias=chain.get("edgeCredentialAlias"),
        )
        for chain in parameters["sketchChains"]
    ]


def _legacy_edges(chain: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"id": f"edge-{index:02d}", "provider": chain["edgeProvider"], "region": chain["edgeRegion"], "size": chain["edgeSize"]}
        for index in range(1, int(chain.get("edgeCount") or 1) + 1)
    ]


def _compile_route_plans(
    route_inputs: list[dict[str, Any]],
    sketch_chains: list[SketchChainPlan],
    kind: str,
) -> list[RoutePlan]:
    chains_by_id = {chain.id: chain for chain in sketch_chains}
    routes = []
    for index, route in enumerate(route_inputs, start=1):
        chain = chains_by_id[route["sketchChainId"]]
        details = {key: value for key, value in route.items() if key not in {"name", "sketchChainId"}}
        if kind == "egress":
            details.update(
                {
                    "listenerPort": route["listenerPort"],
                    "ownerProxy": chain.assigned_proxy,
                    "backingSketchChainId": chain.id,
                    "profileFile": f"{_profile_file_name(route['name'])}-socks5.conf",
                    "publicationPath": f"/opt/{chain.assigned_proxy}/{_profile_file_name(route['name'])}-socks5.conf",
                }
            )
        routes.append(
            RoutePlan(
                id=f"{kind}-{index:02d}",
                name=route["name"],
                sketch_chain_id=chain.id,
                proxy=chain.assigned_proxy,
                kind=kind,
                details=details,
            )
        )
    return routes


def _compile_proxy_stacks(ingress_routes: list[RoutePlan]) -> list[ProxyStackPlan]:
    routes_by_proxy: dict[str, list[RoutePlan]] = {}
    for route in ingress_routes:
        routes_by_proxy.setdefault(route.proxy, []).append(route)

    return [
        ProxyStackPlan(
            proxy=proxy,
            ingress_route_ids=[route.id for route in routes],
            domains=[str(route.details.get("domain", "")) for route in routes if route.details.get("domain")],
        )
        for proxy, routes in sorted(routes_by_proxy.items())
    ]


def _compile_run_intent() -> list[dict[str, Any]]:
    return [
        {"step": "render_git_artifacts", "mode": "dry_run"},
        {"step": "render_terraform_inputs", "mode": "dry_run"},
        {"step": "render_ansible_inventory", "mode": "dry_run"},
        {"step": "plan_provider_operations", "mode": "dry_run"},
    ]


def _compile_validation_gates(
    template_id: str,
    node_groups: list[NodeGroupPlan],
    sketch_chains: list[SketchChainPlan],
    egress_profiles: list[RoutePlan],
    ingress_routes: list[RoutePlan],
    reverse_channels: list[RoutePlan],
    run_intent: list[dict[str, Any]],
) -> list[RevisionValidationGate]:
    node_groups_by_id = {node_group.id: node_group for node_group in node_groups}
    route_chain_ids = {route.sketch_chain_id for route in egress_profiles + ingress_routes + reverse_channels}
    chain_ids = {chain.id for chain in sketch_chains}
    expected_proxy_count = 1 if is_single_proxy_template(template_id) else 2
    expected_proxy_label = "1 OCI proxy" if expected_proxy_count == 1 else f"{expected_proxy_count} OCI proxies"
    template_label = {"dev-infra": "Dev Infra", "small-dev-infra": "Small Dev Infra"}.get(template_id, "Standard RTI")
    route_requirements_met = route_chain_ids.issubset(chain_ids)
    if template_id == "standard-rti":
        route_requirements_met = route_requirements_met and bool(egress_profiles) and bool(ingress_routes)

    return [
        _gate(
            "core-topology",
            "Core topology",
            "homebase" in node_groups_by_id
            and node_groups_by_id.get("proxy") == NodeGroupPlan("proxy", "proxy", "oci", expected_proxy_count, "192.168.2.0/24"),
            f"{template_label} OCI homebase and proxy topology is resolved.",
            f"{template_label} requires one homebase and {expected_proxy_label} before deployment.",
        ),
        _gate(
            "sketch-chain-topology",
            "Sketch chain topology",
            bool(sketch_chains)
            and all(
                f"middle-{chain.id}" in node_groups_by_id
                and (
                    f"edge-{chain.id}" in node_groups_by_id
                    or all(f"edge-{chain.id}-{edge['id']}" in node_groups_by_id for edge in chain.edges or [])
                )
                for chain in sketch_chains
            ),
            "Every sketch chain has resolved middle and edge node groups.",
            "Each sketch chain must resolve middle and edge node groups.",
        ),
        _gate(
            "route-chain-references",
            "Route chain references",
            route_requirements_met,
            "Egress, ingress, and optional reverse-channel routes reference declared sketch chains.",
            "Egress, ingress, and optional reverse-channel routes must reference declared sketch chains.",
        ),
        _gate(
            "sketch-management-opsec",
            "Sketch management opsec",
            all(
                chain.management_path[:3] == ["barragan", "homebase", chain.assigned_proxy]
                and chain.management_path[-2:] == [f"middle-{chain.id}", f"edge-{chain.id}"]
                for chain in sketch_chains
            ),
            "Sketch management paths route through Barragan, homebase, and the assigned proxy.",
            "Sketch management must not bypass the Barragan-controlled homebase and proxy path.",
        ),
        _gate(
            "proxy-egress-profile-state",
            "Proxy egress profile state",
            bool(egress_profiles)
            and all(
                profile.details.get("ownerProxy") == profile.proxy
                and profile.details.get("backingSketchChainId") == profile.sketch_chain_id
                and isinstance(profile.details.get("listenerPort"), int)
                and str(profile.details.get("publicationPath", "")).startswith(f"/opt/{profile.proxy}/")
                for profile in egress_profiles
            ),
            "Operator-facing proxy egress profiles include owner proxy, listener port, backing chain, and publication path.",
            "Proxy egress profiles must explicitly model /opt/proxyXX profile state.",
        ),
        _gate(
            "plan-only-intent",
            "Plan-only intent",
            bool(run_intent)
            and all(step.get("mode") == "dry_run" and not bool(step.get("mutation", False)) for step in run_intent),
            "Run intent is dry-run only and does not request live mutation.",
            "Compiled revisions must remain plan-only until live execution is explicitly enabled.",
        ),
    ]


def _gate(
    gate_id: str,
    label: str,
    passed: bool,
    passed_message: str,
    failed_message: str,
) -> RevisionValidationGate:
    return RevisionValidationGate(
        id=gate_id,
        label=label,
        status="passed" if passed else "failed",
        severity="info" if passed else "blocker",
        message=passed_message if passed else failed_message,
    )


def _profile_file_name(name: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in str(name))
    slug = "-".join(part for part in cleaned.split("-") if part)
    return slug or "profile"
