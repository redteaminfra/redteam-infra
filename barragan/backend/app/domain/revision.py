# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NodeGroupPlan:
    id: str
    role: str
    provider: str
    count: int
    subnet: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "role": self.role,
            "provider": self.provider,
            "count": self.count,
            "subnet": self.subnet,
        }


@dataclass(frozen=True)
class SketchChainPlan:
    id: str
    assigned_proxy: str
    middle_provider: str
    edge_provider: str
    management_path: list[str]
    middle_region: str
    edge_region: str
    middle_size: str
    edge_size: str
    edge_count: int = 1
    edges: list[dict[str, Any]] | None = None
    middle_credential_alias: str | None = None
    edge_credential_alias: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "assignedProxy": self.assigned_proxy,
            "middleProvider": self.middle_provider,
            "edgeProvider": self.edge_provider,
            "managementPath": self.management_path,
            "middleRegion": self.middle_region,
            "edgeRegion": self.edge_region,
            "middleSize": self.middle_size,
            "edgeSize": self.edge_size,
            "edgeCount": self.edge_count,
            "edges": self.edges or [],
            "middleCredentialAlias": self.middle_credential_alias,
            "edgeCredentialAlias": self.edge_credential_alias,
        }


@dataclass(frozen=True)
class RoutePlan:
    id: str
    name: str
    sketch_chain_id: str
    proxy: str
    kind: str
    details: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "sketchChainId": self.sketch_chain_id,
            "proxy": self.proxy,
            "kind": self.kind,
            "details": self.details,
        }


@dataclass(frozen=True)
class ProxyStackPlan:
    proxy: str
    ingress_route_ids: list[str]
    domains: list[str]

    def to_dict(self) -> dict:
        return {
            "proxy": self.proxy,
            "ingressRouteIds": self.ingress_route_ids,
            "domains": self.domains,
        }


@dataclass(frozen=True)
class RevisionValidationGate:
    id: str
    label: str
    status: str
    severity: str
    message: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass(frozen=True)
class DeploymentRevisionPlan:
    id: str
    engagement_id: str
    revision_number: int
    status: str
    template_id: str
    input_parameters: dict[str, Any]
    node_groups: list[NodeGroupPlan]
    sketch_chains: list[SketchChainPlan]
    egress_profiles: list[RoutePlan]
    ingress_routes: list[RoutePlan]
    proxy_stacks: list[ProxyStackPlan]
    reverse_channels: list[RoutePlan]
    run_intent: list[dict[str, Any]]
    validation_gates: list[RevisionValidationGate]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "engagementId": self.engagement_id,
            "revisionNumber": self.revision_number,
            "status": self.status,
            "templateId": self.template_id,
            "inputParameters": self.input_parameters,
            "resolvedTopology": {
                "nodeGroups": [node_group.to_dict() for node_group in self.node_groups],
                "sketchChains": [chain.to_dict() for chain in self.sketch_chains],
                "egressProfiles": [profile.to_dict() for profile in self.egress_profiles],
                "ingressRoutes": [route.to_dict() for route in self.ingress_routes],
                "proxyStacks": [stack.to_dict() for stack in self.proxy_stacks],
                "reverseChannels": [channel.to_dict() for channel in self.reverse_channels],
            },
            "runIntent": self.run_intent,
            "validationGates": [gate.to_dict() for gate in self.validation_gates],
        }
