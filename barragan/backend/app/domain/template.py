# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TemplateSummary:
    id: str
    name: str
    version: str
    description: str
    default_node_groups: list[str]
    supported_providers: list[str]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "defaultNodeGroups": self.default_node_groups,
            "supportedProviders": self.supported_providers,
        }


@dataclass(frozen=True)
class TemplateParameter:
    name: str
    label: str
    kind: str
    required: bool
    default: Any = None
    options: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label,
            "kind": self.kind,
            "required": self.required,
            "default": self.default,
            "options": self.options,
            "description": self.description,
        }


@dataclass(frozen=True)
class NodeGroupSpec:
    role: str
    provider: str
    count: int
    required: bool
    subnet: str | None = None
    enabled_by_default: bool = True

    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "provider": self.provider,
            "count": self.count,
            "required": self.required,
            "subnet": self.subnet,
            "enabledByDefault": self.enabled_by_default,
        }


@dataclass(frozen=True)
class ServiceProfileSpec:
    id: str
    name: str
    placement: str
    requires_ingress_route: bool = False
    publishes_egress_profile: bool = False
    requires_reverse_channel: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "placement": self.placement,
            "requiresIngressRoute": self.requires_ingress_route,
            "publishesEgressProfile": self.publishes_egress_profile,
            "requiresReverseChannel": self.requires_reverse_channel,
        }


@dataclass(frozen=True)
class TemplateDetail:
    summary: TemplateSummary
    parameters: list[TemplateParameter]
    node_groups: list[NodeGroupSpec]
    service_profiles: list[ServiceProfileSpec]
    provider_constraints: dict[str, Any]
    route_defaults: dict[str, Any]
    reverse_channel_defaults: dict[str, Any]

    def to_summary_dict(self) -> dict:
        return self.summary.to_dict()

    def to_dict(self) -> dict:
        body = self.to_summary_dict()
        body.update(
            {
                "parameters": [parameter.to_dict() for parameter in self.parameters],
                "nodeGroups": [node_group.to_dict() for node_group in self.node_groups],
                "serviceProfiles": [profile.to_dict() for profile in self.service_profiles],
                "providerConstraints": self.provider_constraints,
                "routeDefaults": self.route_defaults,
                "reverseChannelDefaults": self.reverse_channel_defaults,
            }
        )
        return body


@dataclass(frozen=True)
class TemplateValidationResult:
    valid: bool
    errors: list[str]
    normalized: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "normalized": self.normalized,
        }
