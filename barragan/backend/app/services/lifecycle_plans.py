# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.domain import DeploymentRevisionPlan


@dataclass(frozen=True)
class LifecyclePlan:
    action: str
    target_id: str
    mode: str
    steps: list[dict[str, Any]]
    preserved_refs: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "targetId": self.target_id,
            "mode": self.mode,
            "steps": self.steps,
            "preservedRefs": self.preserved_refs,
        }


def plan_replace_edge(
    revision: DeploymentRevisionPlan,
    ingress_route_id: str,
    replacement_provider: str,
) -> LifecyclePlan:
    topology = revision.to_dict()["resolvedTopology"]
    ingress_route = _find_route(topology["ingressRoutes"], ingress_route_id)
    chain = _find_chain(topology["sketchChains"], ingress_route["sketchChainId"])
    affected_egress_profiles = [
        {
            "profileId": profile["id"],
            "publicationPath": profile["details"]["publicationPath"],
            "listenerPort": profile["details"]["listenerPort"],
        }
        for profile in topology["egressProfiles"]
        if profile["sketchChainId"] == chain["id"]
    ]

    return LifecyclePlan(
        action="replace_edge",
        target_id=ingress_route_id,
        mode="dry_run",
        steps=[
            {
                "step": "plan_replacement_edge",
                "provider": replacement_provider,
                "sketchChainId": chain["id"],
                "mutation": False,
            },
            {
                "step": "plan_dns_and_certificate_cutover",
                "domain": ingress_route["details"].get("domain"),
                "mutation": False,
            },
            {
                "step": "plan_proxy_route_rewire",
                "proxy": chain["assignedProxy"],
                "ingressRouteId": ingress_route_id,
                "mutation": False,
            },
            {
                "step": "plan_egress_profile_republish",
                "egressProfiles": affected_egress_profiles,
                "mutation": False,
            },
            {
                "step": "plan_path_validation",
                "managementPath": chain["managementPath"],
                "mutation": False,
            },
            {
                "step": "plan_old_edge_teardown",
                "sketchChainId": chain["id"],
                "mutation": False,
            },
        ],
        preserved_refs={"revisionId": revision.id, "sketchChainId": chain["id"]},
    )


def plan_route_repair(revision: DeploymentRevisionPlan, route_id: str) -> LifecyclePlan:
    topology = revision.to_dict()["resolvedTopology"]
    all_routes = topology["ingressRoutes"] + topology["egressProfiles"] + topology["reverseChannels"]
    route = _find_route(all_routes, route_id)
    chain = _find_chain(topology["sketchChains"], route["sketchChainId"])
    egress_profile = route if route["kind"] == "egress" else None

    return LifecyclePlan(
        action="repair_route",
        target_id=route_id,
        mode="dry_run",
        steps=[
            {"step": "plan_route_config_check", "routeId": route_id, "mutation": False},
            {
                "step": "plan_proxy_profile_republish",
                "proxy": chain["assignedProxy"],
                "egressProfile": (
                    {
                        "profileId": egress_profile["id"],
                        "publicationPath": egress_profile["details"]["publicationPath"],
                        "listenerPort": egress_profile["details"]["listenerPort"],
                    }
                    if egress_profile
                    else None
                ),
                "mutation": False,
            },
            {"step": "plan_reverse_channel_check", "sketchChainId": chain["id"], "mutation": False},
            {"step": "plan_path_validation", "managementPath": chain["managementPath"], "mutation": False},
        ],
        preserved_refs={"revisionId": revision.id, "sketchChainId": chain["id"]},
    )


def plan_archive(revision: DeploymentRevisionPlan, artifact_refs: list[str] | None = None) -> LifecyclePlan:
    return LifecyclePlan(
        action="archive_engagement",
        target_id=revision.engagement_id,
        mode="dry_run",
        steps=[
            {"step": "preserve_barragan_metadata", "mutation": False},
            {"step": "preserve_deployment_revision_history", "revisionId": revision.id, "mutation": False},
            {"step": "preserve_generated_artifacts", "artifactRefs": artifact_refs or [], "mutation": False},
            {"step": "plan_backup_or_snapshot_refs", "mutation": False},
            {"step": "preserve_secret_refs", "mutation": False},
            {"step": "plan_infrastructure_destroy", "mutation": False},
        ],
        preserved_refs={
            "engagementId": revision.engagement_id,
            "revisionId": revision.id,
            "artifactRefs": artifact_refs or [],
            "secretRefs": [],
            "backupRefs": [],
        },
    )


def _find_route(routes: list[dict[str, Any]], route_id: str) -> dict[str, Any]:
    for route in routes:
        if route["id"] == route_id:
            return route
    raise ValueError(f"unknown route: {route_id}")


def _find_chain(chains: list[dict[str, Any]], chain_id: str) -> dict[str, Any]:
    for chain in chains:
        if chain["id"] == chain_id:
            return chain
    raise ValueError(f"unknown sketch chain: {chain_id}")
