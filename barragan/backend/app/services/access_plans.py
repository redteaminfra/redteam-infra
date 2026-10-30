# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.domain import DeploymentRevisionPlan


@dataclass(frozen=True)
class PlatformAccessUser:
    user_id: str
    username: str
    credential_ref: str
    privileges: list[str]


@dataclass(frozen=True)
class AccessTarget:
    host_group_id: str
    access_kind: str
    users: list[dict[str, Any]]

    def to_dict(self) -> dict:
        return {
            "hostGroupId": self.host_group_id,
            "accessKind": self.access_kind,
            "users": self.users,
        }


@dataclass(frozen=True)
class AccessPropagationPlan:
    engagement_id: str
    revision_id: str
    mode: str
    targets: list[AccessTarget]
    steps: list[dict[str, Any]]

    def to_dict(self) -> dict:
        return {
            "engagementId": self.engagement_id,
            "revisionId": self.revision_id,
            "mode": self.mode,
            "targets": [target.to_dict() for target in self.targets],
            "steps": self.steps,
        }


def plan_access_propagation(
    revision: DeploymentRevisionPlan,
    users: list[PlatformAccessUser],
    allow_proxy_ssh: bool = False,
) -> AccessPropagationPlan:
    topology = revision.to_dict()["resolvedTopology"]
    core_users = [
        {
            "platformUserId": user.user_id,
            "username": user.username,
            "credentialRef": user.credential_ref,
            "privileges": user.privileges,
        }
        for user in users
    ]
    targets = [AccessTarget("homebase", "core_named", core_users)]

    if allow_proxy_ssh:
        targets.append(AccessTarget("proxy", "core_named", core_users))

    sketch_users = [
        {
            "username": "sketch-management",
            "credentialRef": "secret://barragan/sketch-management",
            "platformUserId": None,
            "privileges": ["automation"],
        }
    ]
    for chain in topology["sketchChains"]:
        targets.append(AccessTarget(f"middle-{chain['id']}", "sketch_management", sketch_users))
        targets.append(AccessTarget(f"edge-{chain['id']}", "sketch_management", sketch_users))

    return AccessPropagationPlan(
        engagement_id=revision.engagement_id,
        revision_id=revision.id,
        mode="dry_run",
        targets=targets,
        steps=[
            {"step": "plan_core_named_access", "mutation": False},
            {"step": "plan_sketch_management_access", "mutation": False},
            {"step": "plan_access_audit_events", "mutation": False},
        ],
    )
