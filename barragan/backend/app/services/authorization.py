# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Iterable


class ActionClass(str, Enum):
    VIEW = "view"
    OPERATE = "operate"
    APPROVE_DESTRUCTIVE = "approve_destructive"
    ADMINISTER = "administer"


ROLE_ACTIONS: dict[str, frozenset[ActionClass]] = {
    "administrator": frozenset(ActionClass),
    "operator": frozenset({ActionClass.VIEW, ActionClass.OPERATE}),
    "infrastructure_manager": frozenset({ActionClass.VIEW, ActionClass.OPERATE, ActionClass.ADMINISTER}),
    "approver": frozenset({ActionClass.VIEW, ActionClass.APPROVE_DESTRUCTIVE}),
    "viewer": frozenset({ActionClass.VIEW}),
    "auditor": frozenset({ActionClass.VIEW}),
    "service_account": frozenset(),
}

PUBLIC_PATHS = frozenset({"/api/health", "/api/auth/login", "/api/auth/session"})
FORCED_CHANGE_PATHS = frozenset({"/api/auth/password", "/api/auth/logout", "/api/auth/logout-all", "/api/auth/session"})

ADMIN_PATHS = (
    re.compile(r"^/api/team(?:/|$)"),
    re.compile(r"^/api/credentials(?:/|$)"),
    re.compile(r"^/api/provider-catalog/sketch/region-policies(?:/|$)"),
    re.compile(r"^/api/provider-catalog/sketch/digitalocean/preflight$"),
    re.compile(r"^/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs(?:/|$)"),
    re.compile(r"^/api/engagements/[^/]+/team(?:/|$)"),
    re.compile(r"^/api/engagements/[^/]+/sketch-ssh-key/material$"),
)
DESTRUCTIVE_PATHS = (
    re.compile(r"/(?:archive|teardown|retire|remove|revoke|rotate|deactivate|cancel|stop|disable|release)(?:/|$)"),
    re.compile(r"^/api/dashboard/orphan-candidates/actions$"),
)
OPERATE_PATHS = (
    # This explicit detail surface returns the intentionally operator-visible
    # plaintext scanner-deterrence token, so it requires operate even on GET.
    re.compile(r"^/api/engagements/[^/]+/inbound-channels/[^/]+/request-header-gate$"),
)


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    action: ActionClass
    reason: str


def action_for_request(method: str, path: str) -> ActionClass:
    normalized_method = method.upper()
    if any(pattern.search(path) for pattern in ADMIN_PATHS):
        return ActionClass.ADMINISTER
    if normalized_method == "DELETE" or any(pattern.search(path) for pattern in DESTRUCTIVE_PATHS):
        return ActionClass.APPROVE_DESTRUCTIVE
    if any(pattern.search(path) for pattern in OPERATE_PATHS):
        return ActionClass.OPERATE
    if normalized_method in {"GET", "HEAD", "OPTIONS"}:
        return ActionClass.VIEW
    return ActionClass.OPERATE


def authorize(roles: Iterable[str], method: str, path: str) -> AuthorizationDecision:
    action = action_for_request(method, path)
    granted = frozenset().union(*(ROLE_ACTIONS.get(role, frozenset()) for role in roles))
    if action in granted:
        return AuthorizationDecision(True, action, "role grants action")
    return AuthorizationDecision(False, action, "no assigned role grants action")
