# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from typing import Any

from app.storage.service_repository import EngagementServiceRepository, SqlAlchemyEngagementServiceRepository


NATIVE_STATIC_WEB_CAPABILITY_ID = "barragan.static-web-site"
STATIC_WEB_HOST_CLASS = "proxy"
STATIC_WEB_SERVICE_TYPE = "web-static"
CLAIMING_STATUSES = {"active", "configured", "applying", "removing", "remove failed"}


def static_web_capability_state(
    engagement_id: str,
    *,
    repository: EngagementServiceRepository | None = None,
) -> dict[str, Any]:
    repo = repository or SqlAlchemyEngagementServiceRepository()
    sites = [
        service
        for service in repo.list_for_engagement(engagement_id)
        if service.service_type == STATIC_WEB_SERVICE_TYPE and service.status.strip().lower() in CLAIMING_STATUSES
    ]
    return {
        "claimed": bool(sites),
        "claimingCount": len(sites),
        "claimingSiteIds": [service.service_id for service in sites],
        "reason": (
            "Static Web remains selected while configured sites depend on it. Remove those sites before deselecting it."
            if sites
            else ""
        ),
    }


def with_implied_static_web_selection(
    overrides: dict[str, list[dict[str, str]]],
    state: dict[str, Any],
) -> tuple[dict[str, list[dict[str, str]]], bool]:
    normalized = {
        "deselectedDefaults": [dict(row) for row in overrides.get("deselectedDefaults", [])],
        "selectedOptionals": [dict(row) for row in overrides.get("selectedOptionals", [])],
    }
    if not state.get("claimed") or static_web_is_selected(normalized):
        return normalized, False
    normalized["selectedOptionals"].append(
        {"hostClass": STATIC_WEB_HOST_CLASS, "id": NATIVE_STATIC_WEB_CAPABILITY_ID}
    )
    normalized["selectedOptionals"].sort(key=lambda item: (item["hostClass"], item["id"]))
    return normalized, True


def static_web_is_selected(overrides: dict[str, list[dict[str, str]]]) -> bool:
    return any(
        row.get("hostClass") == STATIC_WEB_HOST_CLASS and row.get("id") == NATIVE_STATIC_WEB_CAPABILITY_ID
        for row in overrides.get("selectedOptionals", [])
    )
