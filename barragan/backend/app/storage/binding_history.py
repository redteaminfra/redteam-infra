# Copyright (c) 2026, Oracle and/or its affiliates.
"""Independent binding history excluded by original four-host cleanup."""

INDEPENDENT_BINDING_ACTION_PREFIXES = (
    "inbound_channel_", "outbound_channel_", "certificate_asset_",
    "engagement_dns_", "web_static_service_", "backflips_service_",
    "desktop_service_", "legacy_homebase_role_service_",
)


def is_independent_binding_history(action: str) -> bool:
    return (action == "engagement_channels_update"
            or action.startswith(INDEPENDENT_BINDING_ACTION_PREFIXES))
