# Copyright (c) 2026, Oracle and/or its affiliates.
"""Live purchase availability for a new append edge, never cleanup authority."""

from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import (
    ProviderCatalogRegionSizeUnavailable, require_selected_digitalocean_region_sizes,
)
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.storage.credential_repository import SqlAlchemyCredentialRepository


class MixedAppendAvailabilityAttention(ValueError):
    """Safe operator-facing reason why no append may start."""


def require_mixed_append_digitalocean_availability(
    policy: dict, region: str, size: str, *, credential_repository=None,
    catalog_transport=None,
) -> None:
    """Read live offers using the exact authenticated retained connection.

    Only the proposed new edge is checked. Historical nodes, proof readers and
    destroy authority must never depend on this purchase-availability read.
    """
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    try:
        connection = policy["provider_connection_id"]
        expected = (policy["credential_secret_sha256"], policy["credential_updated_at"])
        digest, updated_at, encrypted = _credential_snapshot(connection, credentials)
        if (digest, updated_at) != expected:
            raise ValueError("retained credential snapshot differs")
        token = decrypt_secret_value(encrypted)
        if type(token) is not str or not token:
            raise ValueError("credential unavailable")
        try:
            require_selected_digitalocean_region_sizes(
                token, [(region, size)], transport=catalog_transport)
        except ProviderCatalogRegionSizeUnavailable:
            raise MixedAppendAvailabilityAttention(
                "The inherited DigitalOcean edge size is unavailable in the selected region. Choose a compatible region; no append started.") from None
        # A connection change during the GET cannot validate another identity.
        if _credential_snapshot(connection, credentials) != (digest, updated_at, encrypted):
            raise ValueError("retained credential snapshot changed during catalog read")
    except MixedAppendAvailabilityAttention:
        raise
    except Exception:
        raise MixedAppendAvailabilityAttention(
            "DigitalOcean availability could not be verified with the retained connection. Refresh the catalog and try again; no append started.") from None


def require_reviewed_mixed_append_availability(parent, *, jobs,
        credential_repository=None, catalog_transport=None) -> None:
    """Purchase check at approval/pristine dispatch, never after command intent."""
    from app.services.provider_keyed_mixed_initial_plan_parent import (
        _parent_id, validate_mixed_initial_apply_seal,
    )
    try:
        initial = jobs.get(_parent_id(parent.input["coreJobId"]))
        if (initial is None or initial.target_id != parent.target_id
                or initial.status != "succeeded" or initial.input.get("phase") != "completed"
                or initial.input.get("corePlanId") != parent.input["corePlanId"]):
            raise ValueError("retained source differs")
        policy = validate_mixed_initial_apply_seal(initial)["reviewedPolicy"]["digitalocean"]
        selected = parent.input["reviewRequest"]["digitalocean"]
        if selected["edgeSize"] != policy["nonsecret_varfile"]["edge_size"]:
            raise ValueError("inherited size differs")
        require_mixed_append_digitalocean_availability(policy,
            selected["edgeRegion"], selected["edgeSize"],
            credential_repository=credential_repository, catalog_transport=catalog_transport)
    except MixedAppendAvailabilityAttention:
        raise
    except Exception:
        raise MixedAppendAvailabilityAttention(
            "DigitalOcean availability could not be verified with the retained connection. Refresh the catalog and try again; no append started.") from None


def require_no_independent_mixed_append_bindings(engagement_id, *, jobs, domain_repository=None):
    """Keep fresh Review within the original four-host cleanup contract.

    Canonical core intent snapshots are not independent binding ownership.
    The established cleanup guard owns that distinction, including history.
    """
    from app.services.provider_keyed_mixed_published_teardown_collector import _empty_owned_bindings
    from app.storage.domain_repository import SqlAlchemyDomainRepository
    try:
        _empty_owned_bindings(engagement_id, jobs,
            domain_repository or SqlAlchemyDomainRepository())
    except Exception:
        raise MixedAppendAvailabilityAttention(
            "Review cross-provider edges before configuring independent channels, services, DNS or certificates. Existing bindings or unverified history block this Review; no append started.") from None
