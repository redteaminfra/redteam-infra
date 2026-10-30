# Copyright (c) 2026, Oracle and/or its affiliates.
"""Narrow read-only guard for retiring a Barragan-owned DigitalOcean selector.

The terminal provider absence receipt proves Barragan's droplets are gone.
DigitalOcean's aggregate tag count and complete firewall inventory then veto
other attachments without requesting inventory scopes Barragan does not use.
"""

from __future__ import annotations

from typing import Callable

from app.services.provider_catalog import ProviderCatalogTransport
from app.services.provider_keyed_digitalocean_absence import _ORIGIN
from app.services.provider_keyed_digitalocean_tag_eligibility import _complete_inventory
from app.services.provider_keyed_selector_reservation import _require_no_firewall_selector_use
from app.services.provider_keyed_selector_retirement import DeleteTransport


class PublishedSelectorGuardError(ValueError):
    """The reserved tag's exact absence or empty membership is unproved."""


def read_published_selector_guard(
    catalog: ProviderCatalogTransport, status: DeleteTransport,
    token: str, selector: str, fence: Callable[[], object],
) -> bool:
    """Return whether the tag exists, after fenced aggregate/firewall checks.

    A missing tag is already retired. A present tag with zero aggregate
    attachments may be deleted once a separate one-shot intent is durable.
    This does not make DigitalOcean's check/delete pair atomic.
    """
    try:
        fence()
        exact_status = status.get_tag_status(token, selector)
        fence()
        if type(exact_status) is not int or exact_status not in {200, 404}:
            raise ValueError("exact selector status differs")
        present = exact_status == 200
        if present:
            fence()
            body = catalog.request(_ORIGIN, "GET", f"/tags/{selector}", token)
            fence()
            if type(body) is not dict or type(body.get("tag")) is not dict:
                raise ValueError("exact tag body is incomplete")
            tag = body["tag"]
            resources = tag.get("resources")
            if (tag.get("name") != selector or type(resources) is not dict
                    or type(resources.get("count")) is not int
                    or resources["count"] != 0):
                raise ValueError("selector has an attachment or count is incomplete")
        firewalls = _complete_inventory(
            catalog, token, "/firewalls", "firewalls", {}, fence)
        _require_no_firewall_selector_use(firewalls, selector)
        fence()
        if status.get_tag_status(token, selector) != exact_status:
            raise ValueError("selector changed across inventory reads")
        fence()
        return present
    except Exception:
        raise PublishedSelectorGuardError(
            "published selector membership or exact status is unproved") from None
