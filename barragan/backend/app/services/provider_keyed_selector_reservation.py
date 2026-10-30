# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot DigitalOcean selector creation and post-creation visibility gate.

Only a claimed initial apply may call this after journaling selector absence.
The caller journals intent *before* POST and the exact 201 receipt afterward.
An interrupted intent is deliberately not retryable.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol

from app.services.provider_catalog import ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.services.provider_keyed_selector_preflight import _ORIGIN, _SELECTOR


class SelectorReservationError(ValueError):
    """Creation or exclusive visibility is uncertain; never retry POST."""


@dataclass(frozen=True)
class ReservationResponse:
    status: int
    body: dict


class ReservationTransport(Protocol):
    def create_tag(self, token: str, selector: str) -> ReservationResponse: ...


class UrllibReservationTransport:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def create_tag(self, token: str, selector: str) -> ReservationResponse:
        request = urllib.request.Request(
            f"{_ORIGIN}/tags", method="POST",
            data=json.dumps({"name": selector}, separators=(",", ":")).encode(),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                     "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                payload = response.read(65537)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            raise SelectorReservationError("selector creation outcome is uncertain") from None
        if len(payload) > 65536:
            raise SelectorReservationError("selector creation response is oversized")
        try:
            body = json.loads(payload)
        except (ValueError, UnicodeError):
            raise SelectorReservationError("selector creation response is invalid") from None
        if type(body) is not dict:
            raise SelectorReservationError("selector creation response is invalid")
        return ReservationResponse(status, body)


def reserve_and_verify_selector(
    selector: str, token: str, *, fence: Callable[[], None],
    on_intent: Callable[[], None], on_receipt: Callable[[int, str], None],
    get_transport: ProviderCatalogTransport | None = None,
    post_transport: ReservationTransport | None = None,
) -> tuple[str, ...]:
    """Create exactly once, then prove the owned tag is empty and unused.

    A 201 only records creation. It never authorizes eventual deletion by itself.
    The independent same-token inventory check covers taggable resources and
    firewall selector references before Terraform is allowed to apply.
    """
    if (type(selector) is not str or _SELECTOR.fullmatch(selector) is None
            or type(token) is not str or not token):
        raise SelectorReservationError("selector reservation input is invalid")
    try:
        fence()
        on_intent()
        fence()
        response = (post_transport or UrllibReservationTransport()).create_tag(token, selector)
        if (type(response) is not ReservationResponse or type(response.status) is not int
                or response.status != 201 or type(response.body) is not dict
                or type(response.body.get("tag")) is not dict
                or response.body["tag"].get("name") != selector):
            raise SelectorReservationError("selector creation receipt is unverified")
        fence()
        on_receipt(response.status, selector)
        fence()
        client = get_transport or UrllibProviderCatalogTransport()
        # Imported after the apply-job module is initialized: the teardown
        # visibility helper has a reverse dependency through continuation.
        from app.services.provider_keyed_digitalocean_tag_eligibility import (
            _complete_inventory, _empty_visible_tag_inventory,
        )
        readable = _empty_visible_tag_inventory(client, token, selector, fence)
        _require_no_firewall_selector_use(
            _complete_inventory(client, token, "/firewalls", "firewalls", {}, fence), selector,
        )
        fence()
        return readable
    except Exception:
        raise SelectorReservationError("selector reservation or exclusive visibility is unverified") from None


def _require_no_firewall_selector_use(firewalls: list[dict], selector: str) -> None:
    """Include rule references, not only the firewall's top-level selector list."""
    for firewall in firewalls:
        if type(firewall) is not dict:
            raise SelectorReservationError("firewall inventory is incomplete")
        tags = firewall.get("tags")
        inbound = firewall.get("inbound_rules")
        outbound = firewall.get("outbound_rules")
        if ("inbound_rules" not in firewall or "outbound_rules" not in firewall
                or type(tags) is not list
                or (inbound is not None and type(inbound) is not list)
                or (outbound is not None and type(outbound) is not list)
                or any(type(tag) is not str or not tag for tag in tags)):
            raise SelectorReservationError("firewall inventory is incomplete")
        if any(tag.casefold() == selector.casefold() for tag in tags):
            raise SelectorReservationError("selector is used by a firewall")
        for rules, endpoint in ((inbound or [], "sources"), (outbound or [], "destinations")):
            for rule in rules:
                if type(rule) is not dict or type(rule.get(endpoint)) is not dict:
                    raise SelectorReservationError("firewall rule selector references are incomplete")
                references = rule[endpoint].get("tags", [])
                if type(references) is not list or any(type(tag) is not str or not tag for tag in references):
                    raise SelectorReservationError("firewall rule selector references are incomplete")
                if any(tag.casefold() == selector.casefold() for tag in references):
                    raise SelectorReservationError("selector is used by a firewall rule")
