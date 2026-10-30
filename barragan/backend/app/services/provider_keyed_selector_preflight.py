# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, new-state DigitalOcean firewall selector availability check.

This is an advisory gate for a fresh selector. Callers must repeat it close to
apply and inspect actual attachments afterward; provider inventories are not a
transactional reservation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.storage.credential_repository import CredentialRepository, SqlAlchemyCredentialRepository


_ORIGIN = "https://api.digitalocean.com/v2"
_SELECTOR = re.compile(r"^[a-z0-9][a-z0-9-]{7,62}$")
_PAGE_SIZE = 200
_MAX_PAGES = 10000


class SelectorPreflightError(ValueError):
    """The selector is occupied or its account-wide availability is unknown."""


@dataclass(frozen=True)
class SelectorPreflightEvidence:
    tags_checked: int
    firewalls_checked: int
    droplets_checked: int


def require_new_digitalocean_selector_available(
    selector: str,
    engagement_tag: str,
    expected_provider_connection_id: str,
    *,
    repository: CredentialRepository | None = None,
    transport: ProviderCatalogTransport | None = None,
) -> SelectorPreflightEvidence:
    """Reject any selector already attached to a firewall or Droplet.

    The credential is the centrally managed active default, not the requesting
    operator's token. No secret, resource identifier, or provider error body is
    included in returned evidence or exceptions.
    """

    if not isinstance(selector, str) or not _SELECTOR.fullmatch(selector):
        raise SelectorPreflightError("invalid DigitalOcean selector")
    if not isinstance(engagement_tag, str) or selector == engagement_tag:
        raise SelectorPreflightError("selector must differ from engagement tag")
    if not isinstance(expected_provider_connection_id, str) or not expected_provider_connection_id:
        raise SelectorPreflightError("provider connection is unavailable")

    try:
        credential = (repository or SqlAlchemyCredentialRepository()).get_default("digitalocean")
    except Exception:
        raise SelectorPreflightError("provider connection is unavailable") from None
    if (
        credential is None
        or credential.id != expected_provider_connection_id
        or credential.provider != "digitalocean"
        or credential.status != "active"
        or not credential.is_default
    ):
        raise SelectorPreflightError("provider connection changed or is unavailable")
    try:
        token = decrypt_secret_value(credential.encrypted_secret)
    except Exception:
        raise SelectorPreflightError("provider credential is unavailable") from None
    if not token:
        raise SelectorPreflightError("provider credential is unavailable")

    client = transport or UrllibProviderCatalogTransport()
    tags_checked = _scan_endpoint("tags", selector, token, client)
    firewalls_checked = _scan_endpoint("firewalls", selector, token, client)
    droplets_checked = _scan_endpoint("droplets", selector, token, client)
    # DigitalOcean excludes GPU Droplets from the default list. Its type=gpus
    # filter cannot be combined with tag_name, so inspect that inventory too.
    droplets_checked += _scan_endpoint("droplets", selector, token, client, gpu_only=True)
    return SelectorPreflightEvidence(tags_checked, firewalls_checked, droplets_checked)


def _scan_endpoint(
    kind: str, selector: str, token: str, transport: ProviderCatalogTransport, *, gpu_only: bool = False,
) -> int:
    if gpu_only and kind != "droplets":
        raise SelectorPreflightError("provider inventory filter is invalid")
    suffix = "&type=gpus" if gpu_only else ""
    path = f"/{kind}?page=1&per_page={_PAGE_SIZE}{suffix}"
    effective_page_size: int | None = None
    seen_paths: set[str] = set()
    seen_ids: set[str] = set()
    count = 0
    total: int | None = None
    for page in range(1, _MAX_PAGES + 1):
        if path in seen_paths:
            raise SelectorPreflightError("provider inventory pagination loop")
        seen_paths.add(path)
        try:
            body = transport.request(_ORIGIN, "GET", path, token)
        except Exception:
            raise SelectorPreflightError("provider inventory request failed") from None
        if not isinstance(body, dict) or not isinstance(body.get(kind), list):
            raise SelectorPreflightError("provider inventory response is incomplete")
        meta = body.get("meta")
        if not isinstance(meta, dict) or type(meta.get("total")) is not int or meta["total"] < 0:
            raise SelectorPreflightError("provider inventory total is missing")
        if total is None:
            total = meta["total"]
        elif meta["total"] != total:
            raise SelectorPreflightError("provider inventory changed during pagination")
        items = body[kind]
        if len(items) > _PAGE_SIZE or (page > 1 and not items):
            raise SelectorPreflightError("provider inventory page is malformed")
        for item in items:
            if not isinstance(item, dict):
                raise SelectorPreflightError("provider inventory item is malformed")
            if kind == "tags":
                identifier = item.get("name")
                if not isinstance(identifier, str) or not identifier:
                    raise SelectorPreflightError("provider inventory item is malformed")
                occupied = identifier.casefold() == selector.casefold()
            else:
                identifier = item.get("id")
                tags = item.get("tags")
                if (
                    not isinstance(identifier, (str, int)) or isinstance(identifier, bool) or not str(identifier)
                    or not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags)
                ):
                    raise SelectorPreflightError("provider inventory item is malformed")
                occupied = any(tag.casefold() == selector.casefold() for tag in tags)
            identity = str(identifier).casefold()
            if identity in seen_ids:
                raise SelectorPreflightError("provider inventory item is malformed")
            seen_ids.add(identity)
            if occupied:
                raise SelectorPreflightError("selector is already used by a provider resource")
        count += len(items)
        if count > total:
            raise SelectorPreflightError("provider inventory exceeds reported total")
        links = body.get("links", {})
        if not isinstance(links, dict):
            raise SelectorPreflightError("provider inventory pagination is malformed")
        pages = links.get("pages", {})
        if not isinstance(pages, dict):
            raise SelectorPreflightError("provider inventory pagination is malformed")
        next_url = pages.get("next")
        if next_url is None:
            if count != total:
                raise SelectorPreflightError("provider inventory is truncated")
            return count
        if count >= total:
            raise SelectorPreflightError("provider inventory pagination is malformed")
        path, effective_page_size = _validated_next_path(
            next_url, kind, page + 1, effective_page_size, gpu_only=gpu_only,
        )
    raise SelectorPreflightError("provider inventory exceeds page limit")


def _validated_next_path(
    value: Any, kind: str, expected_page: int, effective_page_size: int | None, *, gpu_only: bool = False,
) -> tuple[str, int]:
    if not isinstance(value, str):
        raise SelectorPreflightError("provider inventory next URL is unsafe")
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise SelectorPreflightError("provider inventory next URL is unsafe") from None
    if (
        parsed.scheme != "https"
        or parsed.netloc != "api.digitalocean.com"
        or parsed.path != f"/v2/{kind}"
        or parsed.fragment
    ):
        raise SelectorPreflightError("provider inventory next URL is unsafe")
    try:
        query = parse_qs(parsed.query, strict_parsing=True)
    except ValueError:
        raise SelectorPreflightError("provider inventory next URL is unsafe") from None
    expected_keys = {"page", "per_page", "type"} if gpu_only else {"page", "per_page"}
    if (set(query) != expected_keys or query["page"] != [str(expected_page)]
            or (gpu_only and query["type"] != ["gpus"])):
        raise SelectorPreflightError("provider inventory next URL is unsafe")
    sizes = query["per_page"]
    if len(sizes) != 1 or not sizes[0].isdigit():
        raise SelectorPreflightError("provider inventory next URL is unsafe")
    page_size = int(sizes[0])
    if not 1 <= page_size <= _PAGE_SIZE or (effective_page_size is not None and page_size != effective_page_size):
        raise SelectorPreflightError("provider inventory next URL is unsafe")
    suffix = "&type=gpus" if gpu_only else ""
    return f"/{kind}?page={expected_page}&per_page={page_size}{suffix}", page_size
