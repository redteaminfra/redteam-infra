# Copyright (c) 2026, Oracle and/or its affiliates.
"""GET-only visibility snapshot for a destroyed keyed DigitalOcean selector.

The initial apply did not journal proof that Barragan created the tag. This
module therefore never authorizes deletion, even after complete empty reads.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.services.provider_keyed_destroy_absence_preflight import (
    _read_success_boundary, reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_digitalocean_absence import (
    DigitalOceanAbsenceEvidence, _ORIGIN,
    _require_destroy_fence,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class DigitalOceanTagEligibilityError(ValueError):
    """Tag ownership, read visibility or membership is uncertain."""


@dataclass(frozen=True)
class DigitalOceanTagEligibilityEvidence:
    selector_tag: str
    empty_state_sha256: str
    readable_types: tuple[str, ...]
    zero_membership: bool
    reviewed_selector_use: bool
    exclusive_creation_proven: bool = False
    delete_authorized: bool = False


_TYPES = (
    ("droplets", "/droplets", "droplets", {}),
    ("gpu_droplets", "/droplets", "droplets", {"type": "gpus"}),
    ("images", "/images", "images", {"private": "true"}),
    ("volumes", "/volumes", "volumes", {}),
    ("volume_snapshots", "/snapshots", "snapshots", {"resource_type": "volume"}),
)
# Database metadata can still positively veto deletion, but Barragan does not
# manage databases and does not require database:read for selector cleanup.
_COUNT_TYPES = ("droplets", "images", "volumes", "volume_snapshots", "databases")
_PAGE_SIZE = 200
_MAX_PAGES = 10000


def _complete_inventory(client: ProviderCatalogTransport, token: str, endpoint: str,
                        key: str, filters: dict[str, str], fence: Callable[[], None]) -> list[dict]:
    rows: list[dict] = []
    total = None
    seen: set[str] = set()
    suffix = "".join(f"&{name}={value}" for name, value in filters.items())
    size = _PAGE_SIZE
    for page in range(1, _MAX_PAGES + 1):
        path = f"{endpoint}?page={page}&per_page={size}{suffix}"
        fence()
        body = client.request(_ORIGIN, "GET", path, token)
        fence()
        # A redacted DevTest read observed snapshots:null, meta.total:0 and
        # no next page for this filter. Its exact links keys were not saved;
        # accept only this conservative, explicitly complete subset until a
        # read-only live shape fixture proves any broader representation.
        if (endpoint == "/snapshots" and key == "snapshots"
                and filters == {"resource_type": "volume"} and page == 1
                and type(body) is dict and body.get(key) is None):
            meta = body.get("meta")
            links = body.get("links")
            pages = links.get("pages", {}) if type(links) is dict else None
            if (set(body) == {key, "meta", "links"}
                    and type(meta) is dict and set(meta) == {"total"}
                    and type(meta["total"]) is int and meta["total"] == 0
                    and type(links) is dict and set(links) <= {"pages"}
                    and type(pages) is dict
                    and (not pages or pages == {"next": None})):
                return []
            raise DigitalOceanTagEligibilityError(
                "nullable snapshot inventory is not a complete empty page")
        if (type(body) is not dict or type(body.get(key)) is not list
                or type(body.get("meta")) is not dict
                or type(body["meta"].get("total")) is not int
                or body["meta"]["total"] < 0
                or type(body.get("links", {})) is not dict
                or type(body.get("links", {}).get("pages", {})) is not dict):
            raise DigitalOceanTagEligibilityError("provider inventory page is incomplete")
        items = body[key]
        if len(items) > size or (page > 1 and not items):
            raise DigitalOceanTagEligibilityError("provider inventory page is invalid")
        if total is None:
            total = body["meta"]["total"]
        elif total != body["meta"]["total"]:
            raise DigitalOceanTagEligibilityError("provider inventory changed during pagination")
        for row in items:
            identifier = row.get("id") if type(row) is dict else None
            if (type(identifier) not in (str, int) or not str(identifier)
                    or str(identifier) in seen):
                raise DigitalOceanTagEligibilityError("provider inventory identity is invalid")
            seen.add(str(identifier))
            rows.append(row)
        if len(rows) > total:
            raise DigitalOceanTagEligibilityError("provider inventory exceeds total")
        next_url = body.get("links", {}).get("pages", {}).get("next")
        if next_url is None:
            if len(rows) != total:
                raise DigitalOceanTagEligibilityError("provider inventory is truncated")
            return rows
        if len(rows) >= total or type(next_url) is not str:
            raise DigitalOceanTagEligibilityError("provider inventory next page is invalid")
        try:
            parsed = urlsplit(next_url)
            query = parse_qs(parsed.query, strict_parsing=True)
        except ValueError:
            raise DigitalOceanTagEligibilityError("provider inventory next page is unsafe") from None
        expected = {"page": [str(page + 1)], **{k: [v] for k, v in filters.items()}}
        if (parsed.scheme != "https" or parsed.netloc != "api.digitalocean.com"
                or parsed.path != f"/v2{endpoint}" or parsed.fragment
                or set(query) != set(expected) | {"per_page"}
                or any(query.get(k) != v for k, v in expected.items())
                or len(query["per_page"]) != 1
                or not query["per_page"][0].isdigit()):
            raise DigitalOceanTagEligibilityError("provider inventory next page is unsafe")
        next_size = int(query["per_page"][0])
        if not 1 <= next_size <= _PAGE_SIZE or (page > 1 and next_size != size):
            raise DigitalOceanTagEligibilityError("provider inventory page size differs")
        size = next_size
    raise DigitalOceanTagEligibilityError("provider inventory page bound exceeded")


def _empty_visible_tag_inventory(client: ProviderCatalogTransport, token: str,
                                 selector: str, fence: Callable[[], None]) -> tuple[str, ...]:
    """Require complete same-token reads of scoped taggable resource families."""
    readable = []
    for label, endpoint, key, filters in _TYPES:
        rows = _complete_inventory(client, token, endpoint, key, filters, fence)
        for row in rows:
            tags = row.get("tags")
            if (type(tags) is not list or any(type(item) is not str or not item for item in tags)
                    or len(tags) != len(set(tag.casefold() for tag in tags))):
                raise DigitalOceanTagEligibilityError("provider tag membership is incomplete")
            if label == "volume_snapshots" and row.get("resource_type") != "volume":
                raise DigitalOceanTagEligibilityError("snapshot resource type is unverified")
            if label == "images" and row.get("private") is not True:
                raise DigitalOceanTagEligibilityError("account image visibility is unverified")
            if any(tag.casefold() == selector.casefold() for tag in tags):
                raise DigitalOceanTagEligibilityError("selector still has a provider member")
        readable.append(label)
    fence()
    body = client.request(_ORIGIN, "GET", f"/tags/{selector}", token)
    fence()
    tag = body.get("tag") if type(body) is dict else None
    resources = tag.get("resources") if type(tag) is dict else None
    if (type(tag) is not dict or tag.get("name") != selector
            or type(resources) is not dict or type(resources.get("count")) is not int
            or resources["count"] != 0):
        raise DigitalOceanTagEligibilityError("selector tag identity or membership differs")
    for kind in _COUNT_TYPES:
        if kind in resources and (type(resources[kind]) is not dict
                                  or type(resources[kind].get("count")) is not int
                                  or resources[kind]["count"] != 0):
            raise DigitalOceanTagEligibilityError("selector tag type membership differs")
    # The per-type objects are optional in DO's schema. The independent 200
    # inventories above are required even when the aggregate count is zero.
    return tuple(readable)


def inspect_successful_digitalocean_tag_eligibility(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
    handoff_auditor: Callable = audit_pending_provider_keyed_bootstrap,
    credential_check: Callable = _credential_snapshot,
    absence_reconciler: Callable = reconcile_successful_digitalocean_destroy_absence,
    transport: ProviderCatalogTransport | None = None,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
) -> DigitalOceanTagEligibilityEvidence:
    """Read-only evidence; successful return is still *ineligible* for DELETE."""
    try:
        if (environment != "devtest" or state_root != _default_state_root()
                or not state_root.is_absolute() or state_root.resolve(strict=True) != state_root):
            raise ValueError("DevTest state root required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup

        def boundary():
            return _read_success_boundary(
                teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
                credentials=credentials, lookup=lookup,
                handoff_auditor=handoff_auditor,
                credential_check=credential_check, state_root=state_root,
            )

        before = boundary()
        client = transport or UrllibProviderCatalogTransport()
        absence = absence_reconciler(
            teardown_parent_id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            credential_repository=credentials, lease_lookup=lookup,
            handoff_auditor=handoff_auditor, credential_check=credential_check,
            transport=client,
        )
        if (type(absence) is not DigitalOceanAbsenceEvidence
                or absence.empty_state_sha256 != before.intent.empty_state_sha256
                or absence.selector_tag_cleanup_pending is not True
                or boundary() != before):
            raise ValueError("reviewed provider absence differs")
        def verified_encrypted():
            digest, updated_at, encrypted_value = credential_check(
                before.intent.credential_record_id, credentials)
            if ((digest, updated_at) != (before.intent.credential_secret_sha256,
                                         before.intent.credential_updated_at)
                    or type(encrypted_value) is not str or not encrypted_value):
                raise ValueError("provider credential changed")
            return encrypted_value

        encrypted = verified_encrypted()
        token = decrypt_secret(encrypted)
        if type(token) is not str or not token:
            raise ValueError("provider credential unavailable")
        def fence():
            if boundary() != before:
                raise ValueError("reviewed tag boundary changed")
            verified_encrypted()
            _require_destroy_fence(before.workspace, before.intent)

        readable = _empty_visible_tag_inventory(client, token, before.intent.selector_tag, fence)
        if boundary() != before:
            raise ValueError("reviewed tag boundary changed")
        verified_encrypted()
        _require_destroy_fence(before.workspace, before.intent)
        return DigitalOceanTagEligibilityEvidence(
            before.intent.selector_tag, before.intent.empty_state_sha256,
            readable, True, True,
        )
    except Exception:
        raise DigitalOceanTagEligibilityError(
            "selector cleanup visibility or ownership is unverified; no deletion was authorized"
        ) from None
