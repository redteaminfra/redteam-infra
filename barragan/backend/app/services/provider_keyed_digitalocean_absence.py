# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only DevTest reconciliation after a complete keyed DigitalOcean destroy.

This helper has no runtime caller. Its evidence is a provider inventory snapshot,
not authorization to delete the remaining selector tag or mark core cleanup done.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.services.provider_keyed_initial_teardown import _SHARED
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.storage.credential_repository import CredentialRepository


_ORIGIN = "https://api.digitalocean.com/v2"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_SELECTOR = re.compile(r"^[a-z0-9][a-z0-9-]{7,62}$")
_DROPLET = re.compile(r"^[1-9][0-9]*$")
_NODE_ADDRESS = re.compile(r'^digitalocean_droplet\.(middle|edge)\["[A-Za-z0-9._-]+"\]$')
_FIREWALL = re.compile(r"^[0-9a-fA-F-]{36}$")
_PAGE_SIZE = 200
_MAX_PAGES = 10000


class DigitalOceanAbsenceError(ValueError):
    """Redacted failure: provider absence or reviewed identity is unverified."""


class _InventorySettling(DigitalOceanAbsenceError):
    """A changing provider listing may be retried within the polling bound."""


@dataclass(frozen=True)
class DigitalOceanAbsenceIntent:
    """Independently persisted pre-destroy identities and post-destroy fence."""

    resource_ids: Mapping[str, str]
    selector_tag: str
    pre_destroy_state_sha256: str
    state_lineage: str
    pre_destroy_serial: int
    empty_state_sha256: str
    destroy_phase_sha256: str
    credential_record_id: str
    credential_secret_sha256: str
    credential_updated_at: str


@dataclass(frozen=True)
class DigitalOceanAbsenceEvidence:
    empty_state_sha256: str
    verified_absent_droplet_ids: tuple[str, ...]
    verified_absent_firewall_id: str
    verified_absent_ssh_key_id: str
    selector_tag_cleanup_pending: bool
    attempts: int


def reconcile_digitalocean_keyed_destroy_absence(
    workspace: ProviderKeyedWorkspace,
    intent: DigitalOceanAbsenceIntent,
    *,
    environment: str,
    deployment_target: str,
    credential_repository: CredentialRepository,
    transport: ProviderCatalogTransport | None = None,
    max_attempts: int = 12,
    poll_interval_seconds: float = 5.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> DigitalOceanAbsenceEvidence:
    """Poll provider GET inventories until every reviewed resource is absent."""

    if environment != "devtest" or deployment_target != "barragan-testing":
        raise DigitalOceanAbsenceError("absence reconciliation requires DevTest disposable scope")
    if (not isinstance(workspace, ProviderKeyedWorkspace)
            or workspace.provider != "digitalocean" or workspace.schema != SCHEMA
            or not isinstance(intent, DigitalOceanAbsenceIntent)):
        raise DigitalOceanAbsenceError("absence reconciliation input is invalid")
    if (type(max_attempts) is not int or not 1 <= max_attempts <= 12
            or not isinstance(poll_interval_seconds, (int, float))
            or not math.isfinite(poll_interval_seconds)
            or not 0 <= poll_interval_seconds <= 10):
        raise DigitalOceanAbsenceError("absence polling bound is invalid")
    _validate_intent(workspace, intent)
    _require_destroy_fence(workspace, intent)
    client = transport or UrllibProviderCatalogTransport()
    for attempt in range(1, max_attempts + 1):
        encrypted = _credential(intent, credential_repository)
        try:
            token = decrypt_secret_value(encrypted)
        except Exception:
            raise DigitalOceanAbsenceError("provider credential is unavailable") from None
        if not token:
            raise DigitalOceanAbsenceError("provider credential is unavailable")
        try:
            settled, tag_pending = _inspect_once(client, token, intent)
        except _InventorySettling:
            settled, tag_pending = False, False
        except DigitalOceanAbsenceError:
            raise
        except Exception:
            settled, tag_pending = False, False  # bounded provider settling/transport retry
        finally:
            del token
        _credential(intent, credential_repository)
        _require_destroy_fence(workspace, intent)
        if settled:
            return DigitalOceanAbsenceEvidence(
                intent.empty_state_sha256,
                tuple(sorted(_owned_droplet_ids(intent))),
                intent.resource_ids["digitalocean_firewall.firewall"],
                intent.resource_ids["digitalocean_ssh_key.key"],
                tag_pending,
                attempt,
            )
        if attempt < max_attempts:
            sleeper(poll_interval_seconds)
    raise DigitalOceanAbsenceError("provider absence did not settle within the polling bound")


def _validate_intent(workspace: ProviderKeyedWorkspace, intent: DigitalOceanAbsenceIntent) -> None:
    if (workspace.path.is_symlink() or not workspace.path.is_dir()
            or workspace.path.resolve() != workspace.path
            or workspace.state_path != workspace.path / "terraform.tfstate"
            or intent.credential_record_id != workspace.provider_connection_id
            or not isinstance(intent.selector_tag, str)
            or not _SELECTOR.fullmatch(intent.selector_tag)
            or not all(isinstance(value, str) and _HASH.fullmatch(value) for value in (
                intent.pre_destroy_state_sha256, intent.empty_state_sha256,
                intent.destroy_phase_sha256, intent.credential_secret_sha256,
            ))
            or intent.pre_destroy_state_sha256 == intent.empty_state_sha256
            or type(intent.pre_destroy_serial) is not int or intent.pre_destroy_serial < 1):
        raise DigitalOceanAbsenceError("reviewed absence intent is invalid")
    try:
        UUID(intent.state_lineage)
    except (ValueError, TypeError, AttributeError):
        raise DigitalOceanAbsenceError("reviewed state lineage is invalid") from None
    if not isinstance(intent.resource_ids, Mapping):
        raise DigitalOceanAbsenceError("reviewed resource identities are invalid")
    addresses = set(intent.resource_ids)
    nodes = addresses - _SHARED
    if (not nodes or not all(isinstance(key, str) and _NODE_ADDRESS.fullmatch(key) for key in nodes)
            or addresses != nodes | _SHARED
            or any(not isinstance(value, str) or not value for value in intent.resource_ids.values())
            or any(not _DROPLET.fullmatch(intent.resource_ids[address]) for address in nodes)
            or len(_owned_droplet_ids(intent)) != len(nodes)
            or not _FIREWALL.fullmatch(intent.resource_ids["digitalocean_firewall.firewall"])
            or not _DROPLET.fullmatch(intent.resource_ids["digitalocean_ssh_key.key"])):
        raise DigitalOceanAbsenceError("reviewed resource identities are invalid")


def _owned_droplet_ids(intent: DigitalOceanAbsenceIntent) -> set[str]:
    return {value for address, value in intent.resource_ids.items() if _NODE_ADDRESS.fullmatch(address)}


def _require_destroy_fence(workspace: ProviderKeyedWorkspace, intent: DigitalOceanAbsenceIntent) -> None:
    try:
        if workspace.path.is_symlink() or workspace.path.resolve() != workspace.path:
            raise ValueError("workspace path changed")
        state_path = workspace.state_path
        phase_path = workspace.path / ".barragan-apply-phase.json"
        if (state_path.is_symlink() or phase_path.is_symlink()
                or _hash_file(state_path) != intent.empty_state_sha256
                or _hash_file(phase_path) != intent.destroy_phase_sha256):
            raise ValueError("fence hash changed")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        phase = json.loads(phase_path.read_text(encoding="utf-8"))
        if (phase != {"schema": SCHEMA, "phase": "destroy_applied"}
                or state.get("version") != 4 or state.get("terraform_version") != "1.15.5"
                or state.get("lineage") != intent.state_lineage
                or type(state.get("serial")) is not int
                or state["serial"] <= intent.pre_destroy_serial
                or state.get("resources") != []):
            raise ValueError("empty state invalid")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise DigitalOceanAbsenceError("retained destroy state or phase changed") from None


def _credential(intent: DigitalOceanAbsenceIntent, repository: CredentialRepository) -> str:
    try:
        digest, updated_at, encrypted = _credential_snapshot(intent.credential_record_id, repository)
    except Exception:
        raise DigitalOceanAbsenceError("provider connection is unavailable") from None
    if (digest, updated_at) != (intent.credential_secret_sha256, intent.credential_updated_at):
        raise DigitalOceanAbsenceError("provider credential changed since destroy")
    return encrypted


def _inspect_once(
    client: ProviderCatalogTransport, token: str, intent: DigitalOceanAbsenceIntent,
) -> tuple[bool, bool]:
    droplets = _inventory(client, token, "/droplets", "droplets")
    gpu_droplets = _inventory(client, token, "/droplets", "droplets", gpu_only=True)
    firewalls = _inventory(client, token, "/firewalls", "firewalls")
    keys = _inventory(client, token, "/account/keys", "ssh_keys")
    tags = _inventory(client, token, "/tags", "tags")
    owned_droplets = _owned_droplet_ids(intent)
    selector = intent.selector_tag
    for droplet in droplets + gpu_droplets:
        identifier = _identifier(droplet, _DROPLET)
        labels = _tags(droplet)
        if selector in labels and identifier not in owned_droplets:
            raise DigitalOceanAbsenceError("selector is attached to an unreviewed Droplet")
    for firewall in firewalls:
        identifier = _identifier(firewall, _FIREWALL)
        if selector in _tags(firewall) and identifier != intent.resource_ids["digitalocean_firewall.firewall"]:
            raise DigitalOceanAbsenceError("selector is attached to an unreviewed firewall")
    droplet_ids = {_identifier(row, _DROPLET) for row in droplets + gpu_droplets}
    firewall_ids = {_identifier(row, _FIREWALL) for row in firewalls}
    key_ids = {_identifier(row, _DROPLET) for row in keys}
    present = (bool(droplet_ids & owned_droplets)
               or intent.resource_ids["digitalocean_firewall.firewall"] in firewall_ids
               or intent.resource_ids["digitalocean_ssh_key.key"] in key_ids)
    matching_tags = [row for row in tags if isinstance(row, dict)
                     and isinstance(row.get("name"), str)
                     and row["name"].casefold() == selector.casefold()]
    if len(matching_tags) > 1:
        raise DigitalOceanAbsenceError("selector tag inventory is inconsistent")
    if matching_tags:
        tag = matching_tags[0]
        if tag["name"] != selector:
            raise DigitalOceanAbsenceError("selector tag identity differs")
        resources = tag.get("resources")
        if not isinstance(resources, dict) or type(resources.get("count")) is not int or resources["count"] < 0:
            raise DigitalOceanAbsenceError("selector tag resource count is unverified")
        if resources["count"]:
            return False, False
    return not present, bool(matching_tags)


def _inventory(
    client: ProviderCatalogTransport, token: str, endpoint: str, key: str, *, gpu_only: bool = False,
) -> list[dict]:
    rows: list[dict] = []
    total: int | None = None
    seen_ids: set[str] = set()
    suffix = "&type=gpus" if gpu_only else ""
    path = f"{endpoint}?page=1&per_page={_PAGE_SIZE}{suffix}"
    effective_page_size: int | None = None
    if gpu_only and endpoint != "/droplets":
        raise DigitalOceanAbsenceError("provider inventory filter is invalid")
    for page in range(1, _MAX_PAGES + 1):
        body = client.request(_ORIGIN, "GET", path, token)
        if not isinstance(body, dict) or not isinstance(body.get(key), list):
            raise DigitalOceanAbsenceError("provider inventory is incomplete")
        items = body[key]
        meta = body.get("meta")
        links = body.get("links", {})
        if (len(items) > (effective_page_size or _PAGE_SIZE) or not isinstance(meta, dict)
                or type(meta.get("total")) is not int or meta["total"] < 0
                or not isinstance(links, dict) or not isinstance(links.get("pages", {}), dict)):
            raise DigitalOceanAbsenceError("provider inventory pagination is invalid")
        if total is None:
            total = meta["total"]
        elif total != meta["total"]:
            raise _InventorySettling("provider inventory changed during pagination")
        for item in items:
            if not isinstance(item, dict):
                raise DigitalOceanAbsenceError("provider inventory item is invalid")
            identifier = item.get("name") if key == "tags" else item.get("id")
            if ((key == "tags" and (not isinstance(identifier, str) or not identifier))
                    or (key != "tags" and (type(identifier) not in (str, int) or not str(identifier)))):
                raise DigitalOceanAbsenceError("provider inventory item is invalid")
            normalized = str(identifier).casefold()
            if normalized in seen_ids:
                raise DigitalOceanAbsenceError("provider inventory repeats an item")
            seen_ids.add(normalized)
            rows.append(item)
        if len(rows) > total:
            raise DigitalOceanAbsenceError("provider inventory exceeds reported total")
        next_url = links.get("pages", {}).get("next")
        if next_url is None:
            if len(rows) != total:
                raise _InventorySettling("provider inventory was truncated")
            return rows
        if len(rows) >= total:
            raise DigitalOceanAbsenceError("provider inventory has an unreviewed next page")
        path, effective_page_size = _require_next_url(
            next_url, endpoint, page + 1,
            effective_page_size=effective_page_size, gpu_only=gpu_only,
        )
    raise DigitalOceanAbsenceError("provider inventory exceeded page bound")


def _require_next_url(
    value: object, endpoint: str, page: int, *,
    effective_page_size: int | None, gpu_only: bool,
) -> tuple[str, int]:
    if not isinstance(value, str):
        raise DigitalOceanAbsenceError("provider inventory next URL is unsafe")
    try:
        url = urlsplit(value)
        query = parse_qs(url.query, strict_parsing=True)
    except ValueError:
        raise DigitalOceanAbsenceError("provider inventory next URL is unsafe") from None
    keys = {"page", "per_page", "type"} if gpu_only else {"page", "per_page"}
    if (url.scheme != "https" or url.netloc != "api.digitalocean.com"
            or url.path != f"/v2{endpoint}" or url.fragment
            or set(query) != keys or query["page"] != [str(page)]
            or (gpu_only and query["type"] != ["gpus"])):
        raise DigitalOceanAbsenceError("provider inventory next URL is unsafe")
    sizes = query["per_page"]
    if len(sizes) != 1 or not sizes[0].isdigit():
        raise DigitalOceanAbsenceError("provider inventory next URL is unsafe")
    size = int(sizes[0])
    if (not 1 <= size <= _PAGE_SIZE
            or (effective_page_size is not None and size != effective_page_size)):
        raise DigitalOceanAbsenceError("provider inventory next URL is unsafe")
    return f"{endpoint}?page={page}&per_page={size}{'&type=gpus' if gpu_only else ''}", size


def _identifier(item: dict, pattern: re.Pattern[str]) -> str:
    identifier = item.get("id")
    if type(identifier) not in (str, int) or not pattern.fullmatch(str(identifier)):
        raise DigitalOceanAbsenceError("provider inventory identity is invalid")
    return str(identifier)


def _tags(item: dict) -> set[str]:
    value = item.get("tags")
    if not isinstance(value, list) or any(not isinstance(tag, str) for tag in value):
        raise DigitalOceanAbsenceError("provider resource tags are incomplete")
    return {tag.casefold() for tag in value}


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
