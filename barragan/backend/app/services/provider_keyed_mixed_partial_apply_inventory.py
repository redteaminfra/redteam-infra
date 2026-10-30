# Copyright (c) 2026, Oracle and/or its affiliates.
"""GET-only retained-state and provider observation for a sealed mixed Apply.

This snapshot deliberately does not assert a Terraform Apply outcome or grant
cleanup authority. The future Apply child must supply its exact journal and
claim fence when assembling an ApplyObservation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from app.integrations.linode_validation import UrllibLinodeTransport
from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_core_destroy_preview import _read_regular
from app.services.provider_keyed_digitalocean_absence import _inventory as _do_inventory
from app.services.provider_keyed_initial_plan_gate import _verify_audited_workspace
from app.services.provider_keyed_inspector_linode_cleanup import _complete_rows
from app.services.provider_keyed_linode_initial_plan_gate import _workspace as _verify_linode_workspace
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.services.provider_keyed_saved_plan_runner import _require_canonical_workspace_paths
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import StoredJobRun


class MixedPartialApplyInventoryAttention(ValueError):
    """The read-only snapshot is incomplete or changed during observation."""


class MixedPartialApplyInventorySettling(MixedPartialApplyInventoryAttention):
    """The selector count lags already visible, fully listed tagged Droplets."""


@dataclass(frozen=True)
class MixedPartialApplyInventorySnapshot:
    provider: str
    state_json: bytes | None
    state_sha256: str | None
    phase: str | None
    inventory: tuple[Mapping[str, object], ...]
    linode_firewall_attached_node_ids: tuple[str, ...] | None
    selector_tag_exists: bool | None
    selector_resources_count: int | None
    selector_attached_node_ids: tuple[str, ...] | None
    observation_sha256: str


def _file(path: Path) -> bytes | None:
    if path.is_symlink():
        raise ValueError("workspace file is a symlink")
    return _read_regular(path) if path.is_file() else None


def _local(workspace: ProviderKeyedWorkspace, *, phase_mode: str = "apply"):
    state = _file(workspace.state_path)
    raw_phase = _file(workspace.path / ".barragan-apply-phase.json")
    phase = None
    if raw_phase is not None:
        value = json.loads(raw_phase)
        allowed = ({"schema": SCHEMA, "phase": "destroy_applied"},) if phase_mode == "destroy_applied" else (
            {"schema": SCHEMA, "phase": "apply_started"},
            {"schema": SCHEMA, "phase": "applied"},
        )
        if value not in allowed:
            raise ValueError("retained Apply phase is invalid")
        phase = value["phase"]
    if state is None and phase is not None:
        # A command may have started without producing state. Keep the phase
        # for later journal reconciliation; the classifier returns uncertain.
        pass
    return state, phase, raw_phase


def _credential(repository, provider: str, policy: Mapping[str, object]) -> str:
    record = repository.get(policy["provider_connection_id"])
    default = repository.get_default(provider)
    if (record is None or default is None or record != default
            or record.provider != provider or record.status != "active"
            or record.is_default is not True
            or hashlib.sha256(record.encrypted_secret.encode()).hexdigest()
            != policy["credential_secret_sha256"]
            or record.updated_at != policy["credential_updated_at"]):
        raise ValueError("sealed provider credential changed")
    return record.encrypted_secret


def _linode(client, token: str, fence: Callable[[], str], policy):
    fence()
    instances = _complete_rows(client, token, "/linode/instances")
    fence()
    firewalls = _complete_rows(client, token, "/networking/firewalls")
    fence()
    rows = []
    for kind, collection in (("node", instances), ("firewall", firewalls)):
        for row in collection:
            label, tags = row.get("label"), row.get("tags")
            if type(label) is not str or type(tags) is not list or any(type(tag) is not str for tag in tags):
                raise ValueError("Linode identity is incomplete")
            rows.append({"kind": kind, "id": row["id"], "name": label, "tags": tags})
    name = f'fw-{policy["engagement_name"]}-firewall'
    selected = [row for row in firewalls if row.get("label") == name
                or policy["engagement_name"] in row.get("tags", [])]
    if len(selected) > 1:
        raise ValueError("Linode reviewed firewall is ambiguous")
    if not selected:
        return tuple(rows), ()
    firewall = selected[0]
    devices = _complete_rows(client, token, f'/networking/firewalls/{firewall["id"]}/devices')
    fence()
    ids = []
    for device in devices:
        entity = device.get("entity")
        if (type(entity) is not dict or entity.get("type") != "linode"
                or type(entity.get("id")) is not int):
            raise ValueError("Linode firewall has an unreviewed device attachment")
        ids.append(str(entity["id"]))
    if len(set(ids)) != len(ids):
        raise ValueError("Linode firewall device attachment repeats")
    return tuple(rows), tuple(sorted(ids))


def _digitalocean(client, token: str, selector: str, fence: Callable[[], str], *,
                  include_firewall_details: bool = False):
    def read(endpoint: str, key: str, *, gpu_only: bool = False):
        fence()
        rows = _do_inventory(client, token, endpoint, key, gpu_only=gpu_only)
        fence()
        return rows

    collections = (
        ("node", read("/droplets", "droplets")),
        ("node", read("/droplets", "droplets", gpu_only=True)),
        ("firewall", read("/firewalls", "firewalls")),
        ("ssh_key", read("/account/keys", "ssh_keys")),
    )
    tags = read("/tags", "tags")
    rows = []
    seen = set()
    attached = set()
    for kind, collection in collections:
        for row in collection:
            identifier = str(row["id"])
            if (kind, identifier) in seen:
                # The normal and GPU Droplet views must not overlap.
                raise ValueError("DigitalOcean inventory repeats a resource")
            seen.add((kind, identifier))
            name = row.get("name")
            labels = row.get("tags", [] if kind == "ssh_key" else None)
            if (type(name) is not str or type(labels) is not list
                    or any(type(tag) is not str for tag in labels)):
                raise ValueError("DigitalOcean identity is incomplete")
            normalized = {"kind": kind, "id": row["id"], "name": name, "tags": labels}
            if kind == "firewall" and include_firewall_details and selector in labels:
                normalized["firewall"] = row
            if kind == "ssh_key":
                if type(row.get("public_key")) is not str:
                    raise ValueError("DigitalOcean SSH key identity is incomplete")
                normalized["public_key"] = row["public_key"]
            if kind == "node" and selector in labels:
                attached.add(identifier)
            rows.append(normalized)
    selected = [tag for tag in tags if tag.get("name", "").casefold() == selector.casefold()]
    if len(selected) > 1 or (selected and selected[0].get("name") != selector):
        raise ValueError("DigitalOcean selector identity differs")
    count = 0
    if selected:
        resources = selected[0].get("resources")
        count = resources.get("count") if type(resources) is dict else None
        if type(count) is not int or count < 0:
            raise ValueError("DigitalOcean selector count is incomplete")
    if count > len(attached):
        # A tag-only POST remains visible with count zero, but any member in
        # a resource family outside Barragan's Droplets is ambiguous here.
        raise ValueError("DigitalOcean selector has an unreviewed attachment")
    return tuple(rows), bool(selected), count, tuple(sorted(attached))


class _FencedLinodeTransport:
    def __init__(self, inner, fence, expected):
        self.inner, self.fence, self.expected = inner, fence, expected

    def request(self, method, path, token, body=None):
        if method != "GET" or body is not None or self.fence() != self.expected:
            raise ValueError("Linode snapshot fence changed")
        result = self.inner.request(method, path, token)
        if self.fence() != self.expected:
            raise ValueError("Linode snapshot fence changed")
        return result


class _FencedDigitalOceanTransport:
    def __init__(self, inner, fence, expected):
        self.inner, self.fence, self.expected = inner, fence, expected

    def request(self, origin, method, path, token):
        if method != "GET" or self.fence() != self.expected:
            raise ValueError("DigitalOcean snapshot fence changed")
        result = self.inner.request(origin, method, path, token)
        if self.fence() != self.expected:
            raise ValueError("DigitalOcean snapshot fence changed")
        return result


def collect_provider_inventory_snapshot(
    parent: StoredJobRun, provider: str, workspace: ProviderKeyedWorkspace, *,
    fence: Callable[[], str], process_quiescent: Callable[[], bool],
    credential_repository=None, linode_transport=None, digitalocean_transport=None,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
    phase_mode: str = "apply",
) -> MixedPartialApplyInventorySnapshot:
    """Read one sealed provider under a caller-authenticated journal/claim fence."""
    try:
        seal = validate_mixed_initial_apply_seal(parent)
        if (phase_mode not in {"apply", "destroy_applied"}
                or provider not in seal["orderedProviders"]
                or not isinstance(workspace, ProviderKeyedWorkspace)
                or workspace.schema != SCHEMA or workspace.provider != provider
                or not callable(fence) or not callable(process_quiescent)):
            raise ValueError("provider snapshot boundary differs")
        policy = seal["reviewedPolicy"][provider]
        if workspace.provider_connection_id != policy["provider_connection_id"]:
            raise ValueError("workspace provider connection differs")
        _require_canonical_workspace_paths(workspace)
        if provider == "linode":
            _verify_linode_workspace(workspace)
        else:
            _verify_audited_workspace(workspace)
        repository = credential_repository or SqlAlchemyCredentialRepository()
        encrypted = _credential(repository, provider, policy)
        token = decrypt_secret(encrypted)
        if type(token) is not str or not token:
            raise ValueError("provider credential is unavailable")
        before_fence = fence()
        if type(before_fence) is not str or not before_fence or process_quiescent() is not True:
            raise ValueError("Apply command may still be running")
        before = _local(workspace, phase_mode=phase_mode)
        if provider == "linode":
            inventory, linode_attached = _linode(
                _FencedLinodeTransport(linode_transport or UrllibLinodeTransport(),
                                       fence, before_fence), token, fence, policy)
            selector_exists = selector_count = selector_attached = None
        else:
            inventory, selector_exists, selector_count, selector_attached = _digitalocean(
                _FencedDigitalOceanTransport(
                    digitalocean_transport or UrllibProviderCatalogTransport(),
                    fence, before_fence), token,
                policy["selector_tag"], fence)
            linode_attached = None
        if (fence() != before_fence or process_quiescent() is not True
                or _local(workspace, phase_mode=phase_mode) != before
                or _credential(repository, provider, policy) != encrypted):
            raise ValueError("provider snapshot changed during read")
        state, phase, _ = before
        summary = {"provider": provider, "stateSha256": hashlib.sha256(state).hexdigest()
                   if state is not None else None, "phase": phase, "inventory": inventory,
                   "linodeAttachments": linode_attached, "selectorExists": selector_exists,
                   "selectorCount": selector_count, "selectorAttachments": selector_attached,
                   "fence": before_fence}
        digest = hashlib.sha256(json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if provider == "digitalocean" and selector_count < len(selector_attached):
            # The after-read fence, credential, process, and state checks above
            # have completed. Caller may take another complete snapshot.
            raise MixedPartialApplyInventorySettling("DigitalOcean selector count is settling")
        return MixedPartialApplyInventorySnapshot(
            provider, state, summary["stateSha256"], phase, inventory,
            linode_attached, selector_exists, selector_count, selector_attached, digest)
    except MixedPartialApplyInventorySettling:
        raise
    except Exception:
        # Transport exceptions can include provider response bodies or tokens.
        raise MixedPartialApplyInventoryAttention(
            "mixed provider inventory or retained state requires review") from None
