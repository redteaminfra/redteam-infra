# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only provider reconciliation after a fresh keyed DigitalOcean apply.

This DevTest-only helper has no runtime caller. It checks provider firewall
membership and policy, not active UFW, listeners, or external reachability.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import urllib.error
from uuid import UUID
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import ProviderCatalogError, ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.storage.credential_repository import CredentialRepository


_ORIGIN = "https://api.digitalocean.com/v2"
_DROPLET_ID = re.compile(r"^[1-9][0-9]*$")
_FIREWALL_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_NODE_ADDRESS = re.compile(r'^digitalocean_droplet\.(middle|edge)\["[A-Za-z0-9._-]+"\]$')


class DigitalOceanAttachmentError(ValueError):
    """Provider evidence is incomplete or differs from the reviewed policy."""


class DigitalOceanAttachmentStillSettling(DigitalOceanAttachmentError):
    """Bounded GET polling ended without a hard identity or policy mismatch."""


@dataclass(frozen=True)
class ExpectedDigitalOceanNode:
    address: str
    droplet_id: str
    name: str
    region: str
    public_ipv4: str


@dataclass(frozen=True)
class DigitalOceanAttachmentIntent:
    state_sha256: str
    firewall_id: str
    firewall_name: str
    selector_tag: str
    trusted_ssh_cidrs: tuple[str, ...]
    nodes: tuple[ExpectedDigitalOceanNode, ...]
    credential_record_id: str
    credential_secret_sha256: str
    credential_updated_at: str


@dataclass(frozen=True)
class DigitalOceanAttachmentEvidence:
    state_sha256: str
    firewall_id: str
    verified_droplet_ids: tuple[str, ...]
    attempts: int
    provider_membership_verified: bool = True
    host_policy_verified: bool = False


def reconcile_digitalocean_initial_attachment(
    workspace: ProviderKeyedWorkspace,
    intent: DigitalOceanAttachmentIntent,
    *,
    environment: str,
    deployment_target: str,
    credential_repository: CredentialRepository,
    transport: ProviderCatalogTransport | None = None,
    max_attempts: int = 12,
    poll_interval_seconds: float = 5.0,
    sleeper: Callable[[float], None] = time.sleep,
    expected_phase: str = "applied",
) -> DigitalOceanAttachmentEvidence:
    """Poll only provider GETs until fresh attachment propagation settles.

    The caller must construct ``intent`` from independently persisted draft
    policy and the exact state hash/identities verified after apply. Provider
    inventory is a snapshot; repeat this check close to declaring readiness or
    adding union ports, because membership can change after it returns.
    """

    if (environment != "devtest" or deployment_target != "barragan-testing"
            or expected_phase not in {"applied", "destroy_started"}):
        raise DigitalOceanAttachmentError("attachment reconciliation requires DevTest disposable scope")
    if (not isinstance(workspace, ProviderKeyedWorkspace) or workspace.provider != "digitalocean"
            or workspace.schema != SCHEMA or not isinstance(intent, DigitalOceanAttachmentIntent)):
        raise DigitalOceanAttachmentError("attachment reconciliation input is invalid")
    if type(max_attempts) is not int or not 1 <= max_attempts <= 12 or not 0 <= poll_interval_seconds <= 10:
        raise DigitalOceanAttachmentError("attachment polling bound is invalid")
    _validate_intent(workspace, intent)
    state_hash = _require_state_identity(workspace, intent, expected_phase=expected_phase)
    client = transport or UrllibProviderCatalogTransport()
    for attempt in range(1, max_attempts + 1):
        digest, updated_at, encrypted = _credential(intent, credential_repository)
        try:
            token = decrypt_secret_value(encrypted)
        except Exception:
            raise DigitalOceanAttachmentError("provider credential is unavailable") from None
        if not token:
            raise DigitalOceanAttachmentError("provider credential is unavailable")
        try:
            settled = _inspect_once(client, token, intent)
        except DigitalOceanAttachmentError:
            raise
        except Exception as exc:
            if _is_http_authorization_failure(exc):
                raise DigitalOceanAttachmentError("provider credential was rejected") from None
            settled = False  # bounded retry for provider transport/transient failure
        finally:
            del token
        _credential(intent, credential_repository)
        if (_hash_file(workspace.state_path) != state_hash
                or _require_state_identity(workspace, intent, expected_phase=expected_phase) != state_hash):
            raise DigitalOceanAttachmentError("retained Terraform state changed during reconciliation")
        if settled:
            return DigitalOceanAttachmentEvidence(
                state_hash, intent.firewall_id,
                tuple(sorted(node.droplet_id for node in intent.nodes)), attempt,
            )
        if attempt < max_attempts:
            sleeper(poll_interval_seconds)
    raise DigitalOceanAttachmentStillSettling("provider attachment did not settle within the polling bound")


def require_digitalocean_pre_destroy_membership(
    workspace: ProviderKeyedWorkspace,
    intent: DigitalOceanAttachmentIntent,
    *,
    environment: str,
    deployment_target: str,
    credential_repository: CredentialRepository,
    transport: ProviderCatalogTransport | None = None,
    expected_phase: str = "applied",
) -> None:
    """One-shot GET veto for current membership immediately before destroy.

    This does not authorize any address or ID outside the independently
    confirmed teardown scope. A provider still settling, incomplete listing,
    or transport failure vetoes execution; there is no mutation or retry here.
    """
    if (environment != "devtest" or deployment_target != "barragan-testing"
            or expected_phase not in {"applied", "destroy_started"}):
        raise DigitalOceanAttachmentError("pre-destroy membership requires DevTest disposable scope")
    if (not isinstance(workspace, ProviderKeyedWorkspace) or workspace.provider != "digitalocean"
            or workspace.schema != SCHEMA or not isinstance(intent, DigitalOceanAttachmentIntent)):
        raise DigitalOceanAttachmentError("pre-destroy membership input is invalid")
    _validate_intent(workspace, intent)
    _require_state_identity(workspace, intent, expected_phase=expected_phase)
    _, _, encrypted = _credential(intent, credential_repository)
    try:
        token = decrypt_secret_value(encrypted)
    except Exception:
        raise DigitalOceanAttachmentError("provider credential is unavailable") from None
    if not token:
        raise DigitalOceanAttachmentError("provider credential is unavailable")
    try:
        client = transport or UrllibProviderCatalogTransport()
        tagged_ids = _selector_droplet_ids(client, token, intent.selector_tag)
        expected_ids = {node.droplet_id for node in intent.nodes}
        if tagged_ids != expected_ids:
            raise DigitalOceanAttachmentError("pre-destroy selector membership differs from confirmed Droplets")
        firewall = _request(client, f"/firewalls/{intent.firewall_id}", token).get("firewall")
        if (not isinstance(firewall, dict) or firewall.get("id") != intent.firewall_id
                or firewall.get("name") != intent.firewall_name
                or firewall.get("tags") != [intent.selector_tag]
                or firewall.get("droplet_ids") != []):
            raise DigitalOceanAttachmentError("pre-destroy firewall membership differs from confirmed selector")
        if firewall.get("status") != "succeeded" or firewall.get("pending_changes") != []:
            raise DigitalOceanAttachmentError("pre-destroy firewall membership is not settled")
    except DigitalOceanAttachmentError:
        raise
    except Exception:
        raise DigitalOceanAttachmentError("pre-destroy provider membership is unverified") from None
    finally:
        del token
    _credential(intent, credential_repository)
    _require_state_identity(workspace, intent, expected_phase=expected_phase)


def _is_http_authorization_failure(exc: Exception) -> bool:
    cause = exc.__cause__ if isinstance(exc, ProviderCatalogError) else exc
    return isinstance(cause, urllib.error.HTTPError) and cause.code in (401, 403)


def _validate_intent(workspace: ProviderKeyedWorkspace, intent: DigitalOceanAttachmentIntent) -> None:
    if (workspace.path.is_symlink() or not workspace.path.is_dir()
            or workspace.path.resolve() != workspace.path
            or workspace.state_path != workspace.path / "terraform.tfstate"
            or not _HASH.fullmatch(intent.state_sha256)
            or not _FIREWALL_ID.fullmatch(intent.firewall_id)
            or not intent.firewall_name or not isinstance(intent.selector_tag, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{7,62}", intent.selector_tag)
            or not intent.nodes or not intent.trusted_ssh_cidrs
            or intent.credential_record_id != workspace.provider_connection_id):
        raise DigitalOceanAttachmentError("reviewed attachment intent is invalid")
    ids: set[str] = set()
    addresses: set[str] = set()
    for node in intent.nodes:
        if (not isinstance(node, ExpectedDigitalOceanNode)
                or not _NODE_ADDRESS.fullmatch(node.address)
                or not _DROPLET_ID.fullmatch(node.droplet_id)
                or not node.name or not node.region):
            raise DigitalOceanAttachmentError("reviewed node intent is invalid")
        try:
            if ipaddress.ip_address(node.public_ipv4).version != 4:
                raise ValueError("not IPv4")
        except ValueError:
            raise DigitalOceanAttachmentError("reviewed node address is invalid") from None
        if node.droplet_id in ids or node.address in addresses:
            raise DigitalOceanAttachmentError("reviewed node identity repeats")
        ids.add(node.droplet_id)
        addresses.add(node.address)
    try:
        if (len(set(intent.trusted_ssh_cidrs)) != len(intent.trusted_ssh_cidrs)
                or any(ipaddress.ip_network(cidr, strict=True).version != 4
                       or not cidr.endswith("/32") for cidr in intent.trusted_ssh_cidrs)):
            raise ValueError("not trusted IPv4 host")
    except ValueError:
        raise DigitalOceanAttachmentError("reviewed SSH source policy is invalid") from None


def _require_state_identity(
    workspace: ProviderKeyedWorkspace, intent: DigitalOceanAttachmentIntent,
    *, expected_phase: str = "applied",
) -> str:
    path = workspace.state_path
    if path.is_symlink() or not path.is_file() or _hash_file(path) != intent.state_sha256:
        raise DigitalOceanAttachmentError("retained Terraform state differs from reviewed state")
    try:
        phase_path = workspace.path / ".barragan-apply-phase.json"
        if phase_path.is_symlink():
            raise ValueError("unsafe phase")
        phase = json.loads(phase_path.read_text(encoding="utf-8"))
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or not isinstance(state.get("lineage"), str):
            raise ValueError("missing lineage")
        UUID(state["lineage"])
        resources = state["resources"]
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise DigitalOceanAttachmentError("retained Terraform state is invalid") from None
    if (phase != {"schema": SCHEMA, "phase": expected_phase} or not isinstance(resources, list)
            or state.get("version") != 4 or type(state.get("serial")) is not int
            or state["serial"] < 1):
        raise DigitalOceanAttachmentError("retained Terraform state is invalid")
    actual: dict[str, Mapping[str, object]] = {}
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("instances"), list):
            raise DigitalOceanAttachmentError("retained Terraform state is invalid")
        base = f'{resource.get("type")}.{resource.get("name")}'
        for instance in resource["instances"]:
            if not isinstance(instance, dict) or not isinstance(instance.get("attributes"), dict):
                raise DigitalOceanAttachmentError("retained Terraform state is invalid")
            key = instance.get("index_key")
            address = f"{base}[{json.dumps(key)}]" if isinstance(key, str) else base
            if address in actual:
                raise DigitalOceanAttachmentError("retained Terraform state repeats a resource")
            actual[address] = instance["attributes"]
    for node in intent.nodes:
        value = actual.get(node.address)
        if (not isinstance(value, dict) or str(value.get("id")) != node.droplet_id
                or value.get("name") != node.name or value.get("region") != node.region
                or value.get("ipv4_address") != node.public_ipv4
                or value.get("tags") != [intent.selector_tag]):
            raise DigitalOceanAttachmentError("retained node differs from reviewed identity")
    firewall = actual.get("digitalocean_firewall.firewall")
    if (not isinstance(firewall, dict) or firewall.get("id") != intent.firewall_id
            or firewall.get("name") != intent.firewall_name
            or firewall.get("tags") != [intent.selector_tag]):
        raise DigitalOceanAttachmentError("retained firewall differs from reviewed identity")
    relevant = {address for address in actual if address.startswith(("digitalocean_droplet.", "digitalocean_firewall."))}
    expected = {node.address for node in intent.nodes} | {"digitalocean_firewall.firewall"}
    if relevant != expected:
        raise DigitalOceanAttachmentError("retained provider resources differ from reviewed identity")
    return intent.state_sha256


def _credential(intent: DigitalOceanAttachmentIntent, repository: CredentialRepository) -> tuple[str, str, str]:
    try:
        digest, updated_at, encrypted = _credential_snapshot(intent.credential_record_id, repository)
    except Exception:
        raise DigitalOceanAttachmentError("provider connection is unavailable") from None
    if (digest != intent.credential_secret_sha256 or updated_at != intent.credential_updated_at):
        raise DigitalOceanAttachmentError("provider credential changed since apply")
    return digest, updated_at, encrypted


def _inspect_once(client: ProviderCatalogTransport, token: str, intent: DigitalOceanAttachmentIntent) -> bool:
    firewall = _request(client, f"/firewalls/{intent.firewall_id}", token).get("firewall")
    if not isinstance(firewall, dict) or firewall.get("id") != intent.firewall_id:
        raise DigitalOceanAttachmentError("provider firewall identity is unverified")
    if firewall.get("status") == "failed":
        raise DigitalOceanAttachmentError("provider firewall reported failed status")
    if firewall.get("status") != "succeeded" or firewall.get("pending_changes") != []:
        return False
    _require_firewall_policy(firewall, intent)
    explicit_members = firewall.get("droplet_ids")
    if explicit_members != []:
        raise DigitalOceanAttachmentError("provider firewall has unreviewed explicit Droplet members")
    tagged_ids = _selector_droplet_ids(client, token, intent.selector_tag)
    expected_ids = {node.droplet_id for node in intent.nodes}
    if tagged_ids - expected_ids:
        raise DigitalOceanAttachmentError("selector includes an unreviewed Droplet")
    if tagged_ids != expected_ids:
        return False
    for node in intent.nodes:
        droplet = _request(client, f"/droplets/{node.droplet_id}", token).get("droplet")
        if not isinstance(droplet, dict):
            raise DigitalOceanAttachmentError("provider Droplet identity is unverified")
        region = droplet.get("region")
        if (str(droplet.get("id")) != node.droplet_id
                or droplet.get("name") != node.name
                or not isinstance(region, dict) or region.get("slug") != node.region
                or droplet.get("tags") != [intent.selector_tag]):
            raise DigitalOceanAttachmentError("provider Droplet differs from reviewed identity")
        if droplet.get("status") != "active":
            return False
        memberships = _request(
            client, f"/droplets/{node.droplet_id}/firewalls?page=1&per_page=200", token,
        )
        firewalls = memberships.get("firewalls")
        if not isinstance(firewalls, list):
            raise DigitalOceanAttachmentError("provider firewall membership is incomplete")
        meta = memberships.get("meta")
        links = memberships.get("links", {})
        if not isinstance(meta, dict) or type(meta.get("total")) is not int or meta["total"] < 0:
            raise DigitalOceanAttachmentError("Droplet firewall membership total is unverified")
        if meta["total"] > 1:
            raise DigitalOceanAttachmentError("Droplet has overlapping provider firewalls")
        if not isinstance(links, dict) or not isinstance(links.get("pages", {}), dict):
            raise DigitalOceanAttachmentError("Droplet firewall membership pagination is unverified")
        if links.get("pages", {}).get("next") is not None:
            raise DigitalOceanAttachmentError("Droplet firewall membership has additional pages")
        if len(firewalls) > 1:
            raise DigitalOceanAttachmentError("Droplet has overlapping provider firewalls")
        if not firewalls and meta["total"] == 0:
            return False
        if len(firewalls) != meta["total"]:
            raise DigitalOceanAttachmentError("Droplet firewall membership total differs")
        if not isinstance(firewalls[0], dict) or firewalls[0].get("id") != intent.firewall_id:
            raise DigitalOceanAttachmentError("Droplet firewall membership differs from reviewed policy")
    return True


def _selector_droplet_ids(client: ProviderCatalogTransport, token: str, selector: str) -> set[str]:
    """Inventory non-GPU tagged Droplets and all GPU Droplets separately.

    DigitalOcean's `tag_name` and `type=gpus` filters cannot be combined, and
    the default list excludes GPU Droplets. A tag-only query is insufficient.
    """

    found: set[str] = set()
    for query, filtered in ((f"tag_name={selector}", True), ("type=gpus", False)):
        total: int | None = None
        seen: set[str] = set()
        for page in range(1, 10001):
            body = _request(client, f"/droplets?page={page}&per_page=200&{query}", token)
            rows = body.get("droplets")
            meta = body.get("meta")
            if (not isinstance(rows, list) or not isinstance(meta, dict)
                    or type(meta.get("total")) is not int or meta["total"] < 0
                    or len(rows) > 200):
                raise DigitalOceanAttachmentError("provider Droplet inventory is incomplete")
            if total is None:
                total = meta["total"]
            elif total != meta["total"]:
                raise DigitalOceanAttachmentError("provider Droplet inventory changed during pagination")
            for item in rows:
                if not isinstance(item, dict):
                    raise DigitalOceanAttachmentError("provider Droplet inventory item is invalid")
                identifier = item.get("id")
                tags = item.get("tags")
                if (type(identifier) not in (str, int) or not _DROPLET_ID.fullmatch(str(identifier))
                        or not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags)):
                    raise DigitalOceanAttachmentError("provider Droplet inventory item is invalid")
                normalized = str(identifier)
                if normalized in seen:
                    raise DigitalOceanAttachmentError("provider Droplet inventory repeats an ID")
                seen.add(normalized)
                tagged = any(tag.casefold() == selector.casefold() for tag in tags)
                if filtered and not tagged:
                    raise DigitalOceanAttachmentError("provider tag-filtered inventory is inconsistent")
                if tagged:
                    found.add(normalized)
            if len(seen) > total:
                raise DigitalOceanAttachmentError("provider Droplet inventory exceeds reported total")
            if len(seen) == total:
                links = body.get("links", {})
                if not isinstance(links, dict) or not isinstance(links.get("pages", {}), dict):
                    raise DigitalOceanAttachmentError("provider Droplet inventory pagination is invalid")
                if links.get("pages", {}).get("next") is not None:
                    raise DigitalOceanAttachmentError("provider Droplet inventory has an unreviewed next page")
                break
            if not rows:
                raise DigitalOceanAttachmentError("provider Droplet inventory was truncated")
        else:
            raise DigitalOceanAttachmentError("provider Droplet inventory exceeded page bound")
    return found


def _require_firewall_policy(firewall: dict, intent: DigitalOceanAttachmentIntent) -> None:
    if firewall.get("name") != intent.firewall_name or firewall.get("tags") != [intent.selector_tag]:
        raise DigitalOceanAttachmentError("provider firewall selector differs from reviewed policy")
    peer_cidrs = tuple(sorted(f"{node.public_ipv4}/32" for node in intent.nodes))
    ingress = {
        ("tcp", port, ("0.0.0.0/0",)) for port in ("80", "443", "2222")
    }
    ingress.add(("tcp", "22", tuple(sorted(intent.trusted_ssh_cidrs))))
    # The pinned provider root renders the peer ICMP port_range as 1-65535;
    # DigitalOcean reports that value unchanged in its firewall GET response.
    ingress.update((proto, "1-65535", peer_cidrs)
                   for proto in ("tcp", "udp", "icmp"))
    egress = {(proto, "1-65535" if proto != "icmp" else "0", ("0.0.0.0/0",))
              for proto in ("tcp", "udp", "icmp")}
    if (_normalize_rules(firewall.get("inbound_rules"), "sources") != ingress
            or _normalize_rules(firewall.get("outbound_rules"), "destinations") != egress):
        raise DigitalOceanAttachmentError("provider firewall rules differ from reviewed baseline")


def _normalize_rules(value: object, side: str) -> set[tuple[str, str, tuple[str, ...]]]:
    if not isinstance(value, list):
        raise DigitalOceanAttachmentError("provider firewall rules are incomplete")
    result: set[tuple[str, str, tuple[str, ...]]] = set()
    for rule in value:
        if not isinstance(rule, dict) or rule.get("action", "allow") != "allow":
            raise DigitalOceanAttachmentError("provider firewall rule is invalid")
        sources = rule.get(side)
        if not isinstance(sources, dict) or not isinstance(sources.get("addresses"), list):
            raise DigitalOceanAttachmentError("provider firewall rule source is incomplete")
        if any(key != "addresses" and values not in ([], None) for key, values in sources.items()):
            raise DigitalOceanAttachmentError("provider firewall rule has unreviewed source")
        addresses = sources["addresses"]
        if any(not isinstance(address, str) for address in addresses) or len(set(addresses)) != len(addresses):
            raise DigitalOceanAttachmentError("provider firewall rule addresses are invalid")
        ports = rule.get("ports")
        protocol = rule.get("protocol")
        if not isinstance(ports, str) or not isinstance(protocol, str):
            raise DigitalOceanAttachmentError("provider firewall rule is invalid")
        normalized = (protocol, ports, tuple(sorted(addresses)))
        if normalized in result:
            raise DigitalOceanAttachmentError("provider firewall rule repeats")
        result.add(normalized)
    return result


def _request(client: ProviderCatalogTransport, path: str, token: str) -> dict:
    response = client.request(_ORIGIN, "GET", path, token)
    if not isinstance(response, dict):
        raise DigitalOceanAttachmentError("provider response is incomplete")
    return response


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
