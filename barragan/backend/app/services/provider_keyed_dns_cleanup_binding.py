# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only binding of reviewed keyed teardown edges to their sealed IPs.

This proof is private preparation for a future DNS cleanup child. It does not
authorize a provider write, and callers must reprove live state before GO.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Mapping

from app.domain import JobEvent
from app.services.provider_keyed_host_binding import _digest_json


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_EDGE = re.compile(r'digitalocean_droplet\.edge\["[A-Za-z0-9_-]+"\]\Z')
_MIDDLE = re.compile(r'digitalocean_droplet\.middle\["[A-Za-z0-9_-]+"\]\Z')
_INTENT = "provider host identity binding intended"
_BOUND = "provider host identity bound"


class ProviderKeyedDnsCleanupBindingError(ValueError):
    """Reviewed edge-to-IP identity is unavailable or ambiguous."""


@dataclass(frozen=True)
class ProviderKeyedDnsCleanupBinding:
    engagement_id: str
    core_job_id: str
    core_plan_id: str
    revision_id: str
    state_sha256: str
    manifest_sha256: str
    provider_scope_sha256: str
    edge_public_ips: tuple[str, ...]
    binding_sha256: str


def bind_provider_keyed_dns_cleanup_targets(
    engagement_id: str, *, confirmed_scope: Mapping[str, object],
    provider_scope_sha256: str, host_binding_intent_event: JobEvent,
    host_binding_bound_event: JobEvent,
) -> ProviderKeyedDnsCleanupBinding:
    """Cross-check frozen scope and the initial host-binding journal, with no IO."""
    try:
        if (not _text(engagement_id) or type(confirmed_scope) is not dict
                or confirmed_scope.get("schema") != "provider-keyed-v2"
                or confirmed_scope.get("provider") != "digitalocean"
                or not _sha(provider_scope_sha256)
                or _digest_json({"providerScopes": [confirmed_scope]}) != provider_scope_sha256):
            raise ValueError("reviewed provider scope differs")
        if (not isinstance(host_binding_intent_event, JobEvent)
                or host_binding_intent_event.message != _INTENT
                or host_binding_intent_event.level != "info"
                or not isinstance(host_binding_bound_event, JobEvent)
                or host_binding_bound_event.message != _BOUND
                or host_binding_bound_event.level != "info"
                or host_binding_intent_event.sequence >= host_binding_bound_event.sequence):
            raise ValueError("host binding journal differs")
        manifest = host_binding_intent_event.data
        bound = host_binding_bound_event.data
        if type(manifest) is not dict or type(bound) is not dict:
            raise ValueError("host binding event shape")
        manifest_sha256 = _digest_json(manifest)
        if (bound.get("manifestSha256") != manifest_sha256
                or bound.get("hostProofPending") is not True
                or manifest.get("schema") != "provider-keyed-v2"
                or manifest.get("engagementId") != engagement_id):
            raise ValueError("sealed host binding differs")
        for key in ("coreJobId", "corePlanId", "revisionId", "stateSha256",
                    "sourceRevision", "providerConnectionId"):
            if not _text(confirmed_scope.get(key)) or manifest.get(key) != confirmed_scope[key]:
                raise ValueError("reviewed host context differs")
        if not _sha(confirmed_scope["stateSha256"]):
            raise ValueError("state identity differs")
        chain_ids = confirmed_scope.get("chainIds")
        fingerprints = confirmed_scope.get("chainFingerprints")
        if (type(chain_ids) is not list or not chain_ids or len(set(chain_ids)) != len(chain_ids)
                or any(not _text(value) for value in chain_ids)
                or type(fingerprints) is not dict or set(fingerprints) != set(chain_ids)
                or any(not _text(value) for value in fingerprints.values())
                or manifest.get("chainFingerprints") != [
                    {"chainId": chain_id, "fingerprint": fingerprints[chain_id]}
                    for chain_id in chain_ids]):
            raise ValueError("chain context differs")
        resources = confirmed_scope.get("resources")
        nodes = manifest.get("nodes")
        if (type(resources) is not list or not resources or type(nodes) is not list
                or not nodes):
            raise ValueError("provider nodes are unavailable")
        scope_droplets: dict[str, str] = {}
        scope_addresses: set[str] = set()
        scope_ids: set[str] = set()
        edges: set[str] = set()
        for row in resources:
            if type(row) is not dict or not _text(row.get("address")) or not _text(row.get("id")):
                raise ValueError("provider resource differs")
            address, provider_id = row["address"], row["id"]
            if address in scope_addresses:
                raise ValueError("duplicate provider address")
            scope_addresses.add(address)
            if address.startswith("digitalocean_droplet."):
                if row.get("kind") != "droplet" or provider_id in scope_ids:
                    raise ValueError("ambiguous scoped droplet")
                if _EDGE.fullmatch(address):
                    edges.add(address)
                elif not _MIDDLE.fullmatch(address):
                    raise ValueError("unexpected scoped droplet")
                scope_droplets[address] = provider_id
                scope_ids.add(provider_id)
        if not edges:
            raise ValueError("no scoped edge")
        manifest_addresses: set[str] = set()
        manifest_ids: set[str] = set()
        ips: set[str] = set()
        for row in nodes:
            if type(row) is not dict:
                raise ValueError("manifest node differs")
            address, provider_id = row.get("terraformAddress"), row.get("providerInstanceId")
            if (not _text(address) or not _text(provider_id)
                    or address in manifest_addresses or provider_id in manifest_ids
                    or scope_droplets.get(address) != provider_id
                    or row.get("chainId") not in chain_ids):
                raise ValueError("manifest address or provider ID differs")
            manifest_addresses.add(address)
            manifest_ids.add(provider_id)
            if address in edges:
                if row.get("role") != "edge":
                    raise ValueError("edge role differs")
                ip = _public_ipv4(row.get("publicIp"))
                if ip in ips:
                    raise ValueError("duplicate edge public IP")
                ips.add(ip)
            elif row.get("role") != "middle":
                raise ValueError("middle role differs")
        if manifest_addresses != set(scope_droplets) or len(ips) != len(edges):
            raise ValueError("scoped and sealed node sets differ")
        ordered = tuple(sorted(ips, key=lambda value: int(ipaddress.IPv4Address(value))))
        digest = _digest_json({
            "engagementId": engagement_id, "coreJobId": confirmed_scope["coreJobId"],
            "corePlanId": confirmed_scope["corePlanId"], "revisionId": confirmed_scope["revisionId"],
            "stateSha256": confirmed_scope["stateSha256"], "manifestSha256": manifest_sha256,
            "providerScopeSha256": provider_scope_sha256, "edgePublicIps": ordered,
        })
        return ProviderKeyedDnsCleanupBinding(
            engagement_id, confirmed_scope["coreJobId"], confirmed_scope["corePlanId"],
            confirmed_scope["revisionId"], confirmed_scope["stateSha256"],
            manifest_sha256, provider_scope_sha256, ordered, digest,
        )
    except Exception:
        raise ProviderKeyedDnsCleanupBindingError(
            "sealed keyed edge DNS cleanup targets are unproved") from None


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and value == value.strip()


def _sha(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def _public_ipv4(value: object) -> str:
    if not _text(value):
        raise ValueError("missing public IPv4")
    address = ipaddress.ip_address(value)
    if (not isinstance(address, ipaddress.IPv4Address)
            or not address.is_global or str(address) != value):
        raise ValueError("invalid public IPv4")
    return value
