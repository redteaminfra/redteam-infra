# Copyright (c) 2026, Oracle and/or its affiliates.
"""Compile a fresh DevTest provider topology from reviewed, persisted intent.

No Terraform or provider operation belongs here. The output is an immutable
snapshot for a later job to reserve and independently check at plan/apply time.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, replace
from typing import Any, Literal, Mapping, Sequence

from app.domain.deployment_plan import DeploymentPlan
from app.integrations.managed_host_images import ManagedHostImageProfile
from app.integrations.oci_deployment_targets import OciDeploymentTargetError, normalized_oci_deployment_target
from app.integrations.pilot_standard_rti import pilot_names
from app.services.managed_host_image_continuity import (
    ManagedHostImageContinuityError,
    managed_host_image_profile_named,
)
from app.services.post_core_sketch_continuation import (
    PILOT_CORE_ACTION,
    sketch_chain_intent_fingerprint,
)
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent,
    DigitalOceanNodeCreate,
)
from app.services.provider_keyed_sketch import SCHEMA, compile_provider_topology
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


_KEY = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_REGION = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
_SIZE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_PROXY = re.compile(r"^proxy[0-9]{2}$")
_MATERIALIZED_READ_STATUSES = frozenset({
    "deploying", "reconciling", "deployed", "stopping", "stopped", "starting",
    "tearing_down", "failed",
})
_DROPLET_ID = re.compile(r"^[1-9][0-9]*$")
_EDGE_ADDRESS = re.compile(r'^digitalocean_droplet\.edge\["([a-z0-9-]+-[0-9]{2})"\]$')


class ProviderKeyedPersistedIntentError(ValueError):
    """A reviewed core snapshot and stored chains cannot form a fresh pilot."""


@dataclass(frozen=True)
class ProviderKeyedChainRoute:
    chain_id: str
    middle_node: str
    assigned_proxy: str
    edge_nodes: tuple[str, ...]


@dataclass(frozen=True)
class ProviderKeyedPersistedIntent:
    engagement_id: str
    core_job_id: str
    core_plan_id: str
    revision_id: str
    provider: str
    engagement_name: str
    selector_tag: str
    proxy_egress_ips: dict[str, str]
    topology: dict[str, Any]
    chain_routes: tuple[ProviderKeyedChainRoute, ...]
    nodes: dict[str, DigitalOceanNodeCreate]
    firewall: DigitalOceanInitialFirewallIntent
    nonsecret_varfile: dict[str, Any]


def compile_fresh_digitalocean_persisted_intent(
    engagement: StoredEngagement,
    chains: Sequence[StoredSketchChain],
    core_job: StoredJobRun,
    core_plan: DeploymentPlan,
    image_profile: ManagedHostImageProfile,
    *,
    environment: str,
    provider_state_exists: bool = False,
    mode: Literal["fresh", "applied_read", "materialized_read", "append_plan"] = "fresh",
    proposed_topology: Mapping[str, Any] | None = None,
    reviewed_initial_chains: Sequence[StoredSketchChain] | None = None,
) -> ProviderKeyedPersistedIntent:
    """Derive exact fresh node/firewall inputs, with no caller topology trust.

    The runtime caller must hold the engagement mutation lease and query the
    complete chain set. Fresh mode additionally requires independent absence
    of provider state/resources. Read modes cannot prove retained state node
    identities, live ownership, lifecycle worker quiescence, or safe teardown;
    their callers must cross-check those before any operation.
    """

    def reject(reason: str) -> None:
        raise ProviderKeyedPersistedIntentError(reason)

    if not isinstance(engagement, StoredEngagement) or engagement.sketch_state_schema != SCHEMA:
        reject("engagement is not a provider-keyed-v2 record")
    if environment != "devtest" or mode not in ("fresh", "applied_read", "materialized_read", "append_plan"):
        reject("provider-keyed pilot requires an explicit DevTest read mode")
    if mode == "fresh" and provider_state_exists:
        reject("fresh provider-keyed pilot requires DevTest and no provider state")
    if mode in ("applied_read", "materialized_read", "append_plan") and not provider_state_exists:
        reject("provider state presence differs from the requested read mode")
    target = (engagement.input_parameters or {}).get("deploymentTarget")
    try:
        normalized_target = normalized_oci_deployment_target(target)
    except (OciDeploymentTargetError, RuntimeError, TypeError):
        reject("provider-keyed pilot requires an approved deployment target")
    if normalized_target["name"] != "barragan-testing":
        reject("provider-keyed pilot requires the barragan-testing target")
    if isinstance(target, Mapping) and target.get("region") not in (None, normalized_target["region"]):
        reject("persisted deployment target region changed")
    if not isinstance(core_job, StoredJobRun) or not isinstance(core_plan, DeploymentPlan):
        reject("reviewed core job and plan are required")
    if not isinstance(image_profile, ManagedHostImageProfile) or not image_profile.digitalocean_image:
        reject("pinned DigitalOcean image is missing")
    if not isinstance(core_job.input, Mapping) or not isinstance(core_plan.evidence, Mapping):
        reject("reviewed core job evidence is invalid")
    try:
        canonical_profile = managed_host_image_profile_named(image_profile.name)
    except ManagedHostImageContinuityError:
        reject("pinned managed-host image profile is unknown")
    if canonical_profile != image_profile:
        reject("pinned managed-host image profile object differs from the canonical profile")
    if (core_job.action != PILOT_CORE_ACTION or core_job.status != "succeeded"
            or core_job.input.get("engagementId") != engagement.id
            or core_job.input.get("engagementName") != engagement.name
            or core_job.input.get("sketchStateSchema") != SCHEMA
            or core_job.input.get("postCoreSketchContinuationEligible") is not False
            or core_job.input.get("corePlanId") != core_plan.id
            or core_plan.engagement_id != engagement.id
            or core_plan.status != "applied" or core_plan.apply_job_id != core_job.id
            or core_plan.revision_id != engagement.active_revision
            or core_plan.evidence.get("sketchStateSchema") != SCHEMA
            or core_plan.evidence.get("managedHostImageProfile") != image_profile.name
            or core_plan.evidence.get("digitaloceanImage") != canonical_profile.digitalocean_image):
        reject("core job, revision, plan, and pinned image profile do not match")
    target_fields = ("name", "compartmentId", "region")
    if (not isinstance(core_plan.evidence.get("target"), Mapping)
            or not isinstance(core_job.input.get("target"), Mapping)
            or any(
                source.get(field) != normalized_target[field]
                for source in (core_plan.evidence["target"], core_job.input["target"])
                for field in target_fields
            )
            or any(
                source.get("provider", "oci") != "oci"
                for source in (core_plan.evidence["target"], core_job.input["target"])
            )):
        reject("reviewed core target changed")
    if (not isinstance(chains, Sequence) or len(chains) != 2
            or any(not isinstance(chain, StoredSketchChain) for chain in chains)):
        reject("pilot requires exactly two persisted chains")
    ids = [chain.chain_id for chain in chains]
    expected_ids = core_plan.evidence.get("pendingSketchChainIds")
    fingerprints = core_plan.evidence.get("pendingSketchChainFingerprints")
    if (len(set(ids)) != 2 or not all(isinstance(value, str) and _KEY.fullmatch(value) for value in ids)
            or not isinstance(expected_ids, list) or len(expected_ids) != 2
            or not all(isinstance(value, str) for value in expected_ids)
            or len(set(expected_ids)) != 2 or set(expected_ids) != set(ids)
            or core_job.input.get("pendingSketchChainIds") != expected_ids
            or not isinstance(fingerprints, Mapping)
            or set(fingerprints) != set(ids)
            or core_job.input.get("pendingSketchChainFingerprints") != fingerprints):
        reject("reviewed core chain set changed")
    historical = reviewed_initial_chains if reviewed_initial_chains is not None else chains
    if (len(historical) != 2 or {chain.chain_id for chain in historical} != set(ids)
            or any(chain.engagement_id != engagement.id for chain in historical)):
        reject("reviewed initial chain set differs")
    if any(fingerprints[chain.chain_id] != sketch_chain_intent_fingerprint(chain) for chain in historical):
        reject("persisted chain differs from reviewed core intent")
    if reviewed_initial_chains is not None and mode not in {"materialized_read", "append_plan"}:
        reject("historical initial chain review requires materialized read")
    if mode == "append_plan" and reviewed_initial_chains is None:
        reject("append plan requires the published initial chain review")
    if reviewed_initial_chains is not None:
        initial_by_id = {chain.chain_id: chain for chain in historical}
        expanded = [chain for chain in chains if chain != initial_by_id[chain.chain_id]]
        if len(expanded) != 1:
            reject("exactly one initial chain must have one appended edge")
        current = expanded[0]
        original = initial_by_id[current.chain_id]
        if (original.edge_count != 1 or current.edge_count != 2
                or not isinstance(original.edge_intents, list)
                or not isinstance(current.edge_intents, list)
                or current.edge_intents[:1] != original.edge_intents
                or len(current.edge_intents) != 2
                or current.edge_intents[1].get("id") != "edge-02"
                or len(original.nodes) != 2
                or (mode == "append_plan" and current.nodes != original.nodes)
                or (mode != "append_plan" and (len(current.nodes) != 3
                    or current.nodes[0] != original.nodes[0]
                    or current.nodes[1] != {**original.nodes[1], "edgeCount": "2"}))
                or current != replace(original, edge_count=2,
                    edge_intents=current.edge_intents, nodes=current.nodes,
                    updated_at=current.updated_at)):
            reject("expanded chain changed more than one edge")
    proxy_count = core_job.input.get("proxyCount")
    if type(proxy_count) is not int or proxy_count not in (1, 2):
        reject("reviewed core proxy count is invalid")
    cidrs = core_plan.evidence.get("sshSourceCidrs")
    if not isinstance(cidrs, list) or not cidrs or core_job.input.get("sshSourceCidrs") != cidrs:
        reject("reviewed core SSH sources changed")

    by_id = {chain.chain_id: chain for chain in chains}
    ordered = [by_id[chain_id] for chain_id in expected_ids]
    middles: dict[str, dict[str, Any]] = {}
    groups: dict[str, dict[str, Any]] = {}
    routes: list[ProviderKeyedChainRoute] = []
    regional_next: dict[str, int] = {}
    historical_edge_numbers: dict[str, tuple[tuple[str, int], ...]] = {}
    if reviewed_initial_chains is not None:
        used_keys: set[str] = set()
        for chain in historical:
            identities = []
            for node in chain.nodes[1:]:
                address = node.get("terraformAddress") if isinstance(node, Mapping) else None
                match = _EDGE_ADDRESS.fullmatch(address) if isinstance(address, str) else None
                if match is None or address in used_keys:
                    reject("historical edge address is missing or repeated")
                key = match.group(1)
                region, suffix = key.rsplit("-", 1)
                if node.get("region") != region or int(suffix) < 1:
                    reject("historical edge ordinal differs")
                used_keys.add(address)
                number = int(suffix)
                identities.append((region, number))
                regional_next[region] = max(regional_next.get(region, 0), number)
            historical_edge_numbers[chain.chain_id] = tuple(identities)
    middle_size = ordered[0].middle_size
    edge_size = ordered[0].edge_size
    for ordinal, chain in enumerate(ordered, 1):
        materialized = mode in {"materialized_read", "append_plan"}
        lifecycle_invalid = (
            chain.status not in _MATERIALIZED_READ_STATUSES
            or not isinstance(chain.nodes, list) or not chain.nodes
        ) if materialized else (
            chain.status != "pending" or bool(chain.deploy_job_id or chain.teardown_job_id
                                              or chain.terraform_working_directory or chain.nodes
                                              or chain.burned)
        )
        if (chain.engagement_id != engagement.id
                or lifecycle_invalid
                or chain.middle_provider != "digitalocean"
                or chain.edge_provider != "digitalocean"
                or chain.middle_size != middle_size or chain.edge_size != edge_size
                or not isinstance(chain.middle_size, str) or not _SIZE.fullmatch(chain.middle_size)
                or not isinstance(chain.edge_size, str) or not _SIZE.fullmatch(chain.edge_size)
                or not isinstance(chain.middle_region, str) or not _REGION.fullmatch(chain.middle_region)
                or not isinstance(chain.assigned_proxy, str) or not _PROXY.fullmatch(chain.assigned_proxy)
                or int(chain.assigned_proxy[-2:]) > proxy_count):
            reject("persisted chain is not a fresh compatible DigitalOcean chain")
        middle_key = f"middle_{ordinal:02d}"
        middles[middle_key] = {"region": chain.middle_region, "ordinal": ordinal}
        edges = chain.edge_intents
        if (not isinstance(edges, list) or not edges or len(edges) != chain.edge_count
                or chain.edge_count > 10):
            reject("persisted edge intents are incomplete")
        by_region: dict[str, list[int]] = {}
        edge_names: list[str] = []
        for index, edge in enumerate(edges, 1):
            if (not isinstance(edge, Mapping) or edge.get("id") != f"edge-{index:02d}"
                    or edge.get("provider") != "digitalocean"
                    or edge.get("size") != edge_size
                    or not isinstance(edge.get("region"), str)
                    or not _REGION.fullmatch(edge["region"])):
                reject("persisted edge key, provider, region, or size is invalid")
            region = edge["region"]
            historical_ids = historical_edge_numbers.get(chain.chain_id, ())
            if index <= len(historical_ids):
                old_region, number = historical_ids[index - 1]
                if old_region != region:
                    reject("historical edge region changed")
            else:
                regional_next[region] = regional_next.get(region, 0) + 1
                number = regional_next[region]
            by_region.setdefault(region, []).append(number)
            edge_names.append(f"{region}-{number:02d}")
        for region, numbers in sorted(by_region.items()):
            groups[f"group_{ordinal:02d}_{region.replace('-', '_')}"] = {
                "region": region, "middle_node": middle_key, "ordinals": numbers,
            }
        routes.append(ProviderKeyedChainRoute(chain.chain_id, middle_key, chain.assigned_proxy, tuple(edge_names)))
    topology = compile_provider_topology(middles, groups)
    if proposed_topology is not None and proposed_topology != topology:
        reject("caller topology contradicts persisted intent")
    # Core and Sketch must use the same established Redteam-infra slug. The
    # disposable DevTest draft itself gets an opaque operator-selected name.
    try:
        names = pilot_names(core_job.input["engagementName"])
        engagement_name = names.engagement_name
    except (TypeError, ValueError):
        reject("persisted engagement name is invalid")
    proxy_egress_ips = _reviewed_proxy_egress_ips(
        core_job, {route.assigned_proxy for route in routes}, names,
    )
    trusted = tuple(sorted(f"{ip}/32" for ip in proxy_egress_ips.values()))
    selector = "s" + hashlib.sha256(engagement.id.encode("utf-8")).hexdigest()[:20]
    nodes: dict[str, DigitalOceanNodeCreate] = {}
    for key, middle in topology["middles"].items():
        nodes[f'digitalocean_droplet.middle["{key}"]'] = DigitalOceanNodeCreate(
            f'middle{middle["ordinal"]:02d}-{engagement_name}', image_profile.digitalocean_image,
            middle_size, middle["region"], selector,
        )
    for group in topology["edge_groups"].values():
        for number in group["ordinals"]:
            region = group["region"]
            identity = f"{region}-{number:02d}"
            nodes[f'digitalocean_droplet.edge["{identity}"]'] = DigitalOceanNodeCreate(
                f"edge-{engagement_name}-{region}-{number:02d}",
                image_profile.digitalocean_image, edge_size, region, selector,
            )
    if mode == "materialized_read":
        _validate_materialized_rows(ordered, routes, nodes)
    elif mode == "append_plan":
        # The proposed extra edge has no provider ID/IP until apply. Validate
        # only the already published four nodes against their retained routes.
        initial_by_id = {chain.chain_id: chain for chain in historical}
        retained_routes = [replace(route, edge_nodes=route.edge_nodes[:1])
                           for route in routes]
        _validate_materialized_rows(
            [initial_by_id[chain.chain_id] for chain in ordered], retained_routes, nodes)
    firewall = DigitalOceanInitialFirewallIntent(
        name=f"{engagement_name}-firewall", selector_tag=selector,
        public_tcp_ports=("80", "443", "2222"), public_udp_ports=(),
        trusted_ssh_cidrs=trusted,
    )
    varfile = {
        "middles": topology["middles"], "edge_groups": topology["edge_groups"],
        "docean_image": image_profile.digitalocean_image,
        "engagement_name": engagement_name, "firewall_selector_tag": selector,
        "middle_size": middle_size, "edge_size": edge_size,
        "allowed_tcp_ports": ["22", "80", "443", "2222"],
        "allowed_udp_ports": [], "trusted_ssh_cidrs": list(trusted),
    }
    return ProviderKeyedPersistedIntent(
        engagement.id, core_job.id, core_plan.id, core_plan.revision_id,
        "digitalocean", engagement_name, selector, proxy_egress_ips, topology, tuple(routes), nodes,
        firewall, varfile,
    )


def _validate_materialized_rows(
    chains: Sequence[StoredSketchChain], routes: Sequence[ProviderKeyedChainRoute],
    reviewed_nodes: Mapping[str, DigitalOceanNodeCreate],
) -> None:
    """Check local projection vocabulary; state-backed IDs/IPs need caller proof."""
    seen_ids: set[str] = set()
    seen_ips: set[str] = set()
    for ordinal, (chain, route) in enumerate(zip(chains, routes), 1):
        addresses = [f'digitalocean_droplet.middle["{route.middle_node}"]', *(
            f'digitalocean_droplet.edge["{key}"]' for key in route.edge_nodes
        )]
        if len(chain.nodes) != len(addresses):
            raise ProviderKeyedPersistedIntentError("materialized chain node coverage differs")
        for index, (row, address) in enumerate(zip(chain.nodes, addresses)):
            expected = reviewed_nodes[address]
            role = "middle" if index == 0 else "edge"
            component = "middle" if index == 0 else f"edge-{index:02d}"
            if (not isinstance(row, Mapping)
                    or row.get("chainId") != chain.chain_id
                    or row.get("role") != role or row.get("provider") != "digitalocean"
                    or row.get("terraformAddress") != address
                    or row.get("hostname") != expected.name
                    or row.get("region") != expected.region
                    or row.get("assignedProxy") != route.assigned_proxy
                    or row.get("proxy") != route.assigned_proxy
                    or row.get("componentId") != component
                    or not isinstance(row.get("status"), str) or not row["status"]
                    or not isinstance(row.get("providerInstanceId"), str)
                    or not _DROPLET_ID.fullmatch(row["providerInstanceId"])):
                raise ProviderKeyedPersistedIntentError("materialized chain node row differs")
            if index == 0:
                if type(row.get("middleOrdinal")) is not int or row["middleOrdinal"] != ordinal:
                    raise ProviderKeyedPersistedIntentError("materialized middle ordinal differs")
            elif (row.get("edgeId") != component or row.get("edgeIndex") != str(index)
                  or row.get("edgeCount") != str(len(route.edge_nodes))):
                raise ProviderKeyedPersistedIntentError("materialized edge index differs")
            if not isinstance(row.get("publicIp"), str):
                raise ProviderKeyedPersistedIntentError("materialized public IP is invalid")
            try:
                public_ip = ipaddress.ip_address(row.get("publicIp"))
            except (ValueError, TypeError):
                raise ProviderKeyedPersistedIntentError("materialized public IP is invalid") from None
            if (not isinstance(public_ip, ipaddress.IPv4Address)
                    or public_ip.is_unspecified or public_ip.is_loopback
                    or row["providerInstanceId"] in seen_ids
                    or str(public_ip) in seen_ips):
                raise ProviderKeyedPersistedIntentError("materialized node identities repeat or differ")
            seen_ids.add(row["providerInstanceId"])
            seen_ips.add(str(public_ip))


def _reviewed_proxy_egress_ips(core_job: StoredJobRun, selected: set[str], names: Any) -> dict[str, str]:
    """Bind provider SSH sources to this core job's actual selected proxies."""

    details = next((event.data["connectionDetails"] for event in reversed(core_job.events)
                    if isinstance(event.data, Mapping)
                    and isinstance(event.data.get("connectionDetails"), list)), None)
    if not isinstance(details, list) or not details:
        raise ProviderKeyedPersistedIntentError("reviewed core proxy connection details are missing")
    expected = {"proxy01": names.proxy_name, "proxy02": names.proxy02_name}
    result: dict[str, str] = {}
    for proxy in sorted(selected):
        rows = [row for row in details if isinstance(row, Mapping)
                and row.get("role") == "proxy"
                and row.get("displayName") == expected[proxy]
                and row.get("sshAlias") == expected[proxy]]
        if len(rows) != 1:
            raise ProviderKeyedPersistedIntentError("reviewed core proxy identity is ambiguous")
        try:
            address = ipaddress.ip_address(rows[0].get("publicIp"))
        except (ValueError, TypeError):
            raise ProviderKeyedPersistedIntentError("reviewed core proxy public IP is invalid") from None
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
            raise ProviderKeyedPersistedIntentError("reviewed core proxy public IP is invalid")
        result[proxy] = str(address)
    if len(set(result.values())) != len(result):
        raise ProviderKeyedPersistedIntentError("reviewed core proxies share one public IP")
    return result
