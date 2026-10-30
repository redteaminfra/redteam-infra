# Copyright (c) 2026, Oracle and/or its affiliates.
"""Canonical one-chain DigitalOcean intent from a reviewed mixed core.

This is offline intent compilation, not provider ownership or Apply proof.
The companion Linode compiler checks the shared applied-core generation and
both pending chain identities; this compiler binds the DigitalOcean scope.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from app.domain.deployment_plan import DeploymentPlan
from app.integrations.pilot_standard_rti import pilot_names
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate,
    _SOURCE_REVISION, _SOURCE_SHA256,
)
from app.services.provider_keyed_mixed_digitalocean_plan_gate import _LOCK_SHA256
from app.services.provider_keyed_mixed_linode_intent import (
    MixedLinodeIntentError, compile_mixed_linode_initial_intent,
)
from app.services.provider_keyed_persisted_intent import _reviewed_proxy_egress_ips
from app.services.provider_keyed_sketch import SCHEMA
from app.storage.credential_repository import CredentialRepository
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import JobRepository, StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain
from app.storage.sketch_ssh_key_repository import SketchSshKeyRepository


class MixedDigitalOceanIntentError(ValueError):
    """DigitalOcean intent differs from the active reviewed mixed core."""


@dataclass(frozen=True)
class MixedDigitalOceanInitialIntent:
    engagement_id: str
    engagement_name: str
    core_job_id: str
    core_plan_id: str
    revision_id: str
    review_fingerprint: str
    provider_connection_id: str
    credential_secret_sha256: str
    credential_updated_at: str
    middle_key: str
    edge_key: str
    proxy_name: str
    trusted_ssh_cidrs: tuple[str, ...]
    admin_public_key: str
    ssh_key_name: str
    selector_tag: str
    topology: dict[str, Any]
    nodes: dict[str, DigitalOceanNodeCreate]
    firewall: DigitalOceanInitialFirewallIntent
    nonsecret_varfile: dict[str, Any]

    def expected_local_files(self, private: Path, output: Path) -> dict[str, dict[str, object]]:
        """Render the two known local-file actions for exact plan inspection."""
        middle = self.nodes[f'digitalocean_droplet.middle["{self.middle_key}"]'].name
        edge = self.nodes[f'digitalocean_droplet.edge["{self.edge_key}"]'].name
        inventory = (
            "[all:vars]\ninfra_user=ubuntu\nansible_connection=ssh\n"
            "ansible_ssh_user=root\nansible_ssh_host_key_checking=no\n"
            "ansible_ssh_common_args=-o UserKnownHostsFile=/dev/null "
            "-o ProxyCommand='ssh -o UserKnownHostsFile=/dev/null "
            f"-o StrictHostKeyChecking=no -i {private} -W %h:%p "
            f"{{{{ infra_user }}}}@homebase-{self.engagement_name}'\n\n"
            f"[middle]\n{middle}\n\n[edge]\n{edge}\n"
        )
        common = {"content_base64": None, "directory_permission": "0777",
                  "file_permission": "0600", "sensitive_content": None, "source": None}
        return {
            "local_file.ansible_inventory[0]": {
                **common, "filename": "inventory.ini", "content": inventory},
            "local_file.ssh_stanza[0]": {
                **common, "filename": str(output / f"{self.engagement_name}-sketch")},
        }


def _reject() -> None:
    raise MixedDigitalOceanIntentError("mixed DigitalOcean intent differs from active reviewed core records")


def compile_mixed_digitalocean_initial_intent(
    engagement: StoredEngagement, chains: Sequence[StoredSketchChain],
    core_job: StoredJobRun, core_plan: DeploymentPlan, *,
    job_repository: JobRepository, credential_repository: CredentialRepository,
    ssh_key_repository: SketchSshKeyRepository, expected_admin_public_key: str,
    environment: str,
) -> MixedDigitalOceanInitialIntent:
    """Derive the single reviewed DO middle/edge from persisted mixed records."""
    try:
        shared = compile_mixed_linode_initial_intent(
            engagement, chains, core_job, core_plan,
            job_repository=job_repository, credential_repository=credential_repository,
            ssh_key_repository=ssh_key_repository,
            expected_admin_public_key=expected_admin_public_key, environment=environment)
    except MixedLinodeIntentError as exc:
        raise MixedDigitalOceanIntentError(
            "mixed DigitalOcean intent lacks a valid applied core generation") from exc
    ids = core_plan.evidence["pendingSketchChainIds"]
    by_id = {chain.chain_id: chain for chain in chains}
    ordered = [by_id[chain_id] for chain_id in ids]
    matching = [chain for chain in ordered
                if chain.middle_provider == chain.edge_provider == "digitalocean"]
    if len(matching) != 1:
        _reject()
    chain = matching[0]
    ordinal = ids.index(chain.chain_id) + 1
    scope = core_plan.evidence["sketchAuthorization"]["providerScopes"][0]
    reviewed = core_plan.review["reviewedConfiguration"]
    policy = {
        "publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
        "publicIpv6Allowed": False,
        "managementSsh": {"port": 22, "sourceRule": "selected-proxy-public-ipv4-32",
                          "proxyNames": [chain.assigned_proxy]},
        "peerIngress": {"protocols": ["tcp", "udp", "icmp"],
                        "portRange": "1-65535",
                        "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32"},
        "outboundIpv4": [
            {"protocol": protocol, "portRange": "1-65535", "destination": "0.0.0.0/0"}
            for protocol in ("tcp", "udp")
        ] + [{"protocol": "icmp", "destination": "0.0.0.0/0"}],
        "outboundIpv6": "not-configured",
    }
    source = {"revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
              "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                               "sha256": _LOCK_SHA256, "providerVersion": "2.103.0"}}
    image = scope.get("image")
    connection_id = scope.get("providerConnectionId")
    if (set(scope) != {"provider", "providerConnectionId", "image", "source", "firewall", "chain"}
            or scope.get("provider") != "digitalocean"
            or scope.get("source") != source or scope.get("firewall") != policy
            or not isinstance(image, str) or not image
            or core_plan.evidence.get("digitaloceanImage") != image
            or reviewed.get("digitaloceanImage") != image
            or not isinstance(connection_id, str) or not connection_id):
        _reject()
    snapshots = core_plan.evidence.get("keyedProviderCredentialSnapshots")
    try:
        credential = credential_repository.get(connection_id)
        default = credential_repository.get_default("digitalocean")
    except Exception:
        _reject()
    if (not isinstance(snapshots, dict) or set(snapshots) != {"digitalocean", "linode"}
            or credential is None or default is None
            or credential.id != connection_id or default.id != connection_id
            or credential.provider != "digitalocean" or default.provider != "digitalocean"
            or credential.status != "active" or default.status != "active"
            or credential.is_default is not True or default.is_default is not True
            or not isinstance(credential.encrypted_secret, str) or not credential.encrypted_secret
            or credential.encrypted_secret != default.encrypted_secret
            or credential.updated_at != default.updated_at
            or snapshots["digitalocean"] != {
                "encryptedSecretSha256": hashlib.sha256(credential.encrypted_secret.encode()).hexdigest(),
                "updatedAt": credential.updated_at,
            }):
        _reject()
    selector = "s" + hashlib.sha256(engagement.id.encode()).hexdigest()[:20]
    try:
        names = pilot_names(engagement.name)
        if selector in {engagement.name, names.engagement_name}:
            _reject()
        proxy_ips = _reviewed_proxy_egress_ips(core_job, {chain.assigned_proxy}, names)
        proxy_ip = ipaddress.ip_address(proxy_ips[chain.assigned_proxy])
        if not isinstance(proxy_ip, ipaddress.IPv4Address) or not proxy_ip.is_global:
            _reject()
    except (ValueError, TypeError, KeyError):
        _reject()
    region = chain.edge_region
    edge_ordinal = 1 + sum(previous.edge_region.lower() == region.lower()
                           for previous in ordered[:ordinal - 1])
    middle_key = f"middle_{ordinal:02d}"
    edge_key = f"{region.lower()}-{edge_ordinal:02d}"
    high_water: dict[str, int] = {}
    for previous in ordered[:ordinal]:
        prior_region = previous.edge_region
        high_water[prior_region] = high_water.get(prior_region, 0) + 1
    topology = {
        "schema": SCHEMA,
        "middles": {middle_key: {"region": chain.middle_region, "ordinal": ordinal}},
        "edge_groups": {f"group_{ordinal:02d}_{region.replace('-', '_')}": {
            "region": region, "middle_node": middle_key, "ordinals": [edge_ordinal]}},
        "regional_high_water": dict(sorted(high_water.items())),
    }
    nodes = {
        f'digitalocean_droplet.middle["{middle_key}"]': DigitalOceanNodeCreate(
            f"middle{ordinal:02d}-{names.engagement_name}", image,
            chain.middle_size, chain.middle_region, selector),
        f'digitalocean_droplet.edge["{edge_key}"]': DigitalOceanNodeCreate(
            f"edge-{names.engagement_name}-{region}-{edge_ordinal:02d}", image,
            chain.edge_size, region, selector),
    }
    trusted = (f"{proxy_ip}/32",)
    firewall = DigitalOceanInitialFirewallIntent(
        f"{names.engagement_name}-firewall", selector, ("80", "443", "2222"), (), trusted)
    varfile = {
        "middles": topology["middles"], "edge_groups": topology["edge_groups"],
        "docean_image": image, "engagement_name": names.engagement_name,
        "firewall_selector_tag": selector, "middle_size": chain.middle_size,
        "edge_size": chain.edge_size, "allowed_tcp_ports": ["22", "80", "443", "2222"],
        "allowed_udp_ports": [], "trusted_ssh_cidrs": list(trusted),
    }
    return MixedDigitalOceanInitialIntent(
        engagement.id, shared.engagement_name, core_job.id, core_plan.id,
        core_plan.revision_id, shared.review_fingerprint, connection_id,
        snapshots["digitalocean"]["encryptedSecretSha256"],
        snapshots["digitalocean"]["updatedAt"], middle_key, edge_key,
        chain.assigned_proxy, trusted, shared.admin_public_key, "do-key",
        selector, topology, nodes, firewall, varfile)
