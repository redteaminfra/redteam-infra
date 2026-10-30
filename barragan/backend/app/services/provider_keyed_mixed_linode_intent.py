# Copyright (c) 2026, Oracle and/or its affiliates.
"""Canonical initial Linode intent from a reviewed mixed keyed core generation.

No caller topology, provider plan JSON, or mutable UI input is trusted here.
The execution adapter must re-read these records under the engagement lease.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.domain.deployment_plan import DeploymentPlan
from app.integrations.pilot_standard_rti import pilot_names
from app.integrations.oci_deployment_targets import (
    OciDeploymentTargetError, normalized_oci_deployment_target,
)
from app.services.core_ssh import active_core_connection_details
from app.services.engagement_teardown import PILOT_CORE_ACTION
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_linode_initial_plan_gate import (
    LinodeNodeCreate, _SOURCE_REVISION, _SOURCE_SHA256, _LOCK_SHA256,
)
from app.services.provider_keyed_persisted_intent import _reviewed_proxy_egress_ips
from app.services.provider_keyed_sketch import SCHEMA
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key, _fingerprint
from app.storage.credential_repository import CredentialRepository
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import JobRepository, StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain
from app.storage.sketch_ssh_key_repository import SketchSshKeyRepository


class MixedLinodeIntentError(ValueError):
    """Reviewed mixed Linode inputs are missing or changed."""


@dataclass(frozen=True)
class MixedLinodeInitialIntent:
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
    topology: dict[str, Any]
    nodes: dict[str, LinodeNodeCreate]
    nonsecret_varfile: dict[str, Any]


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _reject() -> None:
    raise MixedLinodeIntentError("mixed Linode intent differs from active reviewed core records")


def compile_mixed_linode_initial_intent(
    engagement: StoredEngagement, chains: Sequence[StoredSketchChain],
    core_job: StoredJobRun, core_plan: DeploymentPlan, *,
    job_repository: JobRepository, credential_repository: CredentialRepository,
    ssh_key_repository: SketchSshKeyRepository, expected_admin_public_key: str,
    environment: str,
) -> MixedLinodeInitialIntent:
    """Derive one Linode middle/edge from the applied core review and records."""
    try:
        active_core_job_id, active_details = (
            active_core_connection_details(job_repository, engagement.id)
            if isinstance(engagement, StoredEngagement) and job_repository is not None
            else ("", []))
        persisted_core = job_repository.get(core_job.id) if job_repository is not None else None
    except Exception:
        _reject()
    try:
        material = (retrieve_sketch_ssh_key(engagement.id, ssh_key_repository)
                    if isinstance(engagement, StoredEngagement) else None)
        key_fingerprint = _fingerprint(material.public_key) if material is not None else ""
    except Exception:
        _reject()
    target = ((engagement.input_parameters or {}).get("deploymentTarget")
              if isinstance(engagement, StoredEngagement)
              and isinstance(engagement.input_parameters, Mapping) else None)
    try:
        normalized_target = normalized_oci_deployment_target(target)
    except (OciDeploymentTargetError, TypeError, RuntimeError):
        _reject()
    if (environment != "devtest" or not isinstance(engagement, StoredEngagement)
            or engagement.sketch_state_schema != SCHEMA
            or engagement.status not in {"planned", "deployed"}
            or normalized_target["name"] != "barragan-testing"
            or not isinstance(target, Mapping)
            or any(target.get(field) != normalized_target[field]
                   for field in ("name", "compartmentId", "region"))
            or not isinstance(core_job, StoredJobRun) or not isinstance(core_plan, DeploymentPlan)
            or core_job.id != active_core_job_id or core_job.action != PILOT_CORE_ACTION
            or core_job.target_type != "oci_compartment"
            or core_job.target != "oci-compartment:barragan-testing"
            or core_job.target_id != normalized_target["compartmentId"]
            or not isinstance(core_job.input.get("target"), Mapping)
            or not isinstance(core_plan.evidence.get("target"), Mapping)
            or any(source.get(field) != normalized_target[field]
                   for source in (core_job.input["target"], core_plan.evidence["target"])
                   for field in ("name", "compartmentId", "region"))
            or core_job.status != "succeeded" or core_plan.status != "applied"
            or core_plan.apply_job_id != core_job.id
            or core_job.input.get("engagementId") != engagement.id
            or core_job.input.get("engagementName") != engagement.name
            or core_job.input.get("sketchStateSchema") != SCHEMA
            or core_job.input.get("postCoreSketchContinuationEligible") is not False
            or core_job.input.get("corePlanId") != core_plan.id
            or core_plan.engagement_id != engagement.id
            or core_plan.revision_id != engagement.active_revision
            or persisted_core != core_job
            or not active_details
            or material is None or material.metadata.engagement_id != engagement.id
            or not material.private_key or not material.public_key.strip()
            or material.metadata.fingerprint != key_fingerprint
            or not isinstance(expected_admin_public_key, str)
            or expected_admin_public_key.strip() != material.public_key.strip()
            or not isinstance(chains, Sequence) or len(chains) != 2):
        _reject()
    auth = core_plan.evidence.get("sketchAuthorization")
    reviewed = core_plan.review.get("reviewedConfiguration")
    ids = core_plan.evidence.get("pendingSketchChainIds")
    fingerprints = core_plan.evidence.get("pendingSketchChainFingerprints")
    if (not isinstance(auth, dict) or not isinstance(reviewed, dict)
            or reviewed.get("sketchAuthorization") != auth
            or auth.get("kind") != "bounded-mixed-post-core-v1"
            or auth.get("fingerprint") != _digest({k: v for k, v in auth.items() if k != "fingerprint"})
            or not isinstance(auth.get("providerScopes"), list)
            or len(auth["providerScopes"]) != 2
            or not all(isinstance(scope, Mapping) for scope in auth["providerScopes"])
            or [scope.get("provider") for scope in auth["providerScopes"]] != ["digitalocean", "linode"]
            or not isinstance(ids, list) or len(ids) != 2 or len(set(ids)) != 2
            or not isinstance(fingerprints, dict) or set(fingerprints) != set(ids)
            or core_job.input.get("pendingSketchChainIds") != ids
            or core_job.input.get("pendingSketchChainFingerprints") != fingerprints):
        _reject()
    by_id = {chain.chain_id: chain for chain in chains if isinstance(chain, StoredSketchChain)}
    if len(by_id) != 2 or set(by_id) != set(ids):
        _reject()
    ordered = [by_id[chain_id] for chain_id in ids]
    for chain in ordered:
        if (chain.engagement_id != engagement.id or chain.status != "pending" or chain.burned
                or chain.deploy_job_id or chain.teardown_job_id
                or chain.terraform_working_directory or chain.nodes
                or chain.edge_count != 1 or not isinstance(chain.edge_intents, list)
                or len(chain.edge_intents) != 1
                or chain.edge_intents[0].get("id") != "edge-01"
                or chain.edge_intents[0].get("provider") != chain.edge_provider
                or chain.edge_intents[0].get("region") != chain.edge_region
                or chain.edge_intents[0].get("size") != chain.edge_size
                or fingerprints[chain.chain_id] != sketch_chain_intent_fingerprint(chain)):
            _reject()
    linode = [chain for chain in ordered if chain.middle_provider == chain.edge_provider == "linode"]
    digitalocean = [chain for chain in ordered if chain.middle_provider == chain.edge_provider == "digitalocean"]
    if len(linode) != 1 or len(digitalocean) != 1:
        _reject()
    for provider, matching in (("digitalocean", digitalocean[0]), ("linode", linode[0])):
        provider_scope = auth["providerScopes"][0 if provider == "digitalocean" else 1]
        if (not isinstance(provider_scope, dict)
                or provider_scope.get("chain") != {
                    "id": matching.chain_id,
                    "fingerprint": fingerprints[matching.chain_id],
                    "assignedProxy": matching.assigned_proxy,
                    "middle": {"provider": provider, "region": matching.middle_region,
                               "size": matching.middle_size},
                    "edges": [{"id": "edge-01", "provider": provider,
                               "region": matching.edge_region, "size": matching.edge_size}],
                }):
            _reject()
    chain = linode[0]
    ordinal = ids.index(chain.chain_id) + 1
    scope = auth["providerScopes"][1]
    reviewed_chain = scope.get("chain") if isinstance(scope, dict) else None
    source = scope.get("source") if isinstance(scope, dict) else None
    firewall = {"publicTcpPorts": ["80", "443", "2222"], "publicUdpPorts": [],
                "publicIpv6Allowed": False,
                "managementSsh": {"port": 22,
                                  "sourceRule": "selected-proxy-public-ipv4-32",
                                  "proxyNames": [chain.assigned_proxy]},
                "peerIngress": {"protocols": ["tcp", "udp", "icmp"],
                                "portRange": "1-65535",
                                "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32"},
                "outboundIpv4": "accept", "outboundIpv6": "drop"}
    if (source != {"revision": _SOURCE_REVISION, "templateSha256": _SOURCE_SHA256,
                   "providerLock": {"path": "barragan-v2/.terraform.lock.hcl",
                                    "sha256": _LOCK_SHA256, "providerVersion": "4.5.0"}}
            or not isinstance(reviewed_chain, dict)
            or scope.get("firewall") != firewall
            or reviewed_chain != {"id": chain.chain_id,
                                  "fingerprint": fingerprints[chain.chain_id],
                                  "assignedProxy": chain.assigned_proxy,
                                  "middle": {"provider": "linode", "region": chain.middle_region,
                                             "size": chain.middle_size},
                                  "edges": [{"id": "edge-01", "provider": "linode",
                                             "region": chain.edge_region,
                                             "size": chain.edge_size}]}
            or not isinstance(scope.get("providerConnectionId"), str)
            or not scope["providerConnectionId"]):
        _reject()
    connection_id = scope["providerConnectionId"]
    snapshots = core_plan.evidence.get("keyedProviderCredentialSnapshots")
    try:
        credential = credential_repository.get(connection_id)
        default = credential_repository.get_default("linode")
    except Exception:
        _reject()
    if (not isinstance(snapshots, dict) or set(snapshots) != {"digitalocean", "linode"}
            or credential is None or default is None
            or credential.id != connection_id or default.id != connection_id
            or credential.provider != "linode" or default.provider != "linode"
            or credential.status != "active" or default.status != "active"
            or credential.is_default is not True or default.is_default is not True
            or not isinstance(credential.encrypted_secret, str)
            or not credential.encrypted_secret
            or credential.encrypted_secret != default.encrypted_secret
            or credential.updated_at != default.updated_at
            or snapshots["linode"] != {
                "encryptedSecretSha256": hashlib.sha256(credential.encrypted_secret.encode()).hexdigest(),
                "updatedAt": credential.updated_at,
            }):
        _reject()
    try:
        names = pilot_names(engagement.name)
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
    image = scope.get("image")
    if (not isinstance(image, str) or not image
            or core_plan.evidence.get("linodeImage") != image
            or reviewed.get("linodeImage") != image):
        _reject()
    public_key = material.public_key.strip()
    regional_high_water: dict[str, int] = {}
    for reviewed_chain in ordered[:ordinal]:
        reviewed_region = reviewed_chain.edge_region
        regional_high_water[reviewed_region] = regional_high_water.get(reviewed_region, 0) + 1
    topology = {"schema": SCHEMA,
                "middles": {middle_key: {"region": chain.middle_region, "ordinal": ordinal}},
                "edge_groups": {f"group_{ordinal:02d}_{region.replace('-', '_')}": {
                    "region": region, "middle_node": middle_key, "ordinals": [edge_ordinal]}},
                "regional_high_water": dict(sorted(regional_high_water.items()))}
    nodes = {
        f'linode_instance.middle["{middle_key}"]': LinodeNodeCreate(
            f"middle{ordinal:02d}-{names.engagement_name}", image,
            chain.middle_size, chain.middle_region, names.engagement_name, (public_key,)),
        f'linode_instance.edge["{edge_key}"]': LinodeNodeCreate(
            f"edge-{names.engagement_name}-{region}-{edge_ordinal:02d}", image,
            chain.edge_size, region, names.engagement_name, (public_key,)),
    }
    trusted = (f"{proxy_ip}/32",)
    varfile = {"middles": topology["middles"], "edge_groups": topology["edge_groups"],
               "linode_image": image, "engagement_name": names.engagement_name,
               "middle_type": chain.middle_size, "edge_type": chain.edge_size,
               "allowed_tcp_ports": ["22", "80", "443", "2222"],
               "allowed_udp_ports": [],
               "trusted_ssh_cidrs": list(trusted)}
    return MixedLinodeInitialIntent(
        engagement.id, names.engagement_name, core_job.id, core_plan.id,
        core_plan.revision_id, auth["fingerprint"], connection_id,
        snapshots["linode"]["encryptedSecretSha256"], snapshots["linode"]["updatedAt"],
        middle_key, edge_key, chain.assigned_proxy, trusted, public_key,
        topology, nodes, varfile,
    )
