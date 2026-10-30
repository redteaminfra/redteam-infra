# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from app.core.runtime import has_runtime_context
from app.domain import DeploymentRevisionPlan
from app.services.credentials import resolve_default_credential_alias
from app.integrations.managed_host_images import managed_host_image_profile


CORE_PROVIDER = "oci"
SKETCH_PROVIDERS = {"linode", "digitalocean"}
SKETCH_PROVIDER_DEFAULTS = {
    "linode": {
        "moduleSource": "external/sketch/linode",
        "tokenVariable": "linode_api_token",
        "tokenEnvVar": "TF_VAR_linode_api_token",
        "imageVariable": "linode_image",
        "imageDefault": managed_host_image_profile().linode_image,
        "middleSizeVariable": "middle_type",
        "edgeSizeVariable": "edge_type",
        "middleSizeDefault": "g6-nanode-1",
        "edgeSizeDefault": "g6-nanode-1",
    },
    "digitalocean": {
        "moduleSource": "external/sketch/digitalocean",
        "tokenVariable": "do_pat",
        "tokenEnvVar": "TF_VAR_do_pat",
        "imageVariable": "docean_image",
        "imageDefault": managed_host_image_profile().digitalocean_image,
        "middleSizeVariable": "middle_size",
        "edgeSizeVariable": "edge_size",
        "middleSizeDefault": "s-1vcpu-1gb",
        "edgeSizeDefault": "s-1vcpu-1gb",
    },
}


@dataclass(frozen=True)
class ProviderResourcePlan:
    id: str
    provider: str
    role: str
    count: int
    mode: str
    attributes: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider,
            "role": self.role,
            "count": self.count,
            "mode": self.mode,
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class ProviderPlanBundle:
    revision_id: str
    mode: str
    core: list[ProviderResourcePlan]
    sketch: list[ProviderResourcePlan]
    warnings: list[str]

    def to_dict(self) -> dict:
        return {
            "revisionId": self.revision_id,
            "mode": self.mode,
            "core": [resource.to_dict() for resource in self.core],
            "sketch": [resource.to_dict() for resource in self.sketch],
            "warnings": self.warnings,
        }


def build_provider_plan_bundle(revision: DeploymentRevisionPlan) -> ProviderPlanBundle:
    body = revision.to_dict()
    core = []
    sketch = []
    warnings = []
    sketch_chains_by_id = {
        chain["id"]: chain for chain in body["resolvedTopology"]["sketchChains"]
    }

    for node_group in body["resolvedTopology"]["nodeGroups"]:
        provider = node_group["provider"]
        attributes = {
            "subnet": node_group.get("subnet"),
            "sourceRevisionId": revision.id,
        }
        if provider in SKETCH_PROVIDERS:
            chain = _sketch_chain_for_node_group(node_group["id"], sketch_chains_by_id)
            if chain:
                attributes.update(_sketch_resource_attributes(revision, node_group, chain))
                if not attributes.get("credentialAlias"):
                    warnings.append(
                        f"{node_group['id']} has no active default {provider} credential; live provider mutation will be blocked"
                    )
            else:
                warnings.append(f"sketch node group has no matching chain: {node_group['id']}")
        resource = ProviderResourcePlan(
            id=node_group["id"],
            provider=provider,
            role=node_group["role"],
            count=node_group["count"],
            mode="dry_run",
            attributes=attributes,
        )
        if provider == CORE_PROVIDER:
            core.append(resource)
        elif provider in SKETCH_PROVIDERS:
            sketch.append(resource)
        else:
            warnings.append(f"unsupported provider in dry-run plan: {provider}")

    return ProviderPlanBundle(
        revision_id=revision.id,
        mode="dry_run",
        core=core,
        sketch=sketch,
        warnings=warnings,
    )


def render_terraform_intent(bundle: ProviderPlanBundle) -> dict:
    return {
        "mode": "dry_run",
        "mutation": False,
        "providers": {
            "oci": [resource.to_dict() for resource in bundle.core],
            "linode": [
                resource.to_dict() for resource in bundle.sketch if resource.provider == "linode"
            ],
            "digitalocean": [
                resource.to_dict() for resource in bundle.sketch if resource.provider == "digitalocean"
            ],
        },
        "warnings": bundle.warnings,
    }


def _sketch_chain_for_node_group(node_group_id: str, chains_by_id: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    for prefix in ("middle-", "edge-"):
        if node_group_id.startswith(prefix):
            return chains_by_id.get(node_group_id.removeprefix(prefix))
    return None


def _sketch_resource_attributes(
    revision: DeploymentRevisionPlan,
    node_group: dict[str, Any],
    chain: dict[str, Any],
) -> dict[str, Any]:
    provider = node_group["provider"]
    role = node_group["role"]
    defaults = SKETCH_PROVIDER_DEFAULTS[provider]
    credential_alias = (
        chain.get("middleCredentialAlias") if role == "middle" else chain.get("edgeCredentialAlias")
    )
    credential_source = "explicit_alias" if credential_alias else "provider_default"
    if not credential_alias:
        credential_alias = _default_credential_alias(provider)
    region = chain["middleRegion"] if role == "middle" else chain["edgeRegion"]
    size = chain["middleSize"] if role == "middle" else chain["edgeSize"]
    size_variable = defaults["middleSizeVariable"] if role == "middle" else defaults["edgeSizeVariable"]
    credential_ref = _credential_ref(provider, credential_alias)

    terraform_variables = {
        defaults["tokenVariable"]: {
            "source": "credential_alias",
            "credentialAlias": credential_alias,
            "credentialRef": credential_ref,
            "credentialSource": credential_source,
            "envVar": defaults["tokenEnvVar"],
            "sensitive": True,
        },
        defaults["imageVariable"]: defaults["imageDefault"],
        size_variable: size,
        "engagement_name": revision.input_parameters["engagementName"],
        "allowed_tcp_ports": ["22", "80", "443", "2222"],
        "ssh_pub_key_path": "~/.ssh/barragan_testing.pub",
        "ssh_priv_key_path": "~/.ssh/barragan_testing",
        "ssh_config_path": "~/.ssh",
    }
    if role == "middle":
        terraform_variables["middle_region"] = region
        terraform_variables["middle_count"] = 1
    else:
        terraform_variables["edge_regions"] = [region]
        terraform_variables["edge_count_per_region"] = int(chain.get("edgeCount") or 1)

    return {
        "chainId": chain["id"],
        "assignedProxy": chain["assignedProxy"],
        "credentialAlias": credential_alias,
        "credentialRef": credential_ref,
        "credentialSource": credential_source if credential_alias else "missing_provider_default",
        "credentialEnvVar": defaults["tokenEnvVar"],
        "region": region,
        "size": size,
        "moduleSource": defaults["moduleSource"],
        "resourceName": _sketch_resource_name(revision.input_parameters["engagementName"], role, chain["id"]),
        "terraformVariables": terraform_variables,
    }


def _credential_ref(provider: str, credential_alias: str | None) -> str | None:
    if not credential_alias:
        return None
    return f"credential://{provider}/{credential_alias}"


def _default_credential_alias(provider: str) -> str | None:
    if not has_runtime_context():
        return None
    try:
        return resolve_default_credential_alias(provider)
    except (RuntimeError, SQLAlchemyError):
        return None


def _sketch_resource_name(engagement_name: str, role: str, chain_id: str) -> str:
    suffix = chain_id.replace("_", "-")
    return f"{role}-{engagement_name}-{suffix}"


def render_ansible_intent(revision: DeploymentRevisionPlan, bundle: ProviderPlanBundle) -> dict:
    topology = revision.to_dict()["resolvedTopology"]
    return {
        "mode": "dry_run",
        "mutation": False,
        "inventory": {
            "core": [resource.to_dict() for resource in bundle.core],
            "sketch": [resource.to_dict() for resource in bundle.sketch],
        },
        "runbook": [
            {
                "step": "configure_homebase",
                "targets": [resource.id for resource in bundle.core if resource.role == "homebase"],
            },
            {
                "step": "configure_proxies",
                "targets": [resource.id for resource in bundle.core if resource.role == "proxy"],
            },
            {
                "step": "configure_sketch_through_managed_paths",
                "managementPaths": [
                    chain["managementPath"] for chain in topology["sketchChains"]
                ],
            },
            {
                "step": "publish_operator_proxy_profiles",
                "profiles": [
                    {
                        "profileId": profile["id"],
                        "ownerProxy": profile["proxy"],
                        "listenerPort": profile["details"]["listenerPort"],
                        "publicationPath": profile["details"]["publicationPath"],
                        "backingSketchChainId": profile["sketchChainId"],
                    }
                    for profile in topology["egressProfiles"]
                ],
            },
        ],
    }
