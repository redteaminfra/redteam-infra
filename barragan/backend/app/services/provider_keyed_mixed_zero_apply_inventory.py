# Copyright (c) 2026, Oracle and/or its affiliates.
"""GET-only provider visibility for a fenced mixed generation with no Sketch Apply.

An empty complete read is transient evidence, never destroy authority. This
module has no provider write, Terraform, public route, or lifecycle caller.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from app.integrations.linode_validation import UrllibLinodeTransport
from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_digitalocean_tag_eligibility import _complete_inventory
from app.services.provider_keyed_inspector_linode_cleanup import _complete_rows
from app.services.provider_keyed_mixed_initial_plan_parent import _records
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    audit_mixed_zero_apply_teardown_source,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_selector_preflight import _scan_endpoint
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository


class MixedZeroApplyInventoryAttention(ValueError):
    """Provider absence or its reviewed authority is currently uncertain."""


@dataclass(frozen=True)
class MixedZeroApplyInventoryEvidence:
    linode_instances_checked: int
    linode_firewalls_checked: int
    digitalocean_tags_checked: int
    digitalocean_droplets_checked: int
    digitalocean_firewalls_checked: int
    observation_sha256: str


def _credential(provider, intent, repository):
    record = repository.get(intent.provider_connection_id)
    default = repository.get_default(provider)
    if (record is None or default is None or record != default
            or record.id != intent.provider_connection_id
            or record.provider != provider or record.status != "active"
            or record.is_default is not True
            or hashlib.sha256(record.encrypted_secret.encode()).hexdigest()
            != intent.credential_secret_sha256
            or record.updated_at != intent.credential_updated_at):
        raise ValueError("reviewed provider credential changed")
    return record.encrypted_secret


def _linode_rows(client, token: str, intent, inspector_rows):
    planned_labels = {node.label.casefold() for node in intent.nodes.values()}
    planned_labels.add(intent.engagement_name.casefold())
    planned_labels.add(f"fw-{intent.engagement_name}-firewall".casefold())
    planned_tags = {node.tag.casefold() for node in intent.nodes.values()}
    allowed = {
        ("/linode/instances" if row.resource_type == "inspector_instance"
         else "/networking/firewalls", str(row.resource_id)): row
        for row in inspector_rows
    }
    result = {}
    for endpoint in ("/linode/instances", "/networking/firewalls"):
        rows = _complete_rows(client, token, endpoint)
        for row in rows:
            label = row.get("label")
            tags = row.get("tags")
            if (type(label) is not str or not label
                    or type(tags) is not list or any(type(tag) is not str for tag in tags)):
                raise ValueError("Linode row identity is incomplete")
            if label.casefold() in planned_labels or any(
                    tag.casefold() in planned_tags for tag in tags):
                raise ValueError("reviewed Linode Sketch identity is visible")
            inspector = allowed.get((endpoint, str(row["id"])))
            if inspector is not None and label != inspector.name:
                raise ValueError("owned Inspector Linode identity changed")
        result[endpoint] = rows
    return result


def _digitalocean_rows(client, token: str, intent):
    selector = intent.selector_tag.casefold()
    names = {node.name.casefold() for node in intent.nodes.values()}
    names.add(intent.firewall.name.casefold())
    tags_count = _scan_endpoint("tags", intent.selector_tag, token, client)
    result = {}
    for endpoint, filters in (("/droplets", {}), ("/droplets", {"type": "gpus"}),
                              ("/firewalls", {})):
        rows = _complete_inventory(client, token, endpoint, endpoint[1:], filters, lambda: None)
        for row in rows:
            name = row.get("name")
            tags = row.get("tags")
            if (type(name) is not str or not name or type(tags) is not list
                    or any(type(tag) is not str for tag in tags)):
                raise ValueError("DigitalOcean row identity is incomplete")
            if name.casefold() in names or any(tag.casefold() == selector for tag in tags):
                raise ValueError("reviewed DigitalOcean Sketch identity is visible")
        result[(endpoint, tuple(sorted(filters.items())))] = rows
    return tags_count, result


def inspect_mixed_zero_apply_provider_inventory(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, lease_owner: str,
    job_repository=None, engagement_repository=None, sketch_repository=None,
    plan_repository=None, credential_repository=None, ssh_key_repository=None,
    provider_resource_repository=None, lease_lookup=None,
    linode_transport=None, digitalocean_transport=None,
    decrypt_secret=decrypt_secret_value,
) -> MixedZeroApplyInventoryEvidence:
    """Return one ephemeral GET observation, never a durable equality fence."""
    jobs = job_repository or SqlAlchemyJobRepository()
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    lookup = lease_lookup or _db_lease_lookup
    audit_kwargs = dict(
        engagement_id=engagement_id, core_job_id=core_job_id,
        environment=environment, state_root=state_root,
        core_state_root=core_state_root, lease_owner=lease_owner,
        job_repository=jobs, engagement_repository=engagements,
        sketch_repository=sketches, plan_repository=plans,
        credential_repository=credentials, ssh_key_repository=keys,
        provider_resource_repository=resources, lease_lookup=lookup,
        lease_operation="provider_keyed_teardown_fence",
    )
    try:
        source = audit_mixed_zero_apply_teardown_source(**audit_kwargs)
        _, _, _, _, intents = _records(
            core_job_id, engagement_id, lease_owner, lookup, engagements,
            sketches, jobs, plans, credentials, keys,
            lease_operation="provider_keyed_teardown_fence")
        secrets = {provider: _credential(provider, intents[provider], credentials)
                   for provider in ("linode", "digitalocean")}
        tokens = {provider: decrypt_secret(secret) for provider, secret in secrets.items()}
        if any(type(token) is not str or not token for token in tokens.values()):
            raise ValueError("provider credential unavailable")
        inspector_rows = resources.list_for_engagement(engagement_id)
        inspector_rows = [row for row in inspector_rows
                          if row.id in source.owned_inspector_record_ids]
        if {row.id for row in inspector_rows} != set(source.owned_inspector_record_ids):
            raise ValueError("owned Inspector rows changed")
        linode = _linode_rows(linode_transport or UrllibLinodeTransport(),
                              tokens["linode"], intents["linode"], inspector_rows)
        tags_count, digitalocean = _digitalocean_rows(
            digitalocean_transport or UrllibProviderCatalogTransport(),
            tokens["digitalocean"], intents["digitalocean"])
        if audit_mixed_zero_apply_teardown_source(**audit_kwargs) != source:
            raise ValueError("fenced source changed during provider reads")
        if any(_credential(provider, intents[provider], credentials) != secrets[provider]
               for provider in ("linode", "digitalocean")):
            raise ValueError("provider credential changed during reads")
        summary = {
            "source": asdict(source),
            "linode": {endpoint: sorted(rows, key=lambda row: str(row["id"]))
                       for endpoint, rows in linode.items()},
            "digitalocean": {str(key): sorted(rows, key=lambda row: str(row["id"]))
                             for key, rows in digitalocean.items()},
            "tagsChecked": tags_count,
        }
        digest = hashlib.sha256(json.dumps(summary, sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest()
        return MixedZeroApplyInventoryEvidence(
            len(linode["/linode/instances"]), len(linode["/networking/firewalls"]),
            tags_count, sum(len(rows) for (endpoint, _), rows in digitalocean.items()
                            if endpoint == "/droplets"),
            len(digitalocean[("/firewalls", ())]), digest,
        )
    except Exception:
        # Provider transports may include raw response bodies in exceptions.
        raise MixedZeroApplyInventoryAttention(
            "mixed zero-Apply provider visibility requires fresh review") from None
