# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only persisted authority for a later keyed DNS cleanup child.

This module does not authorize a Namecheap mutation. A future GO must reread
this authority under the shared domain lock and prove the live DNS zone.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.services.provider_keyed_comprehensive_teardown import (
    _child_id, recognize_provider_keyed_group_retired,
)
from app.services.provider_keyed_destroy_absence_preflight import _read_success_boundary
from app.services.provider_keyed_dns_cleanup_binding import (
    bind_provider_keyed_dns_cleanup_targets,
)
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class ProviderKeyedDnsCleanupAuthorityError(ValueError):
    """Persisted DNS cleanup identity or assignment cannot be proven."""


@dataclass(frozen=True)
class ProviderKeyedDnsCleanupAuthority:
    engagement_id: str
    domain_id: str
    assignment_id: int
    teardown_parent_id: str
    core_job_id: str
    initial_job_id: str
    group_job_id: str
    scope_snapshot_id: str
    provider_scope_sha256: str
    parent_journal_sha256: str
    initial_journal_sha256: str
    group_journal_sha256: str
    binding_sha256: str
    edge_public_ips: tuple[str, ...]


def load_keyed_dns_cleanup_authority(
    teardown_parent_id: str, domain_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, provider_resource_repository=None,
    domain_repository=None, lease_lookup=None,
) -> ProviderKeyedDnsCleanupAuthority:
    """Load and reread the exact saved keyed teardown and host-binding proof."""
    try:
        if environment != "devtest" or not teardown_parent_id or not domain_id:
            raise ValueError("DevTest persisted authority only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        chains = sketch_repository or SqlAlchemySketchChainRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        domains = domain_repository or SqlAlchemyDomainRepository()
        lookup = lease_lookup or _db_lease_lookup

        parent = jobs.get(teardown_parent_id)
        if parent is not None and getattr(parent, "action", None) == "provider_keyed_mixed_published_cleanup":
            from app.services.provider_keyed_mixed_published_binding_manifest import load_mixed_published_dns_authority
            first = load_mixed_published_dns_authority(parent, domain_id, jobs=jobs,
                plans=plans, sketches=chains, domains=domains, lookup=lookup)
            if load_mixed_published_dns_authority(jobs.get(parent.id), domain_id, jobs=jobs,
                    plans=plans, sketches=chains, domains=domains, lookup=lookup) != first:
                raise ValueError("mixed DNS authority changed during read")
            return first

        def read() -> ProviderKeyedDnsCleanupAuthority:
            bound = _read_success_boundary(
                teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
                credentials=credentials, lookup=lookup,
                handoff_auditor=audit_pending_provider_keyed_bootstrap,
                credential_check=_credential_snapshot, state_root=state_root,
            )
            recognize_provider_keyed_group_retired(
                teardown_parent_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                credential_repository=credentials, provider_resource_repository=resources,
                lease_lookup=lookup,
            )
            parent = jobs.get(teardown_parent_id)
            initial_id = _job_ids(bound.core.id)[0]
            initial = jobs.get(initial_id)
            group_id = _child_id(bound.core.id)
            group = jobs.get(group_id)
            if (parent != bound.parent or initial is None or group is None
                    or initial.target_id != bound.parent.target_id
                    or group.target_id != bound.parent.target_id):
                raise ValueError("persisted keyed jobs changed")
            intent = [event for event in initial.events
                      if event.message == "provider host identity binding intended"]
            sealed = [event for event in initial.events
                      if event.message == "provider host identity bound"]
            if len(intent) != 1 or len(sealed) != 1:
                raise ValueError("persisted host binding differs")
            snapshot = parent.input["scopeSnapshot"]
            binding = bind_provider_keyed_dns_cleanup_targets(
                parent.target_id, confirmed_scope=snapshot["providerScopes"][0],
                provider_scope_sha256=snapshot["providerScopeSha256"],
                host_binding_intent_event=intent[0], host_binding_bound_event=sealed[0],
            )
            asset = domains.get_asset(domain_id)
            assignments = domains.list_assignments(domain_id=domain_id)
            active = [row for row in assignments if row.status == "active"]
            if (asset is None or asset.registrar != "namecheap" or len(active) != 1
                    or active[0].engagement_id != parent.target_id
                    or type(active[0].id) is not int):
                raise ValueError("active Namecheap assignment differs")
            return ProviderKeyedDnsCleanupAuthority(
                engagement_id=parent.target_id, domain_id=domain_id,
                assignment_id=active[0].id, teardown_parent_id=parent.id,
                core_job_id=bound.core.id, initial_job_id=initial_id,
                group_job_id=group_id, scope_snapshot_id=snapshot["snapshotId"],
                provider_scope_sha256=binding.provider_scope_sha256,
                parent_journal_sha256=job_event_digest(parent.events),
                initial_journal_sha256=job_event_digest(initial.events),
                group_journal_sha256=job_event_digest(group.events),
                binding_sha256=binding.binding_sha256,
                edge_public_ips=binding.edge_public_ips,
            )

        first = read()
        if read() != first:
            raise ValueError("keyed DNS authority changed during read")
        return first
    except Exception:
        raise ProviderKeyedDnsCleanupAuthorityError(
            "persisted keyed DNS cleanup authority is unproved"
        ) from None
