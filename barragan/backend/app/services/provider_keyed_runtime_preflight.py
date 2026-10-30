# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only runtime preflight for the fresh DigitalOcean provider-keyed pilot.

The caller must already hold the engagement's ``provider_keyed_initial`` core
mutation lease. This function neither acquires it nor prepares a Terraform
workspace. Its result is a snapshot, so an eventual plan/apply dispatcher must
repeat ownership and intent checks at the mutation boundary.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable

from app.integrations.oci_deployment_targets import OciDeploymentTargetError, normalized_oci_deployment_target
from app.services.core_ssh import active_core_connection_details
from app.services.managed_host_image_continuity import (
    ManagedHostImageContinuityError,
    managed_host_image_profile_named,
)
from app.services.engagement_teardown import engagement_teardown_in_progress
from app.services.provider_keyed_persisted_intent import (
    ProviderKeyedPersistedIntent,
    ProviderKeyedPersistedIntentError,
    compile_fresh_digitalocean_persisted_intent,
)
from app.services.provider_keyed_sketch import SCHEMA
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.deployment_plan_repository import (
    DeploymentPlanRepository,
    SqlAlchemyDeploymentPlanRepository,
)
from app.storage.engagement_repository import EngagementRepository, SqlAlchemyEngagementRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import SketchChainRepository, SqlAlchemySketchChainRepository, StoredSketchChain


_SAFE_ENGAGEMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
_SAFE_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_LEASE_OPERATION = "provider_keyed_initial"
LeaseLookup = Callable[[str], tuple[str, str] | None]


class ProviderKeyedRuntimePreflightError(ValueError):
    """The current persisted engagement is not eligible for fresh keyed deploy."""


def preflight_fresh_digitalocean_provider(
    engagement_id: str,
    core_job_id: str,
    *,
    lease_owner: str,
    environment: str,
    state_root: Path,
    engagement_repository: EngagementRepository | None = None,
    sketch_repository: SketchChainRepository | None = None,
    job_repository: JobRepository | None = None,
    plan_repository: DeploymentPlanRepository | None = None,
    lease_lookup: LeaseLookup | None = None,
) -> ProviderKeyedPersistedIntent:
    """Compile only the complete, current, reviewed fresh two-chain intent.

    ``state_root`` is Barragan's private Sketch Terraform state root. Any
    preexisting engagement directory is a recovery case, never a fresh deploy.
    Provider account/selector availability is a later independent preflight.
    """

    if environment != "devtest":
        raise ProviderKeyedRuntimePreflightError("provider-keyed runtime requires DevTest")
    if not isinstance(engagement_id, str) or not _SAFE_ENGAGEMENT.fullmatch(engagement_id):
        raise ProviderKeyedRuntimePreflightError("engagement identity is invalid")
    if not isinstance(core_job_id, str) or not core_job_id.strip():
        raise ProviderKeyedRuntimePreflightError("reviewed core job identity is required")
    if not isinstance(lease_owner, str) or not _SAFE_OWNER.fullmatch(lease_owner):
        raise ProviderKeyedRuntimePreflightError("engagement mutation lease owner is invalid")
    lookup = lease_lookup or _db_lease_lookup
    _require_lease(lookup, engagement_id, lease_owner)
    _require_fresh_state_root(state_root, engagement_id)

    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    _require_no_teardown(engagement_id, jobs)
    engagement = engagements.get(engagement_id)
    core_job = jobs.get(core_job_id)
    if engagement is None or core_job is None:
        raise ProviderKeyedRuntimePreflightError("engagement or reviewed core job is unavailable")
    if (engagement.id != engagement_id or core_job.id != core_job_id
            or engagement.status not in {"planned", "deployed"}):
        raise ProviderKeyedRuntimePreflightError("engagement or core job identity is ineligible")
    try:
        target = normalized_oci_deployment_target(engagement.input_parameters.get("deploymentTarget"))
    except (OciDeploymentTargetError, RuntimeError, TypeError, AttributeError) as exc:
        raise ProviderKeyedRuntimePreflightError("persisted deployment target is invalid") from exc
    if (core_job.target_type != "oci_compartment"
            or core_job.target != f"oci-compartment:{target['name']}"
            or core_job.target_id != target["compartmentId"]):
        raise ProviderKeyedRuntimePreflightError("reviewed core job targets another OCI compartment")
    active_core_id, _ = active_core_connection_details(jobs, engagement_id)
    if active_core_id != core_job.id:
        raise ProviderKeyedRuntimePreflightError("reviewed core job is not the active core generation")
    plan_id = core_job.input.get("corePlanId") if isinstance(core_job.input, dict) else None
    if not isinstance(plan_id, str) or not plan_id:
        raise ProviderKeyedRuntimePreflightError("reviewed core plan identity is missing")
    core_plan = plans.get(plan_id)
    if core_plan is None or core_plan.id != plan_id:
        raise ProviderKeyedRuntimePreflightError("reviewed core plan is unavailable")
    profile_name = core_plan.evidence.get("managedHostImageProfile") if isinstance(core_plan.evidence, dict) else None
    if not isinstance(profile_name, str) or not profile_name:
        raise ProviderKeyedRuntimePreflightError("reviewed managed-host image profile is missing")
    try:
        profile = managed_host_image_profile_named(profile_name)
    except ManagedHostImageContinuityError as exc:
        raise ProviderKeyedRuntimePreflightError("reviewed managed-host image profile is unknown") from exc

    complete_chains = chains.list_for_engagement(engagement_id)
    current_chains = [chain for chain in complete_chains if not _inert_aborted_intent(chain, engagement_id)]
    try:
        intent = compile_fresh_digitalocean_persisted_intent(
            engagement, current_chains, core_job, core_plan, profile,
            environment=environment,
            provider_state_exists=False,
        )
    except ProviderKeyedPersistedIntentError as exc:
        raise ProviderKeyedRuntimePreflightError(str(exc)) from exc

    # The lease should serialize mutations. Re-reading still detects a caller
    # using a stale snapshot or an unleased writer before this preflight exits.
    if (engagements.get(engagement_id) != engagement
            or jobs.get(core_job_id) != core_job
            or plans.get(plan_id) != core_plan
            or chains.list_for_engagement(engagement_id) != complete_chains):
        raise ProviderKeyedRuntimePreflightError("persisted provider intent changed during preflight")
    active_core_id, _ = active_core_connection_details(jobs, engagement_id)
    if active_core_id != core_job.id:
        raise ProviderKeyedRuntimePreflightError("reviewed core job is no longer the active core generation")
    _require_fresh_state_root(state_root, engagement_id)
    _require_no_teardown(engagement_id, jobs)
    _require_lease(lookup, engagement_id, lease_owner)
    return intent


def _inert_aborted_intent(chain: object, engagement_id: str) -> bool:
    return (
        isinstance(chain, StoredSketchChain)
        and chain.engagement_id == engagement_id
        and chain.status == "aborted"
        and not chain.burned
        and not chain.deploy_job_id
        and not chain.teardown_job_id
        and not chain.terraform_working_directory
        and not chain.nodes
    )


def reviewed_mixed_chain_rows(complete_chains, reviewed_ids, engagement_id: str) -> list[StoredSketchChain]:
    """Select the exact reviewed pair; only inert aborted history may coexist.

    Callers retain the complete repository snapshot for their mutation fences.
    This projection never changes or deletes historical records.
    """
    if (not isinstance(reviewed_ids, (list, tuple)) or len(reviewed_ids) != 2
            or any(type(identifier) is not str or not identifier for identifier in reviewed_ids)
            or len(set(reviewed_ids)) != 2
            or not isinstance(complete_chains, (list, tuple))
            or any(not isinstance(row, StoredSketchChain) or row.engagement_id != engagement_id
                   for row in complete_chains)):
        raise ProviderKeyedRuntimePreflightError("reviewed mixed chain inventory differs")
    by_id = {row.chain_id: row for row in complete_chains}
    if (len(by_id) != len(complete_chains)
            or not set(reviewed_ids).issubset(by_id)
            or any(not _inert_aborted_intent(row, engagement_id)
                   for row in complete_chains if row.chain_id not in reviewed_ids)):
        raise ProviderKeyedRuntimePreflightError("reviewed mixed chain inventory differs")
    return [by_id[identifier] for identifier in reviewed_ids]


def _db_lease_lookup(engagement_id: str) -> tuple[str, str] | None:
    from app.storage.models import CoreMutationLeaseModel

    row = CoreMutationLeaseModel.query.get(engagement_id)
    return (row.owner_id, row.operation) if row is not None else None


def _require_lease(lookup: LeaseLookup, engagement_id: str, owner: str,
                   *, operation: str = _LEASE_OPERATION) -> None:
    if operation not in {_LEASE_OPERATION, "provider_keyed_teardown_fence"} or lookup(
            engagement_id) != (owner, operation):
        raise ProviderKeyedRuntimePreflightError("engagement mutation lease is not held by this provider job")


def _require_no_teardown(engagement_id: str, jobs: JobRepository) -> None:
    if engagement_teardown_in_progress(engagement_id, repository=jobs) is not None:
        raise ProviderKeyedRuntimePreflightError("engagement teardown is queued or running")


def _require_fresh_state_root(root: Path, engagement_id: str) -> None:
    if root != _default_state_root():
        raise ProviderKeyedRuntimePreflightError("Sketch state root differs from configured runtime root")
    if not isinstance(root, Path) or not root.is_absolute() or root.resolve(strict=False) != root:
        raise ProviderKeyedRuntimePreflightError("Sketch state root is not canonical")
    if os.path.lexists(root) and (root.is_symlink() or not root.is_dir()):
        raise ProviderKeyedRuntimePreflightError("Sketch state root is unsafe")
    engagement_root = root / engagement_id
    if os.path.lexists(engagement_root):
        raise ProviderKeyedRuntimePreflightError(
            f"fresh {SCHEMA} deployment requires no existing Sketch provider workspace or state"
        )
