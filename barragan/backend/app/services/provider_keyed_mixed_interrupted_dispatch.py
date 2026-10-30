# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private review/reservation and two-plan seal for interrupted mixed cleanup.

This coordinator has no Terraform command runner and no provider write. The
sealed checkpoint is a prerequisite for later one-shot provider destruction,
not itself GO authority.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import stat
from typing import Callable, Mapping
from uuid import uuid4

from app.services.core_ssh import active_core_connection_details
from app.services.engagement_teardown import _fingerprint
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_initial_apply_child import _child_id
from app.services.provider_keyed_mixed_initial_host_attestation import (
    recognize_safe_incomplete_mixed_host_worker,
)
from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id as _host_worker_id
from app.services.provider_keyed_mixed_initial_apply_proof import _process_quiescent
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id as initial_parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    _parent_id as cleanup_parent_id, propose_mixed_interrupted_cleanup,
    _review_scope_input,
    recognize_mixed_interrupted_cleanup_checkpoint,
    recognize_mixed_interrupted_sealed_plans,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import (
    MixedInterruptedDestroyPlan, MixedInterruptedDestroyPlanSet,
    bind_mixed_interrupted_destroy_plans,
)
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedProviderScope, MixedInterruptedReview,
    review_mixed_interrupted_source,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import (
    collect_provider_inventory_snapshot,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


class MixedInterruptedDispatchAttention(ValueError):
    """A fenced mixed review or both-plan seal requires operator attention."""


def is_mixed_interrupted_request(job: StoredJobRun | None, *, jobs=None) -> bool:
    if job is None:
        return False
    from app.services.provider_keyed_mixed_interrupted_cleanup import ACTION
    if job.action == ACTION:
        return True
    if job.action != "pilot_standard_rti_guarded_execute":
        return False
    jobs = jobs or SqlAlchemyJobRepository()
    parent = jobs.get(cleanup_parent_id(job.id))
    if parent is not None:
        return parent.action == ACTION and parent.target_id == job.input.get("engagementId")
    initial = jobs.get(initial_parent_id(job.id))
    return (initial is not None and initial.action == "provider_keyed_mixed_initial"
            and initial.status in {"queued", "running"}
            and initial.input.get("phase") in {"apply_sealed", "awaiting_mixed_host_proof"})


def _review_snapshot_id(review: MixedInterruptedReview) -> str:
    """Bind operator confirmation to source facts, excluding collection nonce."""
    payload = asdict(review)
    payload.pop("review_sha256")
    for scope in payload["scopes"]:
        scope.pop("observation_sha256")
    return hashlib.sha256(json.dumps(payload, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _core_inspector_scope(core: StoredJobRun, *, jobs, core_state_root: Path,
                          plan_repository=None, provider_resource_repository=None) -> dict:
    """Read the same sealed OCI/Inspector authority used by the teardown tail."""
    from app.services.provider_keyed_mixed_zero_apply_inspector_negative import _targets
    from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
        _core_inventory, _owned_inspector_records,
    )
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    plan = plans.get(core.input.get("corePlanId"))
    if (plan is None or plan.engagement_id != core.input.get("engagementId")
            or plan.evidence.get("target", {}).get("name") != "barragan-testing"):
        raise ValueError("reviewed core plan differs")
    inventory = _core_inventory(core, plan, core_state_root)
    proxy_count = plan.evidence["proxyCount"]
    targets = _targets(core, proxy_count)
    inspector_ids = _owned_inspector_records(core.input["engagementId"], jobs, resources)
    if (len(inspector_ids) != 2 or len(set(inspector_ids)) != 2
            or any(type(value) is not str or not value for value in inspector_ids)
            or jobs.get(core.id) != core or plans.get(plan.id) != plan
            or _core_inventory(core, plan, core_state_root) != inventory
            or _owned_inspector_records(core.input["engagementId"], jobs, resources)
            != inspector_ids):
        raise ValueError("reviewed core or Inspector changed")
    return {"jobId": core.id, "planId": plan.id,
            "stateSha256": inventory.raw_state_sha256,
            "inventorySha256": inventory.inventory_sha256,
            "proxyCount": proxy_count, "targets": targets,
            "ownedInspectorRecordIds": list(inspector_ids)}


def _scope_snapshot_id(review: MixedInterruptedReview, scope: dict) -> str:
    return _fingerprint({"sketchReviewSha256": _review_snapshot_id(review),
                         "coreInspectorScope": scope})


def _saved_core_inspector_scope(parent: StoredJobRun) -> dict:
    scope = parent.input.get("reviewScope")
    if scope is None:
        raise ValueError("saved mixed core and Inspector review is absent")
    validated = _review_scope_input(scope)
    if parent.input.get("reviewScopeSha256") != validated["reviewScopeSha256"]:
        raise ValueError("saved mixed core and Inspector review differs")
    return validated["reviewScope"]


def _workspace(initial: StoredJobRun, provider: str, state_root: Path) -> ProviderKeyedWorkspace:
    seal = validate_mixed_initial_apply_seal(initial)
    connection_id = seal["reviewedPolicy"][provider]["provider_connection_id"]
    fingerprint = hashlib.sha256(f"{provider}\0{connection_id}".encode()).hexdigest()
    root = state_root / initial.target_id / SCHEMA / provider / fingerprint
    marker_path = root / ".barragan-provider-keyed-state.json"
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or root.resolve(strict=True) != root or marker_path.is_symlink()):
        raise ValueError("mixed provider workspace differs")
    marker = json.loads(marker_path.read_text())
    if (type(marker) is not dict or marker.get("schema") != SCHEMA
            or marker.get("engagement_id") != initial.target_id
            or marker.get("provider") != provider
            or marker.get("provider_connection_id") != connection_id
            or marker.get("connection_fingerprint") != fingerprint
            or type(marker.get("source_revision")) is not str
            or type(marker.get("source_files")) is not dict):
        raise ValueError("mixed provider workspace marker differs")
    source_sha = hashlib.sha256(json.dumps(marker["source_files"], sort_keys=True).encode()).hexdigest()
    return ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data", SCHEMA,
        provider, connection_id, fingerprint, marker["source_revision"], source_sha)


def _quiescent_child(child: StoredJobRun | None,
                     process_quiescent: Callable[[dict], bool]) -> bool:
    if child is None:
        return True
    starts = [row.data for row in child.events
              if row.message == "mixed provider Apply command started before GO"]
    if len(starts) > 1:
        return False
    if not starts:
        return True
    data = starts[0]
    if type(data) is not dict or not {"bootId", "pid", "pgid", "startTicks"} <= set(data):
        return False
    return process_quiescent({key: data[key] for key in ("bootId", "pid", "pgid", "startTicks")}) is True


def _default_quiescent(identity: dict) -> bool:
    return _process_quiescent(identity["bootId"], identity["pid"],
                              identity["pgid"], identity["startTicks"])


def _saved_review(parent: StoredJobRun) -> MixedInterruptedReview:
    raw = parent.input.get("source")
    if type(raw) is not dict or set(raw) != {
            "engagement_id", "core_job_id", "seal_journal_sha256", "ordered_providers",
            "scopes", "review_sha256"}:
        raise ValueError("mixed interrupted saved review differs")
    scopes = []
    for item in raw["scopes"]:
        if type(item) is not dict or set(item) != set(MixedInterruptedProviderScope.__dataclass_fields__):
            raise ValueError("mixed interrupted provider scope differs")
        scopes.append(MixedInterruptedProviderScope(
            **{**item, "resource_ids": tuple(tuple(row) for row in item["resource_ids"])}))
    return MixedInterruptedReview(
        raw["engagement_id"], raw["core_job_id"], raw["seal_journal_sha256"],
        tuple(raw["ordered_providers"]), tuple(scopes), raw["review_sha256"])


def _saved_plans(parent: StoredJobRun) -> MixedInterruptedDestroyPlanSet:
    if len(parent.events) != 2 or parent.events[1].message != "both mixed destroy plans sealed":
        raise ValueError("mixed interrupted plan seal is absent")
    event = parent.events[1].data
    if type(event) is not dict or set(event) != {"planSet", "planSetSha256"}:
        raise ValueError("mixed interrupted saved plan event differs")
    raw = event["planSet"]
    if (type(raw) is not dict or set(raw) != {
            "review_sha256", "ordered_providers", "plans", "plan_set_sha256"}
            or raw["plan_set_sha256"] != event["planSetSha256"]
            or type(raw["plans"]) is not list):
        raise ValueError("mixed interrupted saved plan set differs")
    plans = []
    for item in raw["plans"]:
        if type(item) is not dict or set(item) != set(MixedInterruptedDestroyPlan.__dataclass_fields__):
            raise ValueError("mixed interrupted saved provider plan differs")
        plans.append(MixedInterruptedDestroyPlan(
            **{**item, "resource_ids": tuple(tuple(row) for row in item["resource_ids"])}))
    return MixedInterruptedDestroyPlanSet(
        raw["review_sha256"], tuple(raw["ordered_providers"]),
        tuple(plans), raw["plan_set_sha256"])


def _verify_saved_plan_artifacts(plans: MixedInterruptedDestroyPlanSet,
                                 plan_paths: Mapping[str, Path | None],
                                 show_json: Mapping[str, str | None]) -> None:
    if set(plan_paths) != set(plans.ordered_providers) or set(show_json) != set(plans.ordered_providers):
        raise ValueError("both saved provider plans are required")
    for plan in plans.plans:
        path, shown = plan_paths[plan.provider], show_json[plan.provider]
        if plan.plan_path is None:
            if path is not None or shown is not None:
                raise ValueError("unexpected provider plan artifact")
            continue
        if (not isinstance(path, Path) or str(path) != plan.plan_path
                or path.is_symlink() or not path.is_file()
                or path.parent.resolve(strict=True) != path.parent
                or type(shown) is not str):
            raise ValueError("saved provider plan artifact differs")
        meta = path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_size < 1
                or meta.st_size > 128 * 1024 * 1024):
            raise ValueError("saved provider plan metadata differs")
        plan_bytes = path.read_bytes()
        if (len(plan_bytes) != meta.st_size
                or hashlib.sha256(plan_bytes).hexdigest() != plan.plan_sha256
                or hashlib.sha256(shown.encode()).hexdigest() != plan.show_json_sha256):
            raise ValueError("saved provider plan bytes or show output changed")


def _fresh_review(initial: StoredJobRun, *, jobs, lookup, state_root,
                  quiescent, snapshot_collector, credential_repository,
                  linode_transport, digitalocean_transport):
    if (initial.status != "running" or initial.finished_at is not None
            or initial.input.get("phase") not in {"apply_sealed", "awaiting_mixed_host_proof"}):
        raise ValueError("mixed initial cleanup phase differs")
    seal = validate_mixed_initial_apply_seal(initial)
    order = tuple(seal["orderedProviders"])
    core_job_id = initial.input["coreJobId"]
    engagement_id = initial.target_id
    children = {provider: jobs.get(_child_id(core_job_id, provider)) for provider in order}
    host_rows = None
    if initial.input["phase"] == "awaiting_mixed_host_proof":
        core = jobs.get(core_job_id)
        binding = jobs.get(_binding_child_id(core_job_id))
        worker = jobs.get(_host_worker_id(core_job_id))
        active_core_id, _ = active_core_connection_details(jobs, engagement_id)
        recognize_safe_incomplete_mixed_host_worker(
            initial, core, children, binding, worker, active_core_id,
            process_quiescent=quiescent)
        host_rows = (core, binding, worker)
    generation = uuid4().hex

    def fence() -> str:
        if (jobs.get(initial.id) != initial
                or any(jobs.get(_child_id(core_job_id, provider)) != children[provider]
                       for provider in order)
                or (host_rows is not None and (
                    jobs.get(core_job_id) != host_rows[0]
                    or jobs.get(_binding_child_id(core_job_id)) != host_rows[1]
                    or jobs.get(_host_worker_id(core_job_id)) != host_rows[2]))
                or lookup(engagement_id) != (initial.input["corePlanId"],
                                             "provider_keyed_initial")):
            raise ValueError("mixed initial generation changed during review")
        return generation

    snapshots = {}
    for provider in order:
        workspace = _workspace(initial, provider, state_root)
        snapshots[provider] = snapshot_collector(
            initial, provider, workspace, fence=fence,
            process_quiescent=lambda provider=provider: _quiescent_child(
                children[provider], quiescent),
            credential_repository=credential_repository,
            linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport)
    review = review_mixed_interrupted_source(
        initial, children, snapshots, fence=fence, process_quiescent=quiescent)
    return review, snapshots, generation, host_rows


def preview_mixed_interrupted_cleanup(
    job: StoredJobRun, *, environment: str, state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, lease_lookup=None, credential_repository=None,
    plan_repository=None, provider_resource_repository=None,
    linode_transport=None, digitalocean_transport=None,
    process_quiescent: Callable[[dict], bool] | None = None,
    snapshot_collector: Callable = collect_provider_inventory_snapshot,
) -> dict:
    """Read-only preview of the exact two-provider interrupted teardown scope."""
    if environment != "devtest":
        raise MixedInterruptedDispatchAttention("mixed interrupted cleanup is DevTest-only")
    state_root = state_root or _default_state_root()
    if state_root != _default_state_root():
        raise MixedInterruptedDispatchAttention("configured DevTest state root differs")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        core_id = (job.input.get("coreJobId") if job.action ==
                   "provider_keyed_mixed_interrupted_cleanup" else job.id)
        core = jobs.get(core_id)
        initial = jobs.get(initial_parent_id(core_id))
        parent = jobs.get(cleanup_parent_id(core_id))
        if (core is None or core.action != "pilot_standard_rti_guarded_execute"
                or initial is None or initial.target_id != core.input.get("engagementId")
                or job.id not in {core.id, parent.id if parent else None}):
            raise ValueError("mixed interrupted core differs")
        if parent is None:
            review, _, _, _ = _fresh_review(
                initial, jobs=jobs, lookup=lookup, state_root=state_root,
                quiescent=process_quiescent or _default_quiescent,
                snapshot_collector=snapshot_collector,
                credential_repository=credential_repository,
                linode_transport=linode_transport,
                digitalocean_transport=digitalocean_transport)
        else:
            if parent.status == "succeeded":
                from app.services.provider_keyed_mixed_interrupted_terminal import (
                    _historical_parent, recognize_mixed_interrupted_terminal,
                )
                recognize_mixed_interrupted_terminal(
                    core.input["engagementId"], core.id, environment=environment,
                    job_repository=jobs, lease_lookup=lookup)
                historical = _historical_parent(parent)
            else:
                historical = parent
            review = _saved_review(parent)
            if parent.status != "succeeded" and lookup(core.input["engagementId"]) != (
                    initial.input["corePlanId"], "provider_keyed_teardown_fence"):
                raise ValueError("mixed interrupted teardown fence differs")
            if historical.input.get("phase") == "plans_sealed":
                recognize_mixed_interrupted_sealed_plans(
                    historical, initial, review, _saved_plans(historical))
            else:
                recognize_mixed_interrupted_cleanup_checkpoint(historical, initial, review)
        name = str(core.input.get("engagementName") or core.input["engagementId"])
        scope = (_saved_core_inspector_scope(parent) if parent is not None
                 else _core_inspector_scope(
                     core, jobs=jobs, core_state_root=core_state_root,
                     plan_repository=plan_repository,
                     provider_resource_repository=provider_resource_repository))
        from app.services.engagement_teardown import _confirmation_phrase
        return {
            "snapshotId": _scope_snapshot_id(review, scope),
            "engagementId": review.engagement_id,
            "engagementName": name,
            "confirmationPhrase": _confirmation_phrase(name),
            "parentJobId": parent.id if parent else None,
            "orderedScope": [
                {"id": "sketch", "label": "Destroy owned Sketch providers",
                 "items": [{"provider": scope.provider, "kind": scope.kind,
                            "resourceCount": len(scope.resource_ids)}
                           for scope in review.scopes]},
                {"id": "core", "label": "Destroy core infrastructure",
                 "items": [{key: scope[key] for key in (
                     "jobId", "planId", "stateSha256", "proxyCount")}]},
                {"id": "inspector-verify", "label": "Verify retired public endpoints",
                 "items": [{"coreJobId": core.id,
                            "targetCount": len(scope["targets"])}]},
                {"id": "inspector-cleanup", "label": "Destroy retained Inspector",
                 "items": [{"tracked": True,
                            "ownedProviderRecordIds": scope["ownedInspectorRecordIds"]}]},
            ],
        }
    except Exception:
        raise MixedInterruptedDispatchAttention(
            "mixed interrupted cleanup source requires fresh review") from None


def start_mixed_interrupted_cleanup(
    job: StoredJobRun, body: dict, *, environment: str,
    state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, plan_repository=None, provider_resource_repository=None,
    lease_lookup=None, credential_repository=None,
    linode_transport=None, digitalocean_transport=None,
    process_quiescent: Callable[[dict], bool] | None = None,
    snapshot_collector: Callable = collect_provider_inventory_snapshot,
) -> StoredJobRun:
    """Compare one operator confirmation, then fence its fresh provider source."""
    jobs = job_repository or SqlAlchemyJobRepository()
    preview = preview_mixed_interrupted_cleanup(
        job, environment=environment, state_root=state_root,
        core_state_root=core_state_root,
        job_repository=jobs, lease_lookup=lease_lookup,
        plan_repository=plan_repository,
        provider_resource_repository=provider_resource_repository,
        credential_repository=credential_repository,
        linode_transport=linode_transport,
        digitalocean_transport=digitalocean_transport,
        process_quiescent=process_quiescent,
        snapshot_collector=snapshot_collector)
    if (body.get("snapshotId") != preview["snapshotId"]
            or body.get("confirmation") != preview["confirmationPhrase"]):
        raise MixedInterruptedDispatchAttention(
            "mixed interrupted cleanup review changed; review again")
    core_id = (job.input.get("coreJobId") if job.action ==
               "provider_keyed_mixed_interrupted_cleanup" else job.id)
    existing = jobs.get(cleanup_parent_id(core_id))
    if existing is not None and existing.status == "succeeded":
        from app.services.provider_keyed_mixed_interrupted_terminal import (
            recognize_mixed_interrupted_terminal,
        )
        return recognize_mixed_interrupted_terminal(
            preview["engagementId"], core_id, environment=environment,
            job_repository=jobs, lease_lookup=lease_lookup or _db_lease_lookup)
    return reserve_mixed_interrupted_cleanup(
        preview["engagementId"], core_id,
        requested_by=str(body.get("requestedBy") or job.requested_by or "operator"),
        environment=environment, state_root=state_root,
        core_state_root=core_state_root,
        job_repository=jobs, lease_lookup=lease_lookup,
        plan_repository=plan_repository,
        provider_resource_repository=provider_resource_repository,
        credential_repository=credential_repository,
        linode_transport=linode_transport,
        digitalocean_transport=digitalocean_transport,
        process_quiescent=process_quiescent,
        snapshot_collector=snapshot_collector,
        expected_snapshot_id=preview["snapshotId"],
    )


def reserve_mixed_interrupted_cleanup(
    engagement_id: str, core_job_id: str, *, requested_by: str,
    environment: str, state_root: Path | None = None,
    core_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    job_repository=None, lease_lookup=None, credential_repository=None,
    plan_repository=None, provider_resource_repository=None,
    linode_transport=None, digitalocean_transport=None,
    process_quiescent: Callable[[dict], bool] | None = None,
    snapshot_collector: Callable = collect_provider_inventory_snapshot,
    expected_snapshot_id: str | None = None,
) -> StoredJobRun:
    """GET both scopes, then atomically fence their exact review parent."""
    if environment != "devtest":
        raise MixedInterruptedDispatchAttention("mixed interrupted cleanup is DevTest-only")
    state_root = state_root or _default_state_root()
    if state_root != _default_state_root():
        raise MixedInterruptedDispatchAttention("configured DevTest state root differs")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    quiescent = process_quiescent or _default_quiescent
    try:
        initial = jobs.get(initial_parent_id(core_job_id))
        existing = jobs.get(cleanup_parent_id(core_job_id))
        if initial is None or initial.target_id != engagement_id:
            raise ValueError("mixed interrupted initial checkpoint differs")
        if existing is not None:
            if lookup(engagement_id) != (initial.input["corePlanId"],
                                         "provider_keyed_teardown_fence"):
                raise ValueError("mixed interrupted existing fence differs")
            review = _saved_review(existing)
            core = jobs.get(core_job_id)
            if core is None:
                raise ValueError("mixed interrupted core is absent")
            scope = _saved_core_inspector_scope(existing)
            if existing.input.get("phase") == "plans_sealed":
                recognize_mixed_interrupted_sealed_plans(
                    existing, initial, review, _saved_plans(existing))
            else:
                recognize_mixed_interrupted_cleanup_checkpoint(existing, initial, review)
            if (expected_snapshot_id is not None
                    and expected_snapshot_id != _scope_snapshot_id(review, scope)):
                raise ValueError("mixed interrupted reviewed source changed")
            return existing
        review, snapshots, generation, host_rows = _fresh_review(
            initial, jobs=jobs, lookup=lookup, state_root=state_root,
            quiescent=quiescent, snapshot_collector=snapshot_collector,
            credential_repository=credential_repository,
            linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport)
        core = jobs.get(core_job_id)
        if core is None:
            raise ValueError("mixed interrupted core is absent")
        scope = _core_inspector_scope(
            core, jobs=jobs, core_state_root=core_state_root,
            plan_repository=plan_repository,
            provider_resource_repository=provider_resource_repository)
        if (expected_snapshot_id is not None
                and expected_snapshot_id != _scope_snapshot_id(review, scope)):
            raise ValueError("mixed interrupted reviewed source changed")
        proposal = propose_mixed_interrupted_cleanup(
            initial, review, requested_by=requested_by, review_scope=scope)
        if _core_inspector_scope(
                core, jobs=jobs, core_state_root=core_state_root,
                plan_repository=plan_repository,
                provider_resource_repository=provider_resource_repository) != scope:
            raise ValueError("reviewed core or Inspector changed before reservation")
        return jobs.reserve_mixed_interrupted_cleanup_parent(
            proposal, initial=initial, review=review,
            snapshots_by_provider=snapshots, process_quiescent=quiescent,
            state_root=state_root, review_generation=generation,
            host_rows=host_rows)
    except Exception:
        raise MixedInterruptedDispatchAttention(
            "mixed interrupted cleanup source requires fresh review") from None


def seal_mixed_interrupted_cleanup_plans(
    engagement_id: str, core_job_id: str, *,
    plan_paths: Mapping[str, Path | None], show_json: Mapping[str, str | None],
    environment: str, state_root: Path | None = None,
    job_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Validate both saved plans and CAS the second checkpoint; no Apply."""
    if environment != "devtest":
        raise MixedInterruptedDispatchAttention("mixed interrupted cleanup is DevTest-only")
    state_root = state_root or _default_state_root()
    if state_root != _default_state_root():
        raise MixedInterruptedDispatchAttention("configured DevTest state root differs")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        initial = jobs.get(initial_parent_id(core_job_id))
        parent = jobs.get(cleanup_parent_id(core_job_id))
        if initial is None or parent is None or parent.target_id != engagement_id:
            raise ValueError("mixed interrupted cleanup checkpoint differs")
        review = _saved_review(parent)
        sealed_before = parent.input.get("phase") == "plans_sealed"
        if sealed_before:
            saved = _saved_plans(parent)
            recognize_mixed_interrupted_sealed_plans(parent, initial, review, saved)
        else:
            recognize_mixed_interrupted_cleanup_checkpoint(parent, initial, review)
        if lookup(engagement_id) != (initial.input["corePlanId"],
                                     "provider_keyed_teardown_fence"):
            raise ValueError("mixed interrupted teardown fence differs")
        order = tuple(review.ordered_providers)
        if set(plan_paths) != set(order) or set(show_json) != set(order):
            raise ValueError("both saved provider plans are required")
        if sealed_before:
            _verify_saved_plan_artifacts(saved, plan_paths, show_json)
            return parent
        generation = uuid4().hex

        def fence() -> str:
            if (jobs.get(initial.id) != initial or jobs.get(parent.id) != parent
                    or lookup(engagement_id) != (initial.input["corePlanId"],
                                                 "provider_keyed_teardown_fence")):
                raise ValueError("mixed destroy plan generation changed")
            return generation

        before_states = {}
        for provider in order:
            workspace = _workspace(initial, provider, state_root)
            if workspace.state_path.is_symlink():
                raise ValueError("mixed retained state is unsafe")
            before_states[provider] = (workspace.state_path.read_bytes()
                                       if workspace.state_path.exists() else None)
            fence()
        plans = bind_mixed_interrupted_destroy_plans(
            initial, review, before_states, plan_paths, show_json, fence=fence)
        return jobs.seal_mixed_interrupted_destroy_plans(
            parent, initial=initial, review=review, plan_set=plans,
            before_states=before_states, plan_paths=plan_paths,
            show_json=show_json, state_root=state_root)
    except Exception:
        raise MixedInterruptedDispatchAttention(
            "both mixed destroy plans require exact review") from None
