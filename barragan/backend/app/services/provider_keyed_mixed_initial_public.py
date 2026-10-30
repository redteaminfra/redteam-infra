# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest continuation of one reviewed mixed Deploy through host-proof handoff."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable

from app.core.command_environment import barragan_subprocess_env
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_digitalocean_tag_eligibility import _complete_inventory
from app.services.provider_keyed_mixed_initial_deploy_continuation import (
    advance_mixed_initial_deploy_to_host_proof,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    ProviderHostObservation, reserve_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_bootstrap import (
    _worker_id as _host_worker_id, run_mixed_initial_bootstrap,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    ACTION as MIXED_PARENT_ACTION, _PHASES as PRE_HOST_PHASES,
    _parent_id, prepare_or_reuse_mixed_initial_plans, seal_mixed_initial_apply,
)
from app.services.provider_keyed_selector_preflight import _scan_endpoint
from app.services.provider_keyed_selector_reservation import (
    UrllibReservationTransport, _require_no_firewall_selector_use,
)
from app.services.sketch_ssh_keys import ensure_sketch_ssh_key, retrieve_sketch_ssh_key
from app.services.sketch_transport_ssh_keys import (
    ensure_sketch_transport_ssh_key, retrieve_sketch_transport_ssh_key,
)
from app.services.sketch_state_workspaces import _default_state_root
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository


class MixedInitialPublicAttention(ValueError):
    """Reviewed mixed Deploy needs reconciliation; do not infer a replay."""


def is_reviewed_mixed_initial(plan) -> bool:
    evidence = getattr(plan, "evidence", None)
    authorization = evidence.get("sketchAuthorization") if isinstance(evidence, dict) else None
    return isinstance(authorization, dict) and authorization.get("kind") == "bounded-mixed-post-core-v1"


def _proof_child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-strict-host-proof-{core_job_id.removeprefix('job-')}"


def prove_selector_absent_before_mixed_apply(source, renew: Callable[[], None], *,
                                             transport=None) -> str:
    """Read the selected DO account with the Apply source token immediately before POST."""
    selector, token = source.selector_tag, source.selector_token
    if (not isinstance(selector, str) or not selector
            or not isinstance(token, str) or not token
            or not callable(renew)):
        raise MixedInitialPublicAttention("DigitalOcean selector source is incomplete")
    client = transport or UrllibProviderCatalogTransport()

    class FencedTransport:
        def request(self, origin, method, path, credential):
            if credential != token or method != "GET":
                raise MixedInitialPublicAttention("selector inventory source differs")
            renew()
            body = client.request(origin, method, path, credential)
            renew()
            return body

    fenced = FencedTransport()
    try:
        tags = _scan_endpoint("tags", selector, token, fenced)
        firewalls = _scan_endpoint("firewalls", selector, token, fenced)
        droplets = _scan_endpoint("droplets", selector, token, fenced)
        gpu_droplets = _scan_endpoint("droplets", selector, token, fenced, gpu_only=True)
        rules = _complete_inventory(fenced, token, "/firewalls", "firewalls", {}, renew)
        _require_no_firewall_selector_use(rules, selector)
        renew()
    except Exception:
        raise MixedInitialPublicAttention("DigitalOcean selector absence is unproved") from None
    evidence = {"selector": selector, "receiptSha256": source.receipt_sha256,
                "planSha256": source.plan_sha256, "tags": tags,
                "firewalls": firewalls, "droplets": droplets, "gpuDroplets": gpu_droplets}
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def advance_reviewed_mixed_initial(core_job_id: str, *, environment: str,
                                   rollout_enabled: bool, job_repository=None,
                                   plan_repository=None, plan_builder=None,
                                   seal_builder=None, continuation=None,
                                   host_continuation=None,
                                   proof_continuation=None,
                                   selector_get_transport=None,
                                   selector_post_transport=None):
    """Join both saved plans and both one-shot provider proofs under the core lease."""
    from app.services.guarded_test_deployment import _require_configured_keyed_source
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    core = jobs.get(core_job_id)
    inputs = core.input if core is not None and isinstance(core.input, dict) else {}
    terminal = core.events[-1] if core is not None and core.events else None
    engagement_id, plan_id = inputs.get("engagementId"), inputs.get("corePlanId")
    plan = plans.get(plan_id) if isinstance(plan_id, str) else None
    if (environment != "devtest" or rollout_enabled is not True
            or core is None or core.status != "succeeded"
            or core.action != "pilot_standard_rti_guarded_execute"
            or terminal is None or terminal.message != "pilot Standard RTI run finished"
            or terminal.data.get("ok") is not True
            or terminal.data.get("mutationStatus") != "deployed"
            or terminal.data.get("ansibleStatus") != "validated"
            or terminal.data.get("finalCleanupStatus") != "pending_operator_teardown"
            or inputs.get("providerKeyedDispatchAuthorized") is not True
            or inputs.get("sketchStateSchema") != "provider-keyed-v2"
            or not isinstance(engagement_id, str) or not engagement_id
            or plan is None or plan.engagement_id != engagement_id
            or plan.id != plan_id or plan.status != "applied" or plan.stage != "applied"
            or plan.apply_job_id != core.id or not is_reviewed_mixed_initial(plan)
            or _db_lease_lookup(engagement_id) != (plan_id, "provider_keyed_initial")):
        raise MixedInitialPublicAttention("reviewed mixed core or lease differs")
    pin = inputs.get("providerKeyedSourcePin")
    try:
        if (not isinstance(pin, dict) or not isinstance(pin.get("root"), str)
                or _require_configured_keyed_source(pin) != pin):
            raise ValueError
    except Exception:
        raise MixedInitialPublicAttention("reviewed mixed source pin differs") from None
    parent = jobs.get(_parent_id(core_job_id))
    if (parent is not None and isinstance(parent.input, dict)
            and parent.input.get("phase") == "awaiting_mixed_host_proof"):
        if jobs.get(_proof_child_id(core_job_id)) is not None:
            raise MixedInitialPublicAttention("mixed strict proof exists; no host command may be replayed")
        worker = jobs.get(_host_worker_id(core_job_id))
        if worker is not None:
            if getattr(worker, "status", None) != "succeeded" or getattr(worker, "finished_at", None) is None:
                raise MixedInitialPublicAttention("mixed host worker exists; no host command may be replayed")
            return (proof_continuation or advance_reviewed_mixed_initial_proof)(
                core_job_id, environment=environment, rollout_enabled=rollout_enabled,
                job_repository=jobs, plan_repository=plans)
        completed = (host_continuation or advance_reviewed_mixed_initial_host)(
            core_job_id, environment=environment, rollout_enabled=rollout_enabled,
            job_repository=jobs, plan_repository=plans)
        if getattr(completed, "status", None) == "succeeded" and getattr(completed, "finished_at", None):
            return (proof_continuation or advance_reviewed_mixed_initial_proof)(
                core_job_id, environment=environment, rollout_enabled=rollout_enabled,
                job_repository=jobs, plan_repository=plans)
        return completed
    # The mixed compilers require the same durable administration identity as
    # the established single-provider plan worker. Bootstrap later consumes a
    # separate, already-created transport identity. Create each only once while
    # the reviewed core still owns the engagement lease, before either plan.
    admin = retrieve_sketch_ssh_key(engagement_id)
    if admin is None:
        if _db_lease_lookup(engagement_id) != (plan_id, "provider_keyed_initial"):
            raise MixedInitialPublicAttention("reviewed mixed lease changed before key creation")
        ensure_sketch_ssh_key(engagement_id)
        admin = retrieve_sketch_ssh_key(engagement_id)
    if admin is None or not admin.private_key or not admin.public_key:
        raise MixedInitialPublicAttention("stored Sketch administration key is unavailable")
    transport = retrieve_sketch_transport_ssh_key(engagement_id)
    if transport is None:
        if _db_lease_lookup(engagement_id) != (plan_id, "provider_keyed_initial"):
            raise MixedInitialPublicAttention("reviewed mixed lease changed before key creation")
        ensure_sketch_transport_ssh_key(engagement_id)
        transport = retrieve_sketch_transport_ssh_key(engagement_id)
    if transport is None or not transport.private_key or not transport.public_key:
        raise MixedInitialPublicAttention("stored Sketch transport key is unavailable")
    state_root = _default_state_root()
    template_root = Path(pin["root"])
    kwargs = {"engagement_id": engagement_id, "lease_owner": plan_id,
              "environment": environment, "state_root": state_root,
              "template_root": template_root, "job_repository": jobs,
              "plan_repository": plans}
    (plan_builder or prepare_or_reuse_mixed_initial_plans)(core_job_id, **kwargs)
    (seal_builder or seal_mixed_initial_apply)(core_job_id, **kwargs)
    get_transport = selector_get_transport or UrllibProviderCatalogTransport()
    post_transport = selector_post_transport or UrllibReservationTransport()
    (continuation or advance_mixed_initial_deploy_to_host_proof)(
        engagement_id, core_job_id, environment=environment,
        state_root=state_root, job_repository=jobs,
        selector_absence_prover=lambda source, renew:
            prove_selector_absent_before_mixed_apply(
                source, renew, transport=get_transport),
        selector_get_transport=get_transport,
        selector_post_transport=post_transport,
    )
    completed = (host_continuation or advance_reviewed_mixed_initial_host)(
        core_job_id, environment=environment, rollout_enabled=rollout_enabled,
        job_repository=jobs, plan_repository=plans)
    if getattr(completed, "status", None) == "succeeded" and getattr(completed, "finished_at", None):
        return (proof_continuation or advance_reviewed_mixed_initial_proof)(
            core_job_id, environment=environment, rollout_enabled=rollout_enabled,
            job_repository=jobs, plan_repository=plans)
    return completed


def advance_reviewed_mixed_initial_proof(
    core_job_id: str, *, environment: str, rollout_enabled: bool,
    job_repository=None, plan_repository=None, proof_runner=None,
):
    """Continue only a completed bootstrap into the one-shot proof gate."""
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    core = jobs.get(core_job_id)
    inputs = core.input if core is not None and isinstance(core.input, dict) else {}
    engagement_id, plan_id = inputs.get("engagementId"), inputs.get("corePlanId")
    parent = jobs.get(_parent_id(core_job_id))
    worker = jobs.get(_host_worker_id(core_job_id))
    plan = plans.get(plan_id) if isinstance(plan_id, str) else None
    if (environment != "devtest" or rollout_enabled is not True
            or core is None or core.status != "succeeded"
            or core.action != "pilot_standard_rti_guarded_execute"
            or inputs.get("providerKeyedDispatchAuthorized") is not True
            or inputs.get("sketchStateSchema") != "provider-keyed-v2"
            or not isinstance(engagement_id, str) or not engagement_id
            or plan is None or plan.engagement_id != engagement_id
            or plan.status != "applied" or plan.stage != "applied"
            or plan.apply_job_id != core_job_id or not is_reviewed_mixed_initial(plan)
            or _db_lease_lookup(engagement_id) != (plan_id, "provider_keyed_initial")
            or parent is None or parent.action != MIXED_PARENT_ACTION
            or parent.status != "running" or parent.finished_at is not None
            or parent.target_id != engagement_id
            or not isinstance(parent.input, dict)
            or parent.input.get("phase") != "awaiting_mixed_host_proof"
            or parent.input.get("coreJobId") != core_job_id
            or parent.input.get("corePlanId") != plan_id
            or worker is None or worker.status != "succeeded"
            or worker.finished_at is None
            or jobs.get(_proof_child_id(core_job_id)) is not None):
        raise MixedInitialPublicAttention("completed mixed host worker authority differs")
    if proof_runner is None:
        from app.services.provider_keyed_mixed_initial_publication import (
            publish_mixed_initial_strict_host_proof,
        )
        proof_runner = publish_mixed_initial_strict_host_proof
    return proof_runner(engagement_id, core_job_id, environment=environment,
                        job_repository=jobs, plan_repository=plans)


def advance_reviewed_mixed_initial_host(
    core_job_id: str, *, environment: str, rollout_enabled: bool,
    job_repository=None, plan_repository=None, fresh_observer=None,
    binding_reserver=None, bootstrap_runner=None,
):
    """Continue the same reviewed Deploy through one-shot host bootstrap only."""
    from app.services.guarded_test_deployment import _require_configured_keyed_source
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
    from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
    from app.services.provider_keyed_core_destroy_preview import _read_regular
    from app.services.provider_keyed_mixed_initial_apply_child import (
        _child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
    )
    from app.services.provider_keyed_mixed_initial_apply_proof import (
        prove_mixed_initial_prior_provider_fresh,
    )

    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    core = jobs.get(core_job_id)
    inputs = core.input if core is not None and isinstance(core.input, dict) else {}
    engagement_id, plan_id = inputs.get("engagementId"), inputs.get("corePlanId")
    plan = plans.get(plan_id) if isinstance(plan_id, str) else None
    parent = jobs.get(_parent_id(core_job_id))
    terminal = core.events[-1] if core is not None and core.events else None
    if (environment != "devtest" or rollout_enabled is not True
            or core is None or core.status != "succeeded"
            or core.action != "pilot_standard_rti_guarded_execute"
            or terminal is None or terminal.message != "pilot Standard RTI run finished"
            or terminal.data.get("ok") is not True
            or terminal.data.get("mutationStatus") != "deployed"
            or terminal.data.get("ansibleStatus") != "validated"
            or terminal.data.get("finalCleanupStatus") != "pending_operator_teardown"
            or inputs.get("providerKeyedDispatchAuthorized") is not True
            or inputs.get("sketchStateSchema") != "provider-keyed-v2"
            or not isinstance(engagement_id, str) or not engagement_id
            or plan is None or plan.engagement_id != engagement_id
            or plan.id != plan_id or plan.status != "applied" or plan.stage != "applied"
            or plan.apply_job_id != core.id or not is_reviewed_mixed_initial(plan)
            or _db_lease_lookup(engagement_id) != (plan_id, "provider_keyed_initial")
            or parent is None or parent.action != MIXED_PARENT_ACTION
            or parent.target_id != engagement_id or parent.status != "running"
            or parent.finished_at is not None
            or not isinstance(parent.input, dict)
            or parent.input.get("engagementId") != engagement_id
            or parent.input.get("coreJobId") != core_job_id
            or parent.input.get("corePlanId") != plan_id
            or parent.input.get("phase") != "awaiting_mixed_host_proof"):
        raise MixedInitialPublicAttention("reviewed mixed host handoff differs")
    pin = inputs.get("providerKeyedSourcePin")
    try:
        if (not isinstance(pin, dict) or not isinstance(pin.get("root"), str)
                or _require_configured_keyed_source(pin) != pin):
            raise ValueError
    except Exception:
        raise MixedInitialPublicAttention("reviewed mixed source pin differs") from None
    if (jobs.get(_host_worker_id(core_job_id)) is not None
            or jobs.get(_proof_child_id(core_job_id)) is not None):
        raise MixedInitialPublicAttention("mixed host worker exists; no host command may be replayed")

    def observe(parent_row, provider, fence):
        child = jobs.get(_child_id(core_job_id, provider))
        terminal = recognize_mixed_initial_apply_terminal(child, parent_row, provider)
        workspace = _prior_workspace(parent_row, provider, terminal)
        classified = prove_mixed_initial_prior_provider_fresh(
            parent_row, child, workspace, fence=fence,
            process_quiescent=lambda identity: _process_quiescent(
                identity["bootId"], identity["pid"], identity["pgid"],
                identity["startTicks"]),
        )
        fence()
        raw = _read_regular(workspace.state_path)
        fence()
        return ProviderHostObservation(classified, raw)

    observer = fresh_observer or observe
    (binding_reserver or reserve_mixed_initial_host_binding)(
        engagement_id, core_job_id, environment=environment,
        fresh_observer=observer, job_repository=jobs)
    env = barragan_subprocess_env()
    env[TEMPLATE_ROOT_ENV] = pin["root"]
    return (bootstrap_runner or run_mixed_initial_bootstrap)(
        engagement_id, core_job_id, environment=environment,
        bootstrap_env=env, fresh_observer=observer, job_repository=jobs)


def recover_reviewed_mixed_initial_dispatches(*, environment: str,
                                              rollout_enabled: bool,
                                              schedule: Callable[[Callable[[], None]], None]
                                              ) -> list[str]:
    """Schedule exact retained mixed cores; their worker rechecks all authority."""
    if environment != "devtest" or rollout_enabled is not True:
        return []
    from app.storage.models import DeploymentPlanModel
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

    jobs = SqlAlchemyJobRepository()
    scheduled = []
    for row in DeploymentPlanModel.query.filter_by(status="applied", stage="applied").all():
        if not is_reviewed_mixed_initial(row):
            continue
        core_id = row.apply_job_id
        core = jobs.get(core_id) if isinstance(core_id, str) else None
        if (core is None or core.status != "succeeded"
                or not isinstance(core.input, dict)
                or core.input.get("providerKeyedDispatchAuthorized") is not True
                or core.input.get("engagementId") != row.engagement_id
                or core.input.get("corePlanId") != row.id
                or _db_lease_lookup(row.engagement_id) !=
                   (row.id, "provider_keyed_initial")):
            continue
        parent = jobs.get(_parent_id(core_id))
        if parent is not None and (
                parent.action != MIXED_PARENT_ACTION
                or parent.target_type != "engagement"
                or parent.target != f"engagement:{row.engagement_id}"
                or parent.target_id != row.engagement_id
                or not isinstance(parent.input, dict)
                or parent.input.get("engagementId") != row.engagement_id
                or parent.input.get("coreJobId") != core_id
                or parent.input.get("corePlanId") != row.id
                or parent.status not in {"queued", "running"}
                or parent.finished_at is not None
                or parent.input.get("phase") not in {*PRE_HOST_PHASES, "awaiting_mixed_host_proof"}):
            continue
        if parent is not None and parent.input.get("phase") == "awaiting_mixed_host_proof":
            if parent.status != "running":
                continue
            if jobs.get(_proof_child_id(core_id)) is not None:
                continue
            worker = jobs.get(_host_worker_id(core_id))
            if worker is None:
                schedule(lambda core_id=core_id: advance_reviewed_mixed_initial_host(
                    core_id, environment=environment, rollout_enabled=True))
            elif (getattr(worker, "status", None) == "succeeded"
                  and getattr(worker, "finished_at", None) is not None
                  and jobs.get(_proof_child_id(core_id)) is None):
                schedule(lambda core_id=core_id: advance_reviewed_mixed_initial_proof(
                    core_id, environment=environment, rollout_enabled=True))
            else:
                continue
        else:
            schedule(lambda core_id=core_id: advance_reviewed_mixed_initial(
                core_id, environment=environment, rollout_enabled=True))
        scheduled.append(core_id)
    return scheduled
