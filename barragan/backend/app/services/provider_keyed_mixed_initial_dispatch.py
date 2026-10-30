# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private mixed initial Deploy sequence through the provider proof handoff.

The supplied workers are the existing one-shot Apply, exact provider proof,
and read-only handoff services. This dispatcher does not recover a provider
write whose command may have started, contact a host, or publish chains.
"""

from __future__ import annotations

from typing import Callable

from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, recognize_mixed_initial_apply_result,
    recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_coordinator import (
    HANDOFF_PHASE, _core_matches, recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


class MixedInitialDispatchAttention(ValueError):
    """The reviewed one-action sequence needs exact reconciliation."""


def advance_mixed_initial_provider_proofs(
    engagement_id: str, core_job_id: str, *, environment: str,
    apply_once: Callable[[str], StoredJobRun],
    prove_applied: Callable[[str], StoredJobRun],
    persist_handoff: Callable[[], StoredJobRun],
    job_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Apply and prove providers in reviewed order, then persist host handoff.

    The callbacks bind the concrete source, credentials, provider transports,
    and renewing child claims. A running child without a complete result is
    never sent to ``apply_once`` or ``prove_applied``. An already succeeded
    child is authenticated without repeating a provider command or proof.
    """
    if environment != "devtest" or not engagement_id or not core_job_id:
        raise MixedInitialDispatchAttention("mixed Deploy sequence is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        parent = jobs.get(_parent_id(core_job_id))
        core = jobs.get(core_job_id)
        if (parent is None or core is None or parent.target_id != engagement_id
                or parent.status != "running" or parent.finished_at is not None):
            raise ValueError("mixed parent or core differs")
        seal = validate_mixed_initial_apply_seal(parent)
        _require_lease(lookup, engagement_id, parent.input["corePlanId"])
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        if not _core_matches(parent, core, active_id):
            raise ValueError("mixed active core differs")

        def require_active_core() -> str:
            active_id, _ = active_core_connection_details(jobs, engagement_id)
            if not _core_matches(parent, core, active_id):
                raise ValueError("mixed active core changed")
            return active_id

        order = seal["orderedProviders"]
        if parent.input.get("phase") == HANDOFF_PHASE:
            children = {provider: jobs.get(_child_id(core_job_id, provider)) for provider in order}
            recognize_mixed_initial_host_proof_handoff(parent, core, active_id, children)
            return parent
        if parent.input.get("phase") != "apply_sealed":
            raise ValueError("both provider plans must be sealed before Apply")
        for provider in order:
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            if jobs.get(parent.id) != parent or jobs.get(core.id) != core:
                raise ValueError("mixed parent or core changed between providers")
            require_active_core()
            child_id = _child_id(core_job_id, provider)
            child = jobs.get(child_id)
            if child is None:
                require_active_core()
                started = apply_once(provider)
                require_active_core()
                child = jobs.get(child_id)
                if child != started:
                    raise ValueError("provider Apply result was not retained")
            if child is None:
                raise ValueError("provider Apply child is absent")
            if child.status != "succeeded":
                result = recognize_mixed_initial_apply_result(child, parent, provider)
                if result["stage"] not in {"applied", "awaiting", "proved"}:
                    raise ValueError("provider write result is uncertain")
                require_active_core()
                finished = prove_applied(provider)
                require_active_core()
                child = jobs.get(child_id)
                if child != finished:
                    raise ValueError("provider terminal proof was not retained")
            recognize_mixed_initial_apply_terminal(child, parent, provider)
            require_active_core()
        _require_lease(lookup, engagement_id, parent.input["corePlanId"])
        if jobs.get(parent.id) != parent or jobs.get(core.id) != core:
            raise ValueError("mixed parent or core changed before host handoff")
        require_active_core()
        checkpoint = persist_handoff()
        if (checkpoint != jobs.get(parent.id)
                or checkpoint.input.get("phase") != HANDOFF_PHASE):
            raise ValueError("mixed host handoff was not retained")
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        children = {provider: jobs.get(_child_id(core_job_id, provider)) for provider in order}
        recognize_mixed_initial_host_proof_handoff(checkpoint, core, active_id, children)
        return checkpoint
    except Exception as exc:
        raise MixedInitialDispatchAttention(
            "mixed initial Deploy sequence needs exact reconciliation") from exc
