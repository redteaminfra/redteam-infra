# Copyright (c) 2026, Oracle and/or its affiliates.
"""Continue one approved mixed append through both provider and host proofs.

The durable child journals, rather than this dispatcher, decide whether a
provider command can start. An existing command intent is never dispatched
again. Provider and host observations use their existing bounded workers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.error_locations import _APP_ROOT, sanitized_error_locations
from app.core.runtime import runtime_value
from app.services.provider_keyed_mixed_append_availability import (
    MixedAppendAvailabilityAttention, require_reviewed_mixed_append_availability,
)
from app.services.provider_keyed_mixed_append_first_proof_job import (
    prove_and_finish_first_mixed_append_apply,
)
from app.services.provider_keyed_mixed_append_pair_apply_binding import (
    build_first_mixed_append_apply_bindings,
)
from app.services.provider_keyed_mixed_append_pair_apply_child import (
    _child_id as first_child_id, _precommand as first_precommand,
    run_first_mixed_append_provider_apply,
)
from app.services.provider_keyed_mixed_append_pair_parent import _plan_child_id
from app.services.provider_keyed_mixed_append_pair_host_proof import (
    SixHostProofReceipt, _child_id as host_child_id,
    prove_mixed_append_pair_hosts, validate_six_host_receipt_child,
)
from app.services.provider_keyed_mixed_append_second_apply_binding import (
    build_second_mixed_append_apply_bindings,
)
from app.services.provider_keyed_mixed_append_second_apply_child import (
    _child_id as second_child_id, _precommand as second_precommand,
    run_second_mixed_append_provider_apply,
)
from app.services.provider_keyed_mixed_append_second_proof_job import (
    prove_and_finish_second_mixed_append_apply,
)
from app.services.provider_keyed_mixed_append_six_source import (
    collect_fresh_six_node_host_source, verify_six_node_local_fence,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


class MixedAppendApplyRuntimeAttention(ValueError):
    """A durable boundary needs review; this runtime will not replay GO."""


_PUBLICATION_CLAIM = timedelta(minutes=15)
_LOGGER = logging.getLogger(__name__)


def _log_runtime_failure(error: Exception) -> None:
    """Retain predicate locations, including suppressed contexts, without data.

    Do not format exceptions or traceback source: either can contain provider
    output or credentials. Bounds also protect logging from cyclic chains.
    """
    locations = sanitized_error_locations(error)
    _LOGGER.error("Mixed append failure locations: %s", locations)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def mixed_append_pristine_apply_available(parent, *, jobs, lease_lookup=None):
    """A sealed pair with no command intent may be checked and started again."""
    from app.services.provider_keyed_mixed_unapplied_append_teardown import no_apply_present
    if parent.input.get("phase") != "apply_sealed" or not no_apply_present(parent, jobs):
        return False
    return (lease_lookup or _db_lease_lookup)(parent.target_id) == (
        parent.input["corePlanId"], "provider_keyed_mixed_append")


def mixed_append_proof_resume_available(
    parent, *, jobs, lease_lookup=None, claim=None,
) -> bool:
    """Cheap UI/startup boundary; POST and worker reopen full saved authority."""
    from app.services.provider_keyed_mixed_append_second_proof_job import _result

    try:
        first = jobs.get(first_child_id(parent.id))
        second = jobs.get(second_child_id(parent.id))
        if (parent.action != "provider_keyed_mixed_append" or parent.status != "running"
                or parent.finished_at is not None
                or parent.input.get("phase") != "apply_sealed"
                or parent.input.get("schema") != "mixed-append-pair-parent-v1"
                or parent.target_type != "engagement"
                or parent.target != f"engagement:{parent.target_id}"
                or parent.input.get("engagementId") != parent.target_id
                or tuple(parent.input.get("providerOrder", ())) not in (
                    ("linode", "digitalocean"), ("digitalocean", "linode"))
                or not parent.events
                or parent.events[-1].message != "mixed append pair approved"
                or parent.events[-1].data != {
                    "reviewSha256": parent.input["reviewSha256"],
                    "planChildId": _plan_child_id(parent.id)}
                or first is None or first.status != "succeeded"
                or first.finished_at is None or len(first.events) != 10
                or type(first.events[5].data.get("returnCode")) is not int
                or first.events[5].data["returnCode"] != 0
                or first.events[-1].message != "mixed append first provider Apply succeeded"
                or first.events[-1].data != {
                    "proofJournalSha256": job_event_digest(first.events[:9])}
                or second is None or second.status != "running"
                or second.finished_at is not None or len(second.events) != 8
                or type(second.events[5].data.get("returnCode")) is not int
                or not second.input.get("claimOwner")
                or not second.input.get("claimToken")
                or (datetime.fromisoformat(second.input["claimExpiresAt"]) > _now()
                    if claim is None else (
                        tuple(second.input.get(key) for key in ("claimOwner", "claimToken")) != claim
                        or datetime.fromisoformat(second.input["claimExpiresAt"]) <= _now()))
                or jobs.get(host_child_id(parent.id)) is not None
                or (lease_lookup or _db_lease_lookup)(parent.target_id) != (
                    parent.input["corePlanId"], "provider_keyed_mixed_append")):
            return False
        # Reuse the exact eight-event grammar for the affordance. Its actual
        # receipt and full saved-plan gate are authenticated below before work.
        _result(parent, second, {
            "planSha256": second.events[2].data["planSha256"],
            "terraformBinarySha256": second.events[2].data["terraformSha256"]})
        return True
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return False


def require_mixed_append_proof_resume(parent, *, jobs, lease_lookup=None, claim=None):
    """Authenticate the read-only resumption without issuing provider commands."""
    from app.services.core_ssh import active_core_connection_details
    from app.services.provider_keyed_mixed_append_first_proof_job import (
        _load_approved_first_source, _journal as first_journal,
    )
    from app.services.provider_keyed_mixed_append_second_proof_job import (
        _journal as second_journal,
    )
    from app.services.provider_keyed_mixed_append_second_apply_binding import _approved_second
    from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
    from app.services.provider_keyed_terraform_release import require_devtest_terraform_release

    if not mixed_append_proof_resume_available(
            parent, jobs=jobs, lease_lookup=lease_lookup, claim=claim):
        raise MixedAppendApplyRuntimeAttention("completed Apply proof is not resumable")
    first = jobs.get(first_child_id(parent.id))
    second = jobs.get(second_child_id(parent.id))
    first_source = _load_approved_first_source(parent, jobs, require_devtest_terraform_release)
    second_source = _approved_second(parent, jobs, require_devtest_terraform_release)
    first_result, first_stage = first_journal(parent, first, first_source)
    second_result, second_stage = second_journal(
        parent, second, second_source, job_event_digest(first.events))
    if (first_stage != "terminal" or second_stage != "awaiting"
            or active_core_connection_details(jobs, parent.target_id)[0] != parent.input["coreJobId"]
            or any(_process_quiescent(*(result.started_identity[key]
                       for key in ("bootId", "pid", "pgid", "startTicks"))) is not True
                   for result in (first_result, second_result))
            or jobs.get(parent.id) != parent
            or jobs.get(first.id) != first or jobs.get(second.id) != second
            or not mixed_append_proof_resume_available(
                parent, jobs=jobs, lease_lookup=lease_lookup, claim=claim)):
        raise MixedAppendApplyRuntimeAttention("completed Apply proof source changed")


def claim_mixed_append_proof_resume(parent, *, jobs):
    """One POST owns the existing proof child; no new job or provider command."""
    require_mixed_append_proof_resume(parent, jobs=jobs)
    child = jobs.get(second_child_id(parent.id))
    first = jobs.get(first_child_id(parent.id))
    at = _now()
    owner, token = f"mixed-append-second-proof-{uuid4().hex}", uuid4().hex
    claimed = jobs.claim_lease(
        child.id, owner=owner, token=token, claimed_at=at.isoformat(),
        expires_at=(at + timedelta(minutes=2)).isoformat(),
        eligible_statuses={"running"})
    if (claimed is None or claimed.events != child.events
            or jobs.get(parent.id) != parent or jobs.get(first.id) != first
            or not mixed_append_proof_resume_available(
                parent, jobs=jobs, claim=(owner, token))):
        raise MixedAppendApplyRuntimeAttention("proof resume claim changed")
    return owner, token


def run_mixed_append_apply(parent_id: str, *, proof_resume_only: bool = False, proof_resume_claim=None) -> tuple:
    """Public dispatcher entry: recover the pinned source from the core job."""
    from app.services.guarded_test_deployment import _require_configured_keyed_source

    jobs = SqlAlchemyJobRepository()
    try:
        if runtime_value("ENVIRONMENT") != "devtest":
            raise ValueError("mixed append Apply is DevTest-only")
        parent = jobs.get(parent_id)
        if parent is None or parent.action != "provider_keyed_mixed_append":
            raise ValueError("mixed append parent differs")
        core = jobs.get(parent.input["coreJobId"])
        if (core is None or core.status != "succeeded"
                or core.input.get("engagementId") != parent.target_id
                or core.input.get("corePlanId") != parent.input.get("corePlanId")):
            raise ValueError("mixed append selected core differs")
        pin = core.input.get("providerKeyedSourcePin")
        if (not isinstance(pin, dict) or _require_configured_keyed_source(pin) != pin
                or type(pin.get("root")) is not str):
            raise ValueError("mixed append source pin differs")
        env = barragan_subprocess_env()
        env[TEMPLATE_ROOT_ENV] = pin["root"]
        return advance_mixed_append_apply(
            parent_id, environment="devtest", bootstrap_env=env,
            job_repository=jobs, proof_resume_only=proof_resume_only,
            proof_resume_claim=proof_resume_claim)
    except Exception as error:
        _log_runtime_failure(error)
        raise MixedAppendApplyRuntimeAttention(
            "mixed append selected source or Apply boundary needs review") from None


def recover_approved_mixed_append_applies(
    *, environment: str, schedule: Callable[[Callable[[], None]], None],
    job_repository=None, lease_lookup=None, limit: int = 500,
) -> list[str]:
    """Reschedule only approved, still-owned parents after process restart.

    The child-stage checks in ``advance_mixed_append_apply`` remain the GO
    authority. A scheduled uncertain write stops there without replay.
    """
    if environment != "devtest" or not callable(schedule) or limit <= 0:
        return []
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    scheduled = []
    for parent in jobs.list_by_actions_and_statuses(
            actions={"provider_keyed_mixed_append"},
            statuses={"running"}, limit=limit):
        data = parent.input
        if (parent.finished_at is not None or not isinstance(data, dict)
                or data.get("phase") != "apply_sealed"
                or parent.target_type != "engagement"
                or parent.target != f"engagement:{parent.target_id}"
                or data.get("engagementId") != parent.target_id
                or type(data.get("coreJobId")) is not str
                or type(data.get("corePlanId")) is not str
                or type(data.get("providerOrder")) is not list
                or tuple(data.get("providerOrder", ())) not in (
                    ("digitalocean", "linode"), ("linode", "digitalocean"))
                or not parent.events
                or parent.events[-1].message != "mixed append pair approved"
                or parent.events[-1].data != {
                    "reviewSha256": data.get("reviewSha256"),
                    "planChildId": _plan_child_id(parent.id)}
                or lookup(parent.target_id) != (
                    data["corePlanId"], "provider_keyed_mixed_append")):
            continue
        pending = jobs.get(second_child_id(parent.id))
        held_claim = (tuple(pending.input.get(key) for key in ("claimOwner", "claimToken"))
                      if pending is not None else None)
        if (mixed_append_proof_resume_available(parent, jobs=jobs, lease_lookup=lookup)
                or held_claim is not None and mixed_append_proof_resume_available(
                    parent, jobs=jobs, lease_lookup=lookup, claim=held_claim)):
            continue  # This proof boundary requires the operator's UI action.
        schedule(lambda parent_id=parent.id: run_mixed_append_apply(parent_id))
        scheduled.append(parent.id)
    return scheduled


def _resume_receipt(parent, child, source) -> SixHostProofReceipt:
    """Rebuild the terminal host receipt after a worker process restart."""
    if child is None or child.status != "succeeded" or not child.events:
        raise ValueError("mixed append host contact is not terminal")
    data = child.events[-1].data
    receipt = SixHostProofReceipt(
        parent.id, child.id, data["sourceSha256"],
        tuple(data["providerOrder"]), tuple(data["chainIds"]),
        tuple(data["newEdgeAddresses"]), tuple(data["newEdgeIds"]),
        tuple(data["providerProofDigests"]),
        tuple(data["bootstrapEventDigests"]),
        tuple(data["sketchKnownHostsDigests"]), tuple(data["rawProbeDigests"]),
        job_event_digest(child.events), child.input["claimOwner"],
        child.input["claimToken"],
    )
    return validate_six_host_receipt_child(parent, child, receipt, source=source)


def advance_mixed_append_apply(
    parent_id: str, *, environment: str, bootstrap_env: Mapping[str, str],
    job_repository=None, sketch_repository=None, lease_lookup=None,
    credential_repository=None, linode_transport=None, digitalocean_transport=None,
    first_bindings_builder: Callable = build_first_mixed_append_apply_bindings,
    first_apply_runner: Callable = run_first_mixed_append_provider_apply,
    first_proof_finisher: Callable = prove_and_finish_first_mixed_append_apply,
    second_bindings_builder: Callable = build_second_mixed_append_apply_bindings,
    second_apply_runner: Callable = run_second_mixed_append_provider_apply,
    second_proof_finisher: Callable = prove_and_finish_second_mixed_append_apply,
    source_collector: Callable = collect_fresh_six_node_host_source,
    host_prover: Callable = prove_mixed_append_pair_hosts,
    local_fence: Callable = verify_six_node_local_fence,
    publisher=None, proof_resume_only: bool = False, proof_resume_claim=None,
) -> tuple:
    """Advance one operator-approved 4-to-6 Apply without a second approval.

    A saved provider command intent, even one without a result, is never
    dispatched. Exact-result proof workers may resume after a crash. An
    existing started host child is likewise a permanent contact fence. An exact
    never-started reservation can advance through its original queued CAS.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    writer = publisher or chains
    try:
        parent = jobs.get(parent_id)
        if (environment != "devtest" or parent is None
                or parent.action != "provider_keyed_mixed_append"
                or parent.status != "running" or parent.finished_at is not None
                or parent.input.get("phase") != "apply_sealed"
                or parent.target_type != "engagement"
                or parent.target != f"engagement:{parent.target_id}"
                or type(parent.input.get("providerOrder")) is not list
                or tuple(parent.input.get("providerOrder", ())) not in (
                    ("digitalocean", "linode"), ("linode", "digitalocean"))
                or lookup(parent.target_id) != (
                    parent.input["corePlanId"], "provider_keyed_mixed_append")):
            raise ValueError("mixed append approval or lease differs")

        if proof_resume_only:
            if (type(proof_resume_claim) is not tuple or len(proof_resume_claim) != 2
                    or any(type(value) is not str or not value for value in proof_resume_claim)):
                raise ValueError("proof resume requires its server-owned claim")
            require_mixed_append_proof_resume(
                parent, jobs=jobs, lease_lookup=lookup, claim=proof_resume_claim)
        first = jobs.get(first_child_id(parent_id))
        first_claim = {}
        if first is None or first_precommand(first, parent):
            if proof_resume_only:
                raise ValueError("proof resume cannot dispatch first Terraform command")
            require_reviewed_mixed_append_availability(parent, jobs=jobs,
                credential_repository=credential_repository)
            bindings = first_bindings_builder(
                parent_id, job_repository=jobs, lease_lookup=lookup,
                credential_repository=credential_repository)
            first = first_apply_runner(
                parent_id, environment=environment, job_repository=jobs,
                lease_lookup=lookup, **bindings)
            # Continue only the claim returned by this invocation's Apply.
            # Restarted proof workers must acquire independently after expiry.
            first_claim = {"claim_owner": first.input["claimOwner"],
                           "claim_token": first.input["claimToken"]}
        # This worker recognizes only exact successful result/proof journals.
        # It never invokes Terraform, including when a child already exists.
        first = first_proof_finisher(
            parent_id, environment=environment, job_repository=jobs,
            lease_lookup=lookup, credential_repository=credential_repository,
            linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport, **first_claim)
        if first is None or first.id != first_child_id(parent_id) or first.status != "succeeded":
            raise ValueError("mixed append first provider has no terminal proof")

        second = jobs.get(second_child_id(parent_id))
        second_claim = ({"claim_owner": proof_resume_claim[0],
                         "claim_token": proof_resume_claim[1]}
                        if proof_resume_only and proof_resume_claim is not None else {})
        if second is None or second_precommand(second, parent):
            if proof_resume_only:
                raise ValueError("proof resume cannot dispatch second Terraform command")
            bindings = second_bindings_builder(
                parent_id, job_repository=jobs, lease_lookup=lookup,
                credential_repository=credential_repository,
                linode_transport=linode_transport,
                digitalocean_transport=digitalocean_transport)
            second = second_apply_runner(
                parent_id, environment=environment, job_repository=jobs,
                lease_lookup=lookup, **bindings)
            second_claim = {"claim_owner": second.input["claimOwner"],
                            "claim_token": second.input["claimToken"]}
        second = second_proof_finisher(
            parent_id, environment=environment, job_repository=jobs,
            lease_lookup=lookup, credential_repository=credential_repository,
            linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport, **second_claim)
        if second is None or second.id != second_child_id(parent_id) or second.status != "succeeded":
            raise ValueError("mixed append second provider has no terminal proof")

        def fresh_source():
            return source_collector(
                parent_id, job_repository=jobs, sketch_repository=chains,
                credential_repository=credential_repository, lease_lookup=lookup,
                linode_transport=linode_transport,
                digitalocean_transport=digitalocean_transport)

        source = fresh_source()
        host = jobs.get(host_child_id(parent_id))
        if host is None or host.status == "queued":
            receipt = host_prover(
                parent_id, environment=environment, bootstrap_env=bootstrap_env,
                fresh_source=fresh_source, job_repository=jobs, lease_lookup=lookup)
            host = jobs.get(host_child_id(parent_id))
        else:
            receipt = _resume_receipt(parent, host, source)
        if host is None or host.status != "succeeded":
            raise ValueError("mixed append six-host proof is not terminal")
        validate_six_host_receipt_child(parent, host, receipt, source=source)

        # The host child owns the matching parent claim. Refresh that same
        # identity for a bounded provider GET/publication window; a competing
        # claim or a provider read beyond the window stops without replay.
        at = _now()
        claimed = jobs.claim_lease(
            parent_id, owner=receipt.claim_owner, token=receipt.claim_token,
            claimed_at=at.isoformat(),
            expires_at=(at + _PUBLICATION_CLAIM).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"apply_sealed"})
        if (claimed is None or claimed.input.get("claimOwner") != receipt.claim_owner
                or claimed.input.get("claimToken") != receipt.claim_token
                or jobs.get(host.id) != host):
            raise ValueError("mixed append publication claim changed")
        proofs = {claimed.input["providerOrder"][0]: first,
                  claimed.input["providerOrder"][1]: second}
        return writer.publish_provider_keyed_mixed_append_pair(
            parent=claimed, before_chains=source.before_chains,
            after_chains=source.chains, provider_proof_children=proofs,
            host_proof_child=host, receipt=receipt,
            expected_parent_event_digest=job_event_digest(claimed.events),
            expected_provider_event_digests={
                provider: job_event_digest(child.events)
                for provider, child in proofs.items()},
            expected_host_event_digest=job_event_digest(host.events),
            claim_owner=receipt.claim_owner, claim_token=receipt.claim_token,
            finished_at=_now().isoformat(), fresh_source=fresh_source,
            local_fence=local_fence)
    except Exception:
        raise MixedAppendApplyRuntimeAttention(
            "mixed append Apply stopped at its last proved boundary") from None
