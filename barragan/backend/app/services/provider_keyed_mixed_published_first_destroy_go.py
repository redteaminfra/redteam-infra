# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot provider destroys for a published mixed generation.

This worker is deliberately not dispatched by HTTP Start. It requires a
reserved/sealed parent, repeated direct fresh two-provider reads, a locked
exact saved-plan show, and a durable command intent before one gated Apply.
Any uncertain intent is never replayed.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_mixed_interrupted_destroy_go import (
    _empty_state, _real_show, _terraform_env,
)
from app.services.provider_keyed_mixed_interrupted_destroy_source import _binary_sha, _sha
from app.services.provider_keyed_mixed_partial_apply_inventory import _credential
from app.services.provider_keyed_mixed_published_destroy_child import (
    child_id, propose_published_mixed_destroy_child,
    recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_destroy_source import attest_published_mixed_destroy_show
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    recognize_published_mixed_plans_sealed,
    saved_published_mixed_destroy_plans,
    saved_published_mixed_initial_review,
)
from app.services.provider_keyed_mixed_published_teardown_collector import collect_published_mixed_initial_teardown
from app.services.provider_keyed_mixed_published_post_first_collector import collect_published_mixed_post_first_transition
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_sketch import SCHEMA, _write_json
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.services.provider_keyed_mixed_published_teardown_authority import published_review_policy

from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


class PublishedMixedFirstDestroyGoAttention(ValueError):
    """The first provider's one-shot destroy needs review, never blind replay."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(at: str) -> str:
    return (datetime.fromisoformat(at) + timedelta(minutes=10)).isoformat()


def _same_new_child(saved: StoredJobRun, proposed: StoredJobRun) -> bool:
    original = datetime.fromisoformat(proposed.created_at)
    stored = datetime.fromisoformat(saved.created_at)
    if original.tzinfo == timezone.utc and stored.tzinfo is None:
        return (stored.replace(tzinfo=timezone.utc) == original
                and saved == replace(
                    proposed, created_at=saved.created_at))
    return saved == proposed


def _run_published_mixed_provider_destroy(
    cleanup_id: str, *, environment: str,
    provider_index: int,
    job_repository=None, lease_lookup=None, credential_repository=None,
    show_runner=_real_show,
    release_validator=require_devtest_terraform_release,
    gated_command_runner=run_gated_command,
) -> StoredJobRun:
    """Run one exact saved-plan Apply once; return awaiting absence."""
    if environment != "devtest":
        raise PublishedMixedFirstDestroyGoAttention(
            "published mixed destroy is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    try:
        cleanup = jobs.get(cleanup_id)
        review = saved_published_mixed_initial_review(cleanup)
        plans = saved_published_mixed_destroy_plans(cleanup)
        scope = cleanup.input["reviewScope"]
        name = cleanup.input["engagementName"]
        recognize_published_mixed_plans_sealed(
            cleanup, review, plans, scope, name)
        source = review.source
        initial = jobs.get(source.parent_job_id)
        if initial is None:
            raise ValueError("published mixed initial parent disappeared")
        provider = source.ordered_providers[provider_index]
        plan = plans.plans[provider_index]
        first_child = (jobs.get(child_id(source.core_job_id,
                                         source.ordered_providers[0]))
                       if provider_index == 1 else None)
        prior_receipt_sha = (first_child.events[7].data["receiptSha256"]
                             if first_child is not None
                             and len(first_child.events) == 8 else None)
        if provider_index == 1 and prior_receipt_sha is None:
            raise ValueError("published mixed first absence is not saved")
        workspace = Path(plan.plan_path).parent
        state_path = workspace / "terraform.tfstate"
        phase_path = workspace / ".barragan-apply-phase.json"
        if state_path.is_symlink():
            raise ValueError("published mixed retained state is unsafe")
        before_state = state_path.read_bytes()
        lease = (source.core_plan_id, "provider_keyed_teardown_fence")
        generation = f"{cleanup.id}:{plans.plan_set_sha256}"
        child_key = child_id(source.core_job_id, provider)
        current: StoredJobRun | None = None

        def fence() -> str:
            if (lookup(source.engagement_id) != lease
                    or jobs.get(cleanup.id) != cleanup
                    or jobs.get(initial.id) != initial
                    or (first_child is not None
                        and jobs.get(first_child.id) != first_child)
                    or (current is not None and jobs.get(child_key) != current)):
                raise ValueError("published mixed one-shot source fence changed")
            return generation

        def fresh() -> None:
            fence()
            if provider_index == 0:
                collected = collect_published_mixed_initial_teardown(
                    source.engagement_id, source.core_job_id,
                    job_repository=jobs, lease_lookup=lookup,
                    allow_teardown_fence=True)
                exact = (collected.review == review
                         and collected.core_inspector_scope == scope
                         and collected.observations[provider].state_json == before_state
                         and collected.workspaces[provider] == workspace)
            else:
                collected = collect_published_mixed_post_first_transition(
                    cleanup_id, job_repository=jobs, lease_lookup=lookup,
                    credential_repository=credentials)
                exact = (collected.cleanup == cleanup
                         and collected.initial == initial
                         and collected.review == review
                         and collected.plans == plans
                         and collected.first_destroy_child == first_child
                         and collected.transition.first_absence.receipt_sha256
                             == prior_receipt_sha
                         and collected.transition.second_provider == provider
                         and collected.transition.second_state_sha256
                             == plan.before_state_sha256
                         and collected.transition.source_generation == generation
                         and collected.second_observation.state_json == before_state)
            if not exact or fence() != generation:
                raise ValueError("published mixed fresh two-provider review changed")

        fresh()
        release = release_validator(environment="devtest")
        if (release.path != Path(plan.terraform_path)
                or release.sha256 != plan.terraform_sha256):
            raise ValueError("published mixed pinned Terraform release changed")
        owner, token = f"mixed-published-destroy-{uuid4().hex}", uuid4().hex

        def claimed_fence() -> None:
            if (current is None or current.input.get("claimOwner") != owner
                    or current.input.get("claimToken") != token
                    or datetime.now(timezone.utc)
                       >= datetime.fromisoformat(current.input["claimExpiresAt"])
                    or fence() != generation):
                raise ValueError("published mixed destroy worker claim changed")

        def renew() -> None:
            nonlocal current
            claimed_fence()
            at = _now()
            updated = jobs.renew_lease(
                child_key, owner=owner, token=token,
                heartbeat_at=at, expires_at=_later(at))
            if updated is None or updated.events != current.events:
                raise ValueError("published mixed destroy claim renewal failed")
            current = updated

        def append(message: str, data: dict) -> None:
            nonlocal current
            claimed_fence()
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                current, owner=owner, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(current.events) + 1, "info", message, data))
            if updated is None:
                raise ValueError("published mixed destroy journal CAS failed")
            current = updated

        expected_phase = ("apply_started" if review.failed_append_recovery is not None
            and review.failed_append_recovery["failedProvider"] == provider
            or review.cleanup_observation is not None and review.cleanup_observation["provider"] == provider else "applied")

        def under_lock(_attested_plan) -> StoredJobRun:
            nonlocal current
            fresh()
            policy = published_review_policy(review, initial, provider)
            encrypted = _credential(credentials, provider, policy)
            command_env = _terraform_env(workspace)
            if (phase_path.is_symlink()
                    or json.loads(phase_path.read_text())
                       != {"schema": SCHEMA, "phase": expected_phase}):
                raise ValueError("published mixed retained Apply phase changed")
            proposal = propose_published_mixed_destroy_child(
                cleanup, review, plans, provider, scope, name,
                prior_absence_receipt_sha256=prior_receipt_sha)
            existing = jobs.get(child_key)
            if existing is None:
                saved = jobs.save_if_absent(proposal)
                if not _same_new_child(saved, proposal):
                    raise ValueError("published mixed one-shot child reservation changed")
            else:
                saved = existing
            if recognize_published_mixed_destroy_child(
                    saved, cleanup, review, plans, provider, scope, name) != "queued":
                raise ValueError("published mixed command already started or uncertain")
            current = jobs.start_if_queued(
                saved, started_at=_now(), event=JobEvent(
                    2, "info", "published mixed provider destroy started", {}))
            if current is None:
                raise ValueError("published mixed one-shot child start changed")
            at = _now()
            current = jobs.claim_lease(
                child_key, owner=owner, token=token,
                claimed_at=at, expires_at=_later(at),
                eligible_statuses={"running"})
            if (current is None or recognize_published_mixed_destroy_child(
                    current, cleanup, review, plans, provider, scope, name)
                    != "started"):
                raise ValueError("published mixed one-shot child claim changed")
            append("published mixed provider destroy show proved", {
                "planSha256": plan.plan_sha256,
                "showSha256": plan.show_json_sha256,
                "beforeStateSha256": plan.before_state_sha256,
            })
            command = [plan.terraform_path, "apply", "-input=false",
                       "-lock=true", "-no-color", plan.plan_path]
            argv_sha = hashlib.sha256(json.dumps(
                command, separators=(",", ":")).encode()).hexdigest()
            stage = "none"
            intent = started = None

            def local_pre_go() -> None:
                if (state_path.is_symlink() or phase_path.is_symlink()
                        or state_path.read_bytes() != before_state
                        or _sha(Path(plan.plan_path)) != plan.plan_sha256
                        or _binary_sha(Path(plan.terraform_path))
                           != plan.terraform_sha256
                        or json.loads(phase_path.read_text())
                           != {"schema": SCHEMA, "phase": expected_phase}
                        or _terraform_env(workspace) != command_env
                        or _credential(credentials, provider, policy) != encrypted):
                    raise ValueError("published mixed pre-GO state or plan changed")

            def before_intent(value) -> None:
                nonlocal stage, intent
                if (stage != "none" or value.scratch_path != str(workspace)
                        or value.argv_sha256 != argv_sha):
                    raise ValueError("published mixed destroy intent command changed")
                renew()
                fresh()
                renew()
                local_pre_go()
                append("published mixed provider destroy command intended", {
                    "invocationId": value.invocation_id,
                    "argvSha256": value.argv_sha256,
                    "showJournalSha256": job_event_digest(current.events),
                })
                intent, stage = value, "intent"

            def before_go(value) -> None:
                nonlocal stage, started
                if stage != "intent" or value.intent != intent:
                    raise ValueError("published mixed destroy start identity changed")
                renew()
                fresh()
                renew()
                local_pre_go()
                append("published mixed provider destroy command started before GO", {
                    "invocationId": intent.invocation_id,
                    "bootId": value.identity.boot_id,
                    "pid": value.identity.pid,
                    "pgid": value.identity.pgid,
                    "startTicks": value.identity.start_ticks,
                })
                _write_json(phase_path, {"schema": SCHEMA,
                                         "phase": "destroy_started"})
                started, stage = value, "started"
                claimed_fence()

            def heartbeat(value) -> None:
                if stage != "started" or value != started:
                    raise ValueError("published mixed destroy heartbeat changed")
                renew()

            def result(value) -> None:
                nonlocal stage
                if stage != "started" or value.started != started:
                    raise ValueError("published mixed destroy result identity changed")
                append("published mixed provider destroy result fenced", {
                    "invocationId": intent.invocation_id,
                    "returnCode": value.returncode,
                    "stdoutBytes": value.stdout_bytes,
                    "stderrBytes": value.stderr_bytes,
                    "stdoutTruncated": value.stdout_truncated,
                    "stderrTruncated": value.stderr_truncated,
                })
                stage = "result"

            renew()
            fresh()
            renew()
            local_pre_go()
            outcome = gated_command_runner(
                command, scratch_path=workspace, provider_keyed_v2=True,
                gate_timeout_seconds=1200, intent_callback=before_intent,
                started_callback=before_go, heartbeat_callback=heartbeat,
                result_callback=result, env=command_env)
            if (stage != "result" or outcome.started != started
                    or outcome.returncode != 0 or outcome.stdout_truncated
                    or outcome.stderr_truncated):
                raise ValueError("published mixed one-shot result needs review")
            _empty_state(state_path, plan.state_lineage, plan.state_serial)
            _write_json(phase_path, {"schema": SCHEMA,
                                     "phase": "destroy_applied"})
            append("published mixed provider awaiting exact absence", {
                "commandResultSequence": 6})
            if (recognize_published_mixed_destroy_child(
                    current, cleanup, review, plans, provider, scope, name)
                    != "awaiting_absence"):
                raise ValueError("published mixed one-shot journal differs")
            # The Apply worker has no remaining provider write. Expire only
            # its own claim so a separate GET-only absence worker can take a
            # distinct claim without waiting for the normal worker timeout.
            handoff_at = _now()
            handed_off = jobs.renew_lease(
                child_key, owner=owner, token=token,
                heartbeat_at=handoff_at, expires_at=handoff_at)
            if (handed_off is None or handed_off.events != current.events
                    or handed_off.input.get("claimOwner") != owner
                    or handed_off.input.get("claimToken") != token):
                raise ValueError("published mixed absence claim handoff changed")
            current = handed_off
            return current

        return attest_published_mixed_destroy_show(
            initial, cleanup, review, plans, provider, before_state,
            scope, name, fence=fence, show_runner=show_runner,
            release_validator=lambda: release, on_attested=under_lock)
    except Exception:
        raise PublishedMixedFirstDestroyGoAttention(
            "published mixed destroy requires exact one-shot review; never replay uncertain intent") from None


def run_published_mixed_first_provider_destroy(cleanup_id: str, **kwargs) -> StoredJobRun:
    """Run the first provider while both original states remain full."""
    return _run_published_mixed_provider_destroy(
        cleanup_id, provider_index=0, **kwargs)


def run_published_mixed_second_provider_destroy(cleanup_id: str, **kwargs) -> StoredJobRun:
    """Run provider 2 only after the terminal first receipt and fresh transition."""
    return _run_published_mixed_provider_destroy(
        cleanup_id, provider_index=1, **kwargs)
