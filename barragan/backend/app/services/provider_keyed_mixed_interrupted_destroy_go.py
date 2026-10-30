# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, one-shot mixed interrupted provider destroy Apply."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_mixed_interrupted_cleanup import recognize_mixed_interrupted_sealed_plans
from app.services.provider_keyed_mixed_interrupted_destroy_child import (
    MixedInterruptedDestroyChildAttention, _child_id, _digest,
    propose_mixed_interrupted_destroy_child, recognize_mixed_interrupted_destroy_child,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import MixedInterruptedDestroyPlanSet
from app.services.provider_keyed_mixed_interrupted_destroy_source import (
    MixedInterruptedDestroyShow, _binary_sha, _sha,
    bind_mixed_interrupted_destroy_show,
)
from app.services.provider_keyed_mixed_initial_apply_child import _child_id as _apply_child_id
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import prove_mixed_interrupted_provider_absence
from app.services.provider_keyed_mixed_interrupted_source import (
    MixedInterruptedReview, review_mixed_interrupted_provider_source,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import _credential
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_sketch import SCHEMA, _write_json
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.credential_repository import SqlAlchemyCredentialRepository


class MixedInterruptedDestroyGoAttention(ValueError):
    """A one-shot destroy write or its durable evidence needs review."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=120)).isoformat()


_COMMAND_ENV = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
                          "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"})


def _terraform_env(cwd: Path) -> dict[str, str]:
    data_dir = cwd / ".terraform-data"
    if data_dir.is_symlink() or not data_dir.is_dir():
        raise MixedInterruptedDestroyGoAttention("saved destroy Terraform data directory differs")
    return {**{key: value for key, value in os.environ.items() if key in _COMMAND_ENV},
            "TF_CLI_CONFIG_FILE": "/dev/null", "TF_DATA_DIR": str(data_dir)}


def _real_show(command: tuple[str, ...], cwd: Path) -> str:
    env = _terraform_env(cwd)
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                            timeout=120, check=False, env=env)
    if result.returncode != 0 or not result.stdout:
        raise MixedInterruptedDestroyGoAttention("saved destroy show failed")
    return result.stdout


def _empty_state(path: Path, before_lineage: str, before_serial: int) -> None:
    if path.is_symlink() or not path.is_file():
        raise MixedInterruptedDestroyGoAttention("retained destroy state is unavailable")
    value = json.loads(path.read_text())
    if (value.get("version") != 4 or value.get("terraform_version") != "1.15.5"
            or value.get("lineage") != before_lineage
            or type(value.get("serial")) is not int or value["serial"] <= before_serial
            or value.get("resources") != []):
        raise MixedInterruptedDestroyGoAttention("retained destroy state is not empty")


_STABLE_SCOPE_FIELDS = (
    "provider", "kind", "child_journal_sha256", "state_sha256", "lineage",
    "serial", "resource_ids", "selector_tag", "selector_retirement_pending",
)


def _same_owned_scope(current, reviewed) -> bool:
    return all(getattr(current, field) == getattr(reviewed, field)
               for field in _STABLE_SCOPE_FIELDS)


def _same_owned_review(current, reviewed: MixedInterruptedReview) -> bool:
    return (type(current) is MixedInterruptedReview
            and current.engagement_id == reviewed.engagement_id
            and current.core_job_id == reviewed.core_job_id
            and current.seal_journal_sha256 == reviewed.seal_journal_sha256
            and current.ordered_providers == reviewed.ordered_providers
            and all(_same_owned_scope(now, sealed) for now, sealed in zip(
                current.scopes, reviewed.scopes, strict=True)))


def _same_new_reservation(saved: StoredJobRun, proposed: StoredJobRun) -> bool:
    """Account only for SQLite's loss of UTC tzinfo on a newly inserted job."""
    try:
        original = datetime.fromisoformat(proposed.created_at)
        stored = datetime.fromisoformat(saved.created_at)
        if original.tzinfo != timezone.utc or stored.tzinfo is not None:
            return saved == proposed
        return (stored.replace(tzinfo=timezone.utc) == original
                and saved == replace(proposed, created_at=saved.created_at))
    except (TypeError, ValueError):
        return False


def run_first_mixed_interrupted_provider_destroy(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
    provider: str, before_state: bytes, *, environment: str,
    exact_both_scope_prover: Callable[[Callable[[], None]], MixedInterruptedReview] | None = None,
    inventory_collector: Callable | None = None,
    process_quiescent: Callable[[dict], bool] | None = None,
    job_repository=None, lease_lookup=None,
    credential_repository=None,
    terraform_path: Path = Path("/usr/bin/terraform"),
    show_runner: Callable[[tuple[str, ...], Path], str] = _real_show,
    release_validator: Callable = require_devtest_terraform_release,
    gated_command_runner: Callable = run_gated_command,
) -> StoredJobRun:
    """Run one exact Apply at most once; an uncertain journal is never retried."""
    try:
        if environment != "devtest":
            raise ValueError("disposable mixed cleanup scope differs")
        recognize_mixed_interrupted_sealed_plans(cleanup, initial, review, plans)
        index = plans.ordered_providers.index(provider)
        if index == 0 and not callable(exact_both_scope_prover):
            raise ValueError("both providers need fresh review")
        if index == 1 and (not callable(inventory_collector)
                           or not callable(process_quiescent)):
            raise ValueError("second provider needs fresh first absence and own source")
        scope, plan = review.scopes[index], plans.plans[index]
        if (scope.kind not in {"partial", "full"} or plan.plan_path is None
                or type(before_state) is not bytes
                or hashlib.sha256(before_state).hexdigest() != plan.before_state_sha256):
            raise ValueError("state-backed provider source differs")
        jobs = job_repository or SqlAlchemyJobRepository()
        lookup = lease_lookup or _db_lease_lookup
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        policy = initial.events[5].data["reviewedPolicy"][provider]
        lease = (initial.input["corePlanId"], "provider_keyed_teardown_fence")

        def preclaim_fence() -> None:
            if (jobs.get(initial.id) != initial or jobs.get(cleanup.id) != cleanup
                    or lookup(initial.target_id) != lease):
                raise MixedInterruptedDestroyGoAttention("mixed cleanup source fence changed")

        def fresh_authority(check: Callable[[], None]):
            """Observe complete current inventories; never reuse a prior GET result."""
            if index == 0:
                if not _same_owned_review(exact_both_scope_prover(check), review):
                    raise MixedInterruptedDestroyGoAttention("both mixed scopes changed")
                return None
            prior_provider = plans.ordered_providers[0]
            generation = f"{cleanup.id}:{plans.plan_set_sha256}"
            def fenced_generation() -> str:
                check()
                return generation
            first_snapshot = inventory_collector(
                prior_provider, fenced_generation,
                "apply" if review.scopes[0].kind == "failed_absent" else "destroy_applied")
            first_receipt = prove_mixed_interrupted_provider_absence(
                initial, cleanup, review, plans, prior_provider,
                jobs.get(_apply_child_id(initial.input["coreJobId"], prior_provider)),
                jobs.get(_child_id(initial.input["coreJobId"], prior_provider)),
                first_snapshot, fence=fenced_generation,
                process_quiescent=process_quiescent)
            own_snapshot = inventory_collector(provider, fenced_generation, "apply")
            current_scope = review_mixed_interrupted_provider_source(
                initial, provider,
                jobs.get(_apply_child_id(initial.input["coreJobId"], provider)),
                own_snapshot, fence=fenced_generation,
                process_quiescent=process_quiescent)
            expected = review.scopes[index]
            if not _same_owned_scope(current_scope, expected):
                raise MixedInterruptedDestroyGoAttention("second provider scope changed")
            check()
            return first_receipt

        preclaim_fence()
        fresh_authority(preclaim_fence)
        preclaim_fence()
        child_id = _child_id(initial.input["coreJobId"], provider)
        release = release_validator(environment="devtest")
        if (release.path != terraform_path or not isinstance(release.sha256, str)):
            raise ValueError("reviewed Terraform release differs")
        owner, token = f"mixed-interrupted-destroy-{uuid4().hex}", uuid4().hex
        current: StoredJobRun | None = None

        def fence() -> None:
            if (lookup(initial.target_id) != lease or jobs.get(initial.id) != initial
                    or jobs.get(cleanup.id) != cleanup or current is None
                    or jobs.get(child_id) != current
                    or datetime.now(timezone.utc)
                       >= datetime.fromisoformat(current.input["claimExpiresAt"])):
                raise MixedInterruptedDestroyGoAttention("mixed destroy authority changed")

        def renew() -> None:
            nonlocal current
            fence()
            at = _now()
            updated = jobs.renew_lease(child_id, owner=owner, token=token,
                                       heartbeat_at=at, expires_at=_later(at))
            if updated is None or updated.events != current.events:
                raise MixedInterruptedDestroyGoAttention("mixed destroy worker claim expired")
            current = updated

        def append(message: str, data: dict) -> None:
            nonlocal current
            fence()
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                current, owner=owner, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(current.events) + 1, "info", message, data))
            if updated is None:
                raise MixedInterruptedDestroyGoAttention("mixed destroy journal fence lost")
            current = updated

        def under_lock(bound: MixedInterruptedDestroyShow) -> StoredJobRun:
            nonlocal current
            preclaim_fence()
            prior_receipt = fresh_authority(preclaim_fence)
            preclaim_fence()
            _credential(credentials, provider, policy)
            root = Path(bound.plan_path).parent
            command_env = _terraform_env(root)
            proposal = propose_mixed_interrupted_destroy_child(
                initial, cleanup, review, plans, bound)
            existing = jobs.get(child_id)
            if existing is None:
                saved = jobs.save_if_absent(proposal)
                if not _same_new_reservation(saved, proposal):
                    raise MixedInterruptedDestroyGoAttention("one-shot destroy reservation changed")
            else:
                saved = existing
            if recognize_mixed_interrupted_destroy_child(
                    saved, initial, cleanup, review, plans, bound) != "queued":
                raise MixedInterruptedDestroyGoAttention("one-shot destroy queue changed")
            current = jobs.start_if_queued(
                saved, started_at=_now(),
                event=JobEvent(2, "info", "mixed provider destroy started", {}))
            if current is None:
                raise MixedInterruptedDestroyGoAttention("one-shot destroy start changed")
            at = _now()
            current = jobs.claim_lease(child_id, owner=owner, token=token,
                                       claimed_at=at, expires_at=_later(at),
                                       eligible_statuses={"running"})
            if current is None or recognize_mixed_interrupted_destroy_child(
                    current, initial, cleanup, review, plans, bound) != "started":
                raise MixedInterruptedDestroyGoAttention("one-shot destroy claim changed")
            renew()
            show_event = {
                "showSha256": bound.show_sha256, "planSha256": bound.plan_sha256,
                "terraformSha256": bound.terraform_sha256,
                "beforeStateSha256": bound.before_state_sha256,
                "showArgvSha256": bound.argv_sha256}
            if prior_receipt is not None:
                show_event.update({
                    "priorAbsenceObservationSha256": prior_receipt.observation_sha256,
                    "priorAbsenceReceiptSha256": _digest(asdict(prior_receipt))})
            append("mixed provider destroy show proved", show_event)
            plan_path = Path(bound.plan_path)
            state_path = root / "terraform.tfstate"
            phase_path = root / ".barragan-apply-phase.json"
            expected_phase = "applied" if scope.kind == "full" else "apply_started"
            if (phase_path.is_symlink() or json.loads(phase_path.read_text()) !=
                    {"schema": SCHEMA, "phase": expected_phase}):
                raise MixedInterruptedDestroyGoAttention("pre-destroy phase changed")
            command = (bound.terraform_path, "apply", "-input=false", "-lock=true",
                       "-no-color", bound.plan_path)
            stage = "none"
            intent = started = None

            def local_pre_go() -> None:
                if (state_path.is_symlink() or phase_path.is_symlink()
                        or state_path.read_bytes() != before_state
                        or _sha(plan_path) != bound.plan_sha256
                        or _binary_sha(terraform_path) != bound.terraform_sha256
                        or _terraform_env(root) != command_env
                        or not _credential(credentials, provider, policy)
                        or json.loads(phase_path.read_text()) !=
                           {"schema": SCHEMA, "phase": expected_phase}):
                    raise MixedInterruptedDestroyGoAttention("pre-GO state or plan changed")

            def before_intent(value) -> None:
                nonlocal stage, intent
                if (stage != "none" or value.scratch_path != str(root)
                        or value.argv_sha256 != _digest(command)):
                    raise MixedInterruptedDestroyGoAttention("pre-GO state or plan changed")
                renew()
                fresh_authority(renew)
                local_pre_go()
                append("mixed provider destroy command intended", {
                    "invocationId": value.invocation_id, "argvSha256": value.argv_sha256,
                    "showJournalSha256": job_event_digest(current.events),
                    "beforeStateSha256": bound.before_state_sha256,
                    "planSha256": bound.plan_sha256})
                intent, stage = value, "intent"

            def before_go(value) -> None:
                nonlocal stage, started
                if stage != "intent" or value.intent != intent:
                    raise MixedInterruptedDestroyGoAttention("destroy command start changed")
                renew()
                fresh_authority(renew)
                renew()
                local_pre_go()
                append("mixed provider destroy command started before GO", {
                    "invocationId": intent.invocation_id,
                    "bootId": value.identity.boot_id, "pid": value.identity.pid,
                    "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks})
                _write_json(phase_path, {"schema": SCHEMA, "phase": "destroy_started"})
                append("mixed provider phase destroy_started", {"commandStartSequence": 5})
                started, stage = value, "started"
                fence()

            def heartbeat(value) -> None:
                if stage != "started" or value != started:
                    raise MixedInterruptedDestroyGoAttention("destroy heartbeat identity changed")
                renew()

            def result(value) -> None:
                nonlocal stage
                if stage != "started" or value.started != started:
                    raise MixedInterruptedDestroyGoAttention("destroy result identity changed")
                append("mixed provider destroy result fenced", {
                    "invocationId": intent.invocation_id, "returnCode": value.returncode,
                    "stdoutBytes": value.stdout_bytes, "stderrBytes": value.stderr_bytes,
                    "stdoutTruncated": value.stdout_truncated,
                    "stderrTruncated": value.stderr_truncated})
                stage = "result"

            renew()
            fresh_authority(renew)
            renew()
            outcome = gated_command_runner(
                list(command), scratch_path=root, provider_keyed_v2=True,
                gate_timeout_seconds=1200, intent_callback=before_intent,
                started_callback=before_go, heartbeat_callback=heartbeat,
                result_callback=result, env=command_env)
            if (stage != "result" or outcome.started != started or outcome.returncode != 0
                    or outcome.stdout_truncated or outcome.stderr_truncated):
                raise MixedInterruptedDestroyGoAttention("one-shot destroy result needs review")
            _empty_state(state_path, plan.state_lineage, plan.state_serial)
            _write_json(phase_path, {"schema": SCHEMA, "phase": "destroy_applied"})
            append("mixed provider phase destroy_applied", {"commandResultSequence": 7})
            append("mixed provider awaiting exact absence", {"commandResultSequence": 7})
            if recognize_mixed_interrupted_destroy_child(
                    current, initial, cleanup, review, plans, bound) != "awaiting_absence":
                raise MixedInterruptedDestroyGoAttention("one-shot destroy journal differs")
            return current

        return bind_mixed_interrupted_destroy_show(
            initial, cleanup, review, plans, provider, before_state,
            terraform_path, release.sha256, show_runner=show_runner,
            fence=lambda: ("teardown-generation" if lookup(initial.target_id) == lease
                           and jobs.get(initial.id) == initial and jobs.get(cleanup.id) == cleanup
                           else ""),
            release_validator=lambda: release, on_bound=under_lock)
    except Exception:
        raise MixedInterruptedDestroyGoAttention(
            "one-shot mixed destroy requires exact review; never replay an uncertain write") from None


run_mixed_interrupted_provider_destroy = run_first_mixed_interrupted_provider_destroy


def reconcile_mixed_interrupted_destroy_result(
    initial: StoredJobRun, cleanup: StoredJobRun,
    review: MixedInterruptedReview, plans: MixedInterruptedDestroyPlanSet,
    provider: str, *, process_quiescent: Callable[[dict], bool],
    inventory_collector: Callable | None = None,
    job_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Advance exact rc0/empty-state history without replaying Terraform."""
    try:
        recognize_mixed_interrupted_sealed_plans(cleanup, initial, review, plans)
        jobs = job_repository or SqlAlchemyJobRepository()
        lookup = lease_lookup or _db_lease_lookup
        lease = (initial.input["corePlanId"], "provider_keyed_teardown_fence")
        index = plans.ordered_providers.index(provider)
        child_id = _child_id(initial.input["coreJobId"], provider)
        child = jobs.get(child_id)
        if (child is None or jobs.get(initial.id) != initial
                or jobs.get(cleanup.id) != cleanup or lookup(initial.target_id) != lease):
            raise ValueError("mixed result boundary differs")

        def prior_absence() -> None:
            if index == 0:
                return
            if not callable(inventory_collector):
                raise ValueError("second destroy recovery needs fresh prior absence")
            first = plans.ordered_providers[0]
            generation = f"{cleanup.id}:{plans.plan_set_sha256}"
            def fenced_generation() -> str:
                if (lookup(initial.target_id) != lease or jobs.get(initial.id) != initial
                        or jobs.get(cleanup.id) != cleanup):
                    raise ValueError("destroy recovery fence changed")
                return generation
            snapshot = inventory_collector(
                first, fenced_generation,
                "apply" if review.scopes[0].kind == "failed_absent" else "destroy_applied")
            prove_mixed_interrupted_provider_absence(
                initial, cleanup, review, plans, first,
                jobs.get(_apply_child_id(initial.input["coreJobId"], first)),
                jobs.get(_child_id(initial.input["coreJobId"], first)), snapshot,
                fence=fenced_generation, process_quiescent=process_quiescent)

        prior_absence()
        inputs = child.input
        bound = MixedInterruptedDestroyShow(
            provider, inputs["terraformPath"], inputs["terraformSha256"],
            inputs["planPath"], inputs["planSha256"], inputs["showSha256"],
            inputs["beforeStateSha256"],
            _digest((inputs["terraformPath"], "show", "-json", inputs["planPath"])))
        stage = recognize_mixed_interrupted_destroy_child(
            child, initial, cleanup, review, plans, bound)
        if stage == "awaiting_absence":
            return child
        if stage not in {"result", "phase_applied"}:
            raise ValueError("mixed result is not proved")
        identity = child.events[4].data
        if process_quiescent(identity) is not True:
            raise ValueError("destroy process is not quiescent")
        root = Path(bound.plan_path).parent
        lock_path = root / f".barragan-{provider}-plan.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("destroy workspace lock changed")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                if lock_path.is_symlink() or lock_path.stat().st_ino != info.st_ino:
                    raise ValueError("destroy workspace lock was replaced")
                plan = plans.plans[plans.ordered_providers.index(provider)]
                _empty_state(root / "terraform.tfstate", plan.state_lineage, plan.state_serial)
                phase_path = root / ".barragan-apply-phase.json"
                marker = json.loads(phase_path.read_text()) if not phase_path.is_symlink() else None
                allowed = ({"schema": SCHEMA, "phase": "destroy_started"},
                           {"schema": SCHEMA, "phase": "destroy_applied"}) if stage == "result" else (
                           {"schema": SCHEMA, "phase": "destroy_applied"},)
                if marker not in allowed:
                    raise ValueError("destroy phase marker differs")
                # A fresh claim requires the old one to expire. This never
                # permits two workers to append under a shared claim token.
                owner, token = f"mixed-interrupted-destroy-{uuid4().hex}", uuid4().hex
                at = _now()
                current = jobs.claim_lease(child_id, owner=owner, token=token,
                                           claimed_at=at, expires_at=_later(at),
                                           eligible_statuses={"running"})
                if (current is None or recognize_mixed_interrupted_destroy_child(
                        current, initial, cleanup, review, plans, bound) != stage):
                    raise ValueError("destroy recovery claim is unavailable")

                def append(message: str, data: dict) -> None:
                    nonlocal current
                    if (lookup(initial.target_id) != lease or jobs.get(initial.id) != initial
                            or jobs.get(cleanup.id) != cleanup or jobs.get(child_id) != current
                            or process_quiescent(identity) is not True):
                        raise ValueError("destroy recovery fence changed")
                    prior_absence()
                    now = _now()
                    updated = jobs.append_event_if_running_claimed(
                        current, owner=owner, token=token,
                        expected_event_digest=job_event_digest(current.events),
                        heartbeat_at=now, expires_at=_later(now),
                        event=JobEvent(len(current.events) + 1, "info", message, data))
                    if updated is None:
                        raise ValueError("destroy recovery journal CAS lost")
                    current = updated

                if stage == "result":
                    if marker["phase"] == "destroy_started":
                        _write_json(phase_path, {"schema": SCHEMA, "phase": "destroy_applied"})
                    append("mixed provider phase destroy_applied", {"commandResultSequence": 7})
                append("mixed provider awaiting exact absence", {"commandResultSequence": 7})
                if recognize_mixed_interrupted_destroy_child(
                        current, initial, cleanup, review, plans, bound) != "awaiting_absence":
                    raise ValueError("destroy recovery journal differs")
                return current
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise MixedInterruptedDestroyGoAttention(
            "mixed destroy result needs exact no-replay reconciliation") from None
