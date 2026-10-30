# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot first-provider Apply for a reviewed mixed 4-to-6 append.

The caller supplies a locked, audited source and fresh paired pre-GO proof.
There is no route or dispatcher here. A command intent is a no-replay fence,
even if the process never reached GO; poststate proof is a later operation.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_mixed_initial_apply_child import _save_failed_apply_output
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_mixed_initial_apply_child import _saved_plan_sha
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace, mark_provider_keyed_applied, mark_provider_keyed_apply_started,
)
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_append_apply_child"
_OPERATION = "provider_keyed_mixed_append"
_CLAIM_KEYS = {"claimOwner", "claimToken", "claimClaimedAt", "claimHeartbeatAt", "claimExpiresAt"}
_ENV = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
                  "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"})


class MixedAppendFirstApplyAttention(ValueError):
    """The first provider Apply needs read-only reconciliation; never replay."""


@dataclass(frozen=True)
class FirstApplySource:
    workspace: ProviderKeyedWorkspace
    predecessor_state_sha256: str
    plan_sha256: str
    terraform_sha256: str
    lock_fence: Callable[[], None]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(at: str) -> str:
    return (datetime.fromisoformat(at) + timedelta(seconds=120)).isoformat()


def _sha(path: Path) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("retained state is not regular")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def _child_id(parent_id: str) -> str:
    return f"job-provider-keyed-mixed-append-apply-first-{parent_id.removeprefix('job-')}"


def _base(parent: StoredJobRun) -> dict:
    return {
        "engagementId": parent.target_id, "coreJobId": parent.input["coreJobId"],
        "corePlanId": parent.input["corePlanId"], "appendParentId": parent.id,
        "reviewSha256": parent.input["reviewSha256"],
        "provider": parent.input["providerOrder"][0], "providerIndex": 0,
        "mutation": True,
    }


def _precommand(child: StoredJobRun, parent: StoredJobRun) -> bool:
    base = _base(parent)
    if (child.id != _child_id(parent.id) or child.action != ACTION
            or child.target_id != parent.target_id or child.target_type != "engagement"
            or child.target != f"engagement:{parent.target_id}"
            or child.requested_by != parent.requested_by
            or child.finished_at is not None or child.artifact_refs != []
            or {key: value for key, value in child.input.items() if key not in _CLAIM_KEYS} != base):
        return False
    queued = JobEvent(1, "info", "mixed append first Apply queued", {})
    started = JobEvent(2, "info", "mixed append first Apply started", {})
    return ((child.status == "queued" and child.started_at is None
             and child.events == [queued] and child.input == base)
            or (child.status == "running" and child.started_at is not None
                and child.events == [queued, started]))


def run_first_mixed_append_provider_apply(
    parent_id: str, *, environment: str, job_repository=None,
    lease_lookup: Callable[[str], tuple[str, str] | None],
    source_session: Callable[[StoredJobRun, str, Callable[[], None]],
                             AbstractContextManager[FirstApplySource]],
    pair_preflight: Callable[[StoredJobRun, Callable[[], None]], str],
    pre_go_check: Callable[[StoredJobRun, FirstApplySource, Callable[[], None]], str],
    release_check: Callable = require_devtest_terraform_release,
    gated_command_runner: Callable = run_gated_command,
    command_environment: dict[str, str] | None = None,
) -> StoredJobRun:
    """Write at most once, stopping at an exact-result awaiting-proof journal.

    ``pair_preflight`` must use the paired binary re-show fence before the
    source session takes its exclusive first-provider plan lock. Under that
    lock, ``pre_go_check`` must freshly bind both provider inventories,
    credentials, source, lease, and reviewed artifacts without reacquiring
    the plan locks. The source session holds its lock through Apply. This
    private worker cannot be dispatched until those binders and parent
    approval are implemented.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = jobs.get(parent_id)
    raw_env = os.environ if command_environment is None else command_environment
    if (environment != "devtest" or parent is None or parent.action != _OPERATION
            or parent.status != "running" or parent.input.get("phase") != "apply_sealed"
            or parent.target_type != "engagement"
            or parent.target != f"engagement:{parent.target_id}"
            or type(parent.input.get("coreJobId")) is not str
            or type(parent.input.get("corePlanId")) is not str
            or type(parent.input.get("reviewSha256")) is not str
            or len(parent.input["reviewSha256"]) != 64
            or any(char not in "0123456789abcdef" for char in parent.input["reviewSha256"])
            or type(parent.input.get("providerOrder")) is not list
            or len(parent.input["providerOrder"]) != 2
            or set(parent.input["providerOrder"]) != {"linode", "digitalocean"}
            or not callable(lease_lookup) or not callable(source_session)
            or not callable(pair_preflight) or not callable(pre_go_check)
            or any(key.upper().startswith("TF_") for key in raw_env)
            or lease_lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)):
        raise MixedAppendFirstApplyAttention("mixed append first Apply authority differs")
    child_id = _child_id(parent.id)
    existing = jobs.get(child_id)
    if existing is not None and not _precommand(existing, parent):
        raise MixedAppendFirstApplyAttention("mixed append first Apply intent already exists")
    base = _base(parent)
    queued = StoredJobRun(
        child_id, ACTION, "queued", parent.target, "engagement", parent.target_id,
        parent.requested_by, base, [], _now(), None, None,
        [JobEvent(1, "info", "mixed append first Apply queued", {})],
    )
    saved = jobs.save_if_absent(queued)
    if not _precommand(saved, parent):
        raise MixedAppendFirstApplyAttention("mixed append first Apply reservation differs")
    if saved.status == "queued":
        current = jobs.start_if_queued(saved, started_at=_now(), event=JobEvent(
            2, "info", "mixed append first Apply started", {}))
        if current is None:
            raise MixedAppendFirstApplyAttention("mixed append first Apply start lost")
    else:
        current = saved
    owner, token = f"mixed-append-first-{uuid4().hex}", uuid4().hex
    at = _now()
    current = jobs.claim_lease(child_id, owner=owner, token=token,
                               claimed_at=at, expires_at=_later(at),
                               eligible_statuses={"running"})
    if current is None or not _precommand(current, parent):
        raise MixedAppendFirstApplyAttention("mixed append first Apply claim unavailable")

    def fence() -> None:
        if (jobs.get(parent.id) != parent or jobs.get(child_id) != current
                or lease_lookup(parent.target_id) != (parent.input["corePlanId"], _OPERATION)
                or datetime.now(timezone.utc) >= datetime.fromisoformat(
                    current.input["claimExpiresAt"])):
            raise MixedAppendFirstApplyAttention("mixed append first Apply claim changed")

    def renew() -> None:
        nonlocal current
        fence()
        at = _now()
        updated = jobs.renew_lease(child_id, owner=owner, token=token,
                                   heartbeat_at=at, expires_at=_later(at))
        if updated is None or updated.events != current.events:
            raise MixedAppendFirstApplyAttention("mixed append first Apply heartbeat lost")
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
            raise MixedAppendFirstApplyAttention("mixed append first Apply journal CAS lost")
        current = updated

    renew()
    if pair_preflight(parent, renew) != base["reviewSha256"]:
        raise MixedAppendFirstApplyAttention("mixed append paired binary preflight differs")
    provider = base["provider"]
    with source_session(parent, provider, renew) as source:
        renew()
        if (not isinstance(source, FirstApplySource)
                or source.workspace.provider != provider
                or source.workspace.schema != "provider-keyed-v2"
                or not source.workspace.path.is_absolute()
                or not callable(source.lock_fence)):
            raise MixedAppendFirstApplyAttention("mixed append first saved source differs")
        root = source.workspace.path
        plan_path = root / _name(provider, "saved.tfplan")
        release = release_check(environment=environment)
        command = [str(release.path), "apply", "-input=false", "-lock=true",
                   "-no-color", str(plan_path)]
        if (source.terraform_sha256 != release.sha256
                or _saved_plan_sha(plan_path) != source.plan_sha256
                or _sha(source.workspace.state_path) != source.predecessor_state_sha256
                or json.loads((root / ".barragan-apply-phase.json").read_text()) !=
                   {"schema": "provider-keyed-v2", "phase": "applied"}):
            raise MixedAppendFirstApplyAttention("mixed append first predecessor differs")
        if pre_go_check(parent, source, renew) != base["reviewSha256"]:
            raise MixedAppendFirstApplyAttention("mixed append paired pre-GO proof differs")
        renew()
        stage = "none"
        intent = None
        started = None

        def fresh_go_inputs() -> bool:
            """Final under-lock check; safe to call after process spawn, before GO."""
            source.lock_fence()
            fresh_release = release_check(environment=environment)
            return (fresh_release.path == release.path
                    and fresh_release.sha256 == source.terraform_sha256
                    and _saved_plan_sha(plan_path) == source.plan_sha256
                    and _sha(source.workspace.state_path) == source.predecessor_state_sha256
                    and json.loads((root / ".barragan-apply-phase.json").read_text()) ==
                    {"schema": "provider-keyed-v2", "phase": "applied"}
                    and pre_go_check(parent, source, renew) == base["reviewSha256"])

        def on_intent(value) -> None:
            nonlocal intent, stage
            if (stage != "none" or value.scratch_path != str(root)
                    or value.argv_sha256 != _digest(command)
                    or not fresh_go_inputs()):
                raise MixedAppendFirstApplyAttention("mixed append first GO inputs changed")
            append("mixed append first Apply command intended", {
                "invocationId": value.invocation_id, "argvSha256": value.argv_sha256,
                "planSha256": source.plan_sha256, "planPath": str(plan_path),
                "terraformPath": str(release.path), "terraformSha256": release.sha256,
            })
            intent, stage = value, "intent"

        def on_started(value) -> None:
            nonlocal started, stage
            if (stage != "intent" or value.intent != intent
                    or not fresh_go_inputs()):
                raise MixedAppendFirstApplyAttention("mixed append first process differs")
            append("mixed append first Apply command started before GO", {
                "invocationId": intent.invocation_id,
                "bootId": value.identity.boot_id, "pid": value.identity.pid,
                "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks,
            })
            started, stage = value, "started"
            mark_provider_keyed_apply_started(source.workspace)
            append("mixed append first phase apply_started", {
                "commandStartSequence": len(current.events),
            })
            fence()

        def on_heartbeat(value) -> None:
            if stage != "started" or value != started:
                raise MixedAppendFirstApplyAttention("mixed append first heartbeat identity differs")
            source.lock_fence()
            renew()

        def on_result(value) -> None:
            nonlocal stage
            if stage != "started" or value.started != started:
                raise MixedAppendFirstApplyAttention("mixed append first result differs")
            source.lock_fence()
            append("mixed append first Apply command result fenced", {
                "invocationId": intent.invocation_id, "returnCode": value.returncode,
                "stdoutBytes": value.stdout_bytes, "stderrBytes": value.stderr_bytes,
                "stdoutTruncated": value.stdout_truncated,
                "stderrTruncated": value.stderr_truncated,
            })
            stage = "result"

        env = {key: value for key, value in raw_env.items() if key in _ENV}
        env.update(TF_DATA_DIR=str(source.workspace.terraform_data_dir),
                   TF_CLI_CONFIG_FILE="/dev/null")
        outcome = gated_command_runner(
            command, scratch_path=root, provider_keyed_v2=True,
            gate_timeout_seconds=1200, max_output_bytes=1024 * 1024, env=env,
            intent_callback=on_intent, started_callback=on_started,
            heartbeat_callback=on_heartbeat, result_callback=on_result,
        )
        if stage == "result" and outcome.started == started and outcome.returncode != 0:
            try:
                _save_failed_apply_output(source.workspace, outcome,
                    prefix=".barragan-append-first-apply-failure")
            except (OSError, ValueError, TypeError, AttributeError):
                pass  # Diagnostics never authorize replay or change the journal.
        if (stage != "result" or outcome.started != started
                or outcome.returncode != 0 or outcome.stdout_truncated
                or outcome.stderr_truncated):
            raise MixedAppendFirstApplyAttention("mixed append first result uncertain")
        mark_provider_keyed_applied(source.workspace)
        append("mixed append first phase applied", {
            "commandResultSequence": len(current.events),
        })
        append("mixed append first awaiting exact poststate proof", {
            "commandResultSequence": len(current.events) - 1,
        })
        return current
