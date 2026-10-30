# Copyright (c) 2026, Oracle and/or its affiliates.
"""Explicit one-shot DevTest continuation of the reviewed interrupted DO child.

There is no route or automatic dispatcher for this incident operation. The
historical before-GO outcome is operator-attested; every present-day authority
and cloud fact is checked again while the new command is blocked at its gate.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, StartedCommand, run_gated_command,
)
from app.services.provider_keyed_initial_destroy_apply import _require_empty_retained_state
from app.services.provider_keyed_initial_destroy_pre_go_recovery import (
    HistoricalRuntimeAttestation, _INCIDENT_GATE_TIMEOUT,
    _ORIGINAL_INCIDENT, _reviewed_incident, bind_reviewed_digitalocean_destroy_pre_go,
)
from app.services.provider_keyed_initial_teardown import (
    DigitalOceanTeardownIntent, _require_exact_state,
    require_exact_digitalocean_destroy_plan,
)
from app.services.provider_keyed_postapply_preflight import read_applied_digitalocean_provider_for_teardown
from app.services.provider_keyed_saved_plan_runner import (
    _ENV_ALLOWLIST, _hash_file, _ordinal_lock, _require_plan_topology_variables,
)
from app.services.provider_keyed_sketch import _write_json
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest


_PARENT = "job-engagement-teardown-db19aa91df17"
_CHILD = "job-provider-keyed-initial-destroy-apply-db19aa91df17"
_CORE = "job-db19aa91df17"
_ENGAGEMENT = "eng-09c806850ec5"
_REVISION = "bc3a6990f86dcca99381e1659ec337493ddf5275"
_ORIGINAL_JOURNAL = "4a9014cec817e4bc3cc09cd954801ebdf9e91496080d21bc3094f5bc4074f4b8"
_SUFFIX = (
    "provider destroy pre-GO recovery intended",
    "provider destroy command intent fenced",
    "provider destroy command started before GO",
    "provider destroy command result fenced",
    "provider destroy command intent fenced",
    "provider destroy command started before GO",
    "provider destroy command result fenced",
    "provider destroy phase write intended",
    "provider destroy apply completed; absence proof pending",
)


class DigitalOceanPreGoContinuationError(ValueError):
    """The incident continuation stopped; retained child requires attention."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(now: str) -> str:
    # Fresh cloud GET and Inspector proof are deliberately serial. The exact
    # incident cannot be retaken after event 10, so allow bounded provider
    # latency without treating a slow read as an uncertain destroy.
    return (datetime.fromisoformat(now) + timedelta(minutes=15)).isoformat()


def _digest_argv(argv: list[str]) -> str:
    return hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()


def _original_digest(incident) -> str:
    # Keep the original incident's established test seam and deployed pin.
    return _ORIGINAL_JOURNAL if incident == _ORIGINAL_INCIDENT else incident.original_journal_sha256


def _check_prefix(original, current, *, plan_sha: str, incident=None) -> None:
    """Never interpret another run's suffix as authority for a second apply."""
    incident = incident or _ORIGINAL_INCIDENT
    if (original.id != incident.child_id or len(original.events) != 9
            or job_event_digest(original.events) != _original_digest(incident)
            or current.id != original.id or current.status != "running"
            or current.events[:9] != original.events or len(current.events) not in {9, 10, 12, 13, 15}
            or [row.sequence for row in current.events] != list(range(1, len(current.events) + 1))
            or [row.message for row in current.events[9:]] != list(_SUFFIX[:len(current.events) - 9])
            or (current != original and not current.input.get("claimOwner", "").startswith(
                "provider-keyed-destroy-recovery-"))
            or current.input.get("planSha256") != plan_sha):
        raise ValueError("incident recovery journal changed")
    if len(current.events) >= 10 and current.events[9].data != {
            "historicalRevision": incident.revision,
            "originalJournalSha256": _original_digest(incident),
            "planSha256": plan_sha}:
        raise ValueError("incident recovery intent changed")
    if len(current.events) >= 13:
        show = current.events[10:13]
        if (any(row.data.get("phase") != "show" for row in show)
                or show[0].data.get("invocationId") != show[1].data.get("invocationId")
                or show[0].data.get("invocationId") != show[2].data.get("invocationId")
                or show[2].data.get("returnCode") != 0
                or show[2].data.get("stdoutTruncated") is not False
                or show[2].data.get("stderrTruncated") is not False):
            raise ValueError("recovery show journal differs")
    if len(current.events) == 15:
        apply = current.events[13:15]
        if (apply[0].data.get("phase") != "apply"
                or apply[1].data.get("phase") != "apply"
                or apply[0].data.get("invocationId") != apply[1].data.get("invocationId")
                or apply[0].data.get("invocationId") in {
                    original.events[2].data["invocationId"],
                    original.events[7].data["invocationId"],
                    current.events[10].data["invocationId"],
                }):
            raise ValueError("recovery apply journal differs")


def continue_reviewed_digitalocean_destroy_pre_go(
    attestation: HistoricalRuntimeAttestation, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, credential_repository=None,
    engagement_repository=None, sketch_repository=None, lease_lookup=None,
    transport=None, command_environment=None,
    gated_command_runner: Callable = run_gated_command,
    binder: Callable = bind_reviewed_digitalocean_destroy_pre_go,
):
    """Take over one expired claim, re-show one saved plan, apply it at most once.

    A crash or uncertain outcome after the new apply GO is never resumed by
    this function: its journal has more than nine events and cannot be retaken.
    """
    if environment != "devtest" or state_root != _default_state_root() or os.geteuid() == 0:
        raise DigitalOceanPreGoContinuationError("DevTest incident scope is required")
    try:
        incident = _reviewed_incident(attestation.parent_id)
    except (AttributeError, ValueError):
        raise DigitalOceanPreGoContinuationError("DevTest incident scope is required") from None
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    bind_args = dict(environment=environment, state_root=state_root, job_repository=jobs,
                     plan_repository=plans, credential_repository=credentials,
                     engagement_repository=engagement_repository,
                     sketch_repository=sketch_repository, lease_lookup=lease_lookup,
                     transport=transport)
    original = jobs.get(incident.child_id)
    try:
        first = binder(attestation, **bind_args)
        if (original is None or first.parent_id != incident.parent_id
                or first.child_id != incident.child_id
                or first.child_journal_sha256 != _original_digest(incident)):
            raise ValueError("incident source differs")
        _check_prefix(original, original, plan_sha=first.plan_sha256, incident=incident)
        parent = jobs.get(incident.parent_id)
        scope = parent.input["scopeSnapshot"]["providerScopes"][0]
        workspace_path = Path(scope["workspace"])
        # The same writer lock and ordering as normal full-state apply.
        lock_path = workspace_path / ".barragan-initial-full-plan.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("destroy workspace lock differs")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                return _continue_locked(
                    attestation, original, first, parent, bind_args, jobs, plans,
                    credentials, gated_command_runner, command_environment, binder,
                    incident,
                )
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise DigitalOceanPreGoContinuationError(
            "reviewed incident continuation stopped; inspect retained journal, phase and state"
        ) from None


def _continue_locked(attestation, original, first, parent, bind_args, jobs, plans,
                     credentials, gated_command_runner, command_environment, binder,
                     incident=_ORIGINAL_INCIDENT):
    environment, state_root = bind_args["environment"], bind_args["state_root"]
    second = binder(attestation, **bind_args)
    if second != first or jobs.get(incident.child_id) != original:
        raise ValueError("incident source changed before claim")
    intent, workspace, _evidence, _apply_job = read_applied_digitalocean_provider_for_teardown(
        incident.engagement_id, incident.core_id, environment=environment, state_root=state_root,
        mode="destroy_started_read", allowed_teardown_parent_id=incident.parent_id,
        incident_destroy_child_id=incident.child_id,
        engagement_repository=bind_args["engagement_repository"],
        sketch_repository=bind_args["sketch_repository"],
        job_repository=jobs, plan_repository=plans, credential_repository=credentials,
    )
    with _ordinal_lock(workspace):
        return _run_claimed(attestation, original, first, parent, bind_args, jobs,
                            credentials, workspace, intent, gated_command_runner,
                            command_environment, binder, incident)


def _run_claimed(attestation, original, first, parent, bind_args, jobs, credentials,
                 workspace, intent, gated_command_runner, command_environment, binder,
                 incident=_ORIGINAL_INCIDENT):
    env_source = os.environ if command_environment is None else command_environment
    if any(key.upper().startswith("TF_") for key in env_source):
        raise ValueError("caller Terraform environment is unreviewed")
    env = {key: value for key, value in env_source.items() if key in _ENV_ALLOWLIST}
    env["TF_DATA_DIR"] = str(workspace.terraform_data_dir)
    env["TF_CLI_CONFIG_FILE"] = "/dev/null"
    pre = original.events[5].data
    teardown_intent = DigitalOceanTeardownIntent(
        intent.nodes, intent.firewall, pre["resourceIds"], pre["preDestroyStateSha256"],
        pre["credentialRecordId"], pre["credentialSecretSha256"], pre["credentialUpdatedAt"],
    )
    before = _require_exact_state(workspace, teardown_intent)
    preview = jobs.get(original.input["destroyPlanJobId"])
    saved = preview.events[-1].data
    binary, plan_path = saved["terraformBinaryPath"], Path(saved["planPath"])
    show_argv = [binary, "show", "-json", str(plan_path)]
    apply_argv = [binary, "apply", "-input=false", "-lock=true", "-no-color", str(plan_path)]
    if (_hash_file(Path(binary)) != saved["terraformBinarySha256"]
            or _hash_file(plan_path) != first.plan_sha256
            or _hash_file(workspace.state_path) != first.state_sha256
            or original.events[2].data["argvSha256"] != _digest_argv(show_argv)
            or original.events[7].data["argvSha256"] != _digest_argv(apply_argv)):
        raise ValueError("reviewed saved command differs before claim")
    started = _now()
    owner, token = f"provider-keyed-destroy-recovery-{uuid4().hex}", uuid4().hex
    current = jobs.take_over_initial_destroy_apply_pre_go(
        original, expected_event_digest=_original_digest(incident),
        owner=owner, token=token,
        claimed_at=started, expires_at=_later(started),
    )
    if current is None or current.events != original.events:
        raise ValueError("incident CAS takeover lost")

    def authority() -> None:
        observed = jobs.get(incident.child_id)
        expiry = datetime.fromisoformat(current.input["claimExpiresAt"])
        if (observed != current or current.status != "running"
                or current.input.get("claimOwner") != owner
                or current.input.get("claimToken") != token
                or datetime.now(timezone.utc) >= expiry
                or jobs.get(incident.parent_id) != parent):
            raise ValueError("incident recovery claim changed")

    def renew(expected=None):
        nonlocal current
        authority()
        if expected is not None and expected != current:
            raise ValueError("incident recovery fence changed")
        now = _now()
        updated = jobs.renew_lease(incident.child_id, owner=owner, token=token,
                                   heartbeat_at=now, expires_at=_later(now))
        if updated is None or updated.events != current.events:
            raise ValueError("incident recovery lease renewal lost")
        current = updated
        return updated

    def rebind(gated_started=None, gated_argv=None) -> None:
        authority()
        _check_prefix(original, current, plan_sha=first.plan_sha256, incident=incident)
        rebound = binder(
            attestation, **bind_args, original_child=original,
            claimed_child=current, claim_fence=renew,
            gated_started=gated_started, gated_argv=gated_argv,
        )
        if rebound != first:
            raise ValueError("incident recovery boundary changed")
        authority()

    def append(message: str, data: dict) -> None:
        nonlocal current
        authority()
        now = _now()
        updated = jobs.append_destroy_apply_event_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            heartbeat_at=now, expires_at=_later(now),
            event=JobEvent(len(current.events) + 1, "info", message, data),
        )
        if updated is None:
            raise ValueError("incident recovery journal CAS lost")
        current = updated

    rebind()
    append(_SUFFIX[0], {"historicalRevision": incident.revision,
                        "originalJournalSha256": _original_digest(incident),
                        "planSha256": first.plan_sha256})
    def command(phase: str, argv: list[str]):
        invocation = None
        started_command = None

        def on_intent(value: CommandIntent):
            nonlocal invocation
            authority()
            if (value.scratch_path != str(workspace.path)
                    or value.argv_sha256 != _digest_argv(argv)
                    or value.invocation_id in {
                        original.events[2].data["invocationId"],
                        original.events[7].data["invocationId"],
                    }):
                raise ValueError("recovery command intent differs")
            append(_SUFFIX[1], {"phase": phase, "invocationId": value.invocation_id,
                                "argvSha256": value.argv_sha256})
            invocation = value

        def on_start(value: StartedCommand):
            nonlocal started_command
            deadline = time.monotonic() + 15 * 60
            if value.intent != invocation:
                raise ValueError("recovery gated identity differs")
            append(_SUFFIX[2], {"phase": phase, "invocationId": value.intent.invocation_id,
                                "bootId": value.identity.boot_id, "pid": value.identity.pid,
                                "pgid": value.identity.pgid,
                                "startTicks": value.identity.start_ticks})
            started_command = value
            # This callback runs while the child is blocked on GO. A failed
            # check closes the pipe and aborts before Terraform can execute.
            rebind(gated_started=value, gated_argv=argv)
            if time.monotonic() >= deadline:
                raise ValueError("recovery GO proof exceeded its bounded window")
            if (_hash_file(plan_path) != first.plan_sha256
                    or _hash_file(workspace.state_path) != first.state_sha256
                    or _hash_file(Path(binary)) != saved["terraformBinarySha256"]):
                raise ValueError("saved command input changed at GO")

        def on_heartbeat(value: StartedCommand):
            if value != started_command:
                raise ValueError("recovery command heartbeat differs")
            renew()

        def on_result(value: CommandAuditResult):
            if value.started != started_command:
                raise ValueError("recovery command result differs")
            append(_SUFFIX[3], {"phase": phase, "invocationId": invocation.invocation_id,
                                "returnCode": value.returncode,
                                "stdoutBytes": value.stdout_bytes,
                                "stderrBytes": value.stderr_bytes,
                                "stdoutTruncated": value.stdout_truncated,
                                "stderrTruncated": value.stderr_truncated})

        outcome = gated_command_runner(
            argv, scratch_path=workspace.path, provider_keyed_v2=True,
            gate_timeout_seconds=_INCIDENT_GATE_TIMEOUT,
            max_output_bytes=16 * 1024 * 1024 if phase == "show" else 65536,
            env=env, intent_callback=on_intent, started_callback=on_start,
            heartbeat_callback=on_heartbeat, result_callback=on_result,
        )
        if (outcome.started != started_command or outcome.returncode != 0
                or outcome.stdout_truncated or outcome.stderr_truncated):
            raise ValueError("recovery command outcome unproved")
        return outcome

    shown = command("show", show_argv)
    require_exact_digitalocean_destroy_plan(
        shown.stdout, expected_resource_ids=teardown_intent.resource_ids, state=before,
    )
    _require_plan_topology_variables(shown.stdout, workspace)
    rebind()
    command("apply", apply_argv)
    state_sha = _require_empty_retained_state(workspace, before)
    phase_path = workspace.path / ".barragan-apply-phase.json"
    append(_SUFFIX[7], {"phase": "destroy_applied", "path": str(phase_path)})
    _write_json(phase_path, {"schema": "provider-keyed-v2", "phase": "destroy_applied"})
    authority()
    now = _now()
    terminal = jobs.finish_destroy_apply_if_running_claimed(
        current, owner=owner, token=token,
        expected_event_digest=job_event_digest(current.events),
        status="succeeded", finished_at=now,
        event=JobEvent(18, "info", _SUFFIX[8], {
            "stateSha256": state_sha, "providerAbsenceProofPending": True,
        }),
    )
    if terminal is None:
        raise ValueError("incident recovery terminal CAS lost")
    return terminal
