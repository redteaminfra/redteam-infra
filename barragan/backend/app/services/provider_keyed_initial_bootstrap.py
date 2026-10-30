# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant, single-attempt DevTest bootstrap of two projected Sketch chains.

The preparation phase is deliberately non-reclaimable. An expired claim after
preparation or host contact requires manual read-only reconciliation, because
Ansible or SSH descendants and staged private keys may still exist.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping
from uuid import uuid4

from app.services.bootstrap_command_evidence import bootstrap_command_timing
from app.domain import JobEvent
from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentStillSettling, reconcile_digitalocean_initial_attachment,
)
from app.services.provider_keyed_host_binding import (
    _INTENT_MESSAGE, _core_known_hosts, _digest_json, _manifest,
)
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_gated_runner import (
    CommandResult, UnreapedGatedCommandError, run_gated_command,
)
from app.services.provider_keyed_initial_continuation import ACTION, CORE_ACTION, _job_ids, _same_parent
from app.services.provider_keyed_postapply_preflight import preflight_applied_digitalocean_provider
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_bootstrap_apply import (
    SketchBootstrapApplyError, SketchBootstrapApplyResult, SketchBootstrapKeyCleanupUnprovedError,
    SketchBootstrapTimeoutError, BOOTSTRAP_COMMAND_TIMEOUT_SECONDS, BOOTSTRAP_TIMEOUT_MESSAGE,
    apply_sketch_bootstrap, require_pinned_sketch_ansible_source,
)
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_OWNER = f"provider-keyed-bootstrap-{uuid4().hex}"
_CLAIM_SECONDS = 3600


class ProviderKeyedInitialBootstrapError(ValueError):
    """Reviewed bootstrap cannot safely start or advance."""


def bootstrap_initial_digitalocean_chains(
    parent_id: str,
    *,
    environment: str,
    state_root: Path,
    job_repository: JobRepository | None = None,
    plan_repository=None,
    engagement_repository=None,
    sketch_repository=None,
    credential_repository=None,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    postapply_preflight: Callable = preflight_applied_digitalocean_provider,
    attachment_intent_builder: Callable = derive_digitalocean_initial_attachment_intent,
    attachment_reconciler: Callable = reconcile_digitalocean_initial_attachment,
    chain_projector: Callable = project_digitalocean_initial_chains,
    bootstrap_helper: Callable = apply_sketch_bootstrap,
    gated_command_runner: Callable = run_gated_command,
    bootstrap_env: Mapping[str, str] | None = None,
    source_verifier: Callable = require_pinned_sketch_ansible_source,
) -> StoredJobRun:
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains_repo = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    values = parent.input if parent is not None and isinstance(parent.input, dict) else {}
    engagement_id, core_id, plan_id = (values.get(key) for key in ("engagementId", "coreJobId", "corePlanId"))
    if (environment != "devtest" or parent is None or parent.id != parent_id
            or any(not isinstance(value, str) or not value for value in (engagement_id, core_id, plan_id))):
        raise ProviderKeyedInitialBootstrapError("DevTest bootstrap parent is unavailable")
    core = jobs.get(core_id)
    plan = plans.get(plan_id)
    expected_parent, plan_child, apply_child = _job_ids(core_id)
    if (core is None or core.action != CORE_ACTION or core.status != "succeeded"
            or core.input.get("sketchStateSchema") != "provider-keyed-v2"
            or core.input.get("corePlanId") != plan_id or core.input.get("engagementId") != engagement_id
            or plan is None or plan.id != plan_id or plan.engagement_id != engagement_id
            or plan.status != "applied" or plan.apply_job_id != core_id
            or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or parent_id != expected_parent or not _same_parent(
                parent, core, engagement_id, plan_id, plan_child, apply_child)
            or parent.status != "running" or not parent.started_at or parent.finished_at is not None
            or values.get("phase") != "host_identity_bound"
            or lookup(engagement_id) != (plan_id, ACTION)):
        raise ProviderKeyedInitialBootstrapError("reviewed bootstrap parent or core lease differs")
    token = uuid4().hex
    now = _now()
    current = jobs.claim_lease(
        parent_id, owner=_OWNER, token=token, claimed_at=now,
        expires_at=_later(now), eligible_statuses={"running"},
        eligible_phases={"host_identity_bound"},
    )
    if current is None or current.input.get("phase") != "host_identity_bound":
        raise ProviderKeyedInitialBootstrapError("bootstrap claim is unavailable")
    prepared = False
    try:
        _lease(lookup, engagement_id, plan_id)
        reviewed = postapply_preflight(
            engagement_id, core_id, lease_owner=plan_id, environment=environment,
            state_root=state_root, lease_lookup=lookup, job_repository=jobs,
            plan_repository=plans, engagement_repository=engagement_repository,
            sketch_repository=chains_repo, credential_repository=credentials,
        )
        if not isinstance(reviewed, tuple) or len(reviewed) != 4:
            raise ValueError("retained applied evidence is incomplete")
        attachment = attachment_intent_builder(*reviewed)
        proof = attachment_reconciler(
            reviewed[1], attachment, environment=environment,
            deployment_target="barragan-testing", credential_repository=credentials,
            max_attempts=12, poll_interval_seconds=10.0,
        )
        durable = chains_repo.list_for_engagement(engagement_id)
        current_chains = [chain for chain in durable if not _inert_aborted_intent(chain, engagement_id)]
        projections = chain_projector(reviewed[0], attachment, proof, current_chains)
        if len(projections) != 2:
            raise ValueError("complete two-chain bootstrap projection is required")
        manifest = _manifest(core, reviewed, attachment, projections, _core_known_hosts(core))
        intended = [event for event in current.events if event.message == _INTENT_MESSAGE]
        bound = [event for event in current.events if event.message == "provider host identity bound"]
        if (len(intended) != 1 or intended[0].data != manifest
                or len(bound) != 1 or bound[0].data != {
                    "manifestSha256": _digest_json(manifest), "hostProofPending": True,
                }):
            raise ValueError("retained host identity binding differs")
        workspace = reviewed[1]
        if (workspace.source_revision != manifest["sourceRevision"]
                or not isinstance(bootstrap_env, Mapping)
                or not isinstance(bootstrap_env.get(TEMPLATE_ROOT_ENV), str)):
            raise ValueError("pinned bootstrap source input is unavailable")
        source_root = Path(bootstrap_env[TEMPLATE_ROOT_ENV])
        source_verifier(
            env=bootstrap_env, required_source_root=source_root,
            required_source_revision=workspace.source_revision,
        )
        sketch_hosts = workspace.path / ".barragan-sketch-known-hosts"
        if manifest["sketchKnownHostsPath"] != str(sketch_hosts):
            raise ValueError("sketch known-hosts path differs")
        sketch_snapshot = _sketch_file_snapshot(sketch_hosts, empty=True)
        core_hosts = Path(manifest["coreKnownHostsPath"])
        chain_ids = [item.chain.chain_id for item in projections]
        if chain_ids != [row["chainId"] for row in manifest["chainFingerprints"]]:
            raise ValueError("ordered chain set differs from binding")
        scratch = [workspace.path / f".barragan-sketch-bootstrap-{uuid4().hex}" for _ in chain_ids]
        if (len(set(scratch)) != 2 or any(path.exists() or path.is_symlink() or path.parent != workspace.path
                                         for path in scratch)):
            raise ValueError("bootstrap scratch workspace is unavailable")
        _lease(lookup, engagement_id, plan_id)
        current = _save(jobs, current, token, "bootstrap_preparing", "provider bootstrap preparation fenced",
                        {"manifestSha256": _digest_json(manifest), "chainIds": chain_ids,
                         "scratchPaths": [str(path) for path in scratch]})
        prepared = True
        # From here no phase is reclaimable, including after claim expiry.
        for item, scratch_path in zip(projections, scratch):
            chain_id = item.chain.chain_id
            contacted = False
            root_started = False
            command_sequence = 0
            phase_attempts: dict[str, int] = {}

            def fence() -> None:
                nonlocal current
                _lease(lookup, engagement_id, plan_id)
                heartbeat = _now()
                renewed = jobs.renew_lease(
                    current.id, owner=_OWNER, token=token,
                    heartbeat_at=heartbeat, expires_at=_later(heartbeat),
                )
                if (renewed is None or renewed.input.get("claimToken") != token
                        or renewed.input.get("phase") != current.input.get("phase")):
                    raise ProviderKeyedInitialBootstrapError("bootstrap claim was lost")
                current = renewed

            def reporter(status: str, data: dict[str, object]) -> None:
                nonlocal current, contacted, root_started
                # The helper invokes this synchronously before each command
                # boundary. Even callbacks that add no audit event must fence
                # the active core plan and parent worker before it continues.
                fence()
                phase = data.get("phase") if isinstance(data, dict) else None
                if status == "checking" and phase == "root-management-readiness" and not contacted:
                    current = _save(jobs, current, token, "bootstrap_contacted",
                                    "provider bootstrap first host contact fenced", {"chainId": chain_id})
                    contacted = True
                elif status == "starting" and phase == "upstream-root-bootstrap":
                    if not contacted or root_started:
                        raise ProviderKeyedInitialBootstrapError("upstream root bootstrap may start only once")
                    current = _save(jobs, current, token, "bootstrap_root_started",
                                    "provider upstream root bootstrap start fenced", {"chainId": chain_id})
                    root_started = True

            def command_runner(command: list[str], cwd: Path | None,
                               command_env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
                nonlocal current, command_sequence
                if cwd != scratch_path:
                    raise ProviderKeyedInitialBootstrapError("bootstrap command scratch path differs")
                names = [str(part) for part in command]
                if any(name.endswith("wait_for_sketch_readiness.yml") for name in names):
                    phase = "root_management_readiness"
                    if not contacted:
                        raise ProviderKeyedInitialBootstrapError("bootstrap first contact is not fenced")
                elif any(name.endswith("upstream-sketch-playbook.compat.yml") for name in names):
                    phase = "upstream_root_bootstrap"
                    if not root_started:
                        raise ProviderKeyedInitialBootstrapError("bootstrap root start is not fenced")
                elif any(name.endswith("wait_for_sketch_user_readiness.yml") for name in names):
                    phase = "user_readiness"
                elif any(name.endswith("install_sketch_transport.yml") for name in names):
                    phase = "transport_install"
                else:
                    raise ProviderKeyedInitialBootstrapError("bootstrap command phase is unknown")
                if phase in ("user_readiness", "transport_install") and not root_started:
                    raise ProviderKeyedInitialBootstrapError("bootstrap root completion is not fenced")
                command_sequence += 1
                phase_attempts[phase] = phase_attempts.get(phase, 0) + 1
                fields = {"chainId": chain_id, "phase": phase,
                          "sequence": command_sequence, "attempt": phase_attempts[phase]}
                recorded_intent = None
                recorded_start = None
                recorded_result = None

                def save_event(message: str, data: dict[str, object]) -> None:
                    nonlocal current
                    fence()
                    current = _save(jobs, current, token, current.input["phase"], message,
                                    {**fields, **data})

                def on_intent(intent) -> None:
                    nonlocal recorded_intent
                    if recorded_intent is not None:
                        raise ProviderKeyedInitialBootstrapError("bootstrap command intent is duplicated")
                    if intent.scratch_path != str(scratch_path):
                        raise ProviderKeyedInitialBootstrapError("bootstrap command intent path differs")
                    save_event("provider bootstrap command intent fenced", {
                        "invocationId": intent.invocation_id, "scratchPath": intent.scratch_path,
                        "argvSha256": intent.argv_sha256,
                    })
                    recorded_intent = intent

                def on_started(started) -> None:
                    nonlocal recorded_start
                    if recorded_intent is None or recorded_start is not None or started.intent != recorded_intent:
                        raise ProviderKeyedInitialBootstrapError("bootstrap command start differs from intent")
                    identity = started.identity
                    save_event("provider bootstrap command started before GO", {
                        "invocationId": started.intent.invocation_id,
                        "bootId": identity.boot_id, "pid": identity.pid,
                        "pgid": identity.pgid, "startTicks": identity.start_ticks,
                    })
                    recorded_start = started

                def on_heartbeat(started) -> None:
                    if recorded_start is None or started != recorded_start or recorded_result is not None:
                        raise ProviderKeyedInitialBootstrapError("bootstrap command heartbeat differs from start")
                    fence()

                def on_result(outcome) -> None:
                    nonlocal recorded_result
                    if (recorded_start is None or recorded_result is not None
                            or outcome.started != recorded_start):
                        raise ProviderKeyedInitialBootstrapError("bootstrap command result differs from start")
                    save_event("provider bootstrap command result fenced", {
                        "invocationId": outcome.started.intent.invocation_id,
                        "returnCode": outcome.returncode,
                        "stdoutBytes": outcome.stdout_bytes, "stderrBytes": outcome.stderr_bytes,
                        "stdoutTruncated": outcome.stdout_truncated,
                        "stderrTruncated": outcome.stderr_truncated, **bootstrap_command_timing(outcome),
                    })
                    recorded_result = outcome

                outcome = gated_command_runner(
                    command, execution_timeout_seconds=BOOTSTRAP_COMMAND_TIMEOUT_SECONDS, scratch_path=scratch_path,
                    intent_callback=on_intent, started_callback=on_started,
                    heartbeat_callback=on_heartbeat, result_callback=on_result,
                    provider_keyed_v2=True, env=dict(command_env),
                )
                if (not isinstance(outcome, CommandResult)
                        or recorded_intent is None or recorded_start is None or recorded_result is None
                        or outcome.started != recorded_start
                        or recorded_result.timed_out is not False
                        or outcome.returncode != recorded_result.returncode
                        or outcome.stdout_truncated != recorded_result.stdout_truncated
                        or outcome.stderr_truncated != recorded_result.stderr_truncated):
                    raise ProviderKeyedInitialBootstrapError("gated command result is incomplete")
                return subprocess.CompletedProcess(command, outcome.returncode,
                                                   outcome.stdout, outcome.stderr)

            _lease(lookup, engagement_id, plan_id)
            source_verifier(
                env=bootstrap_env, required_source_root=source_root,
                required_source_revision=workspace.source_revision,
            )
            if (_core_known_hosts(core) != (str(core_hosts), manifest["coreKnownHostsSha256"])
                    or _sketch_file_snapshot(sketch_hosts) != sketch_snapshot
                    or chains_repo.list_for_engagement(engagement_id) != durable
                    or scratch_path.exists() or scratch_path.is_symlink()):
                raise ValueError("bootstrap identity changed before host contact")
            result = bootstrap_helper(
                engagement_id, item.chain, repository=jobs, env=bootstrap_env,
                workspace_root=scratch_path, host_policies=item.host_policies,
                proxy_egress_ip=item.proxy_egress_ip,
                initial_sketch_known_hosts_path=sketch_hosts,
                pinned_core_known_hosts_path=core_hosts,
                progress_reporter=reporter,
                runner=command_runner,
                required_source_root=source_root,
                required_source_revision=workspace.source_revision,
            )
            if (not contacted or not root_started or not isinstance(result, SketchBootstrapApplyResult)
                    or result.root_returncode != 0 or result.user_readiness_returncode != 0
                    or result.transport_returncode != 0 or result.node_count != len(item.chain.nodes)):
                raise ValueError("bootstrap helper completion is incomplete")
            _clean_scratch_result(scratch_path)
            _lease(lookup, engagement_id, plan_id)
            new_sketch_snapshot = _sketch_file_snapshot(sketch_hosts)
            if (_core_known_hosts(core) != (str(core_hosts), manifest["coreKnownHostsSha256"])
                    or new_sketch_snapshot[:2] != sketch_snapshot[:2]
                    or chains_repo.list_for_engagement(engagement_id) != durable):
                raise ValueError("bootstrap identity changed after host contact")
            sketch_snapshot = new_sketch_snapshot
            current = _save(jobs, current, token, "bootstrap_chain_completed",
                            "provider chain bootstrap completed; host proof pending",
                            {"chainId": chain_id, "nodeCount": result.node_count,
                             "rootReturnCode": 0, "userReadinessReturnCode": 0,
                             "transportReturnCode": 0})
        _lease(lookup, engagement_id, plan_id)
        return _save(jobs, current, token, "awaiting_strict_host_proof",
                     "provider bootstrap completed; strict host proof pending",
                     {"manifestSha256": _digest_json(manifest), "chainIds": chain_ids,
                      "hostProofPending": True}, release=True)
    except DigitalOceanAttachmentStillSettling:
        if prepared:
            return _attention(jobs, current, token)
        return _save(jobs, current, token, "host_identity_bound",
                     "provider attachment still settling; bootstrap pending",
                     {"attachmentProofPending": True, "hostProofPending": True}, release=True)
    except SketchBootstrapTimeoutError:
        return _attention(jobs, current, token, message=BOOTSTRAP_TIMEOUT_MESSAGE,
                          data={"timedOut": True, "bootstrap": "reconciliation_required"})
    except SketchBootstrapKeyCleanupUnprovedError:
        return _attention(jobs, current, token,
                          message="provider bootstrap key cleanup unproved; manual read-only reconciliation required")
    except UnreapedGatedCommandError:
        return _attention(jobs, current, token,
                          message="provider bootstrap process-group quiescence unproved; staged keys retained",
                          data={"bootstrap": "reconciliation_required", "localQuiescenceUnproved": True})
    except SketchBootstrapApplyError as exc:
        # The helper's command-failure diagnostic is already bounded and
        # redacted. Keep it on the durable job instead of replacing the only
        # actionable Ansible task evidence with a generic attention message.
        detail = str(exc)
        safe_prefixes = (
            "sketch root management readiness failed (exit ",
            "upstream sketch bootstrap failed (exit ",
            "post-root sketch user readiness failed (exit ",
            "sketch transport key installation failed (exit ",
        )
        if detail.startswith(safe_prefixes):
            return _attention(
                jobs, current, token,
                message=("provider bootstrap stopped; manual read-only reconciliation required; "
                         f"{detail[:240]}"),
                data={"failureDetail": detail},
            )
        return _attention(jobs, current, token)
    except Exception:
        return _attention(jobs, current, token)


def _sketch_file_snapshot(path: Path, *, empty: bool = False) -> tuple[int, int, str]:
    parent = path.parent
    if parent.is_symlink() or parent.resolve(strict=True) != parent:
        raise ValueError("sketch known-hosts directory differs")
    directory = parent.stat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid not in (os.getuid(), 0) or directory.st_mode & 0o022:
        raise ValueError("sketch known-hosts directory is unsafe")
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError("sketch known-hosts path differs")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1
                or st.st_mode & 0o077 or (empty and st.st_size != 0)):
            raise ValueError("sketch known-hosts file is unsafe")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 65536):
            digest.update(chunk)
        return st.st_dev, st.st_ino, digest.hexdigest()
    finally:
        os.close(fd)


def _clean_scratch_result(path: Path) -> None:
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError("bootstrap scratch path differs")
    st = path.stat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or st.st_mode & 0o077 or (path / "keys").exists() or (path / "keys").is_symlink()):
        raise ValueError("bootstrap scratch private key cleanup is unproved")


def _save(jobs, parent, token, phase, message, data, *, release=False, failed=False):
    now = _now()
    renewed = jobs.renew_lease(parent.id, owner=_OWNER, token=token,
                               heartbeat_at=now, expires_at=_later(now))
    if renewed is None or renewed.input.get("claimToken") != token:
        raise ProviderKeyedInitialBootstrapError("bootstrap claim was lost")
    updated = replace(
        renewed, status="failed" if failed else "running", finished_at=now if failed else None,
        input={**renewed.input, "phase": phase,
               "claimExpiresAt": now if release else _later(now)},
        events=[*renewed.events, JobEvent(len(renewed.events) + 1,
            "error" if failed else "info", message, data)],
    )
    stored = jobs.save_if_leased(updated, owner=_OWNER, token=token)
    if stored is None or stored.input.get("phase") != phase:
        raise ProviderKeyedInitialBootstrapError("bootstrap claim was lost")
    return stored


def _attention(jobs, parent, token, *, message="provider bootstrap stopped; manual read-only reconciliation required",
               data=None):
    try:
        return _save(jobs, parent, token, "attention", message, data or {}, failed=True)
    except Exception:
        raise ProviderKeyedInitialBootstrapError(
            "provider bootstrap stopped; manual read-only reconciliation required",
        ) from None


def _lease(lookup, engagement_id, plan_id):
    if lookup(engagement_id) != (plan_id, ACTION):
        raise ValueError("core plan lease changed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(now: str) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=_CLAIM_SECONDS)).isoformat()
