# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, one-shot DevTest apply of a saved exact OCI core destroy plan.

Terraform completion is not OCI absence proof. The retained OCID map and
running/terminal child are inputs to a separate read-only reconciliation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.domain import JobEvent
from app.integrations.oci_read_validation import resolve_oci_cli
from app.services.core_deployment_plans import require_keyed_core_terraform_source_manifest
from app.services.engagement_teardown import _fingerprint
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_comprehensive_teardown import _boundary, _child_id
from app.services.provider_keyed_comprehensive_teardown import recognize_provider_keyed_group_retired
from app.services.provider_keyed_core_destroy_preview import (
    ACTION as PREVIEW_ACTION, _EVENT, _exact_destroy, _read_regular,
    _state_data_ids, _terraform_quiescent,
)
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_oci_exact_absence import (
    OciExactWitness, _default_runner as _oci_runner,
    prove_oci_core_visibility,
)
from app.services.provider_keyed_pending_retirement import recognize_pending_keyed_group_retired
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


ACTION = "provider_keyed_core_destroy_apply"
_FENCE = "provider_keyed_teardown_fence"
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class KeyedCoreDestroyApplyAttention(ValueError):
    """Apply is unproved; never retry a recorded child automatically."""


def recover_pending_keyed_oci_core_destroy_pre_go(
    teardown_parent_id: str, *, recovery_child_id: str,
    reviewed_plan_sha256: str, **kwargs,
) -> StoredJobRun:
    """Explicit DevTest-only continuation of one reviewed show-only child."""
    return apply_pending_keyed_oci_core_destroy(
        teardown_parent_id, recovery_child_id=recovery_child_id,
        reviewed_plan_sha256=reviewed_plan_sha256, **kwargs,
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=60)).isoformat()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_identity(path: Path) -> tuple[int, int, str]:
    raw = _read_regular(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError("reviewed file is not regular")
    return info.st_dev, info.st_ino, _sha(raw)


def apply_pending_keyed_oci_core_destroy(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, lease_lookup=None,
    retired_recognizer: Callable = recognize_pending_keyed_group_retired,
    release_check: Callable = require_devtest_terraform_release,
    source_check: Callable = require_keyed_core_terraform_source_manifest,
    gated_command_runner: Callable = run_gated_command,
    visibility_prover: Callable = prove_oci_core_visibility,
    oci_command_runner: Callable = _oci_runner,
    oci_executable: Path | None = None,
    recovery_child_id: str | None = None,
    reviewed_plan_sha256: str | None = None,
) -> StoredJobRun:
    """Apply one saved full core plan; leave provider absence pending."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("private DevTest boundary differs")

        def authority():
            parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
            published = "publishedSource" in parent.input
            if operation != _FENCE:
                raise ValueError("fenced source required")
            coordinator = jobs.get(_child_id(core.id))
            if (coordinator is None or coordinator.status != "running"
                    or coordinator.input.get("phase") != (
                        "group_retired" if published else "pending_group_retired")):
                raise ValueError("group retirement differs")
            # The published source has a sealed historical projection. An
            # injected pending recognizer cannot authorize this authority.
            recognizer = (recognize_provider_keyed_group_retired if published
                          else retired_recognizer)
            recognizer(parent.id, environment=environment, state_root=state_root,
                       job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            plan = plans.get(core.input["corePlanId"])
            evidence = plan.evidence
            if (plan.id != snapshot["providerScopes"][0]["corePlanId"]
                    or plan.apply_job_id != core.id or plan.status != "applied"
                    or plan.engagement_id != parent.target_id
                    or evidence.get("sketchStateSchema") != "provider-keyed-v2"
                    or core.input.get("corePlanEvidenceSha256") != _fingerprint(evidence)
                    or core.input.get("target") != evidence.get("target")
                    or evidence["target"].get("name") != "barragan-testing"
                    or core.input.get("proxyCount") != evidence.get("proxyCount")
                    or core.input.get("elkEnabled") != evidence.get("elkEnabled")
                    or core.input.get("sshSourceCidrs") != evidence.get("sshSourceCidrs")):
                raise ValueError("reviewed core job or plan differs")
            seals = [event for event in core.events if event.message == _EVENT]
            if (len(seals) != 1 or seals[0].level != "info"
                    or core.events[-2] != seals[0]
                    or core.events[-1].message != "pilot Standard RTI run finished"):
                raise ValueError("applied core state seal differs")
            path = Path(evidence["terraformStatePath"])
            run_dir = Path(evidence["runDirectory"])
            data_dir = Path(evidence["terraformDataDir"])
            if (not path.is_absolute() or path.name != "terraform.tfstate"
                    or path.parent.name != "core"
                    or path.parents[2] != DEFAULT_TERRAFORM_STATE_ROOT
                    or path.parent.is_symlink()
                    or path.parent.resolve(strict=True) != path.parent
                    or DEFAULT_TERRAFORM_STATE_ROOT.is_symlink()
                    or not run_dir.is_absolute() or run_dir.is_symlink()
                    or run_dir.resolve(strict=True) != run_dir
                    or not data_dir.is_absolute() or data_dir.is_symlink()
                    or data_dir.resolve(strict=True) != data_dir
                    or data_dir.parent != path.parent
                    or not data_dir.name.startswith("data-core-")):
                raise ValueError("reviewed core workspace differs")
            source_check(run_dir, evidence["keyedCoreTerraformSourceManifest"])
            if _file_identity(run_dir / ".terraform.lock.hcl")[2] != evidence["providerLockFingerprint"]:
                raise ValueError("reviewed provider lock differs")
            public_key = Path(evidence["sshPublicKeyPath"])
            if (not public_key.is_absolute()
                    or _file_identity(public_key)[2] != evidence["publicKeyFingerprint"]):
                raise ValueError("reviewed public key differs")
            state_bytes = _read_regular(path)
            inventory = parse_applied_oci_core_state(
                state_bytes, proxy_count=evidence["proxyCount"],
                elk_enabled=evidence["elkEnabled"],
                compartment_id=evidence["target"]["compartmentId"],
                engagement_name=core.input["engagementName"],
            )
            if seals[0].data != {
                "schema": "applied-oci-core-state-v1",
                "corePlanEvidenceSha256": core.input["corePlanEvidenceSha256"],
                "rawStateSha256": inventory.raw_state_sha256,
                "inventorySha256": inventory.inventory_sha256,
                "lineage": inventory.lineage, "serial": inventory.serial,
                "resourceCount": len(inventory.resources),
            }:
                raise ValueError("reviewed pre-destroy state differs")
            release = release_check(environment=environment)
            if (release.version != evidence["terraformFingerprint"]
                    or not release.path.is_absolute() or not _HASH.fullmatch(release.sha256)):
                raise ValueError("reviewed Terraform release differs")
            preview_id = f"job-provider-keyed-core-destroy-preview-{core.id.removeprefix('job-')}"
            preview = jobs.get(preview_id)
            expected_input = {
                "teardownParentId": parent.id, "coreJobId": core.id,
                "corePlanId": plan.id, "scopeSnapshotId": snapshot["snapshotId"],
                "coordinatorJournalSha256": job_event_digest(coordinator.events),
                "stateSha256": inventory.raw_state_sha256,
                "inventorySha256": inventory.inventory_sha256,
            }
            if (preview is None or preview.action != PREVIEW_ACTION
                    or preview.status != "succeeded" or preview.input != expected_input
                    or preview.target_id != parent.target_id
                    or preview.requested_by != parent.requested_by
                    or preview.artifact_refs != [] or len(preview.events) != 3
                    or [(event.sequence, event.level, event.message) for event in preview.events]
                    != [(1, "info", "core destroy preview queued"),
                        (2, "info", "core destroy preview started"),
                        (3, "info", "core destroy preview saved")]
                    or preview.events[0].data != {} or preview.events[1].data != {}):
                raise ValueError("saved preview journal differs")
            receipt = preview.events[2].data
            plan_path = path.parent / f".barragan-core-destroy-{core.id.removeprefix('job-')}.tfplan"
            if (type(receipt) is not dict or set(receipt) != {
                    "planPath", "planSha256", "planDevice", "planInode",
                    "stateSha256", "inventorySha256", "resourceCount",
                    "terraformBinarySha256", "sourceManifestSha256"}
                    or receipt["planPath"] != str(plan_path)
                    or receipt["stateSha256"] != inventory.raw_state_sha256
                    or receipt["inventorySha256"] != inventory.inventory_sha256
                    or receipt["resourceCount"] != len(inventory.resources)
                    or receipt["terraformBinarySha256"] != release.sha256
                    or receipt["sourceManifestSha256"] != _fingerprint(
                        evidence["keyedCoreTerraformSourceManifest"])
                    or type(receipt["planDevice"]) is not int
                    or type(receipt["planInode"]) is not int
                    or (receipt["planDevice"], receipt["planInode"], receipt["planSha256"])
                    != _file_identity(plan_path)):
                raise ValueError("saved core plan identity differs")
            return (parent, core, snapshot, coordinator, plan, preview, inventory,
                    state_bytes, path, run_dir, data_dir, release, plan_path, receipt)

        initial = authority()
        parent, core, snapshot, coordinator, plan, preview, inventory = initial[:7]
        state_bytes, state_path, run_dir, data_dir, release, plan_path, receipt = initial[7:]
        child_id = f"job-provider-keyed-core-destroy-apply-{core.id.removeprefix('job-')}"
        base_input = {
            "teardownParentId": parent.id, "coreJobId": core.id,
            "corePlanId": plan.id, "scopeSnapshotId": snapshot["snapshotId"],
            "coordinatorJournalSha256": job_event_digest(coordinator.events),
            "previewJobId": preview.id,
            "previewJournalSha256": job_event_digest(preview.events),
            "planSha256": receipt["planSha256"], "mutation": True,
        }
        owner = f"provider-keyed-core-destroy-{uuid4().hex}"
        token = uuid4().hex
        claimed_at = _now()
        recovering = recovery_child_id is not None or reviewed_plan_sha256 is not None
        if recovering:
            child = jobs.get(child_id)
            show_argv = [str(release.path), "show", "-json", str(plan_path)]
            show_digest = _sha(json.dumps(show_argv, separators=(",", ":")).encode())
            if (recovery_child_id != child_id or reviewed_plan_sha256 != receipt["planSha256"]
                    or child is None or child.action != ACTION or child.status != "running"
                    or child.target != f"engagement:{parent.target_id}"
                    or child.target_type != "engagement" or child.target_id != parent.target_id
                    or child.requested_by != parent.requested_by or child.artifact_refs != []
                    or child.started_at is None or child.finished_at is not None
                    or {key: value for key, value in child.input.items()
                        if key not in {"claimOwner", "claimToken", "claimClaimedAt",
                                       "claimExpiresAt", "claimHeartbeatAt"}} != base_input
                    or len(child.events) not in (5, 8)
                    or any(type(child.events[offset].data) is not dict
                           or child.events[offset].data.get("argvSha256") != show_digest
                           for offset in (2, 5) if offset < len(child.events))
                    or any(row.action == ACTION and row.input.get("coreJobId") == core.id
                           and row.id != child_id
                           for row in jobs.list_for_engagement(parent.target_id))
                    or not _terraform_quiescent()):
                raise ValueError("reviewed pre-GO core destroy child differs")
            current = jobs.take_over_core_destroy_apply_pre_go(
                child, expected_event_digest=job_event_digest(child.events),
                owner=owner, token=token, claimed_at=claimed_at,
                expires_at=_later(claimed_at),
            )
            if (current is None or jobs.get(child_id) != current
                    or not _terraform_quiescent()):
                raise ValueError("core destroy pre-GO takeover lost")
        else:
            if jobs.get(child_id) is not None or any(
                    row.action == ACTION and row.input.get("coreJobId") == core.id
                    for row in jobs.list_for_engagement(parent.target_id)):
                raise ValueError("core destroy apply child already exists")
            queued = StoredJobRun(
                id=child_id, action=ACTION, status="queued",
                target=f"engagement:{parent.target_id}", target_type="engagement",
                target_id=parent.target_id, requested_by=parent.requested_by,
                input=base_input, artifact_refs=[], created_at=_now(), started_at=None,
                finished_at=None,
                events=[JobEvent(1, "info", "core destroy apply queued", {})],
            )
            saved = jobs.save_if_absent(queued)
            # SQLite's SQLAlchemy DateTime column round-trips UTC timestamps
            # without their +00:00 suffix. Continue from the persisted row.
            if (saved is None or saved.id != queued.id or saved.action != queued.action
                    or saved.status != queued.status or saved.target != queued.target
                    or saved.target_type != queued.target_type
                    or saved.target_id != queued.target_id
                    or saved.requested_by != queued.requested_by
                    or saved.input != queued.input or saved.artifact_refs != queued.artifact_refs
                    or saved.created_at not in {queued.created_at,
                                               queued.created_at.removesuffix("+00:00")}
                    or saved.started_at is not None or saved.finished_at is not None
                    or saved.events != queued.events or jobs.get(child_id) != saved):
                raise ValueError("core destroy apply reservation lost")
            current = jobs.start_if_queued(
                saved, started_at=_now(),
                event=JobEvent(2, "info", "core destroy apply started", {}),
            )
            if current is None or jobs.get(child_id) != current:
                raise ValueError("core destroy apply start lost")
            current = jobs.claim_lease(
                child_id, owner=owner, token=token, claimed_at=claimed_at,
                expires_at=_later(claimed_at), eligible_statuses={"running"},
            )
            if current is None or jobs.get(child_id) != current:
                raise ValueError("core destroy apply claim lost")

        def claim_fence():
            nonlocal current
            if (jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or jobs.get(coordinator.id) != coordinator
                    or jobs.get(preview.id) != preview or plans.get(plan.id) != plan
                    or lookup(parent.target_id) != (plan.id, _FENCE)
                    or jobs.get(child_id) != current
                    or datetime.now(timezone.utc) >= datetime.fromisoformat(
                        current.input["claimExpiresAt"])):
                raise ValueError("core destroy authority changed")

        def fence():
            claim_fence()
            if authority() != initial:
                raise ValueError("core destroy prestate changed")

        def append(message: str, data: dict, *, prestate: bool = True):
            nonlocal current
            fence() if prestate else claim_fence()
            at = _now()
            updated = jobs.append_core_destroy_apply_event_if_running_claimed(
                current, owner=owner, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(current.events) + 1, "info", message, data),
            )
            if updated is None:
                raise ValueError("core destroy apply journal changed")
            current = updated

        def renew(*, prestate: bool):
            nonlocal current
            fence() if prestate else claim_fence()
            at = _now()
            updated = jobs.renew_lease(child_id, owner=owner, token=token,
                                       heartbeat_at=at, expires_at=_later(at))
            if updated is None or updated.events != current.events:
                raise ValueError("core destroy apply heartbeat changed")
            current = updated

        def run(phase: str, args: list[str]):
            stage = "requested"
            intent = None
            started = None

            def on_intent(value):
                nonlocal stage, intent
                if (stage != "requested" or value.scratch_path != str(run_dir)
                        or not value.invocation_id
                        or value.argv_sha256 != _sha(json.dumps(
                            args, separators=(",", ":")).encode())):
                    raise ValueError("core command intent differs")
                append("core destroy command intent fenced", {
                    "phase": phase, "invocationId": value.invocation_id,
                    "argvSha256": value.argv_sha256,
                })
                intent, stage = value, "intent"

            def on_started(value):
                nonlocal stage, started
                if stage != "intent" or value.intent != intent:
                    raise ValueError("core command start differs")
                append("core destroy command started before GO", {
                    "phase": phase, "invocationId": intent.invocation_id,
                    "bootId": value.identity.boot_id, "pid": value.identity.pid,
                    "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks,
                })
                started, stage = value, "started"
                if phase == "apply":
                    # GO is still held by the gated runner. No state, plan,
                    # source, claim or lease may drift between show and GO.
                    fence()

            def on_heartbeat(value):
                if stage != "started" or value != started:
                    raise ValueError("core command heartbeat differs")
                renew(prestate=phase == "show")

            def on_result(value):
                nonlocal stage
                if stage != "started" or value.started != started:
                    raise ValueError("core command result differs")
                append("core destroy command result fenced", {
                    "phase": phase, "invocationId": intent.invocation_id,
                    "returnCode": value.returncode,
                    "stdoutBytes": value.stdout_bytes,
                    "stderrBytes": value.stderr_bytes,
                    "stdoutTruncated": value.stdout_truncated,
                    "stderrTruncated": value.stderr_truncated,
                }, prestate=phase == "show")
                stage = "result"

            env = {key: value for key, value in barragan_subprocess_env().items()
                   if not key.upper().startswith("TF_")}
            env.update({"TF_DATA_DIR": str(data_dir), "TF_CLI_CONFIG_FILE": "/dev/null"})
            outcome = gated_command_runner(
                args, scratch_path=run_dir, provider_keyed_v2=True,
                max_output_bytes=16 * 1024 * 1024 if phase == "show" else 65536,
                env=env, intent_callback=on_intent, started_callback=on_started,
                heartbeat_callback=on_heartbeat, result_callback=on_result,
            )
            if (stage != "result" or outcome.started != started
                    or outcome.stdout_truncated or outcome.stderr_truncated
                    or outcome.returncode != 0):
                raise ValueError("core destroy command outcome differs")
            return outcome

        fence()
        shown = run("show", [str(release.path), "show", "-json", str(plan_path)])
        _exact_destroy(json.loads(shown.stdout), inventory, _state_data_ids(state_bytes))
        fence()
        if recovering and not _terraform_quiescent():
            raise ValueError("Terraform process appeared during pre-GO recovery")
        ocids = {resource.address: resource.ocid for resource in inventory.resources}
        executable = oci_executable
        if executable is None:
            resolved = resolve_oci_cli()
            if not resolved.ok or resolved.command is None:
                raise ValueError("OCI CLI unavailable")
            executable = Path(resolved.command).resolve(strict=True)
        if (not isinstance(executable, Path) or not executable.is_absolute()
                or executable.is_symlink() or executable.resolve(strict=True) != executable
                or not os.access(executable, os.X_OK)):
            raise ValueError("OCI CLI identity differs")
        cli_identity = _file_identity(executable)

        def witnessed_oci_command(argv, env):
            renew(prestate=True)
            if (_file_identity(executable) != cli_identity
                    or not argv or argv[0] != str(executable)):
                raise ValueError("OCI CLI changed during visibility proof")
            response = oci_command_runner(argv, env)
            renew(prestate=True)
            if _file_identity(executable) != cli_identity:
                raise ValueError("OCI CLI changed during visibility proof")
            return response

        witness = visibility_prover(
            inventory, compartment_id=plan.evidence["target"]["compartmentId"],
            region=plan.evidence["target"]["region"],
            engagement_name=core.input["engagementName"],
            oci_executable=str(executable), runner=witnessed_oci_command,
            fence=lambda: renew(prestate=True),
        )
        if (type(witness) is not OciExactWitness or witness.phase != "present"
                or witness.inventory_sha256 != inventory.inventory_sha256
                or witness.resource_ids_sha256 != _fingerprint(ocids)
                or witness.compartment_id != plan.evidence["target"]["compartmentId"]
                or witness.region != plan.evidence["target"]["region"]
                or witness.auth != "instance_principal"
                or not _HASH.fullmatch(witness.principal_sha256)
                or not _HASH.fullmatch(witness.evidence_sha256)
                or _file_identity(executable) != cli_identity):
            raise ValueError("OCI pre-destroy visibility proof differs")
        fence()
        append("core destroy prestate identity fenced", {
            "coreJobId": core.id, "corePlanId": plan.id,
            "scopeSnapshotId": snapshot["snapshotId"],
            "preDestroyStateSha256": inventory.raw_state_sha256,
            "inventorySha256": inventory.inventory_sha256,
            "lineage": inventory.lineage, "serial": inventory.serial,
            "resourceIds": ocids, "resourceIdsSha256": _fingerprint(ocids),
            "planSha256": receipt["planSha256"],
            "ociCliPath": str(executable), "ociCliSha256": cli_identity[2],
            "ociVisibilityWitness": asdict(witness),
        })
        # The prestate seal is durable before Terraform can erase its IDs.
        if recovering and not _terraform_quiescent():
            raise ValueError("Terraform process appeared before recovered GO")
        run("apply", [str(release.path), "apply", "-input=false", "-lock=true",
                      "-no-color", f"-state={state_path}", str(plan_path)])
        # The state may now be empty. The immutable preview and child remain
        # the authority for a separate exact-ID OCI GET absence proof.
        if (jobs.get(child_id) != current or jobs.get(parent.id) != parent
                or jobs.get(coordinator.id) != coordinator
                or lookup(parent.target_id) != (plan.id, _FENCE)):
            raise ValueError("core destroy result authority changed")
        terminal = jobs.finish_core_destroy_apply_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(current.events) + 1, "info",
                           "core destroy applied; provider absence pending", {
                               "providerAbsenceProofPending": True,
                               "preDestroyResourceIdsSha256": _fingerprint(ocids),
                           }),
        )
        if terminal is None:
            raise ValueError("core destroy terminal journal changed")
        return terminal
    except Exception:
        # A recorded child, including an interrupted show, is never replayed.
        raise KeyedCoreDestroyApplyAttention(
            "core destroy apply is unverified; reconcile retained one-shot child"
        ) from None
