# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only binder for one reviewed DevTest interrupted DO destroy child.

This does not take over the claim or run Terraform. The historical runtime
attestation is an explicit operator-reviewed fact, not machine proof that GO
was never released. All current state and provider observations are fresh.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Callable

from app.services.credentials import decrypt_secret_value
from app.services.engagement_teardown import _fingerprint
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_comprehensive_teardown import _boundary, _child_id
from app.services.provider_keyed_core_destroy_preview import _terraform_quiescent
from app.services.provider_keyed_destroy_apply_continuation import prove_live_keyed_inspector_before_destroy_go
from app.services.provider_keyed_dns_cleanup_checkpoint import prove_provider_keyed_dns_cleanup_checkpoint
from app.services.provider_keyed_gated_runner import (
    _CHILD as _GATE_CHILD, GatedRunnerError, StartedCommand, linux_active_group_members,
    linux_process_identity,
)
from app.services.provider_keyed_digitalocean_absence import _inventory
from app.services.provider_keyed_digitalocean_attachment import reconcile_digitalocean_initial_attachment
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_destroy_apply_job import (
    ACTION, _PREVIEW_DATA_KEYS, _audit_successful_preview_journal,
)
from app.services.provider_keyed_initial_destroy_plan_job import _private_file_digest
from app.services.provider_keyed_initial_teardown import DigitalOceanTeardownIntent, _require_exact_state
from app.services.provider_keyed_postapply_preflight import read_applied_digitalocean_provider_for_teardown
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot, _hash_file, _topology_hash
from app.services.sketch_state_workspaces import _default_state_root
from app.services.provider_keyed_teardown_quiescence import audit_failed_prebinding_provider_bootstrap
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, _valid_initial_destroy_pre_go_takeover, job_event_digest,
)


_HISTORICAL_REVISION = "bc3a6990f86dcca99381e1659ec337493ddf5275"
_INCIDENT_PARENT = "job-engagement-teardown-db19aa91df17"
_INCIDENT_CORE = "job-db19aa91df17"
_INCIDENT_CHILD = "job-provider-keyed-initial-destroy-apply-db19aa91df17"
_INCIDENT_ENGAGEMENT = "eng-09c806850ec5"
_FENCE = "provider_keyed_teardown_fence"
_INCIDENT_GATE_TIMEOUT = 1200


@dataclass(frozen=True)
class ReviewedIncident:
    engagement_id: str
    parent_id: str
    core_id: str
    child_id: str
    revision: str
    api_pid: int
    original_journal_sha256: str
    state_sha256: str = ""
    plan_sha256: str = ""


_ORIGINAL_INCIDENT = ReviewedIncident(
    _INCIDENT_ENGAGEMENT, _INCIDENT_PARENT, _INCIDENT_CORE, _INCIDENT_CHILD,
    _HISTORICAL_REVISION, 317379,
    "4a9014cec817e4bc3cc09cd954801ebdf9e91496080d21bc3094f5bc4074f4b8",
)
_DEVTEST_0CC4_INCIDENT = ReviewedIncident(
    "eng-6ad4d5fb880e", "job-engagement-teardown-b4f1bceb4a7d",
    "job-b4f1bceb4a7d", "job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d",
    "e4f702c984fd8f2448288db1a005d242049362a8", 390677,
    "36a5746659bf771f25429abfca06b76d092b1a36a9769c074a801b6fb2bc3caf",
    "e71116c850d7cd56937f411bf49ef390a19b1b4241e4e7d571a9a88ebfda4df9",
    "e4b910e78bc2045a4c5e1adb734047ad94207c3ce98d6dbd6d7530e6e87aea9c",
)


def _reviewed_incident(parent_id: str) -> ReviewedIncident:
    if parent_id == _ORIGINAL_INCIDENT.parent_id:
        return _ORIGINAL_INCIDENT
    if parent_id == _DEVTEST_0CC4_INCIDENT.parent_id:
        return _DEVTEST_0CC4_INCIDENT
    raise ValueError("unreviewed recovery incident")


class PreGoRecoveryBoundaryError(ValueError):
    """The reviewed one-off recovery source is incomplete or changed."""


@dataclass(frozen=True)
class HistoricalRuntimeAttestation:
    """Operator-reviewed external evidence; this is not a code-generated receipt."""

    reviewed_by: str
    revision: str
    api_pid: int
    api_started_at: str
    evidence_window_end: str
    parent_id: str
    child_id: str
    child_journal_sha256: str
    gated_boot_id: str
    gated_pid: int
    gated_pgid: int
    gated_start_ticks: int
    evidence: str


@dataclass(frozen=True)
class PreGoRecoveryBoundary:
    parent_id: str
    child_id: str
    child_journal_sha256: str
    plan_sha256: str
    state_sha256: str
    resource_ids_sha256: str
    coordinator_journal_sha256: str


def _process_quiescent(boot: str, pid: int, pgid: int, ticks: int,
                       proc_root: Path = Path("/proc")) -> bool:
    """Fail closed on an extant recorded PID/group or any service Terraform."""
    if (not boot or type(pid) is not int or pid <= 0 or type(pgid) is not int
            or pgid != pid or type(ticks) is not int or ticks <= 0
            or not _terraform_quiescent() or not proc_root.is_dir()):
        return False
    try:
        current_boot = (proc_root / "sys/kernel/random/boot_id").read_text().strip()
        if not current_boot or (proc_root / str(pid)).exists():
            return False
        if current_boot == boot:
            for entry in proc_root.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    raw = (entry / "stat").read_text()
                except FileNotFoundError:
                    if entry.exists():
                        return False
                    continue
                tail = raw[raw.rfind(")") + 2:].split()
                if int(tail[2]) == pgid and tail[0] != "Z":
                    return False
    except (OSError, ValueError, IndexError):
        return False
    return True


def _gated_process_exact(started: StartedCommand, argv: list[str]) -> bool:
    """The sole new group is the recorded runner child, still blocked pre-exec."""
    try:
        identity = started.identity
        pid = identity.pid
        command = (Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0"))
        expected = [str(Path(sys.executable).resolve(strict=True)), "-I",
                    str(_GATE_CHILD), None, f"--gate-timeout={_INCIDENT_GATE_TIMEOUT}",
                    "--", *argv]
        return (linux_process_identity(pid) == identity
                and linux_active_group_members(identity) == {pid}
                and len(command) == len(expected)
                and command[:3] == [part.encode() for part in expected[:3]]
                and command[3].decode().isdecimal()
                and command[4:] == [part.encode() for part in expected[4:]])
    except (OSError, ValueError, UnicodeError, GatedRunnerError):
        return False


def _attestation_matches(attestation: HistoricalRuntimeAttestation, child,
                         incident: ReviewedIncident | None = None) -> bool:
    if type(attestation) is not HistoricalRuntimeAttestation:
        return False
    try:
        start = datetime.fromisoformat(attestation.api_started_at)
        window_end = datetime.fromisoformat(attestation.evidence_window_end)
        child_start = datetime.fromisoformat(child.started_at)
    except (ValueError, TypeError):
        return False
    if any(value.tzinfo is None or value.utcoffset() is None
           for value in (start, window_end)):
        return False
    # SQLAlchemy's SQLite DateTime round-trip strips the persisted UTC offset.
    # Only this database timestamp may be interpreted as UTC without one.
    if child_start.tzinfo is None or child_start.utcoffset() is None:
        child_start = child_start.replace(tzinfo=timezone.utc)
    start, window_end, child_start = (value.astimezone(timezone.utc) for value in
                                      (start, window_end, child_start))
    incident = incident or _reviewed_incident(attestation.parent_id)
    recorded = child.events[8].data
    return (
        attestation.reviewed_by.strip() != "" and attestation.evidence == "systemd-journal+clean-git-worktree"
        and attestation.revision == incident.revision
        and type(attestation.api_pid) is int and attestation.api_pid == incident.api_pid
        and start <= child_start <= window_end and start < window_end
        and attestation.parent_id == incident.parent_id
        and attestation.child_id == incident.child_id
        and attestation.child_journal_sha256 == job_event_digest(child.events)
        and (incident == _ORIGINAL_INCIDENT or
             job_event_digest(child.events) == incident.original_journal_sha256)
        and (incident.parent_id != _DEVTEST_0CC4_INCIDENT.parent_id or (
            attestation.api_started_at == "2026-10-14T03:54:27+00:00"
            and attestation.gated_boot_id == "a002e341-34dd-43bc-9650-3d10a3f2cca6"
            and attestation.gated_pid == 391058
            and attestation.gated_pgid == 391058
            and attestation.gated_start_ticks == 1176259684))
        and (attestation.gated_boot_id, attestation.gated_pid,
             attestation.gated_pgid, attestation.gated_start_ticks) == (
                recorded.get("bootId"), recorded.get("pid"),
                recorded.get("pgid"), recorded.get("startTicks"))
    )


def _ssh_key_present(intent: DigitalOceanTeardownIntent, credentials, transport) -> bool:
    """Read the sixth cloud ID; attachment reconciliation covers the other five."""
    digest, updated, encrypted = _credential_snapshot(intent.credential_record_id, credentials)
    if (digest, updated) != (intent.credential_secret_sha256, intent.credential_updated_at):
        return False
    token = decrypt_secret_value(encrypted)
    try:
        keys = _inventory(transport, token, "/account/keys", "ssh_keys")
    finally:
        del token
    expected = intent.resource_ids["digitalocean_ssh_key.key"]
    return sum(str(row.get("id")) == expected for row in keys if type(row) is dict) == 1


def bind_reviewed_digitalocean_destroy_pre_go(
    attestation: HistoricalRuntimeAttestation, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, credential_repository=None,
    engagement_repository=None, sketch_repository=None, lease_lookup=None,
    attachment_prover: Callable = reconcile_digitalocean_initial_attachment,
    ssh_key_prover: Callable = _ssh_key_present,
    inspector_prover: Callable = prove_live_keyed_inspector_before_destroy_go,
    bootstrap_auditor: Callable = audit_failed_prebinding_provider_bootstrap,
    dns_checkpoint_prover: Callable = prove_provider_keyed_dns_cleanup_checkpoint,
    transport=None, process_quiescence: Callable = _process_quiescent,
    original_child=None, claimed_child=None, claim_fence: Callable | None = None,
    gated_started: StartedCommand | None = None, gated_argv: list[str] | None = None,
    gated_process_prover: Callable = _gated_process_exact,
) -> PreGoRecoveryBoundary:
    """Observe this exact disposable incident without changing any persisted data."""
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root()
                or state_root.is_symlink() or state_root.resolve(strict=True) != state_root
                or os.geteuid() == 0 or state_root.stat().st_uid != os.geteuid()):
            raise ValueError("DevTest state root differs")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        incident = _reviewed_incident(attestation.parent_id)
        parent, core, snapshot, operation = _boundary(incident.parent_id, jobs, plans, lookup)
        coordinator = jobs.get(_child_id(core.id))
        child = jobs.get(incident.child_id)
        continuing = original_child is not None or claimed_child is not None
        if continuing and (original_child is None or claimed_child is None
                           or child != claimed_child or original_child.id != child.id
                           or len(original_child.events) != 9
                           or child.events[:9] != original_child.events):
            raise ValueError("claimed incident journal differs")
        audit_child = original_child if continuing else child
        gated = continuing and len(child.events) in {12, 15}
        if (gated != (gated_started is not None or gated_argv is not None)
                or (gated and (not isinstance(gated_started, StartedCommand)
                    or type(gated_argv) is not list
                    or child.events[-1].data != {
                        "phase": "show" if len(child.events) == 12 else "apply",
                        "invocationId": gated_started.intent.invocation_id,
                        "bootId": gated_started.identity.boot_id,
                        "pid": gated_started.identity.pid,
                        "pgid": gated_started.identity.pgid,
                        "startTicks": gated_started.identity.start_ticks,
                    } or not gated_process_prover(gated_started, gated_argv)))):
            raise ValueError("recovery gated process differs")
        if (parent.target_id != incident.engagement_id or core.id != incident.core_id
                or operation != _FENCE or coordinator is None or coordinator.status != "running"
                or coordinator.input.get("phase") != "inspector_ready"
                or child is None or child.id != incident.child_id or child.action != ACTION
                or child.status != "running" or child.finished_at is not None
                or child.target_id != parent.target_id or child.requested_by != parent.requested_by
                or child.artifact_refs != [] or child.input.get("teardownParentId") != parent.id
                or child.input.get("coreJobId") != core.id
                or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                or (not continuing and len(child.events) != 9)
                or not _attestation_matches(attestation, audit_child, incident)):
            raise ValueError("incident parent, coordinator, or attestation differs")
        now = datetime.now(timezone.utc)
        if not _valid_initial_destroy_pre_go_takeover(
            audit_child, expected_event_digest=job_event_digest(audit_child.events),
            owner="provider-keyed-destroy-recovery-read-only", token="r" * 32,
            claimed_at=now.isoformat(), expires_at=(now + timedelta(minutes=1)).isoformat(),
        ):
            raise ValueError("expired exact pre-GO child differs")
        identity = audit_child.events[8].data
        if not process_quiescence(identity["bootId"], identity["pid"],
                                  identity["pgid"], identity["startTicks"]):
            raise ValueError("gated process or Terraform is not quiescent")
        scope = snapshot["providerScopes"][0]
        if (scope.get("provider") != "digitalocean"
                or child.input.get("corePlanId") != scope["corePlanId"]
                or child.input.get("providerScopeSha256") != snapshot["providerScopeSha256"]):
            raise ValueError("confirmed provider scope differs")
        bootstrap_auditor(
            core.id, confirmed_scope=scope, confirmed_scope_sha256=_fingerprint(snapshot),
            workspace_root=Path(scope["workspace"]), job_repository=jobs,
        )
        intent, workspace, evidence, apply_job = read_applied_digitalocean_provider_for_teardown(
            parent.target_id, core.id, environment=environment, state_root=state_root,
            mode="destroy_started_recovery_read" if continuing else "destroy_started_read",
            incident_recovery_child=child if continuing else None,
            allowed_teardown_parent_id=parent.id,
            incident_destroy_child_id=child.id,
            engagement_repository=engagement_repository, sketch_repository=sketch_repository,
            job_repository=jobs, plan_repository=plans, credential_repository=credentials,
        )
        attachment = derive_digitalocean_initial_attachment_intent(
            intent, workspace, evidence, apply_job, expected_phase="destroy_started",
        )
        resource_ids = {row["address"]: row["id"] for row in scope["resources"]}
        pre = audit_child.events[5].data
        if (len(resource_ids) != 8 or workspace.path != Path(scope["workspace"])
                or (incident.state_sha256 and scope["stateSha256"] != incident.state_sha256)
                or pre["resourceIds"] != resource_ids
                or pre["resourceIdsSha256"] != _fingerprint(resource_ids)
                or pre["preDestroyStateSha256"] != scope["stateSha256"]
                or pre["selectorTag"] != intent.selector_tag
                or pre["credentialRecordId"] != workspace.provider_connection_id
                or pre["credentialSecretSha256"] != attachment.credential_secret_sha256
                or pre["credentialUpdatedAt"] != attachment.credential_updated_at
                or attachment.state_sha256 != scope["stateSha256"]):
            raise ValueError("prestate ownership differs")
        teardown_intent = DigitalOceanTeardownIntent(
            intent.nodes, intent.firewall, resource_ids, scope["stateSha256"],
            attachment.credential_record_id, attachment.credential_secret_sha256,
            attachment.credential_updated_at,
        )
        state = _require_exact_state(workspace, teardown_intent)
        if (state["lineage"] != pre["stateLineage"] or state["serial"] != pre["preDestroySerial"]
                or _hash_file(workspace.state_path) != scope["stateSha256"]
                or audit_child.events[6].data != {
                    "phase": "destroy_started",
                    "path": str(workspace.path / ".barragan-apply-phase.json"),
                }
                or json.loads((workspace.path / ".barragan-apply-phase.json").read_text())
                != {"schema": "provider-keyed-v2", "phase": "destroy_started"}):
            raise ValueError("retained state or phase differs")
        preview_id = child.input["destroyPlanJobId"]
        preview = jobs.get(preview_id)
        plan_path = workspace.path / ".barragan-initial-destroy.tfplan"
        if (preview is None or preview.id != f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
                or preview.action != "provider_keyed_initial_destroy_plan"
                or preview.status != "succeeded" or preview.artifact_refs != [str(plan_path)]
                or not preview.events or type(preview.events[-1].data) is not dict):
            raise ValueError("saved destroy preview differs")
        saved = preview.events[-1].data
        if (set(saved) != _PREVIEW_DATA_KEYS or saved["planPath"] != str(plan_path)
                or (incident.plan_sha256 and saved["planSha256"] != incident.plan_sha256)
                or saved["planSha256"] != child.input["planSha256"]
                or _private_file_digest(plan_path) != saved["planSha256"]
                or saved["stateSha256"] != scope["stateSha256"]
                or saved["sourceRevision"] != workspace.source_revision
                or saved["sourceSha256"] != workspace.source_sha256
                or saved["markerSha256"] != _hash_file(workspace.path / ".barragan-provider-keyed-state.json")
                or saved["lockfileSha256"] != _hash_file(workspace.path / ".terraform.lock.hcl")
                or saved["topologySha256"] != _topology_hash(workspace)
                or saved["inputSha256"] != evidence["inputSha256"]
                or saved["terraformBinarySha256"] != _hash_file(Path(saved["terraformBinaryPath"]))):
            raise ValueError("saved destroy inputs differ")
        binary = saved["terraformBinaryPath"]
        expected_show = [binary, "show", "-json", str(plan_path)]
        expected_apply = [binary, "apply", "-input=false", "-lock=true", "-no-color",
                          str(plan_path)]
        def argv_digest(argv: list[str]) -> str:
            return hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
        if (audit_child.events[2].data["argvSha256"] != argv_digest(expected_show)
                or audit_child.events[7].data["argvSha256"] != argv_digest(expected_apply)):
            raise ValueError("destroy command argv differs from saved plan")
        _audit_successful_preview_journal(preview, workspace, evidence, plan_path)

        observed_child = child

        def stable() -> None:
            nonlocal observed_child
            if continuing:
                if claim_fence is None:
                    raise ValueError("claimed recovery lacks a lease fence")
                refreshed = claim_fence(observed_child)
                if (refreshed is None or refreshed.id != observed_child.id
                        or refreshed.events != observed_child.events
                        or refreshed.input.get("claimOwner") != observed_child.input.get("claimOwner")
                        or refreshed.input.get("claimToken") != observed_child.input.get("claimToken")
                        or {key: value for key, value in refreshed.input.items()
                            if key not in {"claimHeartbeatAt", "claimExpiresAt"}}
                        != {key: value for key, value in observed_child.input.items()
                            if key not in {"claimHeartbeatAt", "claimExpiresAt"}}):
                    raise ValueError("claimed recovery lease changed")
                observed_child = refreshed
            if (jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or jobs.get(coordinator.id) != coordinator
                    or jobs.get(child.id) != observed_child
                    or jobs.get(preview.id) != preview
                    or lookup(parent.target_id) != (scope["corePlanId"], _FENCE)
                    or _hash_file(workspace.state_path) != scope["stateSha256"]
                    or _private_file_digest(plan_path) != saved["planSha256"]
                    or (gated and not gated_process_prover(gated_started, gated_argv))
                    or not process_quiescence(identity["bootId"], identity["pid"],
                                              identity["pgid"], identity["startTicks"])):
                raise ValueError("incident authority changed")

        stable()
        dns_checkpoint = dns_checkpoint_prover(snapshot, job_repository=jobs, fence=stable)
        if (type(dns_checkpoint) is not dict
                or any(pre[key] != dns_checkpoint[key] for key in (
                    "dnsCleanupManifestSha256", "dnsCleanupHandoffJournalSha256",
                    "dnsCleanupCheckpointSha256"))):
            raise ValueError("fresh DNS checkpoint differs")
        stable()
        attachment_prover(
            workspace, attachment, environment=environment,
            deployment_target="barragan-testing", credential_repository=credentials,
            transport=transport, max_attempts=1, expected_phase="destroy_started",
        )
        stable()
        if not ssh_key_prover(teardown_intent, credentials,
                              transport or UrllibProviderCatalogTransport()):
            raise ValueError("reviewed SSH key is not present")
        stable()
        inspector_prover(parent.id, environment=environment, job_repository=jobs,
                         plan_repository=plans, lease_lookup=lookup, fence=stable)
        stable()
        return PreGoRecoveryBoundary(
            parent.id, child.id, job_event_digest(audit_child.events), saved["planSha256"],
            scope["stateSha256"], pre["resourceIdsSha256"], job_event_digest(coordinator.events),
        )
    except Exception:
        raise PreGoRecoveryBoundaryError(
            "reviewed DevTest pre-GO recovery boundary is unproved; no claim or provider mutation occurred"
        ) from None
