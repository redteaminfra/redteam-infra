# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot OCI destroy preview for a fenced mixed zero-Apply build.

This saves review evidence only. It has no public caller or Apply path.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping

from app.core.command_environment import barragan_subprocess_env
from app.domain import JobEvent
from app.services.core_deployment_plans import require_keyed_core_terraform_source_manifest
from app.services.engagement_teardown import _fingerprint
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_core_destroy_preview import (
    _exact_destroy, _read_regular, _run, _sha, _state_data_ids,
)
from app.services.provider_keyed_mixed_zero_apply_cleanup import _parent_id
from app.services.provider_keyed_mixed_interrupted_cleanup import _parent_id as _interrupted_parent_id
from app.services.provider_keyed_mixed_interrupted_oci_tail import (
    audit_current_interrupted_oci_tail, stable_interrupted_oci_authority,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    parent_id as _published_parent_id,
)
from app.services.provider_keyed_mixed_published_tail_authority import (
    PublishedMixedTailAuthority, audit_published_mixed_tail_authority,
    stable_published_mixed_tail_authority,
)
from app.services.provider_keyed_mixed_post_sketch_absence import (
    audit_zero_apply_post_sketch_absence,
)
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import (
    CertificateAssetModel, CertificateBindingModel, DomainAssignmentModel,
    DomainDnsRecordOwnershipModel, EngagementServiceModel,
)


ACTION = "provider_keyed_mixed_zero_apply_core_destroy_preview"
_FENCE = "provider_keyed_teardown_fence"
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class MixedZeroApplyCorePreviewAttention(ValueError):
    """A saved preview is absent or uncertain; no OCI destroy was applied."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-core-destroy-preview-{core_job_id.removeprefix('job-')}"


def queued_preview_restartable(child: StoredJobRun | None, parent: StoredJobRun,
                               core_job_id: str, *, authority=None) -> bool:
    """Read-only journal selector; the worker still audits source and files."""
    published = parent.action == "provider_keyed_mixed_published_cleanup"
    source = (parent.input.get("publishedSource" if published else "source")
              if isinstance(parent.input, dict) else None)
    if not isinstance(source, dict):
        return False
    interrupted = parent.action == "provider_keyed_mixed_interrupted_cleanup"
    expected_input = {
        "schema": ("mixed-published-core-preview-v1" if published
                   else "mixed-interrupted-core-preview-v1" if interrupted
                   else "mixed-zero-apply-core-preview-v1"),
        "teardownParentId": parent.id, "coreJobId": core_job_id,
        "corePlanId": parent.input.get("corePlanId"),
        "sourceSha256": (parent.input.get("publishedSourceSha256") if published
                         else parent.input.get("sourceSha256") if interrupted
                         else _fingerprint(source)),
        "parentJournalSha256": job_event_digest(parent.events),
        "stateSha256": (authority.core_state_sha256 if (interrupted or published) and authority is not None
                        else source.get("core_state_sha256")),
        "inventorySha256": (authority.core_inventory_sha256 if (interrupted or published) and authority is not None
                            else source.get("core_inventory_sha256")),
        "leaseOperation": _FENCE,
    }
    if interrupted or published:
        if authority is None:
            return False
        expected_input["inspectorRecordIds"] = list(authority.owned_inspector_record_ids)
    return bool(child is not None and child.id == _child_id(core_job_id)
                and child.action == ACTION and child.status == "queued"
                and child.target == f"engagement:{parent.target_id}"
                and child.target_type == "engagement"
                and child.target_id == parent.target_id
                and child.requested_by == parent.requested_by
                and child.input == expected_input and child.artifact_refs == []
                and child.started_at is None and child.finished_at is None
                and child.events == [JobEvent(1, "info", "mixed core destroy preview queued", {})])


def _recognize_extended_core_preview(child: StoredJobRun, parent: StoredJobRun,
                                     core_job_id: str, authority, *, published: bool) -> dict:
    """Authenticate an exact published/interrupted preview before OCI GO."""
    expected_action = ("provider_keyed_mixed_published_cleanup" if published
                       else "provider_keyed_mixed_interrupted_cleanup")
    if parent.action != expected_action:
        raise ValueError("mixed core parent differs")
    expected_input = {
        "schema": ("mixed-published-core-preview-v1" if published
                   else "mixed-interrupted-core-preview-v1"),
        "teardownParentId": parent.id, "coreJobId": core_job_id,
        "corePlanId": parent.input.get("corePlanId"),
        "sourceSha256": parent.input.get(
            "publishedSourceSha256" if published else "sourceSha256"),
        "parentJournalSha256": job_event_digest(parent.events),
        "stateSha256": authority.core_state_sha256,
        "inventorySha256": authority.core_inventory_sha256,
        "leaseOperation": _FENCE,
        "inspectorRecordIds": list(authority.owned_inspector_record_ids),
    }
    if (child is None or child.id != _child_id(core_job_id)
            or child.action != ACTION or child.status != "succeeded"
            or child.target != f"engagement:{parent.target_id}"
            or child.target_type != "engagement" or child.target_id != parent.target_id
            or child.requested_by != parent.requested_by
            or child.input != expected_input or child.artifact_refs != []
            or child.started_at is None or child.finished_at is None
            or len(child.events) != 3
            or child.events[:2] != [
                JobEvent(1, "info", "mixed core destroy preview queued", {}),
                JobEvent(2, "info", "mixed core destroy preview started", {})]
            or child.events[2].sequence != 3 or child.events[2].level != "info"
            or child.events[2].message != "mixed core destroy preview saved"):
        raise ValueError("interrupted core preview journal differs")
    receipt = child.events[2].data
    if (type(receipt) is not dict or set(receipt) != {
            "planPath", "planDevice", "planInode", "planSha256", "stateSha256",
            "inventorySha256", "resourceCount", "sourceSha256",
            "parentJournalSha256", "sourceManifestSha256", "terraformBinarySha256",
            "leaseOwner", "leaseOperation"}
            or receipt["sourceSha256"] != expected_input["sourceSha256"]
            or receipt["parentJournalSha256"] != expected_input["parentJournalSha256"]
            or receipt["stateSha256"] != expected_input["stateSha256"]
            or receipt["inventorySha256"] != expected_input["inventorySha256"]
            or receipt["leaseOwner"] != expected_input["corePlanId"]
            or receipt["leaseOperation"] != _FENCE
            or not isinstance(receipt["planPath"], str)
            or not _HASH.fullmatch(receipt["planSha256"] or "")
            or not _HASH.fullmatch(receipt["sourceManifestSha256"] or "")
            or not _HASH.fullmatch(receipt["terraformBinarySha256"] or "")
            or type(receipt["planDevice"]) is not int
            or type(receipt["planInode"]) is not int
            or type(receipt["resourceCount"]) is not int
            or receipt["resourceCount"] <= 0):
        raise ValueError("interrupted core preview receipt differs")
    return receipt


def recognize_interrupted_core_preview(child: StoredJobRun, parent: StoredJobRun,
                                       core_job_id: str, authority) -> dict:
    return _recognize_extended_core_preview(
        child, parent, core_job_id, authority, published=False)


def recognize_published_core_preview(child: StoredJobRun, parent: StoredJobRun,
                                     core_job_id: str,
                                     authority: PublishedMixedTailAuthority) -> dict:
    if type(authority) is not PublishedMixedTailAuthority or authority.parent != parent:
        raise ValueError("published OCI authority differs")
    return _recognize_extended_core_preview(
        child, parent, core_job_id, authority, published=True)


def _require_no_independent_bindings(engagement_id: str) -> None:
    """Include dormant rows: they may still own provider-side state."""
    if db.session.query(DomainAssignmentModel.id).filter(
            DomainAssignmentModel.engagement_id == engagement_id,
            DomainAssignmentModel.status == "active").first():
        raise ValueError("independent engagement binding exists")
    if db.session.query(DomainDnsRecordOwnershipModel.id).filter(
            DomainDnsRecordOwnershipModel.engagement_id == engagement_id,
            DomainDnsRecordOwnershipModel.retired_at.is_(None)).first():
        raise ValueError("independent engagement binding exists")
    for model in (CertificateAssetModel, CertificateBindingModel,
                  EngagementServiceModel):
        if db.session.query(model.id).filter(model.engagement_id == engagement_id).first():
            raise ValueError("independent engagement binding exists")


def preview_mixed_zero_apply_oci_core_destroy(
    engagement_id: str, core_job_id: str, *, environment: str, state_root: Path,
    core_state_root: Path, job_repository=None, plan_repository=None,
    lease_lookup=None, source_dependencies: Mapping[str, object] | None = None,
    binding_check: Callable[[str], None] = _require_no_independent_bindings,
    release_check: Callable = require_devtest_terraform_release,
    command_runner: Callable = _run,
    interrupted: bool = False, published: bool = False,
) -> StoredJobRun:
    """Reserve once, inspect exact destroy plan, and retain it for a later GO."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root
                or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT):
            raise ValueError("private DevTest root differs")
        core = jobs.get(core_job_id)
        if core is None or not isinstance(core.input, dict):
            raise ValueError("applied core job is absent")
        plan_id = core.input.get("corePlanId")
        if (type(interrupted) is not bool or type(published) is not bool
                or (interrupted and published)):
            raise ValueError("mixed OCI mode differs")
        parent = jobs.get((_published_parent_id if published else
                           _interrupted_parent_id if interrupted else _parent_id)(core_job_id))
        if parent is None or parent.input.get("corePlanId") != plan_id:
            raise ValueError("fenced cleanup parent is absent")
        dependencies = dict(source_dependencies or {})
        dependencies.update(job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        def audit_source():
            if published:
                return audit_published_mixed_tail_authority(
                    parent.id, environment=environment, state_root=state_root,
                    core_state_root=core_state_root, **dependencies)
            if interrupted:
                return audit_current_interrupted_oci_tail(
                    engagement_id, core_job_id, environment=environment,
                    state_root=state_root, core_state_root=core_state_root,
                    **dependencies)
            return audit_zero_apply_post_sketch_absence(
                parent, engagement_id, core_job_id, environment=environment,
                state_root=state_root, core_state_root=core_state_root,
                lease_owner=plan_id, lease_operation=_FENCE, **dependencies).source

        source = audit_source()
        source_sha = parent.input["publishedSourceSha256" if published else "sourceSha256"]
        if (published and (type(source) is not PublishedMixedTailAuthority
                           or source.parent != parent
                           or source.core_job_id != core_job_id
                           or source.core_plan_id != plan_id
                           or source_sha != _fingerprint(parent.input["publishedSource"]))):
            raise ValueError("published OCI source digest differs")
        if not interrupted and not published and source_sha != _fingerprint(parent.input["source"]):
            raise ValueError("mixed OCI source digest differs")
        binding_check(engagement_id)
        plan = plans.get(plan_id)
        evidence = plan.evidence
        state_path = Path(evidence["terraformStatePath"])
        run_directory = Path(evidence["runDirectory"])
        data_dir = Path(evidence["terraformDataDir"])
        public_key_path = Path(evidence["sshPublicKeyPath"])
        if (state_path.name != "terraform.tfstate" or state_path.parent.name != "core"
                or state_path.parents[2] != core_state_root
                or not run_directory.is_absolute() or run_directory.is_symlink()
                or not run_directory.is_dir() or not data_dir.is_absolute()
                or data_dir.parent != state_path.parent or data_dir.is_symlink()
                or not data_dir.is_dir() or not data_dir.name.startswith("data-core-")
                or not public_key_path.is_absolute()):
            raise ValueError("reviewed core paths differ")
        lock_path = run_directory / ".terraform.lock.hcl"
        release = release_check(environment=environment)
        if (release.version != evidence.get("terraformFingerprint")
                or not isinstance(release.path, Path) or not release.path.is_absolute()
                or not isinstance(release.sha256, str) or len(release.sha256) != 64):
            raise ValueError("reviewed Terraform binary differs")
        state_bytes = _read_regular(state_path)
        inventory = parse_applied_oci_core_state(
            state_bytes, proxy_count=evidence["proxyCount"],
            elk_enabled=evidence["elkEnabled"],
            compartment_id=evidence["target"]["compartmentId"],
            engagement_name=core.input["engagementName"])
        if (source.core_state_sha256 != inventory.raw_state_sha256
                or source.core_inventory_sha256 != inventory.inventory_sha256):
            raise ValueError("retained OCI state differs")
        source_manifest = evidence["keyedCoreTerraformSourceManifest"]

        def recheck() -> None:
            if (jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or plans.get(plan.id) != plan
                    or lookup(engagement_id) != (plan.id, _FENCE)
                    or _sha(_read_regular(state_path)) != inventory.raw_state_sha256
                    or _sha(_read_regular(lock_path)) != evidence["providerLockFingerprint"]
                    or _sha(_read_regular(public_key_path)) != evidence["publicKeyFingerprint"]
                    or release_check(environment=environment) != release):
                raise ValueError("core preview authority changed")
            require_keyed_core_terraform_source_manifest(run_directory, source_manifest)
            binding_check(engagement_id)
            fresh = audit_source()
            if ((stable_published_mixed_tail_authority(fresh)
                 != stable_published_mixed_tail_authority(source)) if published
                else (stable_interrupted_oci_authority(fresh)
                      != stable_interrupted_oci_authority(source)) if interrupted
                else fresh != source):
                raise ValueError("fenced mixed source changed")

        recheck()
        child_id = _child_id(core_job_id)
        existing = jobs.get(child_id)
        related = [row for row in jobs.list_for_engagement(engagement_id)
                   if row.action == ACTION and row.input.get("coreJobId") == core_job_id]
        if any(row.id != child_id for row in related):
            raise ValueError("alien core preview child exists")
        plan_path = state_path.parent / f".barragan-mixed-core-destroy-{core_job_id.removeprefix('job-')}.tfplan"
        if plan_path.exists() or plan_path.is_symlink():
            raise ValueError("orphan core preview plan exists")
        child_input = {"schema": ("mixed-published-core-preview-v1" if published
                                   else "mixed-interrupted-core-preview-v1" if interrupted
                                   else "mixed-zero-apply-core-preview-v1"),
                       "teardownParentId": parent.id, "coreJobId": core.id,
                       "corePlanId": plan.id, "sourceSha256": source_sha,
                       "parentJournalSha256": job_event_digest(parent.events),
                       "stateSha256": inventory.raw_state_sha256,
                       "inventorySha256": inventory.inventory_sha256,
                       "leaseOperation": _FENCE}
        if interrupted or published:
            child_input["inspectorRecordIds"] = list(source.owned_inspector_record_ids)
        child = StoredJobRun(
            id=child_id, action=ACTION, status="queued", target=f"engagement:{engagement_id}",
            target_type="engagement", target_id=engagement_id,
            requested_by=parent.requested_by,
            input=child_input,
            artifact_refs=[], created_at=_now(), started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "mixed core destroy preview queued", {})])
        # A saved queued child has not crossed the start CAS and can use the
        # same identity. A running two-event child is ambiguous: this older
        # preview journal has no command-intent marker, so a missing tfplan
        # cannot prove Terraform was never invoked.
        if existing is not None and not queued_preview_restartable(
                existing, parent, core_job_id, authority=source):
            raise ValueError("core preview is not safely queued")
        saved = jobs.save_if_absent(child)
        if (saved.id != child.id or saved.action != child.action
                or saved.status != "queued" or saved.target_id != child.target_id
                or saved.input != child.input or saved.events != child.events
                or saved.started_at is not None or saved.finished_at is not None):
            raise ValueError("core preview reservation lost")
        running = jobs.start_if_queued(
            saved, started_at=_now(),
            event=JobEvent(2, "info", "mixed core destroy preview started", {}))
        if running is None:
            raise ValueError("core preview start lost")
        # From here, any exception leaves the same running child visible.
        recheck()
        descriptor = os.open(plan_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as reserved:
            identity = os.fstat(reserved.fileno())
        env = {**barragan_subprocess_env(), "TF_DATA_DIR": str(data_dir)}
        command = [str(release.path), "plan", "-destroy", "-input=false",
                   "-detailed-exitcode", f"-out={plan_path}", f"-state={state_path}",
                   "-var", f"region={evidence['target']['region']}",
                   "-var", f"compartment_ocid={evidence['target']['compartmentId']}",
                   "-var", f"ssh_public_key_path={public_key_path}",
                   "-var", f"ssh_source_cidrs={json.dumps(evidence['sshSourceCidrs'])}"]
        recheck()
        result = command_runner(command, run_directory, env)
        if result.returncode != 2:
            raise ValueError("Terraform destroy preview did not produce exact changes")
        recheck()  # A slow plan cannot authorize a later show after drift.
        plan_stat = plan_path.stat()
        if (plan_path.is_symlink() or not stat.S_ISREG(plan_stat.st_mode)
                or (plan_stat.st_dev, plan_stat.st_ino) != (identity.st_dev, identity.st_ino)):
            raise ValueError("saved plan identity changed")
        plan_bytes = _read_regular(plan_path)
        if not plan_bytes:
            raise ValueError("saved plan is empty")
        shown = command_runner([str(release.path), "show", "-json", str(plan_path)],
                               run_directory, env)
        if shown.returncode != 0 or not isinstance(shown.stdout, str):
            raise ValueError("saved plan show failed")
        _exact_destroy(json.loads(shown.stdout), inventory, _state_data_ids(state_bytes))
        recheck()
        if (jobs.get(running.id) != running or _sha(_read_regular(plan_path)) != _sha(plan_bytes)):
            raise ValueError("saved preview changed")
        finished = jobs.finish_if_running(
            running, status="succeeded", finished_at=_now(),
            event=JobEvent(3, "info", "mixed core destroy preview saved", {
                "planPath": str(plan_path), "planDevice": plan_stat.st_dev,
                "planInode": plan_stat.st_ino, "planSha256": _sha(plan_bytes),
                "stateSha256": inventory.raw_state_sha256,
                "inventorySha256": inventory.inventory_sha256,
                "resourceCount": len(inventory.resources),
                "sourceSha256": source_sha,
                "parentJournalSha256": job_event_digest(parent.events),
                "sourceManifestSha256": _fingerprint(source_manifest),
                "terraformBinarySha256": release.sha256,
                "leaseOwner": plan.id, "leaseOperation": _FENCE}))
        if finished is None:
            raise ValueError("core preview journal commit failed")
        return finished
    except Exception:
        raise MixedZeroApplyCorePreviewAttention(
            "mixed core destroy preview is unverified; no core destroy was applied") from None
