# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, one-shot OCI core destroy preview for a retired keyed group.

The saved plan is review evidence, never authority to apply. No dispatcher calls
this module. A recorded child, including an interrupted one, cannot be replayed.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Callable, Mapping

from app.domain import JobEvent
from app.services.core_deployment_plans import require_keyed_core_terraform_source_manifest
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_comprehensive_teardown import (
    _boundary, _child_id, recognize_provider_keyed_group_retired,
)
from app.services.provider_keyed_oci_core_state import _DATA_ADDRESSES, parse_applied_oci_core_state
from app.services.provider_keyed_pending_retirement import recognize_pending_keyed_group_retired
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.core.command_environment import barragan_subprocess_env


ACTION = "provider_keyed_core_destroy_preview"
_FENCE = "provider_keyed_teardown_fence"
_EVENT = "applied OCI core state sealed"


class KeyedCoreDestroyPreviewAttention(ValueError):
    """The preview is not safely reviewable; no core destroy was applied."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        original = os.fstat(stream.fileno())
        if not stat.S_ISREG(original.st_mode):
            raise ValueError("core preview file is not regular")
        contents = stream.read()
        after = os.fstat(stream.fileno())
        if (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("core preview file changed while read")
        if path.is_symlink() or path.stat().st_ino != original.st_ino:
            raise ValueError("core preview file identity changed")
        return contents


def _state_data_ids(state_bytes: bytes) -> dict[str, str]:
    """Map the parser-approved OCI data instances to Terraform show addresses."""
    state = json.loads(state_bytes)
    result: dict[str, str] = {}
    for resource in state["resources"]:
        if resource["mode"] != "data":
            continue
        base = f'data.{resource["type"]}.{resource["name"]}'
        if f'{resource["type"]}.{resource["name"]}' not in _DATA_ADDRESSES:
            raise ValueError("unexpected OCI data source")
        for instance in resource["instances"]:
            address = base + ("[0]" if instance.get("index_key") == 0 else "")
            identifier = instance["attributes"].get("id")
            if (address in result or not isinstance(identifier, str)
                    or not identifier):
                raise ValueError("OCI data source identity differs")
            result[address] = identifier
    return result


def _exact_destroy(show: object, inventory, expected_data: dict[str, str]) -> None:
    if not isinstance(show, dict) or show.get("resource_drift") not in (None, []) \
            or show.get("errored") is True or show.get("applyable") is not True \
            or show.get("complete") is not True:
        raise ValueError("Terraform destroy show is ambiguous")
    changes = show.get("resource_changes")
    if not isinstance(changes, list) or len(changes) != len(inventory.resources):
        raise ValueError("Terraform destroy inventory differs")
    expected = {row.address: row.ocid for row in inventory.resources}
    planned = show.get("planned_values")
    planned_root = planned.get("root_module") if isinstance(planned, dict) else None
    if planned_root not in (None, {}):
        if (not isinstance(planned_root, dict)
                or not set(planned_root).issubset({"resources", "child_modules"})
                or planned_root.get("child_modules") not in (None, [])
                or not isinstance(planned_root.get("resources", []), list)):
            raise ValueError("Terraform destroy planned values differ")
        planned_seen = set()
        for row in planned_root.get("resources", []):
            if (not isinstance(row, dict) or row.get("mode") != "data"
                    or row.get("address") not in expected_data
                    or row["address"] in planned_seen
                    or row.get("provider_name") != "registry.terraform.io/oracle/oci"
                    or row.get("type") != row["address"].split(".", 2)[1]
                    or not isinstance(row.get("values"), dict)
                    or row["values"].get("id") != expected_data[row["address"]]):
                raise ValueError("Terraform destroy retains unexpected planned resource")
            planned_seen.add(row["address"])
    prior = show.get("prior_state")
    values = prior.get("values") if isinstance(prior, dict) else None
    module = values.get("root_module") if isinstance(values, dict) else None
    prior_rows = module.get("resources") if isinstance(module, dict) else None
    if (not isinstance(prior_rows, list) or len(prior_rows) != len(expected) + len(expected_data)
            or not set(module).issubset({"resources", "child_modules"})
            or module.get("child_modules") not in (None, [])):
        raise ValueError("saved plan prior state differs from sealed inventory")
    prior_seen = set()
    data_seen = set()
    for row in prior_rows:
        if (not isinstance(row, dict) or not isinstance(row.get("values"), dict)
                or not isinstance(row.get("address"), str)
                or row.get("provider_name") != "registry.terraform.io/oracle/oci"
                or row.get("type") != (row["address"].split(".", 2)[1]
                                       if row.get("mode") == "data"
                                       else row["address"].split(".", 1)[0])):
            raise ValueError("saved plan prior resource differs from sealed inventory")
        if row["mode"] == "data":
            if (row["address"] not in expected_data or row["address"] in data_seen
                    or row["values"].get("id") != expected_data[row["address"]]):
                raise ValueError("saved plan prior data differs")
            data_seen.add(row["address"])
        elif (row["mode"] == "managed" and row["address"] in expected
              and row["address"] not in prior_seen
              and row["values"].get("id") == expected[row["address"]]):
            prior_seen.add(row["address"])
        else:
            raise ValueError("saved plan prior resource differs from sealed inventory")
    if prior_seen != set(expected) or data_seen != set(expected_data):
        raise ValueError("saved plan prior inventory is incomplete")
    seen = set()
    for row in changes:
        if not isinstance(row, dict) or not isinstance(row.get("change"), dict):
            raise ValueError("Terraform destroy change differs")
        address = row.get("address")
        change = row["change"]
        before = change.get("before")
        if (address not in expected or address in seen or row.get("mode") != "managed"
                or row.get("provider_name") != "registry.terraform.io/oracle/oci"
                or row.get("type") != address.split(".", 1)[0]
                or change.get("actions") != ["delete"] or not isinstance(before, dict)
                or before.get("id") != expected[address] or change.get("after") is not None
                or change.get("after_unknown") not in (None, {})
                or change.get("replace_paths") not in (None, [])
                or row.get("deposed") is not None or row.get("previous_address") is not None):
            raise ValueError("Terraform destroy change differs from sealed state")
        seen.add(address)
    if seen != set(expected):
        raise ValueError("Terraform destroy omits sealed resource")
    outputs = show.get("output_changes") or {}
    if not isinstance(outputs, dict) or any(
            not _exact_destroy_output(value) for value in outputs.values()):
        raise ValueError("Terraform destroy output differs")


def _exact_destroy_output(value: object) -> bool:
    # Terraform 1.15.5 emits direct changes; older show JSON also uses a
    # nested change. Mixing the two forms is ambiguous.
    if not isinstance(value, dict):
        return False
    if "change" in value:
        if set(value) != {"change"} or not isinstance(value["change"], dict):
            return False
        change = value["change"]
    else:
        change = value
    unknown_present = "after_unknown" in change
    unknown = change.get("after_unknown")
    return (set(change).issubset({"actions", "before", "after", "after_unknown",
                                 "before_sensitive", "after_sensitive"})
            and change.get("actions") in (["delete"], ["no-op"])
            and (change["actions"] != ["delete"] or change.get("after") is None)
            and (not unknown_present or type(unknown) is dict and not unknown
                 or type(unknown) is bool and unknown is False))


def _run(args: list[str], cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=dict(env), capture_output=True, text=True,
                          check=False, timeout=300)


def _terraform_quiescent(proc_root: Path = Path("/proc")) -> bool:
    """Fail closed unless no Terraform executable runs as this service UID."""
    if not proc_root.is_dir():
        return False
    try:
        for process in proc_root.iterdir():
            if not process.name.isdecimal():
                continue
            try:
                uid = process.stat().st_uid
            except FileNotFoundError:
                if process.exists():
                    return False
                continue
            if uid != os.getuid():
                continue
            try:
                executable = os.readlink(process / "exe")
            except FileNotFoundError:
                # A process exited between enumeration and inspection.
                if process.exists():
                    return False
                continue
            name = Path(executable.removesuffix(" (deleted)")).name
            if name == "terraform" or name.startswith("terraform-provider-"):
                return False
    except (OSError, ValueError):
        return False
    return True


def recognize_saved_pending_keyed_oci_core_destroy_preview(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    reviewed_plan_sha256: str, job_repository=None, plan_repository=None,
    lease_lookup=None, retired_recognizer: Callable = recognize_pending_keyed_group_retired,
    release_check: Callable = require_devtest_terraform_release,
    command_runner: Callable = _run,
    quiescence_check: Callable[[], bool] = _terraform_quiescent,
) -> StoredJobRun:
    """Explicit DevTest reconciliation of a saved, interrupted preview.

    Current process quiescence cannot prove historical absence of a worker;
    an operator must separately review the pinned plan SHA and this invocation.
    This is never dispatched automatically and never runs Terraform plan/apply.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root
                or not isinstance(reviewed_plan_sha256, str)
                or len(reviewed_plan_sha256) != 64
                or any(c not in "0123456789abcdef" for c in reviewed_plan_sha256)):
            raise ValueError("private reviewed DevTest boundary differs")

        def authority():
            parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
            if operation != _FENCE:
                raise ValueError("keyed fenced source required")
            published = "publishedSource" in parent.input
            expected_phase = "group_retired" if published else "pending_group_retired"
            coordinator = jobs.get(_child_id(core.id))
            if (coordinator is None or coordinator.status != "running"
                    or coordinator.input.get("phase") != expected_phase):
                raise ValueError("keyed group is not retired")
            recognizer = (recognize_provider_keyed_group_retired if published
                          else retired_recognizer)
            retired_rows = recognizer(parent.id, environment=environment, state_root=state_root,
                                      job_repository=jobs, plan_repository=plans,
                                      lease_lookup=lookup)
            plan = plans.get(core.input["corePlanId"])
            evidence = plan.evidence
            if (lookup(parent.target_id) != (plan.id, _FENCE)
                    or plan.id != snapshot["providerScopes"][0]["corePlanId"]
                    or plan.engagement_id != parent.target_id
                    or plan.apply_job_id != core.id or plan.status != "applied"
                    or evidence.get("sketchStateSchema") != "provider-keyed-v2"
                    or core.input.get("corePlanEvidenceSha256") != _fingerprint(evidence)
                    or core.input.get("target") != evidence.get("target")
                    or evidence["target"].get("name") != "barragan-testing"
                    or core.input.get("proxyCount") != evidence.get("proxyCount")
                    or core.input.get("elkEnabled") != evidence.get("elkEnabled")
                    or core.input.get("sshSourceCidrs") != evidence.get("sshSourceCidrs")):
                raise ValueError("reviewed core plan or job differs")
            seals = [event for event in core.events if event.message == _EVENT]
            if (len(seals) != 1 or seals[0].level != "info"
                    or core.events[-2] != seals[0]
                    or core.events[-1].message != "pilot Standard RTI run finished"):
                raise ValueError("applied core state seal differs")
            state_path = Path(evidence["terraformStatePath"])
            run_dir = Path(evidence["runDirectory"])
            data_dir = Path(evidence["terraformDataDir"])
            if (not state_path.is_absolute() or state_path.name != "terraform.tfstate"
                    or state_path.parent.name != "core"
                    or state_path.parents[2] != DEFAULT_TERRAFORM_STATE_ROOT
                    or not run_dir.is_absolute() or run_dir.is_symlink() or not run_dir.is_dir()
                    or not data_dir.is_absolute() or data_dir.is_symlink() or not data_dir.is_dir()
                    or data_dir.parent != state_path.parent
                    or not data_dir.name.startswith("data-core-")
                    or state_path.parent.is_symlink()
                    or state_path.parent.resolve(strict=True) != state_path.parent
                    or DEFAULT_TERRAFORM_STATE_ROOT.is_symlink()):
                raise ValueError("reviewed core workspace differs")
            require_keyed_core_terraform_source_manifest(
                run_dir, evidence["keyedCoreTerraformSourceManifest"])
            lock_path = run_dir / ".terraform.lock.hcl"
            key_path = Path(evidence["sshPublicKeyPath"])
            if (_sha(_read_regular(lock_path)) != evidence["providerLockFingerprint"]
                    or not key_path.is_absolute()
                    or _sha(_read_regular(key_path)) != evidence["publicKeyFingerprint"]):
                raise ValueError("reviewed source, lock or key differs")
            state_bytes = _read_regular(state_path)
            inventory = parse_applied_oci_core_state(
                state_bytes, proxy_count=evidence["proxyCount"],
                elk_enabled=evidence["elkEnabled"],
                compartment_id=evidence["target"]["compartmentId"],
                engagement_name=core.input["engagementName"])
            if seals[0].data != {
                "schema": "applied-oci-core-state-v1",
                "corePlanEvidenceSha256": core.input["corePlanEvidenceSha256"],
                "rawStateSha256": inventory.raw_state_sha256,
                "inventorySha256": inventory.inventory_sha256,
                "lineage": inventory.lineage, "serial": inventory.serial,
                "resourceCount": len(inventory.resources),
            }:
                raise ValueError("applied core state seal differs")
            release = release_check(environment=environment)
            if (release.version != evidence["terraformFingerprint"]
                    or not isinstance(release.path, Path) or not release.path.is_absolute()
                    or len(release.sha256) != 64):
                raise ValueError("reviewed Terraform release differs")
            child_id = f"job-provider-keyed-core-destroy-preview-{core.id.removeprefix('job-')}"
            child = jobs.get(child_id)
            expected_input = {
                "teardownParentId": parent.id, "coreJobId": core.id,
                "corePlanId": plan.id, "scopeSnapshotId": snapshot["snapshotId"],
                "coordinatorJournalSha256": job_event_digest(coordinator.events),
                "stateSha256": inventory.raw_state_sha256,
                "inventorySha256": inventory.inventory_sha256,
            }
            if (child is None or child.action != ACTION or child.status != "running"
                    or child.target != f"engagement:{parent.target_id}"
                    or child.target_type != "engagement"
                    or child.target_id != parent.target_id
                    or child.requested_by != parent.requested_by
                    or child.input != expected_input or child.artifact_refs
                    or child.finished_at is not None or child.started_at is None
                    or child.events != [
                        JobEvent(1, "info", "core destroy preview queued", {}),
                        JobEvent(2, "info", "core destroy preview started", {}),
                    ] or any(row.action in (ACTION, "provider_keyed_core_destroy_apply")
                             and row.input.get("coreJobId") == core.id
                             and row.id != child.id
                             for row in jobs.list_for_engagement(parent.target_id))):
                raise ValueError("saved preview journal or apply child differs")
            plan_path = state_path.parent / f".barragan-core-destroy-{core.id.removeprefix('job-')}.tfplan"
            raw = _read_regular(plan_path)
            plan_stat = plan_path.stat()
            if (not raw or _sha(raw) != reviewed_plan_sha256
                    or plan_path.is_symlink() or not stat.S_ISREG(plan_stat.st_mode)):
                raise ValueError("reviewed saved plan differs")
            return (parent, core, coordinator, plan, child, retired_rows, recognizer,
                    evidence, state_path, state_bytes, inventory, run_dir, data_dir,
                    lock_path, key_path, release, plan_path, plan_stat)

        first = authority()
        if not quiescence_check():
            raise ValueError("Terraform worker quiescence unproved")
        (parent, core, coordinator, plan, child, retired_rows, recognizer,
         evidence, state_path, state_bytes, inventory, run_dir, data_dir,
         lock_path, key_path, release, plan_path, plan_stat) = first
        env = {**barragan_subprocess_env(), "TF_DATA_DIR": str(data_dir)}
        shown = command_runner([str(release.path), "show", "-json", str(plan_path)],
                               run_dir, env)
        if shown.returncode != 0 or not isinstance(shown.stdout, str):
            raise ValueError("saved core destroy show failed")
        _exact_destroy(json.loads(shown.stdout), inventory, _state_data_ids(state_bytes))
        if not quiescence_check():
            raise ValueError("Terraform worker quiescence changed")
        second = authority()
        if (second[:17] != first[:17]
                or (second[17].st_dev, second[17].st_ino) != (plan_stat.st_dev, plan_stat.st_ino)
                or _sha(_read_regular(plan_path)) != reviewed_plan_sha256
                or lookup(parent.target_id) != (plan.id, _FENCE)
                or not quiescence_check()):
            raise ValueError("core preview authority changed during show")
        finished = jobs.finish_if_running(
            child, status="succeeded", finished_at=_now(),
            event=JobEvent(3, "info", "core destroy preview saved", {
                "planPath": str(plan_path), "planSha256": reviewed_plan_sha256,
                "planDevice": plan_stat.st_dev, "planInode": plan_stat.st_ino,
                "stateSha256": inventory.raw_state_sha256,
                "inventorySha256": inventory.inventory_sha256,
                "resourceCount": len(inventory.resources),
                "terraformBinarySha256": release.sha256,
                "sourceManifestSha256": _fingerprint(evidence["keyedCoreTerraformSourceManifest"]),
            }))
        if finished is None:
            raise ValueError("saved core preview journal commit failed")
        return finished
    except Exception:
        raise KeyedCoreDestroyPreviewAttention(
            "saved core destroy preview is unverified; no core destroy was applied"
        ) from None


def preview_pending_keyed_oci_core_destroy(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, lease_lookup=None,
    retired_recognizer: Callable = recognize_pending_keyed_group_retired,
    release_check: Callable = require_devtest_terraform_release,
    command_runner: Callable = _run,
) -> StoredJobRun:
    """Journal and inspect one saved full OCI destroy plan, without GO/apply."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (environment != "devtest" or state_root != _default_state_root()
                or not isinstance(state_root, Path) or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("private DevTest boundary differs")
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        if operation != _FENCE:
            raise ValueError("keyed fenced source required")
        published = "publishedSource" in parent.input
        expected_phase = "group_retired" if published else "pending_group_retired"
        coordinator = jobs.get(_child_id(core.id))
        if (coordinator is None or coordinator.input.get("phase") != expected_phase
                or coordinator.status != "running"):
            raise ValueError("keyed group is not retired")

        def prove_retired():
            # A caller-supplied pending recognizer cannot substitute for the
            # published generation's sealed historical source.
            recognizer = (recognize_provider_keyed_group_retired if published
                          else retired_recognizer)
            return recognizer(parent.id, environment=environment, state_root=state_root,
                              job_repository=jobs, plan_repository=plans,
                              lease_lookup=lookup)

        retired_rows = prove_retired()
        plan = plans.get(core.input["corePlanId"])
        evidence = plan.evidence
        if (plan.id != snapshot["providerScopes"][0]["corePlanId"]
                or plan.apply_job_id != core.id or plan.status != "applied"
                or evidence.get("sketchStateSchema") != "provider-keyed-v2"
                or core.input.get("corePlanEvidenceSha256") != _fingerprint(evidence)
                or core.input.get("target") != evidence.get("target")
                or core.input.get("proxyCount") != evidence.get("proxyCount")
                or core.input.get("elkEnabled") != evidence.get("elkEnabled")):
            raise ValueError("reviewed core plan or job differs")
        seal_events = [event for event in core.events if event.message == _EVENT]
        if (len(seal_events) != 1 or seal_events[0].level != "info"
                or len(core.events) < 2 or core.events[-2] != seal_events[0]
                or core.events[-1].message != "pilot Standard RTI run finished"):
            raise ValueError("applied core state seal is missing")
        seal = seal_events[0].data
        state_path = Path(evidence["terraformStatePath"])
        run_directory = Path(evidence["runDirectory"])
        data_dir = Path(evidence["terraformDataDir"])
        if (not state_path.is_absolute() or state_path.name != "terraform.tfstate"
                or state_path.parent.name != "core"
                or state_path.parents[2] != DEFAULT_TERRAFORM_STATE_ROOT
                or not run_directory.is_absolute() or not data_dir.is_absolute()
                or run_directory.is_symlink() or not run_directory.is_dir()
                or data_dir.is_symlink() or not data_dir.is_dir()
                or data_dir.parent != state_path.parent
                or not data_dir.name.startswith("data-core-")
                or state_path.parent.is_symlink() or state_path.parent.resolve(strict=True) != state_path.parent
                or DEFAULT_TERRAFORM_STATE_ROOT.is_symlink()):
            raise ValueError("reviewed core workspace or state path differs")
        require_keyed_core_terraform_source_manifest(
            run_directory, evidence["keyedCoreTerraformSourceManifest"])
        lock_path = run_directory / ".terraform.lock.hcl"
        if _sha(_read_regular(lock_path)) != evidence.get("providerLockFingerprint"):
            raise ValueError("provider lock differs")
        public_key_path = Path(evidence["sshPublicKeyPath"])
        if (not public_key_path.is_absolute()
                or _sha(_read_regular(public_key_path)) != evidence.get("publicKeyFingerprint")
                or core.input.get("sshSourceCidrs") != evidence.get("sshSourceCidrs")):
            raise ValueError("reviewed core key or trusted source differs")
        state_bytes = _read_regular(state_path)
        inventory = parse_applied_oci_core_state(
            state_bytes, proxy_count=evidence["proxyCount"],
            elk_enabled=evidence["elkEnabled"],
            compartment_id=evidence["target"]["compartmentId"],
            engagement_name=core.input["engagementName"],
        )
        if seal != {
            "schema": "applied-oci-core-state-v1",
            "corePlanEvidenceSha256": core.input["corePlanEvidenceSha256"],
            "rawStateSha256": inventory.raw_state_sha256,
            "inventorySha256": inventory.inventory_sha256,
            "lineage": inventory.lineage, "serial": inventory.serial,
            "resourceCount": len(inventory.resources),
        }:
            raise ValueError("applied core state seal differs")
        release = release_check(environment=environment)
        if (release.version != evidence.get("terraformFingerprint")
                or not isinstance(release.path, Path)
                or not release.path.is_absolute() or len(release.sha256) != 64):
            raise ValueError("reviewed Terraform release differs")
        child_id = f"job-provider-keyed-core-destroy-preview-{core.id.removeprefix('job-')}"
        if jobs.get(child_id) is not None or any(
                row.action == ACTION and row.input.get("coreJobId") == core.id
                for row in jobs.list_for_engagement(parent.target_id)):
            raise ValueError("core destroy preview child already exists")
        child = StoredJobRun(
            id=child_id, action=ACTION, status="queued", target=f"engagement:{parent.target_id}",
            target_type="engagement", target_id=parent.target_id,
            requested_by=parent.requested_by,
            input={"teardownParentId": parent.id, "coreJobId": core.id,
                   "corePlanId": plan.id, "scopeSnapshotId": snapshot["snapshotId"],
                   "coordinatorJournalSha256": job_event_digest(coordinator.events),
                   "stateSha256": inventory.raw_state_sha256,
                   "inventorySha256": inventory.inventory_sha256},
            artifact_refs=[], created_at=_now(), started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "core destroy preview queued", {})],
        )
        saved = jobs.save_if_absent(child)
        if saved is None or saved.id != child.id or saved.input != child.input or saved.events != child.events:
            raise ValueError("core destroy preview reservation lost")
        running = jobs.start_if_queued(
            saved, started_at=_now(), event=JobEvent(2, "info", "core destroy preview started", {}))
        if running is None:
            raise ValueError("core destroy preview start lost")
        # The durable child is a one-shot command fence. Any interruption now
        # leaves it running for explicit reconciliation, never implicit replay.
        if (jobs.get(parent.id) != parent or jobs.get(coordinator.id) != coordinator
                or jobs.get(core.id) != core or plans.get(plan.id) != plan
                or lookup(parent.target_id) != (plan.id, _FENCE)
                or _sha(_read_regular(state_path)) != inventory.raw_state_sha256):
            raise ValueError("core preview authority changed after reservation")
        if published and prove_retired() != retired_rows:
            raise ValueError("published retired source changed before plan")
        plan_path = state_path.parent / f".barragan-core-destroy-{core.id.removeprefix('job-')}.tfplan"
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
        result = command_runner(command, run_directory, env)
        if result.returncode != 2:
            raise ValueError("Terraform destroy preview did not produce exact changes")
        plan_stat = plan_path.stat()
        if (plan_path.is_symlink() or not stat.S_ISREG(plan_stat.st_mode)
                or (plan_stat.st_dev, plan_stat.st_ino) != (identity.st_dev, identity.st_ino)):
            raise ValueError("saved core destroy plan identity changed")
        plan_bytes = _read_regular(plan_path)
        if not plan_bytes:
            raise ValueError("saved core destroy plan is empty")
        shown = command_runner([str(release.path), "show", "-json", str(plan_path)],
                               run_directory, env)
        if shown.returncode != 0 or not isinstance(shown.stdout, str):
            raise ValueError("saved core destroy show failed")
        _exact_destroy(json.loads(shown.stdout), inventory, _state_data_ids(state_bytes))
        if (jobs.get(parent.id) != parent or jobs.get(coordinator.id) != coordinator
                or jobs.get(running.id) != running or plans.get(plan.id) != plan
                or lookup(parent.target_id) != (plan.id, _FENCE)
                or _sha(_read_regular(state_path)) != inventory.raw_state_sha256
                or _sha(_read_regular(plan_path)) != _sha(plan_bytes)
                or _sha(_read_regular(lock_path)) != evidence["providerLockFingerprint"]
                or _sha(_read_regular(public_key_path)) != evidence["publicKeyFingerprint"]
                or release_check(environment=environment) != release):
            raise ValueError("core preview authority changed during plan")
        if published and prove_retired() != retired_rows:
            raise ValueError("published retired source changed during plan")
        require_keyed_core_terraform_source_manifest(
            run_directory, evidence["keyedCoreTerraformSourceManifest"])
        finished = jobs.finish_if_running(
            running, status="succeeded", finished_at=_now(),
            event=JobEvent(3, "info", "core destroy preview saved", {
                "planPath": str(plan_path), "planSha256": _sha(plan_bytes),
                "planDevice": plan_stat.st_dev, "planInode": plan_stat.st_ino,
                "stateSha256": inventory.raw_state_sha256,
                "inventorySha256": inventory.inventory_sha256,
                "resourceCount": len(inventory.resources),
                "terraformBinarySha256": release.sha256,
                "sourceManifestSha256": _fingerprint(evidence["keyedCoreTerraformSourceManifest"]),
            }),
        )
        if finished is None:
            raise ValueError("core destroy preview journal commit failed")
        return finished
    except Exception:
        raise KeyedCoreDestroyPreviewAttention(
            "core destroy preview is unverified; no core destroy was applied"
        ) from None
