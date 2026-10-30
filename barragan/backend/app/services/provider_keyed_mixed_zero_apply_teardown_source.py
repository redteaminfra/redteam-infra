# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only evidence for a mixed generation stopped before any Sketch Apply.

This is a review source, not destroy authority or provider-absence proof. It
does not run Terraform or contact a provider, and it has no public caller.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, _receipt_data, _records, _validate_parent, validate_mixed_initial_apply_seal,
)
from app.services import provider_keyed_mixed_linode_saved_plan as linode
from app.services import provider_keyed_mixed_digitalocean_saved_plan as digitalocean
from app.services.provider_keyed_mixed_plan_journal import _Journal
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_core_destroy_preview import _read_regular
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, read_provider_topology
from app.services.provider_keyed_terraform_release import _REVIEWED_PATH, _REVIEWED_SHA256
from app.services import provider_keyed_terraform_release as terraform_release
from app.services.provider_keyed_saved_plan_runner import _require_absent_initial_state
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, _valid_core_destroy_show_triple,
    _mixed_core_no_go_attempts, job_event_digest,
)
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository,
)
from app.storage.sketch_chain_repository import (
    SqlAlchemySketchChainRepository, _canonical_keyed_inspector_record,
)
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository


class MixedZeroApplySourceError(ValueError):
    """The zero-Apply generation or retained ownership cannot be proven."""


@dataclass(frozen=True)
class MixedZeroApplySource:
    engagement_id: str
    core_job_id: str
    core_plan_id: str
    parent_job_id: str
    parent_journal_sha256: str
    review_fingerprint: str
    ordered_providers: tuple[str, str]
    provider_receipt_sha256: tuple[str, str]
    core_state_sha256: str
    core_inventory_sha256: str
    owned_inspector_record_ids: tuple[str, str]


_MODULES = {"linode": linode, "digitalocean": digitalocean}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _apply_pre_go_prefix(child, *, core, plan, inventory, preview,
                         interrupted=False, terraform_path: Path | None = None) -> None:
    """Accept only the exact, still pre-GO one-shot Apply journal prefix."""
    events = child.events
    if len(events) >= 11 and events[8].message == "mixed core pre-GO Apply recovery claimed":
        _mixed_core_no_go_attempts(events)
        events = events[:8]
    receipt = preview.events[2].data
    plan_path = receipt["planPath"]
    state_path = plan.evidence["terraformStatePath"]
    arguments = {
        "show": [str(terraform_path or terraform_release._REVIEWED_PATH), "show", "-json", plan_path],
        "apply": [str(terraform_path or terraform_release._REVIEWED_PATH), "apply", "-input=false", "-lock=true",
                  "-no-color", f"-state={state_path}", plan_path],
    }

    def payload(index: int) -> dict:
        data = events[index - 1].data
        if type(data) is not dict:
            raise ValueError("mixed core Apply event payload differs")
        return data

    def present(index: int) -> bool:
        return len(events) >= index

    def hash_value(value) -> bool:
        return type(value) is str and len(value) == 64 and all(
            char in "0123456789abcdef" for char in value)

    for number, phase in ((3, "show"), (7, "apply")):
        if not present(number):
            continue
        data = payload(number)
        if (set(data) != {"phase", "invocationId", "argvSha256"}
                or data["phase"] != phase or not isinstance(data["invocationId"], str)
                or not data["invocationId"]
                or data["argvSha256"] != _fingerprint(arguments[phase])):
            raise ValueError("mixed core Apply command intent differs")
    for number, phase in ((4, "show"), (8, "apply")):
        if not present(number):
            continue
        data = payload(number)
        if (set(data) != {"phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
                or data["phase"] != phase
                or data["invocationId"] != payload(number - 1)["invocationId"]
                or not isinstance(data["bootId"], str) or not data["bootId"]
                or any(type(data[key]) is not int or data[key] < 1
                       for key in ("pid", "pgid", "startTicks"))
                or data["pid"] != data["pgid"]):
            raise ValueError("mixed core Apply command start differs")
    if present(5):
        data = payload(5)
        if (set(data) != {"phase", "invocationId", "returnCode", "stdoutBytes",
                         "stderrBytes", "stdoutTruncated", "stderrTruncated"}
                or data["phase"] != "show"
                or data["invocationId"] != payload(3)["invocationId"]
                or data["returnCode"] != 0
                or any(type(data[key]) is not int or data[key] < 0
                       for key in ("stdoutBytes", "stderrBytes"))
                or data["stdoutTruncated"] is not False
                or data["stderrTruncated"] is not False):
            raise ValueError("mixed core Apply show result differs")
    if present(6):
        data = payload(6)
        ids = {row.address: row.ocid for row in inventory.resources}
        witness = data.get("ociVisibilityWitness")
        expected = {"coreJobId", "corePlanId", "preDestroyStateSha256",
                    "inventorySha256", "lineage", "serial", "resourceIds",
                    "resourceIdsSha256", "planSha256", "ociCliPath", "ociCliSha256",
                    "ociVisibilityWitness", "inspectorReadySha256",
                    "providerObservationSha256"}
        if (set(data) != expected or data["coreJobId"] != core.id
                or data["corePlanId"] != plan.id
                or data["preDestroyStateSha256"] != inventory.raw_state_sha256
                or data["inventorySha256"] != inventory.inventory_sha256
                or data["lineage"] != inventory.lineage or data["serial"] != inventory.serial
                or data["resourceIds"] != ids
                or data["resourceIdsSha256"] != _fingerprint(ids)
                or data["planSha256"] != receipt["planSha256"]
                or not isinstance(data["ociCliPath"], str)
                or not Path(data["ociCliPath"]).is_absolute()
                or not hash_value(data["ociCliSha256"])
                or _digest(_read_regular(Path(data["ociCliPath"]))) != data["ociCliSha256"]
                or not hash_value(data["inspectorReadySha256"])
                or not hash_value(data["providerObservationSha256"])
                or type(witness) is not dict
                or set(witness) != {"phase", "inventory_sha256", "resource_ids_sha256",
                                        "compartment_id", "region", "auth",
                                        "principal_sha256", "evidence_sha256"}
                or witness["phase"] != "present"
                or witness["inventory_sha256"] != inventory.inventory_sha256
                or witness["resource_ids_sha256"] != _fingerprint(ids)
                or witness["compartment_id"] != plan.evidence["target"]["compartmentId"]
                or witness["region"] != plan.evidence["target"]["region"]
                or witness["auth"] != "instance_principal"
                or not hash_value(witness["principal_sha256"])
                or not hash_value(witness["evidence_sha256"])):
            raise ValueError("mixed core Apply prestate seal differs")
    if present(9):
        data = payload(9)
        witness = data.get("ociVisibilityWitness")
        first = payload(6)["ociVisibilityWitness"]
        expected = {"inspectorReadySha256", "providerObservationSha256",
                    "ociVisibilityWitness", "ociVisibilityWitnessSha256"}
        if interrupted:
            expected.add("postSketchAbsence")
        saved_absence = data.get("postSketchAbsence") if interrupted else None
        if (set(data) != expected
                or data["inspectorReadySha256"] != payload(6)["inspectorReadySha256"]
                or not hash_value(data["providerObservationSha256"])
                or (interrupted and (
                    type(saved_absence) is not dict
                    or saved_absence.get("checkpoint_sha256")
                    != data["providerObservationSha256"]))
                or type(witness) is not dict or set(witness) != set(first)
                or any(witness[key] != first[key] for key in first if key != "evidence_sha256")
                or not hash_value(witness["evidence_sha256"])
                or data["ociVisibilityWitnessSha256"] != _fingerprint(witness)):
            raise ValueError("mixed core Apply GO support differs")


def canonical_mixed_core_apply_events(child) -> list[JobEvent]:
    """Validate the one-time SHOW recovery suffix and return canonical events.

    The original four-event SHOW start, optionally with its successful result,
    remains immutable. A recovery marker and one new SHOW triple precede the
    normal prestate/GO suffix. Apply replay cannot be normalized.
    """
    events = child.events
    if len(events) == 11:
        return events
    if (len(events) >= 14 and (len(events) - 8) % 3 == 0
            and events[8].message == "mixed core pre-GO Apply recovery claimed"):
        _mixed_core_no_go_attempts(events[:-3])
        retry = events[-5:]
        if ([(row.level, row.message) for row in retry] != [
                ("info", "core destroy command intent fenced"),
                ("info", "core destroy command started before GO"),
                ("info", "core destroy GO support rechecked"),
                ("info", "core destroy command result fenced"),
                ("info", "core destroy applied; provider absence pending")]
                or retry[3].data.get("phase") != "apply"
                or retry[3].data.get("invocationId") != retry[0].data.get("invocationId")):
            raise ValueError("mixed core pre-GO Apply recovery journal differs")
        return [replace(event, sequence=index) for index, event in enumerate(
            [*events[:6], *retry], start=1)]
    if len(events) not in (14, 15):
        raise ValueError("mixed core Apply journal length differs")
    original_length = len(events) - 10
    original = events[:original_length]
    marker = events[original_length]
    retry = events[original_length + 1:original_length + 4]
    if (marker != JobEvent(original_length + 1, "info", "mixed core SHOW recovery claimed", {
            "originalJournalSha256": job_event_digest(original),
            "originalInvocationId": original[2].data.get("invocationId"),
        }) or (original_length == 5 and not _valid_core_destroy_show_triple(original, 2))
            or original[2].data.get("phase") != "show"
            or original[3].data.get("phase") != "show"
            or original[3].data.get("invocationId") != original[2].data.get("invocationId")
            or [(row.level, row.message) for row in events[:2]] != [
                ("info", "mixed core destroy apply queued"),
                ("info", "mixed core destroy apply started"),
            ]
            or [(row.level, row.message) for row in original[2:4]] != [
                ("info", "core destroy command intent fenced"),
                ("info", "core destroy command started before GO"),
            ]
            or [(row.level, row.message) for row in retry] != [
                ("info", "core destroy command intent fenced"),
                ("info", "core destroy command started before GO"),
                ("info", "core destroy command result fenced"),
            ]
            or not _valid_core_destroy_show_triple(events, original_length + 1)
            or [row.sequence for row in events] != list(range(1, len(events) + 1))
            or events[0].data != {} or events[1].data != {}
            or retry[0].data.get("argvSha256") != original[2].data.get("argvSha256")
            or retry[0].data.get("invocationId") == original[2].data.get("invocationId")
            ):
        raise ValueError("mixed core SHOW recovery marker differs")
    return [replace(event, sequence=index) for index, event in enumerate(
        [*events[:2], *events[original_length + 1:]], start=1)]


def _successful_show(rows: list[dict], receipt_sha: str) -> bool:
    def completed(row: dict) -> bool:
        data = row.get("data", {})
        return (row.get("phase") == "show" and row.get("kind") == "result"
                and data.get("returnCode") == 0
                and data.get("stdoutTruncated") is False
                and data.get("stderrTruncated") is False)
    return bool(rows and completed(rows[-1])
                and any(completed(row) and row.get("sha256") == receipt_sha for row in rows))


def _provider_receipt(provider: str, intent, state_root: Path) -> dict:
    module = _MODULES[provider]
    fingerprint = _digest(f"{provider}\0{intent.provider_connection_id}".encode())
    root = state_root / intent.engagement_id / "provider-keyed-v2" / provider / fingerprint
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
        raise ValueError("provider workspace path changed")
    marker = module._json(root / ".barragan-provider-keyed-state.json", private=False)
    if marker.get("engagement_id") != intent.engagement_id:
        raise ValueError("provider workspace engagement changed")
    provider_root = root.parent
    if any(path.name != fingerprint for path in provider_root.iterdir()):
        raise ValueError("unexpected provider connection workspace")
    source_files = marker.get("source_files")
    if not isinstance(source_files, dict):
        raise ValueError("provider source inventory changed")
    source_sha = _digest(json.dumps(source_files, sort_keys=True).encode())
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data", "provider-keyed-v2",
        provider, intent.provider_connection_id, fingerprint,
        module._SOURCE_REVISION, source_sha,
    )
    # The audited source validator recomputes rendered files and provider lock.
    module.require_audited_workspace(workspace)
    if read_provider_topology(workspace) != intent.topology:
        raise ValueError("provider topology changed")
    _require_absent_initial_state(workspace)
    if ((root / ".barragan-apply-phase.json").exists()
            or (root / ".barragan-apply-phase.json").is_symlink()):
        raise ValueError("provider Apply phase exists")
    receipt = module._json(root / module._RECEIPT)
    if (receipt.get("terraformBinaryPath") != str(_REVIEWED_PATH)
            or receipt.get("terraformBinarySha256") != _REVIEWED_SHA256):
        raise ValueError("provider plan Terraform release changed")
    binary = root / module._PLAN
    module._regular(binary)
    if not binary.stat().st_size:
        raise ValueError("saved provider plan is empty")
    journal = _Journal(root / module._JOURNAL, MixedZeroApplySourceError)
    if (not journal.rows or journal.pending() is not None
            or not journal.plan_intended()
            or not any(row["phase"] == "plan" and row["kind"] == "result"
                       and row["data"].get("returnCode") == 0
                       and row["data"].get("stdoutTruncated") is False
                       and row["data"].get("stderrTruncated") is False
                       for row in journal.rows)
            or not _successful_show(journal.rows, receipt.get("journalSha256"))):
        raise ValueError("provider plan journal is incomplete")
    inputs = root.parents[1] / ".plan-material" / provider / "inputs.json"
    private_root = inputs.parent
    expected_inputs = {**intent.nonsecret_varfile,
                       "ssh_pub_key_path": str(private_root / "admin-public"),
                       "ssh_priv_key_path": str(private_root / "admin-private"),
                       "ssh_config_path": str(private_root / "ssh-output")}
    module._regular(inputs)
    if inputs.read_bytes() != (json.dumps(expected_inputs, sort_keys=True) + "\n").encode():
        raise ValueError("provider plan inputs changed")
    expected = {**module._snapshot(intent, workspace,
                                   Path(receipt["terraformBinaryPath"]), inputs),
                "planSha256": module._sha(binary),
                "showJsonSha256": receipt.get("showJsonSha256"),
                "journalSha256": receipt.get("journalSha256")}
    if (receipt != expected or not isinstance(receipt["showJsonSha256"], str)
            or len(receipt["showJsonSha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in receipt["showJsonSha256"])):
        raise ValueError("provider plan receipt changed")
    return receipt


def _core_inventory(core, plan, core_state_root: Path):
    evidence = plan.evidence
    if (core.status != "succeeded" or plan.status != "applied"
            or plan.apply_job_id != core.id
            or core.input.get("corePlanEvidenceSha256") != _fingerprint(evidence)
            or core.input.get("target") != evidence.get("target")
            or core.input.get("proxyCount") != evidence.get("proxyCount")
            or core.input.get("elkEnabled") != evidence.get("elkEnabled")):
        raise ValueError("applied core review changed")
    state_path = Path(evidence["terraformStatePath"])
    if (not state_path.is_absolute() or state_path.name != "terraform.tfstate"
            or state_path.parent.name != "core" or state_path.parents[2] != core_state_root
            or state_path.is_symlink() or not state_path.is_file()):
        raise ValueError("retained core state path changed")
    from app.services.provider_keyed_core_destroy_preview import _read_regular
    inventory = parse_applied_oci_core_state(
        _read_regular(state_path), proxy_count=evidence["proxyCount"],
        elk_enabled=evidence["elkEnabled"],
        compartment_id=evidence["target"]["compartmentId"],
        engagement_name=core.input["engagementName"],
    )
    seals = [event for event in core.events if event.message == "applied OCI core state sealed"]
    if (len(seals) != 1 or len(core.events) < 2 or core.events[-2] != seals[0]
            or core.events[-1].message != "pilot Standard RTI run finished"
            or seals[0].level != "info" or seals[0].data != {
        "schema": "applied-oci-core-state-v1",
        "corePlanEvidenceSha256": core.input["corePlanEvidenceSha256"],
        "rawStateSha256": inventory.raw_state_sha256,
        "inventorySha256": inventory.inventory_sha256,
        "lineage": inventory.lineage, "serial": inventory.serial,
        "resourceCount": len(inventory.resources),
    }):
        raise ValueError("retained core state seal changed")
    return inventory


def _owned_inspector_records(engagement_id: str, jobs, resources) -> tuple[str, str]:
    """Prove owned records exist; current ready host is a later review gate."""
    active = resources.list_for_engagement(engagement_id)
    if (len(active) != 2 or not all(_canonical_keyed_inspector_record(row)
                                     and row.provider == "linode"
                                     and row.status.lower() not in {"destroyed", "deleted", "retired", "absent"}
                                     for row in active)
            or {row.resource_type for row in active} != {"inspector_instance", "inspector_firewall"}):
        raise ValueError("retained Inspector resources differ")
    for row in active:
        owner = jobs.get(row.adoption_job_id)
        if (owner is None or owner.action not in {"inspector_inspection", "inspector_readiness"}
                or owner.status != "succeeded" or owner.target_id != engagement_id):
            raise ValueError("retained Inspector adoption differs")
    host = next(row for row in active if row.resource_type == "inspector_instance")
    firewall = next(row for row in active if row.resource_type == "inspector_firewall")
    if firewall.metadata.get("inspectorHostResourceId") != host.resource_id:
        raise ValueError("Inspector firewall host changed")
    return tuple(sorted(row.id for row in active))


def audit_mixed_zero_apply_teardown_source(
    engagement_id: str, core_job_id: str, *, environment: str, state_root: Path,
    core_state_root: Path, lease_owner: str, job_repository=None,
    engagement_repository=None, sketch_repository=None, plan_repository=None,
    credential_repository=None, ssh_key_repository=None, provider_resource_repository=None,
    lease_lookup=None, lease_operation: str = "provider_keyed_initial",
) -> MixedZeroApplySource:
    """Reopen local evidence under the initial lease or exact queued cleanup fence."""
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root()
                or not isinstance(core_state_root, Path)
                or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT):
            raise ValueError("unsupported zero-Apply source root")
        jobs = job_repository or SqlAlchemyJobRepository()
        engagements = engagement_repository or SqlAlchemyEngagementRepository()
        sketches = sketch_repository or SqlAlchemySketchChainRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        lookup = lease_lookup or _db_lease_lookup
        if lease_operation not in {"provider_keyed_initial", "provider_keyed_teardown_fence"}:
            raise ValueError("unsupported source lease operation")
        cleanup = None
        if lease_operation == "provider_keyed_teardown_fence":
            from app.services.provider_keyed_mixed_zero_apply_cleanup import (
                ACTION as CLEANUP_ACTION, _PHASE as CLEANUP_PHASE,
                _parent_id as cleanup_parent_id,
            )
            cleanup = jobs.get(cleanup_parent_id(core_job_id))
            if (cleanup is None or cleanup.action != CLEANUP_ACTION
                    or cleanup.status != "queued" or cleanup.started_at is not None
                    or cleanup.finished_at is not None or cleanup.artifact_refs != []
                    or cleanup.target != f"engagement:{engagement_id}"
                    or cleanup.target_type != "engagement"
                    or cleanup.target_id != engagement_id
                    or not isinstance(cleanup.input, dict)
                    or cleanup.input.get("schema") != "mixed-zero-apply-cleanup-v1"
                    or cleanup.input.get("engagementId") != engagement_id
                    or cleanup.input.get("coreJobId") != core_job_id
                    or cleanup.input.get("corePlanId") != lease_owner
                    or cleanup.input.get("phase") != CLEANUP_PHASE
                    or cleanup.input.get("mutation") is not True
                    or not isinstance(cleanup.input.get("source"), dict)
                    or cleanup.input.get("sourceSha256") != _fingerprint(cleanup.input["source"])
                    or cleanup.events != [JobEvent(
                        1, "info", "mixed zero-Apply cleanup fenced",
                        {"sourceSha256": cleanup.input["sourceSha256"]})]):
                raise ValueError("queued mixed cleanup parent changed")
        core, plan, ids, order, intents = _records(
            core_job_id, engagement_id, lease_owner, lookup, engagements,
            sketches, jobs, plans, credentials, keys,
            lease_operation=lease_operation)
        parent = jobs.get(_parent_id(core.id))
        if parent is None:
            raise ValueError("mixed plan parent is absent")
        _validate_parent(parent, core, plan, ids, order)
        if parent.input["phase"] not in {"both_plans_saved", "apply_sealed"}:
            raise ValueError("mixed plans were not both saved")
        if parent.input["phase"] == "apply_sealed":
            validate_mixed_initial_apply_seal(parent, intents=intents)
        related = jobs.list_for_engagement(engagement_id)
        allowed = {core.id, parent.id}
        if cleanup is not None:
            allowed.add(cleanup.id)
        preview = None
        if cleanup is not None:
            from app.services.provider_keyed_mixed_zero_apply_core_preview import (
                ACTION as PREVIEW_ACTION, _child_id as preview_child_id,
            )
            preview = jobs.get(preview_child_id(core.id))
            if preview is not None:
                expected_events = [JobEvent(1, "info", "mixed core destroy preview queued", {})]
                if preview.status in {"running", "succeeded"}:
                    expected_events.append(JobEvent(2, "info", "mixed core destroy preview started", {}))
                if (preview.action != PREVIEW_ACTION
                        or preview.status not in {"queued", "running", "succeeded"}
                        or preview.target != f"engagement:{engagement_id}"
                        or preview.target_type != "engagement" or preview.target_id != engagement_id
                        or preview.requested_by != cleanup.requested_by
                        or preview.artifact_refs != []
                        or (preview.finished_at is None) != (preview.status != "succeeded")
                        or (preview.started_at is None) != (preview.status == "queued")
                        or (preview.events != expected_events if preview.status != "succeeded"
                            else (len(preview.events) != 3
                                  or preview.events[:2] != expected_events
                                  or preview.events[2].sequence != 3
                                  or preview.events[2].level != "info"
                                  or preview.events[2].message != "mixed core destroy preview saved"))):
                    raise ValueError("mixed core preview child differs")
                allowed.add(preview.id)
        apply_child = None
        if cleanup is not None:
            from app.services.provider_keyed_mixed_zero_apply_core_apply import (
                ACTION as MIXED_APPLY_ACTION, _child_id as mixed_apply_child_id,
            )
            apply_child = jobs.get(mixed_apply_child_id(core.id))
            if apply_child is not None:
                messages = [
                    "mixed core destroy apply queued", "mixed core destroy apply started",
                    "core destroy command intent fenced", "core destroy command started before GO",
                    "core destroy command result fenced", "core destroy prestate identity fenced",
                    "core destroy command intent fenced", "core destroy command started before GO",
                    "core destroy GO support rechecked",
                ]
                events = apply_child.events
                if (preview is None or preview.status != "succeeded"
                        or apply_child.action != MIXED_APPLY_ACTION
                        or apply_child.status not in {"queued", "running"}
                        or apply_child.target != f"engagement:{engagement_id}"
                        or apply_child.target_type != "engagement"
                        or apply_child.target_id != engagement_id
                        or apply_child.requested_by != cleanup.requested_by
                        or apply_child.artifact_refs != [] or apply_child.finished_at is not None
                        or (apply_child.started_at is None) != (apply_child.status == "queued")
                        or len(events) < 1 or len(events) > len(messages)
                        or [(event.sequence, event.level, event.message) for event in events]
                        != [(index, "info", message) for index, message in
                            enumerate(messages[:len(events)], 1)]
                        or events[0].data != {}
                        or (len(events) > 1 and events[1].data != {})):
                    raise ValueError("mixed core Apply child differs")
                allowed.add(apply_child.id)
        for row in related:
            if row.id in allowed:
                if row.id == core.id and row != core or row.id == parent.id and row != parent:
                    raise ValueError("mixed source job changed")
                if cleanup is not None and row.id == cleanup.id and row != cleanup:
                    raise ValueError("mixed cleanup parent changed")
                if preview is not None and row.id == preview.id and row != preview:
                    raise ValueError("mixed core preview child changed")
                if apply_child is not None and row.id == apply_child.id and row != apply_child:
                    raise ValueError("mixed core Apply child changed")
                continue
            if (row.action not in {"inspector_inspection", "inspector_readiness"}
                    or row.status != "succeeded" or row.target_id != engagement_id):
                raise ValueError("unknown or partial Sketch mutation exists")
        chains = sketches.list_for_engagement(engagement_id)
        if (len(chains) != 2 or {row.chain_id for row in chains} != set(ids)
                or any(row.status != "pending" or row.nodes or row.deploy_job_id
                       or row.teardown_job_id for row in chains)):
            raise ValueError("mixed chain was applied or published")
        receipts = []
        for index, provider in enumerate(order):
            receipt = _provider_receipt(provider, intents[provider], state_root)
            data = _receipt_data(provider, ids[index], receipt, intents[provider])
            if parent.events[index + 2].data != data:
                raise ValueError("mixed parent receipt differs")
            receipts.append(data)
        if parent.events[4].data != {
            "firstReceiptSha256": receipts[0]["receiptSha256"],
            "secondReceiptSha256": receipts[1]["receiptSha256"],
            "reviewFingerprint": intents["linode"].review_fingerprint,
        }:
            raise ValueError("joined plan receipt differs")
        core_inventory = _core_inventory(core, plan, core_state_root)
        if apply_child is not None:
            _apply_pre_go_prefix(apply_child, core=core, plan=plan,
                                 inventory=core_inventory, preview=preview)
        inspector = _owned_inspector_records(engagement_id, jobs, resources)
        _require_lease(lookup, engagement_id, lease_owner, operation=lease_operation)
        if jobs.get(parent.id) != parent or jobs.get(core.id) != core:
            raise ValueError("mixed source changed during audit")
        result = MixedZeroApplySource(
            engagement_id, core.id, plan.id, parent.id, job_event_digest(parent.events),
            intents["linode"].review_fingerprint, tuple(order),
            tuple(row["receiptSha256"] for row in receipts),
            core_inventory.raw_state_sha256, core_inventory.inventory_sha256, inspector,
        )
        if cleanup is not None:
            sealed = json.loads(json.dumps(asdict(result), sort_keys=True))
            if (cleanup.input != {
                    "schema": "mixed-zero-apply-cleanup-v1",
                    "engagementId": engagement_id, "coreJobId": core.id,
                    "corePlanId": plan.id, "source": sealed,
                    "sourceSha256": _fingerprint(sealed),
                    "phase": CLEANUP_PHASE, "mutation": True,
                } or jobs.get(cleanup.id) != cleanup):
                raise ValueError("mixed cleanup source seal changed")
            if preview is not None and preview.input != {
                    "schema": "mixed-zero-apply-core-preview-v1",
                    "teardownParentId": cleanup.id, "coreJobId": core.id,
                    "corePlanId": plan.id, "sourceSha256": _fingerprint(asdict(result)),
                    "parentJournalSha256": job_event_digest(cleanup.events),
                    "stateSha256": result.core_state_sha256,
                    "inventorySha256": result.core_inventory_sha256,
                    "leaseOperation": "provider_keyed_teardown_fence",
            }:
                raise ValueError("mixed core preview source differs")
            if preview is not None and preview.status == "succeeded":
                from app.services.provider_keyed_core_destroy_preview import _read_regular, _sha
                data = preview.events[2].data
                plan_path = Path(str(data.get("planPath", "")))
                expected_path = (Path(plan.evidence["terraformStatePath"]).parent /
                                 f".barragan-mixed-core-destroy-{core.id.removeprefix('job-')}.tfplan")
                if (set(data) != {"planPath", "planDevice", "planInode", "planSha256",
                                  "stateSha256", "inventorySha256", "resourceCount",
                                  "sourceSha256", "parentJournalSha256",
                                  "sourceManifestSha256", "terraformBinarySha256",
                                  "leaseOwner", "leaseOperation"}
                        or plan_path != expected_path or plan_path.is_symlink()
                        or not plan_path.is_file()
                        or plan_path.stat().st_dev != data.get("planDevice")
                        or plan_path.stat().st_ino != data.get("planInode")
                        or _sha(_read_regular(plan_path)) != data.get("planSha256")
                        or data.get("stateSha256") != result.core_state_sha256
                        or data.get("inventorySha256") != result.core_inventory_sha256
                        or data.get("resourceCount") != len(core_inventory.resources)
                        or data.get("sourceSha256") != _fingerprint(asdict(result))
                        or data.get("parentJournalSha256") != job_event_digest(cleanup.events)
                        or data.get("sourceManifestSha256") != _fingerprint(
                            plan.evidence["keyedCoreTerraformSourceManifest"])
                        or data.get("terraformBinarySha256") != _REVIEWED_SHA256
                        or data.get("leaseOwner") != plan.id
                        or data.get("leaseOperation") != "provider_keyed_teardown_fence"):
                    raise ValueError("saved mixed core preview differs")
            if apply_child is not None:
                base = {key: value for key, value in apply_child.input.items()
                        if key not in {"claimOwner", "claimToken", "claimClaimedAt",
                                       "claimHeartbeatAt", "claimExpiresAt"}}
                if (base != {
                        "teardownParentId": cleanup.id, "coreJobId": core.id,
                        "corePlanId": plan.id, "sourceSha256": _fingerprint(asdict(result)),
                        "previewJobId": preview.id,
                        "previewJournalSha256": job_event_digest(preview.events),
                        "planSha256": preview.events[2].data["planSha256"],
                        "mutation": True,
                    } or (apply_child.status == "running" and
                          (type(apply_child.input.get("claimOwner")) is not str
                           or type(apply_child.input.get("claimToken")) is not str
                           or type(apply_child.input.get("claimExpiresAt")) is not str))):
                    raise ValueError("mixed core Apply source differs")
        return result
    except Exception:
        raise MixedZeroApplySourceError("mixed zero-Apply cleanup source is unproved") from None
