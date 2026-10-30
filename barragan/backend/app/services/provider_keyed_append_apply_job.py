# Copyright (c) 2026, Oracle and/or its affiliates.
"""Internal one-shot Apply child for a reviewed DigitalOcean edge append.

There is deliberately no public dispatcher for this job until the complete
five-node teardown path is proven. Any child created here is a no-replay fence.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.managed_host_image_continuity import managed_host_image_profile_named
from app.services.provider_keyed_append_apply import apply_digitalocean_keyed_edge_append_saved_plan
from app.services.provider_keyed_append_plan_job import (
    ProviderKeyedAppendPlanJobError, _PLAN_EVENT_KEYS,
    reconcile_reviewed_digitalocean_edge_append_plan,
)
from app.services.provider_keyed_append_plan_runner import ProviderKeyedAppendPlanEvidence
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentIntent, ExpectedDigitalOceanNode,
    reconcile_digitalocean_initial_attachment,
)
from app.services.provider_keyed_gated_runner import (
    UnreapedGatedCommandError, run_gated_command,
)
from app.services.provider_keyed_initial_apply_job import _cleanup_owned_keys, _write_owned_key
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_plan_job import _expected_inventory
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_postapply_preflight import read_applied_digitalocean_provider_for_teardown
from app.services.provider_keyed_published_teardown_source import audit_published_provider_keyed_source
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot, _hash_file
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, StoredJobRun, _stored_utc_instant, _utc_instant,
    job_event_digest,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_OWNER = f"provider-keyed-append-apply-{uuid4().hex}"
_SECONDS = 3600


class ProviderKeyedAppendApplyJobError(ValueError):
    """The append child is unproved or its Apply needs reconciliation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(now: str) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=_SECONDS)).isoformat()


def _child_id(parent_id: str) -> str:
    return f"job-provider-keyed-append-apply-{parent_id.removeprefix('job-provider-keyed-append-')}"


def _same_reserved_queued_child(stored: StoredJobRun, expected: StoredJobRun) -> bool:
    """Match the inserted child exactly, allowing only SQLite's UTC timestamp form."""
    if not isinstance(stored, StoredJobRun) or not isinstance(expected, StoredJobRun):
        return False
    created = _stored_utc_instant(stored.created_at)
    requested = _utc_instant(expected.created_at)
    return bool(
        created is not None and requested is not None and created == requested
        and replace(stored, created_at=expected.created_at) == expected
    )


def _completed_apply_child_receipt(child, parent, plan_sha: str,
                                   plan_receipt: dict, retained_ids: set[str]) -> dict:
    """Recognize the one saved-plan GO and both provider GETs, in order."""
    actor = parent.input.get("applyRequestedBy")
    approval = [event for event in parent.events
                if event.message == "provider append Apply requested"]
    if actor is not None and (not isinstance(actor, str) or not actor
            or parent.input.get("applyRequestedPlanSha256") != plan_receipt.get("planSha256")
            or not isinstance(parent.input.get("applyRequestedAt"), str)
            or len(approval) != 1 or approval[0].data != {
                "planJobId": parent.input.get("planJobId"),
                "planSha256": plan_receipt.get("planSha256"),
                "requestedBy": actor,
                "requestedAt": parent.input.get("applyRequestedAt"),
            }):
        raise ValueError("append Apply approval differs")
    if (child is None or child.status != "succeeded" or not child.finished_at
            or child.action != "provider_keyed_edge_append_apply"
            or child.target_id != parent.target_id
            or child.requested_by != parent.input.get("applyRequestedBy", parent.requested_by)
            or child.input.get("parentJobId") != parent.id
            or child.input.get("mutation") is not True
            or not isinstance(parent.input.get("applyReservationId"), str)
            or len(parent.input["applyReservationId"]) != 32
            or len(child.events) < 13
            or child.events[0].message != "provider append Apply child reserved"
            or child.events[0].data != {
                "planJournalSha256": plan_sha,
                "reservationId": parent.input.get("applyReservationId")}
            or child.events[1].message != "provider append Apply preflight started"
            or child.events[-1].message != "provider append apply completed"
            or set(child.events[-1].data) != {
                "stateSha256", "newEdgeAddress", "newEdgeProviderId",
                "newEdgePublicIp", "providerMembershipVerified",
            } or child.events[-1].data["providerMembershipVerified"] is not True):
        raise ValueError("append Apply child completion differs")
    names = [event.message for event in child.events]
    milestones = (
        "provider append Apply child reserved",
        "provider append Apply preflight started",
        "provider append key staging intended",
        "provider append command intent fenced",  # saved show
        "provider append command started before GO",
        "provider append command result fenced",
        "provider append retained membership verified",
        "provider append phase apply_started",
        "provider append command intent fenced",  # saved apply
        "provider append command started before GO",
        "provider append command result fenced",
        "provider append expanded membership verified",
        "provider append apply completed",
    )
    if (names != list(milestones)
            or [event.sequence for event in child.events]
               != list(range(1, len(child.events) + 1))
            or any(event.level != "info" for event in child.events)):
        raise ValueError("append Apply milestone is absent or out of order")
    selected = child.events[2:]
    show_intent, show_start, show_result = selected[1:4]
    apply_intent, apply_start, apply_result = selected[6:9]
    for phase, intent, start, result in (
        ("show", show_intent, show_start, show_result),
        ("apply", apply_intent, apply_start, apply_result),
    ):
        invocation = intent.data.get("invocationId")
        if (intent.data.get("phase") != phase or not invocation
                or start.data.get("phase") != phase
                or result.data.get("phase") != phase
                or start.data.get("invocationId") != invocation
                or result.data.get("invocationId") != invocation
                or not all(start.data.get(field) for field in ("bootId", "pid", "pgid", "startTicks"))
                or result.data.get("returnCode") != 0):
            raise ValueError("append Apply gated command differs")
    binary = plan_receipt.get("terraformBinaryPath")
    plan_path = plan_receipt.get("planPath")
    if (not isinstance(binary, str) or not isinstance(plan_path, str)
            or not Path(binary).is_absolute() or not Path(plan_path).is_absolute()
            or len(retained_ids) != 4):
        raise ValueError("reviewed append command source differs")
    for phase, intent in (("show", show_intent), ("apply", apply_intent)):
        argv = [binary, *(["show", "-json", plan_path] if phase == "show" else
                         ["apply", "-input=false", "-lock=true", "-no-color", plan_path])]
        expected_sha = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
        if intent.data.get("argvSha256") != expected_sha:
            raise ValueError("reviewed append command argv differs")
    before_ids = selected[4].data.get("providerIds")
    after_ids = selected[9].data.get("providerIds")
    new_id = child.events[-1].data["newEdgeProviderId"]
    if (type(before_ids) is not list or len(before_ids) != 4
            or set(before_ids) != retained_ids
            or type(after_ids) is not list or len(after_ids) != 5
            or set(after_ids) != retained_ids | {new_id}
            or len(set(after_ids)) != 5
            or show_intent.data["invocationId"] == apply_intent.data["invocationId"]
            or selected[4].data.get("stateSha256") !=
               selected[5].data.get("stateSha256")
            or selected[9].data.get("stateSha256") !=
               selected[10].data["stateSha256"]):
        raise ValueError("append Apply provider receipts differ")
    return child.events[-1].data


def reconcile_interrupted_digitalocean_edge_append_apply(
    parent_id: str, *, environment: str = "devtest", state_root: Path,
    job_repository=None, sketch_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Close only the two safe parent/child persistence gaps.

    A present unfinished child is an irreversible-command fence. This reader
    never retries Terraform or changes a child journal.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    if (environment != "devtest" or parent is None or parent.status != "running"
            or parent.action != "provider_keyed_edge_append"
            or parent.input.get("phase") != "apply_reserved"
            or parent.input.get("applyJobId") != _child_id(parent_id)
            or parent.input.get("engagementId") != parent.target_id
            or lookup(parent.target_id) != (parent.input.get("corePlanId"),
                                             "provider_keyed_edge_append")
            or parent.events[-1].message != "provider append Apply reserved"):
        raise ProviderKeyedAppendApplyJobError("interrupted append reservation differs")
    plan = jobs.get(parent.input.get("planJobId"))
    child = jobs.get(_child_id(parent_id))
    rows = chains.list_for_engagement(parent.target_id)
    selected = next((row for row in rows if row.chain_id == parent.input.get("chainId")), None)
    if (plan is None or plan.status != "succeeded" or not plan.events
            or plan.events[-1].message != "reviewed append plan saved"
            or parent.input.get("planJournalSha256") != job_event_digest(plan.events)
            or parent.events[-1].data != {
                "planJournalSha256": job_event_digest(plan.events),
                "reservationId": parent.input.get("applyReservationId")}
            or selected is None or not selected.terraform_working_directory):
        raise ProviderKeyedAppendApplyJobError("interrupted append review differs")
    root = Path(selected.terraform_working_directory)
    if (not root.is_absolute() or state_root not in root.parents
            or root.is_symlink() or _hash_file(root / "terraform.tfstate") not in {
                plan.events[-1].data.get("stateSha256"),
                child.events[-1].data.get("stateSha256") if child is not None
                and child.status == "succeeded" and child.events else None,
            }):
        raise ProviderKeyedAppendApplyJobError("interrupted append state differs")
    if child is None:
        if (json.loads((root / ".barragan-apply-phase.json").read_text()).get("phase") != "applied"
                or _hash_file(root / "terraform.tfstate") !=
                   plan.events[-1].data.get("stateSha256")):
            raise ProviderKeyedAppendApplyJobError("append command may have started")
        phase, message, data = "awaiting_apply", "provider append Apply reservation repaired", {}
    elif child.status == "succeeded":
        try:
            retained_ids = {str(node["providerInstanceId"])
                            for row in rows for node in row.nodes}
            receipt = _completed_apply_child_receipt(
                child, parent, job_event_digest(plan.events),
                plan.events[-1].data, retained_ids)
        except ValueError:
            raise ProviderKeyedAppendApplyJobError("append child receipt differs") from None
        if (_hash_file(root / "terraform.tfstate") != receipt["stateSha256"]
                or json.loads((root / ".barragan-apply-phase.json").read_text()).get("phase") != "applied"):
            raise ProviderKeyedAppendApplyJobError("completed append state differs")
        phase = "awaiting_host_proof"
        message = "provider append apply completed; strict host proof pending"
        data = {"stateSha256": child.events[-1].data["stateSha256"],
                "applyJournalSha256": job_event_digest(child.events)}
    else:
        raise ProviderKeyedAppendApplyJobError("append child requires read-only reconciliation")
    token = uuid4().hex
    now = _now()
    claimed = jobs.claim_lease(parent.id, owner=_OWNER, token=token,
                               claimed_at=now, expires_at=_later(now),
                               eligible_statuses={"running"},
                               eligible_phases={"apply_reserved"})
    if claimed is None or jobs.get(_child_id(parent_id)) != child:
        raise ProviderKeyedAppendApplyJobError("interrupted append claim changed")
    updated = jobs.save_if_leased(replace(claimed,
        input={**{key: value for key, value in claimed.input.items()
                  if not key.startswith("claim")}, "phase": phase,
               **({"applyJournalSha256": data["applyJournalSha256"]}
                  if phase == "awaiting_host_proof" else {})},
        events=[*claimed.events, JobEvent(len(claimed.events) + 1,
                                          "info", message, data)]),
        owner=_OWNER, token=token)
    if updated is None:
        raise ProviderKeyedAppendApplyJobError("interrupted append handoff changed")
    return updated


def run_reviewed_digitalocean_edge_append_apply(
    parent_id: str, *, environment: str = "devtest", state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    engagement_repository=None, credential_repository=None, ssh_key_repository=None,
    lease_lookup=None, attachment_reconciler=reconcile_digitalocean_initial_attachment,
    gated_command_runner=run_gated_command,
) -> StoredJobRun:
    """Reserve one deterministic child and apply the exact saved plan once.

    The four-node audit must finish before the child exists: the ordinary
    published-source reader intentionally refuses any append Apply history.
    A crash after reservation therefore stays fenced for explicit recovery.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    if (environment != "devtest" or parent is None
            or parent.action != "provider_keyed_edge_append" or parent.status != "running"
            or parent.input.get("phase") != "awaiting_apply"
            or parent.target_id != parent.input.get("engagementId")
            or jobs.get(_child_id(parent_id)) is not None
            or lookup(parent.target_id) != (parent.input.get("corePlanId"),
                                             "provider_keyed_edge_append")):
        raise ProviderKeyedAppendApplyJobError("reviewed append Apply is unavailable")
    try:
        # This validates the complete 17-key receipt, its saved binary,
        # varfile, state, topology, lockfile, credential, and source identity.
        if reconcile_reviewed_digitalocean_edge_append_plan(
                parent_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                sketch_repository=chains, credential_repository=credentials,
                lease_lookup=lookup) != parent:
            raise ValueError("append review changed")
        plan_child = jobs.get(parent.input["planJobId"])
        plan_event = plan_child.events[-1]
        receipt = plan_event.data
        if (plan_event.message != "reviewed append plan saved"
                or set(receipt) != _PLAN_EVENT_KEYS
                or parent.input.get("planJournalSha256") != job_event_digest(plan_child.events)):
            raise ValueError("append saved plan receipt differs")
        source = audit_published_provider_keyed_source(
            parent.input["coreJobId"], environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            lease_lookup=lookup,
            expected_mutation_lease=(parent.input["corePlanId"], "provider_keyed_edge_append"),
            allowed_append_plan_parent_id=parent.id,
        )
        if (receipt["initialSource"] != json.loads(json.dumps(asdict(source)))
                or receipt["initialSourceSha256"] != _fingerprint(asdict(source))):
            raise ValueError("initial published source changed")
        all_rows = chains.list_for_engagement(parent.target_id)
        rows = [row for row in all_rows if not _inert_aborted_intent(row, parent.target_id)]
        if (len(rows) != 2 or {row.chain_id for row in rows} != set(source.chain_ids)
                or receipt["selectedChain"] not in [row.to_dict() for row in rows]):
            raise ValueError("selected and sibling rows differ")
        selected = next(row for row in rows if row.chain_id == parent.input["chainId"])
        proposed = replace(selected, edge_count=2, edge_intents=[*selected.edge_intents, {
            "id": "edge-02", "provider": "digitalocean",
            "region": parent.input["region"], "size": parent.input["size"],
        }])
        ephemeral = [proposed if row.chain_id == selected.chain_id else row for row in rows]
        core = jobs.get(parent.input["coreJobId"])
        core_plan = plans.get(parent.input["corePlanId"])
        profile = managed_host_image_profile_named(core_plan.evidence["managedHostImageProfile"])
        intent = compile_fresh_digitalocean_persisted_intent(
            engagements.get(parent.target_id), ephemeral, core, core_plan, profile,
            environment=environment, provider_state_exists=True, mode="append_plan",
            reviewed_initial_chains=rows,
        )
        reviewed, workspace, initial_evidence, initial_apply = read_applied_digitalocean_provider_for_teardown(
            parent.target_id, core.id, environment=environment, state_root=state_root,
            mode="materialized_read", engagement_repository=engagements,
            sketch_repository=chains, job_repository=jobs, plan_repository=plans,
            credential_repository=credentials,
        )
        initial_attachment = derive_digitalocean_initial_attachment_intent(
            reviewed, workspace, initial_evidence, initial_apply)
        retained = _state_resources(json.loads(workspace.state_path.read_bytes()))
        new_address = receipt["newEdgeAddress"]
        if (initial_attachment.state_sha256 != source.state_sha256
                or receipt["stateSha256"] != source.state_sha256
                or set(intent.nodes) - {new_address} != {
                    address for address in retained if address.startswith("digitalocean_droplet.")
                } or new_address in retained
                or receipt["retainedSharedIds"] != {
                    address: str(retained[address]["id"]) for address in (
                        "digitalocean_firewall.firewall", "digitalocean_ssh_key.key")
                }):
            raise ValueError("retained four-node set differs")
        release = require_devtest_terraform_release(environment=environment)
        if (receipt["terraformBinaryPath"] != str(release.path)
                or receipt["terraformBinarySha256"] != release.sha256):
            raise ValueError("reviewed Terraform release changed")
        evidence = ProviderKeyedAppendPlanEvidence(
            Path(receipt["planPath"]), receipt["planSha256"], receipt["stateSha256"],
            receipt["topologySha256"], receipt["sourceSha256"], receipt["lockfileSha256"],
            tuple(tuple(entry) for entry in receipt["inputSha256"]),
            receipt["credentialRecordId"], receipt["credentialSecretSha256"],
            receipt["credentialUpdatedAt"], Path(receipt["terraformBinaryPath"]),
            receipt["terraformBinarySha256"],
        )
        material = retrieve_sketch_ssh_key(parent.target_id, ssh_key_repository)
        if material is None or not material.private_key or not material.public_key:
            raise ValueError("reviewed Sketch key is unavailable")
        key_dir = workspace.path.parents[1] / ".plan-material" / "digitalocean"
        private, public = key_dir / "admin-private", key_dir / "admin-public"
        varfile = key_dir / "append-inputs.json"
        variables = {**intent.nonsecret_varfile,
                     "ssh_priv_key_path": str(private), "ssh_pub_key_path": str(public),
                     "ssh_config_path": str(key_dir / "ssh-output")}
        if (varfile.is_symlink() or json.loads(varfile.read_text()) != variables
                or receipt["inputSha256"] != [[str(varfile), _hash_file(varfile)]]):
            raise ValueError("reviewed append inputs changed")
        expected_inventory = _expected_inventory(intent, private)
        if (private.exists() or private.is_symlink() or public.exists() or public.is_symlink()):
            raise ValueError("append key staging paths are not empty")
    except Exception:
        raise ProviderKeyedAppendApplyJobError("reviewed append Apply preflight stopped") from None

    token = uuid4().hex
    claimed_at = _now()
    current_parent = jobs.claim_lease(
        parent.id, owner=_OWNER, token=token, claimed_at=claimed_at,
        expires_at=_later(claimed_at), eligible_statuses={"running"},
        eligible_phases={"awaiting_apply"},
    )
    if current_parent is None or jobs.get(_child_id(parent.id)) is not None:
        raise ProviderKeyedAppendApplyJobError("append Apply claim changed")
    child = None
    current = None
    owned = {}
    unreaped = False
    try:
        # Before creating the no-replay child, reread the immutable four-node
        # source under the claimed lease. No apply child exists yet.
        again = audit_published_provider_keyed_source(
            parent.input["coreJobId"], environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            lease_lookup=lookup,
            expected_mutation_lease=(parent.input["corePlanId"], "provider_keyed_edge_append"),
            allowed_append_plan_parent_id=parent.id,
        )
        if (again != source or chains.list_for_engagement(parent.target_id) != all_rows
                or jobs.get(plan_child.id) != plan_child or _hash_file(workspace.state_path) != source.state_sha256):
            raise ValueError("append source moved before child reservation")
        reservation_id = uuid4().hex
        current_parent = jobs.save_if_leased(replace(
            current_parent, input={**current_parent.input, "phase": "apply_reserved",
                                   "applyJobId": _child_id(parent.id),
                                   "applyReservationId": reservation_id},
            events=[*current_parent.events, JobEvent(len(current_parent.events) + 1,
                "info", "provider append Apply reserved", {"planJournalSha256":
                    job_event_digest(plan_child.events),
                    "reservationId": reservation_id})]), owner=_OWNER, token=token)
        if current_parent is None:
            raise ValueError("append parent reservation lost")
        child = StoredJobRun(
            _child_id(parent.id), "provider_keyed_edge_append_apply", "queued",
            parent.target, "engagement", parent.target_id,
            parent.input.get("applyRequestedBy", parent.requested_by),
            {"engagementId": parent.target_id, "parentJobId": parent.id,
             "coreJobId": parent.input["coreJobId"], "corePlanId": parent.input["corePlanId"],
             "planJobId": plan_child.id, "mutation": True},
            [], _now(), None, None,
            [JobEvent(1, "info", "provider append Apply child reserved", {
                "planJournalSha256": job_event_digest(plan_child.events),
                "reservationId": reservation_id})],
        )
        stored_child = jobs.save_if_absent(child)
        if not _same_reserved_queued_child(stored_child, child):
            raise ValueError("append Apply child already exists")
        current = jobs.start_if_queued(stored_child, started_at=_now(), event=JobEvent(
            2, "info", "provider append Apply preflight started", {}))
        if current is None:
            raise ValueError("append Apply child was already claimed")
        claimed_at = _now()
        current = jobs.claim_lease(current.id, owner=_OWNER, token=token,
                                   claimed_at=claimed_at, expires_at=_later(claimed_at),
                                   eligible_statuses={"running"})
        if current is None:
            raise ValueError("append Apply child claim failed")

        def authority():
            if (lookup(parent.target_id) != (parent.input["corePlanId"], "provider_keyed_edge_append")
                    or jobs.get(current_parent.id) != current_parent
                    or jobs.get(current.id) != current
                    or chains.list_for_engagement(parent.target_id) != all_rows):
                raise ValueError("append Apply authority changed")

        def record(message, data):
            nonlocal current
            authority()
            now = _now()
            current = jobs.append_event_if_running_claimed(
                current, owner=_OWNER, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=now, expires_at=_later(now),
                event=JobEvent(len(current.events) + 1, "info", message, data))
            if current is None:
                raise ValueError("append Apply journal claim changed")

        record("provider append key staging intended", {
            "privateKeyPath": str(private), "publicKeyPath": str(public)})
        _write_owned_key(private, material.private_key, owned)
        _write_owned_key(public, material.public_key, owned)
        command_stage = "none"
        command_kind = None
        command_intent = None
        command_started = None

        def intent_callback(value):
            nonlocal command_stage, command_intent
            if (command_stage not in {"show_requested", "apply_requested"}
                    or value.scratch_path != str(workspace.path)):
                raise ValueError("append command intent differs")
            record("provider append command intent fenced", {
                "phase": command_kind, "invocationId": value.invocation_id,
                "argvSha256": value.argv_sha256})
            command_intent, command_stage = value, "intent"

        def started_callback(value):
            nonlocal command_stage, command_started
            if command_stage != "intent" or value.intent != command_intent:
                raise ValueError("append command start differs")
            record("provider append command started before GO", {
                "phase": command_kind, "invocationId": value.intent.invocation_id,
                "bootId": value.identity.boot_id, "pid": value.identity.pid,
                "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks})
            command_started, command_stage = value, "started"

        def heartbeat_callback(value):
            nonlocal current, current_parent
            if command_stage != "started" or value != command_started:
                raise ValueError("append command heartbeat differs")
            authority()
            now = _now()
            current = jobs.renew_lease(current.id, owner=_OWNER, token=token,
                                       heartbeat_at=now, expires_at=_later(now))
            current_parent = jobs.renew_lease(current_parent.id, owner=_OWNER, token=token,
                                              heartbeat_at=now, expires_at=_later(now))
            if current is None or current_parent is None:
                raise ValueError("append command lease changed")

        def result_callback(value):
            nonlocal command_stage
            if command_stage != "started" or value.started != command_started:
                raise ValueError("append command result differs")
            record("provider append command result fenced", {
                "phase": command_kind, "invocationId": value.started.intent.invocation_id,
                "returnCode": value.returncode, "stdoutBytes": value.stdout_bytes,
                "stderrBytes": value.stderr_bytes,
                "stdoutTruncated": value.stdout_truncated,
                "stderrTruncated": value.stderr_truncated})
            command_stage = "result"

        def command_runner(args, cwd, env):
            nonlocal command_stage, command_kind, unreaped
            if cwd != workspace.path or not args or args[0] != str(evidence.terraform_binary_path):
                raise ValueError("append command binary or workspace differs")
            if (args == [str(evidence.terraform_binary_path), "show", "-json",
                         str(evidence.plan_path)] and command_stage == "none"):
                command_stage, command_kind = "show_requested", "show"
            elif (args == [str(evidence.terraform_binary_path), "apply", "-input=false",
                           "-lock=true", "-no-color", str(evidence.plan_path)]
                  and command_stage == "show_complete"):
                if json.loads((workspace.path / ".barragan-apply-phase.json").read_text()).get("phase") != "apply_started":
                    raise ValueError("append phase was not fenced before command")
                record("provider append phase apply_started", {"stateSha256": source.state_sha256})
                command_stage, command_kind = "apply_requested", "apply"
            else:
                raise ValueError("append command order differs")
            try:
                outcome = gated_command_runner(
                    args, scratch_path=workspace.path, provider_keyed_v2=True,
                    max_output_bytes=16 * 1024 * 1024 if command_kind == "show" else 65536,
                    env=dict(env), intent_callback=intent_callback,
                    started_callback=started_callback, heartbeat_callback=heartbeat_callback,
                    result_callback=result_callback,
                )
            except UnreapedGatedCommandError:
                unreaped = True
                raise
            if command_stage != "result" or outcome.started != command_started:
                raise ValueError("append command audit incomplete")
            if command_kind == "show" and outcome.stdout_truncated:
                raise ValueError("append saved-plan show was truncated")
            command_stage = f"{command_kind}_complete"
            return subprocess.CompletedProcess(
                args, outcome.returncode,
                outcome.stdout if command_kind == "show" else "", "")

        def fresh_get():
            authority()
            proof = attachment_reconciler(
                workspace, initial_attachment, environment=environment,
                deployment_target="barragan-testing", credential_repository=credentials,
                max_attempts=12, poll_interval_seconds=10.0,
            )
            if not proof.provider_membership_verified or proof.state_sha256 != source.state_sha256:
                raise ValueError("retained provider membership differs")
            record("provider append retained membership verified", {
                "stateSha256": source.state_sha256,
                "providerIds": list(proof.verified_droplet_ids)})

        result = apply_digitalocean_keyed_edge_append_saved_plan(
            workspace, evidence, retained_resources=retained, expected_nodes=intent.nodes,
            new_edge_address=new_address, expected_firewall=intent.firewall,
            expected_inventory_content=expected_inventory, reviewed_variables=variables,
            credential_repository=credentials, command_environment=os.environ,
            before_go_provider_check=fresh_get, command_runner=command_runner,
        )
        if command_stage != "apply_complete":
            raise ValueError("append Apply command completion is unproved")
        after = _state_resources(json.loads(workspace.state_path.read_bytes()))
        attachment = DigitalOceanAttachmentIntent(
            result.state_sha256, str(after["digitalocean_firewall.firewall"]["id"]),
            intent.firewall.name, intent.selector_tag, intent.firewall.trusted_ssh_cidrs,
            tuple(ExpectedDigitalOceanNode(
                address, str(after[address]["id"]), intended.name, intended.region,
                after[address]["ipv4_address"],
            ) for address, intended in sorted(intent.nodes.items())),
            evidence.credential_record_id, evidence.credential_secret_sha256,
            evidence.credential_updated_at,
        )
        authority()
        proof = attachment_reconciler(
            workspace, attachment, environment=environment,
            deployment_target="barragan-testing", credential_repository=credentials,
            max_attempts=12, poll_interval_seconds=10.0,
        )
        if (not proof.provider_membership_verified or proof.state_sha256 != result.state_sha256
                or _hash_file(workspace.state_path) != result.state_sha256):
            raise ValueError("expanded provider membership differs")
        record("provider append expanded membership verified", {
            "stateSha256": result.state_sha256,
            "providerIds": list(proof.verified_droplet_ids)})
        _cleanup_owned_keys(owned)
        for stream in owned.values():
            stream.close()
        owned.clear()
        terminal = jobs.finish_if_running_claimed(
            current, owner=_OWNER, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(current.events) + 1, "info", "provider append apply completed", {
                "stateSha256": result.state_sha256,
                "newEdgeAddress": result.new_edge_address,
                "newEdgeProviderId": result.new_edge_provider_id,
                "newEdgePublicIp": result.new_edge_public_ip,
                "providerMembershipVerified": True,
            }),
        )
        if terminal is None:
            raise ValueError("append Apply terminal journal changed")
        parent_after = jobs.save_if_leased(replace(
            current_parent,
            input={**{key: value for key, value in current_parent.input.items()
                      if not key.startswith("claim")},
                   "phase": "awaiting_host_proof",
                   "applyJournalSha256": job_event_digest(terminal.events)},
            events=[*current_parent.events, JobEvent(len(current_parent.events) + 1,
                "info", "provider append apply completed; strict host proof pending", {
                    "stateSha256": result.state_sha256,
                    "applyJournalSha256": job_event_digest(terminal.events),
                })]), owner=_OWNER, token=token)
        if parent_after is None:
            raise ValueError("append Apply parent handoff changed")
        return parent_after
    except Exception:
        if not unreaped:
            try:
                _cleanup_owned_keys(owned, allow_missing=True)
            except OSError:
                pass
            try:
                if current is not None and jobs.get(current.id) == current:
                    jobs.finish_if_running_claimed(
                        current, owner=_OWNER, token=token,
                        expected_event_digest=job_event_digest(current.events),
                        status="failed", finished_at=_now(),
                        event=JobEvent(len(current.events) + 1, "error",
                                       "provider append Apply stopped; reconciliation required", {}),
                    )
                latest = jobs.get(current_parent.id)
                if latest == current_parent:
                    jobs.save_if_leased(replace(
                        current_parent, status="failed", finished_at=_now(),
                        input={**current_parent.input, "phase": "attention"},
                        events=[*current_parent.events, JobEvent(len(current_parent.events) + 1,
                            "error", "provider append Apply stopped; reconciliation required", {})]),
                        owner=_OWNER, token=token)
            except Exception:
                pass
        raise ProviderKeyedAppendApplyJobError(
            "provider append Apply stopped; manual read-only reconciliation required") from None
    finally:
        for stream in owned.values():
            stream.close()
