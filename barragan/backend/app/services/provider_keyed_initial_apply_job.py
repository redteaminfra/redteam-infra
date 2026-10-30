# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant DevTest-only job boundary for one exact saved DigitalOcean plan apply.

No dispatcher calls this module. Success records Terraform/state retention only;
provider attachment, host policy and route proof are separate later gates.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, TextIO
from uuid import uuid4

from app.domain import JobEvent
from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import (
    ProviderCatalogRegionSizeUnavailable, require_selected_digitalocean_region_sizes,
)
from app.services.provider_keyed_initial_apply import apply_digitalocean_keyed_initial_saved_plan
from app.services.provider_keyed_selector_reservation import reserve_and_verify_selector
from app.services.provider_keyed_selector_preflight import SelectorPreflightEvidence
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, StartedCommand,
    UnreapedGatedCommandError, run_gated_command,
)
from app.services.provider_keyed_initial_plan_job import _expected_inventory, _local_file
from app.services.provider_keyed_plan_evidence import decode_preflight_initial_plan_evidence
from app.services.provider_keyed_planned_state_preflight import preflight_planned_digitalocean_provider
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.storage.credential_repository import CredentialRepository, SqlAlchemyCredentialRepository
from app.storage.job_repository import (
    JobRepository, SqlAlchemyJobRepository, StoredJobRun,
    inspector_claim_generation_digest, job_event_digest,
)


ACTION = "provider_keyed_initial_apply"
_CLAIM_OWNER = f"provider-keyed-apply-{uuid4().hex}"
_CLAIM_SECONDS = 60


class ProviderKeyedInitialApplyJobError(ValueError):
    """Redacted apply-job failure; retained phase and state need reconciliation."""


def require_initial_selector_absence_provenance(
    job: StoredJobRun, *, engagement_id: str, core_job_id: str, core_plan_id: str,
    plan_job_id: str, connection_id: str, credential_secret_sha256: str,
    credential_updated_at: str, selector_tag: str, source_sha256: str,
    plan_sha256: str, plan_path: Path, terraform_binary_path: Path,
    terraform_binary_sha256: str,
) -> None:
    """Read a successful job's sealed absence, POST-intent, and 201 journal.

    The caller supplies independently reviewed plan and credential identities.
    A 201 is creation evidence, but provider duplicate-name semantics are not
    yet verified, so this reader alone cannot authorize DELETE.
    """
    invalid = ProviderKeyedInitialApplyJobError("selector absence provenance is unverified")
    if (job.action != ACTION or job.status != "succeeded" or job.finished_at is None
            or job.target_id != engagement_id or job.input != {
                "engagementId": engagement_id, "coreJobId": core_job_id,
                "corePlanId": core_plan_id, "planJobId": plan_job_id, "mutation": True,
            } or any(event.sequence != index for index, event in enumerate(job.events, 1))):
        raise invalid
    expected_tail = [
        "provider saved-plan apply preflight started",
        "provider apply key staging intended",
        "provider apply command intent fenced",
        "provider apply command started before GO",
        "provider apply command result fenced",
        "provider selector absent before initial apply",
        "provider selector creation POST intended",
        "provider selector creation 201 received",
        "provider apply command intent fenced",
        "provider apply command started before GO",
        "provider apply command result fenced",
        "provider saved-plan apply completed; proof pending",
    ]
    if ([event.message for event in job.events[-len(expected_tail):]] != expected_tail
            or any(event.level != "info" for event in job.events[-len(expected_tail):])):
        raise invalid
    scans = [event for event in job.events if event.message == "provider selector absent before initial apply"]
    post_intents = [event for event in job.events if event.message == "provider selector creation POST intended"]
    post_receipts = [event for event in job.events if event.message == "provider selector creation 201 received"]
    applies = [event for event in job.events if event.message == "provider apply command intent fenced"
               and event.data.get("phase") == "apply"]
    starts = [event for event in job.events if event.message == "provider apply command started before GO"
              and event.data.get("phase") == "apply"]
    results = [event for event in job.events if event.message == "provider apply command result fenced"
               and event.data.get("phase") == "apply"]
    completions = [event for event in job.events if event.message == "provider saved-plan apply completed; proof pending"]
    shows = [event for event in job.events if event.message == "provider apply command intent fenced"
             and event.data.get("phase") == "show"]
    show_starts = [event for event in job.events if event.message == "provider apply command started before GO"
                   and event.data.get("phase") == "show"]
    show_results = [event for event in job.events if event.message == "provider apply command result fenced"
                    and event.data.get("phase") == "show"]
    if any(len(group) != 1 for group in (scans, post_intents, post_receipts,
                                          applies, starts, results, completions,
                                          shows, show_starts, show_results)):
        raise invalid
    scan, apply, started, result, completion = (group[0] for group in
                                               (scans, applies, starts, results, completions))
    post_intent, post_receipt = post_intents[0], post_receipts[0]
    expected = {
        "engagementId": engagement_id, "coreJobId": core_job_id,
        "corePlanId": core_plan_id, "planJobId": plan_job_id,
        "applyJobId": job.id, "providerConnectionId": connection_id,
        "credentialSecretSha256": credential_secret_sha256,
        "credentialUpdatedAt": credential_updated_at,
        "selectorTag": selector_tag, "sourceSha256": source_sha256,
        "planSha256": plan_sha256, "planPath": str(plan_path),
        "terraformBinaryPath": str(terraform_binary_path),
        "terraformBinarySha256": terraform_binary_sha256,
    }
    show, show_started, show_result = shows[0], show_starts[0], show_results[0]
    show_argv = [str(terraform_binary_path), "show", "-json", str(plan_path)]
    apply_argv = [str(terraform_binary_path), "apply", "-input=false", "-lock=true",
                  "-no-color", str(plan_path)]
    argv_digest = lambda argv: hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
    intent_keys = {"phase", "invocationId", "argvSha256"}
    started_keys = {"phase", "invocationId", "bootId", "pid", "pgid", "startTicks"}
    result_keys = {"phase", "invocationId", "returnCode", "stdoutBytes", "stderrBytes",
                   "stdoutTruncated", "stderrTruncated"}
    terminal_keys = {"stateSha256", "selectorTag", "attachmentProofPending", "hostProofPending"}
    if (not all(scan.data.get(key) == value for key, value in expected.items())
            or set(scan.data) != set(expected) | {"claimGenerationSha256", "tagsChecked",
                                                     "firewallsChecked", "dropletsChecked"}
            or not isinstance(scan.data.get("claimGenerationSha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", scan.data["claimGenerationSha256"]) is None
            or any(type(scan.data.get(key)) is not int or scan.data[key] < 0
                   for key in ("tagsChecked", "firewallsChecked", "dropletsChecked"))
            or set(post_intent.data) != (set(expected) - {"terraformBinaryPath", "terraformBinarySha256"} | {"selectorAbsenceEventSequence", "claimGenerationSha256"})
            or set(post_receipt.data) != (set(expected) - {"terraformBinaryPath", "terraformBinarySha256"} | {"selectorIntentEventSequence", "httpStatus", "claimGenerationSha256"})
            or any(post_intent.data.get(key) != value or post_receipt.data.get(key) != value
                   for key, value in expected.items() if key not in {"terraformBinaryPath", "terraformBinarySha256"})
            or any(event.data.get("claimGenerationSha256") != scan.data.get("claimGenerationSha256")
                   for event in (post_intent, post_receipt))
            or post_intent.data.get("selectorAbsenceEventSequence") != scan.sequence
            or post_receipt.data.get("selectorIntentEventSequence") != post_intent.sequence
            or post_receipt.data.get("httpStatus") != 201
            or set(show.data) != intent_keys or set(apply.data) != intent_keys | {"selectorAbsenceEventSequence", "selectorReceiptEventSequence"}
            or show.data.get("argvSha256") != argv_digest(show_argv)
            or apply.data.get("argvSha256") != argv_digest(apply_argv)
            or set(show_started.data) != started_keys or set(started.data) != started_keys
            or set(show_result.data) != result_keys or set(result.data) != result_keys
            or set(completion.data) != terminal_keys
            or re.fullmatch(r"[0-9a-f]{64}", str(completion.data.get("stateSha256"))) is None
            or completion.data.get("attachmentProofPending") is not True
            or completion.data.get("hostProofPending") is not True
            or any(value.data.get("phase") != "show" for value in (show, show_started, show_result))
            or any(value.data.get("phase") != "apply" for value in (apply, started, result))
            or show_result.data.get("returnCode") != 0
            or any(value.data.get("returnCode") != 0 for value in (show_result, result))
            or any(value.data.get("stdoutTruncated") is not False
                   or value.data.get("stderrTruncated") is not False for value in (show_result, result))
            or any(type(value.data.get(key)) is not int or value.data[key] < 0
                   for value in (show_result, result) for key in ("stdoutBytes", "stderrBytes"))
            or any(type(value.data.get(key)) is not int or value.data[key] <= 0
                   for value in (show_started, started) for key in ("pid", "pgid", "startTicks"))
            or any(not isinstance(value.data.get("bootId"), str) or not value.data["bootId"]
                   for value in (show_started, started))
            or any(not isinstance(value.data.get("invocationId"), str) or not value.data["invocationId"]
                   for value in (show, apply))
            or any(value.data.get("invocationId") != show.data.get("invocationId")
                   for value in (show_started, show_result))
            or not scan.sequence < post_intent.sequence < post_receipt.sequence < apply.sequence < started.sequence < result.sequence < completion.sequence
            or not show.sequence < show_started.sequence < show_result.sequence < scan.sequence
            or apply.data.get("selectorAbsenceEventSequence") != scan.sequence
            or apply.data.get("selectorReceiptEventSequence") != post_receipt.sequence
            or any(event.data.get("invocationId") != apply.data.get("invocationId")
                   for event in (started, result))
            or result.data.get("returnCode") != 0
            or completion.data.get("selectorTag") != selector_tag):
        raise invalid


def run_fresh_digitalocean_initial_apply_job(
    job_id: str,
    *,
    environment: str,
    state_root: Path,
    lease_lookup=None,
    job_repository: JobRepository | None = None,
    credential_repository: CredentialRepository | None = None,
    ssh_key_repository=None,
    engagement_repository=None,
    sketch_repository=None,
    plan_repository=None,
    selector_transport=None,
    selector_reservation_transport=None,
    catalog_transport=None,
    preflight: Callable = preflight_planned_digitalocean_provider,
    apply: Callable = apply_digitalocean_keyed_initial_saved_plan,
    release_check: Callable = require_devtest_terraform_release,
    gated_command_runner: Callable = run_gated_command,
) -> StoredJobRun:
    """Run a queued apply job once under its core plan's existing lease.

    A running job is never restarted here. A later recovery controller must
    prove worker death and exact pre-apply state before considering recovery.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    job = jobs.get(job_id)
    if (environment != "devtest" or job is None or job.id != job_id
            or job.action != ACTION or job.status != "queued"
            or job.started_at is not None or job.finished_at is not None
            or not isinstance(job.input, dict)
            or job.target_type != "engagement" or job.target_id != job.input.get("engagementId")
            or job.target != f"engagement:{job.target_id}"
            or set(job.input) != {"engagementId", "coreJobId", "corePlanId", "planJobId", "mutation"}
            or any(not isinstance(job.input[key], str) or not job.input[key]
                   for key in ("engagementId", "coreJobId", "corePlanId", "planJobId"))
            or job.input["mutation"] is not True):
        raise ProviderKeyedInitialApplyJobError("queued DevTest provider apply job is invalid")

    preflight_kwargs = dict(
        lease_owner=job.input["corePlanId"], allowed_apply_job_id=job.id,
        environment=environment, state_root=state_root, lease_lookup=lease_lookup,
        engagement_repository=engagement_repository, sketch_repository=sketch_repository,
        job_repository=jobs, plan_repository=plan_repository,
        credential_repository=credentials,
    )
    # Validate the queued record before claiming it. A caller that loses the
    # subsequent CAS must leave the winning worker's job and files untouched.
    try:
        preflight(job.target_id, job.input["coreJobId"], job.input["planJobId"], **preflight_kwargs)
    except Exception:
        raise ProviderKeyedInitialApplyJobError("provider saved-plan apply preflight stopped") from None
    try:
        current = jobs.start_if_queued(
            job, started_at=_now(),
            event=JobEvent(len(job.events) + 1, "info", "provider saved-plan apply preflight started", {}),
        )
    except Exception:
        raise ProviderKeyedInitialApplyJobError("provider saved-plan apply job claim failed") from None
    if current is None:
        raise ProviderKeyedInitialApplyJobError("provider saved-plan apply job was already claimed")

    owned: dict[Path, TextIO] = {}
    cleanup_failed = False
    claim_token: str | None = None
    retain_keys = False
    unreaped_process = False
    unavailable_size: str | None = None
    try:
        # The second read binds the running audit record to the same retained plan.
        intent, workspace, raw_evidence = preflight(
            current.target_id, current.input["coreJobId"], current.input["planJobId"],
            **preflight_kwargs,
        )
        if (intent.engagement_id != current.target_id
                or intent.core_job_id != current.input["coreJobId"]
                or intent.core_plan_id != current.input["corePlanId"]):
            raise ValueError("reviewed intent differs from apply job")
        decoded = decode_preflight_initial_plan_evidence(
            raw_evidence, workspace,
            expected_core_job_id=intent.core_job_id,
            expected_core_plan_id=intent.core_plan_id,
            expected_revision_id=intent.revision_id,
            expected_connection_id=workspace.provider_connection_id,
            expected_selector_tag=intent.selector_tag,
        )
        material = retrieve_sketch_ssh_key(intent.engagement_id, ssh_key_repository)
        if (material is None or not isinstance(material.private_key, str) or not material.private_key
                or not isinstance(material.public_key, str) or not material.public_key
                or hashlib.sha256(material.public_key.encode("utf-8")).hexdigest()
                != decoded.admin_public_key_sha256):
            raise ValueError("durable Sketch key differs from reviewed key")
        release = release_check(environment=environment)
        if (release.path != decoded.apply_evidence.terraform_binary_path
                or release.sha256 != decoded.apply_evidence.terraform_binary_sha256):
            raise ValueError("reviewed Terraform release differs")
        # Planned-state preflight requires the canonical five-key job input.
        # Claim only after that complete second read, then recheck authority
        # before staging keys; an interrupted running claim is never replayed.
        candidate_token = uuid4().hex
        claimed_at = _now()
        claimed = jobs.claim_lease(
            current.id, owner=_CLAIM_OWNER, token=candidate_token,
            claimed_at=claimed_at, expires_at=_later(claimed_at),
            eligible_statuses={"running"},
        )
        if (claimed is None or claimed.status != "running"
                or claimed.input.get("claimOwner") != _CLAIM_OWNER
                or claimed.input.get("claimToken") != candidate_token
                or {key: value for key, value in claimed.input.items() if not key.startswith("claim")}
                != current.input or claimed.events != current.events):
            raise ValueError("provider apply claim changed")
        current = claimed
        claim_token = candidate_token
        lookup = lease_lookup or _db_lease_lookup

        def require_authority() -> None:
            if lookup(current.target_id) != (current.input["corePlanId"], "provider_keyed_initial"):
                raise ValueError("provider apply core lease changed")
            observed = jobs.get(current.id)
            if (observed is None or observed.status != "running"
                    or observed.input.get("claimOwner") != _CLAIM_OWNER
                    or observed.input.get("claimToken") != claim_token
                    or observed.events != current.events):
                raise ValueError("provider apply job claim changed")

        require_authority()
        if (workspace.provider != "digitalocean" or workspace.provider_connection_id != decoded.apply_evidence.credential_record_id
                or workspace.source_sha256 != decoded.apply_evidence.source_sha256
                or decoded.apply_evidence.plan_path != workspace.path / ".barragan-initial-full.tfplan"):
            raise ValueError("reviewed provider workspace changed after claim")
        # A saved plan can outlive provider capacity. Read the live catalog
        # using the exact reviewed connection before staging keys, reserving
        # a selector, or starting Terraform apply. This is a best-effort
        # availability observation, not a capacity reservation.
        digest, updated_at, encrypted = _credential_snapshot(
            decoded.apply_evidence.credential_record_id, credentials)
        if ((digest, updated_at) != (decoded.apply_evidence.credential_secret_sha256,
                                    decoded.apply_evidence.credential_updated_at)):
            raise ValueError("provider credential changed before region availability check")
        token = decrypt_secret_value(encrypted)
        if type(token) is not str or not token:
            raise ValueError("provider credential unavailable")
        try:
            require_selected_digitalocean_region_sizes(
                token, [(node.region, node.size) for node in intent.nodes.values()],
                transport=catalog_transport,
            )
        except ProviderCatalogRegionSizeUnavailable as exc:
            unavailable_size = f"{exc}; no provider mutation started"
            raise
        require_authority()
        directory = workspace.path.parents[1] / ".plan-material" / "digitalocean"
        private = directory / "admin-private"
        public = directory / "admin-public"
        if (not directory.is_dir() or directory.is_symlink() or directory.resolve(strict=True) != directory
                or any(os.path.lexists(path) for path in (private, public))):
            raise ValueError("reviewed key material paths are not empty and canonical")
        # Key staging itself needs a durable pre-write boundary. An interrupted
        # worker can leave these exact retained paths for manual reconciliation.
        require_authority()
        instant = _now()
        staged = jobs.append_event_if_running_claimed(
            current, owner=_CLAIM_OWNER, token=claim_token,
            expected_event_digest=job_event_digest(current.events),
            heartbeat_at=instant, expires_at=_later(instant),
            event=JobEvent(len(current.events) + 1, "info", "provider apply key staging intended", {
                "workspace": str(workspace.path), "privateKeyPath": str(private),
                "publicKeyPath": str(public),
            }),
        )
        if staged is None:
            raise ValueError("provider apply key staging audit claim changed")
        current = staged
        _write_owned_key(private, material.private_key, owned)
        _write_owned_key(public, material.public_key, owned)
        output = directory / "ssh-output"
        local_files = {
            "local_file.ansible_inventory[0]": _local_file(
                "inventory.ini", _expected_inventory(intent, private),
            ),
            "local_file.ssh_stanza[0]": _local_file(
                str(output / f"{intent.engagement_name}-sketch"), None,
            ),
        }
        command_stage = "none"
        command_kind: str | None = None
        command_intent: CommandIntent | None = None
        command_started: StartedCommand | None = None
        selector_absence_event_sequence: int | None = None
        selector_intent_event_sequence: int | None = None
        selector_receipt_event_sequence: int | None = None

        def append_audit(message: str, data: dict) -> None:
            nonlocal current
            require_authority()
            instant = _now()
            saved = jobs.append_event_if_running_claimed(
                current, owner=_CLAIM_OWNER, token=claim_token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=instant, expires_at=_later(instant),
                event=JobEvent(len(current.events) + 1, "info", message, data),
            )
            if saved is None:
                raise ValueError("provider apply command audit claim changed")
            current = saved

        def intent_callback(value: CommandIntent) -> None:
            nonlocal command_stage, command_intent
            if (command_stage not in {"show_requested", "apply_requested"}
                    or value.scratch_path != str(workspace.path)
                    or not value.invocation_id or len(value.argv_sha256) != 64):
                raise ValueError("provider apply command intent differs")
            if command_kind == "apply" and (selector_absence_event_sequence is None
                                             or selector_receipt_event_sequence is None):
                raise ValueError("selector reservation was not journaled before apply")
            append_audit("provider apply command intent fenced", {
                "phase": command_kind, "invocationId": value.invocation_id,
                "argvSha256": value.argv_sha256,
                **({"selectorAbsenceEventSequence": selector_absence_event_sequence,
                    "selectorReceiptEventSequence": selector_receipt_event_sequence}
                   if command_kind == "apply" else {}),
            })
            command_intent, command_stage = value, "intent"

        def selector_absence_callback(evidence: SelectorPreflightEvidence) -> None:
            nonlocal selector_absence_event_sequence
            if (selector_absence_event_sequence is not None or command_stage != "show_complete"
                    or not isinstance(evidence, SelectorPreflightEvidence)
                    or any(type(count) is not int or count < 0 for count in (
                        evidence.tags_checked, evidence.firewalls_checked,
                        evidence.droplets_checked,
                    ))):
                raise ValueError("selector absence proof is invalid or out of order")
            append_audit("provider selector absent before initial apply", {
                "engagementId": intent.engagement_id,
                "coreJobId": intent.core_job_id,
                "corePlanId": intent.core_plan_id,
                "planJobId": current.input["planJobId"],
                "applyJobId": current.id,
                "claimGenerationSha256": inspector_claim_generation_digest(
                    token=claim_token, claimed_at=current.input["claimClaimedAt"],
                ),
                "providerConnectionId": workspace.provider_connection_id,
                "credentialSecretSha256": decoded.apply_evidence.credential_secret_sha256,
                "credentialUpdatedAt": decoded.apply_evidence.credential_updated_at,
                "selectorTag": intent.selector_tag,
                "sourceSha256": workspace.source_sha256,
                "planSha256": decoded.apply_evidence.plan_sha256,
                "planPath": str(decoded.apply_evidence.plan_path),
                "terraformBinaryPath": str(release.path),
                "terraformBinarySha256": release.sha256,
                "tagsChecked": evidence.tags_checked,
                "firewallsChecked": evidence.firewalls_checked,
                "dropletsChecked": evidence.droplets_checked,
            })
            selector_absence_event_sequence = current.events[-1].sequence

        def selector_reservation_callback() -> None:
            nonlocal selector_intent_event_sequence, selector_receipt_event_sequence
            if (command_stage != "show_complete" or selector_absence_event_sequence is None
                    or selector_intent_event_sequence is not None
                    or selector_receipt_event_sequence is not None):
                raise ValueError("selector reservation is out of order")
            digest, updated_at, encrypted = _credential_snapshot(
                decoded.apply_evidence.credential_record_id, credentials)
            if ((digest, updated_at) != (decoded.apply_evidence.credential_secret_sha256,
                                        decoded.apply_evidence.credential_updated_at)):
                raise ValueError("provider credential changed before selector reservation")
            token = decrypt_secret_value(encrypted)
            if type(token) is not str or not token:
                raise ValueError("provider credential unavailable")
            identity = {
                "engagementId": intent.engagement_id, "coreJobId": intent.core_job_id,
                "corePlanId": intent.core_plan_id, "planJobId": current.input["planJobId"],
                "applyJobId": current.id, "providerConnectionId": workspace.provider_connection_id,
                "credentialSecretSha256": digest, "credentialUpdatedAt": updated_at,
                "selectorTag": intent.selector_tag, "sourceSha256": workspace.source_sha256,
                "planSha256": decoded.apply_evidence.plan_sha256,
                "planPath": str(decoded.apply_evidence.plan_path),
                "claimGenerationSha256": inspector_claim_generation_digest(
                    token=claim_token, claimed_at=current.input["claimClaimedAt"]),
            }
            def fence() -> None:
                require_authority()
                observed_digest, observed_updated, _ = _credential_snapshot(
                    decoded.apply_evidence.credential_record_id, credentials)
                if (observed_digest, observed_updated) != (digest, updated_at):
                    raise ValueError("provider credential changed during selector reservation")

            def on_intent() -> None:
                nonlocal selector_intent_event_sequence
                append_audit("provider selector creation POST intended", {
                    **identity, "selectorAbsenceEventSequence": selector_absence_event_sequence,
                })
                selector_intent_event_sequence = current.events[-1].sequence

            def on_receipt(status: int, selector: str) -> None:
                nonlocal selector_receipt_event_sequence
                if (status != 201 or selector != intent.selector_tag
                        or selector_intent_event_sequence is None
                        or selector_receipt_event_sequence is not None):
                    raise ValueError("selector creation receipt differs")
                append_audit("provider selector creation 201 received", {
                    **identity, "selectorIntentEventSequence": selector_intent_event_sequence,
                    "httpStatus": status,
                })
                selector_receipt_event_sequence = current.events[-1].sequence

            reserve_and_verify_selector(
                intent.selector_tag, token, fence=fence, on_intent=on_intent,
                on_receipt=on_receipt, get_transport=selector_transport,
                post_transport=selector_reservation_transport,
            )

        def started_callback(value: StartedCommand) -> None:
            nonlocal command_stage, command_started, retain_keys
            retain_keys = True
            if command_stage != "intent" or value.intent != command_intent:
                raise ValueError("provider apply command start differs")
            append_audit("provider apply command started before GO", {
                "phase": command_kind,
                "invocationId": value.intent.invocation_id,
                "bootId": value.identity.boot_id, "pid": value.identity.pid,
                "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks,
            })
            command_started, command_stage = value, "started"

        def heartbeat_callback(value: StartedCommand) -> None:
            nonlocal current
            if command_stage != "started" or value != command_started:
                raise ValueError("provider apply heartbeat identity differs")
            require_authority()
            instant = _now()
            renewed = jobs.renew_lease(
                current.id, owner=_CLAIM_OWNER, token=claim_token,
                heartbeat_at=instant, expires_at=_later(instant),
            )
            if renewed is None or renewed.events != current.events:
                raise ValueError("provider apply heartbeat claim changed")
            current = renewed

        def result_callback(value: CommandAuditResult) -> None:
            nonlocal command_stage, retain_keys
            if command_stage != "started" or value.started != command_started:
                raise ValueError("provider apply command result differs")
            append_audit("provider apply command result fenced", {
                "phase": command_kind,
                "invocationId": value.started.intent.invocation_id,
                "returnCode": value.returncode, "stdoutBytes": value.stdout_bytes,
                "stderrBytes": value.stderr_bytes,
                "stdoutTruncated": value.stdout_truncated,
                "stderrTruncated": value.stderr_truncated,
            })
            command_stage, retain_keys = "result", False

        def command_runner(args, cwd, env):
            nonlocal retain_keys, unreaped_process, command_stage, command_kind
            if cwd != workspace.path or not args or args[0] != str(release.path):
                raise ValueError("provider command workspace or binary differs")
            if args == [str(release.path), "show", "-json", str(decoded.apply_evidence.plan_path)] and command_stage == "none":
                command_kind, command_stage = "show", "show_requested"
            elif (args == [str(release.path), "apply", "-input=false", "-lock=true", "-no-color",
                          str(decoded.apply_evidence.plan_path)] and command_stage == "show_complete"):
                command_kind, command_stage = "apply", "apply_requested"
            else:
                raise ValueError("provider command order or reviewed plan differs")
            try:
                outcome = gated_command_runner(
                    args, scratch_path=workspace.path, provider_keyed_v2=True,
                    max_output_bytes=16 * 1024 * 1024 if command_kind == "show" else 65536,
                    env=dict(env), intent_callback=intent_callback,
                    started_callback=started_callback, heartbeat_callback=heartbeat_callback,
                    result_callback=result_callback,
                )
            except UnreapedGatedCommandError:
                retain_keys = True
                unreaped_process = True
                raise
            if command_stage != "result" or outcome.started != command_started:
                retain_keys = True
                raise ValueError("provider apply command audit incomplete")
            if command_kind == "show" and outcome.stdout_truncated:
                raise ValueError("reviewed Terraform show output was truncated")
            command_stage = f"{command_kind}_complete"
            # The exact bounded show output is required by the saved-plan
            # semantic gate. Apply output is never needed or persisted.
            return subprocess.CompletedProcess(args, outcome.returncode,
                                               outcome.stdout if command_kind == "show" else "", "")

        result = apply(
            workspace, decoded.apply_evidence,
            environment=environment, deployment_target="barragan-testing",
            expected_terraform_sha256=release.sha256,
            expected_nodes=intent.nodes, expected_ssh_key_name="do-key",
            expected_ssh_public_key=material.public_key.strip(),
            expected_firewall=intent.firewall, expected_local_files=local_files,
            engagement_tag=intent.engagement_name,
            credential_repository=credentials, command_environment=os.environ,
            selector_transport=selector_transport,
            command_runner=command_runner,
            selector_absence_callback=selector_absence_callback,
            selector_reservation_callback=selector_reservation_callback,
        )
        if command_stage != "apply_complete":
            retain_keys = True
            raise ValueError("provider apply returned without supervised command result")
        try:
            _cleanup_owned_keys(owned)
        except OSError:
            cleanup_failed = True
            raise
        for stream in owned.values():
            stream.close()
        owned.clear()
        if (result.selector != intent.selector_tag
                or result.attachment_proof_pending is not True
                or not isinstance(result.state_sha256, str)
                or len(result.state_sha256) != 64
                or any(char not in "0123456789abcdef" for char in result.state_sha256)):
            raise ValueError("provider apply result is unverified")
        require_authority()
        completed = jobs.finish_if_running_claimed(
            current, owner=_CLAIM_OWNER, token=claim_token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(current.events) + 1, "info", "provider saved-plan apply completed; proof pending", {
                "stateSha256": result.state_sha256, "selectorTag": result.selector,
                "attachmentProofPending": True, "hostProofPending": True,
            }),
        )
        if completed is None:
            raise ValueError("provider apply job terminal ownership changed")
        return completed
    except Exception:
        if unreaped_process:
            # A started command without proven process-group quiescence must
            # remain claimed/running for explicit read-only reconciliation.
            # The started event above retains the exact boot/PID/PGID/ticks.
            raise ProviderKeyedInitialApplyJobError(
                "provider apply process quiescence unproved; reconciliation required"
            ) from None
        if not retain_keys:
            try:
                _cleanup_owned_keys(owned, allow_missing=True)
            except OSError:
                cleanup_failed = True
        try:
            message = (unavailable_size if unavailable_size is not None else
                       "provider apply command completion audit unproved; staged keys retained for reconciliation"
                       if retain_keys else "provider saved-plan apply stopped; key-material cleanup and reconciliation required"
                       if cleanup_failed else "provider saved-plan apply stopped; reconciliation required")
            event = JobEvent(len(current.events) + 1, "error", message, {})
            if claim_token is None:
                jobs.finish_if_running(current, status="failed", finished_at=_now(), event=event)
            else:
                jobs.finish_if_running_claimed(
                    current, owner=_CLAIM_OWNER, token=claim_token,
                    expected_event_digest=job_event_digest(current.events),
                    status="failed", finished_at=_now(), event=event,
                )
        except Exception:
            # The terminal audit may already belong to a recovery writer.
            # Keep the caller's redacted reconciliation failure either way.
            pass
        raise ProviderKeyedInitialApplyJobError(
            unavailable_size if unavailable_size is not None else
            "provider saved-plan apply stopped; reconciliation required") from None
    finally:
        for stream in owned.values():
            stream.close()


def _write_owned_key(path: Path, content: str, owned: dict[Path, TextIO]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    stream = os.fdopen(descriptor, "w", encoding="utf-8")
    owned[path] = stream
    info = os.fstat(stream.fileno())
    os.fchmod(stream.fileno(), 0o600)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("new private key material is unsafe")
    stream.write(content)
    stream.flush()
    os.fsync(stream.fileno())


def _cleanup_owned_keys(owned: dict[Path, TextIO], *, allow_missing: bool = False) -> None:
    failed = False
    for path, stream in owned.items():
        try:
            current = path.lstat()
            original = os.fstat(stream.fileno())
            if (not stat.S_ISREG(current.st_mode)
                    or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)):
                raise OSError("private key material ownership changed")
            path.unlink()
        except FileNotFoundError:
            if not allow_missing:
                failed = True
        except OSError:
            failed = True
    if failed:
        raise OSError("private key material cleanup is incomplete")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(instant: str) -> str:
    return (datetime.fromisoformat(instant) + timedelta(seconds=_CLAIM_SECONDS)).isoformat()
