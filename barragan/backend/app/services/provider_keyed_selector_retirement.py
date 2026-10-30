# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private DevTest one-shot retirement of an explicitly reserved DO selector.

An intent is durable before DELETE. A restart may only establish exact tag
absence with read-only calls; it never sends a second DELETE.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Callable, Protocol
import urllib.error
import urllib.request
from uuid import uuid4

from app.domain import JobEvent
from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import ProviderCatalogTransport, UrllibProviderCatalogTransport
from app.services.provider_keyed_core_destroy_absence import (
    ACTION as CORE_ABSENCE_ACTION, prove_pending_keyed_oci_core_destroy_absence,
)
from app.services.provider_keyed_comprehensive_teardown import recognize_provider_keyed_group_retired
from app.services.provider_keyed_destroy_absence_preflight import _read_success_boundary
from app.services.provider_keyed_destroy_absence_preflight import (
    reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_digitalocean_absence import _ORIGIN, _require_destroy_fence
from app.services.provider_keyed_digitalocean_tag_eligibility import (
    _complete_inventory, _empty_visible_tag_inventory, _TYPES,
)
from app.services.provider_keyed_initial_apply_job import require_initial_selector_absence_provenance
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_inspector_negative import (
    ACTION as NEGATIVE_ACTION, prove_pending_keyed_inspector_negative,
)
from app.services.provider_keyed_pending_retirement import recognize_pending_keyed_group_retired
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_selector_preflight import _scan_endpoint
from app.services.provider_keyed_selector_reservation import _require_no_firewall_selector_use
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


ACTION = "provider_keyed_selector_retirement"
_FENCE = "provider_keyed_teardown_fence"


class SelectorRetirementAttention(ValueError):
    """Selector outcome or authority is uncertain; no DELETE is retried."""


@dataclass(frozen=True)
class DeleteResponse:
    status: int
    body: bytes


class DeleteTransport(Protocol):
    def delete_tag(self, token: str, selector: str) -> DeleteResponse: ...
    def get_tag_status(self, token: str, selector: str) -> int: ...


class UrllibDeleteTransport:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def delete_tag(self, token: str, selector: str) -> DeleteResponse:
        request = urllib.request.Request(
            f"{_ORIGIN}/tags/{selector}", method="DELETE",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return DeleteResponse(response.status, response.read(1))
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            raise SelectorRetirementAttention("selector DELETE outcome is uncertain") from None

    def get_tag_status(self, token: str, selector: str) -> int:
        request = urllib.request.Request(
            f"{_ORIGIN}/tags/{selector}", method="GET",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read(1)
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=60)).isoformat()


def _read_empty_membership(client: ProviderCatalogTransport, token: str,
                           selector: str, fence: Callable[[], None], *, tag_present: bool) -> tuple[str, ...]:
    if tag_present:
        readable = _empty_visible_tag_inventory(client, token, selector, fence)
    else:
        readable = []
        for label, endpoint, key, filters in _TYPES:
            for row in _complete_inventory(client, token, endpoint, key, filters, fence):
                tags = row.get("tags")
                if (type(tags) is not list or any(type(tag) is not str or not tag for tag in tags)
                        or any(tag.casefold() == selector.casefold() for tag in tags)):
                    raise ValueError("provider tag membership is unverified")
                if label == "volume_snapshots" and row.get("resource_type") != "volume":
                    raise ValueError("snapshot type is unverified")
                if label == "images" and row.get("private") is not True:
                    raise ValueError("image scope is unverified")
            readable.append(label)
        class FencedTransport:
            def request(self, base, method, path, credential):
                fence()
                result = client.request(base, method, path, credential)
                fence()
                return result

        _scan_endpoint("tags", selector, token, FencedTransport())
    _require_no_firewall_selector_use(
        _complete_inventory(client, token, "/firewalls", "firewalls", {}, fence), selector,
    )
    return tuple(readable)


def _published_selector_history(parent_id: str, *, environment: str, state_root: Path,
                                jobs, plans, chains, credentials, lookup):
    """Reprove saved published history without replaying an Inspector probe."""
    from app.services.provider_keyed_teardown_source import _read_published_post_destroy_boundary

    source, bound = _read_published_post_destroy_boundary(
        parent_id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans, sketch_repository=chains,
        credential_repository=credentials, lease_lookup=lookup,
        credential_check=_credential_snapshot, retired=True,
    )
    recognize_provider_keyed_group_retired(
        parent_id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans, sketch_repository=chains,
        credential_repository=credentials, lease_lookup=lookup,
    )
    return source, bound


def _published_negative(parent, core, snapshot, *, environment, state_root,
                        jobs, plans, chains, credentials, lookup, catalog):
    negatives = [row for row in jobs.list_for_engagement(parent.target_id)
                 if row.action == NEGATIVE_ACTION and row.input.get("coreJobId") == core.id]
    if (len(negatives) != 1 or negatives[0].status != "succeeded"
            or negatives[0].input.get("teardownParentId") != parent.id
            or negatives[0].input.get("corePlanId") != core.input["corePlanId"]
            or negatives[0].input.get("scopeSnapshotId") != snapshot["snapshotId"]):
        raise ValueError("saved Inspector negative child differs")
    negative = negatives[0]

    def fresh_do(parent_id, **options):
        return reconcile_successful_digitalocean_destroy_absence(
            parent_id, **options, transport=catalog,
            max_attempts=1, poll_interval_seconds=0,
        )

    class NoProbeReplay:
        def run(self, **_kwargs):
            raise ValueError("saved Inspector negative proof attempted probe replay")

    recognized = prove_pending_keyed_inspector_negative(
        parent.id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans, sketch_repository=chains,
        credential_repository=credentials, lease_lookup=lookup,
        positive_control=negative.input.get("positiveControl"),
        do_absence_reader=fresh_do, runner=NoProbeReplay(),
    )
    if recognized != negative:
        raise ValueError("saved Inspector negative proof differs")
    return negative


def retire_pending_digitalocean_selector(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
    retired_recognizer: Callable = recognize_pending_keyed_group_retired,
    core_absence_recognizer: Callable = prove_pending_keyed_oci_core_destroy_absence,
    catalog_transport: ProviderCatalogTransport | None = None,
    delete_transport: DeleteTransport | None = None,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
) -> StoredJobRun:
    """Delete one reviewed tag or reconcile an earlier ambiguous one-shot intent."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("private DevTest boundary differs")
        client = catalog_transport or UrllibProviderCatalogTransport()
        parent_marker = jobs.get(teardown_parent_id)
        published = parent_marker is not None and "publishedSource" in parent_marker.input

        def boundary():
            if published:
                source, before = _published_selector_history(
                    teardown_parent_id, environment=environment, state_root=state_root,
                    jobs=jobs, plans=plans, chains=chains, credentials=credentials,
                    lookup=lookup,
                )
            else:
                before = _read_success_boundary(
                    teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
                    credentials=credentials, lookup=lookup,
                    handoff_auditor=audit_pending_provider_keyed_bootstrap,
                    credential_check=_credential_snapshot, state_root=state_root,
                )
                source = None
                retired_recognizer(
                    teardown_parent_id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                    credential_repository=credentials, lease_lookup=lookup,
                )
            if (("publishedSource" in before.parent.input) != published
                    or lookup(before.parent.target_id)
                    != (before.core.input["corePlanId"], _FENCE)):
                raise ValueError("selector source and fence differ")
            return source, before

        before_source, before = boundary()
        parent, core = before.parent, before.core
        selector = before.intent.selector_tag
        if selector != "s" + hashlib.sha256(parent.target_id.encode()).hexdigest()[:20]:
            raise ValueError("selector does not belong to reserved opaque namespace")
        initial_id, initial_plan_id, initial_apply_id = _job_ids(core.id)
        initial = jobs.get(initial_id)
        initial_plan = jobs.get(initial_plan_id)
        initial_apply = jobs.get(initial_apply_id)
        if (initial is None or initial_plan is None or initial_apply is None
                or initial_plan.status != "succeeded" or initial_apply.status != "succeeded"
                or initial_plan.action != "provider_keyed_initial_plan"
                or not initial_plan.events or initial_plan.events[-1].message != "reviewed provider plan saved"
                or initial.target_id != parent.target_id
                or initial_plan.target_id != parent.target_id
                or initial_apply.target_id != parent.target_id):
            raise ValueError("initial selector creation generation differs")
        plan_data = initial_plan.events[-1].data
        if (type(plan_data) is not dict
                or plan_data.get("coreJobId") != core.id
                or plan_data.get("corePlanId") != core.input["corePlanId"]
                or plan_data.get("providerConnectionId") != before.intent.credential_record_id
                or plan_data.get("selectorTag") != selector
                or plan_data.get("sourceSha256") != before.workspace.source_sha256
                or plan_data.get("credentialSecretSha256")
                != before.intent.credential_secret_sha256
                or plan_data.get("credentialUpdatedAt")
                != before.intent.credential_updated_at):
            raise ValueError("original reviewed plan identity differs")
        require_initial_selector_absence_provenance(
            initial_apply, engagement_id=parent.target_id, core_job_id=core.id,
            core_plan_id=core.input["corePlanId"], plan_job_id=initial_plan.id,
            connection_id=before.intent.credential_record_id,
            credential_secret_sha256=before.intent.credential_secret_sha256,
            credential_updated_at=before.intent.credential_updated_at,
            selector_tag=selector, source_sha256=before.workspace.source_sha256,
            plan_sha256=plan_data["planSha256"], plan_path=Path(plan_data["planPath"]),
            terraform_binary_path=Path(plan_data["terraformBinaryPath"]),
            terraform_binary_sha256=plan_data["terraformBinarySha256"],
        )
        absence_id = f"job-provider-keyed-core-destroy-absence-{core.id.removeprefix('job-')}-attempt-"
        absence_jobs = [job for job in jobs.list_for_engagement(parent.target_id)
                        if job.action == CORE_ABSENCE_ACTION and job.status == "succeeded"
                        and job.id.startswith(absence_id)]
        if (len(absence_jobs) != 1 or absence_jobs[0].events[-1].message
                != "core destroy exact absence proved"
                or absence_jobs[0].input.get("teardownParentId") != parent.id
                or absence_jobs[0].input.get("coreJobId") != core.id
                or absence_jobs[0].input.get("scopeSnapshotId")
                != parent.input["scopeSnapshot"]["snapshotId"]):
            raise ValueError("exact OCI core absence is not proved")
        core_absence = absence_jobs[0]
        absence_recognizer = (prove_pending_keyed_oci_core_destroy_absence if published
                              else core_absence_recognizer)
        reviewed_absence = absence_recognizer(
            teardown_parent_id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, lease_lookup=lookup,
        )
        if reviewed_absence != core_absence:
            raise ValueError("sealed OCI absence generation differs")
        negative = (_published_negative(
            parent, core, parent.input["scopeSnapshot"], environment=environment,
            state_root=state_root, jobs=jobs, plans=plans, chains=chains,
            credentials=credentials, lookup=lookup, catalog=client,
        ) if published else None)
        encrypted_digest, updated_at, encrypted = _credential_snapshot(
            before.intent.credential_record_id, credentials)
        if ((encrypted_digest, updated_at)
                != (before.intent.credential_secret_sha256, before.intent.credential_updated_at)):
            raise ValueError("selected provider credential changed")
        token = decrypt_secret(encrypted)
        if type(token) is not str or not token:
            raise ValueError("selected provider credential unavailable")
        base = {
            "engagementId": parent.target_id, "coreJobId": core.id,
            "corePlanId": core.input["corePlanId"], "teardownParentId": parent.id,
            "scopeSnapshotId": parent.input["scopeSnapshot"]["snapshotId"],
            "providerScopeSha256": parent.input["scopeSnapshot"]["providerScopeSha256"],
            "selectorTag": selector, "providerConnectionId": before.intent.credential_record_id,
            "credentialSecretSha256": encrypted_digest, "credentialUpdatedAt": updated_at,
            "initialApplyJobId": initial_apply.id,
            "initialApplyJournalSha256": job_event_digest(initial_apply.events),
            "coreAbsenceJobId": core_absence.id,
            "coreAbsenceJournalSha256": job_event_digest(core_absence.events),
            "mutation": True,
        }
        if negative is not None:
            base.update({"inspectorNegativeJobId": negative.id,
                         "inspectorNegativeJournalSha256": job_event_digest(negative.events)})
        child_id = f"job-provider-keyed-selector-retirement-{core.id.removeprefix('job-')}"
        existing = [job for job in jobs.list_for_engagement(parent.target_id)
                    if job.action == ACTION and job.input.get("coreJobId") == core.id]
        if existing and (len(existing) != 1 or existing[0].id != child_id):
            raise ValueError("unexpected selector retirement child")
        deleter = delete_transport or UrllibDeleteTransport()

        def fence(current: StoredJobRun):
            if (boundary() != (before_source, before)
                    or jobs.get(initial_apply.id) != initial_apply
                    or jobs.get(initial_plan.id) != initial_plan
                    or jobs.get(core_absence.id) != core_absence
                    or (negative is not None and jobs.get(negative.id) != negative)
                    or jobs.get(child_id) != current
                    or _credential_snapshot(before.intent.credential_record_id, credentials)
                    != (encrypted_digest, updated_at, encrypted)):
                raise ValueError("selector retirement authority changed")
            _require_destroy_fence(before.workspace, before.intent)
            if ("claimExpiresAt" in current.input and datetime.now(timezone.utc)
                    >= datetime.fromisoformat(current.input["claimExpiresAt"])):
                raise ValueError("selector retirement claim expired")

        current = jobs.get(child_id)
        if current is None:
            candidate = StoredJobRun(
                child_id, ACTION, "queued", f"engagement:{parent.target_id}",
                "engagement", parent.target_id, parent.requested_by, base, [], _now(),
                None, None, [JobEvent(1, "info", "selector retirement queued", {})],
            )
            current = jobs.save_if_absent(candidate)
            if (current is None or current.id != candidate.id
                    or current.action != candidate.action
                    or current.status != candidate.status
                    or current.target != candidate.target
                    or current.target_type != candidate.target_type
                    or current.target_id != candidate.target_id
                    or current.requested_by != candidate.requested_by
                    or current.input != candidate.input
                    or current.artifact_refs != candidate.artifact_refs
                    or current.created_at not in {
                        candidate.created_at, candidate.created_at.removesuffix("+00:00")}
                    or current.started_at is not None or current.finished_at is not None
                    or current.events != candidate.events
                    or jobs.get(child_id) != current):
                raise ValueError("selector retirement child reservation lost")
            current = jobs.start_if_queued(
                current, started_at=_now(),
                event=JobEvent(2, "info", "selector retirement started", {}),
            )
            if current is None:
                raise ValueError("selector retirement child start lost")
        elif (current.action != ACTION or current.target_id != parent.target_id
              or {key: value for key, value in current.input.items()
                  if not key.startswith("claim")} != base
              or current.finished_at is not None
              or not ((current.status == "queued" and current.started_at is None
                       and len(current.events) == 1
                       and current.events[0].message == "selector retirement queued")
                      or (current.status == "running" and current.started_at is not None
                          and [event.message for event in current.events[:2]]
                          == ["selector retirement queued", "selector retirement started"]
                          and (len(current.events) == 2 or
                               (len(current.events) == 3 and current.events[-1].message
                                == "selector DELETE intended"))))):
            raise ValueError("existing selector retirement needs review")
        if current.status == "queued":
            current = jobs.start_if_queued(
                current, started_at=_now(),
                event=JobEvent(2, "info", "selector retirement started", {}),
            )
            if current is None:
                raise ValueError("selector retirement child restart lost")

        owner = f"provider-keyed-selector-retire-{uuid4().hex}"
        claim_token = uuid4().hex
        claimed_at = _now()
        current = jobs.claim_lease(
            child_id, owner=owner, token=claim_token, claimed_at=claimed_at,
            expires_at=_later(claimed_at), eligible_statuses={"running"},
        )
        if current is None or jobs.get(child_id) != current:
            raise ValueError("selector retirement claim unavailable")
        # Generic claim_lease retains an older generation's heartbeat. Reset
        # it under the new token before a restart can append a terminal event.
        if "claimHeartbeatAt" in current.input:
            renewed_at = _now()
            current = jobs.renew_lease(
                child_id, owner=owner, token=claim_token,
                heartbeat_at=renewed_at, expires_at=_later(renewed_at),
            )
            if current is None or jobs.get(child_id) != current:
                raise ValueError("selector retirement recovery claim lost")
        fence(current)
        prior_intent = len(current.events) == 3
        if not prior_intent:
            if len(current.events) != 2:
                raise ValueError("selector retirement journal differs")
            _read_empty_membership(client, token, selector, lambda: fence(current), tag_present=True)
            fence(current)
            at = _now()
            intended = jobs.append_selector_retirement_event_if_running_claimed(
                current, owner=owner, token=claim_token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(3, "info", "selector DELETE intended", {
                    "selectorTag": selector, "scopeSnapshotId": base["scopeSnapshotId"],
                    "initialApplyJournalSha256": base["initialApplyJournalSha256"],
                    "coreAbsenceJournalSha256": base["coreAbsenceJournalSha256"],
                    **({"inspectorNegativeJobId": negative.id,
                        "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"]}
                       if negative is not None else {}),
                }),
            )
            if intended is None:
                raise ValueError("selector DELETE intent not durable")
            current = intended
            fence(current)
            response = deleter.delete_tag(token, selector)
            if type(response) is not DeleteResponse or response.status != 204 or response.body != b"":
                raise ValueError("selector DELETE receipt is not exact 204 empty")
            message = "selector DELETE 204 received"
            terminal_data = {"httpStatus": 204, "selectorTag": selector}
        else:
            if current.events[-1].data != {
                "selectorTag": selector, "scopeSnapshotId": base["scopeSnapshotId"],
                "initialApplyJournalSha256": base["initialApplyJournalSha256"],
                "coreAbsenceJournalSha256": base["coreAbsenceJournalSha256"],
                **({"inspectorNegativeJobId": negative.id,
                    "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"]}
                   if negative is not None else {}),
            }:
                raise ValueError("prior DELETE intent differs")
            _read_empty_membership(client, token, selector, lambda: fence(current), tag_present=False)
            fence(current)
            if deleter.get_tag_status(token, selector) != 404:
                raise ValueError("selector exact GET is not absent")
            fence(current)
            message = "selector absence reconciled"
            terminal_data = {"selectorTag": selector, "exactGetStatus": 404,
                             "completeTagListAbsent": True}
        finished = jobs.finish_selector_retirement_if_running_claimed(
            current, owner=owner, token=claim_token,
            expected_event_digest=job_event_digest(current.events), finished_at=_now(),
            event=JobEvent(4, "info", message, terminal_data),
        )
        if finished is None:
            raise ValueError("selector retirement terminal journal changed")
        return finished
    except Exception:
        raise SelectorRetirementAttention(
            "selector retirement is unverified; inspect one-shot child without replaying DELETE"
        ) from None


def recognize_pending_digitalocean_selector_retired(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
    retired_recognizer: Callable = recognize_pending_keyed_group_retired,
    core_absence_recognizer: Callable = prove_pending_keyed_oci_core_destroy_absence,
    catalog_transport: ProviderCatalogTransport | None = None,
    status_transport: DeleteTransport | None = None,
    decrypt_secret: Callable[[str], str] = decrypt_secret_value,
) -> StoredJobRun:
    """Reprove one saved selector success using fresh complete reads only.

    The tag GET alone is insufficient: DigitalOcean omits resource types that
    the selected token cannot see. Every supported taggable inventory and all
    firewall references must also be readable and empty of this selector.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("private DevTest state root required")
        catalog = catalog_transport or UrllibProviderCatalogTransport()
        parent_marker = jobs.get(teardown_parent_id)
        published = parent_marker is not None and "publishedSource" in parent_marker.input

        def source():
            if published:
                history, bound = _published_selector_history(
                    teardown_parent_id, environment=environment, state_root=state_root,
                    jobs=jobs, plans=plans, chains=chains, credentials=credentials,
                    lookup=lookup,
                )
            else:
                bound = _read_success_boundary(
                    teardown_parent_id, jobs=jobs, plans=plans, chains=chains,
                    credentials=credentials, lookup=lookup,
                    handoff_auditor=audit_pending_provider_keyed_bootstrap,
                    credential_check=_credential_snapshot, state_root=state_root,
                )
                history = None
                retired_recognizer(
                    teardown_parent_id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                    credential_repository=credentials, lease_lookup=lookup,
                )
            if (("publishedSource" in bound.parent.input) != published
                    or lookup(bound.parent.target_id)
                    != (bound.core.input["corePlanId"], _FENCE)):
                raise ValueError("selector source or fence differs")
            return history, bound

        bound_source, bound = source()
        parent, core = bound.parent, bound.core
        selector = bound.intent.selector_tag
        if selector != "s" + hashlib.sha256(parent.target_id.encode()).hexdigest()[:20]:
            raise ValueError("reserved selector identity differs")
        initial_id, initial_plan_id, initial_apply_id = _job_ids(core.id)
        initial = jobs.get(initial_id)
        initial_plan = jobs.get(initial_plan_id)
        initial_apply = jobs.get(initial_apply_id)
        if (initial is None or initial_plan is None or initial_apply is None
                or initial.action != "provider_keyed_initial"
                or initial_plan.action != "provider_keyed_initial_plan"
                or initial_apply.action != "provider_keyed_initial_apply"
                or initial_plan.status != "succeeded" or initial_apply.status != "succeeded"
                or not initial_plan.events
                or initial_plan.events[-1].message != "reviewed provider plan saved"
                or any(row.target != parent.target
                       or row.target_type != parent.target_type
                       or row.target_id != parent.target_id
                       or row.requested_by != parent.requested_by
                       for row in (initial, initial_plan, initial_apply))):
            raise ValueError("original selector creation generation differs")
        plan_data = initial_plan.events[-1].data
        if (type(plan_data) is not dict
                or plan_data.get("coreJobId") != core.id
                or plan_data.get("corePlanId") != core.input["corePlanId"]
                or plan_data.get("providerConnectionId") != bound.intent.credential_record_id
                or plan_data.get("selectorTag") != selector
                or plan_data.get("sourceSha256") != bound.workspace.source_sha256
                or plan_data.get("credentialSecretSha256")
                != bound.intent.credential_secret_sha256
                or plan_data.get("credentialUpdatedAt")
                != bound.intent.credential_updated_at):
            raise ValueError("original selector plan differs")
        require_initial_selector_absence_provenance(
            initial_apply, engagement_id=parent.target_id, core_job_id=core.id,
            core_plan_id=core.input["corePlanId"], plan_job_id=initial_plan.id,
            connection_id=bound.intent.credential_record_id,
            credential_secret_sha256=bound.intent.credential_secret_sha256,
            credential_updated_at=bound.intent.credential_updated_at,
            selector_tag=selector, source_sha256=bound.workspace.source_sha256,
            plan_sha256=plan_data["planSha256"], plan_path=Path(plan_data["planPath"]),
            terraform_binary_path=Path(plan_data["terraformBinaryPath"]),
            terraform_binary_sha256=plan_data["terraformBinarySha256"],
        )
        absence_prefix = (
            f"job-provider-keyed-core-destroy-absence-{core.id.removeprefix('job-')}-attempt-")
        candidates = [row for row in jobs.list_for_engagement(parent.target_id)
                      if row.action == CORE_ABSENCE_ACTION and row.status == "succeeded"
                      and row.id.startswith(absence_prefix)]
        if (len(candidates) != 1
                or candidates[0].events[-1].message != "core destroy exact absence proved"
                or candidates[0].input.get("teardownParentId") != parent.id
                or candidates[0].input.get("coreJobId") != core.id
                or candidates[0].input.get("scopeSnapshotId")
                != parent.input["scopeSnapshot"]["snapshotId"]):
            raise ValueError("exact OCI absence generation differs")
        core_absence = candidates[0]
        absence_recognizer = (prove_pending_keyed_oci_core_destroy_absence if published
                              else core_absence_recognizer)
        if absence_recognizer(
                teardown_parent_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup,
        ) != core_absence:
            raise ValueError("canonical OCI absence differs")
        negative = (_published_negative(
            parent, core, parent.input["scopeSnapshot"], environment=environment,
            state_root=state_root, jobs=jobs, plans=plans, chains=chains,
            credentials=credentials, lookup=lookup, catalog=catalog,
        ) if published else None)
        secret_digest, updated_at, encrypted = _credential_snapshot(
            bound.intent.credential_record_id, credentials)
        if (secret_digest, updated_at) != (
                bound.intent.credential_secret_sha256,
                bound.intent.credential_updated_at):
            raise ValueError("selected provider credential differs")
        base = {
            "engagementId": parent.target_id, "coreJobId": core.id,
            "corePlanId": core.input["corePlanId"], "teardownParentId": parent.id,
            "scopeSnapshotId": parent.input["scopeSnapshot"]["snapshotId"],
            "providerScopeSha256": parent.input["scopeSnapshot"]["providerScopeSha256"],
            "selectorTag": selector,
            "providerConnectionId": bound.intent.credential_record_id,
            "credentialSecretSha256": secret_digest, "credentialUpdatedAt": updated_at,
            "initialApplyJobId": initial_apply.id,
            "initialApplyJournalSha256": job_event_digest(initial_apply.events),
            "coreAbsenceJobId": core_absence.id,
            "coreAbsenceJournalSha256": job_event_digest(core_absence.events),
            "mutation": True,
        }
        if negative is not None:
            base.update({"inspectorNegativeJobId": negative.id,
                         "inspectorNegativeJournalSha256": job_event_digest(negative.events)})
        child_id = f"job-provider-keyed-selector-retirement-{core.id.removeprefix('job-')}"
        child = jobs.get(child_id)
        related = [row for row in jobs.list_for_engagement(parent.target_id)
                   if row.action == ACTION and row.input.get("coreJobId") == core.id]
        if (child is None or related != [child] or child.action != ACTION
                or child.status != "succeeded" or child.finished_at is None
                or child.target != parent.target or child.target_type != parent.target_type
                or child.target_id != parent.target_id
                or child.requested_by != parent.requested_by
                or child.artifact_refs != []
                or child.input != base
                or len(child.events) != 4
                or [event.sequence for event in child.events] != [1, 2, 3, 4]
                or any(event.level != "info" for event in child.events)
                or [event.message for event in child.events[:3]] != [
                    "selector retirement queued", "selector retirement started",
                    "selector DELETE intended"]
                or [event.data for event in child.events[:3]] != [{}, {}, {
                    "selectorTag": selector, "scopeSnapshotId": base["scopeSnapshotId"],
                    "initialApplyJournalSha256": base["initialApplyJournalSha256"],
                    "coreAbsenceJournalSha256": base["coreAbsenceJournalSha256"],
                    **({"inspectorNegativeJobId": negative.id,
                        "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"]}
                       if negative is not None else {}),
                }]
                or not (
                    (child.events[3].message == "selector DELETE 204 received"
                     and child.events[3].data == {
                         "httpStatus": 204, "selectorTag": selector})
                    or (child.events[3].message == "selector absence reconciled"
                        and child.events[3].data == {
                            "selectorTag": selector, "exactGetStatus": 404,
                            "completeTagListAbsent": True})
                )):
            raise ValueError("saved one-shot selector success differs")
        token = decrypt_secret(encrypted)
        if type(token) is not str or not token:
            raise ValueError("selected provider credential unavailable")
        status = status_transport or UrllibDeleteTransport()

        def fence():
            if (source() != (bound_source, bound) or jobs.get(child.id) != child
                    or jobs.get(initial.id) != initial
                    or jobs.get(initial_plan.id) != initial_plan
                    or jobs.get(initial_apply.id) != initial_apply
                    or jobs.get(core_absence.id) != core_absence
                    or (negative is not None and jobs.get(negative.id) != negative)
                    or _credential_snapshot(bound.intent.credential_record_id, credentials)
                    != (secret_digest, updated_at, encrypted)):
                raise ValueError("selector success authority changed")
            _require_destroy_fence(bound.workspace, bound.intent)

        for _ in range(2):
            fence()
            _read_empty_membership(catalog, token, selector, fence, tag_present=False)
            fence()
            if status.get_tag_status(token, selector) != 404:
                raise ValueError("exact selector GET is not absent")
            fence()
        return child
    except Exception:
        raise SelectorRetirementAttention(
            "saved selector retirement or current provider absence is unverified"
        ) from None
