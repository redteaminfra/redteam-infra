# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private Linode Inspector cleanup for pending keyed teardown.

This binds a successful public-negative receipt and the original selected
credential to the exact owned host/firewall. The preview grants no DELETE authority.
"""

from __future__ import annotations

from app.services.provider_keyed_published_initial_cleanup_authority import (
    queued_cleanup_event_data, validate_cleanup_negative, seal_marker,
    service_retirement_receipt, validate_service_retirement_receipt,
)

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

from app.integrations.linode_validation import LinodeValidationError, UrllibLinodeTransport
from app.domain import JobEvent
from app.services.credentials import decrypt_secret_value
from app.services.observer_checks import (
    INSPECTION_ACTION, INSPECTOR_READINESS_ACTION, INSPECTOR_RESOURCE_SOURCE,
    _inspector_host_from_settings,
    _is_inspector_resource_record, _inspector_firewall_label,
)
from app.services.provider_keyed_comprehensive_teardown import (
    _FENCE, _boundary, _child_id, recognize_provider_keyed_group_retired,
)
from app.services.provider_keyed_inspector_negative import (
    ACTION as NEGATIVE_ACTION, _sha as _negative_input_sha,
    prove_pending_keyed_inspector_negative,
)
from app.services.provider_keyed_inspector_provider_proof import _linode
from app.services.provider_keyed_inspector_readiness_publish import (
    recognize_historical_keyed_inspector_readiness,
)
from app.services.provider_keyed_pending_retirement import recognize_pending_keyed_group_retired
from app.services.provider_keyed_core_destroy_absence import (
    ACTION as CORE_ABSENCE_ACTION, prove_pending_keyed_oci_core_destroy_absence,
)
from app.services.provider_keyed_selector_retirement import recognize_pending_digitalocean_selector_retired
from app.services.provider_keyed_destroy_absence_preflight import (
    reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, StoredJobRun, job_event_digest,
    valid_inspector_management_source_cidr,
)
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    TERMINAL_RECORD_STATUSES, SqlAlchemyProviderResourceRepository,
)


class LinodeInspectorCleanupAttention(ValueError):
    """Cleanup authority or provider outcome is uncertain; no DELETE is retried."""


class _LinodeAbsencePending(ValueError):
    """A prior exact DELETE has not yet converged; reads alone may retry."""


def _published_terminal_binding(parent, group_events, retirement_receipt=None) -> dict:
    """Seal whichever published generation the one-action teardown retired."""
    marker = parent.input["publishedSource"]
    appended = parent.input.get("publishedAppendSource")
    if appended is not None and (type(appended) is not dict
                                 or appended.get("initial_source") != marker):
        raise ValueError("published append terminal source differs")
    marker_seal = seal_marker(parent.input["scopeSnapshot"])
    if marker_seal is not None:
        validate_service_retirement_receipt(parent, parent.input["scopeSnapshot"], retirement_receipt)
    elif retirement_receipt is not None:
        raise ValueError("legacy published cleanup acquired service retirement receipt")
    return {
        "variant": "published_append" if appended is not None else "published",
        "publishedSourceSha256": _negative_input_sha(appended if appended is not None else marker),
        "initialJournalSha256": marker["initial_journal_sha256"],
        "groupRetirementJournalSha256": job_event_digest(group_events),
        **({"appendJournalSha256": appended["append_journal_sha256"]}
           if appended is not None else {}),
        **({"publishedInitialCleanupAuthority": marker_seal,
            "serviceRetirementReceiptSha256": _negative_input_sha(retirement_receipt)}
           if marker_seal is not None else {}),
    }


@dataclass(frozen=True)
class LinodeInspectorCleanupPreview:
    teardown_parent_id: str
    coordinator_job_id: str
    negative_job_id: str
    negative_journal_sha256: str
    negative_input_sha256: str
    creation_journal_sha256: str
    credential_id: str
    credential_sha256: str
    host_record_id: str
    firewall_record_id: str
    host_id: str
    firewall_id: str
    origin: str = "fresh_created"
    adoption_job_id: str = ""


@dataclass(frozen=True)
class LinodeDeleteResponse:
    status: int
    body: bytes


class UrllibLinodeExactDelete:
    """Keep HTTP status and one-byte body evidence that generic transport drops."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def delete(self, path: str, token: str) -> LinodeDeleteResponse:
        if re.fullmatch(r"/(?:linode/instances|networking/firewalls)/[1-9][0-9]*", path) is None:
            raise ValueError("exact Linode DELETE path required")
        request = urllib.request.Request(
            f"https://api.linode.com/v4{path}", method="DELETE",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                # A third byte distinguishes exact {} from a longer body.
                return LinodeDeleteResponse(response.status, response.read(3))
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            raise LinodeInspectorCleanupAttention("Linode DELETE outcome uncertain") from None


def _complete_rows(transport, token: str, endpoint: str) -> tuple[dict, ...]:
    """Read a complete Linode collection while retaining identity-bearing rows."""
    ids: set[str] = set()
    rows: list[dict] = []
    pages = results = None
    for page in range(1, 101):
        body = transport.request("GET", f"{endpoint}?page={page}&page_size=100", token)
        data = body.get("data") if type(body) is dict else None
        if (type(data) is not list or type(body.get("page")) is not int
                or body["page"] != page or type(body.get("pages")) is not int
                or body["pages"] < 1 or type(body.get("results")) is not int
                or body["results"] < 0 or len(data) > 100):
            raise ValueError("Linode list visibility incomplete")
        if pages is None:
            pages, results = body["pages"], body["results"]
        elif pages != body["pages"] or results != body["results"]:
            raise ValueError("Linode list changed during pagination")
        for item in data:
            identifier = item.get("id") if type(item) is dict else None
            if type(identifier) not in {int, str} or re.fullmatch(r"[1-9][0-9]*", str(identifier)) is None:
                raise ValueError("Linode list identity incomplete")
            if str(identifier) in ids:
                raise ValueError("Linode list contains duplicate identity")
            ids.add(str(identifier))
            rows.append(item)
        if page == pages:
            break
    else:
        raise ValueError("Linode list exceeds reviewed page bound")
    if len(ids) != results:
        raise ValueError("Linode list result count differs")
    return tuple(rows)


def _complete_ids(transport, token: str, endpoint: str) -> set[str]:
    return {str(row["id"]) for row in _complete_rows(transport, token, endpoint)}


def _inspector_origin(*, snapshot: dict, events: list[JobEvent], coordinator_id: str,
                      engagement_id: str, host_row, firewall_row, host_ip: str,
                      source_cidr: str, jobs) -> tuple[str, dict, str]:
    """Bind a fresh-created or retained Inspector to its frozen owner."""
    if (host_row.adoption_job_id != firewall_row.adoption_job_id
            or not host_row.adoption_job_id):
        raise ValueError("Inspector pair has no common owner")
    creation = [event for event in events if event.message == "inspector_create_started"]
    retained = [event for event in events if event.message == "retained_inspector_ready"]
    if len(creation) == 1 and not retained:
        intent = creation[0].data
        if (host_row.adoption_job_id != coordinator_id
                or type(intent) is not dict
                or intent.get("provider") != "linode"
                or intent.get("resourceName") != host_row.name
                or intent.get("scopeSnapshotId") != snapshot["snapshotId"]
                or intent.get("managementSourceCidr") != source_cidr):
            raise ValueError("fresh Inspector creation identity differs")
        return "fresh_created", intent, host_row.adoption_job_id
    if creation or len(retained) != 1 or len(events) < 5 or events[4] != retained[0]:
        raise ValueError("Inspector origin journal differs")
    prefix = events[:5]
    if ([event.sequence for event in prefix] != [1, 2, 3, 4, 5]
            or any(event.level != "info" for event in prefix)
            or [event.message for event in prefix] != [
                "keyed teardown coordinator queued", "keyed teardown coordinator started",
                "keyed teardown handoff intended",
                "keyed teardown handoff verified; Inspector preflight pending",
                "retained_inspector_ready",
            ]
            or [event.data for event in prefix[:4]] != [
                queued_cleanup_event_data(snapshot), {}, {},
                {"corePlanId": snapshot["providerScopes"][0]["corePlanId"]},
            ]):
        raise ValueError("retained Inspector source prefix differs")
    from app.storage.job_repository import _RETAINED_READY_KEYS
    data = prefix[4].data
    owner = host_row.adoption_job_id
    owners = snapshot.get("inspector", {}).get("recordOwners")
    owned_ids = snapshot.get("inspector", {}).get("ownedProviderRecordIds")
    adoption = jobs.get(owner)
    if (type(data) is not dict or set(data) != _RETAINED_READY_KEYS
            or data["sourceJournalSha256"] != job_event_digest(prefix[:4])
            or data["scopeSnapshotId"] != snapshot["snapshotId"]
            or data["providerScopeSha256"] != snapshot["providerScopeSha256"]
            or data["provider"] != "linode"
            or data["hostRecordId"] != host_row.id
            or data["firewallRecordId"] != firewall_row.id
            or data["hostId"] != host_row.resource_id
            or data["firewallId"] != firewall_row.resource_id
            or data["publicIp"] != host_ip
            or data["sourceCidr"] != source_cidr
            or not valid_inspector_management_source_cidr(data["sourceCidr"])
            or type(data["credentialId"]) is not str
            or type(data["credentialUpdatedAt"]) is not str
            or type(data["credentialSha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", data["credentialSha256"]) is None
            or any(type(data[key]) is not str
                   or re.fullmatch(r"[0-9a-f]{64}", data[key]) is None
                   for key in ("keyFingerprintSha256", "providerProofSha256",
                               "sshPolicySha256", "nmapVersionSha256",
                               "claimGenerationSha256"))
            or type(owned_ids) is not list or set(owned_ids) != {host_row.id, firewall_row.id}
            or type(owners) is not dict or owners != {host_row.id: owner, firewall_row.id: owner}
            or type(host_row.metadata) is not dict
            or host_row.metadata.get("inspectionJobId") != owner
            or type(firewall_row.metadata) is not dict
            or firewall_row.metadata.get("inspectionJobId") != owner
            or adoption is None or adoption.action not in {
                INSPECTION_ACTION, INSPECTOR_READINESS_ACTION,
            } or adoption.status != "succeeded" or adoption.target_id != engagement_id):
        raise ValueError("retained Inspector ownership or readiness differs")
    return "retained", data, owner


def _retained_key_and_baseline(host, evidence: dict) -> None:
    from app.services.observer_checks import _inspector_support_baseline_current
    from app.services.provider_keyed_inspector_prepare_binder import (
        _existing_key_identity, _safe_key_identity, _verify_key_pair,
    )

    if not _inspector_support_baseline_current(host):
        raise ValueError("retained Inspector support baseline differs")
    key_path, fingerprint = _safe_key_identity(_existing_key_identity)
    if fingerprint != evidence["keyFingerprintSha256"]:
        raise ValueError("retained Inspector key fingerprint differs")
    _verify_key_pair(key_path, fingerprint)


def preview_pending_linode_inspector_cleanup(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None,
    sketch_repository=None, lease_lookup=None, transport=None,
    negative_recognizer=prove_pending_keyed_inspector_negative,
    readiness_recognizer=recognize_historical_keyed_inspector_readiness,
    decrypt_secret=decrypt_secret_value,
    do_catalog_transport=None, selector_status_transport=None,
) -> LinodeInspectorCleanupPreview:
    """Reprove retained ownership with the selected creation credential only."""
    try:
        if environment != "devtest" or not isinstance(state_root, Path):
            raise ValueError("private DevTest cleanup only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        published = "publishedSource" in parent.input
        coordinator = jobs.get(_child_id(core.id))
        negative_id = f"job-provider-keyed-inspector-negative-{core.id.removeprefix('job-')}"
        negative = jobs.get(negative_id)
        if (operation != _FENCE
                or coordinator is None or coordinator.status != "running"
                or coordinator.input.get("phase") != (
                    "group_retired" if published else "pending_group_retired")
                or coordinator.target_id != parent.target_id
                or negative is None or negative.action != NEGATIVE_ACTION
                or negative.status != "succeeded" or negative.finished_at is None
                or negative.input.get("teardownParentId") != parent.id
                or negative.input.get("coreJobId") != core.id
                or negative.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                or negative.target_id != parent.target_id
                or negative.requested_by != parent.requested_by
                or len(negative.events) != 3
                or negative.events[-1].message != "inspector exact public negative proved"
                or any(event.level != "info" for event in negative.events)):
            raise ValueError("exact successful negative receipt required")
        historical = None
        published_retired = None
        if published:
            from app.services.provider_keyed_teardown_source import (
                _read_published_post_destroy_boundary,
            )

            def published_source():
                return _read_published_post_destroy_boundary(
                    parent.id, environment=environment, state_root=state_root,
                    job_repository=jobs, plan_repository=plans,
                    sketch_repository=sketch_repository,
                    credential_repository=credentials, lease_lookup=lookup,
                    credential_check=_credential_snapshot, retired=True,
                )

            historical = published_source()
            if (historical[1].parent != parent or historical[1].core != core
                    or historical[1].scope != snapshot["providerScopes"][0]):
                raise ValueError("published historical source differs")
            published_retired = recognize_provider_keyed_group_retired(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                sketch_repository=sketch_repository,
                credential_repository=credentials,
                provider_resource_repository=resources, lease_lookup=lookup,
            )
            absence_prefix = (
                f"job-provider-keyed-core-destroy-absence-{core.id.removeprefix('job-')}-attempt-")
            saved_absences = [row for row in jobs.list_for_engagement(parent.target_id)
                              if row.action == CORE_ABSENCE_ACTION
                              and row.status == "succeeded"
                              and row.id.startswith(absence_prefix)]
            if (len(saved_absences) != 1
                    or saved_absences[0].input.get("teardownParentId") != parent.id
                    or saved_absences[0].input.get("coreJobId") != core.id
                    or saved_absences[0].input.get("scopeSnapshotId") != snapshot["snapshotId"]):
                raise ValueError("saved OCI absence is missing")
            saved_absence = saved_absences[0]
            if prove_pending_keyed_oci_core_destroy_absence(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup,
            ) != saved_absence:
                raise ValueError("saved OCI absence differs")
        settings = settings_repo.get(parent.target_id)
        host = _inspector_host_from_settings(settings.current_host, settings=settings) if settings else None
        if (settings is None or settings.enabled is not True or settings.provider != "linode"
                or host is None or host.provider != "linode"):
            raise ValueError("retained Linode Inspector differs")
        firewall_data = host.metadata.get("providerFirewall") if type(host.metadata) is dict else None
        firewall_id = firewall_data.get("resourceId") if type(firewall_data) is dict else None
        if (type(host.resource_id) is not str or re.fullmatch(r"[1-9][0-9]*", host.resource_id) is None
                or type(firewall_id) is not str or re.fullmatch(r"[1-9][0-9]*", firewall_id) is None):
            raise ValueError("exact Linode provider IDs required")
        host_record_id = f"linode:inspector:{host.resource_id}"
        firewall_record_id = f"linode:inspector-firewall:{firewall_id}"
        rows = resources.list_for_engagement(parent.target_id)
        active = [row for row in rows if row.status.lower() not in TERMINAL_RECORD_STATUSES
                  and (_is_inspector_resource_record(row)
                       or row.resource_type == "inspector_firewall"
                       or row.source == INSPECTOR_RESOURCE_SOURCE)]
        if (len(active) != 2 or {row.id for row in active}
                != {host_record_id, firewall_record_id}):
            raise ValueError("exclusive owned Inspector pair differs")
        owned = {row.id: row for row in active}
        host_row, firewall_row = owned[host_record_id], owned[firewall_record_id]
        if (host_row.engagement_id != parent.target_id
                or host_row.source != INSPECTOR_RESOURCE_SOURCE
                or host_row.provider != "linode" or host_row.resource_type != "inspector_instance"
                or host_row.resource_id != host.resource_id or host_row.name != host.name
                or host_row.region != host.region or host_row.metadata.get("barraganOwned") is not True
                or host_row.metadata.get("role") != "inspector"
                or firewall_row.engagement_id != parent.target_id
                or firewall_row.source != INSPECTOR_RESOURCE_SOURCE
                or firewall_row.provider != "linode" or firewall_row.resource_type != "inspector_firewall"
                or firewall_row.resource_id != firewall_id
                or firewall_row.name != _inspector_firewall_label("linode", host.name)
                or firewall_row.region != host.region
                or firewall_row.metadata.get("barraganOwned") is not True
                or firewall_row.metadata.get("role") != "inspector_firewall"
                or firewall_row.adoption_job_id != host_row.adoption_job_id):
            raise ValueError("owned Inspector metadata differs")
        events = coordinator.events
        if (not events or [event.sequence for event in events] != list(range(1, len(events) + 1))
                or any(event.level != "info" for event in events)):
            raise ValueError("Inspector creation journal differs")
        origin, intent, adopter = _inspector_origin(
            snapshot=snapshot, events=events, coordinator_id=coordinator.id,
            engagement_id=parent.target_id, host_row=host_row, firewall_row=firewall_row,
            host_ip=host.public_ip,
            source_cidr=firewall_data["managementSourceCidr"], jobs=jobs)
        if (type(intent.get("credentialId")) is not str
                or type(intent.get("credentialSha256")) is not str
                or re.fullmatch(r"[0-9a-f]{64}", intent["credentialSha256"]) is None):
            raise ValueError("selected Inspector credential receipt differs")
        if origin == "fresh_created":
            selected_readiness = (recognize_historical_keyed_inspector_readiness
                                  if published else readiness_recognizer)
            ready = selected_readiness(
                coordinator.id, parent.target_id, environment=environment,
                state_root=state_root, job_repository=jobs, plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resources,
                sketch_repository=sketch_repository, credential_repository=credentials,
                lease_lookup=lookup,
            )
            if (ready.host_record_id != host_record_id
                    or ready.firewall_record_id != firewall_record_id):
                raise ValueError("historical Inspector readiness differs")
        else:
            selected_group = (recognize_provider_keyed_group_retired if published
                              else recognize_pending_keyed_group_retired)
            selected_group(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                sketch_repository=sketch_repository,
                credential_repository=credentials, lease_lookup=lookup,
            )
            _retained_key_and_baseline(host, intent)
        selected = credentials.get(intent["credentialId"])
        if (selected is None or selected.provider != "linode" or selected.status != "active"
                or (origin == "fresh_created" and selected.alias != intent.get("credentialAlias"))
                or selected.updated_at != intent.get("credentialUpdatedAt")
                or hashlib.sha256(selected.encrypted_secret.encode()).hexdigest()
                != intent["credentialSha256"]):
            raise ValueError("selected Inspector credential changed")
        control = negative.input.get("positiveControl")
        if published:
            def fresh_do(parent_id, **options):
                return reconcile_successful_digitalocean_destroy_absence(
                    parent_id, **options, transport=do_catalog_transport,
                    max_attempts=1, poll_interval_seconds=0,
                )

            class NoProbeReplay:
                def run(self, **_kwargs):
                    raise ValueError("saved Inspector proof attempted probe replay")

            selected_negative = prove_pending_keyed_inspector_negative
        else:
            selected_negative = negative_recognizer
        negative_options = dict(
            job_repository=jobs, plan_repository=plans,
            settings_repository=settings_repo, provider_resource_repository=resources,
            sketch_repository=sketch_repository, credential_repository=credentials,
            lease_lookup=lookup, positive_control=control,
        )
        if published:
            negative_options.update(do_absence_reader=fresh_do, runner=NoProbeReplay())
        recognized = selected_negative(
            parent.id, environment=environment, state_root=state_root,
            **negative_options,
        )
        if recognized != negative:
            raise ValueError("negative receipt changed")
        selector = None
        if published:
            selector = recognize_pending_digitalocean_selector_retired(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                sketch_repository=sketch_repository,
                credential_repository=credentials, lease_lookup=lookup,
                catalog_transport=do_catalog_transport,
                status_transport=selector_status_transport,
            )
        token = decrypt_secret(selected.encrypted_secret)
        if type(token) is not str or not token:
            raise ValueError("selected Inspector credential unavailable")
        client = transport or UrllibLinodeTransport(timeout=10)
        proof = _linode(client, token, name=host.name, region=host.region,
                        size=settings.size, host_id=host.resource_id,
                        firewall_id=firewall_id,
                        management_cidr=firewall_data["managementSourceCidr"])
        if (proof.host.public_ip != host.public_ip
                or host.resource_id not in _complete_ids(client, token, "/linode/instances")
                or firewall_id not in _complete_ids(client, token, "/networking/firewalls")):
            raise ValueError("Linode exact host/firewall visibility differs")
        if (jobs.get(coordinator.id) != coordinator or jobs.get(negative.id) != negative
                or (published and jobs.get(saved_absence.id) != saved_absence)
                or (published and (published_source() != historical
                                   or jobs.get(selector.id) != selector))
                or settings_repo.get(parent.target_id) != settings
                or resources.get(host_record_id) != host_row
                or resources.get(firewall_record_id) != firewall_row
                or credentials.get(selected.id) != selected
                or _boundary(parent.id, jobs, plans, lookup) != (parent, core, snapshot, operation)):
            raise ValueError("Inspector authority changed during provider reads")
        if published and recognize_provider_keyed_group_retired(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                sketch_repository=sketch_repository,
                credential_repository=credentials,
                provider_resource_repository=resources, lease_lookup=lookup,
        ) != published_retired:
            raise ValueError("published retired provider records changed during reads")
        return LinodeInspectorCleanupPreview(
            parent.id, coordinator.id, negative.id, job_event_digest(negative.events),
            _negative_input_sha(negative.input),
            job_event_digest(events), selected.id, intent["credentialSha256"],
            host_record_id, firewall_record_id, host.resource_id, firewall_id,
            origin, adopter)
    except Exception:
        raise LinodeInspectorCleanupAttention(
            "Linode Inspector cleanup preview is unverified; no DELETE was sent") from None


ACTION = "provider_keyed_inspector_linode_cleanup"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append(jobs, child: StoredJobRun, message: str, data: dict) -> StoredJobRun:
    """Action-specific SQLite writer slot + exact input/journal CAS."""
    from sqlalchemy import update
    from app.storage.database import db
    from app.storage.models import JobEventModel, JobRunModel

    if (child.action != ACTION or child.status != "running"
            or child.finished_at is not None or child.artifact_refs != []):
        raise ValueError("Inspector cleanup child is not running")
    event = JobEvent(len(child.events) + 1, "info", message, data)
    if db.session.get_bind().dialect.name != "sqlite":
        raise ValueError("reviewed SQLite journal required")
    try:
        changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == child.id, JobRunModel.action == ACTION,
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.input == child.input,
            JobRunModel.target_id == child.target_id,
            JobRunModel.requested_by == child.requested_by,
            JobRunModel.artifact_refs == [],
        ).values(status="running"))
        if changed.rowcount != 1 or jobs.get(child.id) != child:
            raise ValueError("Inspector cleanup journal changed")
        db.session.add(JobEventModel(job_id=child.id, sequence=event.sequence,
                                     level=event.level, message=message, data=data))
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    updated = jobs.get(child.id)
    if (updated is None or updated.events != [*child.events, event]):
        raise ValueError("Inspector cleanup journal commit uncertain")
    return updated


def _exact_absent(transport, token: str, path: str, collection: str,
                  identifier: str, *, fence=lambda: None) -> None:
    """Two complete GET404/list rounds; 404 alone is not provider absence."""
    for _ in range(2):
        fence()
        try:
            transport.request("GET", path, token)
        except LinodeValidationError as exc:
            cause = exc.__cause__
            if not isinstance(cause, urllib.error.HTTPError) or cause.code != 404:
                raise _LinodeAbsencePending("Linode exact GET is inconclusive") from None
        else:
            raise _LinodeAbsencePending("Linode exact resource remains visible")
        if identifier in _complete_ids(transport, token, collection):
            raise _LinodeAbsencePending("Linode list still contains exact resource")
        fence()


def _empty_firewall_devices(transport, token: str, firewall_id: str) -> None:
    path = f"/networking/firewalls/{firewall_id}/devices"
    if _complete_ids(transport, token, path):
        raise ValueError("Inspector firewall still has attached devices")


def _base_from_preview(preview: LinodeInspectorCleanupPreview, *, parent, core,
                       snapshot: dict, selector: StoredJobRun) -> dict:
    return {
        "teardownParentId": parent.id, "coreJobId": core.id,
        "scopeSnapshotId": snapshot["snapshotId"],
        "coordinatorJobId": preview.coordinator_job_id,
        "creationJournalSha256": preview.creation_journal_sha256,
        "negativeJobId": preview.negative_job_id,
        "negativeJournalSha256": preview.negative_journal_sha256,
        "negativeInputSha256": preview.negative_input_sha256,
        "selectorJobId": selector.id,
        "selectorJournalSha256": job_event_digest(selector.events),
        "credentialId": preview.credential_id,
        "credentialSha256": preview.credential_sha256,
        "hostRecordId": preview.host_record_id,
        "firewallRecordId": preview.firewall_record_id,
        "hostId": preview.host_id, "firewallId": preview.firewall_id,
        "origin": preview.origin,
        "adoptionJobId": preview.adoption_job_id or preview.coordinator_job_id,
    }


def _journal_messages(child: StoredJobRun) -> list[str]:
    messages = [event.message for event in child.events]
    expected = ["inspector cleanup queued", "inspector cleanup started",
                "inspector host DELETE intended"]
    if messages[:2] != expected[:2]:
        raise ValueError("Inspector cleanup journal prefix differs")
    tail = messages[2:]
    if tail and tail[0] != expected[2]:
        raise ValueError("Inspector host DELETE intent missing")
    valid = [
        [],
        ["inspector host DELETE intended"],
        ["inspector host DELETE intended", "inspector host DELETE 200 received"],
        ["inspector host DELETE intended", "inspector host absence proved"],
        ["inspector host DELETE intended", "inspector host DELETE 200 received",
         "inspector host absence proved"],
    ]
    for prefix in valid[3:5]:
        valid.extend([prefix + ["inspector firewall DELETE intended"],
                      prefix + ["inspector firewall DELETE intended",
                                "inspector firewall DELETE 200 received"],
                      prefix + ["inspector firewall DELETE intended",
                                "inspector firewall absence proved"],
                      prefix + ["inspector firewall DELETE intended",
                                "inspector firewall DELETE 200 received",
                                "inspector firewall absence proved"]])
    if tail not in valid or [event.sequence for event in child.events] != list(
            range(1, len(child.events) + 1)) or any(event.level != "info" for event in child.events):
        raise ValueError("Inspector cleanup journal sequence differs")
    expected_data = {
        "inspector cleanup queued": {}, "inspector cleanup started": {},
        "inspector host DELETE intended": {
            "path": f"/linode/instances/{child.input.get('hostId')}",
            "resourceId": child.input.get("hostId")},
        "inspector host DELETE 200 received": {},
        "inspector host absence proved": {},
        "inspector firewall DELETE intended": {
            "path": f"/networking/firewalls/{child.input.get('firewallId')}",
            "resourceId": child.input.get("firewallId")},
        "inspector firewall DELETE 200 received": {},
        "inspector firewall absence proved": {},
    }
    if any(event.data != expected_data[event.message] for event in child.events):
        raise ValueError("Inspector cleanup journal evidence differs")
    return messages


def _static_authority(parent_id: str, child: StoredJobRun, *, jobs, plans,
                      settings_repo, resources, credentials, lookup):
    parent, core, snapshot, operation = _boundary(parent_id, jobs, plans, lookup)
    published = "publishedSource" in parent.input
    if (operation != _FENCE
            or child.action != ACTION or child.status != "running"
            or child.target_id != parent.target_id or child.requested_by != parent.requested_by
            or child.input.get("teardownParentId") != parent.id
            or child.input.get("coreJobId") != core.id
            or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]):
        raise ValueError("Linode cleanup generation differs")
    coordinator = jobs.get(child.input["coordinatorJobId"])
    negative = jobs.get(child.input["negativeJobId"])
    if (coordinator is None or coordinator.id != _child_id(core.id)
            or coordinator.status != "running"
            or coordinator.input.get("phase") != (
                "group_retired" if published else "pending_group_retired")
            or coordinator.target_id != parent.target_id
            or job_event_digest(coordinator.events) != child.input["creationJournalSha256"]
            or negative is None or negative.action != NEGATIVE_ACTION
            or negative.status != "succeeded" or negative.finished_at is None
            or negative.target_id != parent.target_id
            or job_event_digest(negative.events) != child.input["negativeJournalSha256"]):
        raise ValueError("sealed Inspector authority differs")
    if (_negative_input_sha(negative.input) != child.input.get("negativeInputSha256")
            or not re.fullmatch(r"[0-9a-f]{64}", child.input["negativeInputSha256"])):
        raise ValueError("sealed Inspector authority differs")
    validate_cleanup_negative(parent, core, snapshot, negative, jobs)
    settings = settings_repo.get(parent.target_id)
    host = _inspector_host_from_settings(settings.current_host, settings=settings) if settings else None
    rows = resources.list_for_engagement(parent.target_id)
    active = [row for row in rows if row.status.lower() not in TERMINAL_RECORD_STATUSES
              and (_is_inspector_resource_record(row) or row.resource_type == "inspector_firewall"
                   or row.source == INSPECTOR_RESOURCE_SOURCE)]
    owned = {row.id: row for row in active}
    host_row = owned.get(child.input["hostRecordId"])
    firewall_row = owned.get(child.input["firewallRecordId"])
    host_firewall = host.metadata.get("providerFirewall") if host is not None else None
    if (settings is None or settings.enabled is not True or settings.provider != "linode"
            or host is None or host.provider != "linode"
            or host.resource_id != child.input["hostId"]
            or type(host_firewall) is not dict
            or host_firewall.get("resourceId") != child.input["firewallId"]
            or host_firewall.get("name") != _inspector_firewall_label("linode", host.name)
            or len(active) != 2 or len(owned) != 2
            or host_row is None or firewall_row is None
            or host_row.engagement_id != parent.target_id
            or host_row.source != INSPECTOR_RESOURCE_SOURCE
            or host_row.provider != "linode" or host_row.resource_type != "inspector_instance"
            or host_row.resource_id != host.resource_id
            or host_row.name != host.name or host_row.region != host.region
            or firewall_row.source != INSPECTOR_RESOURCE_SOURCE
            or firewall_row.engagement_id != parent.target_id
            or firewall_row.provider != "linode"
            or firewall_row.resource_type != "inspector_firewall"
            or firewall_row.resource_id != child.input["firewallId"]
            or firewall_row.name != host_firewall["name"]
            or firewall_row.region != host.region
            or host_row.metadata.get("barraganOwned") is not True
            or host_row.metadata.get("role") != "inspector"
            or host_row.metadata.get("providerFirewall") != host_firewall
            or firewall_row.metadata.get("barraganOwned") is not True
            or firewall_row.metadata.get("role") != "inspector_firewall"
            or firewall_row.metadata.get("inspectorHostResourceId") != host.resource_id
            or firewall_row.metadata.get("managementSourceCidr")
            != host_firewall.get("managementSourceCidr")):
        raise ValueError("owned Inspector rows or settings changed")
    origin, intent, adopter = _inspector_origin(
        snapshot=snapshot, events=coordinator.events, coordinator_id=coordinator.id,
        engagement_id=parent.target_id, host_row=host_row, firewall_row=firewall_row,
        host_ip=host.public_ip, source_cidr=host_firewall["managementSourceCidr"],
        jobs=jobs)
    if (child.input.get("origin") != origin
            or child.input.get("adoptionJobId") != adopter
            or intent.get("credentialId") != child.input["credentialId"]
            or intent.get("credentialSha256") != child.input["credentialSha256"]):
        raise ValueError("sealed Inspector origin changed")
    if (origin == "fresh_created"
            and (adopter != coordinator.id
                 or host_firewall.get("managementSourceCidr")
                 != intent.get("managementSourceCidr"))):
        raise ValueError("fresh Inspector ownership differs")
    selected = credentials.get(child.input["credentialId"])
    if (selected is None or selected.provider != "linode" or selected.status != "active"
            or (origin == "fresh_created" and selected.alias != intent.get("credentialAlias"))
            or selected.updated_at != intent.get("credentialUpdatedAt")
            or hashlib.sha256(selected.encrypted_secret.encode()).hexdigest()
            != child.input["credentialSha256"]):
        raise ValueError("selected Inspector credential changed")
    return parent, core, snapshot, coordinator, negative, settings, host_row, firewall_row, selected


def _wait_absent(transport, token: str, path: str, collection: str,
                 identifier: str, *, sleep, fence=lambda: None, attempts: int = 120) -> None:
    for attempt in range(attempts):
        try:
            _exact_absent(transport, token, path, collection, identifier, fence=fence)
            return
        except _LinodeAbsencePending:
            if attempt == attempts - 1:
                raise
            fence()
            sleep(5)


def _published_retired_authority(parent_id: str, *, environment: str,
                                 state_root: Path, jobs, plans, resources,
                                 credentials, sketch_repository, lookup):
    """Reprove immutable published history while the live Inspector is removed."""
    from app.services.provider_keyed_teardown_source import (
        _read_published_post_destroy_boundary,
    )

    source, bound = _read_published_post_destroy_boundary(
        parent_id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans,
        sketch_repository=sketch_repository, credential_repository=credentials,
        lease_lookup=lookup, credential_check=_credential_snapshot,
        retired=True,
    )
    retired = recognize_provider_keyed_group_retired(
        parent_id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans,
        sketch_repository=sketch_repository, credential_repository=credentials,
        provider_resource_repository=resources, lease_lookup=lookup,
    )
    expected_variant = ("published_append" if "publishedAppendSource" in bound.parent.input
                        else "published")
    if (source.variant != expected_variant or bound.parent.id != parent_id
            or len(retired) != 2):
        raise ValueError("published Inspector source differs")
    return source, bound, retired


def retire_pending_linode_inspector(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None,
    sketch_repository=None, lease_lookup=None,
    read_transport=None, delete_transport=None, decrypt_secret=decrypt_secret_value,
    sleep=time.sleep, preview_reader=preview_pending_linode_inspector_cleanup,
    readiness_reader=recognize_historical_keyed_inspector_readiness,
    group_reader=recognize_pending_keyed_group_retired,
    oci_reader=prove_pending_keyed_oci_core_destroy_absence,
    selector_reader=recognize_pending_digitalocean_selector_retired,
    negative_reader=prove_pending_keyed_inspector_negative,
    selector_catalog_transport=None, selector_status_transport=None,
    do_catalog_transport=None,
) -> StoredJobRun:
    """One-shot exact host then firewall DELETE; restart only GET-reconciles."""
    try:
        if environment != "devtest":
            raise ValueError("DevTest only")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
        resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
        credentials = credential_repository or SqlAlchemyCredentialRepository()
        lookup = lease_lookup or _db_lease_lookup
        saved_parent = jobs.get(teardown_parent_id)
        if saved_parent is not None and saved_parent.status == "succeeded":
            return recognize_pending_linode_inspector_retired(
                teardown_parent_id, environment=environment,
                job_repository=jobs, plan_repository=plans,
                settings_repository=settings_repo,
                provider_resource_repository=resources,
                sketch_repository=sketch_repository, lease_lookup=lookup)
        parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        published = "publishedSource" in parent.input
        if operation != _FENCE:
            raise ValueError("teardown fence differs")
        child_id = f"job-provider-keyed-inspector-linode-cleanup-{core.id.removeprefix('job-')}"
        child = jobs.get(child_id)
        selected_preview = (preview_pending_linode_inspector_cleanup
                            if published else preview_reader)

        def selected_selector() -> StoredJobRun:
            selected_reader = (recognize_pending_digitalocean_selector_retired
                               if published else selector_reader)
            selected = selected_reader(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                sketch_repository=sketch_repository,
                credential_repository=credentials, lease_lookup=lookup,
                catalog_transport=selector_catalog_transport,
                status_transport=selector_status_transport,
            )
            if (type(selected) is not StoredJobRun or selected.status != "succeeded"
                    or selected.target_id != parent.target_id
                    or selected.requested_by != parent.requested_by):
                raise ValueError("exact saved selector retirement is unproved")
            return selected

        if child is None:
            # A 403 or incomplete all-type DO inventory stops here, while the
            # live Inspector is still untouched.
            selector = selected_selector()
            preview = selected_preview(
                teardown_parent_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resources,
                credential_repository=credentials, sketch_repository=sketch_repository,
                lease_lookup=lookup, transport=read_transport,
                decrypt_secret=decrypt_secret,
                do_catalog_transport=do_catalog_transport,
                selector_status_transport=selector_status_transport,
            )
            child = StoredJobRun(
                child_id, ACTION, "queued", f"engagement:{parent.target_id}",
                "engagement", parent.target_id, parent.requested_by,
                _base_from_preview(preview, parent=parent, core=core,
                                   snapshot=snapshot, selector=selector),
                [], _now(), None, None,
                [JobEvent(1, "info", "inspector cleanup queued", {})],
            )
            saved = jobs.save_if_absent(child)
            if (saved is None or saved.id != child.id or saved.action != child.action
                    or saved.status != "queued" or saved.input != child.input
                    or saved.events != child.events or saved.target_id != child.target_id
                    or saved.requested_by != child.requested_by):
                raise ValueError("Inspector cleanup reservation raced")
            child = saved
        if child.status == "queued":
            started = jobs.start_if_queued(
                child, started_at=_now(),
                event=JobEvent(2, "info", "inspector cleanup started", {}))
            if started is None:
                raise ValueError("Inspector cleanup start raced")
            child = started
        if child.status == "succeeded":
            raise ValueError("cleanup child succeeded before terminal parent")
        messages = _journal_messages(child)
        static = _static_authority(parent.id, child, jobs=jobs, plans=plans,
                                   settings_repo=settings_repo, resources=resources,
                                   credentials=credentials, lookup=lookup)
        published_history = (_published_retired_authority(
            parent.id, environment=environment, state_root=state_root,
            jobs=jobs, plans=plans, resources=resources, credentials=credentials,
            sketch_repository=sketch_repository, lookup=lookup,
        ) if published else None)
        selected = static[-1]
        token = decrypt_secret(selected.encrypted_secret)
        if type(token) is not str or not token:
            raise ValueError("selected Inspector credential unavailable")
        reader = read_transport or UrllibLinodeTransport(timeout=10)
        deleter = delete_transport or UrllibLinodeExactDelete()
        host_path = f"/linode/instances/{child.input['hostId']}"
        firewall_path = f"/networking/firewalls/{child.input['firewallId']}"

        def fence():
            if (jobs.get(child.id) != child or _static_authority(
                    parent.id, child, jobs=jobs, plans=plans,
                    settings_repo=settings_repo, resources=resources,
                    credentials=credentials, lookup=lookup) != static):
                raise ValueError("Inspector cleanup authority changed")
            if published and _published_retired_authority(
                    parent.id, environment=environment, state_root=state_root,
                    jobs=jobs, plans=plans, resources=resources,
                    credentials=credentials, sketch_repository=sketch_repository,
                    lookup=lookup) != published_history:
                raise ValueError("published Inspector history changed")

        def historical_ready():
            if child.input["origin"] == "retained":
                current = _static_authority(
                    parent.id, child, jobs=jobs, plans=plans,
                    settings_repo=settings_repo, resources=resources,
                    credentials=credentials, lookup=lookup)
                host = _inspector_host_from_settings(
                    current[5].current_host, settings=current[5])
                evidence = current[3].events[4].data
                _retained_key_and_baseline(host, evidence)
                return
            selected_readiness = (recognize_historical_keyed_inspector_readiness
                                  if published else readiness_reader)
            ready = selected_readiness(
                static[3].id, parent.target_id, environment=environment,
                state_root=state_root, job_repository=jobs, plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resources,
                sketch_repository=sketch_repository, credential_repository=credentials,
                lease_lookup=lookup)
            if (ready.host_record_id != child.input["hostRecordId"]
                    or ready.firewall_record_id != child.input["firewallRecordId"]):
                raise ValueError("historical Inspector pair changed")

        if "inspector host DELETE intended" not in messages:
            selector = selected_selector()
            if (selector.id != child.input.get("selectorJobId")
                    or job_event_digest(selector.events)
                    != child.input.get("selectorJournalSha256")):
                raise ValueError("saved selector retirement changed before Linode GO")
            # Re-preview immediately before consuming the irreversible intent.
            preview = selected_preview(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resources,
                credential_repository=credentials, sketch_repository=sketch_repository,
                lease_lookup=lookup, transport=reader, decrypt_secret=decrypt_secret,
                do_catalog_transport=do_catalog_transport,
                selector_status_transport=selector_status_transport)
            if _base_from_preview(preview, parent=parent, core=core,
                                  snapshot=snapshot, selector=selector) != child.input:
                raise ValueError("Inspector preview changed before host GO")
            fence()
            child = _append(jobs, child, "inspector host DELETE intended",
                            {"path": host_path, "resourceId": child.input["hostId"]})
            fence()
            response = deleter.delete(host_path, token)
            if type(response) is not LinodeDeleteResponse or response != LinodeDeleteResponse(200, b"{}"):
                raise ValueError("Linode host DELETE receipt is not exact 200 {}")
            child = _append(jobs, child, "inspector host DELETE 200 received", {})
        _wait_absent(reader, token, host_path, "/linode/instances",
                     child.input["hostId"], sleep=sleep, fence=fence)
        fence()
        if "inspector host absence proved" not in _journal_messages(child):
            child = _append(jobs, child, "inspector host absence proved", {})

        if "inspector firewall DELETE intended" not in _journal_messages(child):
            historical_ready()
            if published:
                _reprove_pending_sources(
                    parent.id, child, environment=environment, state_root=state_root,
                    jobs=jobs, plans=plans, resources=resources, settings_repo=settings_repo,
                    credentials=credentials, sketch_repository=sketch_repository,
                    lookup=lookup, group_reader=group_reader, oci_reader=oci_reader,
                    selector_reader=selector_reader, negative_reader=negative_reader,
                    selector_catalog_transport=selector_catalog_transport,
                    selector_status_transport=selector_status_transport,
                    do_catalog_transport=do_catalog_transport)
            firewall = reader.request("GET", firewall_path, token)
            if (type(firewall) is not dict or str(firewall.get("id")) != child.input["firewallId"]
                    or firewall.get("label") != static[7].name
                    or child.input["firewallId"] not in _complete_ids(
                        reader, token, "/networking/firewalls")):
                raise ValueError("Inspector firewall changed before GO")
            _empty_firewall_devices(reader, token, child.input["firewallId"])
            fence()
            child = _append(jobs, child, "inspector firewall DELETE intended",
                            {"path": firewall_path, "resourceId": child.input["firewallId"]})
            fence()
            response = deleter.delete(firewall_path, token)
            if type(response) is not LinodeDeleteResponse or response != LinodeDeleteResponse(200, b"{}"):
                raise ValueError("Linode firewall DELETE receipt is not exact 200 {}")
            child = _append(jobs, child, "inspector firewall DELETE 200 received", {})
        _wait_absent(reader, token, firewall_path, "/networking/firewalls",
                     child.input["firewallId"], sleep=sleep, fence=fence)
        _wait_absent(reader, token, host_path, "/linode/instances",
                     child.input["hostId"], sleep=sleep, fence=fence)
        fence()
        if "inspector firewall absence proved" not in _journal_messages(child):
            child = _append(jobs, child, "inspector firewall absence proved", {})
        historical_ready()
        proof_receipts = _reprove_pending_sources(
            parent.id, child, environment=environment, state_root=state_root,
            jobs=jobs, plans=plans, resources=resources, settings_repo=settings_repo,
            credentials=credentials, sketch_repository=sketch_repository,
            lookup=lookup, group_reader=group_reader, oci_reader=oci_reader,
            selector_reader=selector_reader, negative_reader=negative_reader,
            selector_catalog_transport=selector_catalog_transport,
            selector_status_transport=selector_status_transport,
            do_catalog_transport=do_catalog_transport)
        return _finish_atomic(child, static=static, jobs=jobs, settings_repo=settings_repo,
                              resources=resources, parent_id=parent.id, plans=plans,
                              credentials=credentials, lookup=lookup,
                              sketch_repository=sketch_repository,
                              proof_receipts=proof_receipts,
                              environment=environment, state_root=state_root,
                              published_history=published_history)
    except Exception:
        raise LinodeInspectorCleanupAttention(
            "Linode Inspector cleanup requires attention; never replay an intended DELETE") from None


def _reprove_pending_sources(
    parent_id: str, child: StoredJobRun, *, environment: str, state_root: Path,
    jobs, plans, resources, settings_repo, credentials, sketch_repository, lookup,
    group_reader, oci_reader, selector_reader, negative_reader,
    selector_catalog_transport, selector_status_transport, do_catalog_transport,
) -> dict[str, str]:
    """Re-run only the canonical saved-success readers while queued/fenced."""
    parent, core, snapshot, operation = _boundary(parent_id, jobs, plans, lookup)
    if (operation != _FENCE or child.input.get("teardownParentId") != parent.id
            or child.input.get("coreJobId") != core.id
            or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]):
        raise ValueError("terminal source fence differs")
    published = "publishedSource" in parent.input
    selected_group = (recognize_provider_keyed_group_retired if published
                      else group_reader)
    group = selected_group(
        parent.id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans,
        sketch_repository=sketch_repository, credential_repository=credentials,
        provider_resource_repository=resources, lease_lookup=lookup)
    if type(group) is not tuple or len(group) != 2:
        raise ValueError("exact provider group retirement differs")
    selected_oci = (prove_pending_keyed_oci_core_destroy_absence if published
                    else oci_reader)
    saved_oci = None
    if published:
        absence_prefix = (
            f"job-provider-keyed-core-destroy-absence-{core.id.removeprefix('job-')}-attempt-")
        candidates = [row for row in jobs.list_for_engagement(parent.target_id)
                      if row.action == CORE_ABSENCE_ACTION
                      and row.status == "succeeded"
                      and row.id.startswith(absence_prefix)]
        if (len(candidates) != 1
                or candidates[0].input.get("teardownParentId") != parent.id
                or candidates[0].input.get("coreJobId") != core.id
                or candidates[0].input.get("scopeSnapshotId") != snapshot["snapshotId"]):
            raise ValueError("saved OCI absence is missing before cleanup")
        saved_oci = candidates[0]
    oci = selected_oci(parent.id, environment=environment, state_root=state_root,
                     job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
    if published and oci != saved_oci:
        raise ValueError("saved OCI absence changed before cleanup")
    selected_selector = (recognize_pending_digitalocean_selector_retired if published
                         else selector_reader)
    selector = selected_selector(
        parent.id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans,
        sketch_repository=sketch_repository, credential_repository=credentials,
        lease_lookup=lookup, catalog_transport=selector_catalog_transport,
        status_transport=selector_status_transport)
    negative_source = jobs.get(child.input["negativeJobId"])
    if (negative_source is None
            or (published and (negative_source.status != "succeeded"
                               or negative_source.action != NEGATIVE_ACTION))):
        raise ValueError("saved Inspector negative receipt missing")
    if published:
        class NoProbeReplay:
            def run(self, **_kwargs):
                raise ValueError("saved Inspector proof attempted probe replay")

        def fresh_do(parent_id, **options):
            return reconcile_successful_digitalocean_destroy_absence(
                parent_id, **options, transport=do_catalog_transport,
                max_attempts=1, poll_interval_seconds=0,
            )

        selected_negative = prove_pending_keyed_inspector_negative
        negative_extra = {"do_absence_reader": fresh_do, "runner": NoProbeReplay()}
    else:
        selected_negative = negative_reader
        negative_extra = {}
    negative = selected_negative(
        parent.id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans,
        settings_repository=settings_repo, provider_resource_repository=resources,
        sketch_repository=sketch_repository, credential_repository=credentials,
        lease_lookup=lookup,
        positive_control=negative_source.input.get("positiveControl"),
        **negative_extra)
    if (type(oci) is not StoredJobRun or oci.status != "succeeded"
            or oci.action != "provider_keyed_core_destroy_absence"
            or oci.input.get("teardownParentId") != parent.id
            or oci.input.get("coreJobId") != core.id
            or oci.input.get("corePlanId") != core.input["corePlanId"]
            or oci.input.get("scopeSnapshotId") != snapshot["snapshotId"]
            or type(selector) is not StoredJobRun or selector.status != "succeeded"
            or selector.action != "provider_keyed_selector_retirement"
            or selector.input.get("teardownParentId") != parent.id
            or selector.input.get("coreJobId") != core.id
            or selector.input.get("corePlanId") != core.input["corePlanId"]
            or selector.input.get("scopeSnapshotId") != snapshot["snapshotId"]
            or selector.id != child.input.get("selectorJobId")
            or job_event_digest(selector.events) != child.input.get("selectorJournalSha256")
            or type(negative) is not StoredJobRun or negative.status != "succeeded"
            or negative != negative_source
            or negative.id != child.input.get("negativeJobId")
            or job_event_digest(negative.events) != child.input.get("negativeJournalSha256")
            or _negative_input_sha(negative.input) != child.input.get("negativeInputSha256")
            or negative.target_id != parent.target_id
            or selector.target_id != parent.target_id
            or oci.target_id != parent.target_id):
        raise ValueError("canonical pending success receipts differ")
    return {
        "groupCoordinatorSha256": job_event_digest(jobs.get(_child_id(core.id)).events),
        "ociJobId": oci.id,
        "ociJournalSha256": job_event_digest(oci.events),
        "ociInputSha256": _negative_input_sha(oci.input),
        "selectorJobId": selector.id,
        "selectorJournalSha256": job_event_digest(selector.events),
        "selectorInputSha256": _negative_input_sha(selector.input),
        "negativeJobId": negative.id,
        "negativeJournalSha256": job_event_digest(negative.events),
        "negativeInputSha256": _negative_input_sha(negative.input),
    }


def _retire_sealed_services(parent, snapshot, stamp):
    """Writer-slot CAS only; caller commits or rolls back the whole finish."""
    from dataclasses import asdict
    from sqlalchemy import update
    from app.storage.database import db
    from app.storage.models import EngagementServiceModel
    from app.storage.service_repository import SqlAlchemyEngagementServiceRepository

    receipt = service_retirement_receipt(parent, snapshot, stamp.isoformat())
    if receipt is None:
        return None
    before = [entry["before"] for entry in receipt["services"]]
    current = [asdict(row) for row in SqlAlchemyEngagementServiceRepository().list_for_engagement(parent.target_id)]
    if sorted(current, key=lambda row: row["service_id"]) != before:
        raise ValueError("sealed service set changed during final CAS")
    for row in before:
        changed = db.session.execute(update(EngagementServiceModel).where(
            EngagementServiceModel.engagement_id == row["engagement_id"],
            EngagementServiceModel.service_id == row["service_id"],
            EngagementServiceModel.service_type == row["service_type"],
            EngagementServiceModel.name == row["name"],
            EngagementServiceModel.proxy_id == row["proxy_id"],
            EngagementServiceModel.status == row["status"],
            EngagementServiceModel.config == row["config"],
            EngagementServiceModel.apply_job_id == row["apply_job_id"],
            EngagementServiceModel.created_at == datetime.fromisoformat(row["created_at"]),
            EngagementServiceModel.updated_at == datetime.fromisoformat(row["updated_at"]),
        ).values(status="Retired", updated_at=stamp))
        if changed.rowcount != 1:
            raise ValueError("sealed service row changed during final CAS")
    return receipt


def _finish_atomic(child: StoredJobRun, *, static, jobs, settings_repo, resources,
                   parent_id: str, plans, credentials, lookup, sketch_repository,
                   proof_receipts: dict[str, str], environment: str,
                   state_root: Path, published_history) -> StoredJobRun:
    """Commit Inspector, lifecycle, parent, coordinator and lease once."""
    from sqlalchemy import delete, update
    from app.storage.database import db
    from app.storage.models import (
        CoreMutationLeaseModel, EngagementLifecycleEventModel,
        EngagementLifecycleModel, EngagementObserverSettingsModel,
        JobEventModel, JobRunModel, ProviderResourceRecordModel,
    )
    from app.services.engagement_lifecycle import (
        FAILED_SKETCH_STATES, LIVE_SKETCH_STATES, _fingerprint,
        resolve_engagement_lifecycle,
    )
    from app.storage.provider_resource_repository import is_barragan_owned_record
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    if (db.session.get_bind().dialect.name != "sqlite"
            or _journal_messages(child)[-1] != "inspector firewall absence proved"):
        raise ValueError("complete reviewed SQLite cleanup journal required")
    parent, core, snapshot, coordinator, negative, settings, host_row, firewall_row, selected = static
    published = "publishedSource" in parent.input
    if (proof_receipts.get("groupCoordinatorSha256") != job_event_digest(coordinator.events)
            or proof_receipts.get("negativeInputSha256") != child.input["negativeInputSha256"]
            or proof_receipts.get("negativeJournalSha256") != child.input["negativeJournalSha256"]
            or proof_receipts.get("selectorJobId") != child.input["selectorJobId"]
            or proof_receipts.get("selectorJournalSha256") != child.input["selectorJournalSha256"]):
        raise ValueError("canonical terminal proof receipts differ")
    stamp = datetime.now(timezone.utc)
    plan_id = core.input["corePlanId"]
    staged_parent_input = {**parent.input, "phase": "lifecycle_reconciliation",
                           "remainingOwnedResources": []}
    final_coordinator_input = {**coordinator.input, "phase": "inspector_retired"}
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    try:
        # The child CAS takes SQLite's writer slot. All subsequent reads and
        # writes, including the pure lifecycle resolver, share this session.
        changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == child.id, JobRunModel.action == ACTION,
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.input == child.input,
            JobRunModel.target_id == parent.target_id,
            JobRunModel.requested_by == parent.requested_by,
            JobRunModel.artifact_refs == [],
        ).values(status="running"))
        staged = jobs.get(child.id)
        if (changed.rowcount != 1 or staged is None or staged.events != child.events
                or staged.input != child.input or staged.status != "running"
                or _static_authority(parent_id, child, jobs=jobs, plans=plans,
                                     settings_repo=settings_repo, resources=resources,
                                     credentials=credentials, lookup=lookup) != static):
            raise ValueError("Inspector cleanup final CAS lost")
        if published and _published_retired_authority(
                parent_id, environment=environment, state_root=state_root,
                jobs=jobs, plans=plans, resources=resources,
                credentials=credentials, sketch_repository=chains,
                lookup=lookup) != published_history:
            raise ValueError("published Inspector history changed under writer slot")
        # _static_authority above reopened the complete saved seal and negative
        # receipt under this same writer slot before touching service rows.
        retirement_receipt = _retire_sealed_services(parent, snapshot, stamp) if published else None
        for prefix, expected_action in (("oci", "provider_keyed_core_destroy_absence"),
                                        ("selector", "provider_keyed_selector_retirement"),
                                        ("negative", NEGATIVE_ACTION)):
            key = f"{prefix}JournalSha256"
            job_id = proof_receipts[f"{prefix}JobId"]
            saved = jobs.get(job_id)
            if (saved is None or saved.status != "succeeded"
                    or saved.action != expected_action
                    or saved.input.get("teardownParentId") != parent.id
                    or saved.input.get("coreJobId") != core.id
                    or saved.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or (prefix != "negative" and saved.input.get("corePlanId") != plan_id)
                    or job_event_digest(saved.events) != proof_receipts[key]
                    or _negative_input_sha(saved.input) != proof_receipts[
                        key.replace("JournalSha256", "InputSha256")]):
                raise ValueError("terminal source job changed under writer slot")
        current_negative = jobs.get(proof_receipts["negativeJobId"])
        if (_negative_input_sha(current_negative.input)
                != proof_receipts["negativeInputSha256"]):
            raise ValueError("Inspector negative input changed under writer slot")
        lease = db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=parent.target_id).one_or_none()
        if (lease is None or lease.owner_id != plan_id or lease.operation != _FENCE):
            raise ValueError("exact keyed core fence changed")
        plan = plans.get(plan_id)
        if (plan is None or plan.status != "applied" or plan.apply_job_id != core.id):
            raise ValueError("retained core plan changed")
        for row in (host_row, firewall_row):
            result = db.session.execute(update(ProviderResourceRecordModel).where(
                ProviderResourceRecordModel.id == row.id,
                ProviderResourceRecordModel.engagement_id == parent.target_id,
                ProviderResourceRecordModel.status == row.status,
                ProviderResourceRecordModel.lifecycle_state == row.lifecycle_state,
                ProviderResourceRecordModel.metadata_json == row.metadata,
                ProviderResourceRecordModel.adoption_job_id == row.adoption_job_id,
            ).values(status="destroyed", lifecycle_state="destroyed",
                     destroyed_at=stamp, updated_at=stamp))
            if result.rowcount != 1:
                raise ValueError("owned Inspector row changed during final CAS")
        settings_changed = db.session.execute(update(EngagementObserverSettingsModel).where(
            EngagementObserverSettingsModel.engagement_id == parent.target_id,
            EngagementObserverSettingsModel.enabled.is_(True),
            EngagementObserverSettingsModel.current_host == settings.current_host,
            EngagementObserverSettingsModel.provider == "linode",
        ).values(enabled=False, current_host={}, updated_at=stamp))
        if settings_changed.rowcount != 1:
            raise ValueError("Inspector settings changed during final CAS")
        remaining_owned = [row for row in resources.list_for_engagement(parent.target_id)
                           if row.status.lower() not in TERMINAL_RECORD_STATUSES
                           and is_barragan_owned_record(row)]
        remaining_chains = [row for row in chains.list_for_engagement(parent.target_id)
                            if row.status.lower() in LIVE_SKETCH_STATES | FAILED_SKETCH_STATES]
        if remaining_owned or remaining_chains:
            raise ValueError("owned provider or Sketch residue remains")
        parent_changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == parent.id,
            JobRunModel.action == "engagement_comprehensive_teardown",
            JobRunModel.status == "queued", JobRunModel.started_at.is_(None),
            JobRunModel.finished_at.is_(None), JobRunModel.input == parent.input,
            JobRunModel.target_id == parent.target_id,
            JobRunModel.requested_by == parent.requested_by,
        ).values(status="running", started_at=stamp, input=staged_parent_input))
        if parent_changed.rowcount != 1:
            raise ValueError("queued parent changed during final CAS")
        db.session.add(JobEventModel(
            job_id=parent.id, sequence=len(parent.events) + 1, level="info",
            message="engagement resource cleanup gates passed", data={
                "finalCleanupStatus": "verified_clean", "coreJobId": core.id,
                "remainingOwnedResources": []}, created_at=stamp))
        db.session.flush()
        prior_lifecycle = db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id=parent.target_id).one_or_none()
        previous_state = prior_lifecycle.state if prior_lifecycle else "not_deployed"
        staged_resolution = resolve_engagement_lifecycle(
            parent.target_id, previous_state=previous_state, job_repository=jobs,
            provider_resource_repository=resources, sketch_chain_repository=chains)
        if staged_resolution.state != "destroyed":
            raise ValueError("staged lifecycle did not resolve destroyed")
        coordinator_changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == coordinator.id,
            JobRunModel.action == "provider_keyed_comprehensive_teardown",
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.input == coordinator.input,
            JobRunModel.target_id == parent.target_id,
        ).values(input=final_coordinator_input, status="succeeded", finished_at=stamp))
        if coordinator_changed.rowcount != 1:
            raise ValueError("Inspector coordinator changed during final CAS")
        db.session.add(JobEventModel(
            job_id=child.id, sequence=len(child.events) + 1, level="info",
            message="inspector local retirement committed", data={
                "hostRecordId": host_row.id, "firewallRecordId": firewall_row.id,
                "negativeJournalSha256": child.input["negativeJournalSha256"],
            }, created_at=stamp))
        db.session.add(JobEventModel(
            job_id=coordinator.id, sequence=len(coordinator.events) + 1,
            level="info", message="inspector_retired", data={
                "cleanupJobId": child.id, "hostRecordId": host_row.id,
                "firewallRecordId": firewall_row.id,
            }, created_at=stamp))
        published_binding = (_published_terminal_binding(parent, coordinator.events, retirement_receipt)
                             if published else None)
        db.session.add(JobEventModel(
            job_id=coordinator.id, sequence=len(coordinator.events) + 2,
            level="info", message=("published teardown complete" if published
                                    else "pending teardown complete"), data={
                "coreJobId": core.id, "scopeSnapshotId": snapshot["snapshotId"],
                "cleanupJobId": child.id, "proofs": proof_receipts,
                **({"publishedBinding": published_binding} if published else {}),
                **({"serviceRetirementReceipt": retirement_receipt} if retirement_receipt is not None else {}),
            }, created_at=stamp))
        child_changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == child.id, JobRunModel.action == ACTION,
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.input == child.input,
        ).values(status="succeeded", finished_at=stamp))
        if child_changed.rowcount != 1:
            raise ValueError("Inspector cleanup child changed during final CAS")
        parent_done = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == parent.id,
            JobRunModel.action == "engagement_comprehensive_teardown",
            JobRunModel.status == "running", JobRunModel.input == staged_parent_input,
            JobRunModel.finished_at.is_(None),
        ).values(status="succeeded", finished_at=stamp))
        if parent_done.rowcount != 1:
            raise ValueError("staged teardown parent changed")
        db.session.add(JobEventModel(
            job_id=parent.id, sequence=len(parent.events) + 2, level="info",
            message="engagement lifecycle reconciled", data={
                "state": "destroyed", "finalCleanupStatus": "verified_clean"},
            created_at=stamp))
        db.session.flush()
        final_resolution = resolve_engagement_lifecycle(
            parent.target_id, previous_state=previous_state, job_repository=jobs,
            provider_resource_repository=resources, sketch_chain_repository=chains)
        if final_resolution.state != "destroyed":
            raise ValueError("terminal lifecycle did not resolve destroyed")
        fingerprint = _fingerprint(final_resolution.evidence)
        if prior_lifecycle is None:
            prior_lifecycle = EngagementLifecycleModel(engagement_id=parent.target_id)
            db.session.add(prior_lifecycle)
        prior_lifecycle.state = "destroyed"
        prior_lifecycle.evidence_fingerprint = fingerprint
        prior_lifecycle.evidence = final_resolution.evidence
        prior_lifecycle.reconciled_at = stamp
        reason = (f"provider_keyed_published_teardown_verified:{snapshot['snapshotId']}:"
                  f"{_negative_input_sha(published_binding)}" if published else
                  f"provider_keyed_pending_teardown_verified:{snapshot['snapshotId']}")
        db.session.add(EngagementLifecycleEventModel(
            engagement_id=parent.target_id, previous_state=previous_state,
            state="destroyed", evidence_fingerprint=fingerprint,
            evidence=final_resolution.evidence,
            reason=reason,
            created_at=stamp))
        released = db.session.execute(delete(CoreMutationLeaseModel).where(
            CoreMutationLeaseModel.engagement_id == parent.target_id,
            CoreMutationLeaseModel.owner_id == plan_id,
            CoreMutationLeaseModel.operation == _FENCE))
        if released.rowcount != 1:
            raise ValueError("exact keyed fence release changed")
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return recognize_pending_linode_inspector_retired(
        parent_id, environment="devtest", job_repository=jobs,
        plan_repository=plans, settings_repository=settings_repo,
        provider_resource_repository=resources, lease_lookup=lookup,
        sketch_repository=chains)


def recognize_pending_linode_inspector_retired(
    teardown_parent_id: str, *, environment: str, job_repository=None,
    plan_repository=None, settings_repository=None,
    provider_resource_repository=None, sketch_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Read historical terminal generation without queued-parent or fence calls."""
    from app.services.engagement_lifecycle import _fingerprint as evidence_fingerprint
    from app.services.engagement_teardown import _fingerprint as snapshot_fingerprint
    from app.storage.engagement_lifecycle_repository import SqlAlchemyEngagementLifecycleRepository
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    if environment != "devtest":
        raise LinodeInspectorCleanupAttention("DevTest only")
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lifecycles = SqlAlchemyEngagementLifecycleRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        parent = jobs.get(teardown_parent_id)
        if parent is None:
            raise ValueError("terminal parent missing")
        published = "publishedSource" in parent.input
        snapshot = parent.input.get("scopeSnapshot")
        core = jobs.get(parent.input.get("coreJobId"))
        core_plan = plans.get(core.input.get("corePlanId")) if core else None
        core_target = core_plan.evidence.get("target") if core_plan else None
        if (parent.action != "engagement_comprehensive_teardown"
                or parent.status != "succeeded" or parent.finished_at is None
                or parent.input.get("phase") != "lifecycle_reconciliation"
                or parent.input.get("remainingOwnedResources") != []
                or type(snapshot) is not dict
                or type(snapshot.get("snapshotId")) is not str
                or snapshot["snapshotId"] != snapshot_fingerprint({
                    key: value for key, value in snapshot.items() if key != "snapshotId"})
                or core is None or core.status != "succeeded"
                or core.input.get("engagementId") != parent.target_id
                or core.target_type != "oci_compartment"
                or type(core_target) is not dict
                or core.target != f"oci-compartment:{core_target.get('name')}"
                or core.target_id != core_target.get("compartmentId")
                or core_plan.engagement_id != parent.target_id
                or core_plan.status != "applied" or core_plan.apply_job_id != core.id
                or core.input.get("corePlanId") != snapshot.get("providerScopes", [{}])[0].get("corePlanId")
                or len(parent.events) != 3
                or [event.sequence for event in parent.events] != [1, 2, 3]
                or [event.message for event in parent.events] != [
                    "engagement teardown queued", "engagement resource cleanup gates passed",
                    "engagement lifecycle reconciled"]
                or any(event.level != "info" for event in parent.events)
                or parent.events[0].data != queued_cleanup_event_data(snapshot)
                or parent.events[1].data != {
                    "finalCleanupStatus": "verified_clean", "coreJobId": core.id,
                    "remainingOwnedResources": []}
                or parent.events[2].data != {
                    "state": "destroyed", "finalCleanupStatus": "verified_clean"}):
            raise ValueError("terminal parent/snapshot differs")
        identifier = f"job-provider-keyed-inspector-linode-cleanup-{core.id.removeprefix('job-')}"
        child = jobs.get(identifier)
        coordinator = jobs.get(_child_id(core.id))
        negative = jobs.get(child.input.get("negativeJobId")) if child else None
        settings = settings_repo.get(parent.target_id)
        if (child is None or child.action != ACTION
                or child.status != "succeeded" or child.finished_at is None
                or child.target_id != parent.target_id
                or child.requested_by != parent.requested_by
                or child.input.get("teardownParentId") != parent.id
                or child.input.get("coreJobId") != core.id
                or child.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                or child.input.get("coordinatorJobId") != _child_id(core.id)
                or negative is None or negative.action != NEGATIVE_ACTION
                or negative.status != "succeeded" or negative.finished_at is None
                or negative.target_id != parent.target_id
                or negative.input.get("teardownParentId") != parent.id
                or negative.input.get("coreJobId") != core.id
                or negative.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                or job_event_digest(negative.events) != child.input.get("negativeJournalSha256")
                or _negative_input_sha(negative.input) != child.input.get("negativeInputSha256")
                or len(negative.events) != 3
                or negative.events[-1].message != "inspector exact public negative proved"
                or coordinator is None or coordinator.status != "succeeded"
                or coordinator.finished_at is None
                or coordinator.target_id != parent.target_id
                or coordinator.input.get("phase") != "inspector_retired"
                or job_event_digest(coordinator.events[:-2])
                != child.input.get("creationJournalSha256")
                or coordinator.events[-2].message != "inspector_retired"
                or coordinator.events[-2].data != {
                    "cleanupJobId": child.id,
                    "hostRecordId": child.input["hostRecordId"],
                    "firewallRecordId": child.input["firewallRecordId"]}
                or coordinator.events[-1].message != (
                    "published teardown complete" if published
                    else "pending teardown complete")
                or coordinator.events[-1].data.get("coreJobId") != core.id
                or coordinator.events[-1].data.get("scopeSnapshotId") != snapshot["snapshotId"]
                or coordinator.events[-1].data.get("cleanupJobId") != child.id
                or settings is None or settings.enabled is not False
                or settings.current_host != {}
                or child.events[-1].message != "inspector local retirement committed"
                or child.events[-1].data != {
                    "hostRecordId": child.input["hostRecordId"],
                    "firewallRecordId": child.input["firewallRecordId"],
                    "negativeJournalSha256": child.input["negativeJournalSha256"]}
                or not _terminal_journal_valid(child)):
            raise ValueError("Inspector local retirement differs")
        proofs = coordinator.events[-1].data.get("proofs")
        if (type(proofs) is not dict
                or proofs.get("groupCoordinatorSha256")
                != job_event_digest(coordinator.events[:-2])
                or proofs.get("negativeJobId") != negative.id
                or proofs.get("negativeJournalSha256") != child.input["negativeJournalSha256"]
                or proofs.get("negativeInputSha256") != child.input["negativeInputSha256"]
                or proofs.get("selectorJobId") != child.input["selectorJobId"]
                or proofs.get("selectorJournalSha256") != child.input["selectorJournalSha256"]):
            raise ValueError("terminal proof manifest differs")
        validate_cleanup_negative(parent, core, snapshot, negative, jobs)
        if published:
            from app.storage.job_repository import _stored_utc_instant, _utc_instant
            from app.storage.provider_resource_repository import is_barragan_owned_record
            from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
            from app.services.provider_keyed_teardown_quiescence import (
                audit_published_provider_keyed_bootstrap,
            )

            marker = parent.input["publishedSource"]
            append_marker = parent.input.get("publishedAppendSource")
            initial = jobs.get(marker.get("initial_job_id")) if type(marker) is dict else None
            group_prefix = coordinator.events[:-2]
            group_receipt = group_prefix[-1].data if group_prefix else None
            scope = snapshot["providerScopes"][0]
            resource_ids = {item["address"]: str(item["id"])
                            for item in scope["resources"]}
            droplet_ids = sorted(value for address, value in resource_ids.items()
                                 if address.startswith("digitalocean_droplet."))
            apply_id = (f"job-provider-keyed-initial-destroy-apply-"
                        f"{core.id.removeprefix('job-')}")
            apply = jobs.get(apply_id)
            retirement_receipt = coordinator.events[-1].data.get("serviceRetirementReceipt")
            binding = _published_terminal_binding(parent, group_prefix, retirement_receipt)
            if (retirement_receipt is not None
                    and _utc_instant(retirement_receipt["retiredAt"]) != _stored_utc_instant(child.finished_at)):
                raise ValueError("service retirement timestamp differs")
            retired_ids = group_receipt.get("retiredRecordIds") if type(group_receipt) is dict else None
            group_keys = {
                "scopeSnapshotId", "providerScopeSha256", "sourceJournalSha256",
                "applyJobId", "resourceIdsSha256", "verifiedAbsentDropletIds",
                "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId",
                "confirmationCompletedAt", "confirmationExpiresAt",
                "chainIds", "retiredRecordIds", "observedAt",
                "priorChainProjectionSha256",
            }
            expected_marker_keys = {
                "engagement_id", "core_job_id", "core_plan_id", "initial_job_id",
                "initial_journal_sha256", "core_journal_sha256", "scope_sha256",
                "state_sha256", "manifest_sha256", "published_host_evidence_sha256",
                "chain_ids", "chain_projection_sha256",
            }
            manifest_events = ([event for event in initial.events
                                if event.message == "provider host identity binding intended"]
                               if initial is not None else [])
            manifest = manifest_events[0].data if len(manifest_events) == 1 else None
            expected_nodes = manifest.get("nodes") if type(manifest) is dict else None
            bootstrap = (None if append_marker is not None else
                audit_published_provider_keyed_bootstrap(
                    core.id, confirmed_scope=scope,
                    workspace_root=Path(scope["workspace"]), job_repository=jobs,
                ))
            append_job = (jobs.get(append_marker.get("append_job_id"))
                          if type(append_marker) is dict else None)
            expected_droplet_addresses = {
                address for address in resource_ids
                if address.startswith("digitalocean_droplet.")}
            original_addresses = ({node.get("terraformAddress") for node in expected_nodes}
                                  if type(expected_nodes) is list else set())
            append_identity_ok = (
                type(append_marker) is dict
                and append_marker.get("initial_source") == marker
                and append_marker.get("state_sha256") == scope["stateSha256"]
                and append_marker.get("new_edge_address") in expected_droplet_addresses
                and append_marker.get("new_edge_address") not in original_addresses
                and resource_ids.get(append_marker.get("new_edge_address")) ==
                    append_marker.get("new_edge_provider_id")
                and append_job is not None and append_job.status == "succeeded"
                and job_event_digest(append_job.events) ==
                    append_marker.get("append_journal_sha256")
                and append_job.events[-1].message == "provider one-edge append published"
                and append_job.events[-1].data == {
                    "initialSource": marker, "stateSha256": scope["stateSha256"]})
            if (type(marker) is not dict or set(marker) != expected_marker_keys
                    or marker["engagement_id"] != parent.target_id
                    or marker["core_job_id"] != core.id
                    or marker["core_plan_id"] != core_plan.id
                    or (append_marker is None and marker["scope_sha256"] != snapshot_fingerprint(scope))
                    or (append_marker is None and marker["state_sha256"] != scope["stateSha256"])
                    or marker["manifest_sha256"] != (
                        bootstrap.manifest_sha256 if bootstrap is not None else
                        initial.events[-1].data.get("manifestSha256"))
                    or marker["chain_ids"] != scope["chainIds"]
                    or marker["published_host_evidence_sha256"]
                    != initial.events[-1].data.get("hostEvidenceSha256")
                    or initial is None or initial.action != "provider_keyed_initial"
                    or initial.status != "succeeded"
                    or job_event_digest(initial.events) != marker.get("initial_journal_sha256")
                    or job_event_digest(core.events) != marker.get("core_journal_sha256")
                    or len(manifest_events) != 1
                    or type(expected_nodes) is not list
                    or len(expected_nodes) != (4 if append_marker is not None else len(droplet_ids))
                    or (original_addresses | ({append_marker.get("new_edge_address")}
                         if append_marker is not None else set())) != expected_droplet_addresses
                    or (append_marker is not None and not append_identity_ok)
                    or any(str(node.get("providerInstanceId"))
                           != resource_ids[node["terraformAddress"]]
                           or node.get("chainId") not in scope["chainIds"]
                           or node.get("role") not in {"middle", "edge"}
                           for node in expected_nodes)
                    or apply is None or apply.status != "succeeded"
                    or child.input.get("creationJournalSha256") != job_event_digest(group_prefix)
                    or not group_prefix or group_prefix[-1].message != "keyed_provider_group_retired"
                    or (append_marker is None and group_receipt.get("priorChainProjectionSha256")
                        != marker.get("chain_projection_sha256"))
                    or group_receipt.get("sourceJournalSha256")
                    != job_event_digest(group_prefix[:-1])
                    or group_receipt.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or group_receipt.get("providerScopeSha256") != snapshot["providerScopeSha256"]
                    or group_receipt.get("applyJobId") != apply.id
                    or group_receipt.get("resourceIdsSha256") != snapshot_fingerprint(resource_ids)
                    or group_receipt.get("verifiedAbsentDropletIds") != droplet_ids
                    or group_receipt.get("verifiedAbsentFirewallId")
                    != resource_ids["digitalocean_firewall.firewall"]
                    or group_receipt.get("verifiedAbsentSshKeyId")
                    != resource_ids["digitalocean_ssh_key.key"]
                    or group_receipt.get("chainIds") != sorted(scope["chainIds"])
                    or set(group_receipt) != group_keys
                    or type(retired_ids) is not list
                    or retired_ids != sorted(set(retired_ids))
                    or _utc_instant(group_receipt.get("confirmationCompletedAt")) is None
                    or _utc_instant(group_receipt.get("confirmationExpiresAt")) is None
                    or _utc_instant(group_receipt.get("observedAt")) is None
                    or not (_utc_instant(group_receipt["confirmationCompletedAt"])
                            <= _utc_instant(group_receipt["observedAt"])
                            < _utc_instant(group_receipt["confirmationExpiresAt"]))
                    or _utc_instant(group_receipt["confirmationExpiresAt"])
                    > _utc_instant(group_receipt["confirmationCompletedAt"]) + timedelta(seconds=30)
                    or coordinator.events[-1].data.get("publishedBinding") != binding):
                raise ValueError("published terminal history differs")
            from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
            prior_chains = reviewed_mixed_chain_rows(
                SqlAlchemySketchChainRepository().list_for_engagement(parent.target_id),
                scope["chainIds"], parent.target_id)
            if (len(prior_chains) != len(scope["chainIds"])
                    or {row.chain_id for row in prior_chains} != set(scope["chainIds"])
                    or any(row.status != "destroyed" or row.nodes != []
                           or row.deploy_job_id != initial.id
                           or row.teardown_job_id != apply.id
                           or row.terraform_working_directory != scope["workspace"]
                           or row.burned
                           for row in prior_chains)):
                raise ValueError("published retired chains differ")
            owned_digitalocean = [row for row in resources.list_for_engagement(parent.target_id)
                                 if row.provider == "digitalocean"
                                 and is_barragan_owned_record(row)]
            retired_rows = [row for row in owned_digitalocean if row.id in retired_ids]
            sealed_ids = set(resource_ids.values())
            expected_by_kind = {
                "digitalocean_droplet": set(droplet_ids),
                "digitalocean_firewall": {resource_ids["digitalocean_firewall.firewall"]},
                "digitalocean_ssh_key": {resource_ids["digitalocean_ssh_key.key"]},
            }
            kind_aliases = {"droplet": "digitalocean_droplet",
                            "firewall": "digitalocean_firewall",
                            "ssh_key": "digitalocean_ssh_key"}
            if (len(retired_rows) != len(retired_ids)
                    or any(row.status.lower() not in TERMINAL_RECORD_STATUSES
                           for row in owned_digitalocean)
                    or any(row.resource_id not in sealed_ids
                           or row.resource_id not in expected_by_kind.get(
                               kind_aliases.get(row.resource_type.lower().replace("-", "_"),
                                                row.resource_type.lower().replace("-", "_")), set())
                           or row.provider != "digitalocean"
                           or row.engagement_id != parent.target_id
                           or row.adoption_job_id != initial.id
                           or not is_barragan_owned_record(row)
                           or row.status != "destroyed"
                           or row.lifecycle_state != "destroyed"
                           or _stored_utc_instant(row.destroyed_at)
                           != _utc_instant(group_receipt["observedAt"])
                           for row in retired_rows)
                    or lookup(parent.target_id) == (core_plan.id, _FENCE)):
                raise ValueError("published retired provider records differ")
        elif "publishedBinding" in coordinator.events[-1].data:
            raise ValueError("pending terminal acquired published binding")
        for prefix in ("oci", "selector"):
            saved = jobs.get(proofs.get(f"{prefix}JobId"))
            if (saved is None or saved.status != "succeeded"
                    or saved.action != {
                        "oci": "provider_keyed_core_destroy_absence",
                        "selector": "provider_keyed_selector_retirement",
                    }[prefix]
                    or saved.target_id != parent.target_id
                    or saved.input.get("teardownParentId") != parent.id
                    or saved.input.get("coreJobId") != core.id
                    or saved.input.get("corePlanId") != core.input["corePlanId"]
                    or saved.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or job_event_digest(saved.events) != proofs.get(f"{prefix}JournalSha256")
                    or _negative_input_sha(saved.input) != proofs.get(f"{prefix}InputSha256")):
                raise ValueError("terminal provider proof receipt differs")
        historical_host = resources.get(child.input["hostRecordId"])
        historical_firewall = resources.get(child.input["firewallRecordId"])
        if (historical_host is None or historical_firewall is None
                or type(historical_host.metadata) is not dict
                or type(historical_firewall.metadata) is not dict):
            raise ValueError("historical Inspector owned pair missing")
        host_firewall = historical_host.metadata.get("providerFirewall")
        if type(host_firewall) is not dict:
            raise ValueError("historical Inspector firewall metadata missing")
        origin, intent, adopter = _inspector_origin(
            snapshot=snapshot, events=coordinator.events[:-2],
            coordinator_id=coordinator.id, engagement_id=parent.target_id,
            host_row=historical_host, firewall_row=historical_firewall,
            host_ip=historical_host.metadata.get("publicIp"),
            source_cidr=host_firewall.get("managementSourceCidr"), jobs=jobs)
        if (child.input.get("origin") != origin
                or child.input.get("adoptionJobId") != adopter
                or intent.get("credentialId") != child.input["credentialId"]
                or intent.get("credentialSha256") != child.input["credentialSha256"]):
            raise ValueError("historical Inspector origin binding differs")
        for record_id, resource_type, resource_id, role in (
            (child.input["hostRecordId"], "inspector_instance", child.input["hostId"],
             "inspector"),
            (child.input["firewallRecordId"], "inspector_firewall",
             child.input["firewallId"], "inspector_firewall"),
        ):
            row = resources.get(record_id)
            if (row is None or row.engagement_id != parent.target_id
                    or row.provider != "linode" or row.source != INSPECTOR_RESOURCE_SOURCE
                    or row.resource_type != resource_type
                    or row.resource_id != resource_id
                    or row.adoption_job_id != adopter
                    or row.metadata.get("barraganOwned") is not True
                    or row.metadata.get("role") != role
                    or row.status != "destroyed" or row.lifecycle_state != "destroyed"
                    or row.destroyed_at is None):
                raise ValueError("owned Inspector terminal row differs")
            if (role == "inspector" and row.name != historical_host.name) or (
                    role == "inspector_firewall" and row.name != _inspector_firewall_label(
                        "linode", historical_host.name)):
                raise ValueError("owned Inspector terminal name differs")
        event_reason = (f"provider_keyed_published_teardown_verified:{snapshot['snapshotId']}:"
                        f"{_negative_input_sha(binding)}" if published else
                        f"provider_keyed_pending_teardown_verified:{snapshot['snapshotId']}")
        lifecycle_events = [event for event in lifecycles.list_events(parent.target_id)
                            if event.reason == event_reason]
        if (len(lifecycle_events) != 1 or lifecycle_events[0].state != "destroyed"
                or lifecycle_events[0].evidence_fingerprint
                != evidence_fingerprint(lifecycle_events[0].evidence)
                or not any(row.get("kind") == "engagement_teardown_job"
                           and row.get("id") == parent.id and row.get("status") == "succeeded"
                           and row.get("cleanupStatus") == "verified_clean"
                           for row in lifecycle_events[0].evidence)):
            raise ValueError("terminal lifecycle event differs")
        current = lifecycles.get(parent.target_id)
        if (current is not None and current.reconciled_at == lifecycle_events[0].created_at
                and (current.state != "destroyed"
                     or current.evidence_fingerprint != lifecycle_events[0].evidence_fingerprint)):
            raise ValueError("terminal lifecycle projection differs")
        return child
    except Exception:
        raise LinodeInspectorCleanupAttention(
            "Linode Inspector local retirement is unverified") from None


def _terminal_journal_valid(child: StoredJobRun) -> bool:
    messages = [event.message for event in child.events]
    required = ["inspector cleanup queued", "inspector cleanup started",
                "inspector host DELETE intended"]
    if messages[:3] != required or messages[-1:] != ["inspector local retirement committed"]:
        return False
    middle = messages[3:-1]
    if middle[:1] == ["inspector host DELETE 200 received"]:
        middle = middle[1:]
    if middle[:2] != ["inspector host absence proved", "inspector firewall DELETE intended"]:
        return False
    middle = middle[2:]
    if middle[:1] == ["inspector firewall DELETE 200 received"]:
        middle = middle[1:]
    if middle != ["inspector firewall absence proved"]:
        return False
    if ([event.sequence for event in child.events] != list(range(1, len(child.events) + 1))
            or any(event.level != "info" for event in child.events)):
        return False
    expected = {
        "inspector cleanup queued": {}, "inspector cleanup started": {},
        "inspector host DELETE intended": {
            "path": f"/linode/instances/{child.input.get('hostId')}",
            "resourceId": child.input.get("hostId")},
        "inspector host DELETE 200 received": {},
        "inspector host absence proved": {},
        "inspector firewall DELETE intended": {
            "path": f"/networking/firewalls/{child.input.get('firewallId')}",
            "resourceId": child.input.get("firewallId")},
        "inspector firewall DELETE 200 received": {},
        "inspector firewall absence proved": {},
        "inspector local retirement committed": {
            "hostRecordId": child.input.get("hostRecordId"),
            "firewallRecordId": child.input.get("firewallRecordId"),
            "negativeJournalSha256": child.input.get("negativeJournalSha256")},
    }
    return all(event.data == expected[event.message] for event in child.events)
