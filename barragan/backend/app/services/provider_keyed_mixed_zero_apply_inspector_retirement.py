# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot Linode Inspector retirement after mixed zero-Apply teardown.

The engagement's desired Inspector settings remain configured; only its former
host binding and the two exactly owned provider records are retired here.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import time
from typing import Callable

from app.domain import JobEvent
from app.integrations.linode_validation import UrllibLinodeTransport
from app.services.credentials import decrypt_secret_value
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_inspector_linode_cleanup import (
    LinodeDeleteResponse, UrllibLinodeExactDelete, _complete_ids,
    _empty_firewall_devices, _wait_absent,
)
from app.services.provider_keyed_inspector_provider_proof import _linode_devices
from app.services.observer_checks import _is_inspector_owned_resource_record
from app.services.provider_keyed_mixed_zero_apply_core_absence import (
    _authority, _authority_digest,
)
from app.services.provider_keyed_mixed_zero_apply_core_apply import _prove_retained_inspector
from app.services.provider_keyed_mixed_zero_apply_teardown_source import (
    canonical_mixed_core_apply_events,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import _saved_review
from app.services.provider_keyed_mixed_interrupted_selector_retirement import (
    ACTION as INTERRUPTED_SELECTOR_ACTION,
    _child_id as interrupted_selector_id,
    retire_mixed_interrupted_selector,
)
from app.services.provider_keyed_mixed_published_post_oci_source import (
    audit_published_mixed_post_oci_source,
)
from app.services.provider_keyed_mixed_published_selector_retirement import (
    ACTION as PUBLISHED_SELECTOR_ACTION,
    _child_id as published_selector_id,
    retire_published_mixed_selector,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
    ACTION as NEGATIVE_ACTION, _child_id as negative_child_id, latest_negative_attempt,
    _targets as core_targets,
    prove_mixed_zero_apply_inspector_negative,
)
from app.services.provider_keyed_inspector_negative import _classified_results
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


ACTION = "provider_keyed_mixed_zero_apply_inspector_retirement"
PUBLISHED_ACTION = "provider_keyed_mixed_published_inspector_retirement"
_ID = re.compile(r"[1-9][0-9]*\Z")


class MixedZeroApplyInspectorRetirementAttention(ValueError):
    """Exact Linode Inspector retirement needs read-only reconciliation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-inspector-retirement-{core_job_id.removeprefix('job-')}"


def _published_child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-published-inspector-retirement-{core_job_id.removeprefix('job-')}"


def _credential_seal(credential) -> dict:
    if (credential is None or credential.provider != "linode"
            or credential.status != "active" or credential.is_default is not True
            or not credential.id or not credential.updated_at
            or not isinstance(credential.encrypted_secret, str)):
        raise ValueError("selected Inspector credential differs")
    return {"credentialId": credential.id,
            "credentialUpdatedAt": credential.updated_at,
            "credentialSecretSha256": hashlib.sha256(
                credential.encrypted_secret.encode()).hexdigest()}


def _messages(child: StoredJobRun, host_id: str, firewall_id: str) -> list[str]:
    """Closed one-shot journal; a failed or alien event cannot authorize DELETE."""
    stages = [
        ("mixed Inspector retirement queued", {}),
        ("mixed Inspector retirement started", {}),
        ("inspector host DELETE intended", {
            "path": f"/linode/instances/{host_id}", "resourceId": host_id}),
        ("inspector host DELETE 200 received", {}),
        ("inspector host absence proved", {}),
        ("inspector firewall DELETE intended", {
            "path": f"/networking/firewalls/{firewall_id}", "resourceId": firewall_id}),
        ("inspector firewall DELETE 200 received", {}),
        ("inspector firewall absence proved", {}),
        ("mixed Inspector local retirement committed", {
            "hostRecordId": child.input["hostRecordId"],
            "firewallRecordId": child.input["firewallRecordId"]}),
    ]
    messages = [event.message for event in child.events]
    # Exact 200 events may be absent if a DELETE response was lost. The next
    # invocation may only GET/list-reconcile after a saved intent.
    for optional in ("inspector host DELETE 200 received",
                     "inspector firewall DELETE 200 received"):
        if optional not in messages:
            stages = [row for row in stages if row[0] != optional]
    if (len(messages) > len(stages) or messages != [row[0] for row in stages[:len(messages)]]
            or [(event.sequence, event.level, event.data) for event in child.events]
            != [(index, "info", data) for index, (_, data)
                in enumerate(stages[:len(messages)], 1)]):
        raise ValueError("mixed Inspector retirement journal differs")
    return messages


def _append(jobs, child: StoredJobRun, message: str, data: dict, *,
            authority_check: Callable[[], None]) -> StoredJobRun:
    """Persist intent before HTTP using the reviewed SQLite writer slot."""
    from sqlalchemy import update
    from app.storage.database import db
    from app.storage.models import CoreMutationLeaseModel, JobEventModel, JobRunModel

    if (child.action not in {ACTION, PUBLISHED_ACTION} or child.status != "running"
            or child.finished_at is not None or not callable(authority_check)):
        raise ValueError("retirement child is not running")
    event = JobEvent(len(child.events) + 1, "info", message, data)
    try:
        db.session.rollback()
        changed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == child.id, JobRunModel.action == child.action,
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.input == child.input, JobRunModel.target_id == child.target_id,
            JobRunModel.requested_by == child.requested_by,
        ).values(status="running"))
        if changed.rowcount != 1 or jobs.get(child.id) != child:
            raise ValueError("retirement journal changed")
        lease = db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=child.target_id).one_or_none()
        if (lease is None or lease.owner_id != child.input.get("corePlanId")
                or lease.operation != "provider_keyed_teardown_fence"):
            raise ValueError("retirement lease changed")
        authority_check()
        db.session.add(JobEventModel(job_id=child.id, sequence=event.sequence,
                                     level="info", message=message, data=data))
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    saved = jobs.get(child.id)
    if saved is None or saved.events != [*child.events, event]:
        raise ValueError("retirement journal commit uncertain")
    return saved


def retire_mixed_zero_apply_inspector(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, credential_repository=None, lease_lookup=None,
    read_transport=None, delete_transport=None, sleep: Callable = time.sleep,
    decrypt_secret: Callable = decrypt_secret_value,
    readiness_prover: Callable = _prove_retained_inspector,
    negative_recognizer: Callable = prove_mixed_zero_apply_inspector_negative,
    selector_recognizer: Callable = retire_mixed_interrupted_selector,
    identity_reader=None,
    interrupted: bool = False,
    published: bool = False,
    post_source_reader: Callable = audit_published_mixed_post_oci_source,
) -> StoredJobRun:
    """Retire exact owned host then detached firewall, with no DELETE replay."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (environment != "devtest" or type(interrupted) is not bool
                or type(published) is not bool or (interrupted and published)):
            raise ValueError("private DevTest boundary differs")
        identifier = (_published_child_id(core_job_id) if published else _child_id(core_job_id))
        child = jobs.get(identifier)

        def published_source_reader(parent, initial, core, plan, jobs, lookup):
            if child is not None and child.status == "succeeded":
                # Terminal recognition verifies the exact destroyed records
                # below; the normal reader requires those rows still active.
                recorded = tuple(parent.input["reviewScope"]["ownedInspectorRecordIds"])
                return post_source_reader(
                    parent, initial, core, plan, jobs, lookup,
                    inspector_record_reader=lambda *_args: recorded)
            return post_source_reader(parent, initial, core, plan, jobs, lookup)

        def historical_authority():
            return _authority(engagement_id, core_job_id, jobs, plans, lookup,
                              interrupted=interrupted, published=published,
                              post_source_reader=published_source_reader)
        historical = historical_authority()
        historical_sha = _authority_digest(historical)
        parent, core, _, _, applied, plan, source, *_ = historical
        source_sha = (parent.input["publishedSourceSha256"] if published
                      else parent.input["sourceSha256"])
        negative = latest_negative_attempt(jobs, engagement_id, core.id)
        if negative is None or negative.status != "succeeded" or negative.action != NEGATIVE_ACTION:
            raise ValueError("exact public-negative receipt missing")
        selector = None
        if interrupted:
            review = _saved_review(parent)
            if next(row for row in review.scopes
                    if row.provider == "digitalocean").selector_retirement_pending:
                selector = jobs.get(interrupted_selector_id(core.id))
                if (selector is None or selector.action != INTERRUPTED_SELECTOR_ACTION
                        or selector.status != "succeeded"
                        or selector.input.get("teardownParentId") != parent.id
                        or selector.input.get("inspectorNegativeJobId") != negative.id
                        or selector.input.get("inspectorNegativeJournalSha256")
                        != job_event_digest(negative.events)):
                    raise ValueError("exact mixed selector retirement is missing")
        elif published:
            selector = jobs.get(published_selector_id(core.id))
            if (selector is None or selector.action != PUBLISHED_SELECTOR_ACTION
                    or selector.status != "succeeded"
                    or selector.input.get("teardownParentId") != parent.id
                    or selector.input.get("inspectorNegativeJobId") != negative.id
                    or selector.input.get("inspectorNegativeJournalSha256")
                    != job_event_digest(negative.events)):
                raise ValueError("exact published selector retirement is missing")
        def selector_guard(*, fresh: bool = False) -> None:
            if selector is None:
                return
            if (jobs.get(selector.id) != selector or selector.status != "succeeded"
                    or selector.input.get("teardownParentId") != parent.id
                    or selector.input.get("inspectorNegativeJournalSha256")
                    != job_event_digest(negative.events)):
                raise ValueError("mixed selector retirement drifted")
            recognizer = (retire_published_mixed_selector if published
                          else selector_recognizer)
            options = ({"post_source_reader": post_source_reader,
                        "historical_negative": True} if published
                       else {"historical_negative": True})
            if fresh and recognizer(
                    engagement_id, core_job_id, environment=environment,
                    state_root=state_root, core_state_root=core_state_root,
                    job_repository=jobs, plan_repository=plans,
                    credential_repository=credentials, lease_lookup=lookup,
                    identity_reader=identity_reader, **options) != selector:
                raise ValueError("mixed selector absence changed")
        if child is not None and "cleanupMetadataVersion" in child.input and (
                type(child.input["cleanupMetadataVersion"]) is not int or child.input["cleanupMetadataVersion"] != 1):
            raise ValueError("Inspector cleanup metadata version differs")
        if child is not None and child.status == "succeeded":
            targets = core_targets(core, plan.evidence["proxyCount"])
            if published:
                from app.services.provider_keyed_mixed_public_targets import published_targets
                targets = published_targets(parent, targets)
            if parent.input.get("publicTargetSealSha256") is not None and (
                    negative.input.get("publicTargetSealSha256") != parent.input["publicTargetSealSha256"]
                    or negative.input.get("targetCount") != len(targets)):
                raise ValueError("Inspector retirement public targets differ")
            control = negative.input.get("positiveControl")
            receipt = negative.events[2].data if len(negative.events) == 3 else {}
            classifications = ([_classified_results(result, targets, control)
                                for result in receipt.get("rounds", [])]
                               if type(receipt) is dict and type(control) is dict else [])
            rows = [row for row in resources.list_for_engagement(engagement_id)
                    if row.id in source.owned_inspector_record_ids]
            saved_settings = settings_repo.get(engagement_id)
            adoption = jobs.get(child.input.get("adoptionJobId"))
            absence = jobs.get(negative.input.get("ociAbsenceJobId"))
            def terminal_row_matches(row) -> bool:
                original = child.input.get(
                    "hostRecord" if row.resource_type == "inspector_instance"
                    else "firewallRecord")
                actual = asdict(row)
                if type(original) is not dict:
                    return False
                expected_metadata = dict(original.get("metadata") or {})
                if child.input.get("cleanupMetadataVersion") == 1:
                    expected_metadata["cleanupRequired"] = False
                return (actual.get("metadata") == expected_metadata
                        and all(actual.get(key) == value for key, value in original.items()
                                if key not in {"status", "lifecycle_state", "metadata",
                                               "updated_at", "destroyed_at"}))

            original_settings = child.input.get("inspectorSettings")
            actual_settings = asdict(saved_settings) if saved_settings is not None else {}
            if (child.action != (PUBLISHED_ACTION if published else ACTION)
                    or child.target_id != engagement_id
                    or child.requested_by != parent.requested_by
                    or child.finished_at is None or child.artifact_refs != []
                    or child.input.get("teardownParentId") != parent.id
                    or child.input.get("sourceSha256") != source_sha
                    or (published and (
                        child.input.get("sourceMode") != "published"
                        or child.input.get("publishedParentJournalSha256")
                        != parent.input["publishedParentJournalSha256"]))
                    or child.input.get("coreJobId") != core.id
                    or child.input.get("corePlanId") != plan.id
                    or child.input.get("negativeJobId") != negative.id
                    or child.input.get("negativeJournalSha256") != job_event_digest(negative.events)
                    or child.input.get("negativeInputSha256") != _fingerprint(negative.input)
                    or child.input.get("ociApplyJournalSha256") != job_event_digest(applied.events)
                    or child.input.get("historicalAuthoritySha256") != historical_sha
                    or adoption is None or adoption.status != "succeeded"
                    or job_event_digest(adoption.events)
                    != child.input.get("adoptionJournalSha256")
                    or absence is None or absence.status != "succeeded"
                    or job_event_digest(absence.events)
                    != negative.input.get("ociAbsenceJournalSha256")
                    or len(classifications) != 2 or any(row is None for row in classifications)
                    or receipt.get("classifications") != classifications
                    or receipt.get("targetSha256") != _fingerprint(targets)
                    or _messages(child, child.input["hostId"], child.input["firewallId"])[-1]
                    != "mixed Inspector local retirement committed"
                    or {row.id for row in rows} != set(source.owned_inspector_record_ids)
                    or any(row.status != "destroyed" or row.lifecycle_state != "destroyed"
                           or row.destroyed_at is None or not terminal_row_matches(row)
                           for row in rows)
                    or type(original_settings) is not dict
                    or any(actual_settings.get(key) != value for key, value in
                           original_settings.items() if key not in {"current_host", "updated_at"})
                    or saved_settings is None or saved_settings.current_host != {}):
                raise ValueError("historical Inspector retirement differs")
            return child
        selector_guard(fresh=True)
        proved = negative_recognizer(
            engagement_id, core_job_id, environment=environment,
            state_root=state_root, core_state_root=core_state_root,
            positive_control=negative.input["positiveControl"],
            job_repository=jobs, plan_repository=plans,
            settings_repository=settings_repo, provider_resource_repository=resources,
            lease_lookup=lookup, identity_reader=identity_reader,
            **({"interrupted": True} if interrupted else
               {"published": True, "post_source_reader": post_source_reader}
               if published else {}))
        if proved != negative:
            raise ValueError("public-negative receipt differs")
        settings = settings_repo.get(engagement_id)
        selected_rows = {row.id: row for row in resources.list_for_engagement(engagement_id)
                         if row.id in source.owned_inspector_record_ids}
        if len(selected_rows) != 2:
            raise ValueError("owned Inspector pair differs")
        host_row = next((row for row in selected_rows.values()
                         if row.resource_type == "inspector_instance"), None)
        firewall_row = next((row for row in selected_rows.values()
                             if row.resource_type == "inspector_firewall"), None)
        if (host_row is None or firewall_row is None or settings is None
                or host_row.status != "active" or firewall_row.status != "active"
                or host_row.adoption_job_id != firewall_row.adoption_job_id
                or host_row.metadata.get("publicIp") != negative.input["inspectorHost"]["publicIp"]
                or not _ID.fullmatch(host_row.resource_id)
                or not _ID.fullmatch(firewall_row.resource_id)):
            raise ValueError("owned Inspector identity differs")
        owner = jobs.get(host_row.adoption_job_id)
        selected = credentials.get_default("linode")
        credential_seal = _credential_seal(selected)
        if (owner is None or owner.status != "succeeded"
                or owner.target_id != engagement_id
                or owner.input.get("credentialAlias") != selected.alias):
            raise ValueError("Inspector adoption credential differs")
        host_id, firewall_id = host_row.resource_id, firewall_row.resource_id
        host_path = f"/linode/instances/{host_id}"
        firewall_path = f"/networking/firewalls/{firewall_id}"
        original_ready_sha = canonical_mixed_core_apply_events(applied)[5].data[
            "inspectorReadySha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", original_ready_sha):
            raise ValueError("original Inspector readiness seal differs")
        input_data = {
            "teardownParentId": parent.id, "sourceSha256": source_sha,
            "coreJobId": core.id, "corePlanId": plan.id,
            "historicalAuthoritySha256": historical_sha,
            "ociApplyJournalSha256": job_event_digest(applied.events),
            "negativeJobId": negative.id,
            "negativeJournalSha256": job_event_digest(negative.events),
            "negativeInputSha256": _fingerprint(negative.input),
            "hostRecordId": host_row.id, "firewallRecordId": firewall_row.id,
            "hostId": host_id, "firewallId": firewall_id,
            "hostName": host_row.name, "firewallName": firewall_row.name,
            "adoptionJobId": owner.id, "adoptionJournalSha256": job_event_digest(owner.events),
            "inspectorReadySha256": original_ready_sha,
            "settingsSha256": _fingerprint(asdict(settings)),
            "inspectorSettings": asdict(settings),
            "hostRecordSha256": _fingerprint(asdict(host_row)),
            "firewallRecordSha256": _fingerprint(asdict(firewall_row)),
            "hostRecord": asdict(host_row),
            "firewallRecord": asdict(firewall_row),
            **({"cleanupMetadataVersion": 1} if child is None or child.input.get("cleanupMetadataVersion") == 1 else {}),
            **credential_seal,
            **({"sourceMode": "published",
                "publishedParentJournalSha256": parent.input[
                    "publishedParentJournalSha256"]} if published else {}),
        }
        if child is None:
            # A fresh positive host and original GO readiness match are required
            # only before the first irreversible intent.
            def before_go():
                fresh = historical_authority()
                if (fresh != historical or _authority_digest(fresh) != historical_sha
                        or jobs.get(negative.id) != negative
                        or _credential_seal(credentials.get_default("linode")) != credential_seal
                        or _fingerprint(asdict(settings_repo.get(engagement_id)))
                        != input_data["settingsSha256"]):
                    raise ValueError("Inspector GO authority changed")
                selector_guard(fresh=True)
            ready = readiness_prover(source, engagement_id, fence=before_go)
            if ready != original_ready_sha:
                raise ValueError("original Inspector service credential differs")
            before_go()
            child = StoredJobRun(
                identifier, PUBLISHED_ACTION if published else ACTION, "queued",
                f"engagement:{engagement_id}",
                "engagement", engagement_id, parent.requested_by,
                input_data, [], _now(), None, None,
                [JobEvent(1, "info", "mixed Inspector retirement queued", {})])
            child = jobs.save_if_absent(child)
        if (child is None or child.action != (PUBLISHED_ACTION if published else ACTION)
                or child.input != input_data
                or child.target_id != engagement_id or child.requested_by != parent.requested_by
                or child.artifact_refs != [] or child.finished_at is not None):
            raise ValueError("retirement reservation changed")
        if child.status == "queued":
            child = jobs.start_if_queued(
                child, started_at=_now(),
                event=JobEvent(2, "info", "mixed Inspector retirement started", {}))
        if child is None or child.status != "running":
            raise ValueError("retirement child start changed")
        messages = _messages(child, host_id, firewall_id)
        token = decrypt_secret(selected.encrypted_secret)
        if not isinstance(token, str) or not token:
            raise ValueError("selected Inspector credential unavailable")
        reader = read_transport or UrllibLinodeTransport(timeout=10)
        deleter = delete_transport or UrllibLinodeExactDelete()

        def fence():
            fresh = historical_authority()
            if (jobs.get(child.id) != child or jobs.get(negative.id) != negative
                    or fresh != historical or _authority_digest(fresh) != historical_sha
                    or _credential_seal(credentials.get_default("linode")) != credential_seal
                    or _fingerprint(asdict(settings_repo.get(engagement_id)))
                    != input_data["settingsSha256"]
                    or {row.id for row in resources.list_for_engagement(engagement_id)
                        if _is_inspector_owned_resource_record(row)
                        and row.status not in {"destroyed", "deleted", "retired", "absent"}}
                    != {host_row.id, firewall_row.id}
                    or any(_fingerprint(asdict(row)) != input_data[
                            "hostRecordSha256" if row.id == host_row.id else "firewallRecordSha256"]
                           for row in resources.list_for_engagement(engagement_id)
                           if row.id in {host_row.id, firewall_row.id})):
                raise ValueError("Inspector retirement authority changed")
            selector_guard()

        if "inspector host DELETE intended" not in messages:
            fence()
            if readiness_prover(source, engagement_id, fence=fence) != original_ready_sha:
                raise ValueError("original Inspector readiness changed before host GO")
            fence()
            host = reader.request("GET", host_path, token)
            firewall = reader.request("GET", firewall_path, token)
            if (type(host) is not dict or str(host.get("id")) != host_id
                    or host.get("label") != host_row.name
                    or type(host.get("tags")) is not list
                    or set(host["tags"]) != {"barragan", "inspector"}
                    or type(firewall) is not dict
                    or str(firewall.get("id")) != firewall_id
                    or firewall.get("label") != firewall_row.name
                    or host_id not in _complete_ids(reader, token, "/linode/instances")
                    or firewall_id not in _complete_ids(reader, token, "/networking/firewalls")):
                raise ValueError("fresh Inspector provider identity differs")
            _linode_devices(reader, token, firewall_id, host_id)
            # Existing provider proof confirms the sole attachment and policy;
            # the readiness digest above binds that proof to original OCI GO.
            fence()
            child = _append(jobs, child, "inspector host DELETE intended",
                            {"path": host_path, "resourceId": host_id},
                            authority_check=fence)
            fence()
            selector_guard(fresh=True)
            response = deleter.delete(host_path, token)
            if response != LinodeDeleteResponse(200, b"{}"):
                raise ValueError("host DELETE receipt is not exact 200 {}")
            child = _append(jobs, child, "inspector host DELETE 200 received", {},
                            authority_check=fence)
        _wait_absent(reader, token, host_path, "/linode/instances", host_id,
                     sleep=sleep, fence=fence)
        if "inspector host absence proved" not in _messages(child, host_id, firewall_id):
            child = _append(jobs, child, "inspector host absence proved", {},
                            authority_check=fence)
        if "inspector firewall DELETE intended" not in _messages(child, host_id, firewall_id):
            fence()
            firewall = reader.request("GET", firewall_path, token)
            if (type(firewall) is not dict or str(firewall.get("id")) != firewall_id
                    or firewall.get("label") != firewall_row.name
                    or firewall_id not in _complete_ids(reader, token, "/networking/firewalls")):
                raise ValueError("firewall identity differs after host absence")
            _empty_firewall_devices(reader, token, firewall_id)
            fence()
            child = _append(jobs, child, "inspector firewall DELETE intended",
                            {"path": firewall_path, "resourceId": firewall_id},
                            authority_check=fence)
            fence()
            selector_guard(fresh=True)
            response = deleter.delete(firewall_path, token)
            if response != LinodeDeleteResponse(200, b"{}"):
                raise ValueError("firewall DELETE receipt is not exact 200 {}")
            child = _append(jobs, child, "inspector firewall DELETE 200 received", {},
                            authority_check=fence)
        _wait_absent(reader, token, firewall_path, "/networking/firewalls", firewall_id,
                     sleep=sleep, fence=fence)
        _wait_absent(reader, token, host_path, "/linode/instances", host_id,
                     sleep=sleep, fence=fence)
        if "inspector firewall absence proved" not in _messages(child, host_id, firewall_id):
            child = _append(jobs, child, "inspector firewall absence proved", {},
                            authority_check=fence)
        fence()
        selector_guard(fresh=True)
        return _finish_atomic(child, jobs=jobs, plans=plans, lookup=lookup,
                              resources=resources, settings_repo=settings_repo,
                              credentials=credentials, parent=parent, core=core,
                              historical_sha=historical_sha,
                              negative=negative, host_row=host_row, firewall_row=firewall_row,
                              settings=settings, credential_seal=credential_seal,
                              interrupted=interrupted, published=published,
                              post_source_reader=post_source_reader, selector=selector)
    except Exception:
        raise MixedZeroApplyInspectorRetirementAttention(
            "mixed Inspector retirement requires exact read-only reconciliation") from None


def _finish_atomic(child, *, jobs, plans, lookup, resources, settings_repo,
                   credentials, parent, core, negative, host_row, firewall_row,
                   settings, credential_seal, historical_sha, interrupted=False,
                   published=False, post_source_reader=audit_published_mixed_post_oci_source,
                   selector=None):
    """Atomically retire two records, clear current host, and seal child only."""
    from sqlalchemy import update
    from app.storage.database import db
    from app.storage.models import (
        CoreMutationLeaseModel, EngagementObserverSettingsModel,
        JobEventModel, JobRunModel, ProviderResourceRecordModel,
    )

    stamp = datetime.now(timezone.utc)
    try:
        # A previous ORM read transaction may hold cached authority. Acquire
        # the SQLite writer slot from a fresh transaction, then reread it.
        db.session.rollback()
        locked = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == child.id, JobRunModel.action == child.action,
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.input == child.input, JobRunModel.target_id == child.target_id,
        ).values(status="running"))
        db.session.expire_all()
        if (locked.rowcount != 1 or jobs.get(child.id) != child
                or _messages(child, child.input["hostId"], child.input["firewallId"])[-1]
                != "inspector firewall absence proved"
                or jobs.get(parent.id) != parent or jobs.get(negative.id) != negative
                or (selector is not None and jobs.get(selector.id) != selector)
                or _authority_digest(_authority(
                    parent.target_id, core.id, jobs, plans, lookup,
                    interrupted=interrupted, published=published,
                    post_source_reader=post_source_reader)) != historical_sha
                or plans.get(child.input["corePlanId"]).apply_job_id != core.id
                or lookup(parent.target_id) != (child.input["corePlanId"],
                                                   "provider_keyed_teardown_fence")
                or _credential_seal(credentials.get_default("linode")) != credential_seal
                or _fingerprint(asdict(settings_repo.get(parent.target_id)))
                != child.input["settingsSha256"]
                or {row.id: _fingerprint(asdict(row)) for row in
                    resources.list_for_engagement(parent.target_id)
                    if row.id in {host_row.id, firewall_row.id}}
                != {host_row.id: child.input["hostRecordSha256"],
                    firewall_row.id: child.input["firewallRecordSha256"]}
                or {row.id for row in resources.list_for_engagement(parent.target_id)
                    if _is_inspector_owned_resource_record(row)
                    and row.status not in {"destroyed", "deleted", "retired", "absent"}}
                != {host_row.id, firewall_row.id}):
            raise ValueError("Inspector final authority changed")
        lease = db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=parent.target_id).one_or_none()
        if (lease is None or lease.owner_id != child.input["corePlanId"]
                or lease.operation != "provider_keyed_teardown_fence"):
            raise ValueError("Inspector final lease differs")
        for row in (host_row, firewall_row):
            result = db.session.execute(update(ProviderResourceRecordModel).where(
                ProviderResourceRecordModel.id == row.id,
                ProviderResourceRecordModel.engagement_id == parent.target_id,
                ProviderResourceRecordModel.status == row.status,
                ProviderResourceRecordModel.lifecycle_state == row.lifecycle_state,
                ProviderResourceRecordModel.metadata_json == row.metadata,
                ProviderResourceRecordModel.adoption_job_id == row.adoption_job_id,
            ).values(status="destroyed", lifecycle_state="destroyed",
                     metadata_json=({**row.metadata, "cleanupRequired": False}
                                    if child.input.get("cleanupMetadataVersion") == 1 else row.metadata),
                     destroyed_at=stamp, updated_at=stamp))
            if result.rowcount != 1:
                raise ValueError("Inspector record retirement raced")
        changed = db.session.execute(update(EngagementObserverSettingsModel).where(
            EngagementObserverSettingsModel.engagement_id == parent.target_id,
            EngagementObserverSettingsModel.current_host == settings.current_host,
            EngagementObserverSettingsModel.provider == "linode",
        ).values(current_host={}, updated_at=stamp))
        if changed.rowcount != 1:
            raise ValueError("Inspector current host changed")
        committed = db.session.execute(update(JobRunModel).where(
            JobRunModel.id == child.id, JobRunModel.action == child.action,
            JobRunModel.status == "running", JobRunModel.finished_at.is_(None),
            JobRunModel.input == child.input,
        ).values(status="succeeded", finished_at=stamp))
        if committed.rowcount != 1:
            raise ValueError("Inspector terminal child changed")
        db.session.add(JobEventModel(
            job_id=child.id, sequence=len(child.events) + 1, level="info",
            message="mixed Inspector local retirement committed",
            data={"hostRecordId": host_row.id, "firewallRecordId": firewall_row.id}))
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    saved = jobs.get(child.id)
    if saved is None or saved.status != "succeeded":
        raise ValueError("Inspector terminal commit uncertain")
    return saved
