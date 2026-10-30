# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private Inspector proof that former mixed core SSH endpoints are closed.

The retained Inspector is neither retired nor reconfigured here.  This child
is read-only. A terminal failed probe may have a bounded, independently
journaled retry; an unfinished probe remains attention.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import ipaddress
from pathlib import Path
import time
from typing import Callable

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import (
    INSPECTOR_RESOURCE_SOURCE, ObserverSshKey, SshObserverRunner, _inspector_host_from_settings,
    _is_inspector_owned_resource_record, _usable_inspector_host,
)
from app.services.provider_keyed_inspector_negative import (
    _classified_results, _retained_ssh_key,
)
from app.services.provider_keyed_core_destroy_preview import _read_regular
from app.services.provider_keyed_mixed_zero_apply_core_absence import (
    ACTION as ABSENCE_ACTION, _authority, _authority_digest, _child_prefix,
    prove_mixed_zero_apply_oci_core_absence,
)
from app.services.provider_keyed_mixed_published_post_oci_source import (
    audit_published_mixed_post_oci_source,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


ACTION = "provider_keyed_mixed_zero_apply_inspector_negative"
_MAX_ATTEMPTS = 3


class MixedZeroApplyInspectorNegativeAttention(ValueError):
    """The exact Inspector public-negative receipt needs reconciliation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-inspector-negative-{core_job_id.removeprefix('job-')}"


def _attempt_id(core_job_id: str, number: int) -> str:
    return _child_id(core_job_id) if number == 1 else f"{_child_id(core_job_id)}-attempt-{number}"


def _attempts(jobs, engagement_id: str, core_job_id: str) -> list[StoredJobRun]:
    """Reject alien or missing attempts before selecting any receipt."""
    allowed = [_attempt_id(core_job_id, number)
               for number in range(1, _MAX_ATTEMPTS + 1)]
    rows = {row.id: row for row in jobs.list_for_engagement(engagement_id)
            if row.action == ACTION and (
                row.id.startswith(allowed[0]) or row.input.get("coreJobId") == core_job_id)}
    if any(identifier not in allowed for identifier in rows):
        raise ValueError("unexpected mixed Inspector negative child")
    ordered = [rows[identifier] for identifier in allowed if identifier in rows]
    if len(ordered) != len(rows) or any(
            row.id != allowed[index] or jobs.get(row.id) != row
            for index, row in enumerate(ordered)):
        raise ValueError("mixed Inspector attempt lineage differs")
    return ordered


def latest_negative_attempt(jobs, engagement_id: str, core_job_id: str) -> StoredJobRun | None:
    """Return the latest job only when earlier attempts are terminal failures."""
    rows = _attempts(jobs, engagement_id, core_job_id)
    if not rows:
        return None
    base = {key: value for key, value in rows[-1].input.items()
            if key not in {"previousNegativeJobId", "previousNegativeJournalSha256"}}
    for index, row in enumerate(rows):
        expected = dict(base)
        if index:
            expected.update({
                "previousNegativeJobId": rows[index - 1].id,
                "previousNegativeJournalSha256": job_event_digest(rows[index - 1].events),
            })
        if row.input != expected:
            raise ValueError("mixed Inspector attempt input differs")
        if index < len(rows) - 1 and (
                row.status != "failed" or row.started_at is None or row.finished_at is None
                or row.events != [
                    JobEvent(1, "info", "mixed Inspector negative queued", {}),
                    JobEvent(2, "info", "mixed Inspector negative started", {}),
                    JobEvent(3, "error", "mixed Inspector negative unverified", {}),
                ]):
            raise ValueError("mixed Inspector earlier attempt is not a terminal failure")
    return rows[-1]


def _targets(core: StoredJobRun, proxy_count: int) -> list[dict]:
    """Use only this applied core job's saved homebase/proxy connection rows."""
    final = [event.data["connectionDetails"] for event in core.events
             if event.message == "pilot Standard RTI run finished"
             and type(event.data) is dict and "connectionDetails" in event.data]
    earlier = [event.data["connectionDetails"] for event in core.events
               if event.message == "operator inspection ready"
               and type(event.data) is dict and "connectionDetails" in event.data]
    if (len(final) != 1 or type(final[0]) is not list or len(earlier) > 1
            or (earlier and earlier[0] != final[0])):
        raise ValueError("saved core connection receipt differs")
    rows, seen = [], set()
    for detail in final[0]:
        if type(detail) is not dict:
            raise ValueError("saved core connection row differs")
        role, ip = detail.get("role"), detail.get("publicIp")
        if role == "elk":
            continue
        if role not in {"homebase", "proxy"} or type(ip) is not str:
            raise ValueError("saved core SSH target differs")
        address = ipaddress.ip_address(ip)
        if (not isinstance(address, ipaddress.IPv4Address) or not address.is_global
                or str(address) != ip or ip in seen):
            raise ValueError("saved core SSH address differs")
        seen.add(ip)
        rows.append({"id": f"tcp:{ip}:22", "type": "tcp-forbidden", "host": ip,
                     "port": 22, "targetGroup": "core-public-management"})
    if (type(proxy_count) is not int or proxy_count not in {1, 2}
            or len(rows) != proxy_count + 1
            or sum(row.get("role") == "homebase" for row in final[0]) != 1
            or sum(row.get("role") == "proxy" for row in final[0]) != proxy_count):
        raise ValueError("saved core SSH host count differs")
    return sorted(rows, key=lambda row: row["id"])


def prove_mixed_zero_apply_inspector_negative(
    engagement_id: str, core_job_id: str, *, environment: str, state_root: Path,
    core_state_root: Path, positive_control: dict,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, lease_lookup=None, runner=None,
    ssh_key_factory: Callable[[str], ObserverSshKey] = _retained_ssh_key,
    absence_recognizer: Callable = prove_mixed_zero_apply_oci_core_absence,
    identity_reader=None,
    interrupted: bool = False, published: bool = False,
    post_source_reader: Callable = audit_published_mixed_post_oci_source,
) -> StoredJobRun:
    """Seal two classified Inspector rounds after the exact mixed OCI absence."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    lookup = lease_lookup or _db_lease_lookup
    current = None
    try:
        if (type(interrupted) is not bool or type(published) is not bool
                or (interrupted and published)
                or environment != "devtest" or type(positive_control) is not dict or set(
                positive_control) != {"id", "type", "host", "port"}):
            raise ValueError("private Inspector proof boundary differs")
        if (positive_control["id"] != "inspector-external-control"
                or positive_control["type"] != "tcp"
                or type(positive_control["port"]) is not int
                or positive_control["port"] != 443):
            raise ValueError("external control differs")
        control_ip = ipaddress.ip_address(positive_control["host"])
        if (not isinstance(control_ip, ipaddress.IPv4Address)
                or not control_ip.is_global or str(control_ip) != positive_control["host"]):
            raise ValueError("external control address differs")

        def authority(*, recognize_absence: bool = True):
            historical = _authority(engagement_id, core_job_id, jobs, plans, lookup,
                                    interrupted=interrupted, published=published,
                                    post_source_reader=post_source_reader)
            parent, core, _, _, _, plan, source, *_ = historical
            attempts = [row for row in jobs.list_for_engagement(engagement_id)
                        if row.action == ABSENCE_ACTION and row.id.startswith(
                            _child_prefix(core.id) + "-attempt-")]
            succeeded = [row for row in attempts if row.status == "succeeded"]
            if len(succeeded) != 1 or succeeded[0] != sorted(
                    attempts, key=lambda row: row.id)[-1]:
                raise ValueError("successful OCI absence receipt missing")
            # The canonical success branch is read-only. Never call it without
            # a succeeded candidate: otherwise it could start another scan.
            absence_options = ({"interrupted": True} if interrupted else
                               {"published": True,
                                "post_source_reader": post_source_reader} if published else {})
            absent = (absence_recognizer(
                engagement_id, core_job_id, environment=environment,
                state_root=state_root, core_state_root=core_state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup,
                identity_reader=identity_reader, **absence_options)
                if recognize_absence else succeeded[0])
            if absent != succeeded[0] or absent.status != "succeeded":
                raise ValueError("OCI absence receipt changed")
            targets = _targets(core, plan.evidence["proxyCount"])
            if published:
                from app.services.provider_keyed_mixed_public_targets import published_targets
                targets = published_targets(parent, targets)
            if any(row["host"] == control_ip.exploded for row in targets):
                raise ValueError("external control overlaps core")
            settings = settings_repo.get(engagement_id)
            if (settings is None or settings.engagement_id != engagement_id
                    or settings.enabled is not True
                    or settings.mode not in {"once", "continuous"}):
                raise ValueError("retained Inspector settings differ")
            host = _inspector_host_from_settings(settings.current_host, settings=settings)
            if (host is None or not _usable_inspector_host(host)
                    or host.provider != "linode"
                    or not ipaddress.ip_address(host.public_ip).is_global
                    or host.public_ip in {row["host"] for row in targets}
                    or host.public_ip == positive_control["host"]):
                raise ValueError("retained Inspector host differs")
            all_rows = resources.list_for_engagement(engagement_id)
            active_inspector = [row for row in all_rows
                                if _is_inspector_owned_resource_record(row)
                                and row.status.lower() not in {
                                    "destroyed", "deleted", "retired", "absent"}]
            selected = [row for row in all_rows
                        if row.id in source.owned_inspector_record_ids]
            if (len(selected) != 2 or {row.id for row in selected}
                    != set(source.owned_inspector_record_ids)
                    or {row.id for row in active_inspector}
                    != set(source.owned_inspector_record_ids)):
                raise ValueError("retained Inspector ownership differs")
            instance = next((row for row in selected if row.resource_type == "inspector_instance"), None)
            firewall = next((row for row in selected if row.resource_type == "inspector_firewall"), None)
            firewall_data = host.metadata.get("providerFirewall") if isinstance(host.metadata, dict) else None
            if (instance is None or firewall is None or instance.status != "active"
                    or firewall.status != "active" or instance.provider != "linode"
                    or firewall.provider != "linode" or instance.resource_id != host.resource_id
                    or instance.source != INSPECTOR_RESOURCE_SOURCE
                    or firewall.source != INSPECTOR_RESOURCE_SOURCE
                    or instance.name != host.name or instance.region != host.region
                    or instance.metadata.get("publicIp") != host.public_ip
                    or instance.metadata.get("barraganOwned") is not True
                    or instance.metadata.get("role") != "inspector"
                    or firewall.metadata.get("barraganOwned") is not True
                    or firewall.metadata.get("role") != "inspector_firewall"
                    or firewall.metadata.get("inspectorHostResourceId") != host.resource_id
                    or firewall.adoption_job_id != instance.adoption_job_id
                    or not isinstance(firewall_data, dict)
                    or firewall_data.get("resourceId") != firewall.resource_id):
                raise ValueError("retained Inspector record differs")
            return historical, absent, settings, host, selected, targets

        baseline = authority()
        historical, absent, settings, host, selected, targets = baseline
        parent, core, _, _, _, plan, *_ = historical
        inspector_authority_sha = _fingerprint({
            "settings": asdict(settings),
            "records": [asdict(row) for row in selected],
        })
        ssh_key = ssh_key_factory(_child_id(core.id))
        if ssh_key.cleanup_paths:
            raise ValueError("Inspector proof requires retained key")
        key_sha = _fingerprint({"path": ssh_key.private_key_path,
                                "publicKey": ssh_key.public_key})
        def fence():
            fresh = authority()
            if (fresh != baseline
                    or _authority_digest(fresh[0]) != _authority_digest(historical)
                    or _fingerprint({"settings": asdict(fresh[2]),
                                     "records": [asdict(row) for row in fresh[4]]})
                    != inspector_authority_sha):
                raise ValueError("Inspector proof authority changed")
            key = ssh_key_factory(_child_id(core.id))
            if key.cleanup_paths or _fingerprint({"path": key.private_key_path,
                             "publicKey": key.public_key}) != key_sha:
                raise ValueError("retained Inspector key changed")

        def terminal_authority_check():
            # SQLite writer slot held: only persisted/local authority is read.
            fresh = authority(recognize_absence=False)
            if (fresh != baseline
                    or _authority_digest(fresh[0]) != input_data["historicalAuthoritySha256"]
                    or _fingerprint({"settings": asdict(fresh[2]),
                                     "records": [asdict(row) for row in fresh[4]]})
                    != input_data["inspectorAuthoritySha256"]
                    or jobs.get(identifier) != current
                    or hashlib.sha256(_read_regular(Path(
                        plan.evidence["terraformStatePath"]))).hexdigest()
                    != absent.input["emptyStateSha256"]):
                raise ValueError("Inspector terminal authority changed")
            key = ssh_key_factory(_child_id(core.id))
            if key.cleanup_paths or _fingerprint({
                    "path": key.private_key_path,
                    "publicKey": key.public_key}) != key_sha:
                raise ValueError("Inspector terminal key changed")

        input_data = {
            "teardownParentId": parent.id,
            "sourceSha256": parent.input[
                "publishedSourceSha256" if published else "sourceSha256"],
            "coreJobId": core.id, "corePlanId": plan.id,
            "historicalAuthoritySha256": _authority_digest(historical),
            "ociAbsenceJobId": absent.id,
            "ociAbsenceJournalSha256": job_event_digest(absent.events),
            "targetSha256": _fingerprint(targets), "targetCount": len(targets),
            "positiveControl": positive_control,
            "positiveControlSha256": _fingerprint(positive_control),
            "inspectorRecordIds": sorted(row.id for row in selected),
            "inspectorHost": host.to_dict(), "inspectorSettingsUpdatedAt": settings.updated_at,
            "inspectorAuthoritySha256": inspector_authority_sha,
            "inspectorKeySha256": key_sha,
        }
        if parent.input.get("publicTargetSealSha256") is not None:
            input_data["publicTargetSealSha256"] = parent.input["publicTargetSealSha256"]
        prior = latest_negative_attempt(jobs, engagement_id, core.id)
        attempts = _attempts(jobs, engagement_id, core.id)
        identifier = prior.id if prior is not None else _child_id(core.id)
        if len(attempts) > 1:
            input_data.update({
                "previousNegativeJobId": attempts[-2].id,
                "previousNegativeJournalSha256": job_event_digest(attempts[-2].events),
            })
        if prior is not None and prior.status == "failed":
            if (prior.input != input_data or prior.target != f"engagement:{engagement_id}"
                    or prior.target_type != "engagement" or prior.target_id != engagement_id
                    or prior.requested_by != parent.requested_by
                    or prior.started_at is None or prior.finished_at is None
                    or prior.artifact_refs != [] or prior.events != [
                        JobEvent(1, "info", "mixed Inspector negative queued", {}),
                        JobEvent(2, "info", "mixed Inspector negative started", {}),
                        JobEvent(3, "error", "mixed Inspector negative unverified", {}),
                    ] or len(attempts) >= _MAX_ATTEMPTS):
                raise ValueError("failed Inspector attempt cannot be retried")
            input_data.update({
                "previousNegativeJobId": prior.id,
                "previousNegativeJournalSha256": job_event_digest(prior.events),
            })
            identifier = _attempt_id(core.id, len(attempts) + 1)
            prior = jobs.get(identifier)
        if prior is not None and prior.status == "succeeded":
            if (prior.action != ACTION or prior.input != input_data
                    or prior.target != f"engagement:{engagement_id}"
                    or prior.target_type != "engagement"
                    or prior.target_id != engagement_id
                    or prior.requested_by != parent.requested_by
                    or prior.started_at is None or prior.finished_at is None
                    or prior.artifact_refs != []
                    or len(prior.events) != 3
                    or prior.events[:2] != [
                        JobEvent(1, "info", "mixed Inspector negative queued", {}),
                        JobEvent(2, "info", "mixed Inspector negative started", {})]):
                raise ValueError("saved Inspector child differs")
            receipt = prior.events[2]
            if (receipt.sequence != 3 or receipt.level != "info"
                    or receipt.message != "mixed Inspector exact public negative proved"
                    or type(receipt.data) is not dict
                    or set(receipt.data) != {"targetSha256", "rounds", "classifications"}
                    or receipt.data["targetSha256"] != input_data["targetSha256"]
                    or type(receipt.data["rounds"]) is not list
                    or len(receipt.data["rounds"]) != 2
                    or receipt.data["classifications"] != [
                        _classified_results(result, targets, positive_control)
                        for result in receipt.data["rounds"]]
                    or any(row is None for row in receipt.data["classifications"])):
                raise ValueError("saved Inspector classifications differ")
            fence()
            return prior
        if prior is None:
            queued = StoredJobRun(
                identifier, ACTION, "queued", f"engagement:{engagement_id}",
                "engagement", engagement_id, parent.requested_by, input_data, [],
                _now(), None, None,
                [JobEvent(1, "info", "mixed Inspector negative queued", {})])
            prior = jobs.save_if_absent(queued)
        if (prior is None or prior.action != ACTION or prior.input != input_data
                or prior.target != f"engagement:{engagement_id}"
                or prior.target_type != "engagement"
                or prior.target_id != engagement_id
                or prior.requested_by != parent.requested_by
                or prior.status != "queued" or prior.started_at is not None
                or prior.finished_at is not None or prior.artifact_refs != []
                or prior.events != [JobEvent(1, "info", "mixed Inspector negative queued", {})]):
            raise ValueError("started Inspector child cannot be replayed")
        current = jobs.start_if_queued(
            prior, started_at=_now(),
            event=JobEvent(2, "info", "mixed Inspector negative started", {}))
        if current is None:
            raise ValueError("Inspector child start changed")
        rounds = []
        classes = []
        dns_budget = min(900, max([target.get("ttlSeconds", 0) for target in targets] + [0]) + 30)
        dns_deadline = time.monotonic() + dns_budget
        for _ in range(2):
            fence()
            result = (runner or SshObserverRunner()).run(
                host=host, ssh_key=ssh_key,
                spec={"positive": [positive_control], "negative": targets,
                      "timeoutSeconds": 8, "strictNegativeTcp": True,
                      **({"strictNegativeUdp": True, "dnsSettleSeconds": max(0, int(dns_deadline - time.monotonic()))}
                         if parent.input.get("publicTargetSealSha256") is not None else {})})
            classified = _classified_results(result, targets, positive_control)
            if classified is None:
                raise ValueError("Inspector round inconclusive")
            fence()
            rounds.append(result)
            classes.append(classified)
        current = jobs.finish_mixed_inspector_negative_if_running(
            current, lease_owner=plan.id,
            expected_event_digest=job_event_digest(current.events),
            finished_at=_now(), authority_check=terminal_authority_check,
            event=JobEvent(3, "info", "mixed Inspector exact public negative proved", {
                "targetSha256": input_data["targetSha256"], "rounds": rounds,
                "classifications": classes}))
        if current is None:
            raise ValueError("Inspector proof terminal write changed")
        return current
    except Exception:
        if current is not None and current.status == "running":
            try:
                jobs.finish_if_running(current, status="failed", finished_at=_now(),
                    event=JobEvent(3, "error", "mixed Inspector negative unverified", {}))
            except Exception:
                pass
        raise MixedZeroApplyInspectorNegativeAttention(
            "mixed Inspector public-negative proof is unverified") from None
