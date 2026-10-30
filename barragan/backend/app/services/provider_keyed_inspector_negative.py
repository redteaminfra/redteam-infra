# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private pending-build Inspector proof of retired public endpoints.

This is a read-only network continuation.  A successful receipt is evidence for
later reconciliation, not authority to remove the Inspector or finish teardown.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Callable

from app.domain import JobEvent
from app.services.engagement_teardown import _valid_public_targets, _valid_scope_public_targets
from app.services.observer_checks import (
    INSPECTOR_RESOURCE_SOURCE, ObserverSshKey, SshObserverRunner,
    _inspector_host_from_settings,
    _is_inspector_resource_record, _retired_target_public_ips,
    _teardown_target, _usable_inspector_host,
)
from app.services.provider_keyed_comprehensive_teardown import (
    _FENCE, _boundary, _child_id, recognize_provider_keyed_group_retired,
)
from app.services.provider_keyed_core_destroy_absence import (
    ACTION as ABSENCE_ACTION, prove_pending_keyed_oci_core_destroy_absence,
)
from app.services.provider_keyed_destroy_absence_preflight import (
    reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.services.provider_keyed_inspector_prepare_binder import (
    _existing_key_identity, _safe_key_identity, _verify_key_pair,
)
from app.services.provider_keyed_inspector_readiness_publish import (
    recognize_historical_keyed_inspector_readiness,
)
from app.services.provider_keyed_pending_retirement import recognize_pending_keyed_group_retired
from app.services.provider_keyed_pending_cleanup import _require_diagnostic_targets
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import (
    TERMINAL_RECORD_STATUSES, SqlAlchemyProviderResourceRepository,
)


ACTION = "provider_keyed_inspector_negative"
_HASH = set("0123456789abcdef")


class KeyedInspectorNegativeAttention(ValueError):
    """The frozen public-negative proof is absent or needs reconciliation."""


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(char in _HASH for char in value)


def _retained_ssh_key(_job_id: str) -> ObserverSshKey:
    """Use the existing pinned Inspector key; never create one during cleanup."""
    path, digest = _safe_key_identity(_existing_key_identity)
    _verify_key_pair(path, digest)
    with open(path + ".pub", encoding="utf-8") as handle:
        public_key = handle.read().strip()
    return ObserverSshKey(path, public_key)


def _valid_dns_answers(target, answers):
    """Persisted resolver success must contain values of the requested RR type."""
    try:
        kind = target["recordType"]
        for value in answers:
            if kind in {"A", "AAAA"}:
                address = ipaddress.ip_address(value)
                if str(address) != value or address.version != (4 if kind == "A" else 6):
                    return False
            elif kind in {"CNAME", "NS", "MX"}:
                from app.services.provider_keyed_mixed_public_targets import _name
                name = value
                if kind == "MX":
                    preference, name = value.split(" ", 1)
                    if str(int(preference)) != preference or not 0 <= int(preference) <= 65535:
                        return False
                if _name(name) != name:
                    return False
            elif kind != "TXT":
                return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def _classified_results(evidence: object, targets: list[dict], control: dict) -> list[dict] | None:
    if type(evidence) is not dict or type(evidence.get("ok")) is not bool:
        return None
    results = evidence.get("results")
    if type(results) is not list or len(results) != len(targets) + 1:
        return None
    expected = {target["id"]: target for target in [control, *targets]}
    seen: set[str] = set()
    classification = []
    timed_out = False
    for result in results:
        if type(result) is not dict or result.get("id") not in expected:
            return None
        target = expected[result["id"]]
        if (result["id"] in seen or result.get("type") != target["type"]
                or result.get("expected") != (
                    "reachable" if result["id"] == control["id"] else
                    "absent" if target["type"] in {"dns-absent", "dns-record-absent"} else "closed")
                or "observed" not in result):
            return None
        if result["id"] == control["id"]:
            if result.get("ok") is not True or result["observed"] != "":
                return None
        elif target["type"] == "dns-record-absent":
            observed = result["observed"]
            if (result.get("ok") is not True or type(observed) is not dict
                    or set(observed) != {"1.1.1.1", "8.8.8.8"}
                    or any(type(row) is not dict or set(row) != {"status", "answers"}
                        or row["status"] != "answered" or type(row["answers"]) is not list
                        or any(type(value) is not str for value in row["answers"])
                        or row["answers"] != sorted(set(row["answers"]))
                        or not _valid_dns_answers(target, row["answers"])
                        or target["previousAnswer"] in row["answers"]
                        for row in observed.values())):
                return None
            classification.append({"id": result["id"], "classification": "previous_owned_record_answer_absent"})
        elif (result.get("ok") is True and result["observed"] == {
                "status": "closed", "reason": "connection_refused"}):
            classification.append({"id": result["id"], "classification": "closed"})
        elif (result.get("ok") is False and result["observed"] == {
                "status": "inconclusive", "reason": "timed_out", "errorType": "TimeoutError"}):
            classification.append({"id": result["id"],
                                   "classification": ("non_responsive_udp_after_provider_absence" if target["type"] == "udp-forbidden"
                                                      else "non_reachable_after_provider_absence")})
            timed_out = True
        else:
            return None
        seen.add(result["id"])
    if seen != set(expected) or evidence["ok"] != (not timed_out):
        return None
    return sorted(classification, key=lambda row: row["id"])


def prove_pending_keyed_inspector_negative(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
    runner=None, ssh_key_factory: Callable[[str], ObserverSshKey] = _retained_ssh_key,
    positive_control: dict | None = None,
    do_absence_reader: Callable = reconcile_successful_digitalocean_destroy_absence,
    oci_absence_recognizer: Callable = prove_pending_keyed_oci_core_destroy_absence,
) -> StoredJobRun:
    """Persist one exact Inspector-origin negative probe; never remove resources."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    lookup = lease_lookup or _db_lease_lookup
    child = None
    try:
        if environment != "devtest" or not teardown_parent_id:
            raise ValueError("DevTest parent required")
        if (type(positive_control) is not dict
                or set(positive_control) != {"id", "type", "host", "port"}
                or positive_control.get("id") != "inspector-external-control"
                or positive_control.get("type") != "tcp"
                or type(positive_control.get("host")) is not str
                or type(positive_control.get("port")) is not int
                or positive_control["port"] != 443):
            raise ValueError("approved Inspector external control required")
        control_ip = ipaddress.ip_address(positive_control["host"])
        if (control_ip.version != 4 or not control_ip.is_global
                or str(control_ip) != positive_control["host"]):
            raise ValueError("Inspector external control must be global IPv4")

        def authority():
            selected = jobs.get(teardown_parent_id)
            if selected is None:
                raise ValueError("teardown parent missing")
            published = "publishedSource" in selected.input
            group_recognizer = (recognize_provider_keyed_group_retired if published
                                else recognize_pending_keyed_group_retired)
            retired = group_recognizer(
                teardown_parent_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans,
                sketch_repository=sketch_repository,
                credential_repository=credential_repository,
                provider_resource_repository=resources, lease_lookup=lookup,
            )
            if len(retired) != 2:
                raise ValueError("exact provider group retirement is unverified")
            parent, core, snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
            coordinator = jobs.get(_child_id(core.id))
            plan = plans.get(core.input["corePlanId"])
            if (("publishedSource" in parent.input) != published or operation != _FENCE
                    or plan is None or coordinator is None
                    or coordinator.action != "provider_keyed_comprehensive_teardown"
                    or coordinator.target_id != parent.target_id
                    or coordinator.status != "running"
                    or coordinator.input.get("phase") != (
                        "group_retired" if published else "pending_group_retired")
                    or plan.status != "applied" or plan.apply_job_id != core.id):
                raise ValueError("teardown fence differs")
            prefix = f"job-provider-keyed-core-destroy-absence-{core.id.removeprefix('job-')}-attempt-"
            attempts = sorted((row for row in jobs.list_for_engagement(parent.target_id)
                               if row.action == ABSENCE_ACTION and row.id.startswith(prefix)),
                              key=lambda row: row.id)
            success = [row for row in attempts if row.status == "succeeded"]
            if len(success) != 1 or not attempts or success[0] != attempts[-1]:
                raise ValueError("one successful exact OCI absence receipt required")
            absent = success[0]
            receipt = absent.events[-1] if absent.events else None
            witness = receipt.data.get("ociAbsenceWitness") if receipt else None
            if (receipt is None or type(receipt.data) is not dict
                    or absent.target_id != parent.target_id or absent.requested_by != parent.requested_by
                    or absent.finished_at is None or absent.input.get("teardownParentId") != parent.id
                    or absent.input.get("coreJobId") != core.id
                    or absent.input.get("corePlanId") != plan.id
                    or absent.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                    or absent.input.get("preDestroyResourceIdsSha256") != receipt.data.get("preDestroyResourceIdsSha256")
                    or absent.input.get("emptyStateSha256") != receipt.data.get("emptyStateSha256")
                    or not _hash(absent.input.get("preDestroyResourceIdsSha256"))
                    or not _hash(absent.input.get("emptyStateSha256"))
                    or len(absent.events) != 3
                    or [event.message for event in absent.events[:2]] != [
                        "core destroy absence queued", "core destroy absence started"]
                    or any(event.level != "info" for event in absent.events)
                    or [event.sequence for event in absent.events] != [1, 2, 3]
                    or receipt.level != "info" or receipt.message != "core destroy exact absence proved"
                    or type(witness) is not dict or witness.get("phase") != "absent"
                    or witness.get("resource_ids_sha256") != absent.input["preDestroyResourceIdsSha256"]
                    or witness.get("principal_sha256") != absent.input.get("principalSha256")
                    or witness.get("auth") != "instance_principal"
                    or not _hash(witness.get("inventory_sha256"))
                    or not _hash(witness.get("evidence_sha256"))
                    or not _hash(witness.get("principal_sha256"))):
                raise ValueError("OCI absence receipt differs")
            # A succeeded candidate is mandatory before invoking the canonical
            # service. Its success branch is read-only; an absent candidate
            # would otherwise let that service create a new scan attempt.
            absence_recognizer = (prove_pending_keyed_oci_core_destroy_absence if published
                                  else oci_absence_recognizer)
            recognized_absence = absence_recognizer(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup,
            )
            if recognized_absence != absent or recognized_absence.status != "succeeded":
                raise ValueError("canonical OCI core absence receipt differs")
            raw_targets = snapshot.get("publicVerificationTargets")
            if (type(raw_targets) is not list or not raw_targets
                    or not (_valid_scope_public_targets(snapshot) if published
                            else _valid_public_targets(raw_targets))
                    or snapshot.get("inspector", {}).get("verificationTargetCount") != len(raw_targets)):
                raise ValueError("frozen public targets are missing or invalid")
            if published:
                from app.services.provider_keyed_published_initial_cleanup_authority import (
                    KEY, validate_saved_cleanup,
                )
                validate_saved_cleanup(parent, core, snapshot, jobs)
                if KEY not in snapshot:
                    _require_diagnostic_targets(core, snapshot)
            else:
                _require_diagnostic_targets(core, snapshot)
            if any(value["id"] == positive_control["id"] or value["host"] == positive_control["host"]
                   for value in raw_targets):
                raise ValueError("Inspector control overlaps a frozen retired endpoint")
            targets = [_teardown_target(value) for value in raw_targets]
            if len(targets) != len(raw_targets) or any(not row for row in targets):
                raise ValueError("public target omitted during normalization")
            # The runner must see the exact reviewed target IDs/types/hosts/ports.
            for original, normalized in zip(raw_targets, targets):
                if any(normalized.get(key) != original.get(key) for key in
                       ("id", "type", "host", "port", "expectedIp")):
                    raise ValueError("public target normalization drifted")
            settings = settings_repo.get(parent.target_id)
            if (settings is None or settings.engagement_id != parent.target_id
                    or settings.enabled is not True or settings.mode not in {"once", "continuous"}):
                raise ValueError("retained Inspector settings missing")
            host = _inspector_host_from_settings(settings.current_host, settings=settings)
            if (host is None or not _usable_inspector_host(host)
                    or host.public_ip in _retired_target_public_ips(targets)):
                raise ValueError("Inspector host unavailable or collides with target")
            owned = [row for row in resources.list_for_engagement(parent.target_id)
                     if _is_inspector_resource_record(row)
                     and str(row.status).lower() not in TERMINAL_RECORD_STATUSES]
            if len(owned) != 1:
                raise ValueError("exact retained Inspector resource record missing")
            record = owned[0]
            metadata = record.metadata if type(record.metadata) is dict else {}
            frozen_ids = snapshot["inspector"]["ownedProviderRecordIds"]
            newly_created = frozen_ids == []
            if newly_created:
                publication = recognize_historical_keyed_inspector_readiness(
                    coordinator.id, parent.target_id, environment=environment,
                    state_root=state_root,
                    job_repository=jobs, plan_repository=plans,
                    settings_repository=settings_repo,
                    provider_resource_repository=resources,
                    sketch_repository=sketch_repository,
                    credential_repository=credential_repository, lease_lookup=lookup,
                )
                if (publication.status != "inspector_ready_historical"
                        or publication.coordinator_job_id != coordinator.id
                        or publication.host_record_id != record.id):
                    raise ValueError("post-snapshot Inspector publication differs")
            if (record.engagement_id != parent.target_id
                    or record.id != f"{host.provider}:inspector:{host.resource_id}"
                    or record.source != INSPECTOR_RESOURCE_SOURCE
                    or record.provider != host.provider or record.resource_id != host.resource_id
                    or record.region != host.region or record.name != host.name
                    or record.resource_type != f"inspector_{host.resource_type}"
                    or record.status.lower() not in {"active", "running"}
                    or record.lifecycle_state.lower() not in {"active", "running"}
                    or host.provider != settings.provider or host.region != settings.region
                    or metadata.get("barraganOwned") is not True
                    or metadata.get("role") != "inspector"
                    or metadata.get("publicIp") != host.public_ip
                    or type(metadata.get("publicIps")) is not list
                    or host.public_ip not in metadata["publicIps"]
                    or (not newly_created and record.id not in frozen_ids)
                    or (not newly_created and snapshot["inspector"]["recordOwners"].get(record.id)
                        != record.adoption_job_id)):
                raise ValueError("retained Inspector identity differs")
            return parent, core, snapshot, coordinator, plan, absent, settings, record, host, targets

        baseline = authority()
        parent, core, snapshot, coordinator, plan, absent, settings, record, host, targets = baseline
        scope_digest = _sha(snapshot)

        def fence():
            fresh = authority()
            if fresh != baseline or _sha(fresh[2]) != scope_digest:
                raise ValueError("Inspector negative authority changed")

        def fresh_do_absence() -> DigitalOceanAbsenceEvidence:
            options = dict(
                job_repository=jobs, plan_repository=plans,
                sketch_repository=sketch_repository,
                credential_repository=credential_repository, lease_lookup=lookup,
            )
            if "publishedSource" in parent.input:
                options["retired_published"] = True
            proof = do_absence_reader(
                parent.id, environment=environment, state_root=state_root,
                **options,
            )
            if (type(proof) is not DigitalOceanAbsenceEvidence
                    or not _hash(proof.empty_state_sha256)
                    or not proof.verified_absent_droplet_ids
                    or not proof.verified_absent_firewall_id
                    or not proof.verified_absent_ssh_key_id):
                raise ValueError("fresh DigitalOcean exact absence is unverified")
            fence()
            return proof

        def do_identity(proof: DigitalOceanAbsenceEvidence) -> str:
            return _sha({
                "emptyStateSha256": proof.empty_state_sha256,
                "dropletIds": proof.verified_absent_droplet_ids,
                "firewallId": proof.verified_absent_firewall_id,
                "sshKeyId": proof.verified_absent_ssh_key_id,
            })

        do_digest = do_identity(fresh_do_absence())

        input_data = {
            "teardownParentId": parent.id, "coreJobId": core.id,
            "corePlanId": plan.id, "scopeSnapshotId": snapshot["snapshotId"],
            "ociAbsenceJobId": absent.id, "ociAbsenceJournalSha256": job_event_digest(absent.events),
            "targetSha256": _sha(targets), "targetCount": len(targets),
            "positiveControl": positive_control, "positiveControlSha256": _sha(positive_control),
            "freshDigitalOceanAbsenceSha256": do_digest,
            "inspectorRecordId": record.id, "inspectorProvider": host.provider,
            "inspectorResourceId": host.resource_id, "inspectorPublicIp": host.public_ip,
            "inspectorSettingsUpdatedAt": settings.updated_at,
        }
        from app.services.provider_keyed_published_initial_cleanup_authority import MARKER, seal_marker
        marker = seal_marker(snapshot)
        if marker is not None:
            input_data[MARKER] = marker
        child_id = f"job-provider-keyed-inspector-negative-{core.id.removeprefix('job-')}"
        prior = jobs.get(child_id)
        if prior is not None and prior.status == "succeeded":
            if (prior.action != ACTION or prior.input != input_data
                    or prior.target_id != parent.target_id
                    or prior.requested_by != parent.requested_by
                    or prior.status != "succeeded" or prior.finished_at is None
                    or len(prior.events) != 3
                    or [event.message for event in prior.events] != [
                        "inspector negative queued", "inspector negative started",
                        "inspector exact public negative proved"]
                    or prior.events[-1].data.get("targetSha256") != input_data["targetSha256"]
                    or prior.events[-1].data.get("inspectorRecordId") != record.id
                    or type(prior.events[-1].data.get("rounds")) is not list
                    or len(prior.events[-1].data["rounds"]) != 2
                    or prior.events[-1].data.get("classifications") != [
                        _classified_results(round_result, targets, positive_control)
                        for round_result in prior.events[-1].data["rounds"]]
                    or any(item is None for item in prior.events[-1].data["classifications"])
                    ):
                raise ValueError("Inspector negative receipt differs")
            fence()
            return prior
        if prior is not None:
            if (prior.status != "queued" or prior.action != ACTION
                    or prior.input != input_data or prior.target_id != parent.target_id
                    or prior.requested_by != parent.requested_by
                    or prior.started_at is not None or prior.finished_at is not None
                    or prior.artifact_refs != []
                    or prior.events != [JobEvent(1, "info", "inspector negative queued", {})]):
                raise ValueError("started Inspector probe cannot be replayed")
            child = prior
        else:
            child = StoredJobRun(child_id, ACTION, "queued", f"engagement:{parent.target_id}",
                                 "engagement", parent.target_id, parent.requested_by,
                                 input_data, [], _now(), None, None,
                                 [JobEvent(1, "info", "inspector negative queued", {})])
            saved = jobs.save_if_absent(child)
            if (saved is None or saved.id != child.id or saved.action != child.action
                    or saved.status != "queued" or saved.input != child.input
                    or saved.events != child.events or saved.target_id != child.target_id
                    or saved.requested_by != child.requested_by):
                raise ValueError("Inspector negative reservation changed")
            child = saved
        child = jobs.start_if_queued(child, started_at=_now(),
                                     event=JobEvent(2, "info", "inspector negative started", {}))
        if child is None:
            raise ValueError("Inspector negative start changed")
        fence()
        ssh_key = ssh_key_factory(child.id)
        rounds = []
        classifications = []
        for _ in range(2):
            fence()
            result = (runner or SshObserverRunner()).run(
                host=host, ssh_key=ssh_key,
                spec={"positive": [positive_control], "negative": targets,
                      "timeoutSeconds": 8, "strictNegativeTcp": True})
            classified = _classified_results(result, targets, positive_control)
            if classified is None:
                raise ValueError("Inspector probe omitted, failed, or authority changed")
            fence()
            rounds.append(result)
            classifications.append(classified)
        if do_identity(fresh_do_absence()) != do_digest:
            raise ValueError("DigitalOcean exact absence changed during Inspector proof")
        finished = jobs.finish_if_running(child, status="succeeded", finished_at=_now(),
            event=JobEvent(3, "info", "inspector exact public negative proved", {
                "targetSha256": input_data["targetSha256"],
                "inspectorRecordId": record.id, "rounds": rounds,
                "classifications": classifications,
            }))
        if finished is None:
            raise ValueError("Inspector negative receipt write changed")
        return finished
    except Exception:
        if child is not None and child.status == "running":
            try:
                jobs.finish_if_running(child, status="failed", finished_at=_now(),
                    event=JobEvent(len(child.events) + 1, "error",
                                   "inspector negative unverified", {}))
            except Exception:
                pass
        raise KeyedInspectorNegativeAttention(
            "Inspector public-negative proof is unverified; reconcile retained child"
        ) from None


def recognize_historical_pending_keyed_inspector_negative(
    teardown_parent_id: str, *, environment: str,
    job_repository=None, plan_repository=None, settings_repository=None,
    provider_resource_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Recognize the sealed negative receipt after its Inspector was retired.

    The live proof cannot run after retirement: its authority deliberately
    requires an active Inspector. This checks the immutable historical journal
    against the frozen target scope and the canonical Linode retirement receipt.
    It makes no provider or Inspector request.
    """
    if environment != "devtest":
        raise KeyedInspectorNegativeAttention("DevTest historical proof only")
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        # Lazy import avoids the cleanup module's dependency on the live proof.
        from app.services.provider_keyed_inspector_linode_cleanup import (
            recognize_pending_linode_inspector_retired,
        )

        retired = recognize_pending_linode_inspector_retired(
            teardown_parent_id, environment=environment,
            job_repository=jobs, plan_repository=plans,
            settings_repository=settings_repository,
            provider_resource_repository=resources, lease_lookup=lookup,
        )
        parent, core, snapshot, operation = _boundary(
            teardown_parent_id, jobs, plans, lookup)
        if operation != _FENCE or "publishedSource" in parent.input:
            raise ValueError("historical negative generation differs")
        raw_targets = snapshot.get("publicVerificationTargets")
        if (type(raw_targets) is not list or not raw_targets
                or not _valid_public_targets(raw_targets)
                or snapshot.get("inspector", {}).get("verificationTargetCount") != len(raw_targets)):
            raise ValueError("frozen targets differ")
        _require_diagnostic_targets(core, snapshot)
        targets = [_teardown_target(row) for row in raw_targets]
        if (any(not row for row in targets)
                or any(any(normalized.get(key) != original.get(key) for key in
                           ("id", "type", "host", "port", "expectedIp"))
                       for original, normalized in zip(raw_targets, targets))):
            raise ValueError("frozen target normalization differs")
        identifier = f"job-provider-keyed-inspector-negative-{core.id.removeprefix('job-')}"
        child = jobs.get(identifier)
        if (child is None or child.id != retired.input.get("negativeJobId")
                or len([row for row in jobs.list_for_engagement(parent.target_id)
                        if row.action == ACTION and row.input.get("coreJobId") == core.id]) != 1
                or child.action != ACTION or child.status != "succeeded"
                or child.target != parent.target or child.target_type != parent.target_type
                or child.target_id != parent.target_id or child.requested_by != parent.requested_by
                or child.artifact_refs != [] or child.started_at is None
                or child.finished_at is None
                or job_event_digest(child.events) != retired.input.get("negativeJournalSha256")):
            raise ValueError("sealed negative job differs")
        if _sha(child.input) != retired.input.get("negativeInputSha256"):
            raise ValueError("sealed negative input digest differs")
        control = child.input.get("positiveControl")
        if (type(control) is not dict
                or set(control) != {"id", "type", "host", "port"}
                or control.get("id") != "inspector-external-control"
                or control.get("type") != "tcp" or control.get("port") != 443
                or type(control.get("host")) is not str):
            raise ValueError("positive control differs")
        control_ip = ipaddress.ip_address(control["host"])
        if (control_ip.version != 4 or not control_ip.is_global
                or str(control_ip) != control["host"]
                or any(row["id"] == control["id"] or row["host"] == control["host"]
                       for row in raw_targets)):
            raise ValueError("positive control overlaps retired targets")
        expected_keys = {
            "teardownParentId", "coreJobId", "corePlanId", "scopeSnapshotId",
            "ociAbsenceJobId", "ociAbsenceJournalSha256", "targetSha256",
            "targetCount", "positiveControl", "positiveControlSha256",
            "freshDigitalOceanAbsenceSha256", "inspectorRecordId",
            "inspectorProvider", "inspectorResourceId", "inspectorPublicIp",
            "inspectorSettingsUpdatedAt",
        }
        data = child.input
        if (set(data) != expected_keys or data["teardownParentId"] != parent.id
                or data["coreJobId"] != core.id
                or data["corePlanId"] != core.input.get("corePlanId")
                or data["scopeSnapshotId"] != snapshot["snapshotId"]
                or data["targetSha256"] != _sha(targets)
                or data["targetCount"] != len(targets)
                or data["positiveControlSha256"] != _sha(control)
                or not _hash(data["freshDigitalOceanAbsenceSha256"])
                or data["inspectorRecordId"] != retired.input.get("hostRecordId")
                or data["inspectorProvider"] != "linode"
                or data["inspectorResourceId"] != retired.input.get("hostId")
                or type(data["inspectorPublicIp"]) is not str
                or not ipaddress.ip_address(data["inspectorPublicIp"]).is_global
                or type(data["inspectorSettingsUpdatedAt"]) is not str
                or not data["inspectorSettingsUpdatedAt"]):
            raise ValueError("sealed negative input differs")
        datetime.fromisoformat(data["inspectorSettingsUpdatedAt"].replace("Z", "+00:00"))
        host_record = resources.get(data["inspectorRecordId"])
        metadata = host_record.metadata if host_record is not None else None
        if (host_record is None or host_record.engagement_id != parent.target_id
                or host_record.provider != "linode"
                or host_record.resource_id != data["inspectorResourceId"]
                or host_record.status != "destroyed"
                or type(metadata) is not dict
                or metadata.get("barraganOwned") is not True
                or metadata.get("role") != "inspector"
                or metadata.get("publicIp") != data["inspectorPublicIp"]):
            raise ValueError("retired Inspector identity differs")
        absence = jobs.get(data["ociAbsenceJobId"])
        if (absence is None or absence.action != ABSENCE_ACTION
                or absence.status != "succeeded" or absence.target_id != parent.target_id
                or absence.input.get("teardownParentId") != parent.id
                or absence.input.get("coreJobId") != core.id
                or absence.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                or job_event_digest(absence.events) != data["ociAbsenceJournalSha256"]):
            raise ValueError("original OCI absence journal differs")
        if (len(child.events) != 3
                or [event.sequence for event in child.events] != [1, 2, 3]
                or [event.level for event in child.events] != ["info"] * 3
                or [event.message for event in child.events] != [
                    "inspector negative queued", "inspector negative started",
                    "inspector exact public negative proved"]
                or child.events[0].data != {} or child.events[1].data != {}):
            raise ValueError("negative journal sequence differs")
        receipt = child.events[2].data
        if (type(receipt) is not dict
                or set(receipt) != {"targetSha256", "inspectorRecordId", "rounds", "classifications"}
                or receipt["targetSha256"] != data["targetSha256"]
                or receipt["inspectorRecordId"] != data["inspectorRecordId"]
                or type(receipt["rounds"]) is not list or len(receipt["rounds"]) != 2):
            raise ValueError("negative receipt differs")
        classifications = [_classified_results(row, targets, control) for row in receipt["rounds"]]
        if any(row is None for row in classifications) or receipt["classifications"] != classifications:
            raise ValueError("negative classifications differ")
        if jobs.get(child.id) != child or jobs.get(retired.id) != retired:
            raise ValueError("historical receipt changed")
        return child
    except Exception:
        raise KeyedInspectorNegativeAttention(
            "historical Inspector public-negative proof is unverified"
        ) from None
