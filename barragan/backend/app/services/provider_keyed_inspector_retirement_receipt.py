# Copyright (c) 2026, Oracle and/or its affiliates.
"""Cheap read-only cleanup-flag projection from exact stored retirement receipts.

This is reporting evidence only; it grants no mutation or replay authority.
"""
from collections.abc import Mapping
from dataclasses import asdict

from app.storage.job_repository import job_event_digest
from app.services.engagement_teardown import _fingerprint as digest


def inspector_cleanup_resolved(record, jobs) -> bool:
    """Accept an existing engagement job map/list; never query providers or topology."""
    try:
        from app.services.provider_keyed_mixed_zero_apply_inspector_retirement import (
            ACTION, PUBLISHED_ACTION, _child_id, _published_child_id, _messages,
        )
        if (record.resource_type not in {"inspector_instance", "inspector_firewall"}
                or record.provider != "linode" or record.status != "destroyed"
                or record.lifecycle_state != "destroyed" or record.destroyed_at is None
                or record.metadata.get("barraganOwned") is not True):
            return False
        rows = dict(jobs) if isinstance(jobs, Mapping) else {job.id: job for job in jobs}
        candidates = [job for job in rows.values() if job.action in {ACTION, PUBLISHED_ACTION}
            and job.target_id == record.engagement_id
            and record.id in {job.input.get("hostRecordId"), job.input.get("firewallRecordId")}]
        if len(candidates) != 1:
            return False
        child = candidates[0]
        if (child.status != "succeeded" or child.started_at is None or child.finished_at is None
                or child.artifact_refs or child.id != (
                    _published_child_id(child.input["coreJobId"]) if child.action == PUBLISHED_ACTION
                    else _child_id(child.input["coreJobId"]))
                or _messages(child, child.input["hostId"], child.input["firewallId"])[-1]
                    != "mixed Inspector local retirement committed"):
            return False
        version = child.input.get("cleanupMetadataVersion")
        if version is not None and (type(version) is not int or version != 1):
            return False
        for prefix in ("host", "firewall"):
            original = child.input[prefix + "Record"]
            if (digest(original) != child.input[prefix + "RecordSha256"]
                    or original["id"] != child.input[prefix + "RecordId"]
                    or original["resource_id"] != child.input[prefix + "Id"]
                    or original["engagement_id"] != record.engagement_id
                    or original["metadata"].get("barraganOwned") is not True):
                return False
        original = child.input["hostRecord" if record.resource_type == "inspector_instance" else "firewallRecord"]
        actual = asdict(record)
        expected_metadata = dict(original["metadata"])
        if version == 1:
            expected_metadata["cleanupRequired"] = False
        if actual["metadata"] != expected_metadata or any(actual[key] != value for key, value in original.items()
                if key not in {"status", "lifecycle_state", "metadata", "destroyed_at", "updated_at"}):
            return False
        parent = rows.get(child.input["teardownParentId"])
        negative = rows.get(child.input["negativeJobId"])
        from app.services.provider_keyed_mixed_zero_apply_cleanup import ACTION as ZERO_ACTION, _parent_id as zero_id
        from app.services.provider_keyed_mixed_interrupted_cleanup import ACTION as INTERRUPTED_ACTION, _parent_id as interrupted_id
        from app.services.provider_keyed_mixed_published_teardown_checkpoint import ACTION as PARENT_ACTION, parent_id
        from app.services.provider_keyed_mixed_zero_apply_inspector_negative import ACTION as NEGATIVE_ACTION, _attempt_id
        from app.services.provider_keyed_mixed_zero_apply_core_absence import ACTION as ABSENCE_ACTION, _child_prefix
        from app.services.provider_keyed_core_destroy_absence import _MAX_ATTEMPTS
        core_id = child.input["coreJobId"]
        identities = {PARENT_ACTION: parent_id(core_id)} if child.action == PUBLISHED_ACTION else {
            ZERO_ACTION: zero_id(core_id), INTERRUPTED_ACTION: interrupted_id(core_id)}
        if (parent is None or parent.action not in identities or parent.id != identities[parent.action]
                or parent.target_type != "engagement" or parent.target != f"engagement:{record.engagement_id}"
                or negative is None or negative.action != NEGATIVE_ACTION
                or negative.id not in {_attempt_id(core_id, index) for index in range(1, 4)}
                or negative.target_type != "engagement" or negative.target_id != record.engagement_id
                or negative.target != f"engagement:{record.engagement_id}"
                or child.target_type != "engagement" or child.target != parent.target
                or child.requested_by != parent.requested_by or negative.requested_by != parent.requested_by):
            return False
        if (parent is None or parent.status != "succeeded" or parent.finished_at is None
                or parent.target_id != record.engagement_id
                or parent.input.get("coreJobId") != child.input["coreJobId"]
                or parent.input.get("corePlanId") != child.input["corePlanId"]
                or negative is None or negative.status != "succeeded" or negative.finished_at is None
                or negative.input.get("teardownParentId") != parent.id
                or negative.input.get("coreJobId") != child.input["coreJobId"]
                or negative.input.get("corePlanId") != child.input["corePlanId"]
                or digest(negative.input) != child.input["negativeInputSha256"]
                or job_event_digest(negative.events) != child.input["negativeJournalSha256"]):
            return False
        core = rows.get(child.input["coreJobId"])
        from app.services.provider_keyed_mixed_zero_apply_inspector_negative import _targets
        from app.services.provider_keyed_mixed_failed_second_append import extend_retired_targets
        from app.services.provider_keyed_inspector_negative import _classified_results
        details = next(event.data["connectionDetails"] for event in core.events
                       if event.message == "pilot Standard RTI run finished")
        targets = _targets(core, sum(row.get("role") == "proxy" for row in details))
        if parent.input.get("publicTargetSealSha256") is not None:
            return False  # New versioned retirements already store the resolved metadata.
        if child.action == PUBLISHED_ACTION:
            targets = extend_retired_targets(targets, parent)
        receipt = negative.events[-1]
        control = negative.input["positiveControl"]
        classes = [_classified_results(result, targets, control) for result in receipt.data.get("rounds", [])]
        if (negative.input.get("targetCount") != len(targets)
                or negative.input.get("targetSha256") != digest(targets)
                or receipt.message != "mixed Inspector exact public negative proved"
                or receipt.data.get("targetSha256") != digest(targets)
                or len(classes) != 2 or any(row is None for row in classes)
                or receipt.data.get("classifications") != classes):
            return False
        absent = rows.get(negative.input["ociAbsenceJobId"])
        if (absent is None or absent.action != ABSENCE_ACTION
                or absent.id not in {f"{_child_prefix(core_id)}-attempt-{index:02d}" for index in range(1, _MAX_ATTEMPTS + 1)}
                or absent.target_type != "engagement" or absent.target != parent.target
                or absent.requested_by != parent.requested_by
                or absent.status != "succeeded" or absent.finished_at is None
                or absent.target_id != record.engagement_id
                or absent.input.get("teardownParentId") != parent.id
                or absent.input.get("coreJobId") != child.input["coreJobId"]
                or job_event_digest(absent.events) != negative.input["ociAbsenceJournalSha256"]
                or not absent.events or absent.events[-1].message != "mixed core exact absence proved"
                or absent.events[-1].data.get("ociAbsenceWitness", {}).get("phase") != "absent"):
            return False
        final = parent.events[-1]
        return (final.level == "info" and final.message in {
                "published mixed teardown complete", "mixed zero-Apply teardown complete", "mixed interrupted teardown complete"}
            and final.data.get("state") == "destroyed"
            and final.data.get("finalCleanupStatus") == "verified_clean"
            and final.data.get("inspectorRetirementJournalSha256") == job_event_digest(child.events)
            and (final.data.get("ociAbsenceJournalSha256") in {None, job_event_digest(absent.events)}))
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration):
        return False
