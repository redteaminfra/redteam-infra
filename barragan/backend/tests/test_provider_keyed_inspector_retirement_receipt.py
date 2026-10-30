# Copyright (c) 2026, Oracle and/or its affiliates.
"""Legacy cleanup flags require linked exact retirement and absence receipts."""
from dataclasses import asdict, replace
from app.storage.database import db
from test_provider_keyed_mixed_zero_apply_inspector_retirement import (
    case, _sql_ready, _enter_sql, Provider, service,
)

def test_legacy_cleanup_projection_requires_terminal_linked_absence_and_keeps_bytes(case, monkeypatch, tmp_path):
    from app.services.provider_keyed_inspector_retirement_receipt import inspector_cleanup_resolved
    from app.services.provider_keyed_mixed_zero_apply_terminal import _terminal_event
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, _, resources = _enter_sql(case, source, options, state, provider)
        retired = service.retire_mixed_zero_apply_inspector(source.engagement_id, source.core_job_id, **kwargs)
        retired = jobs.save(replace(retired, input={key: value for key, value in retired.input.items()
                                                  if key != "cleanupMetadataVersion"}))
        for record in resources.list_for_engagement(source.engagement_id):
            original = retired.input["hostRecord" if record.resource_type == "inspector_instance" else "firewallRecord"]
            resources.save(replace(record, metadata=original["metadata"]))
        parent = jobs.get(retired.input["teardownParentId"])
        records = resources.list_for_engagement(source.engagement_id)
        all_jobs = {job.id: job for job in jobs.list_for_engagement(source.engagement_id)}
        assert not inspector_cleanup_resolved(records[0], all_jobs)  # destroyed labels are insufficient
        parent = jobs.save(replace(parent, status="succeeded", finished_at=retired.finished_at,
            events=[parent.events[0], _terminal_event(parent, retired)]))
        all_jobs[parent.id] = parent
        before = [asdict(record) for record in records]
        assert all(inspector_cleanup_resolved(record, all_jobs) for record in records)
        negative_id = retired.input["negativeJobId"]
        absent_id = all_jobs[negative_id].input["ociAbsenceJobId"]
        for identifier in (parent.id, negative_id, absent_id):
            for field, value in (("action", "contradictory"), ("target_id", "alien-engagement"),
                                 ("target_type", "provider"), ("target", "engagement:alien")):
                changed = replace(all_jobs[identifier], **{field: value})
                assert not inspector_cleanup_resolved(records[0], {**all_jobs, identifier: changed})
        assert [asdict(record) for record in resources.list_for_engagement(source.engagement_id)] == before
        # Missing/crossed absence and record identities never suppress the stale flag.
        absent_id = all_jobs[retired.input["negativeJobId"]].input["ociAbsenceJobId"]
        assert not inspector_cleanup_resolved(records[0], {key: job for key, job in all_jobs.items() if key != absent_id})
        assert not inspector_cleanup_resolved(replace(records[0], resource_id="999"), all_jobs)
        changed = replace(retired, events=retired.events[:-1])
        assert not inspector_cleanup_resolved(records[0], {**all_jobs, retired.id: changed})
