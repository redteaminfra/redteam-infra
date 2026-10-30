# Copyright (c) 2026, Oracle and/or its affiliates.
"""Existing read consumers project exact retired Inspector flags without writes."""
from dataclasses import asdict, replace
from types import SimpleNamespace

from app.services.provider_resource_reporting import reported_provider_resource
from app.services.engagement_operations import OperationsReadSnapshot, get_operations_overview
from app.storage.database import db
from app.storage.engagement_repository import StoredEngagement
from test_provider_keyed_mixed_zero_apply_inspector_retirement import case, _sql_ready, _enter_sql, Provider, service


def test_operations_projects_authenticated_legacy_metadata_but_retains_canonical_records(case, monkeypatch, tmp_path):
    from app.services.provider_keyed_mixed_zero_apply_terminal import _terminal_event
    from app.services import provider_reconciliation
    case.rows[:] = [replace(record, metadata={**record.metadata, 'cleanupRequired': True,
                    'operatorContext': {'preserve': 'Example fixture'}}) for record in case.rows]
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        kwargs, jobs, _, resources = _enter_sql(case, source, options, state, Provider())
        retired = service.retire_mixed_zero_apply_inspector(source.engagement_id, source.core_job_id, **kwargs)
        retired = jobs.save(replace(retired, input={key: value for key, value in retired.input.items() if key != 'cleanupMetadataVersion'}))
        for record in resources.list_for_engagement(source.engagement_id):
            original = retired.input['hostRecord' if record.resource_type == 'inspector_instance' else 'firewallRecord']
            resources.save(replace(record, metadata=original['metadata']))
        parent = jobs.get(retired.input['teardownParentId'])
        jobs.save(replace(parent, status='succeeded', finished_at=retired.finished_at,
            events=[parent.events[0], _terminal_event(parent, retired)]))
        rows = jobs.list_for_engagement(source.engagement_id)
        records = resources.list_for_engagement(source.engagement_id)
        before = [asdict(record) for record in records]
        for record in records:
            projected = reported_provider_resource(record, rows)
            assert projected['metadata'] == {**record.metadata, 'cleanupRequired': False}
            assert record.metadata['cleanupRequired'] is True
            # Missing receipts or an alien ID preserve every metadata field.
            assert reported_provider_resource(record, [])['metadata'] == record.metadata
            assert reported_provider_resource(replace(record, resource_id='alien'), rows)['metadata'] == record.metadata
        seen = []
        monkeypatch.setattr(provider_reconciliation, 'discover_provider_resources', lambda: [])
        monkeypatch.setattr(provider_reconciliation, 'orphan_candidates_for_engagement', lambda *args, **kwargs:
            seen.extend(kwargs['local_provider_resources']) or [])
        engagement = StoredEngagement(source.engagement_id, 'opaque', 'active', 'operator', 'small-dev-infra', 'rev', {})
        snapshot = OperationsReadSnapshot(jobs={engagement.id: rows}, services={engagement.id: []},
            sketch_chains={engagement.id: []}, provider_records={engagement.id: records}, all_provider_records=records,
            lifecycles={}, total_job_count=len(rows), seed_job_exists=False)
        get_operations_overview(engagement.id, SimpleNamespace(get=lambda _: engagement), jobs,
                                read_snapshot=snapshot)
        assert len(seen) == 2 and all(row['metadata']['cleanupRequired'] is False for row in seen)
        assert [asdict(record) for record in resources.list_for_engagement(source.engagement_id)] == before
