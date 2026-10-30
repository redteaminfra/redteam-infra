# Copyright (c) 2026, Oracle and/or its affiliates.
"""Actual bounded SQL inventory feeds exact cleanup Operations projections."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.services.engagement_operations import get_operations_overview, OperationsReadSnapshot
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import SqliteJobRepository
from test_engagement_operations import _core_deployment_job


def _case(tmp_path):
    repo = SqliteJobRepository(tmp_path / 'progress.sqlite')
    core = replace(_core_deployment_job(), input={**_core_deployment_job().input, 'corePlanId': 'plan-current'},
                   events=[JobEvent(1, 'info', 'core deployed', {'finalCleanupStatus': 'pending_operator_teardown'})])
    from teardown_progress_fixtures import initial_checkpoint
    parent = initial_checkpoint(core)
    parent = replace(parent, input={**parent.input, 'phase': 'plans_sealed'})
    now = datetime.now(timezone.utc)
    marker = replace(parent, id='job-provider-keyed-mixed-published-dispatch-provider-keyed-mixed-published-cleanup-core',
        action='provider_keyed_mixed_published_dispatch_claim', status='running',
        input={'engagementId': 'eng-test', 'parentId': parent.id, 'coreJobId': core.id,
               'corePlanId': 'plan-current', 'publishedSourceSha256': parent.input['publishedSourceSha256'], 'mutation': False,
               'claimOwner': 'mixed-published-dispatch-' + 'a' * 32, 'claimToken': 'b' * 32,
               'claimClaimedAt': (now - timedelta(seconds=10)).isoformat(),
               'claimHeartbeatAt': now.isoformat(), 'claimExpiresAt': (now + timedelta(minutes=2)).isoformat()},
        events=[JobEvent(1, 'info', 'published mixed dispatch queued', {}), JobEvent(2, 'info', 'dispatch started', {})])
    child = replace(parent, id='job-provider-keyed-mixed-published-destroy-core-linode',
        action='provider_keyed_mixed_published_destroy_apply', status='running',
        input={'engagementId': 'eng-test', 'cleanupParentId': parent.id, 'coreJobId': core.id},
        events=[JobEvent(1, 'info', 'provider command started', {})])
    for row in (core, parent, marker, child): repo.save(row)
    return repo, core, parent, marker, child


def _overview(repo):
    engagement = StoredEngagement('eng-test', 'opaque', 'active', 'operator', 'small-dev-infra', 'rev', {})
    rows = repo.list_semantic_for_engagement('eng-test', recent_limit=250)
    snapshot = OperationsReadSnapshot(jobs={'eng-test': rows}, services={'eng-test': []},
        sketch_chains={'eng-test': []}, provider_records={'eng-test': []}, all_provider_records=[],
        lifecycles={}, total_job_count=len(rows), seed_job_exists=False)
    return get_operations_overview('eng-test', type('Engagements', (), {'get': lambda self, key: engagement})(),
        repo, include_provider_findings=False, read_snapshot=snapshot)


@pytest.mark.parametrize('status', ['queued', 'running'])
def test_real_operations_keeps_exact_published_parent_and_owned_worker_beyond_timeline(tmp_path, status):
    repo, core, parent, marker, child = _case(tmp_path)
    repo.save(replace(parent, status=status))
    for index in range(260):
        repo.save(replace(core, id=f'noise-{index}', action='unrelated', created_at='2026-12-01T00:00:00Z', events=[]))
    result = _overview(repo)
    assert result['teardownSelection'] == {'state': 'exact'}
    projected = result['teardownJob']
    assert projected['id'] == parent.id and projected['status'] == status
    assert projected['recoveryState'] == 'in_progress'
    assert projected['phase'] == 'linode_absence'
    assert projected['activeChild']['id'] == child.id
    assert projected['dispatch']['claimState'] == 'live'
    assert projected['dispatch']['heartbeatAt'] == marker.input['claimHeartbeatAt']
    assert 'claimOwner' not in str(projected) and 'claimToken' not in str(projected)


@pytest.mark.parametrize('drift', ['ambiguous', 'generation', 'parent-id', 'source', 'child-id', 'unknown-claim', 'unknown-source', 'unknown-phase'])
def test_actual_operations_rejects_ambiguous_or_forged_progress(tmp_path, drift):
    repo, core, parent, marker, child = _case(tmp_path)
    if drift == 'ambiguous':
        repo.save(replace(parent, id='job-another', action='engagement_comprehensive_teardown'))
    elif drift == 'generation':
        repo.save(replace(parent, input={**parent.input, 'coreJobId': 'job-old'}))
    elif drift == 'parent-id':
        repo.save(replace(parent, input={**parent.input, 'schema': 'unknown'}))
    elif drift == 'unknown-source':
        repo.save(replace(parent, input={**parent.input, 'sourceKind': 'unknown-v1'}))
    elif drift == 'unknown-phase':
        repo.save(replace(parent, input={**parent.input, 'phase': 'unknown'}))
    elif drift == 'source':
        repo.save(replace(parent, input={**parent.input, 'publishedSource': {**parent.input['publishedSource'], 'core_plan_id': 'other'}}))
    elif drift == 'child-id':
        repo.save(replace(child, status='succeeded'))
        repo.save(replace(child, id='job-forged'))
    else:
        repo.save(replace(marker, input={**marker.input, 'claimToken': 'unknown'}))
    result = _overview(repo)
    if drift == 'unknown-phase':
        assert result['teardownJob']['phase'] == 'attention'
        assert result['teardownJob']['recoveryState'] == 'blocked'
    elif drift in {'child-id', 'unknown-claim'}:
        assert result['teardownSelection']['state'] == 'exact'
        if drift == 'child-id': assert result['teardownJob']['activeChild'] is None
        else: assert result['teardownJob']['dispatch']['claimState'] == 'unknown'
    else:
        assert result['teardownJob'] is None
        assert result['teardownSelection']['state'] == ('ambiguous' if drift == 'ambiguous' else 'unavailable')


def test_real_operations_terminal_cleanup_is_historical(tmp_path):
    repo, _, parent, _, _ = _case(tmp_path)
    repo.save(replace(parent, status='succeeded', finished_at='2026-10-26T23:00:00Z', events=[
        *parent.events, JobEvent(2, 'info', 'published mixed teardown complete', {'finalCleanupStatus': 'verified_clean'})]))
    result = _overview(repo)
    assert result['teardownJob']['phase'] == 'complete'
    assert result['teardownJob']['recoveryState'] == 'complete'


@pytest.mark.parametrize('status', ['queued', 'running'])
def test_real_job_show_projects_owned_child_and_heartbeat(client, tmp_path, status):
    from app.storage.job_repository import SqlAlchemyJobRepository
    source, core, parent, marker, child = _case(tmp_path)
    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        for row in (core, replace(parent, status=status), marker, child): repo.save(row)
    response = client.get('/api/orchestrator/barragan-testing/pilot-standard-rti/runs/' + parent.id)
    assert response.status_code == 200
    detail = response.json()['job']
    assert detail['id'] == parent.id and detail['status'] == status
    assert detail['phase'] == 'linode_absence'
    assert detail['activeChild']['id'] == child.id
    assert detail['dispatch']['claimState'] == 'live'
    assert detail['dispatch']['startedAt'] == marker.started_at
    assert detail['dispatch']['finishedAt'] is None
    assert 'claimToken' not in detail['dispatch'] and 'claimOwner' not in detail['dispatch']


def test_job_show_projects_terminal_dispatch_timestamps_without_a_live_claim(client, tmp_path):
    from app.storage.job_repository import SqlAlchemyJobRepository
    _, core, parent, marker, child = _case(tmp_path)
    finish = '2026-10-26T23:00:00+00:00'
    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        repo.save(core)
        repo.save(replace(parent, status='succeeded', finished_at=finish, events=[
            *parent.events, JobEvent(2, 'info', 'published mixed teardown complete', {'finalCleanupStatus': 'verified_clean'})]))
        repo.save(replace(marker, status='succeeded', finished_at=finish,
            input={key: value for key, value in marker.input.items() if not key.startswith('claim')}))
        repo.save(replace(child, status='succeeded', finished_at=finish))
    detail = client.get('/api/orchestrator/barragan-testing/pilot-standard-rti/runs/' + parent.id).json()['job']
    assert detail['phase'] == 'complete'
    assert detail['dispatch']['startedAt'] == marker.started_at
    assert detail['dispatch']['finishedAt'] == finish
    assert detail['dispatch']['heartbeatAt'] is None
    assert detail['dispatch']['claimState'] == 'unknown'
    assert detail['activeChild'] is None
