# Copyright (c) 2026, Oracle and/or its affiliates.
"""Operations recognizes sealed initial completion without rewriting journals."""
from copy import deepcopy
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.engagement_operations import OperationsReadSnapshot, get_operations_overview
from app.services.engagement_teardown import _fingerprint, comprehensive_teardown_recovery_state
from app.services import provider_keyed_published_initial_cleanup_authority as authority
from app.storage.engagement_repository import StoredEngagement
from test_provider_keyed_published_initial_cleanup_authority import ready


@pytest.fixture
def completed(ready):
    # Real generated failed-HTTP workspace and seal, with a complete saved scope.
    scope = ready.snapshot
    provider = scope['providerScopes'][0]
    provider.update(schema='provider-keyed-v2', revisionId='revision',
                    providerConnectionId='connection', workspace='/private/provider',
                    sourceRevision='a' * 40, selectorTag='opaque', stateSha256='b' * 64,
                    chainFingerprints={chain.chain_id: 'c' * 64 for chain in ready.chains})
    provider['resources'] = sorted([
        {'address': node['terraformAddress'], 'id': str(node['providerInstanceId']), 'kind': 'droplet'}
        for chain in ready.chains for node in chain.nodes
    ] + [{'address': address, 'id': 'owned', 'kind': kind} for address, kind in (
        ('digitalocean_ssh_key.key', 'ssh_key'), ('digitalocean_firewall.firewall', 'firewall'),
        ('local_file.ansible_inventory[0]', 'local_file'), ('local_file.ssh_stanza[0]', 'local_file'))],
        key=lambda row: row['address'])
    scope.update(engagementName='example', confirmationPhrase='Destroy example',
                 ownedProviderRecordIds=[], excludedUnmanagedProviderRecords=[],
                 core={'jobId': ready.core.id, 'workspace': '/private/core', 'proxyCount': 2},
                 chains=[{'chainId': chain.chain_id, 'assignedProxy': chain.assigned_proxy,
                          'status': 'deployed', 'deployJobId': ready.initial.id,
                          'alreadyClean': False, 'outboundChannelIds': [],
                          'middle': {'provider': 'digitalocean', 'region': chain.nodes[0]['region']},
                          'edges': [{'id': node['componentId'], 'provider': 'digitalocean',
                                     'region': node['region']} for node in chain.nodes if node['role'] == 'edge']}
                         for chain in ready.chains])
    scope['providerScopeSha256'] = _fingerprint({'providerScopes': scope['providerScopes']})
    manifest = {'schema': 'provider-keyed-dns-cleanup-manifest-v1',
                'engagementId': ready.core.target_id, 'coreJobId': ready.core.id,
                'providerScopeSha256': scope['providerScopeSha256'], 'bindingSha256': 'd' * 64,
                'initialJobId': ready.initial.id, 'initialJournalSha256': 'e' * 64,
                'domainAssignments': [], 'domains': []}
    manifest['manifestSha256'] = 'sha256:' + _fingerprint(manifest)
    scope['dnsCleanupManifest'] = manifest
    parent = ready.parent(ready.build())
    scope = deepcopy(parent.input['scopeSnapshot'])
    scope['inspector'].update(tracked=False, ownedProviderRecordIds=[], recordOwners={})
    scope.pop('snapshotId')
    scope['snapshotId'] = _fingerprint(scope)
    parent = replace(parent, status='succeeded', finished_at='2026-10-20T05:00:00+00:00',
        input={**parent.input, 'engagementId': ready.core.target_id, 'scopeSnapshot': scope,
               'publishedSource': {'core_job_id': ready.core.id, 'core_plan_id': 'plan'},
               'remainingOwnedResources': []}, events=[
            JobEvent(1, 'info', 'engagement teardown queued', authority.queued_cleanup_event_data(scope)),
            JobEvent(2, 'info', 'engagement lifecycle reconciled',
                     {'state': 'destroyed', 'finalCleanupStatus': 'verified_clean'})])
    ready.saved[parent.id] = parent
    assert comprehensive_teardown_recovery_state(parent) == 'complete'
    assert authority.validate_saved_cleanup(parent, ready.core, scope, ready.jobs) is not None
    return ready, parent


def overview(ready, *, bounded=False):
    engagement_id = ready.core.target_id
    jobs = sorted(ready.saved.values(), key=lambda row: row.created_at, reverse=True)
    # Initial provenance may have fallen out of the bounded Operations timeline.
    visible = [row for row in jobs if not bounded or row.id != ready.initial.id]
    repo = SimpleNamespace(get=ready.saved.get, list_for_engagement=lambda _: jobs,
                           list_semantic_for_engagement=lambda _, recent_limit: visible)
    engagement = StoredEngagement(engagement_id, 'example', 'active', 'operator',
                                  'small-dev-infra', 'revision', {})
    snapshot = OperationsReadSnapshot(jobs={engagement_id: visible}, services={engagement_id: []},
        sketch_chains={engagement_id: []}, provider_records={engagement_id: []},
        all_provider_records=[], lifecycles={}, total_job_count=len(jobs), seed_job_exists=False)
    return get_operations_overview(engagement_id, SimpleNamespace(get=lambda _: engagement), repo,
                                  include_provider_findings=False, read_snapshot=snapshot)


@pytest.mark.parametrize('bounded', [False, True])
def test_sealed_completion_retires_only_displayed_core_and_preserves_history(completed, bounded):
    ready, parent = completed
    before = deepcopy({key: asdict(row) for key, row in ready.saved.items()})
    result = overview(ready, bounded=bounded)
    assert result['lifecycle']['state'] == 'destroyed'
    assert result['teardownSelection'] == {'state': 'exact'}
    assert result['teardownJob']['recoveryState'] == 'complete'
    hosts = result['coreInfrastructure']
    assert len(hosts) == 3
    assert all(row['status'] == row['lifecycleState'] == 'destroyed' and row['lastKnown'] for row in hosts)
    assert all(row['health']['source'] == 'cleanup verification' for row in hosts)
    assert [row['publicIp'] for row in hosts] == ['12.0.0.1', '12.0.0.2', '12.0.0.3']
    assert result['healthSummary']['activeHostCount'] == 0
    assert result['healthSummary']['status'] == 'destroyed'
    assert result['coreJob']['status'] == 'succeeded'
    assert {key: asdict(row) for key, row in ready.saved.items()} == before


@pytest.mark.parametrize('drift', [
    'missing-seal', 'malformed-seal', 'unsupported-seal', 'missing-marker', 'changed-marker',
    'missing-source', 'missing-initial', 'changed-initial', 'changed-history', 'changed-core',
    'running', 'unfinished', 'remaining', 'forged-terminal', 'ambiguous', 'legacy',
    'new-queued', 'new-running', 'new-succeeded',
])
def test_unproved_sealed_cleanup_cannot_retire_current_core(completed, drift):
    ready, parent = completed
    parent = deepcopy(parent)
    if drift in {'missing-seal', 'legacy'}:
        parent.input['scopeSnapshot'].pop(authority.KEY)
        if drift == 'legacy':
            parent.input.pop(authority.MARKER)
            parent.input.pop('publishedSource')
    elif drift == 'malformed-seal':
        parent.input['scopeSnapshot'][authority.KEY] = []
    elif drift == 'unsupported-seal':
        parent.input['scopeSnapshot'][authority.KEY]['schema'] = 'unsupported'
    elif drift == 'missing-marker':
        parent.input.pop(authority.MARKER)
    elif drift == 'changed-marker':
        parent.input[authority.MARKER] = {'schema': authority.SCHEMA, 'sha256': 'f' * 64}
    elif drift == 'missing-source':
        parent.input.pop('publishedSource')
    elif drift == 'missing-initial':
        ready.saved.pop(ready.initial.id)
    elif drift in {'changed-initial', 'changed-history', 'changed-core'}:
        row = {'changed-initial': ready.initial, 'changed-history': ready.attempt, 'changed-core': ready.core}[drift]
        ready.saved[row.id] = replace(row, input={**row.input, 'changed': True})
    elif drift == 'running':
        parent = replace(parent, status='running')
    elif drift == 'unfinished':
        parent = replace(parent, finished_at=None)
    elif drift == 'remaining':
        parent.input['remainingOwnedResources'] = ['unproved']
    elif drift == 'forged-terminal':
        parent = replace(parent, events=[*parent.events[:-1], JobEvent(2, 'info',
            'engagement lifecycle reconciled', {'state': 'destroyed'})])
    elif drift == 'ambiguous':
        ready.saved['job-other-cleanup'] = replace(parent, id='job-other-cleanup')
    elif drift.startswith('new-'):
        ready.saved['job-new-core'] = replace(ready.core, id='job-new-core', status=drift[4:],
            created_at='2026-10-20T06:00:00+00:00', input={**ready.core.input, 'corePlanId': 'new-plan'})
    ready.saved[parent.id] = parent
    before = deepcopy({key: asdict(row) for key, row in ready.saved.items()})
    result = overview(ready)
    assert all(row['lifecycleState'] != 'destroyed' and not row['lastKnown']
               for row in result['coreInfrastructure'])
    if not drift.startswith('new-'):
        assert result['healthSummary']['activeHostCount'] == 3
    assert {key: asdict(row) for key, row in ready.saved.items()} == before


@pytest.fixture
def persisted_completion(completed, client):
    """Seal full ORM records, then exercise the production semantic readers."""
    from app.storage.job_repository import SqlAlchemyJobRepository
    ready, parent = completed
    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        for row in ready.saved.values():
            if row.id == ready.core.id:
                row = replace(row, target='oci:example-compartment',
                              target_type='oci_compartment', target_id='example-compartment')
            repo.save(row)
        core = repo.get(ready.core.id)
        # ORM timestamp serialization is part of the immutable source identity.
        scope = deepcopy(parent.input['scopeSnapshot'])
        seal = authority.build_cleanup_seal(core, scope, jobs=repo,
            chains=SimpleNamespace(list_for_engagement=lambda _: ready.chains))
        scope[authority.KEY] = seal
        scope['publicVerificationTargets'] = seal['publicTargets']['targets']
        scope.pop('snapshotId')
        scope['snapshotId'] = _fingerprint(scope)
        parent = repo.save(replace(parent, input={**parent.input, 'scopeSnapshot': scope,
            authority.MARKER: authority.seal_marker(scope)}, events=[
                JobEvent(1, 'info', 'engagement teardown queued', authority.queued_cleanup_event_data(scope)),
                parent.events[-1]]))
        assert authority.validate_saved_cleanup(parent, core, scope, repo) == seal
        engagement = StoredEngagement(core.input['engagementId'], 'example', 'active', 'operator',
                                      'small-dev-infra', 'revision', {})
        engagements = SimpleNamespace(get=lambda _: engagement, list=lambda: [engagement])
        yield repo, core, parent, engagements


def test_real_sql_semantic_operations_and_dashboard_use_full_sealed_evidence(persisted_completion, monkeypatch):
    from app.services import dashboard as dashboard_module
    repo, core, parent, engagements = persisted_completion
    semantic = next(row for row in repo.list_semantic_for_engagement(core.input['engagementId']) if row.id == core.id)
    assert ' ' in semantic.created_at and 'T' in core.created_at
    assert semantic.events == core.events
    with pytest.raises(ValueError):
        authority.validate_saved_cleanup(parent, semantic, parent.input['scopeSnapshot'], repo)
    before = deepcopy([asdict(row) for row in repo.list_for_engagement(core.input['engagementId'])])
    result = get_operations_overview(core.input['engagementId'], engagements, repo, include_provider_findings=False)
    assert result['teardownJob']['recoveryState'] == 'complete'
    assert result['healthSummary']['activeHostCount'] == 0
    assert all(row['lastKnown'] and row['status'] == 'destroyed' for row in result['coreInfrastructure'])
    assert [row['publicIp'] for row in result['coreInfrastructure']] == ['12.0.0.1', '12.0.0.2', '12.0.0.3']
    dashboard_overviews = []
    def capture_overview(*args, **kwargs):
        result = get_operations_overview(*args, **kwargs)
        dashboard_overviews.append(result)
        return result
    monkeypatch.setattr(dashboard_module, 'get_operations_overview', capture_overview)
    dashboard = dashboard_module.get_dashboard_inventory(engagements, repo)
    assert dashboard['summary']['activeInfrastructure'] == 0
    assert dashboard_overviews[0]['healthSummary']['activeHostCount'] == 0
    assert all(row['lastKnown'] and row['status'] == 'destroyed'
               for row in dashboard_overviews[0]['coreInfrastructure'])
    assert [asdict(row) for row in repo.list_for_engagement(core.input['engagementId'])] == before


@pytest.mark.parametrize('record,drift', [
    ('parent', 'missing'), ('core', 'missing'), ('parent', 'status'), ('core', 'status'),
    ('parent', 'input'), ('core', 'input'), ('parent', 'actor'), ('core', 'action'),
    ('parent', 'unfinished'), ('parent', 'terminal'), ('core', 'journal'),
])
def test_full_record_change_after_semantic_selection_fails_closed(persisted_completion, monkeypatch, record, drift):
    from app.services.engagement_operations import _sealed_initial_terminal_projection
    repo, core, parent, _ = persisted_completion
    semantic = {row.id: row for row in repo.list_semantic_for_engagement(core.input['engagementId'])}
    original = repo.get
    selected = parent if record == 'parent' else core
    changed = selected
    if drift == 'missing':
        changed = None
    elif drift == 'status':
        changed = replace(selected, status='running')
    elif drift == 'input':
        changed = replace(selected, input={**selected.input, 'corePlanId': 'other'})
    elif drift == 'actor':
        changed = replace(selected, requested_by='other')
    elif drift == 'action':
        changed = replace(selected, action='other')
    elif drift == 'unfinished':
        changed = replace(selected, finished_at=None)
    elif drift == 'terminal':
        changed = replace(selected, events=selected.events[:-1])
    elif drift == 'journal':
        changed = replace(selected, events=[*selected.events, JobEvent(2, 'info', 'changed', {})])
    monkeypatch.setattr(repo, 'get', lambda key: changed if key == selected.id else original(key))
    assert not _sealed_initial_terminal_projection(semantic[parent.id], semantic[core.id], repo)


@pytest.mark.parametrize('status', ['queued', 'running', 'succeeded'])
def test_real_sql_new_core_generation_supersedes_old_cleanup(persisted_completion, status):
    repo, core, parent, engagements = persisted_completion
    repo.save(replace(core, id='job-new-core', status=status,
        created_at='2026-10-20T06:00:00', input={**core.input, 'corePlanId': 'new-plan'}))
    result = get_operations_overview(core.input['engagementId'], engagements, repo, include_provider_findings=False)
    assert all(not row['lastKnown'] and row['lifecycleState'] != 'destroyed'
               for row in result['coreInfrastructure'])
