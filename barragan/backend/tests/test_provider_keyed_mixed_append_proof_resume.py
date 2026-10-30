# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bounded resume uses real SQL claims and exact persisted provider journals.

Saved source loaders/provider processes are offline witnesses; command journals,
claim handoff, proof-only dispatcher and API/UI boundaries are exercised.
"""
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from app.services import provider_keyed_mixed_append_apply_runtime as runtime
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel, JobRunModel, JobEventModel


@pytest.fixture
def ready(client, tmp_path, monkeypatch):
    from test_provider_keyed_mixed_published_six_integration import persisted_six_case
    from app.services import provider_keyed_mixed_append_first_proof_job as first
    from app.services import provider_keyed_mixed_append_second_apply_binding as second
    from app.services.provider_keyed_mixed_append_pair_apply_binding import _intent
    from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
    from app.services import core_ssh
    case = persisted_six_case(client, tmp_path, monkeypatch)
    with client.application.storage_context():
        jobs = SqlAlchemyJobRepository()
        source = case['source']
        host = jobs.get(runtime.host_child_id(source.parent_id))
        db.session.query(JobEventModel).filter_by(job_id=host.id).delete()
        db.session.query(JobRunModel).filter_by(id=host.id).delete()
        db.session.add(CoreMutationLeaseModel(
            engagement_id=source.engagement_id, owner_id=source.core_plan_id,
            operation='provider_keyed_mixed_append'))
        db.session.commit()
        parent = case['append_parent']
        parent = jobs.save(replace(
            parent, status='running', finished_at=None,
            input={**parent.input, 'phase': 'apply_sealed'}, events=parent.events[:-1]))
        child = jobs.get(runtime.second_child_id(parent.id))
        case['resume_terminal'] = child
        child = jobs.save(replace(
            child, status='running', finished_at=None, events=child.events[:8],
            input={**child.input, 'claimOwner': 'old-proof', 'claimToken': 'old-token',
                   'claimExpiresAt': (runtime._now() - timedelta(minutes=1)).isoformat()}))
        sources = {}
        for index, p in enumerate(source.provider_order):
            root = Path(source.workspace_paths[index])
            read = lambda suffix: root.joinpath(_name(p, suffix)).read_bytes()
            sources[p] = SimpleNamespace(
                intent=_intent(p, parent.input['intents'][p]),
                receipt=json.loads(read('plan-receipt.json')), workspace=root,
                receipt_sha256=parent.input['receiptSha256'][p],
                predecessor_state=read('predecessor.tfstate'),
                reviewed_show_json=read('show.json'))
        monkeypatch.setattr(first, '_load_approved_first_source', lambda *_: sources[source.provider_order[0]])
        monkeypatch.setattr(second, '_approved_second', lambda *_: sources[source.provider_order[1]])
        monkeypatch.setattr('app.services.provider_keyed_initial_destroy_pre_go_recovery._process_quiescent', lambda *_: True)
        monkeypatch.setattr(core_ssh, 'active_core_connection_details', lambda *_: (source.core_job_id, []))
        yield (jobs, parent, child, case)


def test_post_claim_is_unique_and_worker_reauthenticates_same_sql_claim(ready, monkeypatch):
    jobs, parent, child, case = ready
    assert runtime.mixed_append_proof_resume_available(parent, jobs=jobs)
    claim = runtime.claim_mixed_append_proof_resume(parent, jobs=jobs)
    assert not runtime.mixed_append_proof_resume_available(parent, jobs=jobs)
    assert runtime.mixed_append_proof_resume_available(parent, jobs=jobs, claim=claim)
    runtime.require_mixed_append_proof_resume(parent, jobs=jobs, claim=claim)
    with pytest.raises(ValueError):
        runtime.claim_mixed_append_proof_resume(parent, jobs=jobs)
    with pytest.raises(ValueError):
        runtime.require_mixed_append_proof_resume(parent, jobs=jobs, claim=('other', 'other'))
    assert jobs.get(child.id).events == child.events


@pytest.mark.parametrize('drift', [
    'active', 'missing', 'rc_nonzero', 'rc_bool', 'truncated', 'journal', 'first',
    'first_rc_bool', 'host', 'review', 'lease', 'core', 'process'])

def test_resume_fails_closed_before_claim(ready, monkeypatch, drift):
    jobs, parent, child, case = ready
    if drift == 'active':
        jobs.save(replace(child, input={**child.input, 'claimExpiresAt': (runtime._now() + timedelta(minutes=2)).isoformat()}))
    elif drift == 'missing':
        db.session.query(JobEventModel).filter_by(job_id=child.id).delete()
        db.session.query(JobRunModel).filter_by(id=child.id).delete()
        db.session.commit()
    elif drift in {'rc_nonzero', 'rc_bool', 'truncated'}:
        row = child.events[5]
        data = {**row.data, **({'stdoutTruncated': True} if drift == 'truncated' else {'returnCode': False if drift == 'rc_bool' else 1})}
        jobs.save(replace(child, events=[*child.events[:5], replace(row, data=data), *child.events[6:]]))
    elif drift == 'journal':
        jobs.save(replace(child, events=child.events[:-1]))
    elif drift == 'first':
        first = jobs.get(runtime.first_child_id(parent.id))
        jobs.save(replace(first, events=first.events[:-1]))
    elif drift == 'first_rc_bool':
        first = jobs.get(runtime.first_child_id(parent.id))
        row = first.events[5]
        jobs.save(replace(first, events=[*first.events[:5], replace(row, data={**row.data, 'returnCode': False}), *first.events[6:]]))
    elif drift == 'host':
        jobs.save(replace(child, id=runtime.host_child_id(parent.id)))
    elif drift == 'review':
        parent = jobs.save(replace(parent, input={**parent.input, 'reviewSha256': '0' * 64}))
    elif drift == 'lease':
        db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=parent.target_id).update({'operation': 'other'})
        db.session.commit()
    elif drift == 'core':
        monkeypatch.setattr('app.services.core_ssh.active_core_connection_details', lambda *_: ('other', []))
    elif drift == 'process':
        monkeypatch.setattr('app.services.provider_keyed_initial_destroy_pre_go_recovery._process_quiescent', lambda *_: False)
    with pytest.raises(ValueError):
        runtime.claim_mixed_append_proof_resume(parent, jobs=jobs)
    assert jobs.get(child.id) is None or jobs.get(child.id).input.get('claimOwner') == 'old-proof'


@pytest.mark.parametrize('active', [False, True])

def test_startup_does_not_resume_expired_awaiting_proof(ready, active):
    jobs, parent, child, case = ready
    if active:
        jobs.save(replace(child, input={**child.input, 'claimExpiresAt': (runtime._now() + timedelta(minutes=2)).isoformat()}))
    callbacks = []
    assert runtime.recover_approved_mixed_append_applies(environment='devtest', schedule=callbacks.append, job_repository=jobs) == []
    assert callbacks == []


@pytest.mark.parametrize('missing', ['first', 'second'])

def test_proof_only_worker_blocks_fallback_after_admission(monkeypatch, missing):
    from test_provider_keyed_mixed_append_apply_runtime import _case, PARENT_ID
    jobs, trace, options, validate = _case(('digitalocean', 'linode'))
    first = runtime.first_child_id(PARENT_ID)
    second = runtime.second_child_id(PARENT_ID)
    from test_provider_keyed_mixed_append_apply_runtime import _job
    for identifier in (first, second):
        jobs.rows[identifier] = _job(identifier, 'apply', status='succeeded')

    def admit(*_a, **_k):
        jobs.rows.pop(first if missing == 'first' else second)
    monkeypatch.setattr(runtime, 'require_mixed_append_proof_resume', admit)
    options['first_proof_finisher'] = lambda *_a, **_k: jobs.get(first)
    with pytest.raises(runtime.MixedAppendApplyRuntimeAttention):
        runtime.advance_mixed_append_apply(PARENT_ID, **options, proof_resume_only=True, proof_resume_claim=('owner', 'token'))
    assert not any(('binding' in row or 'apply' in row for row in trace))


def test_proof_only_dispatch_continues_existing_host_engine_without_apply(monkeypatch):
    from test_provider_keyed_mixed_append_apply_runtime import _case, _job, PARENT_ID
    jobs, trace, options, validate = _case(('linode', 'digitalocean'))
    first = runtime.first_child_id(PARENT_ID)
    second = runtime.second_child_id(PARENT_ID)
    for identifier in (first, second):
        jobs.rows[identifier] = _job(identifier, 'apply', status='succeeded')
    monkeypatch.setattr(runtime, 'require_mixed_append_proof_resume', lambda *_a, **_k: None)
    monkeypatch.setattr(runtime, 'validate_six_host_receipt_child', validate)
    options['first_proof_finisher'] = lambda *_a, **_k: jobs.get(first)

    def finish(*_a, **kwargs):
        assert kwargs['claim_owner'] == 'resume-owner' and kwargs['claim_token'] == 'resume-token'
        return jobs.get(second)
    options['second_proof_finisher'] = finish
    assert runtime.advance_mixed_append_apply(PARENT_ID, **options, proof_resume_only=True, proof_resume_claim=('resume-owner', 'resume-token')) == ('published-a', 'published-b')
    assert not any(('binding' in row or 'apply' in row for row in trace))
    assert trace.count('host-proof') == 1 and trace.count('publication') == 1


def test_post_sql_claim_reaches_actual_second_finisher_without_commands(ready):
    from app.services import provider_keyed_mixed_append_second_proof_job as second
    from app.storage.job_repository import job_event_digest
    from app.services import provider_keyed_mixed_append_second_apply_binding as binding
    jobs, parent, child, case = ready
    claim = runtime.claim_mixed_append_proof_resume(parent, jobs=jobs)
    runtime.require_mixed_append_proof_resume(parent, jobs=jobs, claim=claim)
    data = case['resume_terminal'].events[8].data
    proof = SimpleNamespace(
        provider=data['provider'], state_sha256=data['stateSha256'],
        lineage=data['lineage'], serial=data['serial'],
        resource_ids=tuple(tuple(row) for row in data['resourceIds']),
        new_edge_address=data['newEdgeAddress'],
        new_edge_provider_id=data['newEdgeProviderId'],
        new_edge_public_ip=data['newEdgePublicIp'],
        inventory_sha256=data['inventorySha256'],
        observation_sha256=data['observationSha256'],
        selector_resources_count=data['selectorResourcesCount'],
        attached_node_ids=tuple(data['attachedNodeIds']))
    observed = []

    def observer(**options):
        # Offline GET witness; lease renewal and both event CAS writes are real.
        for _ in range(3):
            options['fence']()
        observed.append(options['max_attempts'])
        return proof

    terminal = second.prove_and_finish_second_mixed_append_apply(
        parent.id, environment='devtest', job_repository=jobs,
        claim_owner=claim[0], claim_token=claim[1],
        source_loader=binding._approved_second, process_quiescent=lambda _: True,
        first_terminal_proof=lambda *_: job_event_digest(
            jobs.get(runtime.first_child_id(parent.id)).events),
        poststate_observer=observer)
    assert observed == [60]
    assert terminal.status == 'succeeded'
    assert terminal.events[:8] == child.events
    assert terminal.events[8].data == data
    assert len(terminal.events) == 10
    assert jobs.get(child.id) == terminal
    assert jobs.get(parent.id) == parent
