# Copyright (c) 2026, Oracle and/or its affiliates.
"""Real SQL failed central ingress -> cleanup-only observed generation."""
from dataclasses import asdict, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_channel_cleanup_observation as cleanup
from app.services import provider_keyed_channel_apply as channel
from app.services import provider_keyed_ingress_update as ingress
from app.services.provider_keyed_channel_generation import read_channel_generation, EVENT
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_channel_sql_workflow import case
import test_provider_keyed_channel_sql_workflow as workflow


@pytest.fixture(params=['apply_intent', 'apply_result', 'apply_intent:v1', 'apply_result:v1'])
def failed_case(case, tmp_path, monkeypatch, request):
    phase, _, mode = request.param.partition(':')
    legacy, noop = mode == 'v1', mode == 'noop'
    shown, updates, failed_updates = {}, {}, []
    real_gate = ingress._gate
    def gate(raw, update, token, provider):
        real_gate(raw, update, token, provider)
        shown[provider] = raw
    monkeypatch.setattr(ingress, '_gate', gate)
    real_apply = ingress.apply_keyed_ingress_update
    def fail(update, **kwargs):
        updates[update.workspace.provider] = update
        def rejected():
            failed_updates.append(update)
            raise ValueError('post-Apply provider proof rejected waiting status')
        if not noop or { (r.protocol, r.port) for r in update.prior_routes } == { (r.protocol, r.port) for r in update.next_routes }:
            kwargs['post_apply_proof'] = rejected
        return real_apply(update, **kwargs)
    monkeypatch.setattr(ingress, 'apply_keyed_ingress_update', fail)
    with pytest.raises(ValueError, match='post-Apply provider proof'):
        if noop:
            workflow._sql_channel_workflow(case, tmp_path, monkeypatch, 1, 1, 'udp', dns_history=True, noop_metadata=True)
        else:
            workflow.test_sql_central_apply_and_six_teardown_reopen(
                case, tmp_path, monkeypatch, chain_index=getattr(request.node, 'callspec', SimpleNamespace(params={})).params.get('selected_chain_index', 0), edge_index=1, kind='tcp')
    failed_update = failed_updates[-1]
    # Earlier successful provider receipts stay untouched in the additive case.
    updates = {failed_update.workspace.provider: failed_update} if noop else updates
    for update in updates.values():
        ingress._paths(update)[3].chmod(0o600)  # Match real Terraform subprocess umask.
        if legacy:
            status = ingress._paths(update)[0]
            value = json.loads(status.read_bytes())
            value.update(schema='keyed-ingress-update-v1')
            value.pop('predecessorReceiptSha256')
            ingress._write_private_json(status, value)
        if phase == 'apply_intent':
            status = ingress._paths(update)[0]
            value = json.loads(status.read_bytes())
            value['phase'] = 'apply_intent'
            value.pop('returnCode', None); value.pop('postStateSha256', None)
            ingress._write_private_json(status, value)
            Path(str(status).replace('-status.json', '-after.tfstate')).unlink(missing_ok=True)
    case['uncertain_phase'] = phase
    jobs, source = case['jobs'], case['source']
    job = jobs.get(failed_update.job_id if noop else 'job-channel-connected')
    job = jobs.save(replace(job, status='failed', finished_at=datetime.now(timezone.utc).isoformat(),
        events=[*job.events, JobEvent(len(job.events)+1, 'error', 'inbound Apply failed', {})]))
    lease = db.session.get(CoreMutationLeaseModel, source.engagement_id)
    db.session.delete(lease)
    db.session.commit()
    workspaces = {provider: channel._prior_workspace(None, provider, None) for provider in source.provider_order}
    binary = tmp_path / 'terraform'
    release = SimpleNamespace(path=binary, sha256=sha256(binary.read_bytes()).hexdigest(), version='1.15.5')
    monkeypatch.setattr(cleanup, '_audit', lambda _: None)
    monkeypatch.setattr(cleanup, '_credential', ingress._credential)
    calls = []
    def show(argv, root, environment):
        assert argv[1:3] == ['show', '-json']
        calls.append(tuple(argv))
        provider = next(p for p, w in workspaces.items() if w.path == root)
        return subprocess.CompletedProcess(argv, 0, shown[provider], '')
    # Match the already reviewed binary fingerprint in the actual private receipt.
    kwargs = dict(workspaces=workspaces, release_validator=lambda **_: release,
                  show_runner=show, quiescence_check=lambda: True)
    case.update(job=job, workspaces=workspaces, observation_kwargs=kwargs,
                show_calls=calls, updates=updates)
    return case


def observe(case, **kwargs):
    return cleanup.read_cleanup_channel_generation(case['source'], case['append_parent'],
        case['initial'], case['jobs'], **case['observation_kwargs'], **kwargs)


def test_failed_apply_observation_is_cleanup_only_and_reopens_after_destroy(failed_case):
    case = failed_case
    source, jobs, job = case['source'], case['jobs'], case['job']
    original = asdict(source)
    baseline = read_channel_generation(source, case['append_parent'], case['initial'], jobs, require_current_state=False)
    assert baseline.advances == ()  # No successful-generation event is invented.
    generation, observed = observe(case)
    assert observed['schema'] == cleanup.SCHEMA and observed['jobId'] == job.id
    assert generation.state_sha256s[source.provider_order.index(observed['provider'])] == observed['stateSha256']
    assert all(e.message != EVENT for e in jobs.get(job.id).events)
    assert asdict(source) == original
    update = case['updates'][observed['provider']]
    status_path = ingress._paths(update)[0]
    assert json.loads(status_path.read_bytes())['phase'] == case['uncertain_phase']
    # Destroy must not erase the immutable cleanup evidence or need live state.
    for workspace in case['workspaces'].values():
        workspace.state_path.write_text('{"resources":[],"serial":99}')
        (workspace.path / '.barragan-apply-phase.json').write_text('{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
    historical, reopened = observe(case, saved_observation=observed, require_current_state=False)
    assert reopened == observed and historical == generation
    with pytest.raises(ValueError): observe(case, saved_observation=observed)


@pytest.mark.parametrize('drift', ['job_running', 'lease', 'host', 'status', 'plan', 'inputs',
                                   'before', 'state_resource', 'state_lineage', 'state_output',
                                   'observation', 'lock_symlink', 'active_process', 'boolean_rc', 'missing_head', 'foreign_head', 'unknown_schema'])
def test_uncertain_ingress_cleanup_rejects_drift(failed_case, drift, tmp_path):
    case = failed_case
    update = next(iter(case['updates'].values()))
    status, inputs, _, plan = ingress._paths(update)
    if drift == 'observation':
        _, observed = observe(case)
        observed['resourceProjectionSha256'] = '0' * 64
        with pytest.raises(ValueError): observe(case, saved_observation=observed, require_current_state=False)
        return
    if drift in {'missing_head', 'foreign_head', 'unknown_schema'}:
        data = json.loads(status.read_bytes())
        data['schema'] = 'keyed-ingress-update-v2'
        if drift == 'missing_head':
            data.pop('predecessorReceiptSha256', None)
        elif drift == 'foreign_head':
            data['predecessorReceiptSha256'] = 'f' * 64
        else:
            data['schema'] = 'keyed-ingress-update-v999'
        status.write_text(json.dumps(data))
    elif drift == 'boolean_rc':
        data=json.loads(status.read_bytes());data.update(phase='apply_result', returnCode=False, postStateSha256=sha256(update.workspace.state_path.read_bytes()).hexdigest());status.write_text(json.dumps(data))
    elif drift == 'job_running': case['jobs'].save(replace(case['job'], status='running', finished_at=None))
    elif drift == 'lease':
        db.session.add(CoreMutationLeaseModel(engagement_id=case['source'].engagement_id,
            owner_id='job-still-active', operation='inbound_channel_apply')); db.session.commit()
    elif drift == 'host':
        path = Path(next(e.data['hostProof']['path'] for e in case['job'].events if e.message == cleanup.HOST_EVENT))
        path.write_text('{}')
    elif drift == 'status':
        data=json.loads(status.read_bytes());data['routeSha256']='0'*64;status.write_text(json.dumps(data))
    elif drift == 'plan': plan.write_bytes(b'foreign')
    elif drift == 'inputs': inputs.write_text('{}')
    elif drift == 'before': Path(str(inputs).replace('-inputs.json','-before.tfstate')).write_text('{}')
    elif drift.startswith('state_'):
        state=json.loads(update.workspace.state_path.read_bytes())
        if drift == 'state_lineage': state['lineage']='foreign'
        elif drift == 'state_output': state.setdefault('outputs',{})['alien']={'value':'foreign'}
        else: state['resources'][0]['instances'][0]['attributes']['alien']='foreign'
        update.workspace.state_path.write_text(json.dumps(state))
    elif drift == 'lock_symlink':
        path=update.workspace.path/'.barragan-ingress.lock';path.unlink();path.symlink_to(tmp_path/'foreign')
    else: case['observation_kwargs']['quiescence_check']=lambda:False
    with pytest.raises((ValueError, OSError)): observe(case)


@pytest.mark.parametrize('selected_chain_index', [0, 1])
def test_cleanup_observation_passes_actual_review_start_sql_seal_and_restart(
        failed_case, client, tmp_path, monkeypatch, selected_chain_index):
    from test_provider_keyed_mixed_published_six_workflow import _persist
    from test_provider_keyed_mixed_published_teardown_reservation import _attested_plans
    from app.services.provider_keyed_mixed_published_dispatch import preview_published_mixed_cleanup, start_published_mixed_cleanup
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import saved_published_mixed_initial_review, saved_published_mixed_destroy_plans
    from app.services.provider_keyed_mixed_published_teardown_authority import six_historical_rows_sha256
    from app.services import provider_keyed_channel_provider_proof as proof
    case = failed_case
    source = case['source']
    # Use the real observer with only the same pinned-binary/show witness used
    # above; do not replace the observed authority or its SQL writer checks.
    real_observer = cleanup.read_cleanup_channel_generation
    def reader(*args, **kwargs):
        options = {k: v for k, v in case['observation_kwargs'].items() if k != 'workspaces'}
        return real_observer(*args, **{**options, **kwargs})
    monkeypatch.setattr(cleanup, 'read_cleanup_channel_generation', reader)
    monkeypatch.setattr(proof, 'require_current_keyed_firewall', lambda *_a, fence, **_k: fence())
    for provider, workspace in case['workspaces'].items():
        raw = workspace.state_path.read_bytes()
        before = case['observations'][provider]
        case['observations'][provider] = replace(before, state_json=raw, classification=replace(
            before.classification, state_sha256=sha256(raw).hexdigest(), serial=json.loads(raw)['serial']))
    from app.services import provider_keyed_mixed_published_teardown_authority as authority
    from app.services import provider_keyed_mixed_initial_apply_child as initial_child
    monkeypatch.setattr(authority, 'recognize_mixed_initial_apply_terminal', lambda *_: {})
    monkeypatch.setattr(initial_child, '_prior_workspace', lambda _i, p, _t: case['workspaces'][p])
    jobs, plans_repo, sketches, core, collection = _persist(client, tmp_path, monkeypatch, False, existing_case=case)
    review = collection.review
    assert review.cleanup_observation['jobId'] == case['job'].id
    from app.services.provider_keyed_mixed_published_teardown_collector import collect_published_mixed_initial_teardown, PublishedMixedTeardownCollectionAttention
    with pytest.raises(PublishedMixedTeardownCollectionAttention, match='cleanup-only observation cannot authorize channel transport'):
        collect_published_mixed_initial_teardown(source.engagement_id, source.core_job_id,
            job_repository=jobs, read_only_transport=True)
    preview = preview_published_mixed_cleanup(core, environment='devtest', job_repository=jobs)
    saved = start_published_mixed_cleanup(core, {
        'snapshotId': preview['snapshotId'], 'confirmation': preview['confirmationPhrase']},
        environment='devtest', job_repository=jobs)
    assert saved.input['cleanupObservation'] == review.cleanup_observation
    assert saved_published_mixed_initial_review(saved) == review
    # Existing reservation repeat and public restart preserve the same accepted
    # observation and claim grammar, rather than reopening ingress publication.
    assert jobs.reserve_published_mixed_initial_cleanup_parent(saved, collection=collection,
        expected_snapshot_id=saved.input['reviewSnapshotId']) == saved
    restarted = preview_published_mixed_cleanup(core, environment='devtest', job_repository=jobs,
        collector=lambda *_a, **_k: pytest.fail('restart recollected provider state'))
    assert restarted['snapshotId'] == preview['snapshotId']
    from app.services.provider_keyed_mixed_published_dispatch_claim import claim_published_mixed_dispatch, release_published_mixed_dispatch
    claim = claim_published_mixed_dispatch(saved.id, job_repository=jobs)
    assert claim is not None
    assert claim_published_mixed_dispatch(saved.id, job_repository=jobs) is None
    release_published_mixed_dispatch(claim, job_repository=jobs)
    resumed = claim_published_mixed_dispatch(saved.id, job_repository=jobs)
    assert resumed is not None and resumed.token != claim.token
    release_published_mixed_dispatch(resumed, job_repository=jobs)
    plans, states, *_ = _attested_plans(jobs, collection, tmp_path)
    sealed = jobs.seal_published_mixed_initial_destroy_plans(saved, collection=collection,
        plan_set=plans, before_states=states)
    assert saved_published_mixed_destroy_plans(sealed) == plans
    assert six_historical_rows_sha256(review, jobs=jobs, plans=plans_repo, sketches=sketches) == review.historical_rows_sha256
    # Execute the existing one-shot provider GO, including its fresh pre-lock
    # and final callback phase checks, against the accepted cleanup authority.
    from app.services import provider_keyed_mixed_published_first_destroy_go as worker
    from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
    from test_provider_keyed_mixed_published_first_destroy_go import _fake_runner
    provider = review.cleanup_observation['provider']
    provider_index = review.source.ordered_providers.index(provider)
    root = collection.workspaces[provider]
    (root / '.barragan-apply-phase.json').write_text(json.dumps({'schema': 'provider-keyed-v2', 'phase': 'apply_started'}))
    # Saved-plan attestation executes normally; provider transport/decryption
    # remains the same explicitly offline witness as this suite's ingress path.
    monkeypatch.setattr(worker, '_credential', lambda *_: 'encrypted fixture credential')
    monkeypatch.setattr(worker, 'collect_published_mixed_initial_teardown', lambda *_a, **_k: collection)
    plans, states, _, binary, shows = _attested_plans(jobs, collection, tmp_path, with_shows=True)
    calls = []
    if provider_index == 1:
        from test_provider_keyed_mixed_published_absence import _awaiting, _empty_snapshot
        from app.services.provider_keyed_mixed_published_absence import prove_published_mixed_provider_absence, propose_published_mixed_first_absence_event
        first = review.source.ordered_providers[0]
        first_child = _awaiting(sealed, review, plans, collection.core_inspector_scope, first)
        empty = _empty_snapshot(plans.plans[0])
        generation = f'{sealed.id}:{plans.plan_set_sha256}'
        receipt = prove_published_mixed_provider_absence(case['initial'], sealed, review, plans, first, first_child, empty,
            collection.core_inspector_scope, 'Opaque', fence=lambda: 'stable', process_quiescent=lambda _: True)
        first_child = jobs.save(replace(first_child, status='succeeded', finished_at=first_child.started_at,
            events=[*first_child.events, propose_published_mixed_first_absence_event(first_child, receipt)]))
        collection.workspaces[first].joinpath('terraform.tfstate').write_bytes(empty.state_json)
        transition = SimpleNamespace(second_provider=provider, first_absence=receipt,
            second_state_sha256=plans.plans[1].before_state_sha256, source_generation=generation)
        monkeypatch.setattr(worker, 'collect_published_mixed_post_first_transition', lambda *_a, **_k: SimpleNamespace(
            cleanup=sealed, initial=jobs.get(review.source.parent_job_id), review=review, plans=plans,
            first_destroy_child=first_child, transition=transition, second_observation=collection.observations[provider]))
    child = worker._run_published_mixed_provider_destroy(sealed.id, provider_index=provider_index,
        environment='devtest', job_repository=jobs,
        show_runner=lambda *_: shows[provider],
        release_validator=lambda **_: ProviderKeyedTerraformRelease(binary,
            sha256(binary.read_bytes()).hexdigest(), '1.15.5', 'linux_amd64'),
        gated_command_runner=_fake_runner(provider, root, calls))
    assert child.events[-1].message == 'published mixed provider awaiting exact absence'
    assert len(calls) == 1


@pytest.mark.parametrize('drift', [None, 'row_duplicate', 'object_duplicate', 'status', 'object_status',
                                   'missing', 'added', 'failure', 'outputs', 'version', 'object_order'])
def test_state_envelope_accepts_only_check_collection_order(drift):
    from copy import deepcopy
    before = {'version': 4, 'terraform_version': '1.15.5', 'lineage': 'retained', 'serial': 16,
        'outputs': {'retained': {'value': 'exact'}}, 'resources': [], 'check_results': [
            {'object_kind': 'resource', 'config_addr': 'digitalocean_firewall.firewall', 'status': 'pass',
             'objects': [{'object_addr': 'digitalocean_firewall.firewall["a"]', 'status': 'pass'},
                         {'object_addr': 'digitalocean_firewall.firewall["b"]', 'status': 'pass'}]},
            {'object_kind': 'var', 'config_addr': 'var.edge_groups', 'status': 'pass',
             'objects': [{'object_addr': 'var.edge_groups', 'status': 'pass'}]}]}
    after = deepcopy(before)
    after['serial'] = 18
    after['check_results'].reverse()
    if drift == 'row_duplicate': after['check_results'].append(deepcopy(after['check_results'][0]))
    elif drift == 'object_duplicate': after['check_results'][1]['objects'].append(deepcopy(after['check_results'][1]['objects'][0]))
    elif drift == 'object_order': after['check_results'][1]['objects'].reverse()
    elif drift == 'status': after['check_results'][1]['status'] = 'unknown'
    elif drift == 'object_status': after['check_results'][1]['objects'][0]['status'] = 'unknown'
    elif drift == 'missing': after['check_results'].pop()
    elif drift == 'added': after['check_results'].append({'object_kind': 'var', 'config_addr': 'var.alien', 'status': 'pass', 'objects': []})
    elif drift == 'failure': after['check_results'][0]['objects'][0]['failure_messages'] = ['new failure']
    elif drift == 'outputs': after['outputs']['retained']['value'] = 'changed'
    elif drift == 'version': after['terraform_version'] = 'different'
    if drift in {'row_duplicate', 'object_duplicate'}:
        with pytest.raises(ValueError): cleanup._state_envelope(after)
    else:
        assert (cleanup._state_envelope(before) == cleanup._state_envelope(after)) is (drift is None)


@pytest.mark.parametrize('failed_case', ['apply_intent:noop', 'apply_result:noop'], indirect=True)
def test_failed_metadata_noop_observation_reopens_without_publication_or_retry(failed_case):
    case = failed_case
    jobs, job, source = case['jobs'], case['job'], case['source']
    original_job = jobs.get(job.id)
    baseline = read_channel_generation(source, case['append_parent'], case['initial'], jobs, require_current_state=False)
    assert baseline.advances  # The failed no-op follows genuine successful SQL advances.
    with pytest.raises(ValueError):
        read_channel_generation(source, case['append_parent'], case['initial'], jobs)
    generation, observed = observe(case)
    assert observed['jobId'] == job.id and generation.receipt_heads == baseline.receipt_heads
    assert generation.advances[-1] == {'cleanupObservationSha256': cleanup._digest(observed)}
    assert all(e.message != EVENT for e in jobs.get(job.id).events)
    assert jobs.get(job.id) == original_job and original_job.status == 'failed'
    assert json.loads(ingress._paths(next(iter(case['updates'].values())))[0].read_bytes())['phase'] == case['uncertain_phase']
    for workspace in case['workspaces'].values():
        workspace.state_path.write_text('{"resources":[],"serial":99}')
    historical, reopened = observe(case, saved_observation=observed, require_current_state=False)
    assert historical == generation and reopened == observed
    with pytest.raises(ValueError):
        observe(case, saved_observation={**observed, 'serial': observed['serial'] + 1}, require_current_state=False)


@pytest.mark.parametrize('failed_case', ['apply_intent:noop'], indirect=True)
def test_metadata_noop_cleanup_uses_existing_review_start_sql_reservation(failed_case, client, tmp_path, monkeypatch):
    test_cleanup_observation_passes_actual_review_start_sql_seal_and_restart(
        failed_case, client, tmp_path, monkeypatch, selected_chain_index=1)


@pytest.mark.parametrize('failed_case', ['apply_intent:noop'], indirect=True)
def test_failed_metadata_noop_cannot_downgrade_to_legacy_cleanup(failed_case):
    case = failed_case
    status = ingress._paths(next(iter(case['updates'].values())))[0]
    value = json.loads(status.read_bytes())
    value['schema'] = 'keyed-ingress-update-v1'
    value.pop('predecessorReceiptSha256')
    status.write_text(json.dumps(value))
    with pytest.raises(ValueError): observe(case)
    assert all(e.message != EVENT for e in case['jobs'].get(case['job'].id).events)
