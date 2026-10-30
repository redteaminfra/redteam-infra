# Copyright (c) 2026, Oracle and/or its affiliates.
"""Real SQL cleanup admission and coordinator wiring; external GETs are witnesses.

Both append plans, complete provider journals, failed host contact journal,
10-resource scopes, reservation/lease transfer, plan seals and retirement are
production readers/writers. No host command or provider mutation runs.
"""
from dataclasses import replace
import pytest
from app.domain import JobEvent
from app.services import provider_keyed_unpublished_six_cleanup as recovery
from app.services.provider_keyed_mixed_append_pair_host_proof import _child_id


def unpublish_failed_host_case(source, jobs, sketches, monkeypatch):
    from app.services import provider_keyed_mixed_append_six_source as fresh
    parent = jobs.get(source.parent_id)
    host = jobs.get(_child_id(parent.id))
    # Real producer journal: stop after last provider's four completed raw
    # commands, before interpretation accepted its capture or publication.
    assert host.events[-2].message == 'mixed append edge raw proof captured'
    events = host.events[:-2]
    assert events[-1].message == 'mixed append raw command result fenced'
    failed = jobs.save(replace(host, status='failed', events=[*events,
        JobEvent(len(events)+1, 'error', 'mixed append host proof stopped; reconciliation required', {})]))
    jobs.save(replace(parent, status='running', finished_at=None,
        input={**parent.input, 'phase':'apply_sealed', 'claimOwner':host.input['claimOwner'], 'claimToken':host.input['claimToken']}, events=parent.events[:-1]))
    from pathlib import Path
    from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
    for provider, root in zip(source.provider_order, source.workspace_paths):
        journal=Path(root)/_name(provider,'plan-journal.jsonl')
        journal.write_bytes(b'offline planning journal witness')
        journal.chmod(0o600)
    for chain in source.before_chains:
        sketches.save(chain)
        from app.storage.database import db
        from app.storage.models import SketchChainModel
        from datetime import datetime
        row=db.session.query(SketchChainModel).filter_by(engagement_id=chain.engagement_id,chain_id=chain.chain_id).one()
        row.updated_at=datetime.fromisoformat(chain.updated_at)
        db.session.commit()
    monkeypatch.setattr(recovery, '_process_quiescent', lambda *_: True)
    # The existing fresh six-source reader's external inventory/source stage
    # is witnessed here. Full saved-plan gates and journals remain real below.
    monkeypatch.setattr(fresh, 'collect_fresh_six_node_host_source', lambda *_a, **_k: source)
    from app.storage.database import db
    from app.storage.models import CoreMutationLeaseModel
    db.session.add(CoreMutationLeaseModel(engagement_id=source.engagement_id,
        owner_id=source.core_plan_id, operation='provider_keyed_mixed_append'))
    db.session.commit()
    recovery.require_failed_host(source, jobs.get(parent.id), failed, process_quiescent=lambda *_: True)
    return failed


@pytest.mark.parametrize('reverse', [False,True])
def test_unpublished_review_start_seal_restart(client,tmp_path,monkeypatch,reverse):
    from test_provider_keyed_mixed_published_six_workflow import _persist
    from test_provider_keyed_mixed_published_teardown_reservation import _attested_plans
    from app.services.provider_keyed_mixed_published_dispatch import preview_published_mixed_cleanup, start_published_mixed_cleanup
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import saved_published_mixed_initial_review
    from app.services.provider_keyed_mixed_published_teardown_authority import six_historical_rows_sha256
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
    with client.application.storage_context():
        jobs,plans,sketches,core,collection=_persist(client,tmp_path,monkeypatch,reverse,unpublished=True)
        review=collection.review
        assert review.unpublished_six_recovery['schema']==recovery.SOURCE_KIND
        assert sum(len(s['resources']) for s in review.provider_scopes)==10
        append=jobs.get(review.source.six_node_source.parent_id)
        failed=jobs.get(_child_id(append.id))
        assert failed.status=='failed' and append.status=='running'
        assert sum(len(r.nodes) for r in sketches.list_for_engagement(core.target_id))==4
        preview=preview_published_mixed_cleanup(core,environment='devtest',job_repository=jobs)
        assert preview['startAvailable']
        saved=start_published_mixed_cleanup(core,{'snapshotId':preview['snapshotId'],
            'confirmation':preview['confirmationPhrase']},environment='devtest',job_repository=jobs)
        assert saved.input['sourceKind']==recovery.SOURCE_KIND
        assert saved_published_mixed_initial_review(saved)==review
        assert _db_lease_lookup(core.target_id)==(review.source.core_plan_id,'provider_keyed_teardown_fence')
        plan_set,states,*_=_attested_plans(jobs,collection,tmp_path)
        jobs.seal_published_mixed_initial_destroy_plans(saved,collection=collection,plan_set=plan_set,before_states=states)
        assert six_historical_rows_sha256(review,jobs=jobs,plans=plans,sketches=sketches)==review.historical_rows_sha256
        again=preview_published_mixed_cleanup(core,environment='devtest',job_repository=jobs,
            collector=lambda *_a,**_k:pytest.fail('restart recollected/host replayed'))
        assert not again['startAvailable']
        assert jobs.get(append.id)==append and jobs.get(failed.id)==failed


@pytest.mark.parametrize('drift',['missing_result','active_process','source','lease','row','state','saved_plan','apply_journal','unknown_host_event','incomplete_raw'])
def test_unpublished_start_rejects_drift(client,tmp_path,monkeypatch,drift):
    from test_provider_keyed_mixed_published_six_workflow import _persist
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import propose_published_mixed_initial_cleanup
    from app.storage.database import db
    from app.storage.models import CoreMutationLeaseModel
    with client.application.storage_context():
        jobs,plans,sketches,core,collection=_persist(client,tmp_path,monkeypatch,False,unpublished=True)
        review=collection.review; source=review.source.six_node_source
        proposal=propose_published_mixed_initial_cleanup(review,collection.core_inspector_scope,'Opaque',requested_by='operator')
        host=jobs.get(_child_id(source.parent_id))
        if drift=='missing_result': jobs.save(replace(host,events=host.events[:-2]+[host.events[-1]]))
        elif drift=='unknown_host_event':
            jobs.save(replace(host,events=[*host.events[:-1],replace(host.events[-1],message='other failure')]))
        elif drift=='incomplete_raw':
            events=host.events[:-4]+[replace(host.events[-1],sequence=len(host.events)-3)]
            jobs.save(replace(host,events=events))
        elif drift=='apply_journal':
            from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as apply_id
            child=jobs.get(apply_id(source.parent_id))
            jobs.save(replace(child,events=child.events[:-1]))
        elif drift=='active_process': monkeypatch.setattr(recovery,'_process_quiescent',lambda *_:False)
        elif drift=='source': jobs.save(replace(host,input={**host.input,'sourceSha256':'0'*64}))
        elif drift=='lease':
            db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=source.engagement_id).update({'owner_id':'other'})
            db.session.commit()
        elif drift=='row':
            row=sketches.list_for_engagement(source.engagement_id)[0]
            sketches.save(replace(row,assigned_proxy='other'))
        elif drift=='state': collection.workspaces[source.provider_order[0]].joinpath('terraform.tfstate').write_bytes(b'{}')
        else:
            from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
            collection.workspaces[source.provider_order[0]].joinpath(_name(source.provider_order[0],'saved.tfplan')).write_bytes(b'changed')
        with pytest.raises(ValueError):
            jobs.reserve_published_mixed_initial_cleanup_parent(proposal,collection=collection,
                expected_snapshot_id=proposal.input['reviewSnapshotId'])
        assert jobs.get(proposal.id) is None


def test_unpublished_cannot_authorize_channel_transport(client,tmp_path,monkeypatch):
    from test_provider_keyed_mixed_published_six_workflow import _persist
    from app.services.provider_keyed_mixed_published_teardown_collector import collect_published_mixed_initial_teardown
    with client.application.storage_context():
        jobs,_,_,core,_=_persist(client,tmp_path,monkeypatch,False,unpublished=True)
        with pytest.raises(ValueError):
            collect_published_mixed_initial_teardown(core.target_id,core.id,job_repository=jobs,read_only_transport=True)

@pytest.mark.parametrize('reverse',[False,True])
def test_unpublished_real_post_first_collector_reopens_after_either_provider_empty(client,tmp_path,monkeypatch,reverse):
    from test_provider_keyed_mixed_published_six_workflow import _persist
    from test_provider_keyed_mixed_published_teardown_reservation import _attested_plans
    from test_provider_keyed_mixed_published_absence import _awaiting,_empty_snapshot
    from test_provider_keyed_mixed_interrupted_source import _snapshot
    from app.services.provider_keyed_mixed_published_absence import prove_published_mixed_provider_absence,propose_published_mixed_first_absence_event
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import propose_published_mixed_initial_cleanup
    from app.services import provider_keyed_mixed_published_post_first_collector as post
    from app.services import provider_keyed_mixed_published_six_collector as collector
    from types import SimpleNamespace
    with client.application.storage_context():
        jobs,plans_repo,sketches,core,collection=_persist(client,tmp_path,monkeypatch,reverse,unpublished=True)
        review,scope=collection.review,collection.core_inspector_scope
        queued=propose_published_mixed_initial_cleanup(review,scope,'Opaque',requested_by='operator')
        queued=jobs.reserve_published_mixed_initial_cleanup_parent(queued,collection=collection,expected_snapshot_id=queued.input['reviewSnapshotId'])
        plans,states,*_=_attested_plans(jobs,collection,tmp_path)
        parent=jobs.seal_published_mixed_initial_destroy_plans(queued,collection=collection,plan_set=plans,before_states=states)
        first,second=review.source.ordered_providers
        child=_awaiting(parent,review,plans,scope,first)
        generation=f'{parent.id}:{plans.plan_set_sha256}'
        empty=_snapshot(first,tag=first=='digitalocean',phase='destroy_applied',state=_empty_snapshot(plans.plans[0]).state_json,generation=generation)
        receipt=prove_published_mixed_provider_absence(jobs.get(review.source.parent_job_id),parent,review,plans,
            first,child,empty,scope,'Opaque',fence=lambda:generation,process_quiescent=lambda _:True)
        jobs.save(replace(child,status='succeeded',finished_at=child.started_at,events=[*child.events,propose_published_mixed_first_absence_event(child,receipt)]))
        collection.workspaces[first].joinpath('terraform.tfstate').write_bytes(empty.state_json)
        monkeypatch.setattr(recovery,'_process_quiescent',lambda *_:pytest.fail('historical reopening scanned current cleanup process'))
        monkeypatch.setattr(post,'_core_inspector_scope',lambda *_a,**_k:scope)
        monkeypatch.setattr(post,'recognize_mixed_initial_apply_terminal',lambda *_:{})
        monkeypatch.setattr(post,'_prior_workspace',lambda _i,p,_t:SimpleNamespace(path=collection.workspaces[p]))
        monkeypatch.setattr(post,'collect_provider_inventory_snapshot',lambda *_a,**_k:empty)
        def observe(provider,*_a,current_generation=None,**_k):
            assert provider==second and current_generation is None
            return collection.observations[provider]
        monkeypatch.setattr(collector,'_fresh_observation',observe)
        reopened=post.collect_published_mixed_post_first_transition(parent.id,job_repository=jobs,process_quiescent=lambda _:True)
        assert reopened.review==review and reopened.transition.second_provider==second


@pytest.mark.parametrize('reverse',[False,True])
def test_unpublished_existing_provider_go_and_historical_heartbeat(client,tmp_path,monkeypatch,reverse):
    import hashlib,json
    from test_provider_keyed_mixed_published_six_workflow import _persist
    from test_provider_keyed_mixed_published_teardown_reservation import _attested_plans
    from test_provider_keyed_mixed_published_first_destroy_go import _fake_runner
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import propose_published_mixed_initial_cleanup
    from app.services.provider_keyed_mixed_published_teardown_authority import six_historical_rows_sha256
    from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
    from app.services import provider_keyed_mixed_published_first_destroy_go as worker
    with client.application.storage_context():
        jobs,plans_repo,sketches,core,collection=_persist(client,tmp_path,monkeypatch,reverse,unpublished=True)
        review,scope=collection.review,collection.core_inspector_scope
        queued=propose_published_mixed_initial_cleanup(review,scope,'Opaque',requested_by='operator')
        queued=jobs.reserve_published_mixed_initial_cleanup_parent(queued,collection=collection,expected_snapshot_id=queued.input['reviewSnapshotId'])
        plans,states,_,binary,shows=_attested_plans(jobs,collection,tmp_path,with_shows=True)
        parent=jobs.seal_published_mixed_initial_destroy_plans(queued,collection=collection,plan_set=plans,before_states=states)
        provider=review.source.ordered_providers[0];root=collection.workspaces[provider]
        (root/'.terraform-data').mkdir(exist_ok=True)
        (root/'.barragan-apply-phase.json').write_text(json.dumps({'schema':'provider-keyed-v2','phase':'applied'}))
        monkeypatch.setattr(worker,'_credential',lambda *_:'encrypted fixture credential')
        monkeypatch.setattr(worker,'collect_published_mixed_initial_teardown',lambda *_a,**_k:collection)
        calls=[];command=_fake_runner(provider,root,calls)
        def runner(*args,**kwargs):
            result=command(*args,**kwargs)
            # A teardown's own active process must not invalidate immutable
            # host-failure evidence read by heartbeat/tail callbacks.
            with monkeypatch.context() as patch:
                patch.setattr(recovery,'_process_quiescent',lambda *_:False)
                assert six_historical_rows_sha256(review,jobs=jobs,plans=plans_repo,sketches=sketches)==review.historical_rows_sha256
            return result
        child=worker.run_published_mixed_first_provider_destroy(parent.id,environment='devtest',job_repository=jobs,
            show_runner=lambda *_:shows[provider],release_validator=lambda **_:ProviderKeyedTerraformRelease(
                binary,hashlib.sha256(binary.read_bytes()).hexdigest(),'1.15.5','linux_amd64'),gated_command_runner=runner)
        assert child.events[-1].message=='published mixed provider awaiting exact absence' and len(calls)==1
