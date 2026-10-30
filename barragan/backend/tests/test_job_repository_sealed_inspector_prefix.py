# Copyright (c) 2026, Oracle and/or its affiliates.
"""Sealed failed-HTTP source through actual SQL Inspector claim/readiness CAS.

The focused fixture's source/provider catalog seams are explicit. This module
proves the writer prefix contract; the canonical Linux flow proves composition.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete

from app.domain import JobEvent
from app.services import engagement_teardown as teardown
from app.services import provider_keyed_comprehensive_teardown as coordinator
from app.services import provider_keyed_published_initial_cleanup_authority as authority
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.models import JobRunModel
from test_job_repository_keyed_retained_inspector import _transition, _ready_event
from test_provider_keyed_published_teardown_reservation import _sealed_case


def _sealed_handoff(client, monkeypatch, tmp_path):
    from app.services import provider_keyed_teardown_source as source_selector
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
    jobs, proposal, source = _sealed_case(client, monkeypatch, tmp_path)
    parent = teardown.start_engagement_teardown(source.core_job_id, {
        "snapshotId": proposal.input["scopeSnapshot"]["snapshotId"],
        "confirmation": proposal.input["scopeSnapshot"]["confirmationPhrase"],
    }, provider_keyed_environment="devtest", provider_keyed_published_source=source,
       provider_keyed_coordinator=lambda _identifier: None, job_repository=jobs)
    monkeypatch.setattr(source_selector, "audit_published_provider_keyed_source", lambda *_a, **_kw: source)
    monkeypatch.setattr(source_selector, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: parent.input["scopeSnapshot"]["providerScopes"][0])
    child = coordinator.run_provider_keyed_comprehensive_handoff(parent.id,
        environment="devtest", job_repository=jobs,
        plan_repository=SqlAlchemyDeploymentPlanRepository(), lease_lookup=_db_lease_lookup,
        now=lambda: datetime.now(timezone.utc)-timedelta(minutes=6), token_factory=lambda: "h"*32)
    return jobs,parent,child


def test_sealed_public_start_handoff_claim_heartbeat_ready_and_reopen(client,monkeypatch,tmp_path):
    with client.application.storage_context():
        jobs,parent,child=_sealed_handoff(client,monkeypatch,tmp_path)
        claimed=_transition(jobs,child,"claim")
        assert claimed is not None and claimed.events==child.events
        renewed=_transition(jobs,claimed,"heartbeat")
        assert renewed is not None and renewed.events==child.events
        def saved_authority():
            core=jobs.get(parent.input["coreJobId"])
            authority.validate_saved_cleanup(parent,core,parent.input["scopeSnapshot"],jobs)
        ready=_transition(jobs,renewed,"ready",event=_ready_event(renewed),authority=saved_authority)
        assert ready is not None and ready.input["phase"]=="inspector_ready"
        assert ready.events[:4]==child.events and len(ready.events)==5
        assert SqlAlchemyJobRepository().get(ready.id)==ready
        assert jobs.get(parent.id)==parent
        assert _transition(jobs,renewed,"ready",event=_ready_event(renewed),authority=saved_authority) is None


@pytest.mark.parametrize("drift",["child_marker","parent_marker","missing_parent","foreign_parent",
    "actor","core_plan","parent_actor","rehashed_scope"])
def test_sealed_claim_rejects_missing_marker_or_parent_lineage(client,monkeypatch,tmp_path,drift):
    with client.application.storage_context():
        jobs,parent,child=_sealed_handoff(client,monkeypatch,tmp_path)
        if drift=="child_marker":
            child=jobs.save(replace(child,events=[replace(child.events[0],data={"snapshotId":child.input["scopeSnapshotId"]}),*child.events[1:]]))
        elif drift=="parent_marker":
            jobs.save(replace(parent,input={k:v for k,v in parent.input.items() if k!=authority.MARKER}))
        elif drift=="missing_parent":
            db.session.execute(delete(JobRunModel).where(JobRunModel.id==parent.id));db.session.commit()
        elif drift in {"foreign_parent","core_plan"}:
            key="teardownParentId" if drift=="foreign_parent" else "corePlanId"
            child=jobs.save(replace(child,input={**child.input,key:"foreign"}))
        elif drift=="actor":child=jobs.save(replace(child,requested_by="foreign"))
        elif drift=="parent_actor":jobs.save(replace(parent,requested_by="foreign"))
        else:
            scope={**parent.input["scopeSnapshot"],"engagementName":"changed"}
            scope["snapshotId"]=teardown._fingerprint({k:v for k,v in scope.items() if k!="snapshotId"})
            jobs.save(replace(parent,input={**parent.input,"scopeSnapshot":scope}))
        before=jobs.get(child.id)
        assert _transition(jobs,before,"claim") is None
        assert jobs.get(child.id)==before


def test_sealed_parent_race_rolls_back_entire_claim(client,monkeypatch,tmp_path):
    from sqlalchemy import event
    with client.application.storage_context():
        jobs,parent,child=_sealed_handoff(client,monkeypatch,tmp_path)
        engine=db.session.get_bind()
        races=[]
        def race(connection,cursor,statement,parameters,context,executemany):
            if not races and statement.startswith("UPDATE job_runs SET input="):
                races.append(True)
                other=connection.connection.cursor()
                try:
                    other.execute("UPDATE job_runs SET requested_by=? WHERE id=?",("changed-under-writer",parent.id))
                finally:
                    other.close()
        event.listen(engine,"after_cursor_execute",race)
        try:
            assert _transition(jobs,child,"claim") is None
        finally:
            event.remove(engine,"after_cursor_execute",race)
        assert races==[True]
        assert jobs.get(child.id)==child and jobs.get(parent.id)==parent


def test_sealed_ready_provider_absence_publication_keeps_exact_prefix(client,monkeypatch,tmp_path):
    from test_job_repository_keyed_provider_absent import publish
    with client.application.storage_context():
        jobs,parent,child=_sealed_handoff(client,monkeypatch,tmp_path)
        claimed=_transition(jobs,child,"claim")
        ready=_transition(jobs,claimed,"ready",event=_ready_event(claimed),authority=lambda:None)
        # This isolated writer test supplies absence proof data; the full Linux
        # flow obtains that data through the actual plan/apply/absence readers.
        absent=publish(jobs,ready)
        assert absent is not None and absent.input["phase"]=="provider_absent"
        assert absent.events[:4]==child.events and jobs.get(parent.id)==parent


@pytest.mark.parametrize("provider",["linode","digitalocean"])
def test_sealed_sql_intent_stage_and_completion_heartbeat_prefix(client,monkeypatch,tmp_path,provider):
    from test_job_repository_keyed_inspector_intent import append, DATA
    from test_job_repository_keyed_inspector_stage import complete
    from test_job_repository_keyed_inspector_heartbeat import heartbeat
    with client.application.storage_context():
        jobs,parent,child=_sealed_handoff(client,monkeypatch,tmp_path)
        now=datetime.now(timezone.utc)
        claimed=jobs.claim_lease(child.id,owner="provider-keyed-inspector-create",token="a"*32,
            claimed_at=(now-timedelta(seconds=1)).isoformat(),expires_at=(now+timedelta(minutes=4)).isoformat(),
            eligible_statuses={"running"},eligible_phases={"awaiting_inspector_preflight"})
        intent=append(jobs,claimed,data={**DATA,"provider":provider,
            "scopeSnapshotId":child.input["scopeSnapshotId"],"providerScopeSha256":child.input["providerScopeSha256"]})
        assert intent is not None
        completed=complete(jobs,intent,provider)
        renewed=heartbeat(jobs,completed)
        assert renewed is not None and renewed.events==completed.events
        assert renewed.events[:4]==child.events and jobs.get(parent.id)==parent


def test_standalone_sqlite_cannot_claim_a_sealed_child(client,monkeypatch,tmp_path):
    from app.storage.job_repository import SqliteJobRepository
    with client.application.storage_context():
        _jobs,_parent,child=_sealed_handoff(client,monkeypatch,tmp_path)
        standalone=SqliteJobRepository(tmp_path/"standalone.sqlite")
        standalone.save(child)
        assert _transition(standalone,standalone.get(child.id),"claim") is None
        assert standalone.get(child.id)==child


def _sealed_group_retirement(client, monkeypatch, tmp_path):
    """Real prefix/absence/retirement writers; external absence/source fixtures."""
    from pathlib import Path
    from types import SimpleNamespace
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
    from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
    from test_job_repository_keyed_provider_absent import publish, proof
    jobs, parent, child = _sealed_handoff(client, monkeypatch, tmp_path)
    claimed = _transition(jobs, child, "claim")
    ready = _transition(jobs, claimed, "ready", event=_ready_event(claimed), authority=lambda: None)
    chains = SqlAlchemySketchChainRepository()
    rows = tuple(sorted(chains.list_for_engagement(parent.target_id), key=lambda row: row.chain_id))
    # The upstream source seam predates the example public-IP projection added
    # by _sealed_case. Bind its fixture source digest to those actual saved rows.
    parent = jobs.save(replace(parent, input={**parent.input, "publishedSource": {
        **parent.input["publishedSource"],
        "chain_projection_sha256": teardown._fingerprint({row.chain_id: row.to_dict() for row in rows}),
    }}))
    scope = parent.input["scopeSnapshot"]["providerScopes"][0]
    ids = {row["address"]: row["id"] for row in scope["resources"]}
    # Existing source fixture includes the local-file IDs; all provider identities
    # and runtime rows remain exact. No provider/state probe is claimed here.
    data = proof(ready)
    data.update(resourceIdsSha256=teardown._fingerprint(ids),
                verifiedAbsentDropletIds=sorted(value for key, value in ids.items()
                    if key.startswith("digitalocean_droplet.")),
                verifiedAbsentFirewallId=ids["digitalocean_firewall.firewall"],
                verifiedAbsentSshKeyId=ids["digitalocean_ssh_key.key"])
    preview = jobs.save(replace(parent, id=data["previewJobId"], action="example_preview",
        status="succeeded", started_at=parent.created_at, finished_at=parent.created_at,
        input={}, events=[JobEvent(1, "info", "example external preview", {})]))
    applied = jobs.save(replace(preview, id=data["applyJobId"], action="provider_keyed_initial_destroy_apply"))
    data.update(previewJournalSha256=job_event_digest(preview.events),
                applyJournalSha256=job_event_digest(applied.events))
    absent = publish(jobs, ready, evidence=data)
    resources = SqlAlchemyProviderResourceRepository()
    completed = datetime.now(timezone.utc)
    retire = {key: data[key] for key in (
        "scopeSnapshotId", "providerScopeSha256", "applyJobId", "resourceIdsSha256",
        "verifiedAbsentDropletIds", "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId")}
    retire.update(sourceJournalSha256=job_event_digest(absent.events),
                  confirmationCompletedAt=completed.isoformat(),
                  confirmationExpiresAt=(completed+timedelta(seconds=30)).isoformat())
    arguments = dict(coordinator=absent, prior_chains=rows,
        prior_records=tuple(sorted(resources.list_for_engagement(parent.target_id), key=lambda row: row.id)),
        group_apply_job_id=applied.id, resource_ids=ids, proof=retire,
        authority=lambda: None,
        prior_chain_projection_sha256=teardown._fingerprint({row.chain_id: row.to_dict() for row in rows}))
    source = SimpleNamespace(variant="published", teardown_parent_id=parent.id)
    core = jobs.get(parent.input["coreJobId"])
    def read_source(*_args, **_options):
        bound = SimpleNamespace(parent=jobs.get(parent.id), core=core, scope=scope,
            chains=tuple(chains.list_for_engagement(parent.target_id)),
            workspace=SimpleNamespace(path=Path(rows[0].terraform_working_directory)),
            intent=SimpleNamespace(resource_ids=ids, empty_state_sha256=data["emptyStateSha256"]),
            preview_job=preview, apply_job=applied)
        return source, bound
    from app.services import provider_keyed_teardown_source
    from app.services import sketch_state_workspaces
    monkeypatch.setattr(provider_keyed_teardown_source, "_read_published_post_destroy_boundary", read_source)
    root = tmp_path / "reader-state"
    root.mkdir()
    monkeypatch.setattr(sketch_state_workspaces, "_default_state_root", lambda: root)
    return jobs, parent, chains, arguments, root


def test_sealed_group_writer_and_both_restart_readers(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, chains, arguments, root = _sealed_group_retirement(client, monkeypatch, tmp_path)
        assert coordinator.recognize_provider_keyed_destroy_absence(parent.id,
            environment="devtest", state_root=root) == arguments["coordinator"]
        retired = chains.publish_provider_keyed_group_retired(**arguments)
        assert all(row.status == "destroyed" for row in retired)
        db.session.remove()
        recognized = coordinator.recognize_provider_keyed_group_retired(parent.id,
            environment="devtest", state_root=root)
        assert recognized == retired
        # Historical readers use the authenticated source boundary, not the
        # current queued-parent transition helper. Its full source authority is
        # an explicit seam here; the Linux flow exercises actual terminal proof.
        jobs.save(replace(parent, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
            input={**parent.input, "phase": "completed"}))
        assert coordinator.recognize_provider_keyed_group_retired(parent.id,
            environment="devtest", state_root=root) == retired


@pytest.mark.parametrize("drift", ["child_marker", "parent_marker", "missing_parent", "actor", "terminal_parent", "race"])
def test_sealed_group_writer_rejects_parent_downgrade_and_race(client, monkeypatch, tmp_path, drift):
    from sqlalchemy import event
    from app.storage.sketch_chain_repository import ProviderKeyedPublicationConflict
    with client.application.storage_context():
        jobs, parent, chains, arguments, _root = _sealed_group_retirement(client, monkeypatch, tmp_path)
        child = arguments["coordinator"]
        if drift == "child_marker":
            child = jobs.save(replace(child, events=[replace(child.events[0],
                data={"snapshotId": child.input["scopeSnapshotId"]}), *child.events[1:]]))
            arguments["coordinator"] = child
            arguments["proof"]["sourceJournalSha256"] = job_event_digest(child.events)
        elif drift == "parent_marker":
            jobs.save(replace(parent, input={key: value for key, value in parent.input.items() if key != authority.MARKER}))
        elif drift == "missing_parent":
            db.session.execute(delete(JobRunModel).where(JobRunModel.id == parent.id)); db.session.commit()
        elif drift == "actor":
            jobs.save(replace(parent, requested_by="foreign"))
        elif drift == "terminal_parent":
            jobs.save(replace(parent, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat()))
        before_parent = jobs.get(parent.id)
        engine = db.session.get_bind()
        races = []
        def race(connection, cursor, statement, parameters, context, executemany):
            if drift == "race" and not races and statement.startswith("UPDATE job_runs SET input="):
                races.append(True)
                connection.exec_driver_sql("UPDATE job_runs SET requested_by=? WHERE id=?", ("foreign", parent.id))
        event.listen(engine, "after_cursor_execute", race)
        try:
            with pytest.raises(ProviderKeyedPublicationConflict):
                chains.publish_provider_keyed_group_retired(**arguments)
        finally:
            event.remove(engine, "after_cursor_execute", race)
        assert jobs.get(child.id) == child and jobs.get(parent.id) == before_parent
        assert tuple(sorted(chains.list_for_engagement(parent.target_id), key=lambda row: row.chain_id)) == arguments["prior_chains"]
        assert races == ([True] if drift == "race" else [])


@pytest.mark.parametrize("phase", ["provider_absent", "group_retired"])
def test_sealed_restart_reader_rejects_child_prefix_downgrade(client, monkeypatch, tmp_path, phase):
    with client.application.storage_context():
        jobs, parent, chains, arguments, root = _sealed_group_retirement(client, monkeypatch, tmp_path)
        if phase == "group_retired":
            chains.publish_provider_keyed_group_retired(**arguments)
        child = jobs.get(arguments["coordinator"].id)
        jobs.save(replace(child, events=[replace(child.events[0],
            data={"snapshotId": child.input["scopeSnapshotId"]}), *child.events[1:]]))
        reader = (coordinator.recognize_provider_keyed_destroy_absence if phase == "provider_absent"
                  else coordinator.recognize_provider_keyed_group_retired)
        with pytest.raises(coordinator.ProviderKeyedComprehensiveTeardownAttention):
            reader(parent.id, environment="devtest", state_root=root)
