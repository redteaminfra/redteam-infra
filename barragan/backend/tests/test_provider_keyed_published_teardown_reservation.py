# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private SQLite writer reservation for a completed keyed generation."""

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
import sqlite3
import json

import pytest
from sqlalchemy import text

from app.domain import JobEvent
from app.services import engagement_teardown as teardown
from app.services import provider_keyed_dns_cleanup_manifest
from app.services import provider_keyed_published_teardown_source as published
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import (
    PublishedKeyedTeardownReservationConflict, SqlAlchemyJobRepository, StoredJobRun,
    job_event_digest,
)
from app.storage.models import CoreMutationLeaseModel
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_chain_publication import _case as publication_case
from test_provider_keyed_teardown_quiescence import _completed


def _case(client, monkeypatch, tmp_path):
    chains, jobs, _leases, args = publication_case(client)
    _bootstrap_jobs, bootstrap_parent, workspace, _scope = _completed(tmp_path)
    host_manifest = next(event.data for event in bootstrap_parent.events
                         if event.message == "provider host identity binding intended")
    pending = jobs.save(replace(args["parent"], events=bootstrap_parent.events))
    args.update(parent=pending, manifest=host_manifest,
                manifest_sha256=teardown._fingerprint(host_manifest),
                state_sha256=host_manifest["stateSha256"],
                applied_workspace_path=str(workspace),
                expected_event_digest=job_event_digest(pending.events))
    proof_child = args["proof_child"]
    proof_events = [
        replace(event, data={"manifestSha256": args["manifest_sha256"]})
        if event.sequence in (1, 2) else event
        for event in proof_child.events
    ]
    proof_child = jobs.save(replace(
        proof_child,
        input={**proof_child.input, "manifestSha256": args["manifest_sha256"]},
        events=proof_events,
    ))
    args.update(proof_child=proof_child,
                proof_child_event_digest=job_event_digest(proof_child.events))
    chains.publish_provider_keyed_initial_chains(**args)
    core = jobs.get("job-core")
    jobs.save(replace(core, input={**core.input, "workspaceDir": "/private/tmp/opaque-core"}))
    core = jobs.get("job-core")
    scope = {
        "schema": "provider-keyed-v2", "provider": "digitalocean",
        "coreJobId": core.id, "corePlanId": core.input["corePlanId"],
        "workspace": args["applied_workspace_path"], "stateSha256": args["state_sha256"],
        "sourceRevision": host_manifest["sourceRevision"],
        "providerConnectionId": host_manifest["providerConnectionId"],
        "revisionId": host_manifest["revisionId"], "selectorTag": "opaque-selector",
        "chainIds": core.input["pendingSketchChainIds"],
        "chainFingerprints": core.input["pendingSketchChainFingerprints"],
        "resources": sorted([
            {"address": row["terraformAddress"],
             "id": str(row["providerInstanceId"]), "kind": "droplet"}
            for chain in chains.list_for_engagement(core.input["engagementId"])
            for row in chain.nodes
        ] + [
            {"address": address, "id": "1", "kind": kind}
            for address, kind in (
                ("digitalocean_ssh_key.key", "ssh_key"),
                ("digitalocean_firewall.firewall", "firewall"),
                ("local_file.ansible_inventory[0]", "local_file"),
                ("local_file.ssh_stanza[0]", "local_file"),
            )
        ], key=lambda row: row["address"]),
    }
    from app.services import provider_keyed_teardown_scope
    monkeypatch.setattr(provider_keyed_teardown_scope,
                        "build_digitalocean_keyed_teardown_scope",
                        lambda *_args, **_kwargs: scope)
    from app.services import provider_keyed_dns_cleanup_binding
    initial = jobs.get(args["parent"].id)
    # The shared bootstrap test fixture uses documentation-only 198.51.100/24
    # IPs, while the real binder intentionally accepts only global addresses.
    # Its own tests cover edge parsing; this reservation test keeps that pure
    # proof as a stable seam and exercises the in-writer journal binding.
    binding = SimpleNamespace(
        binding_sha256="a" * 64,
        provider_scope_sha256=teardown._fingerprint({"providerScopes": [scope]}),
        manifest_sha256=args["manifest_sha256"],
        edge_public_ips=("8.8.8.8",),
    )
    monkeypatch.setattr(provider_keyed_dns_cleanup_binding,
                        "bind_provider_keyed_dns_cleanup_targets",
                        lambda *_args, **_kwargs: binding)
    base = {
        "schema": "provider-keyed-dns-cleanup-manifest-v1",
        "engagementId": core.input["engagementId"], "coreJobId": core.id,
        "providerScopeSha256": teardown._fingerprint({"providerScopes": [scope]}),
        "bindingSha256": binding.binding_sha256,
        "initialJobId": args["parent"].id,
        "initialJournalSha256": job_event_digest(initial.events),
        "domainAssignments": [], "domains": [],
    }
    manifest = {**base, "manifestSha256": "sha256:" + teardown._fingerprint(base)}
    preview = teardown._current_scope_snapshot(
        core, jobs=jobs, chains=chains,
        resources=SqlAlchemyProviderResourceRepository(),
        domain_repository=SqlAlchemyDomainRepository(), inspector_state_reader=None,
        reviewed_dns_manifest=manifest,
    )
    source = published.PublishedProviderKeyedSource(
        core.input["engagementId"], core.id, core.input["corePlanId"],
        args["parent"].id, job_event_digest(initial.events), "d" * 64,
        teardown._fingerprint(scope),
        scope["stateSha256"], args["manifest_sha256"], "e" * 64,
        tuple(scope["chainIds"]), "f" * 64,
    )
    audits = []
    def audit(*_args, **_kwargs):
        audits.append("read")
        return source
    monkeypatch.setattr(published, "audit_published_provider_keyed_source", audit)
    from app.services import provider_keyed_dns_cleanup_manifest
    monkeypatch.setattr(provider_keyed_dns_cleanup_manifest,
                        "build_provider_keyed_dns_cleanup_manifest",
                        lambda *_args, **_kwargs: pytest.fail("Namecheap preview ran under SQLite writer"))
    now = datetime.now(timezone.utc).isoformat()
    parent = StoredJobRun(
        id=teardown._parent_id(core.id), action=teardown.ENGAGEMENT_TEARDOWN_ACTION,
        status="queued", target=f"engagement:{core.input['engagementId']}",
        target_type="engagement", target_id=core.input["engagementId"],
        requested_by="operator", input={
            "engagementId": core.input["engagementId"], "coreJobId": core.id,
            "scopeSnapshot": preview, "phase": "queued", "outcomes": {},
            "remainingOwnedResources": [], "mutation": True,
            "confirmation": "redacted",
        }, artifact_refs=[], created_at=now, started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "engagement teardown queued",
                         {"snapshotId": preview["snapshotId"]})],
    )
    return jobs, parent, source, audits


def _sealed_case(client, monkeypatch, tmp_path):
    """Real channel renderer/history/snapshot; upstream source/DNS seam from _case."""
    from app.services.inbound_channel_apply import (
        _resolved_spec_from_channel, render_inbound_apply_workspace, _apply_phase_commands, _phase_command_dict,
    )
    from app.services.inbound_channel_artifacts import render_inbound_channel_artifacts
    from test_provider_keyed_published_initial_cleanup_authority import _job
    jobs, proposal, source, _audits = _case(client, monkeypatch, tmp_path)
    chains = SqlAlchemySketchChainRepository()
    rows = [chains.save(replace(chain, nodes=[{**node, "publicIp": f"11.0.{i}.{n+1}"}
        for n, node in enumerate(chain.nodes)])) for i, chain in enumerate(chains.list_for_engagement(source.engagement_id), 1)]
    proxies = sorted({chain.assigned_proxy for chain in rows})
    connections = [{"role": "homebase", "displayName": "homebase-example", "sshAlias": "homebase-example",
        "publicIp": "12.0.0.1", "privateIp": "192.168.0.10", "sshUser": "user"}] + [
        {"role": "proxy", "displayName": f"{name}-example", "sshAlias": f"{name}-example", "publicIp": f"12.0.0.{i+2}",
         "privateIp": f"192.168.{i+2}.11", "sshUser": "user"} for i,name in enumerate(proxies)]
    core = jobs.get(source.core_job_id)
    core = jobs.save(replace(core, input={**core.input, "engagementName": "example", "proxyCount": len(proxies)},
        created_at="2026-10-20T01:00:00+00:00", started_at="2026-10-20T01:00:00+00:00", finished_at="2026-10-20T01:00:00+00:00",
        events=[*core.events, JobEvent(len(core.events)+1,"info","core connection details",{"connectionDetails":connections})]))
    initial = jobs.get(source.initial_job_id)
    jobs.save(replace(initial, created_at="2026-10-20T02:00:00+00:00", started_at="2026-10-20T02:00:00+00:00", finished_at="2026-10-20T02:00:00+00:00"))
    chain = rows[0]
    middle = next(node for node in chain.nodes if node["role"] == "middle")
    edge = next(node for node in chain.nodes if node["role"] == "edge")
    channel = {"channelId":"attempt", "domain":"example.invalid", "protocol":"HTTP", "mode":"http-openresty",
        "externalPort":"80", "internalPort":"80", "proxy":f"{chain.assigned_proxy}-example", "middle":middle["hostname"],
        "edge":edge["hostname"], "terminatesOn":f"{chain.assigned_proxy}-example", "service":"Static Web",
        "serviceType":"web-static", "serviceId":"web-example", "chainId":chain.chain_id}
    spec, route = _resolved_spec_from_channel("example", {"coreInfrastructure": connections,
        "sketchInfrastructure":[{**node,"chainId":row.chain_id} for row in rows for node in row.nodes]}, channel)
    rendered = render_inbound_apply_workspace(spec, render_inbound_channel_artifacts(spec), route=route,keyed_sketch_policy=True)
    inventory = [getattr(route,role).name for role in ("proxy","middle","edge")]
    attempt = _job("job-attempt","inbound_channel_apply","failed",source.engagement_id,
        inputs={"engagementId":source.engagement_id,"channelId":"attempt","proxyId":route.proxy.name,"mutation":True},events=[
            JobEvent(1,"info","inbound channel apply workspace rendered",{"channelId":"attempt","workspaceDir":"/private/tmp/fixture",
                "resolvedRoute":route.to_dict(),"workspaceEvidence":rendered.to_dict(),"inventoryTargets":inventory,"inboundChannels":[channel]}),
            JobEvent(2,"info","inbound channel Ansible apply started",{"inventoryTargets":inventory,"cwd":"/private/tmp/fixture",
                "commands":[_phase_command_dict(command) for command in _apply_phase_commands("/usr/bin/ansible-playbook",rendered)]}),
            JobEvent(3,"info","keyed channel ingress requires observation",{"errorType":"ValueError"}),
            JobEvent(4,"error","inbound channel provider ingress sync failed",{"channelId":"attempt"})])
    jobs.save(replace(attempt,artifact_refs=[rendered.inventory.target,rendered.ssh_config.target,
        *[play.target for play in rendered.playbooks],rendered.manifest.target]))
    manifest = proposal.input["scopeSnapshot"]["dnsCleanupManifest"]
    monkeypatch.setattr(provider_keyed_dns_cleanup_manifest,"build_provider_keyed_dns_cleanup_manifest",lambda *_a,**_k:manifest)
    snapshot = teardown._current_scope_snapshot(core,jobs=jobs,chains=chains,
        resources=SqlAlchemyProviderResourceRepository(),domain_repository=SqlAlchemyDomainRepository(),inspector_state_reader=None)
    proposal = replace(proposal,input={**proposal.input,"scopeSnapshot":snapshot},events=[
        JobEvent(1,"info","engagement teardown queued",{"snapshotId":snapshot["snapshotId"]})])
    return jobs, proposal, source


def test_real_failed_http_producer_public_start_reserves_exact_sealed_parent(client, monkeypatch, tmp_path):
    """Do not mock public start, parent boundary, reservation, seal or history."""
    from app.services import provider_keyed_published_initial_cleanup_authority as authority
    with client.application.storage_context():
        jobs, proposal, source = _sealed_case(client,monkeypatch,tmp_path)
        scope = proposal.input["scopeSnapshot"]
        assert not teardown._valid_public_targets(scope["publicVerificationTargets"])  # Legacy remains strict.
        assert teardown._parent_boundary_fields(proposal) is not None
        original = json.loads(json.dumps(scope))
        seen=[]
        def coordinator(identifier):
            seen.append(identifier)
            parent=jobs.get(identifier)
            assert parent.status=="queued" and parent.events[0].data==authority.queued_cleanup_event_data(scope)
        saved=teardown.start_engagement_teardown(source.core_job_id,{
            "snapshotId":scope["snapshotId"],"confirmation":scope["confirmationPhrase"]},
            provider_keyed_environment="devtest",provider_keyed_published_source=source,
            provider_keyed_coordinator=coordinator,job_repository=jobs)
        reopened = SqlAlchemyJobRepository().get(saved.id)
        assert reopened.input[authority.MARKER] == authority.seal_marker(scope)
        assert reopened.events[0].data[authority.MARKER] == authority.seal_marker(scope)
        assert scope == original and reopened.input["scopeSnapshot"] == original
        authority.validate_saved_cleanup(reopened,jobs.get(source.core_job_id),scope,jobs)
        assert jobs.reserve_published_keyed_teardown_parent(proposal, reviewed_source=source) == saved
        assert seen == [saved.id]
        assert len([row for row in jobs.list_for_engagement(source.engagement_id)
                    if row.action==teardown.ENGAGEMENT_TEARDOWN_ACTION]) == 1
        lease=db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=source.engagement_id).one()
        assert (lease.owner_id,lease.operation)==(source.core_plan_id,"provider_keyed_teardown_fence")


@pytest.mark.parametrize("drift",["missing_seal","malformed","schema","unknown_group","foreign","omitted","extra",
    "rehashed_target","manifest","provider_scope","source_core"])
def test_sealed_parent_boundary_rejects_forged_target_shapes(client,monkeypatch,tmp_path,drift):
    from app.services import provider_keyed_published_initial_cleanup_authority as authority
    with client.application.storage_context():
        jobs,proposal,source=_sealed_case(client,monkeypatch,tmp_path)
        scope=json.loads(json.dumps(proposal.input["scopeSnapshot"]))
        listener=next(row for row in scope["publicVerificationTargets"] if row["targetGroup"]=="former-public-listener")
        if drift=="missing_seal":scope.pop(authority.KEY)
        elif drift=="malformed":scope[authority.KEY]=None
        elif drift=="schema":scope[authority.KEY]["schema"]="unknown"
        elif drift=="unknown_group":listener["targetGroup"]="unreviewed"
        elif drift in {"foreign","rehashed_target"}:
            listener.update(host="13.0.0.99",id="tcp:13.0.0.99:80")
            if drift=="rehashed_target":
                seal=scope[authority.KEY]
                sealed=next(row for row in seal["publicTargets"]["targets"] if row["targetGroup"]=="former-public-listener")
                sealed.update(listener)
                seal["publicTargets"]["sha256"]=authority.digest({k:v for k,v in seal["publicTargets"].items() if k!="sha256"})
                seal["sha256"]=authority.digest({k:v for k,v in seal.items() if k!="sha256"})
        elif drift=="omitted":scope["publicVerificationTargets"].remove(listener)
        elif drift=="extra":scope["publicVerificationTargets"].append({**listener,"host":"13.0.0.99","id":"tcp:13.0.0.99:80"})
        elif drift=="manifest":scope[authority.KEY]["targetManifest"]["sourceSha256"]="0"*64
        elif drift=="provider_scope":scope[authority.KEY]["source"]["providerScope"]["corePlanId"]="foreign"
        else:scope[authority.KEY]["source"]["core"]["id"]="job-foreign"
        # Even a recomputed outer digest is not source/target authority.
        if type(scope.get(authority.KEY)) is dict:
            seal=scope[authority.KEY];seal["sha256"]=authority.digest({k:v for k,v in seal.items() if k!="sha256"})
        scope["snapshotId"]=teardown._fingerprint({k:v for k,v in scope.items() if k!="snapshotId"})
        forged=replace(proposal,input={**proposal.input,"scopeSnapshot":scope},events=[
            JobEvent(1,"info","engagement teardown queued",{"snapshotId":scope["snapshotId"]})])
        assert teardown._parent_boundary_fields(forged) is None
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_teardown_parent(forged,reviewed_source=source)
        assert jobs.get(proposal.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=source.engagement_id).count()==0


def test_persisted_sealed_parent_cannot_drop_marker_or_listener_targets(client,monkeypatch,tmp_path):
    from app.services import provider_keyed_published_initial_cleanup_authority as authority
    with client.application.storage_context():
        jobs,proposal,source=_sealed_case(client,monkeypatch,tmp_path)
        saved=jobs.reserve_published_keyed_teardown_parent(proposal,reviewed_source=source)
        for drift in ("marker","seal_and_targets"):
            data=json.loads(json.dumps(saved.input))
            data.pop(authority.MARKER)
            if drift=="seal_and_targets":
                data["scopeSnapshot"].pop(authority.KEY)
                data["scopeSnapshot"]["publicVerificationTargets"]=[row for row in data["scopeSnapshot"]["publicVerificationTargets"] if row["port"]==22]
            forged=replace(saved,input=data)
            with pytest.raises(ValueError):
                authority.validate_saved_cleanup(forged,jobs.get(source.core_job_id),data["scopeSnapshot"],jobs)


def test_self_consistent_forged_projection_is_not_writer_authority(client,monkeypatch,tmp_path):
    from app.services import provider_keyed_published_initial_cleanup_authority as authority
    from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
    from app.services.provider_keyed_mixed_public_targets import build_public_target_seal
    with client.application.storage_context():
        jobs,proposal,source=_sealed_case(client,monkeypatch,tmp_path)
        scope=json.loads(json.dumps(proposal.input["scopeSnapshot"]))
        seal=scope[authority.KEY]
        address=seal["attempts"][0]["edge"]["terraformAddress"]
        for chain in seal["source"]["chains"]:
            for node in chain["nodes"]:
                if node["terraformAddress"]==address:node["publicIp"]="13.0.0.99"
        seal["attempts"][0]["edge"]["publicIp"]="13.0.0.99"
        for node in seal["targetManifest"]["edgeTargets"]:
            if node["terraformAddress"]==address:node["publicIp"]="13.0.0.99"
        seal["targetManifest"]["sourceSha256"]=authority.digest(seal["source"])
        routes=tuple(KeyedRouteIntent(**{**row,"public_sources":tuple(row["public_sources"])})
                     for row in seal["publicTargets"]["routeIntents"])
        core_targets=[row for row in seal["publicTargets"]["targets"] if row["targetGroup"]=="core-public-management"]
        seal["publicTargets"]=build_public_target_seal(seal["targetManifest"],core_targets,routes)
        scope["publicVerificationTargets"]=seal["publicTargets"]["targets"]
        seal["sha256"]=authority.digest({k:v for k,v in seal.items() if k!="sha256"})
        scope["snapshotId"]=teardown._fingerprint({k:v for k,v in scope.items() if k!="snapshotId"})
        forged=replace(proposal,input={**proposal.input,"scopeSnapshot":scope},events=[
            JobEvent(1,"info","engagement teardown queued",{"snapshotId":scope["snapshotId"]})])
        assert teardown._parent_boundary_fields(forged) is not None  # Shape is not ownership.
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_teardown_parent(forged,reviewed_source=source)
        assert jobs.get(proposal.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=source.engagement_id).count()==0


def test_writer_reserves_parent_event_and_fence_once_without_dns_get(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, source, audits = _case(client, monkeypatch, tmp_path)
        saved = jobs.reserve_published_keyed_teardown_parent(parent, reviewed_source=source)
        assert saved.status == "queued" and saved.input["publishedSource"]["scope_sha256"] == source.scope_sha256
        assert len(audits) == 2
        lease = db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=parent.target_id).one()
        assert (lease.owner_id, lease.operation) == (source.core_plan_id, "provider_keyed_teardown_fence")
        restarted = SqlAlchemyJobRepository()
        retry = replace(parent, created_at=datetime.now(timezone.utc).isoformat(),
                        requested_by="different-request-body")
        assert restarted.reserve_published_keyed_teardown_parent(retry, reviewed_source=source) == saved
        assert len(jobs.get(parent.id).events) == 1


def test_writer_rolls_back_both_parent_and_fence_on_snapshot_drift(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, source, _audits = _case(client, monkeypatch, tmp_path)
        changed = replace(parent, input={**parent.input,
            "scopeSnapshot": {**parent.input["scopeSnapshot"], "engagementName": "changed"}})
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_teardown_parent(changed, reviewed_source=source)
        assert jobs.get(parent.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=parent.target_id).count() == 0


def test_writer_rejects_competing_lease_without_parent_insert(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, source, _audits = _case(client, monkeypatch, tmp_path)
        SqlAlchemyDeploymentPlanRepository().acquire(parent.target_id, "other", "prepare")
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_teardown_parent(parent, reviewed_source=source)
        assert jobs.get(parent.id) is None


@pytest.mark.parametrize("field", ["initialJournalSha256", "bindingSha256"])
def test_writer_rejects_forged_dns_source_binding(client, monkeypatch, tmp_path, field):
    with client.application.storage_context():
        jobs, parent, source, _audits = _case(client, monkeypatch, tmp_path)
        snapshot = parent.input["scopeSnapshot"]
        manifest = dict(snapshot["dnsCleanupManifest"])
        manifest[field] = "f" * 64
        manifest["manifestSha256"] = "sha256:" + teardown._fingerprint(
            {key: value for key, value in manifest.items() if key != "manifestSha256"})
        changed = {**snapshot, "dnsCleanupManifest": manifest}
        changed["snapshotId"] = teardown._fingerprint(
            {key: value for key, value in changed.items() if key != "snapshotId"})
        proposed = replace(parent, input={**parent.input, "scopeSnapshot": changed},
                           events=[JobEvent(1, "info", "engagement teardown queued",
                                            {"snapshotId": changed["snapshotId"]})])
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_teardown_parent(proposed, reviewed_source=source)
        assert jobs.get(parent.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=parent.target_id).count() == 0


def test_writer_slot_blocks_second_sqlite_connection_during_source_audit(monkeypatch, tmp_path):
    from app import create_app
    from app.core.config import TestConfig

    class FileConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'writer.sqlite'}"

    file_client = create_app(FileConfig).test_client()
    with file_client.application.storage_context():
        jobs, parent, source, _audits = _case(file_client, monkeypatch, tmp_path)
        observed = []
        def second_writer(*_args, **_kwargs):
            with sqlite3.connect(db.engine.url.database, timeout=0.05) as connection:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    connection.execute("UPDATE deployment_plans SET status = status WHERE id = ?",
                                       (source.core_plan_id,))
            observed.append("serialized")
            return source
        monkeypatch.setattr(published, "audit_published_provider_keyed_source", second_writer)
        assert jobs.reserve_published_keyed_teardown_parent(parent, reviewed_source=source)
        assert observed == ["serialized", "serialized"]


def test_default_snapshot_path_still_invokes_manifest_builder(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, _source, _audits = _case(client, monkeypatch, tmp_path)
        manifest = parent.input["scopeSnapshot"]["dnsCleanupManifest"]
        from app.services import provider_keyed_dns_cleanup_manifest
        calls = []
        def builder(*_args, **_kwargs):
            calls.append("build")
            return manifest
        monkeypatch.setattr(provider_keyed_dns_cleanup_manifest,
                            "build_provider_keyed_dns_cleanup_manifest", builder)
        rebuilt = teardown._current_scope_snapshot(
            jobs.get("job-core"), jobs=jobs,
            chains=SqlAlchemySketchChainRepository(),
            resources=SqlAlchemyProviderResourceRepository(),
            domain_repository=SqlAlchemyDomainRepository(), inspector_state_reader=None,
        )
        assert calls == ["build"]
        assert rebuilt == parent.input["scopeSnapshot"]


def test_lease_insert_failure_rolls_back_parent_and_event(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, source, _audits = _case(client, monkeypatch, tmp_path)
        db.session.execute(text("""
            CREATE TRIGGER stop_keyed_fence BEFORE INSERT ON core_mutation_leases
            WHEN NEW.operation = 'provider_keyed_teardown_fence'
            BEGIN SELECT RAISE(ABORT, 'injected fence failure'); END
        """))
        db.session.commit()
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_teardown_parent(parent, reviewed_source=source)
        assert jobs.get(parent.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=parent.target_id).count() == 0


def test_same_id_without_its_fence_requires_recovery(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, source, _audits = _case(client, monkeypatch, tmp_path)
        assert jobs.reserve_published_keyed_teardown_parent(parent, reviewed_source=source)
        db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=parent.target_id).delete()
        db.session.commit()
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            SqlAlchemyJobRepository().reserve_published_keyed_teardown_parent(
                parent, reviewed_source=source)
        assert jobs.get(parent.id).status == "queued"


def test_second_applied_state_audit_drift_rolls_back_reservation(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, parent, source, _audits = _case(client, monkeypatch, tmp_path)
        calls = 0
        def changing_source(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return source if calls == 1 else replace(source, state_sha256="0" * 64)
        monkeypatch.setattr(published, "audit_published_provider_keyed_source", changing_source)
        with pytest.raises(PublishedKeyedTeardownReservationConflict):
            jobs.reserve_published_keyed_teardown_parent(parent, reviewed_source=source)
        assert calls == 2 and jobs.get(parent.id) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=parent.target_id).count() == 0
