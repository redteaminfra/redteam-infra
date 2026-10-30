# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted worker journals feed the existing five-node cleanup coordinator.

Cloud, source-binding and provider-rule witnesses are controlled offline inputs;
worker ordering, SQL checkpoints, exact current state and destroy contracts run.
"""
from contextlib import nullcontext
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import copy
import hashlib
import json
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_failed_second_append as failure
from app.services import provider_keyed_mixed_failed_append_teardown as legacy
from app.services import provider_keyed_mixed_published_teardown_collector as collector
from app.services import provider_keyed_mixed_append_pair_apply_child as first_worker
from app.services import provider_keyed_mixed_append_second_apply_child as second_worker
from app.services import provider_keyed_mixed_append_first_proof_job as proof_worker
from app.services.provider_keyed_mixed_append_first_poststate import FirstPoststateProof
from app.services.provider_keyed_mixed_append_linode_intent import MixedLinodeOnDigitalOceanAppendIntent
from app.services.provider_keyed_linode_initial_plan_gate import LinodeNodeCreate
from app.services.provider_keyed_mixed_append_pair_parent import _parent_id as append_id
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _canonical
from app.services.provider_keyed_mixed_initial_plan_parent import validate_mixed_initial_apply_seal
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_mixed_partial_apply_source import _state, ProviderApplyClassification
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.provider_keyed_gated_runner import CommandIntent, CommandAuditResult, CommandResult, StartedCommand, ProcessIdentity
from app.services.provider_keyed_mixed_published_teardown_checkpoint import propose_published_mixed_initial_cleanup, saved_published_mixed_initial_review
from app.services.provider_keyed_mixed_published_teardown_authority import published_review_states, published_review_policy
from app.services.provider_keyed_mixed_published_destroy_source import attest_published_mixed_destroy_show
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_reservation import _persisted, _attested_plans
from test_provider_keyed_mixed_failed_append_workflow import _history


def _write(path, blob):
    path.write_bytes(blob)
    path.chmod(0o600)


def _fixture(ready, tmp_path, monkeypatch, *, core_placeholder=False):
    if core_placeholder:
        from app.domain import JobEvent
        from app.integrations.pilot_standard_rti import pilot_channel_rows, pilot_names
        core = ready.case.jobs.get("job-core")
        core = replace(core, input={**core.input, "proxyCount": 1, "deploymentMode": "hold_for_review"})
        rows = pilot_channel_rows(pilot_names(core.input["engagementName"]), region=core.input["target"]["region"], proxy_count=1)
        events = list(core.events)
        for message in ("core infrastructure deployed; preparing continuous Inspector",
                        "operator inspection ready", "pilot Standard RTI run finished"):
            events.append(JobEvent(len(events) + 1, "info", message, copy.deepcopy(rows)))
        events[-1] = replace(events[-1], data={**events[-1].data, "ok": True, "mutationStatus": "deployed",
            "ansibleStatus": "validated", "finalCleanupStatus": "pending_operator_teardown"})
        core = replace(core, events=events)
        ready.case.jobs.save(core)
        ready.case.records["core_job"] = core
        ready.case.records["core_plan"].evidence["proxyCount"] = 1
    from test_provider_keyed_mixed_failed_second_append import _ACTUAL_CHECKS
    import test_provider_keyed_mixed_initial_host_binding as host_fixture
    original_state = host_fixture._state
    def initial_state(parent, provider, number):
        raw, cloud, nodes = original_state(parent, provider, number)
        if provider == "digitalocean":
            parsed = json.loads(raw)
            parsed["check_results"] = copy.deepcopy(_ACTUAL_CHECKS["predecessorChecks"])
            raw = json.dumps(parsed).encode()
        return raw, cloud, nodes
    # Add actual records before the historical publication receipts are minted.
    monkeypatch.setattr(host_fixture, "_state", initial_state)
    jobs, original, _ = _persisted(ready, tmp_path, monkeypatch)
    source = original.review.source
    initial = jobs.get(source.parent_job_id)
    policies = validate_mixed_initial_apply_seal(initial)["reviewedPolicy"]
    raw_before = {p: original.observations[p].state_json for p in source.ordered_providers}
    parsed = {p: json.loads(raw) for p, raw in raw_before.items()}
    actual = {p: _state_resources(raw) for p, raw in parsed.items()}
    address = 'linode_instance.edge["append"]'
    old_node = next(row for key, row in policies["linode"]["nodes"].items() if ".edge[" in key)
    node = LinodeNodeCreate("edge02-opaque", old_node["image"], old_node["node_type"], old_node["region"], old_node["tag"], tuple(old_node["authorized_keys"]))
    intent = MixedLinodeOnDigitalOceanAppendIntent(source.engagement_id, source.core_job_id,
        source.chain_ids[source.ordered_providers.index("digitalocean")], "digitalocean_droplet.middle", "retained",
        hashlib.sha256(raw_before["digitalocean"]).hexdigest(), hashlib.sha256(raw_before["linode"]).hexdigest(),
        tuple((a, str(row["id"])) for a, row in sorted(actual["digitalocean"].items())),
        tuple((a, str(row["id"])) for a, row in sorted(actual["linode"].items())),
        ("1.1.1.1/32",), ("1.1.1.1/32",), address, node, 2, policies["linode"]["nonsecret_varfile"])
    post = copy.deepcopy(parsed)
    for provider in post:
        post[provider]["serial"] += 4
        post[provider]["resources"] = [row for row in post[provider]["resources"] if row["type"] != "local_file"]
    edge = next(row for row in post["linode"]["resources"] if row["type"] == "linode_instance" and row["name"] == "edge")
    new = copy.deepcopy(edge["instances"][0])
    new["index_key"] = "append"
    new["attributes"].update(id=999999, label=node.label, ipv4=["45.33.62.72"], ip_address="45.33.62.72")
    edge["instances"].append(new)
    # Real failed-second check records: all nine predecessor/plan checks pass;
    # current retains eight pass rows and the exact incomplete firewall record.
    post["digitalocean"]["check_results"] = copy.deepcopy(_ACTUAL_CHECKS["currentChecks"])
    post_raw = {p: json.dumps(raw).encode() for p, raw in post.items()}
    workspaces, plan_hashes = {}, {}
    binary = tmp_path / "terraform-fixture"
    binary.write_bytes(b"reviewed binary")
    binary.chmod(0o755)
    release = SimpleNamespace(path=binary, sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    for provider, root in original.workspaces.items():
        workspaces[provider] = ProviderKeyedWorkspace(root, root / "terraform.tfstate", root / ".terraform-data",
            "provider-keyed-v2", provider, policies[provider]["provider_connection_id"], "fixture", "revision", "a" * 64)
        _write(root / _name(provider, "predecessor.tfstate"), raw_before[provider])
        _write(root / _name(provider, "saved.tfplan"), provider.encode())
        plan_hashes[provider] = hashlib.sha256(provider.encode()).hexdigest()
        _write(root / ".barragan-topology.json", b'{}')
        _write(root / ".barragan-apply-phase.json", b'{"schema":"provider-keyed-v2","phase":"applied"}')
    parent = jobs.save(replace(initial, id=append_id(source.core_job_id), action="provider_keyed_mixed_append",
        status="running", finished_at=None, events=[], input={"schema": "mixed-append-pair-parent-v1",
        "phase": "apply_sealed", "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
        "corePlanId": source.core_plan_id, "providerOrder": ["linode", "digitalocean"], "reviewSha256": "a" * 64,
        "historicalRowsSha256": original.review.historical_rows_sha256,
        "liveBindingsSha256": "pending"}))
    from app.services.provider_keyed_mixed_append_live_bindings import collect_mixed_append_live_bindings
    parent = jobs.save(replace(parent, input={**parent.input, "liveBindingsSha256": _canonical({
        "schema": "mixed-append-live-bindings-v1", "bindings": collect_mixed_append_live_bindings(source.engagement_id, job_repository=jobs)})}))
    db.session.add(CoreMutationLeaseModel(engagement_id=source.engagement_id, owner_id=source.core_plan_id,
                                        operation="provider_keyed_mixed_append"))
    db.session.commit()
    calls = []
    def gate(provider, code):
        def invoke(command, **kwargs):
            calls.append(provider)
            intended = CommandIntent(provider, str(workspaces[provider].path), hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest())
            kwargs["intent_callback"](intended)
            started = StartedCommand(intended, ProcessIdentity("11111111-1111-4111-8111-111111111111", 123, 123, 99))
            kwargs["started_callback"](started)
            _write(workspaces[provider].state_path, post_raw[provider])
            kwargs["result_callback"](CommandAuditResult(started, code, 0, 0, False, False))
            return CommandResult(started, code, "", "", False, False)
        return invoke
    def mark(phase):
        return lambda workspace: _write(workspace.path / ".barragan-apply-phase.json", json.dumps({"schema":"provider-keyed-v2", "phase":phase}).encode())
    for module in (first_worker, second_worker):
        monkeypatch.setattr(module, "mark_provider_keyed_apply_started", mark("apply_started"))
        monkeypatch.setattr(module, "mark_provider_keyed_applied", mark("applied"))
    lookup = lambda _: (source.core_plan_id, "provider_keyed_mixed_append")
    first_source = first_worker.FirstApplySource(workspaces["linode"], hashlib.sha256(raw_before["linode"]).hexdigest(), plan_hashes["linode"], release.sha256, lambda: None)
    first_worker.run_first_mixed_append_provider_apply(parent.id, environment="devtest", job_repository=jobs,
        lease_lookup=lookup, source_session=lambda *_: nullcontext(first_source), pair_preflight=lambda *_: "a" * 64,
        pre_go_check=lambda *_: "a" * 64, release_check=lambda **_: release,
        gated_command_runner=gate("linode", 0), command_environment={})
    receipt = {"provider":"linode", "engagementId":source.engagement_id, "coreJobId":source.core_job_id,
               "planSha256":plan_hashes["linode"], "terraformBinarySha256":release.sha256,
               "predecessorStateSha256":hashlib.sha256(raw_before["linode"]).hexdigest()}
    approved = proof_worker._ApprovedFirstSource(workspaces["linode"], intent, receipt, "b" * 64, raw_before["linode"], b'{}')
    ids = tuple((a, str(row["id"])) for a,row in sorted(_state_resources(post["linode"]).items()))
    nodes = tuple(sorted(identifier for a,identifier in ids if a.startswith("linode_instance.")))
    proof = FirstPoststateProof("linode", hashlib.sha256(post_raw["linode"]).hexdigest(), post["linode"]["lineage"],
        post["linode"]["serial"], ids, address, "999999", "45.33.62.72", "c" * 64, "d" * 64, None, nodes)
    first_claim = jobs.get(first_worker._child_id(parent.id)).input
    proof_worker.prove_and_finish_first_mixed_append_apply(parent.id, environment="devtest", job_repository=jobs,
        claim_owner=first_claim["claimOwner"], claim_token=first_claim["claimToken"],
        lease_lookup=lookup, process_quiescent=lambda _:True, source_loader=lambda *_: approved,
        poststate_observer=lambda **_: proof)
    second_source = second_worker.SecondApplySource(workspaces["digitalocean"], hashlib.sha256(raw_before["digitalocean"]).hexdigest(), plan_hashes["digitalocean"], release.sha256, lambda:None)
    second_options = dict(environment="devtest", job_repository=jobs, lease_lookup=lookup,
        source_session=lambda *_: nullcontext(second_source), first_terminal_proof=lambda *_: job_event_digest(jobs.get(first_worker._child_id(parent.id)).events),
        second_preflight=lambda *_:"a" * 64, pre_go_check=lambda *_:"a" * 64,
        release_check=lambda **_:release, gated_command_runner=gate("digitalocean",1), command_environment={})
    with pytest.raises(second_worker.MixedAppendSecondApplyAttention):
        second_worker.run_second_mixed_append_provider_apply(parent.id, **second_options)
    # Only the reader clock advances; retained worker rows/journals stay untouched.
    class Expired(datetime):
        @classmethod
        def now(cls, tz=None): return datetime.now(timezone.utc) + timedelta(days=1)
    monkeypatch.setattr(failure,"datetime",Expired)
    monkeypatch.setattr(failure,"_load_approved_first_source",lambda *_:approved)
    shown = json.dumps({"checks": _ACTUAL_CHECKS["planChecks"], "resource_changes":[{"address":a,"change":{"actions":["delete"]}} for a in legacy._LOCAL]}).encode()
    second_approved = SimpleNamespace(predecessor_state=raw_before["digitalocean"], reviewed_show_json=shown)
    monkeypatch.setattr(failure,"_approved_second",lambda *_:second_approved)
    original_journals = failure.prove_second_failure_journals
    monkeypatch.setattr(failure,"prove_second_failure_journals",lambda p,j,**kwargs:original_journals(p,j,release_check=lambda **_:release,process_quiescent=kwargs.get("process_quiescent",lambda *_:True)))
    monkeypatch.setattr(legacy,"immutable_failure_evidence",lambda *_a,**_k:{"witness":"separately-tested-artifacts"})
    observed = {}
    current = failure.current_policies(initial,approved)
    for provider, raw in post_raw.items():
        state, _, cloud = _state(provider,current[provider],raw)
        observed[provider] = ProviderHostObservation(ProviderApplyClassification(provider,"full",hashlib.sha256(raw).hexdigest(),state["lineage"],state["serial"],tuple(sorted(cloud.items()))),raw)
    from app.services.provider_keyed_mixed_partial_apply_inventory import MixedPartialApplyInventorySnapshot
    snapshots = {}
    for provider, raw in post_raw.items():
        _, resources, cloud = _state(provider, current[provider], raw)
        inventory = []
        for resource_address, identifier in cloud.items():
            attributes = resources[resource_address]
            kind = "node" if resource_address in current[provider]["nodes"] else "ssh_key" if resource_address == "digitalocean_ssh_key.key" else "firewall"
            row = {"kind": kind, "id": identifier, "name": attributes.get("label" if provider == "linode" else "name"), "tags": attributes.get("tags", [])}
            if kind == "ssh_key": row["public_key"] = attributes["public_key"]
            inventory.append(row)
        members = tuple(sorted(cloud[key] for key in current[provider]["nodes"]))
        snapshots[provider] = MixedPartialApplyInventorySnapshot(provider, raw, hashlib.sha256(raw).hexdigest(),
            "applied" if provider == "linode" else "apply_started", tuple(inventory),
            members if provider == "linode" else None, True if provider == "digitalocean" else None,
            len(members) if provider == "digitalocean" else None, members if provider == "digitalocean" else None, "e" * 64)
    original_fresh = legacy.fresh_failed_append_observation
    monkeypatch.setattr(legacy,"fresh_failed_append_observation",lambda *args, **kwargs:original_fresh(*args, **kwargs,
        snapshot_reader=lambda _i,p,*a,**k:snapshots[p]))
    monkeypatch.setattr(failure,"prove_first_mixed_append_poststate", lambda **kwargs: proof)
    monkeypatch.setattr(failure,"_process_quiescent", lambda *_: True)
    monkeypatch.setattr(failure,"require_current_keyed_firewall", lambda p, policy, resources, **kwargs: None)
    monkeypatch.setattr(collector,"active_core_connection_details",lambda *_:(source.core_job_id,[]))
    monkeypatch.setattr(collector,"_core_inspector_scope",lambda *_a,**_k:original.core_inspector_scope)
    collection = collector.collect_published_mixed_initial_teardown(source.engagement_id,source.core_job_id,job_repository=jobs)
    return jobs, collection, calls, second_options, snapshots


def test_actual_workers_to_five_node_preview_start_seal_and_restart(client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, calls, second_options, snapshots = _fixture(ready,tmp_path,monkeypatch)
        review=collection.review
        assert review.failed_append_recovery["kind"] == "failed-second-v1"
        assert len(review.source.host_rows)==4
        assert sum(len(policy["nodes"]) for policy in review.failed_append_recovery["currentPolicies"].values())==5
        queued=propose_published_mixed_initial_cleanup(review,collection.core_inspector_scope,"Opaque",requested_by="operator")
        parent=jobs.reserve_published_mixed_initial_cleanup_parent(queued,collection=collection,expected_snapshot_id=queued.input["reviewSnapshotId"])
        assert saved_published_mixed_initial_review(parent)==review
        plans,states,paths,binary,shows=_attested_plans(jobs,collection,tmp_path,with_shows=True)
        sealed=jobs.seal_published_mixed_initial_destroy_plans(parent,collection=collection,plan_set=plans,before_states=states)
        assert saved_published_mixed_initial_review(sealed)==review
        assert _history(review,jobs)==review.historical_rows_sha256
        # Both selected destroys attest the current five-node scope, not the historical four IDs.
        from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
        initial = jobs.get(review.source.parent_job_id)
        for provider in review.source.ordered_providers:
            plan = attest_published_mixed_destroy_show(initial, sealed, review, plans, provider, states[provider],
                collection.core_inspector_scope, "Opaque", fence=lambda:"stable", show_runner=lambda command,cwd:shows[provider],
                release_validator=lambda:ProviderKeyedTerraformRelease(binary,hashlib.sha256(binary.read_bytes()).hexdigest(),"1.15.5","linux_amd64"))
            assert dict(plan.resource_ids) == {row["address"]: row["id"] for row in review.provider_scopes[review.source.ordered_providers.index(provider)]["resources"]}
        assert calls==["linode","digitalocean"]
        append=jobs.get(review.failed_append_recovery["appendParentId"])
        with pytest.raises(second_worker.MixedAppendSecondApplyAttention):
            second_worker.run_second_mixed_append_provider_apply(append.id,**second_options)
        assert calls==["linode","digitalocean"]


def test_five_node_saved_review_after_first_absence_attests_second_without_reopening_first(client,ready,tmp_path,monkeypatch):
    from app.services.provider_keyed_mixed_published_absence import prove_published_mixed_provider_absence, propose_published_mixed_first_absence_event
    from app.services.provider_keyed_mixed_published_second_transition import review_published_mixed_second_transition
    from test_provider_keyed_mixed_published_absence import _awaiting, _empty_snapshot
    with client.application.storage_context():
        jobs,collection,calls,options,snapshots=_fixture(ready,tmp_path,monkeypatch)
        review=collection.review
        proposal=propose_published_mixed_initial_cleanup(review,collection.core_inspector_scope,"Opaque",requested_by="operator")
        parent=jobs.reserve_published_mixed_initial_cleanup_parent(proposal,collection=collection,expected_snapshot_id=proposal.input["reviewSnapshotId"])
        plans,states,*_=_attested_plans(jobs,collection,tmp_path)
        parent=jobs.seal_published_mixed_initial_destroy_plans(parent,collection=collection,plan_set=plans,before_states=states)
        initial=jobs.get(review.source.parent_job_id)
        first,second=review.source.ordered_providers
        child=_awaiting(parent,review,plans,collection.core_inspector_scope,first)
        from test_provider_keyed_mixed_interrupted_source import _snapshot
        generation=f"{parent.id}:{plans.plan_set_sha256}"
        empty=_empty_snapshot(plans.plans[0])
        snapshot=_snapshot(first,tag=first=="digitalocean",phase="destroy_applied",state=empty.state_json,generation=generation)
        receipt=prove_published_mixed_provider_absence(initial,parent,review,plans,first,child,snapshot,
            collection.core_inspector_scope,"Opaque",fence=lambda:generation,process_quiescent=lambda _:True)
        child=jobs.save(replace(child,status="succeeded",finished_at=child.started_at,events=[*child.events,propose_published_mixed_first_absence_event(child,receipt)]))
        _write(collection.workspaces[first]/"terraform.tfstate",snapshot.state_json)
        _write(collection.workspaces[first]/".barragan-apply-phase.json",b'{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
        reopened=saved_published_mixed_initial_review(jobs.get(parent.id))
        assert reopened==review
        assert _history(reopened,jobs)==review.historical_rows_sha256
        # The real remaining-provider observation supports either initial cleanup order.
        workspace=SimpleNamespace(path=collection.workspaces[second],state_path=collection.workspaces[second]/"terraform.tfstate")
        observed=legacy.fresh_failed_append_observation(initial,jobs.get(review.failed_append_recovery["appendParentId"]),second,workspace,
            fence=lambda:generation,jobs=jobs)
        import app.services.provider_keyed_mixed_published_post_first_collector as post_collector
        monkeypatch.setattr(post_collector,"active_core_connection_details",lambda *_:(review.source.core_job_id,[]))
        monkeypatch.setattr(post_collector,"_core_inspector_scope",lambda *_a,**_k:collection.core_inspector_scope)
        monkeypatch.setattr(post_collector,"collect_provider_inventory_snapshot",lambda *_a,**_k:snapshot)
        fresh=post_collector.collect_published_mixed_post_first_transition(parent.id,job_repository=jobs,process_quiescent=lambda _:True)
        assert fresh.review==reopened and fresh.second_observation==observed
        transition=review_published_mixed_second_transition(initial,parent,reopened,plans,child,snapshot,observed,
            collection.core_inspector_scope,"Opaque",fence=lambda:generation,process_quiescent=lambda _:True,
            historical_source_unchanged=lambda:_history(reopened,jobs)==review.historical_rows_sha256,
            fresh_core_inspector_scope=lambda:collection.core_inspector_scope,
            fresh_empty_bindings=lambda:{kind:() for kind in ("channels","domains","certificates","sites")})
        assert transition.second_state_sha256==plans.plans[1].before_state_sha256
        _write(collection.workspaces[second]/"terraform.tfstate",_empty_snapshot(plans.plans[1]).state_json)
        _write(collection.workspaces[second]/".barragan-apply-phase.json",b'{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
        assert _history(reopened,jobs)==review.historical_rows_sha256
        assert calls==["linode","digitalocean"]


@pytest.mark.parametrize("drift",["extra-owned-node","missing-key","changed-key","selector-extra","selector-duplicate","bad-snapshot-hash","state-policy","history-policy","history-identity","active-chain-history","aliased-chain-history"])
def test_five_node_source_rejects_changed_cloud_policy_history_and_selector(client,ready,tmp_path,monkeypatch,drift):
    from app.services.provider_keyed_mixed_published_teardown_collector import PublishedMixedTeardownCollectionAttention
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
    with client.application.storage_context():
        jobs,collection,calls,options,snapshots=_fixture(ready,tmp_path,monkeypatch)
        review=collection.review
        snapshot=snapshots["digitalocean"]
        rows=list(snapshot.inventory)
        if drift=="extra-owned-node": rows.append({**next(row for row in rows if row["kind"]=="node"),"id":"untracked"})
        elif drift=="missing-key": rows=[row for row in rows if row["kind"]!="ssh_key"]
        elif drift=="changed-key": rows=[{**row,"public_key":"changed"} if row["kind"]=="ssh_key" else row for row in rows]
        elif drift=="selector-extra": snapshots["digitalocean"]=replace(snapshot,selector_attached_node_ids=(*snapshot.selector_attached_node_ids,"untracked"),selector_resources_count=3)
        elif drift=="selector-duplicate": snapshots["digitalocean"]=replace(snapshot,selector_attached_node_ids=(*snapshot.selector_attached_node_ids,snapshot.selector_attached_node_ids[0]))
        elif drift=="bad-snapshot-hash": snapshots["digitalocean"]=replace(snapshot,state_sha256="0"*64)
        elif drift=="state-policy":
            raw=json.loads(snapshot.state_json)
            node=next(row for row in raw["resources"] if row["type"]=="digitalocean_droplet")
            node["instances"][0]["attributes"]["size"]="changed"
            blob=json.dumps(raw).encode()
            _write(collection.workspaces["digitalocean"]/"terraform.tfstate",blob)
            snapshots["digitalocean"]=replace(snapshot,state_json=blob,state_sha256=hashlib.sha256(blob).hexdigest())
        elif drift.startswith("history-"):
            saved=copy.deepcopy(review.failed_append_recovery)
            if drift=="history-policy": saved["currentPolicies"]["linode"]["nodes"][next(iter(saved["currentPolicies"]["linode"]["nodes"]))]["label"]="changed"
            else: saved["currentResourceIds"]["linode"][next(iter(saved["currentResourceIds"]["linode"]))]="changed"
            with pytest.raises(ValueError): failure.second_failure_history(replace(review,failed_append_recovery=saved),jobs=jobs,workspaces={},initial=jobs.get(review.source.parent_job_id))
            return
        else:
            from app.services.provider_keyed_mixed_published_teardown_authority import historical_published_mixed_rows_sha256
            if drift=="active-chain-history":
                repo=SqlAlchemySketchChainRepository()
                ghost=next(row for row in repo.list_for_engagement(review.source.engagement_id) if row.status=="aborted")
                repo.save(replace(ghost,status="pending"))
                with pytest.raises(ValueError): _history(review,jobs)
            else:
                # The canonical selection helper must never repair aliased mapping keys.
                from app.services.provider_keyed_mixed_published_teardown_authority import historical_published_mixed_rows_sha256 as history
                from test_provider_keyed_mixed_published_teardown_authority import _case
                # Direct mapping rejection happens before optional recovery artifacts.
                initial=jobs.get(review.source.parent_job_id)
                from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
                with pytest.raises(ValueError):
                    history(parent=initial,core=initial,plan=SqlAlchemyDeploymentPlanRepository().get(review.source.core_plan_id),binding=initial,bootstrap=initial,
                        proof_child=initial,apply_children={},chains={"alias":SimpleNamespace(chain_id="real")})
            return
        if drift in {"extra-owned-node","missing-key","changed-key"}: snapshots["digitalocean"]=replace(snapshot,inventory=tuple(rows))
        with pytest.raises(PublishedMixedTeardownCollectionAttention):
            collector.collect_published_mixed_initial_teardown(review.source.engagement_id,review.source.core_job_id,job_repository=jobs)
        assert calls==["linode","digitalocean"]


def test_public_preview_start_and_existing_coordinator_resume_without_first_go_replay(client,ready,tmp_path,monkeypatch):
    from app.services.provider_keyed_mixed_published_dispatch import preview_published_mixed_cleanup,start_published_mixed_cleanup
    from app.services.provider_keyed_mixed_published_public import advance_published_mixed_cleanup,PublishedMixedPublicAttention
    from app.services.provider_keyed_mixed_published_absence import prove_published_mixed_provider_absence,propose_published_mixed_first_absence_event,propose_published_mixed_second_absence_event
    from app.services.provider_keyed_mixed_published_destroy_child import child_id
    from test_provider_keyed_mixed_published_absence import _awaiting,_empty_snapshot
    with client.application.storage_context():
        jobs,collection,calls,options,snapshots=_fixture(ready,tmp_path,monkeypatch,core_placeholder=True)
        review=collection.review
        core=jobs.get(review.source.core_job_id)
        from app.services.provider_keyed_mixed_append_live_bindings import collect_mixed_append_live_bindings
        retained_bindings = collect_mixed_append_live_bindings(review.source.engagement_id, job_repository=jobs)
        retained_hash = jobs.get(append_id(core.id)).input["liveBindingsSha256"]
        assert len(retained_bindings["channels"]) == 1
        assert retained_hash == _canonical({"schema": "mixed-append-live-bindings-v1", "bindings": retained_bindings})
        initial=jobs.get(review.source.parent_job_id)
        lookup=lambda _: (review.source.core_plan_id,"provider_keyed_mixed_append")
        collect=lambda *_a,**_k:collection
        preview=preview_published_mixed_cleanup(core,environment="devtest",job_repository=jobs,lease_lookup=lookup,collector=collect)
        assert preview["startAvailable"] and not preview["blockers"]
        parent=start_published_mixed_cleanup(core,{"snapshotId":preview["snapshotId"],"confirmation":preview["confirmationPhrase"]},
            environment="devtest",job_repository=jobs,lease_lookup=lookup,collector=collect)
        plans,states,*_=_attested_plans(jobs,collection,tmp_path)
        parent=jobs.seal_published_mixed_initial_destroy_plans(parent,collection=collection,plan_set=plans,before_states=states)
        order=review.source.ordered_providers
        progress=[]
        receipts={}
        interrupted=[True]
        def run(index):
            def step(*args,**kwargs):
                if index==1 and interrupted[0]:
                    interrupted[0]=False
                    raise RuntimeError("diagnostic stop after persisted first absence")
                provider=order[index]
                progress.append(provider+":GO")
                prior=jobs.get(child_id(review.source.core_job_id,order[0])).events[-1].data["receiptSha256"] if index else None
                return jobs.save(_awaiting(parent,review,plans,collection.core_inspector_scope,provider,prior=prior,engagement_name=parent.input["engagementName"]))
            return step
        def absent(index):
            def step(*args,**kwargs):
                provider=order[index]
                child=jobs.get(child_id(review.source.core_job_id,provider))
                snapshot=_empty_snapshot(plans.plans[index])
                prior=jobs.get(child_id(review.source.core_job_id,order[0])).events[-1].data["receiptSha256"] if index else None
                receipt=prove_published_mixed_provider_absence(initial,parent,review,plans,provider,child,snapshot,
                    collection.core_inspector_scope,parent.input["engagementName"],fence=lambda:"stable",process_quiescent=lambda _:True)
                receipts[provider]=receipt
                event=(propose_published_mixed_first_absence_event(child,receipt) if index==0 else
                       propose_published_mixed_second_absence_event(child,receipt,receipts[order[0]]))
                result=jobs.save(replace(child,status="succeeded",finished_at=child.started_at,events=[*child.events,event]))
                _write(collection.workspaces[provider]/"terraform.tfstate",snapshot.state_json)
                _write(collection.workspaces[provider]/".barragan-apply-phase.json",b'{"schema":"provider-keyed-v2","phase":"destroy_applied"}')
                progress.append(provider+":absent")
                return result
            return step
        def tail(name):
            def step(*args,**kwargs):
                assert _history(review,jobs)==review.historical_rows_sha256
                assert all(json.loads((root/"terraform.tfstate").read_bytes())["resources"]==[] for root in collection.workspaces.values())
                targets=failure.extend_retired_targets([],parent)
                assert targets[0]["host"]=="45.33.62.72"
                progress.append(name)
                return SimpleNamespace(status="succeeded")
            return step
        driver=dict(environment="devtest",positive_control_ipv4="1.1.1.1",job_repository=jobs,
            lease_lookup=lambda _:(review.source.core_plan_id,"provider_keyed_teardown_fence"),
            plan_worker=lambda *_a,**_k:jobs.get(parent.id),first_runner=run(0),first_absence=absent(0),
            second_runner=run(1),second_absence=absent(1),oci_tail=tail("OCI"),inspector_tail=tail("Inspector+selector"),terminal=tail("terminal"))
        with pytest.raises(PublishedMixedPublicAttention):advance_published_mixed_cleanup(parent.id,**driver)
        assert progress==[order[0]+":GO",order[0]+":absent"]
        result=advance_published_mixed_cleanup(parent.id,**driver)
        assert result.status=="succeeded"
        assert progress==[order[0]+":GO",order[0]+":absent",order[1]+":GO",order[1]+":absent","OCI","Inspector+selector","terminal"]
        assert calls==["linode","digitalocean"]
        assert jobs.get(append_id(core.id)).input["liveBindingsSha256"] == retained_hash
        assert collect_mixed_append_live_bindings(review.source.engagement_id, job_repository=jobs) == retained_bindings


def test_stopped_failure_label_uses_only_exact_journals_claims_and_processes(client,ready,tmp_path,monkeypatch):
    with client.application.storage_context():
        jobs,collection,calls,options,snapshots=_fixture(ready,tmp_path,monkeypatch)
        parent=jobs.get(collection.review.failed_append_recovery["appendParentId"])
        monkeypatch.setattr(failure,"_load_approved_first_source",lambda *_:pytest.fail("status must not reopen artifacts"))
        monkeypatch.setattr(failure,"_approved_second",lambda *_:pytest.fail("status must not reopen artifacts"))
        assert failure.stopped_second_failure_attention(parent,jobs,process_quiescent=lambda *_:True)
        assert not failure.stopped_second_failure_attention(parent,jobs,process_quiescent=lambda *_:False)
        second=jobs.get(second_worker._child_id(parent.id))
        originals={first_worker._child_id(parent.id):jobs.get(first_worker._child_id(parent.id)),second.id:second}
        for drift in ("live-claim","result","process","first-hash","owner"):
            rows=dict(originals)
            if drift=="live-claim":rows[second.id]=replace(second,input={**second.input,"claimExpiresAt":(datetime.now(timezone.utc)+timedelta(days=2)).isoformat()})
            elif drift=="owner":rows[second.id]=replace(second,input={**second.input,"claimOwner":"unrecognized"})
            elif drift=="first-hash":
                first=rows[first_worker._child_id(parent.id)]
                rows[first.id]=replace(first,events=[*first.events[:-1],replace(first.events[-1],data={"proofJournalSha256":"0"*64})])
            else:
                index=5 if drift=="result" else 3
                events=list(second.events)
                events[index]=replace(events[index],data={**events[index].data,**({"returnCode":0} if drift=="result" else {"pid":True})})
                rows[second.id]=replace(second,events=events)
            fake=SimpleNamespace(get=lambda identifier:rows.get(identifier))
            assert not failure.stopped_second_failure_attention(parent,fake,process_quiescent=lambda *_:True)
        assert calls==["linode","digitalocean"]


@pytest.mark.parametrize("source_drift", [False, True])
def test_real_published_plan_worker_uses_current_five_node_policy_and_seals_once(client, ready, tmp_path, monkeypatch, source_drift):
    from pathlib import Path
    from app.services import provider_keyed_mixed_published_plan_worker as worker
    from app.services import provider_keyed_mixed_interrupted_plan_worker as producer
    from app.services.provider_keyed_mixed_published_destroy_plan import bind_published_mixed_initial_destroy_plans
    from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import saved_published_mixed_destroy_plans
    from app.services.provider_keyed_mixed_published_destroy_source import attest_published_mixed_destroy_show
    with client.application.storage_context():
        jobs, collection, apply_calls, _, _ = _fixture(ready, tmp_path, monkeypatch, core_placeholder=True)
        review = collection.review
        initial = jobs.get(review.source.parent_job_id)
        proposal = propose_published_mixed_initial_cleanup(review, collection.core_inspector_scope, "Opaque", requested_by="operator")
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(proposal, collection=collection,
            expected_snapshot_id=proposal.input["reviewSnapshotId"])
        _, states, paths, binary, shows = _attested_plans(jobs, collection, tmp_path, with_shows=True)
        for path in paths.values():
            path.unlink()  # Only real gated plan callbacks below produce the candidate plans.
        release = ProviderKeyedTerraformRelease(binary, hashlib.sha256(binary.read_bytes()).hexdigest(), "1.15.5", "linux_amd64")
        monkeypatch.setattr(worker, "_default_state_root", lambda: ready.case.state_root)
        monkeypatch.setattr(worker, "DEFAULT_TERRAFORM_STATE_ROOT", tmp_path / "oci")
        monkeypatch.setattr(worker, "_workspace", lambda _initial, provider, _root:
            SimpleNamespace(path=collection.workspaces[provider], state_path=collection.workspaces[provider] / "terraform.tfstate",
                            terraform_data_dir=collection.workspaces[provider] / ".terraform-data"))
        checks, commands, changed = [], [], [False]
        def source_gate(workspace):
            checks.append(workspace.path)
            if changed[0]: raise ValueError("rendered source changed")
        monkeypatch.setattr(producer, "require_linode_workspace", source_gate)
        monkeypatch.setattr(producer, "require_do_workspace", source_gate)
        monkeypatch.setattr(producer, "_credential", lambda *_: "offline-token")
        key = validate_mixed_initial_apply_seal(initial)["reviewedPolicy"]["linode"]["admin_public_key"]
        monkeypatch.setattr(producer, "retrieve_sketch_ssh_key", lambda *_: SimpleNamespace(public_key=key, private_key="offline-key"))
        for root in collection.workspaces.values():
            (root / ".terraform-data").mkdir(exist_ok=True)
        def bind(*args, **kwargs):
            return bind_published_mixed_initial_destroy_plans(*args, **kwargs,
                release_validator=lambda: release,
                show_runner=lambda command, cwd: shows[next(p for p, path in paths.items() if path == Path(command[-1]))])
        monkeypatch.setattr(worker, "bind_published_mixed_initial_destroy_plans", bind)
        def gated(argv, **kwargs):
            provider = next(p for p, root in collection.workspaces.items() if root == Path(kwargs["scratch_path"]))
            phase = argv[1]
            commands.append((provider, phase))
            intent = CommandIntent(str(len(commands)), str(kwargs["scratch_path"]), hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest())
            kwargs["intent_callback"](intent)
            started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 1))
            kwargs["started_callback"](started)
            kwargs["heartbeat_callback"](started)
            if phase == "plan":
                inputs = Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("-var-file=")))
                policy = published_review_policy(review, initial, provider)
                rendered = json.loads(inputs.read_bytes())
                assert all(rendered[k] == v for k, v in policy["nonsecret_varfile"].items())
                assert inputs.parent.name.startswith(".barragan-published-destroy-material-")
                Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("-out="))).write_bytes(("real-gated-" + provider).encode())
            stdout = {"version": '{"terraform_version":"1.15.5"}', "init": "", "plan": "", "show": shows[provider]}[phase]
            kwargs["result_callback"](CommandAuditResult(started, 0, len(stdout), 0, False, False))
            if phase == "init" and source_drift: changed[0] = True
            return CommandResult(started, 0, stdout, "", False, False)
        options = dict(environment="devtest", state_root=ready.case.state_root, core_state_root=tmp_path / "oci",
            job_repository=jobs, credential_repository=SimpleNamespace(), ssh_key_repository=SimpleNamespace(),
            lease_lookup=lambda _: (review.source.core_plan_id, "provider_keyed_teardown_fence"),
            collector=lambda *_a, **_k: collection, release_validator=lambda **_: release,
            gated_command_runner=gated, command_environment={})
        if source_drift:
            with pytest.raises(worker.PublishedMixedPlanWorkerAttention):
                worker.prepare_published_mixed_destroy_plans(queued.id, **options)
            assert [phase for _, phase in commands] == ["version", "init"]
            assert not any(path.exists() for path in paths.values())
            return
        sealed = worker.prepare_published_mixed_destroy_plans(queued.id, **options)
        restored = saved_published_mixed_initial_review(jobs.get(sealed.id))
        plans = saved_published_mixed_destroy_plans(sealed)
        assert restored == review and restored.reviewed_policies is None
        for plan in plans.plans:
            provider = plan.provider
            policy = published_review_policy(restored, initial, provider)
            assert len(policy["nodes"]) == (3 if provider == "linode" else 2)
            assert dict(plan.resource_ids) == {row["address"]: row["id"] for row in restored.provider_scopes[review.source.ordered_providers.index(provider)]["resources"]}
            attested = attest_published_mixed_destroy_show(initial, sealed, restored, plans, provider, states[provider],
                collection.core_inspector_scope, "Opaque", fence=lambda: "stable", show_runner=lambda command, cwd: shows[provider],
                release_validator=lambda: release)
            assert attested == plan
            root = collection.workspaces[provider]
            assert not any((material / name).exists() for material in root.glob(".barragan-published-destroy-material-*")
                           for name in ("admin-public", "admin-private", "credential.json"))
        assert commands == [(p, phase) for p in review.source.ordered_providers for phase in ("version", "init", "plan", "show")]
        assert len(checks) > len(commands)
        before = list(commands)
        assert worker.prepare_published_mixed_destroy_plans(queued.id, **options) == sealed
        assert commands == before and apply_calls == ["linode", "digitalocean"]
