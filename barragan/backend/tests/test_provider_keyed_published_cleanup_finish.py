# Copyright (c) 2026, Oracle and/or its affiliates.
"""SQLite final writer + real historical reader; upstream provider proofs stubbed.

The owned-source and full producer collectors have their own focused tests.
These tests isolate the terminal transaction, receipt and restart boundaries.
"""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import copy

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_inspector_linode_cleanup as cleanup
from app.services import provider_keyed_published_initial_cleanup_authority as authority
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_public_targets import build_public_target_seal
from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository, StoredEngagementService
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_inspector_linode_cleanup import _durable_case, _run_durable, _Cloud, _job
from test_provider_keyed_chain_projection import _fixture


def _prepared(tmp_path, monkeypatch, *, ghost=False, reverse=False):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    captured = {}
    finish = cleanup._finish_atomic
    def capture(child, **kwargs):
        captured.update(child=child, **kwargs)
        return child
    monkeypatch.setattr(cleanup, "_finish_atomic", capture)
    cloud = _Cloud()
    _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    monkeypatch.setattr(cleanup, "_finish_atomic", finish)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        parent, core, snapshot, coordinator, negative, settings, host, firewall, credential = captured["static"]
        scope = {"corePlanId": "plan-core", "coreJobId":core.id,"provider":"digitalocean",
                 "chainIds": [row.chain_id for row in _fixture()[3]],
                 "workspace": str(tmp_path / "provider"), "stateSha256": "a" * 64,
                 "resources": [{"address": f"digitalocean_droplet.node{i}", "id": str(100+i)} for i in range(4)]
                     + [{"address": "digitalocean_firewall.firewall", "id": "firewall-id"},
                        {"address": "digitalocean_ssh_key.key", "id": "key-id"}]}
        initial_id = "job-provider-keyed-initial-core"
        nodes = [{"terraformAddress": f"digitalocean_droplet.node{i}", "providerInstanceId": str(100+i),
                  "chainId": scope["chainIds"][i // 2], "role": "middle" if i % 2 == 0 else "edge",
                  "hostname":f"node{i}","publicIp":f"11.0.0.{i+1}"} for i in range(4)]
        core = jobs.save(replace(core, action="pilot_standard_rti_guarded_execute"))
        initial = jobs.save(_job(initial_id, "provider_keyed_initial", "succeeded", parent.target_id,
            {"engagementId": parent.target_id, "coreJobId": core.id, "corePlanId": "plan-core"}, [
            JobEvent(1, "info", "provider host identity binding intended", {"nodes": nodes}),
            JobEvent(2, "info", "provider two-chain host proof published", {
                "manifestSha256": "b" * 64, "hostEvidenceSha256": "c" * 64})]))
        apply = jobs.save(_job("job-provider-keyed-initial-destroy-apply-core", "provider_keyed_initial_destroy_apply",
            "succeeded", parent.target_id, {}, []))
        marker = {"engagement_id": parent.target_id, "core_job_id": core.id, "core_plan_id": "plan-core",
            "initial_job_id": initial.id, "initial_journal_sha256": job_event_digest(initial.events),
            "core_journal_sha256": job_event_digest(core.events), "scope_sha256": _fingerprint(scope),
            "state_sha256": scope["stateSha256"], "manifest_sha256": "b" * 64,
            "published_host_evidence_sha256": "c" * 64, "chain_ids": scope["chainIds"],
            "chain_projection_sha256": "d" * 64}
        services = SqlAlchemyEngagementServiceRepository()
        saved_services = [services.save(StoredEngagementService(parent.target_id, f"site-{i}", "web-static",
            f"example{i}", "proxy01", "Configured", {"siteName": f"example{i}", "domain": "example.invalid"},
            f"job-creating-site-{i}")) for i in range(2)]
        failed = jobs.save(_job("job-failed-http", "inbound_channel_apply", "failed", parent.target_id,
                               {"mutation": True}, [JobEvent(1, "error", "fixture terminal failure", {})]))
        failed = jobs.save(replace(failed, finished_at=core.finished_at))
        source = {"core": authority._job_identity(core), "initial": authority._job_identity(initial),
            "coreHosts": [{"publicIp": "12.0.0.1"}], "providerScope":scope,
            "chains":[replace(row,engagement_id=parent.target_id,status="deployed",
                nodes=[node for node in nodes if node["chainId"]==row.chain_id]).to_dict() for row in _fixture()[3]]}
        manifest = {"coreJobId": core.id, "sourceSha256": authority.digest(source), "domains": [],
            "edgeTargets":[{**node,"provider":"digitalocean"} for node in nodes if node["role"]=="edge"]}
        targets = [{"id": "tcp:12.0.0.1:22", "type": "tcp-forbidden", "host": "12.0.0.1", "port": 22,
                    "targetGroup": "core-public-management"}]
        routes = (KeyedRouteIntent(failed.id, "web", "digitalocean_droplet.node1", "digitalocean_droplet.node0",
                                  80, 80, ("0.0.0.0/0",)),)
        seal = {"schema": authority.SCHEMA, "engagementId": parent.target_id, "coreJobId": core.id,
            "source": source,
            "services": [{"service": asdict(row)} for row in saved_services],
            "evidence": [authority._job_identity(failed)], "targetManifest": manifest,
            "attempts": [{"jobId": failed.id, "edge": nodes[1], "middle":nodes[0],
                          "channel": {"externalPort": "80","chainId":scope["chainIds"][0]}}],
            "publicTargets": build_public_target_seal(manifest, targets, routes)}
        seal["sha256"] = authority.digest(seal)
        snapshot.clear()
        snapshot.update({"engagementId":parent.target_id,"coreJobId":core.id,
                         "providerScopes": [scope], "providerScopeSha256": _fingerprint(scope),
                         authority.KEY: seal, "publicVerificationTargets": seal["publicTargets"]["targets"],
                         "inspector": {"verificationTargetCount": len(seal["publicTargets"]["targets"])}})
        snapshot["snapshotId"] = _fingerprint(snapshot)
        parent = jobs.save(replace(parent, input={**parent.input, "scopeSnapshot": snapshot,
            "publishedSource": marker, authority.MARKER: authority.seal_marker(snapshot)}, events=[
                replace(parent.events[0], data=authority.queued_cleanup_event_data(snapshot))]))
        from app.services.observer_checks import _teardown_target
        negative = jobs.save(replace(negative, input={**negative.input, "scopeSnapshotId": snapshot["snapshotId"],
            authority.MARKER: authority.seal_marker(snapshot), "targetCount": len(snapshot["publicVerificationTargets"]),
            "targetSha256": authority.digest([_teardown_target(row) for row in snapshot["publicVerificationTargets"]])}))
        stamp = datetime.now(timezone.utc)
        receipt = {"scopeSnapshotId": snapshot["snapshotId"], "providerScopeSha256": snapshot["providerScopeSha256"],
            "sourceJournalSha256": "", "applyJobId": apply.id,
            "resourceIdsSha256": _fingerprint({row["address"]: row["id"] for row in scope["resources"]}),
            "verifiedAbsentDropletIds": [str(100+i) for i in range(4)], "verifiedAbsentFirewallId": "firewall-id",
            "verifiedAbsentSshKeyId": "key-id", "confirmationCompletedAt": stamp.isoformat(),
            "confirmationExpiresAt": (stamp+timedelta(seconds=30)).isoformat(), "observedAt": stamp.isoformat(),
            "chainIds": sorted(scope["chainIds"]), "retiredRecordIds": [], "priorChainProjectionSha256": "d" * 64}
        create = replace(coordinator.events[0], data={**coordinator.events[0].data, "scopeSnapshotId": snapshot["snapshotId"]})
        receipt["sourceJournalSha256"] = job_event_digest([create])
        coordinator = jobs.save(replace(coordinator, input={**coordinator.input, "phase": "group_retired"},
            events=[create, JobEvent(2, "info", "keyed_provider_group_retired", receipt)]))
        child = jobs.save(replace(captured["child"], input={**captured["child"].input,
            "scopeSnapshotId": snapshot["snapshotId"], "creationJournalSha256": job_event_digest(coordinator.events),
            "negativeJournalSha256": job_event_digest(negative.events),
            "negativeInputSha256": cleanup._negative_input_sha(negative.input)}))
        proofs = copy.deepcopy(captured["proof_receipts"])
        proofs.update(groupCoordinatorSha256=job_event_digest(coordinator.events),
                      negativeJournalSha256=job_event_digest(negative.events),
                      negativeInputSha256=cleanup._negative_input_sha(negative.input))
        for prefix in ("oci", "selector"):
            saved = jobs.get(proofs[f"{prefix}JobId"])
            saved = jobs.save(replace(saved, input={**saved.input, "scopeSnapshotId": snapshot["snapshotId"]}))
            proofs[f"{prefix}InputSha256"] = cleanup._negative_input_sha(saved.input)
        chains = SqlAlchemySketchChainRepository()
        rows = [replace(row, engagement_id=parent.target_id, status="destroyed", nodes=[],
            deploy_job_id=initial.id, teardown_job_id=apply.id, terraform_working_directory=scope["workspace"])
            for row in _fixture()[3]]
        if ghost:
            rows.append(replace(rows[0], chain_id="inert-history", status="aborted", deploy_job_id="",
                                teardown_job_id="", terraform_working_directory="", burned=False))
        for row in reversed(rows) if reverse else rows:
            chains.save(row)
        monkeypatch.setattr(cleanup, "_published_retired_authority", lambda *_a, **_k: "upstream-proved")
        import app.services.provider_keyed_teardown_quiescence as quiescence
        monkeypatch.setattr(quiescence, "audit_published_provider_keyed_bootstrap",
                            lambda *_a, **_k: SimpleNamespace(manifest_sha256="b" * 64))
        captured.update(child=child, static=(parent, core, snapshot, coordinator, negative, settings, host, firewall, credential),
                        proof_receipts=proofs, published_history="upstream-proved", sketch_repository=chains)
    return state, parent, captured, cloud


def _finish(state, captured):
    with db.bind(state):
        return cleanup._finish_atomic(**captured)


@pytest.mark.parametrize("reverse", [False, True])
def test_sealed_finish_retires_services_atomically_and_restarts_without_current_definitions(tmp_path, monkeypatch, reverse):
    state, parent, captured, cloud = _prepared(tmp_path, monkeypatch, ghost=True, reverse=reverse)
    result = _finish(state, captured)
    with db.bind(state):
        services = SqlAlchemyEngagementServiceRepository()
        rows = services.list_for_engagement(parent.target_id)
        assert len(rows) == 2 and all(row.status == "Retired" for row in rows)
        for actual, sealed in zip(rows, parent.input["scopeSnapshot"][authority.KEY]["services"]):
            assert {key: value for key, value in asdict(actual).items() if key not in {"status", "updated_at"}} == {
                key: value for key, value in sealed["service"].items() if key not in {"status", "updated_at"}}
        # A new legitimate deployment may edit or reuse a desired service.
        services.save(replace(rows[0], status="Configured", config={"domain": "later.invalid"}, apply_job_id="job-later"))
    with db.bind(state):
        assert cleanup.recognize_pending_linode_inspector_retired(parent.id, environment="devtest") == result
    assert len(cloud.deletes) == 2  # Historical reader has no transport or replay.


@pytest.mark.parametrize("drift", ["config", "owner", "extra", "missing", "creator", "race", "cas_race"])
def test_sealed_service_drift_rolls_back_entire_finish(tmp_path, monkeypatch, drift):
    from sqlalchemy import update, delete
    from app.storage.models import EngagementServiceModel, CoreMutationLeaseModel
    state, parent, captured, _cloud = _prepared(tmp_path, monkeypatch)
    with db.bind(state):
        services = SqlAlchemyEngagementServiceRepository()
        row = services.list_for_engagement(parent.target_id)[0]
        if drift == "config": services.save(replace(row, config={"changed": True}))
        elif drift == "owner":
            db.session.execute(update(EngagementServiceModel).where(EngagementServiceModel.service_id == row.service_id)
                               .values(proxy_id="foreign")); db.session.commit()
        elif drift == "extra": services.save(replace(row, service_id="extra"))
        elif drift == "missing":
            db.session.execute(delete(EngagementServiceModel).where(EngagementServiceModel.service_id == row.service_id))
            db.session.commit()
        elif drift == "creator": services.save(replace(row, apply_job_id="job-foreign"))
        elif drift == "race":
            retire = cleanup._retire_sealed_services
            def race(*args):
                receipt = retire(*args)
                # Fail after both service updates, testing transaction rollback.
                raise ValueError("simulated later CAS failure")
            monkeypatch.setattr(cleanup, "_retire_sealed_services", race)
        else:
            execute = db.session.execute
            injected = []
            def race_on_service_cas(statement, *args, **kwargs):
                if (not injected and getattr(statement, "is_update", False)
                        and statement.table.name == "engagement_services"):
                    injected.append(True)
                    execute(update(EngagementServiceModel).where(
                        EngagementServiceModel.service_id == row.service_id).values(config={"raced": True}))
                return execute(statement, *args, **kwargs)
            monkeypatch.setattr(db.session, "execute", race_on_service_cas)
        with pytest.raises(ValueError):
            cleanup._finish_atomic(**captured)
        assert SqlAlchemyJobRepository().get(parent.id).status == "queued"
        assert SqlAlchemyJobRepository().get(captured["child"].id).status == "running"
        assert all(row.status == "Configured" for row in services.list_for_engagement(parent.target_id))
        assert captured["settings_repo"].get(parent.target_id).enabled is True
        assert all(row.status == "active" for row in captured["resources"].list_for_engagement(parent.target_id))
        assert db.session.query(CoreMutationLeaseModel).filter_by(engagement_id=parent.target_id).count() == 1


@pytest.mark.parametrize("drift", ["receipt_missing", "receipt_forged", "marker_missing", "targets_removed"])
def test_terminal_seal_and_service_receipt_cannot_downgrade(tmp_path, monkeypatch, drift):
    state, parent, captured, _cloud = _prepared(tmp_path, monkeypatch)
    _finish(state, captured)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        coordinator = jobs.get(cleanup._child_id(captured["static"][1].id))
        if drift.startswith("receipt"):
            data = copy.deepcopy(coordinator.events[-1].data)
            if drift == "receipt_missing": data.pop("serviceRetirementReceipt")
            else: data["serviceRetirementReceipt"]["services"][0]["after"]["status"] = "Configured"
            jobs.save(replace(coordinator, events=[*coordinator.events[:-1], replace(coordinator.events[-1], data=data)]))
        else:
            saved = jobs.get(parent.id)
            data = copy.deepcopy(saved.input)
            if drift == "marker_missing": data.pop(authority.MARKER)
            else:
                data["scopeSnapshot"].pop(authority.KEY)
                data.pop(authority.MARKER)
                data["scopeSnapshot"]["publicVerificationTargets"] = [row for row in data["scopeSnapshot"]["publicVerificationTargets"] if row["port"] == 22]
            jobs.save(replace(saved, input=data))
        with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
            cleanup.recognize_pending_linode_inspector_retired(parent.id, environment="devtest")


def test_static_inspector_authority_rejects_rehashed_core_only_negative(tmp_path, monkeypatch):
    state, parent, captured, _cloud = _prepared(tmp_path, monkeypatch)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        negative = jobs.get(captured["child"].input["negativeJobId"])
        negative = jobs.save(replace(negative, input={**negative.input,
            "targetSha256": authority.digest([{"host": "12.0.0.1", "port": 22}]), "targetCount": 1}))
        child = jobs.save(replace(captured["child"], input={**captured["child"].input,
            "negativeInputSha256": cleanup._negative_input_sha(negative.input)}))
        with pytest.raises(ValueError, match="negative targets differ"):
            cleanup._static_authority(parent.id, child, jobs=jobs, plans=captured["plans"],
                settings_repo=captured["settings_repo"], resources=captured["resources"],
                credentials=captured["credentials"], lookup=captured["lookup"])


def test_historical_reader_rejects_negative_downgrade_even_when_input_hashes_match(tmp_path, monkeypatch):
    state, parent, captured, _cloud = _prepared(tmp_path, monkeypatch)
    _finish(state, captured)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        child = jobs.get(captured["child"].id)
        negative = jobs.get(child.input["negativeJobId"])
        data = copy.deepcopy(negative.input)
        data.pop(authority.MARKER)
        data["targetCount"] = 1
        negative = jobs.save(replace(negative, input=data))
        hashed = cleanup._negative_input_sha(negative.input)
        jobs.save(replace(child, input={**child.input, "negativeInputSha256": hashed}))
        coordinator = jobs.get(cleanup._child_id(captured["static"][1].id))
        terminal = copy.deepcopy(coordinator.events[-1].data)
        terminal["proofs"]["negativeInputSha256"] = hashed
        jobs.save(replace(coordinator, events=[*coordinator.events[:-1], replace(coordinator.events[-1], data=terminal)]))
        with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
            cleanup.recognize_pending_linode_inspector_retired(parent.id, environment="devtest")


@pytest.mark.parametrize("drift", ["burned", "nodes"])
def test_historical_extra_chain_still_requires_strict_inert_projection(tmp_path, monkeypatch, drift):
    state, parent, captured, _cloud = _prepared(tmp_path, monkeypatch, ghost=True)
    _finish(state, captured)
    with db.bind(state):
        chains = SqlAlchemySketchChainRepository()
        ghost = next(row for row in chains.list_for_engagement(parent.target_id) if row.chain_id == "inert-history")
        chains.save(replace(ghost, **({"burned": True} if drift == "burned" else {"nodes": [{"role": "edge"}]})))
        with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
            cleanup.recognize_pending_linode_inspector_retired(parent.id, environment="devtest")
