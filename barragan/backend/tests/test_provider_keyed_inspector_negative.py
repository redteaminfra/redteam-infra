# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted, no-network tests of the private Inspector negative boundary."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_inspector_negative as service
from app.services.observer_checks import INSPECTOR_RESOURCE_SOURCE, ObserverSshKey
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.storage.job_repository import SqliteJobRepository, StoredJobRun, job_event_digest


def _job(identifier, action, status, engagement, input_data, events, *, finished=False):
    return StoredJobRun(identifier, action, status, f"engagement:{engagement}",
                        "engagement", engagement, "operator", input_data, [],
                        "2026-10-09T00:00:00+00:00", "2026-10-09T00:00:01+00:00",
                        "2026-10-09T00:00:02+00:00" if finished else None,
                        events)


def _case(tmp_path, monkeypatch):
    engagement = "eng-disposable"
    targets = [{"id": "tcp:8.8.8.8:22", "type": "tcp-forbidden", "host": "8.8.8.8",
                "port": 22, "targetGroup": "core-public-management"},
               {"id": "tcp:9.9.9.9:22", "type": "tcp-forbidden", "host": "9.9.9.9",
                "port": 22, "targetGroup": "core-public-management"}]
    snapshot = {"snapshotId": "a" * 64, "publicVerificationTargets": targets,
                "core": {"proxyCount": 1},
                "inspector": {"verificationTargetCount": 2,
                              "ownedProviderRecordIds": ["linode:inspector:12345"],
                              "recordOwners": {"linode:inspector:12345": "job-inspector"}}}
    parent = _job("job-parent", "engagement_teardown", "queued", engagement,
                  {"phase": "queued"}, [JobEvent(1, "info", "engagement teardown queued", {})])
    core = _job("job-core", "pilot_standard_rti", "succeeded", engagement,
                {"corePlanId": "plan-core", "proxyCount": 1},
                [JobEvent(1, "info", "core connections", {"connectionDetails": [
                    {"role": "homebase", "publicIp": "8.8.8.8"},
                    {"role": "proxy", "publicIp": "9.9.9.9"}]})], finished=True)
    coordinator = _job(service._child_id(core.id), "provider_keyed_comprehensive_teardown",
                       "running", engagement, {"phase": "pending_group_retired"}, [])
    absent = _job("job-provider-keyed-core-destroy-absence-core-attempt-01",
                  service.ABSENCE_ACTION, "succeeded", engagement,
                  {"teardownParentId": parent.id, "coreJobId": core.id,
                   "corePlanId": "plan-core", "scopeSnapshotId": snapshot["snapshotId"],
                   "preDestroyResourceIdsSha256": "b" * 64,
                   "emptyStateSha256": "c" * 64, "principalSha256": "e" * 64},
                  [JobEvent(1, "info", "core destroy absence queued", {}),
                   JobEvent(2, "info", "core destroy absence started", {}),
                   JobEvent(3, "info", "core destroy exact absence proved", {
                       "preDestroyResourceIdsSha256": "b" * 64,
                       "emptyStateSha256": "c" * 64,
                       "ociAbsenceWitness": {"phase": "absent", "evidence_sha256": "d" * 64,
                                             "resource_ids_sha256": "b" * 64,
                                             "principal_sha256": "e" * 64,
                                             "inventory_sha256": "f" * 64,
                                             "auth": "instance_principal"}})],
                  finished=True)
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    for row in (parent, core, coordinator, absent):
        jobs.save(row)
    plan = SimpleNamespace(id="plan-core", status="applied", apply_job_id=core.id)
    plans = SimpleNamespace(get=lambda identifier: plan if identifier == plan.id else None)
    host = {"provider": "linode", "resourceType": "instance", "resourceId": "12345",
            "name": "inspector-opaque", "region": "us-sea", "publicIp": "198.51.100.10",
            "sshUser": "barragan", "status": "running"}
    settings = SimpleNamespace(engagement_id=engagement, enabled=True, mode="continuous",
                               provider="linode", region="us-sea",
                               current_host=host, updated_at="2026-10-09T00:00:00+00:00")
    settings_repo = SimpleNamespace(get=lambda _: settings)
    record = SimpleNamespace(id="linode:inspector:12345", engagement_id=engagement,
                             source=INSPECTOR_RESOURCE_SOURCE, provider="linode",
                             resource_id="12345", region="us-sea", name="inspector-opaque",
                             resource_type="inspector_instance", status="running",
                             lifecycle_state="running", adoption_job_id="job-inspector",
                             metadata={"barraganOwned": True, "role": "inspector",
                                       "publicIp": "198.51.100.10",
                                       "publicIps": ["198.51.100.10"]})
    resources = SimpleNamespace(rows=[record])
    resources.list_for_engagement = lambda _: list(resources.rows)
    monkeypatch.setattr(service, "_boundary", lambda *_: (
        jobs.get(parent.id), jobs.get(core.id), snapshot, service._FENCE))
    monkeypatch.setattr(service, "recognize_pending_keyed_group_retired",
                        lambda *_args, **_kwargs: ("chain-1", "chain-2"))
    calls = []

    class Runner:
        def run(self, *, host, ssh_key, spec):
            calls.append((host, ssh_key, spec))
            return {"ok": True, "results": [
                {"id": spec["positive"][0]["id"], "type": "tcp", "ok": True,
                 "expected": "reachable", "observed": ""},
                *[{"id": row["id"], "type": row["type"], "ok": True,
                   "expected": "absent" if row["type"] == "dns-absent" else "closed",
                   "observed": "verified" if row["type"] == "dns-absent" else
                   {"status": "closed", "reason": "connection_refused"}}
                  for row in spec["negative"]]]}

    options = dict(environment="devtest", state_root=tmp_path,
                   job_repository=jobs, plan_repository=plans,
                   settings_repository=settings_repo, provider_resource_repository=resources,
                   lease_lookup=lambda _: (plan.id, service._FENCE), runner=Runner(),
                   ssh_key_factory=lambda _: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 fake"),
                   positive_control={"id": "inspector-external-control", "type": "tcp",
                                     "host": "1.1.1.1", "port": 443},
                   oci_absence_recognizer=lambda *_args, **_kwargs: jobs.get(absent.id),
                   do_absence_reader=lambda *_args, **_kwargs: DigitalOceanAbsenceEvidence(
                       "c" * 64, ("101", "102"), "fw-1", "key-1", True, 1))
    return parent, snapshot, settings, record, calls, options


def test_file_backed_sqlite_success_restart_recognizes_without_second_probe(tmp_path, monkeypatch):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    first = service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert first.status == "succeeded"
    assert len(first.events[-1].data["rounds"]) == 2
    assert calls[0][0].public_ip == "198.51.100.10"
    assert calls[0][2]["positive"] == [options["positive_control"]]
    assert calls[0][2]["strictNegativeTcp"] is True
    assert len(calls) == 2
    fresh = SqliteJobRepository(options["job_repository"].database_path)
    assert fresh.get(first.id) == first
    assert service.prove_pending_keyed_inspector_negative(
        parent.id, **{**options, "job_repository": fresh}) == first
    assert len(calls) == 2


@pytest.mark.parametrize("variant", ["empty", "malformed", "omitted", "duplicate", "drift", "inspector", "absence"])
def test_incomplete_or_drifted_scope_never_probes_or_succeeds(tmp_path, monkeypatch, variant):
    parent, snapshot, settings, record, calls, options = _case(tmp_path, monkeypatch)
    if variant == "empty":
        snapshot["publicVerificationTargets"] = []
        snapshot["inspector"]["verificationTargetCount"] = 0
    elif variant == "malformed":
        snapshot["publicVerificationTargets"][0]["port"] = "22"
    elif variant == "omitted":
        snapshot["publicVerificationTargets"].pop()
    elif variant == "duplicate":
        snapshot["publicVerificationTargets"].append(dict(snapshot["publicVerificationTargets"][0]))
    elif variant == "drift":
        snapshot["publicVerificationTargets"][0]["host"] = "not a canonical host!"
    elif variant == "inspector":
        settings.current_host["publicIp"] = "8.8.8.8"
    else:
        absent = options["job_repository"].get(
            "job-provider-keyed-core-destroy-absence-core-attempt-01")
        options["job_repository"].save(replace(absent, status="failed"))
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert calls == []


@pytest.mark.parametrize("variant", ["top", "missing", "wrong_type", "failed", "control_missing", "control_observed"])
def test_ambiguous_inspector_response_persists_failed_child(tmp_path, monkeypatch, variant):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    class BadRunner:
        def run(self, *, host, ssh_key, spec):
            calls.append(spec)
            result = {"ok": True, "results": [
                {"id": spec["positive"][0]["id"], "type": "tcp", "ok": True,
                 "expected": "reachable", "observed": ""},
                *[{"id": row["id"], "type": row["type"], "ok": True,
                   "expected": "absent" if row["type"] == "dns-absent" else "closed",
                   "observed": "verified" if row["type"] == "dns-absent" else
                   {"status": "closed", "reason": "connection_refused"}}
                  for row in spec["negative"]]]}
            if variant == "top": result["ok"] = False
            if variant == "missing": result["results"].pop()
            if variant == "wrong_type": result["results"][1]["type"] = "dns-absent"
            if variant == "failed": result["results"][0]["ok"] = False
            if variant == "control_missing": result["results"].pop(0)
            if variant == "control_observed": result["results"][0]["observed"] = {"error": "unsupported"}
            return result
    options["runner"] = BadRunner()
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    child = options["job_repository"].get("job-provider-keyed-inspector-negative-core")
    assert child.status == "failed"
    assert child.events[-1].message == "inspector negative unverified"


def test_missing_external_control_fails_before_any_probe(tmp_path, monkeypatch):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    options["positive_control"] = None
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert calls == []


def test_forged_group_retirement_cannot_launch_inspector_probe(tmp_path, monkeypatch):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    def reject(*_args, **_kwargs):
        raise ValueError("retirement proof differs")
    monkeypatch.setattr(service, "recognize_pending_keyed_group_retired", reject)
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert calls == []


def test_rejected_canonical_oci_absence_cannot_launch_inspector_probe(tmp_path, monkeypatch):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    def reject(*_args, **_kwargs):
        raise ValueError("canonical OCI absence differs")
    options["oci_absence_recognizer"] = reject
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert calls == []


def test_post_snapshot_created_inspector_uses_one_shot_publication_receipt(tmp_path, monkeypatch):
    parent, snapshot, settings, record, calls, options = _case(tmp_path, monkeypatch)
    snapshot["inspector"]["ownedProviderRecordIds"] = []
    snapshot["inspector"]["recordOwners"] = {}
    coordinator_id = service._child_id("job-core")
    jobs = options["job_repository"]
    coordinator = jobs.get(coordinator_id)
    record.adoption_job_id = coordinator_id
    record.metadata["providerFirewall"] = {"resourceId": "fw-12"}
    settings.current_host["metadata"] = {"providerFirewall": {"resourceId": "fw-12"}}
    firewall = SimpleNamespace(
        id="linode:inspector-firewall:fw-12", engagement_id=parent.target_id,
        source=INSPECTOR_RESOURCE_SOURCE, provider="linode", region="us-sea",
        resource_id="fw-12", resource_type="inspector_firewall", status="active",
        lifecycle_state="active", adoption_job_id=coordinator_id,
        metadata={"barraganOwned": True, "role": "inspector_firewall",
                  "inspectorHostResourceId": "12345"})
    options["provider_resource_repository"].rows.append(firewall)
    link = JobEvent(1, "info", "inspector_owned_unprepared", {
        "hostRecordId": record.id, "firewallRecordId": firewall.id,
        "hostId": "12345", "firewallId": "fw-12", "provider": "linode",
        "publicIp": "198.51.100.10", "scopeSnapshotId": snapshot["snapshotId"]})
    prepare = JobEvent(2, "info", "inspector_prepare_started", {})
    ready = JobEvent(3, "info", "inspector selected-source proof published", {
        "scopeSnapshotId": snapshot["snapshotId"], "settingsPublished": True,
        "preparationJournalSha256": job_event_digest([link, prepare]),
        "supportProofSha256": "a" * 64,
        "hostRecordId": record.id, "firewallRecordId": firewall.id})
    jobs.save(replace(coordinator, events=[link, prepare, ready]))
    calls_to_recognizer = []
    def recognized(*args, **kwargs):
        calls_to_recognizer.append((args, kwargs))
        return SimpleNamespace(status="inspector_ready_historical",
                               coordinator_job_id=coordinator_id,
                               host_record_id=record.id,
                               firewall_record_id=firewall.id)
    monkeypatch.setattr(service, "recognize_historical_keyed_inspector_readiness", recognized)
    result = service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert result.status == "succeeded"
    assert len(calls) == 2
    assert len(calls_to_recognizer) >= 1


@pytest.mark.parametrize("reason", ["timed_out", "network_unreachable", "name_resolution_failed", "transport_error"])
def test_tcp_inconclusive_never_counts_as_public_negative(tmp_path, monkeypatch, reason):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    class InconclusiveRunner:
        def run(self, *, host, ssh_key, spec):
            calls.append(spec)
            return {"ok": True, "results": [
                {"id": row["id"], "type": row["type"], "ok": True,
                 "expected": "reachable" if row["id"] == "inspector-external-control" else
                 "absent" if row["type"] == "dns-absent" else "closed",
                 "observed": {"status": "inconclusive", "reason": reason}}
                for row in [*spec["positive"], *spec["negative"]]]}
    options["runner"] = InconclusiveRunner()
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert len(calls) == 1


def test_provider_absence_backed_timeout_has_distinct_persisted_classification(tmp_path, monkeypatch):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    class TimeoutRunner:
        def run(self, *, host, ssh_key, spec):
            calls.append(spec)
            rows = [{"id": "inspector-external-control", "type": "tcp",
                     "expected": "reachable", "ok": True, "observed": ""}]
            for target in spec["negative"]:
                rows.append({"id": target["id"], "type": "tcp-forbidden",
                             "expected": "closed", "ok": False,
                             "observed": {"status": "inconclusive", "reason": "timed_out",
                                          "errorType": "TimeoutError"}})
            return {"ok": False, "results": rows}
    options["runner"] = TimeoutRunner()
    result = service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert result.status == "succeeded"
    assert len(calls) == 2
    for classified in result.events[-1].data["classifications"]:
        assert {row["classification"] for row in classified} == {
            "non_reachable_after_provider_absence"}
    assert all(round_result["ok"] is False for round_result in result.events[-1].data["rounds"])


def test_fresh_provider_absence_drift_after_probes_fails_closed(tmp_path, monkeypatch):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    scans = []
    def drifting(*_args, **_kwargs):
        scans.append(len(scans))
        return DigitalOceanAbsenceEvidence("c" * 64, ("101", "102"),
                                           "fw-1" if len(scans) == 1 else "fw-2",
                                           "key-1", True, 1)
    options["do_absence_reader"] = drifting
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert len(calls) == 2
    assert options["job_repository"].get("job-provider-keyed-inspector-negative-core").status == "failed"


def test_inspector_drift_after_first_round_cannot_persist_success(tmp_path, monkeypatch):
    parent, _, settings, _, calls, options = _case(tmp_path, monkeypatch)
    class DriftRunner:
        def run(self, *, host, ssh_key, spec):
            calls.append(spec)
            settings.current_host["publicIp"] = "198.51.100.99"
            return {"ok": True, "results": [
                {"id": row["id"], "type": row["type"], "ok": True,
                 "expected": "reachable" if row["id"] == "inspector-external-control" else
                 "absent" if row["type"] == "dns-absent" else "closed",
                 "observed": "verified" if row["type"] != "tcp-forbidden" else
                 {"status": "closed", "reason": "connection_refused"}}
                for row in [*spec["positive"], *spec["negative"]]]}
    options["runner"] = DriftRunner()
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert len(calls) == 1
    assert options["job_repository"].get("job-provider-keyed-inspector-negative-core").status == "failed"


def test_queued_pre_probe_restart_is_safe(tmp_path, monkeypatch):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    jobs = options["job_repository"]
    start = jobs.start_if_queued
    jobs.start_if_queued = lambda *_args, **_kwargs: None
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    queued = jobs.get("job-provider-keyed-inspector-negative-core")
    assert queued.status == "queued" and calls == []
    jobs.start_if_queued = start
    result = service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert result.status == "succeeded" and len(calls) == 2


def test_started_probe_crash_is_not_replayed(tmp_path, monkeypatch):
    parent, _, _, _, calls, options = _case(tmp_path, monkeypatch)
    class CrashingRunner:
        def run(self, *, host, ssh_key, spec):
            calls.append(spec)
            raise SystemExit("simulated process death")
    options["runner"] = CrashingRunner()
    with pytest.raises(SystemExit):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    child = options["job_repository"].get("job-provider-keyed-inspector-negative-core")
    assert child.status == "running"
    with pytest.raises(service.KeyedInspectorNegativeAttention):
        service.prove_pending_keyed_inspector_negative(parent.id, **options)
    assert len(calls) == 1
