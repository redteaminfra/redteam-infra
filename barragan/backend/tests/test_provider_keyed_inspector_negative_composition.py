# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted composition of historical Inspector and pending retirement proofs.

The earlier provider destroy success boundary is a fixture. The retirement and
readiness recognizers, two Inspector probe rounds, and restart receipt are real.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_inspector_negative as negative
from app.services import provider_keyed_pending_retirement as retirement
from app.services import provider_keyed_inspector_readiness_publish as readiness
from app.services.engagement_teardown import _fingerprint
from app.services.observer_checks import ObserverSshKey
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository, StoredSketchChain
from test_job_repository_keyed_provider_absent import proof as absent_proof
from test_provider_keyed_inspector_readiness_publish import _capability
import test_provider_keyed_comprehensive_teardown as source_fixture
import test_provider_keyed_teardown_handoff as handoff_fixture


def _case(tmp_path, monkeypatch):
    original_completed = handoff_fixture._completed

    def with_core_connections(path):
        jobs, bootstrap, workspace, scope = original_completed(path)
        core = jobs.get("job-core")
        details = [
            {"role": "homebase", "publicIp": "8.8.4.4"},
            {"role": "proxy", "publicIp": "9.9.9.9"},
            {"role": "proxy", "publicIp": "1.0.0.1"},
        ]
        jobs.save(replace(core, events=[*core.events, JobEvent(
            len(core.events) + 1, "info", "core connection details",
            {"connectionDetails": details})]))
        return jobs, bootstrap, workspace, scope

    monkeypatch.setattr(handoff_fixture, "_completed", with_core_connections)
    original_fixture = source_fixture._fixture
    targets = [
        {"id": f"tcp:{ip}:22", "type": "tcp-forbidden", "host": ip,
         "port": 22, "targetGroup": "core-public-management"}
        for ip in ("8.8.4.4", "9.9.9.9", "1.0.0.1")
    ]

    def with_targets(path):
        jobs, bootstrap, queued, scope, plans, options = original_fixture(path)
        old = queued.input["scopeSnapshot"]
        snapshot = {**old, "publicVerificationTargets": targets,
                    "inspector": {**old["inspector"], "verificationTargetCount": len(targets)}}
        snapshot.pop("snapshotId")
        snapshot["snapshotId"] = _fingerprint(snapshot)
        queued = jobs.save(replace(queued, input={**queued.input, "scopeSnapshot": snapshot},
                                   events=[JobEvent(1, "info", "engagement teardown queued",
                                                    {"snapshotId": snapshot["snapshotId"]})]))
        return jobs, bootstrap, queued, scope, plans, options

    monkeypatch.setattr(source_fixture, "_fixture", with_targets)
    # The existing real Inspector creation/publication fixture normally uses a
    # memory database. Redirect only its database construction to a disk file.
    original_configure = db.configure
    uri = f"sqlite:///{tmp_path / 'inspector-composition.sqlite'}"
    monkeypatch.setattr(db, "configure", lambda _uri: original_configure(uri))
    state, parent, receipt, capability = _capability(tmp_path, monkeypatch)
    monkeypatch.setattr(db, "configure", original_configure)

    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        resources = SqlAlchemyProviderResourceRepository()
        chains = SqlAlchemySketchChainRepository()
        readiness.publish_proved_keyed_inspector_readiness(
            capability, parent.target_id, environment="devtest")
        ready = jobs.get(receipt.coordinator_job_id)
        snapshot = parent.input["scopeSnapshot"]
        now = datetime.now(timezone.utc)
        earlier = (now - timedelta(minutes=2)).isoformat()
        ids = {
            'digitalocean_droplet.middle["chain-1"]': "101",
            'digitalocean_droplet.edge["chain-1"]': "201",
            'digitalocean_droplet.middle["chain-2"]': "102",
            'digitalocean_droplet.edge["chain-2"]': "202",
            "digitalocean_firewall.firewall": "11111111-1111-1111-1111-111111111111",
            "digitalocean_ssh_key.key": "789",
        }
        rows = []
        for index in (1, 2):
            rows.append(chains.save(StoredSketchChain(
                chain_id=f"chain-{index}", engagement_id=parent.target_id,
                assigned_proxy="proxy01", middle_provider="digitalocean",
                middle_region="nyc3", middle_size="s-1vcpu-1gb",
                edge_provider="digitalocean", edge_region="sfo3",
                edge_size="s-1vcpu-1gb", status="destroyed", burned=False,
                burned_note="", deploy_job_id="", teardown_job_id="apply-1",
                terraform_working_directory="", nodes=[], created_at=earlier,
                updated_at=earlier, edge_count=1,
                edge_intents=[{"id": "edge-01", "provider": "digitalocean",
                               "region": "sfo3", "size": "s-1vcpu-1gb"}],
            )))
        fingerprints = {row.chain_id: sketch_chain_intent_fingerprint(row) for row in rows}
        preview = jobs.save(StoredJobRun(
            "preview-1", "provider_keyed_initial_destroy_preview", "succeeded",
            f"engagement:{parent.target_id}", "engagement", parent.target_id,
            parent.requested_by, {}, [], earlier, earlier, earlier,
            [JobEvent(1, "info", "preview", {})]))
        applied = jobs.save(StoredJobRun(
            "apply-1", "provider_keyed_initial_destroy_apply", "succeeded",
            f"engagement:{parent.target_id}", "engagement", parent.target_id,
            parent.requested_by, {}, [], earlier, earlier, earlier,
            [JobEvent(1, "info", "apply", {})]))
        intent = SimpleNamespace(resource_ids=ids, empty_state_sha256="3" * 64)
        proof = {**absent_proof(ready),
                 "previewJobId": preview.id,
                 "previewJournalSha256": job_event_digest(preview.events),
                 "applyJobId": applied.id,
                 "applyJournalSha256": job_event_digest(applied.events),
                 "resourceIdsSha256": _fingerprint(ids),
                 "verifiedAbsentDropletIds": ["101", "102", "201", "202"],
                 "verifiedAbsentFirewallId": ids["digitalocean_firewall.firewall"],
                 "verifiedAbsentSshKeyId": ids["digitalocean_ssh_key.key"]}
        proof["observedAt"] = (
            datetime.fromisoformat(proof["confirmationCompletedAt"])
            + timedelta(microseconds=1)).isoformat()
        absent_event = JobEvent(len(ready.events) + 1, "info", "provider_absent", proof)
        absent = replace(ready, input={**ready.input, "phase": "provider_absent"},
                         events=[*ready.events, absent_event])
        retirement_event = JobEvent(len(absent.events) + 1, "info",
                                    "keyed_pending_provider_group_retired", {
            "scopeSnapshotId": snapshot["snapshotId"],
            "providerScopeSha256": snapshot["providerScopeSha256"],
            "sourceJournalSha256": job_event_digest(absent.events),
            "applyJobId": applied.id, "resourceIdsSha256": _fingerprint(ids),
            "verifiedAbsentDropletIds": ["101", "102", "201", "202"],
            "verifiedAbsentFirewallId": ids["digitalocean_firewall.firewall"],
            "verifiedAbsentSshKeyId": ids["digitalocean_ssh_key.key"],
            "confirmationCompletedAt": proof["confirmationCompletedAt"],
            "confirmationExpiresAt": proof["confirmationExpiresAt"],
            "chainIds": ["chain-1", "chain-2"],
            "chainFingerprints": fingerprints,
            "retiredRecordIds": [], "observedAt": proof["observedAt"],
        })
        jobs.save(replace(absent, input={**absent.input, "phase": "pending_group_retired"},
                          events=[*absent.events, retirement_event]))
        core_absence = jobs.save(StoredJobRun(
            "job-provider-keyed-core-destroy-absence-core-attempt-01",
            negative.ABSENCE_ACTION, "succeeded", f"engagement:{parent.target_id}",
            "engagement", parent.target_id, parent.requested_by,
            {"teardownParentId": parent.id, "coreJobId": ready.input["coreJobId"],
             "corePlanId": ready.input["corePlanId"],
             "scopeSnapshotId": snapshot["snapshotId"],
             "preDestroyResourceIdsSha256": "b" * 64, "emptyStateSha256": "c" * 64,
             "principalSha256": "e" * 64}, [], earlier, earlier, now.isoformat(),
            [JobEvent(1, "info", "core destroy absence queued", {}),
             JobEvent(2, "info", "core destroy absence started", {}),
             JobEvent(3, "info", "core destroy exact absence proved", {
                 "preDestroyResourceIdsSha256": "b" * 64,
                 "emptyStateSha256": "c" * 64,
                 "ociAbsenceWitness": {
                     "phase": "absent", "auth": "instance_principal",
                     "resource_ids_sha256": "b" * 64, "principal_sha256": "e" * 64,
                     "inventory_sha256": "f" * 64, "evidence_sha256": "d" * 64,
                 },
             })],
        ))
        core = jobs.get(ready.input["coreJobId"])
        bound = SimpleNamespace(
            parent=jobs.get(parent.id), core=core, preview_job=preview,
            apply_job=applied, scope={"chainIds": ["chain-1", "chain-2"],
                                      "chainFingerprints": fingerprints},
            intent=intent, chains=tuple(rows),
        )
        monkeypatch.setattr(retirement, "_boundary", lambda *_args, **_kwargs: bound)
        return state, parent, ready, bound, resources, core_absence


def test_historical_publication_and_retirement_reject_extra_active_firewall(
        tmp_path, monkeypatch):
    state, parent, ready, bound, resources, _ = _case(tmp_path, monkeypatch)
    with db.bind(state):
        options = dict(environment="devtest", state_root=tmp_path)
        assert len(retirement.recognize_pending_keyed_group_retired(parent.id, **options)) == 2
        historical = readiness.recognize_historical_keyed_inspector_readiness(
            ready.id, parent.target_id, **options)
        assert historical.status == "inspector_ready_historical"
        now = datetime.now(timezone.utc).isoformat()
        resources.save(StoredProviderResourceRecord(
            id="linode:inspector-firewall:extra", engagement_id=parent.target_id,
            engagement_name=bound.parent.input["scopeSnapshot"]["engagementName"],
            provider="linode", resource_type="inspector_firewall", resource_id="extra",
            name="opaque", region="us-east", lifecycle_state="active", status="active",
            source="barragan_inspector_job", metadata={"barraganOwned": True,
                "role": "inspector_firewall"}, adoption_job_id=ready.id,
            adopted_at=now, updated_at=now))
        with pytest.raises(retirement.ProviderKeyedComprehensiveTeardownAttention):
            retirement.recognize_pending_keyed_group_retired(parent.id, **options)
        with pytest.raises(readiness.InspectorReadinessPublicationAttention):
            readiness.recognize_historical_keyed_inspector_readiness(
                ready.id, parent.target_id, **options)


def test_retired_group_and_historical_inspector_prove_two_rounds_then_restart(
        tmp_path, monkeypatch):
    state, parent, ready, bound, _resources, core_absence = _case(tmp_path, monkeypatch)
    probes = []

    class Inspector:
        def run(self, *, host, ssh_key, spec):
            assert host.resource_id == "123" and host.provider == "linode"
            assert ssh_key.public_key == "ssh-ed25519 test"
            assert spec["strictNegativeTcp"] is True
            assert spec["timeoutSeconds"] == 8
            assert {row["id"] for row in spec["negative"]} == {
                "tcp:8.8.4.4:22", "tcp:9.9.9.9:22", "tcp:1.0.0.1:22"}
            probes.append(spec)
            return {"ok": True, "results": [
                {"id": spec["positive"][0]["id"], "type": "tcp", "ok": True,
                 "expected": "reachable", "observed": ""},
                *[{"id": row["id"], "type": row["type"], "ok": True,
                   "expected": "closed",
                   "observed": {"status": "closed", "reason": "connection_refused"}}
                  for row in spec["negative"]],
            ]}

    exact_do_absence = DigitalOceanAbsenceEvidence(
        bound.intent.empty_state_sha256, ("101", "102", "201", "202"),
        bound.intent.resource_ids["digitalocean_firewall.firewall"],
        bound.intent.resource_ids["digitalocean_ssh_key.key"], True, 1)
    def prior_oci_absence(parent_id, **_kwargs):
        assert parent_id == parent.id
        saved = SqlAlchemyJobRepository().get(core_absence.id)
        assert saved is not None and saved.id == core_absence.id
        assert saved.status == "succeeded" and saved.events == core_absence.events
        return saved

    options = dict(
        environment="devtest", state_root=tmp_path, runner=Inspector(),
        positive_control={"id": "inspector-external-control", "type": "tcp",
                          "host": "4.2.2.2", "port": 443},
        ssh_key_factory=lambda _: ObserverSshKey("/tmp/fake-key", "ssh-ed25519 test"),
        do_absence_reader=lambda *_args, **_kwargs: exact_do_absence,
        oci_absence_recognizer=prior_oci_absence,
    )
    with db.bind(state):
        assert len(retirement.recognize_pending_keyed_group_retired(
            parent.id, environment="devtest", state_root=tmp_path)) == 2
        assert readiness.recognize_historical_keyed_inspector_readiness(
            ready.id, parent.target_id, environment="devtest", state_root=tmp_path,
        ).status == "inspector_ready_historical"
        result = negative.prove_pending_keyed_inspector_negative(parent.id, **options)
        assert result.status == "succeeded" and result.input["ociAbsenceJobId"] == core_absence.id
        assert len(result.events[-1].data["rounds"]) == 2 and len(probes) == 2
    assert state.uri == f"sqlite:///{tmp_path / 'inspector-composition.sqlite'}"
    assert (tmp_path / "inspector-composition.sqlite").is_file()
    reopened = db.configure(state.uri)
    with db.bind(reopened):
        assert negative.prove_pending_keyed_inspector_negative(parent.id, **options) == result
    assert len(probes) == 2


def test_forged_oci_success_receipt_cannot_start_inspector_probe(tmp_path, monkeypatch):
    state, parent, _ready, bound, _resources, core_absence = _case(tmp_path, monkeypatch)

    class NoProbe:
        def run(self, **_kwargs):
            pytest.fail("forged OCI absence reached Inspector")

    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        jobs.save(replace(core_absence, status="failed"))
        with pytest.raises(negative.KeyedInspectorNegativeAttention):
            negative.prove_pending_keyed_inspector_negative(
                parent.id, environment="devtest", state_root=tmp_path,
                runner=NoProbe(), positive_control={
                    "id": "inspector-external-control", "type": "tcp",
                    "host": "4.2.2.2", "port": 443},
                do_absence_reader=lambda *_args, **_kwargs: DigitalOceanAbsenceEvidence(
                    bound.intent.empty_state_sha256, ("101", "102", "201", "202"),
                    bound.intent.resource_ids["digitalocean_firewall.firewall"],
                    bound.intent.resource_ids["digitalocean_ssh_key.key"], True, 1),
                oci_absence_recognizer=lambda *_args, **_kwargs: jobs.get(core_absence.id),
            )
        assert not [job for job in jobs.list_for_engagement(parent.target_id)
                    if job.action == negative.ACTION]
