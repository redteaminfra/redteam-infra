# Copyright (c) 2026, Oracle and/or its affiliates.
"""Mixed Apply terminal proof requires an exact full provider observation."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_initial_apply_proof as proof
from app.services import provider_keyed_mixed_initial_apply_child as child_service
from app.services import provider_keyed_mixed_partial_apply_inventory as collector
from app.services.provider_keyed_mixed_partial_apply_source import ProviderApplyClassification
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case


_STATE = b"state"
_SHA = hashlib.sha256(_STATE).hexdigest()
_LINEAGE = "123e4567-e89b-12d3-a456-426614174000"


class Jobs:
    def __init__(self, parent, child):
        self.rows = {parent.id: parent, child.id: child}
        self.append_calls = []
        self.finish_calls = 0

    def get(self, id):
        return self.rows.get(id)

    def renew_lease(self, id, *, owner, token, heartbeat_at, expires_at):
        row = self.rows[id]
        if row.input.get("claimOwner") != owner or row.input.get("claimToken") != token:
            return None
        updated = replace(row, input={**row.input, "claimHeartbeatAt": heartbeat_at,
                                      "claimExpiresAt": expires_at})
        self.rows[id] = updated
        return updated

    def append_event_if_running_claimed(self, row, *, owner, token,
                                        expected_event_digest, heartbeat_at, expires_at, event):
        if self.rows[row.id] != row or job_event_digest(row.events) != expected_event_digest:
            return None
        updated = replace(row, events=[*row.events, event],
                          input={**row.input, "claimHeartbeatAt": heartbeat_at,
                                 "claimExpiresAt": expires_at})
        self.rows[row.id] = updated
        self.append_calls.append(event.message)
        return updated

    def finish_if_running_claimed(self, row, *, owner, token,
                                  expected_event_digest, status, finished_at, event):
        if self.rows[row.id] != row or job_event_digest(row.events) != expected_event_digest:
            return None
        updated = replace(row, status=status, finished_at=finished_at,
                          events=[*row.events, event])
        self.rows[row.id] = updated
        self.finish_calls += 1
        return updated


def _fixture(provider, stage="awaiting"):
    core = "job-opaque"
    parent_id = proof._parent_id(core)
    child_id = proof._child_id(core, provider)
    now = datetime.now(timezone.utc)
    events = [JobEvent(index, "info", f"sealed {index}", {}) for index in range(1, 7)]
    parent = StoredJobRun(parent_id, "provider_keyed_mixed_initial", "running",
                          "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
                          {"corePlanId": "plan-opaque"}, [], now.isoformat(),
                          now.isoformat(), None, events)
    child_events = [JobEvent(1, "info", "result", {})]
    if stage in {"applied", "awaiting", "proved"}:
        child_events.append(JobEvent(2, "info", "mixed provider phase applied", {}))
    if stage in {"awaiting", "proved"}:
        child_events.append(JobEvent(3, "info", "mixed provider awaiting exact observation", {}))
    if stage == "proved":
        child_events.append(JobEvent(4, "info", "mixed provider full observation proved", {
            "classifierKind": "full", "stateSha256": _SHA, "inventorySha256": _SHA,
            "observationSha256": _SHA, "resourceIds": {"node": "17"},
            "lineage": _LINEAGE, "serial": 1, "inventoryCount": 1,
            "selectorResourcesCount": None, "selectorAttachedNodeIds": None,
            "linodeFirewallAttachedNodeIds": [],
            "commandResultJournalSha256": _SHA,
        }))
    child = StoredJobRun(child_id, "provider_keyed_mixed_initial_apply_child", "running",
                         "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
                         {"claimOwner": "owner", "claimToken": "token",
                          "claimExpiresAt": (now + timedelta(minutes=2)).isoformat()},
                         [], now.isoformat(), now.isoformat(), None, child_events)
    root = Path("/tmp/opaque-mixed-proof")
    workspace = ProviderKeyedWorkspace(root, root / "terraform.tfstate", root / ".terraform-data",
                                       SCHEMA, provider, f"{provider}-credential", "fingerprint",
                                       "0" * 40, _SHA)
    return core, parent, child, workspace


def _recognize(child, parent, provider):
    messages = [row.message for row in child.events]
    stage = ("proved" if messages[-1] == "mixed provider full observation proved" else
             "awaiting" if messages[-1] == "mixed provider awaiting exact observation" else
             "applied" if messages[-1] == "mixed provider phase applied" else "result")
    return {"stage": stage, "provider": provider, "journalSha256": job_event_digest(child.events),
            "commandResultJournalSha256": _SHA, "commandResultSequence": 1,
            "planPath": "/tmp/opaque-mixed-proof/.barragan-linode-initial-full.tfplan",
            "startedIdentity": {"bootId": "boot", "pid": 2, "pgid": 2, "startTicks": 3}}


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_full_proof_finishes_both_provider_orders(provider, monkeypatch):
    core, parent, child, workspace = _fixture(provider)
    jobs = Jobs(parent, child)
    monkeypatch.setattr(proof, "recognize_mixed_initial_apply_result", _recognize)
    monkeypatch.setattr(proof, "_require_lease", lambda *args: None)
    snapshot = SimpleNamespace(phase="applied", state_json=_STATE, state_sha256=_SHA,
                               inventory=(), selector_tag_exists=True,
                               selector_attached_node_ids=(),
                               linode_firewall_attached_node_ids=(),
                               selector_resources_count=0, observation_sha256=_SHA)
    monkeypatch.setattr(proof, "collect_provider_inventory_snapshot", lambda *a, **k: snapshot)
    monkeypatch.setattr(proof, "classify_sealed_provider_apply", lambda *a, **k:
                        ProviderApplyClassification(provider, "full", _SHA, _LINEAGE, 1,
                                                    (("node", "17"),)))
    result = proof.prove_and_finish_mixed_initial_apply(
        "eng-opaque", core, provider, workspace, environment="devtest",
        job_repository=jobs, lease_lookup=lambda *_: None,
        process_quiescent=lambda identity: True, claim_owner="owner", claim_token="token")
    assert result.status == "succeeded"
    assert jobs.append_calls == ["mixed provider full observation proved"]
    assert jobs.finish_calls == 1


@pytest.mark.parametrize("kind", ["partial", "uncertain"])
def test_incomplete_classification_never_finishes(kind, monkeypatch):
    core, parent, child, workspace = _fixture("linode")
    jobs = Jobs(parent, child)
    monkeypatch.setattr(proof, "recognize_mixed_initial_apply_result", _recognize)
    monkeypatch.setattr(proof, "_require_lease", lambda *args: None)
    snapshot = SimpleNamespace(phase="applied", state_json=_STATE, state_sha256=_SHA,
                               inventory=(), selector_tag_exists=None,
                               selector_attached_node_ids=None,
                               linode_firewall_attached_node_ids=(),
                               selector_resources_count=None, observation_sha256=_SHA)
    monkeypatch.setattr(proof, "collect_provider_inventory_snapshot", lambda *a, **k: snapshot)
    monkeypatch.setattr(proof, "classify_sealed_provider_apply", lambda *a, **k:
                        ProviderApplyClassification("linode", kind))
    with pytest.raises(proof.MixedInitialApplyProofAttention):
        proof.prove_and_finish_mixed_initial_apply(
            "eng-opaque", core, "linode", workspace, environment="devtest",
            job_repository=jobs, lease_lookup=lambda *_: None,
            process_quiescent=lambda identity: True, claim_owner="owner", claim_token="token",
            max_observation_attempts=1)
    assert jobs.finish_calls == 0


def test_restart_after_proof_finishes_without_provider_reads(monkeypatch):
    core, parent, child, workspace = _fixture("linode", "proved")
    jobs = Jobs(parent, child)
    monkeypatch.setattr(proof, "recognize_mixed_initial_apply_result", _recognize)
    monkeypatch.setattr(proof, "_require_lease", lambda *args: None)
    monkeypatch.setattr(proof, "collect_provider_inventory_snapshot", lambda *a, **k:
                        pytest.fail("provider inventory should not be replayed"))
    result = proof.prove_and_finish_mixed_initial_apply(
        "eng-opaque", core, "linode", workspace, environment="devtest",
        job_repository=jobs, lease_lookup=lambda *_: None,
        process_quiescent=lambda identity: True, claim_owner="owner", claim_token="token")
    assert result.status == "succeeded"
    assert jobs.append_calls == []


def test_delayed_attachment_uses_second_fresh_snapshot(monkeypatch):
    core, parent, child, workspace = _fixture("linode")
    jobs = Jobs(parent, child)
    monkeypatch.setattr(proof, "recognize_mixed_initial_apply_result", _recognize)
    monkeypatch.setattr(proof, "_require_lease", lambda *args: None)
    calls = []
    snapshot = SimpleNamespace(phase="applied", state_json=_STATE, state_sha256=_SHA,
                               inventory=(), selector_tag_exists=None,
                               selector_attached_node_ids=None,
                               linode_firewall_attached_node_ids=(),
                               selector_resources_count=None, observation_sha256=_SHA)

    def observe(*args, **kwargs):
        calls.append("GET")
        return snapshot

    def classify(*args, **kwargs):
        return (ProviderApplyClassification("linode", "uncertain") if len(calls) == 1
                else ProviderApplyClassification("linode", "full", _SHA, _LINEAGE, 1,
                                                 (("node", "17"),)))

    monkeypatch.setattr(proof, "collect_provider_inventory_snapshot", observe)
    monkeypatch.setattr(proof, "classify_sealed_provider_apply", classify)
    monkeypatch.setattr(proof, "_linode_attachment_settling", lambda *args: True)
    result = proof.prove_and_finish_mixed_initial_apply(
        "eng-opaque", core, "linode", workspace, environment="devtest",
        job_repository=jobs, lease_lookup=lambda *_: None,
        process_quiescent=lambda identity: True, claim_owner="owner", claim_token="token",
        max_observation_attempts=2, poll_interval_seconds=0, sleeper=lambda _: None)
    assert result.status == "succeeded" and calls == ["GET", "GET"]


def _managed(type_name, name, attributes, key=None):
    instance = {"attributes": attributes}
    if key is not None:
        instance["index_key"] = key
    return {"mode": "managed", "type": type_name, "name": name,
            "instances": [instance]}


def _state_and_rows(provider, policy):
    resources, rows, nodes = [], [], []
    for index, (address, node) in enumerate(sorted(policy["nodes"].items()), 101):
        kind, base = address.split(".", 1)
        name = base.split("[", 1)[0]
        key = json.loads(base[base.index("[") + 1:-1])
        if provider == "linode":
            attributes = {"id": index, "label": node["label"], "tags": [node["tag"]],
                          "image": node["image"], "region": node["region"], "type": node["node_type"]}
            rows.append({"id": index, "label": node["label"], "tags": [node["tag"]]})
        else:
            attributes = {"id": str(index), "name": node["name"],
                          "tags": [node["firewall_selector_tag"]], "image": node["image"],
                          "region": node["region"], "size": node["size"]}
            rows.append({"id": index, "name": node["name"],
                         "tags": [node["firewall_selector_tag"]]})
        resources.append(_managed(kind, name, attributes, key))
        nodes.append(str(index))
    if provider == "linode":
        firewall = {"id": 301, "label": f'fw-{policy["engagement_name"]}-firewall',
                    "tags": [policy["engagement_name"]]}
        resources.extend([
            _managed("linode_firewall", "firewall", firewall),
            _managed("random_password", "root_password", {"id": "password"}),
        ])
    else:
        firewall = {"id": "fw-301", "name": policy["firewall"]["name"],
                    "tags": [policy["firewall"]["selector_tag"]]}
        resources.extend([
            _managed("digitalocean_firewall", "firewall", firewall),
            _managed("digitalocean_ssh_key", "key", {
                "id": "401", "name": policy["ssh_key_name"],
                "public_key": policy["admin_public_key"]}),
        ])
    resources.extend([
        _managed("local_file", "ansible_inventory", {"id": "inventory"}, 0),
        _managed("local_file", "ssh_stanza", {"id": "ssh-stanza"}, 0),
    ])
    state = {"version": 4, "terraform_version": "1.15.5", "lineage": _LINEAGE,
             "serial": 1, "resources": resources}
    return state, rows, firewall, nodes


@pytest.mark.parametrize("interrupt_finish", [False, True], ids=["normal", "restart-after-proof"])
@pytest.mark.parametrize("result_only", [False, True], ids=["normal-phase", "restart-after-result"])
def test_persisted_seal_child_collector_classifier_and_terminal_both_orders(
        ready, monkeypatch, interrupt_finish, result_only):
    order = ready.parent.input["orderedProviders"]
    provider = order[0]
    if result_only:
        original_mark = child_service.mark_provider_keyed_applied
        monkeypatch.setattr(child_service, "mark_provider_keyed_applied", lambda workspace:
                            (_ for _ in ()).throw(RuntimeError("injected phase crash")))
        with pytest.raises(RuntimeError, match="injected phase crash"):
            child_service.run_mixed_initial_provider_apply(provider=provider, **ready.args)
        monkeypatch.setattr(child_service, "mark_provider_keyed_applied", original_mark)
        child = ready.case.jobs.get(child_service._child_id("job-core", provider))
        assert child_service.recognize_mixed_initial_apply_result(
            child, ready.parent, provider)["stage"] == "result"
        with ready.case.jobs._connect() as connection:
            connection.execute("UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', ?) WHERE id = ?",
                               ("2020-01-01T00:00:00+00:00", child.id))
        child = ready.case.jobs.get(child.id)
    else:
        child = child_service.run_mixed_initial_provider_apply(provider=provider, **ready.args)
    policy = ready.parent.events[5].data["reviewedPolicy"][provider]
    state, nodes_rows, firewall, node_ids = _state_and_rows(provider, policy)
    path = next((ready.case.state_root / "eng-opaque" / "provider-keyed-v2" / provider).iterdir())
    (path / "terraform.tfstate").write_text(json.dumps(state))
    marker = json.loads((path / ".barragan-provider-keyed-state.json").read_text())
    workspace = ProviderKeyedWorkspace(path, path / "terraform.tfstate", path / ".terraform-data",
                                       SCHEMA, provider, marker["provider_connection_id"],
                                       path.name, marker["source_revision"],
                                       hashlib.sha256(json.dumps(marker["source_files"],
                                                                 sort_keys=True).encode()).hexdigest())
    if result_only:
        lock = path / (".barragan-linode-plan.lock" if provider == "linode"
                       else ".barragan-digitalocean-plan.lock")
        lock.write_bytes(b"")
        lock.chmod(0o600)

    class LinodeTransport:
        def request(self, method, endpoint, token):
            assert method == "GET"
            if endpoint.startswith("/linode/instances?"):
                data = nodes_rows
            elif endpoint.startswith("/networking/firewalls?"):
                data = [firewall]
            elif endpoint.startswith("/networking/firewalls/301/devices?"):
                data = [{"id": index + 1, "entity": {"id": int(identifier), "type": "linode"}}
                        for index, identifier in enumerate(node_ids)]
            else:
                raise AssertionError(endpoint)
            return {"data": data, "page": 1, "pages": 1, "results": len(data)}

    class DoTransport:
        def request(self, origin, method, endpoint, token):
            assert method == "GET"
            if endpoint.startswith("/droplets?"):
                key = "droplets"
                data = [] if "type=gpus" in endpoint else nodes_rows
            elif endpoint.startswith("/firewalls?"):
                key, data = "firewalls", [firewall]
            elif endpoint.startswith("/account/keys?"):
                key, data = "ssh_keys", [{"id": 401, "name": policy["ssh_key_name"],
                                           "public_key": policy["admin_public_key"]}]
            elif endpoint.startswith("/tags?"):
                key, data = "tags", [{"name": policy["selector_tag"],
                                      "resources": {"count": len(node_ids)}}]
            else:
                raise AssertionError(endpoint)
            return {key: data, "meta": {"total": len(data)}, "links": {"pages": {}}}

    original = proof.collect_provider_inventory_snapshot
    # The parent fixture renders an isolated source fixture, not the pinned
    # upstream audited checkout; keep the real state/GET/claim proof below.
    monkeypatch.setattr(collector, "_verify_linode_workspace", lambda workspace: None)
    monkeypatch.setattr(collector, "_verify_audited_workspace", lambda workspace: None)
    monkeypatch.setattr(proof, "collect_provider_inventory_snapshot",
                        lambda *args, **kwargs: original(*args, **kwargs,
                                                          decrypt_secret=lambda secret: secret))
    args = dict(
        environment="devtest", job_repository=ready.case.jobs,
        lease_lookup=ready.case.args["lease_lookup"],
        credential_repository=ready.case.args["credential_repository"],
        linode_transport=LinodeTransport(), digitalocean_transport=DoTransport(),
        process_quiescent=lambda identity: True,
        claim_owner=child.input["claimOwner"], claim_token=child.input["claimToken"])
    if interrupt_finish:
        original_finish = ready.case.jobs.finish_if_running_claimed
        monkeypatch.setattr(ready.case.jobs, "finish_if_running_claimed", lambda *a, **k: None)
        with pytest.raises(proof.MixedInitialApplyProofAttention):
            proof.prove_and_finish_mixed_initial_apply(
                "eng-opaque", "job-core", provider, workspace, **args)
        retained = ready.case.jobs.get(child.id)
        assert retained.events[-1].message == "mixed provider full observation proved"
        args["claim_owner"] = retained.input["claimOwner"]
        args["claim_token"] = retained.input["claimToken"]
        monkeypatch.setattr(ready.case.jobs, "finish_if_running_claimed", original_finish)
        monkeypatch.setattr(proof, "collect_provider_inventory_snapshot", lambda *a, **k:
                            pytest.fail("proved restart must not re-read provider"))
    result = proof.prove_and_finish_mixed_initial_apply(
        "eng-opaque", "job-core", provider, workspace, **args)
    assert result.status == "succeeded"
    assert result.events[-2].message == "mixed provider full observation proved"
    assert result.events[-2].data["resourceIds"]
    if not interrupt_finish:
        fresh = proof.prove_mixed_initial_prior_provider_fresh(
            ready.parent, result, workspace, fence=lambda: "active-second-provider-generation",
            process_quiescent=lambda identity: True,
            credential_repository=ready.case.args["credential_repository"],
            linode_transport=LinodeTransport(), digitalocean_transport=DoTransport())
        assert fresh.kind == "full"
        changed = dict(state)
        changed["serial"] = 2
        (path / "terraform.tfstate").write_text(json.dumps(changed))
        with pytest.raises(proof.MixedInitialApplyProofAttention):
            proof.prove_mixed_initial_prior_provider_fresh(
                ready.parent, result, workspace, fence=lambda: "active-second-provider-generation",
                process_quiescent=lambda identity: True,
                credential_repository=ready.case.args["credential_repository"],
                linode_transport=LinodeTransport(), digitalocean_transport=DoTransport())
    monkeypatch.setattr(proof, "collect_provider_inventory_snapshot", lambda *a, **k:
                        pytest.fail("exact terminal duplicate must not read provider"))
    assert proof.prove_and_finish_mixed_initial_apply(
        "eng-opaque", "job-core", provider, workspace, **args) == result


def test_sqlalchemy_proof_and_finish_cas_fail_when_core_lease_changes():
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-opaque",
            operation="provider_keyed_initial"))
        db.session.commit()
        repo = SqlAlchemyJobRepository()
        core, _, child, _ = _fixture("linode")
        base = {"engagementId": "eng-opaque", "coreJobId": core,
                "corePlanId": "plan-opaque", "mixedParentId": "job-parent",
                "sealJournalSha256": _SHA, "provider": "linode", "providerIndex": 0,
                "chainId": "chain-opaque", "receiptSha256": _SHA, "mutation": True}
        child = replace(child, input=base)
        repo.save(child)
        now = datetime.now(timezone.utc)
        claimed = repo.claim_lease(child.id, owner="owner", token="token",
                                   claimed_at=now.isoformat(),
                                   expires_at=(now + timedelta(minutes=5)).isoformat(),
                                   eligible_statuses={"running"})
        assert claimed is not None
        event = JobEvent(len(claimed.events) + 1, "info", "mixed provider full observation proved", {})

        def append(row):
            return repo.append_event_if_running_claimed(
                row, owner="owner", token="token",
                expected_event_digest=job_event_digest(row.events),
                heartbeat_at=(now + timedelta(seconds=1)).isoformat(),
                expires_at=(now + timedelta(minutes=5)).isoformat(), event=event)

        from sqlalchemy import text
        db.session.execute(text("UPDATE core_mutation_leases SET operation = 'provider_keyed_teardown_fence'"))
        db.session.commit()
        assert append(claimed) is None
        assert len(repo.get(child.id).events) == len(claimed.events)
        db.session.execute(text("UPDATE core_mutation_leases SET operation = 'provider_keyed_initial'"))
        db.session.commit()
        appended = append(claimed)
        assert appended is not None
        db.session.execute(text("UPDATE core_mutation_leases SET operation = 'provider_keyed_teardown_fence'"))
        db.session.commit()
        assert repo.finish_if_running_claimed(
            appended, owner="owner", token="token",
            expected_event_digest=job_event_digest(appended.events), status="succeeded",
            finished_at=(now + timedelta(seconds=2)).isoformat(),
            event=JobEvent(len(appended.events) + 1, "info", "finished", {})) is None
        assert repo.get(child.id).status == "running"
