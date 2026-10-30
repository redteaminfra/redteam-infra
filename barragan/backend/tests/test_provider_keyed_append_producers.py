# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted one-edge Apply producer with fake gated Terraform and provider GETs."""

from dataclasses import asdict, replace
from datetime import datetime, timezone
import copy
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_append_apply import ProviderKeyedAppendApplyResult
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentIntent, ExpectedDigitalOceanNode,
)
from app.services.provider_keyed_initial_plan_gate import DigitalOceanNodeCreate
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
from app.storage.job_repository import SqliteJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import StoredSketchChain
from test_provider_keyed_append_apply import _reviewed_case
from test_provider_keyed_append_plan_gate import (
    INTENT, INVENTORY, NEW, POLICY, REVIEWED_VARIABLES,
)
from test_provider_keyed_initial_plan_gate import workspace
import app.services.provider_keyed_append_apply_job as producer
import app.services.provider_keyed_append_apply as apply_helper


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _job(job_id, action, status, target_id, values, events):
    now = datetime.now(timezone.utc).isoformat()
    return StoredJobRun(job_id, action, status, f"engagement:{target_id}",
                        "engagement", target_id, "operator", values, [],
                        now, now, now if status == "succeeded" else None, events)


def _case(workspace, tmp_path, monkeypatch):
    shown, retained, evidence, phase, plan_path, expected_nodes = _reviewed_case(
        workspace, tmp_path, monkeypatch)
    state = json.loads(workspace.state_path.read_text())
    for resource in state["resources"]:
        if resource["type"] != "digitalocean_droplet":
            continue
        instance = resource["instances"][0]
        address = f'{resource["type"]}.{resource["name"]}[{json.dumps(instance["index_key"])}]'
        intent = DigitalOceanNodeCreate(
            f'retained-{instance["index_key"]}', INTENT.image, INTENT.size,
            "sfo3" if "sfo3" in address else "nyc3", POLICY.selector_tag)
        expected_nodes[address] = intent
        extra = {"name": intent.name, "region": intent.region,
                 "tags": [intent.firewall_selector_tag]}
        instance["attributes"].update(extra)
        retained[address].update(extra)
        next(row["change"] for row in shown["resource_changes"]
             if row["address"] == address)["before"].update(extra)
        next(row["change"] for row in shown["resource_changes"]
             if row["address"] == address)["after"].update(extra)
        next(row for row in shown["prior_state"]["values"]["root_module"]["resources"]
             if row["address"] == address)["values"].update(extra)
    state.update(lineage=str(uuid4()), serial=2, terraform_version="1.15.5")
    workspace.state_path.write_text(json.dumps(state, sort_keys=True))
    before_sha = _sha(workspace.state_path)
    material = workspace.path.parents[1] / ".plan-material" / "digitalocean"
    variables = {**REVIEWED_VARIABLES,
                 "ssh_priv_key_path": str(material / "admin-private"),
                 "ssh_pub_key_path": str(material / "admin-public"),
                 "ssh_config_path": str(material / "ssh-output")}
    varfile = material / "append-inputs.json"
    varfile.write_text(json.dumps(variables))
    varfile.chmod(0o600)
    for key, value in variables.items():
        shown["variables"][key] = {"value": value}
    expected_nodes = dict(expected_nodes)
    after = copy.deepcopy(state)
    new = {"id": "900001", "name": INTENT.name, "image": INTENT.image,
           "size": INTENT.size, "region": INTENT.region,
           "tags": [POLICY.selector_tag], "ipv4_address": "203.0.113.55"}
    name = re.match(r'digitalocean_droplet\.edge\["([^"]+)"\]', NEW).group(1)
    after["resources"].append({"mode": "managed", "type": "digitalocean_droplet",
        "name": "edge", "instances": [{"index_key": name, "attributes": new}]})
    after["serial"] = 3
    engagement_id = "eng-producer"
    now = datetime.now(timezone.utc).isoformat()
    addresses = list(expected_nodes)
    first = addresses[:2]
    second = addresses[2:4]
    def chain(chain_id, selected_addresses):
        nodes = [{"chainId": chain_id, "role": "middle" if i == 0 else "edge",
                  "terraformAddress": address, "providerInstanceId": retained[address]["id"],
                  "publicIp": retained[address]["ipv4_address"],
                  "hostname": expected_nodes[address].name, "region": expected_nodes[address].region,
                  "status": "deployed", "provider": "digitalocean", "assignedProxy": "proxy01",
                  "proxy": "proxy01", "componentId": "middle" if i == 0 else "edge-01",
                  **({"edgeId": "edge-01", "edgeIndex": "1", "edgeCount": "1"} if i else {})}
                 for i, address in enumerate(selected_addresses)]
        return StoredSketchChain(chain_id, engagement_id, "proxy01", "digitalocean", "nyc3",
            INTENT.size, "digitalocean", "nyc3", INTENT.size, "deployed", False, "",
            "job-initial", "", str(workspace.path), nodes, now, now, 1,
            [{"id": "edge-01", "provider": "digitalocean", "region": "nyc3",
              "size": INTENT.size}])
    rows = [chain("chain-a", first), chain("chain-b", second)]
    chains = SimpleNamespace(list_for_engagement=lambda _eng: list(rows))
    source = PublishedProviderKeyedSource(engagement_id, "job-core", "plan-core",
        "job-initial", "1"*64, "2"*64, "3"*64, before_sha, "4"*64, "5"*64,
        ("chain-a", "chain-b"), _fingerprint({row.chain_id: row.to_dict() for row in rows}))
    source_record = json.loads(json.dumps(asdict(source)))
    plan_receipt = {"initialSource": source_record, "initialSourceSha256": _fingerprint(asdict(source)),
        "selectedChain": rows[0].to_dict(), "newEdgeAddress": NEW,
        "retainedSharedIds": {key: str(retained[key]["id"]) for key in
            ("digitalocean_firewall.firewall", "digitalocean_ssh_key.key")},
        "planPath": str(plan_path), "planSha256": _sha(plan_path),
        "stateSha256": before_sha, "topologySha256": evidence.topology_sha256,
        "sourceSha256": evidence.source_sha256, "lockfileSha256": evidence.lockfile_sha256,
        "inputSha256": [[str(varfile), _sha(varfile)]],
        "credentialRecordId": workspace.provider_connection_id,
        "credentialSecretSha256": "a"*64,
        "credentialUpdatedAt": "2026-10-13T00:00:00+00:00",
        "terraformBinaryPath": str(evidence.terraform_binary_path),
        "terraformBinarySha256": evidence.terraform_binary_sha256}
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    plan = jobs.save(_job("job-plan", "provider_keyed_edge_append_plan", "succeeded",
        engagement_id, {"parentJobId": "job-provider-keyed-append-producer", "mutation": False},
        [JobEvent(1, "info", "reviewed append plan saved", plan_receipt)]))
    parent_id = "job-provider-keyed-append-producer"
    parent = jobs.save(_job(parent_id, "provider_keyed_edge_append", "running",
        engagement_id, {"phase": "awaiting_apply", "engagementId": engagement_id,
            "coreJobId": "job-core", "corePlanId": "plan-core", "chainId": rows[0].chain_id,
            "region": INTENT.region, "size": INTENT.size,
            "initialSourceSha256": plan_receipt["initialSourceSha256"],
            "planJobId": plan.id, "planJournalSha256": job_event_digest(plan.events),
            "mutation": True},
        [JobEvent(1, "info", "provider append plan ready for review",
                  {"planJobId": plan.id, "planSha256": plan_receipt["planSha256"]})]))
    core = jobs.save(_job("job-core", "core", "succeeded", engagement_id, {}, []))
    profile_plan = SimpleNamespace(evidence={"managedHostImageProfile": "test"})
    intent = SimpleNamespace(nodes=expected_nodes, firewall=POLICY,
        selector_tag=POLICY.selector_tag, nonsecret_varfile=REVIEWED_VARIABLES,
        proxy_egress_ips={"proxy01": "192.0.2.1"})
    monkeypatch.setattr(producer, "reconcile_reviewed_digitalocean_edge_append_plan",
                        lambda *_a, **_k: jobs.get(parent_id))
    monkeypatch.setattr(producer, "audit_published_provider_keyed_source",
                        lambda *_a, **_k: source)
    monkeypatch.setattr(producer, "compile_fresh_digitalocean_persisted_intent",
                        lambda *_a, **_k: intent)
    monkeypatch.setattr(producer, "managed_host_image_profile_named", lambda *_a: object())
    monkeypatch.setattr(producer, "read_applied_digitalocean_provider_for_teardown",
                        lambda *_a, **_k: (None, workspace, None, None))
    old_nodes = tuple(ExpectedDigitalOceanNode(
        address, str(retained[address]["id"]), expected_nodes[address].name,
        expected_nodes[address].region, retained[address]["ipv4_address"])
        for address in expected_nodes if address != NEW)
    initial_attachment = DigitalOceanAttachmentIntent(
        before_sha, str(retained["digitalocean_firewall.firewall"]["id"]),
        POLICY.name, POLICY.selector_tag, POLICY.trusted_ssh_cidrs, old_nodes,
        workspace.provider_connection_id, "a"*64, "2026-10-13T00:00:00+00:00")
    monkeypatch.setattr(producer, "derive_digitalocean_initial_attachment_intent",
                        lambda *_a: initial_attachment)
    monkeypatch.setattr(producer, "require_devtest_terraform_release", lambda **_k:
        SimpleNamespace(path=evidence.terraform_binary_path,
                        sha256=evidence.terraform_binary_sha256))
    monkeypatch.setattr(producer, "retrieve_sketch_ssh_key", lambda *_a:
        SimpleNamespace(private_key="PRIVATE", public_key="PUBLIC"))
    monkeypatch.setattr(producer, "_expected_inventory", lambda *_a: INVENTORY)
    monkeypatch.setattr(producer, "_credential_snapshot", lambda *_a:
        ("a"*64, "2026-10-13T00:00:00+00:00", "ciphertext"))
    monkeypatch.setattr(apply_helper, "_credential_snapshot", lambda *_a:
        ("a"*64, "2026-10-13T00:00:00+00:00", "ciphertext"))
    calls = []
    def get(_workspace, attachment, **_kwargs):
        assert _workspace == workspace
        assert attachment.firewall_id == initial_attachment.firewall_id
        assert attachment.firewall_name == POLICY.name
        assert attachment.selector_tag == POLICY.selector_tag
        assert attachment.trusted_ssh_cidrs == POLICY.trusted_ssh_cidrs
        assert (attachment.credential_record_id, attachment.credential_secret_sha256,
                attachment.credential_updated_at) == (
                    initial_attachment.credential_record_id,
                    initial_attachment.credential_secret_sha256,
                    initial_attachment.credential_updated_at)
        expected = {node.address: node.droplet_id for node in old_nodes}
        if attachment.state_sha256 != before_sha:
            expected[NEW] = "900001"
        assert {node.address: node.droplet_id for node in attachment.nodes} == expected
        ids = ([retained[a]["id"] for a in expected_nodes if a != NEW]
               if attachment.state_sha256 == before_sha else
               [retained[a]["id"] for a in expected_nodes if a != NEW] + ["900001"])
        calls.append(("GET", tuple(ids)))
        return SimpleNamespace(provider_membership_verified=True,
                               state_sha256=attachment.state_sha256,
                               verified_droplet_ids=ids)
    def gated(args, *, scratch_path, intent_callback, started_callback,
              heartbeat_callback, result_callback, **_kwargs):
        phase = args[1]
        calls.append(("terraform", phase))
        raw = json.dumps(args, separators=(",", ":")).encode()
        command_intent = CommandIntent(phase, str(scratch_path), hashlib.sha256(raw).hexdigest())
        intent_callback(command_intent)
        started = StartedCommand(command_intent, ProcessIdentity("boot", 100, 100, 100))
        started_callback(started)
        heartbeat_callback(started)
        output = json.dumps(shown) if phase == "show" else ""
        result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
        if phase == "apply":
            assert json.loads(phase_path.read_text())["phase"] == "apply_started"
            workspace.state_path.write_text(json.dumps(after, sort_keys=True))
        return CommandResult(started, 0, output, "", False, False)
    phase_path = phase
    opts = dict(state_root=tmp_path, job_repository=jobs,
        plan_repository=SimpleNamespace(get=lambda _id: profile_plan),
        sketch_repository=chains, engagement_repository=SimpleNamespace(get=lambda _id: object()),
        credential_repository=object(), lease_lookup=lambda _id:
            ("plan-core", "provider_keyed_edge_append"),
        attachment_reconciler=get, gated_command_runner=gated)
    return jobs, parent_id, rows, calls, opts


def test_apply_producer_one_saved_go_and_persisted_receipt(workspace, tmp_path, monkeypatch):
    jobs, parent_id, rows, calls, opts = _case(workspace, tmp_path, monkeypatch)
    result = producer.run_reviewed_digitalocean_edge_append_apply(parent_id, **opts)
    assert result.input["phase"] == "awaiting_host_proof"
    assert calls == [("terraform", "show"), ("GET", tuple(
        node["providerInstanceId"] for row in rows for node in row.nodes)),
        ("terraform", "apply"), ("GET", tuple(
        [node["providerInstanceId"] for row in rows for node in row.nodes] + ["900001"]))]
    child = jobs.get(producer._child_id(parent_id))
    assert child.status == "succeeded" and len(child.events) == 13
    assert [row.edge_count for row in rows] == [1, 1]
    material = workspace.path.parents[1] / ".plan-material" / "digitalocean"
    assert not (material / "admin-private").exists()
    assert not (material / "admin-public").exists()
    reopened = SqliteJobRepository(tmp_path / "jobs.sqlite")
    assert reopened.get(child.id) == child
    with pytest.raises(producer.ProviderKeyedAppendApplyJobError):
        producer.run_reviewed_digitalocean_edge_append_apply(
            parent_id, **{**opts, "job_repository": reopened})
    assert [call for call in calls if call == ("terraform", "apply")] == [
        ("terraform", "apply")]


def test_apply_terminal_crash_recovers_without_replaying_saved_plan(
        workspace, tmp_path, monkeypatch):
    jobs, parent_id, rows, calls, opts = _case(workspace, tmp_path, monkeypatch)
    save = jobs.save_if_leased

    def crash_after_terminal(value, **kwargs):
        if value.input.get("phase") == "awaiting_host_proof":
            assert jobs.get(producer._child_id(parent_id)).status == "succeeded"
            raise KeyboardInterrupt("hard crash after Apply terminal")
        return save(value, **kwargs)

    monkeypatch.setattr(jobs, "save_if_leased", crash_after_terminal)
    with pytest.raises(KeyboardInterrupt, match="hard crash"):
        producer.run_reviewed_digitalocean_edge_append_apply(parent_id, **opts)
    assert jobs.get(parent_id).input["phase"] == "apply_reserved"
    child = jobs.get(producer._child_id(parent_id))
    assert child.status == "succeeded"
    assert [call for call in calls if call == ("terraform", "apply")] == [
        ("terraform", "apply")]
    parent = jobs.get(parent_id)
    jobs.save(replace(parent, input={**parent.input,
        "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
    reopened = SqliteJobRepository(tmp_path / "jobs.sqlite")
    recovered = producer.reconcile_interrupted_digitalocean_edge_append_apply(
        parent_id, state_root=tmp_path, job_repository=reopened,
        sketch_repository=opts["sketch_repository"], lease_lookup=opts["lease_lookup"])
    assert recovered.input["phase"] == "awaiting_host_proof"
    assert reopened.get(child.id) == child
    assert len([call for call in calls if call == ("terraform", "apply")]) == 1
