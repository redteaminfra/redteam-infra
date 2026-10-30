# Copyright (c) 2026, Oracle and/or its affiliates.
"""The internal append HostProof producer contacts only one new edge."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_append_host_collection import _decode_type
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_host_identity_probe import DigitalOceanRawHostCollection
from app.services.provider_keyed_host_policy_interpreter import interpret_digitalocean_host_policy
from app.services.provider_keyed_host_surface_interpreter import interpret_digitalocean_host_surface
from app.services.provider_keyed_initial_plan_gate import DigitalOceanNodeCreate
from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.models import CoreMutationLeaseModel, JobRunModel
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from provider_keyed_append_receipts import strict_edge_raw_fixture
from test_provider_keyed_append_source import _pending_atomic_append_writer_case
from test_provider_keyed_host_surface_interpreter import _key
import app.services.provider_keyed_append_host_proof_job as producer


def _case(client, tmp_path, monkeypatch):
    chains, args = _pending_atomic_append_writer_case(client, tmp_path, monkeypatch)
    jobs = SqlAlchemyJobRepository()
    parent = args["parent"]
    plan = jobs.get(parent.input["planJobId"])
    apply = jobs.get(parent.input["applyJobId"])
    proof = jobs.get(parent.input["hostProofJobId"])
    db.session.delete(db.session.get(JobRunModel, proof.id))
    db.session.commit()
    before = args["before"]
    other = args["other"]
    source = replace(args["initial_source"], chain_projection_sha256=
        _fingerprint({row.chain_id: row.to_dict() for row in (before, other)}))
    source_record = json.loads(json.dumps(asdict(source)))
    source_sha = _fingerprint(asdict(source))
    receipt = {**plan.events[-1].data,
        "initialSource": source_record, "initialSourceSha256": source_sha,
        "selectedChain": before.to_dict()}
    plan = jobs.save(replace(plan, events=[replace(plan.events[-1], data=receipt)]))
    plan_sha = job_event_digest(plan.events)
    apply = jobs.save(replace(apply, events=[replace(apply.events[0], data={
        **apply.events[0].data, "planJournalSha256": plan_sha}), *apply.events[1:]]))
    apply_sha = job_event_digest(apply.events)
    parent = jobs.save(replace(parent, status="running", finished_at=None,
        input={**{key: value for key, value in parent.input.items()
                  if not key.startswith("claim")}, "phase": "awaiting_host_proof",
            "coreJobId": source.core_job_id, "corePlanId": source.core_plan_id,
            "region": args["after"].edge_intents[1]["region"],
            "size": args["after"].edge_intents[1]["size"],
            "initialSourceSha256": source_sha, "planJournalSha256": plan_sha,
            "applyJournalSha256": apply_sha},
        events=[JobEvent(1, "info", "provider append plan ready for review", {
            "planJobId": plan.id, "planSha256": receipt["planSha256"]}),
            JobEvent(2, "info", "provider append apply completed; strict host proof pending", {
                "stateSha256": args["state_sha256"], "applyJournalSha256": apply_sha})]))
    root = Path(before.terraform_working_directory)
    (root / ".barragan-apply-phase.json").write_text(json.dumps({
        "schema": "provider-keyed-v2", "phase": "applied"}))
    producer._host_evidence_path(root, parent.id).unlink()
    sketch_hosts = root / ".barragan-sketch-known-hosts"
    sketch_hosts.write_text("opaque sketch known hosts\n")
    core_hosts = tmp_path / "core-known-hosts"
    core_hosts.write_text("opaque core known hosts\n")
    state = json.loads((root / "terraform.tfstate").read_text())
    actual = producer._state_resources(state)
    nodes = {address: DigitalOceanNodeCreate(
        values["name"], values["image"], values["size"], values["region"],
        values["tags"][0]) for address, values in actual.items()
        if address.startswith("digitalocean_droplet.")}
    tag = next(iter(nodes.values())).firewall_selector_tag
    policy = SimpleNamespace(name=actual["digitalocean_firewall.firewall"]["name"],
                             trusted_ssh_cidrs=("192.0.2.10/32",))
    intent = SimpleNamespace(nodes=nodes, firewall=policy, selector_tag=tag,
        proxy_egress_ips={before.assigned_proxy: "192.0.2.1"})
    new = args["after"].nodes[2]
    middle_ip = before.nodes[0]["publicIp"]
    edge_policy = {"sketch_firewall_v2_enabled": True,
                   "sketch_firewall_v2_ssh_sources": [f"{middle_ip}/32"],
                   "sketch_firewall_v2_rules": []}
    calls = []
    monkeypatch.setattr(producer, "compile_fresh_digitalocean_persisted_intent",
                        lambda *_a, **_k: intent)
    monkeypatch.setattr(producer, "managed_host_image_profile_named", lambda *_a: object())
    monkeypatch.setattr(producer, "_verify_audited_workspace", lambda *_a: None)
    monkeypatch.setattr(producer, "_credential_snapshot", lambda *_a: (
        receipt["credentialSecretSha256"], receipt["credentialUpdatedAt"], "ciphertext"))
    monkeypatch.setattr(producer, "render_sketch_host_policy", lambda *_a:
        {new["hostname"]: edge_policy})
    monkeypatch.setattr(producer, "_core_hosts", lambda *_a, **_k: (
        SimpleNamespace(host="198.51.100.10", user="operator",
            ssh_private_key_path="/tmp/opaque-core-key"),
        SimpleNamespace(host="10.0.0.2", user="operator", host_key_alias="192.0.2.1")))
    monkeypatch.setattr(producer, "_core_known_hosts", lambda *_a: (
        str(core_hosts), hashlib.sha256(core_hosts.read_bytes()).hexdigest()))
    monkeypatch.setattr(producer, "require_pinned_sketch_ansible_source", lambda **_k: None)
    monkeypatch.setattr(producer, "retrieve_sketch_ssh_key", lambda *_a:
        SimpleNamespace(public_key=_key(1)))
    monkeypatch.setattr(producer, "retrieve_sketch_transport_ssh_key", lambda *_a:
        SimpleNamespace(public_key=_key(2)))
    def get(_workspace, attachment, **_kwargs):
        assert attachment.state_sha256 == args["state_sha256"]
        assert {node.address: node.droplet_id for node in attachment.nodes} == {
            address: str(values["id"]) for address, values in actual.items()
            if address.startswith("digitalocean_droplet.")}
        calls.append(("GET", len(attachment.nodes)))
        return SimpleNamespace(provider_membership_verified=True,
            state_sha256=attachment.state_sha256,
            verified_droplet_ids=[node.droplet_id for node in attachment.nodes])
    def gated(command, *, scratch_path, intent_callback, started_callback,
              heartbeat_callback, result_callback, **_kwargs):
        assert _kwargs["execution_timeout_seconds"] == 1800
        assert command[-2:] == ["--limit", new["hostname"]]
        phase = next(part for part in command if str(part).endswith(".yml"))
        calls.append(("bootstrap", Path(phase).name, command[-1]))
        seq = len([item for item in calls if item[0] == "bootstrap"])
        intent_event = CommandIntent(f"bootstrap-{seq}", str(scratch_path), "a" * 64)
        intent_callback(intent_event)
        started = StartedCommand(intent_event, ProcessIdentity("boot", seq, seq, seq))
        started_callback(started)
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
        return CommandResult(started, 0, "", "", False, False)
    def bootstrap(_engagement, selected, *, runner, only_edge_name,
                  workspace_root, **_kwargs):
        assert only_edge_name == new["hostname"]
        assert selected.nodes[:2] == args["after"].nodes[:2]
        for name in ("wait_for_sketch_readiness.yml",
                     "upstream-sketch-playbook.compat.yml",
                     "wait_for_sketch_user_readiness.yml",
                     "install_sketch_transport.yml"):
            runner(["ansible-playbook", str(tmp_path / name), "--limit", only_edge_name],
                   workspace_root, {})
        return SketchBootstrapApplyResult(0, 0, 1, 0)
    def collector(*, manifest, manifest_sha256, chain_id, expected,
                  reviewed_core_route, scratch_path, scratch_intent_callback,
                  intent_callback, started_callback, heartbeat_callback,
                  result_callback, **_kwargs):
        assert chain_id == before.chain_id
        assert expected.address == new["terraformAddress"]
        assert reviewed_core_route == {
            "homebasePublicIp": "198.51.100.10", "homebaseUser": "operator",
            "proxyPrivateIp": "10.0.0.2", "proxyPublicIp": "192.0.2.1",
            "proxyUser": "operator", "coreSshKeyPath": "/tmp/opaque-core-key"}
        calls.append(("route", chain_id, expected.address))
        raw = strict_edge_raw_fixture(monkeypatch,
            manifest_sha=manifest_sha256, chain_id=chain_id,
            address=expected.address, provider_id=expected.droplet_id,
            region=expected.region, public_ip=expected.public_ipv4,
            hostname=expected.name, middle_ip=middle_ip,
            admin_public_key=_key(1), transport_public_key=_key(2))
        collection = _decode_type(DigitalOceanRawHostCollection, json.loads(raw))
        ids = [collection.identity.invocation_id,
               collection.firewall_before.invocation_id,
               collection.surface.invocation_id,
               collection.firewall_after.invocation_id]
        scratch_intent_callback(SimpleNamespace(scratch_path=str(scratch_path)))
        for seq, invocation in enumerate(ids, 5):
            item = CommandIntent(invocation, str(scratch_path), "b" * 64)
            intent_callback(item)
            started = StartedCommand(item, ProcessIdentity("boot", seq, seq, seq))
            started_callback(started)
            heartbeat_callback(started)
            result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
        calls.append(("probe", tuple(ids)))
        return collection
    opts = dict(state_root=tmp_path, bootstrap_env={TEMPLATE_ROOT_ENV: str(tmp_path)},
        job_repository=jobs, plan_repository=SimpleNamespace(get=lambda _id:
            SimpleNamespace(evidence={"managedHostImageProfile": "test"})),
        sketch_repository=chains, engagement_repository=SimpleNamespace(get=lambda _id: object()),
        credential_repository=object(), lease_lookup=lambda _id:
            (source.core_plan_id, "provider_keyed_edge_append"),
        attachment_reconciler=get, bootstrap_helper=bootstrap,
        edge_collector=collector, gated_command_runner=gated)
    return jobs, chains, parent.id, before, other, args["after"], calls, opts


def test_host_producer_contacts_only_new_edge_and_publishes_atomically(
        client, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, chains, parent_id, before, other, after, calls, opts = _case(
            client, tmp_path, monkeypatch)
        reopened_opts = {**opts, "job_repository": SqlAlchemyJobRepository(),
                         "sketch_repository": SqlAlchemySketchChainRepository()}
        result = producer.publish_reviewed_digitalocean_edge_append_host_proof(
            parent_id, **reopened_opts)
        assert result.status == "succeeded" and result.input["phase"] == "completed"
        selected = chains.get(before.engagement_id, before.chain_id)
        assert selected.edge_count == 2
        assert selected.nodes[:2] == after.nodes[:2]
        assert selected.nodes[2]["providerInstanceId"] == after.nodes[2]["providerInstanceId"]
        assert chains.get(other.engagement_id, other.chain_id) == other
        assert [item for item in calls if item[0] == "bootstrap"]
        assert len([item for item in calls if item[0] == "bootstrap"]) == 4
        assert len([item for item in calls if item[0] == "probe"]) == 1
        child = jobs.get(producer._child_id(parent_id))
        assert child.status == "succeeded"
        artifact = Path(child.events[-1].data["hostEvidencePath"])
        assert artifact.stat().st_mode & 0o777 == 0o600
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == child.events[-1].data[
            "hostEvidenceSha256"]
        assert db.session.get(CoreMutationLeaseModel, before.engagement_id) is None


@pytest.mark.parametrize("crash_stage", ["queued", "terminal", "sealed"])
def test_host_producer_restarts_same_child_without_recontact(
        client, tmp_path, monkeypatch, crash_stage):
    with client.application.storage_context():
        jobs, chains, parent_id, before, other, after, calls, opts = _case(
            client, tmp_path, monkeypatch)
        restore = None
        if crash_stage == "queued":
            original = jobs.save_if_absent
            def crash_after_queued(value):
                saved = original(value)
                assert saved.status == "queued" and saved.started_at is None
                raise KeyboardInterrupt("after queued HostProof child")
            monkeypatch.setattr(jobs, "save_if_absent", crash_after_queued)
            restore = lambda: monkeypatch.setattr(jobs, "save_if_absent", original)
        elif crash_stage == "terminal":
            original = chains.append_provider_keyed_host_proof_event
            def crash_after_terminal(*args, **kwargs):
                saved = original(*args, **kwargs)
                if saved.status == "succeeded":
                    raise KeyboardInterrupt("after HostProof terminal")
                return saved
            monkeypatch.setattr(chains, "append_provider_keyed_host_proof_event",
                                crash_after_terminal)
            restore = lambda: monkeypatch.setattr(
                chains, "append_provider_keyed_host_proof_event", original)
        else:
            original = chains.publish_provider_keyed_edge_append
            def crash_after_seal(**kwargs):
                assert kwargs["parent"].input["phase"] == "awaiting_publication"
                raise KeyboardInterrupt("after parent HostProof seal")
            monkeypatch.setattr(chains, "publish_provider_keyed_edge_append", crash_after_seal)
            restore = lambda: monkeypatch.setattr(
                chains, "publish_provider_keyed_edge_append", original)
        with pytest.raises(KeyboardInterrupt):
            producer.publish_reviewed_digitalocean_edge_append_host_proof(parent_id, **opts)
        restore()
        old_contact = [item for item in calls if item[0] in {"bootstrap", "probe"}]
        parent = jobs.get(parent_id)
        assert parent.status == "running"
        jobs.save(replace(parent, input={**parent.input,
            "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
        reopened_opts = {**opts, "job_repository": SqlAlchemyJobRepository(),
                         "sketch_repository": SqlAlchemySketchChainRepository()}
        result = producer.publish_reviewed_digitalocean_edge_append_host_proof(
            parent_id, **reopened_opts)
        assert result.status == "succeeded" and result.input["phase"] == "completed"
        assert chains.get(before.engagement_id, before.chain_id).edge_count == 2
        assert chains.get(other.engagement_id, other.chain_id) == other
        new_contact = [item for item in calls if item[0] in {"bootstrap", "probe"}]
        if crash_stage == "queued":
            assert old_contact == []
            assert len([item for item in new_contact if item[0] == "bootstrap"]) == 4
            assert len([item for item in new_contact if item[0] == "probe"]) == 1
        else:
            assert new_contact == old_contact
        assert db.session.get(CoreMutationLeaseModel, before.engagement_id) is None


def test_started_host_command_is_never_replayed_after_uncertain_crash(
        client, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, chains, parent_id, before, other, after, calls, opts = _case(
            client, tmp_path, monkeypatch)
        def crash_after_start(command, *, scratch_path, intent_callback,
                              started_callback, **_kwargs):
            item = CommandIntent("uncertain-command", str(scratch_path), "a" * 64)
            intent_callback(item)
            started_callback(StartedCommand(item, ProcessIdentity("boot", 7, 7, 7)))
            calls.append(("uncertain-start", command[-1]))
            raise KeyboardInterrupt("lost supervisor after host process start")
        opts["gated_command_runner"] = crash_after_start
        with pytest.raises(KeyboardInterrupt):
            producer.publish_reviewed_digitalocean_edge_append_host_proof(parent_id, **opts)
        parent = jobs.get(parent_id)
        assert parent.input["phase"] == "host_proof_reserved"
        jobs.save(replace(parent, input={**parent.input,
            "claimExpiresAt": "2020-01-01T00:00:00+00:00"}))
        contact_before = [item for item in calls if item[0] in {
            "uncertain-start", "bootstrap", "probe"}]
        with pytest.raises(producer.ProviderKeyedAppendHostProofError):
            producer.publish_reviewed_digitalocean_edge_append_host_proof(parent_id, **opts)
        assert [item for item in calls if item[0] in {
            "uncertain-start", "bootstrap", "probe"}] == contact_before
        assert chains.get(before.engagement_id, before.chain_id) == before
        assert chains.get(other.engagement_id, other.chain_id) == other


def test_append_bootstrap_timeout_audited_once_and_child_cannot_replay(client, tmp_path, monkeypatch):
    from app.services.provider_keyed_gated_runner import GatedCommandTimeoutError
    with client.application.storage_context():
        jobs, chains, parent_id, before, other, after, calls, opts = _case(client, tmp_path, monkeypatch)
        attempts = []
        def timeout(command, *, scratch_path, intent_callback, started_callback,
                    heartbeat_callback, result_callback, execution_timeout_seconds, **kwargs):
            assert execution_timeout_seconds == 1800
            attempts.append(command)
            intent = CommandIntent("timed-command", str(scratch_path), "a" * 64)
            started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
            intent_callback(intent)
            started_callback(started)
            result_callback(CommandAuditResult(started, -15, 0, 0, False, False, timed_out=True))
            raise GatedCommandTimeoutError("local bootstrap execution timed out")
        opts["gated_command_runner"] = timeout
        with pytest.raises(producer.ProviderKeyedAppendHostProofError, match="timed out"):
            producer.publish_reviewed_digitalocean_edge_append_host_proof(parent_id, **opts)
        child = jobs.get(producer._child_id(parent_id))
        assert child.status == "failed"
        assert jobs.get(parent_id).input["phase"] == "attention"
        assert child.events[-1].data == {"bootstrap": "reconciliation_required", "timedOut": True}
        audits = [event for event in child.events if event.message == "provider append bootstrap command result fenced"]
        assert len(audits) == 1 and audits[0].data["timedOut"] is True
        assert chains.get(before.engagement_id, before.chain_id) == before
        assert chains.get(other.engagement_id, other.chain_id) == other
        with pytest.raises(producer.ProviderKeyedAppendHostProofError):
            producer.publish_reviewed_digitalocean_edge_append_host_proof(parent_id, **opts)
        assert len(attempts) == 1
