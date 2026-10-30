# Copyright (c) 2026, Oracle and/or its affiliates.
"""Retained state, not provider inventory, supplies expected attachment identity."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_initial_attachment_adapter as service
from app.services import provider_keyed_digitalocean_attachment as attachment_service
from app.services.provider_keyed_initial_plan_gate import (
    DigitalOceanInitialFirewallIntent, DigitalOceanNodeCreate, _SOURCE_REVISION, _SOURCE_SHA256,
)
from app.services.provider_keyed_persisted_intent import ProviderKeyedPersistedIntent
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.services.provider_keyed_terraform_release import _REVIEWED_PATH, _REVIEWED_SHA256
from app.storage.job_repository import StoredJobRun


def _fixture(tmp_path: Path):
    engagement_id, connection_id, selector = "eng-opaque", "connection-opaque", "selector123"
    fingerprint = hashlib.sha256(f"digitalocean\0{connection_id}".encode()).hexdigest()
    root = tmp_path / engagement_id / SCHEMA / "digitalocean" / fingerprint
    root.mkdir(parents=True)
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data", SCHEMA,
        "digitalocean", connection_id, fingerprint, _SOURCE_REVISION, _SOURCE_SHA256,
    )
    address = 'digitalocean_droplet.middle["middle_01"]'
    node = DigitalOceanNodeCreate("middle01-opaque", "image-opaque", "size-opaque", "nyc3", selector)
    reviewed = ProviderKeyedPersistedIntent(
        engagement_id=engagement_id, core_job_id="job-core-opaque", core_plan_id="plan-opaque",
        revision_id="revision-opaque", provider="digitalocean", engagement_name="opaque",
        selector_tag=selector, proxy_egress_ips={"proxy01": "192.0.2.10"},
        topology={}, chain_routes=(), nodes={address: node},
        firewall=DigitalOceanInitialFirewallIntent("opaque-firewall", selector,
            ("80", "443", "2222"), (), ("192.0.2.10/32",)),
        nonsecret_varfile={},
    )
    state = {
        "version": 4, "serial": 1, "lineage": "11111111-1111-4111-8111-111111111111",
        "resources": [
            {"type": "digitalocean_droplet", "name": "middle", "instances": [{
                "index_key": "middle_01", "attributes": {"id": 101, "name": node.name,
                    "region": node.region, "ipv4_address": "203.0.113.10", "tags": [selector]},
            }]},
            {"type": "digitalocean_firewall", "name": "firewall", "instances": [{
                "attributes": {"id": "11111111-2222-4333-8444-555555555555",
                    "name": "opaque-firewall", "tags": [selector]},
            }]},
        ],
    }
    (root / ".barragan-apply-phase.json").write_text(json.dumps({"schema": SCHEMA, "phase": "applied"}))
    _write_state(workspace, state)
    material = root.parents[1] / ".plan-material" / "digitalocean"
    evidence = {
        "coreJobId": reviewed.core_job_id, "corePlanId": reviewed.core_plan_id,
        "revisionId": reviewed.revision_id, "providerConnectionId": connection_id,
        "selectorTag": selector, "sourceRevision": _SOURCE_REVISION,
        "planPath": str(root / ".barragan-initial-full.tfplan"),
        "planSha256": "a" * 64, "sourceSha256": _SOURCE_SHA256,
        "markerSha256": "b" * 64, "topologySha256": "c" * 64,
        "lockfileSha256": "d" * 64,
        "inputSha256": [[str(material / "inputs.json"), "e" * 64]],
        "credentialSecretSha256": "f" * 64,
        "credentialUpdatedAt": "2026-10-07T00:00:00+00:00",
        "terraformBinaryPath": str(_REVIEWED_PATH),
        "terraformBinarySha256": _REVIEWED_SHA256, "terraformVersion": "1.15.5",
        "adminPublicKeySha256": "1" * 64,
        "adminPrivateKeyPath": str(material / "admin-private"),
        "adminPublicKeyPath": str(material / "admin-public"),
        "sshOutputDirectory": str(material / "ssh-output"),
    }
    apply = _apply_job(reviewed, _hash(workspace.state_path))
    return reviewed, workspace, evidence, apply, state


def _write_state(workspace, state):
    workspace.state_path.write_text(json.dumps(state, sort_keys=True))


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _apply_job(reviewed, state_hash):
    return StoredJobRun(
        id="job-provider-keyed-initial-apply-core-opaque",
        action="provider_keyed_initial_apply", status="succeeded",
        target=f"engagement:{reviewed.engagement_id}", target_type="engagement",
        target_id=reviewed.engagement_id, requested_by="operator",
        input={"engagementId": reviewed.engagement_id, "coreJobId": reviewed.core_job_id,
               "corePlanId": reviewed.core_plan_id,
               "planJobId": "job-provider-keyed-initial-plan-core-opaque", "mutation": True},
        artifact_refs=[], created_at="2026-10-07T00:00:00+00:00",
        started_at="2026-10-07T00:01:00+00:00", finished_at="2026-10-07T00:02:00+00:00",
        events=[JobEvent(1, "info", "provider saved-plan apply completed; proof pending",
            {"stateSha256": state_hash, "selectorTag": reviewed.selector_tag,
             "attachmentProofPending": True, "hostProofPending": True})],
    )


def test_derives_exact_attachment_identity_from_reviewed_state(tmp_path):
    reviewed, workspace, evidence, apply, _state = _fixture(tmp_path)
    result = service.derive_digitalocean_initial_attachment_intent(reviewed, workspace, evidence, apply)
    assert result.state_sha256 == _hash(workspace.state_path)
    assert result.firewall_id == "11111111-2222-4333-8444-555555555555"
    assert result.nodes[0].address == 'digitalocean_droplet.middle["middle_01"]'
    assert result.nodes[0].droplet_id == "101"
    assert result.nodes[0].public_ipv4 == "203.0.113.10"
    assert result.trusted_ssh_cidrs == ("192.0.2.10/32",)
    assert result.credential_record_id == "connection-opaque"
    assert result.credential_secret_sha256 == "f" * 64


@pytest.mark.parametrize("mismatch", [
    "state_hash", "node_name", "node_region", "node_tag", "extra_droplet",
    "firewall_name", "module", "selector", "credential", "phase", "apply_input",
])
def test_rejects_state_apply_and_plan_mismatch(tmp_path, mismatch):
    reviewed, workspace, evidence, apply, state = _fixture(tmp_path)
    if mismatch == "state_hash":
        workspace.state_path.write_text(workspace.state_path.read_text() + " ")
    elif mismatch == "node_name":
        state["resources"][0]["instances"][0]["attributes"]["name"] = "wrong"
    elif mismatch == "node_region":
        state["resources"][0]["instances"][0]["attributes"]["region"] = "wrong"
    elif mismatch == "node_tag":
        state["resources"][0]["instances"][0]["attributes"]["tags"] = ["wrong"]
    elif mismatch == "extra_droplet":
        state["resources"][0]["instances"].append({"index_key": "extra", "attributes": {
            "id": 102, "name": "extra", "region": "nyc3", "ipv4_address": "203.0.113.11",
            "tags": [reviewed.selector_tag]}})
    elif mismatch == "firewall_name":
        state["resources"][1]["instances"][0]["attributes"]["name"] = "wrong"
    elif mismatch == "module":
        state["resources"][0]["module"] = "module.unreviewed"
    elif mismatch == "selector":
        apply = replace(apply, events=[replace(apply.events[0], data={
            **apply.events[0].data, "selectorTag": "wrong"})])
    elif mismatch == "credential":
        evidence["providerConnectionId"] = "wrong"
    elif mismatch == "phase":
        (workspace.path / ".barragan-apply-phase.json").write_text(json.dumps({"schema": SCHEMA, "phase": "planned"}))
    else:
        apply = replace(apply, input={**apply.input, "planJobId": "wrong"})
    if mismatch in {"node_name", "node_region", "node_tag", "extra_droplet", "firewall_name", "module"}:
        _write_state(workspace, state)
        apply = _apply_job(reviewed, _hash(workspace.state_path))
    with pytest.raises(service.ProviderKeyedInitialAttachmentAdapterError, match="reviewed apply"):
        service.derive_digitalocean_initial_attachment_intent(reviewed, workspace, evidence, apply)


def test_derived_intent_reconciles_with_actual_get_only_provider_contract(tmp_path, monkeypatch):
    reviewed, workspace, plan_evidence, apply, _state = _fixture(tmp_path)
    encrypted = "encrypted-fixture-token"
    plan_evidence["credentialSecretSha256"] = hashlib.sha256(encrypted.encode()).hexdigest()
    intent = service.derive_digitalocean_initial_attachment_intent(
        reviewed, workspace, plan_evidence, apply,
    )

    class Credentials:
        def get(self, identifier):
            return self.get_default("digitalocean") if identifier == workspace.provider_connection_id else None

        def get_default(self, provider):
            assert provider == "digitalocean"
            return type("Credential", (), {
                "id": workspace.provider_connection_id, "provider": provider,
                "status": "active", "is_default": True,
                "encrypted_secret": encrypted,
                "updated_at": plan_evidence["credentialUpdatedAt"],
            })()

    def rule(protocol, ports, addresses, *, side="sources"):
        return {"protocol": protocol, "ports": ports, side: {"addresses": addresses}}

    node = intent.nodes[0]
    peer = f"{node.public_ipv4}/32"
    inbound = [rule("tcp", port, ["0.0.0.0/0"]) for port in ("80", "443", "2222")]
    inbound.append(rule("tcp", "22", list(intent.trusted_ssh_cidrs)))
    inbound.extend(rule(protocol, "1-65535", [peer])
                   for protocol in ("tcp", "udp", "icmp"))
    outbound = [rule(protocol, "0" if protocol == "icmp" else "1-65535",
                     ["0.0.0.0/0"], side="destinations")
                for protocol in ("tcp", "udp", "icmp")]
    responses = {
        f"/firewalls/{intent.firewall_id}": {"firewall": {
            "id": intent.firewall_id, "name": intent.firewall_name,
            "status": "succeeded", "pending_changes": [],
            "tags": [intent.selector_tag], "droplet_ids": [],
            "inbound_rules": inbound, "outbound_rules": outbound,
        }},
        f"/droplets?page=1&per_page=200&tag_name={intent.selector_tag}": {
            "droplets": [{"id": int(node.droplet_id), "tags": [intent.selector_tag]}],
            "meta": {"total": 1}, "links": {},
        },
        "/droplets?page=1&per_page=200&type=gpus": {
            "droplets": [], "meta": {"total": 0}, "links": {},
        },
        f"/droplets/{node.droplet_id}": {"droplet": {
            "id": int(node.droplet_id), "name": node.name,
            "region": {"slug": node.region}, "tags": [intent.selector_tag],
            "status": "active",
        }},
        f"/droplets/{node.droplet_id}/firewalls?page=1&per_page=200": {
            "firewalls": [{"id": intent.firewall_id}],
            "meta": {"total": 1}, "links": {},
        },
    }

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, origin, method, path, token):
            self.calls.append((origin, method, path, token))
            return responses[path]

    monkeypatch.setattr(attachment_service, "decrypt_secret_value", lambda value: "fixture-api-token")
    transport = Transport()
    proof = attachment_service.reconcile_digitalocean_initial_attachment(
        workspace, intent, environment="devtest", deployment_target="barragan-testing",
        credential_repository=Credentials(), transport=transport,
        sleeper=lambda _seconds: pytest.fail("settled proof must not sleep"),
    )
    assert proof.provider_membership_verified is True
    assert proof.host_policy_verified is False
    assert proof.state_sha256 == intent.state_sha256
    assert proof.verified_droplet_ids == (node.droplet_id,)
    assert all(method == "GET" and token == "fixture-api-token"
               for _origin, method, _path, token in transport.calls)
