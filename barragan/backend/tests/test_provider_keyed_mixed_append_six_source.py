# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from types import SimpleNamespace
import hashlib
from dataclasses import replace
import json

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_append_six_source import (
    MixedAppendSixSourceAttention, collect_fresh_six_node_host_source,
    project_mixed_append_six_chains,
    verify_six_node_local_fence,
)
from app.services.provider_keyed_mixed_append_first_poststate import prove_first_mixed_append_poststate
from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_child_id
from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_child_id
from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository, StoredSketchChain
from test_provider_keyed_mixed_append_first_poststate import _case as provider_case


def _case(order):
    chains = []
    intents = {}
    request = {}
    proofs = {}
    for provider in order:
        middle_provider = "linode" if provider == "digitalocean" else "digitalocean"
        chain_id = f"chain-{middle_provider}"
        middle = {"chainId": chain_id, "role": "middle", "provider": middle_provider,
                  "hostname": f"middle-{middle_provider}",
                  "terraformAddress": f'{middle_provider}_instance.middle["one"]',
                  "providerInstanceId": f"{middle_provider}-middle-id", "publicIp": "8.8.8.8",
                  "region": "old", "assignedProxy": "proxy01", "proxy": "proxy01",
                  "status": "deployed", "componentId": "middle"}
        old_edge = {**middle, "role": "edge", "hostname": f"edge-{middle_provider}",
                    "terraformAddress": f'{middle_provider}_instance.edge["one"]',
                    "providerInstanceId": f"{middle_provider}-edge-id",
                    "publicIp": "1.1.1.1", "componentId": "edge-01",
                    "edgeId": "edge-01", "edgeIndex": "1", "edgeCount": "1"}
        chains.append(StoredSketchChain(
            chain_id, "eng-one", "proxy01", middle_provider, "old", "small",
            middle_provider, "old", "small", "deployed", False, "", "initial-job",
            "", f"/tmp/{middle_provider}", [middle, old_edge],
            "2026-10-19T00:00:00+00:00", "2026-10-19T00:00:00+00:00", 1,
            [{"id": "edge-01", "provider": middle_provider,
              "region": "old", "size": "small"}],
        ))
        edge = ({"name": f"new-{provider}", "region": "new", "size": "small"}
                if provider == "digitalocean" else
                {"label": f"new-{provider}", "region": "new", "node_type": "small"})
        address = f'{provider}_instance.edge["new"]'
        middle_key = ("linode_middle" if provider == "digitalocean"
                      else "digitalocean_middle")
        intents[provider] = {"new_edge": edge, "new_edge_address": address,
                             f"{middle_key}_address": middle["terraformAddress"],
                             f"{middle_key}_id": middle["providerInstanceId"]}
        request[provider] = {"edgeRegion": "new",
                             "edgeSize" if provider == "digitalocean" else "edgeType": "small"}
        proofs[provider] = {"provider": provider, "newEdgeAddress": address,
                            "newEdgeProviderId": f"{provider}-new-id",
                            "newEdgePublicIp": "9.9.9.9" if provider == "digitalocean"
                            else "4.4.4.4"}
    # The old host IPs are unique in real generations. Keep the fixture so too.
    chains[1].nodes[0]["publicIp"] = "8.8.4.4"
    chains[1].nodes[1]["publicIp"] = "1.0.0.1"
    parent = SimpleNamespace(
        action="provider_keyed_mixed_append", status="running", target_id="eng-one",
        started_at="2026-10-19T01:00:00+00:00",
        input={"phase": "apply_sealed", "providerOrder": list(order),
               "chainOrder": [chain.chain_id for chain in chains],
               "intents": intents, "reviewRequest": request,
               "selectedMiddles": {
                   provider: chain.nodes[0]["terraformAddress"]
                   for provider, chain in zip(order, chains, strict=True)}},
    )
    return parent, tuple(chains), proofs


@pytest.mark.parametrize("order", [
    ("digitalocean", "linode"), ("linode", "digitalocean"),
])
def test_six_node_projection_preserves_four_hosts_and_cross_provider_route(order):
    parent, before, proofs = _case(order)
    after = project_mixed_append_six_chains(parent, before, proofs)
    assert len(after) == 2
    assert [node for row in after for node in row.nodes if node["role"] == "edge"]
    for index, provider in enumerate(order):
        assert after[index].nodes[0] == before[index].nodes[0]
        assert after[index].nodes[1] == {**before[index].nodes[1], "edgeCount": "2"}
        assert after[index].nodes[2]["provider"] == provider
        assert after[index].nodes[2]["chainId"] == before[index].chain_id
        assert after[index].edge_intents[0] == before[index].edge_intents[0]
        assert after[index].edge_intents[1]["provider"] == provider
        assert after[index].edge_count == 2
    assert before[0].nodes[1]["edgeCount"] == "1"


def test_six_node_projection_rejects_wrong_provider_proof():
    parent, before, proofs = _case(("digitalocean", "linode"))
    proofs["digitalocean"]["newEdgeAddress"] = "wrong"
    with pytest.raises(MixedAppendSixSourceAttention):
        project_mixed_append_six_chains(parent, before, proofs)


def test_six_node_projection_rejects_changed_middle_selection():
    parent, before, proofs = _case(("digitalocean", "linode"))
    parent.input["selectedMiddles"]["digitalocean"] = "wrong"
    with pytest.raises(MixedAppendSixSourceAttention):
        project_mixed_append_six_chains(parent, before, proofs)


def test_local_publication_fence_reads_only_exact_state_and_trust(tmp_path, monkeypatch):
    import app.services.provider_keyed_mixed_append_six_source as module

    monkeypatch.setattr(module, "validate_six_node_host_source", lambda source: source)
    roots, state_hashes = [], []
    for provider in ("linode", "digitalocean"):
        root = tmp_path / provider
        root.mkdir(mode=0o700)
        state = root / "terraform.tfstate"
        state.write_bytes(provider.encode())
        trust = root / ".barragan-sketch-known-hosts"
        trust.write_bytes(f"trust-{provider}".encode())
        trust.chmod(0o600)
        roots.append(str(root))
        state_hashes.append(hashlib.sha256(state.read_bytes()).hexdigest())
    core = tmp_path / "core-known-hosts"
    core.write_bytes(b"core trust")
    core.chmod(0o600)
    source = SimpleNamespace(
        core_known_hosts_path=str(core),
        core_known_hosts_sha256=hashlib.sha256(core.read_bytes()).hexdigest(),
        workspace_paths=tuple(roots), state_sha256s=tuple(state_hashes),
        source_sha256="stable",
    )
    assert verify_six_node_local_fence(source) == "stable"
    (tmp_path / "linode" / "terraform.tfstate").write_bytes(b"changed")
    with pytest.raises(MixedAppendSixSourceAttention):
        verify_six_node_local_fence(source)


def _proof_event(proof, provider):
    return {"provider": provider, "stateSha256": proof.state_sha256,
            "lineage": proof.lineage, "serial": proof.serial,
            "resourceIds": [list(row) for row in proof.resource_ids],
            "newEdgeAddress": proof.new_edge_address,
            "newEdgeProviderId": proof.new_edge_provider_id,
            "newEdgePublicIp": proof.new_edge_public_ip,
            "inventorySha256": proof.inventory_sha256,
            "selectorResourcesCount": proof.selector_resources_count,
            "attachedNodeIds": list(proof.attached_node_ids)}


@pytest.mark.parametrize("order", [
    ("digitalocean", "linode"), ("linode", "digitalocean"),
])
@pytest.mark.parametrize("lease_operation", ["provider_keyed_mixed_append", "provider_keyed_teardown_fence"])
def test_persisted_collector_reopens_both_provider_poststates_and_vetoes_drift(
        tmp_path, monkeypatch, order, lease_operation):
    import app.services.provider_keyed_mixed_append_six_source as module
    import app.services.provider_keyed_mixed_append_second_apply_binding as binding

    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        jobs, sketches = SqlAlchemyJobRepository(), SqlAlchemySketchChainRepository()
        base_parent, original, _ = _case(order)
        parent_id = "job-provider-keyed-mixed-append-core"
        parent_input = {**base_parent.input, "coreJobId": "job-core",
                        "corePlanId": "plan-core", "reviewSha256": "a" * 64}
        prior = {provider: provider_case(provider) for provider in order}
        # Independent provider fixtures use the same illustrative IP. A joined
        # engagement needs two distinct global edge addresses.
        linode_state = json.loads(prior["linode"]["snapshot"].state_json)
        for resource in linode_state["resources"]:
            if (resource["type"] == "linode_instance"
                    and resource["name"] == "edge"):
                for instance in resource["instances"]:
                    if instance.get("index_key") == "us-sea-02":
                        instance["attributes"]["ipv4"] = ["4.4.4.4"]
            if resource["type"] == "linode_firewall":
                for row in resource["instances"][0]["attributes"]["inbound"][4:7]:
                    row["ipv4"] = ["4.4.4.4/32" if ip == "9.9.9.9/32" else ip
                                   for ip in row["ipv4"]]
        raw_linode_state = json.dumps(linode_state).encode()
        linode_plan = json.loads(prior["linode"]["reviewed_show_json"])
        next(change for change in linode_plan["resource_changes"]
             if change["address"] == prior["linode"]["intent"].new_edge_address
             )["change"]["after"]["ipv4"] = ["4.4.4.4"]
        firewall_after = next(change for change in linode_plan["resource_changes"]
                              if change["address"] == "linode_firewall.firewall")["change"]["after"]
        for row in firewall_after["inbound"][4:7]:
            row["ipv4"] = ["4.4.4.4/32" if ip == "9.9.9.9/32" else ip
                           for ip in row["ipv4"]]
        prior["linode"]["reviewed_show_json"] = json.dumps(linode_plan).encode()
        prior["linode"]["snapshot"] = replace(
            prior["linode"]["snapshot"], state_json=raw_linode_state,
            state_sha256=hashlib.sha256(raw_linode_state).hexdigest())
        proof = {provider: prove_first_mixed_append_poststate(**prior[provider])
                 for provider in order}
        before = []
        for index, provider in enumerate(order):
            chain = original[index]
            intent = prior[provider]["intent"]
            middle = chain.nodes[0]
            middle_key = "linode_middle" if provider == "digitalocean" else "digitalocean_middle"
            middle["terraformAddress"] = getattr(intent, f"{middle_key}_address")
            middle["providerInstanceId"] = str(getattr(intent, f"{middle_key}_id"))
            retained = dict(intent.retained_linode_ids if chain.middle_provider == "linode"
                            else intent.retained_digitalocean_ids)
            old_edge = chain.nodes[1]
            old_edge["terraformAddress"] = next(address for address in retained
                                                if ".edge[" in address)
            old_edge["providerInstanceId"] = str(retained[old_edge["terraformAddress"]])
            edge = intent.new_edge
            parent_input["intents"][provider] = {
                "new_edge": ({"name": edge.name, "region": edge.region,
                              "size": edge.size} if provider == "digitalocean" else
                             {"label": edge.label, "region": edge.region,
                              "node_type": edge.node_type}),
                "new_edge_address": intent.new_edge_address,
                f"{middle_key}_address": middle["terraformAddress"],
                f"{middle_key}_id": middle["providerInstanceId"],
            }
            parent_input["selectedMiddles"][provider] = middle["terraformAddress"]
            parent_input["reviewRequest"][provider] = {
                "edgeRegion": edge.region,
                "edgeSize" if provider == "digitalocean" else "edgeType":
                    edge.size if provider == "digitalocean" else edge.node_type,
            }
            before.append(chain)
            sketches.save(chain)
        now = "2026-10-19T01:00:00+00:00"
        def job(identifier, action, status="succeeded", events=None, input_data=None):
            return StoredJobRun(identifier, action, status, "engagement:eng-one",
                                "engagement", "eng-one", "operator", input_data or {},
                                [], now, now, now if status == "succeeded" else None,
                                events or [JobEvent(1, "info", "done", {})])
        core = job("job-core", "pilot_standard_rti_guarded_execute",
                   input_data={"engagementId": "eng-one"})
        parent = job(parent_id, "provider_keyed_mixed_append", "running",
                     [JobEvent(1, "info", "mixed append pair approved", {})], parent_input)
        historical = job("job-mixed-initial", "provider_keyed_mixed_initial")
        binding_child = job(_binding_child_id(core.id), "provider_keyed_mixed_initial_host_binding")
        children = {}
        for index, provider in enumerate(order):
            events = [JobEvent(sequence, "info", "journal", {})
                      for sequence in range(1, 9)]
            events.append(JobEvent(9, "info", "poststate proved",
                                   _proof_event(proof[provider], provider)))
            child = job(first_child_id(parent.id) if index == 0 else second_child_id(parent.id),
                        "provider apply child", events=events)
            children[provider] = child
        for row in (core, parent, historical, binding_child, *children.values()):
            jobs.save(row)

        roots = {}
        for provider in order:
            root = tmp_path / provider
            root.mkdir()
            (root / "terraform.tfstate").write_bytes(prior[provider]["snapshot"].state_json)
            roots[provider] = root
        core_trust = tmp_path / "core-known-hosts"
        core_trust.write_bytes(b"reviewed core trust")
        core_trust.chmod(0o600)
        sources = {provider: SimpleNamespace(
            intent=prior[provider]["intent"],
            predecessor_state=prior[provider]["predecessor_state"],
            reviewed_show_json=prior[provider]["reviewed_show_json"],
            receipt={}, historical=historical,
            workspace=SimpleNamespace(path=roots[provider], source_revision="revision"))
            for provider in order}
        monkeypatch.setattr(module, "active_core_connection_details",
                            lambda *args: (core.id, {}))
        monkeypatch.setattr(module, "_load_approved_first_source",
                            lambda *args: sources[order[0]])
        monkeypatch.setattr(module, "_approved_second",
                            lambda *args: sources[order[1]])
        manifest = {"nodes": [{key: node[key] if key != "assignedProxy" else chain.assigned_proxy
                               for key in ("chainId", "provider", "role", "hostname",
                                           "terraformAddress", "providerInstanceId",
                                           "publicIp", "region", "assignedProxy")}
                              for chain in before for node in chain.nodes]}
        monkeypatch.setattr(module, "recognize_mixed_initial_host_binding",
                            lambda *args: manifest)
        monkeypatch.setattr(binding, "_journal", lambda *args: (
            SimpleNamespace(started_identity={"bootId": "boot", "pid": 1,
                                              "pgid": 1, "startTicks": 1}), "terminal"))
        monkeypatch.setattr(binding, "_process_quiescent", lambda *args: True)
        monkeypatch.setattr(module, "second_journal", lambda *args: (
            SimpleNamespace(started_identity={"bootId": "boot", "pid": 2,
                                              "pgid": 2, "startTicks": 2}), "terminal"))
        monkeypatch.setattr(module, "_process_quiescent", lambda *args: True)
        monkeypatch.setattr(module, "_core_hosts", lambda *args, **kwargs: (
            None, SimpleNamespace(host_key_alias="203.0.113.10")))
        monkeypatch.setattr(module, "_core_known_hosts", lambda *args: (
            str(core_trust), hashlib.sha256(core_trust.read_bytes()).hexdigest()))
        snapshots = {provider: prior[provider]["snapshot"] for provider in order}
        reads = []
        def collect(*, intent, fence, **kwargs):
            fence()
            provider = "digitalocean" if hasattr(intent.new_edge, "name") else "linode"
            reads.append(provider)
            return snapshots[provider]
        options = dict(job_repository=jobs, sketch_repository=sketches,
                       credential_repository=object(),
                       lease_lookup=lambda _: ("plan-core", lease_operation),
                       lease_operation=lease_operation, snapshot_collector=collect)
        source = collect_fresh_six_node_host_source(parent.id, **options)
        assert reads == list(order)
        assert source.provider_order == order
        assert source.provider_proof_digests == tuple(
            job_event_digest(children[provider].events) for provider in order)
        assert tuple(len(chain.nodes) for chain in source.chains) == (3, 3)
        assert len(source.host_rows) == 6
        reads.clear()
        snapshots[order[1]] = replace(snapshots[order[1]], state_sha256="0" * 64)
        with pytest.raises(MixedAppendSixSourceAttention):
            collect_fresh_six_node_host_source(parent.id, **options)
        assert reads == list(order)
