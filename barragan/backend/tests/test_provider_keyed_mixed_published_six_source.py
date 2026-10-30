# Copyright (c) 2026, Oracle and/or its affiliates.
"""The published six-node source reopens exact append history and current rows."""

from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_initial_plan_gate import DigitalOceanNodeCreate
from app.services.provider_keyed_linode_initial_plan_gate import LinodeNodeCreate
from app.services.provider_keyed_mixed_append_intent import (
    MixedDigitalOceanOnLinodeAppendIntent, _SHARED_DO, _SHARED_LINODE,
)
from app.services.provider_keyed_mixed_append_linode_intent import MixedLinodeOnDigitalOceanAppendIntent
from app.services.provider_keyed_mixed_append_pair_plan import seal_mixed_append_pair_plan
import app.services.provider_keyed_mixed_append_pair_host_proof as host_proof
from app.services.provider_keyed_mixed_published_six_source import (
    MixedPublishedSixSourceAttention, derive_mixed_published_six_policies,
    recognize_mixed_published_six_source, same_published_chain,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _SUMMARY_KEYS
from app.storage.database import db
from app.storage.job_repository import (
    SqlAlchemyJobRepository, StoredJobRun, job_event_digest,
)
from app.storage.models import EngagementModel
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
import test_provider_keyed_mixed_append_pair_host_proof as host_test
from test_provider_keyed_mixed_published_six_scope import _case


def _saved(reverse=False):
    source, options = _case(reverse)
    parent, old_host = options["append_parent"], options["host_proof_child"]
    host = replace(old_host,
        input={"claimOwner": "mixed-append-host-proof-worker",
               "claimToken": "token"},
        events=[JobEvent(1, "info", "mixed append six-host proof completed", {
            "sourceSha256": source.source_sha256,
            "providerOrder": list(source.provider_order),
            "chainIds": list(source.chain_ids),
            "newEdgeAddresses": list(source.new_edge_addresses),
            "newEdgeIds": [chain.nodes[2]["providerInstanceId"]
                           for chain in source.chains],
            "providerProofDigests": list(source.provider_proof_digests),
            "bootstrapEventDigests": ["a" * 64, "b" * 64],
            "sketchKnownHostsDigests": ["c" * 64, "d" * 64],
            "rawProbeDigests": ["e" * 64, "f" * 64],
        })])
    data = json.loads(json.dumps(parent.events[-1].data))
    data["hostProofJournalSha256"] = job_event_digest(host.events)
    parent = replace(parent, events=[replace(parent.events[-1], data=data)])
    return source, parent, host, options


@pytest.mark.parametrize("reverse", [False, True])
def test_saved_six_node_source_round_trip_and_current_rows(reverse):
    source, parent, host, options = _saved(reverse)
    selected, receipt = recognize_mixed_published_six_source(
        parent, host_proof_child=host,
        provider_children=options["provider_children"],
        current_chains=options["chains"],
        host_receipt_validator=lambda _parent, _child, receipt, **_kw: receipt)
    assert selected == source
    assert receipt.source_sha256 == source.source_sha256
    assert receipt.child_event_sha256 == job_event_digest(host.events)


def test_sqlite_utc_timestamp_round_trip_keeps_every_other_chain_field_bound():
    source, _ = _case()
    published = source.chains[0]
    assert same_published_chain(replace(
        published, created_at="2026-10-19T00:00:00",
        updated_at="2026-10-19T00:00:00"), published)
    assert not same_published_chain(replace(
        published, updated_at="2026-10-19T00:00:01"), published)
    assert not same_published_chain(replace(
        published, assigned_proxy="foreign"), published)


@pytest.mark.parametrize("drift", [
    "source", "digest", "host", "provider", "chain", "schema",
])
def test_saved_six_node_source_rejects_history_or_current_drift(drift):
    source, parent, host, options = _saved()
    children, chains = options["provider_children"], options["chains"]
    if drift in {"source", "digest", "schema"}:
        data = dict(parent.events[-1].data)
        if drift == "source":
            saved = dict(data["source"])
            saved["core_job_id"] = "job-foreign"
            data["source"] = saved
        elif drift == "digest":
            data["sourceSha256"] = "0" * 64
        else:
            saved = dict(data["source"])
            saved["unexpected"] = True
            data["source"] = saved
        parent = replace(parent, events=[replace(parent.events[-1], data=data)])
    elif drift == "host":
        host = replace(host, events=[replace(host.events[-1],
                                            message="foreign host proof")])
    elif drift == "provider":
        provider = source.provider_order[0]
        child = children[provider]
        children = {**children, provider: replace(child, events=[replace(
            child.events[0], message="foreign provider proof"),
            *child.events[1:]])}
    else:
        chain_id = source.chain_ids[0]
        chains = {**chains, chain_id: replace(chains[chain_id],
                                              assigned_proxy="foreign")}
    with pytest.raises(MixedPublishedSixSourceAttention):
        recognize_mixed_published_six_source(
            parent, host_proof_child=host, provider_children=children,
            current_chains=chains,
            host_receipt_validator=lambda _parent, _child, receipt, **_kw: receipt)


def test_persisted_source_reopens_real_one_shot_host_receipt(
        client, tmp_path, monkeypatch):
    """Use the existing local host producer, then reopen its saved DB journals."""
    provider_events = {
        provider: [JobEvent(1, "info", f"{provider} provider proof", {})]
        for provider in ("digitalocean", "linode")}
    with client.application.storage_context():
        original_source = host_test._source()
        db.session.add(EngagementModel(
            id=original_source.engagement_id, name="opaque", status="deployed",
            owner="operator", template_id="small-dev", active_revision="rev",
            input_parameters={}, sketch_state_schema="provider-keyed-v2"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        chains = SqlAlchemySketchChainRepository()
        for chain in original_source.chains:
            chains.save(chain)
        persisted = tuple(chains.get(original_source.engagement_id, chain.chain_id)
                          for chain in original_source.chains)
        monkeypatch.setattr(host_test, "_source", lambda: replace(
            original_source, chains=persisted,
            provider_proof_digests=tuple(job_event_digest(provider_events[provider])
                                         for provider in original_source.provider_order)))
        original_validator = host_proof.validate_six_host_receipt_child
        captured = []

        def capture(parent, child, receipt, *, source):
            result = original_validator(parent, child, receipt, source=source)
            captured.append((parent, child, result, source))
            return result

        monkeypatch.setattr(host_proof, "validate_six_host_receipt_child", capture)
        host_test.test_two_edge_contact_is_one_shot_and_receipt_reopens(
            tmp_path, monkeypatch, None, "memory")
        assert captured
        before_parent, host, receipt, source = captured[0]
        finished = datetime.now(timezone.utc).isoformat()
        children = {provider: StoredJobRun(
            f"job-{provider}-append-proof", "provider-proof", "succeeded",
            before_parent.target, before_parent.target_type, source.engagement_id,
            before_parent.requested_by, {}, [], finished, finished, finished,
            provider_events[provider]) for provider in source.provider_order}
        parent = replace(before_parent, status="succeeded", finished_at=finished,
                         input={**before_parent.input, "phase": "completed"},
                         events=[JobEvent(1, "info",
                             "mixed append six-node generation published", {
                                 "sourceSha256": source.source_sha256,
                                 "source": json.loads(json.dumps(asdict(source))),
                                 "hostProofJournalSha256": job_event_digest(host.events),
                                 "providerProofJournalSha256": {
                                     provider: job_event_digest(children[provider].events)
                                     for provider in source.provider_order},
                                 "chainIds": list(source.chain_ids),
                             })])
        jobs.save(parent)
        jobs.save(host)
        for child in children.values():
            jobs.save(child)
        selected, reopened_receipt = recognize_mixed_published_six_source(
            jobs.get(parent.id), host_proof_child=jobs.get(host.id),
            provider_children={provider: jobs.get(child.id)
                               for provider, child in children.items()},
            current_chains={chain.chain_id: chains.get(
                source.engagement_id, chain.chain_id) for chain in source.chains})
        assert selected == source
        assert reopened_receipt == receipt


def _policy_case():
    source, options = _case()
    def droplet(row):
        return {**row, "terraformAddress": row["terraformAddress"].replace(
            "digitalocean_instance.", "digitalocean_droplet.")}
    def corrected(chain):
        edges = chain.edge_intents
        if len(chain.nodes) == 3:
            edge = chain.nodes[2]
            edges = [*edges, {"id": "edge-02", "provider": edge["provider"],
                              "region": edge["region"], "size": "small"}]
        return replace(chain, nodes=[droplet(row) for row in chain.nodes],
                       edge_intents=edges)
    source = replace(source,
        before_chains=tuple(corrected(row) for row in source.before_chains),
        chains=tuple(corrected(row) for row in source.chains),
        new_edge_addresses=tuple(address.replace(
            "digitalocean_instance.", "digitalocean_droplet.")
            for address in source.new_edge_addresses))
    parent = options["append_parent"]
    event = parent.events[-1]
    parent = replace(parent, events=[replace(event, data={**event.data,
        "source": json.loads(json.dumps(asdict(source))),
        "sourceSha256": source.source_sha256})])
    base = {}
    for provider in source.provider_order:
        old = {node["terraformAddress"] for chain in source.before_chains
               for node in chain.nodes if node["provider"] == provider}
        policy = json.loads(json.dumps(options["reviewed_policies"][provider]))
        policy["nodes"] = {address.replace(
            "digitalocean_instance.", "digitalocean_droplet."): row
            for address, row in policy["nodes"].items()
            if address.replace("digitalocean_instance.",
                               "digitalocean_droplet.") in old}
        base[provider] = policy
    intents, inputs, files, receipts = {}, {}, {}, {}
    predecessors = {"digitalocean": b"old do", "linode": b"old linode"}
    old_states = {provider: hashlib.sha256(value).hexdigest()
                  for provider, value in predecessors.items()}
    old_ids = {}
    for provider, shared in (("digitalocean", _SHARED_DO),
                             ("linode", _SHARED_LINODE)):
        nodes = {node["terraformAddress"]: node["providerInstanceId"]
                 for chain in source.before_chains for node in chain.nodes
                 if node["provider"] == provider}
        old_ids[provider] = tuple(sorted({**nodes, **{
            address: f"shared-{provider}-{index}"
            for index, address in enumerate(sorted(shared))}}.items()))
    for index, provider in enumerate(source.provider_order):
        edge = source.chains[index].nodes[2]
        name = edge["hostname"]
        common = dict(engagement_id=source.engagement_id,
                      core_job_id=source.core_job_id,
                      chain_id=source.chain_ids[index],
                      digitalocean_state_sha256=old_states["digitalocean"],
                      linode_state_sha256=old_states["linode"],
                      retained_digitalocean_ids=old_ids["digitalocean"],
                      retained_linode_ids=old_ids["linode"],
                      prior_trusted_ssh_cidrs=("8.8.8.1/32",),
                      trusted_ssh_cidrs=("8.8.8.1/32", "8.8.8.2/32"),
                      new_edge_address=source.new_edge_addresses[index],
                      new_edge_ordinal=2,
                      nonsecret_varfile={"final": provider})
        if provider == "digitalocean":
            intent = MixedDigitalOceanOnLinodeAppendIntent(
                **common, linode_middle_address=source.before_chains[index].nodes[0][
                    "terraformAddress"], linode_middle_id="21",
                new_edge=DigitalOceanNodeCreate(
                    name, "image", "small", edge["region"], "tag"))
        else:
            intent = MixedLinodeOnDigitalOceanAppendIntent(
                **common, digitalocean_middle_address=source.before_chains[index].nodes[0][
                    "terraformAddress"], digitalocean_middle_id="41",
                new_edge=LinodeNodeCreate(
                    name, "image", "small", edge["region"], "tag", ("ssh-public",)))
        intents[provider] = asdict(intent)
        inputs[provider] = intent.nonsecret_varfile
        root = Path(source.workspace_paths[index])
        def save(suffix, value):
            files[root / suffix] = value
            return hashlib.sha256(value).hexdigest()
        input_sha = save(_name(provider, "inputs.json"),
                         json.dumps(inputs[provider]).encode())
        plan_sha = save(_name(provider, "saved.tfplan"),
                        f"saved {provider} plan".encode())
        show_sha = save(_name(provider, "show.json"), b"{}")
        save(_name(provider, "predecessor.tfstate"), predecessors[provider])
        topology_sha = save(".barragan-topology.json", b'{"schema":"provider-keyed-v2"}')
        marker_sha = save(".barragan-provider-keyed-state.json", b"marker")
        lock_sha = save(".terraform.lock.hcl", b"lock")
        predecessor_sha = hashlib.sha256(files[
            root / _name(provider, "predecessor.tfstate")]).hexdigest()
        intents[provider]["digitalocean_state_sha256"] = old_states["digitalocean"]
        intents[provider]["linode_state_sha256"] = old_states["linode"]
        receipt = {
            "schema": "mixed-append-saved-plan-receipt-v1",
            "provider": provider, "engagementId": source.engagement_id,
            "coreJobId": source.core_job_id, "chainId": source.chain_ids[index],
            "predecessorStateSha256": predecessor_sha,
            "newEdgeAddress": source.new_edge_addresses[index],
            "planSha256": plan_sha, "showJsonSha256": show_sha,
            "sourceRevision": source.source_revisions[index],
            "sourceSha256": "1" * 64, "sourceMarkerSha256": marker_sha,
            "topologySha256": topology_sha, "lockfileSha256": lock_sha,
            "inputSha256": input_sha, "credentialRecordId": "cred",
            "credentialSecretSha256": "2" * 64,
            "credentialUpdatedAt": "2026-10-19T00:00:00Z",
            "terraformBinarySha256": "3" * 64, "journalSha256": "4" * 64,
        }
        receipts[provider] = save(_name(provider, "plan-receipt.json"),
                                  json.dumps(receipt).encode())
    request = {
        "digitalocean": {"selectedChainId": intents["digitalocean"]["chain_id"],
                         "edgeRegion": intents["digitalocean"]["new_edge"]["region"],
                         "edgeSize": "small", "edgeImage": "image", "selectorTag": "tag"},
        "linode": {"selectedChainId": intents["linode"]["chain_id"],
                   "edgeRegion": intents["linode"]["new_edge"]["region"],
                   "edgeType": "small", "edgeImage": "image", "engagementTag": "tag"},
    }
    from app.services.provider_keyed_mixed_append_pair_apply_binding import _intent
    decoded = {provider: _intent(provider, intents[provider])
               for provider in source.provider_order}
    receipt_rows = []
    for provider in source.provider_order:
        root = Path(source.workspace_paths[source.provider_order.index(provider)])
        receipt_rows.append({key: json.loads(files[
            root / _name(provider, "plan-receipt.json")])[key]
                             for key in _SUMMARY_KEYS})
    pair_sha = seal_mixed_append_pair_plan(
        decoded["digitalocean"], decoded["linode"], tuple(receipt_rows),
        reviewed_provider_order=source.provider_order,
        reviewed_chain_order=source.chain_ids).review_sha256
    parent = replace(parent, input={**parent.input, "intents": intents,
        "reviewedInputs": inputs, "receiptSha256": receipts,
        "reviewRequest": request, "pairPlanSha256": pair_sha})
    initial = replace(parent, input={"engagementId": source.engagement_id,
                                      "coreJobId": source.core_job_id})
    return source, parent, initial, base, files


def test_final_policy_reopens_saved_inputs_and_adds_both_foreign_edges():
    source, parent, initial, base, files = _policy_case()
    result = derive_mixed_published_six_policies(
        source, parent, initial,
        artifact_reader=lambda path, **_kw: files[path],
        initial_seal_reader=lambda _parent: {
            "corePlanId": source.core_plan_id, "reviewedPolicy": base},
        )
    assert set(result) == set(source.provider_order)
    for provider, policy in result.items():
        assert len(policy["nodes"]) == 3
        assert policy["nonsecret_varfile"] == {"final": provider}
        assert policy["topology"] == {"schema": "provider-keyed-v2"}


@pytest.mark.parametrize("drift", [
    "inputs", "plan", "receipt", "topology", "intent", "pair_review",
    "saved_source", "initial_nodes",
])
def test_final_policy_rejects_saved_plan_or_review_drift(drift):
    source, parent, initial, base, files = _policy_case()
    provider = source.provider_order[0]
    root = Path(source.workspace_paths[0])
    if drift in {"inputs", "plan", "receipt", "topology"}:
        suffix = {
            "inputs": _name(provider, "inputs.json"),
            "plan": _name(provider, "saved.tfplan"),
            "receipt": _name(provider, "plan-receipt.json"),
            "topology": ".barragan-topology.json",
        }[drift]
        files[root / suffix] += b" "
    elif drift == "intent":
        data = dict(parent.input)
        intents = json.loads(json.dumps(data["intents"]))
        intents[provider]["new_edge"]["name"] = "foreign"
        data["intents"] = intents
        parent = replace(parent, input=data)
    elif drift == "pair_review":
        parent = replace(parent, input={**parent.input, "pairPlanSha256": "0" * 64})
    elif drift == "saved_source":
        event = parent.events[-1]
        parent = replace(parent, events=[replace(event, data={**event.data,
            "source": {**event.data["source"], "core_job_id": "foreign"}})])
    else:
        base[provider]["nodes"].pop(next(iter(base[provider]["nodes"])))
    with pytest.raises(MixedPublishedSixSourceAttention):
        derive_mixed_published_six_policies(
            source, parent, initial,
            artifact_reader=lambda path, **_kw: files[path],
            initial_seal_reader=lambda _parent: {
                "corePlanId": source.core_plan_id, "reviewedPolicy": base},
            )
