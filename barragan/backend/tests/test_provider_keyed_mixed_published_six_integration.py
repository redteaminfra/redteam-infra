# Copyright (c) 2026, Oracle and/or its affiliates.
"""A saved six-node generation survives the writer-to-teardown read path.

This is an offline persistence test. Provider states and routed host captures
are fixture evidence; the publication writer, retained host-receipt validator,
initial seal reader, append-plan sealer, source reader, and scope reader are real.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _MESSAGES, _digest, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
from app.services.provider_keyed_mixed_published_six_scope import build_mixed_published_six_teardown_scope
from app.services.provider_keyed_mixed_published_six_source import (
    derive_mixed_published_six_policies, recognize_mixed_published_six_source,
)
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel, EngagementModel
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
import app.services.provider_keyed_mixed_append_pair_host_proof as host_proof
import test_provider_keyed_mixed_append_pair_host_proof as host_test
from test_provider_keyed_mixed_published_six_source import _policy_case
from test_provider_keyed_mixed_published_six_scope import _case, _resource
from app.services.provider_keyed_mixed_append_pair_apply_binding import _intent
from app.services.provider_keyed_mixed_append_pair_parent import _plan_child_id
from app.services.provider_keyed_mixed_append_pair_plan import seal_mixed_append_pair_plan
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _SUMMARY_KEYS
from app.services.provider_keyed_mixed_append_first_poststate import FirstPoststateProof
from app.services.provider_keyed_mixed_published_six_journal import validate_mixed_published_six_journals
import app.services.provider_keyed_mixed_append_first_proof_job as first_proof
import app.services.provider_keyed_mixed_append_second_proof_job as second_proof
import app.services.provider_keyed_mixed_append_pair_apply_child as first_apply
import app.services.provider_keyed_mixed_append_second_apply_child as second_apply


def _initial_parent(source, reviewed_policies):
    """Build the exact durable six-event initial seal, with the real reader."""
    order = source.provider_order
    ids = tuple(next(chain.chain_id for chain in source.before_chains
                     if chain.middle_provider == provider) for provider in order)
    review = "a" * 64
    inputs = {"engagementId": source.engagement_id,
              "coreJobId": source.core_job_id, "corePlanId": source.core_plan_id,
              "revisionId": "rev", "reviewFingerprint": review,
              "orderedProviders": list(order), "chainIds": list(ids),
              "phase": "completed", "mutation": True}
    rows = [JobEvent(1, "info", _MESSAGES[0], {
        "coreJobId": source.core_job_id, "reviewFingerprint": review}),
        JobEvent(2, "info", _MESSAGES[1], {})]
    for index, provider in enumerate(order):
        rows.append(JobEvent(index + 3, "info", _MESSAGES[index + 2], {
            "provider": provider, "chainId": ids[index],
            "receiptSha256": str(index + 1) * 64}))
    rows.append(JobEvent(5, "info", _MESSAGES[4], {
        "firstReceiptSha256": rows[2].data["receiptSha256"],
        "secondReceiptSha256": rows[3].data["receiptSha256"],
        "reviewFingerprint": review}))
    snapshots = [reviewed_policies[provider] for provider in order]
    seal = {"schema": "mixed-initial-apply-seal-v1",
            "corePlanId": source.core_plan_id, "reviewFingerprint": review,
            "orderedProviders": list(order), "chainIds": list(ids),
            "providerConnectionIds": [f"connection-{provider}" for provider in order],
            "receiptSha256": [rows[2].data["receiptSha256"],
                              rows[3].data["receiptSha256"]],
            "intentSha256": [_digest(snapshot) for snapshot in snapshots],
            "sourceCredentialSnapshotSha256": _digest(snapshots),
            "firstFiveJournalSha256": job_event_digest(rows),
            "reviewedPolicy": reviewed_policies}
    rows.append(JobEvent(6, "info", _MESSAGES[5], seal))
    parent = StoredJobRun(
        "job-provider-keyed-mixed-initial-core", "provider_keyed_mixed_initial",
        "succeeded", f"engagement:{source.engagement_id}", "engagement",
        source.engagement_id, "operator", inputs, [],
        "2026-10-19T00:00:00+00:00", "2026-10-19T00:00:00+00:00",
        "2026-10-19T00:00:00+00:00", rows)
    assert validate_mixed_initial_apply_seal(parent) == seal
    return parent


def _states_and_children(source, options):
    """Use the complete two-provider state fixture with droplet addresses."""
    observations, children, state_hashes, proof_digests = {}, {}, [], []
    for index, provider in enumerate(source.provider_order):
        original = options["observations"][provider]
        raw = original.state_json.replace(
            b"digitalocean_instance", b"digitalocean_droplet")
        state = json.loads(raw)
        for resource in state["resources"]:
            for instance in resource["instances"]:
                address = resource["type"] + "." + resource["name"]
                if "index_key" in instance:
                    address += "[" + json.dumps(instance["index_key"]) + "]"
                row = next((row for row in source.host_rows
                            if row.terraform_address == address), None)
                if row is not None:
                    instance["attributes"]["region"] = next(
                        node["region"] for chain in source.chains
                        for node in chain.nodes
                        if node["terraformAddress"] == address)
        raw = json.dumps(state, sort_keys=True).encode()
        digest = hashlib.sha256(raw).hexdigest()
        resource_ids = tuple((address.replace(
            "digitalocean_instance.", "digitalocean_droplet."), value)
            for address, value in original.classification.resource_ids)
        classification = replace(original.classification,
                                 state_sha256=digest, resource_ids=resource_ids)
        observations[provider] = ProviderHostObservation(classification, raw)
        state_hashes.append(digest)
        old = options["provider_children"][provider]
        events = list(old.events)
        events[8] = replace(events[8], data={
            **events[8].data, "stateSha256": digest,
            "resourceIds": sorted([address.replace(
                "digitalocean_instance.", "digitalocean_droplet."), value]
                for address, value in events[8].data["resourceIds"])})
        events[9] = replace(events[9], data={
            "proofJournalSha256": job_event_digest(events[:9])})
        children[provider] = replace(old, id=(
            f"job-provider-keyed-mixed-append-apply-{'first' if index == 0 else 'second'}-"
            f"{source.parent_id.removeprefix('job-')}"), events=events)
        proof_digests.append(job_event_digest(events))
    return observations, children, tuple(state_hashes), tuple(proof_digests)



def _terminal_children(source, approved, files, old_roots, observations, children):
    """Create real result/proof grammars over the saved fixture state artifacts."""
    predecessors, retained, hashes = {}, {}, {}
    for provider in source.provider_order:
        state = json.loads(observations[provider].state_json)
        new_address = source.new_edge_addresses[source.provider_order.index(provider)]
        state["resources"] = [resource for resource in state["resources"]
            if resource["type"] + "." + resource["name"] + (
                "[" + json.dumps(resource["instances"][0]["index_key"]) + "]"
                if "index_key" in resource["instances"][0] else "") != new_address]
        for address in ("local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"):
            state["resources"].append(_resource(address, {"id": address}))
        state["serial"] -= 1
        predecessors[provider] = json.dumps(state, sort_keys=True).encode()
        hashes[provider] = hashlib.sha256(predecessors[provider]).hexdigest()
        retained[provider] = sorted([resource["type"] + "." + resource["name"] + (
            "[" + json.dumps(instance["index_key"]) + "]" if "index_key" in instance else ""),
            str(instance["attributes"]["id"])]
            for resource in state["resources"] for instance in resource["instances"])
    data = json.loads(json.dumps(approved.input))
    receipts = {}
    for provider in source.provider_order:
        intent = data["intents"][provider]
        for item in source.provider_order:
            intent[item + "_state_sha256"] = hashes[item]
            intent["retained_" + item + "_ids"] = retained[item]
        root = old_roots[provider]
        files[root / _name(provider, "predecessor.tfstate")] = predecessors[provider]
        path = root / _name(provider, "plan-receipt.json")
        receipts[provider] = json.loads(files[path])
        receipts[provider]["predecessorStateSha256"] = hashes[provider]
        files[path] = json.dumps(receipts[provider]).encode()
        data["receiptSha256"][provider] = hashlib.sha256(files[path]).hexdigest()
    decoded = {provider: _intent(provider, data["intents"][provider])
               for provider in source.provider_order}
    data["pairPlanSha256"] = seal_mixed_append_pair_plan(
        decoded["digitalocean"], decoded["linode"],
        tuple({key: receipts[provider][key] for key in _SUMMARY_KEYS}
              for provider in source.provider_order),
        reviewed_provider_order=source.provider_order,
        reviewed_chain_order=source.chain_ids).review_sha256
    data.update(phase="apply_sealed", schema="mixed-append-pair-parent-v1")
    historical = replace(approved, status="running", finished_at=None, input=data)
    result_children = {}
    for index, provider in enumerate(source.provider_order):
        stage = "first" if index == 0 else "second"
        module = first_apply if index == 0 else second_apply
        receipt = receipts[provider]
        messages = [
            (f"mixed append {stage} Apply queued", {}),
            (f"mixed append {stage} Apply started", {}),
            (f"mixed append {stage} Apply command intended", {
                "invocationId": "saved-invocation-" + provider,
                "argvSha256": "5" * 64, "planSha256": receipt["planSha256"],
                "planPath": str(Path(source.workspace_paths[index]) / _name(provider, "saved.tfplan")),
                "terraformPath": "/terraform", "terraformSha256": receipt["terraformBinarySha256"]}),
            (f"mixed append {stage} Apply command started before GO", {
                "invocationId": "saved-invocation-" + provider,
                "bootId": "saved-boot", "pid": 123, "pgid": 123, "startTicks": 99}),
            (f"mixed append {stage} phase apply_started", {"commandStartSequence": 4}),
            (f"mixed append {stage} Apply command result fenced", {
                "invocationId": "saved-invocation-" + provider, "returnCode": 0,
                "stdoutBytes": 0, "stderrBytes": 0,
                "stdoutTruncated": False, "stderrTruncated": False}),
            (f"mixed append {stage} phase applied", {"commandResultSequence": 6}),
            (f"mixed append {stage} awaiting exact poststate proof", {"commandResultSequence": 6}),
        ]
        child = replace(children[provider], id=module._child_id(historical.id),
            action=module.ACTION, status="running", finished_at=None,
            input=module._base(historical), events=[JobEvent(number, "info", message, payload)
                for number, (message, payload) in enumerate(messages, 1)])
        artifact_source = first_proof._ApprovedFirstSource(None, decoded[provider], receipt,
            data["receiptSha256"][provider], predecessors[provider],
            files[old_roots[provider] / _name(provider, "show.json")])
        result = (first_proof.recognize_first_mixed_append_zero_result(historical, child, receipt)
                  if index == 0 else second_proof._result(historical, child, receipt))
        original = children[provider].events[8].data
        edge = source.chains[index].nodes[2]
        attached = tuple(sorted(row.provider_instance_id for row in source.host_rows
                                if row.provider == provider))
        proof = FirstPoststateProof(provider, original["stateSha256"], original["lineage"],
            original["serial"], tuple(tuple(row) for row in original["resourceIds"]),
            edge["terraformAddress"], edge["providerInstanceId"], edge["publicIp"],
            "6" * 64, "7" * 64, None if provider == "linode" else len(attached), attached)
        first_digest = (None if index == 0 else job_event_digest(
            result_children[source.provider_order[0]].events))
        payload = (first_proof._proof_event_data(historical, artifact_source, result, proof)
                   if index == 0 else second_proof._proof_data(
                       historical, artifact_source, result, first_digest, proof))
        events = [*child.events, JobEvent(9, "info", f"mixed append {stage} exact poststate proved", payload)]
        events.append(JobEvent(10, "info", f"mixed append {stage} provider Apply succeeded",
                               {"proofJournalSha256": job_event_digest(events)}))
        child = replace(child, status="succeeded", finished_at=children[provider].finished_at,
                        events=events)
        assert (first_proof._journal(historical, child, artifact_source) if index == 0
                else second_proof._journal(historical, child, artifact_source, first_digest))[1] == "terminal"
        result_children[provider] = child
    return replace(approved, input=data), result_children

def persisted_six_case(client, tmp_path, monkeypatch, *, reverse=False, inert_history=False, sql_host=False):
    """Persist the real publication and return its read-only teardown inputs."""
    source, approved, _initial, base, files = _policy_case()
    _fixture_source, options = _case()
    if reverse:
        source = replace(source, **{name: tuple(reversed(getattr(source, name)))
            for name in ("provider_order", "chain_ids", "before_chains", "chains",
                         "new_edge_addresses", "provider_proof_digests",
                         "state_sha256s", "workspace_paths", "source_revisions",
                         "proxy_egress_ips")})
        approved = replace(approved, input={**approved.input,
            "providerOrder": list(source.provider_order),
            "chainOrder": list(source.chain_ids)})
    assert set(source.chain_ids) == set(_fixture_source.chain_ids)
    host_root = tmp_path / "host"
    host_root.mkdir()
    roots = (host_root / "do", host_root / "linode")
    old_roots = dict(zip(source.provider_order, map(Path, source.workspace_paths)))
    new_roots = dict(zip(source.provider_order, roots))
    def moved(chain):
        provider = chain.middle_provider
        return replace(chain, terraform_working_directory=str(new_roots[provider]))
    def writer_ready(before, after):
        middle = {**before.nodes[0], "componentId": "middle"}
        edge = {**before.nodes[1], "componentId": "edge-01"}
        old = replace(moved(before), nodes=[middle, edge])
        new = {**after.nodes[2], "componentId": "edge-02",
               "edgeId": "edge-02", "edgeIndex": "2", "edgeCount": "2",
               "status": "deployed", "proxy": after.assigned_proxy}
        published = replace(old, edge_count=2,
            edge_intents=after.edge_intents,
            nodes=[middle, {**edge, "edgeCount": "2"}, new],
            updated_at=after.updated_at)
        return old, published
    rows = tuple(writer_ready(before, after) for before, after in zip(
        source.before_chains, source.chains, strict=True))
    source = replace(source,
        workspace_paths=tuple(str(root) for root in roots),
        core_known_hosts_path=str(host_root / "core-known-hosts"),
        before_chains=tuple(row[0] for row in rows),
        chains=tuple(row[1] for row in rows))
    observations, children, states, proofs = _states_and_children(source, options)
    approved, children = _terminal_children(
        source, approved, files, old_roots, observations, children)
    source = replace(source, state_sha256s=states, provider_proof_digests=tuple(
        job_event_digest(children[provider].events) for provider in source.provider_order))

    with client.application.storage_context():
        db.session.add(EngagementModel(
            id=source.engagement_id, name="opaque", status="deployed",
            owner="operator", template_id="small-dev", active_revision="rev",
            input_parameters={}, sketch_state_schema="provider-keyed-v2"))
        db.session.commit()
        chains = SqlAlchemySketchChainRepository()
        jobs = SqlAlchemyJobRepository()
        if inert_history:
            chains.save(replace(source.before_chains[0], chain_id="old-default",
                status="aborted", burned=False, deploy_job_id="", teardown_job_id="",
                terraform_working_directory="", nodes=[]))
        before = tuple(chains.save(chain) for chain in source.before_chains)
        after = tuple(replace(chain,
            created_at=before[index].created_at,
            updated_at=datetime.now(timezone.utc).isoformat())
            for index, chain in enumerate(source.chains))
        source = replace(source, before_chains=before, chains=after)

        # The host fixture runs the one-shot producer and its real receipt
        # validator over local routed-capture artifacts. Only the provider
        # observations are fixture data; no cloud or Terraform command runs.
        captured = []
        real_validator = host_proof.validate_six_host_receipt_child
        monkeypatch.setattr(host_test, "_source", lambda: source)
        def capture(parent, child, receipt, *, source):
            result = real_validator(parent, child, receipt, source=source)
            captured.append((child, result, source))
            return result
        monkeypatch.setattr(host_proof, "validate_six_host_receipt_child", capture)
        if sql_host:
            # Preserve the outer publication database while the exact worker
            # produces its persisted receipt through real SQL claims/CAS.
            state = db.configure('sqlite:///:memory:')
            with db.bind(state):
                db.create_all()
                host_test.test_two_edge_contact_is_one_shot_and_receipt_reopens(
                    host_root, monkeypatch, SqlAlchemyJobRepository(), 'sql-queued')
        else:
            host_test.test_two_edge_contact_is_one_shot_and_receipt_reopens(
                host_root, monkeypatch, None, "memory")
        host, receipt, produced_source = captured[0]
        assert produced_source == source
        for old_path, value in files.items():
            provider = next(provider for provider, root in old_roots.items()
                            if old_path.is_relative_to(root))
            selected = new_roots[provider] / old_path.relative_to(old_roots[provider])
            selected.write_bytes(value)
            selected.chmod(0o600)

        now = datetime.now(timezone.utc)
        claimed = (now - timedelta(minutes=2)).isoformat()
        finished = (now + timedelta(seconds=10)).isoformat()
        expiry = (now + timedelta(minutes=30)).isoformat()
        approved = replace(approved, status="running", finished_at=None,
            created_at=claimed, started_at=claimed,
            input={**approved.input, "schema": "mixed-append-pair-parent-v1",
                   "engagementId": source.engagement_id, "mutation": True,
                   "phase": "apply_sealed",
                   "claimOwner": receipt.claim_owner,
                   "claimToken": receipt.claim_token,
                   "claimClaimedAt": claimed, "claimExpiresAt": expiry},
            events=[JobEvent(1, "info", "mixed append pair approved",
                             {"reviewSha256": approved.input["reviewSha256"],
                              "planChildId": _plan_child_id(approved.id)})])
        jobs.save(approved)
        jobs.save(host)
        for child in children.values():
            jobs.save(replace(child, created_at=claimed, started_at=claimed,
                              finished_at=claimed))
        initial = jobs.save(_initial_parent(source, base))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=source.engagement_id, owner_id=source.core_plan_id,
            operation="provider_keyed_mixed_append"))
        db.session.commit()
        proof_by_provider = {provider: job_event_digest(children[provider].events)
                             for provider in source.provider_order}
        writer_args = dict(
            parent=jobs.get(approved.id), before_chains=before, after_chains=after,
            provider_proof_children={provider: jobs.get(child.id)
                                     for provider, child in children.items()},
            host_proof_child=jobs.get(host.id), receipt=receipt,
            expected_parent_event_digest=job_event_digest(approved.events),
            expected_provider_event_digests=proof_by_provider,
            expected_host_event_digest=job_event_digest(host.events),
            claim_owner=receipt.claim_owner, claim_token=receipt.claim_token,
            finished_at=finished,
            fresh_source=lambda: source,
            local_fence=lambda selected: selected.source_sha256)
        published = chains.publish_provider_keyed_mixed_append_pair(**writer_args)
        assert len(published) == 2

        parent = jobs.get(approved.id)
        child_rows = {provider: jobs.get(child.id)
                      for provider, child in children.items()}
        current = {chain.chain_id: chains.get(source.engagement_id, chain.chain_id)
                   for chain in source.chains}
        reopened, reopened_receipt = recognize_mixed_published_six_source(
            parent, host_proof_child=jobs.get(host.id),
            provider_children=child_rows, current_chains=current)
        assert reopened == source
        assert reopened_receipt == receipt
        policies = derive_mixed_published_six_policies(
            reopened, parent, jobs.get(initial.id))
        assert all(len(policy["nodes"]) == 3 for policy in policies.values())
        validate_mixed_published_six_journals(reopened, parent, child_rows)
        scope = build_mixed_published_six_teardown_scope(
            reopened, append_parent=parent, host_proof_child=jobs.get(host.id),
            host_receipt=reopened_receipt, provider_children=child_rows,
            reviewed_policies=policies,
            reviewed_chain_fingerprints={
                chain.chain_id: sketch_chain_intent_fingerprint(chain)
                for chain in source.chains},
            observations=observations, chains=current,
            live_bindings={key: tuple(rows)
                           for key, rows in options["live_bindings"].items()})
        assert scope.binding_count == 4
        assert len(scope.provider_scopes) == 2
        assert sum(len(policy["nodes"]) for policy in policies.values()) == 6

        return dict(source=reopened, append_parent=parent,
                    host_proof_child=jobs.get(host.id), host_receipt=reopened_receipt,
                    provider_children=child_rows, reviewed_policies=policies,
                    reviewed_chain_fingerprints={chain.chain_id:
                        sketch_chain_intent_fingerprint(chain) for chain in source.chains},
                    observations=observations, chains=current,
                    live_bindings=options["live_bindings"])


@pytest.mark.parametrize("reverse", [False, True])
def test_persisted_writer_source_policy_and_six_scope_join(client, tmp_path, monkeypatch, reverse):
    persisted_six_case(client, tmp_path, monkeypatch, reverse=reverse)


def test_sql_queued_host_worker_receipt_publishes_and_reopens_six_scope(client, tmp_path, monkeypatch):
    persisted_six_case(client, tmp_path, monkeypatch, sql_host=True, inert_history=True)
