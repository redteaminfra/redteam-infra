# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline join of one Deploy, four routed captures, receipt, and SQL publication."""

from dataclasses import replace
from types import SimpleNamespace
import hashlib
import json
import os
import stat

import pytest

from app.services import provider_keyed_mixed_initial_public as public
from app.services import provider_keyed_mixed_initial_publication as publication
from app.services import provider_keyed_mixed_initial_host_proof as proof
from app.services import provider_keyed_mixed_strict_host_receipt as receipt_module
from app.services import provider_keyed_mixed_initial_apply_child as apply_module
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanHostIdentityEvidence, DigitalOceanRawFirewallEvidence,
    DigitalOceanRawHostCollection, DigitalOceanRawHostSurfaceEvidence,
)
from app.services.provider_keyed_mixed_linode_host_probe import (
    LinodeRawHostCollection, LinodeRawHostIdentity,
)
from app.services.provider_keyed_mixed_strict_host_receipt import (
    validate_receipt_child as real_validate_receipt_child,
)
from app.services.sketch_bootstrap import SketchBootstrapCoreHost
from test_provider_keyed_mixed_initial_composed_sql import _completed_bootstrap_case
from test_provider_keyed_mixed_initial_publication_transaction import _public_key


def _join_case(client, monkeypatch, tmp_path, reverse):
    repo, jobs, leases, args, _old_contacts = _completed_bootstrap_case(
        client, monkeypatch, tmp_path, reverse=reverse)
    # The reused writer fixture stubs this gate. Restore the actual receipt
    # validator so this test crosses the complete collector-to-writer join.
    monkeypatch.setattr(receipt_module, "validate_receipt_child",
                        real_validate_receipt_child)
    source = args["source"]
    projections = args["projected_chains"]
    parent = jobs.get(source.parent_job_id)
    jobs.save(replace(parent, input={key: value for key, value in parent.input.items()
                                    if not key.startswith("claim")}))
    manifest = {
        "schema": "mixed-initial-host-binding-v1",
        "engagementId": source.engagement_id,
        "orderedProviders": list(source.ordered_providers),
        "chainIds": list(source.chain_ids),
        "nodes": [{**node} for projection in projections for node in projection.chain.nodes],
    }
    source = replace(source, binding_manifest_sha256=receipt_module._sha(manifest))
    args["source"] = source
    binding_id = "job-provider-keyed-mixed-host-binding-core"
    binding = jobs.get(binding_id)
    jobs.save(replace(binding, input={**binding.input,
        "manifestSha256": source.binding_manifest_sha256}))
    workspaces = {provider: tmp_path / provider for provider in source.ordered_providers}
    for path in workspaces.values():
        path.mkdir()
    args["provider_workspaces"] = {provider: str(path) for provider, path in workspaces.items()}
    monkeypatch.setattr(apply_module, "recognize_mixed_initial_apply_terminal",
                        lambda _child, _parent, provider: {
                            "planPath": str(workspaces[provider] / "saved.tfplan"),
                            "proof": {"stateSha256": next(state.state_sha256 for state in
                                       source.provider_states if state.provider == provider),
                                      "lineage": "lineage", "serial": 1,
                                      "resourceIds": {"instance": provider + "-1"}},
                        })

    # These are the external observations and core connection that a disposable
    # deployment would supply. The proof journal, artifact, receipt, and writer
    # below remain real and persisted.
    monkeypatch.setattr(proof, "active_core_connection_details",
                        lambda *_args: ("job-core", {}))
    monkeypatch.setattr(proof, "_core_known_hosts",
                        lambda _core: (str(tmp_path / "core-known-hosts"), "a" * 64))
    monkeypatch.setattr(proof, "_sketch_file_snapshot",
                        lambda _path: (0, 0, "c" * 64))
    monkeypatch.setattr(proof, "_process_quiescent", lambda *_args: True)
    monkeypatch.setattr(proof, "validate_mixed_initial_apply_seal",
                        lambda _parent: {"orderedProviders": source.ordered_providers,
                                          "chainIds": list(source.chain_ids),
                                          "reviewedPolicy": {}})
    monkeypatch.setattr(proof, "recognize_mixed_initial_host_binding",
                        lambda _binding, _parent: manifest)
    monkeypatch.setattr(proof, "recognize_mixed_initial_apply_terminal",
                        lambda _child, _parent, provider: {"provider": provider})
    monkeypatch.setattr(proof, "_prior_workspace",
                        lambda _parent, provider, _terminal: SimpleNamespace(
                            path=workspaces[provider]))
    monkeypatch.setattr(proof, "recognize_mixed_initial_publication_source",
                        lambda **_kwargs: source)
    monkeypatch.setattr(proof, "project_mixed_initial_chains",
                        lambda *_args: projections)
    monkeypatch.setattr(proof, "_core_hosts", lambda *_args, **_kwargs: (
        SketchBootstrapCoreHost("homebase", "1.1.1.1", "user", "/tmp/identity"),
        SketchBootstrapCoreHost("proxy01", "192.168.2.12", "user", "/tmp/identity",
                                "8.8.8.8")))
    monkeypatch.setattr(proof, "_sketch_nodes", lambda *_args, **_kwargs: (object(), (object(),)))
    admin = SimpleNamespace(public_key=_public_key(1))
    transport = SimpleNamespace(public_key=_public_key(2))
    monkeypatch.setattr(proof, "retrieve_sketch_ssh_key", lambda _eng: admin)
    monkeypatch.setattr(proof, "retrieve_sketch_transport_ssh_key", lambda _eng: transport)

    # The interpreter profiles have their own literal raw-capture tests. Here
    # they assert that the verifier passed each selected expected identity.
    def interpreted(collection, *, expected_identity, expected_predecessor_ipv4,
                    expected_policy, **_kwargs):
        assert collection.identity == expected_identity
        assert expected_policy is not None
        return SimpleNamespace(predecessor_ipv4=expected_predecessor_ipv4,
                               complete_ssh_policy=True)

    for name in ("interpret_linode_host_policy", "interpret_linode_host_surface",
                 "interpret_digitalocean_host_policy", "interpret_digitalocean_host_surface"):
        monkeypatch.setattr(receipt_module, name, interpreted)

    seen = []

    def routed_capture(*, scratch_path, scratch_intent_callback, intent_callback,
                       started_callback, heartbeat_callback, result_callback,
                       node=None, expected=None, manifest_sha256=None,
                       core_known_hosts_sha256=None, sketch_known_hosts_sha256=None,
                       **_kwargs):
        selected = node if node is not None else next(row for row in manifest["nodes"]
            if row["hostname"] == expected.name)
        hostname = selected["hostname"]
        seen.append(hostname)
        scratch_intent_callback(str(scratch_path))
        invocations = []
        for index in range(4):
            invocation = f"{hostname}-{index}"
            invocations.append(invocation)
            intent = CommandIntent(invocation, str(scratch_path), "a" * 64)
            intent_callback(intent)
            started = StartedCommand(intent, ProcessIdentity("boot", 10, 10, 20))
            started_callback(started)
            heartbeat_callback(started)
            result_callback(CommandAuditResult(started, 0, 123, 0, False, False))
        core_sha = core_known_hosts_sha256 or "a" * 64
        sketch_sha = sketch_known_hosts_sha256 or "c" * 64
        common = (manifest_sha256, selected["chainId"], selected["terraformAddress"],
                  selected["providerInstanceId"])
        rest = (selected["region"], selected["publicIp"], hostname, "boot")
        do_identity = DigitalOceanHostIdentityEvidence(
            *common, *rest, "alias", invocations[0], core_sha, sketch_sha)
        predecessor = "8.8.8.8" if selected["role"] == "middle" else next(
            row["publicIp"] for row in manifest["nodes"]
            if row["chainId"] == selected["chainId"] and row["role"] == "middle")
        ssh_connection = (predecessor, 50000, selected["publicIp"], 22)
        before = DigitalOceanRawFirewallEvidence(do_identity, invocations[1], "boot", 1, 2, (), ())
        surface = DigitalOceanRawHostSurfaceEvidence(
            do_identity, invocations[2], "boot", 3, 4, predecessor,
            ssh_connection, (), (), "listeners")
        after = replace(before, invocation_id=invocations[3], started_at_ns=5,
                        completed_at_ns=6)
        raw = DigitalOceanRawHostCollection(do_identity, before, surface, after)
        if node is None:
            return raw
        linode_identity = LinodeRawHostIdentity(
            *common, "linode/ubuntu24.04", *rest, ssh_connection,
            invocations[0], core_sha, sketch_sha)
        return LinodeRawHostCollection(linode_identity, raw)

    def real_collect(engagement_id, core_job_id, **kwargs):
        return proof.collect_mixed_initial_strict_host_proof(
            engagement_id, core_job_id, **kwargs,
            fresh_observer=lambda *_args: None,
            linode_collector=routed_capture,
            digitalocean_middle_collector=routed_capture,
            digitalocean_edge_collector=routed_capture)

    monkeypatch.setattr(publication, "collect_mixed_initial_strict_host_proof", real_collect)
    monkeypatch.setattr(publication, "recognize_mixed_initial_host_binding",
                        lambda _binding, _parent: manifest)
    return repo, jobs, leases, args, seen


@pytest.mark.parametrize("reverse", [False, True], ids=["linode-first", "digitalocean-first"])
def test_real_four_host_receipt_flows_through_one_deploy_and_atomic_sql(
        client, monkeypatch, tmp_path, reverse):
    with client.application.storage_context():
        repo, jobs, leases, args, seen = _join_case(client, monkeypatch, tmp_path, reverse)
        parent = public.advance_reviewed_mixed_initial(
            "job-core", environment="devtest", rollout_enabled=True,
            job_repository=jobs)
        assert parent.status == "succeeded"
        assert parent.input["phase"] == "completed"
        assert seen == [row.hostname for row in args["source"].host_rows]
        assert len(set(seen)) == 4
        child = jobs.get(public._proof_child_id("job-core"))
        assert child.status == "succeeded"
        assert len(child.events) == 60
        evidence_path = next(event.data["evidencePath"] for event in child.events
                             if event.message == "mixed strict host proof completed")
        with open(evidence_path, "rb") as stream:
            artifact = stream.read()
        assert stat.S_IMODE(os.stat(evidence_path).st_mode) == 0o600
        assert hashlib.sha256(artifact).hexdigest() == child.events[-2].data["hostEvidenceSha256"]
        assert len(json.loads(artifact)) == 4
        assert {row.chain_id: (row.status, row.terraform_working_directory)
                for row in repo.list_for_engagement(args["source"].engagement_id)} == {
            chain.chain_id: ("deployed", args["provider_workspaces"][chain.middle_provider])
            for chain in args["pending_chains"]}
        assert leases.acquire(args["source"].engagement_id, "next-plan", "prepare")
        scheduled = []
        assert public.recover_reviewed_mixed_initial_dispatches(
            environment="devtest", rollout_enabled=True,
            schedule=scheduled.append) == []
        assert scheduled == [] and len(seen) == 4
