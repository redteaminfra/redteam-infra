# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fresh six-node observations use actual append proof resource domains.

The provider snapshot is offline fixture data from the append poststate tests;
no credential, provider request, or Terraform execution occurs here.
"""
from dataclasses import asdict, replace
import hashlib
import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_published_six_collector import _fresh_observation
from app.services.provider_keyed_mixed_append_first_poststate import prove_first_mixed_append_poststate
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
from test_provider_keyed_mixed_append_first_poststate import _case


def _observation_case(tmp_path, provider):
    data = _case(provider)
    snapshot = data["snapshot"]
    proof = prove_first_mixed_append_poststate(**data)
    actual = _state_resources(json.loads(snapshot.state_json))
    nodes = {}
    for address, attrs in actual.items():
        if not address.startswith(("linode_instance.", "digitalocean_droplet.")):
            continue
        nodes[address] = ({"label": attrs["label"], "tag": attrs["tags"][0],
                           "image": attrs["image"], "region": attrs["region"],
                           "node_type": attrs["type"]} if provider == "linode" else
                          {"name": attrs["name"], "firewall_selector_tag": attrs["tags"][0],
                           "image": attrs["image"], "region": attrs["region"],
                           "size": attrs["size"]})
    policy = {"nodes": nodes, "engagement_name": "e7c9a4d2",
              "firewall": {"name": "e7c9a4d2-firewall", "selector_tag": "s12345678"},
              "ssh_key_name": "key", "admin_public_key": "ssh-ed25519 reviewed"}
    receipt = json.dumps({"provider": provider}).encode()
    path = tmp_path / _name(provider, "plan-receipt.json")
    path.write_bytes(receipt)
    path.chmod(0o600)
    source = SimpleNamespace(provider_order=(provider,), workspace_paths=(str(tmp_path),),
                             state_sha256s=(snapshot.state_sha256,))
    append = SimpleNamespace(input={"intents": {provider: asdict(data["intent"])},
        "receiptSha256": {provider: hashlib.sha256(receipt).hexdigest()}})
    events = [JobEvent(i, "info", "fixture", {}) for i in range(1, 10)]
    events[3] = replace(events[3], data={"bootId": "boot", "pid": 1, "pgid": 1, "startTicks": 1})
    events[8] = replace(events[8], data={"stateSha256": proof.state_sha256,
        "lineage": proof.lineage, "serial": proof.serial,
        "resourceIds": [list(row) for row in proof.resource_ids]})
    child = SimpleNamespace(events=events)
    options = dict(snapshot_reader=lambda **kwargs: snapshot,
                   process_quiescent=lambda *args: True)
    return source, append, SimpleNamespace(path=tmp_path), policy, child, snapshot, options


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_fresh_observation_accepts_real_append_proof_resource_ids(tmp_path, provider):
    source, append, workspace, policy, child, snapshot, options = _observation_case(tmp_path, provider)
    calls = []
    result = _fresh_observation(provider, source, append, workspace, policy, child,
                                lambda: calls.append(True) or "generation", **options)
    assert result.state_json == snapshot.state_json
    assert result.classification.kind == "full"
    assert len(child.events[8].data["resourceIds"]) == 5
    assert len(result.classification.resource_ids) == (4 if provider == "linode" else 5)
    assert calls


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("drift", ["proof_id", "attachment", "duplicate_attachment", "state", "process"])
def test_fresh_observation_rejects_append_or_provider_drift(tmp_path, provider, drift):
    source, append, workspace, policy, child, snapshot, options = _observation_case(tmp_path, provider)
    if drift == "proof_id":
        child.events[8].data["resourceIds"] = child.events[8].data["resourceIds"][:-1]
    elif drift in {"attachment", "duplicate_attachment"}:
        key = ("linode_firewall_attached_node_ids" if provider == "linode"
               else "selector_attached_node_ids")
        attachment = (("foreign",) if drift == "attachment" else
                      (*getattr(snapshot, key), getattr(snapshot, key)[0]))
        snapshot = replace(snapshot, **{key: attachment})
        options["snapshot_reader"] = lambda **kwargs: snapshot
    elif drift == "state":
        source.state_sha256s = ("f" * 64,)
    else:
        options["process_quiescent"] = lambda *args: False
    with pytest.raises(ValueError):
        _fresh_observation(provider, source, append, workspace, policy, child,
                           lambda: "generation", **options)


def _persisted_collection(client, tmp_path, monkeypatch, *, inert_history=False):
    """Real saved append readers; stub only original core/Inspector plumbing.

    Core connection, initial child/workspace reconstruction and DNS preview
    each have their own tests. This fixture does not claim live provider proof.
    """
    from app.services import provider_keyed_mixed_published_six_collector as module
    from app.storage.job_repository import SqlAlchemyJobRepository
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
    from test_provider_keyed_mixed_published_six_integration import persisted_six_case
    case = persisted_six_case(client, tmp_path, monkeypatch, inert_history=inert_history)
    source = case["source"]
    core = SimpleNamespace(id=source.core_job_id, input={
        "engagementId": source.engagement_id, "corePlanId": source.core_plan_id})
    plan = SimpleNamespace(id=source.core_plan_id, engagement_id=source.engagement_id,
        status="applied", apply_job_id=core.id, evidence={"pendingSketchChainFingerprints": {
            chain.chain_id: module.sketch_chain_intent_fingerprint(chain)
            for chain in source.before_chains}})
    overrides = {core.id: core}
    for provider in source.provider_order:
        key = module.initial_child_id(core.id, provider)
        overrides[key] = SimpleNamespace(id=key)
    for provider in source.provider_order:
        Path(source.workspace_paths[source.provider_order.index(provider)]).joinpath("terraform.tfstate").write_bytes(
            case["observations"][provider].state_json)
    real_jobs = SqlAlchemyJobRepository()
    class Jobs:
        def get(self, key):
            return overrides[key] if key in overrides else real_jobs.get(key)
        def list_for_engagement(self, key):
            return real_jobs.list_for_engagement(key)
    monkeypatch.setattr(module, "active_core_connection_details",
                        lambda *args: (core.id, []))
    monkeypatch.setattr(module, "recognize_mixed_initial_apply_terminal",
                        lambda child, parent, provider: provider)
    monkeypatch.setattr(module, "_prior_workspace", lambda parent, provider, terminal:
        SimpleNamespace(path=Path(
            source.workspace_paths[source.provider_order.index(provider)]),
            state_path=Path(source.workspace_paths[source.provider_order.index(provider)]) / "terraform.tfstate"))
    monkeypatch.setattr(module, "_core_inspector_scope", lambda *args, **kwargs: {"core": core.id, "targets": []})
    mutable = {"lease": None, "bindings": case["live_bindings"]}
    options = dict(job_repository=Jobs(),
        plan_repository=SimpleNamespace(get=lambda key: plan if key == plan.id else None),
        sketch_repository=SqlAlchemySketchChainRepository(), domain_repository=object(),
        provider_resource_repository=object(), lease_lookup=lambda key: mutable["lease"],
        binding_inventory=lambda key: mutable["bindings"],
        fresh_observer=lambda provider, *args: case["observations"][provider],
        manifest_builder=lambda *args, **kwargs: {"dns": "separately-tested"})
    return module, case, mutable, options


@pytest.mark.parametrize("inert_history", [False, True])
def test_collector_joins_persisted_six_source_policies_and_scope(client, tmp_path, monkeypatch, inert_history):
    module, case, mutable, options = _persisted_collection(client, tmp_path, monkeypatch, inert_history=inert_history)
    source = case["source"]
    with client.application.storage_context():
        result = module.collect_published_mixed_six_teardown(
            source.engagement_id, source.core_job_id, **options)
    assert result.source == source
    assert result.reviewed_policies == case["reviewed_policies"]
    assert result.scope.binding_count == 4
    assert set(result.workspaces) == {"digitalocean", "linode"}
    if inert_history:
        from app.services import provider_keyed_channel_apply as channel
        monkeypatch.setattr(channel, "active_core_connection_details",
                            lambda *args: (source.core_job_id, []))
        monkeypatch.setattr(channel, "_prior_workspace", module._prior_workspace)
        monkeypatch.setattr(channel, "recognize_mixed_initial_apply_terminal",
                            module.recognize_mixed_initial_apply_terminal)
        with client.application.storage_context():
            reopened = channel.load_keyed_channel_source(
                source.engagement_id, options["job_repository"],
                sketches=options["sketch_repository"])
            ghost = options["sketch_repository"].get(source.engagement_id, "old-default")
        assert reopened[0] == source
        assert ghost.status == "aborted" and not ghost.nodes and not ghost.deploy_job_id


@pytest.mark.parametrize("drift", ["bindings", "lease", "job", "new_job", "chain", "core_scope"])
def test_collector_fences_drift_during_provider_read(client, tmp_path, monkeypatch, drift):
    module, case, mutable, options = _persisted_collection(client, tmp_path, monkeypatch)
    source = case["source"]
    def observe(provider, *args):
        if drift == "bindings":
            mutable["bindings"] = {**mutable["bindings"], "domains": ()}
        elif drift == "lease":
            mutable["lease"] = ("other", "mutation")
        elif drift in {"job", "new_job"}:
            from app.storage.job_repository import SqlAlchemyJobRepository
            jobs = SqlAlchemyJobRepository()
            parent = jobs.get(source.parent_id)
            jobs.save(replace(parent, status="failed") if drift == "job" else
                      replace(parent, id="new-engagement-job", action="inbound_channel_apply"))
        elif drift == "chain":
            from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
            chains = SqlAlchemySketchChainRepository()
            chain = chains.get(source.engagement_id, source.chain_ids[0])
            chains.save(replace(chain, assigned_proxy="other"))
        else:
            monkeypatch.setattr(module, "_core_inspector_scope",
                                lambda *args, **kwargs: {"core": "changed"})
        return case["observations"][provider]
    options["fresh_observer"] = observe
    with client.application.storage_context(), pytest.raises(module.MixedPublishedSixCollectionAttention):
        module.collect_published_mixed_six_teardown(source.engagement_id, source.core_job_id, **options)


def test_collector_accepts_only_exact_teardown_fence(client, tmp_path, monkeypatch):
    module, case, mutable, options = _persisted_collection(client, tmp_path, monkeypatch)
    source = case["source"]
    mutable["lease"] = (source.core_plan_id, "provider_keyed_teardown_fence")
    with client.application.storage_context():
        with pytest.raises(module.MixedPublishedSixCollectionAttention):
            module.collect_published_mixed_six_teardown(source.engagement_id, source.core_job_id, **options)
        result = module.collect_published_mixed_six_teardown(
            source.engagement_id, source.core_job_id, allow_teardown_fence=True, **options)
    assert result.source == source
