# Copyright (c) 2026, Oracle and/or its affiliates.
"""SQLite-backed one-shot caller proof using fake routed SSH commands only."""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import text

from app.services.provider_keyed_initial_dispatch import _recover_one
from app.services.provider_keyed_initial_host_publication import (
    ProviderKeyedInitialHostPublicationError, publish_initial_digitalocean_host_proof,
)
from app.services.provider_keyed_strict_host_proof import StrictHostSetProof
from app.services.sketch_bootstrap import SketchBootstrapCoreHost
from app.storage.database import db
from app.storage.models import JobEventModel, JobRunModel
from test_provider_keyed_chain_projection import _fixture
from test_provider_keyed_chain_publication import _case
from test_provider_keyed_host_surface_interpreter import _key


def _setup(client, tmp_path, monkeypatch):
    repo, jobs, plans, args = _case(client, workspace_path=str(tmp_path))
    child_id = args["proof_child"].id
    JobEventModel.query.filter_by(job_id=child_id).delete()
    JobRunModel.query.filter_by(id=child_id).delete()
    db.session.commit()
    parent = jobs.get(args["parent"].id)
    jobs.save(replace(parent, input={**parent.input,
        "claimExpiresAt": "2000-01-01T00:00:00+00:00"}))
    (tmp_path / ".barragan-sketch-known-hosts").write_text("known hosts\n")
    reviewed, attachment, attachment_proof, _chains = _fixture()
    core = jobs.get("job-core")
    plan = plans.get("plan-core")
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_dispatch._phase_authority",
        lambda *_a, **_k: (core, plan, {"root": "/pinned/source"}),
    )
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_host_publication._default_state_root",
        lambda: tmp_path,
    )
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_host_publication._core_known_hosts",
        lambda _core: ("/pinned/core/known_hosts", "f" * 64),
    )
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_host_publication._manifest",
        lambda *_a, **_k: args["manifest"],
    )
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_host_publication.retrieve_sketch_ssh_key",
        lambda _engagement: SimpleNamespace(public_key=_key(1)),
    )
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_host_publication.retrieve_sketch_transport_ssh_key",
        lambda _engagement: SimpleNamespace(public_key=_key(2)),
    )
    def core_hosts(_jobs, _engagement, proxy_id, **_kwargs):
        egress = {"proxy01": "8.8.8.8", "proxy02": "9.9.9.9"}[proxy_id]
        key = "/private/core/key"
        return (SketchBootstrapCoreHost("homebase", "203.0.113.10", "user", key),
                SketchBootstrapCoreHost("proxy", "192.168.2.2", "user", key, egress))
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_host_publication._core_hosts", core_hosts,
    )
    values = dict(
        parent_id=parent.id, environment="devtest", state_root=tmp_path,
        job_repository=jobs, plan_repository=plans, sketch_repository=repo,
        credential_repository=object(),
        postapply_preflight=lambda *_a, **_k: (
            reviewed, SimpleNamespace(path=tmp_path), {}, "applied"),
        attachment_intent_builder=lambda *_a: attachment,
        attachment_reconciler=lambda *_a, **_k: attachment_proof,
    )
    return repo, jobs, plans, args, values


def _fake_collector(seen, *, fail_at=None, crash_at=None, lose_claim_at=None,
                    parent_id=None):
    def collect(**kwargs):
        node = kwargs["expected"]
        spec = kwargs["ssh_spec"]
        role = "middle" if node.name == spec.middle.name else "edge"
        assert node.name in spec.host_policies
        assert spec.proxy.host_key_alias == spec.proxy_egress_ip
        assert spec.homebase.host == kwargs["reviewed_core_route"]["homebasePublicIp"]
        assert spec.proxy.host == kwargs["reviewed_core_route"]["proxyPrivateIp"]
        assert spec.pinned_core_known_hosts_path == "/pinned/core/known_hosts"
        assert spec.initial_sketch_known_hosts_path.endswith("/.barragan-sketch-known-hosts")
        assert spec.host_policies[node.name]["sketch_firewall_v2_ssh_sources"] == [
            f"{spec.proxy_egress_ip if role == 'middle' else spec.middle.public_ip}/32"]
        seen.append((node.name, role, kwargs["chain_id"], node.address))
        scratch = str(kwargs["scratch_path"])
        kwargs["scratch_intent_callback"](SimpleNamespace(scratch_path=scratch))
        for number in range(4):
            intent = SimpleNamespace(invocation_id=f"{node.name}-{number}",
                                     scratch_path=scratch, argv_sha256="a" * 64)
            kwargs["intent_callback"](intent)
            started = SimpleNamespace(intent=intent,
                identity=SimpleNamespace(boot_id="boot", pid=100, pgid=100, start_ticks=7))
            kwargs["started_callback"](started)
            kwargs["heartbeat_callback"](started)
            if lose_claim_at == node.name and number == 1:
                db.session.execute(text("""
                    UPDATE job_runs SET input = json_set(input, '$.claimToken', 'lost')
                    WHERE id = :parent
                """), {"parent": parent_id})
                db.session.commit()
            if fail_at == node.name and number == 1:
                raise RuntimeError("selected host failed")
            if crash_at == node.name and number == 1:
                raise SystemExit("worker vanished after command start")
            kwargs["result_callback"](SimpleNamespace(started=started, returncode=0,
                stdout_bytes=1, stderr_bytes=0, stdout_truncated=False,
                stderr_truncated=False))
        return SimpleNamespace(name=node.name)
    return collect


def _verify_fake(projections, captures, **_kwargs):
    nodes = [node for item in projections for node in item.chain.nodes]
    assert [capture.name for capture in captures] == [node["hostname"] for node in nodes]
    names = tuple(sorted(node["hostname"] for node in nodes))
    return StrictHostSetProof(names,
        tuple(next(node["providerInstanceId"] for node in nodes if node["hostname"] == name)
              for name in names), "e" * 64)


def test_composed_caller_publishes_all_hosts_and_reopens_sqlite(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        repo, jobs, plans, args, values = _setup(client, tmp_path, monkeypatch)
        seen = []
        collector = _fake_collector(seen)
        finished = publish_initial_digitalocean_host_proof(
            **values, middle_collector=collector, edge_collector=collector,
            proof_verifier=_verify_fake)
        assert finished.status == "succeeded"
        assert len(seen) == len({name for name, *_ in seen}) == 7
        assert {role for _name, role, *_ in seen} == {"middle", "edge"}
        child = jobs.get(args["proof_child"].id)
        assert child.status == "succeeded"
        assert child.events[-1].message == "strict host proof published"
        assert all(row.status == "deployed" for row in repo.list_for_engagement(finished.target_id))
        db.session.remove()
        assert jobs.get(finished.id).status == "succeeded"
        assert jobs.get(child.id).status == "succeeded"
        assert all(row.status == "deployed" for row in repo.list_for_engagement(finished.target_id))


def test_corrected_initial_plan_publishes_without_touching_aborted_prior_row(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        repo, jobs, plans, args, values = _setup(client, tmp_path, monkeypatch)
        original = args["pending_chains"][0]
        ghost = repo.save(replace(original, chain_id="proxy01-nyc3-01", status="aborted"))
        seen = []
        collector = _fake_collector(seen)
        finished = publish_initial_digitalocean_host_proof(
            **values, middle_collector=collector, edge_collector=collector,
            proof_verifier=_verify_fake)
        assert finished.status == "succeeded" and len(seen) == 7
        assert repo.get(ghost.engagement_id, ghost.chain_id) == ghost
        assert {row.chain_id for row in repo.list_for_engagement(ghost.engagement_id)
                if row.status == "deployed"} == {chain.chain_id for chain in args["pending_chains"]}
        db.session.remove()
        assert jobs.get(finished.id).status == "succeeded"
        assert repo.get(ghost.engagement_id, ghost.chain_id) == ghost


def test_second_host_failure_preserves_all_pending_chains(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        repo, jobs, plans, args, values = _setup(client, tmp_path, monkeypatch)
        second = args["projected_chains"][0].chain.nodes[1]["hostname"]
        seen = []
        collector = _fake_collector(seen, fail_at=second)
        with pytest.raises(ProviderKeyedInitialHostPublicationError):
            publish_initial_digitalocean_host_proof(
                **values, middle_collector=collector, edge_collector=collector,
                proof_verifier=_verify_fake)
        assert [name for name, *_ in seen] == [
            args["projected_chains"][0].chain.nodes[0]["hostname"], second]
        assert jobs.get(values["parent_id"]).status == "failed"
        assert jobs.get(args["proof_child"].id).status == "failed"
        assert all(row.status == "pending" for row in repo.list_for_engagement(
            args["parent"].target_id))


def test_source_drift_after_capture_blocks_publication(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        repo, jobs, plans, args, values = _setup(client, tmp_path, monkeypatch)
        core = jobs.get("job-core")
        plan = plans.get("plan-core")
        calls = []
        def authority(*_a, **_k):
            calls.append(1)
            if len(calls) > 1:
                raise ValueError("source drift")
            return core, plan, {"root": "/pinned/source"}
        monkeypatch.setattr("app.services.provider_keyed_initial_dispatch._phase_authority", authority)
        collector = _fake_collector([])
        with pytest.raises(ProviderKeyedInitialHostPublicationError):
            publish_initial_digitalocean_host_proof(
                **values, middle_collector=collector, edge_collector=collector,
                proof_verifier=_verify_fake)
        assert len(calls) == 2
        assert jobs.get(values["parent_id"]).status == "failed"
        assert all(row.status == "pending" for row in repo.list_for_engagement(
            args["parent"].target_id))


def test_claim_loss_during_second_command_stops_without_partial_publish(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        repo, jobs, plans, args, values = _setup(client, tmp_path, monkeypatch)
        first = args["projected_chains"][0].chain.nodes[0]["hostname"]
        collector = _fake_collector([], lose_claim_at=first,
                                    parent_id=values["parent_id"])
        with pytest.raises(ProviderKeyedInitialHostPublicationError):
            publish_initial_digitalocean_host_proof(
                **values, middle_collector=collector, edge_collector=collector,
                proof_verifier=_verify_fake)
        assert jobs.get(args["proof_child"].id).status == "failed"
        assert jobs.get(values["parent_id"]).status == "running"
        assert all(row.status == "pending" for row in repo.list_for_engagement(
            args["parent"].target_id))


def test_partial_child_restart_never_recontacts(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        repo, jobs, plans, args, values = _setup(client, tmp_path, monkeypatch)
        first = args["projected_chains"][0].chain.nodes[0]["hostname"]
        seen = []
        collector = _fake_collector(seen, crash_at=first)
        with pytest.raises(SystemExit):
            publish_initial_digitalocean_host_proof(
                **values, middle_collector=collector, edge_collector=collector,
                proof_verifier=_verify_fake)
        child = jobs.get(args["proof_child"].id)
        assert child.status == "running"
        assert child.events[-1].message == "strict host proof command started before GO"
        db.session.execute(text("""
            UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', '2000-01-01T00:00:00+00:00')
            WHERE id = :parent
        """), {"parent": values["parent_id"]})
        db.session.commit()
        with patch("app.services.provider_keyed_initial_dispatch.publish_initial_digitalocean_host_proof") as replay:
            _recover_one("job-core", environment="devtest", rollout_enabled=True)
        replay.assert_not_called()
        assert plans.get("plan-core").stage == "provider_keyed_initial_attention"
        assert all(row.status == "pending" for row in repo.list_for_engagement(
            args["parent"].target_id))
