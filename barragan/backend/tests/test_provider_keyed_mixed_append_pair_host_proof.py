# Copyright (c) 2026, Oracle and/or its affiliates.
"""Focused offline fences for the private paired cross-provider host proof."""

from dataclasses import dataclass, replace, asdict
import hashlib
import json
from types import SimpleNamespace
from pathlib import Path

import pytest
import app.services.provider_keyed_mixed_append_pair_host_proof as proof

from app.services.provider_keyed_mixed_append_pair_host_proof import (
    MixedAppendPairHostProofAttention, SixNodeHostSource,
    _child_id, _probe_cross_provider_edge, prove_mixed_append_pair_hosts,
    validate_six_node_host_source,
)
from app.services.sketch_bootstrap import (
    SketchBootstrapCoreHost, SketchBootstrapNode, SketchBootstrapSpec,
)
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.storage.sketch_chain_repository import StoredSketchChain
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity,
    StartedCommand,
)
from app.services.sketch_bootstrap_apply import SketchBootstrapApplyResult
from app.services.provider_keyed_host_identity_probe import DigitalOceanRawHostCollection
from app.services.provider_keyed_mixed_linode_host_probe import (
    LinodeRawHostCollection, LinodeRawHostIdentity,
)
from app.services.provider_keyed_append_host_collection import _decode_type
from app.services.provider_keyed_mixed_strict_host_receipt import MixedStrictHostProofAttention
from provider_keyed_append_receipts import strict_edge_raw_fixture


def _chain(chain_id, middle_provider, proxy, start):
    nodes = [
        {"chainId": chain_id, "role": "middle", "provider": middle_provider,
         "hostname": f"middle-{start}",
         "terraformAddress": f'{middle_provider}_instance.middle["{start}"]',
         "providerInstanceId": str(start), "publicIp": f"8.8.1.{start}",
         "region": "test-1", "assignedProxy": proxy, "edgeCount": "1"},
        {"chainId": chain_id, "role": "edge", "provider": middle_provider,
         "hostname": f"edge-{start}",
         "terraformAddress": f'{middle_provider}_instance.edge["{start}"]',
         "providerInstanceId": str(start + 10),
         "publicIp": f"8.8.1.{start + 10}",
         "region": "test-1", "assignedProxy": proxy, "edgeCount": "1"},
    ]
    return StoredSketchChain(
        chain_id, "eng-test", proxy, middle_provider, "test-1", "small",
        middle_provider, "test-1", "small", "deployed", False, "", "job-core",
        "", f"/private/tmp/{chain_id}", nodes, "2026-10-19T00:00:00+00:00",
        "2026-10-19T00:00:00+00:00", 1,
        [{"id": "edge-01", "provider": middle_provider,
          "region": "test-1", "size": "small"}],
    )


def _source():
    before = (_chain("chain-l", "linode", "proxy01", 21),
              _chain("chain-d", "digitalocean", "proxy02", 41))
    providers = ("digitalocean", "linode")
    after = []
    for index, item in enumerate(before):
        provider = providers[index]
        edge = {
            "chainId": item.chain_id, "role": "edge", "provider": provider,
            "hostname": f"edge-new-{index}",
            "terraformAddress": f'{provider}_instance.edge["new-{index}"]',
            "providerInstanceId": str(101 + index),
            "publicIp": f"8.8.2.{21 + index}", "region": "test-2",
            "assignedProxy": item.assigned_proxy, "edgeCount": "2",
        }
        after.append(replace(
            item, edge_count=2,
            nodes=[item.nodes[0], {**item.nodes[1], "edgeCount": "2"}, edge],
        ))
    return SixNodeHostSource(
        "job-provider-keyed-mixed-append-core", "eng-test", "job-core",
        "plan-core", providers, ("chain-l", "chain-d"), before,
        tuple(after), tuple(row.nodes[2]["terraformAddress"] for row in after),
        ("a" * 64, "b" * 64), ("c" * 64, "d" * 64),
        ("/private/tmp/do", "/private/tmp/linode"), ("rev", "rev"),
        ("203.0.113.21", "203.0.113.22"),
        "/private/tmp/core-known-hosts", "1" * 64,
    )


def _spec(source, index):
    chain = source.chains[index]
    middle = chain.nodes[0]
    homebase = SketchBootstrapCoreHost("homebase", "8.8.4.1", "ubuntu", "/key")
    proxy = SketchBootstrapCoreHost(chain.assigned_proxy, "10.0.0.2", "ubuntu",
                                    "/key", source.proxy_egress_ips[index])
    return SketchBootstrapSpec(
        homebase, proxy, SketchBootstrapNode(middle["hostname"], middle["publicIp"]),
        tuple(SketchBootstrapNode(row["hostname"], row["publicIp"])
              for row in chain.nodes[1:]),
        "/unused", "/unused", "/unused", "/unused", "/unused",
        {chain.nodes[2]["hostname"]: {
            "sketch_firewall_v2_enabled": True,
            "sketch_firewall_v2_ssh_sources": [middle["publicIp"] + "/32"],
            "sketch_firewall_v2_rules": [],
        }}, source.proxy_egress_ips[index],
        source.workspace_paths[index] + "/.barragan-sketch-known-hosts",
        source.core_known_hosts_path,
    )


def test_source_binds_six_hosts_and_foreign_middle_without_relabeling():
    source = validate_six_node_host_source(_source())
    assert len(source.host_rows) == 6
    assert [row.provider for row in source.host_rows] == [
        "linode", "linode", "digitalocean",
        "digitalocean", "digitalocean", "linode",
    ]
    assert len(source.source_sha256) == 64
    assert _child_id(source.parent_id).endswith("-core")


def test_source_rejects_retained_host_change_and_same_provider_edge():
    source = _source()
    changed = replace(source.chains[0], nodes=[
        {**source.chains[0].nodes[0], "providerInstanceId": "999"},
        *source.chains[0].nodes[1:],
    ])
    with pytest.raises(MixedAppendPairHostProofAttention):
        validate_six_node_host_source(replace(source, chains=(changed, source.chains[1])))
    changed = replace(source.chains[0], nodes=[
        *source.chains[0].nodes[:2],
        {**source.chains[0].nodes[2], "provider": "linode"},
    ])
    with pytest.raises(MixedAppendPairHostProofAttention):
        validate_six_node_host_source(replace(source, chains=(changed, source.chains[1])))


def test_probe_refuses_wrong_middle_before_any_host_contact(tmp_path):
    source = _source()
    spec = _spec(source, 0)
    wrong = replace(spec, middle=SketchBootstrapNode("other", spec.middle.public_ip))
    calls = []
    with pytest.raises(MixedAppendPairHostProofAttention, match="route"):
        _probe_cross_provider_edge(
            source, 0, wrong, scratch=tmp_path / "scratch",
            sketch_known_hosts_sha256="e" * 64,
            fence=lambda: calls.append("fence"), on_scratch=lambda _: None,
            on_intent=lambda _: None, on_started=lambda _: None,
            on_heartbeat=lambda _: None, on_result=lambda _: None,
            runner=lambda *args, **kwargs: calls.append("runner"))
    assert calls == []
    assert not (tmp_path / "scratch").exists()


def test_source_rejects_duplicate_six_host_identity():
    source = _source()
    changed = replace(source.chains[1], nodes=[
        *source.chains[1].nodes[:2],
        {**source.chains[1].nodes[2],
         "publicIp": source.chains[0].nodes[2]["publicIp"]},
    ])
    with pytest.raises(MixedAppendPairHostProofAttention):
        validate_six_node_host_source(replace(source, chains=(source.chains[0], changed)))


def test_existing_host_child_is_permanent_no_replay_fence():
    source = _source()
    parent = SimpleNamespace(
        id=source.parent_id, action="provider_keyed_mixed_append",
        status="running", finished_at=None, target_id=source.engagement_id,
        input={"phase": "apply_sealed", "corePlanId": source.core_plan_id},
    )
    class Jobs:
        def get(self, job_id):
            return parent if job_id == source.parent_id else object()

    contact = []
    with pytest.raises(MixedAppendPairHostProofAttention, match="never replay"):
        prove_mixed_append_pair_hosts(
            source.parent_id, environment="devtest",
            bootstrap_env={TEMPLATE_ROOT_ENV: "/tmp/upstream"},
            fresh_source=lambda: contact.append("source"), job_repository=Jobs(),
            lease_lookup=lambda _: (source.core_plan_id,
                                    "provider_keyed_mixed_append"),
            bootstrap_helper=lambda *a, **kw: contact.append("bootstrap"),
            raw_collector=lambda *a, **kw: contact.append("probe"),
        )
    assert contact == []


def test_production_host_contact_is_rejected_before_repository_read():
    with pytest.raises(MixedAppendPairHostProofAttention, match="DevTest-only"):
        prove_mixed_append_pair_hosts(
            _source().parent_id, environment="prod", bootstrap_env={},
            fresh_source=lambda: (_ for _ in ()).throw(AssertionError("contact")),
            job_repository=object(),
        )


@dataclass(frozen=True)
class _FakeCollection:
    provider: str
    marker: str

    @property
    def raw(self):
        return self

    @property
    def identity(self):
        return SimpleNamespace(invocation_id=self.provider + '-metadata')

    @property
    def surface(self):
        return SimpleNamespace(invocation_id=self.provider + '-surface',
                               boot_id='fixture-boot', listeners_raw=self.marker + '\n')


class _MemoryJobs:
    def __init__(self, parent):
        self.rows = {parent.id: parent}

    def get(self, key):
        return self.rows.get(key)

    def save_if_absent(self, row):
        return self.rows.setdefault(row.id, row)

    def start_if_queued(self, row, *, started_at, event):
        changed = replace(row, status="running", started_at=started_at,
                          events=[*row.events, event])
        self.rows[row.id] = changed
        return changed

    def claim_lease(self, key, *, owner, token, **_kwargs):
        row = self.rows[key]
        changed = replace(row, input={**row.input, "claimOwner": owner,
                                      "claimToken": token})
        self.rows[key] = changed
        return changed

    def renew_lease(self, key, *, owner, token, **_kwargs):
        row = self.rows[key]
        assert row.input["claimOwner"] == owner
        assert row.input["claimToken"] == token
        return row

    def append_event_if_running_claimed(self, row, *, owner, token,
                                        expected_event_digest, event, **_kwargs):
        assert job_event_digest(row.events) == expected_event_digest
        assert row.input["claimOwner"] == owner
        assert row.input["claimToken"] == token
        changed = replace(row, events=[*row.events, event])
        self.rows[row.id] = changed
        return changed

    def finish_if_running_claimed(self, row, *, owner, token,
                                  expected_event_digest, status, finished_at,
                                  event):
        assert job_event_digest(row.events) == expected_event_digest
        assert row.input["claimOwner"] == owner
        assert row.input["claimToken"] == token
        changed = replace(row, status=status, finished_at=finished_at,
                          events=[*row.events, event])
        self.rows[row.id] = changed
        return changed


def _emit_command(index, scratch, on_intent, on_started, on_heartbeat, on_result):
    intent = CommandIntent(f"invocation-{index}", str(scratch), "a" * 64)
    started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
    on_intent(intent)
    on_started(started)
    on_heartbeat(started)
    on_result(CommandAuditResult(started, 0, 1, 0, False, False))
    return CommandResult(started, 0, "ok", "", False, False)


@pytest.fixture
def sql_jobs():
    from app.storage.database import db
    from app.storage import models
    from app.storage.job_repository import SqlAlchemyJobRepository
    state = db.configure('sqlite:///:memory:')
    with db.bind(state):
        db.create_all()
        yield SqlAlchemyJobRepository()


def test_raw_sqlite_host_cas_stays_closed_without_parent_lease_join(tmp_path):
    from app.storage.job_repository import SqliteJobRepository, _claimed_apply_base
    source = _source()
    now = proof._now()
    owner, token = 'mixed-append-host-proof-fixture', 'token'
    inputs = dict(parentJobId=source.parent_id, sourceSha256=source.source_sha256, mutation=True,
        claimOwner=owner, claimToken=token, claimClaimedAt=now, claimHeartbeatAt=now,
        claimExpiresAt=proof._later(now))
    child = StoredJobRun(_child_id(source.parent_id), proof.ACTION, 'running',
        f'engagement:{source.engagement_id}', 'engagement', source.engagement_id,
        'operator', inputs, [], now, now, None,
        [proof.JobEvent(1, 'info', 'mixed append host proof reserved',
                        {'sourceSha256': source.source_sha256})])
    assert _claimed_apply_base(child, owner, token, allow_mixed_append_host=True) is not None
    jobs = SqliteJobRepository(tmp_path / 'raw.sqlite')
    child = jobs.save(child)
    common = dict(owner=owner, token=token, expected_event_digest=job_event_digest(child.events),
                  event=proof.JobEvent(2, 'info', 'contact', {}))
    assert jobs.append_event_if_running_claimed(child, **common,
        heartbeat_at=now, expires_at=proof._later(now)) is None
    assert jobs.finish_if_running_claimed(child, **common, status='succeeded', finished_at=now) is None
    assert jobs.get(child.id) == child


@pytest.mark.parametrize('mode', ['memory', 'memory-timeout', 'memory-invalid-sockets', 'sql-fresh', 'sql-queued',
    'sql-active-parent', 'sql-started', 'sql-finished', 'sql-child-claim',
    'sql-other-input', 'sql-other-event', 'sql-other-source', 'sql-other-target',
    'sql-other-operator', 'sql-no-lease', 'sql-parent-claim-drift'])
def test_two_edge_contact_is_one_shot_and_receipt_reopens(tmp_path, monkeypatch, sql_jobs, mode):
    source = _source()
    roots = (tmp_path / "do", tmp_path / "linode")
    for root in roots:
        root.mkdir()
    source = replace(source, workspace_paths=tuple(str(root) for root in roots),
                     core_known_hosts_path=str(tmp_path / "core-known-hosts"))
    parent = StoredJobRun(
        source.parent_id, "provider_keyed_mixed_append", "running",
        f"engagement:{source.engagement_id}", "engagement", source.engagement_id,
        "operator", {"phase": "apply_sealed", "coreJobId": source.core_job_id,
                     "corePlanId": source.core_plan_id,
                     "providerOrder": list(source.provider_order),
                     "chainOrder": list(source.chain_ids)},
        [], "2026-10-19T00:00:00+00:00", "2026-10-19T00:00:01+00:00", None, [],
    )
    jobs = _MemoryJobs(parent) if mode.startswith('memory') else sql_jobs
    if not mode.startswith('memory'):
        from app.storage.database import db
        from app.storage.models import CoreMutationLeaseModel
        jobs.save(parent)
        db.session.add(CoreMutationLeaseModel(engagement_id=source.engagement_id,
            owner_id=source.core_plan_id, operation='provider_keyed_mixed_append'))
        db.session.commit()
        if mode != 'sql-fresh':
            queued = StoredJobRun(_child_id(parent.id), proof.ACTION, 'queued', parent.target,
                'engagement', parent.target_id, parent.requested_by,
                dict(parentJobId=parent.id, sourceSha256=source.source_sha256, mutation=True),
                [], proof._now(), None, None,
                [proof.JobEvent(1, 'info', 'mixed append host proof reserved',
                                {'sourceSha256': source.source_sha256})])
            if mode == 'sql-started': queued = replace(queued, status='running', started_at=proof._now())
            if mode == 'sql-finished': queued = replace(queued, finished_at=proof._now())
            if mode == 'sql-child-claim': queued = replace(queued, input={**queued.input, 'claimOwner': 'old'})
            if mode == 'sql-other-input': queued = replace(queued, input={**queued.input, 'other': True})
            if mode == 'sql-other-event': queued = replace(queued, events=[*queued.events, proof.JobEvent(2, 'info', 'contact', {})])
            if mode == 'sql-other-source': queued = replace(queued, input={**queued.input, 'sourceSha256': 'f'*64})
            if mode == 'sql-other-target': queued = replace(queued, target_id='other')
            if mode == 'sql-other-operator': queued = replace(queued, requested_by='other')
            saved = jobs.save(queued)
            assert saved != queued and saved.created_at == queued.created_at.removesuffix('+00:00')
            now = proof._now()
            jobs.claim_lease(parent.id, owner='expired-worker', token='old-token',
                claimed_at=now if mode == 'sql-active-parent' else '2020-01-01T00:00:00+00:00',
                expires_at=proof._later(now) if mode == 'sql-active-parent' else '2020-01-01T01:00:00+00:00',
                eligible_statuses={'running'}, eligible_phases={'apply_sealed'})
        if mode == 'sql-no-lease':
            CoreMutationLeaseModel.query.filter_by(engagement_id=source.engagement_id).delete()
            db.session.commit()
    monkeypatch.setattr(proof, "require_pinned_sketch_ansible_source",
                        lambda **_kw: None)
    monkeypatch.setattr(proof, "_clean_scratch_result", lambda _path: None)
    monkeypatch.setattr(proof, "_sketch_file_snapshot",
                        lambda _path: (0, 0, "e" * 64))
    monkeypatch.setattr(proof, "_core_hosts", lambda *_a, **_kw: (
        SketchBootstrapCoreHost("homebase", "8.8.4.1", "ubuntu", "/key"),
        SketchBootstrapCoreHost("proxy", "10.0.0.2", "ubuntu", "/key",
                                source.proxy_egress_ips[0]),
    ))
    def verify(_source, _index, captured, **_kw):
        diagnostic = Path(_source.workspace_paths[_index]) / (
            f".barragan-mixed-append-socket-diagnostic-{_child_id(parent.id)}-{_source.provider_order[_index]}.json")
        assert json.loads(diagnostic.read_text())["listenersRaw"] == "raw\n"
        if mode == 'memory-invalid-sockets':
            from app.services.provider_keyed_host_surface_interpreter import HostSurfaceInterpretationError
            raise HostSurfaceInterpretationError('socket row syntax differs')
        return hashlib.sha256(json.dumps(asdict(captured), sort_keys=True,
                               separators=(",", ":")).encode()).hexdigest()
    monkeypatch.setattr(proof, "_verify_cross_provider_collection", verify)
    sequence = {"value": 0}
    captured_ids = {}

    def reloaded(_source, index, *_args):
        ids = captured_ids[_source.provider_order[index]]
        raw = SimpleNamespace(
            firewall_before=SimpleNamespace(invocation_id=ids[1]),
            surface=SimpleNamespace(invocation_id=ids[2]),
            firewall_after=SimpleNamespace(invocation_id=ids[3]),
        )
        wrapper = SimpleNamespace(identity=SimpleNamespace(invocation_id=ids[0]),
                                  raw=raw)
        if _source.provider_order[index] == "linode":
            return wrapper
        return SimpleNamespace(identity=wrapper.identity,
                               firewall_before=raw.firewall_before,
                               surface=raw.surface,
                               firewall_after=raw.firewall_after)

    monkeypatch.setattr(proof, "_read_collection", reloaded)

    def gated(command, *, scratch_path, intent_callback, started_callback,
              heartbeat_callback, result_callback, **_kw):
        assert _kw["execution_timeout_seconds"] == 1800
        sequence["value"] += 1
        if mode == "memory-timeout":
            from app.services.provider_keyed_gated_runner import GatedCommandTimeoutError
            intent = CommandIntent("timed-command", str(scratch_path), "a" * 64)
            started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
            intent_callback(intent)
            started_callback(started)
            result_callback(CommandAuditResult(started, -15, 0, 0, False, False, timed_out=True))
            raise GatedCommandTimeoutError("local bootstrap execution timed out")
        return _emit_command(sequence["value"], scratch_path,
                             intent_callback, started_callback,
                             heartbeat_callback, result_callback)

    def bootstrap(_eng, chain, *, progress_reporter, runner, workspace_root,
                  only_edge_name, **_kw):
        assert only_edge_name == chain.nodes[2]["hostname"]
        workspace_root.mkdir()
        progress_reporter("checking", {"phase": "root-management-readiness"})
        for _phase, filename in proof._PHASES:
            runner([filename], workspace_root, {})
        return SketchBootstrapApplyResult(0, 0, 1, 0)

    def collect(current, index, _spec, *, scratch, on_scratch, on_intent,
                on_started, on_heartbeat, on_result, **_kw):
        on_scratch(str(scratch))
        invocations = []
        for _ in range(4):
            sequence["value"] += 1
            invocations.append(f"invocation-{sequence['value']}")
            _emit_command(sequence["value"], scratch, on_intent,
                          on_started, on_heartbeat, on_result)
        captured_ids[current.provider_order[index]] = tuple(invocations)
        captured = _FakeCollection(current.provider_order[index], "raw")
        proof._write_socket_diagnostic(current, index, _child_id(current.parent_id), captured)
        return captured

    kwargs = dict(environment="devtest", bootstrap_env={TEMPLATE_ROOT_ENV: str(tmp_path)},
                  fresh_source=lambda: source, job_repository=jobs,
                  lease_lookup=lambda _: (source.core_plan_id,
                                          "provider_keyed_mixed_append"),
                  bootstrap_helper=bootstrap, gated_command_runner=gated,
                  raw_collector=collect)
    if mode == 'sql-parent-claim-drift':
        original = jobs.append_event_if_running_claimed
        def changed_parent(*args, **kw):
            parent = jobs.get(source.parent_id)
            jobs.save(replace(parent, input={**parent.input, 'claimToken': 'changed'}))
            return original(*args, **kw)
        monkeypatch.setattr(jobs, 'append_event_if_running_claimed', changed_parent)
    if mode == 'memory-timeout':
        with pytest.raises(MixedAppendPairHostProofAttention, match="timed out"):
            prove_mixed_append_pair_hosts(source.parent_id, **kwargs)
        child = jobs.get(_child_id(source.parent_id))
        assert child.status == "failed"
        assert child.events[-1].data == {"bootstrap": "reconciliation_required", "timedOut": True}
        audits = [event for event in child.events if event.message == "mixed append bootstrap command result fenced"]
        assert len(audits) == 1 and audits[0].data["timedOut"] is True
        assert sequence["value"] == 1
        with pytest.raises(MixedAppendPairHostProofAttention):
            prove_mixed_append_pair_hosts(source.parent_id, **kwargs)
        assert sequence["value"] == 1
        return
    if mode == 'memory-invalid-sockets':
        with pytest.raises(MixedAppendPairHostProofAttention):
            prove_mixed_append_pair_hosts(source.parent_id, **kwargs)
        assert list(roots[0].glob('.barragan-mixed-append-socket-diagnostic-*'))
        assert not proof._artifact_path(source, 0, _child_id(parent.id)).exists()
        assert not any(event.message == 'mixed append edge raw proof captured'
                       for event in jobs.rows[_child_id(parent.id)].events)
        return
    if mode not in ('memory', 'sql-fresh', 'sql-queued'):
        with pytest.raises(MixedAppendPairHostProofAttention):
            prove_mixed_append_pair_hosts(source.parent_id, **kwargs)
        assert sequence['value'] == 0
        return
    receipt = prove_mixed_append_pair_hosts(source.parent_id, **kwargs)
    child = jobs.get(receipt.child_id)
    assert child.status == "succeeded"
    assert sequence["value"] == 16
    assert receipt == proof.validate_six_host_receipt_child(
        jobs.get(source.parent_id), child, receipt, source=source)
    if mode != 'memory':
        from app.services.provider_keyed_mixed_append_apply_runtime import _resume_receipt
        assert _resume_receipt(jobs.get(source.parent_id), child, source) == receipt
        assert receipt.claim_token != 'old-token'
    forged = replace(receipt, raw_probe_sha256s=("0" * 64,
                                                 receipt.raw_probe_sha256s[1]))
    with pytest.raises(MixedAppendPairHostProofAttention):
        proof.validate_six_host_receipt_child(
            jobs.get(source.parent_id), child, forged, source=source)
    drifted_source = replace(source, state_sha256s=("0" * 64,
                                                    source.state_sha256s[1]))
    with pytest.raises(MixedAppendPairHostProofAttention):
        proof.validate_six_host_receipt_child(
            jobs.get(source.parent_id), child, receipt, source=drifted_source)
    raw_at = next(index for index, event in enumerate(child.events)
                  if event.message == "mixed append raw command intended")
    tampered_events = list(child.events)
    for index in (raw_at, raw_at + 1, raw_at + 2):
        event = tampered_events[index]
        tampered_events[index] = replace(
            event, data={**event.data, "invocationId": "different-raw-command"})
    tampered = replace(child, events=tampered_events)
    tampered_receipt = replace(receipt,
                               child_event_sha256=job_event_digest(tampered.events))
    with pytest.raises(MixedAppendPairHostProofAttention):
        proof.validate_six_host_receipt_child(
            jobs.get(source.parent_id), tampered, tampered_receipt,
            source=source)
    with pytest.raises(MixedAppendPairHostProofAttention):
        prove_mixed_append_pair_hosts(source.parent_id, **kwargs)
    assert sequence["value"] == 16


@pytest.mark.parametrize("first_provider", ["digitalocean", "linode"])
def test_cross_provider_probe_routes_through_real_foreign_middle(
        tmp_path, monkeypatch, first_provider):
    source = _source()
    if first_provider == "linode":
        source = replace(source,
            provider_order=tuple(reversed(source.provider_order)),
            chain_ids=tuple(reversed(source.chain_ids)),
            before_chains=tuple(reversed(source.before_chains)),
            chains=tuple(reversed(source.chains)),
            new_edge_addresses=tuple(reversed(source.new_edge_addresses)),
            provider_proof_digests=tuple(reversed(source.provider_proof_digests)),
            state_sha256s=tuple(reversed(source.state_sha256s)),
            workspace_paths=tuple(reversed(source.workspace_paths)),
            source_revisions=tuple(reversed(source.source_revisions)),
            proxy_egress_ips=tuple(reversed(source.proxy_egress_ips)))
    root = tmp_path / "provider"
    root.mkdir()
    core = tmp_path / "core-known-hosts"
    core.write_text("pinned core\n")
    source = replace(source, workspace_paths=(str(root),
                                              source.workspace_paths[1]),
                     core_known_hosts_path=str(core),
                     core_known_hosts_sha256=hashlib.sha256(
                         core.read_bytes()).hexdigest())
    provider = source.provider_order[0]
    node, middle = source.chains[0].nodes[2], source.chains[0].nodes[0]
    spec = _spec(source, 0)
    fake_policy = proof._host_policy(source, 0)
    spec = replace(spec, host_policies=fake_policy)
    (root / ".barragan-sketch-known-hosts").write_text("pinned sketch\n")
    monkeypatch.setattr(proof, "_sketch_file_snapshot",
                        lambda _path: (0, 0, "e" * 64))
    monkeypatch.setattr(proof, "_require_pinned_aliases",
                        lambda *_args: None)

    def stage_key(_engagement, directory):
        directory.mkdir(mode=0o700)
        private = directory / "id_ed25519"
        private.write_text("private fixture\n")
        private.chmod(0o600)
        return private, directory / "id_ed25519.pub"

    monkeypatch.setattr(proof, "write_existing_sketch_ssh_key_files", stage_key)
    alias = f"barragan-bootstrap-user-{node['hostname']}"
    monkeypatch.setattr(proof, "render_strict_v2_sketch_identity_ssh_config",
                        lambda _spec: f"Host {alias}\n  ConnectTimeout 15\n"
                        "  ControlMaster no\n  ControlPersist no\n")
    monkeypatch.setattr(proof, "_stable_firewall_commands", lambda _rows: ())
    monkeypatch.setattr(proof, "_verify_cross_provider_collection",
                        lambda *_args, **_kwargs: "a" * 64)
    boot = "11111111-1111-4111-8111-111111111111"
    invocations = []

    def runner(argv, *, scratch_path, intent_callback, started_callback,
               heartbeat_callback, result_callback, **_kwargs):
        assert argv[0] == "/usr/bin/ssh"
        assert argv[3] == alias
        assert node["publicIp"] not in argv[:4]
        index = len(invocations) + 1
        invocations.append(index)
        intent = CommandIntent(f"raw-{index}", str(scratch_path), "a" * 64)
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        intent_callback(intent)
        started_callback(started)
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 200, 0, False, False))
        if provider == "linode":
            payload = {"instance": {"id": int(node["providerInstanceId"]),
                                    "label": node["hostname"],
                                    "region": node["region"],
                                    "image": {"id": "linode/ubuntu24.04"}},
                       "hostname": node["hostname"], "boot_id": boot,
                       "ssh_connection": f"{middle['publicIp']} 12345 {node['publicIp']} 22"}
        else:
            payload = {"id": node["providerInstanceId"],
                       "region": node["region"], "public_ipv4": node["publicIp"],
                       "hostname": node["hostname"], "boot_id": boot}
        return CommandResult(started, 0, json.dumps(payload), "", False, False)

    def raw_capture(identity, *args, **kwargs):
        callback = kwargs.get("intent_callback") or args[-5]
        started_cb = kwargs.get("started_callback") or args[-4]
        heartbeat_cb = kwargs.get("heartbeat_callback") or args[-3]
        result_cb = kwargs.get("result_callback") or args[-2]
        index = len(invocations) + 1
        invocations.append(index)
        intent = CommandIntent(f"raw-{index}", str(tmp_path / "scratch"), "b" * 64)
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        callback(intent)
        started_cb(started)
        heartbeat_cb(started)
        result_cb(CommandAuditResult(started, 0, 1, 0, False, False))
        return SimpleNamespace(boot_id=identity.boot_id,
                               invocation_id=intent.invocation_id,
                               started_at_ns=index, completed_at_ns=index,
                               commands=(), files=(), listeners_raw="raw socket row\n")

    monkeypatch.setattr(proof, "_collect_raw_firewall", raw_capture)
    monkeypatch.setattr(proof, "_collect_raw_host_surface", raw_capture)
    captured = proof._probe_cross_provider_edge(
        source, 0, spec, scratch=tmp_path / "scratch",
        sketch_known_hosts_sha256="e" * 64, fence=lambda: None,
        on_scratch=lambda _: None, on_intent=lambda _: None,
        on_started=lambda _: None, on_heartbeat=lambda _: None,
        on_result=lambda _: None, runner=runner)
    assert captured.identity.provider_instance_id == node["providerInstanceId"]
    assert captured.identity.chain_id == source.chains[0].chain_id
    assert captured.identity.manifest_sha256 == source.source_sha256
    assert len(invocations) == 4


@pytest.mark.parametrize("provider_index", [0, 1])
def test_private_raw_artifact_round_trip_and_mode_fence(
        tmp_path, monkeypatch, provider_index):
    source = _source()
    roots = (tmp_path / "do", tmp_path / "linode")
    for root in roots:
        root.mkdir()
    source = replace(source, workspace_paths=tuple(str(root) for root in roots))
    chain = source.chains[provider_index]
    node, middle = chain.nodes[2], chain.nodes[0]
    payload = strict_edge_raw_fixture(
        monkeypatch, manifest_sha=source.source_sha256,
        chain_id=chain.chain_id, address=node["terraformAddress"],
        provider_id=node["providerInstanceId"], region=node["region"],
        public_ip=node["publicIp"], hostname=node["hostname"],
        middle_ip=middle["publicIp"],
        admin_public_key="ssh-ed25519 fixture-admin",
        transport_public_key="ssh-ed25519 fixture-transport")
    if source.provider_order[provider_index] == "linode":
        raw = _decode_type(DigitalOceanRawHostCollection, json.loads(payload))
        identity = raw.identity
        linode = LinodeRawHostIdentity(
            identity.manifest_sha256, identity.chain_id,
            identity.terraform_address, identity.provider_instance_id,
            "linode/ubuntu24.04", identity.region, identity.public_ipv4,
            identity.hostname, identity.boot_id,
            (middle["publicIp"], 50000, node["publicIp"], 22),
            identity.invocation_id, identity.core_known_hosts_sha256,
            identity.sketch_known_hosts_sha256)
        payload = json.dumps(asdict(LinodeRawHostCollection(linode, raw)),
                             sort_keys=True, separators=(",", ":")).encode()
    child_id = proof._child_id(source.parent_id)
    path = proof._artifact_path(source, provider_index, child_id)
    proof._write_private(path, payload)
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(proof, "_verify_cross_provider_collection",
                        lambda *_args, **_kwargs: digest)
    restored = proof._read_collection(source, provider_index, child_id,
                                      digest, "e" * 64)
    assert restored.identity.terraform_address == node["terraformAddress"]
    assert restored.identity.provider_instance_id == node["providerInstanceId"]
    path.chmod(0o644)
    with pytest.raises(MixedStrictHostProofAttention):
        proof._read_collection(source, provider_index, child_id, digest,
                               "e" * 64)


def _generic_probe_case(tmp_path, monkeypatch, chain_index, host_index):
    """Real strict config and pinned alias checks; mock only remote execution."""
    import base64
    source = _source()
    roots = (tmp_path / "chain-a", tmp_path / "chain-b")
    for root in roots: root.mkdir()
    # A valid public-only SSH wire key, no operational credentials.
    key = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()
    core = tmp_path / "core-known-hosts"
    core.write_text("8.8.4.1 " + key + "\n" + "\n".join(ip + " " + key for ip in source.proxy_egress_ips) + "\n")
    source = replace(source, workspace_paths=tuple(str(root) for root in roots),
        core_known_hosts_path=str(core), core_known_hosts_sha256=hashlib.sha256(core.read_bytes()).hexdigest())
    # Match the actual initial + append enrollment layout: native roots pin
    # their original chain; foreign append roots acquire only middle+new edge.
    trust_rows = [[], []]
    for index, chain in enumerate(source.chains):
        native = source.provider_order.index(chain.middle_provider)
        trust_rows[native].extend(chain.nodes[:2])
        trust_rows[index].extend((chain.nodes[0], chain.nodes[2]))
    for index, nodes in enumerate(trust_rows):
        trust = roots[index] / ".barragan-sketch-known-hosts"
        trust.write_text("".join(f"barragan-bootstrap-sketch-{node['hostname']} {key}\n" for node in nodes))
        trust.chmod(0o600)
    chain = source.chains[chain_index]
    node = chain.nodes[host_index]
    spec = _spec(source, chain_index)
    policies = proof._host_policy(source, chain_index)
    policies[node["hostname"]]["sketch_firewall_v2_rules"] = [
        {"from_ip": "0.0.0.0/0", "proto": "udp", "port": 5353}]
    spec = replace(spec, proxy=replace(spec.proxy, name="proxy"), host_policies=policies,
        initial_sketch_known_hosts_path=str(proof.six_host_known_hosts_path(source, chain_index, host_index)))
    def stage_key(_engagement, directory):
        directory.mkdir(mode=0o700)
        private = directory / "id_ed25519"
        private.write_text("private offline fixture\n")
        private.chmod(0o600)
        return private, directory / "id_ed25519.pub"
    monkeypatch.setattr(proof, "write_existing_sketch_ssh_key_files", stage_key)
    calls = []
    boot = "11111111-1111-4111-8111-111111111111"
    predecessor = source.proxy_egress_ips[chain_index] if host_index == 0 else chain.nodes[0]["publicIp"]
    def runner(argv, *, scratch_path, intent_callback, started_callback, heartbeat_callback, result_callback, **kwargs):
        config = (scratch_path / "identity-ssh.conf").read_text()
        calls.append((tuple(argv), config))
        assert argv[0] == "/usr/bin/ssh"
        assert argv[3] == f"barragan-bootstrap-user-{node['hostname']}"
        assert node["publicIp"] not in argv[:4]
        blocks = {chunk.splitlines()[0]: "\n".join(chunk.splitlines()[1:]) for chunk in config.split("Host ")[1:]}
        selected = blocks[argv[3]]
        jump = "barragan-bootstrap-proxy" + ("" if host_index == 0 else f",barragan-bootstrap-user-{chain.nodes[0]['hostname']}")
        assert f"  ProxyJump {jump}" in selected
        assert f"  HostKeyAlias barragan-bootstrap-sketch-{node['hostname']}" in selected
        assert "  StrictHostKeyChecking yes" in selected
        assert f"  UserKnownHostsFile {spec.initial_sketch_known_hosts_path}" in selected
        assert "accept-new" not in config and "  ControlMaster no" in selected
        assert "  ServerAliveInterval 10" in selected
        assert f"  ProxyJump barragan-bootstrap-homebase" in blocks["barragan-bootstrap-proxy"]
        assert f"  HostKeyAlias {source.proxy_egress_ips[chain_index]}" in blocks["barragan-bootstrap-proxy"]
        intent = CommandIntent("metadata", str(scratch_path), "a" * 64)
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        intent_callback(intent); started_callback(started); heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 200, 0, False, False))
        if node["provider"] == "linode":
            payload = {"instance": {"id": int(node["providerInstanceId"]), "label": node["hostname"],
                "region": node["region"], "image": {"id": "linode/ubuntu24.04"}},
                "hostname": node["hostname"], "boot_id": boot,
                "ssh_connection": f"{predecessor} 12345 {node['publicIp']} 22"}
        else:
            payload = {"id": node["providerInstanceId"], "region": node["region"],
                "public_ipv4": node["publicIp"], "hostname": node["hostname"], "boot_id": boot}
        return CommandResult(started, 0, json.dumps(payload), "", False, False)
    counter = [1]
    captures = []
    def firewall(identity, *args, **kwargs):
        counter[0] += 1
        captures.append(("firewall", identity, kwargs))
        return SimpleNamespace(boot_id=identity.boot_id, started_at_ns=counter[0], completed_at_ns=counter[0], commands=(), files=())
    def surface(identity, actual_predecessor, *args, **kwargs):
        counter[0] += 1
        captures.append(("surface", identity, kwargs))
        assert actual_predecessor == predecessor
        return SimpleNamespace(boot_id=identity.boot_id, started_at_ns=counter[0], completed_at_ns=counter[0])
    monkeypatch.setattr(proof, "_collect_raw_firewall", firewall)
    monkeypatch.setattr(proof, "_collect_raw_host_surface", surface)
    verified = []
    def interpret(provider):
        def verify(collection, **kwargs):
            verified.append(provider)
            assert kwargs["expected_identity"] == collection.identity
            assert kwargs["expected_policy"] == policies[node["hostname"]]
            assert kwargs["expected_predecessor_ipv4"] == predecessor
        return verify
    monkeypatch.setattr(proof, "interpret_linode_host_policy", interpret("linode"))
    monkeypatch.setattr(proof, "interpret_digitalocean_host_policy", interpret("digitalocean"))
    options = dict(scratch=tmp_path / "scratch", sketch_known_hosts_sha256=hashlib.sha256(
        Path(spec.initial_sketch_known_hosts_path).read_bytes()).hexdigest(), fence=lambda: None,
        on_scratch=lambda _: None, on_intent=lambda _: None, on_started=lambda _: None,
        on_heartbeat=lambda _: None, on_result=lambda _: None, runner=runner,
        host_index=host_index, expected_policy=policies[node["hostname"]])
    return source, spec, options, calls, captures, verified


@pytest.mark.parametrize("chain_index", [0, 1])
@pytest.mark.parametrize("host_index", [0, 1, 2])
def test_generic_probe_six_hosts_real_routes_trust_and_provider_dispatch(tmp_path, monkeypatch, chain_index, host_index):
    source, spec, options, calls, captures, verified = _generic_probe_case(tmp_path, monkeypatch, chain_index, host_index)
    captured = proof._probe_cross_provider_edge(source, chain_index, spec, **options)
    node = source.chains[chain_index].nodes[host_index]
    row = source.host_rows[chain_index * 3 + host_index]
    assert verified == [node["provider"]]
    assert len(calls) == 1
    assert [r[0] for r in captures] == ["firewall", "surface", "firewall"]
    assert captured.identity.terraform_address == row.terraform_address
    assert captured.identity.provider_instance_id == row.provider_instance_id
    assert captured.identity.chain_id == row.chain_id
    assert captured.identity.hostname == row.hostname
    assert captured.identity.manifest_sha256 == source.source_sha256
    assert all(c[1].manifest_sha256 == source.source_sha256 for c in captures)
    assert all(bool(c[2].get("expected_stderr")) == (node["provider"] == "linode") for c in captures)
    assert not (tmp_path / "scratch").exists()


@pytest.mark.parametrize("drift", ["predecessor", "proxy_alias", "core_trust", "selected_pin", "middle_pin", "wrong_known_hosts", "bool_index"])
def test_generic_probe_route_or_trust_drift_prevents_any_remote_contact(tmp_path, monkeypatch, drift):
    source, spec, options, calls, _, verified = _generic_probe_case(tmp_path, monkeypatch, 0, 1)
    if drift == "predecessor":
        options["expected_policy"] = {**options["expected_policy"], "sketch_firewall_v2_ssh_sources": ["8.8.8.8/32"]}
    elif drift == "proxy_alias": spec = replace(spec, proxy=replace(spec.proxy, host_key_alias="8.8.8.8"))
    elif drift == "core_trust": Path(source.core_known_hosts_path).write_text("changed\n")
    elif drift in {"selected_pin", "middle_pin"}:
        node = source.chains[0].nodes[1 if drift == "selected_pin" else 0]
        path = Path(spec.initial_sketch_known_hosts_path)
        path.write_text("".join(line for line in path.read_text().splitlines(keepends=True) if node["hostname"] not in line))
        options["sketch_known_hosts_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    elif drift == "wrong_known_hosts": spec = replace(spec, initial_sketch_known_hosts_path=source.workspace_paths[0] + "/.barragan-sketch-known-hosts")
    else: options["host_index"] = True
    with pytest.raises(ValueError):
        proof._probe_cross_provider_edge(source, 0, spec, **options)
    assert calls == [] and verified == []


@pytest.mark.parametrize("chain_index,host_index,drift", [(0, 0, "predecessor"), (0, 0, "image"), (1, 1, "identity")])
def test_generic_probe_metadata_must_match_source_host_and_actual_predecessor(tmp_path, monkeypatch, chain_index, host_index, drift):
    source, spec, options, calls, captures, verified = _generic_probe_case(tmp_path, monkeypatch, chain_index, host_index)
    real_runner = options["runner"]
    def changed(*args, **kwargs):
        result = real_runner(*args, **kwargs)
        metadata = json.loads(result.stdout)
        if drift == "predecessor": metadata["ssh_connection"] = metadata["ssh_connection"].replace(source.proxy_egress_ips[chain_index], "8.8.8.8")
        elif drift == "image": metadata["instance"]["image"]["id"] = "linode/debian12"
        else: metadata["id"] = "9999"
        return replace(result, stdout=json.dumps(metadata))
    options["runner"] = changed
    with pytest.raises(ValueError):
        proof._probe_cross_provider_edge(source, chain_index, spec, **options)
    assert len(calls) == 1 and captures == [] and verified == []


def test_six_host_trust_mapping_retains_foreign_append_path_and_native_old_hosts():
    source = _source()
    for chain_index, chain in enumerate(source.chains):
        for host_index in range(3):
            expected = (chain_index if host_index == 2 else source.provider_order.index(chain.middle_provider))
            assert proof.six_host_known_hosts_path(source, chain_index, host_index) == Path(source.workspace_paths[expected]) / ".barragan-sketch-known-hosts"
    for chain_index, host_index in [(True, 1), (0, True), (-1, 0), (0, 3)]:
        with pytest.raises(MixedAppendPairHostProofAttention):
            proof.six_host_known_hosts_path(source, chain_index, host_index)


@pytest.mark.parametrize('index', [0, 1])
def test_socket_diagnostic_is_private_bound_and_not_receipt_authority(tmp_path, index):
    source = replace(_source(), workspace_paths=(str(tmp_path), str(tmp_path)))
    child_id = _child_id(source.parent_id)
    captured = _FakeCollection(source.provider_order[index], 'tcp UNKNOWN 0 0 bad row')
    proof._write_socket_diagnostic(source, index, child_id, captured)
    paths = list(tmp_path.glob('.barragan-mixed-append-socket-diagnostic-*'))
    assert len(paths) == 1 and paths[0].stat().st_mode & 0o777 == 0o600
    data = json.loads(paths[0].read_text())
    assert data['authority'] is False and data['sourceSha256'] == source.source_sha256
    assert data['childId'] == child_id and data['provider'] == source.provider_order[index]
    assert data['edgeAddress'] == source.new_edge_addresses[index]
    assert data['surfaceInvocationId'] == captured.surface.invocation_id
    assert data['metadataInvocationId'] == captured.identity.invocation_id
    assert data['bootId'] == captured.surface.boot_id
    assert data['listenersSha256'] == hashlib.sha256(data['listenersRaw'].encode()).hexdigest()
    assert not proof._artifact_path(source, index, child_id).exists()
    with pytest.raises(Exception):
        proof._read_collection(source, index, child_id, 'a'*64, 'e'*64)
    with pytest.raises(FileExistsError):
        proof._write_socket_diagnostic(source, index, child_id, captured)


@pytest.mark.parametrize('kind', ['oversized', 'empty', 'symlink'])
def test_socket_diagnostic_rejects_unsafe_writes(tmp_path, kind):
    source = replace(_source(), workspace_paths=(str(tmp_path), str(tmp_path)))
    child_id = _child_id(source.parent_id)
    captured = _FakeCollection('digitalocean', 'x'*65536 if kind == 'oversized' else 'raw')
    if kind == 'empty':
        captured = SimpleNamespace(surface=SimpleNamespace(listeners_raw=''))
    if kind == 'symlink':
        target = tmp_path / 'untouched'
        target.write_text('unchanged')
        path = tmp_path / f'.barragan-mixed-append-socket-diagnostic-{child_id}-digitalocean.json'
        path.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        proof._write_socket_diagnostic(source, 0, child_id, captured)
    assert not proof._artifact_path(source, 0, child_id).exists()
    if kind == 'symlink':
        assert target.read_text() == 'unchanged'


@pytest.mark.parametrize('chain_index', [0, 1])
def test_actual_probe_retains_diagnostic_before_internal_surface_rejection(tmp_path, monkeypatch, chain_index):
    source, spec, options, *_ = _generic_probe_case(tmp_path, monkeypatch, chain_index, 2)
    options['expected_policy'] = None
    node = source.chains[chain_index].nodes[2]
    middle = source.chains[chain_index].nodes[0]
    spec = replace(spec, host_policies={**spec.host_policies, node['hostname']: {
        'sketch_firewall_v2_enabled': True,
        'sketch_firewall_v2_ssh_sources': [middle['publicIp'] + '/32'],
        'sketch_firewall_v2_rules': []}})
    original = proof._collect_raw_host_surface
    def raw_surface(*args, **kwargs):
        surface = original(*args, **kwargs)
        surface.listeners_raw = 'tcp UNKNOWN 0 0 rejected original row\n'
        surface.invocation_id = 'surface-reject-invocation'
        return surface
    monkeypatch.setattr(proof, '_collect_raw_host_surface', raw_surface)
    def reject(*args, **kwargs):
        from app.services.provider_keyed_host_surface_interpreter import HostSurfaceInterpretationError
        paths = list(Path(source.workspace_paths[chain_index]).glob('.barragan-mixed-append-socket-diagnostic-*'))
        assert len(paths) == 1
        assert json.loads(paths[0].read_text())['listenersRaw'] == 'tcp UNKNOWN 0 0 rejected original row\n'
        raise HostSurfaceInterpretationError('socket row syntax differs')
    monkeypatch.setattr(proof, '_verify_cross_provider_collection', reject)
    from app.services.provider_keyed_host_surface_interpreter import HostSurfaceInterpretationError
    with pytest.raises(HostSurfaceInterpretationError):
        proof._probe_cross_provider_edge(source, chain_index, spec, **options)
    assert not proof._artifact_path(source, chain_index, _child_id(source.parent_id)).exists()
    assert not options['scratch'].exists()


@pytest.mark.parametrize('child_id', ['../escape', 'x'*201, 'different-child'])
def test_socket_diagnostic_rejects_unbound_or_unsafe_child(tmp_path, child_id):
    source = replace(_source(), workspace_paths=(str(tmp_path), str(tmp_path)))
    with pytest.raises(ValueError):
        proof._write_socket_diagnostic(source, 0, child_id, _FakeCollection('digitalocean', 'raw'))
    assert not list(tmp_path.iterdir())
