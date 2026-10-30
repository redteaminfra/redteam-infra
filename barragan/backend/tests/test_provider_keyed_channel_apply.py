# Copyright (c) 2026, Oracle and/or its affiliates.
"""Connected central Apply ordering with witnessed host/provider boundaries.

Provider rule parsing, raw host interpretation and saved binary execution have
separate literal tests. These checks establish that ordinary Apply selects
them, proves all six isolated policies and reviews both plans before a write.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_channel_apply as module
from app.services.inbound_mutation_fence import bind_inbound_mutation
from app.storage.job_repository import StoredJobRun
from test_provider_keyed_mixed_published_six_scope import _case


@pytest.mark.parametrize('chain_index,edge_index', [(0, 1), (0, 2), (1, 1), (1, 2)])
@pytest.mark.parametrize('proxy_form', ['canonical', 'display'])
def test_route_accepts_exact_active_core_proxy_identity_for_all_four_edges(chain_index, edge_index, proxy_form):
    source, _ = _case()
    details = [dict(role='proxy', sshAlias=chain.assigned_proxy + '-c4e91b20',
                    displayName=chain.assigned_proxy + '-c4e91b20', publicIp=source.proxy_egress_ips[index])
               for index, chain in enumerate(source.chains)]
    core = StoredJobRun(source.core_job_id, 'pilot_standard_rti_guarded_execute', 'succeeded',
        'oci-compartment:barragan-testing', 'oci_compartment', 'compartment', 'operator',
        {'engagementId': source.engagement_id}, [], 'created', 'started', 'finished',
        [JobEvent(1, 'info', 'core deployed', {'connectionDetails': details, 'mutationStatus': 'deployed'})])
    jobs = SimpleNamespace(list_for_engagement=lambda _: [core])
    chain = source.chains[chain_index]
    edge = chain.nodes[edge_index]
    channel = dict(channelId='route-one', chainId=chain.chain_id, edge=edge['hostname'],
        middle=chain.nodes[0]['hostname'], proxy=(chain.assigned_proxy if proxy_form == 'canonical'
            else details[chain_index]['displayName']), externalPort='18001', middleRelayPort='8001',
        mode='tcp-forward', protocol='TCP')
    route = module._route(source, channel, jobs)
    assert route.edge_node == edge['terraformAddress']
    assert route.middle_node == chain.nodes[0]['terraformAddress']


@pytest.mark.parametrize('drift', ['foreign_proxy', 'invented_suffix', 'foreign_middle', 'foreign_edge',
    'foreign_chain', 'core_generation', 'missing_proxy', 'duplicate_proxy', 'proxy_ip',
    'alias_conflict', 'foreign_labels', 'duplicate_ip_other_alias', 'empty_label'])
def test_route_rejects_unproven_or_foreign_core_and_sketch_predecessors(drift):
    source, _ = _case()
    chain = source.chains[0]
    details = [dict(role='proxy', sshAlias=chain.assigned_proxy + '-c4e91b20',
                    displayName=chain.assigned_proxy + '-c4e91b20', publicIp=source.proxy_egress_ips[0])]
    channel = dict(channelId='route-one', chainId=chain.chain_id, edge=chain.nodes[2]['hostname'],
        middle=chain.nodes[0]['hostname'], proxy=details[0]['displayName'],
        externalPort='18001', middleRelayPort='8001', mode='tcp-forward', protocol='TCP')
    if drift == 'foreign_proxy': channel['proxy'] = source.chains[1].assigned_proxy + '-c4e91b20'
    if drift == 'invented_suffix': channel['proxy'] = chain.assigned_proxy + '-unrecorded'
    if drift == 'foreign_middle': channel['middle'] = source.chains[1].nodes[0]['hostname']
    if drift == 'foreign_edge': channel['edge'] = source.chains[1].nodes[2]['hostname']
    if drift == 'foreign_chain': channel['chainId'] = source.chains[1].chain_id
    if drift == 'missing_proxy': details.clear()
    if drift == 'duplicate_proxy': details.append(dict(details[0]))
    if drift == 'proxy_ip': details[0]['publicIp'] = '9.9.9.9'
    if drift == 'alias_conflict': details[0]['sshAlias'] = source.chains[1].assigned_proxy
    if drift == 'foreign_labels':
        details[0].update(displayName=source.chains[1].assigned_proxy + '-c4e91b20',
                          sshAlias=source.chains[1].assigned_proxy + '-c4e91b20')
    if drift == 'duplicate_ip_other_alias':
        details.append({**details[0], 'displayName': 'proxy03-other', 'sshAlias': 'proxy03-other'})
    if drift == 'empty_label': details[0].update(displayName='', sshAlias='')
    core = StoredJobRun(source.core_job_id if drift != 'core_generation' else 'other-core',
        'pilot_standard_rti_guarded_execute', 'succeeded', 'core', 'core', 'core', 'operator',
        {'engagementId': source.engagement_id}, [], 'created', 'started', 'finished',
        [JobEvent(1, 'info', 'core deployed', {'connectionDetails': details, 'mutationStatus': 'deployed'})])
    jobs = SimpleNamespace(list_for_engagement=lambda _: [core])
    with pytest.raises(ValueError):
        module._route(source, channel, jobs)


def _setup(tmp_path, monkeypatch, kind, edge_index):
    source, case = _case()
    roots, hashes, workspaces, inputs = [], [], {}, {}
    policies = case["reviewed_policies"]
    for provider in source.provider_order:
        root = tmp_path / provider
        root.mkdir()
        roots.append(str(root))
        state = root / "terraform.tfstate"
        state.write_bytes(case["observations"][provider].state_json)
        hashes.append(hashlib.sha256(state.read_bytes()).hexdigest())
        inputs[provider] = root / "original-inputs.json"
        inputs[provider].write_text(json.dumps({"allowed_tcp_ports": ["22", "80", "443", "2222"],
                                              "allowed_udp_ports": []}))
        inputs[provider].chmod(0o600)
        policies[provider]["nonsecret_varfile"] = json.loads(inputs[provider].read_text())
        workspaces[provider] = SimpleNamespace(path=root, state_path=state, provider=provider)
    known = tmp_path / "core-known-hosts"
    known.write_text("retained core trust")
    known.chmod(0o644)  # Public pinned host keys, as produced by real core bootstrap.
    source = replace(source, workspace_paths=tuple(roots), state_sha256s=tuple(hashes),
                     core_known_hosts_path=str(known),
                     core_known_hosts_sha256=hashlib.sha256(known.read_bytes()).hexdigest())
    initial, append = SimpleNamespace(id="initial"), SimpleNamespace(id="append")
    current = StoredJobRun("job-channel", "inbound_channel_apply", "running", "engagement:eng-test",
        "engagement", "eng-test", "operator", {}, [], "created", "started", None, [])
    rows = {initial.id: initial, append.id: append, current.id: current}
    jobs = SimpleNamespace(get=rows.get, list_for_engagement=lambda _: [rows[current.id]])
    generation = SimpleNamespace(state_sha256s=source.state_sha256s, policies=policies,
        input_paths=inputs, provider_routes={p: () for p in source.provider_order},
        receipt_heads={p: 'b' * 64 for p in source.provider_order})
    monkeypatch.setattr(module, "load_keyed_channel_source", lambda *_: (source, initial, append, generation, workspaces))
    # Unit adapter witnesses project heads from their fake durable events;
    # real SQL receipt authentication/freshness is covered in sql_workflow.
    def projected_heads(*_args, **_kwargs):
        heads = dict(generation.receipt_heads)
        for event in rows[current.id].events:
            if event.message == module.EVENT:
                heads[event.data['provider']] = event.data['receiptSha256']
        return SimpleNamespace(receipt_heads=heads)
    monkeypatch.setattr(module, "read_channel_generation", projected_heads)
    monkeypatch.setattr(module, "runtime_value", lambda _: "devtest")
    lease = ["owner", "inbound_channel_apply"]
    monkeypatch.setattr(module, "_db_lease_lookup", lambda _: tuple(lease))
    monkeypatch.setattr(module, "SqlAlchemySketchChainRepository", lambda:
                        SimpleNamespace(list_for_engagement=lambda _: source.chains))
    monkeypatch.setattr(module, "active_core_connection_details", lambda *_: (source.core_job_id, [
        dict(role='proxy', sshAlias=chain.assigned_proxy + '-opaque',
             displayName=chain.assigned_proxy + '-opaque', publicIp=source.proxy_egress_ips[index])
        for index, chain in enumerate(source.chains)]))
    monkeypatch.setattr(module, "SqlAlchemyCredentialRepository", lambda: object())
    monkeypatch.setattr(module, "read_provider_topology", lambda _: {"topology": "authenticated"})
    calls = []
    def record(message, data):
        job = rows[current.id]
        rows[current.id] = replace(job, events=[*job.events, JobEvent(len(job.events) + 1, "info", message, data)])
    record.job_id = current.id
    def prove(provider, policy, workspace, credentials, fence, *, wait_for_completion=False):
        fence()
        calls.append(("provider-proof", provider))
    monkeypatch.setattr(module, "_prove_provider_generation", prove)
    def hosts(source, policies, jobs, job_id, phase, fence, record):
        fence()
        assert len(policies) == 6
        active = {node for node, policy in policies.items() if policy["sketch_firewall_v2_rules"]}
        assert len(active) == (0 if phase == "before" else 2)
        calls.append(("host-proof", phase))
        return {"path": "private-witness", "sha256": "a" * 64}
    monkeypatch.setattr(module, "_prove_hosts", hosts)
    monkeypatch.setattr(module, "_converge_hosts", lambda *args: calls.append(("converge", "six")))
    def plan(update, **kwargs):
        kwargs["recheck_authority"]()
        calls.append(("plan", update.workspace.provider))
        assert len(update.observed_host_ports) == 3
        assert update.selected_channel_id == "route-one"
        assert set(update.retained_resources) == set(module._state_resources(json.loads(update.workspace.state_path.read_text())))
        status, inputs, *_ = module._paths(update)
        status.write_text("planned")
        inputs.write_text(json.dumps(update.reviewed_variables))
        status.chmod(0o600)
        inputs.chmod(0o600)
    monkeypatch.setattr(module, "plan_keyed_ingress_update", plan)
    def apply(update, **kwargs):
        kwargs["recheck_authority"]()
        calls.append(("apply", update.workspace.provider))
        # This witness changes only serialization to exercise state-generation
        # fence advancement; the real adapter separately proves actual policy.
        with update.workspace.state_path.open("a") as stream:
            stream.write(" ")
        kwargs["post_apply_proof"]()
        return {"postStateSha256": hashlib.sha256(update.workspace.state_path.read_bytes()).hexdigest(),
                "predecessorReceiptSha256": update.predecessor_receipt_sha256}
    monkeypatch.setattr(module, "apply_keyed_ingress_update", apply)
    chain = source.chains[0]
    channel = {"channelId": "route-one", "chainId": chain.chain_id,
        "edge": chain.nodes[edge_index]["hostname"], "middle": chain.nodes[0]["hostname"],
        "proxy": chain.assigned_proxy, "externalPort": "80" if kind == "web" else "18001",
        "relayPort": "8001", "middleRelayPort": "8001",
        "mode": "http-openresty" if kind == "web" else "tcp-forward", "protocol": kind.upper()}
    return source, jobs, record, channel, calls, lease


@pytest.mark.parametrize('drift', [None, 'changed_bytes', 'symlink'])
def test_public_core_known_hosts_fence_requires_exact_stable_regular_evidence(tmp_path, monkeypatch, drift):
    source, jobs, record, channel, calls, _ = _setup(tmp_path, monkeypatch, 'tcp', 1)
    known = Path(source.core_known_hosts_path)
    assert known.stat().st_mode & 0o777 == 0o644
    if drift == 'changed_bytes': known.write_text('different core host key')
    if drift == 'symlink':
        retained = tmp_path / 'retained-known-hosts'
        known.rename(retained)
        known.symlink_to(retained)
    with bind_inbound_mutation('owner'):
        if drift:
            with pytest.raises(ValueError):
                module.sync_keyed_channel_apply(source.engagement_id, channel, jobs=jobs, record=record)
            assert calls == []
        else:
            module.sync_keyed_channel_apply(source.engagement_id, channel, jobs=jobs, record=record)
            assert ('host-proof', 'after') in calls


@pytest.mark.parametrize("kind", ["tcp", "udp", "web"])
@pytest.mark.parametrize("edge_index", [1, 2])
def test_central_apply_proves_six_hosts_and_reviews_all_plans_before_any_apply(tmp_path, monkeypatch, kind, edge_index):
    source, jobs, record, channel, calls, _ = _setup(tmp_path, monkeypatch, kind, edge_index)
    with bind_inbound_mutation("owner"):
        module.sync_keyed_channel_apply(source.engagement_id, channel, jobs=jobs, record=record)
    plans = [index for index, row in enumerate(calls) if row[0] == "plan"]
    applies = [index for index, row in enumerate(calls) if row[0] == "apply"]
    assert len(plans) == len(applies) == (0 if kind == "web" else edge_index)
    if plans:
        assert max(plans) < min(applies)
        assert calls.index(("host-proof", "after")) < min(plans)
    assert any(event.message == module.HOST_EVENT for event in jobs.get(record.job_id).events)
    assert len([event for event in jobs.get(record.job_id).events if event.message == module.EVENT]) == len(applies)


def test_second_plan_failure_never_releases_first_provider_apply(tmp_path, monkeypatch):
    source, jobs, record, channel, calls, _ = _setup(tmp_path, monkeypatch, "udp", 2)
    original = module.plan_keyed_ingress_update
    def plan(update, **kwargs):
        if any(row[0] == "plan" for row in calls):
            raise ValueError("second provider rejected")
        return original(update, **kwargs)
    monkeypatch.setattr(module, "plan_keyed_ingress_update", plan)
    with bind_inbound_mutation("owner"), pytest.raises(ValueError, match="second provider rejected"):
        module.sync_keyed_channel_apply(source.engagement_id, channel, jobs=jobs, record=record)
    assert not any(row[0] == "apply" for row in calls)


def test_lease_change_during_host_proof_stops_before_provider_plan(tmp_path, monkeypatch):
    source, jobs, record, channel, calls, lease = _setup(tmp_path, monkeypatch, "tcp", 2)
    original = module._prove_hosts
    def hosts(*args):
        result = original(*args)
        lease[0] = "another-owner"
        return result
    monkeypatch.setattr(module, "_prove_hosts", hosts)
    with bind_inbound_mutation("owner"), pytest.raises(ValueError, match="lease changed"):
        module.sync_keyed_channel_apply(source.engagement_id, channel, jobs=jobs, record=record)
    assert not any(row[0] in {"plan", "apply"} for row in calls)


@pytest.mark.parametrize("failure", [None, "ingress", "transport"])
def test_ordinary_apply_dispatches_keyed_and_preserves_completed_provider_receipt_on_failure(tmp_path, monkeypatch, failure):
    import subprocess
    from app.services import inbound_channel_apply as ordinary
    job = StoredJobRun("job-channel", "inbound_channel_apply", "running", "engagement:eng-test",
        "engagement", "eng-test", "operator", {}, [], "created", "started", None, [])
    saved = [job]
    def save(value):
        saved[0] = value
        return value
    repo = SimpleNamespace(save=save)
    monkeypatch.setattr(ordinary, "_keyed_engagement", lambda _: True)
    monkeypatch.setattr(ordinary, "sync_provider_ingress_for_inbound_channel",
                        lambda *args, **kwargs: pytest.fail("keyed Apply selected split-v1 ingress"))
    monkeypatch.setattr(ordinary, "_rollback_failed_inbound_apply",
                        lambda *args, **kwargs: pytest.fail("completed keyed ingress blindly rolled back"))
    monkeypatch.setattr(ordinary, "_save_managed_http_backend_site", lambda *args: None)
    monkeypatch.setattr(ordinary, "_merged_inbound_channels", lambda engagement, channel_id, row: [row])
    def sync(engagement, channel, *, jobs, record):
        record(module.EVENT, {"provider": "linode", "afterStateSha256": "a" * 64})
        if failure == "ingress":
            raise ValueError("requires observation")
    monkeypatch.setattr(module, "sync_keyed_channel_apply", sync)
    calls = []
    def command(argv, cwd):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1 if failure == "transport" else 0, "", "")
    result = ordinary._finish_inbound_apply_job_with_execution_workspace(repo, job, "eng-test", "route",
        [ordinary.InboundApplyCommand("apply", "Apply route", True, ["ansible-playbook"])],
        tmp_path, command, {"channelId": "route", "status": "Pending Validation"}, "chain", "opaque")
    assert result.status == ("succeeded" if failure is None else "failed")
    assert any(event.message == module.EVENT for event in result.events)
    assert bool(calls) == (failure != "ingress")


def test_keyed_inventory_routes_transport_to_sketch_but_excludes_legacy_sketch_firewall_mutations():
    from app.services import inbound_channel_apply as ordinary
    from app.services.inbound_channel_artifacts import render_inbound_channel_artifacts
    from test_inbound_channel_apply import _http_validation_overview
    overview, channel = _http_validation_overview()
    spec, route = ordinary._resolved_spec_from_channel("opaque", overview, channel)
    artifacts = render_inbound_channel_artifacts(spec)
    workspace = ordinary.render_inbound_apply_workspace(spec, artifacts, route=route, keyed_sketch_policy=True)
    groups = workspace.inventory.content.split("[inbound_firewall_targets:children]\n")
    assert "selected_middle\nselected_edge" in groups[0]
    assert groups[1].splitlines()[0] == "selected_proxy"
    assert "inbound_channel_targets" not in groups[1]


@pytest.mark.parametrize("chain_index", [0, 1])
def test_direct_host_convergence_uses_each_original_and_appended_edges_trust_config(tmp_path, monkeypatch, chain_index):
    """Exercise the real convergence loop, without _setup's convergence stub."""
    from dataclasses import dataclass
    from app.services.provider_keyed_mixed_append_pair_host_proof import six_host_known_hosts_path
    source, _ = _case()
    roots = (tmp_path / "digitalocean", tmp_path / "linode")
    for root in roots:
        root.mkdir()
    source = replace(source, workspace_paths=tuple(str(root) for root in roots))
    chain = source.chains[chain_index]
    before = {node["terraformAddress"]: {"sketch_firewall_v2_rules": []}
              for item in source.chains for node in item.nodes}
    after = {address: {"sketch_firewall_v2_rules": list(policy["sketch_firewall_v2_rules"])}
             for address, policy in before.items()}
    for node in chain.nodes[1:]:
        after[node["terraformAddress"]]["sketch_firewall_v2_rules"] = [
            {"proto": "udp", "port": 5353, "from_ip": "0.0.0.0/0"}]
    @dataclass(frozen=True)
    class WitnessSpec:
        admin_private_key_path: str
        host_index: int
        trust_path: str
    specs, rendered, commands = [], [], []
    def spec(selected_source, index, policies, jobs, *, host_index):
        assert selected_source == source and index == chain_index and policies == after
        specs.append(host_index)
        return WitnessSpec("unused", host_index,
                           str(six_host_known_hosts_path(source, index, host_index)))
    def render(value):
        rendered.append(value)
        assert Path(value.admin_private_key_path).is_file()
        return f"host-index={value.host_index}\nUserKnownHostsFile={value.trust_path}\n"
    def stage_key(_engagement, directory):
        directory.mkdir(mode=0o700)
        private = directory / "id_ed25519"
        private.write_text("private offline fixture")
        private.chmod(0o600)
        return private, directory / "id_ed25519.pub"
    def runner(argv, **kwargs):
        index = 1 + len(commands)
        assert argv[:2] == ["/usr/bin/ssh", "-F"]
        assert argv[3] == f"barragan-bootstrap-user-{chain.nodes[index]['hostname']}"
        config = Path(argv[2])
        assert config.stat().st_mode & 0o777 == 0o600
        expected_path = six_host_known_hosts_path(source, chain_index, index)
        assert config.read_text() == f"host-index={index}\nUserKnownHostsFile={expected_path}\n"
        assert argv[4] == "sudo -n ufw allow proto udp from 0.0.0.0/0 to any port 5353"
        assert kwargs["provider_keyed_v2"] is True
        commands.append(tuple(argv))
        return SimpleNamespace(returncode=0, stdout_truncated=False, stderr_truncated=False)
    monkeypatch.setattr(module, "_spec", spec)
    monkeypatch.setattr(module, "render_strict_v2_sketch_identity_ssh_config", render)
    monkeypatch.setattr(module, "write_existing_sketch_ssh_key_files", stage_key)
    monkeypatch.setattr(module, "run_gated_command", runner)
    module._converge_hosts(source, before, after, object(), lambda: None, lambda *args: None)
    assert specs == [1, 2]
    assert len(rendered) == len(commands) == 2
    assert rendered[0].trust_path != rendered[1].trust_path
    assert all(not list(root.iterdir()) for root in roots)


@pytest.mark.parametrize("phase", ["before", "after"])
def test_host_proof_actual_writer_is_private_and_strictly_readable(tmp_path, monkeypatch, phase):
    source, _ = _case()
    policies = {node["terraformAddress"]: {"policy": "witness"}
                for chain in source.chains for node in chain.nodes}
    roots = tuple(str(tmp_path / provider) for provider in source.provider_order)
    for root in roots:
        Path(root).mkdir()
    source = replace(source, workspace_paths=roots)
    known = tmp_path / "known_hosts"
    known.write_text("pinned host key")
    known.chmod(0o600)
    monkeypatch.setattr(module, "_spec", lambda *a, **kw:
                        SimpleNamespace(initial_sketch_known_hosts_path=str(known)))
    @dataclass
    class Capture:
        host_index: int
    contacts = []
    def probe(*args, **kwargs):
        contacts.append(kwargs["host_index"])
        return Capture(kwargs["host_index"])
    monkeypatch.setattr(module, "_probe_cross_provider_edge", probe)
    proof = module._prove_hosts(source, policies, None, "job-private", phase,
                                lambda: None, lambda *a: None)
    path = Path(proof["path"])
    assert path.stat().st_mode & 0o777 == 0o600
    raw = module._read(path)
    assert proof["sha256"] == hashlib.sha256(raw).hexdigest()
    assert json.loads(raw) == {"sourceSha256": source.source_sha256,
        "policySha256": module._digest(policies),
        "captures": [{"host_index": i} for i in (0, 1, 2, 0, 1, 2)]}
    assert contacts == [0, 1, 2, 0, 1, 2]


def test_keyed_failure_logs_frames_without_exception_secret(tmp_path, monkeypatch, caplog):
    from app.services import inbound_channel_apply as inbound
    job = StoredJobRun("job-private", "inbound_channel_apply", "running", "target", "target",
        "target", "operator", {}, [], "created", "started", None, [])
    class Jobs:
        def save(self, value): return value
    monkeypatch.setattr(inbound, "_keyed_engagement", lambda _: True)
    monkeypatch.setattr(inbound, "_merged_inbound_channels", lambda *a: [])
    secret = "TOKEN-DO-NOT-LOG"
    def fail(*args, **kwargs):
        raise RuntimeError(secret)
    monkeypatch.setattr(module, "sync_keyed_channel_apply", fail)
    failed = inbound._finish_inbound_apply_job_with_execution_workspace(
        Jobs(), job, "engagement", "channel", [], tmp_path, None, {}, "chain", "engagement")
    assert failed.status == "failed"
    assert "Keyed channel ingress stopped (RuntimeError)" in caplog.text
    assert "exception details redacted" in caplog.text
    assert "TOKEN-DO-NOT-LOG" not in caplog.text
    assert "in fail" in caplog.text


@pytest.mark.parametrize("raise_inside", [False, True])
def test_policy_scratch_under_real_setgid_parent_passes_gate_and_cleans_up(tmp_path, raise_inside):
    from app.services.provider_keyed_gated_runner import _private_scratch_path
    parent = tmp_path / "shared-provider-workspace"
    parent.mkdir()
    parent.chmod(0o2770)
    if not parent.stat().st_mode & 0o2000:
        pytest.skip("Test filesystem does not retain directory setgid")
    assert parent.stat().st_mode & 0o7777 == 0o2770
    captured = []
    def exercise():
        with module._policy_scratch(parent) as root:
            captured.append(root)
            assert root.stat().st_mode & 0o7777 == 0o700
            assert _private_scratch_path(root) == root
            (root / "ssh.conf").write_text("offline trust configuration")
            if raise_inside:
                raise ValueError("definite failure")
    if raise_inside:
        with pytest.raises(ValueError, match="definite failure"):
            exercise()
    else:
        exercise()
    assert len(captured) == 1 and not captured[0].exists()
    assert list(parent.iterdir()) == []


def test_completion_wait_is_enabled_only_for_post_apply_provider_proof(tmp_path, monkeypatch):
    source, jobs, record, channel, calls, _ = _setup(tmp_path, monkeypatch, "tcp", 1)
    original = module._prove_provider_generation
    observations = []
    def proof(provider, policy, workspace, credentials, fence, *, wait_for_completion=False):
        observations.append((provider, wait_for_completion))
        return original(provider, policy, workspace, credentials, fence,
                        wait_for_completion=wait_for_completion)
    monkeypatch.setattr(module, "_prove_provider_generation", proof)
    with bind_inbound_mutation("owner"):
        module.sync_keyed_channel_apply(source.engagement_id, channel, jobs=jobs, record=record)
    applied = [provider for phase, provider in calls if phase == "apply"]
    assert [provider for provider, wait in observations if wait] == applied
    assert len([wait for _, wait in observations if not wait]) > len(applied)
