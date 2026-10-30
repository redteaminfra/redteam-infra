# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline real ledger -> saved-plan gate -> one-shot adapter composition."""
from dataclasses import replace
import hashlib
import json
import subprocess

import pytest

from app.services import provider_keyed_ingress_plan_gate as gate
from app.services import provider_keyed_ingress_update as runtime
from app.services.provider_keyed_host_policy import Edge, Middle, Topology
from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent, render_keyed_route_projection
from app.services.provider_keyed_linode_udp_source_gate import _CANDIDATE_SOURCE_REVISION
from app.services.terraform_plan_gate import TerraformPlanGateError
from test_provider_keyed_ingress_plan_gate import _case, _do_rule, _linode_rule
from test_provider_keyed_ingress_update import Credentials, _state


def _dns_case(middle_provider, edge_provider, shared_middle, provider):
    prefixes = {'linode': 'linode_instance', 'digitalocean': 'digitalocean_droplet'}
    middle1 = f'{prefixes[middle_provider]}.middle["chain-one/middle-01"]'
    middle2 = middle1 if shared_middle else f'{prefixes[middle_provider]}.middle["chain-two/middle-01"]'
    edge1 = f'{prefixes[edge_provider]}.edge["sfo/edge-02"]'
    edge2 = f'{prefixes[edge_provider]}.edge["nyc/edge-01"]'
    middles = {middle1: Middle('192.0.2.20', 'proxy01')}
    if not shared_middle:
        middles[middle2] = Middle('192.0.2.21', 'proxy01')
    topology = Topology({'proxy01': '192.0.2.10'}, middles,
                       {edge1: Edge('192.0.2.30', middle1), edge2: Edge('192.0.2.31', middle2)})
    providers = {**{node: middle_provider for node in middles}, edge1: edge_provider, edge2: edge_provider}
    first = KeyedRouteIntent('existing-dns', 'udp', edge1, middle1, 53, 8000, ('0.0.0.0/0',))
    selected = KeyedRouteIntent('new-dns', 'udp', edge2, middle2, 53, 8001, ('0.0.0.0/0',))
    before_projection = render_keyed_route_projection(topology, providers, (first,))
    after_projection = render_keyed_route_projection(topology, providers, (first, selected))
    plan, args, firewall, field, _ = _case(provider)
    rule = _do_rule if provider == 'digitalocean' else _linode_rule
    old_routes = before_projection.provider_routes[provider]
    new_routes = after_projection.provider_routes[provider]
    old_udp = sorted({route.port for route in old_routes})
    new_udp = sorted({route.port for route in new_routes})
    fixed = args['retained_resources'][firewall][field][-1]
    before = {**args['retained_resources'][firewall], field:
              [rule('tcp', p) for p in (80, 443, 2222)] + [rule('udp', p) for p in old_udp] + [fixed]}
    after = {**before, field:
             [rule('tcp', p) for p in (80, 443, 2222)] + [rule('udp', p) for p in new_udp] + [fixed]}
    nodes = sorted(node for node in providers if providers[node] == provider)
    retained = {firewall: before, **{node: {'id': str(i+1)} for i, node in enumerate(nodes)}}
    before['linodes'] = [retained[node]['id'] for node in nodes]
    after['linodes'] = list(before['linodes'])
    variables = {'engagement_name': 'opaque', 'allowed_tcp_ports': ['22', '80', '443', '2222'],
                 'allowed_udp_ports': [str(p) for p in new_udp]}
    noop = old_udp == new_udp
    plan.update(applyable=not noop, variables={k: {'value': v} for k, v in variables.items()},
        prior_state={'values': {'root_module': {'resources': [
            {'address': address, 'mode': 'managed', 'values': value} for address, value in retained.items()]}}},
        resource_changes=[{'address': address, 'mode': 'managed', 'change': {
            'actions': ['no-op'] if noop or address != firewall else ['update'], 'before': value,
            'after': after if address == firewall else value, 'after_unknown': {},
            'before_sensitive': {}, 'after_sensitive': {}}} for address, value in retained.items()])
    workspace = args['workspace']
    if provider == 'linode':
        workspace = replace(workspace, source_revision=_CANDIDATE_SOURCE_REVISION)
    args.update(workspace=workspace, retained_resources=retained, prior_routes=old_routes,
        next_routes=new_routes, selected_channel_id='new-dns', attached_node_addresses=tuple(nodes),
        observed_host_ports={node: tuple(sorted({(r['proto'], r['port']) for r in
            after_projection.host_policies[node]['sketch_firewall_v2_rules']})) for node in nodes},
        reviewed_variables=variables)
    return plan, args, before_projection, after_projection


def _audit_seams(monkeypatch):
    # Audited upstream source/credential/provider observations are separate gates.
    monkeypatch.setattr(gate, 'require_digitalocean_workspace', lambda _: None)
    monkeypatch.setattr(gate, 'require_candidate_linode_udp_workspace', lambda _: None)


@pytest.mark.parametrize('middle_provider,edge_provider', [('linode', 'digitalocean'), ('digitalocean', 'linode')])
@pytest.mark.parametrize('shared_middle', [False, True])
def test_dns_saved_plans_accept_per_node_ownership_and_exact_shared_union(monkeypatch, middle_provider, edge_provider, shared_middle):
    _audit_seams(monkeypatch)
    for provider in (middle_provider, edge_provider):
        plan, args, before, after = _dns_case(middle_provider, edge_provider, shared_middle, provider)
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)
        assert all(rule in after.host_policies[node]['sketch_firewall_v2_rules']
                   for node, policy in before.host_policies.items() for rule in policy['sketch_firewall_v2_rules'])
        if provider == edge_provider:
            assert args['reviewed_variables']['allowed_udp_ports'] == ['53']
            assert plan['applyable'] is False
            assert len({r.node_address for r in args['next_routes']}) == 2
        else:
            assert args['reviewed_variables']['allowed_udp_ports'] == ['8000', '8001']


def _adapter_case(tmp_path, monkeypatch, middle_provider, edge_provider, shared_middle, provider):
    _audit_seams(monkeypatch)
    plan, args, before_projection, after_projection = _dns_case(
        middle_provider, edge_provider, shared_middle, provider)
    root = tmp_path / provider
    root.mkdir()
    (root / '.terraform-data').mkdir()
    (root / '.terraform.lock.hcl').write_text('pinned')
    (root / '.barragan-topology.json').write_text(json.dumps({'schema': 'provider-keyed-v2'}))
    state_path = root / 'terraform.tfstate'
    state_path.write_text(json.dumps({**_state(args['retained_resources']), 'serial': 20, 'lineage': 'opaque-fixture'}))
    binary = root / 'terraform'
    binary.write_text('reviewed binary')
    binary.chmod(0o700)
    tcp, udp = gate._union(gate._route_ports(args['prior_routes'], set(args['attached_node_addresses'])))
    retained_variables = {**args['reviewed_variables'], 'allowed_tcp_ports': ['22'] + [str(p) for p in sorted(tcp)],
                          'allowed_udp_ports': [str(p) for p in sorted(udp)],
                          'ssh_pub_key_path': '/kept/public', 'ssh_priv_key_path': '/kept/private',
                          'ssh_config_path': '/kept/output'}
    reviewed = {**retained_variables, **args['reviewed_variables']}
    inputs = root / 'original-inputs.json'
    inputs.write_text(json.dumps(retained_variables))
    plan['variables'] = {k: {'value': v} for k, v in reviewed.items()}
    plan['variables']['do_pat' if provider == 'digitalocean' else 'linode_api_token'] = {'value': 'token'}
    workspace = replace(args['workspace'], path=root, state_path=state_path, terraform_data_dir=root / '.terraform-data')
    update = runtime.KeyedIngressUpdate(workspace, 'job-first', 'new-dns', args['retained_resources'],
        args['prior_routes'], args['next_routes'], args['attached_node_addresses'], args['observed_host_ports'],
        retained_variables, reviewed, inputs, hashlib.sha256(inputs.read_bytes()).hexdigest(),
        hashlib.sha256(state_path.read_bytes()).hexdigest(), runtime._digest({'schema': 'provider-keyed-v2'}), predecessor_receipt_sha256='a' * 64)
    monkeypatch.setattr(runtime, '_audit', lambda _: None)
    monkeypatch.setattr(runtime, 'decrypt_secret_value', lambda _: 'token')
    validator = lambda **_: type('Release', (), {'path': binary, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                                               'version': '1.15.5'})()
    calls = []

    def run(argv, cwd, env):
        calls.append(argv[1])
        if argv[1] == 'plan':
            (root / next(p[5:] for p in argv if p.startswith('-out='))).write_bytes(b'saved-binary')
        if argv[1] == 'apply' and plan['applyable']:
            after = {row['address']: row['change']['after'] for row in plan['resource_changes']}
            state_path.write_text(json.dumps(_state(after)))
        return subprocess.CompletedProcess(argv, 0, json.dumps(plan) if argv[1] == 'show' else '', '')

    return update, plan, Credentials(provider), validator, run, calls, before_projection, after_projection


@pytest.mark.parametrize('middle_provider,edge_provider', [('linode', 'digitalocean'), ('digitalocean', 'linode')])
@pytest.mark.parametrize('shared_middle', [False, True])
def test_two_provider_adapter_composition_retains_siblings_and_authenticates_noop(tmp_path, monkeypatch,
        middle_provider, edge_provider, shared_middle):
    for provider in (middle_provider, edge_provider):
        update, plan, credentials, validator, run, calls, before, after = _adapter_case(
            tmp_path, monkeypatch, middle_provider, edge_provider, shared_middle, provider)
        state_before = update.workspace.state_path.read_bytes()
        checks, postchecks = [], []
        def postproof():
            postchecks.append(provider)
            assert after.host_policies != before.host_policies
            expected = {row['address']: row['change']['after'] for row in plan['resource_changes']}
            assert runtime._state_resources(json.loads(update.workspace.state_path.read_text())) == expected
            assert update.observed_host_ports == {node: tuple(sorted({(r['proto'], r['port'])
                for r in after.host_policies[node]['sketch_firewall_v2_rules']}))
                for node in update.attached_node_addresses}
        kwargs = dict(credentials=credentials, recheck_authority=lambda: checks.append(provider),
                      command_environment={}, command_runner=run, release_validator=validator)
        runtime.plan_keyed_ingress_update(update, **kwargs)
        result = runtime.apply_keyed_ingress_update(update, post_apply_proof=postproof, **kwargs)
        assert result['phase'] == 'applied'
        assert calls == ['init', 'plan', 'show', 'show', 'apply']
        assert postchecks == [provider] and checks
        assert (update.workspace.state_path.read_bytes() == state_before) == (provider == edge_provider)
        with pytest.raises(runtime.KeyedIngressUpdateAttention):
            runtime.apply_keyed_ingress_update(update, post_apply_proof=postproof, **kwargs)
        assert calls.count('apply') == 1


@pytest.mark.parametrize('tamper', ['status', 'resource', 'unknown', 'output', 'output-unknown', 'output-sensitive',
                                  'wrong-union', 'extra-node', 'sibling', 'same-public', 'duplicate-channel'])
def test_noop_saved_plan_rejects_hidden_change_and_scope_drift(monkeypatch, tamper):
    _audit_seams(monkeypatch)
    plan, args, _, _ = _dns_case('linode', 'digitalocean', False, 'digitalocean')
    if tamper == 'status':
        plan['applyable'] = True
    elif tamper == 'resource':
        plan['resource_changes'][0]['change']['after']['tags'] = ['foreign']
    elif tamper == 'unknown':
        plan['resource_changes'][0]['change']['after_unknown'] = {'status': True}
    elif tamper.startswith('output'):
        change = {'actions': ['no-op'], 'before': 'opaque', 'after': 'opaque',
                  'after_unknown': False, 'before_sensitive': False, 'after_sensitive': False}
        if tamper == 'output':
            change.update(actions=['update'], after='changed')
        elif tamper == 'output-unknown':
            change['after_unknown'] = True
        else:
            change['after_sensitive'] = True
        plan['output_changes'] = {'owned': change}
    elif tamper == 'wrong-union':
        args['reviewed_variables']['allowed_udp_ports'] = ['53', '54']
    elif tamper == 'extra-node':
        args['attached_node_addresses'] += ('digitalocean_droplet.edge["foreign"]',)
    elif tamper == 'sibling':
        args['next_routes'] = (replace(args['next_routes'][0], channel_id='changed-sibling'), *args['next_routes'][1:])
    elif tamper == 'same-public':
        args['next_routes'] = (*args['next_routes'][:-1], replace(args['next_routes'][-1],
            node_address=args['next_routes'][0].node_address))
    else:
        args['next_routes'] += (args['next_routes'][-1],)
    with pytest.raises(TerraformPlanGateError):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_plan_failure_preserves_host_policy_and_state_then_new_job_can_review(tmp_path, monkeypatch):
    update, plan, credentials, validator, run, calls, _, host_projection = _adapter_case(
        tmp_path, monkeypatch, 'linode', 'digitalocean', False, 'digitalocean')
    before_state = update.workspace.state_path.read_bytes()
    plan['applyable'] = True  # Incorrect metadata for the exact unchanged union.
    kwargs = dict(credentials=credentials, recheck_authority=lambda: None,
                  command_environment={}, command_runner=run, release_validator=validator)
    with pytest.raises(TerraformPlanGateError):
        runtime.plan_keyed_ingress_update(update, **kwargs)
    assert 'apply' not in calls
    assert update.workspace.state_path.read_bytes() == before_state
    saved_failure_artifacts = {p.name: p.read_bytes() for p in update.workspace.path.glob('.barragan-ingress-job-first*')}
    assert saved_failure_artifacts
    plan['applyable'] = False
    retry = replace(update, job_id='job-new-reviewed-retry')
    runtime.plan_keyed_ingress_update(retry, **kwargs)
    result = runtime.apply_keyed_ingress_update(retry, post_apply_proof=lambda: None, **kwargs)
    assert result['phase'] == 'applied' and calls.count('apply') == 1
    assert all((update.workspace.path / name).read_bytes() == value for name, value in saved_failure_artifacts.items())
    assert update.workspace.state_path.read_bytes() == before_state
    assert host_projection.host_policies  # Desired host proof survives; no manual artifact deletion/replay.


def test_same_node_relay_collision_rejected_but_protocols_are_independent():
    node = 'digitalocean_droplet.middle["owned"]'
    first = gate.KeyedIngressRoute('first', 'udp', 8000, node)
    with pytest.raises(TerraformPlanGateError):
        gate._route_ports((first, replace(first, channel_id='second')), {node})
    assert gate._route_ports((first, replace(first, channel_id='second', protocol='tcp')), {node}) == {
        node: {('udp', 8000), ('tcp', 8000)}}


@pytest.mark.parametrize('drift', ['serial', 'output', 'firewall', 'node'])
def test_noop_adapter_rejects_state_drift_before_success(tmp_path, monkeypatch, drift):
    update, plan, credentials, validator, run, calls, _, _ = _adapter_case(
        tmp_path, monkeypatch, 'linode', 'digitalocean', False, 'digitalocean')
    kwargs = dict(credentials=credentials, recheck_authority=lambda: None,
                  command_environment={}, command_runner=run, release_validator=validator)
    runtime.plan_keyed_ingress_update(update, **kwargs)
    def corrupt(argv, cwd, env):
        result = run(argv, cwd, env)
        if argv[1] == 'apply':
            state = json.loads(update.workspace.state_path.read_bytes())
            if drift == 'serial':
                state['serial'] = 42
            elif drift == 'output':
                state['outputs'] = {'foreign': {'value': 'changed'}}
            else:
                rows = runtime._state_resources(state)
                selected = next(k for k in rows if ('firewall' in k) == (drift == 'firewall'))
                rows[selected]['id'] = 'foreign'
            update.workspace.state_path.write_text(json.dumps(state))
        return result
    kwargs['command_runner'] = corrupt
    with pytest.raises(runtime.KeyedIngressUpdateAttention, match='state differs'):
        runtime.apply_keyed_ingress_update(update, post_apply_proof=lambda: pytest.fail('unproved state'), **kwargs)
    assert calls.count('apply') == 1
    assert json.loads(runtime._paths(update)[0].read_text())['phase'] == 'apply_intent'
