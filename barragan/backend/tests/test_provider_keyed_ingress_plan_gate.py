# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from app.services import provider_keyed_ingress_plan_gate as gate
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.terraform_plan_gate import TerraformPlanGateError


def _workspace(provider: str) -> ProviderKeyedWorkspace:
    return ProviderKeyedWorkspace(Path('/tmp/unused'), Path('/tmp/unused/state'), Path('/tmp/unused/data'),
                                  'provider-keyed-v2', provider, 'connection', 'fingerprint', '0' * 40, '0' * 64)


def _do_rule(proto: str, port: int) -> dict:
    return {'action': 'allow', 'protocol': proto, 'port_range': str(port),
            'source_addresses': ['0.0.0.0/0'], 'source_droplet_ids': [],
            'source_kubernetes_ids': [], 'source_load_balancer_uids': [], 'source_tags': []}


def _linode_rule(proto: str, port: int) -> dict:
    return {'action': 'ACCEPT', 'protocol': proto.upper(), 'label': f'allow-{proto}-{port}',
            'ports': str(port), 'ipv4': ['0.0.0.0/0'], 'ipv6': None, 'description': ''}


def _case(provider: str):
    prefix = 'digitalocean_droplet' if provider == 'digitalocean' else 'linode_instance'
    firewall_address = 'digitalocean_firewall.firewall' if provider == 'digitalocean' else 'linode_firewall.firewall'
    field = 'inbound_rule' if provider == 'digitalocean' else 'inbound'
    rule = _do_rule if provider == 'digitalocean' else _linode_rule
    middle, edge, sibling = [f'{prefix}.{role}["{key}"]' for role, key in
                              (('middle', '01'), ('edge', '01'), ('edge', '02'))]
    fixed = ({'action': 'allow', 'protocol': 'tcp', 'port_range': '22',
              'source_addresses': ['192.0.2.8/32']} if provider == 'digitalocean'
             else {'action': 'ACCEPT', 'protocol': 'TCP', 'ports': '22',
                   'ipv4': ['192.0.2.8/32'], 'label': 'allow-tcp-22-trusted'})
    before_rules = [rule('tcp', port) for port in (80, 443, 2222)] + [fixed]
    after_rules = [rule('tcp', port) for port in (80, 443, 2222, 3333)] + [fixed]
    before = {'id': 'fw-1', field: before_rules, 'outbound': [{'action': 'ACCEPT'}],
              'tags': ['owned'], 'linodes': ['1', '2', '3']}
    after = {**before, field: after_rules}
    retained = {firewall_address: before, middle: {'id': '1'}, edge: {'id': '2'}, sibling: {'id': '3'}}
    variables = {'allowed_tcp_ports': ['22', '80', '443', '2222', '3333'],
                 'engagement_name': 'opaque'}
    if provider == 'digitalocean':
        variables['allowed_udp_ports'] = []
    plan = {'format_version': '1.2', 'terraform_version': '1.15.5',
            'applyable': True, 'complete': True, 'errored': False, 'resource_drift': [],
            'variables': {key: {'value': value} for key, value in variables.items()},
            'prior_state': {'values': {'root_module': {'resources': [
                {'address': address, 'mode': 'managed', 'values': value}
                for address, value in retained.items()]}}},
            'resource_changes': [{'address': address, 'mode': 'managed', 'change':
                {'actions': ['update'] if address == firewall_address else ['no-op'],
                 'before': value, 'after': after if address == firewall_address else value,
                 'after_unknown': {}, 'before_sensitive': {}, 'after_sensitive': {}}}
                for address, value in retained.items()]}
    route = gate.KeyedIngressRoute('channel-1', 'tcp', 3333, edge)
    args = dict(workspace=_workspace(provider), retained_resources=retained,
                prior_routes=(), next_routes=(route,), selected_channel_id='channel-1',
                attached_node_addresses=(middle, edge, sibling),
                observed_host_ports={middle: (), edge: (('tcp', 3333),), sibling: ()},
                reviewed_variables=variables)
    return plan, args, firewall_address, field, sibling


@pytest.mark.parametrize('provider', ['linode', 'digitalocean'])
def test_accepts_exact_selected_add_and_remove(monkeypatch, provider):
    monkeypatch.setattr(gate, 'require_linode_workspace', lambda _: None)
    monkeypatch.setattr(gate, 'require_digitalocean_workspace', lambda _: None)
    plan, args, firewall, field, _ = _case(provider)
    gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)
    removed = copy.deepcopy(plan)
    removed['resource_changes'][0]['change']['before'] = plan['resource_changes'][0]['change']['after']
    removed['resource_changes'][0]['change']['after'] = plan['resource_changes'][0]['change']['before']
    removed['prior_state']['values']['root_module']['resources'][0]['values'] = removed['resource_changes'][0]['change']['before']
    retained = {**args['retained_resources'], firewall: removed['resource_changes'][0]['change']['before']}
    variables = {**args['reviewed_variables'], 'allowed_tcp_ports': ['22', '80', '443', '2222']}
    removed['variables'] = {key: {'value': value} for key, value in variables.items()}
    gate.require_keyed_ingress_saved_plan(json.dumps(removed), **{**args, 'retained_resources': retained,
        'prior_routes': args['next_routes'], 'next_routes': (), 'observed_host_ports': {node: () for node in args['attached_node_addresses']},
        'reviewed_variables': variables})


@pytest.mark.parametrize('provider', ['linode', 'digitalocean'])
@pytest.mark.parametrize('tamper', ['sibling-host', 'unreviewed-port', 'node-update', 'egress',
                                    'attachment', 'prior-state', 'variable', 'unknown-policy', 'extra-resource'])
def test_rejects_unreviewed_plan_or_isolation(monkeypatch, provider, tamper):
    monkeypatch.setattr(gate, 'require_linode_workspace', lambda _: None)
    monkeypatch.setattr(gate, 'require_digitalocean_workspace', lambda _: None)
    plan, args, firewall, field, sibling = _case(provider)
    plan = copy.deepcopy(plan)
    args = copy.deepcopy(args)
    if tamper == 'sibling-host':
        args['observed_host_ports'][sibling] = (('tcp', 3333),)
    elif tamper == 'unreviewed-port':
        rule = _do_rule if provider == 'digitalocean' else _linode_rule
        plan['resource_changes'][0]['change']['after'][field].append(rule('tcp', 4444))
    elif tamper == 'node-update':
        plan['resource_changes'][1]['change']['actions'] = ['update']
    elif tamper == 'egress':
        plan['resource_changes'][0]['change']['after']['outbound'] = [{'action': 'DROP'}]
    elif tamper == 'attachment':
        plan['resource_changes'][0]['change']['after']['linodes'] = ['99']
    elif tamper == 'prior-state':
        plan['prior_state']['values']['root_module']['resources'][1]['values']['id'] = 'changed'
    elif tamper == 'variable':
        plan['variables']['allowed_tcp_ports']['value'].append('4444')
    elif tamper == 'unknown-policy':
        plan['resource_changes'][0]['change']['after_unknown'] = {field: True}
    elif tamper == 'extra-resource':
        plan['resource_changes'].append({'address': 'evil_resource.evil', 'mode': 'managed', 'change': {'actions': ['create']}})
    with pytest.raises(TerraformPlanGateError):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_selected_route_may_have_distinct_edge_and_middle_ports(monkeypatch):
    monkeypatch.setattr(gate, 'require_digitalocean_workspace', lambda _: None)
    plan, args, firewall, field, _ = _case('digitalocean')
    middle = args['attached_node_addresses'][0]
    args['next_routes'] += (gate.KeyedIngressRoute('channel-1', 'tcp', 8001, middle),)
    args['observed_host_ports'][middle] = (('tcp', 8001),)
    plan['resource_changes'][0]['change']['after'][field].append(_do_rule('tcp', 8001))
    args['reviewed_variables']['allowed_tcp_ports'].append('8001')
    gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_digitalocean_udp_route_uses_udp_union_and_only_selected_host(monkeypatch):
    provider = 'digitalocean'
    monkeypatch.setattr(gate, 'require_linode_workspace', lambda _: None)
    monkeypatch.setattr(gate, 'require_digitalocean_workspace', lambda _: None)
    plan, args, _, field, _ = _case(provider)
    edge = args['attached_node_addresses'][1]
    args['next_routes'] = (gate.KeyedIngressRoute('channel-1', 'udp', 3478, edge),)
    args['observed_host_ports'][edge] = (('udp', 3478),)
    args['reviewed_variables']['allowed_tcp_ports'] = ['22', '80', '443', '2222']
    args['reviewed_variables']['allowed_udp_ports'] = ['3478']
    plan['variables'] = {key: {'value': value} for key, value in args['reviewed_variables'].items()}
    rule = _do_rule if provider == 'digitalocean' else _linode_rule
    plan['resource_changes'][0]['change']['after'][field] = [
        rule('tcp', port) for port in (80, 443, 2222)
    ] + [rule('udp', 3478), plan['resource_changes'][0]['change']['after'][field][-1]]
    gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_linode_udp_requires_new_audited_source_contract(monkeypatch):
    monkeypatch.setattr(gate, 'require_linode_workspace', lambda _: None)
    plan, args, _, _, _ = _case('linode')
    edge = args['attached_node_addresses'][1]
    args['next_routes'] = (gate.KeyedIngressRoute('channel-1', 'udp', 3478, edge),)
    args['observed_host_ports'][edge] = (('udp', 3478),)
    with pytest.raises(TerraformPlanGateError, match='Terraform ports'):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_rejects_sibling_route_change_even_when_public_union_is_same(monkeypatch):
    monkeypatch.setattr(gate, 'require_digitalocean_workspace', lambda _: None)
    plan, args, _, _, sibling = _case('digitalocean')
    prior_sibling = gate.KeyedIngressRoute('sibling-channel', 'udp', 5500, sibling)
    args['prior_routes'] = (prior_sibling,)
    args['next_routes'] = (args['next_routes'][0],
                           gate.KeyedIngressRoute('sibling-channel', 'udp', 5501, sibling))
    with pytest.raises(TerraformPlanGateError, match='sibling'):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


@pytest.mark.parametrize('tamper', [
    {'ipv6': ['::/0']},
    {'extra_provider_field': 'permissive'},
    {'description': 'unexpected'},
])
def test_linode_public_rule_rejects_ipv6_or_unreviewed_fields(monkeypatch, tamper):
    monkeypatch.setattr(gate, 'require_linode_workspace', lambda _: None)
    plan, args, _, field, _ = _case('linode')
    plan['resource_changes'][0]['change']['after'][field][3].update(tamper)
    with pytest.raises(TerraformPlanGateError, match='public Linode rule'):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


_PINNED_LEGACY_DEFAULTS = {"edge_count_per_region": 1, "edge_regions": [],
                           "middle_count": 1, "middle_region": None}


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_accepts_real_keyed_unused_legacy_defaults_without_changing_reviewed_inputs(monkeypatch, provider):
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    monkeypatch.setattr(gate, "require_digitalocean_workspace", lambda _: None)
    plan, args, *_ = _case(provider)
    original = copy.deepcopy(args["reviewed_variables"])
    plan["variables"].update({key: {"value": value} for key, value in _PINNED_LEGACY_DEFAULTS.items()})
    gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)
    assert args["reviewed_variables"] == original


@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
@pytest.mark.parametrize("name, value", [
    ("edge_count_per_region", 2), ("edge_count_per_region", True),
    ("middle_count", 0), ("middle_count", True),
    ("edge_regions", ["us-west"]), ("edge_regions", None),
    ("middle_region", "us-west"), ("middle_region", []),
    ("external_middle_nodes", []), ("arbitrary_extra", None),
])
def test_rejects_changed_legacy_default_or_arbitrary_extra_variable(monkeypatch, provider, name, value):
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    monkeypatch.setattr(gate, "require_digitalocean_workspace", lambda _: None)
    plan, args, *_ = _case(provider)
    plan["variables"].update({key: {"value": value} for key, value in _PINNED_LEGACY_DEFAULTS.items()})
    plan["variables"][name] = {"value": value}
    with pytest.raises(TerraformPlanGateError, match="reviewed inputs"):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_rejects_default_variable_extra_envelope_fields(monkeypatch):
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    plan, args, *_ = _case("linode")
    plan["variables"]["middle_count"] = {"value": 1, "sensitive": False}
    with pytest.raises(TerraformPlanGateError, match="reviewed inputs"):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def _linode_computed_update_case():
    plan, args, firewall, field, sibling = _case("linode")
    plan, args = copy.deepcopy(plan), copy.deepcopy(args)
    metadata = {"created": "2026-10-20T01:00:00", "updated": "2026-10-20T02:00:00",
                "fingerprint": "retained-fingerprint", "version": 3, "status": "enabled",
                "devices": [{"id": 11}, {"id": 12}], "interfaces": [], "nodebalancers": []}
    args["retained_resources"][firewall].update(copy.deepcopy(metadata))
    plan["prior_state"]["values"]["root_module"]["resources"][0]["values"].update(copy.deepcopy(metadata))
    change = plan["resource_changes"][0]["change"]
    change["before"].update(copy.deepcopy(metadata))
    change["after"].update(copy.deepcopy(metadata))
    for key in ("fingerprint", "updated", "version"):
        change["after"].pop(key)
    # Literal structural-known shapes from the actual pinned-provider show.
    change["after_unknown"] = {
        "devices": [{}, {}], "fingerprint": True,
        "inbound": [{"ipv4": [False]} for _ in change["after"][field]],
        "interfaces": [], "linodes": [False, False, False], "nodebalancers": [],
        "outbound": [{"ipv6": [False]}], "tags": [False], "updated": True, "version": True,
    }
    return plan, args, change


def test_accepts_actual_linode_computed_update_and_structural_known_masks(monkeypatch):
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    plan, args, _ = _linode_computed_update_case()
    gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


@pytest.mark.parametrize("field, value", [
    ("status", "disabled"), ("id", "another-firewall"), ("tags", ["foreign"]),
    ("linodes", ["1", "2"]), ("devices", []), ("interfaces", [42]),
    ("nodebalancers", [99]), ("outbound", []), ("inbound_policy", "ACCEPT"),
])
def test_computed_update_preserves_exact_identity_attachment_egress_and_policy(monkeypatch, field, value):
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    plan, args, change = _linode_computed_update_case()
    change["after"][field] = value
    with pytest.raises(TerraformPlanGateError, match="attachment, egress, or identity"):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


@pytest.mark.parametrize("field, mask", [
    ("status", True), ("id", True), ("tags", [True]), ("linodes", [False, True, False]),
    ("devices", [{"id": True}, {}]), ("interfaces", True), ("nodebalancers", [True]),
    ("outbound", [{"ipv6": [True]}]), ("inbound", [{"ipv4": [True]}]),
    ("inbound", [{"ports": True}]), ("inbound_policy", True),
])
def test_computed_update_rejects_unknown_policy_identity_or_attachment(monkeypatch, field, mask):
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    plan, args, change = _linode_computed_update_case()
    change["after_unknown"][field] = mask
    with pytest.raises(TerraformPlanGateError, match="provider-unknown"):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_computed_update_still_binds_complete_retained_before(monkeypatch):
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    plan, args, change = _linode_computed_update_case()
    change["before"]["fingerprint"] = "changed-before"
    with pytest.raises(TerraformPlanGateError):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)


def test_digitalocean_computed_status_uses_same_recursive_mask_contract(monkeypatch):
    monkeypatch.setattr(gate, "require_digitalocean_workspace", lambda _: None)
    plan, args, _, field, _ = _case("digitalocean")
    change = plan["resource_changes"][0]["change"]
    change["after"].update(status="waiting", pending_changes=[])
    change["after_unknown"] = {"status": True, "pending_changes": [],
                               field: [{"source_addresses": [False]} for _ in change["after"][field]]}
    gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)
    change["after_unknown"][field][0]["source_addresses"] = [True]
    with pytest.raises(TerraformPlanGateError, match="provider-unknown"):
        gate.require_keyed_ingress_saved_plan(json.dumps(plan), **args)
