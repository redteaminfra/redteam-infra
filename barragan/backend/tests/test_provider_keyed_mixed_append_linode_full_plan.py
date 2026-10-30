# Copyright (c) 2026, Oracle and/or its affiliates.
"""Synthetic semantic regressions for the Linode mixed-append JSON gate.

Pinned provider schema masks are isolated here; the authentic saved-plan mask
comparison is performed only against the private DevTest plan on the host.
"""

import copy
from dataclasses import replace
from types import SimpleNamespace
import json

import pytest

from app.services import provider_keyed_mixed_append_linode_full_plan as gate
from app.services.terraform_plan_gate import TerraformPlanGateError
from test_provider_keyed_mixed_append_linode_plan_preflight import _case_plan, workspace


def _rule(action, protocol, label, ports=None, ipv4=None, ipv6=None):
    return {"action": action, "protocol": protocol, "label": label,
            "ports": ports, "ipv4": ipv4, "ipv6": ipv6, "description": ""}


def _fixture(monkeypatch):
    plan, args, original = _case_plan()
    reviewed = {**original.nonsecret_varfile,
                "allowed_tcp_ports": ["22", "80", "443", "2222"],
                "allowed_udp_ports": [],
                "ssh_pub_key_path": "/private/fixture/admin.pub",
                "ssh_priv_key_path": "/private/fixture/admin",
                "ssh_config_path": "/private/fixture/ssh"}
    intent = replace(original, nonsecret_varfile=reviewed)
    plan["variables"] = {key: {"value": value} for key, value in {
        **reviewed, **gate._DEFAULTS, "linode_api_token": "fixture-token"}.items()}
    changes = {row["address"]: row["change"] for row in plan["resource_changes"]}
    prior = {row["address"]: row["values"] for row in
             plan["prior_state"]["values"]["root_module"]["resources"]}
    retained_edge = next(address for address in prior if address.startswith("linode_instance.edge["))
    prior[retained_edge]["root_pass"] = "fixture-retained-password"
    changes[retained_edge]["before"]["root_pass"] = "fixture-retained-password"
    changes[retained_edge]["after"]["root_pass"] = "fixture-retained-password"
    new = changes[intent.new_edge_address]
    new.update(before=None, before_sensitive=False,
               after={"label": intent.new_edge.label, "image": intent.new_edge.image,
                      "type": intent.new_edge.node_type, "region": intent.new_edge.region,
                      "tags": [intent.new_edge.tag],
                      "authorized_keys": list(intent.new_edge.authorized_keys),
                      "root_pass": "fixture-retained-password",
                      "fixture-static": "approved"},
               after_unknown={"fixture": "node-unknown"},
               after_sensitive={"fixture": "node-sensitive"})
    ips = ["1.1.1.1/32", "1.0.0.1/32"]
    before_rules = [_rule("ACCEPT", "TCP", f"allow-tcp-{port}", port, ["0.0.0.0/0"])
                    for port in ("80", "443", "2222")]
    before_rules += [_rule("ACCEPT", "TCP", "allow-tcp-22-trusted", "22",
                           list(intent.prior_trusted_ssh_cidrs))]
    before_rules += [_rule("ACCEPT", proto.upper(),
                           f"allow-{intent.new_edge.tag}-host-{proto}", ipv4=ips)
                     for proto in ("tcp", "udp", "icmp")]
    before_rules += [_rule("DROP", proto.upper(), f"block-ipv6-{proto}", ipv6=["::/0"])
                     for proto in ("tcp", "udp", "icmp")]
    before = {"label": f"fw-{intent.new_edge.tag}-firewall", "tags": [intent.new_edge.tag],
              "inbound_policy": "DROP", "outbound_policy": "ACCEPT",
              "linodes": [1001, 1002], "inbound": before_rules,
              "fingerprint": "old", "updated": "old", "version": 1}
    after = copy.deepcopy(before)
    for field in ("fingerprint", "updated", "version"):
        after.pop(field)
    after["linodes"].append(None)
    after["inbound"][3]["ipv4"] = list(intent.trusted_ssh_cidrs)
    for rule in after["inbound"][4:7]:
        rule.pop("ipv4")
    prior["linode_firewall.firewall"].clear()
    prior["linode_firewall.firewall"].update(copy.deepcopy(before))
    changes["linode_firewall.firewall"].update(
        before=before, after=after,
        after_unknown={"fixture": "firewall-unknown"},
        before_sensitive={"fixture": "firewall-before-sensitive"},
        after_sensitive={"fixture": "firewall-after-sensitive"})
    for address in ("local_file.ansible_inventory[0]", "local_file.ssh_stanza[0]"):
        changes[address].update(after=None, after_unknown={},
                                before_sensitive={"sensitive_content": True},
                                after_sensitive=False)
    old_key = retained_edge.split('["', 1)[1].removesuffix('"]')
    new_key = intent.new_edge_address.split('["', 1)[1].removesuffix('"]')
    outputs = {
        "edge_instance_ids": ["1002"], "edge_public_ips": ["1.0.0.1"],
        "edge_nodes": {old_key: {"id": "1002", "label": prior[retained_edge]["label"],
                                 "middle_node": "middle_02", "public_ip": "1.0.0.1"}},
        "middle_instance_ids": ["1001"], "middle_public_ips": ["1.1.1.1"],
        "middle_nodes": {"middle_02": {"id": "1001", "label": "middle02-fixture",
                                       "public_ip": "1.1.1.1"}},
        "public-key": reviewed["ssh_pub_key_path"],
        "run-ansible": "Run ansible to configure hosts with:\n\t"
                       "ansible-playbook ../ansible/sketch-playbook.yml -i inventory.ini "
                       f'-e "ssh_pub_key={reviewed["ssh_pub_key_path"]}" '
                       f'-e "ssh_config_path={reviewed["ssh_config_path"]}/{reviewed["engagement_name"]}-sketch"',
        "good-bye": "Have a nice day!", "root-password": "fixture-password",
        "root-password-retrieval": "fixture-instructions",
    }
    plan["prior_state"]["values"]["outputs"] = {
        name: {"value": value} for name, value in outputs.items()}
    plan["output_changes"] = {}
    for name, value in outputs.items():
        after_value = copy.deepcopy(value)
        unknown = False
        if name in ("edge_instance_ids", "edge_public_ips"):
            after_value.append(None)
            unknown = [False, True]
        elif name == "edge_nodes":
            after_value[new_key] = {"label": intent.new_edge.label,
                                    "middle_node": "middle_01"}
            unknown = {old_key: {}, new_key: {"id": True, "public_ip": True}}
        plan["output_changes"][name] = {
            "actions": ["update" if name in ("edge_instance_ids", "edge_public_ips", "edge_nodes")
                        else "no-op"], "before": value, "after": after_value,
            "after_unknown": unknown,
            "before_sensitive": name == "root-password",
            "after_sensitive": name == "root-password"}
    state = json.dumps({"outputs": {name: {"value": value} for name, value in outputs.items()}}).encode()
    approved = {
        '{"fixture-static":"approved"}': gate._REAL_NODE_STATIC_SHA256,
        '{"fixture":"node-unknown"}': gate._NEW_EDGE_UNKNOWN,
        '{"fixture":"node-sensitive"}': gate._NEW_EDGE_SENSITIVE,
        '{"fixture":"firewall-unknown"}': gate._FIREWALL_UNKNOWN,
        '{"fixture":"firewall-before-sensitive"}': gate._FIREWALL_BEFORE_SENSITIVE,
        '{"fixture":"firewall-after-sensitive"}': gate._FIREWALL_AFTER_SENSITIVE,
    }
    real_digest = gate._digest
    monkeypatch.setattr(gate, "_digest", lambda value: approved.get(
        json.dumps(value, sort_keys=True, separators=(",", ":")), real_digest(value)))
    monkeypatch.setattr(gate, "require_mixed_linode_append_retained_plan_preflight",
                        lambda *args, **kwargs: None)
    return plan, intent, reviewed, state


def _check(plan, intent, reviewed, state):
    gate.require_mixed_linode_append_full_plan(
        json.dumps(plan), workspace=SimpleNamespace(source_revision=gate._SOURCE_REVISION), intent=intent,
        digitalocean_state_json=b"fixture-do", linode_state_json=state,
        reviewed_variables=reviewed)


def test_synthetic_semantic_plan_accepts_exact_append(monkeypatch):
    _check(*_fixture(monkeypatch))


@pytest.mark.parametrize("mutation", [
    "firewall_protocol", "firewall_action", "firewall_port", "public_ssh",
    "wrong_parent", "extra_output", "new_image", "root_password", "variable",
])
def test_synthetic_semantic_plan_rejects_unreviewed_delta(monkeypatch, mutation):
    plan, intent, reviewed, state = _fixture(monkeypatch)
    changes = {row["address"]: row["change"] for row in plan["resource_changes"]}
    if mutation.startswith("firewall_") or mutation == "public_ssh":
        inbound = changes["linode_firewall.firewall"]["after"]["inbound"]
        if mutation == "firewall_protocol":
            inbound[4]["protocol"] = "UDP"
        elif mutation == "firewall_action":
            inbound[4]["action"] = "DROP"
        elif mutation == "firewall_port":
            inbound[0]["ports"] = "22"
        else:
            inbound[3]["ipv4"] = ["0.0.0.0/0"]
    elif mutation == "wrong_parent":
        key = intent.new_edge_address.split('["', 1)[1].removesuffix('"]')
        plan["output_changes"]["edge_nodes"]["after"][key]["middle_node"] = "middle_02"
    elif mutation == "extra_output":
        plan["output_changes"]["extra"] = {"actions": ["create"]}
    elif mutation == "new_image":
        changes[intent.new_edge_address]["after"]["image"] = "other-image"
    elif mutation == "root_password":
        changes[intent.new_edge_address]["after"]["root_pass"] = "other-password"
    else:
        plan["variables"]["linode_image"]["value"] = "other-image"
    with pytest.raises(TerraformPlanGateError):
        _check(plan, intent, reviewed, state)


@pytest.mark.parametrize('value', [None, ['53']])
def test_candidate_append_keeps_explicit_empty_udp_union(monkeypatch, value):
    plan, intent, reviewed, state = _fixture(monkeypatch)
    if value is None:
        reviewed.pop('allowed_udp_ports')
        plan['variables'].pop('allowed_udp_ports')
    else:
        reviewed['allowed_udp_ports'] = value
        plan['variables']['allowed_udp_ports'] = {'value': value}
    intent = replace(intent, nonsecret_varfile=reviewed)
    with pytest.raises(TerraformPlanGateError, match='reviewed inputs'):
        _check(plan, intent, reviewed, state)


@pytest.mark.parametrize('drift', [None, 'firewall_before', 'node_noop'])
def test_full_gate_joins_real_retained_preflight_with_timestamp_refresh(workspace, monkeypatch, drift):
    import hashlib
    from test_provider_keyed_mixed_append_intent import _raw
    from test_provider_keyed_mixed_append_linode_plan_preflight import _with_timestamp_refresh
    from app.services.provider_keyed_mixed_append_linode_plan_preflight import require_mixed_linode_append_retained_plan_preflight
    plan, intent, reviewed, state_outputs = _fixture(monkeypatch)
    monkeypatch.setattr(gate, 'require_mixed_linode_append_retained_plan_preflight',
                        require_mixed_linode_append_retained_plan_preflight)
    prior = {row['address']: copy.deepcopy(row['values']) for row in
             plan['prior_state']['values']['root_module']['resources']}
    changes = {row['address']: row['change'] for row in plan['resource_changes']}
    before = prior['linode_firewall.firewall']
    before.update(id=dict(intent.retained_linode_ids)['linode_firewall.firewall'],
                  updated='2026-10-20T19:18:08Z')
    changes['linode_firewall.firewall']['after']['id'] = before['id']
    _with_timestamp_refresh(plan, before)
    changes['linode_firewall.firewall']['before_sensitive'] = copy.deepcopy(plan['resource_drift'][0]['change']['before_sensitive'])
    state = json.loads(_raw(prior))
    state['outputs'] = json.loads(state_outputs)['outputs']
    state_raw = json.dumps(state).encode()
    _, args, _ = _case_plan()
    intent = replace(intent, linode_state_sha256=hashlib.sha256(state_raw).hexdigest())
    if drift == 'firewall_before': changes['linode_firewall.firewall']['before']['updated'] = '2026-10-20T19:18:10Z'
    elif drift == 'node_noop':
        node = next(address for address in changes if address.startswith('linode_instance.middle'))
        changes[node]['after']['region'] = 'different-region'
    original = copy.deepcopy((plan, state_raw))
    kwargs = dict(workspace=workspace, intent=intent,
        digitalocean_state_json=args['provider_states']['digitalocean'], linode_state_json=state_raw,
        reviewed_variables=reviewed)
    if drift:
        with pytest.raises(TerraformPlanGateError): gate.require_mixed_linode_append_full_plan(json.dumps(plan), **kwargs)
    else:
        gate.require_mixed_linode_append_full_plan(json.dumps(plan), **kwargs)
    assert (plan, state_raw) == original
