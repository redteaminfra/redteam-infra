# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact mixed append saved-plan resource delta, stale state and drift vetoes."""

import copy
import hashlib
import json

import pytest

from app.services.provider_keyed_initial_plan_gate import DigitalOceanInitialFirewallIntent
from app.services.provider_keyed_mixed_append_intent import (
    compile_mixed_digitalocean_on_linode_append_intent,
)
from app.services.provider_keyed_mixed_append_plan_gate import (
    require_mixed_digitalocean_on_linode_append_full_plan,
)
from app.services.terraform_plan_gate import TerraformPlanGateError
from test_provider_keyed_append_plan_gate import _fixture, _metadata
from test_provider_keyed_initial_plan_gate import workspace  # audited template fixture
from test_provider_keyed_mixed_append_intent import _raw, mixed_fixture


def _case(workspace):
    source = mixed_fixture()
    plan, original = _fixture()
    # The existing one-provider append fixture has two DO chains. Keep one
    # DO chain, then switch the new edge to the externally declared middle.
    renamed_middle = 'digitalocean_droplet.middle["primary"]'
    kept = {'digitalocean_droplet.middle["middle_01"]',
            'digitalocean_droplet.edge["nyc3-01"]'}
    retained = {(('digitalocean_droplet.middle["middle_01"]'
                  if address == renamed_middle else address)): copy.deepcopy(value)
                for address, value in original.items()
                if address in kept or address == renamed_middle
                or not address.startswith("digitalocean_droplet.")}
    original_do_state = json.loads(source["provider_states"]["digitalocean"])
    from app.services.provider_keyed_initial_teardown import _state_resources
    source_nodes = _state_resources(original_do_state)
    for address in kept:
        retained[address] = copy.deepcopy(source_nodes[address])
    for address in retained:
        if address not in kept:
            retained[address]["id"] = source_nodes[address]["id"]
    policy = DigitalOceanInitialFirewallIntent(
        "e7c9a4d2-firewall", "s12345678", ("80", "443", "2222"), (),
        ("9.9.9.9/32", "1.1.1.1/32"),
    )
    retained["digitalocean_firewall.firewall"]["name"] = policy.name
    retained["digitalocean_firewall.firewall"]["tags"] = [policy.selector_tag]
    peers = sorted(value["ipv4_address"] + "/32" for address, value in retained.items()
                   if address in kept)
    for rule in retained["digitalocean_firewall.firewall"]["inbound_rule"]:
        if rule["port_range"] == "1-65535":
            rule["source_addresses"] = peers
        elif rule["port_range"] == "22":
            rule["source_addresses"] = ["9.9.9.9/32"]
    source["provider_states"]["digitalocean"] = _raw(retained)
    source["provider_state_sha256"]["digitalocean"] = hashlib.sha256(
        source["provider_states"]["digitalocean"]).hexdigest()
    source["published_binding"]["providerStates"][0]["stateSha256"] = (
        source["provider_state_sha256"]["digitalocean"])
    source["provider_resource_ids"]["digitalocean"] = {
        address: str(value["id"]) for address, value in retained.items()}
    intent = compile_mixed_digitalocean_on_linode_append_intent(**source)
    resources = []
    for resource in plan["resource_changes"]:
        address = resource["address"]
        if address.startswith("digitalocean_droplet.") and address not in kept \
                and address != renamed_middle \
                and address != 'digitalocean_droplet.edge["nyc3-02"]':
            continue
        row = copy.deepcopy(resource)
        if address == renamed_middle:
            address = 'digitalocean_droplet.middle["middle_01"]'
            row.update(_metadata(address))
        change = row["change"]
        if address in retained:
            change["before"] = copy.deepcopy(retained[address])
            change["after"] = copy.deepcopy(retained[address])
        if address == "digitalocean_firewall.firewall":
            change["after"]["inbound_rule"] = copy.deepcopy(
                resource["change"]["after"]["inbound_rule"])
            change["after"]["name"] = policy.name
            change["after"]["tags"] = [policy.selector_tag]
            for rule in change["after"]["inbound_rule"]:
                if rule["port_range"] == "22":
                    rule["source_addresses"] = sorted(policy.trusted_ssh_cidrs)
            for key in ("before_sensitive", "after_sensitive"):
                for item in change[key]["inbound_rule"][:3]:
                    item["source_addresses"] = ([False] * 2 if key == "before_sensitive" else [])
            ssh_index = next(index for index, rule in enumerate(change["after"]["inbound_rule"])
                             if rule["protocol"] == "tcp" and rule["port_range"] == "22")
            change["after_sensitive"]["inbound_rule"][ssh_index]["source_addresses"] = [False, False]
            change["after_unknown"]["inbound_rule"][ssh_index]["source_addresses"] = [False, False]
        elif address.startswith("digitalocean_droplet."):
            if address == 'digitalocean_droplet.edge["nyc3-02"]':
                row.update(_metadata(intent.new_edge_address))
                change["after"].update(
                    name=intent.new_edge.name, image=intent.new_edge.image,
                    size=intent.new_edge.size, region=intent.new_edge.region,
                    tags=[policy.selector_tag], ssh_keys=["do-key"])
        elif address == "digitalocean_ssh_key.key":
            change["before_sensitive"] = {}
            change["after_sensitive"] = {}
        elif address.startswith("local_file."):
            change["actions"] = ["delete"]
            change["after"] = None
            change["after_unknown"] = {}
            change["after_sensitive"] = False
            change.pop("replace_paths", None)
        resources.append(row)
    plan["resource_changes"] = resources
    plan["prior_state"]["values"]["root_module"]["resources"] = [
        {**_metadata(address), "values": copy.deepcopy(value)}
        for address, value in retained.items()]
    variables = {**intent.nonsecret_varfile,
                 "allowed_tcp_ports": ["22", "80", "443", "2222"],
                 "allowed_udp_ports": [], "middle_size": "s-1vcpu-1gb-amd",
                 "ssh_config_path": "opaque-ssh-dir",
                 "ssh_priv_key_path": "opaque-private-path",
                 "ssh_pub_key_path": "opaque-public-path"}
    plan["variables"] = {key: {"value": copy.deepcopy(value)}
                         for key, value in variables.items()}
    plan["variables"].update({key: {"value": value} for key, value in {
        "edge_count_per_region": 1, "edge_regions": [], "middle_count": 1,
        "middle_region": None, "do_pat": "test-only-redacted",
    }.items()})
    return plan, source, intent, policy, variables


def _check(workspace, plan, source, intent, policy, variables):
    require_mixed_digitalocean_on_linode_append_full_plan(
        json.dumps(plan), workspace=workspace, intent=intent,
        digitalocean_state_json=source["provider_states"]["digitalocean"],
        linode_state_json=source["provider_states"]["linode"],
        firewall=policy, reviewed_variables=variables)


def test_exact_cross_provider_append_plan(workspace):
    case = _case(workspace)
    firewall_change = next(row["change"] for row in case[0]["resource_changes"]
                           if row["address"] == "digitalocean_firewall.firewall")
    ssh = next(rule for rule in firewall_change["after"]["inbound_rule"]
               if rule["protocol"] == "tcp" and rule["port_range"] == "22")
    assert ssh["source_addresses"] == sorted(case[3].trusted_ssh_cidrs)
    _check(workspace, *case)


@pytest.mark.parametrize("change", [
    "retained_replace", "extra_delete", "firewall_selector", "local_retained",
    "external_parent", "state_swap", "drift", "unknown_edge",
    "unrelated_ssh_cidr", "missing_middle_ssh_cidr", "broad_ssh_cidr",
    "altered_baseline_ssh_cidr",
])
def test_mixed_append_rejects_unreviewed_changes(workspace, change):
    plan, source, intent, policy, variables = _case(workspace)
    plan, source, variables = copy.deepcopy((plan, source, variables))
    if change == "retained_replace":
        next(row for row in plan["resource_changes"] if row["address"].startswith(
            "digitalocean_droplet.middle"))["change"]["actions"] = ["delete", "create"]
    elif change == "extra_delete":
        plan["resource_changes"].append({**_metadata("digitalocean_droplet.edge[\"rogue-01\"]"),
                                          "change": {"actions": ["delete"]}})
    elif change == "firewall_selector":
        next(row for row in plan["resource_changes"] if row["address"] ==
             "digitalocean_firewall.firewall")["change"]["after"]["tags"] = ["other"]
    elif change == "local_retained":
        next(row for row in plan["resource_changes"] if row["address"] ==
             "local_file.ssh_stanza[0]")["change"]["actions"] = ["no-op"]
    elif change == "external_parent":
        plan["variables"]["external_middle_nodes"]["value"] = ["wrong"]
    elif change == "state_swap":
        source["provider_states"]["linode"] += b" "
    elif change == "drift":
        plan["resource_drift"] = [{"address": "digitalocean_droplet.edge"}]
    elif change == "unknown_edge":
        next(row for row in plan["resource_changes"] if row["address"] ==
             intent.new_edge_address)["change"]["after_unknown"]["name"] = True
    elif change in {"unrelated_ssh_cidr", "missing_middle_ssh_cidr", "broad_ssh_cidr",
                    "altered_baseline_ssh_cidr"}:
        cidrs = {
            "unrelated_ssh_cidr": ["9.9.9.9/32", "1.1.1.1/32", "8.8.8.8/32"],
            "missing_middle_ssh_cidr": ["9.9.9.9/32"],
            "broad_ssh_cidr": ["9.9.9.9/32", "1.1.1.0/24"],
            "altered_baseline_ssh_cidr": ["8.8.8.8/32", "1.1.1.1/32"],
        }[change]
        plan["variables"]["trusted_ssh_cidrs"]["value"] = cidrs
        rules = next(row for row in plan["resource_changes"] if row["address"] ==
                     "digitalocean_firewall.firewall")["change"]["after"]["inbound_rule"]
        next(rule for rule in rules if rule["protocol"] == "tcp" and rule["port_range"] == "22")[
            "source_addresses"] = cidrs
    with pytest.raises(TerraformPlanGateError):
        _check(workspace, plan, source, intent, policy, variables)


def _refresh_case(workspace):
    from dataclasses import replace
    from app.services.provider_keyed_initial_teardown import _state_resources
    plan, source, intent, policy, variables = _case(workspace)
    retained = _state_resources(json.loads(source['provider_states']['digitalocean']))
    nodes = sorted(a for a in retained if a.startswith('digitalocean_droplet.'))
    for number, address in enumerate(nodes, 101):
        retained[address]['id'] = str(number)
    before = retained['digitalocean_firewall.firewall']
    before.update(status='waiting', droplet_ids=None, pending_changes=[
        {'droplet_id': int(retained[a]['id']), 'removing': False, 'status': 'waiting'} for a in nodes])
    refreshed = {**copy.deepcopy(before), 'status': 'succeeded', 'droplet_ids': [], 'pending_changes': []}
    source['provider_states']['digitalocean'] = _raw(retained)
    intent = replace(intent, digitalocean_state_sha256=hashlib.sha256(source['provider_states']['digitalocean']).hexdigest(),
        retained_digitalocean_ids=tuple(sorted((a, str(v['id'])) for a, v in retained.items())))
    for row in plan['prior_state']['values']['root_module']['resources']:
        row['values'] = copy.deepcopy(refreshed if row['address']=='digitalocean_firewall.firewall' else retained[row['address']])
    for row in plan['resource_changes']:
        if row['address'] in nodes:
            row['change']['before'] = copy.deepcopy(retained[row['address']])
            row['change']['after'] = copy.deepcopy(retained[row['address']])
    change = next(r['change'] for r in plan['resource_changes'] if r['address']=='digitalocean_firewall.firewall')
    old_sensitive = copy.deepcopy(change['before_sensitive'])
    old_sensitive['pending_changes'] = [{}, {}]
    new_sensitive = {**copy.deepcopy(old_sensitive), 'pending_changes': [], 'droplet_ids': []}
    plan['resource_drift'] = [{**_metadata('digitalocean_firewall.firewall'), 'change': {
        'actions': ['update'], 'before': copy.deepcopy(before), 'after': copy.deepcopy(refreshed),
        'after_unknown': {}, 'before_sensitive': old_sensitive, 'after_sensitive': new_sensitive}}]
    change['before'] = copy.deepcopy(refreshed)
    change['after'].update(status='succeeded', droplet_ids=[], pending_changes=[])
    for key in ('after_unknown','before_sensitive','after_sensitive'):
        change[key].update(droplet_ids=[], pending_changes=[])
    return plan, source, intent, policy, variables


def test_exact_completed_tag_selector_refresh_is_accepted(workspace):
    _check(workspace, *_refresh_case(workspace))


@pytest.mark.parametrize('drift', ['extra_row', 'provider', 'raw_before', 'foreign_pending',
    'removing', 'status', 'policy', 'tag', 'egress', 'firewall_id', 'attachments',
    'unknown_mask', 'sensitive_mask', 'prior_state', 'planned_before'])
def test_completed_firewall_refresh_rejects_every_other_change(workspace, drift):
    plan, source, intent, policy, variables = _refresh_case(workspace)
    row = plan['resource_drift'][0]; change = row['change']
    if drift == 'extra_row': plan['resource_drift'].append(copy.deepcopy(row))
    elif drift == 'provider': row['provider_name'] = 'registry.terraform.io/hashicorp/local'
    elif drift == 'raw_before': change['before']['status'] = 'succeeded'
    elif drift == 'foreign_pending': change['before']['pending_changes'][0]['droplet_id'] = 999
    elif drift == 'removing': change['before']['pending_changes'][0]['removing'] = True
    elif drift == 'status': change['after']['status'] = 'waiting'
    elif drift == 'policy': change['after']['inbound_rule'][0]['source_addresses'] = ['0.0.0.0/0']
    elif drift == 'tag': change['after']['tags'] = ['foreign']
    elif drift == 'egress': change['after']['outbound_rule'] = []
    elif drift == 'firewall_id': change['after']['id'] = 'foreign'
    elif drift == 'attachments': change['after']['droplet_ids'] = [101]
    elif drift == 'unknown_mask': change['after_unknown'] = {'status': True}
    elif drift == 'sensitive_mask': change['after_sensitive'].pop('droplet_ids')
    elif drift == 'prior_state': next(r for r in plan['prior_state']['values']['root_module']['resources'] if r['address']==row['address'])['values']['status'] = 'waiting'
    else: next(r for r in plan['resource_changes'] if r['address']==row['address'])['change']['before']['status'] = 'waiting'
    with pytest.raises(TerraformPlanGateError):
        _check(workspace, plan, source, intent, policy, variables)
