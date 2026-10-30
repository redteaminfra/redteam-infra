# Copyright (c) 2026, Oracle and/or its affiliates.
"""Synthetic action-scope tests; these are not real saved-plan calibration."""

import copy
import json

import pytest

from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_append_linode_intent import (
    compile_mixed_linode_on_digitalocean_append_intent,
)
from app.services.provider_keyed_mixed_append_linode_plan_preflight import (
    require_mixed_linode_append_retained_plan_preflight,
)
from app.services.terraform_plan_gate import TerraformPlanGateError
from test_provider_keyed_linode_initial_plan_gate import PLAN, workspace
from test_provider_keyed_mixed_append_linode_intent import _case


def _metadata(address):
    if address.startswith("linode_instance."):
        role = "middle" if ".middle[" in address else "edge"
        return {"address": address, "mode": "managed", "type": "linode_instance",
                "name": role, "index": address.split('["', 1)[1].removesuffix('"]'),
                "provider_name": "registry.terraform.io/linode/linode"}
    if address.startswith("local_file."):
        return {"address": address, "mode": "managed", "type": "local_file",
                "name": address.split(".", 1)[1].split("[", 1)[0], "index": 0,
                "provider_name": "registry.terraform.io/hashicorp/local"}
    kind, name, provider = (
        ("linode_firewall", "firewall", "linode") if address.startswith("linode_firewall")
        else ("random_password", "root_password", "hashicorp/random"))
    if provider == "linode":
        provider = "linode/linode"
    return {"address": address, "mode": "managed", "type": kind, "name": name,
            "provider_name": "registry.terraform.io/" + provider}


def _case_plan():
    args = _case()
    intent = compile_mixed_linode_on_digitalocean_append_intent(**args)
    retained = _state_resources(json.loads(args["provider_states"]["linode"]))
    plan = {"format_version": "1.2", "terraform_version": "1.15.5",
            "applyable": True, "complete": True, "errored": False,
            "prior_state": {"values": {"root_module": {"resources": [
                {**_metadata(address), "values": copy.deepcopy(values)}
                for address, values in retained.items()]}}},
            "resource_changes": []}
    for address, values in retained.items():
        action = ("update" if address == "linode_firewall.firewall" else
                  "delete" if address.startswith("local_file.") else "no-op")
        change = {"actions": [action], "before": copy.deepcopy(values),
                  "after": copy.deepcopy(values), "after_unknown": {},
                  "before_sensitive": {}, "after_sensitive": {}}
        if action == "delete":
            change["after"] = None
        plan["resource_changes"].append({**_metadata(address), "change": change})
    created = copy.deepcopy(next(row for row in PLAN["resource_changes"]
                             if row["address"].startswith("linode_instance.edge")))
    created.update(_metadata(intent.new_edge_address))
    created["change"]["after"].update(
        label=intent.new_edge.label, image=intent.new_edge.image,
        type=intent.new_edge.node_type, region=intent.new_edge.region,
        tags=[intent.new_edge.tag], authorized_keys=list(intent.new_edge.authorized_keys))
    plan["resource_changes"].append(created)
    return plan, args, intent


def _check(workspace, plan, args, intent):
    require_mixed_linode_append_retained_plan_preflight(
        json.dumps(plan), workspace=workspace, intent=intent,
        digitalocean_state_json=args["provider_states"]["digitalocean"],
        linode_state_json=args["provider_states"]["linode"])


def test_exact_retained_nodes_noop_in_synthetic_append_shape(workspace):
    case = _case_plan()
    _check(workspace, *case)
    _check(workspace, *copy.deepcopy(case))  # deterministic after restart


@pytest.mark.parametrize("change", [
    "replace_middle", "change_middle_image", "change_middle_id", "extra_resource",
    "omit_password", "drift", "stale_do_state", "stale_linode_state",
    "firewall_delete", "new_edge_replace", "retained_local_recreate",
    "shared_prior_change",
])
def test_retained_plan_preflight_rejects_scope_or_state_drift(workspace, change):
    plan, args, intent = copy.deepcopy(_case_plan())
    middle = next(row for row in plan["resource_changes"]
                  if row["address"].startswith("linode_instance.middle"))
    if change == "replace_middle":
        middle["change"]["actions"] = ["delete", "create"]
    elif change == "change_middle_image":
        middle["change"]["after"]["image"] = "linode/ubuntu22.04"
    elif change == "change_middle_id":
        next(row for row in plan["prior_state"]["values"]["root_module"]["resources"]
             if row["address"] == middle["address"])["values"]["id"] = 9999
    elif change == "extra_resource":
        plan["resource_changes"].append({**_metadata('linode_instance.edge["rogue-01"]'),
                                         "change": {"actions": ["create"]}})
    elif change == "omit_password":
        plan["resource_changes"] = [row for row in plan["resource_changes"]
                                    if row["address"] != "random_password.root_password"]
    elif change == "drift":
        plan["resource_drift"] = [{"address": middle["address"]}]
    elif change == "stale_do_state":
        args["provider_states"]["digitalocean"] += b" "
    elif change == "stale_linode_state":
        args["provider_states"]["linode"] += b" "
    elif change == "firewall_delete":
        next(row for row in plan["resource_changes"]
             if row["address"] == "linode_firewall.firewall")["change"]["actions"] = ["delete"]
    elif change == "new_edge_replace":
        next(row for row in plan["resource_changes"]
             if row["address"] == intent.new_edge_address)["change"]["actions"] = ["delete", "create"]
    elif change == "retained_local_recreate":
        next(row for row in plan["resource_changes"]
             if row["address"] == "local_file.ssh_stanza[0]")["change"]["actions"] = ["delete", "create"]
    elif change == "shared_prior_change":
        next(row for row in plan["prior_state"]["values"]["root_module"]["resources"]
             if row["address"] == "linode_firewall.firewall")["values"]["label"] = "changed"
    with pytest.raises(TerraformPlanGateError):
        _check(workspace, plan, args, intent)


def _firewall_refresh_mask():
    # Real Terraform structural mask from the pinned initial fixture, extended
    # to the two already attached devices and two retained peer addresses.
    mask = copy.deepcopy(next(row['change']['after_sensitive'] for row in PLAN['resource_changes']
                              if row['address'] == 'linode_firewall.firewall'))
    mask['devices'] = [{}, {}]
    for rule in mask['inbound'][4:7]: rule['ipv4'] = [False, False]
    return mask


def _with_timestamp_refresh(plan, before):
    from app.services.provider_keyed_mixed_append_linode_plan_preflight import _FIREWALL_BEFORE_SENSITIVE
    import hashlib
    mask = _firewall_refresh_mask()
    assert hashlib.sha256(json.dumps(mask, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == _FIREWALL_BEFORE_SENSITIVE
    after = {**copy.deepcopy(before), 'updated': '2026-10-20T19:18:09Z'}
    plan['resource_drift'] = [{**_metadata('linode_firewall.firewall'), 'change': {
        'actions': ['update'], 'before': copy.deepcopy(before), 'after': after,
        'after_unknown': {}, 'before_sensitive': mask, 'after_sensitive': copy.deepcopy(mask)}}]
    next(row for row in plan['prior_state']['values']['root_module']['resources']
         if row['address'] == 'linode_firewall.firewall')['values'] = copy.deepcopy(after)
    next(row for row in plan['resource_changes'] if row['address'] == 'linode_firewall.firewall')['change']['before'] = copy.deepcopy(after)
    return plan


def _timestamp_refresh_case():
    import hashlib
    from test_provider_keyed_mixed_append_intent import _raw
    plan, args, intent = _case_plan()
    retained = _state_resources(json.loads(args['provider_states']['linode']))
    before = retained['linode_firewall.firewall']
    # Preserve the complete real provider firewall shape, not a metadata-only
    # toy: both rulesets, attachment collections, status and rule fingerprint.
    before.update(copy.deepcopy(next(row['change']['after'] for row in PLAN['resource_changes']
                                     if row['address'] == 'linode_firewall.firewall')))
    before.update(label=f'fw-{intent.new_edge.tag}-firewall', tags=[intent.new_edge.tag],
        linodes=[1001, 1002], devices=[{'id': 2001, 'entity_id': 1001, 'type': 'linode', 'label': 'middle', 'url': '/v4/linode/instances/1001'},
                                    {'id': 2002, 'entity_id': 1002, 'type': 'linode', 'label': 'edge', 'url': '/v4/linode/instances/1002'}],
        interfaces=[], nodebalancers=[], status='enabled', disabled=False,
        created='2026-10-20T19:18:00Z', updated='2026-10-20T19:18:08Z', fingerprint='owned-rules', version=1)
    for rule in before['inbound'][4:7]: rule['ipv4'] = ['1.1.1.1/32', '1.0.0.1/32']
    args['provider_states']['linode'] = _raw(retained)
    args['provider_state_sha256']['linode'] = hashlib.sha256(args['provider_states']['linode']).hexdigest()
    next(row for row in args['published_binding']['providerStates'] if row['provider'] == 'linode')['stateSha256'] = args['provider_state_sha256']['linode']
    intent = compile_mixed_linode_on_digitalocean_append_intent(**args)
    return _with_timestamp_refresh(plan, before), args, intent


def test_exact_owned_firewall_updated_refresh_uses_refreshed_prior_without_mutating_raw(workspace):
    plan, args, intent = _timestamp_refresh_case()
    original = copy.deepcopy((plan, args))
    _check(workspace, plan, args, intent)
    assert (plan, args) == original


@pytest.mark.parametrize('drift', ['duplicate', 'foreign_scope', 'provider', 'index', 'extra_field', 'action',
    'id', 'label', 'tags', 'policy', 'egress', 'attachment', 'disabled', 'fingerprint', 'version',
    'raw_before', 'unknown', 'before_mask', 'after_mask', 'reverse', 'same_time', 'offset', 'invalid_time',
    'prior_mismatch', 'change_before_mismatch'])
def test_timestamp_refresh_rejects_every_unreviewed_delta(workspace, drift):
    plan, args, intent = _timestamp_refresh_case()
    row = plan['resource_drift'][0]
    change = row['change']
    if drift == 'duplicate': plan['resource_drift'].append(copy.deepcopy(row))
    elif drift == 'foreign_scope': row['address'] = intent.new_edge_address
    elif drift == 'provider': row['provider_name'] = 'registry.terraform.io/hashicorp/random'
    elif drift == 'index': row['index'] = None
    elif drift == 'extra_field': change['replace_paths'] = []
    elif drift == 'action': change['actions'] = ['delete', 'create']
    elif drift in ('id', 'label', 'tags', 'fingerprint', 'version'): change['after'][drift] = 'changed'
    elif drift == 'policy': change['after']['inbound_policy'] = 'ACCEPT'
    elif drift == 'egress': change['after']['outbound'].pop()
    elif drift == 'attachment': change['after']['linodes'].append(999)
    elif drift == 'disabled': change['after']['disabled'] = True
    elif drift == 'raw_before': change['before']['updated'] = '2026-10-20T19:18:07Z'
    elif drift == 'unknown': change['after_unknown'] = {'updated': True}
    elif drift == 'before_mask': change['before_sensitive']['tags'] = [True]
    elif drift == 'after_mask': change['after_sensitive']['tags'] = [True]
    elif drift == 'reverse': change['after']['updated'] = '2026-10-20T19:18:07Z'
    elif drift == 'same_time': change['after']['updated'] = change['before']['updated']
    elif drift == 'offset': change['after']['updated'] = '2026-10-20T19:18:09+00:00'
    elif drift == 'invalid_time': change['after']['updated'] = '2026-02-30T19:18:09Z'
    elif drift == 'prior_mismatch':
        next(row for row in plan['prior_state']['values']['root_module']['resources'] if row['address'] == 'linode_firewall.firewall')['values']['updated'] = '2026-10-20T19:18:10Z'
    elif drift == 'change_before_mismatch':
        next(row for row in plan['resource_changes'] if row['address'] == 'linode_firewall.firewall')['change']['before']['updated'] = '2026-10-20T19:18:10Z'
    with pytest.raises(TerraformPlanGateError): _check(workspace, plan, args, intent)
