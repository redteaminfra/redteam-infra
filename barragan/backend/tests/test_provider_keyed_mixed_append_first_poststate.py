# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact first-provider poststate is independent of provider ordering."""

import copy
import hashlib
import json

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_append_pair_apply_child import (
    ACTION as APPLY_ACTION, _base as apply_base, _child_id as apply_child_id,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_append_first_poststate import (
    FirstResultJournal, MixedAppendFirstPoststateAttention, observe_first_mixed_append_poststate,
    prove_first_mixed_append_poststate, recognize_first_mixed_append_zero_result,
)
from app.services.provider_keyed_mixed_append_intent import (
    compile_mixed_digitalocean_on_linode_append_intent,
)
from app.services.provider_keyed_mixed_append_linode_intent import (
    compile_mixed_linode_on_digitalocean_append_intent,
)
from app.services.provider_keyed_mixed_partial_apply_inventory import (
    MixedPartialApplyInventorySnapshot,
)
from test_provider_keyed_mixed_append_intent import _raw, mixed_fixture
from test_provider_keyed_mixed_append_linode_intent import _case as linode_case
from app.storage.job_repository import StoredJobRun


def _case(provider, *, reused_id_across_kinds=False):
    args = mixed_fixture() if provider == "digitalocean" else linode_case()
    if provider == "digitalocean":
        resources = _state_resources(json.loads(args["provider_states"][provider]))
        resources["digitalocean_firewall.firewall"].update(
            name="e7c9a4d2-firewall", tags=["s12345678"], droplet_ids=None,
            inbound_rule=[{"protocol": proto, "port_range": "1-65535",
                           "source_addresses": ["8.8.4.4/32", "8.8.8.8/32"]}
                          for proto in ("icmp", "tcp", "udp")] +
                         [{"protocol": "tcp", "port_range": "22",
                           "source_addresses": ["9.9.9.9/32"]}])
        resources["digitalocean_ssh_key.key"].update(
            name="key", tags=[], public_key="ssh-ed25519 reviewed")
        if reused_id_across_kinds:
            resources["digitalocean_firewall.firewall"]["id"] = "do-middle"
        args["provider_states"][provider] = _raw(resources)
        args["provider_state_sha256"][provider] = hashlib.sha256(args["provider_states"][provider]).hexdigest()
        args["provider_resource_ids"][provider] = {a: str(v["id"]) for a, v in resources.items()}
        next(row for row in args["published_binding"]["providerStates"]
             if row["provider"] == provider)["stateSha256"] = args["provider_state_sha256"][provider]
        intent = compile_mixed_digitalocean_on_linode_append_intent(**args)
        new = {"id": "do-new", "name": intent.new_edge.name,
               "image": intent.new_edge.image, "size": intent.new_edge.size,
               "region": intent.new_edge.region, "tags": [intent.new_edge.firewall_selector_tag],
               "ssh_keys": ["do-key"], "ipv4_address": "9.9.9.9"}
    else:
        resources = _state_resources(json.loads(args["provider_states"][provider]))
        for address in (a for a in resources if a.startswith("linode_instance.")):
            resources[address].update(image="linode/ubuntu24.04", type="g6-nanode-1",
                                      authorized_keys=["ssh-ed25519 fixture"])
        resources["linode_firewall.firewall"].update(
            label="fw-e7c9a4d2-firewall", tags=["e7c9a4d2"], linodes=[1001, 1002],
            inbound=[{"label": f"rule-{n}", "ipv4": ["0.0.0.0/0"]} for n in range(10)])
        if reused_id_across_kinds:
            resources["linode_firewall.firewall"]["id"] = 1001
        resources["linode_firewall.firewall"]["inbound"][3]["ipv4"] = ["9.9.9.9/32"]
        for row in resources["linode_firewall.firewall"]["inbound"][4:7]:
            row["ipv4"] = ["1.1.1.1/32", "1.0.0.1/32"]
        args["provider_states"][provider] = _raw(resources)
        args["provider_state_sha256"][provider] = hashlib.sha256(args["provider_states"][provider]).hexdigest()
        args["provider_resource_ids"][provider] = {a: str(v["id"]) for a, v in resources.items()}
        next(row for row in args["published_binding"]["providerStates"]
             if row["provider"] == provider)["stateSha256"] = args["provider_state_sha256"][provider]
        intent = compile_mixed_linode_on_digitalocean_append_intent(**args)
        new = {"id": 1003, "label": intent.new_edge.label,
               "image": intent.new_edge.image, "type": intent.new_edge.node_type,
               "region": intent.new_edge.region, "tags": [intent.new_edge.tag],
               "authorized_keys": ["ssh-ed25519 fixture"], "ipv4": ["9.9.9.9"]}
    prior = copy.deepcopy(resources)
    after = copy.deepcopy(resources)
    after.pop("local_file.ansible_inventory[0]")
    after.pop("local_file.ssh_stanza[0]")
    after[intent.new_edge_address] = new
    if provider == "digitalocean":
        fw = after["digitalocean_firewall.firewall"]
        for row in fw["inbound_rule"][:3]:
            row["source_addresses"].append("9.9.9.9/32")
        fw["inbound_rule"][3]["source_addresses"] = list(intent.trusted_ssh_cidrs)
    else:
        fw = after["linode_firewall.firewall"]
        fw["linodes"].append(1003)
        fw["inbound"][3]["ipv4"] = list(intent.trusted_ssh_cidrs)
        for row in fw["inbound"][4:7]:
            row["ipv4"].append("9.9.9.9/32")
    post = json.loads(_raw(after))
    post["serial"] = 2
    raw_post = json.dumps(post).encode()
    changes = []
    for address, old in prior.items():
        if address.startswith("local_file."):
            change = {"actions": ["delete"], "before": old, "after": None}
        elif address.endswith("firewall.firewall"):
            change = {"actions": ["update"], "before": old, "after": after[address]}
        else:
            change = {"actions": ["no-op"], "before": old, "after": old}
        changes.append({"address": address, "change": change})
    changes.append({"address": intent.new_edge_address,
                    "change": {"actions": ["create"], "before": None, "after": new}})
    show = json.dumps({"terraform_version": "1.15.5", "resource_changes": changes}).encode()
    inventory = []
    for address, value in after.items():
        if address.startswith("local_file.") or address.startswith("random_password."):
            continue
        kind = "node" if ".middle[" in address or ".edge[" in address else (
            "ssh_key" if "ssh_key" in address else "firewall")
        inventory.append({"kind": kind, "id": value["id"],
                          "name": value["label" if provider == "linode" else "name"],
                          "tags": value.get("tags", []),
                          **({"public_key": value["public_key"]} if kind == "ssh_key" else {})})
    snapshot = MixedPartialApplyInventorySnapshot(
        provider, raw_post, hashlib.sha256(raw_post).hexdigest(), "applied",
        tuple(inventory),
        tuple(sorted(str(after[a]["id"]) for a in after if a.startswith("linode_instance.")))
        if provider == "linode" else None,
        True if provider == "digitalocean" else None,
        3 if provider == "digitalocean" else None,
        tuple(sorted(str(after[a]["id"]) for a in after if a.startswith("digitalocean_droplet.")))
        if provider == "digitalocean" else None,
        "a" * 64,
    )
    return dict(intent=intent, predecessor_state=args["provider_states"][provider],
                reviewed_show_json=show, snapshot=snapshot,
                command_result_proved=True, process_quiescent=True)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_first_provider_exact_poststate_and_inventory(provider):
    data = _case(provider)
    proof = prove_first_mixed_append_poststate(**data)
    assert proof.provider == provider
    assert proof.serial == 2
    assert proof.new_edge_public_ip == "9.9.9.9"
    assert len(proof.resource_ids) == 5


def _private_ip_case(provider="linode", *, field="private_ip", actual=False):
    from dataclasses import replace
    data = _case(provider)
    state = json.loads(data["snapshot"].state_json)
    address = data["intent"].new_edge_address
    _state_resources(state)[address][field] = actual
    raw = json.dumps(state).encode()
    data["snapshot"] = replace(data["snapshot"], state_json=raw,
                               state_sha256=hashlib.sha256(raw).hexdigest())
    show = json.loads(data["reviewed_show_json"])
    change = next(row["change"] for row in show["resource_changes"]
                  if row["address"] == address)
    change["after"][field] = None
    change["after_unknown"] = {}
    data["reviewed_show_json"] = json.dumps(show).encode()
    return data


def test_linode_new_private_ip_null_plan_matches_disabled_created_state():
    data = _private_ip_case()
    original = (data["reviewed_show_json"], data["snapshot"].state_json)
    assert prove_first_mixed_append_poststate(**data).provider == "linode"
    assert (data["reviewed_show_json"], data["snapshot"].state_json) == original


@pytest.mark.parametrize("provider,field,actual", [
    ("linode", "private_ip", True), ("linode", "private_ip", 0),
    ("linode", "private_ip", ""), ("linode", "network_helper", False),
    ("digitalocean", "private_ip", False),
])
def test_private_ip_normalization_does_not_cover_other_values_or_fields(provider, field, actual):
    with pytest.raises(MixedAppendFirstPoststateAttention):
        prove_first_mixed_append_poststate(**_private_ip_case(provider, field=field, actual=actual))


def test_private_ip_normalization_preserves_all_other_known_new_edge_fields():
    from dataclasses import replace
    data = _private_ip_case()
    state = json.loads(data["snapshot"].state_json)
    _state_resources(state)[data["intent"].new_edge_address]["authorized_keys"] = ["other"]
    raw = json.dumps(state).encode()
    data["snapshot"] = replace(data["snapshot"], state_json=raw,
                               state_sha256=hashlib.sha256(raw).hexdigest())
    with pytest.raises(MixedAppendFirstPoststateAttention):
        prove_first_mixed_append_poststate(**data)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_node_and_firewall_may_share_numeric_id_across_resource_kinds(provider):
    data = _case(provider, reused_id_across_kinds=True)
    proof = prove_first_mixed_append_poststate(**data)
    assert proof.new_edge_address == data["intent"].new_edge_address


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_uncertain_command_result_never_proves(provider):
    data = _case(provider)
    data["command_result_proved"] = False
    with pytest.raises(MixedAppendFirstPoststateAttention):
        prove_first_mixed_append_poststate(**data)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_original_node_id_or_region_drift_rejected(provider):
    data = _case(provider)
    state = json.loads(data["snapshot"].state_json)
    resource = next(row for row in state["resources"] if row["type"] in
                    {"linode_instance", "digitalocean_droplet"})
    resource["instances"][0]["attributes"]["region"] = "other"
    raw = json.dumps(state).encode()
    data["snapshot"] = copy.copy(data["snapshot"])
    from dataclasses import replace
    data["snapshot"] = replace(data["snapshot"], state_json=raw,
                                state_sha256=hashlib.sha256(raw).hexdigest())
    with pytest.raises(MixedAppendFirstPoststateAttention):
        prove_first_mixed_append_poststate(**data)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_missing_or_extra_attachment_requires_fresh_observation(provider):
    from dataclasses import replace
    data = _case(provider)
    snapshot = data["snapshot"]
    if provider == "linode":
        snapshot = replace(snapshot, linode_firewall_attached_node_ids=("1001", "1002"))
    else:
        snapshot = replace(snapshot, selector_resources_count=2)
    data["snapshot"] = snapshot
    with pytest.raises(MixedAppendFirstPoststateAttention):
        prove_first_mixed_append_poststate(**data)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_observer_renews_during_one_attachment_settling_window(provider):
    from dataclasses import replace
    data = _case(provider)
    full = data["snapshot"]
    if provider == "linode":
        incomplete = replace(full, linode_firewall_attached_node_ids=("1001", "1002"))
    else:
        incomplete = replace(full, selector_resources_count=2)
    snapshots = iter((incomplete, full))
    fences = []
    sleeps = []
    proof = observe_first_mixed_append_poststate(
        intent=data["intent"], predecessor_state=data["predecessor_state"],
        reviewed_show_json=data["reviewed_show_json"],
        journal=FirstResultJournal("child", provider, "a" * 64, "b" * 64, {"pid": 1}),
        snapshot_reader=lambda: next(snapshots),
        fence=lambda: fences.append(1) or "claim-generation",
        process_quiescent=lambda _: True,
        poll_interval_seconds=0, sleeper=lambda value: sleeps.append(value))
    assert proof.state_sha256 == full.state_sha256
    assert sleeps == [0]
    assert len(fences) >= 3


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_observer_restart_rejects_changed_state_during_settling(provider):
    from dataclasses import replace
    data = _case(provider)
    full = data["snapshot"]
    if provider == "linode":
        incomplete = replace(full, linode_firewall_attached_node_ids=("1001", "1002"))
    else:
        incomplete = replace(full, selector_resources_count=2)
    changed = replace(full, state_sha256="b" * 64)
    snapshots = iter((incomplete, changed))
    with pytest.raises(MixedAppendFirstPoststateAttention):
        observe_first_mixed_append_poststate(
            intent=data["intent"], predecessor_state=data["predecessor_state"],
            reviewed_show_json=data["reviewed_show_json"],
            journal=FirstResultJournal("child", provider, "a" * 64, "b" * 64, {"pid": 1}),
            snapshot_reader=lambda: next(snapshots), fence=lambda: "claim",
            process_quiescent=lambda _: True,
            poll_interval_seconds=0, sleeper=lambda _: None)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_exact_zero_result_journal_recognized_in_both_provider_orders(provider):
    from dataclasses import replace
    order = [provider, "linode" if provider == "digitalocean" else "digitalocean"]
    parent = StoredJobRun(
        "job-parent", "provider_keyed_mixed_append", "running", "engagement:eng-one",
        "engagement", "eng-one", "operator",
        {"phase": "apply_sealed", "coreJobId": "job-core", "corePlanId": "plan-core",
         "reviewSha256": "a" * 64, "providerOrder": order}, [],
        "2026-10-19T00:00:00+00:00", "2026-10-19T00:00:00+00:00", None, [])
    receipt = {"provider": provider, "engagementId": "eng-one",
               "coreJobId": "job-core", "planSha256": "b" * 64,
               "terraformBinarySha256": "c" * 64}
    messages = [
        ("mixed append first Apply queued", {}),
        ("mixed append first Apply started", {}),
        ("mixed append first Apply command intended", {
            "invocationId": "invocation", "argvSha256": "d" * 64,
            "planSha256": "b" * 64, "planPath": "/saved.tfplan",
            "terraformPath": "/terraform", "terraformSha256": "c" * 64}),
        ("mixed append first Apply command started before GO", {
            "invocationId": "invocation", "bootId": "boot", "pid": 20,
            "pgid": 20, "startTicks": 50}),
        ("mixed append first phase apply_started", {"commandStartSequence": 4}),
        ("mixed append first Apply command result fenced", {
            "invocationId": "invocation", "returnCode": 0,
            "stdoutBytes": 0, "stderrBytes": 0,
            "stdoutTruncated": False, "stderrTruncated": False}),
        ("mixed append first phase applied", {"commandResultSequence": 6}),
        ("mixed append first awaiting exact poststate proof", {"commandResultSequence": 6}),
    ]
    events = [JobEvent(index, "info", message, data)
              for index, (message, data) in enumerate(messages, 1)]
    child = StoredJobRun(
        apply_child_id(parent.id), APPLY_ACTION, "running", parent.target,
        parent.target_type, parent.target_id, parent.requested_by, apply_base(parent), [],
        parent.created_at, parent.started_at, None, events)
    result = recognize_first_mixed_append_zero_result(parent, child, receipt)
    assert result.provider == provider
    assert result.started_identity["pid"] == 20
    bad = replace(child, events=[*events[:5],
                                 replace(events[5], data={**events[5].data, "returnCode": 1}),
                                 *events[6:]])
    with pytest.raises(MixedAppendFirstPoststateAttention):
        recognize_first_mixed_append_zero_result(parent, bad, receipt)


from test_provider_keyed_initial_plan_gate import workspace


def test_append_observer_binds_selected_firewall_details_in_digest(workspace, monkeypatch):
    from app.services import provider_keyed_mixed_append_first_poststate as module
    data = _case('digitalocean')
    snapshot = data['snapshot']
    monkeypatch.setattr(module, '_require_canonical_workspace_paths', lambda _: None)
    monkeypatch.setattr(module, '_verify_audited_workspace', lambda _: None)
    monkeypatch.setattr(module, '_credential', lambda *args: 'encrypted')
    monkeypatch.setattr(module, '_local', lambda _: (snapshot.state_json, 'applied', None))
    detail = dict(status='waiting', pending_changes=[])
    def observed(*args, include_firewall_details=False):
        assert include_firewall_details is True
        rows = copy.deepcopy(snapshot.inventory)
        next(row for row in rows if row['kind'] == 'firewall')['firewall'] = copy.deepcopy(detail)
        return rows, True, 3, snapshot.selector_attached_node_ids
    monkeypatch.setattr(module, '_digitalocean', observed)
    kwargs = dict(intent=data['intent'], workspace=workspace,
        receipt=dict(provider='digitalocean', credentialRecordId=workspace.provider_connection_id,
            credentialSecretSha256='a'*64, credentialUpdatedAt='now',
            engagementId=data['intent'].engagement_id, coreJobId=data['intent'].core_job_id),
        fence=lambda: 'generation', process_quiescent=lambda: True,
        credential_repository=object(), decrypt_secret=lambda _: 'token')
    before = module.collect_first_mixed_append_inventory_snapshot(**kwargs)
    detail['status'] = 'succeeded'
    after = module.collect_first_mixed_append_inventory_snapshot(**kwargs)
    assert before.observation_sha256 != after.observation_sha256
    assert before.state_sha256 == after.state_sha256


def _completed_refresh_case(workspace, drift):
    from dataclasses import replace
    from test_provider_keyed_mixed_append_plan_gate import _refresh_case, _check
    plan, source, intent, policy, variables = _refresh_case(workspace)
    _check(workspace, plan, source, intent, policy, variables)
    prior = _state_resources(json.loads(source['provider_states']['digitalocean']))
    after = {a: copy.deepcopy(v) for a, v in prior.items() if not a.startswith('local_file.')}
    changes = {row['address']: row['change'] for row in plan['resource_changes']}
    after[intent.new_edge_address] = {**copy.deepcopy(changes[intent.new_edge_address]['after']),
        'id': '103', 'ipv4_address': '9.9.9.9'}
    fw = copy.deepcopy(changes['digitalocean_firewall.firewall']['after'])
    peers = sorted(v['ipv4_address'] + '/32' for a, v in after.items() if a.startswith('digitalocean_droplet.'))
    for row in fw['inbound_rule'][:3]: row['source_addresses'] = peers
    after['digitalocean_firewall.firewall'] = fw
    if drift == 'direct_attachment': fw['droplet_ids'] = [101]
    if drift == 'refresh_before': plan['resource_drift'][0]['change']['before']['status'] = 'succeeded'
    completion = drift not in (None, 'direct_attachment', 'refresh_before')
    if completion:
        # Real provider post-Apply state repeats waiting attachments even though
        # the freshly listed firewall has finished applying the reviewed rules.
        fw.update(status='waiting', pending_changes=[
            {'droplet_id': int(value['id']), 'removing': False, 'status': 'waiting'}
            for address, value in after.items() if address.startswith('digitalocean_droplet.')])
        observed = {key: copy.deepcopy(fw[key]) for key in ('id', 'name', 'tags', 'droplet_ids')}
        observed.update(status='succeeded', pending_changes=[])
        for side, prefix, api_side in [('inbound', 'source', 'sources'), ('outbound', 'destination', 'destinations')]:
            observed[side + '_rules'] = [dict(protocol=row['protocol'],
                ports='0' if side == 'outbound' and row['protocol'] == 'icmp' else row['port_range'],
                **{api_side: {'addresses': copy.deepcopy(row[prefix + '_addresses'])}})
                for row in fw[side + '_rule']]
        if drift == 'live_waiting': observed['status'] = 'waiting'
        if drift == 'live_pending': observed['pending_changes'] = copy.deepcopy(fw['pending_changes'])
        if drift == 'live_identity': observed['id'] = 'other'
        if drift == 'live_rules': observed['inbound_rules'].pop()
        if drift == 'live_egress': observed['outbound_rules'].pop()
        if drift == 'live_attachment': observed['droplet_ids'] = [101]
        if drift == 'live_selector': observed['tags'] = ['other']
        if drift == 'pending_missing': fw['pending_changes'].pop()
        if drift == 'pending_duplicate': fw['pending_changes'][-1] = fw['pending_changes'][0]
        if drift == 'pending_extra': fw['pending_changes'].append({'droplet_id': 999, 'removing': False, 'status': 'waiting'})
        if drift == 'pending_removing': fw['pending_changes'][0]['removing'] = True
        if drift == 'pending_status': fw['pending_changes'][0]['status'] = 'failed'
        if drift == 'state_rules': fw['inbound_rule'].pop()
        if drift == 'unknown_status': changes['digitalocean_firewall.firewall']['after_unknown']['status'] = True
        if drift == 'plan_waiting': changes['digitalocean_firewall.firewall']['after']['status'] = 'waiting'
        if drift == 'other_state_field': fw['created_at'] = 'changed'
    post = json.loads(_raw(after)); post['serial'] = 2
    raw = json.dumps(post).encode()
    inventory = []
    for address, value in after.items():
        kind = 'node' if address.startswith('digitalocean_droplet.') else ('ssh_key' if address=='digitalocean_ssh_key.key' else 'firewall')
        inventory.append({'kind': kind, 'id': value['id'], 'name': value['name'],
            'tags': value.get('tags', []), **({'public_key': value.get('public_key')} if kind=='ssh_key' else {})})
        if completion and kind == 'firewall' and drift != 'missing_details':
            inventory[-1]['firewall'] = observed
    snapshot = MixedPartialApplyInventorySnapshot('digitalocean', raw, hashlib.sha256(raw).hexdigest(),
        'applied', tuple(inventory), None, True, 3,
        tuple(sorted(str(v['id']) for a, v in after.items() if a.startswith('digitalocean_droplet.'))), 'a'*64)
    if drift == 'selector_count': snapshot = replace(snapshot, selector_resources_count=2)
    if drift == 'selector_membership': snapshot = replace(snapshot, selector_attached_node_ids=('101', '102'))
    kwargs = dict(intent=intent, predecessor_state=source['provider_states']['digitalocean'],
        reviewed_show_json=json.dumps(plan).encode(), snapshot=snapshot,
        command_result_proved=True, process_quiescent=True)
    return kwargs


@pytest.mark.parametrize('drift', [None, 'direct_attachment', 'refresh_before',
    'post_completion', 'live_waiting', 'live_pending', 'live_identity', 'live_rules',
    'live_egress', 'live_attachment', 'live_selector', 'missing_details',
    'pending_missing', 'pending_duplicate', 'pending_extra', 'pending_removing',
    'pending_status', 'state_rules', 'unknown_status', 'plan_waiting', 'other_state_field',
    'selector_count', 'selector_membership'])
def test_gate_validated_completed_refresh_survives_poststate_proof(workspace, drift):
    kwargs = _completed_refresh_case(workspace, drift)
    snapshot = kwargs["snapshot"]
    original = (snapshot.state_json, kwargs['reviewed_show_json'])
    if drift not in (None, 'post_completion'):
        with pytest.raises(MixedAppendFirstPoststateAttention): prove_first_mixed_append_poststate(**kwargs)
    else:
        assert prove_first_mixed_append_poststate(**kwargs).new_edge_provider_id == '103'
    assert (snapshot.state_json, kwargs['reviewed_show_json']) == original


def _observe_completion(data, snapshots, *, observer=observe_first_mixed_append_poststate,
                        sleeper=lambda _: None, fence=lambda: 'claim', max_attempts=12):
    return observer(
        intent=data['intent'], predecessor_state=data['predecessor_state'],
        reviewed_show_json=data['reviewed_show_json'],
        journal=FirstResultJournal('child', 'digitalocean', 'a' * 64, 'b' * 64, {'pid': 1}),
        snapshot_reader=lambda: next(snapshots), fence=fence,
        process_quiescent=lambda _: True, sleeper=sleeper, max_attempts=max_attempts)


@pytest.mark.parametrize('do_stage', ['first', 'second'])
@pytest.mark.parametrize('pending_count', [0, 1, 3])
def test_owned_firewall_completion_settles_in_both_provider_orders(workspace, do_stage, pending_count):
    from dataclasses import replace
    import inspect
    from app.services.provider_keyed_mixed_append_first_proof_job import prove_and_finish_first_mixed_append_apply
    from app.services.provider_keyed_mixed_append_second_proof_job import prove_and_finish_second_mixed_append_apply
    finisher = (prove_and_finish_first_mixed_append_apply if do_stage == 'first'
                else prove_and_finish_second_mixed_append_apply)
    observer = inspect.signature(finisher).parameters['poststate_observer'].default
    assert observer is observe_first_mixed_append_poststate
    data = _completed_refresh_case(workspace, 'post_completion')
    full = data['snapshot']
    waiting = copy.deepcopy(full)
    live = next(row['firewall'] for row in waiting.inventory if row['kind'] == 'firewall')
    resources = _state_resources(json.loads(waiting.state_json))
    pending = resources['digitalocean_firewall.firewall']['pending_changes'][:pending_count]
    live.update(status='waiting', pending_changes=copy.deepcopy(pending))
    # The returned receipt must come from the real final observation, never
    # from the completion-only classification projection.
    full = replace(full, observation_sha256='f' * 64)
    original = copy.deepcopy((waiting, full, data['reviewed_show_json'], data['predecessor_state']))
    sleeps = []
    with pytest.raises(MixedAppendFirstPoststateAttention):
        prove_first_mixed_append_poststate(**{**data, 'snapshot': waiting})
    proof = _observe_completion(data, iter((waiting, full)), observer=observer, sleeper=sleeps.append)
    assert sleeps == [5.0]
    assert proof.observation_sha256 == 'f' * 64
    assert proof.state_sha256 == full.state_sha256
    assert (waiting, full, data['reviewed_show_json'], data['predecessor_state']) == original


def test_owned_firewall_completion_exhaustion_never_returns_projected_proof(workspace):
    data = _completed_refresh_case(workspace, 'post_completion')
    waiting = data['snapshot']
    live = next(row['firewall'] for row in waiting.inventory if row['kind'] == 'firewall')
    live.update(status='waiting', pending_changes=[])
    original = copy.deepcopy(waiting)
    sleeps = []
    snapshots = iter([waiting] * 12)
    with pytest.raises(MixedAppendFirstPoststateAttention, match='did not settle'):
        _observe_completion(data, snapshots, sleeper=sleeps.append)
    assert sleeps == [5.0] * 11
    assert list(snapshots) == []
    assert waiting == original


@pytest.mark.parametrize('drift', [
    'foreign', 'duplicate', 'removing', 'pending_status', 'pending_type', 'pending_shape',
    'identity', 'tags', 'direct_attachment', 'inbound', 'outbound', 'selector',
    'count', 'inventory', 'raw_state', 'plan', 'raw_pending'])
def test_completion_wait_vetoes_drift_before_any_sleep(workspace, drift):
    from dataclasses import replace
    data = _completed_refresh_case(workspace, 'post_completion')
    waiting = data['snapshot']
    live = next(row['firewall'] for row in waiting.inventory if row['kind'] == 'firewall')
    resources = _state_resources(json.loads(waiting.state_json))
    live.update(status='waiting', pending_changes=copy.deepcopy(resources['digitalocean_firewall.firewall']['pending_changes']))
    pending = live['pending_changes']
    if drift == 'foreign': pending[0]['droplet_id'] = 999999
    elif drift == 'duplicate': pending.append(copy.deepcopy(pending[0]))
    elif drift == 'removing': pending[0]['removing'] = True
    elif drift == 'pending_status': pending[0]['status'] = 'failed'
    elif drift == 'pending_type': pending[0]['droplet_id'] = True
    elif drift == 'pending_shape': pending[0]['extra'] = 1
    elif drift == 'identity': live['id'] = 'other'
    elif drift == 'tags': live['tags'] = ['other']
    elif drift == 'direct_attachment': live['droplet_ids'] = [101]
    elif drift == 'inbound': live['inbound_rules'].pop()
    elif drift == 'outbound': live['outbound_rules'].pop()
    elif drift == 'selector': waiting = replace(waiting, selector_attached_node_ids=('101', '102'))
    elif drift == 'count': waiting = replace(waiting, selector_resources_count=2)
    elif drift == 'inventory': waiting = replace(waiting, inventory=waiting.inventory[:-1])
    elif drift in ('raw_state', 'raw_pending'):
        state = json.loads(waiting.state_json)
        if drift == 'raw_state': state['serial'] = 1
        else:
            for row in state['resources']:
                if row['type'] == 'digitalocean_firewall': row['instances'][0]['attributes']['pending_changes'].pop()
        raw = json.dumps(state).encode()
        waiting = replace(waiting, state_json=raw, state_sha256=hashlib.sha256(raw).hexdigest())
    elif drift == 'plan':
        plan = json.loads(data['reviewed_show_json']); plan['terraform_version'] = 'changed'
        data['reviewed_show_json'] = json.dumps(plan).encode()
    original = copy.deepcopy(waiting)
    snapshots = iter((waiting,))
    with pytest.raises(MixedAppendFirstPoststateAttention):
        _observe_completion(data, snapshots, sleeper=lambda _: pytest.fail('drift must not sleep'))
    assert waiting == original


@pytest.mark.parametrize('drift', ['state', 'claim'])
def test_completion_wait_cannot_adopt_changed_generation(workspace, drift):
    from dataclasses import replace
    data = _completed_refresh_case(workspace, 'post_completion')
    full = data['snapshot']
    waiting = copy.deepcopy(full)
    next(row['firewall'] for row in waiting.inventory if row['kind'] == 'firewall').update(
        status='waiting', pending_changes=[])
    next_snapshot = replace(full, state_sha256='b' * 64) if drift == 'state' else full
    generation = ['claim']
    def sleep(_):
        if drift == 'claim': generation[0] = 'foreign-claim'
    with pytest.raises(MixedAppendFirstPoststateAttention):
        _observe_completion(data, iter((waiting, next_snapshot)), sleeper=sleep,
                            fence=lambda: generation[0])


@pytest.mark.parametrize('drift', [None, 'policy', 'timestamp', 'mask'])
def test_linode_poststate_uses_exact_refreshed_firewall_baseline(drift):
    from dataclasses import replace
    from test_provider_keyed_mixed_append_linode_plan_preflight import _with_timestamp_refresh
    data = _case('linode')
    prior = json.loads(data['predecessor_state'])
    post = json.loads(data['snapshot'].state_json)
    def firewall(state):
        return next(row['instances'][0]['attributes'] for row in state['resources']
                    if row['type'] == 'linode_firewall')
    firewall(prior)['updated'] = '2026-10-20T19:18:08Z'
    firewall(post)['updated'] = '2026-10-20T19:18:09Z'
    before = _state_resources(prior)
    raw_prior = json.dumps(prior).encode()
    data['predecessor_state'] = raw_prior
    data['intent'] = replace(data['intent'], linode_state_sha256=hashlib.sha256(raw_prior).hexdigest())
    plan = json.loads(data['reviewed_show_json'])
    # The shared poststate proof accepts only resource_changes; add the same
    # refreshed prior-state envelope used by the real saved-plan reader.
    plan['prior_state'] = {'values': {'root_module': {'resources': [
        {'address': address, 'values': copy.deepcopy(value)} for address, value in before.items()]}}}
    _with_timestamp_refresh(plan, before['linode_firewall.firewall'])
    after = next(row['change']['after'] for row in plan['resource_changes'] if row['address'] == 'linode_firewall.firewall')
    after['updated'] = '2026-10-20T19:18:09Z'
    if drift == 'policy': plan['resource_drift'][0]['change']['after']['inbound'].pop()
    elif drift == 'timestamp': plan['resource_drift'][0]['change']['after']['updated'] = '2026-10-20T19:18:07Z'
    elif drift == 'mask': plan['resource_drift'][0]['change']['after_sensitive']['tags'] = [True]
    raw_post = json.dumps(post).encode()
    data['snapshot'] = replace(data['snapshot'], state_json=raw_post, state_sha256=hashlib.sha256(raw_post).hexdigest())
    data['reviewed_show_json'] = json.dumps(plan).encode()
    original = copy.deepcopy(data)
    if drift:
        with pytest.raises(MixedAppendFirstPoststateAttention): prove_first_mixed_append_poststate(**data)
    else:
        proof = prove_first_mixed_append_poststate(**data)
        assert proof.state_sha256 == data['snapshot'].state_sha256
    assert data == original


@pytest.mark.parametrize('stage', ['first', 'second'])
def test_default_settling_budget_outlasts_twelve_observations_and_keeps_fence(workspace, stage):
    import inspect
    from app.services.provider_keyed_mixed_append_first_proof_job import (
        prove_and_finish_first_mixed_append_apply,
    )
    from app.services.provider_keyed_mixed_append_second_proof_job import (
        prove_and_finish_second_mixed_append_apply,
    )
    finisher = (prove_and_finish_first_mixed_append_apply if stage == 'first'
                else prove_and_finish_second_mixed_append_apply)
    budget = inspect.signature(finisher).parameters['max_observation_attempts'].default
    assert budget == 60
    assert inspect.signature(observe_first_mixed_append_poststate).parameters['max_attempts'].default == budget
    data = _completed_refresh_case(workspace, 'post_completion')
    full = data['snapshot']
    waiting = copy.deepcopy(full)
    next(row['firewall'] for row in waiting.inventory if row['kind'] == 'firewall').update(
        status='waiting', pending_changes=[])
    sleeps, renewals = [], []

    def renew():
        renewals.append(True)
        return 'same-claim'

    proof = _observe_completion(
        data, iter([waiting] * 20 + [full]), max_attempts=budget,
        sleeper=sleeps.append, fence=renew)
    assert sleeps == [5.0] * 20
    assert len(renewals) >= 42
    assert proof.observation_sha256 == full.observation_sha256
    assert proof.state_sha256 == full.state_sha256
