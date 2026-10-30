# Copyright (c) 2026, Oracle and/or its affiliates.
"""Strict metadata-only no-op state, with actual adapter/history seams separate."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json

import pytest

from app.services import provider_keyed_ingress_update as ingress
from test_keyed_ingress_socket_composition import _adapter_case


def _checked(state):
    state.update(version=4, terraform_version='1.15.5', outputs={'owned': {'value': 'exact', 'type': 'string'}})
    state['check_results'] = [{'object_kind': 'var', 'config_addr': f'var.{name}', 'status': 'pass',
        'objects': [{'object_addr': f'var.{name}[{i}]', 'status': 'pass'} for i in range(2)]}
        for name in ('middle_count', 'edge_count_per_region')]
    return state


def _bytes(state):
    return json.dumps(state).encode()


@pytest.mark.parametrize('drift', [None, 'resources', 'private', 'outputs', 'lineage', 'schema', 'terraform',
    'check_status', 'object_status', 'missing', 'added', 'duplicate', 'object_duplicate', 'nested_order',
    'kind', 'empty_identity', 'malformed', 'serial_bool', 'serial_backwards', 'serial_jump', 'same_serial_changed_bytes'])
def test_noop_metadata_allows_only_check_row_order_and_one_serial_tick(drift):
    before = _checked({'resources': [{'type': 'owned', 'instances': [{'attributes': {'id': 'exact'}, 'private': 'opaque'}]}],
                       'serial': 20, 'lineage': 'exact'})
    after = deepcopy(before)
    after['serial'] += 1
    after['check_results'].reverse()
    if drift == 'resources': after['resources'].append({'type': 'foreign'})
    elif drift == 'private': after['resources'][0]['instances'][0]['private'] = 'changed'
    elif drift == 'outputs': after['outputs']['owned']['value'] = 'changed'
    elif drift == 'lineage': after['lineage'] = 'foreign'
    elif drift == 'schema': after['version'] = True
    elif drift == 'terraform': after['terraform_version'] = 'other'
    elif drift == 'check_status': after['check_results'][0]['status'] = 'unknown'
    elif drift == 'object_status': after['check_results'][0]['objects'][0]['status'] = 'fail'
    elif drift == 'missing': after['check_results'].pop()
    elif drift == 'added': after['check_results'].append({**deepcopy(after['check_results'][0]), 'config_addr': 'var.foreign'})
    elif drift == 'duplicate': after['check_results'].append(deepcopy(after['check_results'][0]))
    elif drift == 'object_duplicate': after['check_results'][0]['objects'].append(deepcopy(after['check_results'][0]['objects'][0]))
    elif drift == 'nested_order': after['check_results'][0]['objects'].reverse()
    elif drift == 'kind': after['check_results'][0]['object_kind'] = 'resource'
    elif drift == 'empty_identity': after['check_results'][0]['config_addr'] = ''
    elif drift == 'malformed': after['check_results'][0]['objects'] = None
    elif drift == 'serial_bool': after['serial'] = True
    elif drift == 'serial_backwards': after['serial'] = 19
    elif drift == 'serial_jump': after['serial'] = 22
    elif drift == 'same_serial_changed_bytes': after['serial'] = 20
    if drift is None:
        ingress._require_noop_state(_bytes(before), _bytes(after))
        ingress._require_noop_state(_bytes(before), _bytes(before))
    else:
        with pytest.raises(ValueError): ingress._require_noop_state(_bytes(before), _bytes(after))


@pytest.mark.parametrize('provider,middle', [('linode', 'digitalocean'), ('digitalocean', 'linode')])
def test_real_one_shot_adapter_captures_metadata_noop_and_runs_postproof(tmp_path, monkeypatch, provider, middle):
    update, plan, credentials, validator, run, calls, _, _ = _adapter_case(
        tmp_path, monkeypatch, middle, provider, False, provider)
    path = update.workspace.state_path
    path.write_bytes(_bytes(_checked(json.loads(path.read_bytes()))))
    before_raw = path.read_bytes()
    update = replace(update, state_sha256=sha256(before_raw).hexdigest())
    def metadata_apply(argv, root, env):
        result = run(argv, root, env)
        if argv[1] == 'apply':
            state = json.loads(path.read_bytes())
            state['serial'] += 1
            state['check_results'].reverse()
            path.write_bytes(_bytes(state))
        return result
    kwargs = dict(credentials=credentials, recheck_authority=lambda: None,
        command_environment={}, command_runner=metadata_apply, release_validator=validator)
    ingress.plan_keyed_ingress_update(update, **kwargs)
    proofs = []
    done = ingress.apply_keyed_ingress_update(update, post_apply_proof=lambda: proofs.append(path.read_bytes()), **kwargs)
    assert done['phase'] == 'applied' and done['postStateSha256'] == sha256(path.read_bytes()).hexdigest()
    assert proofs == [path.read_bytes()] and before_raw != path.read_bytes()
    assert calls.count('apply') == 1
    assert (path.parent / f'.barragan-ingress-{update.job_id}-after.tfstate').read_bytes() == path.read_bytes()
    with pytest.raises(ingress.KeyedIngressUpdateAttention):
        ingress.apply_keyed_ingress_update(update, post_apply_proof=lambda: pytest.fail('replay'), **kwargs)
    assert calls.count('apply') == 1


def test_noop_serial_tick_without_check_reordering_is_valid():
    before = _checked({'resources': [], 'serial': 2, 'lineage': 'exact'})
    after = deepcopy(before)
    after['serial'] = 3
    ingress._require_noop_state(_bytes(before), _bytes(after))
