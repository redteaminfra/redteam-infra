# Copyright (c) 2026, Oracle and/or its affiliates.
"""Ingress commands temporarily reuse the original sealed canonical SSH files."""
from dataclasses import replace
import fcntl
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_append_pair_apply_binding as binding
from app.services import provider_keyed_ingress_update as ingress
from test_provider_keyed_ingress_update import _setup
from test_provider_keyed_mixed_append_pair_apply_binding import _admin_key_setup


def _case(tmp_path, monkeypatch, provider):
    fixture_root = tmp_path / 'ingress'
    fixture_root.mkdir()
    update, credentials, release, original, calls = _setup(fixture_root, monkeypatch, provider)
    material = update.workspace.path.parents[1] / '.plan-material' / provider
    material.mkdir(parents=True, exist_ok=True, mode=0o700)
    public, private = material / 'admin-public', material / 'admin-private'
    variables = {**update.retained_variables, 'ssh_pub_key_path': str(public),
                 'ssh_priv_key_path': str(private)}
    update.retained_input_path.write_text(json.dumps(variables))
    update = replace(update, retained_variables=variables,
        reviewed_variables={**update.reviewed_variables, 'ssh_pub_key_path': str(public),
                            'ssh_priv_key_path': str(private)},
        retained_input_sha256=hashlib.sha256(update.retained_input_path.read_bytes()).hexdigest())
    public_value, private_value, _ = _admin_key_setup(monkeypatch, {provider: update.workspace})
    parent = SimpleNamespace(target_id='eng', input={'coreJobId': 'job-core'})
    jobs = SimpleNamespace(get=lambda _: object())
    def stage():
        # Staging and cleanup must be under the existing exclusive ingress lock.
        lock = update.workspace.path / '.barragan-ingress.lock'
        with lock.open('r+b') as descriptor:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return binding._staged_append_admin_material(parent, update.workspace,
                                                     update.reviewed_variables, jobs)
    def runner(argv, root, env):
        # Upstream Terraform evaluates file(local.ssh_pub_key_path). Read the
        # literal retained path here, without a material-reader mock.
        assert Path(update.reviewed_variables['ssh_pub_key_path']).read_text() == public_value
        assert private.read_text() == private_value
        assert public.stat().st_mode & 0o777 == private.stat().st_mode & 0o777 == 0o600
        result = original(argv, root, env)
        if argv[1] == 'show':
            shown = json.loads(result.stdout)
            shown['variables'].update({key: {'value': value}
                                       for key, value in update.reviewed_variables.items()})
            result.stdout = json.dumps(shown)
        return result
    kwargs = dict(credentials=credentials, release_validator=release,
        recheck_authority=lambda: None, command_environment={},
        staged_admin_material=stage, command_runner=runner)
    return update, kwargs, public, private, calls


@pytest.mark.parametrize('provider', ['linode', 'digitalocean'])
def test_sealed_literal_paths_exist_only_inside_plan_and_apply_lock(tmp_path, monkeypatch, provider):
    update, kwargs, public, private, calls = _case(tmp_path, monkeypatch, provider)
    assert not public.exists() and not private.exists()
    ingress.plan_keyed_ingress_update(update, **kwargs)
    assert not public.exists() and not private.exists()
    ingress.apply_keyed_ingress_update(update, post_apply_proof=lambda: None, **kwargs)
    assert calls == ['init', 'plan', 'show', 'show', 'apply']
    assert not public.exists() and not private.exists()


def test_material_fixture_is_independent_of_sibling_test_state(tmp_path, monkeypatch):
    sibling_material = tmp_path / '.plan-material' / 'digitalocean'
    sibling_material.mkdir(parents=True)
    sibling_material.chmod(0o755)
    foreign = sibling_material / 'unrelated'
    foreign.write_bytes(b'sibling fixture state')
    case_root = tmp_path / 'case'
    case_root.mkdir()
    update, kwargs, public, private, calls = _case(case_root, monkeypatch, 'digitalocean')
    ingress.plan_keyed_ingress_update(update, **kwargs)
    assert public.is_relative_to(case_root) and private.is_relative_to(case_root)
    assert calls == ['init', 'plan', 'show']
    assert not public.exists() and not private.exists()
    assert foreign.read_bytes() == b'sibling fixture state'
    assert sibling_material.stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize('phase', ['plan', 'apply'])
@pytest.mark.parametrize('drift', ['public', 'symlink', 'receipt', 'key', 'path'])
def test_material_drift_never_reaches_ingress_command(tmp_path, monkeypatch, phase, drift):
    update, kwargs, public, private, calls = _case(tmp_path, monkeypatch, 'linode')
    if phase == 'apply':
        ingress.plan_keyed_ingress_update(update, **kwargs)
    before = list(calls)
    if drift == 'public':
        public.write_bytes(b'foreign'); public.chmod(0o600)
    elif drift == 'symlink':
        public.symlink_to(tmp_path / 'missing')
    elif drift == 'receipt':
        (update.workspace.path / '.barragan-linode-plan-receipt.json').write_text('{}')
    elif drift == 'key':
        monkeypatch.setattr(binding, 'retrieve_sketch_ssh_key', lambda _: None)
    else:
        update.reviewed_variables['ssh_pub_key_path'] += '-foreign'
    try:
        with pytest.raises((ValueError, OSError)):
            if phase == 'plan': ingress.plan_keyed_ingress_update(update, **kwargs)
            else: ingress.apply_keyed_ingress_update(update, post_apply_proof=lambda: None, **kwargs)
        assert calls == before
        if drift == 'public': assert public.read_bytes() == b'foreign'
        if drift == 'symlink': assert public.is_symlink()
    finally:
        for path in (public, private):
            if path.exists() or path.is_symlink(): path.unlink()


@pytest.mark.parametrize('phase', ['plan', 'apply'])
def test_definite_command_exception_cleans_only_matching_material(tmp_path, monkeypatch, phase):
    update, kwargs, public, private, calls = _case(tmp_path, monkeypatch, 'digitalocean')
    if phase == 'apply': ingress.plan_keyed_ingress_update(update, **kwargs)
    def fail(*_): raise RuntimeError('definite command boundary exception')
    kwargs['command_runner'] = fail
    with pytest.raises(RuntimeError):
        if phase == 'plan': ingress.plan_keyed_ingress_update(update, **kwargs)
        else: ingress.apply_keyed_ingress_update(update, post_apply_proof=lambda: None, **kwargs)
    assert not public.exists() and not private.exists()


@pytest.mark.parametrize('phase', ['plan', 'apply'])
def test_material_change_during_command_is_fenced_before_next_command(tmp_path, monkeypatch, phase):
    update, kwargs, public, private, calls = _case(tmp_path, monkeypatch, 'digitalocean')
    if phase == 'apply': ingress.plan_keyed_ingress_update(update, **kwargs)
    original = kwargs['command_runner']
    before = len(calls)
    def mutate(*args):
        result = original(*args)
        public.write_bytes(b'foreign-during-command')
        return result
    kwargs['command_runner'] = mutate
    try:
        with pytest.raises(ValueError, match='staged private material differs'):
            if phase == 'plan': ingress.plan_keyed_ingress_update(update, **kwargs)
            else: ingress.apply_keyed_ingress_update(update, post_apply_proof=lambda: None, **kwargs)
        assert len(calls) == before + 1
        assert public.read_bytes() == b'foreign-during-command'
        assert private.is_file()  # Drift preserves the whole exact staged set for observation.
    finally:
        public.unlink(missing_ok=True)
        private.unlink(missing_ok=True)


def test_lost_authority_does_not_stage_material(tmp_path, monkeypatch):
    update, kwargs, public, private, calls = _case(tmp_path, monkeypatch, 'linode')
    def lost(): raise ValueError('engagement lease changed')
    kwargs['recheck_authority'] = lost
    with pytest.raises(ValueError, match='lease changed'):
        ingress.plan_keyed_ingress_update(update, **kwargs)
    assert not calls and not public.exists() and not private.exists()


@pytest.mark.parametrize('phase', ['plan', 'apply'])
def test_unreaped_command_keeps_material_for_observation(tmp_path, monkeypatch, phase):
    update, kwargs, public, private, calls = _case(tmp_path, monkeypatch, 'linode')
    if phase == 'apply': ingress.plan_keyed_ingress_update(update, **kwargs)
    from app.services.provider_keyed_gated_runner import UnreapedGatedCommandError
    def fail(*_): raise UnreapedGatedCommandError('command still running')
    kwargs['command_runner'] = fail
    try:
        with pytest.raises(UnreapedGatedCommandError):
            if phase == 'plan': ingress.plan_keyed_ingress_update(update, **kwargs)
            else: ingress.apply_keyed_ingress_update(update, post_apply_proof=lambda: None, **kwargs)
        assert public.is_file() and private.is_file()
    finally:
        public.unlink(missing_ok=True)
        private.unlink(missing_ok=True)
