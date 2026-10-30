# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import subprocess
import tarfile

import pytest

from app.services import c2_observer_capability as c2


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    def git(*args):
        return subprocess.run(['git', *args], cwd=source, check=True, capture_output=True, text=True).stdout.strip()
    git('init')
    git('config', 'user.name', 'Test')
    git('config', 'user.email', 'test@example.invalid')
    (source / 'pyproject.toml').write_text('[project]\nname="test-c2"\nversion="0.0.0"\n')
    git('add', 'pyproject.toml')
    git('commit', '-m', 'Fixture source')
    revision = git('rev-parse', 'HEAD')
    lock = tmp_path / 'reviewed.lock'
    lock.write_bytes(b'example==1.0 --hash=sha256:' + b'a' * 64 + b'\n')
    monkeypatch.setattr(c2, 'SOURCE_REVISION', revision)
    monkeypatch.setattr(c2, 'DEPENDENCY_SHA256', hashlib.sha256(lock.read_bytes()).hexdigest())
    monkeypatch.setenv(c2.SOURCE_ROOT_ENV, str(source))
    monkeypatch.setenv(c2.DEPENDENCY_LOCK_ENV, str(lock))
    return source, lock, c2.controller_artifacts()


def prepared(tmp_path, artifacts):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    identities = c2.prepare_artifacts(workspace, artifacts[2])
    return workspace, identities, {c2.ARTIFACTS_KEY: identities}


def test_selection_only_explicit_homebase():
    assert c2.is_selected({'selectedOptionals': [{'id': c2.CAPABILITY_ID, 'hostClass': 'homebase'}]})
    assert not c2.is_selected({'selectedOptionals': [{'id': c2.CAPABILITY_ID, 'hostClass': 'proxy'}]})
    assert not c2.is_selected({'selectedOptionals': []})
    assert not c2.is_selected({'selectedOptionals': ['c2-observer']})


def test_controller_sources_committed_pinned_clean(artifacts, monkeypatch):
    source, _, package = artifacts
    with tarfile.open(fileobj=io.BytesIO(package['source']), mode='r:gz') as archive:
        assert archive.getnames() == ['pyproject.toml']
        assert archive.pax_headers['comment'] == c2.SOURCE_REVISION
    (source / 'credentials-untracked').write_text('must not enter artifact')
    with pytest.raises(c2.C2ObserverArtifactError, match='clean'):
        c2.controller_artifacts()
    (source / 'credentials-untracked').unlink()
    monkeypatch.setattr(c2, 'SOURCE_REVISION', '0' * 40)
    with pytest.raises(c2.C2ObserverArtifactError, match='pinned'):
        c2.controller_artifacts()


@pytest.mark.parametrize('variable', [c2.SOURCE_ROOT_ENV, c2.DEPENDENCY_LOCK_ENV])
def test_missing_controller_inputs_fail_closed(artifacts, monkeypatch, variable):
    monkeypatch.delenv(variable)
    with pytest.raises(c2.C2ObserverArtifactError, match=variable):
        c2.controller_artifacts()


def test_rejects_checkout_subdirectory(artifacts, monkeypatch):
    source, _, _ = artifacts
    (source / 'subdir').mkdir()
    monkeypatch.setenv(c2.SOURCE_ROOT_ENV, str(source / 'subdir'))
    with pytest.raises(c2.C2ObserverArtifactError, match='own Git checkout'):
        c2.controller_artifacts()


def test_dependency_lock_pin_regular_file_size(artifacts, tmp_path, monkeypatch):
    _, lock, _ = artifacts
    lock.write_bytes(b'unreviewed')
    with pytest.raises(c2.C2ObserverArtifactError, match='reviewed pin'):
        c2.controller_artifacts()
    link = tmp_path / 'linked.lock'
    link.symlink_to(lock)
    monkeypatch.setenv(c2.DEPENDENCY_LOCK_ENV, str(link))
    with pytest.raises(c2.C2ObserverArtifactError, match='unsafe'):
        c2.controller_artifacts()
    monkeypatch.setenv(c2.DEPENDENCY_LOCK_ENV, str(tmp_path))
    with pytest.raises(c2.C2ObserverArtifactError, match='regular file'):
        c2.controller_artifacts()
    monkeypatch.setenv(c2.DEPENDENCY_LOCK_ENV, str(lock))
    lock.write_bytes(b'x' * (c2.LOCK_LIMIT + 1))
    with pytest.raises(c2.C2ObserverArtifactError, match='bounded regular file'):
        c2.controller_artifacts()


def test_prepared_artifacts_private_idempotent_offline(artifacts, tmp_path, monkeypatch):
    workspace, identities, metadata = prepared(tmp_path, artifacts)
    assert c2.prepare_artifacts(workspace, artifacts[2]) == identities
    monkeypatch.delenv(c2.SOURCE_ROOT_ENV)
    monkeypatch.delenv(c2.DEPENDENCY_LOCK_ENV)
    assert c2.execution_inputs(workspace, metadata) == identities
    for key in ('source', 'dependencyLock'):
        path = workspace / identities[key]['relativePath']
        assert path.read_bytes() == artifacts[2][key]
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('kind', ['source', 'dependencyLock'])
def test_artifact_tampering_rejected(artifacts, tmp_path, kind):
    workspace, identities, metadata = prepared(tmp_path, artifacts)
    (workspace / identities[kind]['relativePath']).write_bytes(b'changed')
    with pytest.raises(c2.C2ObserverArtifactError, match='changed'):
        c2.execution_inputs(workspace, metadata)
    with pytest.raises(c2.C2ObserverArtifactError, match='changed'):
        c2.prepare_artifacts(workspace, artifacts[2])


@pytest.mark.parametrize('kind,key,value', [
    ('source', 'revision', '0' * 40), ('source', 'sha256', 'bad'),
    ('source', 'relativePath', '../outside'), ('source', 'relativePath', '/tmp/outside'),
    ('dependencyLock', 'sha256', '0' * 64), ('dependencyLock', 'relativePath', 'barragan/other.lock'),
])
def test_metadata_cannot_rebind_paths_or_pins(artifacts, tmp_path, kind, key, value):
    workspace, identities, _ = prepared(tmp_path, artifacts)
    changed = {name: dict(identity) for name, identity in identities.items()}
    changed[kind][key] = value
    with pytest.raises(c2.C2ObserverArtifactError):
        c2.execution_inputs(workspace, {c2.ARTIFACTS_KEY: changed})


def test_metadata_extra_vars_refused(artifacts, tmp_path):
    workspace, identities, _ = prepared(tmp_path, artifacts)
    with pytest.raises(c2.C2ObserverArtifactError):
        c2.execution_inputs(workspace, {c2.ARTIFACTS_KEY: {**identities, 'vars': {'command': 'publish'}}})
    variables = c2.role_variables(identities)
    assert set(variables) == {'c2_observer_source_archive', 'c2_observer_source_sha256',
                              'c2_observer_source_revision', 'c2_observer_dependency_lock',
                              'c2_observer_dependency_sha256'}
    for key in ('c2_observer_source_archive', 'c2_observer_dependency_lock'):
        assert variables[key].startswith('{{ playbook_dir }}/../barragan/artifacts/')


@pytest.mark.parametrize('ancestor', ['barragan', 'barragan/artifacts'])
def test_symlinked_artifact_ancestors_refused(artifacts, tmp_path, ancestor):
    workspace = tmp_path / 'workspace'
    target = tmp_path / 'outside'
    workspace.mkdir()
    target.mkdir()
    link = workspace / ancestor
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(c2.C2ObserverArtifactError, match='symlinks'):
        c2.prepare_artifacts(workspace, artifacts[2])
    assert list(target.iterdir()) == []


def test_execution_copy_rechecks_both_bytes_and_destination(artifacts, tmp_path):
    workspace, identities, metadata = prepared(tmp_path, artifacts)
    execution = tmp_path / 'execution'
    c2.copy_artifacts(execution, workspace, identities)
    assert c2.execution_inputs(execution, metadata) == identities
    for kind in ('source', 'dependencyLock'):
        assert (execution / identities[kind]['relativePath']).read_bytes() == artifacts[2][kind]
    (execution / identities['dependencyLock']['relativePath']).write_bytes(b'changed')
    with pytest.raises(c2.C2ObserverArtifactError, match='changed'):
        c2.copy_artifacts(execution, workspace, identities)


def test_copy_detects_race_after_initial_verification(artifacts, tmp_path, monkeypatch):
    workspace, identities, _ = prepared(tmp_path, artifacts)
    original = c2._read_regular
    calls = 0
    def changing_read(path, limit):
        nonlocal calls
        calls += 1
        if calls == 3:
            return b'changed after execution_inputs'
        return original(path, limit)
    monkeypatch.setattr(c2, '_read_regular', changing_read)
    with pytest.raises(c2.C2ObserverArtifactError, match='changed while'):
        c2.copy_artifacts(tmp_path / 'execution', workspace, identities)


def test_missing_or_malformed_saved_inputs_fail_closed(tmp_path):
    for value in [None, [], {}, {'source': []}, {'source': {}, 'dependencyLock': None}]:
        with pytest.raises(c2.C2ObserverArtifactError):
            c2.execution_inputs(tmp_path, {c2.ARTIFACTS_KEY: value})


def test_render_and_copy_both_artifacts_in_role_apply_plan(artifacts, tmp_path):
    import yaml
    from app.services.capability_execution import (
        CapabilityRoleApplyPlan, copy_core_capability_roles, render_core_capability_apply_playbook,
    )
    from app.services.redteam_infra_template import RedteamInfraTemplateSource
    workspace, identities, _ = prepared(tmp_path, artifacts)
    role = workspace / 'ansible/roles/c2_observer/tasks'
    role.mkdir(parents=True)
    (role / 'main.yml').write_text('---\n[]\n')
    plan = CapabilityRoleApplyPlan(
        source=RedteamInfraTemplateSource(workspace, 'engagement-workspace'),
        roles_by_host_class={'homebase': [{'id': c2.CAPABILITY_ID, 'role': 'c2_observer'}]},
        selected_count=1, executable_count=1, skipped=[], warnings=[], errors=[],
        c2_observer_inputs=identities,
    )
    plays = yaml.safe_load(render_core_capability_apply_playbook(plan))
    task = next(task for task in plays[1]['tasks'] if task.get('ansible.builtin.include_role'))
    assert task['vars'] == c2.role_variables(identities)
    assert plan.to_summary()['c2Observer'] == identities
    destination = tmp_path / 'execution'
    copy_core_capability_roles(destination, plan)
    assert c2.execution_inputs(destination, {c2.ARTIFACTS_KEY: identities}) == identities
    assert (destination / 'ansible/roles/c2_observer/tasks/main.yml').exists()
    (workspace / identities['dependencyLock']['relativePath']).write_bytes(b'changed after planning')
    with pytest.raises(c2.C2ObserverArtifactError):
        copy_core_capability_roles(tmp_path / 'another-execution', plan)


def test_reconciliation_rejects_lock_drift_before_writes(artifacts, tmp_path):
    import yaml
    from app.services.capability_execution import CapabilityRoleApplyPlan
    from app.services.capability_reconciliation import (
        CapabilityReconciliationValidationError, _write_reconciliation_workspace,
    )
    from app.services.redteam_infra_template import RedteamInfraTemplateSource
    workspace, identities, _ = prepared(tmp_path, artifacts)
    plan = CapabilityRoleApplyPlan(
        source=RedteamInfraTemplateSource(workspace, 'engagement-workspace'),
        roles_by_host_class={'homebase': [{'id': c2.CAPABILITY_ID, 'role': 'c2_observer'}]},
        selected_count=1, executable_count=1, skipped=[], warnings=[], errors=[],
        c2_observer_inputs=identities,
    )
    destination = tmp_path / 'execution'
    with pytest.raises(CapabilityReconciliationValidationError):
        _write_reconciliation_workspace(destination, plan, (), 'deployment-test',
            capability_lock=yaml.safe_dump({'c2Observer': {**identities, 'dependencyLock': {'sha256': '0' * 64}}}))
    assert not destination.exists()


def test_interrupted_partial_write_leaves_no_final_and_save_retry_succeeds(artifacts, tmp_path, monkeypatch):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    real_fdopen = c2.os.fdopen
    class InterruptedWrite:
        def __init__(self, descriptor, mode):
            self.stream = real_fdopen(descriptor, mode)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def write(self, content):
            self.stream.write(content[:4])
            self.stream.flush()
            raise OSError('interrupted after partial write')
    with monkeypatch.context() as scoped:
        scoped.setattr(c2.os, 'fdopen', InterruptedWrite)
        with pytest.raises(c2.C2ObserverArtifactError, match='prepared safely'):
            c2.prepare_artifacts(workspace, artifacts[2])
    assert list((workspace / 'barragan/artifacts').iterdir()) == []
    identities = c2.prepare_artifacts(workspace, artifacts[2])
    assert c2.execution_inputs(workspace, {c2.ARTIFACTS_KEY: identities}) == identities


@pytest.mark.parametrize('same_content', [True, False])
def test_atomic_publication_verifies_concurrent_final_without_clobber(artifacts, tmp_path, monkeypatch, same_content):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    real_link = c2.os.link
    raced = False
    def concurrent_link(source, destination, **kwargs):
        nonlocal raced
        if not raced:
            raced = True
            Path(destination).write_bytes(Path(source).read_bytes() if same_content else b'different concurrent final')
        return real_link(source, destination, **kwargs)
    monkeypatch.setattr(c2.os, 'link', concurrent_link)
    if same_content:
        identities = c2.prepare_artifacts(workspace, artifacts[2])
        assert c2.execution_inputs(workspace, {c2.ARTIFACTS_KEY: identities}) == identities
    else:
        with pytest.raises(c2.C2ObserverArtifactError, match='changed'):
            c2.prepare_artifacts(workspace, artifacts[2])
        finals = list((workspace / 'barragan/artifacts').iterdir())
        assert len(finals) == 1
        assert finals[0].read_bytes() == b'different concurrent final'
    assert not list((workspace / 'barragan/artifacts').glob('*.tmp'))
