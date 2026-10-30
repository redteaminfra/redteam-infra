# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from app.services import atc_capability as atc

CONFIG = {'operatorId': 'operator/alice', 'operatorName': 'Alice Example', 'port': 8790}
CONTEXT = {'id': 'eng-opaque123', 'codename': 'Saffron Harbor'}
POSTGRES = 'docker.io/library/postgres:16.13@sha256:' + 'a' * 64


@pytest.fixture
def release(tmp_path, monkeypatch):
    # A test-only tracked verifier makes delegation observable. Native bundle
    # format validation belongs to RTI's verifier suite; no real release exists.
    root = tmp_path / 'rti'
    helper = root / 'ansible/roles/atc/files/verify_release.py'
    helper.parent.mkdir(parents=True)
    helper.write_text('''import hashlib,json,sys
from pathlib import Path
path,digest,revision,version,postgres=sys.argv[1:]
if Path(path).read_bytes()!=b"synthetic-native-test-bundle" or hashlib.sha256(Path(path).read_bytes()).hexdigest()!=digest:
    sys.exit(2)
print(json.dumps({"sha256":digest,"sourceRevision":revision,"version":version,"postgresImage":postgres,"migrationLevel":"b"*64,"members":42}))
''')
    def git(*args):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
    git('init')
    git('config', 'user.name', 'Test')
    git('config', 'user.email', 'test@example.invalid')
    git('add', '.')
    git('commit', '-m', 'Synthetic verifier fixture')
    monkeypatch.setattr(atc, 'resolve_redteam_infra_template_source', lambda: SimpleNamespace(root=root))
    archive = tmp_path / 'native-release.tar.gz'
    archive.write_bytes(b'synthetic-native-test-bundle')
    monkeypatch.setenv(atc.ARCHIVE_ENV, str(archive))
    monkeypatch.setenv(atc.SHA256_ENV, hashlib.sha256(archive.read_bytes()).hexdigest())
    monkeypatch.setenv(atc.POSTGRES_ENV, POSTGRES)
    return archive, root


def prepared(tmp_path, release):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    identity = atc.prepare_release(workspace, atc.controller_release())
    metadata = {atc.CONFIGURATION_KEY: CONFIG, atc.CONTEXT_KEY: CONTEXT, atc.RELEASE_KEY: identity}
    return workspace, identity, metadata


def test_selection_and_configuration_defaults():
    assert atc.normalize_configuration(None) == {'operatorId': '', 'operatorName': '', 'port': 8790}
    assert atc.normalize_configuration(CONFIG, required=True) == CONFIG
    with pytest.raises(atc.ATCCapabilityError, match='before selecting'):
        atc.normalize_configuration(None, required=True)
    assert atc.is_selected({'selectedOptionals': [{'id': 'atc', 'hostClass': 'homebase'}]})
    assert not atc.is_selected({'selectedOptionals': [{'id': 'atc', 'hostClass': 'proxy'}]})


@pytest.mark.parametrize('value', [[], {'operatorUser': 'root'}, {'engagementId': 'other'},
    {**CONFIG, 'port': True}, {**CONFIG, 'port': '8790'}, {**CONFIG, 'port': 1023},
    {**CONFIG, 'port': 65536}, {**CONFIG, 'port': 15432}, {**CONFIG, 'port': 17474},
    {**CONFIG, 'port': 17687}, {**CONFIG, 'operatorId': 'a; command'},
    {**CONFIG, 'operatorName': 'Alice\nEVIL=1'}, {**CONFIG, 'operatorName': ' Alice'},
    {**CONFIG, 'operatorName': 'x'*129}, {**CONFIG, 'operatorName': 'Alice\x00'},
    {**CONFIG, 'operatorName': 'Alice\tSmith'}, {**CONFIG, 'root': '/tmp/evil'}])
def test_configuration_rejects_untyped_or_arbitrary_fields(value):
    with pytest.raises(atc.ATCCapabilityError):
        atc.normalize_configuration(value, required=True)


def test_context_comes_from_trusted_engagement_object_only():
    assert atc.engagement_context(SimpleNamespace(id=CONTEXT['id'], name=CONTEXT['codename'])) == CONTEXT
    for invalid in [CONTEXT, {'id': 'other', 'name': 'other'}, None,
                    SimpleNamespace(id='bad\nidentity', name='Saffron'), SimpleNamespace(id='valid', name='')]:
        with pytest.raises(atc.ATCCapabilityError):
            atc.engagement_context(invalid)


@pytest.mark.parametrize('variable', [atc.ARCHIVE_ENV, atc.SHA256_ENV, atc.POSTGRES_ENV])
def test_missing_administrator_artifact_blocks_preparation(release, monkeypatch, variable):
    monkeypatch.delenv(variable)
    with pytest.raises(atc.ATCCapabilityError, match='Controller administrator must prepare'):
        atc.controller_release()


def test_artifact_checksum_regular_file_and_verifier_required(release, tmp_path, monkeypatch):
    archive, root = release
    archive.write_bytes(b'changed')
    with pytest.raises(atc.ATCCapabilityError, match='reviewed artifact'):
        atc.controller_release()
    archive.write_bytes(b'synthetic-native-test-bundle')
    linked = tmp_path / 'linked.tar.gz'
    linked.symlink_to(archive)
    monkeypatch.setenv(atc.ARCHIVE_ENV, str(linked))
    with pytest.raises(atc.ATCCapabilityError, match='unsafe'):
        atc.controller_release()
    monkeypatch.setenv(atc.ARCHIVE_ENV, str(archive))
    (root / 'dirty').write_text('unreviewed')
    with pytest.raises(atc.ATCCapabilityError, match='clean configured RTI'):
        atc.controller_release()


def test_app_source_archive_is_not_assumed_to_be_native_release(release, monkeypatch):
    archive, _ = release
    archive.write_bytes(b'not-a-native-install-bundle')
    monkeypatch.setenv(atc.SHA256_ENV, hashlib.sha256(archive.read_bytes()).hexdigest())
    with pytest.raises(atc.ATCCapabilityError, match='native bundle failed the RTI release contract'):
        atc.controller_release()


def test_release_private_idempotent_and_public_state_has_no_controller_path(release, tmp_path, monkeypatch):
    workspace, identity, metadata = prepared(tmp_path, release)
    assert atc.prepare_release(workspace, atc.controller_release()) == identity
    for variable in (atc.ARCHIVE_ENV, atc.SHA256_ENV, atc.POSTGRES_ENV):
        monkeypatch.delenv(variable)
    inputs = atc.execution_inputs(workspace, metadata)
    assert inputs['configuration'] == CONFIG
    assert inputs['engagement'] == CONTEXT
    assert atc.public_state(metadata) == {'configuration': CONFIG}
    assert (workspace / identity['relativePath']).stat().st_mode & 0o777 == 0o600
    assert 'path' not in identity
    variables = atc.role_variables(inputs)
    assert variables['atc_operator_os_user'] == 'user'
    assert variables['atc_install_root'] == '/opt/atc'
    assert variables['atc_engagement_id'] == CONTEXT['id']
    assert variables['atc_engagement_codename'] == CONTEXT['codename']
    assert variables['atc_postgres_image'] == POSTGRES
    assert variables['atc_release_archive'].startswith('{{ playbook_dir }}/../barragan/artifacts/')
    assert all('inference' not in name and 'graph' not in name for name in variables)


@pytest.mark.parametrize('key,value', [('sourceRevision', '0'*40), ('version', '1.0.0'),
    ('sourceRevision', 'ce0ec10066c34b5a9772729dcbd01c1d85ac0b3d'), ('version', '0.6.0'),
    ('postgresImage', 'postgres:latest'), ('migrationLevel', 'bad'), ('relativePath', '../outside'),
    ('relativePath', '/tmp/outside'), ('sha256', 'bad')])
def test_release_metadata_cannot_rebind_identity_or_path(release, tmp_path, key, value):
    workspace, identity, metadata = prepared(tmp_path, release)
    metadata[atc.RELEASE_KEY] = {**identity, key: value}
    with pytest.raises(atc.ATCCapabilityError):
        atc.execution_inputs(workspace, metadata)


def test_exact_bytes_verified_again_before_execution_copy(release, tmp_path):
    workspace, identity, metadata = prepared(tmp_path, release)
    destination = tmp_path / 'execution'
    inputs = atc.execution_inputs(workspace, metadata)
    atc.copy_artifacts(destination, workspace, inputs)
    assert atc.execution_inputs(destination, metadata) == inputs
    (workspace / identity['relativePath']).write_bytes(b'tampered after planning')
    with pytest.raises(atc.ATCCapabilityError, match='changed'):
        atc.copy_artifacts(tmp_path / 'another-execution', workspace, inputs)


def test_symlink_parent_is_refused_before_writing(release, tmp_path):
    workspace = tmp_path / 'workspace'
    outside = tmp_path / 'outside'
    workspace.mkdir()
    outside.mkdir()
    (workspace / 'barragan').symlink_to(outside, target_is_directory=True)
    with pytest.raises(atc.ATCCapabilityError, match='symlinks'):
        atc.prepare_release(workspace, atc.controller_release())
    assert list(outside.iterdir()) == []


def test_interrupted_stream_copy_retries_without_partial_final(release, tmp_path, monkeypatch):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    reviewed = atc.controller_release()
    original = atc._hash_stream
    def interrupted(stream, output=None):
        if output is not None:
            output.write(b'partial')
            raise OSError('simulated interrupted copy')
        return original(stream)
    with monkeypatch.context() as scoped:
        scoped.setattr(atc, '_hash_stream', interrupted)
        with pytest.raises(atc.ATCCapabilityError, match='prepared safely'):
            atc.prepare_release(workspace, reviewed)
    assert list((workspace / 'barragan/artifacts').iterdir()) == []
    assert atc.prepare_release(workspace, reviewed)['sha256'] == reviewed['identity']['sha256']
