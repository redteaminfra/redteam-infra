# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import copy
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile

import pytest

from app.services import loottool_capability as loot

ENGAGEMENT = 'eng-abc123'


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    source = tmp_path/'source'
    source.mkdir()
    def git(*args):
        return subprocess.run(['git', *args], cwd=source, capture_output=True, text=True, check=True).stdout.strip()
    git('init')
    git('config', 'user.name', 'Fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    (source/'pyproject.toml').write_text('[project]\nname="loot-fixture"\nversion="0.0.0"\n')
    git('add', '.')
    git('commit', '-m', 'Fixture source')
    monkeypatch.setattr(loot, 'SOURCE_REVISION', git('rev-parse', 'HEAD'))
    image = tmp_path/'reviewed-image.tar'
    image.write_bytes(b'reviewed-docker-save-fixture\n')
    monkeypatch.setattr(loot, 'IMAGE_ARCHIVE_SHA256', hashlib.sha256(image.read_bytes()).hexdigest())
    monkeypatch.setenv(loot.SOURCE_ROOT_ENV, str(source))
    monkeypatch.setenv(loot.IMAGE_ARCHIVE_ENV, str(image))
    return source, image, loot.controller_artifacts()


def prepare(tmp_path, artifacts):
    workspace = tmp_path/'workspace'
    inputs = loot.prepare_artifacts(workspace, artifacts[2], engagement_id=ENGAGEMENT)
    return workspace, inputs, {loot.ARTIFACTS_KEY: inputs}


def test_selection_only_explicit_homebase():
    assert loot.is_selected({'selectedOptionals':[{'id':'loottool-v2','hostClass':'homebase'}]})
    assert not loot.is_selected({'selectedOptionals':[{'id':'loottool-v2','hostClass':'proxy'}]})
    assert not loot.is_selected({'selectedOptionals':['loottool-v2']})
    assert not loot.is_selected({'selectedOptionals':[]})


def test_pinned_clean_git_archive_and_streamed_image_reference(artifacts):
    _, image, package = artifacts
    assert package['imageArchive'] == image
    assert isinstance(package['imageArchive'], Path)
    with tarfile.open(fileobj=io.BytesIO(package['source']), mode='r:gz') as archive:
        assert archive.getnames() == ['pyproject.toml']
        assert archive.pax_headers['comment'] == loot.SOURCE_REVISION


@pytest.mark.parametrize('variable', [loot.SOURCE_ROOT_ENV, loot.IMAGE_ARCHIVE_ENV])
def test_missing_controller_inputs_fail_closed(artifacts, monkeypatch, variable):
    monkeypatch.delenv(variable)
    with pytest.raises(loot.LootToolArtifactError, match=variable):
        loot.controller_artifacts()


def test_dirty_or_wrong_revision_source_is_not_archived(artifacts, monkeypatch):
    source, _, _ = artifacts
    (source/'untracked-credentials').write_text('never include')
    with pytest.raises(loot.LootToolArtifactError, match='clean'):
        loot.controller_artifacts()
    (source/'untracked-credentials').unlink()
    monkeypatch.setattr(loot, 'SOURCE_REVISION', '0'*40)
    with pytest.raises(loot.LootToolArtifactError, match='pinned'):
        loot.controller_artifacts()


def test_source_subdirectory_is_not_accepted_as_checkout(artifacts, monkeypatch):
    source, _, _ = artifacts
    (source/'subdir').mkdir()
    monkeypatch.setenv(loot.SOURCE_ROOT_ENV, str(source/'subdir'))
    with pytest.raises(loot.LootToolArtifactError, match='own Git checkout'):
        loot.controller_artifacts()


def test_wrong_image_digest_symlink_directory_and_size_are_refused(artifacts, tmp_path, monkeypatch):
    _, image, _ = artifacts
    image.write_bytes(b'not-reviewed')
    with pytest.raises(loot.LootToolArtifactError, match='reviewed pin'):
        loot.controller_artifacts()
    link = tmp_path/'linked.tar'; link.symlink_to(image)
    monkeypatch.setenv(loot.IMAGE_ARCHIVE_ENV, str(link))
    with pytest.raises(loot.LootToolArtifactError, match='unsafe'):
        loot.controller_artifacts()
    monkeypatch.setenv(loot.IMAGE_ARCHIVE_ENV, str(tmp_path))
    with pytest.raises(loot.LootToolArtifactError, match='regular file'):
        loot.controller_artifacts()
    monkeypatch.setenv(loot.IMAGE_ARCHIVE_ENV, str(image))
    monkeypatch.setattr(loot, 'IMAGE_LIMIT', 1)
    with pytest.raises(loot.LootToolArtifactError, match='bounded regular file'):
        loot.controller_artifacts()


def test_artifacts_are_private_idempotent_and_reusable_without_controller_env(artifacts, tmp_path, monkeypatch):
    workspace, inputs, metadata = prepare(tmp_path, artifacts)
    assert loot.prepare_artifacts(workspace, artifacts[2], engagement_id=ENGAGEMENT) == inputs
    monkeypatch.delenv(loot.SOURCE_ROOT_ENV)
    monkeypatch.delenv(loot.IMAGE_ARCHIVE_ENV)
    assert loot.execution_inputs(workspace, metadata, engagement_id=ENGAGEMENT) == inputs
    for key in ('source','imageArchive'):
        path = workspace/inputs[key]['relativePath']
        assert path.stat().st_mode & 0o777 == 0o600
    assert (workspace/inputs['source']['relativePath']).read_bytes() == artifacts[2]['source']
    assert (workspace/inputs['imageArchive']['relativePath']).read_bytes() == artifacts[1].read_bytes()


@pytest.mark.parametrize('engagement_id', [None, '', 'Other Engagement', '../escape', 'ENG-UPPER', 'a'*64])
def test_scope_requires_exact_trusted_compatible_id(artifacts, tmp_path, engagement_id):
    with pytest.raises(loot.LootToolArtifactError, match='trusted engagement ID'):
        loot.prepare_artifacts(tmp_path/'not-created', artifacts[2], engagement_id=engagement_id)
    assert not (tmp_path/'not-created').exists()


def test_scope_never_comes_from_workspace_directory(artifacts, tmp_path):
    unrelated = tmp_path/'different-engagement-name'
    inputs = loot.prepare_artifacts(unrelated, artifacts[2], engagement_id=ENGAGEMENT)
    assert inputs['configuration']['evidenceScope'] == ENGAGEMENT
    with pytest.raises(loot.LootToolArtifactError, match='scope'):
        loot.execution_inputs(unrelated, {loot.ARTIFACTS_KEY:inputs}, engagement_id='eng-other')


@pytest.mark.parametrize('kind', ['source','imageArchive'])
@pytest.mark.parametrize('fault', ['tamper','missing'])
def test_changed_or_missing_retained_artifacts_fail_closed(artifacts, tmp_path, kind, fault):
    workspace, inputs, metadata = prepare(tmp_path, artifacts)
    path = workspace/inputs[kind]['relativePath']
    if fault == 'missing': path.unlink()
    else: path.write_bytes(b'tampered')
    with pytest.raises(loot.LootToolArtifactError):
        loot.execution_inputs(workspace, metadata, engagement_id=ENGAGEMENT)
    destination = tmp_path/'not-executed'
    with pytest.raises(loot.LootToolArtifactError):
        loot.copy_artifacts(destination, workspace, inputs, engagement_id=ENGAGEMENT)
    assert not destination.exists()


@pytest.mark.parametrize('field,value', [('sourceRoot','/tmp/other'), ('evidenceScope','eng-other'), ('apiPort',9000), ('answerPort',9001)])
def test_saved_configuration_cannot_override_baseline(artifacts, tmp_path, field, value):
    workspace, inputs, _ = prepare(tmp_path, artifacts)
    changed = copy.deepcopy(inputs)
    changed['configuration'][field] = value
    with pytest.raises(loot.LootToolArtifactError, match='pinned installation contract'):
        loot.execution_inputs(workspace, {loot.ARTIFACTS_KEY:changed}, engagement_id=ENGAGEMENT)


@pytest.mark.parametrize('field', ['application','applicationConfig','elasticsearch','python'])
def test_images_are_fixed_and_independent_identities(artifacts, tmp_path, field):
    workspace, inputs, _ = prepare(tmp_path, artifacts)
    assert inputs['images']['application'] != inputs['images']['applicationConfig']
    changed = copy.deepcopy(inputs)
    changed['images'][field] = 'mutable:latest'
    with pytest.raises(loot.LootToolArtifactError, match='pinned installation contract'):
        loot.execution_inputs(workspace, {loot.ARTIFACTS_KEY:changed}, engagement_id=ENGAGEMENT)


def test_path_escape_and_symlink_artifact_parent_fail_closed(artifacts, tmp_path):
    workspace, inputs, _ = prepare(tmp_path, artifacts)
    changed = copy.deepcopy(inputs); changed['imageArchive']['relativePath']='../escape.tar'
    with pytest.raises(loot.LootToolArtifactError):
        loot.execution_inputs(workspace, {loot.ARTIFACTS_KEY:changed}, engagement_id=ENGAGEMENT)
    other = tmp_path/'elsewhere'; other.mkdir()
    destination = tmp_path/'destination'; (destination/'barragan').mkdir(parents=True)
    (destination/'barragan/artifacts').symlink_to(other,target_is_directory=True)
    with pytest.raises(loot.LootToolArtifactError, match='symlinks'):
        loot.copy_artifacts(destination, workspace, inputs, engagement_id=ENGAGEMENT)
    assert list(other.iterdir()) == []


def test_copy_preserves_both_artifacts_and_requires_same_engagement(artifacts, tmp_path):
    workspace, inputs, _ = prepare(tmp_path, artifacts)
    destination = tmp_path/'execution'
    loot.copy_artifacts(destination, workspace, inputs, engagement_id=ENGAGEMENT)
    assert loot.execution_inputs(destination, {loot.ARTIFACTS_KEY:inputs}, engagement_id=ENGAGEMENT) == inputs
    with pytest.raises(loot.LootToolArtifactError):
        loot.copy_artifacts(tmp_path/'other-execution', workspace, inputs, engagement_id='eng-other')
    assert not (tmp_path/'other-execution').exists()


def test_large_image_is_streamed_without_path_read_bytes(artifacts, tmp_path, monkeypatch):
    source, image, _ = artifacts
    chunk = b'x'*32768
    with image.open('wb') as output:
        for _ in range(5): output.write(chunk)
    monkeypatch.setattr(loot, 'IMAGE_ARCHIVE_SHA256', hashlib.sha256(chunk*5).hexdigest())
    monkeypatch.setattr(loot, 'CHUNK_SIZE', 1024)
    original = Path.read_bytes
    def no_image_read(path):
        if path.suffix == '.tar': pytest.fail('Docker archive must be streamed')
        return original(path)
    monkeypatch.setattr(Path,'read_bytes',no_image_read)
    package = loot.controller_artifacts()
    workspace = tmp_path/'streamed'
    inputs = loot.prepare_artifacts(workspace, package, engagement_id=ENGAGEMENT)
    loot.copy_artifacts(tmp_path/'streamed-runtime', workspace, inputs, engagement_id=ENGAGEMENT)


def test_atomic_publication_failure_leaves_no_partial_final_and_retry_works(artifacts, tmp_path, monkeypatch):
    relative = loot._inputs(hashlib.sha256(artifacts[2]['source']).hexdigest(),ENGAGEMENT)['source']['relativePath']
    destination = tmp_path/'atomic'
    original = loot.os.fsync
    def interrupted(fd): raise OSError('fixture fsync failure')
    monkeypatch.setattr(loot.os,'fsync',interrupted)
    with pytest.raises(loot.LootToolArtifactError):
        loot.prepare_artifacts(destination,artifacts[2],engagement_id=ENGAGEMENT)
    assert not (destination/relative).exists()
    assert list((destination/'barragan/artifacts').iterdir()) == []
    monkeypatch.setattr(loot.os,'fsync',original)
    assert loot.prepare_artifacts(destination,artifacts[2],engagement_id=ENGAGEMENT)['source']['relativePath'] == relative


def test_publication_race_verifies_existing_winner(artifacts, tmp_path, monkeypatch):
    original = loot.os.link
    def race(source,target):
        Path(target).write_bytes(Path(source).read_bytes())
        raise FileExistsError('another writer completed')
    monkeypatch.setattr(loot.os,'link',race)
    inputs = loot.prepare_artifacts(tmp_path/'race',artifacts[2],engagement_id=ENGAGEMENT)
    assert inputs['configuration']['evidenceScope']==ENGAGEMENT
    monkeypatch.setattr(loot.os,'link',original)


def test_role_variables_are_exact_nonsecret_baseline_allowlist(artifacts,tmp_path):
    _,inputs,_ = prepare(tmp_path,artifacts)
    variables = loot.role_variables(inputs)
    assert len(variables)==13
    assert all(key.startswith('loottool_v2_') for key in variables)
    assert variables['loottool_v2_evidence_scope']==ENGAGEMENT
    assert variables['loottool_v2_source_root']=='/engagement/loot'
    assert variables['loottool_v2_api_port']==8080 and variables['loottool_v2_answer_port']==8082
    assert variables['loottool_v2_app_image']==loot.APP_IMAGE
    assert variables['loottool_v2_app_config_digest']==loot.APP_CONFIG_DIGEST
    assert variables['loottool_v2_app_archive'].startswith('{{ playbook_dir }}/../barragan/artifacts/')
    assert not any(word in key.lower() for key in variables for word in ('token','password','inference','ingest','atc','worker'))


def test_manifest_exposes_only_optional_homebase_role(tmp_path):
    from app.services.capability_catalog import discover_capability_catalog
    from app.services.redteam_infra_template import RedteamInfraTemplateSource
    root = tmp_path/'roles'
    for role in ('go_simple_upload_server','inference_proxy','c2_observer','loottool_v2','atc'):
        (root/'ansible/roles'/role).mkdir(parents=True)
    catalog = discover_capability_catalog(source=RedteamInfraTemplateSource(root,'test')).to_dict()
    entry = next(item for item in catalog['capabilities'] if item['id']==loot.CAPABILITY_ID)
    assert catalog['status']=='passed'
    assert entry['classification']=='optional'
    assert entry['placement']['allowedHostClasses']==['homebase']
    assert entry['implementation']['role']=='loottool_v2'
    assert entry['lifecycle']['remove']=='manual'
    assert 'integration' not in entry
    assert 'not yet qualified' in entry['description']
