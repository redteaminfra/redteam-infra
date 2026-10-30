# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pinned LootTool search baseline artifacts; no ingestion or optional workers.

The Docker-save archive is streamed throughout preparation and execution. Only
committed Git source and the exact reviewed image bytes reach the workspace.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any, BinaryIO

CAPABILITY_ID = 'loottool-v2'
SOURCE_REVISION = '59a4c4682393e1a542dd61493284b2b2a5cdd79f'
IMAGE_ARCHIVE_SHA256 = 'b35a12296dab657fba01ff5c327968e5b59fb10e8f942f992f3901aaf6f6b4fb'
APP_IMAGE = 'sha256:0e0c84223d3732fd0814e968a5152b08cbbab4f78fc46fb42205b1526c684541'
APP_CONFIG_DIGEST = 'sha256:79e67ef01c47b07a0123c2126a144b9bb4f2865f048d64d7e9e244987571d16a'
PYTHON_IMAGE = 'python@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d'
ELASTICSEARCH_IMAGE = 'docker.elastic.co/elasticsearch/elasticsearch@sha256:f456578fc2a620a8a4f4c21d070fff1f6070345adb2be5e5626b65be72aea350'
SOURCE_ROOT_ENV = 'BARRAGAN_LOOTTOOL_SOURCE_ROOT'
IMAGE_ARCHIVE_ENV = 'BARRAGAN_LOOTTOOL_IMAGE_ARCHIVE'
ARTIFACTS_KEY = 'loottoolArtifacts'
SOURCE_LIMIT = 64 * 1024 * 1024
IMAGE_LIMIT = 4 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


class LootToolArtifactError(ValueError):
    pass


def is_selected(overrides: dict[str, Any]) -> bool:
    return any(row.get('id') == CAPABILITY_ID and row.get('hostClass') == 'homebase'
               for row in overrides.get('selectedOptionals', []) if isinstance(row, dict))


def _scope(engagement_id: str) -> str:
    # The caller supplies the authoritative engagement ID; no directory-name,
    # hostname, slug or acquired-artifact provenance inference belongs here.
    if not isinstance(engagement_id, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', engagement_id):
        raise LootToolArtifactError('LootTool requires an exact trusted engagement ID compatible with its evidence scope')
    return engagement_id


def _git(root: Path, *args: str, binary: bool = False) -> Any:
    try:
        return subprocess.run(['git', '--no-optional-locks', *args], cwd=root,
                              capture_output=True, text=not binary, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise LootToolArtifactError('LootTool controller source could not be verified or archived') from exc


def _open_regular(path: Path, limit: int) -> BinaryIO:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise LootToolArtifactError('LootTool artifact must be a bounded regular file')
        stream = os.fdopen(descriptor, 'rb')
        descriptor = None
        return stream
    except OSError as exc:
        raise LootToolArtifactError('LootTool artifact is unavailable or unsafe') from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _hash_stream(stream: BinaryIO, limit: int, output: BinaryIO | None = None) -> str:
    digest, size = hashlib.sha256(), 0
    while chunk := stream.read(CHUNK_SIZE):
        size += len(chunk)
        if size > limit:
            raise LootToolArtifactError('LootTool artifact exceeds its size bound')
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    return digest.hexdigest()


def _verify_file(path: Path, digest: str, limit: int) -> None:
    with _open_regular(path, limit) as source:
        if _hash_stream(source, limit) != digest:
            raise LootToolArtifactError('LootTool artifact bytes do not match the reviewed pin')


def controller_artifacts() -> dict[str, Any]:
    configured = os.environ.get(SOURCE_ROOT_ENV, '').strip()
    if not configured:
        raise LootToolArtifactError(f'Controller administrator must configure {SOURCE_ROOT_ENV}')
    root = Path(configured).resolve()
    if not root.is_dir() or Path(_git(root, 'rev-parse', '--show-toplevel').strip()).resolve() != root:
        raise LootToolArtifactError('LootTool source must be its own Git checkout')
    def verify() -> None:
        if _git(root, 'rev-parse', 'HEAD').strip() != SOURCE_REVISION:
            raise LootToolArtifactError(f'LootTool source must be pinned at {SOURCE_REVISION}')
        if _git(root, 'status', '--porcelain', '--untracked-files=all').strip():
            raise LootToolArtifactError('LootTool source checkout must be clean')
    verify()
    archive = _git(root, 'archive', '--format=tar.gz', SOURCE_REVISION, binary=True)
    verify()
    if len(archive) > SOURCE_LIMIT:
        raise LootToolArtifactError('LootTool source archive exceeds the allowed size')
    configured_image = os.environ.get(IMAGE_ARCHIVE_ENV, '').strip()
    if not configured_image:
        raise LootToolArtifactError(f'Controller administrator must configure {IMAGE_ARCHIVE_ENV}')
    image = Path(configured_image)
    if not image.is_absolute():
        raise LootToolArtifactError('LootTool image archive requires an absolute controller path')
    _verify_file(image, IMAGE_ARCHIVE_SHA256, IMAGE_LIMIT)
    return {'source': archive, 'imageArchive': image}


def _safe_artifact(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not re.fullmatch(
        r'barragan/artifacts/loottool-v2-(?:[0-9a-f]{40}-[0-9a-f]{64}\.tar\.gz|image-[0-9a-f]{64}\.tar)', relative
    ):
        raise LootToolArtifactError('LootTool artifact path is invalid')
    root = root.resolve()
    target = root / relative
    for path in [target, *target.parents]:
        if path == root:
            break
        if path.is_symlink():
            raise LootToolArtifactError('LootTool artifacts must not use symlinks')
    if root not in target.resolve().parents:
        raise LootToolArtifactError('LootTool artifact escapes the workspace')
    return target


def _publish(root: Path, relative: str, stream: BinaryIO, digest: str, limit: int) -> None:
    """Publish only complete verified bytes; a failed attempt leaves no final."""
    target = _safe_artifact(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        _verify_file(target, digest, limit)
        return
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix='.loottool-artifact-', dir=target.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, 'wb') as output:
            if _hash_stream(stream, limit, output) != digest:
                raise LootToolArtifactError('LootTool artifact changed while preparing execution')
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError:
            _verify_file(target, digest, limit)
    except OSError as exc:
        raise LootToolArtifactError('LootTool artifact could not be prepared safely') from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _inputs(source_digest: str, engagement_id: str) -> dict[str, Any]:
    if not isinstance(source_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', source_digest):
        raise LootToolArtifactError('LootTool source identity is invalid')
    return {
        'source': {'revision': SOURCE_REVISION, 'sha256': source_digest,
                   'relativePath': f'barragan/artifacts/loottool-v2-{SOURCE_REVISION}-{source_digest}.tar.gz'},
        'imageArchive': {'sha256': IMAGE_ARCHIVE_SHA256,
                         'relativePath': f'barragan/artifacts/loottool-v2-image-{IMAGE_ARCHIVE_SHA256}.tar'},
        'images': {'application': APP_IMAGE, 'applicationConfig': APP_CONFIG_DIGEST,
                   'elasticsearch': ELASTICSEARCH_IMAGE, 'python': PYTHON_IMAGE},
        'configuration': {'evidenceScope': _scope(engagement_id), 'sourceRoot': '/engagement/loot',
                          'apiPort': 8080, 'answerPort': 8082},
    }


def prepare_artifacts(workspace_root: Path, artifacts: dict[str, Any], *, engagement_id: str) -> dict[str, Any]:
    _scope(engagement_id)
    if not isinstance(artifacts, dict) or set(artifacts) != {'source', 'imageArchive'} or not isinstance(artifacts['source'], bytes) or len(artifacts['source']) > SOURCE_LIMIT or not isinstance(artifacts['imageArchive'], Path):
        raise LootToolArtifactError('LootTool requires reviewed source bytes and a streamed controller image artifact')
    inputs = _inputs(hashlib.sha256(artifacts['source']).hexdigest(), engagement_id)
    # Validate both controller artifacts before any workspace artifact writes.
    _verify_file(artifacts['imageArchive'], IMAGE_ARCHIVE_SHA256, IMAGE_LIMIT)
    source = inputs['source']
    _publish(workspace_root, source['relativePath'], io.BytesIO(artifacts['source']), source['sha256'], SOURCE_LIMIT)
    image = inputs['imageArchive']
    with _open_regular(artifacts['imageArchive'], IMAGE_LIMIT) as stream:
        _publish(workspace_root, image['relativePath'], stream, image['sha256'], IMAGE_LIMIT)
    return execution_inputs(workspace_root, {ARTIFACTS_KEY: inputs}, engagement_id=engagement_id)


def execution_inputs(workspace_root: Path, metadata: dict[str, Any], *, engagement_id: str) -> dict[str, Any]:
    artifacts = metadata.get(ARTIFACTS_KEY)
    if not isinstance(artifacts, dict) or not isinstance(artifacts.get('source'), dict):
        raise LootToolArtifactError('Save LootTool selection to prepare its pinned source and image archive')
    expected = _inputs(artifacts['source'].get('sha256'), engagement_id)
    if artifacts != expected:
        raise LootToolArtifactError('LootTool artifact, image or engagement scope differs from the pinned installation contract')
    for key, limit in [('source', SOURCE_LIMIT), ('imageArchive', IMAGE_LIMIT)]:
        identity = expected[key]
        _verify_file(_safe_artifact(workspace_root, identity['relativePath']), identity['sha256'], limit)
    return expected


def copy_artifacts(destination: Path, source_root: Path, inputs: dict[str, Any], *, engagement_id: str) -> None:
    checked = execution_inputs(source_root, {ARTIFACTS_KEY: inputs}, engagement_id=engagement_id)
    for key, limit in [('source', SOURCE_LIMIT), ('imageArchive', IMAGE_LIMIT)]:
        identity = checked[key]
        with _open_regular(_safe_artifact(source_root, identity['relativePath']), limit) as stream:
            _publish(destination, identity['relativePath'], stream, identity['sha256'], limit)
    execution_inputs(destination, {ARTIFACTS_KEY: inputs}, engagement_id=engagement_id)


def role_variables(inputs: dict[str, Any]) -> dict[str, Any]:
    source, image, images, config = (inputs[key] for key in ('source', 'imageArchive', 'images', 'configuration'))
    return {
        'loottool_v2_source_archive': '{{ playbook_dir }}/../' + source['relativePath'],
        'loottool_v2_source_sha256': source['sha256'],
        'loottool_v2_source_revision': source['revision'],
        'loottool_v2_app_image': images['application'],
        'loottool_v2_elasticsearch_image': images['elasticsearch'],
        'loottool_v2_python_image': images['python'],
        'loottool_v2_evidence_scope': config['evidenceScope'],
        'loottool_v2_source_root': config['sourceRoot'],
        'loottool_v2_api_port': config['apiPort'],
        'loottool_v2_answer_port': config['answerPort'],
        'loottool_v2_app_archive': '{{ playbook_dir }}/../' + image['relativePath'],
        'loottool_v2_app_archive_sha256': image['sha256'],
        'loottool_v2_app_config_digest': images['applicationConfig'],
    }
