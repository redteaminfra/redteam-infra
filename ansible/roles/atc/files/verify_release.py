#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: Apache-2.0
"""Validate an app-built native bundle without extracting or executing it."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

LIMIT = 1024 * 1024 * 1024
REQUIRED = {
    'install.sh', 'release.env', 'atc-source.bundle', 'constraints.txt',
    'atc-maintenance.in', 'atc-source-check.sh', 'atc-postgres-guard.sh',
    'atc-graph-runtime-guard.py', 'atc-operation-fence.py',
    'atc-neo4j-guard.sh', 'atc-neo4j-entrypoint.sh', 'atc_upgrade_graph_guard.py',
    'upgrade-policy-v1.json', 'verify-upgrade-policy.py', 'verify-graphiti-adapter.py',
    'atc-install.conf.example', 'inference.env.example', 'web-dist/index.html',
    'systemd/atc-api.service.in', 'systemd/atc-postgres.service.in',
    'systemd/atc-interpretation-worker.service.in',
    'systemd/atc-graph-neo4j.service.in', 'systemd/atc-graph-adapter@.service.in',
    'systemd/atc-graph-projection-worker@.service.in',
}


def canonical(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or '..' in path.parts or '.git' in path.parts
            or str(path) != name.rstrip('/') or not re.fullmatch(r'[A-Za-z0-9_./+@-]+', name)):
        raise ValueError('release contains an unsafe member path')
    return str(path)


def parse_manifest(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*=[^\s]+', line):
            raise ValueError('release manifest is malformed')
        key, value = line.split('=', 1)
        if key in result:
            raise ValueError('release manifest contains duplicate keys')
        result[key] = value
    return result


def verify(path, expected_sha256, revision, version, postgres_image):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha256) or not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('exact release SHA256 and source revision are required')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[._+-][A-Za-z0-9.-]+)?', version):
        raise ValueError('exact release version is required')
    if not re.fullmatch(r'docker\.io/library/postgres:16(?:[.-][A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}', postgres_image):
        raise ValueError('PostgreSQL must use an explicit official version16 digest')
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > LIMIT:
        raise ValueError('release archive must be a regular controller file within 1 GiB')
    with source.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _hash(handle)
    if digest != expected_sha256:
        raise ValueError('release archive SHA256 differs from the reviewed artifact')
    hashes, captured, names, total = {}, {}, set(), 0
    with tarfile.open(source, 'r:gz') as archive:
        for member in archive:
            name = canonical(member.name)
            if name in names or not (member.isfile() or member.isdir()) or member.mode & 0o7022:
                raise ValueError('release contains duplicate, linked, special or writable members')
            names.add(name)
            total += member.size
            if len(names) > 20000 or total > 4 * LIMIT or member.size > LIMIT:
                raise ValueError('release exceeds extraction bounds')
            if member.isfile():
                stream = archive.extractfile(member)
                hashes[name] = _hash(stream)
                if name in {'release.env', 'checksums.sha256'}:
                    if member.size > 4 * 1024 * 1024:
                        raise ValueError('release manifest exceeds bounds')
                    captured[name] = archive.extractfile(member).read()
    if not REQUIRED <= hashes.keys() or 'checksums.sha256' not in captured:
        raise ValueError('release lacks the native app installation contract')
    expected = {}
    for line in captured['checksums.sha256'].decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  \./(.+)', line)
        if not match:
            raise ValueError('release checksum manifest is malformed')
        name = canonical(match[2])
        if name in expected or name == 'checksums.sha256':
            raise ValueError('release checksum manifest is ambiguous')
        expected[name] = match[1]
    if expected != {name: value for name, value in hashes.items() if name != 'checksums.sha256'}:
        raise ValueError('release internal file checksums do not match exactly')
    manifest = parse_manifest(captured['release.env'])
    for key, value in {'SOURCE_COMMIT': revision, 'RELEASE_VERSION': version,
                       'POSTGRES_IMAGE': postgres_image, 'SOURCE_BUNDLE': 'atc-source.bundle'}.items():
        if manifest.get(key) != value:
            raise ValueError('release manifest differs from the requested pinned identity')
    if not re.fullmatch(r'[0-9a-f]{64}', manifest.get('MIGRATION_LEVEL', '')):
        raise ValueError('release lacks an exact migration identity')
    for abi in ('cp310', 'cp311', 'cp312'):
        if not any(name.startswith('wheelhouse/' + abi + '/') and name.endswith('.whl') for name in hashes):
            raise ValueError('release lacks a supported offline ATC wheelhouse')
    graph_archive = manifest.get('GRAPHITI_ADAPTER_ARCHIVE', '')
    graph_wheels = manifest.get('GRAPHITI_WHEELHOUSE', '')
    if (not graph_archive.startswith('graphiti/') or hashes.get(graph_archive) != manifest.get('GRAPHITI_ADAPTER_SHA256')
            or not graph_wheels.startswith('graphiti/') or not any(name.startswith(graph_wheels + '/') and name.endswith('.whl') for name in hashes)):
        raise ValueError('release lacks its measured dormant graph closure')
    return {'sha256': digest, 'sourceRevision': revision, 'version': version,
            'postgresImage': postgres_image, 'migrationLevel': manifest['MIGRATION_LEVEL'], 'members': len(names)}


def _hash(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
    return digest.hexdigest()


if __name__ == '__main__':
    try:
        print(json.dumps(verify(*sys.argv[1:])))
    except (OSError, ValueError, UnicodeError, tarfile.TarError) as exc:
        raise SystemExit(str(exc)) from None
