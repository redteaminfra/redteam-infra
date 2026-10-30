#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.
"""Verify a reviewed single-image Docker-save artifact; optionally import it."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile


def verify(path, expected_sha, config_digest, revision, local_id):
    for value, pattern in [(expected_sha, r'[0-9a-f]{64}'),
                           (config_digest, r'sha256:[0-9a-f]{64}'),
                           (local_id, r'sha256:[0-9a-f]{64}'), (revision, r'[0-9a-f]{40}')]:
        if not re.fullmatch(pattern, value):
            raise ValueError('invalid image identity')
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024**3:
        raise ValueError('invalid image archive')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _hash(stream)
    if digest != expected_sha:
        raise ValueError('image archive checksum mismatch')
    with tarfile.open(path, 'r:') as archive:
        members = {}
        size = 0
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or str(name) in members or not (member.isfile() or member.isdir()):
                raise ValueError('unsafe image archive member')
            members[str(name)] = member
            size += member.size
            if size > 2 * 1024**3 or len(members) > 10000:
                raise ValueError('image archive bounds exceeded')
        def read(name, maximum=4 * 1024**2):
            member = members[name]
            if not member.isfile() or member.size > maximum:
                raise ValueError('invalid image metadata')
            return archive.extractfile(member).read()
        manifest = json.loads(read('manifest.json'))
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError('only a single application image is supported')
        config = read(manifest[0]['Config'])
        if 'sha256:' + hashlib.sha256(config).hexdigest() != config_digest:
            raise ValueError('image config identity mismatch')
        config_data = json.loads(config)
        if config_data.get('os') != 'linux' or config_data.get('architecture') != 'amd64':
            raise ValueError('image config platform mismatch')
        if (config_data.get('config') or {}).get('Labels', {}).get('org.opencontainers.image.revision') != revision:
            raise ValueError('image config revision mismatch')
        # Docker-save OCI blobs are content-addressed; verify every blob, including
        # layers. The reviewed local ID may be a store's manifest/index or config.
        blob_names = {}
        for name, member in members.items():
            if not member.isfile() or not name.startswith('blobs/sha256/'):
                continue
            suffix = name.removeprefix('blobs/sha256/')
            if not re.fullmatch(r'[0-9a-f]{64}', suffix) or _hash(archive.extractfile(member)) != suffix:
                raise ValueError('image blob content mismatch')
            blob_names['sha256:' + suffix] = name
        def bound_to_config(identity, visited):
            if identity == config_digest:
                return True
            if identity in visited or identity not in blob_names or len(visited) > 8:
                return False
            value = json.loads(read(blob_names[identity]))
            if not isinstance(value, dict):
                return False
            if isinstance(value.get('config'), dict):
                # Only an actual OCI/Docker image manifest can bind a config;
                # a random layer/config blob is never an image identity.
                return (value.get('schemaVersion') == 2
                        and value.get('mediaType') in {
                            'application/vnd.oci.image.manifest.v1+json',
                            'application/vnd.docker.distribution.manifest.v2+json'}
                        and value['config'].get('digest') == config_digest)
            children = value.get('manifests')
            if (value.get('schemaVersion') != 2 or value.get('mediaType') not in {
                    'application/vnd.oci.image.index.v1+json',
                    'application/vnd.docker.distribution.manifest.list.v2+json'}
                    or not isinstance(children, list) or not 1 <= len(children) <= 16
                    or any(not isinstance(child, dict) for child in children)):
                return False
            digests = [child.get('digest') for child in children]
            if any(not isinstance(digest, str) for digest in digests) or len(set(digests)) != len(digests):
                return False
            runtime = [child for child in children if child.get('platform') == {
                'os': 'linux', 'architecture': 'amd64'}]
            if len(runtime) != 1:
                return False
            descriptor = runtime[0]
            if descriptor.get('mediaType') not in {
                    'application/vnd.oci.image.manifest.v1+json',
                    'application/vnd.docker.distribution.manifest.v2+json',
                    'application/vnd.oci.image.index.v1+json',
                    'application/vnd.docker.distribution.manifest.list.v2+json'}:
                return False
            runtime_annotations = descriptor.get('annotations', {})
            if not isinstance(runtime_annotations, dict) or runtime_annotations.get('vnd.docker.reference.type') is not None:
                return False
            runtime_digest = descriptor.get('digest')
            if not bound_to_config(runtime_digest, visited | {identity}):
                return False
            for child in children:
                if child is descriptor:
                    continue
                annotations = child.get('annotations')
                if (child.get('platform') != {'os': 'unknown', 'architecture': 'unknown'}
                        or child.get('mediaType') != 'application/vnd.oci.image.manifest.v1+json'
                        or not isinstance(annotations, dict)
                        or annotations.get('vnd.docker.reference.type') != 'attestation-manifest'
                        or annotations.get('vnd.docker.reference.digest') != runtime_digest
                        or child.get('digest') not in blob_names):
                    return False
                attestation = json.loads(read(blob_names[child['digest']]))
                if (not isinstance(attestation, dict) or attestation.get('schemaVersion') != 2
                        or attestation.get('mediaType') != 'application/vnd.oci.image.manifest.v1+json'
                        or not isinstance(attestation.get('config'), dict)
                        or attestation['config'].get('digest') not in blob_names
                        or not isinstance(attestation.get('layers'), list) or not attestation['layers']):
                    return False
                attestation_config = json.loads(read(blob_names[attestation['config']['digest']]))
                if (not isinstance(attestation_config, dict) or attestation_config.get('os') != 'unknown'
                        or attestation_config.get('architecture') != 'unknown'):
                    return False
                # BuildKit attestations are evidence metadata, never additional
                # executable runtimes. Their content-addressed blobs were all
                # hashed above; allow only in-toto payloads attached to this runtime.
                for layer in attestation['layers']:
                    if (not isinstance(layer, dict) or layer.get('mediaType') != 'application/vnd.in-toto+json'
                            or layer.get('digest') not in blob_names):
                        return False
            return True
        if not bound_to_config(local_id, set()):
            raise ValueError('local image identity is not bound to the reviewed image config')
    return {'configDigest': config_digest, 'localId': local_id, 'platform': 'linux/amd64', 'revision': revision,
            'rootfsDiffIds': config_data.get('rootfs', {}).get('diff_ids', []),
            'runtimeConfig': {key: (config_data.get('config') or {}).get(key)
                              for key in ('Env', 'Entrypoint', 'Cmd', 'User', 'WorkingDir')}}


def _hash(stream):
    digest = hashlib.sha256()
    while data := stream.read(1024 * 1024):
        digest.update(data)
    return digest.hexdigest()


def ensure_loaded(path, identity):
    def inspected():
        result = subprocess.run(['docker', 'image', 'inspect', identity['localId']],
                                capture_output=True, timeout=30)
        if result.returncode:
            return None
        data = json.loads(result.stdout)[0]
        if data.get('Id') != identity['localId'] or data.get('Os') != 'linux' or data.get('Architecture') != 'amd64':
            raise ValueError('imported local image identity/platform mismatch')
        if (data.get('Config') or {}).get('Labels', {}).get('org.opencontainers.image.revision') != identity['revision']:
            raise ValueError('imported local image revision mismatch')
        # Inspect IDs differ between Docker stores. Export this exact daemon ID
        # and hash its config bytes, rather than treating index ID as config ID
        # or comparing only a subset of human-readable inspect properties.
        with tempfile.TemporaryDirectory(prefix='loottool-image-check-') as temporary:
            exported = str(Path(temporary) / 'image.tar')
            subprocess.run(['docker', 'image', 'save', '--output', exported, identity['localId']],
                           check=True, capture_output=True, timeout=120)
            with tarfile.open(exported, 'r:') as archive:
                member = archive.getmember('manifest.json')
                if member.size > 4 * 1024**2:
                    raise ValueError('exported image metadata bounds exceeded')
                manifest = json.load(archive.extractfile(member))
                if not isinstance(manifest, list) or len(manifest) != 1:
                    raise ValueError('exported image ambiguity')
                config_member = archive.getmember(manifest[0]['Config'])
                if config_member.size > 4 * 1024**2:
                    raise ValueError('exported config bounds exceeded')
                if 'sha256:' + _hash(archive.extractfile(config_member)) != identity['configDigest']:
                    raise ValueError('daemon image config does not match reviewed config identity')
        return data
    if inspected() is not None:
        return False
    subprocess.run(['docker', 'load', '--input', path], check=True, capture_output=True, timeout=300)
    if inspected() is None:
        raise ValueError('daemon did not expose the reviewed local identity; inspect its config/index ID explicitly')
    return True


if __name__ == '__main__':
    try:
        identity = verify(*sys.argv[1:6])
        if len(sys.argv) == 7 and sys.argv[6] == 'load':
            identity['changed'] = ensure_loaded(sys.argv[1], identity)
        print(json.dumps(identity))
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OSError, tarfile.TarError, subprocess.SubprocessError):
        sys.exit('LootTool image archive/import identity validation failed')
