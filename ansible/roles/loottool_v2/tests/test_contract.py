# Copyright (c) 2026, Oracle and/or its affiliates.
import hashlib
import importlib.util
import io
import os
import json
from pathlib import Path
import tarfile
import tempfile
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FILES = Path(__file__).resolve().parents[1] / 'files'


def load(name):
    spec = importlib.util.spec_from_file_location(name, FILES / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = load('runtime')
archive = load('verify_archive')
images = load('verify_images')
bindings = load('verify_bindings')
image_archive = load('verify_image_archive')


def proposed():
    return {
        'LOOTTOOL_GIT_COMMIT': 'a' * 40,
        'LOOTTOOL_APP_IMAGE': 'example/app@sha256:' + 'b' * 64,
        'ELASTICSEARCH_IMAGE': 'example/es@sha256:' + 'c' * 64,
        'PYTHON_IMAGE': 'example/python@sha256:' + 'd' * 64,
        'LOOTTOOL_EVIDENCE_SCOPE': 'shared-loot',
        'LOOTTOOL_SOURCE_ROOT': '/engagement/loot',
        'LOOTTOOL_API_LISTEN_PORT': '8080',
        'LOOTTOOL_ANSWER_LISTEN_PORT': '8082',
    }


class RuntimeTests(unittest.TestCase):
    def test_reapply_preserves_all_credentials(self):
        fresh = runtime.prepare(proposed())
        second = runtime.prepare(proposed(), fresh)
        self.assertEqual(second, fresh)
        self.assertEqual(len({fresh[k] for k in runtime.SECRET_FIELDS}), 3)
        self.assertEqual(second['LOOTTOOL_API_LISTEN_HOST'], '127.0.0.1')
        self.assertNotIn('LOOTTOOL_INFERENCE_API_KEY', second)

    def test_scope_source_state_port_and_upgrade_changes_refused(self):
        fresh = runtime.prepare(proposed())
        for field in proposed():
            bad = proposed()
            bad[field] += 'changed'
            with self.subTest(field=field), self.assertRaises(ValueError):
                runtime.prepare(bad, fresh)
        changed = dict(fresh, LOOTTOOL_ES_DATA_ROOT='/other')
        with self.assertRaises(ValueError):
            runtime.prepare(proposed(), changed)

    def test_credentials_never_rotated_or_silently_repaired(self):
        fresh = runtime.prepare(proposed())
        for key in runtime.SECRET_FIELDS:
            changed = dict(fresh)
            changed.pop(key)
            with self.assertRaises(ValueError):
                runtime.prepare(proposed(), changed)

    def test_dotenv_injection_refused(self):
        for value in ['x\nEVIL=1', '${SECRET}', "x'", 'x\\y']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                runtime.dotenv({'SAFE': value})

    def test_optional_activation_rejected(self):
        fresh = runtime.prepare(proposed())
        for key in ['COMPOSE_PROFILES', 'LOOTTOOL_INFERENCE_API_KEY', 'LOOTTOOL_ATC_TOKEN']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                runtime.prepare(proposed(), dict(fresh, **{key: 'secret'}))


class ArchiveTests(unittest.TestCase):
    def artifact(self, directory, extra=None):
        path = Path(directory) / 'release.tar.gz'
        names = ['pyproject.toml', 'compose.yaml', 'Dockerfile', 'LICENSE-2.0.txt',
                 'src/loottool/deployment.py', 'src/loottool/config.py',
                 'deploy/create-certificates.sh', 'deploy/create-service-users.sh']
        with tarfile.open(path, 'w:gz', pax_headers={'comment': 'a' * 40}) as output:
            for name in names:
                member = tarfile.TarInfo(name)
                member.mode = 0o644
                member.size = 1
                output.addfile(member, io.BytesIO(b'x'))
            if extra:
                output.addfile(extra)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_valid_exact_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.artifact(directory)
            self.assertEqual(archive.verify(path, digest, 'a' * 40)['members'], 8)
            for wrong_digest, wrong_revision in [('0' * 64, 'a' * 40), (digest, 'b' * 40)]:
                with self.assertRaises(ValueError):
                    archive.verify(path, wrong_digest, wrong_revision)

    def test_traversal_symlink_and_duplicate_rejected(self):
        for name, kind in [('../bad', tarfile.REGTYPE), ('link', tarfile.SYMTYPE),
                           ('compose.yaml', tarfile.REGTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                extra = tarfile.TarInfo(name)
                extra.type = kind
                path, digest = self.artifact(directory, extra)
                with self.assertRaises(ValueError):
                    archive.verify(path, digest, 'a' * 40)


class ImageTests(unittest.TestCase):
    def test_registry_identity_platform_and_source(self):
        ref = proposed()['LOOTTOOL_APP_IMAGE']
        image = {'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [ref],
                 'Config': {'Labels': {'org.opencontainers.image.revision': 'a' * 40}}}
        images.validate(image, ref, 'a' * 40)
        for changed in [dict(image, Architecture='arm64'), dict(image, RepoDigests=[]),
                        dict(image, Config={'Labels': {}})]:
            with self.assertRaises(ValueError):
                images.validate(changed, ref, 'a' * 40)


class BindingTests(unittest.TestCase):
    def baseline(self):
        rows = []
        for service in ('api', 'elasticsearch'):
            rows.append({'Config': {'Labels': {'com.docker.compose.project': 'loottool-v2',
                                              'com.docker.compose.service': service}},
                         'HostConfig': {'NetworkMode': 'evidence', 'PortBindings':
                             {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8080'}]} if service == 'api' else {}},
                         'State': {'Running': True, 'Health': {'Status': 'healthy'}}, 'Mounts': []})
        return rows

    def test_private_healthy_baseline(self):
        bindings.validate(self.baseline(), 8080)

    def test_public_port_private_es_and_optional_services_rejected(self):
        for mutation in ('public', 'es', 'optional', 'loot', 'unhealthy'):
            rows = self.baseline()
            if mutation == 'public':
                rows[0]['HostConfig']['PortBindings']['8080/tcp'][0]['HostIp'] = '0.0.0.0'
            elif mutation == 'es':
                rows[1]['HostConfig']['PortBindings'] = {'9200/tcp': []}
            elif mutation == 'optional':
                rows[0]['Config']['Labels']['com.docker.compose.service'] = 'explorer-worker'
            elif mutation == 'loot':
                rows[0]['Mounts'] = [{'Destination': '/loot'}]
            else:
                rows[0]['State']['Health']['Status'] = 'unhealthy'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                bindings.validate(rows, 8080)


class DockerArchiveTests(unittest.TestCase):
    def artifact(self, directory, revision='a' * 40):
        config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'config': {
            'Labels': {'org.opencontainers.image.revision': revision}}}).encode()
        config_sha = hashlib.sha256(config).hexdigest()
        manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'config': {'digest': 'sha256:' + config_sha}}).encode()
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        payloads = {'blobs/sha256/' + config_sha: config,
                    'blobs/sha256/' + manifest_sha: manifest,
                    'manifest.json': json.dumps([{'Config': 'blobs/sha256/' + config_sha, 'Layers': []}]).encode()}
        path = Path(directory) / 'image.tar'
        with tarfile.open(path, 'w') as output:
            for name, data in payloads.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
        return path, hashlib.sha256(path.read_bytes()).hexdigest(), 'sha256:' + config_sha, 'sha256:' + manifest_sha

    def test_config_and_store_manifest_identity_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            path, digest, config, manifest = self.artifact(directory)
            self.assertNotEqual(config, manifest)
            for local in (config, manifest):
                result = image_archive.verify(path, digest, config, 'a' * 40, local)
                self.assertEqual(result['configDigest'], config)
                self.assertEqual(result['localId'], local)

    def test_wrong_archive_config_source_and_local_identity_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path, digest, config, manifest = self.artifact(directory)
            for sha, conf, revision, local in [('0' * 64, config, 'a' * 40, manifest),
                    (digest, 'sha256:' + '0' * 64, 'a' * 40, manifest),
                    (digest, config, 'b' * 40, manifest),
                    (digest, config, 'a' * 40, 'sha256:' + '0' * 64)]:
                with self.subTest(sha=sha, conf=conf, revision=revision, local=local), self.assertRaises(ValueError):
                    image_archive.verify(path, sha, conf, revision, local)


class DaemonConfigTests(DockerArchiveTests):
    def test_daemon_index_id_requires_exact_reviewed_config_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path, digest, config, manifest = self.artifact(directory)
            identity = image_archive.verify(path, digest, config, 'a' * 40, manifest)
            def run(args, **kwargs):
                if args[:3] == ['docker', 'image', 'inspect']:
                    return SimpleNamespace(returncode=0, stdout=json.dumps([{'Id': manifest,
                        'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Labels': {
                            'org.opencontainers.image.revision': 'a' * 40}}}]).encode())
                if args[:3] == ['docker', 'image', 'save']:
                    shutil.copyfile(path, args[4])
                    return SimpleNamespace(returncode=0)
                raise AssertionError('unexpected Docker mutation')
            with patch.object(image_archive.subprocess, 'run', side_effect=run):
                self.assertFalse(image_archive.ensure_loaded(str(path), identity))
                bad = dict(identity, configDigest='sha256:' + '0' * 64)
                with self.assertRaisesRegex(ValueError, 'daemon image config'):
                    image_archive.ensure_loaded(str(path), bad)


class InterruptedRuntimeTests(unittest.TestCase):
    def test_interrupted_publication_reuses_same_credentials_and_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'config'
            pending = root.with_name('.config.pending')
            request = {'action': 'write', 'proposed': proposed()}
            real_replace = runtime.os.replace
            for failed_replace in (1, 2):
                with self.subTest(failed_replace=failed_replace):
                    if root.exists():
                        import shutil
                        shutil.rmtree(root)
                    if pending.exists():
                        import shutil
                        shutil.rmtree(pending)
                    count = 0
                    def interrupted(source, destination):
                        nonlocal count
                        count += 1
                        if count == failed_replace:
                            raise OSError('simulated interruption')
                        return real_replace(source, destination)
                    with patch.object(runtime, 'ROOT', root), patch.object(runtime, '_check_private'), \
                         patch.object(runtime, 'guard_release'), patch.object(runtime, 'check_paths'), \
                         patch.object(runtime.os, 'replace', side_effect=interrupted):
                        with self.assertRaises(OSError):
                            runtime.configure(request)
                    saved = json.loads((pending / 'runtime.json').read_text()) if (pending / 'runtime.json').exists() else None
                    # A SIGKILL could leave an old random temporary; it cannot
                    # block the next attempt or become the authoritative JSON.
                    (pending / '.runtime.env.tmp-leftover').write_text('incomplete')
                    with patch.object(runtime, 'ROOT', root), patch.object(runtime, '_check_private'), \
                         patch.object(runtime, 'guard_release'), patch.object(runtime, 'check_paths'):
                        self.assertTrue(runtime.configure(request)['changed'])
                        final = json.loads((root / 'runtime.json').read_text())
                        self.assertEqual((root / 'runtime.env').read_text(), runtime.dotenv(final))
                        if saved:
                            self.assertEqual(saved, final)
                        self.assertFalse(runtime.configure(request)['changed'])

    def test_exact_release_symlink_refused_before_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            install = Path(directory) / 'install'
            releases = install / 'releases'
            releases.mkdir(parents=True)
            unrelated = Path(directory) / 'unrelated'
            unrelated.mkdir()
            (releases / ('a' * 40)).symlink_to(unrelated, target_is_directory=True)
            with patch.object(runtime, 'INSTALL_ROOT', install), self.assertRaisesRegex(ValueError, 'symlink'):
                runtime.guard_release('a' * 40)
            self.assertEqual(list(unrelated.iterdir()), [])

    def test_unarchive_has_no_partial_extraction_skip_marker(self):
        tasks = (FILES.parent / 'tasks/main.yml').read_text()
        self.assertNotIn('creates:', tasks)


class UnrelatedImageTests(DockerArchiveTests):
    def test_unrelated_manifest_and_layer_cannot_bind_another_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path, digest, config, manifest = self.artifact(directory)
            with tarfile.open(path, 'a') as archive:
                for content in [b'layer', json.dumps({'schemaVersion': 2,
                        'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                        'config': {'digest': 'sha256:' + '0' * 64}}).encode()]:
                    identity = hashlib.sha256(content).hexdigest()
                    member = tarfile.TarInfo('blobs/sha256/' + identity)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with tarfile.open(path, 'r') as archive:
                candidates = [m.name.removeprefix('blobs/sha256/') for m in archive if m.name.startswith('blobs/sha256/')]
            for candidate in candidates:
                if 'sha256:' + candidate in (config, manifest):
                    continue
                with self.subTest(candidate=candidate), self.assertRaises((ValueError, json.JSONDecodeError)):
                    image_archive.verify(path, digest, config, 'a' * 40, 'sha256:' + candidate)


class BuildkitAttestationTests(DockerArchiveTests):
    def attested_artifact(self, directory, variant=None):
        path, _, config, manifest = self.artifact(directory)
        objects = {}
        def blob(value):
            raw = json.dumps(value).encode()
            digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            objects['blobs/sha256/' + digest.removeprefix('sha256:')] = raw
            return digest
        attestation_config = blob({'os': 'unknown', 'architecture': 'unknown', 'config': {}})
        payload = blob({'predicateType': 'https://slsa.dev/provenance/v1'})
        attestation = blob({'schemaVersion': 2,
            'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'config': {'digest': attestation_config}, 'layers': [{
                'digest': payload, 'mediaType': 'application/vnd.in-toto+json'
                if variant != 'runtime-layer' else 'application/vnd.oci.image.layer.v1.tar+gzip'}]})
        runtime = {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'digest': manifest, 'platform': {'os': 'linux', 'architecture': 'amd64'}}
        evidence = {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'digest': attestation, 'platform': {'os': 'unknown', 'architecture': 'unknown'},
            'annotations': {'vnd.docker.reference.type': 'attestation-manifest',
                            'vnd.docker.reference.digest': manifest}}
        children = [runtime, evidence]
        if variant == 'missing-annotation':
            evidence.pop('annotations')
        elif variant == 'wrong-reference':
            evidence['annotations']['vnd.docker.reference.digest'] = 'sha256:' + '0' * 64
        elif variant == 'other-platform':
            evidence['platform'] = {'os': 'linux', 'architecture': 'arm64'}
        elif variant == 'two-runtimes':
            evidence['platform'] = {'os': 'linux', 'architecture': 'amd64'}
        elif variant == 'arbitrary-blob':
            evidence['digest'] = payload
        elif variant == 'missing-blob':
            evidence['digest'] = 'sha256:' + '0' * 64
        index = blob({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': children})
        with tarfile.open(path, 'a') as archive:
            for name, raw in objects.items():
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        return path, hashlib.sha256(path.read_bytes()).hexdigest(), config, index

    def test_exact_runtime_plus_bound_buildkit_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            path, digest, config, index = self.attested_artifact(directory)
            result = image_archive.verify(path, digest, config, 'a' * 40, index)
            self.assertEqual(result['localId'], index)
            self.assertEqual(result['configDigest'], config)

    def test_attestation_cannot_introduce_another_runtime_or_unbound_blob(self):
        for variant in ('missing-annotation', 'wrong-reference', 'other-platform', 'two-runtimes',
                        'arbitrary-blob', 'missing-blob', 'runtime-layer'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                path, digest, config, index = self.attested_artifact(directory, variant)
                with self.assertRaises(ValueError):
                    image_archive.verify(path, digest, config, 'a' * 40, index)


class ReviewedArchiveTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('LOOTTOOL_V2_REVIEWED_IMAGE_ARCHIVE'),
                         'set explicit reviewed archive path for real-artifact verification')
    def test_exact_owner_supplied_buildkit_archive(self):
        result = image_archive.verify(os.environ['LOOTTOOL_V2_REVIEWED_IMAGE_ARCHIVE'],
            'b35a12296dab657fba01ff5c327968e5b59fb10e8f942f992f3901aaf6f6b4fb',
            'sha256:79e67ef01c47b07a0123c2126a144b9bb4f2865f048d64d7e9e244987571d16a',
            '59a4c4682393e1a542dd61493284b2b2a5cdd79f',
            'sha256:0e0c84223d3732fd0814e968a5152b08cbbab4f78fc46fb42205b1526c684541')
        self.assertEqual(result['platform'], 'linux/amd64')


class BaselineSourcePermissionTests(unittest.TestCase):
    def test_operator_only_source_does_not_block_baseline_or_change_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / 'loot'
            source.mkdir(mode=0o2770)
            source.chmod(0o2770)
            real_stat = source.stat()
            state = {key: str(source.parent / ('state-' + str(index)))
                     for index, key in enumerate(runtime.STATE)}
            with patch.object(runtime, 'STATE', state):
                values = runtime.prepare(dict(proposed(), LOOTTOOL_SOURCE_ROOT=str(source)))
            # Model standard Homebase root:redteam(2770), inaccessible to UID10001.
            # We cannot chown test fixtures to root; assert no credential switch,
            # read attempt, metadata mutation or binding expansion is performed.
            fake_stat = os.stat_result((real_stat.st_mode, real_stat.st_ino, real_stat.st_dev,
                                        real_stat.st_nlink, 0, 4321, real_stat.st_size,
                                        real_stat.st_atime, real_stat.st_mtime, real_stat.st_ctime))
            real_path_stat = Path.stat
            def stat(path, *args, **kwargs):
                return fake_stat if path == source else real_path_stat(path, *args, **kwargs)
            real_read_text = Path.read_text
            def read_text(path, *args, **kwargs):
                return '1048576' if str(path) == '/proc/sys/vm/max_map_count' else real_read_text(path, *args, **kwargs)
            with patch.object(runtime, 'STATE', state), patch.object(runtime, 'ROOT', source.parent / 'config'), \
                 patch.object(runtime, 'INSTALL_ROOT', source.parent / 'install'), \
                 patch.object(Path, 'stat', stat), patch.object(Path, 'read_text', read_text), \
                 patch.object(runtime.shutil, 'disk_usage', return_value=SimpleNamespace(free=100*1024**3)), \
                 patch.object(runtime.socket, 'socket'), \
                 patch.object(runtime.os, 'fork', side_effect=AssertionError('no UID check')), \
                 patch.object(runtime.os, 'listdir', side_effect=PermissionError('operator-only source')) as listing:
                runtime.check_paths(values)
                listing.assert_not_called()
            self.assertEqual(source.stat().st_mode, real_stat.st_mode)
            self.assertEqual(source.stat().st_uid, real_stat.st_uid)
            self.assertEqual(source.stat().st_gid, real_stat.st_gid)
            self.assertEqual(source.stat().st_mtime_ns, real_stat.st_mtime_ns)
            self.assertEqual(values['LOOTTOOL_API_LISTEN_HOST'], '127.0.0.1')
            self.assertNotIn('group_add', values)
            self.assertNotIn('/loot', values.values())

    def test_source_existence_symlink_and_overlap_guards_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'source'
            source.mkdir()
            linked = root / 'linked'
            linked.symlink_to(source, target_is_directory=True)
            base_state = {key: str(root / ('state-' + str(index)))
                          for index, key in enumerate(runtime.STATE)}
            for invalid, expected in [(root / 'missing', 'must already exist'),
                                      (linked, 'symlink'), (source, 'state and source overlap')]:
                state = dict(base_state)
                if invalid == source:
                    state['LOOTTOOL_ES_DATA_ROOT'] = str(source / 'state')
                with self.subTest(source=invalid), patch.object(runtime, 'STATE', state), \
                     patch.object(runtime, 'ROOT', root / 'config'), \
                     patch.object(runtime, 'INSTALL_ROOT', root / 'install'):
                    values = runtime.prepare(dict(proposed(), LOOTTOOL_SOURCE_ROOT=str(invalid)))
                    with self.assertRaisesRegex(ValueError, expected):
                        runtime.check_paths(values)


if __name__ == '__main__':
    unittest.main()
