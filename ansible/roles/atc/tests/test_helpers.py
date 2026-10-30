# Copyright (c) 2026, Oracle and/or its affiliates.
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

ROLE = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROLE/'files'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

release = load('verify_release')
host = load('host_state')
REVISION, SHA = 'a'*40, 'b'*64
IMAGE = 'docker.io/library/postgres:16@sha256:'+'c'*64


def configuration():
    return {'root': '/opt/atc', 'python': '/usr/bin/python3', 'port': 8790,
        'operatorUser': 'user', 'engagementId': 'Z123', 'codename': 'Example',
        'engagementStatus': 'active', 'operatorId': 'human/one', 'operatorName': 'Operator',
        'version': '0.6.0', 'revision': REVISION, 'sha256': SHA,
        'postgresImage': IMAGE, 'migrationLevel': 'd'*64}


def state(config):
    return {'INSTALL_ROOT': config['root'], 'API_PORT': str(config['port']),
        'RELEASE_VERSION': config['version'], 'SOURCE_COMMIT': config['revision'],
        'POSTGRES_IMAGE': config['postgresImage'], 'MIGRATION_LEVEL': config['migrationLevel'],
        'OPERATOR_OS_USER': config['operatorUser'], 'ENGAGEMENT_ID': config['engagementId'],
        'ENGAGEMENT_CODENAME': config['codename'], 'ENGAGEMENT_STATUS': config['engagementStatus'],
        'TEAM_MEMBER_ID': config['operatorId'], 'TEAM_MEMBER_NAME': config['operatorName'], 'PHASE': 'healthy'}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def bundle(self, *, mutation=None, extra=None, version='0.6.0', migration='d'*64, include_license=False):
        files = {name: b'test contract fixture\n' for name in release.REQUIRED}
        if include_license:
            files['LICENSE-2.0.txt'] = b'packaged license contract fixture\n'
        graph = b'dormant graph fixture'
        files['graphiti/adapter.tar.gz'] = graph
        for abi in ('cp310','cp311','cp312'):
            files['wheelhouse/'+abi+'/example.whl'] = b'offline wheel fixture'
        files['graphiti/wheelhouse/cp310/example.whl'] = b'dormant wheel fixture'
        files['release.env'] = ('RELEASE_VERSION='+version+'\nSOURCE_COMMIT='+REVISION+'\nSOURCE_BUNDLE=atc-source.bundle\nPOSTGRES_IMAGE='+IMAGE+'\nMIGRATION_LEVEL='+migration+'\nGRAPHITI_ADAPTER_ARCHIVE=graphiti/adapter.tar.gz\nGRAPHITI_ADAPTER_SHA256='+hashlib.sha256(graph).hexdigest()+'\nGRAPHITI_WHEELHOUSE=graphiti/wheelhouse/cp310\n').encode()
        files['checksums.sha256'] = ''.join(hashlib.sha256(value).hexdigest()+'  ./'+name+'\n' for name,value in sorted(files.items())).encode()
        if mutation:
            mutation(files)
        archive = self.root/'release.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name,content in files.items():
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(content), 0o644
                tar.addfile(entry, io.BytesIO(content))
            if extra:
                tar.addfile(extra)
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def verify(self, path, digest, **kwargs):
        return release.verify(str(path), digest, kwargs.get('revision', REVISION), kwargs.get('version','0.6.0'), kwargs.get('image',IMAGE))

    def test_complete_bundle_is_bound_to_requested_identity(self):
        path,digest = self.bundle()
        result = self.verify(path,digest)
        self.assertEqual(result['sourceRevision'],REVISION)
        self.assertEqual(result['sha256'],digest)
        self.assertEqual(result['postgresImage'],IMAGE)

    def test_061_bundle_uses_its_own_version_and_migration_identity(self):
        path, digest = self.bundle(version='0.6.1', migration='e'*64, include_license=True)
        verified = self.verify(path, digest, version='0.6.1')
        self.assertEqual(verified['version'], '0.6.1')
        self.assertEqual(verified['migrationLevel'], 'e'*64)
        with self.assertRaisesRegex(ValueError, 'pinned identity'):
            self.verify(path, digest, version='0.6.0')

    def test_outer_digest_tamper(self):
        path,digest = self.bundle()
        with self.assertRaises(ValueError): self.verify(path,'f'*64)

    def test_internal_tamper_and_unlisted_content(self):
        for mutate in (lambda f:f.__setitem__('install.sh',b'tampered'),lambda f:f.__setitem__('unlisted',b'extra'),lambda f:f.pop('atc-source.bundle')):
            with self.subTest(mutate=mutate):
                path,digest = self.bundle(mutation=mutate)
                with self.assertRaises(ValueError): self.verify(path,digest)

    def test_requested_release_must_match_manifest(self):
        path,digest=self.bundle()
        for kwargs in ({'revision':'e'*40},{'version':'0.7.0'},{'image':IMAGE[:-1]+'e'}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError): self.verify(path,digest,**kwargs)

    def test_traversal_symlink_hardlink_and_duplicate_members_are_refused(self):
        for name,kind in (('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('linked',tarfile.SYMTYPE),('hard',tarfile.LNKTYPE),('install.sh',tarfile.REGTYPE)):
            with self.subTest(name=name):
                extra=tarfile.TarInfo(name); extra.type=kind; extra.linkname='outside'
                path,digest=self.bundle(extra=extra)
                with self.assertRaises(ValueError): self.verify(path,digest)

    def test_symlink_controller_artifact_is_refused(self):
        path,digest=self.bundle(); linked=self.root/'linked'; linked.symlink_to(path)
        with self.assertRaises(ValueError): self.verify(linked,digest)

    def test_mutable_image_invalid_revision_and_manifest_duplicates_are_refused(self):
        path,digest=self.bundle()
        for kwargs in ({'image':'postgres:latest'},{'revision':'short'}):
            with self.assertRaises(ValueError): self.verify(path,digest,**kwargs)
        with self.assertRaises(ValueError): release.parse_manifest(b'A=one\nA=two\n')

    def test_checksum_manifest_cannot_duplicate_or_escape(self):
        for line in ('0'*64+'  ./../escape\n','0'*64+'  ./install.sh\n'):
            path,digest=self.bundle(mutation=lambda f:f.__setitem__('checksums.sha256',f['checksums.sha256']+line.encode()))
            with self.assertRaises(ValueError): self.verify(path,digest)


class RetainedSettingsTests(unittest.TestCase):
    def test_valid_configuration_and_same_identity(self):
        config=configuration()
        self.assertEqual(host.validate_configuration(config),config)
        host.check_identity(state(config),config)

    def test_every_retained_setting_drift_is_refused(self):
        config=configuration()
        for key in state(config):
            with self.subTest(key=key):
                changed=state(config); changed[key]='changed'
                with self.assertRaises(ValueError): host.check_identity(changed,config)

    def test_partial_phase_never_becomes_automatic_repair(self):
        for phase in ('staged','secrets','identity-starting','database','unknown'):
            config=configuration(); recorded=state(config); recorded['PHASE']=phase
            with self.assertRaises(ValueError): host.check_identity(recorded,config)

    def test_invalid_inputs_and_answer_file_injection_are_refused(self):
        for key,value in [('port',True),('port',15432),('port',80),('port',65536),('root','/opt'),('root','/opt/../root/atc'),('root','/tmp/atc'),('operatorUser','root; id'),('codename','name\nAPI_PORT=1234'),('operatorName',' leading'),('revision','branch'),('postgresImage','postgres:16')]:
            with self.subTest(key=key,value=value):
                config=configuration(); config[key]=value
                with self.assertRaises(ValueError): host.validate_configuration(config)

    def test_protected_state_rejects_links_and_writable_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary).resolve()/'state'; path.write_text('PHASE=healthy\n'); path.chmod(0o600)
            self.assertTrue(host.protected(path,owner=os.getuid(),mode=0o600))
            linked=Path(temporary).resolve()/'linked'; linked.symlink_to(path)
            with self.assertRaises(ValueError): host.protected(linked,owner=os.getuid())
            hard=Path(temporary).resolve()/'hard'; os.link(path,hard)
            with self.assertRaises(ValueError): host.protected(path,owner=os.getuid())
            hard.unlink(); path.chmod(0o666)
            with self.assertRaises(ValueError): host.protected(path,owner=os.getuid())

    def test_role_uses_noninteractive_app_boundary_and_preserves_recovery(self):
        tasks=(ROLE/'tasks/main.yml').read_text()
        self.assertIn("'--non-interactive'",tasks)
        self.assertIn("['--repair']",tasks)
        self.assertNotIn('--upgrade',tasks)
        self.assertNotIn('db init',tasks)
        self.assertNotIn('token create',tasks)
        self.assertIn("ansible_distribution_version == '22.04'",tasks)
        self.assertIn('no_log: true',tasks)
        self.assertIn('restore-journal.json',host.MARKERS)
        self.assertIn('upgrade-journal.json',host.MARKERS)


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()/'atc'
        self.root.mkdir()
        self.config = configuration()
        self.config['root'] = str(self.root)
        for path in ('source/.git', 'config', 'recovery', 'releases'):
            (self.root/path).mkdir(parents=True, exist_ok=True)
        self.state_path = self.root/'install-state.env'
        self.write_state(state(self.config))
        for secret in ('database_password','credential_key'):
            (self.root/'config'/secret).write_bytes(b'protected-original-secret')
            (self.root/'config'/secret).chmod(0o600)
        runtime = {'ATC_API_HOST': '127.0.0.1', 'ATC_API_PORT': str(self.config['port']),
            'ATC_DATABASE_URL': 'postgresql://atc@127.0.0.1:15432/atc',
            'ATC_DATABASE_PASSWORD_FILE': str(self.root/'config/database_password.api'),
            'ATC_CREDENTIAL_KEY_FILE': str(self.root/'config/credential_key.api'),
            'ATC_ARTIFACT_ROOT': str(self.root/'artifacts'),
            'ATC_WEB_DIST': str(self.root/'releases'/self.config['version']/'web-dist')}
        (self.root/'config/api.env').write_text(''.join(key+'='+value+'\n' for key,value in runtime.items()))
        (self.root/'config/api.env').chmod(0o440)
        self.receipt = self.root/'.ansible-release.json'
        self.receipt.write_text(json.dumps({'sha256': SHA, 'sourceRevision': REVISION, 'version':'0.6.0'}))
        self.receipt.chmod(0o600)
        original_protected = host.protected
        def protected(path, **kwargs):
            if str(path).startswith(str(self.root)):
                return original_protected(path, owner=os.getuid(), **kwargs)
            return True
        patches = [patch.object(host, 'protected', protected),
            patch.object(host, 'validate_configuration', lambda c:c),
            patch.object(host.os, 'geteuid', lambda:0),
            patch.object(host.shutil, 'which', lambda name:'/usr/bin/'+name),
            patch.object(host.pwd, 'getpwnam', lambda name: type('Account',(),{'pw_uid':1000,'pw_dir':'/home/user'})()),
            patch.object(host, 'command', self.command),
            patch.object(host, 'ready', lambda c:True)]
        for item in patches:
            item.start(); self.addCleanup(item.stop)

    def command(self, argv, **kwargs):
        if argv[0] == self.config['python']: return '3.10\n'
        if argv[0] == 'docker': return '24.0\n'
        if argv[-2:] == ['rev-parse','HEAD']: return REVISION+'\n'
        if '--porcelain' in argv: return ''
        raise AssertionError('unexpected command')

    def write_state(self, value):
        self.state_path.write_text(''.join(key+'='+item+'\n' for key,item in value.items()))
        self.state_path.chmod(0o600)

    def test_non_docker_preflight_validates_retained_state_without_starting_daemon(self):
        from unittest.mock import patch
        with patch.object(host.shutil, 'which', side_effect=lambda name: None if name == 'docker' else '/usr/bin/'+name), \
             patch.object(host, '_docker_ready', side_effect=AssertionError('no daemon check before dependency decision')), \
             patch.object(host, 'ready', side_effect=AssertionError('no runtime readiness before dependency decision')):
            self.assertEqual(host.assess(self.config, require_docker=False), {'mode':'preflight','localReady':False})
            self.write_state({**state(self.config), 'TEAM_MEMBER_ID':'changed'})
            with self.assertRaises(ValueError):
                host.assess(self.config, require_docker=False)

    def test_unsafe_diagnostic_receipt_refused_before_dependency_changes(self):
        from unittest.mock import patch
        for kind in ('symlink', 'hardlink', 'public'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                outside = Path(temporary).resolve()/'outside'
                outside.write_bytes(b'preserve-private-evidence')
                outside.chmod(0o600)
                receipt = Path(temporary).resolve()/'receipt'
                if kind == 'symlink':
                    receipt.symlink_to(outside)
                elif kind == 'hardlink':
                    os.link(outside, receipt)
                else:
                    receipt.write_bytes(b'preserve-receipt'); receipt.chmod(0o644)
                # The surrounding fixture already models protected host ancestors;
                # root ownership for the receipt is modeled as this test's UID.
                real_protected = host.protected
                def mapped(path, **kwargs):
                    if str(path) == '/var/cache/atc/last-install-result.json':
                        return type(self)._receipt_guard(receipt, kwargs)
                    return real_protected(path, **kwargs)
                with patch.object(host, 'protected', mapped), self.assertRaises(ValueError):
                    host.assess(self.config, require_docker=False)
                self.assertEqual(outside.read_bytes(), b'preserve-private-evidence')
                self.assertEqual(outside.stat().st_mode & 0o777, 0o600)

    @staticmethod
    def _receipt_guard(path, kwargs):
        # Load an unpatched implementation, using actual types/modes/link counts.
        return load('host_state').protected(path, owner=os.getuid(), **kwargs)

    def test_fresh_foreign_api_or_postgres_listener_fails_before_docker(self):
        from unittest.mock import patch
        fresh = {**self.config, 'root': str(self.root/'fresh')}
        for port in (self.config['port'],15432):
            def command(argv, **kwargs):
                return 'LISTEN 0 128 0.0.0.0:'+str(port)+' 0.0.0.0:*' if argv[0]=='ss' else self.command(argv, **kwargs)
            with self.subTest(port=port), patch.object(host, 'command', command), \
                 patch.object(host, '_docker_ready', side_effect=AssertionError('no daemon action')):
                with self.assertRaisesRegex(ValueError, 'listener conflicts'):
                    host.assess(fresh, require_docker=False)

    def test_capacity_fails_before_docker_install_or_runtime_check(self):
        from unittest.mock import patch
        with patch.object(host.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 2*1024**3})()), \
             patch.object(host, '_docker_ready', side_effect=AssertionError('no daemon action')):
            with self.assertRaisesRegex(ValueError, '4 GiB'):
                host.assess(self.config, require_docker=False)

    def test_unchanged_apply_is_read_only_noop_and_preserves_keys(self):
        before={str(path):path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(host.assess(self.config),{'mode':'none','localReady':True})
        self.assertEqual(before,{str(path):path.read_bytes() for path in self.root.rglob('*') if path.is_file()})

    def test_failed_readiness_requests_only_same_release_repair(self):
        from unittest.mock import patch
        with patch.object(host,'ready',return_value=False):
            self.assertEqual(host.assess(self.config),{'mode':'repair','localReady':False})

    def test_existing_unreceipted_release_must_converge_before_claiming_artifact(self):
        self.receipt.unlink()
        self.assertEqual(host.assess(self.config),{'mode':'repair','localReady':True})

    def test_artifact_change_is_refused_without_rewriting_receipt(self):
        before=self.receipt.read_bytes()
        config={**self.config,'sha256':'e'*64}
        with self.assertRaises(ValueError): host.assess(config)
        self.assertEqual(self.receipt.read_bytes(),before)

    def test_every_recovery_marker_is_preserved_and_refused(self):
        for marker in host.MARKERS:
            with self.subTest(marker=marker):
                path=self.root/'recovery'/marker
                path.write_bytes(b'original recovery evidence')
                with self.assertRaises(ValueError): host.assess(self.config)
                self.assertEqual(path.read_bytes(),b'original recovery evidence')
                path.unlink()

    def test_dangling_recovery_marker_is_also_refused(self):
        path=self.root/'recovery/restore-intent.json'; path.symlink_to(self.root/'absent')
        with self.assertRaises(ValueError): host.assess(self.config)
        self.assertTrue(path.is_symlink())

    def test_optional_worker_configuration_is_preserved_without_starting_it(self):
        for name in ('inference.env','topo.env'):
            with self.subTest(name=name):
                path=self.root/'config'/name; path.write_bytes(b'operator configuration')
                with self.assertRaises(ValueError): host.assess(self.config)
                self.assertEqual(path.read_bytes(),b'operator configuration')
                path.unlink()

    def test_missing_key_is_not_regenerated(self):
        path=self.root/'config/credential_key'; path.unlink()
        with self.assertRaises(ValueError): host.assess(self.config)
        self.assertFalse(path.exists())

    def test_runtime_listener_drift_is_not_implicitly_reconfigured(self):
        path=self.root/'config/api.env'
        path.chmod(0o640)
        path.write_text(path.read_text().replace('ATC_API_PORT=8790','ATC_API_PORT=9000'))
        path.chmod(0o440)
        with self.assertRaises(ValueError): host.assess(self.config)
        self.assertIn('ATC_API_PORT=9000',path.read_text())

    def test_source_patch_is_not_overwritten(self):
        from unittest.mock import patch
        original=self.command
        def dirty(argv, **kwargs):
            return ' M src/atc/server.py\n' if '--porcelain' in argv else original(argv,**kwargs)
        with patch.object(host,'command',dirty):
            with self.assertRaises(ValueError): host.assess(self.config)


if __name__=='__main__': unittest.main()
