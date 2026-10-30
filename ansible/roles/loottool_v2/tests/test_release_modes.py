# Copyright (c) 2026, Oracle and/or its affiliates.
"""Retained release recovery with real Git mode fixtures; no operational source."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import tarfile

ROLE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify_release', ROLE/'files/verify_release.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ReleaseModeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='release-mode-fixture-', dir=os.environ.get('ROLE_TEST_TEMP_ROOT'))
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        source = self.base/'git'
        (source/'scripts').mkdir(parents=True)
        (source/'README.md').write_text('immutable fixture\n')
        (source/'scripts/run.sh').write_text('#!/bin/sh\nprintf fixture\\n\n')
        (source/'scripts/run.sh').chmod(0o755)
        def git(*args):
            return subprocess.run(['git',*args],cwd=source,check=True,capture_output=True).stdout
        git('init'); git('config','user.name','Test'); git('config','user.email','test@example.invalid')
        git('add','.'); git('commit','-m','Mode fixture')
        self.archive = self.base/'source.tar.gz'
        self.archive.write_bytes(git('-c','tar.umask=0002','archive','--format=tar.gz','HEAD'))
        self.release = self.base/'release'
        self.release.mkdir(mode=0o755)
        with tarfile.open(self.archive,'r:gz') as archive:
            self.assertEqual({m.name:m.mode for m in archive},
                {'README.md':0o664,'scripts':0o775,'scripts/run.sh':0o775})
            # This archive was just built from the test's own three safe paths.
            # Preserve Git's modes to reproduce GNU tar, rather than Python's
            # data filter (which silently strips group-write permissions).
            archive.extractall(self.release,filter='fully_trusted')
        self.sentinel = self.base/'operator-content'
        self.sentinel.write_bytes(b'outside release remains unchanged')
        self.foreign_uid = set()
        self.foreign_gid = set()
        original_stat = Path.stat
        def root_stat(path,*args,**kwargs):
            value = original_stat(path,*args,**kwargs)
            # Non-root laptop fixtures model root ownership. Parent permissions
            # outside the release are also modeled as the real protected /opt tree;
            # actual retained member mode/type/bytes remain unmodified and checked.
            mode = value.st_mode
            if path in self.release.parents:
                mode &= ~0o022
            return os.stat_result((mode,value.st_ino,value.st_dev,value.st_nlink,
                10001 if path in self.foreign_uid else 0,10001 if path in self.foreign_gid else 0,
                value.st_size,value.st_atime,value.st_mtime,value.st_ctime))
        patched = patch.object(Path,'stat',root_stat)
        patched.start(); self.addCleanup(patched.stop)

    def test_exact_git_modes_allow_precheck_but_not_strict_verification(self):
        verifier.verify_before_extract(self.archive,self.release)
        with self.assertRaisesRegex(ValueError,'unprotected release file'):
            verifier.verify(self.archive,self.release)
        # Golden post-extraction state; actual Ansible normalization is exercised
        # separately when GNU tar is available, not claimed by this helper test.
        (self.release/'README.md').chmod(0o644)
        (self.release/'scripts').chmod(0o755)
        (self.release/'scripts/run.sh').chmod(0o755)
        verifier.verify(self.archive,self.release)
        self.assertEqual(stat.S_IMODE((self.release/'scripts/run.sh').stat().st_mode),0o755)
        self.assertEqual(self.sentinel.read_bytes(),b'outside release remains unchanged')

    def test_missing_members_allow_partial_retry(self):
        (self.release/'scripts/run.sh').unlink()
        verifier.verify_before_extract(self.archive,self.release)
        self.assertFalse((self.release/'scripts/run.sh').exists())

    def test_changed_bytes_are_refused_and_preserved_before_extraction(self):
        target=self.release/'README.md'
        target.write_bytes(b'operator modification')
        with self.assertRaisesRegex(ValueError,'bytes changed'):
            verifier.verify_before_extract(self.archive,self.release)
        self.assertEqual(target.read_bytes(),b'operator modification')
        self.assertEqual(self.sentinel.read_bytes(),b'outside release remains unchanged')

    def test_symlink_type_and_foreign_ownership_refused_before_extraction(self):
        target=self.release/'README.md'
        for condition in ('symlink','directory','uid','gid'):
            with self.subTest(condition=condition):
                if target.is_symlink() or target.is_file(): target.unlink()
                elif target.is_dir(): target.rmdir()
                self.foreign_uid.clear(); self.foreign_gid.clear()
                if condition=='symlink': target.symlink_to(self.sentinel)
                elif condition=='directory': target.mkdir()
                else:
                    target.write_bytes(b'immutable fixture\n'); target.chmod(0o664)
                    (self.foreign_uid if condition=='uid' else self.foreign_gid).add(target)
                with self.assertRaises(ValueError):
                    verifier.verify_before_extract(self.archive,self.release)
                self.assertEqual(self.sentinel.read_bytes(),b'outside release remains unchanged')

    def test_hardlinked_file_cannot_change_outside_release_sentinel(self):
        target=self.release/'README.md'
        target.unlink()
        # Match reviewed bytes so only the alias guard can reject this case.
        self.sentinel.write_bytes(b'immutable fixture\n')
        self.sentinel.chmod(0o664)
        os.link(self.sentinel,target)
        before=(self.sentinel.read_bytes(),stat.S_IMODE(self.sentinel.stat().st_mode))
        self.assertGreater(target.stat().st_nlink,1)
        with self.assertRaisesRegex(ValueError,'hardlinked'):
            verifier.verify_before_extract(self.archive,self.release)
        self.assertEqual((self.sentinel.read_bytes(),stat.S_IMODE(self.sentinel.stat().st_mode)),before)
        self.sentinel.chmod(0o644)
        before=(self.sentinel.read_bytes(),stat.S_IMODE(self.sentinel.stat().st_mode))
        with self.assertRaises(ValueError):
            verifier.verify(self.archive,self.release)
        self.assertEqual((self.sentinel.read_bytes(),stat.S_IMODE(self.sentinel.stat().st_mode)),before)

    def test_unexpected_writable_modes_refused(self):
        (self.release/'README.md').chmod(0o666)
        with self.assertRaises(ValueError): verifier.verify_before_extract(self.archive,self.release)
        (self.release/'README.md').chmod(0o674)
        with self.assertRaises(ValueError): verifier.verify_before_extract(self.archive,self.release)

    def test_strict_verifier_still_refuses_group_write_and_tampering(self):
        for path in [self.release/'README.md',self.release/'scripts',self.release/'scripts/run.sh']:
            path.chmod(0o755 if path.is_dir() or path.suffix=='.sh' else 0o644)
        (self.release/'README.md').chmod(0o664)
        with self.assertRaisesRegex(ValueError,'unprotected release file'):
            verifier.verify(self.archive,self.release)
        (self.release/'README.md').chmod(0o644)
        (self.release/'README.md').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'bytes changed'):
            verifier.verify(self.archive,self.release)

    @unittest.skipUnless(os.environ.get('ROLE_GATE_ANSIBLE'), 'set ROLE_GATE_ANSIBLE for actual unarchive regression')
    def test_actual_ansible_unarchive_normalizes_modes_preserves_exec_and_sentinel(self):
        import yaml
        tar=shutil.which('gtar') or shutil.which('tar')
        if not tar or 'GNU tar' not in subprocess.run([tar,'--version'],capture_output=True,text=True).stdout:
            self.skipTest('GNU tar is unavailable; run this fixture on isolated Linux')
        tasks=yaml.safe_load((ROLE/'tasks/main.yml').read_text())
        before=next(i for i,t in enumerate(tasks) if t['name']=='Refuse retained release changes before extraction or normalization')
        extraction=next(i for i,t in enumerate(tasks) if t['name']=='Extract immutable source release')
        self.assertLess(before,extraction)
        options=tasks[extraction]['ansible.builtin.unarchive']
        self.assertEqual((options['owner'],options['group'],options['mode']),('root','root','u=rwX,go=rX'))
        # Execute the production extraction attributes against harmless temp files;
        # fixture UID/GID use the test runner because no root/host mutation is needed.
        options={**options,'src':str(self.archive),'dest':str(self.release),
                 'owner':str(os.getuid()),'group':str(os.getgid())}
        play=self.base/'extract.json'
        play.write_text(json.dumps([{'hosts':'localhost','gather_facts':False,'tasks':[
            {'ansible.builtin.unarchive':options}]}]))
        env=dict(os.environ,ANSIBLE_LOCAL_TEMP=str(self.base/'local'),ANSIBLE_REMOTE_TEMP=str(self.base/'remote'))
        result=subprocess.run([os.environ['ROLE_GATE_ANSIBLE'],'-i','localhost,','-c','local',str(play)],
                              env=env,capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(stat.S_IMODE((self.release/'README.md').stat().st_mode),0o644)
        self.assertEqual(stat.S_IMODE((self.release/'scripts').stat().st_mode),0o755)
        self.assertEqual(stat.S_IMODE((self.release/'scripts/run.sh').stat().st_mode),0o755)
        verifier.verify(self.archive,self.release)
        self.assertEqual(self.sentinel.read_bytes(),b'outside release remains unchanged')


if __name__=='__main__':
    unittest.main()
