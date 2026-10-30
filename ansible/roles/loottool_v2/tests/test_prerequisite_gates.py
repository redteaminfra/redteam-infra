# Copyright (c) 2026, Oracle and/or its affiliates.
"""Opt-in local Ansible tests with a harmless Docker-role fixture, no installer."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ANSIBLE = os.environ.get('ROLE_GATE_ANSIBLE')
ROLE = Path(__file__).resolve().parents[1]


@unittest.skipUnless(ANSIBLE, 'set ROLE_GATE_ANSIBLE to exercise isolated Ansible gates')
class PrerequisiteGateTests(unittest.TestCase):
    def run_role(self, *, case, full=False):
        import yaml
        with tempfile.TemporaryDirectory(prefix='role-prerequisite-gate-') as temporary:
            root = Path(temporary)
            roles = root / 'roles'
            copied = roles / ROLE.name
            shutil.copytree(ROLE, copied, ignore=shutil.ignore_patterns('__pycache__'))
            docker = roles / 'docker/tasks'
            docker.mkdir(parents=True)
            (docker / 'main.yml').write_text('- ansible.builtin.debug:\n    msg: PREREQUISITE_STUB_REACHED\n')
            binary = root / 'bin'
            binary.mkdir()
            script = binary / 'docker'
            version = '23.0' if case == 'old' else '24.0'
            script.write_text('#!/bin/sh\n' + ('exit 1\n' if case == 'stopped' else
                'if [ "$1" = compose ]; then ' + ('exit 1' if case == 'missing-compose' else 'echo 2.22.0') +
                '; else echo '+version+'; fi\n'))
            script.chmod(0o755)
            if full:
                distribution = '24.04' if ROLE.name == 'atc' else '22.04'
                if case == 'bad-artifact':
                    distribution = '22.04' if ROLE.name == 'atc' else '24.04'
                    if ROLE.name == 'loottool_v2':
                        # Isolate the artifact gate from unrelated host paths;
                        # real target path/resource checks have their own tests.
                        (copied / 'files/runtime.py').write_text('import json\nprint(json.dumps({"proposed":{},"existing":None}))\n')
                variables = {'ansible_distribution':'Ubuntu', 'ansible_distribution_version':distribution,
                    'ansible_architecture':'x86_64','ansible_service_mgr':'systemd','ansible_memtotal_mb':16384,
                    'ansible_facts':{'python':{'executable':sys.executable}},
                    'atc_release_archive':str(root/'missing.tar.gz'),'atc_release_sha256':'a'*64,
                    'atc_source_revision':'b'*40,'atc_release_version':'0.6.0',
                    'atc_postgres_image':'docker.io/library/postgres:16@sha256:'+'c'*64,
                    'loottool_v2_source_archive':str(root/'missing.tar.gz'),'loottool_v2_source_sha256':'a'*64,
                    'loottool_v2_source_revision':'b'*40,'loottool_v2_app_image':'example/app@sha256:'+'c'*64,
                    'loottool_v2_elasticsearch_image':'example/es@sha256:'+'d'*64,
                    'loottool_v2_python_image':'python@sha256:'+'e'*64}
                role_spec = ROLE.name
            else:
                tasks = yaml.safe_load((copied / 'tasks/main.yml').read_text())
                first = next(index for index, task in enumerate(tasks) if task['name'].startswith('Assess genuine Docker absence'))
                last = next(index for index, task in enumerate(tasks[first:], first) if task['name'] == 'Require supported Docker and Compose versions')
                (copied / 'tasks/main.yml').write_text(yaml.safe_dump(tasks[first:last+1], sort_keys=False))
                mode = 'absent' if case in ('absent','retained-no-docker') else 'existing'
                (copied / 'files/docker_presence.py').write_text('print(\'{"mode":"'+mode+'"}\')\n')
                variables = {'atc_before_docker': {'stdout': json.dumps({'mode': 'preflight' if case=='retained-no-docker' else 'install'})},
                    'loottool_v2_inspection': {'stdout': json.dumps({'existing': {} if case=='retained-no-docker' else None})}}
                role_spec = ROLE.name
            playbook = root / 'test.json'
            playbook.write_text(json.dumps([{'hosts':'localhost','gather_facts':False,'vars':variables,'roles':[role_spec]}]))
            environment = dict(os.environ, ANSIBLE_ROLES_PATH=str(roles), ANSIBLE_LOCAL_TEMP=str(root/'local'),
                               ANSIBLE_REMOTE_TEMP=str(root/'remote'), PATH=str(binary)+':'+os.environ['PATH'])
            result = subprocess.run([ANSIBLE,'-i','localhost,','-c','local',str(playbook)],
                                    capture_output=True,text=True,env=environment,timeout=60)
            return result.returncode, result.stdout+result.stderr

    def test_invalid_platform_cannot_reach_docker_role(self):
        code, output = self.run_role(case='bad-platform',full=True)
        self.assertNotEqual(code,0,output)
        self.assertNotIn('PREREQUISITE_STUB_REACHED',output)

    def test_invalid_artifact_cannot_reach_docker_role(self):
        code, output = self.run_role(case='bad-artifact',full=True)
        self.assertNotEqual(code,0,output)
        self.assertIn('controller before target writes' if ROLE.name == 'atc' else 'pinned application preflight',output)
        self.assertNotIn('PREREQUISITE_STUB_REACHED',output)

    def test_only_genuine_absence_selects_dependency_role(self):
        for case in ('absent','existing','stopped','old','missing-compose','retained-no-docker'):
            with self.subTest(case=case):
                code,output=self.run_role(case=case)
                self.assertEqual(code==0,case in ('absent','existing'),output)
                self.assertEqual('PREREQUISITE_STUB_REACHED' in output,case=='absent',output)


if __name__ == '__main__':
    unittest.main()
