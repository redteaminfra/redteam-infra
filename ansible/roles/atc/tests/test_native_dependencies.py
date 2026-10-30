# Copyright (c) 2026, Oracle and/or its affiliates.
"""Real Ansible branches with harmless package/Docker stand-ins, no host install."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ANSIBLE = os.environ.get('ROLE_GATE_ANSIBLE')
ROLE = Path(__file__).resolve().parents[1]


def tasks():
    import yaml
    return yaml.safe_load((ROLE/'tasks/main.yml').read_text())


class DependencyOrderingTests(unittest.TestCase):
    def test_dependency_mutations_follow_all_read_only_fences(self):
        values = tasks()
        names = [item['name'] for item in values]
        package = names.index("Supply only a fresh host's missing Ubuntu Python venv prerequisite")
        bootstrap = names.index('Prove private venv and pip bootstrap before Docker dependency changes')
        docker = names.index('Install Docker through the existing upstream role only when genuinely absent')
        cache = names.index('Cache only the exact PostgreSQL dependency for a fresh installation')
        for prefix in ('Validate the complete reviewed release', 'Check non-Docker prerequisites',
                       'Refuse to recreate missing Docker'):
            index = next(i for i, name in enumerate(names) if name.startswith(prefix))
            self.assertLess(index, package)
        self.assertLess(package, bootstrap)
        self.assertLess(bootstrap, docker)
        self.assertLess(names.index('Check prerequisites and retained identity without changing the host'), cache)
        block = values[package]['block']
        self.assertEqual(block[-1]['ansible.builtin.apt']['name'], 'python3.10-venv')
        self.assertEqual(block[-1]['ansible.builtin.apt']['state'], 'present')
        image = values[cache]
        self.assertIn("mode == 'install'", image['when'])
        self.assertEqual(image['block'][-1]['ansible.builtin.command']['argv'],
                         ['docker', 'image', 'pull', '{{ atc_postgres_image }}'])

    def test_diagnostics_are_private_bounded_and_precede_failure_and_cleanup(self):
        convergence = next(item for item in tasks() if item['name'].startswith('Converge through'))
        block = convergence['block']
        index = next(i for i, item in enumerate(block) if item['name'].startswith('Retain bounded'))
        self.assertTrue(block[index-1]['no_log'])
        receipt = block[index]
        self.assertTrue(receipt['no_log'])
        config = receipt['ansible.builtin.copy']
        self.assertEqual((config['dest'], config['owner'], config['group'], config['mode']),
                         ('/var/cache/atc/last-install-result.json', 'root', 'root', '0600'))
        self.assertIn('[:16384]', config['content'])
        self.assertTrue(block[index+1]['name'].startswith('Require successful'))
        self.assertEqual(convergence['always'][0]['ansible.builtin.file']['path'], '{{ atc_staging.path }}')


@unittest.skipUnless(ANSIBLE, 'set ROLE_GATE_ANSIBLE for isolated actual Ansible branches')
class NativeDependencyBranchTests(unittest.TestCase):
    def play(self, root, selected, variables, *, check=False):
        import yaml
        playbook = root/'play.yml'
        playbook.write_text(yaml.safe_dump([{'hosts':'localhost', 'gather_facts':False,
                                           'vars':variables, 'tasks':selected}], sort_keys=False))
        environment = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(root/'local'),
                           ANSIBLE_REMOTE_TEMP=str(root/'remote'))
        result = subprocess.run([ANSIBLE, '-i', 'localhost,', '-c', 'local', str(playbook)] +
                                (['--check'] if check else []), capture_output=True, text=True,
                                env=environment, timeout=90)
        return result.returncode, result.stdout+result.stderr

    def test_missing_venv_fresh_only_and_actual_bootstrap(self):
        for mode, missing, distro, check in [('install',True,True,False),
                ('install',False,True,False), ('preflight',True,True,False),
                ('install',True,False,False), ('install',True,True,True)]:
            with self.subTest(mode=mode,missing=missing,distro=distro,check=check), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                values = tasks()
                first = next(i for i, t in enumerate(values) if t['name'].startswith('Check complete Python'))
                last = next(i for i, t in enumerate(values) if t['name'].startswith('Prove private venv'))
                selected = copy.deepcopy(values[first:last+1])
                # Model missing distro module; execute the actual temporary-venv
                # proof using this controller's interpreter after a harmless apt stub.
                selected[0]['ansible.builtin.command']['argv'] = [sys.executable, '-c', 'raise SystemExit('+str(int(missing))+')']
                block = selected[1]['block']
                block[1]['ansible.builtin.command']['argv'] = [sys.executable, '-c', 'raise SystemExit('+str(int(not distro))+')']
                block[-1].pop('ansible.builtin.apt')
                block[-1]['ansible.builtin.debug'] = {'msg':'VENV_PACKAGE_STUB'}
                selected.append({'ansible.builtin.debug':{'msg':'BOOTSTRAP_SUCCEEDED'}})
                code, output = self.play(root, selected, {'atc_python_executable':sys.executable,
                    'atc_before_docker':{'stdout':json.dumps({'mode':mode})}}, check=check)
                success = mode=='install' and distro and not (missing and check)
                self.assertEqual(code==0, success, output)
                self.assertEqual('VENV_PACKAGE_STUB' in output, missing and success, output)
                self.assertEqual('BOOTSTRAP_SUCCEEDED' in output, success, output)

    def test_exact_postgres_cached_fresh_and_retained_branches(self):
        for mode, cached, check in [('install',False,False),('install',True,False),
                                   ('repair',False,False),('install',False,True)]:
            with self.subTest(mode=mode,cached=cached,check=check), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                event = root/'events'
                docker = root/'docker'
                docker.write_text('#!'+sys.executable+'\nimport sys\nfrom pathlib import Path\np=Path('+repr(str(event))+')\nwith p.open("a") as out: out.write(" ".join(sys.argv[1:])+"\\n")\nraise SystemExit('+str(0 if cached else 1)+' if sys.argv[2]=="inspect" else 0)\n')
                docker.chmod(0o755)
                selected = copy.deepcopy(next(t for t in tasks() if t['name'].startswith('Cache only the exact')))
                for item in selected['block']:
                    if 'ansible.builtin.command' in item:
                        item['ansible.builtin.command']['argv'][0] = str(docker)
                pin = 'docker.io/library/postgres:16@sha256:'+'a'*64
                code, output = self.play(root, [selected], {'atc_current_state':{'stdout':json.dumps({'mode':mode})},
                    'atc_postgres_image':pin}, check=check)
                self.assertEqual(code==0, not (mode=='install' and not cached and check), output)
                events = event.read_text() if event.exists() else ''
                self.assertEqual('image pull '+pin in events, mode=='install' and not cached and not check)
                self.assertEqual('image inspect' in events, mode=='install')

    def test_failed_installer_receipt_is_bounded_censored_and_survives_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root/'stage'; stage.mkdir()
            convergence = next(t for t in tasks() if t['name'].startswith('Converge through'))
            block = convergence['block']
            first = next(i for i, t in enumerate(block) if t['name'].startswith('Run only the supported'))
            selected = copy.deepcopy(block[first:first+3])
            selected[0]['ansible.builtin.command']['argv'] = [sys.executable, '-c',
                'import sys; print("PRIVATE-OUTPUT"+"x"*20000); print("PRIVATE-ERROR",file=sys.stderr); raise SystemExit(7)']
            selected[0]['changed_when'] = False
            receipt = root/'last-install-result.json'
            config = selected[1]['ansible.builtin.copy']
            config['dest'] = str(receipt)
            # Local fixture runs as the controller user; production owner/group
            # and cache path are independently asserted above.
            config.pop('owner'); config.pop('group')
            code, output = self.play(root, [{'block':selected,'always':copy.deepcopy(convergence['always'])}],
                {'atc_staging':{'path':str(stage)},'atc_source_revision':'a'*40,'atc_release_sha256':'b'*64})
            self.assertNotEqual(code,0,output)
            self.assertNotIn('PRIVATE-OUTPUT',output)
            self.assertNotIn('PRIVATE-ERROR',output)
            record = json.loads(receipt.read_text())
            self.assertEqual(record['rc'],7)
            self.assertEqual(len(record['stdout']),16384)
            self.assertTrue(record['stdoutTruncated'])
            self.assertEqual(record['stderr'],'PRIVATE-ERROR')
            self.assertEqual(receipt.stat().st_mode & 0o777,0o600)
            self.assertFalse(stage.exists())


if __name__ == '__main__':
    unittest.main()
