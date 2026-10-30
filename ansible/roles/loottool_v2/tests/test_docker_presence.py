# Copyright (c) 2026, Oracle and/or its affiliates.
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location('docker_presence', Path(__file__).resolve().parents[1] / 'files/docker_presence.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DockerPresenceTests(unittest.TestCase):
    def assess(self, *, executables=(), footprints=(), packages='', units='', unit_error=None):
        def run(argv, **kwargs):
            if argv[0] == 'dpkg-query':
                return SimpleNamespace(stdout=packages)
            if argv[0] == 'systemctl':
                # Ubuntu 22's empty pattern query returned 1 in the live failure.
                # Only the unfiltered inventory is reliable; do not ignore rc1.
                if any('*' in item for item in argv):
                    raise subprocess.CalledProcessError(1, argv, output='', stderr='')
                self.assertEqual(argv, ['systemctl', 'list-unit-files', '--no-pager', '--no-legend'])
                self.assertTrue(kwargs['check'])
                self.assertEqual(kwargs['timeout'], 15)
                if unit_error is not None:
                    raise unit_error
                return SimpleNamespace(stdout=units)
            self.fail('only read-only inventory commands are permitted')
        with patch.object(module.os, 'geteuid', return_value=0), \
             patch.object(module.shutil, 'which', side_effect=lambda name: '/usr/bin/'+name if name in executables else None), \
             patch.object(module.os.path, 'lexists', side_effect=lambda name: name in footprints), \
             patch.object(module.subprocess, 'run', side_effect=run):
            return module.assess()

    def test_genuine_absence_only(self):
        self.assertEqual(self.assess(packages='bash\tinstalled\n'), {'mode': 'absent'})

    def test_any_existing_client_never_invites_install_or_start(self):
        # Healthy, stopped, old or incomplete engines share this non-install path;
        # read-only daemon/Compose version gates decide whether Apply may proceed.
        self.assertEqual(self.assess(executables={'docker'}), {'mode': 'existing'})

    def test_existing_runtime_executables_refused(self):
        for name in module.EXECUTABLES:
            with self.subTest(executable=name), self.assertRaises(ValueError):
                self.assess(executables={name})

    def test_socket_and_orphaned_state_or_configuration_refused(self):
        for path in module.FOOTPRINTS:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.assess(footprints={path})

    def test_installed_and_residual_runtime_packages_refused(self):
        for name in ('docker-ce', 'docker.io', 'docker-ce-cli:amd64', 'containerd.io', 'moby-engine', 'runc', 'podman-docker'):
            for status in ('installed', 'config-files'):
                with self.subTest(package=name, status=status), self.assertRaises(ValueError):
                    self.assess(packages=name+'\t'+status+'\n')

    def test_service_units_and_unknown_inventory_refused(self):
        with self.assertRaises(ValueError):
            self.assess(units='docker.socket enabled enabled\n')
        with patch.object(module.os, 'geteuid', return_value=0), \
             patch.object(module.shutil, 'which', return_value=None), \
             patch.object(module.os.path, 'lexists', return_value=False), \
             patch.object(module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('dpkg-query', 15)):
            with self.assertRaises(subprocess.TimeoutExpired):
                module.assess()

    def test_full_inventory_ignores_unrelated_units_and_accepts_no_matches(self):
        self.assertEqual(self.assess(units='ssh.service enabled enabled\ncron.service enabled enabled\n'),
                         {'mode': 'absent'})
        self.assertEqual(self.assess(), {'mode': 'absent'})

    def test_full_inventory_refuses_any_runtime_unit_state(self):
        for name in ('docker.service', 'docker.socket', 'containerd.service',
                     'moby.service', 'podman.socket', 'podman-auto-update.timer'):
            with self.subTest(unit=name), self.assertRaises(ValueError):
                self.assess(units='ssh.service enabled enabled\n'+name+' disabled disabled\n')

    def test_full_inventory_failure_and_bounds_remain_fail_closed(self):
        for failure in (subprocess.CalledProcessError(1, 'systemctl', output='', stderr=''),
                        subprocess.TimeoutExpired('systemctl', 15)):
            with self.subTest(failure=type(failure).__name__), self.assertRaises(type(failure)):
                self.assess(unit_error=failure)
        for inventory in ('x' * (1024 * 1024 + 1), 'malformed\n'):
            with self.assertRaises(ValueError):
                self.assess(units=inventory)

    def test_root_is_required_before_any_inventory(self):
        with patch.object(module.os, 'geteuid', return_value=1000), self.assertRaises(ValueError):
            module.assess()


if __name__ == '__main__':
    unittest.main()
