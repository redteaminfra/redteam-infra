# Copyright (c) 2026, Oracle and/or its affiliates.
"""Execute the role's real stat/assert preflight on synthetic local paths only.

Requires Ansible beside the test interpreter; otherwise explicitly skipped.
This is not a full native role installation or reapply test.
"""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:
    yaml = None


ROLE = Path(__file__).resolve().parents[1]
ANSIBLE = Path(sys.executable).parent / "ansible-playbook"


@unittest.skipUnless(ANSIBLE.is_file() and yaml is not None, "requires Ansible and PyYAML in the test environment")
class RetainedStatePreflight(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.pepper = self.root / "pepper"
        self.database = self.root / "proxy.db"
        self.marker = self.root / "mutation-marker"

    def run_guard(self, *, accepted=False, config=False):
        names = {
            "Inspect retained authentication and metering state before changes",
            "Refuse unsafe existing pepper even without a database",
            "Refuse to replace missing credentials or configuration for an existing database",
        }
        tasks = [copy.deepcopy(task) for task in yaml.safe_load((ROLE / "tasks/main.yml").read_text()) if task["name"] in names]
        self.assertEqual(len(tasks), 3)
        tasks[0]["loop"] = [str(self.pepper), str(self.database)]
        tasks.append({"name": "Synthetic mutation sentinel after all guards", "ansible.builtin.copy": {
            "content": "guard accepted\n", "dest": str(self.marker), "mode": "0600",
        }})
        playbook = self.root / "preflight.json"
        playbook.write_text(json.dumps([{
            "hosts": "localhost", "gather_facts": False, "connection": "local",
            "vars": {"ansible_python_interpreter": sys.executable,
                     "inference_proxy_existing_config": {"stat": {"exists": config}}},
            "tasks": tasks,
        }]))
        env = {**os.environ, "ANSIBLE_LOCAL_TEMP": str(self.root / "ansible-local"),
               "ANSIBLE_REMOTE_TEMP": str(self.root / "ansible-remote"), "ANSIBLE_NOCOLOR": "1"}
        result = subprocess.run([str(ANSIBLE), "-i", "localhost,", str(playbook)],
                                capture_output=True, text=True, timeout=30, env=env, cwd=self.root)
        self.assertEqual(result.returncode, 0 if accepted else 2, result.stdout + result.stderr)
        self.assertEqual(self.marker.exists(), accepted)
        if not accepted:
            self.assertIn('"evaluated_to": false', result.stdout)
            self.assertNotIn("Synthetic mutation sentinel", result.stdout)

    def test_no_database_symlink_pepper_is_refused_without_touching_target(self):
        target = self.root / "unrelated"
        target.write_bytes(b"unrelated file preserved" * 2)
        target.chmod(0o600)
        before = (target.read_bytes(), target.stat())
        self.pepper.symlink_to(target)
        self.run_guard()
        after = (target.read_bytes(), target.stat())
        self.assertEqual(before, after)
        self.assertTrue(self.pepper.is_symlink())

    def test_no_database_dangling_pepper_symlink_is_refused(self):
        target = self.root / "absent-target"
        self.pepper.symlink_to(target)
        self.run_guard()
        self.assertTrue(self.pepper.is_symlink())
        self.assertFalse(target.exists())

    def test_no_database_directory_pepper_is_refused(self):
        self.pepper.mkdir()
        before = self.pepper.stat()
        self.run_guard()
        self.assertEqual(before, self.pepper.stat())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires a local FIFO fixture")
    def test_no_database_fifo_pepper_is_refused_without_opening(self):
        os.mkfifo(self.pepper)
        before = self.pepper.stat()
        self.run_guard()
        self.assertEqual(before, self.pepper.stat())

    def test_no_database_short_regular_pepper_is_refused(self):
        self.pepper.write_bytes(b"short")
        self.run_guard()
        self.assertEqual(self.pepper.read_bytes(), b"short")

    def test_no_database_regular_pepper_is_preserved_and_accepted(self):
        self.pepper.write_bytes(b"synthetic fixture pepper" * 2)
        before = (self.pepper.read_bytes(), self.pepper.stat())
        self.run_guard(accepted=True)
        self.assertEqual(before, (self.pepper.read_bytes(), self.pepper.stat()))

    def test_fresh_install_without_pepper_or_database_is_accepted(self):
        self.run_guard(accepted=True)
        self.assertFalse(self.pepper.exists())
        self.assertFalse(self.database.exists())

    def test_database_without_original_configuration_is_refused(self):
        self.database.write_bytes(b"synthetic database fixture")
        self.pepper.write_bytes(b"synthetic fixture pepper" * 2)
        self.run_guard(config=False)

    def test_database_without_original_pepper_is_refused(self):
        self.database.write_bytes(b"synthetic database fixture")
        self.run_guard(config=True)

    def test_database_with_original_configuration_and_pepper_is_accepted(self):
        self.database.write_bytes(b"synthetic database fixture")
        self.pepper.write_bytes(b"synthetic fixture pepper" * 2)
        self.run_guard(config=True, accepted=True)


if __name__ == "__main__":
    unittest.main()
