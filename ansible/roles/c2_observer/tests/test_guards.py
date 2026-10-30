# Copyright (c) 2026, Oracle and/or its affiliates.
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

FILES = Path(__file__).resolve().parents[1] / "files"
def load(name):
    spec = importlib.util.spec_from_file_location(name, FILES / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

archive = load("verify_archive")
lock = load("verify_lock")
preflight = load("preflight")
REV = "a" * 40
SHA = "b" * 64

class Guards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def source(self, extra=None):
        p = self.root / "source.tar.gz"
        with tarfile.open(p, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": REV}) as tar:
            for name in ["pyproject.toml", "src/c2_observer/__init__.py", "src/c2_observer/cli.py", "src/c2_observer/health.py"] + ([extra] if extra else []):
                member = tarfile.TarInfo(name)
                member.size = 1
                tar.addfile(member, io.BytesIO(b"x"))
        return p, hashlib.sha256(p.read_bytes()).hexdigest()

    def test_exact_archive_and_commit(self):
        p, sha = self.source()
        self.assertEqual(archive.verify(p, sha, REV)["members"], 4)
        with self.assertRaises(ValueError): archive.verify(p, sha, "c" * 40)
        with self.assertRaises(ValueError): archive.verify(p, SHA, REV)

    def test_traversal_refused(self):
        p, sha = self.source("../escape")
        with self.assertRaises(ValueError): archive.verify(p, sha, REV)

    def test_hashed_closure(self):
        p = self.root / "requirements.lock"
        text = "".join(name + "==1.0 --hash=sha256:" + SHA + "\n" for name in ("jsonschema", "rfc8785", "setuptools", "wheel"))
        p.write_text(text)
        self.assertEqual(lock.verify(p, hashlib.sha256(p.read_bytes()).hexdigest()), 4)
        for bad in [text + "--extra-index-url https://example.invalid\n", text.replace("==1.0", ">=1.0", 1), text + text]:
            p.write_text(bad)
            with self.assertRaises(ValueError): lock.verify(p, hashlib.sha256(p.read_bytes()).hexdigest())

    def test_lock_continuation(self):
        p = self.root / "requirements.lock"
        p.write_text("".join(n + "==1.0 " + chr(92) + "\n    --hash=sha256:" + SHA + "\n" for n in ("jsonschema", "rfc8785", "setuptools", "wheel")))
        self.assertEqual(lock.verify(p, hashlib.sha256(p.read_bytes()).hexdigest()), 4)

    def test_symlink_lock_refused(self):
        p = self.root / "target"; p.write_text("x")
        link = self.root / "link"; link.symlink_to(p)
        with self.assertRaises(ValueError): lock.verify(link, hashlib.sha256(b"x").hexdigest())

    def test_nonempty_unmanaged_install_refused_before_writes(self):
        # A canonical /opt path is required; inspect a real temporary tree while
        # bypassing only ancestor ownership/mode checks for this laptop fixture.
        root = self.root / "install"; root.mkdir(); (root / "existing").write_text("keep")
        realstat = Path.stat
        def stat(path, *a, **kw):
            original = realstat(path, *a, **kw)
            class Safe:
                st_uid = 0
                st_mode = original.st_mode & ~0o022
            return Safe()
        with patch.object(Path, "stat", stat):
            with self.assertRaises(ValueError): preflight.check(root, REV, SHA, SHA)
        self.assertEqual((root / "existing").read_text(), "keep")

    def test_same_intent_retry_and_changed_identity(self):
        root = self.root / "install"; root.mkdir()
        expected = dict(revision=REV, sourceSha256=SHA, dependencySha256=SHA)
        (root / ".artifact-intent.json").write_text(json.dumps(expected))
        realstat = Path.stat
        def stat(path, *a, **kw):
            original = realstat(path, *a, **kw)
            class Safe:
                st_uid = 0
                st_mode = original.st_mode & ~0o022
            return Safe()
        with patch.object(Path, "stat", stat):
            self.assertEqual(preflight.check(root, REV, SHA, SHA), expected)
            with self.assertRaises(ValueError): preflight.check(root, "c"*40, SHA, SHA)

    def test_pinned_release_symlink_refused(self):
        root = self.root / "install"; root.mkdir()
        (root / "releases").mkdir()
        (root / ".artifact-intent.json").write_text(json.dumps(dict(revision=REV, sourceSha256=SHA, dependencySha256=SHA)))
        outside = self.root / "outside"; outside.mkdir()
        (root / "releases" / REV).symlink_to(outside)
        realstat = Path.stat
        def stat(path, *a, **kw):
            original = realstat(path, *a, **kw)
            class Safe:
                st_uid = 0
                st_mode = original.st_mode & ~0o022
            return Safe()
        with patch.object(Path, "stat", stat):
            with self.assertRaises(ValueError): preflight.check(root, REV, SHA, SHA)
        self.assertEqual(list(outside.iterdir()), [])

    def test_dependency_install_disallows_build_isolation_downloads(self):
        tasks = (FILES.parent / "tasks/main.yml").read_text()
        self.assertIn("--only-binary=:all:", tasks)
        self.assertIn("c2_observer_dependency_health.rc", tasks)
        self.assertIn("not c2_observer_completed.stat.exists", tasks)

    def test_clear_environment_repairs_missing_pip_entrypoint(self):
        env = self.root / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(env)], check=True, capture_output=True)
        (env / "bin/pip").unlink()
        subprocess.run([sys.executable, "-m", "venv", "--clear", str(env)], check=True, capture_output=True)
        self.assertTrue((env / "bin/pip").is_file())
        result = subprocess.run([str(env / "bin/pip"), "--version"], check=True, capture_output=True)
        self.assertIn(b"pip", result.stdout)
        self.assertIn("venv, --clear, /opt/c2-observer/venv]", (FILES.parent / "tasks/main.yml").read_text())

if __name__ == "__main__": unittest.main()
