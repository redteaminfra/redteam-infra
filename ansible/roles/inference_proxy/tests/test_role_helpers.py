# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline safety/convergence tests. These do not prove Ubuntu installation."""

import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


ROLE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROLE / "files" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = load("verify_archive").verify
configure = load("configure").configure
REVISION = "a" * 40
COMPARTMENT = "ocid1.compartment.oc1..example"
REQUIRED = [
    "pyproject.toml", "config.example.toml", "src/oci_inference_proxy/__init__.py",
    "systemd/inference-proxy.service", "systemd/inference-proxy-purge.service",
    "systemd/inference-proxy-purge.timer",
]


class RoleHelpers(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def archive(self, extra=None, revision=REVISION):
        path = self.root / "source.tar.gz"
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": revision}) as archive:
            for name in REQUIRED:
                info = tarfile.TarInfo(name)
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b""))
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_exact_archive_passes(self):
        path, digest = self.archive()
        self.assertEqual(verify(path, digest, REVISION), {
            "revision": REVISION, "sha256": digest, "members": len(REQUIRED),
        })

    def test_checksum_and_revision_are_independent_fences(self):
        path, digest = self.archive()
        with self.assertRaisesRegex(ValueError, "SHA256"):
            verify(path, "b" * 64, REVISION)
        with self.assertRaisesRegex(ValueError, "provenance"):
            verify(path, digest, "b" * 40)

    def test_symlink_and_escape_members_are_rejected(self):
        for name in ("../escape", "/absolute", "source/../../escape"):
            with self.subTest(name=name):
                path, digest = self.archive(tarfile.TarInfo(name))
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    verify(path, digest, REVISION)
        link = tarfile.TarInfo("symlink")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        path, digest = self.archive(link)
        with self.assertRaisesRegex(ValueError, "regular"):
            verify(path, digest, REVISION)

    def test_duplicate_paths_are_rejected(self):
        path, digest = self.archive(tarfile.TarInfo(REQUIRED[0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify(path, digest, REVISION)

    def test_equivalent_duplicate_paths_are_rejected(self):
        path, digest = self.archive(tarfile.TarInfo("src/./oci_inference_proxy/__init__.py"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify(path, digest, REVISION)

    def test_configuration_preserves_operator_policy_and_is_unchanged_on_reapply(self):
        example = self.root / "example.toml"
        example.write_text('[server]\nhost="127.0.0.1"\nport=8787\n[oci]\nregion="old"\ncompartment_id="old"\nauth="instance_principal"\n[limits]\nper_agent_rpm=42\n[aliases]\ncustom="operator-model"\n')
        target = self.root / "config.toml"
        self.assertTrue(configure(target, example, "us-chicago-1", COMPARTMENT, "8787")["changed"])
        contents = target.read_text()
        self.assertIn('custom="operator-model"', contents)
        self.assertIn("per_agent_rpm=42", contents)
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        before = target.stat().st_mtime_ns
        self.assertFalse(configure(target, example, "us-chicago-1", COMPARTMENT, "8787")["changed"])
        self.assertEqual(target.stat().st_mtime_ns, before)
        with self.assertRaisesRegex(ValueError, "operator migration"):
            configure(target, example, "us-chicago-1", COMPARTMENT, "8788")
        self.assertEqual(target.read_text(), contents)

    def test_existing_region_and_compartment_are_not_implicitly_migrated(self):
        example = self.root / "example.toml"
        example.write_text('[server]\nport=8787\n[oci]\nregion="us-chicago-1"\ncompartment_id="old"\n')
        target = self.root / "config.toml"
        configure(target, example, "us-chicago-1", COMPARTMENT, "8787")
        before = target.read_bytes()
        for region, compartment in (("us-phoenix-1", COMPARTMENT), ("us-chicago-1", "new")):
            with self.subTest(region=region, compartment=compartment):
                with self.assertRaisesRegex(ValueError, "operator migration"):
                    configure(target, example, region, compartment, "8787")
                self.assertEqual(target.read_bytes(), before)

    def test_preflight_is_read_only_for_existing_and_missing_configuration(self):
        example = self.root / "example.toml"
        example.write_text('[server]\nport=8787\n[oci]\ncompartment_id="old"\n')
        target = self.root / "config.toml"
        self.assertFalse(configure(target, "missing-example", "us-chicago-1", COMPARTMENT, "8787", check_only=True)["changed"])
        self.assertFalse(target.exists())
        configure(target, example, "us-chicago-1", COMPARTMENT, "8787")
        before = target.stat().st_mtime_ns
        self.assertFalse(configure(target, "missing-example", "us-chicago-1", COMPARTMENT, "8787", check_only=True)["changed"])
        self.assertEqual(target.stat().st_mtime_ns, before)

    def test_preflight_tasks_precede_mutation_and_do_not_hash_pepper(self):
        tasks = (ROLE / "tasks" / "main.yml").read_text()
        mutation = tasks.index("- name: Install native prerequisites")
        for name in (
            "Reject implicit configuration migration", "Verify requested listener is idle",
            "Refuse unsafe existing pepper", "Refuse to replace missing credentials",
        ):
            self.assertLess(tasks.index("- name: " + name), mutation)
        retained = tasks[tasks.index("- name: Inspect retained authentication"):]
        retained = retained[:retained.index("- name: Refuse")]
        self.assertIn("get_checksum: false", retained)


    def test_custom_storage_is_not_migrated_or_overwritten(self):
        target = self.root / "config.toml"
        original = '[storage]\ndatabase="/operator/proxy.db"\n'
        target.write_text(original)
        with self.assertRaisesRegex(ValueError, "migration"):
            configure(target, "unused", "us-chicago-1", COMPARTMENT, "8787")
        self.assertEqual(target.read_text(), original)

    def test_invalid_configuration_is_preserved(self):
        target = self.root / "config.toml"
        target.write_text("[broken")
        with self.assertRaises(ValueError):
            configure(target, "unused", "us-chicago-1", COMPARTMENT, "8787")
        self.assertEqual(target.read_text(), "[broken")

    def test_existing_authentication_is_not_silently_converted(self):
        target = self.root / "config.toml"
        original = '[oci]\nauth="config_file"\nconfig_file="/operator/oci/config"\n'
        target.write_text(original)
        with self.assertRaisesRegex(ValueError, "authentication requires operator migration"):
            configure(target, "unused", "us-chicago-1", COMPARTMENT, "8787")
        self.assertEqual(target.read_text(), original)


if __name__ == "__main__":
    unittest.main()
