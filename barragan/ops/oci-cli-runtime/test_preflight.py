# Copyright (c) 2026, Oracle and/or its affiliates.
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("oci_runtime_preflight", Path(__file__).with_name("preflight.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SHA = "a" * 64


def lock(value="oci-cli==3.84.0", digest=SHA):
    return f"{value} \\\n    --hash=sha256:{digest}\n"


class PreflightTests(unittest.TestCase):
    def test_exact_hash_lock_parses(self):
        self.assertEqual(MODULE.parse_lock("# generated\n" + lock()), {"oci-cli": ("3.84.0", {SHA})})

    def test_direct_url_and_options_are_rejected(self):
        for value in ("oci-cli @ https://example.invalid/pkg.whl", "--extra-index-url https://example.invalid",
                      "-r other.txt", "oci-cli>=3.84.0", "oci-cli==3.84.0;python_version>'3'"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.parse_lock(value + "\n")

    def test_missing_hash_or_duplicate_package_is_rejected(self):
        for text in ("oci-cli==3.84.0\n", lock() + lock(), "oci-cli==3.84.0 \\\n    --hash=sha256:" + "z" * 64 + "\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                MODULE.parse_lock(text)

    def test_wheel_must_match_locked_digest_and_name(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "oci_cli-3.84.0-py3-none-any.whl"
            wheel.write_bytes(b"wheel contents")
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            with patch.object(MODULE, "safe_path"):
                MODULE.verify_wheelhouse(directory, MODULE.parse_lock(lock(digest=digest)))
                with self.assertRaisesRegex(ValueError, "digest differs"):
                    MODULE.verify_wheelhouse(directory, MODULE.parse_lock(lock()))
                wheel.rename(Path(directory) / "other-3.84.0-py3-none-any.whl")
                with self.assertRaisesRegex(ValueError, "not an exact locked"):
                    MODULE.verify_wheelhouse(directory, MODULE.parse_lock(lock(digest=digest)))

    def test_untrusted_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "unsafe artifact path"):
                MODULE.safe_path(directory, directory=True)


if __name__ == "__main__":
    unittest.main()
