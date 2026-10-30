# Copyright (c) 2026, Oracle and/or its affiliates.
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("self-check.py")
SPEC = importlib.util.spec_from_file_location("oci_runtime_self_check", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
LIVE = "ocid1.vcn.oc1.aaalive"
RETIRED = "ocid1.vcn.oc1.aaaretired"
COMPARTMENT = "ocid1.compartment.oc1.aaaexample"


class SelfCheckTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.executable = Path(self.temporary.name) / "oci"
        self.executable.write_text("#!/bin/sh\nexit 0\n")
        self.executable.chmod(0o755)
        self.argv = ["self-check.py", "--oci", str(self.executable),
                     "--region", "us-sanjose-1", "--compartment-id", COMPARTMENT,
                     "--live-kind", "vcn", "--live-id", LIVE,
                     "--retired-kind", "vcn", "--retired-id", RETIRED]

    def fake_run(self, argv):
        if argv[-1] == "--version":
            return (0, "3.84.0\n", "")
        if "list" in argv:
            return (0, '{"data": [{"id": "' + LIVE + '"}]}' if "vcn" in argv else '{"data": []}', "")
        if LIVE in argv:
            return (0, '{"data": {"id": "' + LIVE + '", "compartment-id": "' + COMPARTMENT + '"}}', "")
        return (1, "", 'ServiceError: {"status": 404, "code": "NotAuthorizedOrNotFound"}')

    def test_all_read_shapes_pass(self):
        with patch.object(sys, "argv", self.argv), patch.object(MODULE, "run", side_effect=self.fake_run), patch.object(MODULE, "require_service_environment"):
            MODULE.main()

    def test_wrong_list_visibility_fails(self):
        def missing_live(argv):
            result = self.fake_run(argv)
            if "list" in argv and "vcn" in argv:
                return (0, '{"data": []}', "")
            return result
        with patch.object(sys, "argv", self.argv), patch.object(MODULE, "run", side_effect=missing_live), patch.object(MODULE, "require_service_environment"):
            with self.assertRaisesRegex(ValueError, "visibility differ"):
                MODULE.main()

    def test_wrong_404_shape_fails(self):
        def wrong_404(argv):
            if RETIRED in argv:
                return (1, "", 'ServiceError: {"status": 403, "code": "NotAuthorizedOrNotFound"}')
            return self.fake_run(argv)
        with patch.object(sys, "argv", self.argv), patch.object(MODULE, "run", side_effect=wrong_404), patch.object(MODULE, "require_service_environment"):
            with self.assertRaisesRegex(ValueError, "status differs"):
                MODULE.main()

    def test_malformed_id_fails_before_cloud_read(self):
        argv = [RETIRED + "bad" if part == RETIRED else part for part in self.argv]
        argv[argv.index("--retired-kind") + 1] = "instance"
        with patch.object(sys, "argv", argv), patch.object(MODULE, "run") as runner, patch.object(MODULE, "require_service_environment"):
            with self.assertRaisesRegex(ValueError, "kind differs"):
                MODULE.main()
            runner.assert_not_called()

    def test_wrong_user_fails_before_cloud_read(self):
        with patch.object(MODULE.pwd, "getpwnam", return_value=type("User", (), {"pw_uid": 1001})()), patch.object(MODULE.os, "geteuid", return_value=0), patch.object(MODULE, "run") as runner:
            with self.assertRaisesRegex(ValueError, "run as barragan"):
                MODULE.main()
            runner.assert_not_called()

    def test_inherited_environment_fails_before_cloud_read(self):
        with patch.object(MODULE.pwd, "getpwnam", return_value=type("User", (), {"pw_uid": 1001})()), patch.object(MODULE.os, "geteuid", return_value=1001), patch.dict(MODULE.os.environ, {"OCI_METADATA_BASE_URL": "http://evil"}), patch.object(MODULE, "run") as runner:
            with self.assertRaisesRegex(ValueError, "clean environment"):
                MODULE.main()
            runner.assert_not_called()

    def test_exact_urllib3_filter_is_required_and_other_warnings_fail(self):
        with patch.object(MODULE.pwd, "getpwnam", return_value=type("User", (), {"pw_uid": 1001})()), patch.object(MODULE.os, "geteuid", return_value=1001), patch.dict(MODULE.os.environ, MODULE.EXPECTED_ENVIRONMENT, clear=True):
            MODULE.require_service_environment()
            with patch.dict(MODULE.os.environ, {"PYTHONWARNINGS": "ignore::FutureWarning"}):
                with self.assertRaisesRegex(ValueError, "clean environment"):
                    MODULE.require_service_environment()
        with self.assertRaisesRegex(ValueError, "unexpected stderr"):
            MODULE.check_json(0, '{"data": []}', "WARNING: unrelated\n", list)
        with self.assertRaisesRegex(ValueError, "unexpected stderr"):
            MODULE.check_json(0, '{"data": []}', "FutureWarning: strict\n", list)


if __name__ == "__main__":
    unittest.main()
