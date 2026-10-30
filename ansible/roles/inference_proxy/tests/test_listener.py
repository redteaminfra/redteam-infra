# Copyright (c) 2026, Oracle and/or its affiliates.
"""Synthetic Linux proc fixtures only; no host service or socket manipulation."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROLE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_listener", ROLE / "files" / "check_listener.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ListenerPreflight(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "net").mkdir()
        (self.root / "net" / "tcp").write_text("header\n")
        (self.root / "123" / "fd").mkdir(parents=True)
        self.config = self.root / "config.toml"
        self.config.write_text('[server]\nhost="127.0.0.1"\nport=8787\n')
        (self.root / "123" / "environ").write_bytes(module.CONFIG_ENV.encode() + b"\0PYTHONUNBUFFERED=1\0")
        self.properties = {
            "LoadState": "loaded", "MainPID": "123", "Environment": module.CONFIG_ENV + " PYTHONUNBUFFERED=1",
            "EnvironmentFiles": "",
            "ExecStart": "{ path=" + module.SERVER_PATH + " ; argv[]=" + module.SERVER_PATH + " ; ignore_errors=no ; pid=123 ; code=(null) ; status=0/0 }",
        }

    def check(self, *, pid=123, **kwargs):
        properties = {**self.properties, "MainPID": str(pid)}
        return module.check_listener(8787, proc_root=self.root, properties=properties, config_path=self.config, **kwargs)

    def listener(self, address="0100007F", inode="456", protocol="tcp", port="2253"):
        (self.root / "net" / protocol).write_text(
            f"header\n0: {address}:{port} 00000000:0000 0A 0:0 00:0 0 0 0 {inode}\n"
        )

    def test_idle_port_without_running_service_needs_no_config_or_fd_access(self):
        self.config.unlink()
        self.properties["LoadState"] = "not-found"
        self.assertEqual(self.check(pid=0), {
            "occupied": False, "owned_by_service": False,
        })

    def test_stopped_alternate_config_unit_is_refused_with_missing_or_stale_config(self):
        self.properties["Environment"] = "INFERENCE_PROXY_CONFIG=/operator/alternate.toml"
        for present in (False, True):
            if present:
                self.config.write_text("# stale canonical config\n")
            else:
                self.config.unlink()
            with self.subTest(canonical_present=present), self.assertRaisesRegex(ValueError, "configuration binding"):
                self.check(pid=0)
            self.assertEqual(self.config.exists(), present)

    def test_stopped_alternate_command_unit_is_refused(self):
        self.properties["ExecStart"] = self.properties["ExecStart"].replace(module.SERVER_PATH, "/operator/server")
        with self.assertRaisesRegex(ValueError, "command"):
            self.check(pid=0)

    def test_stopped_canonical_unit_needs_original_configuration(self):
        self.config.unlink()
        with self.assertRaises(OSError):
            self.check(pid=0)

    def test_stopped_compatible_unit_is_accepted_without_proc_environment(self):
        (self.root / "123" / "environ").unlink()
        before = (self.config.read_bytes(), self.config.stat().st_mtime_ns)
        self.assertFalse(self.check(pid=0)["occupied"])
        self.assertEqual((self.config.read_bytes(), self.config.stat().st_mtime_ns), before)

    def test_masked_or_unknown_unit_is_not_a_fresh_install(self):
        for load_state in ("masked", "error", "bad-setting", ""):
            self.properties["LoadState"] = load_state
            with self.subTest(load_state=load_state), self.assertRaisesRegex(ValueError, "unit state"):
                self.check(pid=0)

    def test_existing_owned_loopback_listener_is_accepted(self):
        self.listener()
        (self.root / "123" / "fd" / "9").symlink_to("socket:[456]")
        before = (self.config.read_bytes(), self.config.stat().st_mtime_ns)
        self.assertEqual(self.check(), {
            "occupied": True, "owned_by_service": True,
        })
        self.assertEqual((self.config.read_bytes(), self.config.stat().st_mtime_ns), before)

    def test_alternate_config_unit_is_rejected_with_missing_or_stale_canonical_config(self):
        self.listener()
        (self.root / "123" / "fd" / "9").symlink_to("socket:[456]")
        self.properties["Environment"] = "INFERENCE_PROXY_CONFIG=/operator/alternate.toml"
        for present in (False, True):
            if present:
                self.config.write_text("# stale canonical config\n")
            else:
                self.config.unlink()
            with self.subTest(canonical_present=present), self.assertRaisesRegex(ValueError, "configuration binding"):
                self.check()
            self.assertEqual(self.config.exists(), present)
            if present:
                self.assertEqual(self.config.read_text(), "# stale canonical config\n")

    def test_owned_listener_requires_canonical_regular_configuration(self):
        self.listener()
        (self.root / "123" / "fd" / "9").symlink_to("socket:[456]")
        self.config.unlink()
        with self.assertRaises(OSError):
            self.check()
        self.config.symlink_to(self.root / "123" / "environ")
        with self.assertRaisesRegex(ValueError, "canonical configuration"):
            self.check()

    def test_execstart_requires_exact_server_path_and_no_arguments(self):
        self.listener()
        (self.root / "123" / "fd" / "9").symlink_to("socket:[456]")
        valid = self.properties["ExecStart"]
        for command in (
            valid.replace(module.SERVER_PATH, module.SERVER_PATH + "-alternate"),
            valid.replace(" ; ignore_errors", " --config /operator/alternate.toml ; ignore_errors"),
            valid + " ; " + valid,
            "{ path=/bin/sh ; argv[]=/bin/sh -c " + module.SERVER_PATH + " ; ignore_errors=no ; }",
        ):
            self.properties["ExecStart"] = command
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, "command"):
                self.check()

    def test_environment_binding_is_exact_not_a_substring(self):
        self.listener()
        (self.root / "123" / "fd" / "9").symlink_to("socket:[456]")
        for environment in (
            module.CONFIG_ENV + ".old", "PREFIX_" + module.CONFIG_ENV,
            module.CONFIG_ENV + " INFERENCE_PROXY_CONFIG=/other/config.toml",
            'OTHER="' + module.CONFIG_ENV + '"', "",
        ):
            self.properties["Environment"] = environment
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                self.check()

    def test_running_environment_must_also_match_unit_binding(self):
        self.listener()
        (self.root / "123" / "fd" / "9").symlink_to("socket:[456]")
        for environment in (b"INFERENCE_PROXY_CONFIG=/operator/alternate.toml\0", b"OTHER=1\0", b"missing-nul"):
            (self.root / "123" / "environ").write_bytes(environment)
            with self.subTest(environment=environment), self.assertRaisesRegex(ValueError, "binding"):
                self.check()
        self.properties["EnvironmentFiles"] = "/operator/environment (ignore_errors=no)"
        with self.assertRaisesRegex(ValueError, "environment files"):
            self.check()

    def test_running_service_on_another_port_is_not_adopted_as_idle_install(self):
        with self.assertRaisesRegex(ValueError, "does not own the requested listener"):
            self.check()

    def test_live_query_rejects_service_identity_change(self):
        self.listener()
        (self.root / "123" / "fd" / "9").symlink_to("socket:[456]")
        with patch.object(module, "service_properties", side_effect=[self.properties, {**self.properties, "MainPID": "124"}]):
            with self.assertRaisesRegex(ValueError, "identity changed"):
                module.check_listener(8787, proc_root=self.root, config_path=self.config)

    def test_systemctl_query_fails_closed_except_missing_unit(self):
        for returncode, stdout, accepted in (
            (1, "", False), (0, "MainPID=unknown\n", False),
            (1, "LoadState=not-found\nMainPID=0\n", True),
        ):
            with patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], returncode, stdout, "")):
                if accepted:
                    self.assertFalse(module.check_listener(8787, proc_root=self.root)["occupied"])
                else:
                    with self.assertRaises(ValueError):
                        module.check_listener(8787, proc_root=self.root)

    def test_foreign_or_inactive_service_listener_fails_closed(self):
        self.listener()
        for pid in (0, 123, 999):
            with self.subTest(pid=pid), self.assertRaises((ValueError, OSError)):
                self.check(pid=pid)

    def test_wildcard_nonloopback_and_ipv6_are_not_adopted(self):
        (self.root / "123" / "fd" / "9").symlink_to("socket:[456]")
        for address in ("00000000", "0100000A"):
            self.listener(address)
            with self.assertRaisesRegex(ValueError, "non-loopback"):
                self.check()
        (self.root / "net" / "tcp").write_text("header\n")
        self.listener("00000000000000000000000000000000", protocol="tcp6")
        with self.assertRaisesRegex(ValueError, "non-loopback"):
            self.check()

    def test_different_port_is_ignored_and_unreadable_tables_are_not_idle(self):
        self.listener(port="2254")
        self.assertFalse(self.check(pid=0)["occupied"])
        (self.root / "net" / "tcp").write_text("header\nbroken\n")
        with self.assertRaises(ValueError):
            self.check(pid=0)
        (self.root / "net" / "tcp").unlink()
        with self.assertRaises(OSError):
            self.check(pid=0)

    def test_fresh_config_preflight_needs_no_toml_site_package_or_example(self):
        target = self.root / "absent.toml"
        result = subprocess.run([
            sys.executable, "-S", str(ROLE / "files" / "configure.py"), "--check",
            str(target), "missing-example", "us-chicago-1", "synthetic-compartment", "8787",
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
