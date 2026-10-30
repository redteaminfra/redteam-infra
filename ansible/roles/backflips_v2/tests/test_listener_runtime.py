# Copyright (c) 2026, Oracle and/or its affiliates.
import configparser
import importlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROLE_ROOT = Path(__file__).resolve().parents[1]
FLIP_FILES = ROLE_ROOT / "files" / "flip_files"

fake_settings = types.ModuleType("sshbackflip.settings")
fake_settings.BACKFLIPS_BASE_DIR = Path("/opt/backflips")
fake_settings.BACKFLIPS_DB = Path("/opt/backflips/etc/backflips_db")
fake_settings.BACKFLIP_IP = "127.0.0.1"
fake_settings.BACKFLIP_PORT = "2222"
fake_settings.BACKFLIP_SERVER = "example.invalid"
fake_settings.BACKFLIP_USER = "flip"
fake_settings.AUTHORIZED_KEYS = Path("/opt/backflips/etc/authorized_keys")
fake_settings.CONTAINERS_DIR = Path("/opt/backflips/containers")
fake_settings.KEYS_DIR = Path("/opt/backflips/keys")
fake_settings.MIDDLE_IP = ""
fake_settings.MIDDLE_USER = "sketchssh"
fake_settings.MIDDLE_KEY_PATH = "/opt/ssh-proxy/keys/sketchkey"
fake_settings.config = configparser.ConfigParser()
fake_settings.configPath = "/tmp/backflips.conf"
sys.modules["sshbackflip.settings"] = fake_settings
sys.path.insert(0, str(FLIP_FILES))
core = importlib.import_module("sshbackflip.core")


class ListenerRuntimeTests(unittest.TestCase):
    def test_compose_uses_dns_safe_alias_and_isolated_listener_config(self):
        rendered = json.loads(
            core.render_listener_compose(
                "Example Listener",
                "203.0.113.10",
                "2222",
                "flip",
                "198.51.100.20",
                "sketchssh",
                "/opt/ssh-proxy/keys/example",
            )
        )

        listener = rendered["services"]["backflip_example-listener"]
        autossh = rendered["services"]["autossh_example-listener"]
        network = "listener_example-listener"

        self.assertEqual(
            listener["networks"][network]["aliases"],
            ["listener-example-listener"],
        )
        self.assertEqual(
            listener["volumes"],
            ["/opt/backflips/etc/ssh/example-listener:/config"],
        )
        self.assertNotIn(str(core.settings.AUTHORIZED_KEYS), listener["volumes"])
        forward_index = autossh["command"].index("-R") + 1
        self.assertEqual(
            autossh["command"][forward_index],
            "2222:listener-example-listener:2222",
        )

    def test_add_server_accepts_an_ip_callback_host(self):
        config = configparser.ConfigParser()
        with (
            mock.patch.object(core, "create_listener_project", return_value="172.18.0.2"),
            mock.patch.object(core, "commit_server_config"),
        ):
            core.add_server(
                "example",
                "203.0.113.10",
                "2222",
                "flip",
                middleIP="198.51.100.20",
                config=config,
            )

        self.assertEqual(config.get("example", "callbackHost"), "203.0.113.10")

    def test_add_server_rolls_back_runtime_when_config_persistence_fails(self):
        config = configparser.ConfigParser()
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_dir = Path(temporary_directory) / "project"
            config_dir = Path(temporary_directory) / "config"
            project_dir.mkdir()
            config_dir.mkdir()
            with (
                mock.patch.object(core, "create_listener_project", return_value="172.18.0.2"),
                mock.patch.object(core, "commit_server_config", side_effect=OSError("disk full")),
                mock.patch.object(core, "_docker_compose") as compose,
                mock.patch.object(core, "listener_project_dir", return_value=project_dir),
                mock.patch.object(core, "listener_config_dir", return_value=config_dir),
                self.assertRaisesRegex(OSError, "disk full"),
            ):
                core.add_server(
                    "example",
                    "203.0.113.10",
                    "2222",
                    "flip",
                    middleIP="198.51.100.20",
                    config=config,
                )

            compose.assert_called_once_with(
                "example",
                "down",
                "--remove-orphans",
                check=False,
            )
            self.assertFalse(project_dir.exists())
            self.assertFalse(config_dir.exists())
            self.assertFalse(config.has_section("example"))

    def test_create_listener_project_starts_runtime_and_returns_container_ip(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            key_path = root / "sketch-key"
            key_path.touch()
            authorized_keys = root / "authorized_keys"
            authorized_keys.write_text("ssh-ed25519 example\n")

            with (
                mock.patch.object(core.settings, "CONTAINERS_DIR", root / "containers"),
                mock.patch.object(core.settings, "BACKFLIPS_BASE_DIR", root),
                mock.patch.object(core.settings, "AUTHORIZED_KEYS", authorized_keys),
                mock.patch.object(core, "_docker_compose") as compose,
                mock.patch.object(core, "wait_for_listener_runtime", return_value="172.18.0.2") as wait,
            ):
                internal_ip = core.create_listener_project(
                    "example",
                    "203.0.113.10",
                    "2222",
                    "flip",
                    "198.51.100.20",
                    "sketchssh",
                    str(key_path),
                )

            self.assertEqual(internal_ip, "172.18.0.2")
            compose.assert_called_once_with("example", "up", "--detach", "--build")
            wait.assert_called_once_with("example")
            listener_config = root / "etc" / "ssh" / "example"
            self.assertEqual(
                (listener_config / ".ssh" / "authorized_keys").read_text(),
                "ssh-ed25519 example\n",
            )
            self.assertTrue((listener_config / "sshd" / "sshd_config").is_file())

    def test_sync_listener_authorized_keys_updates_active_listener_copies(self):
        config = configparser.ConfigParser()
        config.add_section("one")
        config.add_section("two")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            canonical = root / "authorized_keys"
            canonical.write_text("ssh-ed25519 new-key\n")
            for name in config.sections():
                destination = root / name / ".ssh" / "authorized_keys"
                destination.parent.mkdir(parents=True)
                destination.write_text("ssh-ed25519 old-key\n")

            with (
                mock.patch.object(core.settings, "AUTHORIZED_KEYS", canonical),
                mock.patch.object(
                    core,
                    "listener_config_dir",
                    side_effect=lambda name: root / name,
                ),
            ):
                core.sync_listener_authorized_keys(config)

            for name in config.sections():
                destination = root / name / ".ssh" / "authorized_keys"
                self.assertEqual(destination.read_text(), "ssh-ed25519 new-key\n")
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_listener_status_requires_listener_and_autossh(self):
        with mock.patch.object(
            core.subprocess,
            "run",
            side_effect=[
                mock.Mock(returncode=0, stdout="running 172.18.0.2\n"),
                mock.Mock(returncode=0, stdout="running\n"),
            ],
        ):
            self.assertEqual(core.listener_status("example"), ("running", "172.18.0.2"))

    def test_listener_status_reports_degraded_when_autossh_is_not_running(self):
        with mock.patch.object(
            core.subprocess,
            "run",
            side_effect=[
                mock.Mock(returncode=0, stdout="running 172.18.0.2\n"),
                mock.Mock(returncode=0, stdout="restarting\n"),
            ],
        ):
            self.assertEqual(
                core.listener_status("example"),
                ("degraded (listener=running, autossh=restarting)", "172.18.0.2"),
            )

    def test_wait_for_listener_runtime_rejects_autossh_failure(self):
        with (
            mock.patch.object(
                core,
                "listener_status",
                return_value=("degraded (listener=running, autossh=exited)", "172.18.0.2"),
            ),
            mock.patch.object(core.time, "sleep"),
            self.assertRaisesRegex(RuntimeError, "autossh=exited"),
        ):
            core.wait_for_listener_runtime("example", attempts=2, interval=0)

    def test_wait_for_listener_runtime_requires_two_healthy_observations(self):
        with (
            mock.patch.object(
                core,
                "listener_status",
                side_effect=[
                    ("degraded (listener=running, autossh=restarting)", "172.18.0.2"),
                    ("running", "172.18.0.2"),
                    ("running", "172.18.0.2"),
                ],
            ) as status,
            mock.patch.object(core.time, "sleep"),
        ):
            self.assertEqual(
                core.wait_for_listener_runtime("example", attempts=3, interval=0),
                "172.18.0.2",
            )

        self.assertEqual(status.call_count, 3)

    def test_remove_server_cleans_stale_project_without_config_section(self):
        config = configparser.ConfigParser()
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_dir = Path(temporary_directory) / "listener"
            project_dir.mkdir()
            (project_dir / "docker-compose.yml").touch()
            with (
                mock.patch.object(core, "_docker_compose") as compose,
                mock.patch.object(core, "listener_project_dir", return_value=project_dir),
                mock.patch.object(core, "listener_config_dir", return_value=Path(temporary_directory) / "config"),
                mock.patch.object(
                    core,
                    "listener_compose_path",
                    return_value=project_dir / "docker-compose.yml",
                ),
            ):
                core.remove_server("missing", config=config)

            compose.assert_called_once_with("missing", "down", "--remove-orphans")
            self.assertFalse(project_dir.exists())

    def test_remove_server_preserves_state_when_compose_fails(self):
        config = configparser.ConfigParser()
        config.add_section("example")
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_dir = Path(temporary_directory) / "listener"
            project_dir.mkdir()
            compose_path = project_dir / "docker-compose.yml"
            compose_path.touch()
            failure = core.subprocess.CalledProcessError(
                1,
                ["docker", "compose", "down"],
                stderr="daemon unavailable",
            )
            with (
                mock.patch.object(core, "_docker_compose", side_effect=failure),
                mock.patch.object(core, "listener_project_dir", return_value=project_dir),
                mock.patch.object(core, "listener_config_dir", return_value=Path(temporary_directory) / "config"),
                mock.patch.object(core, "listener_compose_path", return_value=compose_path),
                mock.patch.object(core, "commit_server_config") as commit,
                self.assertRaises(SystemExit),
            ):
                core.remove_server("example", config=config)

            self.assertTrue(project_dir.exists())
            self.assertTrue(config.has_section("example"))
            commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
