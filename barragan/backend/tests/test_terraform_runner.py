# Copyright (c) 2026, Oracle and/or its affiliates.
from unittest.mock import patch

import pytest

from app.integrations.terraform_runner import LocalTerraformCommandRunner, _variable_args


def test_variable_args_passes_strings_without_json_quoting():
    args = _variable_args(
        {
            "edge_regions": ["us-sea"],
            "edge_count_per_region": 1,
            "ssh_pub_key_path": "/var/lib/barragan/ssh/barragan_testing.pub",
        }
    )

    assert args == [
        "-var",
        'edge_count_per_region=1',
        "-var",
        'edge_regions=["us-sea"]',
        "-var",
        "ssh_pub_key_path=/var/lib/barragan/ssh/barragan_testing.pub",
    ]


def test_provider_firewall_apply_can_be_narrowed_without_refreshing_compute(tmp_path):
    with patch("subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        LocalTerraformCommandRunner().run(
            "apply",
            working_directory=str(tmp_path),
            env={},
            variables={"allowed_udp_ports": ["53"]},
            targets=("linode_firewall.firewall",),
            refresh=False,
        )

    args = run.call_args.args[0]
    assert "-refresh=false" in args
    assert "-target=linode_firewall.firewall" in args
    assert args[0:2] == ["terraform", "apply"]


def test_plan_is_non_mutating_and_reports_a_detailed_change_exit_code(tmp_path):
    with patch("subprocess.run") as run:
        run.return_value.returncode = 2
        run.return_value.stdout = "Plan: 1 to add, 0 to change, 0 to destroy."
        run.return_value.stderr = ""
        result = LocalTerraformCommandRunner().run(
            "plan",
            working_directory=str(tmp_path),
            env={},
            variables={"edge_regions": ["us-dal"]},
            targets=("linode_instance.edge",),
            refresh=False,
        )

    args = run.call_args.args[0]
    assert args[0:5] == ["terraform", "plan", "-input=false", "-detailed-exitcode", "-json"]
    assert "-refresh=false" in args
    assert "-target=linode_instance.edge" in args
    assert result.returncode == 2


def test_retained_workspace_init_uses_readonly_lockfile(tmp_path):
    with patch("subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        LocalTerraformCommandRunner().run(
            "init", working_directory=str(tmp_path), env={}, readonly_lock=True, backend=False
        )
    assert run.call_args.args[0] == ["terraform", "init", "-input=false", "-backend=false", "-lockfile=readonly"]


def test_terraform_version_is_machine_readable_and_rejects_planning_options(tmp_path):
    with patch("subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = '{}'
        run.return_value.stderr = ""
        LocalTerraformCommandRunner().run("version", working_directory=str(tmp_path), env={})
    assert run.call_args.args[0] == ["terraform", "version", "-json"]
    with pytest.raises(ValueError, match="does not accept"):
        LocalTerraformCommandRunner().run(
            "version", working_directory=str(tmp_path), env={}, targets=("x.y",)
        )


@pytest.mark.parametrize(
    "command,options",
    [
        ("init", {"targets": ("x.y",)}),
        ("init", {"saved_plan_path": "plan"}),
        ("init", {"refresh": False}),
        ("plan", {"readonly_lock": True}),
        ("show", {"backend": False, "saved_plan_path": "plan"}),
    ],
)
def test_runner_rejects_command_option_crossovers(tmp_path, command, options):
    with pytest.raises(ValueError, match="does not accept"):
        LocalTerraformCommandRunner().run(command, working_directory=str(tmp_path), env={}, **options)


def test_runner_can_isolate_capture_environment_from_controller_process(tmp_path):
    with patch("subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "{}"
        run.return_value.stderr = ""
        LocalTerraformCommandRunner().run(
            "version",
            working_directory=str(tmp_path),
            env={"TF_DATA_DIR": str(tmp_path / "terraform-data")},
            inherit_environment=False,
        )
    assert run.call_args.kwargs["env"] == {"TF_DATA_DIR": str(tmp_path / "terraform-data")}
