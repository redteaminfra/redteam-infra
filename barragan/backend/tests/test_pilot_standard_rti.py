# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.integrations.ansible_disposable_validation import (
    SSH_PRIVATE_KEY_ENV,
    SSH_PUBLIC_KEY_ENV,
    SSH_SOURCE_CIDR_ENV,
)
from app.integrations.oci_disposable_terraform import EXECUTION_CONFIRMATION
from app.integrations.oci_read_validation import BARRAGAN_TESTING_COMPARTMENT_ID, DEFAULT_REGION
from app.domain import EngagementDetail, JobEvent
from app.integrations.pilot_standard_rti import (
    CORE_MANAGEMENT_SSH_USER,
    PILOT_CIDR,
    PILOT_HOMEBASE_CIDR,
    PILOT_HOMEBASE_NAME,
    PILOT_HOMEBASE_PRIVATE_IP,
    PILOT_PROXY_CIDR,
    PILOT_PROXY02_NAME,
    PILOT_PROXY02_PRIVATE_IP,
    PILOT_PROXY_NAME,
    PILOT_PROXY_PRIVATE_IP,
    WORKSPACE_NAME,
    CAPABILITY_APPLY_TIMEOUT_SECONDS,
    BOOTSTRAP_VALIDATE_TIMEOUT_SECONDS,
    ANSIBLE_TASK_EVENT_LIMIT,
    COMMAND_HEARTBEAT_EVENT_LIMIT,
    COMMAND_PROGRESS_EVENT_LIMIT,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    OCI_CORE_DHCP_DNS_SERVERS,
    OCI_CORE_AGENT_PROCESS_PATTERN,
    TERRAFORM_MUTATION_TIMEOUT_SECONDS,
    SSH_READINESS_COMMAND_TIMEOUT_SECONDS,
    STANDARD_RTI_SSH_READINESS_TIMEOUT_SECONDS,
    _command_timeout_seconds,
    _emit_ansible_progress,
    _ensure_private_known_hosts_directory,
    _run_guarded_command,
    _run_command,
    _runtime_inventory_ini,
    _cleanup_resource_label,
    _connection_details,
    build_pilot_execution_commands,
    build_pilot_standard_rti_workspace,
    execute_pilot_standard_rti,
    execute_pilot_standard_rti_teardown,
    pilot_channel_rows,
    pilot_names,
    render_pilot_standard_rti_workspace,
)
from app.services.guarded_test_deployment import (
    GuardedDeploymentConfirmationError,
    PILOT_JOB_ACTION,
    get_guarded_pilot_standard_rti_run,
    pilot_standard_rti_readiness,
    run_guarded_pilot_standard_rti,
    start_guarded_pilot_standard_rti_run,
    teardown_guarded_pilot_standard_rti_run,
)
from app.services.jobs import enqueue_job
from app.integrations.managed_host_images import MANAGED_HOST_IMAGE_PROFILES
from app.services.provider_keyed_host_binding import _core_known_hosts
from app.storage.job_repository import SqliteJobRepository


def test_known_hosts_directory_is_private_under_collaborator_umask(tmp_path):
    workspace = tmp_path / "core"
    workspace.mkdir(mode=0o700)
    prior_umask = os.umask(0o002)
    try:
        ssh_dir = workspace / "ssh"
        _ensure_private_known_hosts_directory(ssh_dir)
    finally:
        os.umask(prior_umask)
    assert ssh_dir.stat().st_mode & 0o7777 == 0o700
    known_hosts = ssh_dir / "known_hosts"
    known_hosts.write_text("45.79.201.30 ssh-ed25519 pinned-test-host-key\n")
    known_hosts.chmod(0o600)
    core = SimpleNamespace(events=[SimpleNamespace(data={"workspaceDir": str(workspace)})])
    assert _core_known_hosts(core)[0] == str(known_hosts)


@pytest.mark.parametrize("mode", [0o700, 0o750])
def test_existing_safe_known_hosts_directory_is_preserved(tmp_path, mode):
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    ssh_dir.chmod(mode)
    _ensure_private_known_hosts_directory(ssh_dir)
    assert ssh_dir.stat().st_mode & 0o7777 == mode


def test_existing_unsafe_known_hosts_directory_or_symlink_is_rejected(tmp_path):
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    ssh_dir.chmod(0o775)
    with pytest.raises(ValueError, match="known-hosts directory is unsafe"):
        _ensure_private_known_hosts_directory(ssh_dir)
    ssh_dir.rmdir()
    ssh_dir.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="known-hosts directory is unsafe"):
        _ensure_private_known_hosts_directory(ssh_dir)


def test_existing_file_cannot_replace_known_hosts_directory(tmp_path):
    ssh_dir = tmp_path / "ssh"
    ssh_dir.write_text("not a directory")
    with pytest.raises(ValueError, match="known-hosts directory is unsafe"):
        _ensure_private_known_hosts_directory(ssh_dir)


@pytest.mark.parametrize("kind", ["group_writable", "symlink", "file"])
def test_unsafe_known_hosts_directory_stops_pilot_before_commands(tmp_path, kind):
    workspace = tmp_path / "core"
    workspace.mkdir(mode=0o700)
    ssh_dir = workspace / "ssh"
    if kind == "group_writable":
        ssh_dir.mkdir()
        ssh_dir.chmod(0o775)
    elif kind == "symlink":
        ssh_dir.symlink_to(tmp_path, target_is_directory=True)
    else:
        ssh_dir.write_text("not a directory")
    commands: list[tuple[str, ...]] = []

    def forbidden_runner(command, *_args):
        commands.append(tuple(command))
        pytest.fail("external command ran before known-hosts directory validation")

    with pytest.raises(ValueError, match="known-hosts directory is unsafe"):
        execute_pilot_standard_rti(
            workspace,
            runner=forbidden_runner,
            preflight_runner=forbidden_runner,
            env={
                "OCI_CLI_PATH": sys.executable,
                "TERRAFORM_BIN": sys.executable,
                "ANSIBLE_BIN": sys.executable,
                "ANSIBLE_PLAYBOOK_BIN": sys.executable,
            },
            prepared_plan_path=workspace / "reviewed.tfplan",
        )
    assert commands == []


def _legacy_core_state(source_images):
    return {
        "version": 4,
        "serial": 1,
        "lineage": "legacy-core",
        "outputs": {},
        "resources": [{
            "mode": "managed",
            "type": "oci_core_instance",
            "instances": [
                {"attributes": {"source_details": [{"source_id": image}]}}
                for image in source_images
            ],
        }],
    }


def test_legacy_unpinned_teardown_uses_retained_image_without_profile_lookup(tmp_path, monkeypatch):
    source_image = "ocid1.image.oc1.iad.legacy-exact"
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text(json.dumps(_legacy_core_state([source_image])))
    monkeypatch.setenv("BARRAGAN_MANAGED_HOST_IMAGE_PROFILE", "invalid-current-profile")
    calls = []

    def runner(command, cwd):
        calls.append(command)
        return completed(command, '{"data": []}')

    with patch(
        "app.integrations.pilot_standard_rti.managed_host_image_profile",
        side_effect=AssertionError("teardown must not resolve a current image profile"),
    ), patch(
        "app.services.managed_host_image_continuity.pinned_managed_host_image_profile",
        side_effect=AssertionError("legacy teardown must not require an image pin"),
    ), patch(
        "app.services.managed_host_image_continuity.resolve_or_pin_managed_host_image_profile",
        side_effect=AssertionError("teardown must not write an image pin"),
    ):
        result = execute_pilot_standard_rti_teardown(
            tmp_path / "workspace",
            runner=runner,
            preflight_runner=lambda command: completed(command, '{"data": []}'),
            env={
                "OCI_CLI_PATH": _executable(str(tmp_path), "oci"),
                "TERRAFORM_BIN": _executable(str(tmp_path), "terraform"),
                SSH_PUBLIC_KEY_ENV: "/tmp/pilot.pub",
                SSH_SOURCE_CIDR_ENV: "198.51.100.10/32",
                "PATH": "",
            },
            terraform_state_path=state_path,
        )

    assert result.ok
    assert [command[1] for command in calls if Path(command[0]).name == "terraform"] == ["init", "destroy"]
    variables = (tmp_path / "workspace" / "variables.tf").read_text()
    assert f'default     = "{source_image}"' in variables
    assert 'variable "ubuntu_version" {\n  type        = string\n  default     = ""' in variables
    assert 'count                    = var.oci_source_image_id == "" ? 1 : 0' in (
        tmp_path / "workspace" / "main.tf"
    ).read_text()
    assert json.loads(state_path.read_text()) == _legacy_core_state([source_image])


@pytest.mark.parametrize("images, message", [
    ([2404], "valid source image OCID"),
    ([None], "valid source image OCID"),
    ([], "no managed compute image identity"),
    (["ocid1.image.oc1.iad.first", "ocid1.image.oc1.iad.second"], "conflicting source image identities"),
])
def test_legacy_teardown_rejects_missing_invalid_or_conflicting_images_before_commands(tmp_path, images, message):
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text(json.dumps(_legacy_core_state(images)))

    def forbidden_runner(*args):
        pytest.fail("external command ran before retained image validation")

    with pytest.raises(ValueError, match=message):
        execute_pilot_standard_rti_teardown(
            tmp_path / "workspace",
            engagement_id="eng-legacy-unpinned",
            runner=forbidden_runner,
            preflight_runner=forbidden_runner,
            terraform_state_path=state_path,
        )


def test_first_provisioning_keeps_current_image_profile_validation(monkeypatch):
    monkeypatch.delenv("BARRAGAN_MANAGED_HOST_IMAGE_PROFILE", raising=False)
    workspace = build_pilot_standard_rti_workspace()
    assert 'default     = "24.04"' in _artifact_content(workspace, "variables.tf")

    monkeypatch.setenv("BARRAGAN_MANAGED_HOST_IMAGE_PROFILE", "invalid-current-profile")
    with pytest.raises(ValueError, match="BARRAGAN_MANAGED_HOST_IMAGE_PROFILE"):
        build_pilot_standard_rti_workspace()


class PilotStandardRtiIntegrationTests(unittest.TestCase):
    def test_rendered_workspace_uses_explicit_engagement_image_profile(self):
        workspace = build_pilot_standard_rti_workspace(
            host_image_profile=MANAGED_HOST_IMAGE_PROFILES["ubuntu-22.04"]
        )

        variables = _artifact_content(workspace, "variables.tf")
        main = _artifact_content(workspace, "main.tf")

        self.assertIn('default     = "22.04"', variables)
        self.assertIn('count                    = var.oci_source_image_id == "" ? 1 : 0', main)
        self.assertIn("data.oci_core_images.ubuntu[0].images[0].id", main)

    def test_rendered_retained_workspace_uses_exact_oci_source_image(self):
        source_image = "ocid1.image.oc1.iad.retained-exact"
        workspace = build_pilot_standard_rti_workspace(
            host_image_profile=MANAGED_HOST_IMAGE_PROFILES["ubuntu-22.04"],
            retained_oci_source_image_id=source_image,
        )

        variables = _artifact_content(workspace, "variables.tf")
        main = _artifact_content(workspace, "main.tf")

        self.assertIn(f'default     = "{source_image}"', variables)
        self.assertEqual(main.count("source_id               = local.ubuntu_source_image_id"), 3)
        self.assertIn(
            'ubuntu_source_image_id = var.oci_source_image_id != "" ? '
            "var.oci_source_image_id : data.oci_core_images.ubuntu[0].images[0].id",
            main,
        )
        self.assertIn('count                    = var.oci_source_image_id == "" ? 1 : 0', main)

    def test_rendered_workspace_matches_standard_rti_pilot_shape(self):
        workspace = build_pilot_standard_rti_workspace()
        artifact_content = "\n".join(artifact.content for artifact in workspace.artifacts)
        bootstrap_content = _artifact_content(workspace, "ansible/bootstrap_validate.yml")

        self.assertEqual(workspace.workspace if hasattr(workspace, "workspace") else WORKSPACE_NAME, WORKSPACE_NAME)
        self.assertEqual(workspace.target.compartment_id, BARRAGAN_TESTING_COMPARTMENT_ID)
        self.assertIn(PILOT_CIDR, artifact_content)
        self.assertIn(PILOT_HOMEBASE_CIDR, artifact_content)
        self.assertIn(PILOT_PROXY_CIDR, artifact_content)
        self.assertIn(PILOT_HOMEBASE_NAME, artifact_content)
        self.assertIn(PILOT_PROXY_NAME, artifact_content)
        self.assertIn(PILOT_PROXY02_NAME, artifact_content)
        self.assertIn(PILOT_HOMEBASE_PRIVATE_IP, artifact_content)
        self.assertIn(PILOT_PROXY_PRIVATE_IP, artifact_content)
        self.assertIn(PILOT_PROXY02_PRIVATE_IP, artifact_content)
        self.assertIn("var.ssh_source_cidrs", artifact_content)
        self.assertIn("hosts: pilot_rti", artifact_content)
        self.assertIn("ansible.builtin.ping", artifact_content)
        self.assertIn("/dropbox", artifact_content)
        self.assertIn("/engagement", artifact_content)
        self.assertIn("cloud-init status --wait", artifact_content)
        self.assertIn("Wait for apt and dpkg locks to clear", artifact_content)
        self.assertIn("/var/lib/dpkg/lock-frontend", artifact_content)
        self.assertIn("Install Ubuntu repository management tools", artifact_content)
        self.assertIn("Enable Ubuntu universe repository for legacy RTI packages", artifact_content)
        self.assertIn("add-apt-repository -y universe", artifact_content)
        self.assertIn("Ensure legacy nfsnobody ACL account exists for RTI NFS role compatibility", artifact_content)
        self.assertNotIn("Apply Redteam-infra homebase baseline role", bootstrap_content)
        self.assertNotIn("name: homebase", bootstrap_content)
        self.assertIn('resource "oci_core_default_dhcp_options" "pilot"', artifact_content)
        self.assertIn(f"custom_dns_servers = {json.dumps(list(OCI_CORE_DHCP_DNS_SERVERS))}", artifact_content)
        self.assertNotIn("Apply Redteam-infra OCI resolver baseline", bootstrap_content)
        self.assertNotIn("name: oci", bootstrap_content)
        self.assertNotIn("Create homebase engagement workspace directory", bootstrap_content)
        self.assertNotIn("Create homebase engagement loot directory", bootstrap_content)
        self.assertNotIn("nfs-kernel-server", bootstrap_content)
        self.assertNotIn("nfs-common", bootstrap_content)
        self.assertNotIn("Install baseline RTI operator tools", bootstrap_content)
        self.assertNotIn("- nmap", bootstrap_content)
        self.assertNotIn("Install homebase desktop and VNC baseline packages", bootstrap_content)
        self.assertNotIn("BARRAGAN MANAGED VNC FIRST LOGIN", bootstrap_content)
        self.assertNotIn("Apply legacy dropbox ACLs on homebase export", bootstrap_content)
        self.assertNotIn('setfacl -m "u:${anonymous_user}:rwx" "{{ dropbox_path }}"', bootstrap_content)
        self.assertNotIn('setfacl -R -m "d:g:redteam:rwX" "{{ dropbox_path }}"', bootstrap_content)
        self.assertNotIn("lock_timeout", bootstrap_content)
        self.assertNotIn("exportfs -ra", bootstrap_content)
        self.assertNotIn("Allow proxy subnet through homebase host firewall for dropbox NFS", bootstrap_content)
        self.assertNotIn("barragan-dropbox-nfs", bootstrap_content)
        self.assertNotIn("findmnt -rn -T {{ dropbox_path }} -t nfs,nfs4", bootstrap_content)
        self.assertIn("homebase_required_paths", artifact_content)
        self.assertIn("/opt/proxy01", artifact_content)
        self.assertIn("/opt/proxy02", artifact_content)
        self.assertNotIn("Canonicalize Dante-oriented homebase user profiles", bootstrap_content)
        self.assertNotIn("proxychains_port", artifact_content)
        self.assertNotIn("Autonomous", artifact_content)
        self.assertNotIn("load_balancer", artifact_content)

    def test_engagement_names_match_standard_rti_conventions(self):
        workspace = build_pilot_standard_rti_workspace(engagement_name="AB01")
        names = pilot_names("AB01")
        artifact_content = "\n".join(artifact.content for artifact in workspace.artifacts)
        cleanup_display_names = [command[-1] for command in workspace.cleanup["verificationCommands"]]

        self.assertEqual(names.vcn_name, "ab01-vcn")
        self.assertEqual(names.homebase_name, "homebase-ab01")
        self.assertEqual(names.proxy_name, "proxy01-ab01")
        self.assertEqual(names.proxy02_name, "proxy02-ab01")
        self.assertIn("homebase-ab01", artifact_content)
        self.assertIn("proxy01-ab01", artifact_content)
        self.assertIn("proxy02-ab01", artifact_content)
        self.assertIn("ab01-vcn", artifact_content)
        self.assertIn("homebase-ab01", cleanup_display_names)
        self.assertIn("proxy01-ab01", cleanup_display_names)
        self.assertIn("proxy02-ab01", cleanup_display_names)
        self.assertIn("ab01-vcn", cleanup_display_names)

    def test_dev_infra_workspace_omits_proxy02(self):
        workspace = build_pilot_standard_rti_workspace(engagement_name="SK02-dev", proxy_count=1)
        artifact_content = "\n".join(artifact.content for artifact in workspace.artifacts)
        cleanup_display_names = [command[-1] for command in workspace.cleanup["verificationCommands"]]

        self.assertEqual(workspace.proxy_count, 1)
        self.assertEqual(workspace.to_dict()["topology"]["template"], "Dev Infra")
        self.assertIn("homebase-sk02-dev", artifact_content)
        self.assertIn("proxy01-sk02-dev", artifact_content)
        self.assertNotIn("proxy02-sk02-dev", artifact_content)
        self.assertNotIn('resource "oci_core_instance" "proxy02"', artifact_content)
        self.assertIn("homebase-sk02-dev", cleanup_display_names)
        self.assertIn("proxy01-sk02-dev", cleanup_display_names)
        self.assertNotIn("proxy02-sk02-dev", cleanup_display_names)
        self.assertIn("proxy01 ansible_host=0.0.0.0", artifact_content)
        self.assertNotIn("proxy02 ansible_host=0.0.0.0", artifact_content)

    def test_standard_dev_proxy_counts_and_elk_inherit_stock_oci_instance_policy(self):
        cases = (
            ("standard-rti", 2, False, ("homebase", "proxy01", "proxy02")),
            ("dev-infra", 1, False, ("homebase", "proxy01")),
            ("standard-rti", 1, True, ("homebase", "proxy01", "elk")),
        )
        for template_id, proxy_count, elk_enabled, resources in cases:
            with self.subTest(template_id=template_id, proxy_count=proxy_count, elk_enabled=elk_enabled):
                terraform = _artifact_content(
                    build_pilot_standard_rti_workspace(
                        template_id=template_id,
                        proxy_count=proxy_count,
                        elk_enabled=elk_enabled,
                    ),
                    "main.tf",
                )
                for resource in resources:
                    instance = _terraform_resource(terraform, "oci_core_instance", resource)
                    self.assertNotIn("depends_on", instance)
                    self.assertIn("agent_config {", instance)
                    self.assertIn("are_all_plugins_disabled = true", instance)
                    self.assertIn("is_monitoring_disabled   = true", instance)
                    self.assertIn('name          = "Compute Instance Monitoring"', instance)
                    self.assertIn('desired_state = "DISABLED"', instance)
                    if resource.startswith("proxy"):
                        self.assertIn("skip_source_dest_check = true", instance)

    def test_compute_profiles_render_typed_role_variables_and_fixed_shape_without_shape_config(self):
        standard = build_pilot_standard_rti_workspace(template_id="standard-rti", proxy_count=2)
        dev = build_pilot_standard_rti_workspace(template_id="dev-infra", proxy_count=1)
        small = build_pilot_standard_rti_workspace(template_id="small-dev-infra", proxy_count=1)
        standard_vars = json.loads(_artifact_content(standard, "terraform.tfvars.json"))
        dev_vars = json.loads(_artifact_content(dev, "terraform.tfvars.json"))
        small_vars = json.loads(_artifact_content(small, "terraform.tfvars.json"))
        standard_tf = _artifact_content(standard, "main.tf")
        dev_tf = _artifact_content(dev, "main.tf")

        self.assertEqual(standard_vars["homebase_shape"], "BM.Standard3.64")
        self.assertEqual(standard_vars["homebase_ocpus"], 64)
        self.assertEqual(standard_vars["homebase_memory_in_gbs"], 1024)
        self.assertEqual(dev_vars["homebase_shape"], "VM.Standard.E4.Flex")
        self.assertEqual(dev_vars["homebase_ocpus"], 16)
        self.assertEqual(dev_vars["homebase_memory_in_gbs"], 512)
        self.assertEqual(small_vars["homebase_shape"], "VM.Standard.E4.Flex")
        self.assertEqual(small_vars["homebase_ocpus"], 4)
        self.assertEqual(small_vars["homebase_memory_in_gbs"], 64)
        self.assertEqual(small_vars["proxy_ocpus"], 1)
        self.assertEqual(small_vars["proxy_memory_in_gbs"], 8)
        self.assertEqual(small_vars["boot_volume_size_in_gbs"], 128)
        self.assertEqual(small.to_dict()["topology"]["template"], "Small Dev Infra")
        self.assertNotIn("elk", [resource["name"] for resource in small.resources])
        self.assertEqual(standard_vars["proxy_ocpus"], 2)
        self.assertEqual(standard_vars["proxy_memory_in_gbs"], 32)
        self.assertEqual(standard_vars["boot_volume_size_in_gbs"], 512)
        self.assertEqual(standard_tf.count("shape               = var.homebase_shape"), 1)
        homebase_standard = standard_tf.split('resource "oci_core_instance" "homebase"', 1)[1].split(
            'resource "oci_core_instance" "proxy01"', 1
        )[0]
        homebase_dev = dev_tf.split('resource "oci_core_instance" "homebase"', 1)[1].split(
            'resource "oci_core_instance" "proxy01"', 1
        )[0]
        self.assertNotIn("shape_config", homebase_standard)
        self.assertIn("shape_config", homebase_dev)
        self.assertIn("boot_volume_size_in_gbs = var.boot_volume_size_in_gbs", standard_tf)

    def test_small_dev_infra_rejects_elk_and_second_proxy(self):
        with self.assertRaisesRegex(ValueError, "requires exactly 1 OCI proxy"):
            build_pilot_standard_rti_workspace(template_id="small-dev-infra", proxy_count=2)
        with self.assertRaisesRegex(ValueError, "does not support an ELK"):
            build_pilot_standard_rti_workspace(template_id="small-dev-infra", proxy_count=1, elk_enabled=True)

    def test_rendered_bootstrap_yaml_has_one_actionable_first_boot_task(self):
        import yaml

        workspace = build_pilot_standard_rti_workspace(template_id="standard-rti", proxy_count=2, elk_enabled=True)
        playbook = _artifact_content(workspace, "ansible/bootstrap_validate.yml")
        parsed = yaml.safe_load(playbook)
        matching = [
            task
            for play in parsed
            for task in play.get("tasks", [])
            if task.get("name") == "Wait for first-boot package activity to finish"
        ]

        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["ansible.builtin.command"], "cloud-init status --wait")

    def test_core_bootstrap_disables_oracle_cloud_agent_after_cloud_init(self):
        import yaml

        workspace = build_pilot_standard_rti_workspace(template_id="dev-infra", proxy_count=1, elk_enabled=True)
        playbook = _artifact_content(workspace, "ansible/bootstrap_validate.yml")
        parsed = yaml.safe_load(playbook)
        tasks = parsed[0]["tasks"]
        first_boot = next(index for index, task in enumerate(tasks) if task.get("name") == "Wait for first-boot package activity to finish")
        disable = next(index for index, task in enumerate(tasks) if task.get("name") == "Disable Oracle Cloud Agent framework services")
        process_assertion = next(
            index for index, task in enumerate(tasks) if task.get("name") == "Assert Oracle Cloud Agent framework and plugins stopped"
        )
        task = tasks[disable]
        assertion = tasks[process_assertion]

        self.assertEqual(disable, first_boot + 1)
        self.assertEqual(process_assertion, disable + 1)
        self.assertEqual(task["ansible.builtin.command"]["argv"], ["systemctl", "disable", "--now", "{{ item }}"])
        units = parsed[0]["vars"]["oracle_cloud_agent_units"]
        self.assertEqual(
            units,
            [
                "snap.oracle-cloud-agent.oracle-cloud-agent-updater.service",
                "snap.oracle-cloud-agent.oracle-cloud-agent.service",
            ],
        )
        self.assertNotIn("failed_when", task)
        self.assertEqual(
            assertion["ansible.builtin.command"]["argv"],
            ["pgrep", "--full", "--list-full", "{{ oracle_cloud_agent_process_pattern }}"],
        )
        self.assertEqual(parsed[0]["vars"]["oracle_cloud_agent_process_pattern"], OCI_CORE_AGENT_PROCESS_PATTERN)
        self.assertEqual(assertion["failed_when"], "oracle_cloud_agent_processes.rc != 1")
        self.assertFalse(assertion["changed_when"])

    def test_bootstrap_defers_upstream_oci_resolver_role_to_capability_pass(self):
        workspace = build_pilot_standard_rti_workspace(template_id="dev-infra", proxy_count=1)
        bootstrap = _artifact_content(workspace, "ansible/bootstrap_validate.yml")

        self.assertNotIn("Install upstream OCI resolver persistence prerequisite", bootstrap)
        self.assertNotIn("Apply Redteam-infra OCI resolver baseline", bootstrap)

    def test_optional_elk_is_private_tracked_and_managed_through_homebase(self):
        workspace = build_pilot_standard_rti_workspace(
            engagement_name="OF02", template_id="standard-rti", proxy_count=2, elk_enabled=True
        )
        terraform = _artifact_content(workspace, "main.tf")
        inventory = _artifact_content(workspace, "ansible/inventory.ini")
        cleanup_names = [command[-1] for command in workspace.cleanup["verificationCommands"]]

        self.assertIn('resource "oci_core_subnet" "utility"', terraform)
        self.assertIn('resource "oci_core_nat_gateway" "utility"', terraform)
        self.assertIn('resource "oci_core_route_table" "utility"', terraform)
        self.assertIn("route_table_id             = oci_core_route_table.utility.id", terraform)
        self.assertIn("network_entity_id = oci_core_nat_gateway.utility.id", terraform)
        self.assertIn('output "utility_network"', terraform)
        self.assertIn('resource "oci_core_instance" "elk"', terraform)
        self.assertIn("prohibit_public_ip_on_vnic = true", terraform)
        self.assertIn("assign_public_ip = false", terraform)
        self.assertIn("elk-of02", cleanup_names)
        self.assertIn("of02-utility-subnet", cleanup_names)
        self.assertIn("of02-utility-route", cleanup_names)
        self.assertIn("of02-nat", cleanup_names)
        nat_cleanup = next(command for command in workspace.cleanup["verificationCommands"] if "nat-gateway" in command)
        self.assertEqual(_cleanup_resource_label(nat_cleanup), "nat_gateway")
        self.assertIn("[elk]", inventory)
        self.assertIn("192.168.1.0/24", terraform)
        self.assertIn("private_ip       = \"192.168.1.13\"", terraform)
        self.assertIn("ansible_host=192.168.1.13", inventory)
        self.assertIn("[pilot_rti:children]\nhomebase\nproxies\nelk", inventory)
        bootstrap = _artifact_content(workspace, "ansible/bootstrap_validate.yml")
        self.assertIn("192.168.1.13 elk-of02.infra.redteam elk-of02 elk", bootstrap)
        topology = workspace.to_dict()["topology"]
        self.assertIn(
            {"role": "utility", "cidr": "192.168.1.0/24", "privateIp": "192.168.1.13"},
            topology["subnets"],
        )
        self.assertIn(
            {"role": "elk", "displayName": "elk-of02", "privateIp": "192.168.1.13"},
            topology["nodes"],
        )
        details = _connection_details(
            {"homebase": "203.0.113.10", "proxy01": "203.0.113.11", "proxy02": "203.0.113.12"},
            workspace.names,
            DEFAULT_REGION,
            proxy_count=2,
            elk_enabled=True,
        )
        homebase_detail = next(row for row in details if row["role"] == "homebase")
        proxy_detail = next(row for row in details if row["role"] == "proxy")
        elk_detail = next(row for row in details if row["role"] == "elk")
        self.assertNotIn("nmap", homebase_detail["services"])
        self.assertIn("nmap", proxy_detail["services"])
        self.assertEqual(elk_detail["privateIp"], "192.168.1.13")
        self.assertIn("ubuntu@192.168.1.13", elk_detail["sshCommand"])
        from app.services.engagement_operations import _ssh_config
        from app.services.revision_compiler import _compile_node_groups

        self.assertIn("# LocalForward 5601 192.168.1.13:5601", _ssh_config(details)["stanza"])
        groups = _compile_node_groups({"proxyCount": 2, "elkEnabled": True, "sketchChains": []})
        elk_group = next(group for group in groups if group.role == "elk")
        self.assertEqual(elk_group.subnet, "192.168.1.0/24")
        runtime_inventory = _runtime_inventory_ini(
            {"homebase": "203.0.113.10", "proxy01": "203.0.113.11", "proxy02": "203.0.113.12"},
            names=workspace.names,
            proxy_count=2,
            elk_enabled=True,
            ssh_private_key_path="/keys/core",
            known_hosts_path="/keys/known_hosts",
        )
        self.assertIn("ansible_ssh_private_key_file=/keys/core", runtime_inventory)
        self.assertIn("ProxyCommand='ssh -i /keys/core", runtime_inventory)
        self.assertIn("UserKnownHostsFile=/keys/known_hosts", runtime_inventory)
        self.assertIn("StrictHostKeyChecking=accept-new", runtime_inventory)
        self.assertIn("-W %h:%p ubuntu@203.0.113.10", runtime_inventory)
        self.assertIn("barragan_expected_hostname=homebase-of02", runtime_inventory)
        self.assertIn("barragan_expected_hostname=proxy01-of02", runtime_inventory)
        self.assertNotIn("ProxyJump", runtime_inventory)

    def test_optional_elk_selects_and_targets_elk_capability_roles(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace_dir = Path(temp_dir) / "workspace"
            workspace = render_pilot_standard_rti_workspace(
                workspace_dir, engagement_name="OF02", template_id="standard-rti", proxy_count=2, elk_enabled=True
            )
            capability_plan = json.loads((workspace_dir / "ansible" / "capability-plan.json").read_text(encoding="utf-8"))
            capability_playbook = (workspace_dir / "ansible" / "apply_capabilities.yml").read_text(encoding="utf-8")

            self.assertTrue(any(entry["role"] == "elk" for entry in capability_plan["rolesByHostClass"]["elk"]))
            self.assertIn("- name: Apply elk selected capabilities", capability_playbook)
            self.assertIn("  hosts: elk", capability_playbook)
            self.assertIn("name: elk", capability_playbook)
            self.assertTrue(workspace.elk_enabled)

    def test_bootstrap_playbook_installs_managed_core_hosts_block_only_on_core_hosts(self):
        workspace = build_pilot_standard_rti_workspace(engagement_name="OF02")
        playbook = _artifact_content(workspace, "ansible/bootstrap_validate.yml")

        self.assertIn("hosts: pilot_rti", playbook)
        self.assertIn("Read target hostname before Barragan configuration", playbook)
        self.assertIn("Assert target belongs to the selected core deployment", playbook)
        self.assertIn("\n  vars:\n", playbook)
        self.assertNotIn("\n    vars:\n", playbook)
        self.assertIn("ansible.builtin.blockinfile", playbook)
        self.assertIn("path: /etc/hosts", playbook)
        self.assertIn('marker: "# {mark} BARRAGAN MANAGED CORE HOSTS"', playbook)
        self.assertIn("192.168.0.10 homebase-of02.infra.redteam homebase-of02 homebase", playbook)
        self.assertIn("192.168.2.11 proxy01-of02.infra.redteam proxy01-of02 proxy01", playbook)
        self.assertIn("192.168.2.12 proxy02-of02.infra.redteam proxy02-of02 proxy02", playbook)
        self.assertIn(f'core_management_user: "{CORE_MANAGEMENT_SSH_USER}"', playbook)
        self.assertIn("Create Barragan core management user", playbook)
        self.assertNotIn("Canonicalize Dante-oriented homebase user profiles", playbook)
        self.assertIn("/home/{{ core_management_user }}/.ssh/authorized_keys", playbook)
        self.assertIn("/etc/sudoers.d/90-barragan-core-management", playbook)
        self.assertNotIn("middle01", playbook)
        self.assertNotIn("edge-", playbook)
        self.assertNotIn("sketch-", playbook.lower())
        self.assertNotIn("sketch01", playbook.lower())

    def test_render_writes_terraform_and_ansible_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            template_root = Path(temp_dir) / "redteam-infra-template"
            role_tasks = template_root / "ansible" / "roles" / "homebase" / "tasks"
            role_tasks.mkdir(parents=True)
            (role_tasks / "main.yml").write_text(
                "---\n- name: Test homebase role\n  ansible.builtin.debug:\n    msg: copied\n",
                encoding="utf-8",
            )
            oci_defaults = template_root / "ansible" / "roles" / "oci" / "defaults"
            oci_tasks = template_root / "ansible" / "roles" / "oci" / "tasks"
            oci_defaults.mkdir(parents=True)
            oci_tasks.mkdir(parents=True)
            (oci_defaults / "main.yml").write_text(
                "dns_servers:\n  - 1.1.1.1\n  - 8.8.8.8\n",
                encoding="utf-8",
            )
            (oci_tasks / "main.yml").write_text(
                "- name: Stop resolved\n  systemd:\n    name: systemd-resolved.service\n    state: stopped\n"
                "- name: Disable resolved\n  systemd:\n    name: systemd-resolved.service\n    enabled: false\n"
                "- name: Mask resolved\n  systemd:\n    name: systemd-resolved.service\n    masked: true\n"
                "- name: Write resolver\n  template:\n    src: templates/resolv.conf.j2\n    dest: /etc/resolv.conf\n"
                "- name: Block VCN resolver\n  iptables:\n    action: insert\n    chain: OUTPUT\n    destination: 169.254.169.254/32\n    protocol: '{{ item }}'\n    destination_port: '53'\n    jump: DROP\n    state: present\n  with_items: [tcp, udp]\n"
                "- name: Save iptables\n  command: iptables-save -f /etc/iptables/rules.v4\n",
                encoding="utf-8",
            )

            workspace_dir = Path(temp_dir) / "workspace"
            with patch.dict(os.environ, {"BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT": str(template_root)}):
                workspace = render_pilot_standard_rti_workspace(workspace_dir)
            files = {artifact.path for artifact in workspace.artifacts}

            self.assertIn("main.tf", files)
            self.assertIn("ansible/inventory.ini", files)
            self.assertIn("ansible/bootstrap_validate.yml", files)
            self.assertTrue((workspace_dir / "main.tf").exists())
            self.assertTrue((workspace_dir / "ansible" / "bootstrap_validate.yml").exists())
            copied_role = workspace_dir / "ansible" / "roles" / "homebase" / "tasks" / "main.yml"
            self.assertTrue(copied_role.exists())
            self.assertIn("Test homebase role", copied_role.read_text(encoding="utf-8"))
            self.assertTrue((workspace_dir / "ansible" / "roles" / "oci" / "tasks" / "main.yml").exists())
            terraform = (workspace_dir / "main.tf").read_text(encoding="utf-8")
            self.assertIn('resource "oci_core_security_list" "proxy_ingress"', terraform)
            self.assertIn('resource "oci_core_security_list" "homebase_nfs"', terraform)
            self.assertIn("display_name   = \"pilot-ssh-only-proxy-ingress\"", terraform)
            self.assertIn("display_name   = \"pilot-ssh-only-homebase-nfs\"", terraform)
            self.assertIn("min = 2222", terraform)
            self.assertIn("max = 8080", terraform)
            self.assertIn('protocol = "17"', terraform)
            self.assertIn("udp_options", terraform)
            self.assertIn('protocol = "17"\n    source   = "192.168.0.0/16"', terraform)
            self.assertNotIn("min = 5454", terraform)
            self.assertIn("source   = \"192.168.2.0/24\"", terraform)
            self.assertIn("min = 111", terraform)
            self.assertIn("max = 111", terraform)
            self.assertIn("min = 2049", terraform)
            self.assertIn("max = 2049", terraform)
            self.assertIn("security_list_ids          = [oci_core_security_list.ssh_only.id, oci_core_security_list.homebase_nfs.id]", terraform)
            self.assertIn("security_list_ids          = [oci_core_security_list.ssh_only.id, oci_core_security_list.proxy_ingress.id]", terraform)
            self.assertEqual(terraform.count("instance_options"), 3)
            self.assertEqual(terraform.count("are_legacy_imds_endpoints_disabled = true"), 3)

    def test_render_validates_oci_role_from_selected_capability_plan_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            selected_source = Path(temp_dir) / "retained-engagement-workspace"
            selected_oci = selected_source / "ansible" / "roles" / "oci"
            (selected_oci / "defaults").mkdir(parents=True)
            (selected_oci / "tasks").mkdir(parents=True)
            (selected_oci / "defaults" / "main.yml").write_text("dns_servers: []\n", encoding="utf-8")
            (selected_oci / "tasks" / "main.yml").write_text("[]\n", encoding="utf-8")
            capability_plan = SimpleNamespace(
                source=SimpleNamespace(ansible_role_path=lambda role_name: selected_oci),
                to_summary=lambda: {},
            )

            with patch.dict(
                os.environ,
                {"BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT": "/private/tmp/redteam-infra-wi0288"},
            ), patch(
                "app.integrations.pilot_standard_rti.build_core_capability_role_apply_plan",
                return_value=capability_plan,
            ), patch("app.integrations.pilot_standard_rti.copy_core_capability_roles"), patch(
                "app.integrations.pilot_standard_rti.render_core_capability_apply_playbook",
                return_value="---\n",
            ):
                with self.assertRaisesRegex(ValueError, "OCI resolver defaults"):
                    render_pilot_standard_rti_workspace(
                        Path(temp_dir) / "rendered",
                        engagement_id="eng-selected-source",
                    )

    def test_render_fails_closed_when_upstream_oci_role_loses_resolver_contract(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            template_root = Path(temp_dir) / "redteam-infra-template"
            for role_name in ("homebase", "oci"):
                role_tasks = template_root / "ansible" / "roles" / role_name / "tasks"
                role_tasks.mkdir(parents=True)
                (role_tasks / "main.yml").write_text("---\n[]\n", encoding="utf-8")
            oci_defaults = template_root / "ansible" / "roles" / "oci" / "defaults"
            oci_defaults.mkdir(parents=True)
            (oci_defaults / "main.yml").write_text("dns_servers:\n  - 169.254.169.254\n", encoding="utf-8")

            with (
                patch.dict(os.environ, {"BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT": str(template_root)}),
                self.assertRaisesRegex(ValueError, "resolver defaults do not match"),
            ):
                render_pilot_standard_rti_workspace(Path(temp_dir) / "workspace")

    def test_render_fails_closed_when_upstream_oci_role_loses_firewall_lifecycle(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            template_root = Path(temp_dir) / "redteam-infra-template"
            for role_name in ("homebase", "oci"):
                role_tasks = template_root / "ansible" / "roles" / role_name / "tasks"
                role_tasks.mkdir(parents=True)
                (role_tasks / "main.yml").write_text("---\n[]\n", encoding="utf-8")
            oci_defaults = template_root / "ansible" / "roles" / "oci" / "defaults"
            oci_defaults.mkdir(parents=True)
            (oci_defaults / "main.yml").write_text("dns_servers:\n  - 1.1.1.1\n  - 8.8.8.8\n", encoding="utf-8")

            with (
                patch.dict(os.environ, {"BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT": str(template_root)}),
                self.assertRaisesRegex(ValueError, "required resolver lifecycle"),
            ):
                render_pilot_standard_rti_workspace(Path(temp_dir) / "workspace")

    def test_render_copies_homebase_role_baseline(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace_dir = Path(temp_dir) / "workspace"
            render_pilot_standard_rti_workspace(workspace_dir)

            copied_role = workspace_dir / "ansible" / "roles" / "homebase"
            tasks = (copied_role / "tasks" / "main.yml").read_text(encoding="utf-8")
            profile_append = (copied_role / "files" / "skel-append-profile.sh").read_text(encoding="utf-8")
            vnc_unit = (copied_role / "files" / "skel" / ".config" / "systemd" / "user" / "vncserver@.service").read_text(encoding="utf-8")
            xstartup = (copied_role / "files" / "skel" / ".vnc" / "xstartup").read_text(encoding="utf-8")

            self.assertIn("xfce4", tasks)
            self.assertIn("xfce4-goodies", tasks)
            self.assertIn("tigervnc-standalone-server", tasks)
            self.assertIn("tigervnc-viewer", tasks)
            self.assertIn("proxychains4", tasks)
            self.assertIn("Set executable bit on /etc/skel/.vnc/xstartup", tasks)
            self.assertIn("Add block to /etc/skel/.profile to run setup-xfce4-vnc on first login", tasks)
            self.assertIn("Hashit", tasks)
            self.assertIn("Implant_cryptor", tasks)
            self.assertIn("Remove unwanted xfce4 utilities", tasks)
            self.assertIn("vncpasswd -f", profile_append)
            self.assertIn("PORT=$(($(id -u) - 6000 + 1))", profile_append)
            self.assertIn("systemctl --user enable vncserver@$PORT.service", profile_append)
            self.assertIn("systemctl --user start vncserver@$PORT.service", profile_append)
            self.assertIn("ExecStart=/usr/bin/vncserver :%i", vnc_unit)
            self.assertIn("xfce4-session", xstartup)

    def test_commands_include_two_node_ansible_validation_and_cleanup(self):
        workspace = build_pilot_standard_rti_workspace()
        commands = build_pilot_execution_commands(
            workspace,
            terraform_executable="/usr/bin/terraform",
            ansible_executable="/usr/bin/ansible",
            ansible_playbook_executable="/usr/bin/ansible-playbook",
            ssh_source_cidrs=["198.51.100.10/32", "160.34.86.0/23"],
        )

        self.assertEqual(commands[0], ["/usr/bin/terraform", "init", "-input=false"])
        self.assertIn('ssh_source_cidrs=["198.51.100.10/32", "160.34.86.0/23"]', commands[1])
        self.assertEqual(commands[2], ["/usr/bin/terraform", "output", "-json"])
        self.assertIn("pilot_rti", commands[3])
        self.assertIn("ansible.builtin.wait_for_connection", commands[3])
        self.assertEqual(commands[4][-2:], ["-m", "ping"])
        self.assertIn("ansible/bootstrap_validate.yml", commands[5])
        self.assertIn("ansible/apply_capabilities.yml", commands[6])
        self.assertEqual(commands[7][1], "destroy")
        self.assertGreaterEqual(len(commands[8:]), 8)
        self.assertFalse(any("-parallelism=1" in part for command in commands for part in command))

    def test_commands_keep_terraform_state_and_runtime_data_outside_rendered_workspace(self):
        commands = build_pilot_execution_commands(
            build_pilot_standard_rti_workspace(),
            terraform_executable="terraform",
            terraform_state_path="/private/state/engagement/core/terraform.tfstate",
            terraform_data_dir="/private/state/engagement/core/data-run-01",
        )

        for index in (0, 1, 2, 7):
            self.assertEqual(commands[index][:2], ["env", "TF_DATA_DIR=/private/state/engagement/core/data-run-01"])
        self.assertIn("-state=/private/state/engagement/core/terraform.tfstate", commands[1])
        self.assertIn("-state=/private/state/engagement/core/terraform.tfstate", commands[2])
        self.assertIn("-state=/private/state/engagement/core/terraform.tfstate", commands[7])

    def test_capability_apply_uses_extended_timeout_for_first_run_roles(self):
        self.assertEqual(
            _command_timeout_seconds(["ansible-playbook", "ansible/bootstrap_validate.yml"]),
            BOOTSTRAP_VALIDATE_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            _command_timeout_seconds(["ansible-playbook", "ansible/apply_capabilities.yml"]),
            CAPABILITY_APPLY_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            _command_timeout_seconds(["terraform", "apply"]),
            TERRAFORM_MUTATION_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            _command_timeout_seconds(["env", "TF_DATA_DIR=/private/state", "/usr/bin/terraform", "destroy"]),
            TERRAFORM_MUTATION_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            _command_timeout_seconds(["terraform", "output"]),
            DEFAULT_COMMAND_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            _command_timeout_seconds(["ansible", "pilot_rti", "-m", "ansible.builtin.wait_for_connection"]),
            SSH_READINESS_COMMAND_TIMEOUT_SECONDS,
        )

    def test_only_selected_core_capability_command_gets_ninety_minutes(self):
        commands = build_pilot_execution_commands(build_pilot_standard_rti_workspace())
        extended = [command for command in commands
                    if _command_timeout_seconds(command) == 5400]
        self.assertEqual(len(extended), 1)
        self.assertIn("ansible/apply_capabilities.yml", extended[0])
        self.assertEqual(CAPABILITY_APPLY_TIMEOUT_SECONDS, 5400)
        self.assertEqual(_command_timeout_seconds(
            ["ansible-playbook", "ansible/bootstrap_validate.yml"]), 1800)
        self.assertEqual(_command_timeout_seconds(["terraform", "apply"]), 1800)
        self.assertEqual(_command_timeout_seconds(["terraform", "destroy"]), 1800)
        self.assertEqual(_command_timeout_seconds(["terraform", "output"]), 240)
        self.assertEqual(_command_timeout_seconds(
            ["ansible-playbook", "ansible/other.yml"]), 240)
        self.assertEqual(_command_timeout_seconds(
            ["ansible", "pilot_rti", "-m", "ansible.builtin.wait_for_connection"]), 660)

    def test_core_readiness_allows_for_bare_metal_startup(self):
        commands = build_pilot_execution_commands(build_pilot_standard_rti_workspace())

        self.assertIn(
            f"timeout={STANDARD_RTI_SSH_READINESS_TIMEOUT_SECONDS}",
            commands[3][-1],
        )

    def test_execute_with_fake_runner_destroys_and_verifies_cleanup(self):
        calls = []

        def runner(command, cwd):
            calls.append(command)
            if len(command) > 1 and command[1] == "output":
                return completed(
                    command,
                    json.dumps(
                        {
                            "public_ips": {
                                "value": {
                                    "homebase": "203.0.113.10",
                                    "proxy01": "203.0.113.11",
                                    "proxy02": "203.0.113.12",
                                }
                            }
                        }
                    ),
                )
            return completed(command, '{"data": []}')

        with tempfile.TemporaryDirectory() as temp_dir:
            terraform_path = _executable(temp_dir, "terraform")
            oci_path = _executable(temp_dir, "oci")
            ansible_path = _executable(temp_dir, "ansible")
            ansible_playbook_path = _executable(temp_dir, "ansible-playbook")
            result = execute_pilot_standard_rti(
                Path(temp_dir) / "workspace",
                runner=runner,
                preflight_runner=lambda command: completed(command, '{"data": []}'),
                env={
                    "OCI_CLI_PATH": oci_path,
                    "TERRAFORM_BIN": terraform_path,
                    "ANSIBLE_BIN": ansible_path,
                    "ANSIBLE_PLAYBOOK_BIN": ansible_playbook_path,
                    SSH_PUBLIC_KEY_ENV: "/tmp/pilot.pub",
                    SSH_PRIVATE_KEY_ENV: "/tmp/pilot",
                    SSH_SOURCE_CIDR_ENV: "198.51.100.10/32",
                    "PATH": "",
                },
                deployment_mode="destroy_after_validation",
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.mutation_status, "destroyed")
        self.assertEqual(result.ansible_status, "validated")
        self.assertEqual(result.final_cleanup_status, "verified_clean")
        self.assertEqual(result.connection_details[0]["publicIp"], "203.0.113.10")
        self.assertEqual(result.connection_details[0]["sshUser"], CORE_MANAGEMENT_SSH_USER)
        self.assertEqual(result.connection_details[0]["sshCommand"], "ssh homebase-pilot")
        self.assertEqual(result.connection_details[0]["region"], DEFAULT_REGION)
        self.assertEqual(result.connection_details[1]["region"], DEFAULT_REGION)
        self.assertEqual(result.connection_details[2]["displayName"], "proxy02-pilot")
        self.assertEqual(result.connection_details[2]["publicIp"], "203.0.113.12")
        self.assertEqual(result.connection_details[2]["privateIp"], PILOT_PROXY02_PRIVATE_IP)
        self.assertEqual(result.connection_details[2]["region"], DEFAULT_REGION)
        self.assertIn("proxy config banks", result.connection_details[0]["services"])
        self.assertNotIn("nmap", result.connection_details[0]["services"])
        self.assertIn("dropbox NFS mount", result.connection_details[1]["services"])
        self.assertIn("nmap", result.connection_details[1]["services"])
        self.assertEqual(result.outbound_channels[0]["chainId"], "chain-1")
        self.assertEqual(result.outbound_channels[0]["proxy"], "proxy01-pilot")
        self.assertEqual(result.outbound_channels[0]["middle"], "Not Deployed")
        self.assertEqual(result.outbound_channels[0]["port"], "3333")
        self.assertEqual(result.inbound_channels, [])
        self.assertTrue(any(command[1] == "apply" for command in calls if len(command) > 1))
        self.assertTrue(any("pilot_rti" in command for command in calls))
        self.assertTrue(any(command[1] == "destroy" for command in calls if len(command) > 1))
        self.assertEqual(result.cleanup_verification.remaining_count, 0)

    def test_retained_workspace_teardown_initializes_before_destroy(self):
        calls = []
        progress_events = []
        retained_source_image = "ocid1.image.oc1.iad.retained-teardown"

        def runner(command, cwd):
            calls.append(command)
            return completed(command, '{"data": []}')

        with tempfile.TemporaryDirectory() as temp_dir:
            terraform_path = _executable(temp_dir, "terraform")
            oci_path = _executable(temp_dir, "oci")
            state_path = Path(temp_dir) / "terraform.tfstate"
            state_path.write_text(
                json.dumps(
                    {
                        "version": 4,
                        "serial": 1,
                        "lineage": "retained-teardown",
                        "outputs": {},
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "oci_core_instance",
                                "instances": [
                                    {
                                        "attributes": {
                                            "source_details": [
                                                {"source_id": retained_source_image}
                                            ]
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            workspace_path = Path(temp_dir) / "workspace"
            result = execute_pilot_standard_rti_teardown(
                workspace_path,
                runner=runner,
                preflight_runner=lambda command: completed(command, '{"data": []}'),
                env={
                    "OCI_CLI_PATH": oci_path,
                    "TERRAFORM_BIN": terraform_path,
                    SSH_PUBLIC_KEY_ENV: "/tmp/pilot.pub",
                    SSH_SOURCE_CIDR_ENV: "198.51.100.10/32",
                    "PATH": "",
                },
                terraform_state_path=state_path,
                host_image_profile=MANAGED_HOST_IMAGE_PROFILES["ubuntu-22.04"],
                progress_callback=progress_events.append,
            )
            rendered_variables = (workspace_path / "variables.tf").read_text(encoding="utf-8")
            rendered_main = (workspace_path / "main.tf").read_text(encoding="utf-8")

        terraform_commands = [
            command[1]
            for command in calls
            if command and Path(command[0]).name == "terraform"
        ]
        self.assertEqual(terraform_commands, ["init", "destroy"])
        self.assertTrue(result.ok)
        self.assertEqual(result.mutation_status, "destroyed")
        self.assertEqual(progress_events[0]["message"], "OCI read preflight completed")
        self.assertEqual(progress_events[1]["message"], "infrastructure command started")
        self.assertEqual(progress_events[1]["data"]["phase"], "Initialize Terraform workspace")
        self.assertIn("Terraform workspace initialized", [event["message"] for event in progress_events])
        self.assertIn(f'default     = "{retained_source_image}"', rendered_variables)
        self.assertIn('default     = "22.04"', rendered_variables)
        self.assertIn('count                    = var.oci_source_image_id == "" ? 1 : 0', rendered_main)

    def test_retained_workspace_teardown_rejects_invalid_image_before_commands(self):
        calls = []

        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "terraform.tfstate"
            state_path.write_text(
                json.dumps(
                    {
                        "version": 4,
                        "serial": 1,
                        "lineage": "invalid-retained-teardown",
                        "outputs": {},
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "oci_core_instance",
                                "instances": [
                                    {"attributes": {"source_details": [{"source_id": 2404}]}}
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "valid source image OCID"):
                execute_pilot_standard_rti_teardown(
                    Path(temp_dir) / "workspace",
                    runner=lambda command, cwd: calls.append(command),
                    preflight_runner=lambda command: calls.append(command),
                    terraform_state_path=state_path,
                    host_image_profile=MANAGED_HOST_IMAGE_PROFILES["ubuntu-22.04"],
                )

        self.assertEqual(calls, [])

    def test_slow_guarded_command_emits_bounded_heartbeat_without_exposing_command(self):
        progress_events = []

        def runner(command, cwd):
            time.sleep(0.035)
            return completed(command, "secret command output")

        with patch("app.integrations.pilot_standard_rti.COMMAND_HEARTBEAT_SECONDS", 0.01), patch(
            "app.integrations.pilot_standard_rti.COMMAND_HEARTBEAT_EVENT_LIMIT", 2
        ):
            result = _run_guarded_command(
                ["ansible-playbook", "--token", "do-not-persist"],
                None,
                runner,
                step="ansible_capabilities",
                progress_callback=progress_events.append,
            )

        self.assertTrue(result.ok)
        self.assertTrue(result.started_at)
        self.assertTrue(result.finished_at)
        self.assertIsNotNone(result.elapsed_seconds)
        self.assertGreaterEqual(result.elapsed_seconds or 0, 0)
        self.assertEqual(progress_events[0]["data"]["eventKind"], "command_started")
        heartbeats = [event for event in progress_events if event["data"]["eventKind"] == "command_heartbeat"]
        self.assertEqual(len(heartbeats), 2)
        self.assertTrue(all(event["data"]["phase"] == "Apply selected RTI capabilities" for event in heartbeats))
        self.assertNotIn("do-not-persist", json.dumps(progress_events))

    def test_ansible_progress_accepts_only_safe_bounded_headers(self):
        events = []

        def emit(event_kind, **data):
            events.append({"eventKind": event_kind, **data})

        emitted = _emit_ansible_progress(
            "PLAY [Configure core] *****\n"
            "TASK [proxy : Install baseline package] *****\n"
            "TASK [set token is supersecret] *****\n"
            "changed: [203.0.113.10] => {raw output}\n",
            emit,
        )

        self.assertEqual(emitted, 2)
        self.assertEqual(events[0]["play"], "Configure core")
        self.assertEqual(events[1]["task"], "proxy : Install baseline package")
        self.assertNotIn("203.0.113.10", json.dumps(events))
        self.assertNotIn("super-secret", json.dumps(events))
        self.assertNotIn("supersecret", json.dumps(events))

        many_events = []
        many_headers = "\n".join(f"TASK [Safe task {index}] *****" for index in range(200))
        self.assertEqual(
            _emit_ansible_progress(many_headers, lambda event_kind, **data: many_events.append(data), limit=ANSIBLE_TASK_EVENT_LIMIT),
            ANSIBLE_TASK_EVENT_LIMIT,
        )
        self.assertEqual(len(many_events), ANSIBLE_TASK_EVENT_LIMIT)
        self.assertEqual(ANSIBLE_TASK_EVENT_LIMIT + COMMAND_HEARTBEAT_EVENT_LIMIT, COMMAND_PROGRESS_EVENT_LIMIT)

    def test_default_runner_streams_safe_task_progress_and_heartbeat(self):
        progress_events = []
        command = [
            sys.executable,
            "-c",
            "import time; print('TASK [proxy : Install baseline tools] *****', flush=True); time.sleep(0.04)",
        ]
        with patch("app.integrations.pilot_standard_rti.COMMAND_HEARTBEAT_SECONDS", 0.01), patch(
            "app.integrations.pilot_standard_rti.COMMAND_OBSERVATION_SECONDS", 0.005
        ), patch("app.integrations.pilot_standard_rti.ANSIBLE_TASK_EVENT_THROTTLE_SECONDS", 0.0):
            result = _run_guarded_command(
                command,
                None,
                _run_command,
                step="ansible_capabilities",
                progress_callback=progress_events.append,
            )

        self.assertTrue(result.ok)
        kinds = [event["data"]["eventKind"] for event in progress_events]
        self.assertIn("ansible_task", kinds)
        self.assertIn("command_heartbeat", kinds)
        task_event = next(event for event in progress_events if event["data"]["eventKind"] == "ansible_task")
        self.assertEqual(task_event["data"]["task"], "proxy : Install baseline tools")

    def test_default_runner_timeout_kills_and_reaps_process(self):
        started = time.monotonic()
        with patch("app.integrations.pilot_standard_rti._command_timeout_seconds", return_value=0.03), patch(
            "app.integrations.pilot_standard_rti.COMMAND_OBSERVATION_SECONDS", 0.005
        ):
            result = _run_guarded_command(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                None,
                _run_command,
                step="terraform_apply",
            )

        self.assertFalse(result.ok)
        self.assertLess(time.monotonic() - started, 1)
        self.assertIn("timed out", result.stderr.lower())

    def test_failed_ansible_capability_apply_writes_full_output_artifacts_and_bounded_excerpt(self):
        failure_intro = "TASK [proxy01 : exact failed task marker]\n" + ("early diagnostic line\n" * 2000)
        failure_tail = ("late recap line\n" * 2000) + "PLAY RECAP proxy01 failed=1\n"
        long_stdout = failure_intro + ("middle noise\n" * 9000) + failure_tail
        progress_events = []

        def runner(command, cwd):
            if any("apply_capabilities" in str(part) for part in command):
                return subprocess.CompletedProcess(command, 2, stdout=long_stdout, stderr="fatal: proxy01 failed")
            if len(command) > 1 and command[1] == "output":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(
                        {
                            "public_ips": {
                                "value": {
                                    "homebase": "203.0.113.10",
                                    "proxy01": "203.0.113.11",
                                }
                            }
                        }
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            terraform_path = _executable(temp_dir, "terraform")
            oci_path = _executable(temp_dir, "oci")
            ansible_path = _executable(temp_dir, "ansible")
            ansible_playbook_path = _executable(temp_dir, "ansible-playbook")
            workspace = Path(temp_dir) / "workspace"
            result = execute_pilot_standard_rti(
                workspace,
                runner=runner,
                preflight_runner=lambda command: completed(command, '{"data": []}'),
                env={
                    "OCI_CLI_PATH": oci_path,
                    "TERRAFORM_BIN": terraform_path,
                    "ANSIBLE_BIN": ansible_path,
                    "ANSIBLE_PLAYBOOK_BIN": ansible_playbook_path,
                    SSH_PUBLIC_KEY_ENV: "/tmp/pilot.pub",
                    SSH_PRIVATE_KEY_ENV: "/tmp/pilot",
                    SSH_SOURCE_CIDR_ENV: "198.51.100.10/32",
                    "PATH": "",
                },
                deployment_mode="destroy_after_validation",
                proxy_count=1,
                progress_callback=progress_events.append,
            )

            self.assertFalse(result.ok)
            self.assertEqual(result.mutation_status, "ansible_failed")
            failure_event = next(
                event for event in progress_events
                if event["message"] == "Ansible selected capabilities apply completed"
            )
            data = failure_event["data"]
            self.assertEqual(data["status"], "failed")
            self.assertIn("failureOutputExcerpt", data)
            self.assertEqual(data["failureOutput"], data["failureOutputExcerpt"])
            self.assertIn("exact failed task marker", data["failureOutputExcerpt"])
            self.assertIn("PLAY RECAP proxy01 failed=1", data["failureOutputExcerpt"])
            self.assertIn("[... truncated", data["failureOutputExcerpt"])
            self.assertLess(len(data["failureOutputExcerpt"]), len(long_stdout))
            refs = data["commandOutputArtifactRefs"]
            self.assertTrue(any(ref.endswith("/logs/ansible_capabilities.stdout.log") for ref in refs))
            stdout_ref = next(ref for ref in refs if ref.endswith("/logs/ansible_capabilities.stdout.log"))
            stdout_path = Path(stdout_ref.removeprefix("workspace:"))
            self.assertEqual(stdout_path.read_text(encoding="utf-8"), long_stdout)


class PilotStandardRtiServiceTests(unittest.TestCase):
    def setUp(self):
        patcher = patch("app.services.guarded_test_deployment.get_engagement", side_effect=fake_get_engagement)
        patcher.start()
        self.addCleanup(patcher.stop)
        workspace_patcher = patch(
            "app.services.guarded_test_deployment.prepare_core_deployment_run",
            side_effect=lambda *_args, **kwargs: SimpleNamespace(
                run_directory=Path(kwargs["root"]) / "test-core-run",
                state_path=Path(kwargs["state_root"]) / "test.tfstate",
                terraform_data_dir=Path(kwargs["state_root"]) / "test-data",
                state_locator="engagement/eng-zy01/core/terraform.tfstate",
            ),
        )
        workspace_patcher.start()
        self.addCleanup(workspace_patcher.stop)
        state_patcher = patch(
            "app.services.guarded_test_deployment.core_deployment_state_path",
            return_value=Path("/private/state/test.tfstate"),
        )
        state_patcher.start()
        self.addCleanup(state_patcher.stop)

    def test_readiness_exposes_pilot_target_topology_and_guardrails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            readiness = pilot_standard_rti_readiness(
                env={
                    "OCI_CLI_PATH": _executable(temp_dir, "oci"),
                    "TERRAFORM_BIN": _executable(temp_dir, "terraform"),
                    "ANSIBLE_BIN": _executable(temp_dir, "ansible"),
                    "ANSIBLE_PLAYBOOK_BIN": _executable(temp_dir, "ansible-playbook"),
                    SSH_PUBLIC_KEY_ENV: "/tmp/pilot.pub",
                    SSH_PRIVATE_KEY_ENV: "/tmp/pilot",
                    SSH_SOURCE_CIDR_ENV: "198.51.100.10/32",
                    "PATH": "",
                }
            )

        self.assertEqual(readiness["target"]["name"], "barragan-testing")
        self.assertEqual(readiness["target"]["compartmentId"], BARRAGAN_TESTING_COMPARTMENT_ID)
        self.assertEqual(readiness["target"]["region"], DEFAULT_REGION)
        self.assertEqual(readiness["workspace"], WORKSPACE_NAME)
        self.assertEqual(readiness["expectedInstanceDisplayNames"], [PILOT_HOMEBASE_NAME, PILOT_PROXY_NAME, PILOT_PROXY02_NAME])
        self.assertEqual(readiness["topology"]["vcnCidr"], PILOT_CIDR)
        self.assertEqual(readiness["topology"]["subnets"][0]["cidr"], PILOT_HOMEBASE_CIDR)
        self.assertEqual(readiness["topology"]["subnets"][1]["cidr"], PILOT_PROXY_CIDR)
        self.assertEqual(readiness["confirmationToken"], EXECUTION_CONFIRMATION)
        self.assertFalse(readiness["cleanupAcknowledgement"]["required"])
        self.assertTrue(readiness["commandResolution"]["terraform"]["ok"])
        self.assertFalse(readiness["sshIngress"]["allowsPublicInternet"])
        self.assertIn("RedTeam", readiness["guardrails"]["noTouchCompartments"])
        self.assertIn("Vault/KMS/secrets", readiness["guardrails"]["disallowedResourceFamilies"])
        self.assertIn('ssh_source_cidrs=["198.51.100.10/32"]', readiness["commands"]["planned"][1])
        self.assertEqual(readiness["deploymentModes"]["default"], "hold_for_review")
        self.assertEqual(readiness["sshIngress"]["defaultSourceCidrs"], ["198.51.100.10/32"])
        self.assertIn("base host layout", readiness["mutationScope"])
        self.assertIn("configure /dropbox NFS export and proxy mounts", readiness["guardrails"]["harmlessAnsibleActions"])
        self.assertIn("create /engagement workspace on homebase", readiness["guardrails"]["harmlessAnsibleActions"])
        self.assertIn("create /opt/proxy01 and /opt/proxy02 on homebase", readiness["guardrails"]["harmlessAnsibleActions"])
        self.assertTrue(readiness["imdsHardening"]["legacyEndpointsDisabled"])
        self.assertEqual(readiness["imdsHardening"]["terraformAttribute"], "instance_options.are_legacy_imds_endpoints_disabled")
        self.assertGreaterEqual(len(readiness["commands"]["cleanupVerification"]), 9)

    def test_run_rejects_missing_confirmation_without_execution(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append(workspace_dir)
            return {"ok": True}

        with self.assertRaises(GuardedDeploymentConfirmationError):
            run_guarded_pilot_standard_rti({}, executor=executor)

        self.assertEqual(calls, [])

    def test_run_rejects_missing_cleanup_ack_for_immediate_destroy_without_execution(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append(workspace_dir)
            return {"ok": True}

        with self.assertRaises(GuardedDeploymentConfirmationError):
            run_guarded_pilot_standard_rti(
                {"confirmMutation": EXECUTION_CONFIRMATION, "deploymentMode": "destroy_after_validation"},
                executor=executor,
            )

        self.assertEqual(calls, [])

    def test_run_rejects_public_ssh_source_cidr_without_execution(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append(workspace_dir)
            return {"ok": True}

        with self.assertRaises(GuardedDeploymentConfirmationError):
            run_guarded_pilot_standard_rti(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "sshSourceCidrs": ["0.0.0.0/0"],
                },
                executor=executor,
            )

        self.assertEqual(calls, [])

    def test_run_invokes_executor_with_confirmed_workspace_dir(self):
        calls = []

        class FakeResult:
            def to_dict(self):
                return {
                    "ok": True,
                    "workspace": WORKSPACE_NAME,
                    "deploymentMode": "hold_for_review",
                    "mutationStatus": "deployed",
                    "finalCleanupStatus": "pending_operator_teardown",
                }

        def executor(workspace_dir, **kwargs):
            calls.append((workspace_dir, kwargs))
            return FakeResult()

        result = run_guarded_pilot_standard_rti(
            {
                "confirmMutation": EXECUTION_CONFIRMATION,
                "confirmDestroyCleanup": False,
                "deploymentMode": "hold_for_review",
                "workspaceDir": "/tmp/barragan-pilot-service",
                "engagementId": "eng-zy01",
                "sshPrivateKeyPath": "/tmp/private-key",
                "sshPublicKeyPath": "/tmp/public-key.pub",
                "sshSourceCidrs": ["198.51.100.10/32", "160.34.86.0/23"],
            },
            executor=executor,
        )

        self.assertEqual(calls[0][0], Path("/opt/engagements/test-core-run"))
        self.assertEqual(calls[0][1]["ssh_private_key_path"], "/tmp/private-key")
        self.assertEqual(calls[0][1]["ssh_public_key_path"], "/tmp/public-key.pub")
        self.assertEqual(calls[0][1]["ssh_source_cidrs"], ["198.51.100.10/32", "160.34.86.0/23"])
        self.assertEqual(calls[0][1]["deployment_mode"], "hold_for_review")
        self.assertEqual(calls[0][1]["engagement_name"], "ZY01")
        self.assertEqual(result["deployment"]["workspace"], WORKSPACE_NAME)
        self.assertEqual(result["deployment"]["mutationStatus"], "deployed")

    def test_job_backed_run_persists_ordered_success_events_and_sanitized_input(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append((workspace_dir, kwargs))
            return {
                "ok": True,
                **pilot_execution_result(workspace_dir, engagement_name=kwargs["engagement_name"]),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshPrivateKeyPath": "/tmp/secret-private-key",
                    "sshPublicKeyPath": "/tmp/secret-public-key.pub",
                    "sshSourceCidrs": ["198.51.100.10/32", "160.34.86.0/23"],
                    "requestedBy": "operator@example.invalid",
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
                engagement_workspace_root=Path(temp_dir) / "engagements",
                terraform_state_root=Path(temp_dir) / "state",
            )
            persisted = repository.get(job.id)
            final_job = persisted.to_detail() if persisted is not None else None

        self.assertIsNotNone(persisted)
        self.assertIsNotNone(final_job)
        self.assertEqual(job.status, "running")
        self.assertEqual(final_job.status, "succeeded")
        self.assertEqual(final_job.action, "pilot_standard_rti_guarded_execute")
        self.assertEqual(final_job.input["sshSourceCidrs"], ["198.51.100.10/32", "160.34.86.0/23"])
        self.assertEqual(final_job.input["deploymentMode"], "hold_for_review")
        self.assertEqual(final_job.input["engagementId"], "eng-zy01")
        self.assertNotIn("sshPrivateKeyPath", final_job.input)
        self.assertNotIn("sshPublicKeyPath", final_job.input)
        self.assertEqual([event.sequence for event in final_job.events], list(range(1, len(final_job.events) + 1)))
        self.assertIn("pilot Standard RTI executor running", [event.message for event in final_job.events])
        self.assertIn("Terraform apply completed", [event.message for event in final_job.events])
        self.assertIn("SSH readiness validation completed", [event.message for event in final_job.events])
        self.assertIn("Ansible bootstrap validation completed", [event.message for event in final_job.events])
        self.assertIn("operator inspection ready", [event.message for event in final_job.events])
        self.assertEqual(
            final_job.events[-1].data["connectionDetails"][0]["sshCommand"],
            "ssh homebase-zy01",
        )
        self.assertEqual(final_job.events[-1].data["connectionDetails"][0]["region"], DEFAULT_REGION)
        self.assertEqual(final_job.events[-1].data["connectionDetails"][1]["region"], DEFAULT_REGION)
        self.assertIn("proxy config banks", final_job.events[-1].data["connectionDetails"][0]["services"])
        self.assertNotIn("nmap", final_job.events[-1].data["connectionDetails"][0]["services"])
        self.assertIn("nmap", final_job.events[-1].data["connectionDetails"][1]["services"])
        self.assertEqual(final_job.events[-1].data["outboundChannels"][0]["proxy"], "proxy01-zy01")
        self.assertEqual(final_job.events[-1].data["outboundChannels"][0]["edge"], "Not Deployed")
        self.assertEqual(final_job.events[-1].data["inboundChannels"], [])
        self.assertEqual(calls[0][1]["ssh_private_key_path"], "/tmp/secret-private-key")
        serialized_job = json.dumps(final_job.to_dict(), sort_keys=True)
        self.assertNotIn("/tmp/secret-private-key", serialized_job)
        self.assertNotIn("/tmp/secret-public-key.pub", serialized_job)

    @patch("app.services.guarded_test_deployment.try_enqueue_infra_orientation_refresh")
    def test_job_backed_hold_for_review_run_enqueues_orientation_refresh(self, enqueue_refresh):
        def executor(workspace_dir, **kwargs):
            return {
                "ok": True,
                **pilot_execution_result(
                    workspace_dir,
                    mode="hold_for_review",
                    engagement_name=kwargs["engagement_name"],
                ),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )
            finished = repository.get(job.id).to_detail()

        self.assertEqual(finished.status, "succeeded")
        enqueue_refresh.assert_called_once_with("eng-zy01", repository=repository)

    @patch("app.services.guarded_test_deployment._is_runtime_durable_job_repository", return_value=True)
    @patch(
        "app.services.guarded_test_deployment.ensure_continuous_inspector_ready",
        return_value={"required": True, "ready": False, "status": "failed", "errors": ["baseline unavailable"]},
    )
    def test_core_readiness_failure_blocks_post_core_continuation(self, ensure_inspector, runtime_repository):
        def executor(workspace_dir, **kwargs):
            return {
                "ok": True,
                **pilot_execution_result(
                    workspace_dir,
                    mode="hold_for_review",
                    engagement_name=kwargs["engagement_name"],
                ),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )
            finished = repository.get(job.id).to_detail()

        runtime_repository.assert_called_once_with(repository)
        ensure_inspector.assert_called_once_with("eng-zy01", requested_by="core-deployment", job_repository=repository)
        self.assertEqual(finished.status, "failed")
        self.assertFalse(finished.input["postCoreSketchContinuationEligible"])
        self.assertEqual(finished.input["inspectorReadiness"]["status"], "failed")
        self.assertIn("continuous Inspector readiness started", [event.message for event in finished.events])
        self.assertIn("continuous Inspector readiness failed; deployed core is retained", [event.message for event in finished.events])
        self.assertNotIn("operator inspection ready", [event.message for event in finished.events])
        self.assertEqual(finished.events[-1].message, "pilot Standard RTI run finished")
        self.assertEqual(finished.events[-1].level, "error")

    @patch("app.services.guarded_test_deployment._is_runtime_durable_job_repository", return_value=True)
    @patch(
        "app.services.guarded_test_deployment.ensure_continuous_inspector_ready",
        return_value={"required": True, "ready": True, "status": "ready"},
    )
    def test_core_readiness_success_announces_operations_only_after_inspector(self, ensure_inspector, runtime_repository):
        def executor(workspace_dir, **kwargs):
            return {
                "ok": True,
                **pilot_execution_result(
                    workspace_dir,
                    mode="hold_for_review",
                    engagement_name=kwargs["engagement_name"],
                ),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )
            finished = repository.get(job.id).to_detail()

        messages = [event.message for event in finished.events]
        self.assertEqual(finished.status, "succeeded")
        self.assertLess(messages.index("continuous Inspector readiness started"), messages.index("continuous Inspector readiness succeeded"))
        self.assertLess(messages.index("continuous Inspector readiness succeeded"), messages.index("operator inspection ready"))
        self.assertEqual(messages.count("OCI read preflight completed"), 1)
        self.assertEqual(finished.events[-1].message, "pilot Standard RTI run finished")
        runtime_repository.assert_called_once_with(repository)
        ensure_inspector.assert_called_once_with("eng-zy01", requested_by="core-deployment", job_repository=repository)

    @patch("app.services.guarded_test_deployment.start_post_core_sketch_continuation")
    @patch("app.services.guarded_test_deployment.snapshot_pending_sketch_chain_ids", return_value=["chain-a", "chain-b"])
    def test_retained_core_run_persists_exact_sketch_snapshot_and_starts_server_continuation(
        self, snapshot_pending, start_continuation
    ):
        def executor(workspace_dir, **kwargs):
            return {
                "ok": True,
                **pilot_execution_result(
                    workspace_dir,
                    mode="hold_for_review",
                    engagement_name=kwargs["engagement_name"],
                ),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            sketch_repository = object()
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                sketch_repository=sketch_repository,
                background_runner=lambda task: task(),
            )
            finished = repository.get(job.id)

        self.assertEqual(finished.input["pendingSketchChainIds"], ["chain-a", "chain-b"])
        self.assertTrue(finished.input["postCoreSketchContinuationEligible"])
        snapshot_pending.assert_called_once_with("eng-zy01", repository=sketch_repository)
        start_continuation.assert_called_once_with(job.id, job_repository=repository)

    @patch("app.services.guarded_test_deployment.try_enqueue_infra_orientation_refresh")
    def test_job_backed_destroy_after_validation_run_skips_orientation_refresh(self, enqueue_refresh):
        def executor(workspace_dir, **kwargs):
            return {
                "ok": True,
                **pilot_execution_result(
                    workspace_dir,
                    mode="destroy_after_validation",
                    engagement_name=kwargs["engagement_name"],
                ),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": True,
                    "deploymentMode": "destroy_after_validation",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )
            finished = repository.get(job.id).to_detail()

        self.assertEqual(finished.status, "succeeded")
        self.assertFalse(finished.input["postCoreSketchContinuationEligible"])
        enqueue_refresh.assert_not_called()

    def test_job_backed_run_returns_before_background_executor_completes(self):
        calls = []
        scheduled = []

        def executor(workspace_dir, **kwargs):
            calls.append((workspace_dir, kwargs))
            return {"ok": True, **pilot_execution_result(workspace_dir)}

        def background_runner(task):
            scheduled.append(task)

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=background_runner,
            )
            in_progress = repository.get(job.id).to_detail()
            calls_before_background_release = list(calls)
            scheduled[0]()
            finished = repository.get(job.id).to_detail()

        self.assertEqual(job.status, "running")
        self.assertEqual(in_progress.status, "running")
        self.assertEqual([event.message for event in in_progress.events], [
            "pilot Standard RTI run queued",
            "pilot Standard RTI run started",
        ])
        self.assertEqual(calls_before_background_release, [])
        self.assertEqual(finished.status, "succeeded")
        self.assertIn("pilot Standard RTI executor running", [event.message for event in finished.events])

    def test_job_backed_run_rejects_second_core_deploy_without_recreate_confirmation(self):
        def executor(workspace_dir, **kwargs):
            return {"ok": True, **pilot_execution_result(workspace_dir, engagement_name=kwargs["engagement_name"])}

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            first_job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )

            with self.assertRaisesRegex(GuardedDeploymentConfirmationError, "active core infrastructure already exists"):
                start_guarded_pilot_standard_rti_run(
                    {
                        "confirmMutation": EXECUTION_CONFIRMATION,
                        "confirmDestroyCleanup": False,
                        "deploymentMode": "hold_for_review",
                        "engagementId": "eng-zy01",
                        "workspaceDir": str(Path(temp_dir) / "second-pilot-workspace"),
                        "sshSourceCidrs": ["198.51.100.10/32"],
                    },
                    executor=executor,
                    repository=repository,
                    background_runner=lambda task: task(),
                )

            recreate_job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "recreate-pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                    "recreateCore": True,
                    "recreateConfirmation": "recreate-core-zy01",
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )
            persisted_recreate = repository.get(recreate_job.id)

        self.assertNotEqual(first_job.id, recreate_job.id)
        self.assertIsNotNone(persisted_recreate)
        self.assertTrue(persisted_recreate.input["recreateCore"])

    def test_job_detail_recovers_connection_details_from_runtime_inventory(self):
        def executor(workspace_dir, **kwargs):
            inventory_dir = Path(workspace_dir) / "ansible"
            inventory_dir.mkdir(parents=True, exist_ok=True)
            (inventory_dir / "runtime_inventory.ini").write_text(
                "\n".join(
                    [
                        "[homebase]",
                        "homebase ansible_host=146.235.219.8 ansible_user=ubuntu rti_role=homebase private_ip=192.168.0.10",
                        "",
                        "[proxies]",
                        "proxy01 ansible_host=170.9.62.26 ansible_user=ubuntu rti_role=proxy private_ip=192.168.2.11",
                        "proxy02 ansible_host=170.9.62.27 ansible_user=ubuntu rti_role=proxy private_ip=192.168.2.12",
                    ]
                ),
                encoding="utf-8",
            )
            result = pilot_execution_result(workspace_dir, engagement_name=kwargs["engagement_name"])
            result.pop("connectionDetails", None)
            return {"ok": True, **result}

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
                engagement_workspace_root=Path(temp_dir) / "engagements",
                terraform_state_root=Path(temp_dir) / "state",
            )
            detail = get_guarded_pilot_standard_rti_run(job.id, repository=repository)

        self.assertIsNotNone(detail)
        recovered_event = detail.events[-1]
        self.assertEqual(recovered_event.message, "operator connection details recovered")
        self.assertEqual(recovered_event.data["connectionDetails"][0]["sshCommand"], "ssh homebase-zy01")
        self.assertEqual(recovered_event.data["connectionDetails"][0]["region"], DEFAULT_REGION)
        self.assertEqual(recovered_event.data["connectionDetails"][1]["region"], DEFAULT_REGION)
        self.assertEqual(recovered_event.data["connectionDetails"][2]["sshCommand"], "ssh proxy02-zy01")
        self.assertEqual(recovered_event.data["connectionDetails"][2]["publicIp"], "170.9.62.27")

    def test_job_backed_run_persists_progress_events_while_executor_is_active(self):
        observed_during_executor = []

        def executor(workspace_dir, **kwargs):
            kwargs["progress_callback"](
                {
                    "level": "info",
                    "message": "Terraform init completed",
                    "data": {"step": "terraform_init", "status": "succeeded", "returncode": 0},
                }
            )
            active_job = repository.list()[0].to_detail()
            observed_during_executor.append([event.message for event in active_job.events])
            return {
                "ok": True,
                **pilot_execution_result(workspace_dir, engagement_name=kwargs["engagement_name"]),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )
            finished = repository.get(job.id).to_detail()

        self.assertIn("Terraform init completed", observed_during_executor[0])
        self.assertEqual(finished.status, "succeeded")
        self.assertEqual(
            [event.message for event in finished.events].count("Terraform init completed"),
            1,
        )
        self.assertIn("Terraform apply completed", [event.message for event in finished.events])

    def test_job_backed_run_records_failed_status_and_error_event(self):
        def executor(workspace_dir, **kwargs):
            return {
                "ok": False,
                **pilot_execution_result(workspace_dir, apply_ok=False, engagement_name=kwargs["engagement_name"]),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )
            persisted = repository.get(job.id).to_detail()

        self.assertEqual(job.status, "running")
        self.assertEqual(persisted.status, "failed")
        self.assertTrue(any(event.level == "error" for event in persisted.events))
        self.assertEqual(persisted.events[-1].message, "pilot Standard RTI run finished")
        self.assertEqual(persisted.events[-1].data["mutationStatus"], "apply_failed")

    def test_job_backed_run_redacts_key_paths_from_exception_event(self):
        private_key_path = "/home/operator/.ssh/pilot_ed25519"
        public_key_path = "/tmp/secret-public-key.pub"
        generated_key_path = "/tmp/evaluator/generated-private-key.pem"
        env_key_path = "/tmp/env-secret-key"

        def executor(workspace_dir, **kwargs):
            raise RuntimeError(
                "failed to use "
                f"{private_key_path}, {public_key_path}, {env_key_path}, "
                f"--private-key {generated_key_path}, "
                f"ansible_ssh_private_key_file={generated_key_path}"
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            with patch.dict(os.environ, {SSH_PRIVATE_KEY_ENV: env_key_path}):
                job = start_guarded_pilot_standard_rti_run(
                    {
                        "confirmMutation": EXECUTION_CONFIRMATION,
                        "confirmDestroyCleanup": False,
                        "deploymentMode": "hold_for_review",
                        "engagementId": "eng-zy01",
                        "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                        "sshPrivateKeyPath": Path(private_key_path),
                        "sshPublicKeyPath": public_key_path,
                        "sshSourceCidrs": ["198.51.100.10/32"],
                    },
                    executor=executor,
                    repository=repository,
                    background_runner=lambda task: task(),
                )
                persisted = repository.get(job.id).to_detail()

        serialized_job = json.dumps(persisted.to_dict(), sort_keys=True)
        self.assertEqual(job.status, "running")
        self.assertEqual(persisted.status, "failed")
        self.assertIn("errorType", persisted.events[-1].data)
        self.assertIn("[redacted SSH key path]", persisted.events[-1].data["error"])
        self.assertNotIn(private_key_path, serialized_job)
        self.assertNotIn(public_key_path, serialized_job)
        self.assertNotIn(generated_key_path, serialized_job)
        self.assertNotIn(env_key_path, serialized_job)

    def test_job_backed_run_persists_nonterminal_command_activity_for_reload(self):
        def executor(workspace_dir, **kwargs):
            progress = kwargs["progress_callback"]
            progress({
                "level": "info",
                "message": "infrastructure command started",
                "data": {
                    "eventKind": "command_started",
                    "step": "ansible_capabilities",
                    "phase": "Apply selected RTI capabilities",
                    "startedAt": "2026-07-31T12:00:00+00:00",
                    "observedAt": "2026-07-31T12:00:00+00:00",
                },
            })
            progress({
                "level": "info",
                "message": "infrastructure command heartbeat",
                "data": {
                    "eventKind": "command_heartbeat",
                    "step": "ansible_capabilities",
                    "phase": "Apply selected RTI capabilities",
                    "startedAt": "2026-07-31T12:00:00+00:00",
                    "observedAt": "2026-07-31T12:00:20+00:00",
                    "elapsedSeconds": 20,
                },
            })
            return {"ok": True, **pilot_execution_result(workspace_dir)}

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=executor,
                repository=repository,
                background_runner=lambda task: task(),
            )
            persisted = repository.get(job.id)

        activity = [event for event in persisted.events if event.data.get("eventKind") in {"command_started", "command_heartbeat"}]
        self.assertEqual([event.data["eventKind"] for event in activity], ["command_started", "command_heartbeat"])
        self.assertEqual(activity[-1].data["elapsedSeconds"], 20)

    def test_job_backed_run_rejects_guardrail_failures_before_job_creation(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append(workspace_dir)
            return {"ok": True}

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            with self.assertRaises(GuardedDeploymentConfirmationError):
                start_guarded_pilot_standard_rti_run(
                    {
                        "confirmMutation": EXECUTION_CONFIRMATION,
                        "confirmDestroyCleanup": False,
                        "deploymentMode": "hold_for_review",
                        "sshSourceCidrs": ["0.0.0.0/0"],
                    },
                    executor=executor,
                    repository=repository,
                    background_runner=lambda task: task(),
                )

            self.assertEqual(repository.list(), [])
            self.assertEqual(calls, [])


class PilotStandardRtiApiTests(unittest.TestCase):
    def setUp(self):
        patcher = patch("app.services.guarded_test_deployment.get_engagement", side_effect=fake_get_engagement)
        patcher.start()
        self.addCleanup(patcher.stop)
        workspace_patcher = patch(
            "app.services.guarded_test_deployment.prepare_core_deployment_run",
            side_effect=lambda *_args, **kwargs: SimpleNamespace(
                run_directory=Path(kwargs["root"]) / "test-core-run",
                state_path=Path(kwargs["state_root"]) / "test.tfstate",
                terraform_data_dir=Path(kwargs["state_root"]) / "test-data",
                state_locator="engagement/eng-zy01/core/terraform.tfstate",
            ),
        )
        workspace_patcher.start()
        self.addCleanup(workspace_patcher.stop)
        state_patcher = patch(
            "app.services.guarded_test_deployment.core_deployment_state_path",
            return_value=Path("/private/state/test.tfstate"),
        )
        state_patcher.start()
        self.addCleanup(state_patcher.stop)

    def test_readiness_endpoint_returns_operator_payload(self):
        from app import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        client = app.test_client()

        response = client.get("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")
        body = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["readiness"]["confirmationToken"], EXECUTION_CONFIRMATION)
        self.assertEqual(body["readiness"]["expectedInstanceDisplayNames"], [PILOT_HOMEBASE_NAME, PILOT_PROXY_NAME, PILOT_PROXY02_NAME])

    def test_run_endpoint_rejects_bad_confirmation_before_execution(self):
        from app import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        client = app.test_client()

        response = client.post(
            "/api/orchestrator/barragan-testing/pilot-standard-rti/run",
            json={"confirmMutation": "wrong", "confirmDestroyCleanup": True},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("confirmMutation", response.get_json()["error"])

    def test_run_endpoint_returns_fake_execution_result(self):
        from app import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        client = app.test_client()

        with patch(
            "app.asgi.run_guarded_pilot_standard_rti",
            return_value={
                "deployment": {
                    "ok": True,
                    "workspace": WORKSPACE_NAME,
                    "deploymentMode": "hold_for_review",
                    "mutationStatus": "deployed",
                    "finalCleanupStatus": "pending_operator_teardown",
                }
            },
        ) as mocked:
            response = client.post(
                "/api/orchestrator/barragan-testing/pilot-standard-rti/run",
                json={
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["deployment"]["ok"])
        mocked.assert_called_once()

    def test_job_backed_run_endpoint_returns_persisted_status_history(self):
        from app import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        client = app.test_client()

        with patch(
            "app.asgi.start_guarded_pilot_standard_rti_run",
            return_value=FakeJobDetail("job-pilot-001"),
        ) as mocked_start:
            response = client.post(
                "/api/orchestrator/barragan-testing/pilot-standard-rti/runs",
                json={
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["job"]["id"], "job-pilot-001")
        self.assertEqual(response.get_json()["job"]["events"][0]["message"], "pilot Standard RTI run queued")
        mocked_start.assert_called_once()

    def test_job_backed_status_endpoint_returns_404_for_unknown_run(self):
        from app import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        client = app.test_client()

        with patch("app.asgi.get_guarded_pilot_standard_rti_run", return_value=None):
            response = client.get("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-missing")

        self.assertEqual(response.status_code, 404)

    def test_job_backed_teardown_invokes_destroy_for_held_deployment(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append((workspace_dir, kwargs))
            return {"ok": True, **pilot_execution_result(workspace_dir, mode="destroy_after_validation")}

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=lambda workspace_dir, **kwargs: {
                    "ok": True,
                    **pilot_execution_result(workspace_dir, mode="hold_for_review"),
                },
                repository=repository,
                background_runner=lambda task: task(),
                engagement_workspace_root=Path(temp_dir) / "engagements",
                terraform_state_root=Path(temp_dir) / "state",
            )

            with patch(
                "app.services.guarded_test_deployment.verify_retired_public_endpoints_for_teardown",
                return_value={
                    "ok": True,
                    "status": "verified_absent",
                    "targetCount": 3,
                    "targets": [],
                    "evidence": {"ok": True, "results": []},
                },
            ) as verify_teardown, patch(
                "app.services.guarded_test_deployment.cleanup_inspector_for_infrastructure_teardown",
                return_value={
                    "ok": True,
                    "status": "disabled_no_host",
                    "disabled": True,
                    "cleanupVerified": True,
                    "currentHostCleared": True,
                    "inspectorHost": {},
                },
            ) as cleanup_inspector:
                finished = teardown_guarded_pilot_standard_rti_run(
                    job.id,
                    executor=executor,
                    repository=repository,
                )

        self.assertIsNotNone(finished)
        self.assertEqual(finished.status, "succeeded")
        self.assertEqual(calls[0][0], Path(temp_dir) / "engagements" / "test-core-run")
        self.assertEqual(calls[0][1]["ssh_source_cidrs"], ["198.51.100.10/32"])
        self.assertEqual(calls[0][1]["engagement_id"], "eng-zy01")
        self.assertEqual(calls[0][1]["terraform_state_path"], Path("/private/state/test.tfstate"))
        self.assertIn("operator teardown requested", [event.message for event in finished.events])
        self.assertIn("cleanup verification completed", [event.message for event in finished.events])
        self.assertIn("Inspector teardown verification requested", [event.message for event in finished.events])
        self.assertIn("Inspector teardown verification completed", [event.message for event in finished.events])
        self.assertIn("Inspector cleanup requested", [event.message for event in finished.events])
        self.assertIn("Inspector cleanup completed", [event.message for event in finished.events])
        self.assertIn("pilot Standard RTI teardown finished", [event.message for event in finished.events])
        self.assertIs(finished.events[-1].data["ok"], True)
        self.assertEqual(finished.events[-1].data["finalCleanupStatus"], "verified_clean")
        self.assertEqual(finished.events[-1].data["inspectorTeardownVerification"]["status"], "verified_absent")
        self.assertEqual(finished.events[-1].data["inspectorCleanup"]["status"], "disabled_no_host")
        verify_teardown.assert_called_once()
        cleanup_inspector.assert_called_once_with("eng-zy01", "ZY01", job.id)

    def test_job_backed_teardown_resumes_verified_core_cleanup_without_executor(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION, "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review", "engagementId": "eng-resume",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"), "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=lambda workspace_dir, **kwargs: {"ok": True, **pilot_execution_result(workspace_dir, mode="hold_for_review")},
                repository=repository, background_runner=lambda task: task(),
                engagement_workspace_root=Path(temp_dir) / "engagements",
            )
            stored = repository.get(job.id)
            workspace = str(stored.input["workspaceDir"])
            repository.save(replace(stored, status="failed", events=stored.events + [
                JobEvent(108, "info", "operator teardown requested", {"workspaceDir": workspace}),
                JobEvent(119, "info", "cleanup verification completed", {"status": "verified_clean", "ok": True, "remainingCount": 0}),
                JobEvent(120, "error", "pilot Standard RTI teardown finished", {"workspaceDir": workspace, "mutationStatus": "destroyed", "finalCleanupStatus": "verified_clean", "coreCleanupStatus": "verified_clean", "inspectorTeardownVerification": {"ok": False}}),
                JobEvent(121, "info", "operator teardown requested", {"workspaceDir": workspace}),
                JobEvent(123, "error", "pilot Standard RTI teardown failed before a result was returned", {}),
            ]))
            executor_calls = []
            with patch("app.services.guarded_test_deployment.verify_retired_public_endpoints_for_teardown", return_value={"ok": True, "status": "verified_absent", "targetCount": 0, "targets": [], "inspectorHost": {}}), patch(
                "app.services.guarded_test_deployment.cleanup_inspector_for_infrastructure_teardown",
                return_value={"ok": True, "status": "destroyed", "cleanupVerified": True, "currentHostCleared": True, "inspectorHost": {}},
            ):
                finished = teardown_guarded_pilot_standard_rti_run(
                    job.id, executor=lambda *_a, **_k: executor_calls.append(True), repository=repository,
                )
        self.assertEqual(executor_calls, [])
        self.assertEqual(finished.status, "succeeded")
        self.assertIn("core Terraform cleanup skipped from durable prior proof", [event.message for event in finished.events])

    def test_legacy_job_teardown_uses_state_from_recorded_workspace(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append((workspace_dir, kwargs))
            return {"ok": True, **pilot_execution_result(workspace_dir, mode="destroy_after_validation")}

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "legacy-core-run"
            workspace.mkdir()
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = enqueue_job(
                action=PILOT_JOB_ACTION,
                target_type="oci_compartment",
                target_id="barragan-testing",
                requested_by="operator",
                input_data={
                    "engagementId": "eng-legacy",
                    "engagementName": "legacy",
                    "workspaceDir": str(workspace),
                    "proxyCount": 1,
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                repository=repository,
            )
            with patch(
                "app.services.guarded_test_deployment.verify_retired_public_endpoints_for_teardown",
                return_value={"ok": True, "status": "verified_absent", "targets": [], "evidence": {}},
            ), patch(
                "app.services.guarded_test_deployment.cleanup_inspector_for_infrastructure_teardown",
                return_value={"ok": True, "status": "disabled_no_host", "cleanupVerified": True},
            ):
                finished = teardown_guarded_pilot_standard_rti_run(
                    job.id,
                    executor=executor,
                    repository=repository,
                )

        self.assertEqual(finished.status, "succeeded")
        self.assertEqual(calls[0][0], workspace)
        self.assertEqual(calls[0][1]["terraform_state_path"], workspace / "terraform.tfstate")
        self.assertEqual(calls[0][1]["engagement_id"], "eng-legacy")

    def test_job_backed_teardown_fails_if_inspector_cleanup_is_not_verified(self):
        def executor(workspace_dir, **kwargs):
            return {"ok": True, **pilot_execution_result(workspace_dir, mode="destroy_after_validation")}

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=lambda workspace_dir, **kwargs: {
                    "ok": True,
                    **pilot_execution_result(workspace_dir, mode="hold_for_review"),
                },
                repository=repository,
                background_runner=lambda task: task(),
            )

            with patch(
                "app.services.guarded_test_deployment.verify_retired_public_endpoints_for_teardown",
                return_value={
                    "ok": True,
                    "status": "verified_absent",
                    "targetCount": 3,
                    "targets": [],
                    "evidence": {"ok": True, "results": []},
                },
            ), patch(
                "app.services.guarded_test_deployment.cleanup_inspector_for_infrastructure_teardown",
                return_value={
                    "ok": False,
                    "status": "cleanup_required",
                    "disabled": True,
                    "cleanupVerified": False,
                    "currentHostCleared": False,
                    "inspectorHost": {"resourceId": "12345", "name": "inspector-zy01"},
                    "errors": ["provider destroy did not confirm removal"],
                },
            ):
                finished = teardown_guarded_pilot_standard_rti_run(
                    job.id,
                    executor=executor,
                    repository=repository,
                )

        self.assertIsNotNone(finished)
        self.assertEqual(finished.status, "failed")
        self.assertIn("Inspector cleanup failed", [event.message for event in finished.events])
        self.assertEqual(finished.events[-1].level, "error")
        self.assertEqual(finished.events[-1].data["finalCleanupStatus"], "verified_clean")
        self.assertEqual(finished.events[-1].data["inspectorCleanup"]["status"], "cleanup_required")

    def test_job_backed_teardown_skips_missing_inspector_for_core_only_public_management_targets(self):
        def executor(workspace_dir, **kwargs):
            return {"ok": True, **pilot_execution_result(workspace_dir, mode="destroy_after_validation")}

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                    "sshSourceCidrs": ["198.51.100.10/32"],
                },
                executor=lambda workspace_dir, **kwargs: {
                    "ok": True,
                    **pilot_execution_result(workspace_dir, mode="hold_for_review"),
                },
                repository=repository,
                background_runner=lambda task: task(),
            )

            with patch(
                "app.services.guarded_test_deployment.verify_retired_public_endpoints_for_teardown",
                return_value={
                    "ok": False,
                    "status": "inspector_unavailable",
                    "targetCount": 2,
                    "targets": [
                        {
                            "id": "core-management:homebase:22",
                            "type": "tcp-forbidden",
                            "targetGroup": "core-public-management",
                            "host": "203.0.113.10",
                            "port": 22,
                        },
                        {
                            "id": "core-management:proxy01:22",
                            "type": "tcp-forbidden",
                            "targetGroup": "core-public-management",
                            "host": "203.0.113.11",
                            "port": 22,
                        },
                    ],
                    "evidence": {},
                    "errors": ["retained Inspector host is required for teardown verification"],
                },
            ), patch(
                "app.services.guarded_test_deployment.cleanup_inspector_for_infrastructure_teardown",
                return_value={
                    "ok": True,
                    "status": "disabled_no_host",
                    "disabled": True,
                    "cleanupVerified": True,
                    "currentHostCleared": True,
                    "inspectorHost": {},
                },
            ):
                finished = teardown_guarded_pilot_standard_rti_run(
                    job.id,
                    executor=executor,
                    repository=repository,
                )

        self.assertIsNotNone(finished)
        self.assertEqual(finished.status, "succeeded")
        self.assertEqual(
            finished.events[-1].data["inspectorTeardownVerification"]["status"],
            "skipped_no_retained_inspector_core_only",
        )

    def test_job_backed_teardown_retains_inspector_when_public_endpoint_verification_fails(self):
        def executor(workspace_dir, **kwargs):
            return {"ok": True, **pilot_execution_result(workspace_dir, mode="destroy_after_validation")}

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            job = start_guarded_pilot_standard_rti_run(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": False,
                    "deploymentMode": "hold_for_review",
                    "engagementId": "eng-zy01",
                    "workspaceDir": str(Path(temp_dir) / "pilot-workspace"),
                },
                executor=lambda workspace_dir, **kwargs: {
                    "ok": True,
                    **pilot_execution_result(workspace_dir, mode="hold_for_review"),
                },
                repository=repository,
                background_runner=lambda task: task(),
            )

            with patch(
                "app.services.guarded_test_deployment.verify_retired_public_endpoints_for_teardown",
                return_value={
                    "ok": False,
                    "status": "verification_failed",
                    "targetCount": 1,
                    "targets": [{"id": "edge-http", "type": "tcp-forbidden", "host": "203.0.113.50", "port": 80}],
                    "evidence": {"ok": False, "results": [{"id": "edge-http", "ok": False}]},
                },
            ) as verify_teardown, patch(
                "app.services.guarded_test_deployment.cleanup_inspector_for_infrastructure_teardown",
            ) as cleanup_inspector:
                finished = teardown_guarded_pilot_standard_rti_run(
                    job.id,
                    executor=executor,
                    repository=repository,
                )

        self.assertIsNotNone(finished)
        self.assertEqual(finished.status, "failed")
        messages = [event.message for event in finished.events]
        self.assertIn("Inspector teardown verification failed", messages)
        self.assertNotIn("Inspector cleanup requested", messages)
        self.assertEqual(finished.events[-1].data["inspectorTeardownVerification"]["status"], "verification_failed")
        verify_teardown.assert_called_once()
        cleanup_inspector.assert_not_called()


def completed(command, stdout="", returncode=0):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


def _artifact_content(workspace, path):
    for artifact in workspace.artifacts:
        if artifact.path == path:
            return artifact.content
    raise AssertionError(f"artifact {path} not found")


def _terraform_resource(content, resource_type, name):
    header = f'resource "{resource_type}" "{name}" {{'
    start = content.index(header)
    body_start = start + len(header) - 1
    depth = 0
    for offset, character in enumerate(content[body_start:], start=body_start):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return content[start : offset + 1]
    raise AssertionError(f"resource {resource_type}.{name} was not closed")


def pilot_execution_result(workspace_dir, apply_ok=True, mode="hold_for_review", engagement_name="pilot"):
    commands_run = [
        command_result(["terraform", "init"], workspace_dir),
        command_result(["terraform", "apply"], workspace_dir, ok=apply_ok),
        command_result(["terraform", "output"], workspace_dir),
        command_result(["ansible", "pilot_rti", "-m", "ansible.builtin.wait_for_connection"], workspace_dir),
        command_result(["ansible", "pilot_rti", "-m", "ping"], workspace_dir),
        command_result(["ansible-playbook", "ansible/bootstrap_validate.yml"], workspace_dir),
        command_result(["ansible-playbook", "ansible/apply_capabilities.yml"], workspace_dir),
    ]
    if mode == "destroy_after_validation":
        commands_run.append(command_result(["terraform", "destroy"], workspace_dir))
    mutation_status = "deployed" if mode == "hold_for_review" else "destroyed"
    final_cleanup_status = "pending_operator_teardown" if mode == "hold_for_review" else "verified_clean"
    cleanup_verification = None
    if mode == "destroy_after_validation":
        cleanup_verification = {
            "ok": apply_ok,
            "remainingCount": 0 if apply_ok else 1,
            "error": None if apply_ok else "resource remained",
        }
    return {
        "workspace": WORKSPACE_NAME,
        "workspaceDir": str(workspace_dir),
        "deploymentMode": mode,
        "mutation": True,
        "mutationStatus": mutation_status if apply_ok else "apply_failed",
        "ansibleStatus": "validated" if apply_ok else "not_started",
        "finalCleanupStatus": final_cleanup_status if apply_ok else "cleanup_not_verified",
        "preflight": {"ok": True},
        "commandsRun": commands_run,
        "cleanupVerification": cleanup_verification,
        "connectionDetails": pilot_connection_details(engagement_name),
        **pilot_channel_rows(pilot_names(engagement_name), region=DEFAULT_REGION),
    }


def pilot_connection_details(engagement_name="pilot"):
    names = pilot_names(engagement_name)
    return [
        {
            "role": "homebase",
            "displayName": names.homebase_name,
            "sshAlias": names.homebase_name,
            "publicIp": "146.235.219.8",
            "privateIp": PILOT_HOMEBASE_PRIVATE_IP,
            "region": DEFAULT_REGION,
            "sshUser": CORE_MANAGEMENT_SSH_USER,
            "sshCommand": f"ssh {names.homebase_name}",
            "services": ["SSH", "RTI base layout", "proxy config banks", "dropbox NFS export"],
        },
        {
            "role": "proxy",
            "displayName": names.proxy_name,
            "sshAlias": names.proxy_name,
            "publicIp": "170.9.62.26",
            "privateIp": PILOT_PROXY_PRIVATE_IP,
            "region": DEFAULT_REGION,
            "sshUser": CORE_MANAGEMENT_SSH_USER,
            "sshCommand": f"ssh {names.proxy_name}",
            "services": ["SSH", "RTI base layout", "dropbox NFS mount", "nmap"],
        },
        {
            "role": "proxy",
            "displayName": names.proxy02_name,
            "sshAlias": names.proxy02_name,
            "publicIp": "170.9.62.27",
            "privateIp": PILOT_PROXY02_PRIVATE_IP,
            "region": DEFAULT_REGION,
            "sshUser": CORE_MANAGEMENT_SSH_USER,
            "sshCommand": f"ssh {names.proxy02_name}",
            "services": ["SSH", "RTI base layout", "dropbox NFS mount", "nmap"],
        },
    ]


def command_result(command, workspace_dir, ok=True):
    return {
        "command": command,
        "cwd": str(workspace_dir),
        "returncode": 0 if ok else 1,
        "stdout": "",
        "stderr": "",
        "ok": ok,
    }


def fake_get_engagement(engagement_id):
    names = {
        "eng-zy01": "ZY01",
        "eng-ab01": "ab01",
        "eng-created": "ZY01",
    }
    name = names.get(engagement_id, "ZY01")
    return EngagementDetail(
        id=engagement_id,
        name=name,
        status="planned",
        owner="example_operator",
        template_id="standard-rti",
        active_revision=None,
        input_parameters={},
    )


class FakeJobDetail:
    def __init__(self, job_id):
        self.job_id = job_id

    def to_dict(self):
        return {
            "id": self.job_id,
            "action": "pilot_standard_rti_guarded_execute",
            "status": "succeeded",
            "targetType": "oci_compartment",
            "targetId": BARRAGAN_TESTING_COMPARTMENT_ID,
            "requestedBy": "operator",
            "input": {"workspace": WORKSPACE_NAME},
            "artifactRefs": ["workspace:/tmp/pilot"],
            "events": [
                {
                    "sequence": 1,
                    "level": "info",
                    "message": "pilot Standard RTI run queued",
                    "data": {"workspace": WORKSPACE_NAME},
                }
            ],
        }


def _executable(directory: str, name: str) -> str:
    path = Path(directory) / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def test_guarded_run_dispatch_recovery_fence_stops_executor():
    from app.services.engagement_teardown import EngagementTeardownValidationError

    executor_calls = []
    with patch("app.services.guarded_test_deployment._required_engagement", return_value=SimpleNamespace(id="eng-1", name="Engagement")), patch(
        "app.services.guarded_test_deployment._target_for_engagement", return_value=object()
    ), patch("app.services.guarded_test_deployment._validate_guarded_pilot_request"), patch(
        "app.services.engagement_teardown.assert_core_creation_allowed",
        side_effect=EngagementTeardownValidationError([
            "engagement cleanup recovery is required through comprehensive teardown job-parent before creating core infrastructure"
        ]),
    ):
        try:
            start_guarded_pilot_standard_rti_run(
                {"engagementId": "eng-1"}, executor=lambda *_args, **_kwargs: executor_calls.append(True)
            )
        except EngagementTeardownValidationError as exc:
            assert "job-parent" in exc.errors[0]
        else:
            raise AssertionError("guarded core run should be fenced by teardown recovery")

    assert executor_calls == []


if __name__ == "__main__":
    unittest.main()
