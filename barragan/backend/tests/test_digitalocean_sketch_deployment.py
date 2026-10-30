# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.core.config import TestConfig
from app.integrations.terraform_runner import TerraformCommandResult
from app.services.credentials import test_master_key as credential_test_master_key
from app.services.jobs import enqueue_job, run_job
from app.services.digitalocean_sketch_deployment import (
    DIGITALOCEAN_SKETCH_CONFIRMATION,
    DIGITALOCEAN_SKETCH_DEPLOY_ACTION,
    DIGITALOCEAN_SKETCH_RECONCILE_ACTION,
    DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
    run_digitalocean_sketch_job,
    start_guarded_digitalocean_sketch_run,
    start_guarded_digitalocean_sketch_teardown,
)
from app.services.redteam_infra_template import redteam_infra_path
from app.storage.job_repository import SqliteJobRepository
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace
from redteam_infra_test_fixtures import write_sketch_template_fixture


class FakeTerraformRunner:
    def __init__(self, output_body=None, fail_commands=None, output_text=None, stderr_by_command=None, stdout_by_command=None):
        self.output_body = output_body or {}
        self.fail_commands = set(fail_commands or [])
        self.output_text = output_text
        self.stderr_by_command = dict(stderr_by_command or {})
        self.stdout_by_command = dict(stdout_by_command or {})
        self.calls = []

    def run(self, command, *, working_directory, env, variables=None):
        self.calls.append(
            {
                "command": command,
                "workingDirectory": working_directory,
                "env": dict(env),
                "variables": dict(variables or {}),
            }
        )
        stdout = self.stdout_by_command.get(command)
        if stdout is None:
            stdout = self.output_text if command == "output" and self.output_text is not None else json.dumps(self.output_body) if command == "output" else ""
        returncode = 1 if command in self.fail_commands else 0
        return TerraformCommandResult(command=command, returncode=returncode, stdout=stdout, stderr=self.stderr_by_command.get(command, ""))


class RecordingCredentialResolver:
    def __init__(self, token):
        self.token = token
        self.calls = []

    def __call__(self, provider, alias):
        self.calls.append((provider, alias))
        return self.token


class DigitalOceanSketchDeploymentTests(unittest.TestCase):
    def setUp(self):
        self._template_dir = tempfile.TemporaryDirectory()
        root = Path(self._template_dir.name)
        write_sketch_template_fixture(root, providers=("digitalocean",))
        self._template_env = patch.dict("os.environ", {"BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT": str(root)})
        self._template_env.start()
        self._retained_validator = patch(
            "app.services.digitalocean_sketch_deployment.validate_existing_sketch_state_workspace"
        )
        self._retained_validator.start()
        self._collaborator_access = patch(
            "app.services.digitalocean_sketch_deployment.grant_collaborator_access_to_existing_sketch_state_workspace"
        )
        self._collaborator_access.start()

    def tearDown(self):
        self._collaborator_access.stop()
        self._retained_validator.stop()
        self._template_env.stop()
        self._template_dir.cleanup()

    def test_digitalocean_sketch_teardown_returns_running_job_before_background_destroy(self):
        runner = FakeTerraformRunner({})
        tasks = []

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            deploy = enqueue_job(
                action=DIGITALOCEAN_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir, retained=True),
                repository=repository,
            )
            with patch("app.services.digitalocean_sketch_deployment.resolve_credential_secret", return_value="test-token"):
                running = start_guarded_digitalocean_sketch_teardown(
                    deploy.id,
                    repository=repository,
                    runner=runner,
                    background_runner=tasks.append,
                )

                self.assertIsNotNone(running)
                self.assertEqual(running.status, "running")
                self.assertEqual(runner.calls, [])
                self.assertEqual(len(tasks), 1)

                tasks[0]()

            completed = repository.get(running.id)
            self.assertEqual(completed.status, "succeeded")
            self.assertEqual([call["command"] for call in runner.calls], ["init", "destroy", "output"])
            self.assertIn("terraform destroy started", [event.message for event in completed.events])
            self.assertIn("terraform cleanup verified", [event.message for event in completed.events])

    def test_digitalocean_edge_reconcile_requires_and_records_a_reviewed_final_edge_plan(self):
        class PlanRunner(FakeTerraformRunner):
            def run(self, command, *, working_directory, env, variables=None):
                self.calls.append({"command": command, "workingDirectory": working_directory, "env": dict(env), "variables": dict(variables or {})})
                if command == "plan":
                    return TerraformCommandResult(
                        command=command,
                        returncode=2,
                        stdout='{"type":"planned_change","change":{"action":"create","resource":{"addr":"digitalocean_droplet.edge[1]"}}}',
                        stderr="",
                    )
                stdout = json.dumps(self.output_body) if command == "output" else ""
                return TerraformCommandResult(command=command, returncode=0, stdout=stdout, stderr="")

        runner = PlanRunner({"middle_public_ips": {"value": ["203.0.113.10"]}, "edge_public_ips": {"value": ["203.0.113.20", "203.0.113.21"]}})
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_RECONCILE_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator",
                input_data={
                    **_job_input(temp_dir, retained=True),
                    "edgeCount": 2,
                    "edgeRegions": ["sfo3", "nyc3"],
                    "edgeCountPerRegion": 1,
                    "expectedEdgeAddress": "digitalocean_droplet.edge[1]",
                    "expectedEdgeAction": "create",
                },
                repository=repository,
            )
            with patch(
                "app.services.digitalocean_sketch_deployment.prepare_digitalocean_borrower_teardown"
            ) as teardown_compatibility:
                completed = run_job(
                    queued.id,
                    repository=repository,
                    executors={
                        DIGITALOCEAN_SKETCH_RECONCILE_ACTION: lambda job: run_digitalocean_sketch_job(
                            job, runner=runner, credential_resolver=RecordingCredentialResolver("token")
                        )
                    },
                )
            teardown_compatibility.assert_not_called()

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual([call["command"] for call in runner.calls], ["init", "plan", "apply", "output"])
        self.assertIn("terraform edge transition plan approved", [event.message for event in completed.events])

    def test_digitalocean_teardown_adapts_retained_split_key_workspace(self):
        runner = FakeTerraformRunner({})

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text(
                'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
                'variable "sketch_transport_ssh_pub_key_path" {}\n',
                encoding="utf-8",
            )
            (workspace / "output.tf").write_text(
                'resource "local_file" "ssh_stanza" {\n'
                "  count = var.middle_count > 0 && var.edge_count_per_region > 0 ? 1 : 0\n"
                "}\n\n"
                'resource "local_file" "ansible_inventory" {\n'
                "  count = var.middle_count > 0 && var.edge_count_per_region > 0 ? 1 : 0\n"
                "}\n\n"
                'output "middle_public_ips" { value = [] }\n'
                'output "edge_public_ips" { value = [] }\n',
                encoding="utf-8",
            )
            original_run = runner.run
            local_artifacts_at_call: list[tuple[str, bool]] = []

            def observe_local_artifacts(command, *, working_directory, env, variables=None):
                output_text = (Path(working_directory) / "output.tf").read_text(encoding="utf-8")
                local_artifacts_at_call.append(
                    (
                        command,
                        output_text.count("count = 0") == 2
                        and 'output "middle_public_ips"' in output_text
                        and 'output "edge_public_ips"' in output_text,
                    )
                )
                return original_run(
                    command,
                    working_directory=working_directory,
                    env=env,
                    variables=variables,
                )

            runner.run = observe_local_artifacts
            input_data = _job_input(terraform_dir=temp_dir, retained=True)
            input_data.update(
                {
                    "infrastructureAdminSshPrivateKeyPath": "/keys/admin",
                    "infrastructureAdminSshPublicKeyPath": "/keys/admin.pub",
                    "sketchTransportSshPublicKeyPath": "/keys/transport.pub",
                }
            )
            repository = SqliteJobRepository(workspace / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=input_data,
                repository=repository,
            )
            with (
                patch("app.services.digitalocean_sketch_deployment.prepare_digitalocean_ssh_key_reuse") as prepare_key_reuse,
                patch("app.services.digitalocean_sketch_deployment.prepare_digitalocean_borrower_teardown", return_value="unresolved") as borrower_teardown,
            ):
                completed = run_job(
                    queued.id,
                    repository=repository,
                    executors={
                        DIGITALOCEAN_SKETCH_TEARDOWN_ACTION: lambda job: run_digitalocean_sketch_job(
                            job,
                            runner=runner,
                            credential_resolver=RecordingCredentialResolver("test-token"),
                        )
                    },
                )
            prepare_key_reuse.assert_called_once_with(workspace)
            borrower_teardown.assert_called_once_with(workspace)

            variables_text = (workspace / "variables.tf").read_text(encoding="utf-8")

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(local_artifacts_at_call[0], ("init", True))
        self.assertTrue(all(disabled for _, disabled in local_artifacts_at_call))
        self.assertIn('variable "middle_ordinal"', variables_text)
        destroy_variables = runner.calls[1]["variables"]
        self.assertEqual(destroy_variables["infrastructure_admin_ssh_pub_key_path"], "/keys/admin.pub")
        self.assertEqual(destroy_variables["infrastructure_admin_ssh_priv_key_path"], "/keys/admin")
        self.assertEqual(destroy_variables["sketch_transport_ssh_pub_key_path"], "/keys/transport.pub")
        self.assertNotIn("ssh_pub_key_path", destroy_variables)

    def test_digitalocean_borrower_teardown_uses_cached_key_without_live_lookup(self):
        runner = FakeTerraformRunner({})

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "providers.tf").write_text(
                'provider "digitalocean" {}\n\n'
                'data "digitalocean_ssh_keys" "matching_key" {\n'
                '  filter { key = "public_key" values = [chomp(file(local.ssh_pub_key_path))] }\n'
                '}\n\n'
                'resource "digitalocean_ssh_key" "key" {\n'
                '  count = length(data.digitalocean_ssh_keys.matching_key.ssh_keys) == 0 ? 1 : 0\n'
                '  name = "do-key"\n'
                '  public_key = chomp(file(local.ssh_pub_key_path))\n'
                '}\n\n'
                'locals {\n'
                '  sketch_ssh_key_id = data.digitalocean_ssh_keys.matching_key.ssh_keys[0].id\n'
                '}\n\n'
                'provider "local" {}\n',
                encoding="utf-8",
            )
            (workspace / "terraform.tfstate").write_text(
                json.dumps(
                    {
                        "resources": [
                            {
                                "mode": "data",
                                "type": "digitalocean_ssh_keys",
                                "name": "matching_key",
                                "instances": [{"attributes": {"ssh_keys": [{"id": 456}]}}],
                            },
                            {
                                "mode": "managed",
                                "type": "digitalocean_droplet",
                                "instances": [{"attributes": {"image": "ubuntu-22-04-x64"}}],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            observed_providers: list[str] = []
            original_run = runner.run

            def observe_configuration(command, *, working_directory, env, variables=None):
                observed_providers.append((Path(working_directory) / "providers.tf").read_text(encoding="utf-8"))
                return original_run(command, working_directory=working_directory, env=env, variables=variables)

            runner.run = observe_configuration
            repository = SqliteJobRepository(workspace / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir),
                repository=repository,
            )
            completed = run_job(
                queued.id,
                repository=repository,
                executors={
                    DIGITALOCEAN_SKETCH_TEARDOWN_ACTION: lambda job: run_digitalocean_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=RecordingCredentialResolver("test-token"),
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertTrue(observed_providers)
        self.assertTrue(all('data "digitalocean_ssh_keys" "matching_key"' not in text for text in observed_providers))
        self.assertTrue(all("sketch_ssh_key_id = 456" in text for text in observed_providers))

    def test_digitalocean_deploy_adapts_stock_workspace_before_terraform_init(self):
        runner = FakeTerraformRunner({})

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            source = redteam_infra_path("external", "sketch", "digitalocean")
            for source_file in source.glob("*.tf"):
                shutil.copy2(source_file, workspace / source_file.name)
            with (workspace / "output.tf").open("a", encoding="utf-8") as output_tf:
                output_tf.write(
                    '\nresource "local_file" "ssh_stanza" {\n'
                    "  count = var.middle_count > 0 && var.edge_count_per_region > 0 ? 1 : 0\n"
                    "}\n"
                    'resource "local_file" "ansible_inventory" {\n'
                    "  count = var.middle_count > 0 && var.edge_count_per_region > 0 ? 1 : 0\n"
                    "}\n"
                )

            original_run = runner.run
            compatibility_at_call: list[tuple[str, bool]] = []

            def observe_compatibility(command, *, working_directory, env, variables=None):
                variables_text = (Path(working_directory) / "variables.tf").read_text(encoding="utf-8")
                output_text = (Path(working_directory) / "output.tf").read_text(encoding="utf-8")
                compatibility_at_call.append(
                    (
                        command,
                        all(
                            marker in variables_text
                            for marker in (
                                'variable "resource_name_suffix"',
                                'variable "middle_ordinal"',
                                'variable "edge_ordinal"',
                            )
                        )
                        and output_text.count("count = 0") == 2
                        and 'output "middle_public_ips"' in output_text
                        and 'output "edge_public_ips"' in output_text,
                    )
                )
                return original_run(
                    command,
                    working_directory=working_directory,
                    env=env,
                    variables=variables,
                )

            runner.run = observe_compatibility
            repository = SqliteJobRepository(workspace / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir),
                repository=repository,
            )
            with patch(
                "app.services.digitalocean_sketch_deployment.prepare_digitalocean_borrower_teardown"
            ) as teardown_compatibility:
                completed = run_job(
                    queued.id,
                    repository=repository,
                    executors={
                        DIGITALOCEAN_SKETCH_DEPLOY_ACTION: lambda job: run_digitalocean_sketch_job(
                            job,
                            runner=runner,
                            credential_resolver=RecordingCredentialResolver("test-token"),
                        )
                    },
                )
            teardown_compatibility.assert_not_called()

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(compatibility_at_call[0], ("init", True))
        self.assertTrue(all(compatible for _, compatible in compatibility_at_call))

    def test_guarded_digitalocean_deploy_materializes_distinct_admin_and_transport_keys(self):
        secret = "do-token-sensitive-value"
        variables_path = redteam_infra_path("external", "sketch", "digitalocean", "variables.tf")
        variables_path.write_text(
            variables_path.read_text(encoding="utf-8")
            + '\nvariable "infrastructure_admin_ssh_pub_key_path" {}\n'
            + 'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
            + 'variable "sketch_transport_ssh_pub_key_path" {}\n',
            encoding="utf-8",
        )
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.30"]},
                "edge_public_ips": {"value": ["203.0.113.40"]},
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            app = create_app(TestConfig)
            with app.storage_context():
                with patch.dict("os.environ", {"BARRAGAN_CREDENTIAL_MASTER_KEY": credential_test_master_key(), "BARRAGAN_SKETCH_STATE_ROOT": str(Path(temp_dir) / "sketch-state")}):
                    with patch("app.services.digitalocean_sketch_deployment.get_engagement", return_value=type("Engagement", (), {"name": "of02-dev"})()):
                        with patch("app.services.digitalocean_sketch_deployment.resolve_credential_secret", return_value=secret):
                            running = start_guarded_digitalocean_sketch_run(
                                {
                                    "confirmMutation": DIGITALOCEAN_SKETCH_CONFIRMATION,
                                    "engagementId": "eng-of02-dev",
                                    "chainId": "chain-1",
                                    "middleRegion": "sfo3",
                                    "edgeRegion": "sfo3",
                                    "middleSize": "s-1vcpu-1gb",
                                    "edgeSize": "s-1vcpu-1gb",
                                    "middleCredentialAlias": "do-barragan",
                                    "edgeCredentialAlias": "do-barragan",
                                },
                                repository=repository,
                                runner=runner,
                                background_runner=lambda task: task(),
                                workspace_repository=_workspace_repository(),
                            )
            completed = repository.get(running.id).to_detail()
            workspace_variables = (
                Path(next(call["workingDirectory"] for call in runner.calls if call["command"] == "apply"))
                / "variables.tf"
            ).read_text(encoding="utf-8")

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(completed.input["terraformEngagementName"], "of02-dev")
        self.assertEqual(completed.input["resourceNameSuffix"], "")
        self.assertEqual(completed.input["middleOrdinal"], 1)
        self.assertEqual(completed.input["edgeOrdinal"], 1)
        self.assertEqual(completed.input["managedHostImageProfile"], "ubuntu-22.04")
        self.assertTrue(completed.input["materializeKeyFiles"])
        self.assertEqual(completed.input["sshPrivateKeyPath"], "")
        self.assertEqual(completed.input["sshPublicKeyPath"], "")
        self.assertEqual(completed.input["sketchTransportSshPublicKeyPath"], "")
        apply_variables = next(call["variables"] for call in runner.calls if call["command"] == "apply")
        self.assertEqual(apply_variables["docean_image"], "ubuntu-22-04-x64")
        self.assertTrue(Path(apply_variables["infrastructure_admin_ssh_pub_key_path"]).name.endswith("-sketch.pub"))
        self.assertTrue(Path(apply_variables["sketch_transport_ssh_pub_key_path"]).name.endswith("-sketch-transport.pub"))
        self.assertFalse(Path(apply_variables["infrastructure_admin_ssh_pub_key_path"]).exists())
        self.assertFalse(Path(apply_variables["sketch_transport_ssh_pub_key_path"]).exists())
        self.assertIn('variable "infrastructure_admin_ssh_pub_key_path" {}', workspace_variables)
        self.assertIn('variable "sketch_transport_ssh_pub_key_path" {}', workspace_variables)
        self.assertNotIn(secret, str(completed.to_dict()))

    def test_digitalocean_sketch_deploy_records_redacted_infrastructure_output(self):
        secret = "do-token-sensitive-value"
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.30"]},
                "edge_public_ips": {"value": ["203.0.113.40"]},
                "middle_instance_ids": {"value": ["3333"]},
                "edge_instance_ids": {"value": ["4444"]},
            }
        )
        resolver = RecordingCredentialResolver(secret)

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir),
                repository=repository,
            )
            completed = run_job(
                queued.id,
                repository=repository,
                executors={
                    DIGITALOCEAN_SKETCH_DEPLOY_ACTION: lambda job: run_digitalocean_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(resolver.calls, [("digitalocean", "do-barragan")])
        self.assertEqual([call["command"] for call in runner.calls], ["init", "apply", "output"])
        self.assertTrue(all(call["env"]["TF_VAR_do_pat"] == secret for call in runner.calls))
        variables = runner.calls[1]["variables"]
        self.assertEqual(variables["engagement_name"], "of02-dev")
        self.assertEqual(variables["resource_name_suffix"], "")
        self.assertEqual(variables["middle_region"], "sfo3")
        self.assertEqual(variables["edge_regions"], ["sfo3"])
        self.assertEqual(variables["docean_image"], "ubuntu-24-04-x64")
        self.assertEqual(variables["middle_size"], "s-1vcpu-1gb")
        self.assertEqual(variables["edge_size"], "s-1vcpu-1gb")
        self.assertNotIn("do_pat", variables)
        self.assertTrue(variables["ssh_pub_key_path"].endswith("/of02-dev-sketch.pub"))

        output_event = _event_by_message(completed.events, "terraform output recorded")
        rows = output_event.data["sketchInfrastructure"]
        self.assertEqual([row["hostname"] for row in rows], ["middle01-of02-dev", "edge-of02-dev-sfo3-01"])
        self.assertEqual([row["provider"] for row in rows], ["digitalocean", "digitalocean"])
        self.assertEqual([row["providerInstanceId"] for row in rows], ["3333", "4444"])
        self.assertEqual([row["publicIp"] for row in rows], ["203.0.113.30", "203.0.113.40"])
        channel_event = _event_by_message(completed.events, "pending outbound channel artifacts derived")
        self.assertEqual(channel_event.data["outboundChannels"][0]["provider"], "digitalocean")
        self.assertEqual(channel_event.data["outboundChannels"][0]["validation"]["expectedPublicIp"], "203.0.113.40")
        apply_event = _event_by_message(completed.events, "terraform apply completed")
        self.assertTrue(apply_event.data["startedAt"])
        self.assertTrue(apply_event.data["finishedAt"])
        self.assertGreaterEqual(apply_event.data["elapsedSeconds"], 0)
        self.assertNotIn(secret, str(completed.to_dict()))
        self.assertNotIn("token-sensitive-value", str(completed.to_dict()))
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", str(completed.to_dict()))

    def test_digitalocean_sketch_deploy_supports_multiple_edges_per_middle(self):
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.30"]},
                "edge_public_ips": {"value": {"sfo3": ["203.0.113.40", "203.0.113.41"]}},
                "middle_instance_ids": {"value": ["3333"]},
                "edge_instance_ids": {"value": {"sfo3": ["4444", "5555"]}},
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data={**_job_input(terraform_dir=temp_dir), "edgeCount": 2},
                repository=repository,
            )
            completed = run_job(
                queued.id,
                repository=repository,
                executors={
                    DIGITALOCEAN_SKETCH_DEPLOY_ACTION: lambda job: run_digitalocean_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=RecordingCredentialResolver("secret"),
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(runner.calls[1]["variables"]["edge_count_per_region"], 2)
        rows = _event_by_message(completed.events, "terraform output recorded").data["sketchInfrastructure"]
        self.assertEqual([row["hostname"] for row in rows], ["middle01-of02-dev", "edge-of02-dev-sfo3-01", "edge-of02-dev-sfo3-02"])
        self.assertEqual([row["publicIp"] for row in rows], ["203.0.113.30", "203.0.113.40", "203.0.113.41"])
        channel_event = _event_by_message(completed.events, "pending outbound channel artifacts derived")
        channels = channel_event.data["outboundChannels"]
        self.assertEqual([channel["channelId"] for channel in channels], ["chain-1-edge-01", "chain-1-edge-02"])
        self.assertEqual([channel["edge"] for channel in channels], ["edge-of02-dev-sfo3-01", "edge-of02-dev-sfo3-02"])
        self.assertEqual([channel["port"] for channel in channels], ["3333", "3334"])
        self.assertEqual([channel["validation"]["expectedPublicIp"] for channel in channels], ["203.0.113.40", "203.0.113.41"])

    def test_digitalocean_sketch_teardown_verifies_cleanup_without_recording_secret(self):
        secret = "do-token-sensitive-value"
        runner = FakeTerraformRunner({})
        resolver = RecordingCredentialResolver(secret)

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir, retained=True),
                repository=repository,
            )
            completed = run_job(
                queued.id,
                repository=repository,
                executors={
                    DIGITALOCEAN_SKETCH_TEARDOWN_ACTION: lambda job: run_digitalocean_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual([call["command"] for call in runner.calls], ["init", "destroy", "output"])
        self.assertEqual(runner.calls[1]["variables"]["docean_image"], "ubuntu-22-04-x64")
        self.assertTrue(completed.events[-1].data["cleanupVerified"])
        self.assertEqual(completed.events[-1].data["sketchInfrastructure"], [])
        self.assertNotIn(secret, str(completed.to_dict()))

    def test_digitalocean_teardown_accepts_empty_retained_state_with_saved_image_profile(self):
        runner = FakeTerraformRunner({})
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "terraform.tfstate").write_text(
                json.dumps(_empty_retained_state()), encoding="utf-8"
            )
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
                target_type="engagement", target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data={**_job_input(terraform_dir=temp_dir),
                            "managedHostImageProfile": "ubuntu-24.04"},
                repository=repository,
            )
            completed = run_job(
                queued.id, repository=repository,
                executors={DIGITALOCEAN_SKETCH_TEARDOWN_ACTION: lambda job:
                           run_digitalocean_sketch_job(
                               job, runner=runner,
                               credential_resolver=RecordingCredentialResolver("test-token"),
                           )},
            )
        self.assertEqual(completed.status, "succeeded")
        self.assertEqual([call["command"] for call in runner.calls], ["init", "destroy", "output"])
        self.assertEqual(runner.calls[1]["variables"]["docean_image"], "ubuntu-24-04-x64")

    def test_digitalocean_teardown_empty_state_fallback_fails_closed(self):
        invalid_cases = {
            "incomplete envelope": ({"resources": [], "outputs": {}}, "ubuntu-24.04"),
            "invalid serial": ({**_empty_retained_state(), "serial": True}, "ubuntu-24.04"),
            "malformed resource": ({**_empty_retained_state(), "resources": [{"mode": "managed", "type": "digitalocean_firewall"}]}, "ubuntu-24.04"),
            "conflicting compute images": (
                {**_empty_retained_state(), "resources": [{
                    "mode": "managed", "type": "digitalocean_droplet",
                    "instances": [
                        {"attributes": {"image": "ubuntu-22-04-x64"}},
                        {"attributes": {"image": "ubuntu-24-04-x64"}},
                    ],
                }]}, "ubuntu-24.04",
            ),
            "missing saved profile": (_empty_retained_state(), ""),
            "invalid saved profile": (_empty_retained_state(), "ubuntu-99.99"),
        }
        for label, (state, profile) in invalid_cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                (Path(temp_dir) / "terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")
                repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
                queued = enqueue_job(
                    action=DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
                    target_type="engagement", target_id="eng-of02-dev",
                    requested_by="operator@example.invalid",
                    input_data={**_job_input(terraform_dir=temp_dir),
                                "managedHostImageProfile": profile},
                    repository=repository,
                )
                runner = FakeTerraformRunner({})
                completed = run_job(
                    queued.id, repository=repository,
                    executors={DIGITALOCEAN_SKETCH_TEARDOWN_ACTION: lambda job:
                               run_digitalocean_sketch_job(
                                   job, runner=runner,
                                   credential_resolver=RecordingCredentialResolver("test-token"),
                               )},
                )
                self.assertEqual(completed.status, "failed")
                self.assertEqual(runner.calls, [])

    def test_digitalocean_sketch_deploy_attempts_cleanup_after_apply_failure(self):
        runner = FakeTerraformRunner(fail_commands={"apply"})
        resolver = RecordingCredentialResolver("do-token-sensitive-value")

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir),
                repository=repository,
            )
            completed = run_job(
                queued.id,
                repository=repository,
                executors={
                    DIGITALOCEAN_SKETCH_DEPLOY_ACTION: lambda job: run_digitalocean_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        self.assertEqual(completed.status, "failed")
        self.assertEqual([call["command"] for call in runner.calls], ["init", "apply", "destroy", "output"])
        self.assertIn("terraform apply failed", [event.message for event in completed.events])
        self.assertIn("terraform cleanup verified", [event.message for event in completed.events])

    def test_digitalocean_sketch_deploy_records_redacted_provider_failure_diagnostic(self):
        secret = "do-token-sensitive-value"
        runner = FakeTerraformRunner(
            fail_commands={"apply"},
            stderr_by_command={
                "apply": "\n".join(
                    [
                        "Error: error creating firewall: POST https://api.digitalocean.com/v2/firewalls",
                        "",
                        "  with digitalocean_firewall.sketch_edge,",
                        "provider returned Authorization: Bearer do-token-sensitive-value and UDP protocol is invalid",
                    ]
                )
            },
        )
        resolver = RecordingCredentialResolver(secret)

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=DIGITALOCEAN_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir),
                repository=repository,
            )
            completed = run_job(
                queued.id,
                repository=repository,
                executors={
                    DIGITALOCEAN_SKETCH_DEPLOY_ACTION: lambda job: run_digitalocean_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        event = _event_by_message(completed.events, "terraform apply failed")
        diagnostic = event.data["terraformDiagnostic"]
        self.assertEqual(diagnostic["provider"], "digitalocean")
        self.assertEqual(diagnostic["command"], "apply")
        self.assertEqual(diagnostic["returnCode"], 1)
        self.assertEqual(diagnostic["errorClass"], "provider_api_permanent")
        self.assertIn("error creating firewall", diagnostic["summary"])
        self.assertIn("digitalocean_firewall.sketch_edge", diagnostic["resourceHints"])
        self.assertIn("[REDACTED]", diagnostic["stderrExcerpt"])
        self.assertNotIn(secret, str(completed.to_dict()))

    def test_bundled_digitalocean_template_exports_edge_public_ips(self):
        output_tf = redteam_infra_path("external", "sketch", "digitalocean", "output.tf").read_text(encoding="utf-8")

        self.assertIn('output "middle_public_ips"', output_tf)
        self.assertIn('output "edge_public_ips"', output_tf)
        self.assertIn('output "middle_instance_ids"', output_tf)
        self.assertIn('output "edge_instance_ids"', output_tf)

    def test_bundled_digitalocean_template_types_collection_and_count_variables(self):
        variables_tf = redteam_infra_path(
            "external", "sketch", "digitalocean", "variables.tf"
        ).read_text(encoding="utf-8")

        self.assertIn('variable "edge_regions"', variables_tf)
        self.assertIn("type = list(string)", variables_tf)
        self.assertIn('variable "middle_count"', variables_tf)
        self.assertIn('variable "edge_count_per_region"', variables_tf)
        self.assertIn("type        = number", variables_tf)

    def test_bundled_digitalocean_firewall_allows_ipv4_udp_egress(self):
        firewall_tf = redteam_infra_path(
            "external", "sketch", "digitalocean", "firewall.tf"
        ).read_text(encoding="utf-8")

        self.assertIn('protocol              = "udp"', firewall_tf)
        self.assertIn('destination_addresses = ["0.0.0.0/0"]', firewall_tf)
        self.assertIn('destination_addresses = ["::/0"]', firewall_tf)

    def test_bundled_digitalocean_sketch_template_bootstraps_management_and_runtime_users(self):
        middle_tf = redteam_infra_path("external", "sketch", "digitalocean", "middle.tf").read_text(encoding="utf-8")
        edge_tf = redteam_infra_path("external", "sketch", "digitalocean", "edge.tf").read_text(encoding="utf-8")
        cloud_init = redteam_infra_path(
            "external", "sketch", "digitalocean", "templates", "sketch-bootstrap-cloud-init.tftpl"
        ).read_text(encoding="utf-8")

        for resource_tf in (middle_tf, edge_tf):
            self.assertIn("user_data = templatefile", resource_tf)
            self.assertIn("sketch-bootstrap-cloud-init.tftpl", resource_tf)
            self.assertIn("sketch_ssh_public_key = chomp(file(local.ssh_pub_key_path))", resource_tf)
            self.assertNotIn("provisioner \"remote-exec\"", resource_tf)
            self.assertNotIn("connection {", resource_tf)

        self.assertIn("#cloud-config", cloud_init)
        self.assertIn("name: user", cloud_init)
        self.assertIn("gecos: Sketch Management", cloud_init)
        self.assertIn("- sudo", cloud_init)
        self.assertIn('sudo: "ALL=(ALL) NOPASSWD:ALL"', cloud_init)
        self.assertIn("name: sketchssh", cloud_init)
        self.assertIn("gecos: Sketch SSH", cloud_init)
        self.assertIn("shell: /bin/bash", cloud_init)
        self.assertIn("lock_passwd: true", cloud_init)
        self.assertIn("ssh_authorized_keys:", cloud_init)
        self.assertIn("${sketch_ssh_public_key}", cloud_init)
        self.assertNotIn("proxy01", cloud_init)
        self.assertNotIn("homebase", cloud_init)
        self.assertNotIn("edge-", cloud_init)
        self.assertNotIn("middle-", cloud_init)
        self.assertNotIn("do_pat", cloud_init)
        self.assertNotIn("digitalocean", cloud_init.lower())
        self.assertNotIn("provider", cloud_init.lower())
        self.assertNotIn("example_operator", cloud_init)
        self.assertNotIn("aluvshis", cloud_init)


def _empty_retained_state():
    return {
        "version": 4,
        "serial": 1,
        "lineage": "00000000-0000-0000-0000-000000000000",
        "outputs": {},
        "resources": [],
    }


def _job_input(terraform_dir, *, retained=False):
    workspace = Path(terraform_dir)
    workspace.mkdir(parents=True, exist_ok=True)
    if retained:
        (workspace / "terraform.tfstate").write_text(
            json.dumps(
                {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "digitalocean_droplet",
                            "instances": [{"attributes": {"image": "ubuntu-22-04-x64"}}],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
    return {
        "engagementId": "eng-of02-dev",
        "engagementName": "of02-dev",
        "chainId": "chain-1",
        "middleCredentialAlias": "do-barragan",
        "edgeCredentialAlias": "do-barragan",
        "middleRegion": "sfo3",
        "edgeRegion": "sfo3",
        "middleSize": "s-1vcpu-1gb",
        "edgeSize": "s-1vcpu-1gb",
        "terraformWorkingDirectory": terraform_dir,
    }


class _WorkspaceRepository:
    def __init__(self):
        self.workspace = StoredEngagementWorkspace(
            engagement_id="eng-of02-dev",
            slug="of02-dev",
            path="/private/engagements/of02-dev",
            status="prepared",
            profile_id="standard-rti",
            template_source={},
            metadata={"managedHostImageProfile": "ubuntu-22.04"},
        )

    def get(self, engagement_id):
        return self.workspace if engagement_id == self.workspace.engagement_id else None

    def save(self, workspace):
        self.workspace = workspace
        return workspace


def _workspace_repository():
    return _WorkspaceRepository()


def _event_by_message(events, message):
    return next(event for event in events if event.message == message)
