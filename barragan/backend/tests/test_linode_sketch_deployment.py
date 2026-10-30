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
from app.services.jobs import enqueue_job, run_job
from app.services.linode_sketch_deployment import (
    LINODE_SKETCH_CONFIRMATION,
    LINODE_SKETCH_DEPLOY_ACTION,
    LINODE_SKETCH_RECONCILE_ACTION,
    LINODE_SKETCH_TEARDOWN_ACTION,
    LinodeSketchGuardrailError,
    start_guarded_linode_sketch_run,
    start_guarded_linode_sketch_teardown,
    run_linode_sketch_job,
    LinodeSketchSpec,
    _sketch_infrastructure_rows,
)
from app.services.redteam_infra_template import redteam_infra_path
from app.services.credentials import test_master_key as credential_test_master_key
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


class LinodeSketchDeploymentTests(unittest.TestCase):
    def setUp(self):
        self._template_dir = tempfile.TemporaryDirectory()
        root = Path(self._template_dir.name)
        write_sketch_template_fixture(root, providers=("linode",))
        self._template_env = patch.dict("os.environ", {"BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT": str(root)})
        self._template_env.start()
        self._retained_validator = patch(
            "app.services.linode_sketch_deployment.validate_existing_sketch_state_workspace"
        )
        self._retained_validator.start()
        self._collaborator_access = patch(
            "app.services.linode_sketch_deployment.grant_collaborator_access_to_existing_sketch_state_workspace"
        )
        self._collaborator_access.start()

    def tearDown(self):
        self._collaborator_access.stop()
        self._retained_validator.stop()
        self._template_env.stop()
        self._template_dir.cleanup()

    def test_region_major_outputs_correlate_interleaved_edge_rows_by_region(self):
        spec = LinodeSketchSpec(
            engagement_id="eng-1", engagement_name="test", chain_id="proxy01-sea-01", assigned_proxy="proxy01",
            middle_region="us-sea", edge_region="us-sea", middle_size="g6-nanode-1", edge_size="g6-nanode-1",
            middle_count=1, edge_count=4, credential_alias="alias", working_directory="/tmp",
            edge_regions=("us-sea", "us-lax"), edge_count_per_region=2,
            edge_intents=(("edge-01", "us-sea"), ("edge-02", "us-lax"), ("edge-03", "us-sea"), ("edge-04", "us-lax")),
        )
        rows = _sketch_infrastructure_rows(spec, {"edge_public_ips": {"value": {"us-sea": ["1", "3"], "us-lax": ["2", "4"]}}})
        assert [(row["edgeId"], row["region"]) for row in rows if row["role"] == "edge"] == [
            ("edge-01", "us-sea"), ("edge-03", "us-sea"), ("edge-02", "us-lax"), ("edge-04", "us-lax"),
        ]

    def test_linode_sketch_teardown_returns_running_job_before_background_destroy(self):
        runner = FakeTerraformRunner({})
        tasks = []

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            deploy = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir, retained=True),
                repository=repository,
            )
            with patch("app.services.linode_sketch_deployment.resolve_credential_secret", return_value="test-token"):
                running = start_guarded_linode_sketch_teardown(
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

    def test_linode_teardown_adapts_retained_split_key_workspace(self):
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
                action=LINODE_SKETCH_TEARDOWN_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=input_data,
                repository=repository,
            )
            completed = run_job(
                queued.id,
                repository=repository,
                executors={
                    LINODE_SKETCH_TEARDOWN_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=RecordingCredentialResolver("test-token"),
                    )
                },
            )

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

    def test_linode_deploy_adapts_stock_workspace_before_terraform_init(self):
        runner = FakeTerraformRunner({})

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            source = redteam_infra_path("external", "sketch", "linode")
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
                action=LINODE_SKETCH_DEPLOY_ACTION,
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
                    LINODE_SKETCH_DEPLOY_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=RecordingCredentialResolver("test-token"),
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(compatibility_at_call[0], ("init", True))
        self.assertTrue(all(compatible for _, compatible in compatibility_at_call))

    def test_linode_sketch_deploy_runs_as_job_and_records_redacted_infrastructure_output(self):
        secret = "linode-token-sensitive-value"
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.10"]},
                "edge_public_ips": {"value": {"us-sea": "203.0.113.20"}},
                "middle_instance_ids": {"value": ["1111"]},
                "edge_instance_ids": {"value": {"us-sea": "2222"}},
            }
        )
        resolver = RecordingCredentialResolver(secret)

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir),
                repository=repository,
            )

            self.assertEqual(resolver.calls, [])
            self.assertNotIn(secret, str(queued.to_dict()))

            completed = run_job(
                queued.id,
                repository=repository,
                executors={
                    LINODE_SKETCH_DEPLOY_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(resolver.calls, [("linode", "linode-barragan")])
        self.assertEqual([call["command"] for call in runner.calls], ["init", "apply", "output"])
        self.assertTrue(all(call["env"]["TF_VAR_linode_api_token"] == secret for call in runner.calls))
        self.assertEqual(runner.calls[1]["variables"]["engagement_name"], "of02-dev")
        self.assertEqual(runner.calls[1]["variables"]["resource_name_suffix"], "")
        self.assertEqual(runner.calls[1]["variables"]["middle_region"], "us-sea")
        self.assertEqual(runner.calls[1]["variables"]["edge_regions"], ["us-sea"])
        self.assertEqual(runner.calls[1]["variables"]["linode_image"], "linode/ubuntu24.04")
        self.assertTrue(runner.calls[1]["variables"]["ssh_pub_key_path"].endswith("/of02-dev-sketch.pub"))

        output_event = _event_by_message(completed.events, "terraform output recorded")
        rows = output_event.data["sketchInfrastructure"]
        self.assertEqual([row["hostname"] for row in rows], ["middle01-of02-dev", "edge-of02-dev-us-sea-01"])
        self.assertEqual([row["role"] for row in rows], ["middle", "edge"])
        self.assertEqual([row["provider"] for row in rows], ["linode", "linode"])
        self.assertEqual([row["providerInstanceId"] for row in rows], ["1111", "2222"])
        self.assertEqual([row["publicIp"] for row in rows], ["203.0.113.10", "203.0.113.20"])
        channel_event = _event_by_message(completed.events, "pending outbound channel artifacts derived")
        self.assertEqual(channel_event.data["phase"], "outbound_channel_derivation")
        self.assertEqual(len(channel_event.data["outboundChannels"]), 1)
        channel = channel_event.data["outboundChannels"][0]
        self.assertEqual(channel["chainId"], "chain-1")
        self.assertEqual(channel["proxy"], "proxy01")
        self.assertEqual(channel["middle"], "middle01-of02-dev")
        self.assertEqual(channel["edge"], "edge-of02-dev-us-sea-01")
        self.assertEqual(channel["port"], "3333")
        self.assertEqual(channel["provider"], "linode")
        self.assertEqual(channel["region"], "us-sea")
        self.assertEqual(channel["status"], "Pending Proxy Configuration")
        self.assertEqual(channel["profileName"], "chain-1")
        self.assertEqual(channel["publicationPath"], "/opt/proxy01/chain-1-socks5.conf")
        self.assertEqual(channel["validation"]["shellDisplay"], "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com")
        self.assertEqual(channel["validation"]["expectedPublicIp"], "203.0.113.20")
        self.assertEqual(channel["artifactTargets"]["homebaseProxychains"], "/opt/proxy01/chain-1-socks5.conf")
        self.assertEqual(channel["artifactTargets"]["proxySshConfig"], "/opt/ssh-proxy/config-3333")
        self.assertEqual(channel["artifactTargets"]["proxySystemdService"], "/etc/systemd/system/ssh-proxy-3333.service")
        self.assertIn("socks5 192.168.2.11 3333", channel["artifacts"]["homebaseProxychains"]["content"])
        self.assertIn("Hostname 203.0.113.10", channel["artifacts"]["proxySshConfig"]["content"])
        self.assertIn("Hostname 203.0.113.20", channel["artifacts"]["proxySshConfig"]["content"])
        self.assertIn("DynamicForward 0.0.0.0:3333", channel["artifacts"]["proxySshConfig"]["content"])
        self.assertIn("ExecStart=/usr/bin/autossh -M0 -F /opt/ssh-proxy/config-3333 -N edge-of02-dev-us-sea-01", channel["artifacts"]["proxySystemdService"]["content"])
        self.assertEqual(channel["artifacts"]["sketchNodeBoundary"]["middleNodeArtifacts"], [])
        self.assertEqual(channel["artifacts"]["sketchNodeBoundary"]["edgeNodeArtifacts"], [])
        self.assertIn("credential", _event_phases(completed.events))
        self.assertIn("init", _event_phases(completed.events))
        self.assertIn("apply", _event_phases(completed.events))
        self.assertIn("output", _event_phases(completed.events))
        self.assertIn("outbound_channel_derivation", _event_phases(completed.events))
        apply_event = _event_by_message(completed.events, "terraform apply completed")
        self.assertTrue(apply_event.data["startedAt"])
        self.assertTrue(apply_event.data["finishedAt"])
        self.assertGreaterEqual(apply_event.data["elapsedSeconds"], 0)
        self.assertNotIn(secret, str(completed.to_dict()))
        self.assertNotIn("token-sensitive-value", str(completed.to_dict()))
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", str(completed.to_dict()))

    def test_linode_sketch_deploy_supports_multiple_edges_per_middle(self):
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.10"]},
                "edge_public_ips": {"value": {"us-sea": ["203.0.113.20", "203.0.113.21"]}},
                "middle_instance_ids": {"value": ["1111"]},
                "edge_instance_ids": {"value": {"us-sea": ["2222", "3333"]}},
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
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
                    LINODE_SKETCH_DEPLOY_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=RecordingCredentialResolver("secret"),
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(runner.calls[1]["variables"]["edge_count_per_region"], 2)
        rows = _event_by_message(completed.events, "terraform output recorded").data["sketchInfrastructure"]
        self.assertEqual([row["hostname"] for row in rows], ["middle01-of02-dev", "edge-of02-dev-us-sea-01", "edge-of02-dev-us-sea-02"])
        channel_event = _event_by_message(completed.events, "pending outbound channel artifacts derived")
        channels = channel_event.data["outboundChannels"]
        self.assertEqual([channel["channelId"] for channel in channels], ["chain-1-edge-01", "chain-1-edge-02"])
        self.assertEqual([channel["chainId"] for channel in channels], ["chain-1", "chain-1"])
        self.assertEqual([channel["edge"] for channel in channels], ["edge-of02-dev-us-sea-01", "edge-of02-dev-us-sea-02"])
        self.assertEqual([channel["port"] for channel in channels], ["3333", "3334"])
        self.assertEqual([channel["validation"]["expectedPublicIp"] for channel in channels], ["203.0.113.20", "203.0.113.21"])
        self.assertEqual([row["publicIp"] for row in rows], ["203.0.113.10", "203.0.113.20", "203.0.113.21"])

    def test_linode_sketch_deploy_uses_readable_provider_name_and_chain_suffix(self):
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.10"]},
                "edge_public_ips": {"value": ["203.0.113.20"]},
            }
        )
        resolver = RecordingCredentialResolver("linode-token-sensitive-value")

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            for chain_id in ("proxy01-sea-01", "proxy02-sea-01"):
                queued = enqueue_job(
                    action=LINODE_SKETCH_DEPLOY_ACTION,
                    target_type="engagement",
                    target_id="eng-sk02-dev",
                    requested_by="operator@example.invalid",
                    input_data={
                        **_job_input(terraform_dir=temp_dir),
                        "engagementId": "eng-sk02-dev",
                        "engagementName": "SK02-dev",
                        "chainId": chain_id,
                    },
                    repository=repository,
                )
                completed = run_job(
                    queued.id,
                    repository=repository,
                    executors={
                        LINODE_SKETCH_DEPLOY_ACTION: lambda job: run_linode_sketch_job(
                            job,
                            runner=runner,
                            credential_resolver=resolver,
                        )
                    },
                )
                self.assertEqual(completed.status, "succeeded")

        apply_names = [
            (call["variables"]["engagement_name"], call["variables"]["resource_name_suffix"])
            for call in runner.calls
            if call["command"] == "apply"
        ]
        self.assertEqual(
            apply_names,
            [
                ("sk02-dev", ""),
                ("sk02-dev", "-02"),
            ],
        )
        self.assertTrue(all(len(f"allow-{name}{suffix}-host-icmp") <= 32 for name, suffix in apply_names))

    def test_linode_sketch_teardown_verifies_cleanup_without_recording_secret(self):
        secret = "linode-token-sensitive-value"
        runner = FakeTerraformRunner({})
        resolver = RecordingCredentialResolver(secret)

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_TEARDOWN_ACTION,
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
                    LINODE_SKETCH_TEARDOWN_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual([call["command"] for call in runner.calls], ["init", "destroy", "output"])
        self.assertEqual(runner.calls[1]["variables"]["linode_image"], "linode/ubuntu22.04")
        self.assertTrue(completed.events[-1].data["cleanupVerified"])
        self.assertEqual(completed.events[-1].data["sketchInfrastructure"], [])
        self.assertIn("destroy", _event_phases(completed.events))
        self.assertIn("cleanup", _event_phases(completed.events))
        self.assertNotIn(secret, str(completed.to_dict()))

    def test_linode_sketch_teardown_fails_when_cleanup_outputs_remain(self):
        runner = FakeTerraformRunner({"middle_public_ip": {"value": "203.0.113.10"}})
        resolver = RecordingCredentialResolver("linode-token-sensitive-value")

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_TEARDOWN_ACTION,
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
                    LINODE_SKETCH_TEARDOWN_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        self.assertEqual(completed.status, "failed")
        self.assertIn("cleanup verification", completed.events[-1].message)

    def test_linode_sketch_deploy_skips_outbound_channel_artifacts_for_incomplete_output(self):
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.10"]},
                "edge_public_ips": {"value": []},
            }
        )
        resolver = RecordingCredentialResolver("linode-token-sensitive-value")

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
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
                    LINODE_SKETCH_DEPLOY_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        self.assertEqual(completed.status, "succeeded")
        skipped_event = _event_by_message(completed.events, "outbound channel artifacts skipped")
        self.assertEqual(skipped_event.level, "warning")
        self.assertEqual(skipped_event.data["phase"], "outbound_channel_derivation")
        self.assertEqual(skipped_event.data["outboundChannels"], [])
        self.assertIn("incomplete sketch output", skipped_event.data["reason"])
        self.assertNotIn("linode-token-sensitive-value", str(completed.to_dict()))

    def test_linode_sketch_deploy_attempts_cleanup_after_apply_failure(self):
        runner = FakeTerraformRunner(fail_commands={"apply"})
        resolver = RecordingCredentialResolver("linode-token-sensitive-value")

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
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
                    LINODE_SKETCH_DEPLOY_ACTION: lambda job: run_linode_sketch_job(
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

    def test_linode_sketch_deploy_records_redacted_provider_failure_diagnostic(self):
        secret = "linode-token-sensitive-value"
        runner = FakeTerraformRunner(
            fail_commands={"apply"},
            stderr_by_command={
                "apply": "\n".join(
                    [
                        "Error: failed to create firewall rule",
                        "",
                        '  with linode_firewall.sketch_edge["us-sea"],',
                        "Provider returned token=linode-token-sensitive-value and label exceeds maximum length",
                    ]
                )
            },
        )
        resolver = RecordingCredentialResolver(secret)

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
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
                    LINODE_SKETCH_DEPLOY_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        event = _event_by_message(completed.events, "terraform apply failed")
        diagnostic = event.data["terraformDiagnostic"]
        self.assertEqual(diagnostic["provider"], "linode")
        self.assertEqual(diagnostic["command"], "apply")
        self.assertEqual(diagnostic["returnCode"], 1)
        self.assertEqual(diagnostic["errorClass"], "provider_api_permanent")
        self.assertIn("failed to create firewall rule", diagnostic["summary"])
        self.assertIn("linode_firewall.sketch_edge", diagnostic["resourceHints"][0])
        self.assertIn("[REDACTED]", diagnostic["stderrExcerpt"])
        self.assertNotIn(secret, str(completed.to_dict()))

    def test_linode_sketch_deploy_attempts_cleanup_after_invalid_output(self):
        runner = FakeTerraformRunner(output_text="{not-json")
        resolver = RecordingCredentialResolver("linode-token-sensitive-value")

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
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
                    LINODE_SKETCH_DEPLOY_ACTION: lambda job: run_linode_sketch_job(
                        job,
                        runner=runner,
                        credential_resolver=resolver,
                    )
                },
            )

        self.assertEqual(completed.status, "failed")
        self.assertEqual([call["command"] for call in runner.calls], ["init", "apply", "output", "destroy", "output"])
        self.assertIn("terraform output failed", [event.message for event in completed.events])
        self.assertIn("terraform cleanup verification failed", [event.message for event in completed.events])

    def test_generic_job_runner_does_not_execute_linode_sketch_without_guarded_executor(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir),
                repository=repository,
            )

            completed = run_job(queued.id, repository=repository)

        self.assertEqual(completed.status, "failed")
        self.assertIn("unsupported plan-only action", completed.events[-1].message)

    def test_generic_job_exception_redacts_sensitive_details(self):
        secret = "linode-token-sensitive-value"

        def executor(_job):
            raise RuntimeError(f"provider token failed: {secret}")

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_DEPLOY_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator@example.invalid",
                input_data=_job_input(terraform_dir=temp_dir),
                repository=repository,
            )

            completed = run_job(
                queued.id,
                repository=repository,
                executors={LINODE_SKETCH_DEPLOY_ACTION: executor},
            )

        self.assertEqual(completed.status, "failed")
        self.assertNotIn(secret, str(completed.to_dict()))
        self.assertIn("redacted sensitive details", completed.events[-1].message)

    def test_bundled_linode_sketch_template_exports_edge_public_ips(self):
        output_tf = redteam_infra_path("external", "sketch", "linode", "output.tf").read_text(encoding="utf-8")

        self.assertIn('output "middle_public_ips"', output_tf)
        self.assertIn('output "edge_public_ips"', output_tf)
        self.assertIn('output "middle_instance_ids"', output_tf)
        self.assertIn('output "edge_instance_ids"', output_tf)

    def test_bundled_linode_sketch_template_passes_sanitized_host_maps_to_templates(self):
        main_tf = redteam_infra_path("external", "sketch", "linode", "main.tf").read_text(encoding="utf-8")
        output_tf = redteam_infra_path("external", "sketch", "linode", "output.tf").read_text(encoding="utf-8")
        ssh_template = redteam_infra_path(
            "external", "sketch", "linode", "templates", "ssh-stanza.tftpl"
        ).read_text(encoding="utf-8")

        self.assertIn("middle_hosts", main_tf)
        self.assertIn("edge_hosts", main_tf)
        self.assertIn("tolist(node.ipv4)[0]", main_tf)
        self.assertIn("middles = local.middle_hosts", output_tf)
        self.assertIn("edges = local.edge_hosts", output_tf)
        self.assertNotIn("linode_instance.middle.*", output_tf)
        self.assertNotIn("linode_instance.edge.*", output_tf)
        self.assertNotIn(".ip_address", ssh_template)
        self.assertIn("${middle.public_ip}", ssh_template)
        self.assertIn("${edge.public_ip}", ssh_template)

    def test_bundled_linode_sketch_template_bootstraps_management_and_runtime_users(self):
        middle_tf = redteam_infra_path("external", "sketch", "linode", "middle.tf").read_text(encoding="utf-8")
        edge_tf = redteam_infra_path("external", "sketch", "linode", "edge.tf").read_text(encoding="utf-8")
        cloud_init = redteam_infra_path(
            "external", "sketch", "linode", "templates", "sketch-bootstrap-cloud-init.tftpl"
        ).read_text(encoding="utf-8")

        for resource_tf in (middle_tf, edge_tf):
            self.assertIn("metadata {", resource_tf)
            self.assertIn("user_data = base64encode(templatefile", resource_tf)
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
        self.assertNotIn("linode_api_token", cloud_init)
        self.assertNotIn("provider", cloud_init.lower())

    def test_guarded_linode_sketch_run_creates_controlled_workspace_and_sanitized_job(self):
        secret = "linode-token-sensitive-value"
        variables_path = redteam_infra_path("external", "sketch", "linode", "variables.tf")
        variables_path.write_text(
            variables_path.read_text(encoding="utf-8")
            + '\nvariable "infrastructure_admin_ssh_pub_key_path" {}\n'
            + 'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
            + 'variable "sketch_transport_ssh_pub_key_path" {}\n',
            encoding="utf-8",
        )
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.10"]},
                "edge_public_ips": {"value": ["203.0.113.20"]},
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            app = create_app(TestConfig)
            with app.storage_context():
                with patch.dict("os.environ", {"BARRAGAN_CREDENTIAL_MASTER_KEY": credential_test_master_key(), "BARRAGAN_SKETCH_STATE_ROOT": str(Path(temp_dir) / "sketch-state")}):
                    with patch("app.services.linode_sketch_deployment.get_engagement", return_value=type("Engagement", (), {"name": "of02-dev"})()):
                        with patch("app.services.linode_sketch_deployment.resolve_credential_secret", return_value=secret):
                            running = start_guarded_linode_sketch_run(
                                {
                                    "confirmMutation": LINODE_SKETCH_CONFIRMATION,
                                    "engagementId": "eng-of02-dev",
                                    "chainId": "chain-1",
                                    "middleRegion": "us-sea",
                                    "edgeRegion": "us-sea",
                                    "middleSize": "g6-nanode-1",
                                    "edgeSize": "g6-nanode-1",
                                    "middleCredentialAlias": "linode-barragan",
                                    "edgeCredentialAlias": "linode-barragan",
                                    "terraformWorkingDirectory": "/unsafe/operator/path",
                                },
                                repository=repository,
                                runner=runner,
                                background_runner=lambda task: task(),
                                workspace_repository=_workspace_repository(),
                            )
            completed = repository.get(running.id).to_detail()

        self.assertEqual(running.status, "running")
        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(completed.input["terraformEngagementName"], "of02-dev")
        self.assertEqual(completed.input["resourceNameSuffix"], "")
        self.assertEqual(completed.input["middleOrdinal"], 1)
        self.assertEqual(completed.input["edgeOrdinal"], 1)
        self.assertEqual(completed.input["managedHostImageProfile"], "ubuntu-22.04")
        self.assertNotEqual(completed.input["terraformWorkingDirectory"], "/unsafe/operator/path")
        self.assertIn("sketch-state/eng-of02-dev/chain-1/linode", completed.input["terraformWorkingDirectory"])
        self.assertTrue(completed.input["materializeKeyFiles"])
        self.assertEqual(completed.input["sshPrivateKeyPath"], "")
        self.assertEqual(completed.input["sshPublicKeyPath"], "")
        self.assertEqual(completed.input["sketchTransportSshPublicKeyPath"], "")
        apply_variables = next(call["variables"] for call in runner.calls if call["command"] == "apply")
        self.assertEqual(apply_variables["linode_image"], "linode/ubuntu22.04")
        self.assertTrue(Path(apply_variables["infrastructure_admin_ssh_pub_key_path"]).name.endswith("-sketch.pub"))
        self.assertTrue(Path(apply_variables["sketch_transport_ssh_pub_key_path"]).name.endswith("-sketch-transport.pub"))
        self.assertFalse(Path(apply_variables["infrastructure_admin_ssh_pub_key_path"]).exists())
        self.assertFalse(Path(apply_variables["sketch_transport_ssh_pub_key_path"]).exists())
        self.assertNotIn(secret, str(completed.to_dict()))
        self.assertIn("terraform output recorded", [event.message for event in completed.events])

    def test_linode_edge_reconcile_requires_and_records_a_reviewed_final_edge_plan(self):
        class PlanRunner(FakeTerraformRunner):
            def run(self, command, *, working_directory, env, variables=None):
                self.calls.append({"command": command, "workingDirectory": working_directory, "env": dict(env), "variables": dict(variables or {})})
                if command == "plan":
                    return TerraformCommandResult(
                        command=command,
                        returncode=2,
                        stdout='{"type":"planned_change","change":{"action":"delete","resource":{"addr":"linode_instance.edge[1]"}}}',
                        stderr="",
                    )
                stdout = json.dumps(self.output_body) if command == "output" else ""
                return TerraformCommandResult(command=command, returncode=0, stdout=stdout, stderr="")

        runner = PlanRunner({"middle_public_ips": {"value": ["203.0.113.10"]}, "edge_public_ips": {"value": ["203.0.113.20"]}})
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            queued = enqueue_job(
                action=LINODE_SKETCH_RECONCILE_ACTION,
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="operator",
                input_data={
                    **_job_input(temp_dir, retained=True),
                    "edgeCount": 1,
                    "edgeRegions": ["us-sea"],
                    "edgeCountPerRegion": 1,
                    "expectedEdgeAddress": "linode_instance.edge[1]",
                    "expectedEdgeAction": "delete",
                },
                repository=repository,
            )
            completed = run_job(
                queued.id,
                repository=repository,
                executors={LINODE_SKETCH_RECONCILE_ACTION: lambda job: run_linode_sketch_job(job, runner=runner, credential_resolver=RecordingCredentialResolver("token"))},
            )

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual([call["command"] for call in runner.calls], ["init", "plan", "apply", "output"])
        self.assertIn("terraform edge transition plan approved", [event.message for event in completed.events])

    def test_guarded_linode_sketch_run_uses_default_credential_when_aliases_are_absent(self):
        secret = "linode-token-sensitive-value"
        runner = FakeTerraformRunner(
            {
                "middle_public_ips": {"value": ["203.0.113.10"]},
                "edge_public_ips": {"value": ["203.0.113.20"]},
            }
        )
        app = create_app(TestConfig)
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            with app.storage_context():
                with patch.dict("os.environ", {"BARRAGAN_CREDENTIAL_MASTER_KEY": credential_test_master_key(), "BARRAGAN_SKETCH_STATE_ROOT": str(Path(temp_dir) / "sketch-state")}):
                    client = app.test_client()
                    client.post(
                        "/api/credentials",
                        json={"provider": "linode", "alias": "linode-global-default", "secret": secret, "isDefault": True},
                    )
                    with patch("app.services.linode_sketch_deployment.get_engagement", return_value=type("Engagement", (), {"name": "of02-dev"})()):
                        running = start_guarded_linode_sketch_run(
                            {
                                "confirmMutation": LINODE_SKETCH_CONFIRMATION,
                                "engagementId": "eng-of02-dev",
                                "chainId": "chain-1",
                                "middleRegion": "us-sea",
                                "edgeRegion": "us-sea",
                            },
                            repository=repository,
                            runner=runner,
                            background_runner=lambda task: task(),
                            workspace_repository=_workspace_repository(),
                        )
            completed = repository.get(running.id).to_detail()

        self.assertEqual(completed.status, "succeeded")
        self.assertEqual(completed.input["middleCredentialAlias"], "linode-global-default")
        self.assertEqual(completed.input["edgeCredentialAlias"], "linode-global-default")
        self.assertTrue(all(call["env"]["TF_VAR_linode_api_token"] == secret for call in runner.calls))
        self.assertNotIn(secret, str(completed.to_dict()))

    def test_guarded_linode_sketch_run_rejects_unapproved_region_before_job_creation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
            app = create_app(TestConfig)
            with app.storage_context():
                with patch("app.services.linode_sketch_deployment.get_engagement", return_value=type("Engagement", (), {"name": "of02-dev"})()):
                    with self.assertRaises(LinodeSketchGuardrailError) as error:
                        start_guarded_linode_sketch_run(
                            {
                                "confirmMutation": LINODE_SKETCH_CONFIRMATION,
                                "engagementId": "eng-of02-dev",
                                "middleRegion": "us-ord",
                                "edgeRegion": "us-sea",
                                "middleCredentialAlias": "linode-barragan",
                                "edgeCredentialAlias": "linode-barragan",
                            },
                            repository=repository,
                            background_runner=lambda task: task(),
                        )

            self.assertEqual(repository.list(), [])
            self.assertIn("configured allowed regions", str(error.exception))

    def test_guarded_linode_sketch_api_routes(self):
        app = create_app(TestConfig)
        client = app.test_client()
        fake_job = FakeJobDetail("job-sketch-001", LINODE_SKETCH_DEPLOY_ACTION)

        with patch("app.asgi.start_guarded_linode_sketch_run", return_value=fake_job) as start:
            create_response = client.post(
                "/api/orchestrator/barragan-testing/linode-sketch/runs",
                json={
                    "confirmMutation": LINODE_SKETCH_CONFIRMATION,
                    "engagementId": "eng-of02-dev",
                    "middleRegion": "us-sea",
                    "edgeRegion": "us-sea",
                    "middleCredentialAlias": "linode-barragan",
                    "edgeCredentialAlias": "linode-barragan",
                },
            )

        self.assertEqual(create_response.status_code, 201)
        self.assertEqual(create_response.get_json()["job"]["id"], "job-sketch-001")
        start.assert_called_once()

        with patch("app.asgi.get_guarded_linode_sketch_run", return_value=fake_job):
            show_response = client.get("/api/orchestrator/barragan-testing/linode-sketch/runs/job-sketch-001")
        self.assertEqual(show_response.status_code, 200)

        with patch("app.asgi.teardown_guarded_linode_sketch_run", return_value=FakeJobDetail("job-sketch-td", LINODE_SKETCH_TEARDOWN_ACTION)):
            teardown_response = client.post("/api/orchestrator/barragan-testing/linode-sketch/runs/job-sketch-001/teardown")
        self.assertEqual(teardown_response.status_code, 200)
        self.assertEqual(teardown_response.get_json()["job"]["action"], LINODE_SKETCH_TEARDOWN_ACTION)

    def test_guarded_linode_sketch_api_rejects_guardrail_error(self):
        app = create_app(TestConfig)
        client = app.test_client()

        with patch("app.asgi.start_guarded_linode_sketch_run", side_effect=LinodeSketchGuardrailError("bad region")):
            response = client.post("/api/orchestrator/barragan-testing/linode-sketch/runs", json={})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "bad region")


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
                            "type": "linode_instance",
                            "instances": [{"attributes": {"image": "linode/ubuntu22.04"}}],
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
        "middleCredentialAlias": "linode-barragan",
        "edgeCredentialAlias": "linode-barragan",
        "middleRegion": "us-sea",
        "edgeRegion": "us-sea",
        "middleSize": "g6-nanode-1",
        "edgeSize": "g6-nanode-1",
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


def _event_phases(events):
    return {event.data.get("phase") for event in events if event.data.get("phase")}


def _event_by_message(events, message):
    return next(event for event in events if event.message == message)


class FakeJobDetail:
    def __init__(self, job_id, action):
        self.job_id = job_id
        self.action = action

    def to_dict(self):
        return {
            "id": self.job_id,
            "action": self.action,
            "status": "succeeded",
            "targetType": "engagement",
            "targetId": "eng-of02-dev",
            "requestedBy": "operator",
            "input": {"workspace": "linode-sketch", "engagementId": "eng-of02-dev"},
            "artifactRefs": ["terraform:linode-sketch:eng-of02-dev:chain-1"],
            "events": [
                {
                    "sequence": 1,
                    "level": "info",
                    "message": "Linode sketch run queued",
                    "data": {"workspace": "linode-sketch"},
                }
            ],
        }


if __name__ == "__main__":
    unittest.main()
