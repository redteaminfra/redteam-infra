# Copyright (c) 2026, Oracle and/or its affiliates.
import tempfile
import unittest
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.domain import JobEvent
from app.integrations.terraform_runner import TerraformCommandResult
from app.services.redteam_infra_template import redteam_infra_path
from app.services.sketch_provider_firewall import (
    provider_ingress_preflight_errors,
    provider_ingress_plan,
    sync_provider_ingress_for_inbound_channel,
    sync_provider_ingress_for_transport,
)
from app.services.sketch_state_workspaces import prepare_sketch_state_workspace
from app.services.template_compatibility import ensure_sketch_ssh_variable_contract_compatibility
from app.storage.job_repository import StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain
from redteam_infra_test_fixtures import write_sketch_template_fixture


def test_provider_scoped_state_cannot_enter_chain_scoped_ingress_reconciliation():
    runner = FakeTerraformRunner()
    with patch("app.services.sketch_provider_firewall.get_engagement",
        return_value=SimpleNamespace(sketch_state_schema="provider-keyed-v2"),
    ):
        errors = provider_ingress_preflight_errors("eng-keyed", "chain-1")
        result = sync_provider_ingress_for_inbound_channel(
            "eng-keyed", "Keyed", "chain-1", operation="apply",
            channel=_channel("channel-1", "8005"), overview=_overview([]),
            terraform_runner=runner,
        )
    assert errors == ["keyed channel Apply requires a current published six-node generation"]
    assert result.ok is False
    assert result.events[0].data["reason"] == "invalid_sketch_state_schema"
    assert runner.calls == []


def test_missing_engagement_cannot_enter_chain_scoped_ingress_reconciliation():
    runner = FakeTerraformRunner()
    with patch("app.services.sketch_provider_firewall.get_engagement", return_value=None):
        errors = provider_ingress_preflight_errors("eng-missing", "chain-1")
        result = sync_provider_ingress_for_inbound_channel(
            "eng-missing", "Missing", "chain-1", operation="apply",
            channel=_channel("channel-1", "8005"), overview=_overview([]),
            terraform_runner=runner,
        )
    assert errors == ["managed provider ingress requires an existing split-v1 engagement"]
    assert result.ok is False
    assert result.events[0].data["reason"] == "invalid_sketch_state_schema"
    assert runner.calls == []


class FakeTerraformRunner:
    def __init__(self, *, plan_stdout=""):
        self.calls = []
        self.workspace_snapshots = []
        self.plan_stdout = plan_stdout
        self._show_index = 0
        self._planned_variables = {}

    def run(
        self,
        command,
        *,
        working_directory,
        env,
        variables=None,
        targets=(),
        refresh=True,
        saved_plan_path=None,
    ):
        workspace = Path(working_directory)
        self.workspace_snapshots.append(
            {
                "command": command,
                "variablesTf": (workspace / "variables.tf").read_text(encoding="utf-8"),
                "middleTf": (workspace / "middle.tf").read_text(encoding="utf-8")
                if (workspace / "middle.tf").exists()
                else "",
                "edgeTf": (workspace / "edge.tf").read_text(encoding="utf-8")
                if (workspace / "edge.tf").exists()
                else "",
                "providersTf": (workspace / "providers.tf").read_text(encoding="utf-8")
                if (workspace / "providers.tf").exists()
                else "",
            }
        )
        self.calls.append(
            {
                "command": command,
                "workingDirectory": working_directory,
                "env": dict(env),
                "variables": dict(variables or {}),
                "targets": tuple(targets),
                "refresh": refresh,
                "savedPlanPath": str(saved_plan_path) if saved_plan_path is not None else "",
            }
        )
        if command == "plan":
            self._planned_variables[working_directory] = dict(variables or {})
            Path(saved_plan_path).write_bytes(b"saved-plan")
            return TerraformCommandResult(
                command=command,
                returncode=2 if self.plan_stdout else 0,
                stdout="plan-created",
                stderr="",
            )
        if command == "show":
            if isinstance(self.plan_stdout, list):
                stdout = self.plan_stdout[self._show_index]
                self._show_index += 1
            else:
                stdout = self.plan_stdout
            if not stdout:
                provider = "linode" if "TF_VAR_linode_api_token" in env else "digitalocean"
                stdout = _proven_noop_plan(
                    provider,
                    self._planned_variables[working_directory].get("allowed_tcp_ports", []),
                    self._planned_variables[working_directory].get("allowed_udp_ports", []),
                )
            return TerraformCommandResult(
                command=command,
                returncode=0,
                stdout=stdout,
                stderr="",
            )
        return TerraformCommandResult(command=command, returncode=0, stdout="ok", stderr="")


class LiveKeyPathTerraformRunner(FakeTerraformRunner):
    def __init__(self, *, plan_stdout=""):
        super().__init__(plan_stdout=plan_stdout)
        self.key_paths_by_workspace = {}

    def run(self, command, **kwargs):
        workspace = kwargs["working_directory"]
        variables = kwargs.get("variables") or {}
        key_paths = tuple(
            Path(str(value)) for name, value in variables.items() if name.endswith("_key_path")
        )
        if key_paths:
            self.key_paths_by_workspace[workspace] = key_paths
        for path in self.key_paths_by_workspace.get(workspace, ()):
            if not path.is_file():
                raise AssertionError(f"Terraform {command} observed a missing key file")
        return super().run(command, **kwargs)


class LeakyPhaseTerraformRunner(LiveKeyPathTerraformRunner):
    def __init__(self, phase, materialized):
        super().__init__()
        self.phase = phase
        self.materialized = materialized

    def run(self, command, **kwargs):
        result = super().run(command, **kwargs)
        if command != self.phase:
            return result
        paths = self.materialized["paths"]
        leaked = " | ".join(
            f"{path}: {path.read_text(encoding='utf-8').strip()}" for path in paths
        )
        escaped = " | ".join(json.dumps(content)[1:-1] for content in self.materialized["contents"])
        return TerraformCommandResult(
            command=command,
            returncode=1,
            stdout=(
                f"useful {command} diagnostic before secret | {leaked} | "
                f"escaped material: {escaped}"
            ),
            stderr=f"{command} failed in staging directory {paths[0].parent}",
        )


class FakeJobRepository:
    def __init__(self, job):
        self.job = job

    def get(self, job_id):
        return self.job if job_id == self.job.id else None

    def list(self):
        core = StoredJobRun(
            id="job-core",
            action="core_deploy",
            status="succeeded",
            target="engagement:eng-zy01",
            target_type="engagement",
            target_id="eng-zy01",
            requested_by="operator",
            input={"engagementId": "eng-zy01"},
            artifact_refs=[],
            created_at="2026-06-10T00:00:00+00:00",
            started_at="2026-06-10T00:00:00+00:00",
            finished_at="2026-06-10T00:00:00+00:00",
            events=[
                JobEvent(
                    1,
                    "info",
                    "core deployed",
                    {
                        "mutationStatus": "deployed",
                        "connectionDetails": [
                            {"role": "proxy", "sshAlias": "proxy01", "publicIp": "198.51.100.10"}
                        ],
                    },
                )
            ],
        )
        return [self.job, core]


class FakeSketchChainRepository:
    def __init__(self, chain):
        self.chain = chain

    def get(self, engagement_id, chain_id):
        if self.chain.engagement_id == engagement_id and self.chain.chain_id == chain_id:
            return self.chain
        return None


class SketchProviderFirewallTests(unittest.TestCase):
    def setUp(self):
        self._template_dir = tempfile.TemporaryDirectory()
        root = Path(self._template_dir.name)
        write_sketch_template_fixture(root, providers=("linode", "digitalocean"))
        self._template_env = patch.dict("os.environ", {"BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT": str(root)})
        self._template_env.start()
        self._workspace_validation = patch(
            "app.services.sketch_provider_firewall.validate_existing_sketch_state_workspace",
            side_effect=lambda engagement_id, chain_id, provider, workspace, **kwargs: SimpleNamespace(
                path=Path(workspace), state_path=Path(workspace) / "terraform.tfstate"
            ),
        )
        self._retained_image = patch(
            "app.services.sketch_provider_firewall.retained_compute_image_for_workspace",
            return_value="retained-image-identity",
        )
        self._collaborator_access = patch(
            "app.services.sketch_provider_firewall.grant_collaborator_access_to_existing_sketch_state_workspace"
        )
        self._engagement_lookup = patch(
            "app.services.sketch_provider_firewall.get_engagement",
            return_value=SimpleNamespace(sketch_state_schema="split-v1"),
        )
        self._engagement_lookup.start()
        self._workspace_validation.start()
        self._retained_image.start()
        self._collaborator_access.start()

    def tearDown(self):
        self._engagement_lookup.stop()
        self._collaborator_access.stop()
        self._retained_image.stop()
        self._workspace_validation.stop()
        self._template_env.stop()
        self._template_dir.cleanup()

    def test_provider_ingress_preflight_accepts_deployed_supported_workspace(self):
        with tempfile.TemporaryDirectory() as workspace:
            job = _job(terraformWorkingDirectory=workspace)
            chain = _chain(terraform_working_directory=workspace)
            self.assertEqual(
                provider_ingress_preflight_errors(
                    "eng-zy01",
                    "chain-1",
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(chain),
                ),
                [],
            )

    def test_provider_ingress_preflight_rejects_unsupported_or_missing_workspace(self):
        job = _job(terraformWorkingDirectory="")
        chain = _chain(edge_provider="unsupported", terraform_working_directory="")
        errors = provider_ingress_preflight_errors(
            "eng-zy01",
            "chain-1",
            job_repository=FakeJobRepository(job),
            chain_repository=FakeSketchChainRepository(chain),
        )
        self.assertTrue(any("not supported" in error for error in errors))
        self.assertTrue(any("workspace is unavailable" in error for error in errors))

    def test_remove_keeps_shared_provider_port_until_last_channel_is_removed(self):
        shared_a = _channel("edge-zy01-us-sea-01-8005-to-proxy01-18080", "8005")
        shared_b = _channel("edge-zy01-us-sea-01-8005-to-proxy01-18081", "8005")
        overview = _overview([shared_a, shared_b])

        shared_plan = provider_ingress_plan(
            overview,
            "chain-1",
            operation="remove",
            channel=shared_a,
        )
        last_plan = provider_ingress_plan(
            _overview([shared_a]),
            "chain-1",
            operation="remove",
            channel=shared_a,
        )

        self.assertIn(8005, shared_plan.allowed_tcp_ports)
        self.assertNotIn(8005, last_plan.allowed_tcp_ports)
        self.assertEqual(last_plan.allowed_tcp_ports, (22, 80, 443, 2222))

    def test_udp_channels_are_planned_separately_from_tcp_ports(self):
        channel = _channel(
            "edge-zy01-us-sea-01-53-to-homebase-5454",
            "53",
            protocol="UDP",
            mode="udp-forward",
        )

        plan = provider_ingress_plan(_overview([channel]), "chain-1", operation="apply", channel=channel)

        self.assertEqual(plan.allowed_tcp_ports, (22, 80, 443, 2222))
        self.assertEqual(plan.allowed_udp_ports, (53,))

    def test_repairs_legacy_key_references_after_prior_variables_refresh(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text(
                'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                'variable "infrastructure_admin_ssh_priv_key_path" {}\n',
                encoding="utf-8",
            )
            (workspace / "main.tf").write_text(
                "locals { a = var.ssh_pub_key_path; b = var.ssh_priv_key_path }\n",
                encoding="utf-8",
            )

            changed = ensure_sketch_ssh_variable_contract_compatibility(workspace, "linode")

            variables = (workspace / "variables.tf").read_text(encoding="utf-8")
            self.assertEqual(changed, ["variables.tf"])
            self.assertIn('variable "ssh_pub_key_path"', variables)
            self.assertIn('variable "ssh_priv_key_path"', variables)
            self.assertIn('variable "infrastructure_admin_ssh_pub_key_path"', variables)

    def test_linode_sync_runs_terraform_with_allowed_ports_without_recording_secret(self):
        secret = "linode-token-sensitive-value"
        runner = FakeTerraformRunner()
        channel = _channel("edge-zy01-us-sea-01-8005-to-proxy01-18080", "8005")

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text(
                'variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n',
                encoding="utf-8",
            )
            (workspace / "firewall.tf").write_text("# old firewall\n", encoding="utf-8")
            chain = _chain(terraform_working_directory=str(workspace))
            job = _job(terraformWorkingDirectory=str(workspace))

            result = sync_provider_ingress_for_inbound_channel(
                "eng-zy01",
                "ZY01",
                "chain-1",
                operation="apply",
                channel=channel,
                overview=_overview([channel]),
                job_repository=FakeJobRepository(job),
                chain_repository=FakeSketchChainRepository(chain),
                credential_resolver=lambda provider, alias, repository: secret,
                terraform_runner=runner,
            )
            refreshed_firewall = (workspace / "firewall.tf").read_text(encoding="utf-8")

        self.assertTrue(result.ok)
        self.assertEqual([call["command"] for call in runner.calls], ["init", "plan", "show", "apply"])
        plan_call = runner.calls[1]
        apply_call = runner.calls[3]
        self.assertEqual(plan_call["env"]["TF_VAR_linode_api_token"], secret)
        self.assertIn("8005", plan_call["variables"]["allowed_tcp_ports"])
        self.assertEqual(plan_call["variables"]["allowed_udp_ports"], [])
        self.assertNotIn("bootstrap_ssh_source_cidrs", plan_call["variables"])
        self.assertEqual(apply_call["variables"], {})
        self.assertEqual(apply_call["targets"], ())
        self.assertEqual(apply_call["savedPlanPath"], plan_call["savedPlanPath"])
        self.assertIn("for_each = var.allowed_tcp_ports", refreshed_firewall)
        self.assertNotIn("bootstrap_ssh_source_cidrs", refreshed_firewall)
        self.assertNotIn(secret, str(result.events))

    def test_provider_sync_rejects_image_or_key_replacement_without_applying_and_cleans_plan(self):
        channel = _channel("edge-zy01-us-sea-01-8005-to-proxy01-18080", "8005")
        cases = (
            (
                "linode",
                "linode_firewall.firewall",
                "linode_instance.middle[0]",
            ),
            (
                "digitalocean",
                "digitalocean_firewall.firewall",
                "digitalocean_ssh_key.key[0]",
            ),
        )

        for provider, firewall_address, unsafe_address in cases:
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as temp_dir:
                workspace = Path(temp_dir)
                (workspace / "variables.tf").write_text(
                    'variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n',
                    encoding="utf-8",
                )
                (workspace / "firewall.tf").write_text("# old firewall\n", encoding="utf-8")
                plan_stdout = json.dumps(
                    {
                        "resource_changes": [
                            {
                                "address": firewall_address,
                                "change": {"actions": ["update"]},
                            },
                            {
                                "address": unsafe_address,
                                "change": {"actions": ["delete", "create"]},
                            },
                        ]
                    }
                )
                runner = FakeTerraformRunner(plan_stdout=plan_stdout)
                provider_alias = "linode-sketch-dev" if provider == "linode" else "do-sketch-dev"
                region = "us-sea" if provider == "linode" else "sfo3"
                size = "g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb"
                chain = _chain(
                    terraform_working_directory=str(workspace),
                    middle_provider=provider,
                    edge_provider=provider,
                    middle_region=region,
                    edge_region=region,
                    middle_size=size,
                    edge_size=size,
                )
                job = _job(
                    terraformWorkingDirectory=str(workspace),
                    middleCredentialAlias=provider_alias,
                    edgeCredentialAlias=provider_alias,
                )

                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01",
                    "ZY01",
                    "chain-1",
                    operation="apply",
                    channel=channel,
                    overview=_overview([channel]),
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(chain),
                    credential_resolver=lambda selected_provider, alias, repository: f"{selected_provider}-secret",
                    terraform_runner=runner,
                )

                self.assertFalse(result.ok)
                self.assertEqual([call["command"] for call in runner.calls], ["init", "plan", "show"])
                self.assertIn("rejected", result.events[-1].message)
                self.assertFalse(Path(runner.calls[1]["savedPlanPath"]).exists())

    def test_sync_materializes_scrubbed_key_paths_for_the_firewall_apply(self):
        runner = LiveKeyPathTerraformRunner()
        channel = _channel("edge-zy01-us-sea-01-8005-to-proxy01-18080", "8005")
        materialized = {}

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text(
                'variable "allowed_tcp_ports" {}\n'
                'variable "allowed_udp_ports" {}\n'
                'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
                'variable "sketch_transport_ssh_pub_key_path" {}\n',
                encoding="utf-8",
            )
            (workspace / "firewall.tf").write_text("# old firewall\n", encoding="utf-8")
            chain = _chain(terraform_working_directory=str(workspace))
            job = _job(
                terraformWorkingDirectory=str(workspace),
                materializeKeyFiles=True,
                sshPrivateKeyPath="",
                sshPublicKeyPath="",
                infrastructureAdminSshPrivateKeyPath="",
                infrastructureAdminSshPublicKeyPath="",
                sketchTransportSshPublicKeyPath="",
            )

            with patch(
                "app.services.sketch_provider_firewall.materialized_sketch_key_files",
                side_effect=lambda engagement_id: _materialized_keys_context(materialized),
            ):
                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01",
                    "ZY01",
                    "chain-1",
                    operation="apply",
                    channel=channel,
                    overview=_overview([channel]),
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(chain),
                    credential_resolver=lambda provider, alias, repository: "linode-secret",
                    terraform_runner=runner,
                )

        self.assertTrue(result.ok)
        keys = materialized["keys"]
        variables = runner.calls[1]["variables"]
        self.assertEqual(variables["infrastructure_admin_ssh_priv_key_path"], keys.administration_private_key_path)
        self.assertEqual(variables["infrastructure_admin_ssh_pub_key_path"], keys.administration_public_key_path)
        self.assertEqual(variables["sketch_transport_ssh_pub_key_path"], keys.transport_public_key_path)
        self.assertTrue(all(not path.exists() for path in materialized["paths"]))
        self.assertNotIn(str(materialized["root"]), str(result.events))

    def test_transport_sync_restores_upstream_firewall_without_inventing_a_listener(self):
        runner = FakeTerraformRunner()

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text(
                'variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n',
                encoding="utf-8",
            )
            (workspace / "firewall.tf").write_text("# stale Barragan firewall\n", encoding="utf-8")
            chain = _chain(terraform_working_directory=str(workspace))
            job = _job(terraformWorkingDirectory=str(workspace))

            result = sync_provider_ingress_for_transport(
                "eng-zy01",
                "ZY01",
                "chain-1",
                overview=_overview([]),
                job_repository=FakeJobRepository(job),
                chain_repository=FakeSketchChainRepository(chain),
                credential_resolver=lambda provider, alias, repository: "linode-secret",
                terraform_runner=runner,
            )
            refreshed_firewall = (workspace / "firewall.tf").read_text(encoding="utf-8")

        self.assertTrue(result.ok)
        self.assertEqual(result.plan.operation, "transport")
        self.assertEqual(result.plan.channel_id, "")
        self.assertEqual(result.plan.allowed_tcp_ports, (22, 80, 443, 2222))
        self.assertEqual(runner.calls[1]["targets"], ())
        self.assertEqual(runner.calls[3]["savedPlanPath"], runner.calls[1]["savedPlanPath"])
        self.assertNotIn("bootstrap_ssh_source_cidrs", runner.calls[1]["variables"])
        self.assertIn("for_each = var.allowed_tcp_ports", refreshed_firewall)

    def test_transport_sync_reconciles_both_provider_workspaces_for_a_mixed_chain(self):
        runner = FakeTerraformRunner()

        with tempfile.TemporaryDirectory() as temp_dir:
            middle_workspace = Path(temp_dir) / "middle"
            edge_workspace = Path(temp_dir) / "edge"
            for workspace in (middle_workspace, edge_workspace):
                workspace.mkdir()
                (workspace / "variables.tf").write_text(
                    'variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n',
                    encoding="utf-8",
                )
                (workspace / "firewall.tf").write_text("# stale firewall\n", encoding="utf-8")
            chain = _chain(
                terraform_working_directory="",
                middle_provider="linode",
                edge_provider="digitalocean",
                edge_region="sfo3",
                edge_size="s-1vcpu-1gb",
            )
            job = _job(
                childInputs={
                    "middle": {
                        "provider": "linode",
                        "middleCredentialAlias": "linode-sketch-dev",
                        "edgeCredentialAlias": "linode-sketch-dev",
                        "middleCount": 1,
                        "edgeCount": 0,
                        "terraformWorkingDirectory": str(middle_workspace),
                    },
                    "edges": {
                        "provider": "digitalocean",
                        "middleCredentialAlias": "do-sketch-dev",
                        "edgeCredentialAlias": "do-sketch-dev",
                        "middleCount": 0,
                        "edgeCount": 1,
                        "terraformWorkingDirectory": str(edge_workspace),
                        "edgeRegion": "sfo3",
                        "edgeRegions": ["sfo3"],
                        "edgeCountPerRegion": 1,
                        "edgeSize": "s-1vcpu-1gb",
                    },
                },
            )

            result = sync_provider_ingress_for_transport(
                "eng-zy01",
                "ZY01",
                "chain-1",
                overview=_overview([]),
                job_repository=FakeJobRepository(job),
                chain_repository=FakeSketchChainRepository(chain),
                credential_resolver=lambda provider, alias, repository: f"{provider}-secret",
                terraform_runner=runner,
            )

        self.assertTrue(result.ok)
        self.assertEqual(
            [call["command"] for call in runner.calls],
            ["init", "plan", "show", "init", "plan", "show", "apply", "apply"],
        )
        self.assertEqual(runner.calls[1]["workingDirectory"], str(edge_workspace))
        self.assertEqual(runner.calls[1]["targets"], ())
        self.assertEqual(runner.calls[4]["workingDirectory"], str(middle_workspace))
        self.assertEqual(runner.calls[4]["targets"], ())
        self.assertEqual(runner.calls[1]["variables"]["allowed_tcp_ports"], ["22", "80", "443", "2222"])
        self.assertEqual(runner.calls[4]["variables"]["allowed_tcp_ports"], ["22", "80", "443", "2222"])

    def test_mixed_transport_materializes_child_keys_for_the_complete_transaction(self):
        runner = LiveKeyPathTerraformRunner()
        materialized = {}

        with tempfile.TemporaryDirectory() as temp_dir:
            middle_workspace = Path(temp_dir) / "middle"
            edge_workspace = Path(temp_dir) / "edge"
            for workspace in (middle_workspace, edge_workspace):
                workspace.mkdir()
                (workspace / "variables.tf").write_text(
                    'variable "allowed_tcp_ports" {}\n'
                    'variable "allowed_udp_ports" {}\n'
                    'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                    'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
                    'variable "sketch_transport_ssh_pub_key_path" {}\n'
                    'variable "ssh_pub_key_path" {}\n'
                    'variable "ssh_priv_key_path" {}\n'
                )
                (workspace / "firewall.tf").write_text("# retained firewall\n")
            job = _job(childInputs={
                "middle": {
                    "provider": "linode", "middleCount": 1, "edgeCount": 0,
                    "middleCredentialAlias": "linode", "edgeCredentialAlias": "linode",
                    "terraformWorkingDirectory": str(middle_workspace),
                    "materializeKeyFiles": True,
                },
                "edges": {
                    "provider": "digitalocean", "middleCount": 0, "edgeCount": 1,
                    "middleCredentialAlias": "do", "edgeCredentialAlias": "do",
                    "terraformWorkingDirectory": str(edge_workspace), "edgeRegion": "sfo3",
                    "materializeKeyFiles": True,
                },
            })
            chain = _chain(
                terraform_working_directory="", middle_provider="linode",
                edge_provider="digitalocean", edge_region="sfo3", edge_size="s-1vcpu-1gb",
            )
            with patch(
                "app.services.sketch_provider_firewall.materialized_sketch_key_files",
                side_effect=lambda engagement_id: _materialized_keys_context(materialized),
            ) as key_materializer:
                result = sync_provider_ingress_for_transport(
                    "eng-zy01", "ZY01", "chain-1", overview=_overview([]),
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(chain),
                    credential_resolver=lambda *args: "secret", terraform_runner=runner,
                )

        self.assertTrue(result.ok)
        self.assertEqual(key_materializer.call_count, 1)
        self.assertEqual(
            [call["command"] for call in runner.calls],
            ["init", "plan", "show", "init", "plan", "show", "apply", "apply"],
        )
        staged = {str(path) for path in materialized["paths"]}
        for variables in runner.key_paths_by_workspace.values():
            self.assertEqual({str(path) for path in variables}, staged)
        self.assertTrue(all(not path.exists() for path in materialized["paths"]))
        self.assertNotIn(str(materialized["root"]), str(result.events))

    def test_legacy_marker_missing_continues_only_with_existing_declared_key_files(self):
        runner = LiveKeyPathTerraformRunner()
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            admin_private = workspace / "admin"
            admin_public = workspace / "admin.pub"
            transport_public = workspace / "transport.pub"
            for path in (admin_private, admin_public, transport_public):
                path.write_text("key\n")
            (workspace / "variables.tf").write_text(
                'variable "allowed_tcp_ports" {}\n'
                'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
                'variable "sketch_transport_ssh_pub_key_path" {}\n'
            )
            (workspace / "firewall.tf").write_text("# retained firewall\n")
            job = _job(
                terraformWorkingDirectory=str(workspace),
                infrastructureAdminSshPrivateKeyPath=str(admin_private),
                infrastructureAdminSshPublicKeyPath=str(admin_public),
                sketchTransportSshPublicKeyPath=str(transport_public),
            )
            with patch(
                "app.services.sketch_provider_firewall.materialized_sketch_key_files"
            ) as key_materializer:
                result = sync_provider_ingress_for_transport(
                    "eng-zy01", "ZY01", "chain-1", overview=_overview([]),
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(
                        _chain(terraform_working_directory=str(workspace))
                    ),
                    credential_resolver=lambda *args: "secret", terraform_runner=runner,
                )

        self.assertTrue(result.ok)
        key_materializer.assert_not_called()

    def test_legacy_missing_declared_key_fails_typed_before_credentials_or_terraform(self):
        runner = LiveKeyPathTerraformRunner()
        credential_calls = []
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text(
                'variable "allowed_tcp_ports" {}\nvariable "ssh_pub_key_path" {}\n'
            )
            (workspace / "firewall.tf").write_text("# retained firewall\n")
            result = sync_provider_ingress_for_transport(
                "eng-zy01", "ZY01", "chain-1", overview=_overview([]),
                job_repository=FakeJobRepository(_job(
                    terraformWorkingDirectory=str(workspace),
                    sshPublicKeyPath=str(workspace / "missing.pub"),
                )),
                chain_repository=FakeSketchChainRepository(
                    _chain(terraform_working_directory=str(workspace))
                ),
                credential_resolver=lambda *args: credential_calls.append(args) or "secret",
                terraform_runner=runner,
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.events[-1].data["errorType"], "DurableSketchKeyRecoveryError")
        self.assertEqual(credential_calls, [])
        self.assertEqual(runner.calls, [])

    def test_mixed_missing_second_component_key_resolves_no_provider_credentials(self):
        runner = LiveKeyPathTerraformRunner()
        credential_calls = []
        with tempfile.TemporaryDirectory() as temp_dir:
            edge_workspace = Path(temp_dir) / "edge"
            middle_workspace = Path(temp_dir) / "middle"
            for workspace in (edge_workspace, middle_workspace):
                workspace.mkdir()
                (workspace / "variables.tf").write_text(
                    'variable "allowed_tcp_ports" {}\nvariable "ssh_pub_key_path" {}\n'
                )
                (workspace / "firewall.tf").write_text("# retained firewall\n")
            edge_key = edge_workspace / "admin.pub"
            edge_key.write_text("key\n")
            job = _job(childInputs={
                "edge": {
                    "provider": "digitalocean", "middleCount": 0, "edgeCount": 1,
                    "middleCredentialAlias": "do", "edgeCredentialAlias": "do",
                    "terraformWorkingDirectory": str(edge_workspace),
                    "sshPublicKeyPath": str(edge_key),
                },
                "middle": {
                    "provider": "linode", "middleCount": 1, "edgeCount": 0,
                    "middleCredentialAlias": "linode", "edgeCredentialAlias": "linode",
                    "terraformWorkingDirectory": str(middle_workspace),
                    "sshPublicKeyPath": str(middle_workspace / "missing.pub"),
                },
            })
            result = sync_provider_ingress_for_transport(
                "eng-zy01", "ZY01", "chain-1", overview=_overview([]),
                job_repository=FakeJobRepository(job),
                chain_repository=FakeSketchChainRepository(_chain(
                    terraform_working_directory="", edge_provider="digitalocean",
                    middle_provider="linode", edge_region="sfo3", edge_size="s-1vcpu-1gb",
                )),
                credential_resolver=lambda *args: credential_calls.append(args) or "secret",
                terraform_runner=runner,
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.events[-1].data["errorType"], "DurableSketchKeyRecoveryError")
        self.assertEqual(credential_calls, [])
        self.assertEqual(runner.calls, [])

    def test_missing_durable_identity_fails_typed_before_credentials_or_terraform(self):
        runner = LiveKeyPathTerraformRunner()
        credential_calls = []
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text(
                'variable "allowed_tcp_ports" {}\n'
                'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
            )
            (workspace / "firewall.tf").write_text("# retained firewall\n")
            job = _job(terraformWorkingDirectory=str(workspace), materializeKeyFiles=True)
            with patch(
                "app.services.sketch_provider_firewall.materialized_sketch_key_files",
                side_effect=LookupError("durable identity missing"),
            ):
                result = sync_provider_ingress_for_transport(
                    "eng-zy01", "ZY01", "chain-1", overview=_overview([]),
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(
                        _chain(terraform_working_directory=str(workspace))
                    ),
                    credential_resolver=lambda *args: credential_calls.append(args) or "secret",
                    terraform_runner=runner,
                )

        self.assertFalse(result.ok)
        self.assertEqual(result.events[-1].data["errorType"], "DurableSketchKeyRecoveryError")
        self.assertEqual(result.events[-1].data["reason"], "provider_ingress_inputs_unavailable")
        self.assertNotIn("durable identity missing", str(result.events))
        self.assertEqual(credential_calls, [])
        self.assertEqual(runner.calls, [])

    def test_every_terraform_failure_phase_redacts_staged_paths_and_key_content(self):
        for phase in ("init", "plan", "show", "apply"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temp_dir:
                materialized = {}
                workspace = Path(temp_dir)
                (workspace / "variables.tf").write_text(
                    'variable "allowed_tcp_ports" {}\n'
                    'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                    'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
                    'variable "sketch_transport_ssh_pub_key_path" {}\n'
                )
                (workspace / "firewall.tf").write_text("# retained firewall\n")
                runner = LeakyPhaseTerraformRunner(phase, materialized)
                with patch(
                    "app.services.sketch_provider_firewall.materialized_sketch_key_files",
                    side_effect=lambda engagement_id: _materialized_keys_context(materialized),
                ):
                    result = sync_provider_ingress_for_transport(
                        "eng-zy01", "ZY01", "chain-1", overview=_overview([]),
                        job_repository=FakeJobRepository(_job(
                            terraformWorkingDirectory=str(workspace), materializeKeyFiles=True,
                        )),
                        chain_repository=FakeSketchChainRepository(
                            _chain(terraform_working_directory=str(workspace))
                        ),
                        credential_resolver=lambda *args: "secret", terraform_runner=runner,
                    )

                command_result = result.events[-1].data["commandResult"]
                emitted_output = command_result["stdout"] + "\n" + command_result["stderr"]
                self.assertFalse(result.ok)
                self.assertIn(f"useful {phase} diagnostic", emitted_output)
                self.assertIn("[REDACTED SKETCH KEY]", emitted_output)
                self.assertNotIn(str(materialized["root"]), emitted_output)
                for path, content in zip(materialized["paths"], materialized["contents"]):
                    self.assertNotIn(str(path), emitted_output)
                    self.assertNotIn(content, emitted_output)
                    self.assertNotIn(json.dumps(content)[1:-1], emitted_output)
                    self.assertFalse(path.exists())

    def test_digitalocean_template_uses_explicit_inbound_tcp_ports(self):
        firewall_tf = redteam_infra_path(
            "external", "sketch", "digitalocean", "firewall.tf"
        ).read_text(encoding="utf-8")
        variables_tf = redteam_infra_path(
            "external", "sketch", "digitalocean", "variables.tf"
        ).read_text(encoding="utf-8")

        self.assertIn("for_each = var.allowed_tcp_ports", firewall_tf)
        self.assertIn("for_each = var.allowed_udp_ports", firewall_tf)
        self.assertNotIn('protocol         = "tcp"\n    port_range       = "1-65535"\n    source_addresses = ["0.0.0.0/0"]', firewall_tf)
        self.assertIn('variable "allowed_udp_ports"', variables_tf)

    def test_digitalocean_ingress_sync_pins_retained_key_owner_before_apply(self):
        runner = FakeTerraformRunner()
        channel = _channel("edge-zy01-sfo3-01-80-to-proxy01-443", "80")

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text(
                'variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n',
                encoding="utf-8",
            )
            (workspace / "firewall.tf").write_text("# old firewall\n", encoding="utf-8")
            (workspace / "providers.tf").write_text(
                'data "digitalocean_ssh_keys" "matching_key" {\n  filter {\n    key = "public_key"\n    values = [chomp(file(local.ssh_pub_key_path))]\n  }\n}\n\n'
                'resource "digitalocean_ssh_key" "key" {\n  count = length(data.digitalocean_ssh_keys.matching_key.ssh_keys) == 0 ? 1 : 0\n  name = "do-key"\n  public_key = chomp(file(local.ssh_pub_key_path))\n}\n\n'
                'locals {\n  sketch_ssh_key_id = length(data.digitalocean_ssh_keys.matching_key.ssh_keys) > 0 ? data.digitalocean_ssh_keys.matching_key.ssh_keys[0].id : digitalocean_ssh_key.key[0].id\n}\n\n'
                'provider "local" {}\n',
                encoding="utf-8",
            )
            (workspace / "terraform.tfstate").write_text(
                json.dumps(
                    {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "digitalocean_ssh_key",
                                "name": "key",
                                "instances": [{"attributes": {"id": "123"}}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            chain = _chain(
                terraform_working_directory=str(workspace),
                middle_provider="digitalocean",
                edge_provider="digitalocean",
                middle_region="sfo3",
                edge_region="sfo3",
                middle_size="s-1vcpu-1gb",
                edge_size="s-1vcpu-1gb",
            )
            job = _job(
                terraformWorkingDirectory=str(workspace),
                middleCredentialAlias="do-sketch-dev",
                edgeCredentialAlias="do-sketch-dev",
            )

            result = sync_provider_ingress_for_inbound_channel(
                "eng-zy01",
                "ZY01",
                "chain-1",
                operation="apply",
                channel=channel,
                overview=_overview([channel]),
                job_repository=FakeJobRepository(job),
                chain_repository=FakeSketchChainRepository(chain),
                credential_resolver=lambda provider, alias, repository: "do-secret",
                terraform_runner=runner,
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.events[0].data["sshKeyOwnership"], "owner")
        providers = runner.workspace_snapshots[0]["providersTf"]
        self.assertIn("count      = 1", providers)
        self.assertNotIn('data "digitalocean_ssh_keys" "matching_key"', providers)

    def test_mixed_provider_sync_uses_retained_edge_child_workspace(self):
        runner = FakeTerraformRunner()
        channel = _channel(
            "edge-zy01-sfo3-01-53-to-homebase-53053",
            "53",
            protocol="UDP",
            mode="udp-forward",
        )
        channel["relayPort"] = "8000"

        with tempfile.TemporaryDirectory() as temp_dir:
            middle_workspace = Path(temp_dir) / "middle"
            edge_workspace = Path(temp_dir) / "edge"
            for workspace in (middle_workspace, edge_workspace):
                workspace.mkdir()
                (workspace / "variables.tf").write_text(
                    'variable "allowed_tcp_ports" {}\nvariable "allowed_udp_ports" {}\n',
                    encoding="utf-8",
                )
                (workspace / "firewall.tf").write_text("# old firewall\n", encoding="utf-8")
            chain = _chain(
                terraform_working_directory="",
                middle_provider="linode",
                edge_provider="digitalocean",
                edge_region="sfo3",
                edge_size="s-1vcpu-1gb",
            )
            job = _job(
                childInputs={
                    "middle": {
                        "provider": "linode",
                        "middleCredentialAlias": "linode-sketch-dev",
                        "edgeCredentialAlias": "linode-sketch-dev",
                        "middleCount": 1,
                        "edgeCount": 0,
                        "terraformWorkingDirectory": str(middle_workspace),
                    },
                    "edges": {
                        "provider": "digitalocean",
                        "middleCredentialAlias": "do-sketch-dev",
                        "edgeCredentialAlias": "do-sketch-dev",
                        "middleCount": 0,
                        "edgeCount": 1,
                        "terraformWorkingDirectory": str(edge_workspace),
                        "edgeRegion": "sfo3",
                        "edgeRegions": ["sfo3"],
                        "edgeCountPerRegion": 1,
                        "edgeSize": "s-1vcpu-1gb",
                    },
                },
            )

            result = sync_provider_ingress_for_inbound_channel(
                "eng-zy01",
                "ZY01",
                "chain-1",
                operation="apply",
                channel=channel,
                overview=_overview([channel]),
                job_repository=FakeJobRepository(job),
                chain_repository=FakeSketchChainRepository(chain),
                credential_resolver=lambda provider, alias, repository: "do-secret",
                terraform_runner=runner,
            )

        self.assertTrue(result.ok)
        self.assertEqual(
            [call["command"] for call in runner.calls],
            ["init", "plan", "show", "init", "plan", "show", "apply", "apply"],
        )
        self.assertEqual(runner.calls[1]["workingDirectory"], str(edge_workspace))
        self.assertEqual(runner.calls[1]["variables"]["middle_count"], 0)
        self.assertEqual(runner.calls[1]["variables"]["allowed_udp_ports"], ["53"])
        self.assertEqual(runner.calls[4]["workingDirectory"], str(middle_workspace))
        self.assertEqual(runner.calls[4]["variables"]["middle_count"], 1)
        self.assertEqual(runner.calls[4]["variables"]["edge_count_per_region"], 0)
        self.assertEqual(runner.calls[4]["variables"]["allowed_udp_ports"], ["8000"])

    def test_provider_sync_reapplies_workspace_compatibility_before_terraform_init(self):
        chain_id = "proxy02-sfo3-01"
        channel = {
            **_channel("edge-zy01-us-sea-01-8005-to-proxy01-18080", "8005"),
            "chainId": chain_id,
        }

        for provider, region, middle_size, edge_size, credential_alias in (
            ("linode", "us-sea", "g6-nanode-1", "g6-nanode-1", "linode-sketch-dev"),
            ("digitalocean", "sfo3", "s-1vcpu-1gb", "s-1vcpu-1gb", "do-sketch-dev"),
        ):
            source_variables = redteam_infra_path(
                "external", "sketch", provider, "variables.tf"
            )
            source_variables.write_text(
                source_variables.read_text(encoding="utf-8")
                + 'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                + 'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
                + 'variable "sketch_transport_ssh_pub_key_path" {}\n',
                encoding="utf-8",
            )
            for job_shape, identity_input, expected_identity in (
                (
                    "retained",
                    {},
                    {
                        "engagement_name": "zy01-campaign",
                        "resource_name_suffix": "",
                        "middle_ordinal": 1,
                        "edge_ordinal": 1,
                    },
                ),
                (
                    "new",
                    {
                        "terraformEngagementName": "pinned-provider-name",
                        "resourceNameSuffix": "-09",
                        "middleOrdinal": 4,
                        "edgeOrdinal": 7,
                        "infrastructureAdminSshPrivateKeyPath": "/keys/new-admin",
                        "infrastructureAdminSshPublicKeyPath": "/keys/new-admin.pub",
                    },
                    {
                        "engagement_name": "pinned-provider-name",
                        "resource_name_suffix": "-09",
                        "middle_ordinal": 4,
                        "edge_ordinal": 7,
                    },
                ),
            ):
                with (
                    self.subTest(provider=provider, job_shape=job_shape),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    workspace = Path(temp_dir)
                    (workspace / "variables.tf").write_text(
                        'variable "resource_name_suffix" {}\n'
                        'variable "middle_ordinal" {}\n'
                        'variable "edge_ordinal" {}\n'
                        'variable "allowed_tcp_ports" {}\n'
                        'variable "allowed_udp_ports" {}\n'
                        'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                        'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
                        'variable "sketch_transport_ssh_pub_key_path" {}\n',
                        encoding="utf-8",
                    )
                    if job_shape == "retained":
                        resource_type = "linode_firewall" if provider == "linode" else "digitalocean_firewall"
                        label_attribute = "label" if provider == "linode" else "name"
                        state = {
                            "resources": [
                                {
                                    "type": resource_type,
                                    "name": "firewall",
                                    "instances": [
                                        {
                                            "attributes": {
                                                label_attribute: "opaque-provider-name-firewall",
                                                "tags": ["barragan", "opaque-provider-name"],
                                            }
                                        }
                                    ],
                                },
                                {
                                    "type": "linode_instance" if provider == "linode" else "digitalocean_droplet",
                                    "name": "middle" if provider == "linode" else "edge",
                                    "instances": [{"attributes": {"image": "retained-image-identity"}}],
                                },
                            ]
                        }
                        (workspace / "variables.tf").write_text(
                            'variable "resource_name_suffix" {}\n'
                            'variable "middle_ordinal" {}\n'
                            'variable "edge_ordinal" {}\n'
                            'variable "allowed_tcp_ports" {}\n'
                            'variable "ssh_pub_key_path" {}\n'
                            'variable "ssh_priv_key_path" {}\n',
                            encoding="utf-8",
                        )
                        (workspace / "main.tf").write_text(
                            "locals { a = var.ssh_pub_key_path; b = var.ssh_priv_key_path }\n",
                            encoding="utf-8",
                        )
                        (workspace / "terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")
                        (workspace / "keys").mkdir()
                        (workspace / "keys" / "zy01-campaign-sketch.pub").write_text("public", encoding="utf-8")
                        (workspace / "keys" / "zy01-campaign-sketch").write_text("private", encoding="utf-8")
                    else:
                        identity_input = {
                            **identity_input,
                            "infrastructureAdminSshPrivateKeyPath": str(workspace / "new-admin"),
                            "infrastructureAdminSshPublicKeyPath": str(workspace / "new-admin.pub"),
                        }
                        for key_path in (
                            Path(identity_input["infrastructureAdminSshPrivateKeyPath"]),
                            Path(identity_input["infrastructureAdminSshPublicKeyPath"]),
                            workspace / "transport.pub",
                        ):
                            key_path.write_text("key\n")
                        (workspace / "main.tf").write_text(
                            "locals { a = var.infrastructure_admin_ssh_pub_key_path; b = var.infrastructure_admin_ssh_priv_key_path }\n",
                            encoding="utf-8",
                        )
                    (workspace / "middle.tf").write_text(
                        'name = "middle-${var.middle_ordinal}-${var.engagement_name}${var.resource_name_suffix}"\n',
                        encoding="utf-8",
                    )
                    (workspace / "edge.tf").write_text(
                        'name = "edge-${var.edge_ordinal}-${var.engagement_name}${var.resource_name_suffix}"\n',
                        encoding="utf-8",
                    )
                    (workspace / "firewall.tf").write_text("# deployed firewall\n", encoding="utf-8")
                    chain = _chain(
                        chain_id=chain_id,
                        terraform_working_directory=str(workspace),
                        middle_provider=provider,
                        edge_provider=provider,
                        middle_region=region,
                        edge_region=region,
                        middle_size=middle_size,
                        edge_size=edge_size,
                    )
                    job = _job(
                        engagementName="ZY01 Campaign",
                        chainId=chain_id,
                        middleCredentialAlias=credential_alias,
                        edgeCredentialAlias=credential_alias,
                        middleRegion=region,
                        edgeRegion=region,
                        edgeRegions=["region-a", "region-b"],
                        edgeCountPerRegion=3,
                        middleSize=middle_size,
                        edgeSize=edge_size,
                        terraformWorkingDirectory=str(workspace),
                        sshPrivateKeyPath="/keys/retained-admin",
                        sshPublicKeyPath="/keys/retained-admin.pub",
                        sketchTransportSshPublicKeyPath=(
                            str(workspace / "transport.pub") if job_shape == "new" else "/keys/transport.pub"
                        ),
                        **identity_input,
                    )
                    runner = FakeTerraformRunner()

                    result = sync_provider_ingress_for_inbound_channel(
                        "eng-zy01",
                        "ZY01 Campaign",
                        chain_id,
                        operation="apply",
                        channel=channel,
                        overview=_overview([channel]),
                        job_repository=FakeJobRepository(job),
                        chain_repository=FakeSketchChainRepository(chain),
                        credential_resolver=lambda selected_provider, alias, repository: f"{selected_provider}-secret",
                        terraform_runner=runner,
                    )

                    self.assertTrue(result.ok)
                    self.assertEqual(runner.workspace_snapshots[0]["command"], "init")
                    variables_text = runner.workspace_snapshots[0]["variablesTf"]
                    self.assertIn('variable "resource_name_suffix"', variables_text)
                    self.assertIn('variable "middle_ordinal"', variables_text)
                    self.assertIn('variable "edge_ordinal"', variables_text)
                    self.assertRegex(
                        variables_text,
                        r'variable "allowed_tcp_ports" \{\n  type = list\(string\)',
                    )
                    self.assertRegex(
                        variables_text,
                        r'variable "allowed_udp_ports" \{\n  type = list\(string\)',
                    )
                    self.assertIn("var.middle_ordinal", runner.workspace_snapshots[0]["middleTf"])
                    self.assertIn("var.edge_ordinal", runner.workspace_snapshots[0]["edgeTf"])
                    plan_variables = runner.calls[1]["variables"]
                    for key, expected in expected_identity.items():
                        self.assertEqual(
                            plan_variables[key],
                            "opaque-provider-name" if job_shape == "retained" and key == "engagement_name" else expected,
                        )
                    if job_shape == "retained":
                        image_variable = "linode_image" if provider == "linode" else "docean_image"
                        self.assertEqual(plan_variables[image_variable], "retained-image-identity")
                    self.assertEqual(runner.calls[1]["targets"], ())
                    self.assertTrue(runner.calls[1]["refresh"])
                    self.assertEqual(plan_variables["edge_regions"], ["region-a", "region-b"])
                    self.assertEqual(plan_variables["edge_count_per_region"], 3)
                    self.assertEqual(runner.calls[3]["variables"], {})
                    self.assertEqual(runner.calls[3]["targets"], ())
                    self.assertEqual(runner.calls[3]["savedPlanPath"], runner.calls[1]["savedPlanPath"])
                    if job_shape == "retained":
                        self.assertIn('variable "ssh_pub_key_path"', variables_text)
                        self.assertNotIn('variable "infrastructure_admin_ssh_pub_key_path"', variables_text)
                        self.assertEqual(plan_variables["ssh_pub_key_path"], str(workspace / "keys" / "zy01-campaign-sketch.pub"))
                        self.assertEqual(plan_variables["ssh_priv_key_path"], str(workspace / "keys" / "zy01-campaign-sketch"))
                        self.assertEqual(
                            plan_variables["provider_ownership_tags"],
                            ["barragan", "opaque-provider-name"],
                        )
                    else:
                        self.assertEqual(plan_variables["infrastructure_admin_ssh_pub_key_path"], str(workspace / "new-admin.pub"))
                        self.assertEqual(plan_variables["infrastructure_admin_ssh_priv_key_path"], str(workspace / "new-admin"))
                        self.assertEqual(plan_variables["sketch_transport_ssh_pub_key_path"], str(workspace / "transport.pub"))

    def test_unowned_workspace_is_rejected_before_credentials_or_terraform(self):
        runner = FakeTerraformRunner()
        credential_calls = []
        self._workspace_validation.stop()
        try:
            with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
                "os.environ", {"BARRAGAN_SKETCH_STATE_ROOT": temp_dir}
            ):
                root = Path(temp_dir)
                workspace = root / "unowned"
                workspace.mkdir()
                (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n')
                original = (workspace / "variables.tf").read_bytes()
                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01", "ZY01", "chain-1", operation="apply",
                    channel=_channel("channel-1", "8005"), overview=_overview([]),
                    job_repository=FakeJobRepository(_job(terraformWorkingDirectory=str(workspace))),
                    chain_repository=FakeSketchChainRepository(
                        _chain(terraform_working_directory=str(workspace))
                    ),
                    credential_resolver=lambda *args: credential_calls.append(args) or "secret",
                    terraform_runner=runner,
                )
                self.assertFalse(result.ok)
                self.assertEqual(credential_calls, [])
                self.assertEqual(runner.calls, [])
                self.assertEqual((workspace / "variables.tf").read_bytes(), original)
        finally:
            self._workspace_validation.start()

    def test_canonical_workspace_with_symlinked_source_is_rejected_before_side_effects(self):
        runner = FakeTerraformRunner()
        credential_calls = []
        self._workspace_validation.stop()
        try:
            with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
                "os.environ", {"BARRAGAN_SKETCH_STATE_ROOT": str(Path(temp_dir) / "state")}
            ):
                prepared = prepare_sketch_state_workspace(
                    "eng-zy01", "chain-1", "linode",
                    template_directory=redteam_infra_path("external", "sketch", "linode"),
                    root=Path(temp_dir) / "state",
                )
                prepared.state_path.write_text(json.dumps({
                    "resources": [{
                        "mode": "managed", "type": "linode_instance", "name": "edge",
                        "instances": [{"attributes": {"image": "linode/ubuntu20.04"}}],
                    }]
                }))
                prepared.state_path.chmod(0o600)
                outside = Path(temp_dir) / "outside.tf"
                outside.write_text("# outside\n")
                (prepared.path / "linked.tf").symlink_to(outside)
                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01", "ZY01", "chain-1", operation="apply",
                    channel=_channel("channel-1", "8005"), overview=_overview([]),
                    job_repository=FakeJobRepository(_job(terraformWorkingDirectory=str(prepared.path))),
                    chain_repository=FakeSketchChainRepository(
                        _chain(terraform_working_directory=str(prepared.path))
                    ),
                    credential_resolver=lambda *args: credential_calls.append(args) or "secret",
                    terraform_runner=runner,
                )
                self.assertFalse(result.ok)
                self.assertEqual(credential_calls, [])
                self.assertEqual(runner.calls, [])
                self.assertEqual(outside.read_text(), "# outside\n")
        finally:
            self._workspace_validation.start()

    def test_requested_port_with_unproven_empty_plan_is_rejected_without_apply(self):
        runner = FakeTerraformRunner(plan_stdout='{"resource_changes": []}')
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n')
            (workspace / "firewall.tf").write_text("# original firewall\n")
            original = {path.name: path.read_bytes() for path in workspace.glob("*.tf")}
            result = sync_provider_ingress_for_inbound_channel(
                "eng-zy01", "ZY01", "chain-1", operation="apply",
                channel=_channel("channel-1", "8005"), overview=_overview([]),
                job_repository=FakeJobRepository(_job(terraformWorkingDirectory=str(workspace))),
                chain_repository=FakeSketchChainRepository(
                    _chain(terraform_working_directory=str(workspace))
                ),
                credential_resolver=lambda *args: "secret", terraform_runner=runner,
            )
            self.assertFalse(result.ok)
            self.assertEqual([call["command"] for call in runner.calls], ["init", "plan", "show"])
            self.assertIn("omitted the planned provider firewall projection", result.events[-1].data["reason"])
            self.assertEqual(
                {path.name: path.read_bytes() for path in workspace.glob("*.tf")}, original
            )

    def test_proven_exact_noop_reapply_is_accepted(self):
        runner = FakeTerraformRunner()
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n')
            (workspace / "firewall.tf").write_text("# original firewall\n")
            result = sync_provider_ingress_for_inbound_channel(
                "eng-zy01", "ZY01", "chain-1", operation="apply",
                channel=_channel("channel-1", "8005"), overview=_overview([]),
                job_repository=FakeJobRepository(_job(terraformWorkingDirectory=str(workspace))),
                chain_repository=FakeSketchChainRepository(
                    _chain(terraform_working_directory=str(workspace))
                ),
                credential_resolver=lambda *args: "secret", terraform_runner=runner,
            )
            self.assertTrue(result.ok)
            self.assertEqual([call["command"] for call in runner.calls], ["init", "plan", "show", "apply"])
            self.assertEqual(result.events[-1].data["approvedChanges"], [])

    def test_noop_firewall_with_unmanaged_public_sibling_is_not_exact(self):
        proven = json.loads(_proven_noop_plan("linode", ["22", "80", "443", "2222", "8005"], []))
        values = proven["planned_values"]["root_module"]["resources"][0]["values"]
        values["inbound"].append({
            "action": "ACCEPT", "ipv4": ["0.0.0.0/0"], "ipv6": [],
            "label": "sibling", "ports": "9999", "protocol": "TCP",
        })
        plan_stdout = json.dumps({
            "resource_changes": [{
                "address": "linode_firewall.firewall",
                "change": {"actions": ["no-op"], "before": values, "after": values},
            }]
        })
        runner = FakeTerraformRunner(plan_stdout=plan_stdout)
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n')
            (workspace / "firewall.tf").write_text("# original firewall\n")
            result = sync_provider_ingress_for_inbound_channel(
                "eng-zy01", "ZY01", "chain-1", operation="apply",
                channel=_channel("channel-1", "8005"), overview=_overview([]),
                job_repository=FakeJobRepository(_job(terraformWorkingDirectory=str(workspace))),
                chain_repository=FakeSketchChainRepository(
                    _chain(terraform_working_directory=str(workspace))
                ),
                credential_resolver=lambda *args: "secret", terraform_runner=runner,
            )
            self.assertFalse(result.ok)
            self.assertNotIn("apply", [call["command"] for call in runner.calls])
            self.assertIn("does not prove the exact desired", result.events[-1].data["reason"])

    def test_missing_retained_image_is_rejected_before_source_or_credentials(self):
        runner = FakeTerraformRunner()
        credential_calls = []
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n')
            (workspace / "firewall.tf").write_text("# original\n")
            original = {path.name: path.read_bytes() for path in workspace.glob("*.tf")}
            with patch(
                "app.services.sketch_provider_firewall.retained_compute_image_for_workspace",
                side_effect=ValueError("missing retained image"),
            ):
                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01", "ZY01", "chain-1", operation="apply",
                    channel=_channel("channel-1", "8005"), overview=_overview([]),
                    job_repository=FakeJobRepository(_job(terraformWorkingDirectory=str(workspace))),
                    chain_repository=FakeSketchChainRepository(
                        _chain(terraform_working_directory=str(workspace))
                    ),
                    credential_resolver=lambda *args: credential_calls.append(args) or "secret",
                    terraform_runner=runner,
                )
            self.assertFalse(result.ok)
            self.assertEqual(credential_calls, [])
            self.assertEqual(runner.calls, [])
            self.assertEqual({path.name: path.read_bytes() for path in workspace.glob("*.tf")}, original)

    def test_mixed_second_plan_rejection_applies_neither_and_restores_both_sources(self):
        unsafe_middle = json.dumps({
            "resource_changes": [{
                "address": "linode_firewall.firewall",
                "change": {"actions": ["update"]},
            }]
        })
        runner = LiveKeyPathTerraformRunner(plan_stdout=["", unsafe_middle])
        materialized = {}
        with tempfile.TemporaryDirectory() as temp_dir:
            edge_workspace = Path(temp_dir) / "edge"
            middle_workspace = Path(temp_dir) / "middle"
            originals = {}
            for workspace in (edge_workspace, middle_workspace):
                workspace.mkdir()
                (workspace / "variables.tf").write_text(
                    'variable "allowed_tcp_ports" {}\n'
                    'variable "infrastructure_admin_ssh_pub_key_path" {}\n'
                    'variable "infrastructure_admin_ssh_priv_key_path" {}\n'
                    'variable "sketch_transport_ssh_pub_key_path" {}\n'
                )
                (workspace / "firewall.tf").write_text("# original firewall\n")
                originals[workspace] = {
                    path.relative_to(workspace): path.read_bytes() for path in workspace.glob("*.tf")
                }
            job = _job(childInputs={
                "edge": {
                    "provider": "digitalocean", "middleCount": 0, "edgeCount": 1,
                    "middleCredentialAlias": "do", "edgeCredentialAlias": "do",
                    "terraformWorkingDirectory": str(edge_workspace),
                    "materializeKeyFiles": True,
                },
                "middle": {
                    "provider": "linode", "middleCount": 1, "edgeCount": 0,
                    "middleCredentialAlias": "linode", "edgeCredentialAlias": "linode",
                    "terraformWorkingDirectory": str(middle_workspace),
                    "materializeKeyFiles": True,
                },
            })
            chain = _chain(
                terraform_working_directory="", edge_provider="digitalocean",
                middle_provider="linode", edge_region="sfo3", edge_size="s-1vcpu-1gb",
            )
            with patch(
                "app.services.sketch_provider_firewall.materialized_sketch_key_files",
                side_effect=lambda engagement_id: _materialized_keys_context(materialized),
            ):
                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01", "ZY01", "chain-1", operation="apply",
                    channel=_channel("channel-1", "8005"), overview=_overview([]),
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(chain),
                    credential_resolver=lambda *args: "secret", terraform_runner=runner,
                )
            self.assertFalse(result.ok)
            self.assertNotIn("apply", [call["command"] for call in runner.calls])
            self.assertTrue(all(not path.exists() for path in materialized["paths"]))
            self.assertNotIn(str(materialized["root"]), str(result.events))
            for workspace in (edge_workspace, middle_workspace):
                self.assertEqual(
                    {path.relative_to(workspace): path.read_bytes() for path in workspace.glob("*.tf")},
                    originals[workspace],
                )
            for call in runner.calls:
                if call["savedPlanPath"]:
                    self.assertFalse(Path(call["savedPlanPath"]).exists())

    def test_invalid_mixed_middle_is_rejected_before_edge_has_any_side_effect(self):
        runner = FakeTerraformRunner()
        credential_calls = []

        def reject_middle(engagement_id, chain_id, provider, workspace, **kwargs):
            if provider == "linode":
                raise ValueError("middle workspace is not Barragan-owned")
            workspace = Path(workspace)
            return SimpleNamespace(path=workspace, state_path=workspace / "terraform.tfstate")

        self._workspace_validation.stop()
        try:
            with tempfile.TemporaryDirectory() as temp_dir, patch(
                "app.services.sketch_provider_firewall.validate_existing_sketch_state_workspace",
                side_effect=reject_middle,
            ):
                edge_workspace = Path(temp_dir) / "edge"
                middle_workspace = Path(temp_dir) / "middle"
                originals = {}
                for workspace in (edge_workspace, middle_workspace):
                    workspace.mkdir()
                    (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n')
                    (workspace / "firewall.tf").write_text("# original firewall\n")
                    originals[workspace] = {
                        path.name: path.read_bytes() for path in workspace.glob("*.tf")
                    }
                job = _job(childInputs={
                    "edge": {
                        "provider": "digitalocean", "middleCount": 0, "edgeCount": 1,
                        "middleCredentialAlias": "do", "edgeCredentialAlias": "do",
                        "terraformWorkingDirectory": str(edge_workspace),
                    },
                    "middle": {
                        "provider": "linode", "middleCount": 1, "edgeCount": 0,
                        "middleCredentialAlias": "linode", "edgeCredentialAlias": "linode",
                        "terraformWorkingDirectory": str(middle_workspace),
                    },
                })
                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01", "ZY01", "chain-1", operation="apply",
                    channel=_channel("channel-1", "8005"), overview=_overview([]),
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(_chain(
                        terraform_working_directory="", edge_provider="digitalocean",
                        middle_provider="linode", edge_region="sfo3", edge_size="s-1vcpu-1gb",
                    )),
                    credential_resolver=lambda *args: credential_calls.append(args) or "secret",
                    terraform_runner=runner,
                )
                self.assertFalse(result.ok)
                self.assertEqual(credential_calls, [])
                self.assertEqual(runner.calls, [])
                for workspace in (edge_workspace, middle_workspace):
                    self.assertEqual(
                        {path.name: path.read_bytes() for path in workspace.glob("*.tf")},
                        originals[workspace],
                    )
        finally:
            self._workspace_validation.start()

    def test_saved_plan_mutation_before_apply_produces_zero_apply_and_restores_source(self):
        runner = FakeTerraformRunner()
        validation_calls = 0

        def validate_and_mutate(engagement_id, chain_id, provider, workspace, **kwargs):
            nonlocal validation_calls
            validation_calls += 1
            workspace = Path(workspace)
            # The fifth validation occurs after show/approval and before the
            # immediate apply-identity check.
            if validation_calls == 5:
                plan_paths = list(workspace.glob(".barragan-provider-firewall-*.tfplan"))
                self.assertEqual(len(plan_paths), 1)
                plan_paths[0].write_bytes(b"substituted-plan")
            return SimpleNamespace(path=workspace, state_path=workspace / "terraform.tfstate")

        self._workspace_validation.stop()
        try:
            with tempfile.TemporaryDirectory() as temp_dir, patch(
                "app.services.sketch_provider_firewall.validate_existing_sketch_state_workspace",
                side_effect=validate_and_mutate,
            ):
                workspace = Path(temp_dir)
                (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n')
                (workspace / "firewall.tf").write_text("# original firewall\n")
                original = {path.name: path.read_bytes() for path in workspace.glob("*.tf")}
                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01", "ZY01", "chain-1", operation="apply",
                    channel=_channel("channel-1", "8005"), overview=_overview([]),
                    job_repository=FakeJobRepository(_job(terraformWorkingDirectory=str(workspace))),
                    chain_repository=FakeSketchChainRepository(
                        _chain(terraform_working_directory=str(workspace))
                    ),
                    credential_resolver=lambda *args: "secret", terraform_runner=runner,
                )
                self.assertFalse(result.ok)
                self.assertNotIn("apply", [call["command"] for call in runner.calls])
                self.assertIn("saved plan changed", result.events[-1].data["reason"])
                self.assertEqual(
                    {path.name: path.read_bytes() for path in workspace.glob("*.tf")}, original
                )
                self.assertFalse(list(workspace.glob("*.tfplan")))
        finally:
            self._workspace_validation.start()

    def test_partial_apply_preserves_applied_source_and_restores_unstarted_source(self):
        runner = FakeTerraformRunner(plan_stdout=["", ""])
        validation_calls = 0

        def mutate_middle_plan_before_apply(engagement_id, chain_id, provider, workspace, **kwargs):
            nonlocal validation_calls
            validation_calls += 1
            workspace = Path(workspace)
            # Two providers each validate four times through inspection, then
            # twice globally and once immediately per apply. The middle's
            # immediate check is the twelfth call, after edge apply succeeded.
            if validation_calls == 12:
                plan_paths = list(workspace.glob(".barragan-provider-firewall-*.tfplan"))
                self.assertEqual(len(plan_paths), 1)
                plan_paths[0].write_bytes(b"substituted-middle-plan")
            return SimpleNamespace(path=workspace, state_path=workspace / "terraform.tfstate")

        self._workspace_validation.stop()
        try:
            with tempfile.TemporaryDirectory() as temp_dir, patch(
                "app.services.sketch_provider_firewall.validate_existing_sketch_state_workspace",
                side_effect=mutate_middle_plan_before_apply,
            ):
                edge_workspace = Path(temp_dir) / "edge"
                middle_workspace = Path(temp_dir) / "middle"
                originals = {}
                for workspace in (edge_workspace, middle_workspace):
                    workspace.mkdir()
                    (workspace / "variables.tf").write_text('variable "allowed_tcp_ports" {}\n')
                    (workspace / "firewall.tf").write_text("# original firewall\n")
                    originals[workspace] = {
                        path.name: path.read_bytes() for path in workspace.glob("*.tf")
                    }
                job = _job(childInputs={
                    "edge": {
                        "provider": "digitalocean", "middleCount": 0, "edgeCount": 1,
                        "middleCredentialAlias": "do", "edgeCredentialAlias": "do",
                        "terraformWorkingDirectory": str(edge_workspace),
                    },
                    "middle": {
                        "provider": "linode", "middleCount": 1, "edgeCount": 0,
                        "middleCredentialAlias": "linode", "edgeCredentialAlias": "linode",
                        "terraformWorkingDirectory": str(middle_workspace),
                    },
                })
                result = sync_provider_ingress_for_inbound_channel(
                    "eng-zy01", "ZY01", "chain-1", operation="apply",
                    channel=_channel("channel-1", "8005"), overview=_overview([]),
                    job_repository=FakeJobRepository(job),
                    chain_repository=FakeSketchChainRepository(_chain(
                        terraform_working_directory="", edge_provider="digitalocean",
                        middle_provider="linode", edge_region="sfo3", edge_size="s-1vcpu-1gb",
                    )),
                    credential_resolver=lambda *args: "secret", terraform_runner=runner,
                )
                self.assertFalse(result.ok)
                self.assertEqual([call["command"] for call in runner.calls].count("apply"), 1)
                self.assertNotEqual(
                    {path.name: path.read_bytes() for path in edge_workspace.glob("*.tf")},
                    originals[edge_workspace],
                )
                self.assertEqual(
                    {path.name: path.read_bytes() for path in middle_workspace.glob("*.tf")},
                    originals[middle_workspace],
                )
                self.assertFalse(list(edge_workspace.glob("*.tfplan")))
                self.assertFalse(list(middle_workspace.glob("*.tfplan")))
        finally:
            self._workspace_validation.start()


def _overview(channels):
    return {
        "sketchInfrastructure": [
            {
                "chainId": "chain-1",
                "hostname": "edge-zy01-us-sea-01",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            }
        ],
        "inboundChannels": channels,
    }


@contextmanager
def _materialized_keys_context(record):
    with tempfile.TemporaryDirectory(prefix="barragan-sketch-keys-") as temp_dir:
        root = Path(temp_dir)
        paths = (root / "admin", root / "admin.pub", root / "transport.pub")
        contents = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nwi0395-private-secret-material\n-----END OPENSSH PRIVATE KEY-----",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIwi0395AdminPublicMaterial",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIwi0395TransportPublicMaterial",
        )
        for path, content in zip(paths, contents):
            path.write_text(content + "\n")
        keys = SimpleNamespace(
            administration_private_key_path=str(paths[0]),
            administration_public_key_path=str(paths[1]),
            transport_public_key_path=str(paths[2]),
        )
        record.update(root=root, paths=paths, contents=contents, keys=keys)
        yield keys


def _proven_noop_plan(provider, tcp_ports, udp_ports):
    if provider == "linode":
        address = "linode_firewall.firewall"
        values = {
            "inbound": [
                {
                    "action": "ACCEPT",
                    "ipv4": ["0.0.0.0/0"],
                    "ipv6": [],
                    "label": f"allow-{protocol}-{port}",
                    "ports": str(port),
                    "protocol": protocol.upper(),
                }
                for protocol, ports in (("tcp", tcp_ports), ("udp", udp_ports))
                for port in ports
            ]
        }
    else:
        address = "digitalocean_firewall.firewall"
        values = {
            "inbound_rule": [
                {
                    "port_range": str(port),
                    "protocol": protocol,
                    "source_addresses": ["0.0.0.0/0"],
                    "source_droplet_ids": [],
                    "source_kubernetes_ids": [],
                    "source_load_balancer_uids": [],
                    "source_tags": [],
                }
                for protocol, ports in (("tcp", tcp_ports), ("udp", udp_ports))
                for port in ports
            ]
        }
    return json.dumps({
        "resource_changes": [],
        "planned_values": {"root_module": {"resources": [{
            "address": address,
            "values": values,
        }]}},
    })


def _channel(channel_id, external_port, *, protocol="TCP", mode="tcp-forward", status="Validated"):
    return {
        "channelId": channel_id,
        "domain": "example.invalid",
        "protocol": protocol,
        "mode": mode,
        "externalPort": external_port,
        "edge": "edge-zy01-us-sea-01",
        "middle": "middle-zy01-chain-1",
        "proxy": "proxy01-zy01",
        "terminatesOn": "proxy01-zy01",
        "service": "Static Web",
        "internalPort": "18080",
        "purpose": "test",
        "status": status,
    }


def _chain(**overrides):
    values = {
        "chain_id": "chain-1",
        "engagement_id": "eng-zy01",
        "assigned_proxy": "proxy01",
        "middle_provider": "linode",
        "middle_region": "us-sea",
        "middle_size": "g6-nanode-1",
        "edge_provider": "linode",
        "edge_region": "us-sea",
        "edge_size": "g6-nanode-1",
        "status": "deployed",
        "burned": False,
        "burned_note": "",
        "deploy_job_id": "job-linode",
        "teardown_job_id": "",
        "terraform_working_directory": "",
        "nodes": [{"role": "middle", "hostname": "middle-zy01", "publicIp": "203.0.113.20"}],
        "created_at": "2026-06-10T00:00:00+00:00",
        "updated_at": "2026-06-10T00:00:00+00:00",
    }
    values.update(overrides)
    return StoredSketchChain(**values)


def _job(**overrides):
    input_data = {
        "engagementId": "eng-zy01",
        "engagementName": "ZY01",
        "chainId": "chain-1",
        "assignedProxy": "proxy01",
        "middleCredentialAlias": "linode-sketch-dev",
        "edgeCredentialAlias": "linode-sketch-dev",
        "middleRegion": "us-sea",
        "edgeRegion": "us-sea",
        "middleSize": "g6-nanode-1",
        "edgeSize": "g6-nanode-1",
        "terraformWorkingDirectory": "",
        "sshPrivateKeyPath": "/tmp/zy01-sketch",
        "sshPublicKeyPath": "/tmp/zy01-sketch.pub",
    }
    input_data.update(overrides)
    return StoredJobRun(
        id="job-linode",
        action="linode_sketch_deploy",
        status="succeeded",
        target="engagement:eng-zy01",
        target_type="engagement",
        target_id="eng-zy01",
        requested_by="operator",
        input=input_data,
        artifact_refs=[],
        created_at="2026-06-10T00:00:00+00:00",
        started_at="2026-06-10T00:00:00+00:00",
        finished_at="2026-06-10T00:00:00+00:00",
        events=[JobEvent(1, "info", "ok", {})],
    )


if __name__ == "__main__":
    unittest.main()
