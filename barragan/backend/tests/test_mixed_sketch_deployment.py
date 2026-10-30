# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import os
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest

from app import create_app
from app.core.config import TestConfig
from app.domain import JobEvent
from app.integrations.terraform_runner import TerraformCommandResult
from app.services.credentials import test_master_key as credential_test_master_key
from app.services.mixed_sketch_deployment import (
    MIXED_SKETCH_CONFIRMATION,
    MixedSketchGuardrailError,
    _component_resource_name_suffix,
    _cleaned_teardown_component_ids,
    _teardown,
    _validate_retained_children,
    _verified_deploy_cleanup_component_ids,
    resume_guarded_mixed_sketch_teardown,
    start_guarded_mixed_sketch_run,
    start_guarded_mixed_sketch_teardown,
)
from app.storage.job_repository import SqliteJobRepository, StoredJobRun

TestConfig.ENGAGEMENT_REPOS_ROOT = Path(tempfile.gettempdir()) / "barragan-mixed-sketch-test-engagements"


def _mixed_teardown_job(*, events: list[JobEvent], components: list[dict[str, str]] | None = None) -> StoredJobRun:
    child_inputs = {
        "middle": {
            "provider": "linode",
            "middleCount": 1,
            "edgeCount": 0,
            "edgeCountPerRegion": 0,
            "componentId": "middle",
            "terraformWorkingDirectory": "/state/eng-1/chain-1/components/middle/linode",
        },
        "edges": {
            "provider": "digitalocean",
            "middleCount": 0,
            "edgeCount": 1,
            "edgeCountPerRegion": 1,
            "componentId": "edges",
            "terraformWorkingDirectory": "/state/eng-1/chain-1/components/edges/digitalocean",
        },
    }
    input_data = {
        "engagementId": "eng-1",
        "engagementName": "example",
        "chainId": "chain-1",
        "assignedProxy": "proxy01",
        "middleProvider": "linode",
        "edgeProvider": "digitalocean",
        "middleCredentialAlias": "linode-default",
        "edgeCredentialAlias": "do-default",
        "middleRegion": "us-sea",
        "edgeRegion": "sfo3",
        "middleSize": "g6-nanode-1",
        "edgeSize": "s-1vcpu-1gb",
        "edgeCount": 1,
        "edges": [{"id": "edges", "provider": "digitalocean", "region": "sfo3", "size": "s-1vcpu-1gb"}],
        "managedHostImageProfile": "ubuntu-22.04",
        "childInputs": child_inputs,
    }
    if components is not None:
        input_data["components"] = components
    return StoredJobRun(
        id="job-mixed-teardown",
        action="mixed_provider_sketch_teardown",
        status="failed",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input=input_data,
        artifact_refs=[],
        created_at="2026-09-11T00:00:00+00:00",
        started_at="2026-09-11T00:00:00+00:00",
        finished_at="2026-09-11T00:01:00+00:00",
        events=events,
    )


def _cleanup_event(data: dict[str, object]) -> JobEvent:
    return JobEvent(
        1,
        "info",
        "terraform cleanup verified",
        {"phase": "cleanup", "cleanupVerified": True, "sketchInfrastructure": [], **data},
    )


def _automatically_cleaned_failed_deploy_job() -> StoredJobRun:
    components = [
        {"componentId": "middle", "role": "middle", "provider": "digitalocean"},
        {"componentId": "edges", "role": "edge", "provider": "linode"},
    ]
    job = _mixed_teardown_job(events=[], components=components)
    job.input["middleProvider"] = "digitalocean"
    job.input["edgeProvider"] = "linode"
    job.input["childInputs"]["middle"]["provider"] = "digitalocean"
    job.input["childInputs"]["edges"]["provider"] = "linode"
    events = [
        JobEvent(
            1,
            "info",
            "middle middle provider deploy started",
            {"componentId": "middle", "role": "middle", "provider": "digitalocean"},
        ),
        JobEvent(
            2,
            "error",
            "terraform apply failed",
            {"componentRole": "middle", "componentProvider": "digitalocean", "phase": "apply"},
        ),
        JobEvent(
            3,
            "info",
            "terraform destroy completed",
            {"componentRole": "middle", "componentProvider": "digitalocean", "phase": "destroy"},
        ),
        JobEvent(
            4,
            "info",
            "terraform cleanup verified",
            {
                "componentRole": "middle",
                "componentProvider": "digitalocean",
                "phase": "cleanup",
                "cleanupVerified": True,
                "remainingOutputs": [],
            },
        ),
        JobEvent(
            5,
            "error",
            "middle middle provider deploy failed",
            {"componentId": "middle", "role": "middle", "provider": "digitalocean"},
        ),
    ]
    return replace(job, action="mixed_provider_sketch_deploy", events=events)


def test_verified_automatic_cleanup_starts_audited_teardown_without_workspace_or_terraform(tmp_path: Path):
    failed_deploy = _automatically_cleaned_failed_deploy_job()
    repository = SqliteJobRepository(tmp_path / "jobs.sqlite3")
    repository.save(failed_deploy)
    tasks = []

    with patch(
        "app.services.mixed_sketch_deployment._validate_retained_children",
        side_effect=AssertionError("verified retirement must not inspect workspaces"),
    ):
        teardown = start_guarded_mixed_sketch_teardown(
            failed_deploy.id,
            repository=repository,
            runner=object(),
            background_runner=tasks.append,
        )
        assert teardown is not None
        assert teardown.action == "mixed_provider_sketch_teardown"
        assert len(tasks) == 1
        tasks[0]()

    completed = repository.get(teardown.id)
    assert completed is not None
    assert completed.status == "succeeded"
    already_verified = [event for event in completed.events if "cleanup already verified" in event.message]
    assert {event.data["componentId"] for event in already_verified} == {"middle", "edges"}
    assert all(event.data["cleanupVerified"] is True for event in already_verified)
    cleanup_basis = {event.data["componentId"]: event.data["cleanupBasis"] for event in already_verified}
    assert cleanup_basis == {"middle": "automatic_cleanup_verified", "edges": "not_attempted"}
    assert any(event.message == "mixed-provider sketch teardown verified" for event in completed.events)


def test_forged_incomplete_start_cannot_change_retirement_audit_basis(tmp_path: Path):
    failed_deploy = _automatically_cleaned_failed_deploy_job()
    failed_deploy = replace(
        failed_deploy,
        events=[
            *failed_deploy.events,
            JobEvent(
                6,
                "info",
                "edges edge provider deploy started",
                {
                    "componentId": "edges",
                    "role": "edge",
                    "provider": "digitalocean",
                },
            ),
        ],
    )
    repository = SqliteJobRepository(tmp_path / "jobs.sqlite3")
    repository.save(failed_deploy)
    tasks = []

    teardown = start_guarded_mixed_sketch_teardown(
        failed_deploy.id,
        repository=repository,
        runner=object(),
        background_runner=tasks.append,
    )

    assert teardown is not None
    cleanup_basis = {
        event.data["componentId"]: event.data["cleanupBasis"]
        for event in teardown.events
        if "cleanup already verified" in event.message
    }
    assert cleanup_basis == {"middle": "automatic_cleanup_verified", "edges": "not_attempted"}


@pytest.mark.parametrize(
    "defect",
    ["incomplete", "forged", "live_output", "zero_attempt", "reordered", "unexpected_sketch_field"],
)
def test_automatic_cleanup_classifier_rejects_incomplete_or_untrusted_evidence(defect: str):
    job = _automatically_cleaned_failed_deploy_job()
    events = list(job.events)
    if defect == "incomplete":
        events = [event for event in events if event.message != "terraform cleanup verified"]
    elif defect == "forged":
        events = [
            replace(event, data={**event.data, "componentProvider": "linode"})
            if event.message == "terraform cleanup verified"
            else event
            for event in events
        ]
    elif defect == "live_output":
        events.append(JobEvent(6, "info", "mixed-provider sketch output recorded", {"sketchInfrastructure": [{"id": "live"}]}))
    elif defect == "zero_attempt":
        events = [event for event in events if "provider deploy started" not in event.message]
    elif defect == "unexpected_sketch_field":
        events = [
            replace(event, data={**event.data, "sketchInfrastructure": []})
            if event.message == "terraform cleanup verified"
            else event
            for event in events
        ]
    else:
        events = [replace(event, sequence=2) if event.message == "terraform cleanup verified" else event for event in events]
    job = replace(job, events=events)

    assert _verified_deploy_cleanup_component_ids(job, job.input["childInputs"]) == set()


def test_zero_attempt_cleanup_evidence_uses_existing_workspace_fail_closed_path(tmp_path: Path):
    job = _automatically_cleaned_failed_deploy_job()
    job = replace(job, events=[event for event in job.events if "provider deploy started" not in event.message])
    repository = SqliteJobRepository(tmp_path / "jobs.sqlite3")
    repository.save(job)

    with patch(
        "app.services.mixed_sketch_deployment._validate_retained_children",
        side_effect=ValueError("retained workspace unavailable"),
    ) as validate:
        with pytest.raises(ValueError, match="retained workspace unavailable"):
            start_guarded_mixed_sketch_teardown(job.id, repository=repository)

    validate.assert_called_once()


def test_partial_mixed_teardown_retry_skips_only_same_job_clean_component():
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edges", "role": "edge", "provider": "digitalocean"},
    ]
    job = _mixed_teardown_job(
        components=components,
        events=[_cleanup_event({"componentId": "middle", "componentRole": "middle", "componentProvider": "linode"})],
    )
    child_calls = []

    def run_child(child, _runner, *, deploy):
        child_calls.append((child.input["componentId"], deploy))
        return "succeeded", [_cleanup_event({})], ["terraform:edge"]

    with (
        patch("app.services.mixed_sketch_deployment._validate_retained_children") as validate,
        patch("app.services.mixed_sketch_deployment._run_provider_child", side_effect=run_child),
    ):
        status, events, _artifacts = _teardown(job, object())

    assert status == "succeeded"
    assert child_calls == [("edges", False)]
    assert validate.call_args.kwargs["cleaned_component_ids"] == {"middle"}
    assert any(event.data.get("componentId") == "middle" and "already verified" in event.message for event in events)
    assert any(event.data.get("componentId") == "edges" and event.data.get("cleanupVerified") is True for event in events)


def test_resume_failed_mixed_teardown_reuses_same_job_cleanup_evidence(tmp_path: Path):
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edges", "role": "edge", "provider": "digitalocean"},
    ]
    failed = _mixed_teardown_job(
        components=components,
        events=[_cleanup_event({"componentRole": "middle", "componentProvider": "linode"})],
    )
    repository = SqliteJobRepository(tmp_path / "jobs.sqlite3")
    repository.save(failed)
    tasks = []
    child_calls = []

    def run_child(child, _runner, *, deploy):
        child_calls.append(child.input["componentId"])
        return "succeeded", [_cleanup_event({})], []

    with (
        patch("app.services.mixed_sketch_deployment._validate_retained_children") as validate,
        patch("app.services.mixed_sketch_deployment._run_provider_child", side_effect=run_child),
    ):
        resumed = resume_guarded_mixed_sketch_teardown(
            failed.id,
            repository=repository,
            runner=object(),
            background_runner=tasks.append,
        )
        assert resumed is not None
        assert resumed.id == failed.id
        assert len(tasks) == 1
        tasks[0]()

    finished = repository.get(failed.id)
    assert finished is not None
    assert finished.status == "succeeded"
    assert child_calls == ["edges"]
    assert all(call.kwargs["cleaned_component_ids"] == {"middle"} for call in validate.call_args_list)


def test_historical_cleanup_fallback_is_strict_and_unambiguous():
    historical = _mixed_teardown_job(
        components=None,
        events=[_cleanup_event({"componentRole": "middle", "componentProvider": "linode"})],
    )
    assert _cleaned_teardown_component_ids(historical, historical.input["childInputs"]) == {"middle"}

    components = [
        {"componentId": "edge-01", "role": "edge", "provider": "digitalocean"},
        {"componentId": "edge-02", "role": "edge", "provider": "digitalocean"},
    ]
    ambiguous = _mixed_teardown_job(
        components=components,
        events=[_cleanup_event({"componentRole": "edge", "componentProvider": "digitalocean"})],
    )
    assert _cleaned_teardown_component_ids(ambiguous, ambiguous.input["childInputs"]) == set()


def test_forged_component_cleanup_evidence_does_not_skip():
    job = _mixed_teardown_job(
        components=[
            {"componentId": "middle", "role": "middle", "provider": "linode"},
            {"componentId": "edges", "role": "edge", "provider": "digitalocean"},
        ],
        events=[_cleanup_event({"componentId": "middle", "componentRole": "edge", "componentProvider": "digitalocean"})],
    )
    assert _cleaned_teardown_component_ids(job, job.input["childInputs"]) == set()


def test_modern_heterogeneous_multi_edge_job_rejects_componentless_unique_role_provider_evidence():
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edge-do", "role": "edge", "provider": "digitalocean"},
        {"componentId": "edge-linode", "role": "edge", "provider": "linode"},
    ]
    job = _mixed_teardown_job(
        components=components,
        events=[_cleanup_event({"componentRole": "edge", "componentProvider": "digitalocean"})],
    )
    job.input["childInputs"]["edge-do"] = {
        **job.input["childInputs"].pop("edges"),
        "componentId": "edge-do",
    }
    job.input["childInputs"]["edge-linode"] = {
        "provider": "linode",
        "middleCount": 0,
        "edgeCount": 1,
        "edgeCountPerRegion": 1,
        "componentId": "edge-linode",
        "terraformWorkingDirectory": "/state/eng-1/chain-1/components/edge-linode/linode",
    }

    assert _cleaned_teardown_component_ids(job, job.input["childInputs"]) == set()

    job = replace(
        job,
        events=[
            _cleanup_event(
                {
                    "componentId": "edge-do",
                    "componentRole": "edge",
                    "componentProvider": "digitalocean",
                }
            )
        ],
    )
    assert _cleaned_teardown_component_ids(job, job.input["childInputs"]) == {"edge-do"}


def test_componentless_cleanup_rejects_swapped_explicit_role_and_child_counts():
    components = [
        {"componentId": "middle", "role": "edge", "provider": "linode"},
        {"componentId": "edges", "role": "middle", "provider": "digitalocean"},
    ]
    job = _mixed_teardown_job(
        components=components,
        events=[_cleanup_event({"componentId": "middle", "componentRole": "edge", "componentProvider": "linode"})],
    )

    assert _cleaned_teardown_component_ids(job, job.input["childInputs"]) == set()


def test_componentless_cleanup_rejects_mismatched_child_component_id():
    components = [
        {"componentId": "middle", "role": "middle", "provider": "linode"},
        {"componentId": "edges", "role": "edge", "provider": "digitalocean"},
    ]
    job = _mixed_teardown_job(
        components=components,
        events=[_cleanup_event({"componentId": "middle", "componentRole": "middle", "componentProvider": "linode"})],
    )
    job.input["childInputs"]["middle"]["componentId"] = "forged-middle"

    assert _cleaned_teardown_component_ids(job, job.input["childInputs"]) == set()


def test_retained_children_validate_all_siblings_before_any_access_transition():
    spec = {
        "engagementId": "eng-1",
        "chainId": "chain-1",
        "components": [
            {"componentId": "middle", "provider": "linode"},
            {"componentId": "edges", "provider": "digitalocean"},
        ],
    }
    child_inputs = {
        "middle": {"terraformWorkingDirectory": "/state/eng-1/chain-1/components/middle/linode"},
        "edges": {"terraformWorkingDirectory": "/state/eng-1/chain-1/components/edges/digitalocean"},
    }
    validated = SimpleNamespace(path=Path(child_inputs["middle"]["terraformWorkingDirectory"]))

    with (
        patch(
            "app.services.mixed_sketch_deployment.validate_existing_sketch_state_workspace",
            side_effect=[validated, ValueError("unsafe sibling")],
        ),
        patch("app.services.mixed_sketch_deployment.retained_compute_image_for_workspace") as retained_image,
        patch("app.services.mixed_sketch_deployment.grant_collaborator_access_to_existing_sketch_state_workspace") as grant,
    ):
        with pytest.raises(ValueError, match="unsafe sibling"):
            _validate_retained_children(spec, child_inputs)

    retained_image.assert_not_called()
    grant.assert_not_called()


def test_retained_children_skip_image_only_for_proven_clean_component():
    spec = {
        "engagementId": "eng-1",
        "chainId": "chain-1",
        "middleProvider": "linode",
        "edgeProvider": "digitalocean",
        "components": [
            {"componentId": "middle", "role": "middle", "provider": "linode"},
            {"componentId": "edges", "role": "edge", "provider": "digitalocean"},
        ],
    }
    child_inputs = _mixed_teardown_job(events=[], components=spec["components"]).input["childInputs"]
    validated = [
        SimpleNamespace(path=Path(child_inputs["middle"]["terraformWorkingDirectory"])),
        SimpleNamespace(path=Path(child_inputs["edges"]["terraformWorkingDirectory"])),
    ]

    with (
        patch(
            "app.services.mixed_sketch_deployment.validate_existing_sketch_state_workspace",
            side_effect=validated,
        ) as validate,
        patch("app.services.mixed_sketch_deployment.retained_compute_image_for_workspace") as retained_image,
        patch("app.services.mixed_sketch_deployment.grant_collaborator_access_to_existing_sketch_state_workspace") as grant,
    ):
        _validate_retained_children(spec, child_inputs, cleaned_component_ids={"middle"})

    assert validate.call_count == 2
    assert retained_image.call_count == 1
    assert retained_image.call_args.args[2] == "digitalocean"
    assert grant.call_count == 2


class FakeMixedTerraformRunner:
    def __init__(self):
        self.calls = []
        self.variables_by_workspace = {}
        self.destroyed_workspaces = set()

    def run(self, command, *, working_directory, env, variables=None):
        variables = dict(variables or {})
        self.calls.append(
            {
                "command": command,
                "workingDirectory": working_directory,
                "env": dict(env),
                "variables": variables,
            }
        )
        if command in {"apply", "destroy"}:
            self.variables_by_workspace[working_directory] = variables
        if command == "apply":
            provider = "linode" if "TF_VAR_linode_api_token" in env else "digitalocean"
            resource_type = "linode_instance" if provider == "linode" else "digitalocean_droplet"
            image_variable = "linode_image" if provider == "linode" else "docean_image"
            state_path = Path(working_directory, "terraform.tfstate")
            state_path.write_text(
                json.dumps({"resources": [{"mode": "managed", "type": resource_type, "instances": [{"attributes": {"image": variables[image_variable]}}]}]}),
                encoding="utf-8",
            )
            state_path.chmod(0o600)
        if command == "destroy":
            self.destroyed_workspaces.add(working_directory)
        if command == "output":
            if working_directory in self.destroyed_workspaces:
                return TerraformCommandResult(command=command, returncode=0, stdout=json.dumps({}), stderr="")
            variables = self.variables_by_workspace.get(working_directory, {})
            provider = "linode" if "TF_VAR_linode_api_token" in env else "digitalocean"
            region = str((variables.get("edge_regions") or ["us-sea"])[0])
            middle_count = int(variables.get("middle_count") or 0)
            edge_count = int(variables.get("edge_count_per_region") or 0)
            body = {
                "middle_public_ips": {"value": [f"203.0.113.{10 if provider == 'linode' else 20}"][:middle_count]},
                "middle_instance_ids": {"value": [f"{provider}-middle-1"][:middle_count]},
                "edge_public_ips": {"value": {region: [f"203.0.113.{30 + index}" for index in range(edge_count)]}},
                "edge_instance_ids": {"value": {region: [f"{provider}-edge-{index + 1}" for index in range(edge_count)]}},
            }
            return TerraformCommandResult(command=command, returncode=0, stdout=json.dumps(body), stderr="")
        return TerraformCommandResult(command=command, returncode=0, stdout="", stderr="")


def test_individual_edge_components_use_barragan_copied_workspace_compatibility_overlay():
    app = create_app(TestConfig)
    engagement_id = app.test_client().post("/api/engagements", json={"name": f"mix-contract-{uuid4().hex[:8]}", "owner": "operator"}).get_json()["engagement"]["id"]
    runner = FakeMixedTerraformRunner()
    tasks = []
    with tempfile.TemporaryDirectory() as temp_dir:
        repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
        with (
            app.storage_context(),
            patch.dict("os.environ", {"BARRAGAN_CREDENTIAL_MASTER_KEY": credential_test_master_key(), "BARRAGAN_SKETCH_STATE_ROOT": str(Path(temp_dir) / "sketch-state")}),
                patch("app.services.linode_sketch_deployment.resolve_credential_secret", return_value="linode-token"),
                patch("app.services.digitalocean_sketch_deployment.resolve_credential_secret", return_value="do-token"),
                patch("app.services.sketch_state_workspaces._collaborator_group_gid", return_value=os.getgid()),
        ):
            running = start_guarded_mixed_sketch_run(
                {
                    "confirmMutation": MIXED_SKETCH_CONFIRMATION, "engagementId": engagement_id,
                    "middleProvider": "linode", "middleRegion": "us-sea", "middleSize": "g6-nanode-1",
                    "middleCredentialAlias": "linode-sketch-dev", "edgeProvider": "linode", "edgeRegion": "us-sea", "edgeSize": "g6-nanode-1",
                    "edges": [
                        {"id": "edge-01", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1", "credentialAlias": "linode-sketch-dev"},
                        {"id": "edge-02", "provider": "digitalocean", "region": "sfo3", "size": "s-1vcpu-1gb", "credentialAlias": "do-sketch-dev"},
                    ],
                }, repository=repository, runner=runner, background_runner=tasks.append,
            )
            assert running.input["individualEdges"] is True
            assert running.input["managedHostImageProfile"] == "ubuntu-24.04"
            assert {
                child["managedHostImageProfile"]
                for child in running.input["childInputs"].values()
            } == {"ubuntu-24.04"}
            assert str(Path(temp_dir) / "sketch-state") in running.input["terraformWorkspaceRoot"]
            assert "barragan-mixed-sketch-" not in running.input["terraformWorkspaceRoot"]
            assert [component["componentId"] for component in running.input["components"]] == ["middle", "edge-01", "edge-02"]
            tasks[0]()

        completed = repository.get(running.id)
    assert completed is not None
    assert completed.status == "succeeded"
    applies = [call for call in runner.calls if call["command"] == "apply"]
    assert [(call["variables"]["middle_count"], call["variables"]["edge_count_per_region"]) for call in applies] == [(1, 0), (0, 1), (0, 1)]
    assert [call["variables"]["resource_name_suffix"] for call in applies] == ["-middle", "-edge01", "-edge02"]


def test_component_resource_name_suffix_keeps_the_established_proxy_ordinal() -> None:
    assert _component_resource_name_suffix("proxy02-sea-01", "edge-01") == "-02-edge01"


def test_mixed_sketch_deploy_runs_middle_only_and_edge_only_provider_modules():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = client.post("/api/engagements", json={"name": f"mix01-{uuid4().hex[:8]}", "owner": "operator"}).get_json()["engagement"]["id"]
    runner = FakeMixedTerraformRunner()
    tasks = []

    with tempfile.TemporaryDirectory() as temp_dir:
        repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
        with (
            app.storage_context(),
            patch.dict("os.environ", {"BARRAGAN_CREDENTIAL_MASTER_KEY": credential_test_master_key(), "BARRAGAN_SKETCH_STATE_ROOT": str(Path(temp_dir) / "sketch-state")}),
                patch("app.services.linode_sketch_deployment.resolve_credential_secret", return_value="linode-token"),
                patch("app.services.digitalocean_sketch_deployment.resolve_credential_secret", return_value="do-token"),
                patch("app.services.sketch_state_workspaces._collaborator_group_gid", return_value=os.getgid()),
        ):
            running = start_guarded_mixed_sketch_run(
                {
                    "confirmMutation": MIXED_SKETCH_CONFIRMATION,
                    "engagementId": engagement_id,
                    "chainId": "proxy01-sea-01",
                    "assignedProxy": "proxy01",
                    "middleProvider": "linode",
                    "middleRegion": "us-sea",
                    "middleSize": "g6-nanode-1",
                    "middleCredentialAlias": "linode-sketch-dev",
                    "edgeProvider": "digitalocean",
                    "edgeRegion": "sfo3",
                    "edgeSize": "s-1vcpu-1gb",
                    "edgeCredentialAlias": "do-sketch-dev",
                    "edgeCount": 2,
                },
                repository=repository,
                runner=runner,
                background_runner=tasks.append,
            )
            assert running.status == "running"
            assert len(tasks) == 1
            tasks[0]()

        completed = repository.get(running.id)

    assert completed is not None
    assert completed.status == "succeeded"
    apply_calls = [call for call in runner.calls if call["command"] == "apply"]
    assert [call["variables"]["middle_count"] for call in apply_calls] == [1, 0]
    assert [call["variables"]["edge_count_per_region"] for call in apply_calls] == [0, 2]
    output_events = [event for event in completed.events if event.message == "mixed-provider sketch output recorded"]
    assert len(output_events) == 1
    rows = output_events[0].data["sketchInfrastructure"]
    assert [(row["role"], row["provider"]) for row in rows] == [
        ("middle", "linode"),
        ("edge", "digitalocean"),
        ("edge", "digitalocean"),
    ]
    assert len(output_events[0].data["outboundChannels"]) == 2


def test_mixed_sketch_teardown_runs_edge_then_middle_provider_modules():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = client.post("/api/engagements", json={"name": f"mix02-{uuid4().hex[:8]}", "owner": "operator"}).get_json()["engagement"]["id"]
    runner = FakeMixedTerraformRunner()
    deploy_tasks = []
    teardown_tasks = []

    with tempfile.TemporaryDirectory() as temp_dir:
        repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
        with (
            app.storage_context(),
            patch.dict("os.environ", {"BARRAGAN_CREDENTIAL_MASTER_KEY": credential_test_master_key(), "BARRAGAN_SKETCH_STATE_ROOT": str(Path(temp_dir) / "sketch-state")}),
            patch("app.services.linode_sketch_deployment.resolve_credential_secret", return_value="linode-token"),
            patch("app.services.digitalocean_sketch_deployment.resolve_credential_secret", return_value="do-token"),
            patch("app.services.sketch_state_workspaces._collaborator_group_gid", return_value=os.getgid()),
        ):
            deploy = start_guarded_mixed_sketch_run(
                {
                    "confirmMutation": MIXED_SKETCH_CONFIRMATION,
                    "engagementId": engagement_id,
                    "chainId": "proxy01-sea-01",
                    "assignedProxy": "proxy01",
                    "middleProvider": "digitalocean",
                    "middleRegion": "sfo3",
                    "middleSize": "s-1vcpu-1gb",
                    "middleCredentialAlias": "do-sketch-dev",
                    "edgeProvider": "linode",
                    "edgeRegion": "us-sea",
                    "edgeSize": "g6-nanode-1",
                    "edgeCredentialAlias": "linode-sketch-dev",
                },
                repository=repository,
                runner=runner,
                background_runner=deploy_tasks.append,
            )
            deploy_tasks[0]()
            teardown = start_guarded_mixed_sketch_teardown(
                deploy.id,
                repository=repository,
                runner=runner,
                background_runner=teardown_tasks.append,
            )
            assert teardown is not None
            teardown_tasks[0]()

        completed = repository.get(teardown.id)

    assert completed is not None
    assert completed.status == "succeeded"
    destroy_calls = [call for call in runner.calls if call["command"] == "destroy"]
    assert len(destroy_calls) == 2
    assert destroy_calls[0]["variables"]["middle_count"] == 0
    assert destroy_calls[0]["variables"]["edge_count_per_region"] == 1
    assert destroy_calls[1]["variables"]["middle_count"] == 1
    assert destroy_calls[1]["variables"]["edge_count_per_region"] == 0


def test_mixed_sketch_teardown_rejects_invalid_retained_workspace_before_runner_call():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = client.post(
        "/api/engagements",
        json={"name": f"mix-invalid-{uuid4().hex[:8]}", "owner": "operator"},
    ).get_json()["engagement"]["id"]
    runner = FakeMixedTerraformRunner()
    deploy_tasks = []

    with tempfile.TemporaryDirectory() as temp_dir:
        repository = SqliteJobRepository(Path(temp_dir) / "barragan.sqlite3")
        with (
            app.storage_context(),
            patch.dict("os.environ", {"BARRAGAN_CREDENTIAL_MASTER_KEY": credential_test_master_key(), "BARRAGAN_SKETCH_STATE_ROOT": str(Path(temp_dir) / "sketch-state")}),
            patch("app.services.linode_sketch_deployment.resolve_credential_secret", return_value="linode-token"),
            patch("app.services.digitalocean_sketch_deployment.resolve_credential_secret", return_value="do-token"),
            patch("app.services.sketch_state_workspaces._collaborator_group_gid", return_value=os.getgid()),
        ):
            deploy = start_guarded_mixed_sketch_run(
                {
                    "confirmMutation": MIXED_SKETCH_CONFIRMATION,
                    "engagementId": engagement_id,
                    "chainId": "proxy01-sea-01",
                    "middleProvider": "linode",
                    "middleRegion": "us-sea",
                    "middleCredentialAlias": "linode-sketch-dev",
                    "edgeProvider": "digitalocean",
                    "edgeRegion": "sfo3",
                    "edgeCredentialAlias": "do-sketch-dev",
                },
                repository=repository,
                runner=runner,
                background_runner=deploy_tasks.append,
            )
            deploy_tasks[0]()
            calls_before = len(runner.calls)
            first_workspace = Path(next(iter(deploy.input["terraformWorkingDirectories"].values())))
            marker = first_workspace / ".barragan-sketch-state"
            valid_marker = marker.read_text(encoding="utf-8")
            marker.write_text("forged\n", encoding="utf-8")

            with pytest.raises(ValueError, match="ownership marker"):
                start_guarded_mixed_sketch_teardown(deploy.id, repository=repository, runner=runner)

            assert len(runner.calls) == calls_before

            marker.write_text(valid_marker, encoding="utf-8")
            marker.chmod(0o600)
            teardown_tasks = []
            teardown = start_guarded_mixed_sketch_teardown(
                deploy.id,
                repository=repository,
                runner=runner,
                background_runner=teardown_tasks.append,
            )
            assert teardown is not None
            marker.write_text("forged-after-queue\n", encoding="utf-8")
            teardown_tasks[0]()

            finished = repository.get(teardown.id)
            assert finished is not None
            assert finished.status == "failed"
            assert len(runner.calls) == calls_before
