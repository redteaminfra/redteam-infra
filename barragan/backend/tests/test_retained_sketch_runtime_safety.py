# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path
import json
from unittest.mock import patch

import pytest

from app.services.digitalocean_sketch_deployment import (
    DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
    run_digitalocean_sketch_job,
)
from app.services.linode_sketch_deployment import (
    LINODE_SKETCH_TEARDOWN_ACTION,
    run_linode_sketch_job,
)
from app.services.sketch_state_workspaces import SketchStateWorkspaceError
from app.services import sketch_state_workspaces
from app.services.sketch_state_workspaces import prepare_sketch_state_workspace
from app.integrations.terraform_runner import TerraformCommandResult
from app.services.managed_host_image_continuity import ManagedHostImageContinuityError
from app.storage.job_repository import StoredJobRun


class _Runner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(self, command, **_kwargs):
        self.calls.append(command)
        raise AssertionError("Terraform must not run for an invalid retained workspace")


def test_linode_teardown_accepts_canonical_terraform_0644_state_without_rewriting_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "state"
    template = tmp_path / "template"
    template.mkdir()
    (template / "main.tf").write_text("terraform {}\n", encoding="utf-8")
    monkeypatch.setenv("BARRAGAN_SKETCH_STATE_ROOT", str(state_root))
    monkeypatch.setattr(
        sketch_state_workspaces, "_collaborator_group_gid", lambda: sketch_state_workspaces.os.getgid()
    )
    prepared = prepare_sketch_state_workspace(
        "eng-1", "chain-1", "linode", template_directory=template, root=state_root
    )
    prepared.state_path.write_text(
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
    prepared.state_path.chmod(0o644)

    class _SuccessfulRunner:
        observed_access = None

        def run(self, command, **_kwargs):
            if self.observed_access is None:
                self.observed_access = {
                    "root": state_root.stat().st_mode & 0o7777,
                    "workspace": prepared.path.stat().st_mode & 0o7777,
                    "source": (prepared.path / "main.tf").stat().st_mode & 0o777,
                    "state": prepared.state_path.stat().st_mode & 0o777,
                }
            return TerraformCommandResult(
                command=command,
                returncode=0,
                stdout="{}" if command == "output" else "",
                stderr="",
            )

    job = StoredJobRun(
        id="job-retained-0644",
        action=LINODE_SKETCH_TEARDOWN_ACTION,
        status="running",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={
            "engagementId": "eng-1",
            "engagementName": "example",
            "chainId": "chain-1",
            "middleCredentialAlias": "provider-default",
            "edgeCredentialAlias": "provider-default",
            "middleRegion": "us-sea",
            "edgeRegion": "us-sea",
            "middleSize": "g6-nanode-1",
            "edgeSize": "g6-nanode-1",
            "terraformWorkingDirectory": str(prepared.path),
        },
        artifact_refs=[],
        created_at="2026-09-11T00:00:00+00:00",
        started_at="2026-09-11T00:00:00+00:00",
        finished_at=None,
        events=[],
    )

    runner = _SuccessfulRunner()
    status, _events, _artifacts = run_linode_sketch_job(
        job,
        runner=runner,
        credential_resolver=lambda *_args: "token",
    )

    assert status == "succeeded"
    assert runner.observed_access["source"] == 0o640
    assert runner.observed_access["state"] == 0o644
    assert runner.observed_access["root"] in {0o750, 0o2750}
    assert runner.observed_access["workspace"] in {0o750, 0o2750}
    assert prepared.state_path.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize(
    ("provider", "action", "run_job", "module", "region", "size"),
    [
        (
            "linode",
            LINODE_SKETCH_TEARDOWN_ACTION,
            run_linode_sketch_job,
            "app.services.linode_sketch_deployment",
            "us-sea",
            "g6-nanode-1",
        ),
        (
            "digitalocean",
            DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
            run_digitalocean_sketch_job,
            "app.services.digitalocean_sketch_deployment",
            "sfo3",
            "s-1vcpu-1gb",
        ),
    ],
)
def test_retained_runtime_revalidates_before_keys_credentials_or_terraform(
    tmp_path: Path,
    provider: str,
    action: str,
    run_job,
    module: str,
    region: str,
    size: str,
) -> None:
    runner = _Runner()
    job = StoredJobRun(
        id="job-retained",
        action=action,
        status="running",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={
            "engagementId": "eng-1",
            "engagementName": "example",
            "chainId": "chain-1",
            "middleCredentialAlias": "provider-default",
            "edgeCredentialAlias": "provider-default",
            "middleRegion": region,
            "edgeRegion": region,
            "middleSize": size,
            "edgeSize": size,
            "terraformWorkingDirectory": str(tmp_path / "unowned"),
            "materializeKeyFiles": True,
        },
        artifact_refs=[],
        created_at="2026-09-10T00:00:00+00:00",
        started_at="2026-09-10T00:00:00+00:00",
        finished_at=None,
        events=[],
    )

    with patch(f"{module}.materialized_sketch_key_files", side_effect=AssertionError("keys must not materialize")):
        with pytest.raises(SketchStateWorkspaceError):
            run_job(
                job,
                runner=runner,
                credential_resolver=lambda *_args: (_ for _ in ()).throw(
                    AssertionError("credentials must not resolve")
                ),
            )

    assert runner.calls == []


@pytest.mark.parametrize(
    ("provider", "action", "run_job", "module", "resource_type", "region", "size"),
    [
        (
            "linode",
            LINODE_SKETCH_TEARDOWN_ACTION,
            run_linode_sketch_job,
            "app.services.linode_sketch_deployment",
            "linode_instance",
            "us-sea",
            "g6-nanode-1",
        ),
        (
            "digitalocean",
            DIGITALOCEAN_SKETCH_TEARDOWN_ACTION,
            run_digitalocean_sketch_job,
            "app.services.digitalocean_sketch_deployment",
            "digitalocean_droplet",
            "sfo3",
            "s-1vcpu-1gb",
        ),
    ],
)
def test_retained_runtime_rejects_missing_image_before_terraform(
    tmp_path: Path,
    provider: str,
    action: str,
    run_job,
    module: str,
    resource_type: str,
    region: str,
    size: str,
) -> None:
    (tmp_path / "terraform.tfstate").write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "mode": "managed",
                        "type": resource_type,
                        "instances": [{"attributes": {}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    runner = _Runner()
    job = StoredJobRun(
        id="job-retained-image",
        action=action,
        status="running",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={
            "engagementId": "eng-1",
            "engagementName": "example",
            "chainId": "chain-1",
            "middleCredentialAlias": "provider-default",
            "edgeCredentialAlias": "provider-default",
            "middleRegion": region,
            "edgeRegion": region,
            "middleSize": size,
            "edgeSize": size,
            "terraformWorkingDirectory": str(tmp_path),
        },
        artifact_refs=[],
        created_at="2026-09-10T00:00:00+00:00",
        started_at="2026-09-10T00:00:00+00:00",
        finished_at=None,
        events=[],
    )

    with (
        patch(f"{module}.validate_existing_sketch_state_workspace"),
        patch(
            f"{module}.disable_legacy_sketch_local_artifacts",
            side_effect=AssertionError("compatibility sources must not be written"),
        ),
        patch(
            f"{module}.materialized_sketch_key_files",
            side_effect=AssertionError("keys must not materialize"),
        ),
    ):
        with pytest.raises(ManagedHostImageContinuityError):
            run_job(
                job,
                runner=runner,
                credential_resolver=lambda *_args: (_ for _ in ()).throw(
                    AssertionError("credentials must not resolve")
                ),
            )

    assert runner.calls == []
