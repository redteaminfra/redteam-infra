# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.engagement_workspaces import EngagementWorkspaceValidationError
from app.services.guarded_test_deployment import run_guarded_pilot_standard_rti
from app.integrations.oci_disposable_terraform import EXECUTION_CONFIRMATION


def test_core_deployment_is_blocked_before_executor_when_workspace_is_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from app.services.engagement_teardown import assert_core_creation_allowed

    # This service unit owns no runtime database. Model a new engagement while
    # retaining the real cleanup/creation guard before workspace resolution.
    jobs = SimpleNamespace(list_for_engagement=lambda _id: [])
    monkeypatch.setattr(
        "app.services.engagement_teardown.assert_core_creation_allowed",
        lambda engagement_id: assert_core_creation_allowed(
            engagement_id, repository=jobs, lifecycle_state="draft"),
    )
    monkeypatch.setattr(
        "app.services.guarded_test_deployment.get_engagement",
        lambda _id: SimpleNamespace(id="eng-durable", name="Durable Test", input_parameters={}),
    )
    monkeypatch.setattr(
        "app.services.guarded_test_deployment.prepare_core_deployment_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            EngagementWorkspaceValidationError(["engagement workspace must be prepared before core deployment"])
        ),
    )
    called = False

    def executor(*_args, **_kwargs):
        nonlocal called
        called = True
        return {"ok": True}

    with pytest.raises(EngagementWorkspaceValidationError):
        run_guarded_pilot_standard_rti(
            {
                "confirmMutation": EXECUTION_CONFIRMATION,
                "confirmDestroyCleanup": False,
                "deploymentMode": "hold_for_review",
                "engagementId": "eng-durable",
                "sshSourceCidrs": ["198.51.100.10/32"],
            },
            executor=executor,
            engagement_workspace_root=tmp_path / "engagements",
            terraform_state_root=tmp_path / "state",
        )

    assert called is False
