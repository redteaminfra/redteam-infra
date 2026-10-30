# Copyright (c) 2026, Oracle and/or its affiliates.
"""A losing normal Inspector insert does not launch cleanup work."""

from types import SimpleNamespace

import pytest

from app.services import engagement_teardown, observer_checks


def test_cleanup_insert_conflict_prevents_provider_and_background_dispatch(monkeypatch):
    monkeypatch.setattr(engagement_teardown, "assert_engagement_mutation_allowed", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(observer_checks, "get_engagement", lambda _engagement_id: SimpleNamespace(name="test"))
    monkeypatch.setattr(observer_checks, "preview_inspector_cleanup", lambda *_args, **_kwargs: {
        "confirmationToken": "confirm", "blockers": [], "resourceCount": 1, "hosts": [],
    })

    class LosingRepository:
        def insert_inspector_teardown_barrier(self, _job):
            return None

    calls = []
    with pytest.raises(observer_checks.InspectorCleanupValidationError) as error:
        observer_checks.start_inspector_cleanup(
            "eng-1", {"confirmation": "confirm"}, job_repository=LosingRepository(),
            provider_factory=lambda _provider: calls.append("provider"),
            background_runner=lambda _task: calls.append("runner"),
        )
    assert "teardown" in error.value.errors[0]
    assert calls == []


@pytest.mark.parametrize("action", ["readiness", "inspection"])
def test_normal_inspector_insert_conflict_prevents_side_effects(monkeypatch, action):
    monkeypatch.setattr(engagement_teardown, "assert_engagement_mutation_allowed", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(observer_checks, "get_engagement", lambda _id: SimpleNamespace(name="test"))
    settings = SimpleNamespace(
        engagement_id="eng-1", enabled=True, mode="continuous", provider="linode",
        region="us-east", size="g6-nanode-1", current_host={},
    )
    monkeypatch.setattr(observer_checks, "_settings_for_engagement", lambda *_args, **_kwargs: settings)
    monkeypatch.setattr(observer_checks, "_reusable_inspector_host", lambda _settings: None)
    monkeypatch.setattr(observer_checks, "inspection_targets", lambda *_args, **_kwargs: {
        "positive": [{"id": "target-1", "type": "tcp"}], "negative": [],
    })

    class LosingRepository:
        def list_for_engagement(self, _id):
            return []

        def insert_inspector_teardown_barrier(self, _job):
            return None

    calls = []
    common = dict(
        job_repository=LosingRepository(),
        provider_factory=lambda _provider: calls.append("provider"),
        credential_alias_resolver=lambda _provider: "alias",
        credential_secret_resolver=lambda _provider, _alias: "secret",
    )
    if action == "readiness":
        with pytest.raises(observer_checks.InspectorReadinessError):
            observer_checks.ensure_continuous_inspector_ready("eng-1", **common)
    else:
        with pytest.raises(observer_checks.InspectionValidationError):
            observer_checks.start_inspection(
                "eng-1", {}, inspection_repository=SimpleNamespace(),
                background_runner=lambda _task: calls.append("runner"), **common,
            )
    assert calls == []


def test_reused_host_probe_cannot_return_stale_ready_after_teardown(monkeypatch):
    monkeypatch.setattr(observer_checks, "get_engagement", lambda _id: SimpleNamespace(name="test"))
    settings = SimpleNamespace(enabled=True, mode="continuous", provider="linode")
    monkeypatch.setattr(observer_checks, "_settings_for_engagement", lambda *_args, **_kwargs: settings)
    host = observer_checks.ObserverHost("linode", "instance", "42", "opaque", "us-east", "192.0.2.42")
    monkeypatch.setattr(observer_checks, "_reusable_inspector_host", lambda _settings: host)
    monkeypatch.setattr(observer_checks, "_inspector_support_baseline_current", lambda _host: True)

    class Repository:
        rows = []

        def list_for_engagement(self, _id):
            return list(self.rows)

    repo = Repository()

    class Probe:
        def verify_access(self, *, host, ssh_key):
            assert host is not None and ssh_key == "existing-key"
            repo.rows.append(SimpleNamespace(
                id="queued-teardown", action=engagement_teardown.ENGAGEMENT_TEARDOWN_ACTION,
                status="queued",
            ))

    monkeypatch.setattr(observer_checks, "SshObserverRunner", Probe)
    with pytest.raises(engagement_teardown.EngagementTeardownValidationError):
        observer_checks.ensure_continuous_inspector_ready(
            "eng-1", job_repository=repo, runner=Probe(),
            ssh_key_factory=lambda _label: "existing-key",
        )
