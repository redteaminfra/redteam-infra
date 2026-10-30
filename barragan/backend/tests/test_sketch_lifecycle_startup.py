# Copyright (c) 2026, Oracle and/or its affiliates.
from app.asgi import create_app
from app.core.config import TestConfig


def test_create_app_runs_mandatory_sketch_startup_recovery(monkeypatch):
    calls = []
    monkeypatch.setattr("app.asgi.recover_post_core_sketch_continuations", lambda: None)
    monkeypatch.setattr("app.asgi.recover_engagement_teardowns", lambda: None)
    monkeypatch.setattr("app.asgi.recover_sketch_lifecycle", lambda **kwargs: calls.append(kwargs))

    create_app(TestConfig)

    assert calls == [{"startup": True}]


def test_mixed_interrupted_startup_rechecks_selector_before_resume(tmp_path, monkeypatch):
    class DevTestConfig(TestConfig):
        ENVIRONMENT = "devtest"
        PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "1.1.1.1"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'mixed-startup.sqlite'}"

    from app.services import provider_keyed_mixed_interrupted_public as interrupted
    from app.services import provider_keyed_mixed_zero_apply_dispatch as zero
    monkeypatch.setattr(zero, "recover_mixed_zero_apply_dispatches",
                        lambda **_kwargs: [])
    candidates = ["job-interrupted"]
    calls = []

    def recover(*, schedule, **_kwargs):
        for candidate in candidates:
            schedule(candidate)
        return list(candidates)

    monkeypatch.setattr(interrupted, "recover_mixed_interrupted_dispatches", recover)
    monkeypatch.setattr(interrupted, "advance_mixed_interrupted_cleanup",
                        lambda parent_id, **kwargs: calls.append((parent_id, kwargs)))
    scheduled = []
    monkeypatch.setattr("app.core.runtime.start_runtime_task",
                        lambda task, *, name: scheduled.append(task)
                        if name == "barragan-mixed-interrupted-teardown-recovery" else None)
    create_app(DevTestConfig)
    assert len(scheduled) == 1
    candidates.clear()
    scheduled[0]()
    assert calls == []
    candidates.append("job-interrupted")
    scheduled[0]()
    assert calls == [("job-interrupted", {
        "environment": "devtest", "positive_control_ipv4": "1.1.1.1"})]


def test_dns_startup_recovery_is_scheduled_when_periodic_schedulers_are_disabled(tmp_path, monkeypatch):
    class Config(TestConfig):
        TESTING = False
        START_SCHEDULERS = False
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'dns-startup.sqlite'}"

    scheduled = []
    monkeypatch.setattr("app.asgi.recover_interrupted_engagement_dns_applies",
                        lambda *, schedule: schedule(lambda: scheduled.append("ran")))
    monkeypatch.setattr("app.core.runtime.start_runtime_task",
                        lambda task, *, name: scheduled.append((name, task)))
    create_app(Config)
    assert len(scheduled) == 1
    assert scheduled[0][0] == "barragan-dns-apply-recovery"


def test_private_keyed_dns_startup_is_devtest_only_and_binds_state_root(tmp_path, monkeypatch):
    class DevTestConfig(TestConfig):
        TESTING = False
        START_SCHEDULERS = False
        ENVIRONMENT = "devtest"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'keyed-dns-startup.sqlite'}"

    from app.services import sketch_state_workspaces
    monkeypatch.setattr(sketch_state_workspaces, "_default_state_root", lambda: tmp_path)
    calls = []
    monkeypatch.setattr("app.asgi.recover_interrupted_keyed_owned_dns_cleanups",
        lambda **kwargs: calls.append(kwargs) or 0)
    create_app(DevTestConfig)
    assert len(calls) == 1
    assert calls[0]["environment"] == "devtest"
    assert calls[0]["state_root"] == tmp_path

    calls.clear()

    class NonDevTestConfig(DevTestConfig):
        ENVIRONMENT = "test"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'prod-dns-startup.sqlite'}"

    create_app(NonDevTestConfig)
    assert calls == []


def test_non_test_app_with_disabled_schedulers_skips_low_frequency_sketch_monitor(tmp_path, monkeypatch):
    class Config(TestConfig):
        TESTING = False
        START_SCHEDULERS = False
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'startup.sqlite'}"

    calls = []
    monkeypatch.setattr("app.asgi.recover_post_core_sketch_continuations", lambda: None)
    monkeypatch.setattr("app.asgi.recover_engagement_teardowns", lambda: None)
    monkeypatch.setattr("app.asgi.recover_sketch_lifecycle", lambda **kwargs: None)
    monkeypatch.setattr("app.asgi.start_post_core_sketch_recovery_monitor", lambda: None)
    monkeypatch.setattr("app.asgi.start_engagement_teardown_recovery_monitor", lambda: None)
    monkeypatch.setattr("app.asgi.start_sketch_lifecycle_recovery_monitor", lambda: calls.append("started"))

    create_app(Config)

    assert calls == []


def test_non_test_app_with_enabled_schedulers_wires_low_frequency_sketch_monitor(tmp_path, monkeypatch):
    class Config(TestConfig):
        TESTING = False
        START_SCHEDULERS = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'startup-enabled.sqlite'}"

    calls = []
    monkeypatch.setattr("app.asgi.recover_post_core_sketch_continuations", lambda: None)
    monkeypatch.setattr("app.asgi.recover_engagement_teardowns", lambda: None)
    monkeypatch.setattr("app.asgi.recover_sketch_lifecycle", lambda **kwargs: None)
    monkeypatch.setattr("app.asgi.start_post_core_sketch_recovery_monitor", lambda: None)
    monkeypatch.setattr("app.asgi.start_engagement_teardown_recovery_monitor", lambda: None)
    monkeypatch.setattr("app.asgi.start_sketch_lifecycle_recovery_monitor", lambda: calls.append("started"))

    create_app(Config)

    assert calls == ["started"]


def test_monitor_runs_targeted_recovery_with_supplied_repositories(monkeypatch):
    from app.services import sketch_lifecycle_recovery

    jobs = object()
    chains = object()
    calls = []
    monkeypatch.setattr(
        sketch_lifecycle_recovery,
        "recover_sketch_lifecycle",
        lambda **kwargs: calls.append(kwargs),
    )

    sketch_lifecycle_recovery.run_sketch_lifecycle_recovery_monitor(
        job_repository=jobs,
        sketch_repository=chains,
        wait=lambda _seconds: False,
        interval_seconds=900,
        max_cycles=1,
    )

    assert calls == [{"job_repository": jobs, "sketch_repository": chains}]
