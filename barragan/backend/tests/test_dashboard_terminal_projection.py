# Copyright (c) 2026, Oracle and/or its affiliates.
from types import SimpleNamespace

from app.services.dashboard import _inventory_row


def test_verified_destroyed_lifecycle_overrides_retained_healthy_hosts():
    row = _inventory_row(SimpleNamespace(id="eng-test", name="test", status="planned"), {
        "lifecycle": {"state": "destroyed", "terminal": True},
        "healthSummary": {"status": "healthy", "activeHostCount": 2},
        "coreInfrastructure": [{"status": "active", "stale": True, "region": "test"}],
        "sketchInfrastructure": [{"status": "active", "publicIp": "1.2.3.4"}],
    })
    assert row["lifecycleState"] == row["healthStatus"] == "destroyed"
    assert row["activeCoreHostCount"] == row["activeSketchHostCount"] == 0
    assert row["coreHostCount"] == row["sketchHostCount"] == 1
    assert row["lastKnown"] is True


def test_cleanup_required_lifecycle_keeps_hosts_visible_as_attention():
    row = _inventory_row(SimpleNamespace(id="eng-test", name="test", status="planned"), {
        "lifecycle": {"state": "cleanup_required", "terminal": False},
        "healthSummary": {"status": "healthy", "activeHostCount": 1},
        "coreInfrastructure": [{"status": "active"}],
    })
    assert row["lifecycleState"] == "cleanup_not_verified"
    assert row["healthStatus"] == "attention"
    assert row["activeCoreHostCount"] == 1


def test_active_lifecycle_keeps_running_hosts_active():
    row = _inventory_row(SimpleNamespace(id="eng-test", name="test", status="planned"), {
        "lifecycle": {"state": "active", "terminal": False},
        "healthSummary": {"status": "healthy", "activeHostCount": 1},
        "coreInfrastructure": [{"status": "active"}],
    })
    assert row["lifecycleState"] == "active"
    assert row["activeCoreHostCount"] == 1


def test_unknown_lifecycle_preserves_explicit_cleanup_failure():
    row = _inventory_row(SimpleNamespace(id="eng-test", name="test", status="planned"), {
        "lifecycle": {"state": "unknown", "terminal": False},
        "healthSummary": {"status": "cleanup_not_verified"},
        "coreInfrastructure": [{"status": "active"}],
    })
    assert row["lifecycleState"] == "cleanup_not_verified"
