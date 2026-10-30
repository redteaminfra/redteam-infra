# Copyright (c) 2026, Oracle and/or its affiliates.
"""Independent binding history cannot be created inside a paired append lease."""
from dataclasses import replace
from datetime import datetime, timezone
import json
import sqlite3
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from app import create_app
from app.core.config import TestConfig
from app.storage.job_repository import MixedAppendBindingFenceError, SqlAlchemyJobRepository
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from test_job_repository_mixed_append_second import repository, row
from test_domains import domain_client


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("action", ["engagement_channels_update", "inbound_channel_apply_preview",
    "outbound_channel_apply_preview", "certificate_asset_create", "engagement_dns_apply",
    "web_static_service_apply_preview", "backflips_service_apply_preview",
    "desktop_service_apply_preview", "legacy_homebase_role_service_apply_preview"])
@pytest.mark.parametrize("method", ["save", "save_if_absent"])
def test_append_lease_fences_binding_history_atomic_writers(kind, action, method, tmp_path):
    with repository(kind, tmp_path) as jobs:
        candidate = replace(row(datetime.now(timezone.utc).isoformat()), action=action)
        with pytest.raises(MixedAppendBindingFenceError):
            getattr(jobs, method)(candidate)
        assert jobs.get(candidate.id) is None
        # An unrelated Inspector job is unaffected by the restriction.
        assert jobs.save(replace(candidate, action="inspector_cleanup")).action == "inspector_cleanup"


@pytest.mark.parametrize("key", ["inboundChannels", "outboundChannels"])
def test_empty_channel_update_api_is_rejected_without_history(domain_client, key):
    app, client = domain_client
    with app.storage_context():
        db.session.add(CoreMutationLeaseModel(engagement_id="eng-of02-dev", owner_id="core",
            operation="provider_keyed_mixed_append"))
        db.session.commit()
        before = SqlAlchemyJobRepository().list_for_engagement("eng-of02-dev")
    response = client.patch("/api/engagements/eng-of02-dev/operations", json={key: []})
    assert response.status_code == 400
    assert response.get_json() == {"errors": [
        "channel and service changes are unavailable during paired edge append"]}
    with app.storage_context():
        assert SqlAlchemyJobRepository().list_for_engagement("eng-of02-dev") == before


def test_static_web_preview_has_normal_validation_error_without_history(tmp_path, monkeypatch):
    from app.services.web_static_service import (preview_web_static_service_apply,
        WebStaticCoreHost, WebStaticServiceValidationError)
    monkeypatch.setattr("app.services.web_static_service.get_engagement",
                        lambda _: SimpleNamespace(name="opaque"))
    host = WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", str(tmp_path / "known"))
    monkeypatch.setattr("app.services.web_static_service._core_apply_hosts",
                        lambda *_: (host, replace(host, name="proxy01", ansible_host="192.168.2.11", proxy_jump="user@203.0.113.10")))
    with repository("sqlalchemy", tmp_path) as jobs:
        def inspection(command, cwd):
            assert command[0] == "ssh"
            return subprocess.CompletedProcess(command, 0, json.dumps({
                "state": "empty", "fingerprint": "a" * 64}), "")
        with pytest.raises(WebStaticServiceValidationError) as caught:
            preview_web_static_service_apply("eng-opaque", {}, repository=jobs, runner=inspection)
        assert caught.value.errors == [
            "channel and service changes are unavailable during paired edge append"]
        assert jobs.list() == []


def test_channel_history_waits_for_other_connection_append_reservation(tmp_path):
    path = tmp_path / "binding-writer.sqlite"
    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{path}"
    app = create_app(Config)
    with app.storage_context():
        db.session.remove()
    writer = sqlite3.connect(path, timeout=10)
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("INSERT INTO core_mutation_leases (engagement_id, owner_id, operation, acquired_at) "
        "VALUES (?, ?, ?, ?)", ("eng-of02-dev", "core", "provider_keyed_mixed_append",
                                  datetime.now(timezone.utc).isoformat()))
    entered, done = threading.Event(), threading.Event()
    outcomes = []
    def save():
        with app.storage_context():
            entered.set()
            try:
                SqlAlchemyJobRepository().save(replace(row(datetime.now(timezone.utc).isoformat()),
                    target_id="eng-of02-dev", action="engagement_channels_update"))
                outcomes.append("saved")
            except MixedAppendBindingFenceError:
                outcomes.append("fenced")
            finally:
                done.set()
    worker = threading.Thread(target=save)
    worker.start()
    assert entered.wait(2)
    time.sleep(.1)
    assert not done.is_set()
    writer.commit()
    writer.close()
    worker.join(5)
    assert not worker.is_alive() and outcomes == ["fenced"]
    with app.storage_context():
        assert SqlAlchemyJobRepository().get("job-second") is None
        db.session.remove()
        db.engine.dispose()


@pytest.mark.parametrize("family", ["backflips", "desktop", "legacy-role"])
def test_capability_previews_reject_append_lease_with_existing_validation(tmp_path, monkeypatch, family):
    from app.services import backflips_service as backflips
    from app.services import legacy_homebase_role_service as legacy
    from app.services.web_static_service import WebStaticCoreHost
    host = WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known")
    monkeypatch.setattr(backflips, "get_engagement", lambda _: SimpleNamespace(name="opaque"))
    monkeypatch.setattr(backflips, "_core_apply_hosts", lambda *_: (host,
        replace(host, name="proxy01", ansible_host="192.168.2.11", proxy_jump="user@203.0.113.10")))
    monkeypatch.setattr(backflips, "_middle_ip_for_proxy", lambda *_: "198.51.100.20")
    monkeypatch.setattr(legacy, "get_engagement", lambda _: SimpleNamespace(name="opaque"))
    monkeypatch.setattr(legacy, "_core_homebase", lambda *_: legacy.LegacyRoleHost(
        "homebase", "203.0.113.10", "user", "/keys/core", "/tmp/known"))
    with repository("sqlalchemy", tmp_path) as jobs:
        error_type = (backflips.BackflipsServiceValidationError if family == "backflips"
                      else legacy.LegacyHomebaseRoleServiceValidationError)
        with pytest.raises(error_type) as caught:
            if family == "backflips":
                backflips.preview_backflips_service_apply("eng-opaque", repository=jobs)
            elif family == "desktop":
                legacy.preview_desktop_service_apply("eng-opaque", [], repository=jobs)
            else:
                legacy.preview_legacy_homebase_role_service_apply("eng-opaque", "keepassxc", repository=jobs)
        assert caught.value.errors == [
            "channel and service changes are unavailable during paired edge append"]
        assert jobs.list() == []


@pytest.mark.parametrize("path,service,action", [
    ("outbound-channels/chain-opaque/apply-preview", "preview_outbound_channel_apply", "outbound_channel_apply_preview"),
    ("inbound-channels/channel-opaque/apply-preview", "preview_inbound_channel_apply", "inbound_channel_apply_preview"),
    ("dns/preview", "preview_engagement_dns", "engagement_dns_preview"),
])
def test_unhandled_feature_writer_fence_has_central_api_409(domain_client, monkeypatch, path, service, action):
    app, client = domain_client
    with app.storage_context():
        db.session.add(CoreMutationLeaseModel(engagement_id="eng-of02-dev", owner_id="core",
            operation="provider_keyed_mixed_append"))
        db.session.commit()
        before = SqlAlchemyJobRepository().list_for_engagement("eng-of02-dev")
    def attempted_history(*_args, **_kwargs):
        # Reach the real durable writer, bypassing only feature-specific preparation.
        return SqlAlchemyJobRepository().save(replace(row(datetime.now(timezone.utc).isoformat()),
            id="job-forbidden-history", action=action, target_id="eng-of02-dev",
            target="engagement:eng-of02-dev"))
    monkeypatch.setattr("app.asgi." + service, attempted_history)
    response = client.post("/api/engagements/eng-of02-dev/" + path, json={})
    assert response.status_code == 409
    assert response.get_json() == {"errors": [
        "channel and service changes are unavailable during paired edge append"]}
    with app.storage_context():
        assert SqlAlchemyJobRepository().list_for_engagement("eng-of02-dev") == before
