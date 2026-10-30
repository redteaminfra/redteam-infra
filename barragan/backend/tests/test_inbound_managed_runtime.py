# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json

from app.domain import JobEvent
from app.services import inbound_managed_runtime
from app.services.engagement_operations import _inbound_channel
from app.storage.job_repository import StoredJobRun


class FakeJobs:
    def __init__(self, jobs: list[StoredJobRun]):
        self.jobs = jobs

    def list_for_engagement(self, engagement_id: str, *, limit: int | None = None) -> list[StoredJobRun]:
        return self.jobs[:limit]


def test_operations_projection_preserves_route_chain_and_private_backend_port():
    projected = _inbound_channel(
        {
            "channelId": "route-1",
            "chainId": "chain-1",
            "backendPort": "9999",
        }
    )

    assert projected["chainId"] == "chain-1"
    assert projected["backendPort"] == "9999"


def _job(channel_id: str) -> StoredJobRun:
    return StoredJobRun(
        id="job-route-latest",
        action="inbound_channel_apply",
        status="succeeded",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1", "channelId": channel_id, "confirmation": "redacted"},
        artifact_refs=["/controller/workspace/MANIFEST.json"],
        created_at="2026-09-09T12:00:00Z",
        started_at="2026-09-09T12:00:00Z",
        finished_at="2026-09-09T12:01:00Z",
        events=[JobEvent(1, "info", "raw output", {"commandResult": {"stdout": "secret"}})],
    )


def test_managed_runtime_projects_shared_web_ownership_without_secret_or_raw_data(monkeypatch):
    channel_id = "edge-01-443-to-proxy01-443-files"
    monkeypatch.setattr(
        inbound_managed_runtime,
        "get_operations_overview",
        lambda *args, **kwargs: {
            "inboundChannels": [
                {
                    "channelId": channel_id,
                    "chainId": "chain-1",
                    "domain": "files.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "https-openresty",
                    "externalPort": "443",
                    "edge": "edge-01",
                    "middle": "middle-01",
                    "proxy": "proxy01",
                    "terminatesOn": "proxy01",
                    "internalPort": "443",
                    "backendPort": "9999",
                    "service": "Go Simple Upload Server",
                    "serviceId": "http-site-files",
                    "serviceType": "web-http-backend",
                    "status": "Validated",
                    "artifactTargets": {
                        "edgeStream": "/etc/nginx/streams/barragan-web-edge.conf",
                        "middleStream": "/etc/nginx/streams/barragan-web-middle.conf",
                        "proxyStream": "/opt/web/tls/files.map",
                        "workspace": "/opt/engagements/eng-1/private/MANIFEST.json",
                        "traversal": "/opt/web/../secrets",
                    },
                    "validation": {
                        "status": "Validated",
                        "checkedAt": "2026-09-09T12:01:00Z",
                        "externalIngressVerified": True,
                        "probeCommand": ["curl", "--header", "Authorization: secret"],
                        "observedResponse": "secret response",
                    },
                    "certificate": {
                        "type": "letsencrypt",
                        "status": "active",
                        "activationStatus": "active",
                        "domain": "files.example.invalid",
                        "privkey": "/etc/letsencrypt/live/files/privkey.pem",
                        "requestGateToken": "do-not-return",
                    },
                    "requestGateToken": "do-not-return",
                    "backendAuthorization": "do-not-return",
                }
            ]
        },
    )

    result = inbound_managed_runtime.get_inbound_managed_runtime(
        "eng-1", channel_id, job_repository=FakeJobs([_job(channel_id)])
    )

    assert result is not None
    assert result["routingOwner"]["kind"] == "shared-web-ingress"
    assert result["selectedPath"] == {
        "chainId": "chain-1",
        "edge": "edge-01",
        "middle": "middle-01",
        "proxy": "proxy01",
    }
    assert result["site"]["backend"] == {
        "kind": "private-http-service",
        "host": "homebase",
        "port": "9999",
    }
    assert result["certificate"] == {
        "type": "letsencrypt",
        "status": "active",
        "domain": "files.example.invalid",
        "activationStatus": "active",
    }
    assert result["latestJob"] == {
        "id": "job-route-latest",
        "action": "inbound_channel_apply",
        "status": "succeeded",
        "startedAt": "2026-09-09T12:00:00Z",
        "finishedAt": "2026-09-09T12:01:00Z",
    }
    assert result["managedArtifacts"] == [
        {"scope": "edge", "path": "/etc/nginx/streams/barragan-web-edge.conf"},
        {"scope": "middle", "path": "/etc/nginx/streams/barragan-web-middle.conf"},
        {"scope": "proxy", "path": "/opt/web/tls/files.map"},
        {"scope": "proxy", "path": "/var/lib/barragan/managed-runtime/barragan-routes.json"},
    ]
    assert result["failClosedDefault"]["target"] == "127.0.0.1:9"
    encoded = json.dumps(result)
    for forbidden in (
        "do-not-return",
        "Authorization: secret",
        "secret response",
        "commandResult",
        "/controller/",
        "/opt/engagements/",
        "privkey.pem",
        "/opt/web/../secrets",
    ):
        assert forbidden not in encoded


def test_managed_runtime_degrades_gracefully_for_legacy_route_without_artifacts(monkeypatch):
    monkeypatch.setattr(
        inbound_managed_runtime,
        "get_operations_overview",
        lambda *args, **kwargs: {
            "inboundChannels": [
                {
                    "channelId": "legacy-route",
                    "protocol": "TCP",
                    "externalPort": "8443",
                    "edge": "edge-old",
                    "middle": "middle-old",
                    "proxy": "proxy01",
                    "terminatesOn": "homebase",
                    "internalPort": "9443",
                    "service": "Operator service",
                    "status": "Recorded",
                }
            ]
        },
    )

    result = inbound_managed_runtime.get_inbound_managed_runtime(
        "eng-1", "legacy-route", job_repository=FakeJobs([])
    )

    assert result is not None
    assert result["mode"] == "tcp-forward"
    assert result["routingOwner"]["kind"] == "dedicated-stream"
    assert result["selectedPath"]["chainId"] is None
    assert result["managedArtifacts"] == []
    assert "Legacy route metadata" in result["artifactStatus"]
    assert result["latestJob"] is None
