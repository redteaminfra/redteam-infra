# Copyright (c) 2026, Oracle and/or its affiliates.
from pathlib import Path

import pytest

from app.services.inbound_backend_authorization import (
    InboundBackendAuthorizationValidationError,
    render_backend_authorization_fact_play,
    resolve_selected_inbound_backend_authorization,
)
from app.services.inbound_request_header_gate import (
    InboundRequestHeaderGateValidationError,
    RequestHeaderGatePolicy,
    _candidate_policy,
    render_http_backend_site_config,
)
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace


class _WorkspaceRepository:
    def __init__(self, workspace):
        self.workspace = workspace

    def get(self, engagement_id):
        return self.workspace if engagement_id == self.workspace.engagement_id else None


def _selected_workspace() -> StoredEngagementWorkspace:
    return StoredEngagementWorkspace(
        engagement_id="eng-upload",
        slug="upload",
        path="/tmp/upload",
        status="prepared",
        profile_id="standard-rti",
        template_source={},
        metadata={
            "capabilityOverrides": {
                "selectedOptionals": [{"hostClass": "homebase", "id": "go-simple-upload-server"}],
            }
        },
    )


def test_selected_go_upload_capability_loads_private_backend_authorization_without_rendering_token():
    adapter = resolve_selected_inbound_backend_authorization(
        "eng-upload",
        host_class="homebase",
        port=9999,
        workspace_repository=_WorkspaceRepository(_selected_workspace()),
    )

    assert adapter is not None
    assert adapter.capability_id == "go-simple-upload-server"
    assert adapter.max_request_body_mb == 500

    config = render_http_backend_site_config(
        "192.0.2.10",
        9999,
        RequestHeaderGatePolicy(True, "Authorization", "public-route-token", "now", 500),
        backend_authorization=adapter,
    )

    assert "proxy_set_header Authorization \"{{ hostvars[groups['termination_host'][0]].barragan_inbound_backend_authorization }}\";" in config
    assert "public-route-token" in config
    assert "read_write_tokens" not in config
    assert "/etc/go-simple-upload-server/config.json" not in config
    fact_play = "\n".join(render_backend_authorization_fact_play(adapter, inventory_group="termination_host"))
    assert "hosts: termination_host" in fact_play
    assert "/etc/go-simple-upload-server/config.json" in fact_play
    assert "no_log: true" in fact_play


def test_selected_backend_caps_route_request_size():
    adapter = resolve_selected_inbound_backend_authorization(
        "eng-upload",
        host_class="homebase",
        port=9999,
        workspace_repository=_WorkspaceRepository(_selected_workspace()),
    )
    assert adapter is not None

    with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
        _candidate_policy(
            {"enabled": False, "headerName": "Authorization", "tokenAction": "keep", "maxRequestBodyMb": 501},
            None,
            backend_max_request_body_mb=adapter.max_request_body_mb,
        )
    assert "cannot exceed" in caught.value.errors[0]


def test_malformed_selected_backend_manifest_fails_closed(tmp_path: Path):
    manifests = tmp_path / "capabilities"
    manifests.mkdir()
    (manifests / "bad.yml").write_text(
        """apiVersion: barragan/v1
classification: optional
metadata: {id: go-simple-upload-server}
integration:
  inboundHttpBackend:
    hostClass: homebase
    port: 9999
    maxRequestBodyBytes: 500000000
    authorization: {headerName: Authorization, scheme: Bearer, source: {type: json-file, path: /tmp/token, arrayField: tokens, index: 0}}
""",
        encoding="utf-8",
    )

    with pytest.raises(InboundBackendAuthorizationValidationError) as caught:
        resolve_selected_inbound_backend_authorization(
            "eng-upload",
            host_class="homebase",
            port=9999,
            workspace_repository=_WorkspaceRepository(_selected_workspace()),
            manifest_root=tmp_path,
        )
    assert "invalid" in caught.value.errors[0]
