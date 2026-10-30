# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from app.services.inbound_channel_apply import (
    InboundChannelApplyValidationError,
    apply_inbound_channel,
    render_inbound_apply_workspace,
    start_inbound_channel_apply,
)
from app.services.inbound_channel_artifacts import (
    InboundChannelArtifactSpec,
    http_backend_service_name,
    render_inbound_channel_artifacts,
)
from app.services.inbound_request_header_gate import (
    InboundRequestHeaderGateValidationError,
    REQUEST_HEADER_GATE_LIVE_ROUTE_STATUSES,
    RequestHeaderGatePolicy,
    RequestHeaderGateLiveTarget,
    RetainedRequestHeaderGate,
    _require_applied_channel,
    _unregister_active_gate_job,
    _load_retained,
    _policy_path,
    _write_retained,
    get_inbound_request_header_gate,
    load_active_request_header_gate,
    render_http_backend_site_config,
    render_https_request_header_gate_hooks,
    render_request_header_gate_http_runtime,
    update_inbound_request_header_gate,
)
from app.services.inbound_backend_authorization import InboundBackendAuthorization
from app.services.sketch_ssh_keys import SketchSshKeyNotFoundError
from app.storage.engagement_workspace_repository import StoredEngagementWorkspace
from app.storage.job_repository import StoredJobRun
from app.storage.service_repository import StoredEngagementService


class _Jobs:
    def __init__(self):
        self.jobs = []

    def list(self):
        return list(self.jobs)

    def list_for_engagement(self, engagement_id, *, limit=None):
        rows = [job for job in self.jobs if job.input.get("engagementId") == engagement_id]
        return rows[:limit] if limit is not None else rows

    def save(self, job):
        self.jobs = [current for current in self.jobs if current.id != job.id]
        self.jobs.append(job)
        return job

    def get(self, job_id):
        return next((job for job in self.jobs if job.id == job_id), None)


class _Services:
    def __init__(self, services=()):
        self.services = {(service.engagement_id, service.service_id): service for service in services}

    def get(self, engagement_id, service_id):
        return self.services.get((engagement_id, service_id))


@pytest.fixture()
def gate_context(tmp_path, monkeypatch):
    engagement_root = tmp_path / "engagements"
    workspace_path = engagement_root / "zy01-eng1"
    (workspace_path / "barragan").mkdir(parents=True)
    marker = workspace_path / "barragan" / "workspace-manifest.json"
    marker.write_text('{"engagementId":"eng-1","managedBy":"barragan"}\n', encoding="utf-8")
    workspace = StoredEngagementWorkspace(
        engagement_id="eng-1",
        slug="zy01-eng1",
        path=str(workspace_path),
        status="prepared",
        profile_id="standard-rti",
        template_source={},
        metadata={},
    )
    overview = {
        "coreInfrastructure": [
            {
                "role": "homebase",
                "displayName": "homebase-zy01",
                "sshAlias": "homebase-zy01",
                "publicIp": "203.0.113.10",
                "privateIp": "192.168.0.10",
                "sshUser": "user",
            },
            {
                "role": "proxy01",
                "displayName": "proxy01-zy01",
                "sshAlias": "proxy01-zy01",
                "publicIp": "203.0.113.11",
                "privateIp": "192.168.2.11",
                "sshUser": "user",
            },
        ],
        "sketchInfrastructure": [
            {
                "chainId": "chain-1",
                "hostname": "middle01-zy01",
                "role": "middle",
                "publicIp": "198.51.100.20",
            },
            {
                "chainId": "chain-1",
                "hostname": "edge01-zy01",
                "role": "edge",
                "publicIp": "198.51.100.30",
            },
        ],
        "inboundChannels": [
            {
                "channelId": "upload-http",
                "domain": "upload.example.test",
                "protocol": "TCP",
                "mode": "http-openresty",
                "externalPort": "80",
                "edge": "edge01-zy01",
                "middle": "middle01-zy01",
                "proxy": "proxy01-zy01",
                "terminatesOn": "homebase-zy01",
                "service": "Go Simple Upload Server",
                "internalPort": "9999",
                "purpose": "Uploads",
                "status": "Validated",
            }
        ],
    }
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.get_engagement",
        lambda engagement_id: SimpleNamespace(id=engagement_id, name="ZY01") if engagement_id == "eng-1" else None,
    )
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.get_operations_overview",
        lambda engagement_id: overview,
    )
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.load_prepared_engagement_workspace",
        lambda engagement_id, **_kwargs: workspace,
    )
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.resolve_ansible_playbook",
        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook", error=""),
    )
    # Channel lifecycle workspaces now require the already-deployed
    # infrastructure-admin identity.  This fixture models a healthy deployed
    # sketch chain so request-gate tests reach their scheduler, mutex, and
    # secret-redaction assertions instead of exercising the separate
    # missing-key fail-closed contract.
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
        lambda _engagement_id, directory: (
            str(Path(directory) / "infrastructure-admin"),
            str(Path(directory) / "infrastructure-admin.pub"),
        ),
    )
    return SimpleNamespace(
        engagement_root=engagement_root,
        workspace_path=workspace_path,
        workspace=workspace,
        overview=overview,
    )


def test_http_backend_renderer_gates_before_proxying_and_disable_removes_gate():
    policy = RequestHeaderGatePolicy(True, "X-Upload-Token", "safe-token-123", "now")

    enabled = render_http_backend_site_config("192.168.0.10", 9999, policy)
    disabled = render_http_backend_site_config(
        "192.168.0.10",
        9999,
        RequestHeaderGatePolicy(False, "X-Upload-Token", "safe-token-123", "now"),
    )

    assert "map $http_x_upload_token $barragan_request_header_gate" in enabled
    assert '"Bearer safe-token-123" 1;' in enabled
    assert "return 404;" in enabled
    assert enabled.index("return 404;") < enabled.index("proxy_pass http://192.168.0.10:9999;")
    assert "map_hash_bucket_size 512;" not in enabled
    assert "$barragan_request_header_gate" not in disabled
    assert "map_hash_bucket_size 512;" not in disabled
    assert "proxy_pass http://192.168.0.10:9999;" in disabled
    assert "map $http_x_real_ip $barragan_original_client_ip" in enabled
    assert "access_log /dev/stdout barragan_site;" in enabled
    assert "proxy_set_header X-Real-IP $barragan_original_client_ip;" in enabled
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in enabled
    assert "Authorization" not in enabled.split("log_format barragan_site", 1)[1].split("access_log", 1)[0]


def test_http_and_https_render_default_and_custom_request_body_limits_independently_of_gate():
    default_http = render_http_backend_site_config("192.168.0.10", 9999)
    disabled_custom = RequestHeaderGatePolicy(
        False,
        "Authorization",
        "",
        "now",
        750,
    )
    custom_http = render_http_backend_site_config("192.168.0.10", 9999, disabled_custom)
    custom_map, custom_https_server = render_https_request_header_gate_hooks(
        disabled_custom.to_retained_dict()
    )

    assert "client_max_body_size 500000000;" in default_http
    assert "client_max_body_size 750000000;" in custom_http
    assert "listen 8081;" in default_http
    assert "listen 8081 proxy_protocol;" not in default_http
    assert "$remote_addr" in default_http
    assert "$proxy_protocol_addr" not in default_http
    assert "$barragan_request_header_gate" not in custom_http
    assert custom_map == "# Barragan request-header gate is disabled.\n"
    assert custom_https_server == (
        "client_max_body_size 750000000;\n"
        "# Barragan request-header gate is disabled.\n"
    )


def test_max_supported_gate_token_relies_on_stock_openresty_map_sizing():
    token = "A" * 20
    policy = RequestHeaderGatePolicy(True, "Authorization", token, "now")

    http_config = render_http_backend_site_config("192.168.0.10", 9999, policy)
    first_https_map, _first_server = render_https_request_header_gate_hooks(policy.to_retained_dict())
    second_https_map, _second_server = render_https_request_header_gate_hooks(
        RequestHeaderGatePolicy(True, "X-Upload-Token", "B" * 20, "now").to_retained_dict()
    )
    runtime = render_request_header_gate_http_runtime()

    directive = "map_hash_bucket_size 512;"
    assert directive not in http_config
    assert directive not in first_https_map
    assert directive not in second_https_map
    assert runtime == "# Map hash sizing is provided by the stock OpenResty base configuration.\n"
    assert sorted(
        ["00-request-header-gate-map.conf", "00-request-header-gate-00-runtime.conf"]
    ) == ["00-request-header-gate-00-runtime.conf", "00-request-header-gate-map.conf"]


def test_initial_unconfigured_detail_exposes_resolved_edge_without_fabricating_request(gate_context):
    source_channel = gate_context.overview["inboundChannels"][0]

    detail = get_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
    )

    assert detail["edgePublicIp"] == "198.51.100.30"
    assert detail["gate"] == {
        "configured": False,
        "enabled": False,
        "headerName": "Authorization",
        "token": "",
        "status": "Not configured",
        "maxRequestBodyMb": 500,
    }
    assert detail["authorizedRequest"] == {"method": "GET", "curl": ""}
    assert "edgePublicIp" not in detail["channel"]
    assert "edgePublicIp" not in source_channel


def test_gosus_https_detail_keeps_the_managed_client_gate_non_mutable(gate_context, monkeypatch):
    channel = gate_context.overview["inboundChannels"][0]
    channel.update(
        {
            "protocol": "HTTPS",
            "mode": "https-openresty",
            "externalPort": "443",
            "terminatesOn": "proxy01-zy01",
            "internalPort": "443",
            "serviceId": "http-site-0123456789abcdef",
            "serviceType": "web-http-backend",
            "status": "Applied",
        }
    )
    adapter = InboundBackendAuthorization(
        capability_id="go-simple-upload-server",
        host_class="homebase",
        port=9999,
        max_request_body_bytes=500_000_000,
        header_name="Authorization",
        scheme="Bearer",
        config_path="/etc/go-simple-upload-server/config.json",
        array_field="read_write_tokens",
        array_index=0,
    )
    service = StoredEngagementService(
        service_id="http-site-0123456789abcdef",
        engagement_id="eng-1",
        name="Managed GoSUS site",
        service_type="web-http-backend",
        status="Configured",
        proxy_id="proxy01-zy01",
        config={
            "siteName": "upload-site",
            "siteService": "upload_site",
            "siteComposePath": "/opt/web/sites/upload-site.compose.yml",
            "siteConfigPath": "/opt/web/sites/upload-site/config",
            "domain": "upload.example.test",
            "stackModel": "containerized-openresty-v1",
            "composePath": "/opt/web/docker-compose.yml",
            "stackOwnershipPath": "/opt/web/.barragan-stack.json",
        },
    )
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.resolve_selected_inbound_backend_authorization",
        lambda *_args, **_kwargs: adapter,
    )

    detail = get_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        service_repository=_Services([service]),
    )

    assert detail["backendPolicy"] == {
        "capabilityId": "go-simple-upload-server",
        "authorizationManaged": True,
        "maxRequestBodyMb": 500,
    }


def test_gosus_route_rejects_generic_gate_mutation_before_persisting_state(monkeypatch):
    target = RequestHeaderGateLiveTarget(
        mode="https-openresty",
        service_name="managed-upload-site",
        route_name="0123456789abcdef",
        backend_host="192.168.0.10",
        backend_port=9999,
        backend_authorization=InboundBackendAuthorization(
            capability_id="go-simple-upload-server",
            host_class="homebase",
            port=9999,
            max_request_body_bytes=500_000_000,
            header_name="Authorization",
            scheme="Bearer",
            config_path="/etc/go-simple-upload-server/config.json",
            array_field="read_write_tokens",
            array_index=0,
        ),
    )
    monkeypatch.setattr("app.services.inbound_request_header_gate.get_engagement", lambda _engagement_id: SimpleNamespace(name="ZY01"))
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate._supported_channel",
        lambda *_args, **_kwargs: ({"status": "Applied"}, None, None, target),
    )
    monkeypatch.setattr("app.services.inbound_request_header_gate._require_applied_channel", lambda _channel: None)

    with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
        update_inbound_request_header_gate(
            "eng-1",
            "upload-https",
            {"enabled": False, "headerName": "Authorization", "tokenAction": "keep"},
        )

    assert "cannot be changed or disabled" in " ".join(caught.value.errors)


def test_retained_policy_is_atomic_restrictive_and_restart_reusable(gate_context):
    path = _policy_path(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
    )
    policy = RequestHeaderGatePolicy(True, "Authorization", "restart-token-123", "now")
    retained = RetainedRequestHeaderGate("eng-1", "upload-http", policy, None)

    _write_retained(path, retained)
    reloaded = _load_retained(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
        require_workspace=True,
    )

    assert reloaded == retained
    assert load_active_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        require_workspace=True,
    )["token"] == "restart-token-123"
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700
    assert os.stat(path.parents[1]).st_mode & 0o777 == 0o700


def test_pre_request_size_retained_policy_loads_with_500_mb_default(gate_context):
    path = _policy_path(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
    )
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_text(
        json.dumps(
            {
                "schema": "barragan/inbound-request-header-gate/v1",
                "managedBy": "barragan",
                "engagementId": "eng-1",
                "channelId": "upload-http",
                "active": {
                    "enabled": False,
                    "headerName": "Authorization",
                    "token": "",
                    "updatedAt": "before-request-size-field",
                },
                "pending": None,
                "pendingJobId": None,
            }
        ),
        encoding="utf-8",
    )

    retained = _load_retained(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
        require_workspace=True,
    )

    assert retained.active.max_request_body_mb == 500
    assert retained.active.to_retained_dict()["maxRequestBodyMb"] == 500


@pytest.mark.parametrize("policy_field", ["active", "pending"])
def test_retained_active_and_pending_reject_tokens_over_supported_limit(gate_context, policy_field):
    path = _policy_path(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
    )
    invalid = RequestHeaderGatePolicy(True, "Authorization", "X" * 21, "now")
    retained = RetainedRequestHeaderGate(
        "eng-1",
        "upload-http",
        invalid if policy_field == "active" else None,
        invalid if policy_field == "pending" else None,
    )

    with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
        _write_retained(path, retained)

    assert "8-20" in " ".join(caught.value.errors)
    assert not path.exists()

    valid = RequestHeaderGatePolicy(True, "Authorization", "valid-token-123", "now")
    valid_retained = RetainedRequestHeaderGate(
        "eng-1",
        "upload-http",
        valid if policy_field == "active" else None,
        valid if policy_field == "pending" else None,
    )
    _write_retained(path, valid_retained)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw[policy_field]["token"] = "X" * 21
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
        _load_retained(
            "eng-1",
            "upload-http",
            engagement_root=gate_context.engagement_root,
            workspace_repository=None,
            require_workspace=True,
        )
    assert "8-20" in " ".join(caught.value.errors)


def test_policy_path_rejects_symlinked_channel_directory(gate_context):
    channels = gate_context.workspace_path / "barragan" / "inbound-channels"
    channels.mkdir()
    target = gate_context.workspace_path / "outside"
    target.mkdir()
    (channels / "upload-http").symlink_to(target, target_is_directory=True)

    with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
        _policy_path(
            "eng-1",
            "upload-http",
            engagement_root=gate_context.engagement_root,
            workspace_repository=None,
        )
    assert "symlink" in " ".join(caught.value.errors)


def test_generate_applies_transactionally_without_job_secret_exposure(gate_context, tmp_path):
    jobs = _Jobs()
    captured = {}

    def runner(command, cwd):
        captured["command"] = command
        captured["playbook"] = (cwd / "ansible" / "apply_request_header_gate.yml").read_text(encoding="utf-8")
        captured["rollback_playbook"] = (cwd / "ansible" / "rollback_request_header_gate.yml").read_text(
            encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    response = update_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        {"enabled": True, "headerName": "Authorization", "tokenAction": "generate"},
        engagement_root=gate_context.engagement_root,
        repository=jobs,
        runner=runner,
        apply_workspace_root=tmp_path / "apply",
        background_runner=lambda task: task(),
    )
    detail = get_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
    )

    assert response["gate"]["status"] == "Applying"
    assert response["gate"]["token"] == ""
    assert detail["gate"]["configured"] is True
    assert detail["gate"]["enabled"] is True
    token = detail["gate"]["token"]
    assert len(token) == 20
    assert f'"Bearer {token}" 1;' in captured["playbook"]
    assert "no_log: true" in captured["playbook"]
    assert "Restore prior route configuration" in captured["playbook"]
    assert "Validate candidate route configuration" in captured["playbook"]
    assert "Inspect selected HTTP backend proxy mounts" in captured["playbook"]
    assert "from_json" in captured["playbook"]
    assert "selectattr('Source', 'equalto'" in captured["playbook"]
    assert "Require selected HTTP request-body policy in effective configuration" in captured["playbook"]
    assert "no_log: true" in captured["playbook"]
    assert "client_max_body_size 500000000;" in captured["playbook"]
    # The shared assertion helper emits ordinary play-level task indentation.
    # Here it is nested in the transactional block, so every line needs one
    # additional task level.  This exact shape is accepted by Ansible's YAML
    # parser and keeps the following reload task in the same block.
    assert "        - name: Inspect selected HTTP backend proxy mounts" in captured["playbook"]
    assert "        - name: Reload candidate route configuration" in captured["playbook"]
    assert "\n    - name: Inspect selected HTTP backend proxy mounts" not in captured["playbook"]
    assert "        - name: Restore prior route configuration" in captured["rollback_playbook"]
    assert 'barragan_gate_site_compose: "/opt/web/sites/upload_http.compose.yml"' in captured["playbook"]
    remove_command = (
        'argv: [docker, rm, -f, "{{ barragan_gate_service_name }}", '
        '"web_{{ barragan_gate_service_name }}_1"]'
    )
    start_command = (
        'argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, '
        '"{{ barragan_gate_site_compose }}", up, -d, '
        '"{{ barragan_gate_service_name }}"]'
    )
    label_query = (
        'argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", '
        '--filter, "label=com.docker.compose.service={{ barragan_gate_service_name }}"]'
    )
    id_remove = 'argv: [docker, rm, -f, "{{ item }}"]'
    assert captured["playbook"].count(remove_command) == 2
    assert captured["playbook"].count(label_query) == 2
    assert captured["playbook"].count(id_remove) == 2
    assert captured["playbook"].count(start_command) == 2
    assert "--force-recreate" not in captured["playbook"]
    assert "--remove-orphans" not in captured["playbook"]
    assert captured["playbook"].index("Write candidate request-header gate configuration") < captured[
        "playbook"
    ].index("Remove only the selected HTTP backend containers before candidate start")
    assert captured["playbook"].index(
        "Remove only the selected HTTP backend containers before candidate start"
    ) < captured["playbook"].index("Find renamed selected HTTP backend Compose containers for candidate start")
    assert captured["playbook"].index(
        "Find renamed selected HTTP backend Compose containers for candidate start"
    ) < captured["playbook"].index("Remove renamed selected HTTP backend Compose containers for candidate start")
    assert captured["playbook"].index(
        "Remove renamed selected HTTP backend Compose containers for candidate start"
    ) < captured["playbook"].index("Start selected HTTP backend with candidate gate configuration")
    assert captured["playbook"].index(
        "Start selected HTTP backend with candidate gate configuration"
    ) < captured["playbook"].index("Validate candidate route configuration")
    assert captured["playbook"].index("Validate candidate route configuration") < captured[
        "playbook"
    ].index("Inspect selected HTTP backend proxy mounts")
    assert captured["playbook"].index(
        "Require selected HTTP request-body policy in effective configuration"
    ) < captured["playbook"].index("Reload candidate route configuration")
    assert captured["playbook"].index("Restore prior route configuration") < captured["playbook"].index(
        "Remove only the selected HTTP backend containers before restored start"
    )
    assert captured["playbook"].index(
        "Remove only the selected HTTP backend containers before restored start"
    ) < captured["playbook"].index("Find renamed selected HTTP backend Compose containers for restored start")
    assert captured["playbook"].index(
        "Find renamed selected HTTP backend Compose containers for restored start"
    ) < captured["playbook"].index("Remove renamed selected HTTP backend Compose containers for restored start")
    assert captured["playbook"].index(
        "Remove renamed selected HTTP backend Compose containers for restored start"
    ) < captured["playbook"].index("Start selected HTTP backend with restored route configuration")
    assert captured["playbook"].index(
        "Start selected HTTP backend with restored route configuration"
    ) < captured["playbook"].index("Validate restored route configuration")
    assert token in detail["authorizedRequest"]["curl"]
    assert "--request GET" in detail["authorizedRequest"]["curl"]
    assert detail["authorizedRequest"]["curl"] == (
        "curl --include --request GET \\\n"
        "  --header 'Host: upload.example.test' \\\n"
        f"  --header 'Authorization: Bearer {token}' \\\n"
        "  http://198.51.100.30/"
    )
    job_payload = json.dumps([job.to_detail().to_dict() for job in jobs.jobs], sort_keys=True)
    assert token not in job_payload
    assert "Bearer " not in job_payload
    assert jobs.jobs[-1].status == "succeeded"
    assert not any((tmp_path / "apply").iterdir())


def test_bearer_disabled_custom_request_size_is_retained_and_applied_atomically(gate_context, tmp_path):
    jobs = _Jobs()
    captured = {}

    def runner(command, cwd):
        captured["playbook"] = (cwd / "ansible" / "apply_request_header_gate.yml").read_text(
            encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    response = update_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        {
            "enabled": False,
            "headerName": "Authorization",
            "tokenAction": "keep",
            "maxRequestBodyMb": 875,
        },
        engagement_root=gate_context.engagement_root,
        repository=jobs,
        runner=runner,
        apply_workspace_root=tmp_path / "apply",
        background_runner=lambda task: task(),
    )
    detail = get_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        repository=jobs,
    )
    retained = load_active_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        require_workspace=True,
    )

    assert response["gate"]["maxRequestBodyMb"] == 500
    assert detail["gate"]["enabled"] is False
    assert detail["gate"]["maxRequestBodyMb"] == 875
    assert retained["maxRequestBodyMb"] == 875
    assert "client_max_body_size 875000000;" in captured["playbook"]
    assert "$barragan_request_header_gate" not in captured["playbook"]
    assert jobs.jobs[-1].status == "succeeded"


def test_route_reapply_executes_retained_gate_without_persisting_job_secret(
    gate_context,
    tmp_path,
    monkeypatch,
):
    jobs = _Jobs()
    token = "route-token-123"
    captured = {}
    channel = gate_context.overview["inboundChannels"][0]

    monkeypatch.setattr(
        "app.services.inbound_channel_apply.get_engagement",
        lambda engagement_id: SimpleNamespace(id=engagement_id, name="ZY01"),
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.get_operations_overview",
        lambda engagement_id: gate_context.overview,
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.resolve_ansible_playbook",
        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook", error=""),
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.sync_provider_ingress_for_inbound_channel",
        lambda *_args, **_kwargs: SimpleNamespace(ok=True, status="skipped", events=()),
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.try_enqueue_infra_orientation_refresh",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.load_active_request_header_gate",
        lambda *_args, **_kwargs: {
            "enabled": True,
            "headerName": "Authorization",
            "token": token,
            "updatedAt": "now",
        },
    )

    def runner(command, cwd):
        if command[-1] == "ansible/apply_inbound_channel.yml":
            playbook = (cwd / "ansible" / "apply_inbound_channel.yml").read_text(encoding="utf-8")
            captured["playbookDuringExecution"] = playbook
            captured["workspace"] = cwd
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    result = apply_inbound_channel(
        "eng-1",
        channel["channelId"],
        confirmation=f"apply-inbound-{channel['channelId']}",
        repository=jobs,
        runner=runner,
        workspace_root=tmp_path / "reapply",
    )

    assert result["job"]["status"] == "succeeded"
    assert f'"Bearer {token}" 1;' in captured["playbookDuringExecution"]
    service_name = http_backend_service_name(channel["channelId"])
    expected_remove = f"argv: [docker, rm, -f, {service_name}, web_{service_name}_1]"
    expected_start = (
        "argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, "
        "/opt/web/sites/upload_http.compose.yml, up, -d, "
        f"{service_name}]"
    )
    expected_label_query = (
        'argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", '
        f'--filter, "label=com.docker.compose.service={service_name}"]'
    )
    expected_id_remove = 'argv: [docker, rm, -f, "{{ item }}"]'
    assert expected_remove in captured["playbookDuringExecution"]
    assert expected_label_query in captured["playbookDuringExecution"]
    assert expected_id_remove in captured["playbookDuringExecution"]
    assert expected_start in captured["playbookDuringExecution"]
    assert captured["playbookDuringExecution"].count(expected_remove) == 1
    assert captured["playbookDuringExecution"].index(
        "Write HTTP backend proxy config"
    ) < captured["playbookDuringExecution"].index(expected_remove)
    assert captured["playbookDuringExecution"].index(expected_remove) < captured[
        "playbookDuringExecution"
    ].index(expected_label_query)
    assert captured["playbookDuringExecution"].index(expected_label_query) < captured[
        "playbookDuringExecution"
    ].index(expected_id_remove)
    assert captured["playbookDuringExecution"].index(expected_id_remove) < captured[
        "playbookDuringExecution"
    ].index(expected_start)
    assert "--force-recreate" not in captured["playbookDuringExecution"]
    assert "--remove-orphans" not in captured["playbookDuringExecution"]
    assert "docker, rm, -f, proxy" not in captured["playbookDuringExecution"]
    serialized_jobs = json.dumps([job.to_detail().to_dict() for job in jobs.jobs], sort_keys=True)
    assert token not in serialized_jobs
    assert "Bearer " not in serialized_jobs
    evidence = jobs.jobs[0].events[0].data["workspaceEvidence"]
    assert token not in json.dumps(evidence, sort_keys=True)
    assert "Bearer " not in json.dumps(evidence, sort_keys=True)
    scrubbed = (captured["workspace"] / "ansible" / "apply_inbound_channel.yml").read_text(encoding="utf-8")
    assert token not in scrubbed
    assert "Bearer " not in scrubbed


def test_route_reapply_fails_closed_when_deployed_admin_key_is_missing(
    gate_context,
    tmp_path,
    monkeypatch,
):
    """A healthy-fixture shortcut must not weaken the production key guard."""
    channel = gate_context.overview["inboundChannels"][0]
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.get_engagement",
        lambda engagement_id: SimpleNamespace(id=engagement_id, name="ZY01"),
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.get_operations_overview",
        lambda _engagement_id: gate_context.overview,
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.resolve_ansible_playbook",
        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook", error=""),
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            SketchSshKeyNotFoundError("deployed infrastructure-admin key is absent")
        ),
    )

    with pytest.raises(InboundChannelApplyValidationError) as caught:
        start_inbound_channel_apply(
            "eng-1",
            channel["channelId"],
            confirmation=f"apply-inbound-{channel['channelId']}",
            repository=_Jobs(),
            workspace_root=tmp_path / "reapply",
            background_runner=lambda task: task(),
        )

    assert caught.value.errors == ["deployed infrastructure-admin key is absent"]
    workspace_root = tmp_path / "reapply"
    assert not workspace_root.exists() or not any(workspace_root.iterdir())


def test_route_reapply_scheduler_failure_is_terminal_and_discards_gate_workspace(
    gate_context,
    tmp_path,
    monkeypatch,
):
    jobs = _Jobs()
    token = "schedule-token-123"
    channel = gate_context.overview["inboundChannels"][0]
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.get_engagement",
        lambda engagement_id: SimpleNamespace(id=engagement_id, name="ZY01"),
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.get_operations_overview",
        lambda engagement_id: gate_context.overview,
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.resolve_ansible_playbook",
        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook", error=""),
    )
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.load_active_request_header_gate",
        lambda *_args, **_kwargs: {
            "enabled": True,
            "headerName": "Authorization",
            "token": token,
            "updatedAt": "now",
        },
    )
    workspace_root = tmp_path / "reapply"

    with pytest.raises(InboundChannelApplyValidationError) as caught:
        start_inbound_channel_apply(
            "eng-1",
            channel["channelId"],
            confirmation=f"apply-inbound-{channel['channelId']}",
            repository=jobs,
            workspace_root=workspace_root,
            background_runner=lambda task: (_ for _ in ()).throw(RuntimeError("scheduler unavailable")),
        )

    assert "could not be started" in " ".join(caught.value.errors)
    assert jobs.jobs[-1].status == "failed"
    assert jobs.jobs[-1].events[-1].data["status"] == "Apply Failed"
    serialized = json.dumps(jobs.jobs[-1].to_detail().to_dict(), sort_keys=True)
    assert token not in serialized
    assert "Bearer " not in serialized
    assert not workspace_root.exists() or not any(workspace_root.iterdir())


def test_route_reapply_mutex_conflict_discards_gate_workspace(
    gate_context,
    tmp_path,
    monkeypatch,
):
    token = "conflict-token-123"
    channel = gate_context.overview["inboundChannels"][0]
    active = StoredJobRun(
        id="job-static-running",
        action="web_static_service_apply",
        status="running",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1", "proxyId": "proxy01-zy01", "mutation": True},
        artifact_refs=[],
        created_at="2026-08-19T00:00:00+00:00",
        started_at="2026-08-19T00:00:00+00:00",
        finished_at=None,
        events=[],
    )
    jobs = _Jobs()
    jobs.jobs.append(active)
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.get_engagement",
        lambda engagement_id: SimpleNamespace(id=engagement_id, name="ZY01"),
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.get_operations_overview",
        lambda engagement_id: gate_context.overview,
    )
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.resolve_ansible_playbook",
        lambda **_kwargs: SimpleNamespace(ok=True, command="ansible-playbook", error=""),
    )
    monkeypatch.setattr(
        "app.services.inbound_request_header_gate.load_active_request_header_gate",
        lambda *_args, **_kwargs: {
            "enabled": True,
            "headerName": "Authorization",
            "token": token,
            "updatedAt": "now",
        },
    )
    workspace_root = tmp_path / "reapply"

    with pytest.raises(InboundChannelApplyValidationError) as caught:
        start_inbound_channel_apply(
            "eng-1",
            channel["channelId"],
            confirmation=f"apply-inbound-{channel['channelId']}",
            repository=jobs,
            workspace_root=workspace_root,
            background_runner=lambda task: task(),
        )

    assert "job-static-running" in " ".join(caught.value.errors)
    assert [job.id for job in jobs.jobs] == ["job-static-running"]
    assert not workspace_root.exists() or not any(workspace_root.iterdir())


def test_background_runner_start_failure_clears_pending_and_fails_job(gate_context, tmp_path):
    jobs = _Jobs()

    with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
        update_inbound_request_header_gate(
            "eng-1",
            "upload-http",
            {
                "enabled": True,
                "headerName": "Authorization",
                "tokenAction": "provide",
                "token": "start-fail-token-12",
            },
            engagement_root=gate_context.engagement_root,
            repository=jobs,
            runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
            apply_workspace_root=tmp_path / "apply",
            background_runner=lambda task: (_ for _ in ()).throw(RuntimeError("scheduler unavailable")),
        )

    retained = _load_retained(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
        require_workspace=True,
    )
    assert "could not be started" in " ".join(caught.value.errors)
    assert retained.active is None
    assert retained.pending is None
    assert retained.pending_job_id is None
    assert jobs.jobs[-1].status == "failed"
    assert jobs.jobs[-1].events[-1].data["errorType"] == "RuntimeError"
    assert not any((tmp_path / "apply").iterdir())


def test_interrupted_pending_is_failed_and_next_update_retries(gate_context, tmp_path):
    jobs = _Jobs()
    scheduled = []
    path = _policy_path(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
    )
    stable = RequestHeaderGatePolicy(True, "Authorization", "stable-token-123", "before")
    _write_retained(path, RetainedRequestHeaderGate("eng-1", "upload-http", stable, None))
    first = update_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        {
            "enabled": True,
            "headerName": "Authorization",
            "tokenAction": "provide",
            "token": "interrupt-token-12",
        },
        engagement_root=gate_context.engagement_root,
        repository=jobs,
        runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
        apply_workspace_root=tmp_path / "apply",
        background_runner=lambda task: scheduled.append(task),
    )
    interrupted_job_id = first["job"]["id"]
    assert scheduled

    live_detail = get_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        repository=jobs,
    )
    assert live_detail["gate"]["status"] == "Applying"
    assert live_detail["gate"]["token"] == "stable-token-123"
    assert live_detail["pending"]["state"] == "running"
    assert live_detail["job"]["id"] == interrupted_job_id
    assert "interrupt-token-12" not in json.dumps(live_detail, sort_keys=True)

    # A new process has no in-memory task ownership. The retained pending job
    # association makes the interrupted state explicit before retry.
    _unregister_active_gate_job(interrupted_job_id)
    retry_detail = get_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        repository=jobs,
    )
    assert retry_detail["gate"]["status"] == "Retry required"
    assert retry_detail["gate"]["token"] == "stable-token-123"
    assert retry_detail["pending"]["state"] == "retry-required"
    assert "interrupt-token-12" not in json.dumps(retry_detail, sort_keys=True)

    executed_playbooks = []

    def retry_runner(command, cwd):
        executed_playbooks.append(
            (cwd / "ansible" / "apply_request_header_gate.yml").read_text(encoding="utf-8")
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    update_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        {
            "enabled": True,
            "headerName": "X-Retry-Token",
            "tokenAction": "provide",
            "token": "retry-token-456",
        },
        engagement_root=gate_context.engagement_root,
        repository=jobs,
        runner=retry_runner,
        apply_workspace_root=tmp_path / "apply",
        background_runner=lambda task: task(),
    )

    interrupted = jobs.get(interrupted_job_id)
    retained = _load_retained(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
        require_workspace=True,
    )
    assert interrupted.status == "failed"
    assert interrupted.events[-1].data["interrupted"] is True
    assert interrupted.events[-1].data["retainedPolicyReconverged"] is True
    assert '"Bearer stable-token-123" 1;' in executed_playbooks[0]
    assert '"Bearer retry-token-456" 1;' in executed_playbooks[1]
    assert retained.pending is None
    assert retained.pending_job_id is None
    assert retained.active is not None
    assert retained.active.token == "retry-token-456"
    assert jobs.jobs[-1].status == "succeeded"


@pytest.mark.parametrize("status", sorted(REQUEST_HEADER_GATE_LIVE_ROUTE_STATUSES))
def test_request_gate_accepts_only_explicit_live_route_statuses(status):
    _require_applied_channel({"status": status})


@pytest.mark.parametrize(
    "status",
    ["", "Pending", "Pending Apply", "Applying", "Apply Failed", "Removed", "Unknown"],
)
def test_request_gate_rejects_non_live_route_statuses(status):
    with pytest.raises(InboundRequestHeaderGateValidationError):
        _require_applied_channel({"status": status})


def test_failed_rotation_preserves_active_policy_and_clears_pending(gate_context, tmp_path):
    path = _policy_path(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
    )
    original = RequestHeaderGatePolicy(True, "Authorization", "original-token-123", "before")
    _write_retained(path, RetainedRequestHeaderGate("eng-1", "upload-http", original, None))
    jobs = _Jobs()

    update_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        {
            "enabled": True,
            "headerName": "X-Route-Token",
            "tokenAction": "provide",
            "token": "replace-token-456",
        },
        engagement_root=gate_context.engagement_root,
        repository=jobs,
        runner=lambda command, cwd: subprocess.CompletedProcess(
            command,
            0 if command[-1] == "ansible/rollback_request_header_gate.yml" else 2,
            stdout="",
            stderr="failed",
        ),
        apply_workspace_root=tmp_path / "apply",
        background_runner=lambda task: task(),
    )
    retained = _load_retained(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
        require_workspace=True,
    )

    assert retained.active == original
    assert retained.pending is None
    assert jobs.jobs[-1].status == "failed"
    payload = json.dumps(jobs.jobs[-1].to_detail().to_dict(), sort_keys=True)
    assert "replace-token-456" not in payload


def test_post_live_promotion_failure_reconverges_retained_active_policy(
    gate_context,
    tmp_path,
    monkeypatch,
):
    path = _policy_path(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
    )
    original = RequestHeaderGatePolicy(True, "Authorization", "original-token-123", "before")
    _write_retained(path, RetainedRequestHeaderGate("eng-1", "upload-http", original, None))
    jobs = _Jobs()
    executed = []
    promotion_failed = False

    def flaky_write(policy_path, retained):
        nonlocal promotion_failed
        if (
            not promotion_failed
            and retained.pending is None
            and retained.active is not None
            and retained.active.token == "candidate-token-456"
        ):
            promotion_failed = True
            raise OSError("simulated retained promotion failure")
        _write_retained(policy_path, retained)

    def runner(command, cwd):
        playbook_name = command[-1].split("/")[-1]
        executed.append((playbook_name, (cwd / "ansible" / playbook_name).read_text(encoding="utf-8")))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(
        "app.services.inbound_request_header_gate._write_retained",
        flaky_write,
    )
    update_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        {
            "enabled": True,
            "headerName": "X-New-Token",
            "tokenAction": "provide",
            "token": "candidate-token-456",
        },
        engagement_root=gate_context.engagement_root,
        repository=jobs,
        runner=runner,
        apply_workspace_root=tmp_path / "apply",
        background_runner=lambda task: task(),
    )

    retained = _load_retained(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
        require_workspace=True,
    )
    assert [name for name, _content in executed] == [
        "apply_request_header_gate.yml",
        "rollback_request_header_gate.yml",
    ]
    assert '"Bearer candidate-token-456" 1;' in executed[0][1]
    assert '"Bearer original-token-123" 1;' in executed[1][1]
    assert retained.active == original
    assert retained.pending is None
    assert jobs.jobs[-1].status == "failed"
    outcome = jobs.jobs[-1].events[-1]
    assert outcome.data["retainedPolicyReconverged"] is True
    assert outcome.data["retainedStateCleared"] is True
    assert outcome.data["recoveryRequired"] is False
    serialized_job = json.dumps(jobs.jobs[-1].to_detail().to_dict(), sort_keys=True)
    assert "candidate-token-456" not in serialized_job
    assert "original-token-123" not in serialized_job
    assert not any((tmp_path / "apply").iterdir())


def test_disable_with_keep_retains_plaintext_for_later_reenable(gate_context, tmp_path):
    path = _policy_path(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        workspace_repository=None,
    )
    original = RequestHeaderGatePolicy(True, "Authorization", "retained-token-123", "before")
    _write_retained(path, RetainedRequestHeaderGate("eng-1", "upload-http", original, None))

    update_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        {"enabled": False, "headerName": "Authorization", "tokenAction": "keep"},
        engagement_root=gate_context.engagement_root,
        repository=_Jobs(),
        runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
        apply_workspace_root=tmp_path / "apply",
        background_runner=lambda task: task(),
    )
    detail = get_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
    )

    assert detail["gate"] == {
        "configured": True,
        "enabled": False,
        "headerName": "Authorization",
        "token": "retained-token-123",
        "status": "Disabled",
        "maxRequestBodyMb": 500,
    }
    assert detail["authorizedRequest"]["curl"] == ""


@pytest.mark.parametrize(
    "body,error",
    [
        ({"enabled": True, "headerName": "Host", "tokenAction": "generate"}, "cannot be used"),
        ({"enabled": True, "headerName": "X_Bad", "tokenAction": "generate"}, "field name"),
        ({"enabled": True, "headerName": "Authorization", "tokenAction": "provide", "token": "bad token"}, "token must"),
        ({"enabled": True, "headerName": "Authorization", "tokenAction": "provide", "token": "A" * 21}, "8-20"),
        ({"enabled": True, "headerName": "Authorization", "tokenAction": "keep"}, "requires an existing"),
    ],
)
def test_update_validates_header_and_token(gate_context, tmp_path, body, error):
    with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
        update_inbound_request_header_gate(
            "eng-1",
            "upload-http",
            body,
            engagement_root=gate_context.engagement_root,
            repository=_Jobs(),
            apply_workspace_root=tmp_path / "apply",
        )
    assert error in " ".join(caught.value.errors)


@pytest.mark.parametrize("value", [0, 10241, 1.5, "500", True, None])
def test_update_rejects_invalid_max_request_body_mb(gate_context, tmp_path, value):
    with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
        update_inbound_request_header_gate(
            "eng-1",
            "upload-http",
            {
                "enabled": False,
                "headerName": "Authorization",
                "tokenAction": "keep",
                "maxRequestBodyMb": value,
            },
            engagement_root=gate_context.engagement_root,
            repository=_Jobs(),
            apply_workspace_root=tmp_path / "apply",
        )

    assert "maxRequestBodyMb" in " ".join(caught.value.errors)


def test_tcp_udp_and_unmanaged_https_are_rejected_clearly(gate_context):
    channel = gate_context.overview["inboundChannels"][0]
    for mode, expected in (
        ("tcp-forward", "only for Barragan-managed HTTP/HTTPS"),
        ("udp-forward", "only for Barragan-managed HTTP/HTTPS"),
        ("https-openresty", "managed Static Web site"),
    ):
        channel["mode"] = mode
        with pytest.raises(InboundRequestHeaderGateValidationError) as caught:
            get_inbound_request_header_gate(
                "eng-1",
                "upload-http",
                engagement_root=gate_context.engagement_root,
            )
        assert expected in " ".join(caught.value.errors)
    channel["mode"] = "http-openresty"


def test_managed_https_site_gate_renders_sni_correct_get_and_durable_hooks(gate_context, tmp_path):
    channel = gate_context.overview["inboundChannels"][0]
    channel.update(
        {
            "mode": "https-openresty",
            "externalPort": "443",
            "service": "Static Web",
            "serviceId": "web-upload",
            "serviceType": "web-static",
            "internalPort": "18080",
        }
    )
    service = StoredEngagementService(
        engagement_id="eng-1",
        service_id="web-upload",
        service_type="web-static",
        name="upload",
        proxy_id="proxy01",
        status="Configured",
        config={
            "siteName": "upload",
            "domain": "upload.example.test",
            "internalPort": 18080,
            "stackModel": "containerized-openresty-v1",
            "composePath": "/opt/web/docker-compose.yml",
            "siteComposePath": "/opt/web/sites/upload.compose.yml",
            "stackOwnershipPath": "/opt/web/.barragan-stack.json",
            "frontProxyService": "reverse-proxy",
            "siteService": "web-upload",
            "tlsSiteService": "web-upload_tls",
            "tlsSiteConfigPath": "/opt/web/upload/tls-conf/default.conf",
        },
    )
    services = _Services([service])
    jobs = _Jobs()
    captured = {}

    def runner(command, cwd):
        captured["playbook"] = (cwd / "ansible" / "apply_request_header_gate.yml").read_text(encoding="utf-8")
        captured["rollback"] = (cwd / "ansible" / "rollback_request_header_gate.yml").read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    update_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        {
            "enabled": True,
            "headerName": "X-Access-Token",
            "tokenAction": "provide",
            "token": "https-token-123",
        },
        engagement_root=gate_context.engagement_root,
        service_repository=services,
        repository=jobs,
        runner=runner,
        apply_workspace_root=tmp_path / "apply",
        background_runner=lambda task: task(),
    )
    detail = get_inbound_request_header_gate(
        "eng-1",
        "upload-http",
        engagement_root=gate_context.engagement_root,
        service_repository=services,
    )

    assert "map $http_x_access_token $barragan_request_header_gate" in captured["playbook"]
    assert '"Bearer https-token-123" 1;' in captured["playbook"]
    assert "include /etc/nginx/conf.d/request-header-gate*.inc" in captured["playbook"]
    assert "/opt/web/upload/tls-conf:/etc/nginx/conf.d:ro" in captured["playbook"]
    assert "/opt/web/upload/tls-conf/00-request-header-gate-00-runtime.conf" in captured["playbook"]
    assert "map_hash_bucket_size 512;" not in captured["playbook"]
    assert "map_hash_bucket_size 512;" not in captured["rollback"]
    assert captured["playbook"].index("Write candidate HTTPS gate HTTP runtime") < captured["playbook"].index(
        "Write candidate HTTPS gate map"
    )
    assert "barragan_prior_gate_runtime.stat.exists" in captured["playbook"]
    assert "{{ barragan_gate_runtime_path }}.barragan-backup" in captured["playbook"]
    assert 'barragan_gate_service_name: "web-upload_tls"' in captured["playbook"]
    assert 'barragan_gate_legacy_container_name: "barragan_web-upload_tls"' in captured["playbook"]
    https_remove = 'argv: [docker, rm, -f, "{{ barragan_gate_legacy_container_name }}"]'
    https_start = (
        'argv: [docker, compose, -f, /opt/web/docker-compose.yml, -f, '
        '"{{ barragan_gate_site_compose }}", up, -d, "{{ barragan_gate_service_name }}"]'
    )
    https_label_query = (
        'argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", '
        '--filter, "label=com.docker.compose.service={{ barragan_gate_service_name }}"]'
    )
    https_id_remove = 'argv: [docker, rm, -f, "{{ item }}"]'
    assert captured["playbook"].count(https_remove) == 2
    assert captured["playbook"].count(https_label_query) == 2
    assert captured["playbook"].count(https_id_remove) == 2
    assert captured["playbook"].count(https_start) == 2
    assert "--force-recreate" not in captured["playbook"]
    assert "--remove-orphans" not in captured["playbook"]
    assert "docker, rm, -f, proxy" not in captured["playbook"]
    assert "web_{{ barragan_gate_service_name }}_1" not in captured["playbook"]
    assert captured["playbook"].index("Write candidate HTTPS gate server hook") < captured["playbook"].index(
        "Remove only the selected HTTPS site container before candidate start"
    )
    assert captured["playbook"].index(
        "Remove only the selected HTTPS site container before candidate start"
    ) < captured["playbook"].index("Find renamed selected HTTPS site Compose containers for candidate start")
    assert captured["playbook"].index(
        "Find renamed selected HTTPS site Compose containers for candidate start"
    ) < captured["playbook"].index("Remove renamed selected HTTPS site Compose containers for candidate start")
    assert captured["playbook"].index(
        "Remove renamed selected HTTPS site Compose containers for candidate start"
    ) < captured["playbook"].index("Start selected HTTPS site with candidate gate mounts")
    assert captured["playbook"].index("Start selected HTTPS site with candidate gate mounts") < captured[
        "playbook"
    ].index("Find running selected HTTPS site container for candidate gate")
    assert captured["playbook"].index("Find running selected HTTPS site container for candidate gate") < captured[
        "playbook"
    ].index("Validate candidate HTTPS gate")
    assert captured["playbook"].index("Restore selected site and compose files") < captured["playbook"].index(
        "Remove only the selected HTTPS site container before restored start"
    )
    assert captured["playbook"].index(
        "Remove only the selected HTTPS site container before restored start"
    ) < captured["playbook"].index("Find renamed selected HTTPS site Compose containers for restored start")
    assert captured["playbook"].index(
        "Find renamed selected HTTPS site Compose containers for restored start"
    ) < captured["playbook"].index("Remove renamed selected HTTPS site Compose containers for restored start")
    assert captured["playbook"].index(
        "Remove renamed selected HTTPS site Compose containers for restored start"
    ) < captured["playbook"].index("Start restored selected HTTPS site")
    assert captured["playbook"].index("Start restored selected HTTPS site") < captured["playbook"].index(
        "Find running restored HTTPS site container"
    )
    assert captured["playbook"].index("Find running restored HTTPS site container") < captured["playbook"].index(
        "Validate restored selected HTTPS site"
    )
    assert 'argv: [docker, exec, "{{ barragan_https_gate_candidate_container_id }}", openresty, -t]' in captured[
        "playbook"
    ]
    assert detail["authorizedRequest"]["curl"] == (
        "curl --include --request GET \\\n"
        "  --resolve upload.example.test:443:198.51.100.30 \\\n"
        "  --header 'X-Access-Token: Bearer https-token-123' \\\n"
        "  https://upload.example.test/"
    )
    payload = json.dumps([job.to_detail().to_dict() for job in jobs.jobs], sort_keys=True)
    assert "https-token-123" not in payload


def test_inbound_reapply_renderer_preserves_active_gate():
    spec = InboundChannelArtifactSpec(
        engagement="zy01",
        channel_id="upload-http",
        domain="upload.example.test",
        protocol="TCP",
        external_port=80,
        edge_hostname="edge01-zy01",
        middle_hostname="middle01-zy01",
        proxy_hostname="proxy01-zy01",
        terminates_on="homebase-zy01",
        service="Go Simple Upload Server",
        internal_port=9999,
        purpose="Uploads",
        mode="http-openresty",
    )
    artifacts = render_inbound_channel_artifacts(spec)
    workspace = render_inbound_apply_workspace(
        spec,
        artifacts,
        request_header_gate={
            "enabled": True,
            "headerName": "Authorization",
            "token": "reapply-token-123",
            "updatedAt": "now",
            "maxRequestBodyMb": 640,
        },
    )
    playbook = next(item.content for item in workspace.playbooks if item.target.endswith("apply_inbound_channel.yml"))

    assert '"Bearer reapply-token-123" 1;' in playbook
    assert "client_max_body_size 640000000;" in playbook
    assert "client_max_body_size 10240000000;" in playbook
    assert "proxy_request_buffering off;" in playbook
    assert "return 404;" in playbook
