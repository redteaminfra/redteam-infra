# Copyright (c) 2026, Oracle and/or its affiliates.
import base64
from pathlib import Path
import re
import subprocess

from app.services.certificate_manager import (
    _http_backend_transition_command,
    _write_binding_workspace,
    _write_unbinding_workspace,
)
from app.services.inbound_channel_certificate import CertificateCoreHost, _write_dns01_workspace
from app.services.inbound_request_header_gate import render_http_backend_site_config
from app.services.managed_site_observability import render_managed_site_observability_config
from app.services.shared_proxy_stack import SHARED_PROXY_STACK_MUTATION_ACTIONS
from app.storage.certificate_repository import StoredCertificateAsset, StoredCertificateBinding
from app.storage.service_repository import StoredEngagementService


def _service() -> StoredEngagementService:
    return StoredEngagementService(
        engagement_id="eng-1",
        service_id="web-upload",
        service_type="web-static",
        name="upload",
        proxy_id="proxy01",
        status="Configured",
        config={
            "siteName": "upload",
            "domain": "upload.example.test",
            "stackModel": "containerized-openresty-v1",
            "siteComposePath": "/opt/web/sites/upload.compose.yml",
            "siteService": "web_upload",
            "tlsSiteService": "web_upload_tls",
            "tlsSiteConfigPath": "/opt/web/upload/tls-conf/default.conf",
            "tlsRoutePath": "/opt/web/tls/upload.map",
            "composePath": "/opt/web/docker-compose.yml",
            "stackOwnershipPath": "/opt/web/.barragan-stack.json",
        },
    )


def _proxy() -> CertificateCoreHost:
    return CertificateCoreHost(
        "proxy01-eng1",
        "192.0.2.11",
        "user",
        "/keys/core",
        "user@203.0.113.10",
        "/tmp/known-hosts",
    )


def _http_backend_service() -> StoredEngagementService:
    return StoredEngagementService(
        engagement_id="eng-1",
        service_id="http-site-upload",
        service_type="web-http-backend",
        name="upload backend site",
        proxy_id="proxy01",
        status="Configured",
        config={
            "siteName": "upload",
            "domain": "upload.example.test",
            "siteComposePath": "/opt/web/sites/upload.compose.yml",
            "siteService": "barragan-inbound-upload",
            "siteConfigPath": "/opt/web/inbound/upload/conf/default.conf",
            "unboundConfigPath": "/opt/web/inbound/upload/conf/default.conf.barragan-unbound",
            "composePath": "/opt/web/docker-compose.yml",
            "stackOwnershipPath": "/opt/web/.barragan-stack.json",
            "stackModel": "containerized-openresty-v1",
        },
    )


def test_certificate_bind_and_unbind_preserve_plaintext_site_and_optional_gate_hook(tmp_path: Path):
    asset = StoredCertificateAsset(
        id="cert-1",
        engagement_id="eng-1",
        name="upload",
        source="letsencrypt",
        target_proxy_id="proxy01-eng1",
        identifiers=("upload.example.test",),
        primary_identifier="upload.example.test",
        status="active",
    )
    binding = StoredCertificateBinding(
        id="binding-1",
        engagement_id="eng-1",
        certificate_id=asset.id,
        service_id="web-upload",
        channel_id="upload-https",
        hostname="upload.example.test",
    )

    bind = _write_binding_workspace(tmp_path, asset, binding, _service(), _proxy())
    unbind = _write_unbinding_workspace(tmp_path, binding, _service(), _proxy())
    bind_playbook = (bind / "ansible" / "activate_certificate_binding.yml").read_text(encoding="utf-8")
    unbind_playbook = (unbind / "ansible" / "deactivate_certificate_binding.yml").read_text(encoding="utf-8")

    assert "include /etc/nginx/conf.d/request-header-gate*.inc;" in bind_playbook
    assert "include /etc/nginx/conf.d/request-header-gate.inc;" not in bind_playbook
    assert "/opt/web/upload/conf/default.conf" not in bind_playbook
    assert "/opt/web/upload/conf/default.conf" not in unbind_playbook
    assert "web_upload_tls" in bind_playbook
    assert "web_upload_tls" in unbind_playbook
    assert "Activate only the selected TLS sibling transactionally" in bind_playbook
    assert "TLS sibling activation failed after verified restoration" in bind_playbook
    assert "Deactivate only the selected TLS sibling transactionally" in unbind_playbook
    assert "TLS sibling deactivation failed after verified restoration" in unbind_playbook
    assert "/opt/web/http/upload.map" not in unbind_playbook
    assert "/opt/web/upload/conf/00-request-header-gate" not in bind_playbook
    assert "/opt/web/upload/tls-conf/00-request-header-gate" in bind_playbook
    for playbook in (bind_playbook, unbind_playbook):
        assert playbook.index("Detect Docker Compose v2") < playbook.index("Detect Docker Compose v1 fallback")
        assert "when: barragan_compose_v2.rc != 0" in playbook
        assert "barragan_compose_argv +" in playbook
        assert "Verify exact Barragan shared-stack ownership" in playbook
        assert "--force-recreate" not in playbook
        assert "label=com.docker.compose.project=web" in bind_playbook
    assert "Require exact prior selected TLS container state" in bind_playbook
    assert "Require exact prior selected TLS container state" in unbind_playbook


def test_static_web_rebind_and_unbind_preflight_exact_channel_and_certificate_lineage(tmp_path: Path):
    previous = StoredCertificateBinding(
        id="binding-1",
        engagement_id="eng-1",
        certificate_id="cert-old",
        service_id="web-upload",
        channel_id="upload-https-old",
        hostname="upload.example.test",
        status="bound",
    )
    replacement = StoredCertificateBinding(
        id="binding-1",
        engagement_id="eng-1",
        certificate_id="cert-new",
        service_id="web-upload",
        channel_id="upload-https-new",
        hostname="upload.example.test",
        status="activating",
    )
    asset = StoredCertificateAsset(
        id="cert-new",
        engagement_id="eng-1",
        name="upload replacement",
        source="letsencrypt",
        target_proxy_id="proxy01-eng1",
        identifiers=("upload.example.test",),
        primary_identifier="upload.example.test",
        status="active",
    )

    bind = _write_binding_workspace(
        tmp_path, asset, replacement, _service(), _proxy(), previous_binding=previous
    )
    unbind = _write_unbinding_workspace(tmp_path, previous, _service(), _proxy())
    bind_playbook = (bind / "ansible" / "activate_certificate_binding.yml").read_text(encoding="utf-8")
    unbind_playbook = (unbind / "ansible" / "deactivate_certificate_binding.yml").read_text(encoding="utf-8")

    def decoded_preflights(playbook: str) -> str:
        return "\n".join(
            base64.b64decode(value).decode("utf-8")
            for value in re.findall(r"base64\.b64decode\('([A-Za-z0-9+/=]+)'\)", playbook)
        )

    bind_preflight = decoded_preflights(bind_playbook)
    unbind_preflight = decoded_preflights(unbind_playbook)
    assert "previous_live='/etc/letsencrypt/live/barragan/cert-old/current'" in bind_preflight
    assert "upload.example.test web_upload_tls:8081;" in bind_preflight
    assert "cert-new/current" not in bind_preflight
    assert "/etc/letsencrypt/live/barragan/cert-old/current/fullchain.pem" in unbind_preflight
    assert "TLS route does not match the exact bound channel" in unbind_preflight
    assert "Verify exact persisted TLS binding lineage before mutation" in bind_playbook
    assert "Verify exact bound TLS runtime before mutation" in unbind_playbook


def test_certificate_binding_overlays_a_managed_http_backend_without_replacing_its_route(tmp_path: Path):
    asset = StoredCertificateAsset(
        id="cert-1",
        engagement_id="eng-1",
        name="upload",
        source="letsencrypt",
        target_proxy_id="proxy01-eng1",
        identifiers=("upload.example.test",),
        primary_identifier="upload.example.test",
        status="active",
    )
    binding = StoredCertificateBinding(
        id="binding-1",
        engagement_id="eng-1",
        certificate_id=asset.id,
        service_id="http-site-upload",
        channel_id="upload-https",
        hostname="upload.example.test",
    )

    bind = _write_binding_workspace(tmp_path, asset, binding, _http_backend_service(), _proxy())
    unbind = _write_unbinding_workspace(tmp_path, binding, _http_backend_service(), _proxy())
    bind_playbook = (bind / "ansible" / "activate_certificate_binding.yml").read_text(encoding="utf-8")
    unbind_playbook = (unbind / "ansible" / "deactivate_certificate_binding.yml").read_text(encoding="utf-8")

    assert "root /var/www/html/upload" not in bind_playbook
    assert "try_files $uri" not in bind_playbook
    assert "/opt/web/inbound/upload/conf/default.conf" in bind_playbook
    assert "default.conf.barragan-unbound" in bind_playbook
    assert "base64.b64decode" in bind_playbook
    assert "Restrict generated managed backend configurations" in bind_playbook
    assert "path: \"{{ item }}\"" in bind_playbook
    assert "owner: root" in bind_playbook
    assert "group: redteam" in bind_playbook
    assert 'mode: "0640"' in bind_playbook
    assert "- /opt/web/inbound/upload/conf/default.conf.barragan-unbound" in bind_playbook
    assert "- /opt/web/inbound/upload/conf/default.conf.barragan-tls-candidate" in bind_playbook
    assert "default.conf.barragan-unbound" in unbind_playbook


def test_http_backend_tls_transition_handles_fresh_and_legacy_unbound_configs(tmp_path: Path):
    http_config = render_http_backend_site_config("192.168.0.10", 9999)
    http_observability = render_managed_site_observability_config(receives_proxy_protocol=False).rstrip()
    tls_observability = render_managed_site_observability_config(receives_proxy_protocol=True).rstrip()

    def transition(mode: str, source: Path, destination: Path) -> str:
        command = _http_backend_transition_command(
            mode=mode,
            source=str(source),
            destination=str(destination),
            live="/tmp/certificate",
        )
        subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return destination.read_text(encoding="utf-8")

    fresh = tmp_path / "fresh.conf"
    fresh.write_text(http_config, encoding="utf-8")
    assert transition("unbound", fresh, tmp_path / "fresh-unbound.conf") == http_config
    fresh_tls = transition("tls", fresh, tmp_path / "fresh-tls.conf")
    assert "listen 8081 proxy_protocol ssl;" in fresh_tls
    assert tls_observability in fresh_tls
    assert http_observability not in fresh_tls

    legacy = tmp_path / "legacy.conf"
    legacy.write_text(
        http_config.replace("listen 8081;", "listen 8081 proxy_protocol;").replace(http_observability, tls_observability),
        encoding="utf-8",
    )
    assert transition("unbound", legacy, tmp_path / "legacy-unbound.conf") == http_config
    legacy_tls = transition("tls", legacy, tmp_path / "legacy-tls.conf")
    assert "listen 8081 proxy_protocol ssl;" in legacy_tls
    assert tls_observability in legacy_tls


def test_dns01_deploy_keeps_optional_gate_hook_and_certificate_actions_share_mutex(tmp_path: Path):
    workspace = _write_dns01_workspace(
        tmp_path,
        "eng-1",
        "upload-https",
        _proxy(),
        "upload.example.test",
        "operator@example.test",
        "staging",
        {
            "composePath": "/opt/web/docker-compose.yml",
            "siteComposePath": "/opt/web/sites/upload.compose.yml",
            "ownershipPath": "/opt/web/.barragan-stack.json",
            "frontProxyService": "reverse-proxy",
            "siteService": "web_upload",
            "siteName": "upload",
        },
    )
    deploy = (workspace / "ansible" / "deploy_dns01_certificate.yml").read_text(encoding="utf-8")

    assert "include /etc/nginx/conf.d/request-header-gate*.inc;" in deploy
    assert {
        "certificate_asset_bind",
        "certificate_asset_unbind",
        "inbound_channel_certificate_issue",
        "inbound_channel_certificate_renew",
        "inbound_channel_certificate_revoke",
    }.issubset(SHARED_PROXY_STACK_MUTATION_ACTIONS)
