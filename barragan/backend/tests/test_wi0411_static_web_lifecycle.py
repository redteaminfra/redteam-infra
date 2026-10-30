# Copyright (c) 2026, Oracle and/or its affiliates.
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from app.services.certificate_manager import _write_binding_workspace, _write_unbinding_workspace
from app.services.inbound_channel_certificate import CertificateCoreHost
from app.services.web_static_service import (
    WebStaticCoreHost,
    _intent_from_body,
    render_web_static_apply_workspace,
    render_web_static_remove_workspace,
)
from app.storage.certificate_repository import StoredCertificateAsset, StoredCertificateBinding


class FakeComposeOpenRestyRuntime:
    """Execute the selected-container semantics emitted by WI-0411 workspaces."""

    def __init__(self):
        self.files = {}
        self.containers = {}
        self.http_gate = "http-gate"
        self.https_gate = "https-gate"
        self.fingerprints = {}

    def _replace(self, service, protocol):
        assert service not in self.containers, "Compose v1 requires selected-container removal"
        self.containers[service] = {"running": True, "protocol": protocol}

    def apply(self, workspace, *, fail_after_remove=False):
        before = deepcopy((self.files, self.containers, self.http_gate, self.https_gate))
        playbook = workspace.playbook.content
        assert "--force-recreate" not in playbook
        assert "docker-compose" in playbook
        service = workspace.front_route.content.split()[1].split(":")[0]
        self.files[workspace.site_config.target] = workspace.site_config.content
        self.files[workspace.front_route.target] = workspace.front_route.content
        self.files[workspace.site_index.target] = workspace.site_index.content
        self.containers.pop(service, None)
        if fail_after_remove:
            self.files, self.containers, self.http_gate, self.https_gate = before
            raise RuntimeError("remote OpenResty validation failed")
        self._replace(service, "http")

    def bind(self, workspace, binding, asset, *, fail_mid_activation=False):
        before = deepcopy((self.files, self.containers, self.http_gate, self.https_gate))
        playbook = (workspace / "ansible/activate_certificate_binding.yml").read_text()
        assert "--force-recreate" not in playbook
        assert "label=com.docker.compose.service=web_ff10_tls" in playbook
        self.containers.pop("web_ff10_tls", None)
        self.files["tls-route"] = f"{binding.hostname} web_ff10_tls:8081;\n"
        self.files["tls-config"] = asset.id
        if fail_mid_activation:
            self.files, self.containers, self.http_gate, self.https_gate = before
            raise RuntimeError("remote TLS activation failed")
        self._replace("web_ff10_tls", "https")
        self.fingerprints[binding.hostname] = f"sha256:{asset.id}"

    def unbind(self, workspace, hostname):
        playbook = (workspace / "ansible/deactivate_certificate_binding.yml").read_text()
        assert "--force-recreate" not in playbook
        self.containers.pop("web_ff10_tls", None)
        self.files.pop("tls-route", None)
        self.files.pop("tls-config", None)
        self.fingerprints.pop(hostname, None)

    def http_probe(self):
        assert self.containers["web_ff10"]["running"]
        return 200, self.http_gate

    def tls_probe(self, hostname):
        assert self.containers["web_ff10_tls"]["running"]
        return 200, self.https_gate, self.fingerprints[hostname]


def test_executable_static_web_dual_protocol_lifecycle_matrix(tmp_path: Path):
    intent = _intent_from_body("zy01", {"siteName": "ff10", "domain": "ff10.example.test", "proxyId": "proxy01"})
    homebase = WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known")
    proxy = WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known")
    apply = render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy)
    service = intent.to_service("eng-1", status="Configured")
    cert_proxy = CertificateCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known")
    runtime = FakeComposeOpenRestyRuntime()

    runtime.apply(apply)
    assert runtime.http_probe() == (200, "http-gate")

    first = StoredCertificateAsset(id="cert-a", engagement_id="eng-1", name="a", source="letsencrypt", target_proxy_id="proxy01", identifiers=(intent.domain,), primary_identifier=intent.domain, status="active")
    binding = StoredCertificateBinding(id="binding-1", engagement_id="eng-1", certificate_id=first.id, service_id=intent.service_id, channel_id="https-1", hostname=intent.domain, status="bound")
    runtime.bind(_write_binding_workspace(tmp_path, first, binding, service, cert_proxy), binding, first)
    assert runtime.http_probe() == (200, "http-gate")
    assert runtime.tls_probe(intent.domain) == (200, "https-gate", "sha256:cert-a")

    second = StoredCertificateAsset(id="cert-b", engagement_id="eng-1", name="b", source="letsencrypt", target_proxy_id="proxy01", identifiers=(intent.domain,), primary_identifier=intent.domain, status="active")
    rebound = replace(binding, certificate_id=second.id)
    with pytest.raises(RuntimeError):
        runtime.bind(_write_binding_workspace(tmp_path, second, rebound, service, cert_proxy, previous_binding=binding), rebound, second, fail_mid_activation=True)
    assert runtime.http_probe() == (200, "http-gate")
    assert runtime.tls_probe(intent.domain) == (200, "https-gate", "sha256:cert-a")
    runtime.bind(_write_binding_workspace(tmp_path, second, rebound, service, cert_proxy, previous_binding=binding), rebound, second)
    assert runtime.tls_probe(intent.domain) == (200, "https-gate", "sha256:cert-b")

    runtime.apply(apply)
    assert runtime.http_probe() == (200, "http-gate")
    assert runtime.tls_probe(intent.domain) == (200, "https-gate", "sha256:cert-b")
    runtime.unbind(_write_unbinding_workspace(tmp_path, rebound, service, cert_proxy), intent.domain)
    assert runtime.http_probe() == (200, "http-gate")
    assert "web_ff10_tls" not in runtime.containers

    remove = render_web_static_remove_workspace(intent=intent, homebase=homebase, proxy=proxy)
    assert "/opt/web/http/ff10.map" in remove.playbook.content
    runtime.containers.pop("web_ff10")
    assert runtime.https_gate == "https-gate"
