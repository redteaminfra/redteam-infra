# Copyright (c) 2026, Oracle and/or its affiliates.
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from app.domain import JobEvent
from app.storage.domain_repository import SqlAlchemyDomainRepository, StoredDomainAsset, StoredDomainAssignment
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository, StoredEngagementService
from app.storage.certificate_repository import SqlAlchemyCertificateRepository, StoredCertificateBinding
from app.services.certificate_manager import CertificateManagerValidationError, _finish_certificate_binding, _resolve_certbot_bin, bind_certificate_to_channel, start_certificate_issue, start_certificate_reissue, start_certificate_renew, start_certificate_revoke


NOW = "2026-06-29T12:00:00+00:00"


def test_static_tls_docker_go_templates_survive_ansible_jinja_rendering(client, tmp_path):
    import yaml
    from types import SimpleNamespace
    from jinja2 import Environment, StrictUndefined
    from app.services.certificate_manager import (
        CertificateCoreHost, _write_binding_workspace, _write_unbinding_workspace,
    )
    _service(client, 'eng-fixture')
    with client.application.storage_context():
        service = SqlAlchemyEngagementServiceRepository().get('eng-fixture', 'web-static-example')
    asset = SimpleNamespace(id='cert-fixture', target_proxy_id='proxy01')
    binding = SimpleNamespace(id='binding-fixture', hostname='example.com',
                              certificate_id=asset.id, channel_id='channel-fixture')
    proxy = CertificateCoreHost('proxy01', '192.168.2.11', 'user', '/keys/core',
                                'user@203.0.113.10', '/tmp/known_hosts')
    workspaces = [
        (_write_binding_workspace(tmp_path, asset, binding, service, proxy), 'activate'),
        (_write_unbinding_workspace(tmp_path, binding, service, proxy), 'deactivate')]
    environment = Environment(undefined=StrictUndefined)
    for workspace, action in workspaces:
        playbook = yaml.safe_load((workspace / 'ansible' / f'{action}_certificate_binding.yml').read_text())
        commands = []
        def visit(value):
            if isinstance(value, dict):
                argv = value.get('ansible.builtin.command', {}).get('argv')
                if isinstance(argv, list) and argv[:3] == ['docker', 'inspect', '-f']:
                    commands.append(argv)
                for child in value.values(): visit(child)
            elif isinstance(value, list):
                for child in value: visit(child)
        visit(playbook)
        assert len(commands) == 2  # before mutation and rollback verification
        for argv in commands:
            assert environment.from_string(argv[3]).render() == '{{.State.Running}}'
            assert environment.from_string(argv[4]).render() == 'barragan_web_static_example_tls'


def test_certbot_resolution_uses_running_virtualenv_when_path_is_minimal(monkeypatch):
    monkeypatch.setattr("app.services.certificate_manager.shutil.which", lambda _name: None)

    resolved = _resolve_certbot_bin({})

    assert resolved == str(Path(__import__("sys").executable).parent / "certbot")


def test_failed_rebind_restores_the_prior_persisted_binding(tmp_path):
    previous = StoredCertificateBinding(
        id="certbind-1", engagement_id="eng-1", certificate_id="cert-old",
        service_id="web-example", channel_id="https-old", hostname="example.test",
        status="bound", validation={"status": "ok"}, last_job_id="job-old",
    )
    pending = StoredCertificateBinding(
        id="certbind-1", engagement_id="eng-1", certificate_id="cert-new",
        service_id="web-example", channel_id="https-new", hostname="example.test",
        status="activating", validation={"status": "pending"}, last_job_id="job-new",
    )

    class Bindings:
        current = pending

        def get_binding_for_service(self, _engagement_id, _service_id):
            return self.current

        def save_binding(self, binding):
            self.current = binding
            return binding

    class Jobs:
        current = StoredJobRun(
            id="job-new", action="certificate_asset_bind", status="running",
            target="certificate-binding:certbind-1", target_type="certificate_binding",
            target_id="certbind-1", requested_by="operator", input={}, artifact_refs=[],
            created_at=NOW, started_at=NOW, finished_at=None, events=[],
        )

        def get(self, _job_id):
            return self.current

        def save(self, job):
            self.current = job
            return job

    bindings = Bindings()
    jobs = Jobs()
    _finish_certificate_binding(
        bindings, jobs, pending, previous, "job-new", tmp_path, ["ansible-playbook"],
        lambda command, cwd: subprocess.CompletedProcess(command, 2, stdout="", stderr="activation failed"),
    )

    assert bindings.current == previous
    assert jobs.current.status == "failed"


def test_certificate_inventory_supports_wildcard_and_channel_binding(client):
    engagement_id = _engagement(client)
    _domain(client, engagement_id, "example.com")
    _operations(client, engagement_id)
    _service(client, engagement_id)

    profile = client.patch(
        f"/api/engagements/{engagement_id}/certificate-profile",
        json={"acmeEmail": "operator@example.com", "defaultEnvironment": "staging"},
    )
    created = client.post(
        f"/api/engagements/{engagement_id}/certificates",
        json={
            "name": "Example wildcard",
            "source": "self-signed",
            "targetProxyId": "proxy01-zy01",
            "identifiers": ["example.com", "*.example.com"],
            "notes": "Used by campaign landing pages.",
        },
    )

    assert profile.status_code == 200
    assert created.status_code == 201
    asset = created.get_json()["certificate"]
    assert asset["identifiers"] == ["example.com", "*.example.com"]
    assert asset["notes"] == "Used by campaign landing pages."
    assert asset["status"] == "draft"

    # Draft assets are not eligible until issuance creates an active version.
    workspace = client.get(
        f"/api/engagements/{engagement_id}/inbound-channels/edge-zy01-443-to-proxy01-18080/certificate-binding"
    ).get_json()
    assert workspace["tlsStatus"] == "unbound"
    assert workspace["candidates"] == []


def test_certificate_notes_are_mutable_metadata_only(client):
    engagement_id = _engagement(client)
    _domain(client, engagement_id, "example.com")
    _operations(client, engagement_id)

    created = client.post(
        f"/api/engagements/{engagement_id}/certificates",
        json={
            "name": "Notes test",
            "source": "self-signed",
            "targetProxyId": "proxy01-zy01",
            "identifiers": ["example.com"],
            "notes": "Initial purpose",
        },
    )
    certificate_id = created.get_json()["certificate"]["id"]

    updated = client.patch(
        f"/api/engagements/{engagement_id}/certificates/{certificate_id}",
        json={"notes": "Updated purpose and owner"},
    )
    rejected = client.patch(
        f"/api/engagements/{engagement_id}/certificates/{certificate_id}",
        json={"name": "New name"},
    )

    assert updated.status_code == 200
    assert updated.get_json()["certificate"]["notes"] == "Updated purpose and owner"
    assert rejected.status_code == 400
    assert "unsupported certificate metadata fields" in rejected.get_json()["errors"][0]


def test_external_public_certificate_is_metadata_only_and_bindable(client):
    engagement_id = _engagement(client)
    _domain(client, engagement_id, "example.com")
    _operations(client, engagement_id)
    _service(client, engagement_id)
    pem = _public_certificate(["example.com", "*.example.com"])

    response = client.post(
        f"/api/engagements/{engagement_id}/certificates",
        json={
            "name": "External wildcard",
            "source": "external",
            "targetProxyId": "proxy01-zy01",
            "identifiers": ["example.com", "*.example.com"],
            "certificatePem": pem,
        },
    )

    assert response.status_code == 201
    asset = response.get_json()["certificate"]
    assert asset["status"] == "active"
    assert asset["currentVersion"]["fingerprintSha256"]
    assert "certificatePem" not in str(asset)
    assert asset["currentVersion"]["paths"] == {}

    bound = client.patch(
        f"/api/engagements/{engagement_id}/inbound-channels/edge-zy01-443-to-proxy01-18080/certificate-binding",
        json={"certificateId": asset["id"]},
    )
    assert bound.status_code == 200
    assert bound.get_json()["tlsStatus"] == "expected_external"


def test_certificate_rejects_cross_proxy_and_unassigned_identifiers(client):
    engagement_id = _engagement(client)
    _domain(client, engagement_id, "example.com")
    _operations(client, engagement_id)

    unassigned = client.post(
        f"/api/engagements/{engagement_id}/certificates",
        json={"name": "Bad", "source": "letsencrypt", "targetProxyId": "proxy01-zy01", "identifiers": ["other.invalid"]},
    )
    unknown_proxy = client.post(
        f"/api/engagements/{engagement_id}/certificates",
        json={"name": "Bad proxy", "source": "letsencrypt", "targetProxyId": "proxy02-zy01", "identifiers": ["example.com"]},
    )

    assert unassigned.status_code == 400
    assert "active engagement domain assignment" in unassigned.get_json()["errors"][0]
    assert unknown_proxy.status_code == 400
    assert "active proxy" in unknown_proxy.get_json()["errors"][0]


def test_managed_lifecycle_reuses_key_on_renew_rotates_on_reissue_and_keeps_revoked_binding(client, tmp_path):
    engagement_id = _engagement(client)
    _domain(client, engagement_id, "example.com")
    _operations(client, engagement_id)
    _service(client, engagement_id)
    client.patch(f"/api/engagements/{engagement_id}/certificate-profile", json={"acmeEmail": "operator@example.com", "defaultEnvironment": "production"})
    asset = client.post(f"/api/engagements/{engagement_id}/certificates", json={
        "name": "Managed wildcard", "source": "letsencrypt", "targetProxyId": "proxy01-zy01",
        "identifiers": ["example.com", "*.example.com"],
    }).get_json()["certificate"]

    def runner(command: list[str], cwd: Path | None):
        assert cwd is not None
        if command[-1].endswith("prepare_certificate_csr.yml"):
            (cwd / "csr.pem").write_text("test csr")
        if "certonly" in command:
            pem = _public_certificate(["example.com", "*.example.com"])
            (cwd / "cert.pem").write_text(pem)
            (cwd / "fullchain.pem").write_text(pem)
        if command[-1].endswith("fetch_public_certificate.yml"):
            (cwd / "cert.pem").write_text(_public_certificate(["example.com", "*.example.com"]))
        if command[-1].endswith("activate_certificate_binding.yml"):
            playbook = (cwd / "ansible" / "activate_certificate_binding.yml").read_text()
            assert "/opt/web/example/conf/default.conf" not in playbook
            assert "/opt/web/example/tls-conf/default.conf" in playbook
            assert "/opt/web/tls/example.map" in playbook
            assert "web_static_example_tls:8081" in playbook
            assert "'up', '-d', 'web_static_example_tls'" in playbook
            assert "--force-recreate" not in playbook
            assert "Detect Docker Compose v1 fallback" in playbook
            assert "docker, exec, proxy, openresty, -t" in playbook
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    ansible = tmp_path / "ansible-playbook"
    ansible.write_text("#!/bin/sh\nexit 0\n")
    ansible.chmod(0o700)
    kwargs = {"runner": runner, "background_runner": lambda work: work(), "env": {"ANSIBLE_PLAYBOOK_BIN": str(ansible), "CERTBOT_BIN": "/bin/true"}, "workspace_root": tmp_path}
    with client.application.storage_context():
        issued = start_certificate_issue(engagement_id, asset["id"], {}, **kwargs)
        assert issued
        stored = SqlAlchemyCertificateRepository()
        active = stored.get_asset(engagement_id, asset["id"])
        assert active and active.status == "active"
        first = stored.get_version(active.current_version_id).to_dict()
        with pytest.raises(CertificateManagerValidationError) as renew_error:
            start_certificate_renew(engagement_id, asset["id"], {"productionConfirmation": "wrong"}, **kwargs)
        assert "productionConfirmation must equal" in renew_error.value.errors[0]
        renewed = start_certificate_renew(engagement_id, asset["id"], {
            "productionConfirmation": asset["productionConfirmations"]["renew"],
        }, **kwargs)
        assert renewed
        active = stored.get_asset(engagement_id, asset["id"])
        assert stored.get_version(active.current_version_id).key_generation == first["keyGeneration"]
        with pytest.raises(CertificateManagerValidationError) as reissue_error:
            start_certificate_reissue(engagement_id, asset["id"], {}, **kwargs)
        assert "productionConfirmation must equal" in reissue_error.value.errors[0]
        reissued = start_certificate_reissue(engagement_id, asset["id"], {
            "productionConfirmation": asset["productionConfirmations"]["reissue"],
        }, **kwargs)
        assert reissued
        active = stored.get_asset(engagement_id, asset["id"])
        assert stored.get_version(active.current_version_id).key_generation == first["keyGeneration"] + 1

    with client.application.storage_context():
        bound = bind_certificate_to_channel(engagement_id, "edge-zy01-443-to-proxy01-18080", asset["id"], **kwargs)
        assert bound and bound["tlsStatus"] == "bound"
        assert bound["job"]["action"] == "certificate_asset_bind"
        assert bound["job"]["status"] == "succeeded"
        with pytest.raises(CertificateManagerValidationError) as revoke_error:
            start_certificate_revoke(engagement_id, asset["id"], {"productionConfirmation": "wrong"}, **kwargs)
        assert "productionConfirmation must equal" in revoke_error.value.errors[0]
        revoked = start_certificate_revoke(engagement_id, asset["id"], {
            "productionConfirmation": asset["productionConfirmations"]["revoke"],
        }, **kwargs)
        assert revoked and SqlAlchemyCertificateRepository().get_asset(engagement_id, asset["id"]).status == "revoked"
    binding = client.get(f"/api/engagements/{engagement_id}/inbound-channels/edge-zy01-443-to-proxy01-18080/certificate-binding").get_json()
    assert binding["binding"]["certificateId"] == asset["id"]
    assert binding["tlsStatus"] == "critical_revoked"


def _engagement(client) -> str:
    response = client.post("/api/engagements", json={"name": "ZY01", "owner": "operator"})
    assert response.status_code == 201
    return response.get_json()["engagement"]["id"]


def _domain(client, engagement_id: str, name: str):
    with client.application.storage_context():
        repo = SqlAlchemyDomainRepository()
        asset = repo.save_asset(StoredDomainAsset(
            id=f"domain-{name.replace('.', '-')}", domain_name=name, registrar="namecheap",
            registration_started_at="", expiration_at="2027-01-01T00:00:00+00:00", auto_renew=True,
            provider_status="active", notes="", risk_status="clear", risk_flags=[], cooldown_until="",
            assignable_override=False, catalog_state="auto", metadata={}, last_synced_at=NOW, created_at=NOW, updated_at=NOW,
        ))
        repo.save_assignment(StoredDomainAssignment(
            id=None, domain_id=asset.id, engagement_id=engagement_id, engagement_name="ZY01", purpose="website",
            status="active", notes="", assigned_by="operator", released_by="", assigned_at=NOW,
            released_at=None, purpose_tags=["website"],
        ))


def _operations(client, engagement_id: str):
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(StoredJobRun(
            id="job-certificate-manager-ops", action="pilot_standard_rti_guarded_execute", status="succeeded",
            target=f"engagement:{engagement_id}", target_type="engagement", target_id=engagement_id,
            requested_by="operator", input={"engagementId": engagement_id}, artifact_refs=[],
            created_at=NOW, started_at=NOW, finished_at=NOW,
            events=[JobEvent(1, "info", "operations ready", {
                "connectionDetails": [
                    {"role": "homebase", "displayName": "homebase-zy01", "publicIp": "203.0.113.10", "privateIp": "192.168.0.10", "sshUser": "user"},
                    {"role": "proxy", "displayName": "proxy01-zy01", "publicIp": "203.0.113.11", "privateIp": "192.168.2.11", "sshUser": "user"},
                ],
                "coreInfrastructure": [
                    {"hostname": "homebase-zy01", "role": "homebase", "status": "deployed", "publicIp": "203.0.113.10"},
                    {"hostname": "proxy01-zy01", "role": "proxy", "status": "deployed", "publicIp": "203.0.113.11"},
                ],
                "sketchInfrastructure": [],
                "inboundChannels": [{
                    "channelId": "edge-zy01-443-to-proxy01-18080", "domain": "example.com", "protocol": "HTTPS",
                    "mode": "https-openresty", "externalPort": "443", "proxy": "proxy01-zy01",
                    "service": "Static Web", "serviceId": "web-static-example", "serviceType": "web-static",
                    "internalPort": "18080", "status": "Applied",
                }],
                "outboundChannels": [],
            })],
        ))


def _service(client, engagement_id: str):
    with client.application.storage_context():
        SqlAlchemyEngagementServiceRepository().save(StoredEngagementService(
            engagement_id=engagement_id, service_id="web-static-example", service_type="web-static",
            name="Example", proxy_id="proxy01", status="Configured",
            config={"siteName": "example", "domain": "example.com", "stackModel": "containerized-openresty-v1", "composePath": "/opt/web/docker-compose.yml", "siteComposePath": "/opt/web/sites/example.compose.yml", "stackOwnershipPath": "/opt/web/.barragan-stack.json", "frontProxyService": "reverse-proxy", "siteService": "web_static_example", "tlsSiteService": "web_static_example_tls", "tlsSiteConfigPath": "/opt/web/example/tls-conf/default.conf", "httpRoutePath": "/opt/web/http/example.map", "tlsRoutePath": "/opt/web/tls/example.map"},
        ))


def _public_certificate(names: list[str]) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "External CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.PEM).decode()
