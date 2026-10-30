# Copyright (c) 2026, Oracle and/or its affiliates.
from app.domain import JobEvent
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

import pytest

from app.services.inbound_channel_certificate import (
    _parse_certificate_evidence,
    _sanitize_output,
    auto_configure_http01_channel,
    certificate_workspace,
    issue_certificate,
    renew_certificate,
    revoke_certificate,
)
from app.storage.domain_repository import (
    SqlAlchemyDomainRepository,
    StoredDomainAsset,
    StoredDomainAssignment,
    StoredDomainDnsSnapshot,
)
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository, StoredEngagementService


NOW = "2026-06-28T12:00:00+00:00"


@pytest.fixture(autouse=True)
def certificate_clock(monkeypatch):
    # Keep certificate evidence dates deterministic without changing other clocks.
    class CertificateDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            fixed = cls(2026, 6, 30, 12, tzinfo=timezone.utc)
            return fixed.astimezone(tz) if tz is not None else fixed.replace(tzinfo=None)

    monkeypatch.setattr("app.services.inbound_channel_certificate.datetime", CertificateDateTime)


def test_certificate_prerequisites_use_dns01_without_http_support_channel(client):
    engagement_id = _create_engagement(client)
    _save_operations(client, engagement_id, inbound_channels=[_https_channel()])
    _save_assigned_domain(client, engagement_id)

    body = client.get(f"/api/engagements/{engagement_id}/inbound-channels/edge-zy01-443-to-proxy01-18080/certificate").get_json()

    assert body["prerequisites"]["ready"] is True
    assert body["prerequisites"]["challengeType"] == "dns-01"
    checks = {check["id"]: check for check in body["prerequisites"]["checks"]}
    assert checks["dns01-provider"]["status"] == "ready"
    assert "http01-channel" not in checks


def test_letsencrypt_certificate_issue_runs_on_selected_proxy_and_records_remote_evidence(client, tmp_path):
    engagement_id = _create_engagement(client)
    _save_operations(client, engagement_id, inbound_channels=[_https_channel(), _http01_channel()])
    _save_assigned_domain(client, engagement_id)
    _save_web_static_service(client, engagement_id)
    ansible = _executable(tmp_path, "ansible-playbook")
    evidence = {
        "domain": "example.com",
        "issuedAt": "Jun 29 12:00:00 2026 GMT",
        "expiresAt": "Sep 27 12:00:00 2026 GMT",
        "liveDir": "/etc/letsencrypt/live/example.com",
        "fullchain": "/etc/letsencrypt/live/example.com/fullchain.pem",
        "privkey": "/etc/letsencrypt/live/example.com/privkey.pem",
    }

    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        result = issue_certificate(
            engagement_id,
            _https_channel()["channelId"],
            {"certificateType": "letsencrypt", "acmeEmail": "operator@example.com", "acmeEnvironment": "staging"},
            repository=repo,
            runner=_dns01_runner(evidence),
            background_runner=lambda task: task(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible)},
            workspace_root=tmp_path / "workspaces",
        )
        finished = repo.get(result["job"]["id"])

    assert result["job"]["status"] == "running"
    assert result["certificate"]["status"] == "Issuing"
    assert finished is not None and finished.status == "succeeded"
    final_certificate = finished.events[-1].data["certificate"]
    assert final_certificate["certName"] == "example.com"
    assert final_certificate["expiresAt"] == "2026-09-27T12:00:00+00:00"
    assert final_certificate["paths"]["privkey"] == evidence["privkey"]
    first_event = finished.events[0].data
    assert first_event["inventoryTargets"] == ["selected_proxy"]
    assert first_event["challengeType"] == "dns-01"
    assert "--test-cert" in first_event["commands"]["certbot"]
    workspace = Path(first_event["workspaceDir"])
    inventory = (workspace / "ansible/inventory.ini").read_text(encoding="utf-8")
    playbook = (workspace / "ansible/prepare_dns01_certificate.yml").read_text(encoding="utf-8")
    assert "[selected_proxy]" in inventory
    assert "192.168.2.11" in inventory
    assert "203.0.113.10" in inventory
    assert "selected_middle" not in inventory
    assert "selected_edge" not in inventory
    assert "private key inside the shared proxy certificate volume" in playbook
    assert "no_log: true" in playbook
    assert "BEGIN PRIVATE KEY" not in str(finished.to_detail().to_dict())


def test_production_issuance_requires_explicit_channel_domain_confirmation(client):
    engagement_id = _create_engagement(client)
    _save_operations(client, engagement_id, inbound_channels=[_https_channel(), _http01_channel()])
    _save_assigned_domain(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/{_https_channel()['channelId']}/certificate/issue",
        json={"certificateType": "letsencrypt", "acmeEmail": "operator@example.com", "acmeEnvironment": "production"},
    )

    assert response.status_code == 400
    assert "productionConfirmation must equal" in response.get_json()["errors"][0]


def test_failed_live_issue_preserves_previous_certificate_state(client, tmp_path):
    engagement_id = _create_engagement(client)
    previous = {
        "type": "letsencrypt",
        "status": "Issued",
        "domain": "example.com",
        "expiresAt": "2026-08-01T00:00:00+00:00",
        "paths": {
            "liveDir": "/etc/letsencrypt/live/example.com",
            "fullchain": "/etc/letsencrypt/live/example.com/fullchain.pem",
            "privkey": "/etc/letsencrypt/live/example.com/privkey.pem",
        },
    }
    channel = {**_https_channel(), "certificate": previous}
    _save_operations(client, engagement_id, inbound_channels=[channel, _http01_channel()])
    _save_assigned_domain(client, engagement_id)
    _save_web_static_service(client, engagement_id)
    ansible = _executable(tmp_path, "ansible-playbook")

    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        result = issue_certificate(
            engagement_id,
            channel["channelId"],
            {"certificateType": "letsencrypt", "acmeEmail": "operator@example.com"},
            repository=repo,
            runner=lambda command, cwd: subprocess.CompletedProcess(command, 1, stdout="", stderr="token=should-not-leak"),
            background_runner=lambda task: task(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible)},
            workspace_root=tmp_path / "workspaces",
        )
        finished = repo.get(result["job"]["id"])
        workspace = certificate_workspace(engagement_id, channel["channelId"])

    assert finished is not None and finished.status == "failed"
    assert workspace["certificate"]["status"] == "Issued"
    assert workspace["certificate"]["expiresAt"] == previous["expiresAt"]
    assert workspace["certificate"]["lastAttemptStatus"] == "Issue Failed"
    assert "should-not-leak" not in str(finished.to_detail().to_dict())
    assert "token=[REDACTED]" in str(finished.to_detail().to_dict())


def test_letsencrypt_renew_runs_as_selected_proxy_job_and_records_remote_evidence(client, tmp_path):
    engagement_id = _create_engagement(client)
    channel = {**_https_channel(), "certificate": _managed_certificate()}
    _save_operations(client, engagement_id, inbound_channels=[channel, _http01_channel()])
    _save_assigned_domain(client, engagement_id)
    _save_web_static_service(client, engagement_id)
    ansible = _executable(tmp_path, "ansible-playbook")
    evidence = {
        "domain": "example.com",
        "issuedAt": "Jun 29 13:00:00 2026 GMT",
        "expiresAt": "Sep 27 13:00:00 2026 GMT",
        "liveDir": "/etc/letsencrypt/live/example.com",
        "fullchain": "/etc/letsencrypt/live/example.com/fullchain.pem",
        "privkey": "/etc/letsencrypt/live/example.com/privkey.pem",
    }

    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        result = renew_certificate(
            engagement_id,
            channel["channelId"],
            {},
            repository=repo,
            runner=_dns01_runner(evidence),
            background_runner=lambda task: task(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible)},
            workspace_root=tmp_path / "workspaces",
        )
        finished = repo.get(result["job"]["id"])
        workspace = certificate_workspace(engagement_id, channel["channelId"])

    assert result["job"]["status"] == "running"
    assert result["certificate"]["status"] == "Renewing"
    assert finished is not None and finished.status == "succeeded"
    assert workspace["certificate"]["status"] == "Renewed"
    assert workspace["certificate"]["managedBy"] == "barragan"
    assert workspace["certificate"]["certName"] == "example.com"
    assert workspace["certificate"]["expiresAt"] == "2026-09-27T13:00:00+00:00"
    command = finished.events[0].data["commands"]["certbot"]
    assert command[command.index("--preferred-challenges") + 1] == "dns"
    assert "--csr" in command
    assert "--test-cert" in command
    assert finished.events[0].data["inventoryTargets"] == ["selected_proxy"]


def test_failed_renew_preserves_prior_valid_certificate(client, tmp_path):
    engagement_id = _create_engagement(client)
    previous = _managed_certificate()
    channel = {**_https_channel(), "certificate": previous}
    _save_operations(client, engagement_id, inbound_channels=[channel, _http01_channel()])
    _save_assigned_domain(client, engagement_id)
    _save_web_static_service(client, engagement_id)
    ansible = _executable(tmp_path, "ansible-playbook")

    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        result = renew_certificate(
            engagement_id,
            channel["channelId"],
            {},
            repository=repo,
            runner=lambda command, cwd: subprocess.CompletedProcess(command, 1, stdout="", stderr="token=renew-secret"),
            background_runner=lambda task: task(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible)},
            workspace_root=tmp_path / "workspaces",
        )
        finished = repo.get(result["job"]["id"])
        workspace = certificate_workspace(engagement_id, channel["channelId"])

    assert finished is not None and finished.status == "failed"
    assert workspace["certificate"]["status"] == "Issued"
    assert workspace["certificate"]["expiresAt"] == previous["expiresAt"]
    assert workspace["certificate"]["lastAttemptStatus"] == "Renew Failed"
    assert "renew-secret" not in str(finished.to_detail().to_dict())


def test_renew_requires_barragan_lineage_and_production_confirmation(client):
    engagement_id = _create_engagement(client)
    unmanaged = _managed_certificate()
    unmanaged.pop("managedBy")
    channel = {**_https_channel(), "certificate": unmanaged}
    _save_operations(client, engagement_id, inbound_channels=[channel, _http01_channel()])
    _save_assigned_domain(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/{channel['channelId']}/certificate/renew",
        json={},
    )
    assert response.status_code == 400
    assert "managedBy=barragan" in response.get_json()["errors"][0]

    production = {**_managed_certificate(), "acmeEnvironment": "production"}
    channel = {**_https_channel(), "certificate": production}
    _save_operations(client, engagement_id, inbound_channels=[channel, _http01_channel()])
    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/{channel['channelId']}/certificate/renew",
        json={},
    )
    assert response.status_code == 400
    assert "productionConfirmation must equal" in response.get_json()["errors"][0]


def test_revoke_requires_barragan_ownership_and_canonical_domain_paths(client):
    engagement_id = _create_engagement(client)
    unmanaged = _managed_certificate()
    unmanaged.pop("managedBy")
    channel = {**_https_channel(), "certificate": unmanaged}
    _save_operations(client, engagement_id, inbound_channels=[channel])

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/{channel['channelId']}/certificate/revoke",
        json={},
    )
    assert response.status_code == 400
    assert "managedBy=barragan" in response.get_json()["errors"][0]

    channel["certificate"] = {**_managed_certificate(), "paths": {**_managed_certificate()["paths"], "liveDir": "/etc/letsencrypt/live/other.example.com"}}
    _save_operations(client, engagement_id, inbound_channels=[channel])
    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/{channel['channelId']}/certificate/revoke",
        json={},
    )
    assert response.status_code == 400
    assert "canonical domain paths" in response.get_json()["errors"][0]


def test_revoke_runs_certbot_delete_after_revoke_and_removes_paths_only_after_success(client, tmp_path):
    engagement_id = _create_engagement(client)
    channel = {**_https_channel(), "certificate": _managed_certificate()}
    _save_operations(client, engagement_id, inbound_channels=[channel])
    _save_web_static_service(client, engagement_id)
    ansible = _executable(tmp_path, "ansible-playbook")
    def revoke_runner(command, cwd):
        if command[-1] == "ansible/fetch_public_certificate.yml":
            Path(cwd, "cert.pem").write_text("public certificate", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        result = revoke_certificate(
            engagement_id,
            channel["channelId"],
            {},
            repository=repo,
            runner=revoke_runner,
            background_runner=lambda task: task(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible)},
            workspace_root=tmp_path / "workspaces",
        )
        finished = repo.get(result["job"]["id"])
        workspace = certificate_workspace(engagement_id, channel["channelId"])

    assert result["certificate"]["status"] == "Revoking"
    assert result["certificate"]["paths"]["liveDir"] == "/etc/letsencrypt/live/example.com"
    assert finished is not None and finished.status == "succeeded"
    assert workspace["certificate"]["status"] == "Revoked"
    assert "paths" not in workspace["certificate"]
    commands = finished.events[0].data["commands"]
    assert commands["revoke"][1:3] == ["revoke", "--cert-path"]
    assert commands["revoke"][3].endswith("/cert.pem")
    assert "--server" in commands["revoke"]
    fetch_playbook = Path(finished.events[0].data["workspaceDir"], "ansible/fetch_public_certificate.yml").read_text(encoding="utf-8")
    retire_playbook = Path(finished.events[0].data["workspaceDir"], "ansible/retire_proxy_certificate.yml").read_text(encoding="utf-8")
    assert "privkey.pem" not in fetch_playbook
    assert "/etc/letsencrypt/live/example.com" in retire_playbook


def test_failed_revoke_preserves_active_paths_and_status(client, tmp_path):
    engagement_id = _create_engagement(client)
    previous = _managed_certificate()
    channel = {**_https_channel(), "certificate": previous}
    _save_operations(client, engagement_id, inbound_channels=[channel])
    _save_web_static_service(client, engagement_id)
    ansible = _executable(tmp_path, "ansible-playbook")

    with client.application.storage_context():
        repo = SqlAlchemyJobRepository()
        result = revoke_certificate(
            engagement_id,
            channel["channelId"],
            {},
            repository=repo,
            runner=lambda command, cwd: subprocess.CompletedProcess(command, 1, stdout="", stderr="password=revoke-secret"),
            background_runner=lambda task: task(),
            env={"ANSIBLE_PLAYBOOK_BIN": str(ansible)},
            workspace_root=tmp_path / "workspaces",
        )
        finished = repo.get(result["job"]["id"])
        workspace = certificate_workspace(engagement_id, channel["channelId"])

    assert finished is not None and finished.status == "failed"
    assert workspace["certificate"]["status"] == "Issued"
    assert workspace["certificate"]["paths"] == previous["paths"]
    assert workspace["certificate"]["lastAttemptStatus"] == "Revoke Failed"
    assert "revoke-secret" not in str(finished.to_detail().to_dict())


def test_http01_compatibility_endpoint_reports_dns01_needs_no_channel(client, monkeypatch):
    engagement_id = _create_engagement(client)
    _save_web_static_service(client, engagement_id)
    occupied = {**_http01_channel(), "channelId": "other-8000", "externalPort": "9000", "relayPort": "8000", "certificateSupport": {}}
    _save_operations(client, engagement_id, inbound_channels=[_https_channel(), occupied])
    monkeypatch.setattr(
        "app.services.inbound_channel_certificate.start_inbound_channel_apply",
        lambda *args, **kwargs: {"job": {"id": "job-http01", "status": "running"}, "status": "Pending Apply"},
    )

    with client.application.storage_context():
        result = auto_configure_http01_channel(engagement_id, _https_channel()["channelId"])

    assert result["channel"]["channelId"] == _https_channel()["channelId"]
    assert result["status"] == "not_required"
    assert result["challengeType"] == "dns-01"
    assert result["job"]["events"][0]["data"]["mutation"] is False


def test_legacy_failed_http01_channel_does_not_block_dns01(client):
    engagement_id = _create_engagement(client)
    failed_support = {**_http01_channel(), "status": "Apply Failed"}
    _save_operations(client, engagement_id, inbound_channels=[_https_channel(), failed_support])
    _save_assigned_domain(client, engagement_id)

    body = client.get(
        f"/api/engagements/{engagement_id}/inbound-channels/{_https_channel()['channelId']}/certificate"
    ).get_json()

    assert body["prerequisites"]["ready"] is True
    assert body["prerequisites"]["challengeType"] == "dns-01"


def test_remote_evidence_is_bound_to_requested_domain_and_valid_dates():
    wrong_domain = {
        "domain": "other.example.com",
        "issuedAt": "Jun 29 12:00:00 2026 GMT",
        "expiresAt": "Sep 27 12:00:00 2026 GMT",
        "liveDir": "/etc/letsencrypt/live/other.example.com",
        "fullchain": "/etc/letsencrypt/live/other.example.com/fullchain.pem",
        "privkey": "/etc/letsencrypt/live/other.example.com/privkey.pem",
    }
    backwards = {**wrong_domain, "domain": "example.com", "liveDir": "/etc/letsencrypt/live/example.com", "fullchain": "/etc/letsencrypt/live/example.com/fullchain.pem", "privkey": "/etc/letsencrypt/live/example.com/privkey.pem", "expiresAt": "Jun 28 12:00:00 2026 GMT"}

    assert _parse_certificate_evidence(f"BARRAGAN_CERTIFICATE_EVIDENCE={json.dumps(wrong_domain)}", "example.com") is None
    assert _parse_certificate_evidence(f"BARRAGAN_CERTIFICATE_EVIDENCE={json.dumps(backwards)}", "example.com") is None


@pytest.mark.parametrize("expires_at", [
    "2026-06-30T11:59:59+00:00", "2026-06-30T12:00:00+00:00",
])
def test_remote_evidence_expired_at_or_before_clock_is_rejected(expires_at):
    evidence = {
        "domain": "example.com", "issuedAt": "2026-06-29T12:00:00+00:00",
        "expiresAt": expires_at,
        "liveDir": "/etc/letsencrypt/live/example.com",
        "fullchain": "/etc/letsencrypt/live/example.com/fullchain.pem",
        "privkey": "/etc/letsencrypt/live/example.com/privkey.pem",
    }
    assert _parse_certificate_evidence(
        f"BARRAGAN_CERTIFICATE_EVIDENCE={json.dumps(evidence)}", "example.com"
    ) is None
    evidence["expiresAt"] = "2026-06-30T12:00:01+00:00"
    assert _parse_certificate_evidence(
        f"BARRAGAN_CERTIFICATE_EVIDENCE={json.dumps(evidence)}", "example.com"
    ) is not None


def test_private_key_blocks_are_removed_from_command_output():
    output = "before\n-----BEGIN PRIVATE KEY-----\nsensitive\n-----END PRIVATE KEY-----\nafter"

    sanitized = _sanitize_output(output)

    assert "sensitive" not in sanitized
    assert "BEGIN PRIVATE KEY" not in sanitized
    assert "[REDACTED PRIVATE KEY]" in sanitized

    oversized = "-----BEGIN PRIVATE KEY-----\n" + ("sensitive" * 1000)
    oversized_sanitized = _sanitize_output(oversized)
    assert "sensitive" not in oversized_sanitized
    assert "BEGIN PRIVATE KEY" not in oversized_sanitized


def test_overlapping_certificate_issue_is_rejected(client):
    engagement_id = _create_engagement(client)
    channel = {
        **_https_channel(),
        "certificate": {
            "type": "letsencrypt",
            "status": "Issuing",
            "domain": "example.com",
            "lastJobId": "job-already-running",
        },
    }
    _save_operations(client, engagement_id, inbound_channels=[channel, _http01_channel()])
    _save_assigned_domain(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/{channel['channelId']}/certificate/issue",
        json={"certificateType": "letsencrypt", "acmeEmail": "operator@example.com"},
    )

    assert response.status_code == 400
    assert "already running" in response.get_json()["errors"][0]


def test_live_issue_rejects_managed_service_for_another_domain(client):
    engagement_id = _create_engagement(client)
    _save_operations(client, engagement_id, inbound_channels=[_https_channel(), _http01_channel()])
    _save_assigned_domain(client, engagement_id)
    _save_web_static_service(client, engagement_id, domain="other.example.com")

    with client.application.storage_context():
        try:
            issue_certificate(
                engagement_id,
                _https_channel()["channelId"],
                {"certificateType": "letsencrypt", "acmeEmail": "operator@example.com"},
                repository=SqlAlchemyJobRepository(),
            )
        except ValueError as exc:
            assert "site domain does not match" in " ".join(exc.errors)
        else:
            raise AssertionError("expected managed service domain mismatch to fail")


def test_self_signed_certificate_uses_domain_only_identity(client):
    engagement_id = _create_engagement(client)
    _save_operations(client, engagement_id, inbound_channels=[_https_channel()])
    _save_assigned_domain(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/edge-zy01-443-to-proxy01-18080/certificate/issue",
        json={"certificateType": "self-signed"},
    )
    body = response.get_json()

    assert response.status_code == 202
    command = " ".join(body["job"]["events"][0]["data"]["command"])
    assert "/CN=example.com" in command
    assert "subjectAltName=DNS:example.com" in command
    identity_args = ["/CN=example.com", "subjectAltName=DNS:example.com"]
    assert all("red" not in value.lower() for value in identity_args)
    assert all("barragan" not in value.lower() for value in identity_args)
    assert all("zy01" not in value.lower() for value in identity_args)


def test_self_signed_certificate_allows_any_assigned_domain_without_extra_identity_metadata(client):
    engagement_id = _create_engagement(client)
    domain = "oracle-demo.example"
    _save_operations(client, engagement_id, inbound_channels=[_https_channel(domain=domain)])
    _save_assigned_domain(client, engagement_id, domain_name=domain)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/edge-zy01-443-to-proxy01-18080/certificate/issue",
        json={"certificateType": "self-signed"},
    )
    body = response.get_json()

    assert response.status_code == 202
    command = " ".join(body["job"]["events"][0]["data"]["command"])
    assert f"/CN={domain}" in command
    assert f"subjectAltName=DNS:{domain}" in command
    assert "ZY01" not in command
    assert "red team" not in command.lower()


def test_certificate_management_rejects_non_https_channel(client):
    engagement_id = _create_engagement(client)
    _save_operations(
        client,
        engagement_id,
        inbound_channels=[
            {
                **_https_channel(),
                "channelId": "edge-zy01-8080-to-proxy01-18080",
                "protocol": "TCP",
                "mode": "tcp-forward",
                "externalPort": "8080",
            }
        ],
    )

    response = client.get(f"/api/engagements/{engagement_id}/inbound-channels/edge-zy01-8080-to-proxy01-18080/certificate")

    assert response.status_code == 200
    assert response.get_json()["prerequisites"]["checks"][0]["status"] == "blocked"


def test_certificate_management_rejects_tcp_http01_support_channel(client):
    engagement_id = _create_engagement(client)
    channel = _http01_channel()
    _save_operations(client, engagement_id, inbound_channels=[channel])

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/{channel['channelId']}/certificate/issue",
        json={"certificateType": "self-signed"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["certificates can only be managed for HTTPS/OpenResty inbound channels"]


def test_certificate_metadata_survives_operations_normalization(client):
    engagement_id = _create_engagement(client)
    channel = {
        **_https_channel(),
        "certificate": {
            "type": "letsencrypt",
            "status": "Issued",
            "domain": "example.com",
            "paths": {"fullchain": "/etc/letsencrypt/live/example.com/fullchain.pem", "privkey": "/etc/letsencrypt/live/example.com/privkey.pem"},
        },
    }
    _save_operations(client, engagement_id, inbound_channels=[channel])

    with client.application.storage_context():
        workspace = certificate_workspace(engagement_id, channel["channelId"])

    assert workspace["certificate"]["status"] == "Issued"
    assert workspace["certificate"]["paths"]["privkey"].endswith("/privkey.pem")


def _create_engagement(client) -> str:
    response = client.post("/api/engagements", json={"name": "ZY01", "owner": "operator"})
    return response.get_json()["engagement"]["id"]


def _save_operations(client, engagement_id: str, *, inbound_channels: list[dict]):
    with client.application.storage_context():
        repository = SqlAlchemyJobRepository()
        repository.save(
            StoredJobRun(
                id=f"job-ops-{len(inbound_channels)}",
                action="engagement_channels_update",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at=NOW,
                started_at=NOW,
                finished_at=NOW,
                events=[
                    JobEvent(
                        1,
                        "info",
                        "operations ready",
                        {
                            "connectionDetails": [
                                {"role": "homebase", "displayName": "homebase-zy01", "publicIp": "203.0.113.10", "privateIp": "192.168.0.10", "sshUser": "user"},
                                {"role": "proxy", "displayName": "proxy01-zy01", "publicIp": "203.0.113.11", "privateIp": "192.168.2.11", "sshUser": "user"},
                            ],
                            "coreInfrastructure": [
                                {"hostname": "homebase-zy01", "displayName": "homebase-zy01", "role": "homebase", "publicIp": "203.0.113.10", "privateIp": "192.168.0.10", "sshUser": "user", "status": "deployed"},
                                {"hostname": "proxy01-zy01", "displayName": "proxy01-zy01", "role": "proxy", "publicIp": "203.0.113.11", "privateIp": "192.168.2.11", "sshUser": "user", "status": "deployed"},
                            ],
                            "sketchInfrastructure": [
                                {
                                    "chainId": "proxy01-chain-001",
                                    "hostname": "middle-zy01",
                                    "role": "middle",
                                    "proxy": "proxy01",
                                    "publicIp": "198.51.100.20",
                                    "status": "deployed",
                                },
                                {
                                    "chainId": "proxy01-chain-001",
                                    "hostname": "edge-zy01",
                                    "role": "edge",
                                    "proxy": "proxy01",
                                    "publicIp": "198.51.100.30",
                                    "status": "deployed",
                                },
                            ],
                            "inboundChannels": inbound_channels,
                            "outboundChannels": [],
                        },
                    )
                ],
            )
        )

        operations = repository.get(f"job-ops-{len(inbound_channels)}")
        repository.save(replace(
            operations,
            id=f"job-core-{engagement_id}",
            action="pilot_standard_rti_guarded_execute",
            events=[JobEvent(1, "info", "core deployed", {
                "connectionDetails": operations.events[0].data["connectionDetails"]
            })],
        ))


def _save_web_static_service(client, engagement_id: str, *, domain: str = "example.com"):
    with client.application.storage_context():
        SqlAlchemyEngagementServiceRepository().save(
            StoredEngagementService(
                engagement_id=engagement_id,
                service_id="web-static-example",
                service_type="web-static",
                name="Example",
                proxy_id="proxy01",
                status="Configured",
                config={
                    "siteName": "example",
                    "domain": domain,
                    "internalPort": "18080",
                    "contentPath": "/opt/web/example/html/",
                    "stackModel": "containerized-openresty-v1",
                    "composePath": "/opt/web/docker-compose.yml",
                    "stackOwnershipPath": "/opt/web/.barragan-stack.json",
                    "frontProxyService": "reverse-proxy",
                    "certbotService": "certbot",
                    "siteService": "web_static_example",
                    "containerPort": 8081,
                },
            )
        )


def _executable(root: Path, name: str) -> Path:
    path = root / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _dns01_runner(evidence: dict):
    def run(command, cwd):
        cwd = Path(cwd)
        joined = " ".join(command)
        if "prepare_dns01_certificate.yml" in joined:
            (cwd / "csr.pem").write_text("-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="CSR prepared\n", stderr="")
        if "certonly" in command:
            for name in ("cert.pem", "chain.pem", "fullchain.pem"):
                (cwd / name).write_text(f"public {name}\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="DNS challenge validated\n", stderr="")
        if "deploy_dns01_certificate.yml" in joined:
            return subprocess.CompletedProcess(command, 0, stdout=f"BARRAGAN_CERTIFICATE_EVIDENCE={json.dumps(evidence)}\n", stderr="")
        raise AssertionError(f"unexpected DNS-01 command: {command}")

    return run


def _save_assigned_domain(client, engagement_id: str, *, domain_name: str = "example.com"):
    with client.application.storage_context():
        repo = SqlAlchemyDomainRepository()
        repo.save_asset(
            StoredDomainAsset(
                id=f"domain-{domain_name.replace('.', '-')}",
                domain_name=domain_name,
                registrar="namecheap",
                registration_started_at="",
                expiration_at="2027-01-01T00:00:00+00:00",
                auto_renew=True,
                provider_status="active",
                notes="",
                risk_status="green",
                risk_flags=[],
                cooldown_until="",
                assignable_override=False,
                catalog_state="auto",
                metadata={},
                last_synced_at=NOW,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        repo.save_assignment(
            StoredDomainAssignment(
                id=None,
                domain_id=f"domain-{domain_name.replace('.', '-')}",
                engagement_id=engagement_id,
                engagement_name="ZY01",
                purpose="website",
                status="active",
                notes="",
                assigned_by="operator",
                released_by="",
                assigned_at=NOW,
                released_at=None,
                purpose_tags=["website"],
            )
        )
        repo.save_snapshot(
            StoredDomainDnsSnapshot(
                id=None,
                domain_id=f"domain-{domain_name.replace('.', '-')}",
                provider="namecheap",
                hosts=[{"hostName": "@", "type": "A", "address": "198.51.100.30", "ttl": "600"}],
                source="test",
                sync_job_id="job-dns",
                fetched_at=NOW,
            )
        )


def _https_channel(*, domain: str = "example.com") -> dict[str, str]:
    return {
        "channelId": "edge-zy01-443-to-proxy01-18080",
        "domain": domain,
        "protocol": "HTTPS",
        "mode": "https-openresty",
        "externalPort": "443",
        "edge": "edge-zy01",
        "middle": "middle-zy01",
        "proxy": "proxy01-zy01",
        "terminatesOn": "proxy01-zy01",
        "service": "Static Web",
        "serviceId": "web-static-example",
        "serviceType": "web-static",
        "internalPort": "18080",
        "purpose": "campaign site HTTPS",
        "status": "Validated",
    }


def _managed_certificate() -> dict:
    return {
        "type": "letsencrypt",
        "managedBy": "barragan",
        "certName": "example.com",
        "status": "Issued",
        "domain": "example.com",
        "acmeEmail": "operator@example.com",
        "acmeEnvironment": "staging",
        "issuedAt": "2026-06-29T12:00:00+00:00",
        "expiresAt": "2026-09-27T12:00:00+00:00",
        "paths": {
            "liveDir": "/etc/letsencrypt/live/example.com",
            "fullchain": "/etc/letsencrypt/live/example.com/fullchain.pem",
            "privkey": "/etc/letsencrypt/live/example.com/privkey.pem",
        },
    }


def _http01_channel() -> dict[str, str]:
    return {
        "channelId": "edge-zy01-80-to-proxy01-80",
        "domain": "example.com",
        "protocol": "TCP",
        "mode": "tcp-forward",
        "externalPort": "80",
        "relayPort": "8000",
        "edge": "edge-zy01",
        "middle": "middle-zy01",
        "proxy": "proxy01-zy01",
        "terminatesOn": "proxy01-zy01",
        "service": "Static Web",
        "serviceId": "web-static-example",
        "serviceType": "web-static",
        "internalPort": "18080",
        "purpose": "ACME HTTP-01 challenge",
        "status": "Validated",
        "certificateSupport": {"role": "http-01-challenge", "parentChannelId": "edge-zy01-443-to-proxy01-18080"},
    }
