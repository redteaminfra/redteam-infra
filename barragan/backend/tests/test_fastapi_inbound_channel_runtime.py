# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.services.certificate_manager import CertificateManagerValidationError
from app.services.inbound_channel_apply import InboundChannelApplyValidationError
from app.services.inbound_channel_certificate import InboundChannelCertificateValidationError
from app.services.inbound_channel_workflow import InboundChannelWorkflowValidationError
from app.services.inbound_channel_batch import InboundChannelBatchConflictError


ENGAGEMENT_ID = "eng-fastapi-inbound"
CHANNEL_ID = "edge-fastapi-443-to-proxy01-443"


def test_fastapi_inbound_channel_batch_routes(tmp_path, monkeypatch):
    submission_id = "d8c1df26-f7e4-4aa0-b87c-7006b46d143d"
    channel = _channel_payload()
    parent = _job_payload("job-inbound-batch")

    def preview(engagement_id, submitted, channels):
        if engagement_id == "eng-missing":
            return None
        if not channels:
            raise InboundChannelWorkflowValidationError(["add at least one inbound channel"])
        return {"submissionId": submitted, "previewFingerprint": "a" * 64, "channels": [channel], "applyOrder": [CHANNEL_ID], "warnings": [], "status": "ready", "summary": "ready"}

    def create(engagement_id, submitted, fingerprint, channels):
        if engagement_id == "eng-missing":
            return None
        if fingerprint != "a" * 64:
            raise InboundChannelBatchConflictError(["stale"])
        return {"batchId": parent["id"], "channels": [channel], "job": parent}

    def retry(_engagement_id, batch_id):
        if batch_id == "busy":
            raise InboundChannelBatchConflictError(["busy"])
        if batch_id == "missing":
            raise InboundChannelWorkflowValidationError(["batch missing"])
        return {"batchId": parent["id"], "channels": [channel], "job": parent}

    monkeypatch.setattr("app.asgi.preview_inbound_channel_batch", preview)
    monkeypatch.setattr("app.asgi.start_inbound_channel_batch", create)
    monkeypatch.setattr("app.asgi.retry_inbound_channel_batch", retry)
    monkeypatch.setattr("app.asgi.latest_inbound_channel_batch", lambda engagement_id: None if engagement_id == "eng-missing" else {"job": parent})

    class BatchConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'batch.sqlite3'}"

    client = TestClient(create_fastapi_app(BatchConfig))
    preview_response = client.post(f"/api/engagements/{ENGAGEMENT_ID}/inbound-channel-batches/preview", json={"submissionId": submission_id, "channels": [{"edge": "edge"}]})
    assert preview_response.status_code == 200
    assert preview_response.json()["previewFingerprint"] == "a" * 64
    create_response = client.post(f"/api/engagements/{ENGAGEMENT_ID}/inbound-channel-batches", json={"submissionId": submission_id, "previewFingerprint": "a" * 64, "channels": [{"edge": "edge"}]})
    assert create_response.status_code == 202
    assert create_response.json()["batchId"] == "job-inbound-batch"
    stale_response = client.post(f"/api/engagements/{ENGAGEMENT_ID}/inbound-channel-batches", json={"submissionId": submission_id, "previewFingerprint": "stale", "channels": [{"edge": "edge"}]})
    assert stale_response.status_code == 409
    retry_response = client.post(f"/api/engagements/{ENGAGEMENT_ID}/inbound-channel-batches/job-old/retry", json={})
    assert retry_response.status_code == 202
    assert client.get(f"/api/engagements/{ENGAGEMENT_ID}/inbound-channel-batches/latest").json()["job"]["id"] == parent["id"]
    assert client.post(f"/api/engagements/{ENGAGEMENT_ID}/inbound-channel-batches/busy/retry", json={}).status_code == 409


def test_fastapi_inbound_channel_workflow_routes_match_reference_contract(tmp_path, monkeypatch):
    _patch_inbound_workflow_functions(monkeypatch)
    reference_client, fastapi_client = _separate_clients(tmp_path)

    requests = (
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels", {"channelId": CHANNEL_ID}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels", {"channelId": "bad"}),
        ("post", "/api/engagements/eng-missing/inbound-channels", {"channelId": CHANNEL_ID}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/apply-preview", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/apply-preview", {"requestedBy": "bad"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/apply", {"confirmation": f"apply-inbound-{CHANNEL_ID}"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/apply", {"confirmation": "bad"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/validate", {"confirmation": f"validate-inbound-{CHANNEL_ID}"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/validate", {"confirmation": "bad"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/recover", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/bad/recover", {}),
        ("delete", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}", {"confirmation": f"remove-inbound-{CHANNEL_ID}"}),
        ("delete", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}", {"confirmation": "bad"}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_inbound_certificate_binding_routes_match_reference_contract(tmp_path, monkeypatch):
    _patch_certificate_binding_functions(monkeypatch)
    reference_client, fastapi_client = _separate_clients(tmp_path)

    requests = (
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/bad/certificate", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate-binding", {}),
        ("patch", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate-binding", {"certificateId": "cert-1"}),
        ("patch", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate-binding", {"certificateId": "bad"}),
        ("delete", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate-binding", {}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_inbound_legacy_certificate_routes_match_reference_contract(tmp_path, monkeypatch):
    _patch_legacy_certificate_functions(monkeypatch)
    reference_client, fastapi_client = _separate_clients(tmp_path)

    requests = (
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate/prerequisites", {}),
        ("get", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/bad/certificate/prerequisites", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate/challenge-channel", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/bad/certificate/challenge-channel", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate/issue", {"domain": "www.example.test"}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/bad/certificate/issue", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate/renew", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/bad/certificate/renew", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/{CHANNEL_ID}/certificate/revoke", {}),
        ("post", f"/api/engagements/{ENGAGEMENT_ID}/inbound-channels/bad/certificate/revoke", {}),
    )
    for method, path, body in requests:
        reference_response = _request(reference_client, method, path, body)
        fastapi_response = _request(fastapi_client, method, path, body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def _separate_clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app.test_client(), fastapi_app.test_client()


def _request(client, method: str, path: str, body: dict[str, Any]):
    if isinstance(client, TestClient):
        return client.request(method.upper(), path, json=body)
    return client.open(path, method=method.upper(), json=body)


def _patch_inbound_workflow_functions(monkeypatch) -> None:
    def create(engagement_id: str, body: dict[str, Any], *, requested_by: str = "operator"):
        if engagement_id == "eng-missing":
            return None
        if body.get("channelId") == "bad":
            raise InboundChannelWorkflowValidationError(["channel is invalid"])
        return {"channel": _channel_payload(), "job": _job_payload("job-inbound-create"), "status": "applying"}

    def preview(_engagement_id: str, _channel_id: str, *, requested_by: str = "operator"):
        if requested_by == "bad":
            raise InboundChannelApplyValidationError(["requestedBy is invalid"])
        return {"channel": _channel_payload(), "job": _job_payload("job-inbound-preview"), "status": "previewed"}

    def apply(
        _engagement_id: str,
        channel_id: str,
        *,
        confirmation: str,
        requested_by: str = "operator",
        auto_validate: bool = False,
    ):
        assert auto_validate is True
        if confirmation != f"apply-inbound-{channel_id}":
            raise InboundChannelApplyValidationError([f'confirmation must equal "apply-inbound-{channel_id}"'])
        return {"channel": _channel_payload(), "job": _job_payload("job-inbound-apply"), "status": "applying"}

    def validate(_engagement_id: str, channel_id: str, *, confirmation: str, requested_by: str = "operator"):
        if confirmation != f"validate-inbound-{channel_id}":
            raise InboundChannelApplyValidationError([f'confirmation must equal "validate-inbound-{channel_id}"'])
        return {"channel": _channel_payload(), "job": _job_payload("job-inbound-validate"), "status": "validating"}

    def recover(_engagement_id: str, channel_id: str, *, requested_by: str = "operator"):
        if channel_id == "bad":
            raise InboundChannelWorkflowValidationError(["inbound channel bad was not found"])
        return {"channel": _channel_payload(), "job": _job_payload("job-inbound-recover"), "status": "applying"}

    def remove(_engagement_id: str, channel_id: str, *, confirmation: str, requested_by: str = "operator"):
        if confirmation != f"remove-inbound-{channel_id}":
            raise InboundChannelApplyValidationError([f'confirmation must equal "remove-inbound-{channel_id}"'])
        return {"channel": _channel_payload(status="Removed"), "job": _job_payload("job-inbound-remove"), "status": "removing"}

    patches = {
        "create_and_apply_inbound_channel": create,
        "preview_inbound_channel_apply": preview,
        "start_inbound_channel_apply": apply,
        "validate_inbound_channel": validate,
        "recover_inbound_channel": recover,
        "remove_inbound_channel": remove,
    }
    for name, value in patches.items():
        monkeypatch.setattr(f"app.asgi.{name}", value)
        monkeypatch.setattr(f"app.asgi.{name}", value)


def _patch_certificate_binding_functions(monkeypatch) -> None:
    def workspace(_engagement_id: str, channel_id: str):
        if channel_id == "bad":
            raise CertificateManagerValidationError(["inbound channel bad was not found"])
        return {"binding": {"certificateId": "cert-1"}, "candidates": [], "channel": _channel_payload(), "tlsStatus": {"state": "bound"}}

    def legacy_workspace(_engagement_id: str, channel_id: str):
        if channel_id == "bad":
            raise InboundChannelCertificateValidationError(["inbound channel bad was not found"])
        return {"channel": _channel_payload(), "certificate": {}, "prerequisites": {"ready": True, "checks": []}}

    def bind(_engagement_id: str, _channel_id: str, certificate_id: str):
        if certificate_id == "bad":
            raise CertificateManagerValidationError(["certificate bad was not found"])
        return {"binding": {"certificateId": certificate_id}, "channel": _channel_payload(), "tlsStatus": {"state": "bound"}}

    def unbind(_engagement_id: str, _channel_id: str):
        return {"binding": None, "channel": _channel_payload(), "tlsStatus": {"state": "unbound"}}

    for target in ("app.asgi",):
        monkeypatch.setattr(f"{target}.channel_certificate_binding_workspace", workspace)
        monkeypatch.setattr(f"{target}.certificate_workspace", legacy_workspace)
        monkeypatch.setattr(f"{target}.bind_certificate_to_channel", bind)
        monkeypatch.setattr(f"{target}.unbind_certificate_from_channel", unbind)


def _patch_legacy_certificate_functions(monkeypatch) -> None:
    def workspace(_engagement_id: str, channel_id: str):
        if channel_id == "bad":
            raise InboundChannelCertificateValidationError(["inbound channel bad was not found"])
        return {"channel": _channel_payload(), "certificate": {}, "prerequisites": {"ready": True, "checks": []}}

    def challenge(_engagement_id: str, channel_id: str, *, requested_by: str = "operator"):
        if channel_id == "bad":
            raise InboundChannelCertificateValidationError(["inbound channel bad was not found"])
        return {"channel": _channel_payload(), "status": "not_required", "job": _job_payload("job-challenge")}

    def lifecycle(_engagement_id: str, channel_id: str, body: dict[str, Any], *, requested_by: str = "operator"):
        if channel_id == "bad":
            raise InboundChannelCertificateValidationError(["inbound channel bad was not found"])
        return {"certificate": {"domain": body.get("domain") or "www.example.test"}, "job": _job_payload("job-cert"), "status": "running"}

    for target in ("app.asgi",):
        monkeypatch.setattr(f"{target}.certificate_workspace", workspace)
        monkeypatch.setattr(f"{target}.auto_configure_http01_channel", challenge)
        monkeypatch.setattr(f"{target}.issue_certificate", lifecycle)
        monkeypatch.setattr(f"{target}.renew_certificate", lifecycle)
        monkeypatch.setattr(f"{target}.revoke_certificate", lifecycle)


def _channel_payload(status: str = "Pending Apply") -> dict[str, Any]:
    return {
        "channelId": CHANNEL_ID,
        "domain": "www.example.test",
        "protocol": "TCP",
        "mode": "https-openresty",
        "externalPort": "443",
        "edge": "edge-fastapi",
        "middle": "middle-fastapi",
        "proxy": "proxy01",
        "terminatesOn": "proxy01",
        "internalPort": "443",
        "service": "Static Web",
        "purpose": "FastAPI parity",
        "status": status,
    }


def _job_payload(job_id: str) -> dict[str, Any]:
    return {
        "id": job_id,
        "action": "inbound_channel_apply",
        "status": "running",
        "target": f"engagement:{ENGAGEMENT_ID}",
        "targetType": "engagement",
        "targetId": ENGAGEMENT_ID,
        "requestedBy": "operator",
        "input": {"engagementId": ENGAGEMENT_ID, "channelId": CHANNEL_ID},
        "artifactRefs": [],
        "createdAt": "2026-07-06T00:00:00+00:00",
        "startedAt": "2026-07-06T00:00:00+00:00",
        "finishedAt": None,
        "events": [{"level": "INFO", "message": "queued"}],
    }
