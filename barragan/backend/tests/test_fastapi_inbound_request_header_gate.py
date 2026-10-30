# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json

from app import create_app
from app.core.config import TestConfig
from app.services.authentication import AuthenticationService
from app.services.engagements import create_draft_engagement
from app.services.inbound_request_header_gate import InboundRequestHeaderGateValidationError
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.models import TeamMemberModel


def _detail(token: str = "operator-visible-token-123") -> dict:
    return {
        "channel": {
            "channelId": "upload-http",
            "mode": "http-openresty",
            "protocol": "HTTP",
            "domain": "upload.example.test",
        },
        "gate": {
            "configured": True,
            "enabled": True,
            "headerName": "Authorization",
            "token": token,
            "status": "Active",
            "maxRequestBodyMb": 500,
        },
        "authorizedRequest": {
            "method": "GET",
            "curl": f"curl --request GET --header 'Authorization: Bearer {token}' http://198.51.100.30/",
        },
    }


def test_explicit_gate_detail_returns_operator_visible_plaintext(client, monkeypatch):
    expected = _detail()
    monkeypatch.setattr(
        "app.asgi.get_inbound_request_header_gate",
        lambda engagement_id, channel_id, **_kwargs: expected,
    )

    response = client.get(
        "/api/engagements/eng-1/inbound-channels/upload-http/request-header-gate"
    )

    assert response.status_code == 200
    assert response.get_json() == expected


def test_gate_update_passes_discriminated_token_action_and_returns_job(client, monkeypatch):
    captured = {}
    expected = {
        **_detail("active-token-123"),
        "job": {
            "id": "job-gate",
            "action": "inbound_request_header_gate_apply",
            "status": "running",
            "targetType": "engagement",
            "targetId": "eng-1",
            "requestedBy": "operator",
            "input": {"engagementId": "eng-1", "channelId": "upload-http"},
            "artifactRefs": [],
            "events": [],
        },
    }

    def update(engagement_id, channel_id, body, **_kwargs):
        captured.update({"engagementId": engagement_id, "channelId": channel_id, "body": body})
        return expected

    monkeypatch.setattr("app.asgi.update_inbound_request_header_gate", update)
    body = {
        "enabled": True,
        "headerName": "X-RTI-Access",
        "tokenAction": "provide",
        "token": "replacement-token-456",
        "maxRequestBodyMb": 725,
    }

    response = client.open(
        "/api/engagements/eng-1/inbound-channels/upload-http/request-header-gate",
        method="PUT",
        json=body,
    )

    assert response.status_code == 202
    assert captured == {"engagementId": "eng-1", "channelId": "upload-http", "body": body}
    assert response.get_json() == expected


def test_gate_validation_errors_are_bounded_api_errors(client, monkeypatch):
    def invalid(*_args, **_kwargs):
        raise InboundRequestHeaderGateValidationError(["headerName cannot be used as a request gate"])

    monkeypatch.setattr("app.asgi.get_inbound_request_header_gate", invalid)

    response = client.get(
        "/api/engagements/eng-1/inbound-channels/upload-http/request-header-gate"
    )

    assert response.status_code == 400
    assert response.get_json() == {"errors": ["headerName cannot be used as a request gate"]}


def test_authenticated_operator_can_retrieve_gate_but_viewer_and_collection_surfaces_cannot(tmp_path, monkeypatch):
    class GateAuthConfig(TestConfig):
        AUTH_REQUIRED = True
        AUTH_SESSION_COOKIE_NAME = "barragan_gate_test_session"

    GateAuthConfig.SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'gate-auth.sqlite3'}"
    app = create_app(GateAuthConfig)
    with app.storage_context():
        for username, roles in (("operator-one", ("operator",)), ("viewer-one", ("viewer",))):
            member = TeamMemberModel(
                id=f"member-{username}",
                username=username,
                display_name=username,
                status="active",
                global_roles=[],
            )
            db.session.add(member)
            db.session.commit()
            AuthenticationService.from_config(GateAuthConfig).create_account(
                member.id,
                f"{username}-password",
                roles=roles,
                force_password_change=False,
            )
        engagement_id = create_draft_engagement(
            {"name": "ZY-AUTH", "owner": "operator-one"},
            repository=SqlAlchemyEngagementRepository(),
        ).id

    expected = _detail("authenticated-operator-token-123")
    monkeypatch.setattr(
        "app.asgi.get_inbound_request_header_gate",
        lambda engagement_id, channel_id, **_kwargs: expected,
    )
    operator = app.test_client()
    viewer = app.test_client()
    operator_login = operator.post(
        "/api/auth/login",
        json={"username": "operator-one", "password": "operator-one-password"},
    )
    viewer_login = viewer.post(
        "/api/auth/login",
        json={"username": "viewer-one", "password": "viewer-one-password"},
    )
    assert operator_login.status_code == 200
    assert viewer_login.status_code == 200

    path = "/api/engagements/eng-1/inbound-channels/upload-http/request-header-gate"
    assert viewer.get(path).status_code == 403
    operator_response = operator.get(path)
    assert operator_response.status_code == 200
    assert operator_response.get_json()["gate"]["token"] == "authenticated-operator-token-123"

    for collection_path in (
        "/api/jobs",
        "/api/engagements?scope=all",
        "/api/dashboard",
        f"/api/engagements/{engagement_id}/operations",
    ):
        response = operator.get(collection_path)
        assert response.status_code == 200
        serialized = json.dumps(response.get_json(), sort_keys=True)
        assert "authenticated-operator-token-123" not in serialized
        assert "Bearer authenticated-operator-token-123" not in serialized
