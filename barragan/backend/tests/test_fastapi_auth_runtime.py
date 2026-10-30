# Copyright (c) 2026, Oracle and/or its affiliates.
import asyncio
from datetime import datetime, timedelta, timezone
from threading import Lock

import httpx2 as httpx
from sqlalchemy import event

from app import create_app
from app.core.config import TestConfig
from app.services.authentication import AuthenticationService
from app.storage.database import db
from app.storage.models import AuthenticationSessionModel, TeamMemberModel


class AuthTestConfig(TestConfig):
    AUTH_REQUIRED = True
    AUTH_SESSION_COOKIE_NAME = "barragan_test_session"


def _app_with_account(*, roles=("administrator", "service_account")):
    app = create_app(AuthTestConfig)
    with app.storage_context():
        db.session.add(TeamMemberModel(
            id="member-example_operator_three",
            username="example_operator_three",
            display_name="Example Operator",
            status="active",
            global_roles=[],
        ))
        db.session.commit()
        AuthenticationService.from_config(AuthTestConfig).create_account(
            "member-example_operator_three",
            "example_operator_three",
            roles=roles,
            initial_password=True,
        )
    return app


def test_prepare_inbound_channel_requires_authentication_csrf_and_operator_role():
    path = "/api/engagements/missing/inbound-channels/prepare"
    body = {
        "submissionId": "00000000-0000-4000-8000-000000000001",
        "previewFingerprint": "f" * 64,
        "channel": {},
    }
    app = _app_with_account()
    with app.storage_context():
        AuthenticationService.from_config(AuthTestConfig).reset_password(
            "example_operator_three", "long permanent password", force_password_change=False,
        )
    client = app.test_client()
    assert client.post(path, json=body).status_code == 401
    login = client.post("/api/auth/login", json={"username": "example_operator_three", "password": "long permanent password"}).json()
    assert client.post(path, json=body).status_code == 401
    assert client.post(path, headers={"X-Barragan-CSRF": login["csrfToken"]}, json=body).status_code == 404

    viewer_app = _app_with_account(roles=("viewer",))
    with viewer_app.storage_context():
        AuthenticationService.from_config(AuthTestConfig).reset_password(
            "example_operator_three", "long permanent password", force_password_change=False,
        )
    viewer = viewer_app.test_client()
    viewer_login = viewer.post("/api/auth/login", json={"username": "example_operator_three", "password": "long permanent password"}).json()
    assert viewer.post(path, headers={"X-Barragan-CSRF": viewer_login["csrfToken"]}, json=body).status_code == 403


def test_protected_api_requires_login_and_forced_change_blocks_application_data():
    client = _app_with_account().test_client()
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/templates").status_code == 401

    login = client.post("/api/auth/login", json={"username": "example_operator_three", "password": "example_operator_three"})
    assert login.status_code == 200
    payload = login.json()
    assert payload["authenticated"] is True
    assert payload["mustChangePassword"] is True
    assert "HttpOnly" in login.headers["set-cookie"]
    assert "SameSite=strict" in login.headers["set-cookie"]
    assert client.get("/api/templates").status_code == 403

    changed = client.post(
        "/api/auth/password",
        headers={"X-Barragan-CSRF": payload["csrfToken"]},
        json={"currentPassword": "example_operator_three", "newPassword": "long permanent password"},
    )
    assert changed.status_code == 200
    assert changed.json()["mustChangePassword"] is False
    assert client.get("/api/templates").status_code == 200


def test_mutation_requires_csrf_and_server_identity_overrides_requested_by():
    app = _app_with_account()
    with app.storage_context():
        AuthenticationService.from_config(AuthTestConfig).reset_password(
            "example_operator_three",
            "long permanent password",
            force_password_change=False,
        )
    client = app.test_client()
    login = client.post(
        "/api/auth/login",
        json={"username": "example_operator_three", "password": "long permanent password"},
    ).json()
    assert client.post("/api/jobs", json={"action": "example"}).status_code == 401
    created = client.post(
        "/api/jobs",
        headers={"X-Barragan-CSRF": login["csrfToken"]},
        json={
            "action": "example",
            "targetType": "system",
            "targetId": "one",
            "requestedBy": "forged-user",
        },
    )
    assert created.status_code == 201
    assert created.json()["job"]["requestedBy"] == "example_operator_three"


def test_logout_all_revokes_every_session_for_the_authenticated_account():
    app = _app_with_account()
    password = "long permanent password"
    with app.storage_context():
        AuthenticationService.from_config(AuthTestConfig).reset_password(
            "example_operator_three",
            password,
            force_password_change=False,
        )
    first = app.test_client()
    second = app.test_client()
    first_login = first.post(
        "/api/auth/login",
        json={"username": "example_operator_three", "password": password},
    ).json()
    assert second.post(
        "/api/auth/login",
        json={"username": "example_operator_three", "password": password},
    ).status_code == 200

    response = first.post(
        "/api/auth/logout-all",
        headers={"X-Barragan-CSRF": first_login["csrfToken"]},
    )

    assert response.status_code == 200
    assert response.json()["authenticated"] is False
    assert first.get("/api/auth/session").json()["authenticated"] is False
    assert second.get("/api/auth/session").json()["authenticated"] is False


def test_session_bootstrap_coalesces_exact_concurrent_startup_burst():
    app = _app_with_account()
    password = "long permanent password"
    with app.storage_context():
        AuthenticationService.from_config(AuthTestConfig).reset_password(
            "example_operator_three",
            password,
            force_password_change=False,
        )
    client = app.test_client()
    login = client.post(
        "/api/auth/login",
        json={"username": "example_operator_three", "password": password},
    )
    assert login.status_code == 200

    now = datetime.now(timezone.utc)
    with app.storage_context():
        session = AuthenticationSessionModel.query.one()
        session.last_seen_at = now - timedelta(minutes=10)
        session.idle_expires_at = now + timedelta(hours=1)
        session.absolute_expires_at = now + timedelta(hours=3)
        db.session.commit()

    phase = "bootstrap"
    activity_statements = {"bootstrap": 0, "protected": 0}
    activity_updates = {"bootstrap": 0, "protected": 0}
    commits = {"bootstrap": 0, "protected": 0}
    counter_lock = Lock()

    @event.listens_for(app.state.database.engine, "after_cursor_execute")
    def count_authentication_update(
        _connection,
        cursor,
        statement,
        _parameters,
        _context,
        _many,
    ):
        if (
            statement.lstrip().upper().startswith("UPDATE AUTHENTICATION_SESSIONS")
            and "last_seen_at" in statement
        ):
            with counter_lock:
                activity_statements[phase] += 1
                activity_updates[phase] += int(cursor.rowcount == 1)

    @event.listens_for(app.state.database.engine, "commit")
    def count_commit(_connection):
        with counter_lock:
            commits[phase] += 1

    assert client.get("/api/auth/session").status_code == 200
    assert activity_statements["bootstrap"] <= 1
    assert activity_updates["bootstrap"] <= 1
    assert commits["bootstrap"] <= 1

    phase = "protected"
    protected_paths = (
        "/api/templates",
        "/api/engagements?scope=all",
        "/api/dashboard",
        "/api/provider-catalog/sketch?provider=linode",
        "/api/provider-catalog/sketch?provider=digitalocean",
    )
    async def request_protected_burst():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            cookies=client.cookies,
        ) as async_client:
            return await asyncio.gather(
                *(async_client.get(path) for path in protected_paths)
            )

    responses = asyncio.run(request_protected_burst())

    assert [response.status_code for response in responses] == [200] * 5
    assert activity_statements["protected"] == 0
    assert activity_updates["protected"] == 0
    assert commits["protected"] == 0


def test_inference_proxy_status_start_requires_login_csrf_and_operate(monkeypatch):
    path = '/api/engagements/missing/capabilities/inference-proxy/status'
    body = {'bindingFingerprint': 'a' * 64}
    calls = []
    state = {'status': 'checking', 'configuration': None, 'bindingFingerprint': 'a' * 64,
             'homebaseIdentity': None, 'observation': None, 'job': None, 'errors': []}
    def start(*args, **kwargs):
        calls.append(args)
        return state
    monkeypatch.setattr('app.asgi.start_inference_proxy_status', start)
    monkeypatch.setattr('app.asgi.get_inference_proxy_status', lambda *a, **k: state)
    for roles, expected in [(('viewer',), 403), (('operator',), 202)]:
        app = _app_with_account(roles=roles)
        with app.storage_context():
            AuthenticationService.from_config(AuthTestConfig).reset_password(
                'example_operator_three', 'long permanent password', force_password_change=False)
        client = app.test_client()
        before = len(calls)
        assert client.post(path, json=body).status_code == 401
        assert client.get(path).status_code == 401
        assert len(calls) == before
        login = client.post('/api/auth/login', json={'username': 'example_operator_three', 'password': 'long permanent password'}).json()
        assert client.post(path, json=body).status_code == 401
        assert len(calls) == before
        response = client.post(path, headers={'X-Barragan-CSRF': login['csrfToken']}, json=body)
        assert response.status_code == expected
        assert len(calls) == before + (expected == 202)
        assert client.get(path).status_code == 200  # GET is a persisted view and never invokes SSH.
