# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest

from app import create_app
from app.core.config import TestConfig
from app.services.credentials import (
    resolve_credential_secret,
    resolve_default_credential_alias,
    test_master_key as credential_test_master_key,
)
from app.storage.models import CredentialModel


@pytest.fixture()
def credential_client(monkeypatch):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())
    app = create_app(TestConfig)
    return app, app.test_client()


def test_credential_api_encrypts_and_redacts_secret(credential_client):
    app, client = credential_client

    response = client.post(
        "/api/credentials",
        json={
            "provider": "linode",
            "alias": "linode-sketch-dev",
            "description": "Dev sketch token",
            "secret": "linode-token-sensitive-value",
        },
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["credential"]["provider"] == "linode"
    assert body["credential"]["alias"] == "linode-sketch-dev"
    assert body["credential"]["isDefault"] is False
    assert "secret" not in body["credential"]
    assert "encryptedSecret" not in body["credential"]
    assert "linode-token-sensitive-value" not in str(body)

    with app.storage_context():
        row = CredentialModel.query.filter_by(alias="linode-sketch-dev").one()
        assert row.encrypted_secret
        assert "linode-token-sensitive-value" not in row.encrypted_secret
        assert resolve_credential_secret("linode", "linode-sketch-dev") == "linode-token-sensitive-value"

    list_body = client.get("/api/credentials").get_json()
    assert "linode-token-sensitive-value" not in str(list_body)
    assert list_body["credentials"][0]["alias"] == "linode-sketch-dev"


def test_credential_validation_and_disable(credential_client):
    _app, client = credential_client
    create_response = client.post(
        "/api/credentials",
        json={"provider": "digitalocean", "alias": "do-sketch-dev", "secret": "do-token"},
    )
    credential_id = create_response.get_json()["credential"]["id"]

    validate_response = client.post(f"/api/credentials/{credential_id}/validate")
    assert validate_response.status_code == 200
    assert validate_response.get_json()["validation"]["decryptable"] is True
    assert "do-token" not in str(validate_response.get_json())

    delete_response = client.delete(f"/api/credentials/{credential_id}")
    assert delete_response.status_code == 200
    assert delete_response.get_json()["credential"]["status"] == "disabled"


def test_credential_rotation_replaces_secret_and_redacts_response(credential_client):
    app, client = credential_client
    create_response = client.post(
        "/api/credentials",
        json={"provider": "linode", "alias": "linode-rotate", "description": "old token", "secret": "old-secret"},
    )
    credential_id = create_response.get_json()["credential"]["id"]

    rotate_response = client.patch(
        f"/api/credentials/{credential_id}",
        json={"description": "rotated token", "secret": "new-secret"},
    )
    body = rotate_response.get_json()

    assert rotate_response.status_code == 200
    assert body["credential"]["description"] == "rotated token"
    assert body["credential"]["status"] == "active"
    assert "old-secret" not in str(body)
    assert "new-secret" not in str(body)

    with app.storage_context():
        row = CredentialModel.query.filter_by(alias="linode-rotate").one()
        assert "old-secret" not in row.encrypted_secret
        assert "new-secret" not in row.encrypted_secret
        assert resolve_credential_secret("linode", "linode-rotate") == "new-secret"


def test_credential_rotation_reactivates_disabled_alias(credential_client):
    _app, client = credential_client
    create_response = client.post(
        "/api/credentials",
        json={"provider": "digitalocean", "alias": "do-rotate", "secret": "old-token"},
    )
    credential_id = create_response.get_json()["credential"]["id"]
    disable_response = client.delete(f"/api/credentials/{credential_id}")
    assert disable_response.get_json()["credential"]["status"] == "disabled"

    rotate_response = client.patch(
        f"/api/credentials/{credential_id}",
        json={"secret": "new-token"},
    )

    assert rotate_response.status_code == 200
    assert rotate_response.get_json()["credential"]["status"] == "active"
    assert "new-token" not in str(rotate_response.get_json())


def test_credential_create_requires_master_key(monkeypatch):
    monkeypatch.delenv("BARRAGAN_CREDENTIAL_MASTER_KEY", raising=False)
    monkeypatch.delenv("BARRAGAN_CREDENTIAL_MASTER_KEY_FILE", raising=False)
    app = create_app(TestConfig)
    client = app.test_client()

    response = client.post(
        "/api/credentials",
        json={"provider": "linode", "alias": "linode-sketch-dev", "secret": "token"},
    )

    assert response.status_code == 503
    assert "master key" in response.get_json()["error"]


def test_credential_master_key_can_load_from_file(monkeypatch, tmp_path):
    key_path = tmp_path / "credential-master.key"
    key_path.write_text(credential_test_master_key(), encoding="utf-8")
    monkeypatch.delenv("BARRAGAN_CREDENTIAL_MASTER_KEY", raising=False)
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY_FILE", str(key_path))
    app = create_app(TestConfig)
    client = app.test_client()

    response = client.post(
        "/api/credentials",
        json={"provider": "linode", "alias": "linode-file-key", "secret": "token-from-file-key"},
    )

    assert response.status_code == 201
    assert response.get_json()["credential"]["alias"] == "linode-file-key"
    assert "token-from-file-key" not in str(response.get_json())


def test_provider_default_credential_is_unique_and_redacted(credential_client):
    app, client = credential_client
    first = client.post(
        "/api/credentials",
        json={"provider": "linode", "alias": "linode-default-one", "secret": "first-token"},
    ).get_json()["credential"]
    second = client.post(
        "/api/credentials",
        json={"provider": "linode", "alias": "linode-default-two", "secret": "second-token"},
    ).get_json()["credential"]

    first_default = client.post(f"/api/credentials/{first['id']}/default")
    assert first_default.status_code == 200
    assert first_default.get_json()["credential"]["isDefault"] is True
    assert "first-token" not in str(first_default.get_json())

    second_default = client.post(f"/api/credentials/{second['id']}/default")
    assert second_default.status_code == 200
    assert second_default.get_json()["credential"]["isDefault"] is True

    listed = client.get("/api/credentials?provider=linode").get_json()["credentials"]
    defaults = [credential["alias"] for credential in listed if credential["isDefault"]]
    assert defaults == ["linode-default-two"]
    assert "first-token" not in str(listed)
    assert "second-token" not in str(listed)

    with app.storage_context():
        assert resolve_default_credential_alias("linode") == "linode-default-two"


def test_creating_credential_can_mark_provider_default(credential_client):
    _app, client = credential_client

    response = client.post(
        "/api/credentials",
        json={
            "provider": "digitalocean",
            "alias": "do-default",
            "secret": "do-default-token",
            "isDefault": True,
        },
    )

    assert response.status_code == 201
    assert response.get_json()["credential"]["isDefault"] is True
    assert "do-default-token" not in str(response.get_json())
