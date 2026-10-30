# Copyright (c) 2026, Oracle and/or its affiliates.
from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.services.credentials import test_master_key as credential_test_master_key


SECRET = "do-token-sensitive-value"
ROTATED_SECRET = "rotated-do-token-sensitive-value"


def test_fastapi_credentials_index_and_provider_filter_match_reference_contract(tmp_path, monkeypatch):
    reference_client, fastapi_client = _clients(tmp_path, monkeypatch)
    _create(reference_client, "digitalocean", "do-barragan")
    _create(fastapi_client, "digitalocean", "do-barragan")
    _create(reference_client, "linode", "linode-barragan")
    _create(fastapi_client, "linode", "linode-barragan")

    for path in ("/api/credentials", "/api/credentials?provider=digitalocean"):
        reference_response = reference_client.get(path)
        fastapi_response = fastapi_client.get(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert _credentials_without_ids(fastapi_response.json()) == _credentials_without_ids(reference_response.get_json())
        assert SECRET not in str(fastapi_response.json())
        assert "encryptedSecret" not in str(fastapi_response.json())


def test_fastapi_credentials_create_validate_rotate_default_and_disable_match_reference_contract(tmp_path, monkeypatch):
    reference_client, fastapi_client = _clients(tmp_path, monkeypatch)

    reference_created = _create(reference_client, "digitalocean", "do-barragan", is_default=True)
    fastapi_created = _create(fastapi_client, "digitalocean", "do-barragan", is_default=True)
    reference_id = reference_created["credential"]["id"]
    fastapi_id = fastapi_created["credential"]["id"]

    assert _credential_without_id(fastapi_created["credential"]) == _credential_without_id(reference_created["credential"])
    assert SECRET not in str(fastapi_created)
    assert "encryptedSecret" not in str(fastapi_created)

    for reference_path, fastapi_path, method, body in (
        (f"/api/credentials/{reference_id}/validate", f"/api/credentials/{fastapi_id}/validate", "post", {}),
        (
            f"/api/credentials/{reference_id}",
            f"/api/credentials/{fastapi_id}",
            "patch",
            {"secret": ROTATED_SECRET, "description": "rotated provider token"},
        ),
        (f"/api/credentials/{reference_id}/default", f"/api/credentials/{fastapi_id}/default", "post", {}),
        (f"/api/credentials/{reference_id}", f"/api/credentials/{fastapi_id}", "delete", {}),
    ):
        if method == "delete":
            reference_response = reference_client.delete(reference_path)
            fastapi_response = fastapi_client.delete(fastapi_path)
        else:
            reference_response = getattr(reference_client, method)(reference_path, json=body)
            fastapi_response = getattr(fastapi_client, method)(fastapi_path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert _response_without_ids(fastapi_response.json()) == _response_without_ids(reference_response.get_json())
        assert SECRET not in str(fastapi_response.json())
        assert ROTATED_SECRET not in str(fastapi_response.json())
        assert "encryptedSecret" not in str(fastapi_response.json())


def test_fastapi_credentials_validation_and_missing_shapes_match_reference_contract(tmp_path, monkeypatch):
    reference_client, fastapi_client = _clients(tmp_path, monkeypatch)

    requests = (
        ("post", "/api/credentials", {"provider": "unknown", "alias": "bad", "secret": "value"}),
        ("post", "/api/credentials", {"provider": "namecheap", "alias": "namecheap-barragan", "secret": "missing-colon"}),
        ("post", "/api/credentials/cred-missing/validate", {}),
        ("patch", "/api/credentials/cred-missing", {"secret": SECRET}),
        ("delete", "/api/credentials/cred-missing", {}),
        ("post", "/api/credentials/cred-missing/default", {}),
    )
    for method, path, body in requests:
        if method == "delete":
            reference_response = reference_client.delete(path)
            fastapi_response = fastapi_client.delete(path)
        else:
            reference_response = getattr(reference_client, method)(path, json=body)
            fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()
        assert SECRET not in str(fastapi_response.json())


def test_fastapi_credentials_locked_store_shapes_match_reference_contract(tmp_path, monkeypatch):
    reference_client, fastapi_client = _clients(tmp_path, monkeypatch)
    reference_created = _create(reference_client, "digitalocean", "do-barragan")
    fastapi_created = _create(fastapi_client, "digitalocean", "do-barragan")
    monkeypatch.delenv("BARRAGAN_CREDENTIAL_MASTER_KEY", raising=False)
    reference_id = reference_created["credential"]["id"]
    fastapi_id = fastapi_created["credential"]["id"]

    for method, reference_path, fastapi_path, body in (
        ("post", "/api/credentials", "/api/credentials", {"provider": "digitalocean", "alias": "new-alias", "secret": SECRET}),
        ("patch", f"/api/credentials/{reference_id}", f"/api/credentials/{fastapi_id}", {"secret": SECRET}),
        ("post", f"/api/credentials/{reference_id}/validate", f"/api/credentials/{fastapi_id}/validate", {}),
    ):
        reference_response = getattr(reference_client, method)(reference_path, json=body)
        fastapi_response = getattr(fastapi_client, method)(fastapi_path, json=body)

        assert fastapi_response.status_code == reference_response.status_code == 503
        assert fastapi_response.json() == reference_response.get_json()
        assert SECRET not in str(fastapi_response.json())


def _clients(tmp_path, monkeypatch):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())

    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app.test_client(), fastapi_app.test_client()


def _create(client, provider: str, alias: str, *, is_default: bool = False):
    response = client.post(
        "/api/credentials",
        json={
            "provider": provider,
            "alias": alias,
            "description": f"{provider} test credential",
            "secret": SECRET,
            "isDefault": is_default,
        },
    )
    assert response.status_code == 201
    return response.get_json() if hasattr(response, "get_json") else response.json()


def _credentials_without_ids(body: dict) -> dict:
    return {"credentials": [_credential_without_id(credential) for credential in body["credentials"]]}


def _response_without_ids(body: dict) -> dict:
    if "credential" in body:
        return {"credential": _credential_without_id(body["credential"])}
    if "validation" in body:
        return {
            "validation": {
                **body["validation"],
                "credential": _credential_without_id(body["validation"]["credential"]),
            }
        }
    return body


def _credential_without_id(credential: dict) -> dict:
    return {
        key: value
        for key, value in credential.items()
        if key not in {"id", "createdAt", "updatedAt"}
    }
