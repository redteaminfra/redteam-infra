# Copyright (c) 2026, Oracle and/or its affiliates.
import base64
import json

from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig


PUBLIC_KEY = "ssh-ed25519 dGVhbS1mYXN0YXBpLXRlc3Q= team-fastapi"


def test_fastapi_global_team_index_matches_reference_contract(tmp_path):
    reference_client, fastapi_client = _clients(tmp_path)

    reference_response = reference_client.get("/api/team")
    fastapi_response = fastapi_client.get("/api/team")

    assert fastapi_response.status_code == reference_response.status_code
    assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_global_team_create_update_and_deactivate_match_reference_contract(tmp_path):
    reference_client, fastapi_client = _clients(tmp_path)
    payload = {
        "username": "teamfastapi",
        "displayName": "Team FastAPI",
        "email": "teamfastapi@example.invalid",
        "defaultInfraGroups": ["redteam", "volunteer"],
    }

    reference_created = reference_client.post("/api/team", json=payload)
    fastapi_created = fastapi_client.post("/api/team", json=payload)
    reference_member = reference_created.get_json()["member"]
    fastapi_member = fastapi_created.json()["member"]

    assert fastapi_created.status_code == reference_created.status_code == 201
    assert _member_without_ids(fastapi_member) == _member_without_ids(reference_member)

    update = {"displayName": "Team FastAPI Updated", "globalRoles": ["operator", "approver"]}
    reference_updated = reference_client.patch(f"/api/team/{reference_member['id']}", json=update)
    fastapi_updated = fastapi_client.patch(f"/api/team/{fastapi_member['id']}", json=update)

    assert fastapi_updated.status_code == reference_updated.status_code == 200
    assert _member_without_ids(fastapi_updated.json()["member"]) == _member_without_ids(reference_updated.get_json()["member"])

    reference_deactivated = reference_client.post(f"/api/team/{reference_member['id']}/deactivate")
    fastapi_deactivated = fastapi_client.post(f"/api/team/{fastapi_member['id']}/deactivate")

    assert fastapi_deactivated.status_code == reference_deactivated.status_code == 200
    assert fastapi_deactivated.json()["member"]["status"] == reference_deactivated.get_json()["member"]["status"] == "deactivated"
    assert bool(fastapi_deactivated.json()["member"]["deactivatedAt"]) == bool(reference_deactivated.get_json()["member"]["deactivatedAt"])


def test_fastapi_global_team_validation_and_missing_shapes_match_reference_contract(tmp_path):
    reference_client, fastapi_client = _clients(tmp_path)

    for path, method, body in (
        ("/api/team", "post", {"username": "badrole", "globalRoles": ["redteam"]}),
        ("/api/team/user-missing", "patch", {"displayName": "Missing"}),
        ("/api/team/user-missing/deactivate", "post", {}),
        ("/api/team/user-missing/ssh-keys", "post", {"label": "piv", "publicKey": PUBLIC_KEY}),
        ("/api/team/user-missing/ssh-keys/key-missing", "patch", {"label": "piv"}),
        ("/api/team/user-missing/ssh-keys/key-missing", "delete", {}),
    ):
        reference_response = getattr(reference_client, method)(path, json=body) if method != "delete" else reference_client.delete(path)
        fastapi_response = getattr(fastapi_client, method)(path, json=body) if method != "delete" else fastapi_client.delete(path)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def test_fastapi_global_team_ssh_key_lifecycle_matches_reference_contract(tmp_path):
    reference_client, fastapi_client = _clients(tmp_path)
    reference_member = reference_client.post("/api/team", json={"username": "keyfastapi"}).get_json()["member"]
    fastapi_member = fastapi_client.post("/api/team", json={"username": "keyfastapi"}).json()["member"]

    key_payload = {"label": "primary", "publicKey": PUBLIC_KEY}
    reference_key_response = reference_client.post(f"/api/team/{reference_member['id']}/ssh-keys", json=key_payload)
    fastapi_key_response = fastapi_client.post(f"/api/team/{fastapi_member['id']}/ssh-keys", json=key_payload)
    reference_key = reference_key_response.get_json()["sshKey"]
    fastapi_key = fastapi_key_response.json()["sshKey"]

    assert fastapi_key_response.status_code == reference_key_response.status_code == 201
    assert _key_without_ids(fastapi_key) == _key_without_ids(reference_key)

    replacement = "ssh-ed25519 cmVwbGFjZW1lbnQtZmFzdGFwaS10ZXN0 team-fastapi-replacement"
    update_payload = {"label": "piv", "publicKey": replacement}
    reference_updated = reference_client.patch(f"/api/team/{reference_member['id']}/ssh-keys/{reference_key['id']}", json=update_payload)
    fastapi_updated = fastapi_client.patch(f"/api/team/{fastapi_member['id']}/ssh-keys/{fastapi_key['id']}", json=update_payload)

    assert fastapi_updated.status_code == reference_updated.status_code == 200
    assert _key_without_ids(fastapi_updated.json()["sshKey"]) == _key_without_ids(reference_updated.get_json()["sshKey"])

    reference_retired = reference_client.delete(f"/api/team/{reference_member['id']}/ssh-keys/{reference_key['id']}")
    fastapi_retired = fastapi_client.delete(f"/api/team/{fastapi_member['id']}/ssh-keys/{fastapi_key['id']}")

    assert fastapi_retired.status_code == reference_retired.status_code == 200
    assert fastapi_retired.json()["sshKey"]["status"] == reference_retired.get_json()["sshKey"]["status"] == "retired"


def test_fastapi_global_team_import_preview_and_apply_match_reference_contract(tmp_path):
    reference_client, fastapi_client = _clients(tmp_path)
    encoded_keys = base64.b64encode(PUBLIC_KEY.encode("utf-8")).decode("ascii")
    content = {
        "users": [
            {
                "uid": 6100,
                "username": "importfastapi",
                "name": "Import FastAPI",
                "tags": ["redteam", "core"],
                "authorized_keys": encoded_keys,
            }
        ]
    }
    payload = {"format": "json", "fileName": "users.json", "content": json.dumps(content)}

    reference_preview = reference_client.post("/api/team/import/preview", json=payload)
    fastapi_preview = fastapi_client.post("/api/team/import/preview", json=payload)

    assert fastapi_preview.status_code == reference_preview.status_code == 200
    assert fastapi_preview.json()["preview"]["summary"] == reference_preview.get_json()["preview"]["summary"]
    assert fastapi_preview.json()["preview"]["records"][0]["action"] == reference_preview.get_json()["preview"]["records"][0]["action"]

    reference_apply = reference_client.post("/api/team/import/apply", json=payload)
    fastapi_apply = fastapi_client.post("/api/team/import/apply", json=payload)

    assert fastapi_apply.status_code == reference_apply.status_code == 202
    assert fastapi_apply.json()["applied"] == reference_apply.get_json()["applied"]
    assert fastapi_apply.json()["team"]["members"][0]["username"] == reference_apply.get_json()["team"]["members"][0]["username"]


def _clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app.test_client(), fastapi_app.test_client()


def _member_without_ids(member: dict) -> dict:
    return {
        key: value
        for key, value in member.items()
        if key not in {"id", "createdAt", "updatedAt", "deactivatedAt", "sshKeys"}
    }


def _key_without_ids(key: dict) -> dict:
    return {key_name: value for key_name, value in key.items() if key_name not in {"id", "createdAt", "updatedAt", "retiredAt"}}
