# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest

from app import create_app
from app.core.config import TestConfig
from app.storage.database import db
from app.services.credentials import test_master_key as credential_test_master_key
from app.storage.models import SketchChainModel, SketchSshKeyModel


@pytest.fixture()
def sketch_key_client(monkeypatch):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())
    app = create_app(TestConfig)
    return app, app.test_client()


def test_sketch_ssh_key_generation_redacts_material_until_explicit_retrieval(sketch_key_client):
    app, client = sketch_key_client

    create_response = client.post("/api/engagements/eng-of02-dev/sketch-ssh-key")
    body = create_response.get_json()

    assert create_response.status_code == 201
    assert body["key"]["privateKeyName"] == "of02-dev-reference-sketch"
    assert body["key"]["publicKeyName"] == "of02-dev-reference-sketch.pub"
    assert body["key"]["fingerprint"].startswith("SHA256:")
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)
    assert "ssh-ed25519 " not in str(body)

    metadata_response = client.get("/api/engagements/eng-of02-dev/sketch-ssh-key")
    assert metadata_response.status_code == 200
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(metadata_response.get_json())

    with app.storage_context():
        row = SketchSshKeyModel.query.get("eng-of02-dev")
        assert row is not None
        assert "BEGIN OPENSSH PRIVATE KEY" not in row.encrypted_private_key
        assert "ssh-ed25519" not in row.encrypted_public_key


def test_explicit_sketch_ssh_key_material_endpoint_returns_keypair(sketch_key_client):
    _app, client = sketch_key_client
    client.post("/api/engagements/eng-of02-dev/sketch-ssh-key")

    response = client.get("/api/engagements/eng-of02-dev/sketch-ssh-key/material")
    body = response.get_json()

    assert response.status_code == 200
    assert body["keyMaterial"]["key"]["privateKeyName"] == "of02-dev-reference-sketch"
    assert body["keyMaterial"]["privateKey"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert body["keyMaterial"]["publicKey"].startswith("ssh-ed25519 ")


def test_sketch_ssh_key_generation_is_idempotent(sketch_key_client):
    _app, client = sketch_key_client

    first = client.post("/api/engagements/eng-of02-dev/sketch-ssh-key").get_json()["key"]
    second = client.post("/api/engagements/eng-of02-dev/sketch-ssh-key").get_json()["key"]

    assert first["fingerprint"] == second["fingerprint"]


def test_sketch_ssh_key_generation_is_unique_per_engagement(sketch_key_client):
    _app, client = sketch_key_client
    first_engagement = client.post("/api/engagements", json={"name": "KEY01", "owner": "operator"}).get_json()["engagement"]
    second_engagement = client.post("/api/engagements", json={"name": "KEY02", "owner": "operator"}).get_json()["engagement"]

    first = client.post(f"/api/engagements/{first_engagement['id']}/sketch-ssh-key").get_json()["key"]
    second = client.post(f"/api/engagements/{second_engagement['id']}/sketch-ssh-key").get_json()["key"]

    assert first["privateKeyName"] == "key01-sketch"
    assert first["publicKeyName"] == "key01-sketch.pub"
    assert second["privateKeyName"] == "key02-sketch"
    assert second["publicKeyName"] == "key02-sketch.pub"
    assert first["fingerprint"] != second["fingerprint"]


def test_sketch_ssh_key_rotation_preview_redacts_material_and_reports_ready(sketch_key_client):
    _app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "ROT01", "owner": "operator"}).get_json()["engagement"]
    key = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]

    response = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key/rotation-preview")
    body = response.get_json()

    assert response.status_code == 200
    assert body["rotation"]["status"] == "ready"
    assert body["rotation"]["mutation"] is False
    assert body["rotation"]["currentKey"]["fingerprint"] == key["fingerprint"]
    assert body["rotation"]["requiresRepair"] is False
    assert body["rotation"]["confirmation"] == "rotate-sketch-key"
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)
    assert "ssh-ed25519 " not in str(body)


def test_sketch_ssh_key_rotation_requires_confirmation(sketch_key_client):
    _app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "ROT02", "owner": "operator"}).get_json()["engagement"]

    response = client.post(
        f"/api/engagements/{engagement['id']}/sketch-ssh-key/rotate",
        json={"confirmation": "wrong"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ['confirmation must equal "rotate-sketch-key"']


def test_sketch_ssh_key_rotation_changes_key_when_no_live_chain_requires_repair(sketch_key_client):
    app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "ROT03", "owner": "operator"}).get_json()["engagement"]
    first = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]

    response = client.post(
        f"/api/engagements/{engagement['id']}/sketch-ssh-key/rotate",
        json={"confirmation": "rotate-sketch-key"},
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["previousFingerprint"] == first["fingerprint"]
    assert body["key"]["privateKeyName"] == "rot03-sketch"
    assert body["key"]["fingerprint"] != first["fingerprint"]
    assert body["key"]["retiredKeys"][0]["fingerprint"] == first["fingerprint"]
    assert body["key"]["retiredKeys"][0]["status"] == "retired"
    assert body["key"]["retiredKeys"][0]["reason"] == "rotated"
    assert body["rotation"]["status"] == "rotated"
    assert body["rotation"]["currentKey"]["retiredKeys"][0]["fingerprint"] == first["fingerprint"]
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)
    assert "ssh-ed25519 " not in str(body)

    metadata = client.get(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]
    assert metadata["retiredKeys"][0]["fingerprint"] == first["fingerprint"]
    with app.storage_context():
        row = SketchSshKeyModel.query.get(engagement["id"])
        assert row.retired_keys[0]["fingerprint"] == first["fingerprint"]
        assert "BEGIN OPENSSH PRIVATE KEY" not in str(row.retired_keys)
        assert "ssh-ed25519 " not in str(row.retired_keys)


def test_sketch_ssh_key_rotation_accumulates_redacted_retired_key_history(sketch_key_client):
    _app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "ROT05", "owner": "operator"}).get_json()["engagement"]
    first = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]

    second = client.post(
        f"/api/engagements/{engagement['id']}/sketch-ssh-key/rotate",
        json={"confirmation": "rotate-sketch-key"},
    ).get_json()["key"]
    third_response = client.post(
        f"/api/engagements/{engagement['id']}/sketch-ssh-key/rotate",
        json={"confirmation": "rotate-sketch-key"},
    )
    third = third_response.get_json()["key"]

    assert third_response.status_code == 200
    assert [row["fingerprint"] for row in third["retiredKeys"]] == [first["fingerprint"], second["fingerprint"]]
    assert all(row["status"] == "retired" for row in third["retiredKeys"])
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(third_response.get_json())
    assert "ssh-ed25519 " not in str(third_response.get_json())


def test_sketch_ssh_key_rotation_blocks_when_deployed_chain_requires_repair(sketch_key_client):
    app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "ROT04", "owner": "operator"}).get_json()["engagement"]
    first = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]
    with app.storage_context():
        db.session.add(
            SketchChainModel(
                engagement_id=engagement["id"],
                chain_id="proxy01-sea-01",
                assigned_proxy="proxy01",
                middle_provider="linode",
                middle_region="us-sea",
                middle_size="g6-nanode-1",
                edge_provider="linode",
                edge_region="us-sea",
                edge_size="g6-nanode-1",
                status="deployed",
                nodes=[
                    {
                        "hostname": "middle-rot04-proxy01-sea-01",
                        "role": "middle",
                        "provider": "linode",
                        "publicIp": "203.0.113.10",
                    }
                ],
            )
        )
        db.session.commit()

    response = client.post(
        f"/api/engagements/{engagement['id']}/sketch-ssh-key/rotate",
        json={"confirmation": "rotate-sketch-key"},
    )
    body = response.get_json()

    assert response.status_code == 400
    assert body["rotation"]["status"] == "blocked"
    assert body["rotation"]["requiresRepair"] is True
    assert body["rotation"]["affectedChains"][0]["chainId"] == "proxy01-sea-01"
    assert body["rotation"]["affectedChains"][0]["requiredAction"] == "reprovision_or_opsec_safe_repair"
    assert body["rotation"]["opsecBoundary"]["directSketchAccess"] is False

    current = client.get(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]
    assert current["fingerprint"] == first["fingerprint"]
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)


def test_sketch_ssh_key_removal_preview_redacts_material_and_reports_ready(sketch_key_client):
    _app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "RM01", "owner": "operator"}).get_json()["engagement"]
    key = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]

    response = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key/removal-preview")
    body = response.get_json()

    assert response.status_code == 200
    assert body["removal"]["status"] == "ready"
    assert body["removal"]["mutation"] is False
    assert body["removal"]["currentKey"]["fingerprint"] == key["fingerprint"]
    assert body["removal"]["requiresTeardown"] is False
    assert body["removal"]["confirmation"] == "remove-sketch-key"
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)
    assert "ssh-ed25519 " not in str(body)


def test_sketch_ssh_key_removal_requires_confirmation(sketch_key_client):
    _app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "RM02", "owner": "operator"}).get_json()["engagement"]
    client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key")

    response = client.delete(
        f"/api/engagements/{engagement['id']}/sketch-ssh-key",
        json={"confirmation": "wrong"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ['confirmation must equal "remove-sketch-key"']


def test_sketch_ssh_key_removal_blocks_when_chain_is_not_torn_down(sketch_key_client):
    app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "RM03", "owner": "operator"}).get_json()["engagement"]
    key = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]
    with app.storage_context():
        db.session.add(
            SketchChainModel(
                engagement_id=engagement["id"],
                chain_id="proxy01-sea-01",
                assigned_proxy="proxy01",
                middle_provider="linode",
                middle_region="us-sea",
                middle_size="g6-nanode-1",
                edge_provider="linode",
                edge_region="us-sea",
                edge_size="g6-nanode-1",
                status="deployed",
                nodes=[
                    {
                        "hostname": "middle-rm03-proxy01-sea-01",
                        "role": "middle",
                        "provider": "linode",
                        "publicIp": "203.0.113.20",
                    }
                ],
            )
        )
        db.session.commit()

    response = client.delete(
        f"/api/engagements/{engagement['id']}/sketch-ssh-key",
        json={"confirmation": "remove-sketch-key"},
    )
    body = response.get_json()

    assert response.status_code == 400
    assert body["removal"]["status"] == "blocked"
    assert body["removal"]["requiresTeardown"] is True
    assert any(blocker["kind"] == "sketch_chain" for blocker in body["removal"]["blockers"])
    assert body["removal"]["opsecBoundary"]["directSketchAccess"] is False
    current = client.get(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]
    assert current["fingerprint"] == key["fingerprint"]


def test_sketch_ssh_key_removal_deletes_material_after_torn_down_state(sketch_key_client):
    app, client = sketch_key_client
    engagement = client.post("/api/engagements", json={"name": "RM04", "owner": "operator"}).get_json()["engagement"]
    key = client.post(f"/api/engagements/{engagement['id']}/sketch-ssh-key").get_json()["key"]
    with app.storage_context():
        db.session.add(
            SketchChainModel(
                engagement_id=engagement["id"],
                chain_id="proxy01-sea-01",
                assigned_proxy="proxy01",
                middle_provider="linode",
                middle_region="us-sea",
                middle_size="g6-nanode-1",
                edge_provider="linode",
                edge_region="us-sea",
                edge_size="g6-nanode-1",
                status="destroyed",
                nodes=[],
            )
        )
        db.session.commit()

    response = client.delete(
        f"/api/engagements/{engagement['id']}/sketch-ssh-key",
        json={"confirmation": "remove-sketch-key"},
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["removedKey"]["fingerprint"] == key["fingerprint"]
    assert body["removal"]["status"] == "removed"
    assert body["removal"]["removedFingerprint"] == key["fingerprint"]
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)

    assert client.get(f"/api/engagements/{engagement['id']}/sketch-ssh-key").status_code == 404
    assert client.get(f"/api/engagements/{engagement['id']}/sketch-ssh-key/material").status_code == 404
