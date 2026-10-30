# Copyright (c) 2026, Oracle and/or its affiliates.
from pathlib import Path
from types import SimpleNamespace

from app.services.credentials import test_master_key as credential_test_master_key
from app.services.mixed_sketch_deployment import _provider_child_input
from app.services.sketch_ssh_keys import (
    ensure_sketch_ssh_key,
    retrieve_sketch_ssh_key,
    write_existing_sketch_ssh_key_files,
)
from app.services.sketch_transport_ssh_keys import (
    ensure_sketch_transport_ssh_key,
    retrieve_sketch_transport_ssh_key,
    write_sketch_transport_ssh_key_files,
    write_existing_sketch_transport_ssh_key_files,
)
from app.services.sketch_ssh_keys import SketchSshKeyNotFoundError


class MemoryKeyRepository:
    def __init__(self):
        self.key = None

    def get(self, engagement_id):
        if self.key is not None and self.key.engagement_id == engagement_id:
            return self.key
        return None

    def save(self, key):
        self.key = key
        return key


def test_transport_key_is_independent_and_materializes_with_private_permissions(
    monkeypatch, tmp_path
):
    monkeypatch.setenv(
        "BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key()
    )
    engagement = SimpleNamespace(id="eng-1", name="of02-dev")
    monkeypatch.setattr(
        "app.services.sketch_ssh_keys.get_engagement", lambda _engagement_id: engagement
    )
    monkeypatch.setattr(
        "app.services.sketch_transport_ssh_keys.get_engagement",
        lambda _engagement_id: engagement,
    )
    admin_repository = MemoryKeyRepository()
    transport_repository = MemoryKeyRepository()

    ensure_sketch_ssh_key(engagement.id, admin_repository)
    metadata = ensure_sketch_transport_ssh_key(
        engagement.id, transport_repository
    )
    admin = retrieve_sketch_ssh_key(engagement.id, admin_repository)
    transport = retrieve_sketch_transport_ssh_key(
        engagement.id, transport_repository
    )

    assert admin is not None
    assert transport is not None
    assert admin.metadata.fingerprint != transport.metadata.fingerprint
    assert metadata.private_key_name.endswith("-sketch-transport")

    private_path, public_path = write_sketch_transport_ssh_key_files(
        engagement.id, Path(tmp_path), transport_repository
    )
    assert Path(private_path).stat().st_mode & 0o777 == 0o600
    assert Path(public_path).stat().st_mode & 0o777 == 0o644
    assert Path(private_path).read_text(encoding="utf-8") == transport.private_key


def test_existing_transport_key_writer_never_creates_an_absent_key(tmp_path):
    repository = MemoryKeyRepository()

    try:
        write_existing_sketch_transport_ssh_key_files("eng-missing", tmp_path, repository)
    except SketchSshKeyNotFoundError:
        pass
    else:
        raise AssertionError("retrieve-only writer unexpectedly created a transport key")

    assert repository.key is None


def test_existing_infrastructure_admin_writer_never_creates_an_absent_key(tmp_path):
    repository = MemoryKeyRepository()

    try:
        write_existing_sketch_ssh_key_files("eng-missing", tmp_path, repository)
    except SketchSshKeyNotFoundError:
        pass
    else:
        raise AssertionError("retrieve-only writer unexpectedly created an infrastructure-admin key")

    assert repository.key is None


def test_existing_infrastructure_admin_writer_materializes_private_permissions(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", credential_test_master_key())
    engagement = SimpleNamespace(id="eng-1", name="of02-dev")
    monkeypatch.setattr(
        "app.services.sketch_ssh_keys.get_engagement", lambda _engagement_id: engagement
    )
    repository = MemoryKeyRepository()
    ensure_sketch_ssh_key(engagement.id, repository)
    material = retrieve_sketch_ssh_key(engagement.id, repository)

    private_path, public_path = write_existing_sketch_ssh_key_files(
        engagement.id, Path(tmp_path), repository
    )

    assert material is not None
    assert Path(private_path).stat().st_mode & 0o777 == 0o600
    assert Path(public_path).stat().st_mode & 0o777 == 0o644
    assert Path(private_path).read_text(encoding="utf-8") == material.private_key


def test_mixed_child_input_passes_materialized_transport_identity():
    spec = {
        "engagementId": "eng-1",
        "engagementName": "of02-dev",
        "chainId": "proxy01-chain-1",
        "assignedProxy": "proxy01",
        "middleCredentialAlias": "linode-dev",
        "edgeCredentialAlias": "digitalocean-dev",
        "middleRegion": "us-sea",
        "edgeRegion": "sfo3",
        "middleSize": "g6-nanode-1",
        "edgeSize": "s-1vcpu-1gb",
        "edgeCount": 2,
        "edgeRegions": ["sfo3", "nyc3"],
        "edgeCountPerRegion": 1,
        "edges": [],
        "managedHostImageProfile": "ubuntu-24.04",
    }

    child = _provider_child_input(
        spec,
        provider="linode",
        credential_alias="linode-dev",
        middle_count=1,
        edge_count=0,
        workspace=Path("/tmp/middle"),
        private_key_path="/tmp/keys/admin",
        public_key_path="/tmp/keys/admin.pub",
        transport_private_key_path="/tmp/keys/transport",
        transport_public_key_path="/tmp/keys/transport.pub",
    )

    assert child["sshPublicKeyPath"] == "/tmp/keys/admin.pub"
    assert child["sketchTransportSshPrivateKeyPath"] == "/tmp/keys/transport"
    assert child["sketchTransportSshPublicKeyPath"] == "/tmp/keys/transport.pub"
    assert child["managedHostImageProfile"] == "ubuntu-24.04"
