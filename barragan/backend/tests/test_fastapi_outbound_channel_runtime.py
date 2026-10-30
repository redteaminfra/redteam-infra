# Copyright (c) 2026, Oracle and/or its affiliates.
import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import create_app as create_reference_app
from app.asgi import create_app as create_fastapi_app
from app.core.config import TestConfig
from app.domain import JobEvent
from app.services.outbound_channel_artifacts import derive_pending_outbound_channel_from_sketch_rows
from app.storage.database import db
from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository, StoredSketchChain
from tests.runtime_support import storage_context


ENGAGEMENT_ID = "eng-fastapi-outbound"
ENGAGEMENT_NAME = "ZFO01"
CHAIN_ID = "chain-1"


@pytest.fixture(autouse=True)
def _isolated_credential_store(monkeypatch):
    from app.services.credentials import test_master_key
    from app.services import sketch_ssh_keys
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", test_master_key())
    # Both runtimes model the same infrastructure and therefore the same
    # already-provisioned transport identity, in separate encrypted stores.
    pair = sketch_ssh_keys._generate_ed25519_pair()
    monkeypatch.setattr(sketch_ssh_keys, "_generate_ed25519_pair", lambda: pair)


def test_fastapi_outbound_preview_apply_and_validate_match_reference_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)
    _seed_outbound_apply_prerequisites(reference_app, tmp_path / "core-workspace")
    _seed_outbound_apply_prerequisites(fastapi_app.state.database, tmp_path / "core-workspace")
    ansible = _make_executable(tmp_path, "ansible")
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    monkeypatch.setenv("ANSIBLE_BIN", str(ansible))
    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.outbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "outbound-workspaces")
    monkeypatch.setattr("app.services.outbound_channel_apply._apply_workspace_dir",
                        lambda chain_id, _root: tmp_path / "outbound-workspaces" / chain_id)
    monkeypatch.setattr("app.services.outbound_channel_apply._run_command", _successful_runner)
    from app.services.sketch_provider_firewall import ProviderIngressSyncResult
    monkeypatch.setattr(
        "app.services.outbound_channel_apply._reconcile_provider_firewall_for_outbound_apply",
        lambda *_args, **_kwargs: ProviderIngressSyncResult("synced", True, "linode", CHAIN_ID, ()),
    )

    requests = (
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/outbound-channels/{CHAIN_ID}/apply-preview",
            {"requestedBy": "operator"},
            201,
        ),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/outbound-channels/{CHAIN_ID}/apply",
            {"confirmation": f"apply-outbound-{CHAIN_ID}", "requestedBy": "operator"},
            202,
        ),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/outbound-channels/{CHAIN_ID}/validate",
            {"confirmation": f"validate-outbound-{CHAIN_ID}", "requestedBy": "operator"},
            202,
        ),
    )

    for method, path, body, expected_status in requests:
        reference_response = getattr(reference_client, method)(path, json=body)
        fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code == expected_status
        assert _scrub_volatile(fastapi_response.json()) == _scrub_volatile(reference_response.get_json())


def test_fastapi_outbound_validation_errors_match_reference_contract(tmp_path, monkeypatch):
    reference_app, reference_client, fastapi_app, fastapi_client = _separate_clients(tmp_path)
    _seed_engagement(reference_app)
    _seed_engagement(fastapi_app.state.database)
    _seed_outbound_apply_prerequisites(reference_app, tmp_path / "core-workspace")
    _seed_outbound_apply_prerequisites(fastapi_app.state.database, tmp_path / "core-workspace")
    ansible = _make_executable(tmp_path, "ansible")
    monkeypatch.setenv("ANSIBLE_BIN", str(ansible))

    requests = (
        (
            "post",
            f"/api/engagements/eng-missing/outbound-channels/{CHAIN_ID}/apply-preview",
            {},
        ),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/outbound-channels/missing-chain/apply-preview",
            {},
        ),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/outbound-channels/{CHAIN_ID}/apply",
            {"confirmation": "wrong"},
        ),
        (
            "post",
            f"/api/engagements/{ENGAGEMENT_ID}/outbound-channels/{CHAIN_ID}/validate",
            {"confirmation": "wrong"},
        ),
    )

    for method, path, body in requests:
        reference_response = getattr(reference_client, method)(path, json=body)
        fastapi_response = getattr(fastapi_client, method)(path, json=body)

        assert fastapi_response.status_code == reference_response.status_code
        assert fastapi_response.json() == reference_response.get_json()


def _separate_clients(tmp_path):
    class ReferenceSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'reference.sqlite3'}"

    class FastApiSqliteConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fastapi.sqlite3'}"

    reference_app = create_reference_app(ReferenceSqliteConfig)
    fastapi_app = create_fastapi_app(FastApiSqliteConfig)
    return reference_app, reference_app.test_client(), fastapi_app, fastapi_app.test_client()


def _seed_engagement(reference_app) -> None:
    with storage_context(reference_app):
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id=ENGAGEMENT_ID,
                name=ENGAGEMENT_NAME,
                status="draft",
                owner="operator",
                template_id="standard-rti",
                active_revision=None,
                input_parameters={},
                description="FastAPI outbound channel fixture",
                created_at="2026-07-06T00:00:00+00:00",
                updated_at="2026-07-06T00:00:00+00:00",
            )
        )
        db.session.remove()


def _seed_outbound_apply_prerequisites(reference_app, core_workspace: Path) -> None:
    from app.services.sketch_transport_ssh_keys import ensure_sketch_transport_ssh_key
    with storage_context(reference_app):
        ensure_sketch_transport_ssh_key(ENGAGEMENT_ID)
        repository = SqlAlchemyJobRepository()
        repository.save(
            StoredJobRun(
                id=f"job-{ENGAGEMENT_ID}-core",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={
                    "engagementId": ENGAGEMENT_ID,
                    "chainId": CHAIN_ID,
                    "sshPrivateKeyPath": "/tmp/barragan-keys/zfo01-sketch",
                },
                artifact_refs=[],
                created_at="2026-06-04T12:00:00+00:00",
                started_at="2026-06-04T12:01:00+00:00",
                finished_at="2026-06-04T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "operator inspection ready",
                        {
                            "workspaceDir": str(core_workspace),
                            "connectionDetails": [
                                {
                                    "role": "homebase",
                                    "displayName": "homebase-zfo01",
                                    "sshAlias": "homebase-zfo01",
                                    "publicIp": "203.0.113.10",
                                    "privateIp": "192.168.0.10",
                                    "sshUser": "user",
                                },
                                {
                                    "role": "proxy01",
                                    "displayName": "proxy01-zfo01",
                                    "sshAlias": "proxy01-zfo01",
                                    "publicIp": "203.0.113.11",
                                    "privateIp": "192.168.2.11",
                                    "sshUser": "user",
                                },
                            ]
                        },
                    )
                ],
            )
        )
        repository.save(
            StoredJobRun(
                id=f"job-{ENGAGEMENT_ID}-outbound",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{ENGAGEMENT_ID}",
                target_type="engagement",
                target_id=ENGAGEMENT_ID,
                requested_by="operator",
                input={"engagementId": ENGAGEMENT_ID},
                artifact_refs=[],
                created_at="2026-06-04T12:10:00+00:00",
                started_at="2026-06-04T12:11:00+00:00",
                finished_at="2026-06-04T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pending outbound channel artifacts derived",
                        {"outboundChannels": [_pending_outbound_channel()]},
                    ),
                    JobEvent(2, "info", "sketch bootstrap succeeded", {"bootstrap": "succeeded"}),
                ],
            )
        )
        SqlAlchemySketchChainRepository().save(StoredSketchChain(
            chain_id=CHAIN_ID, engagement_id=ENGAGEMENT_ID, assigned_proxy="proxy01",
            middle_provider="linode", middle_region="us-sea", middle_size="g6-nanode-1",
            edge_provider="linode", edge_region="us-sea", edge_size="g6-nanode-1",
            status="deployed", burned=False, burned_note="",
            deploy_job_id=f"job-{ENGAGEMENT_ID}-outbound", teardown_job_id="",
            terraform_working_directory="", nodes=_sketch_nodes(),
            created_at="2026-06-04T12:10:00+00:00", updated_at="2026-06-04T12:15:00+00:00",
        ))
        db.session.remove()


def _pending_outbound_channel() -> dict[str, Any]:
    channel = derive_pending_outbound_channel_from_sketch_rows(
        ENGAGEMENT_NAME,
        CHAIN_ID,
        _sketch_nodes(),
    )
    assert channel is not None
    return channel


def _sketch_nodes():
    return [
            {
                "chainId": CHAIN_ID,
                "hostname": "middle-zfo01-chain-1",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": CHAIN_ID,
                "hostname": "edge-zfo01-chain-1",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.30",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ]


def _make_executable(tmp_path, name: str) -> Path:
    executable = tmp_path / name
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _successful_runner(command, cwd):
    stdout = "203.0.113.30\n" if "ansible.builtin.command" in command else ""
    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


def _scrub_volatile(value):
    if isinstance(value, dict):
        scrubbed = {}
        for key, item in value.items():
            if key == "id" and isinstance(item, str) and item.startswith("job-"):
                scrubbed[key] = "<job-id>"
            elif key in {"createdAt", "startedAt", "finishedAt", "checkedAt", "lastCheckedAt"} and item:
                scrubbed[key] = "<timestamp>"
            elif key in {"workspaceDir", "cwd"} and item:
                scrubbed[key] = "<workspace-dir>"
            else:
                scrubbed[key] = _scrub_volatile(item)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_volatile(item) for item in value]
    return value
