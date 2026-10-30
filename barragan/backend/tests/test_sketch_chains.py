# Copyright (c) 2026, Oracle and/or its affiliates.
from unittest.mock import Mock, patch
from contextlib import contextmanager
from dataclasses import replace
import threading
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app import create_app
from app.core.config import TestConfig
from app.storage.database import db
from app.storage.models import SketchChainModel
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun
from app.services.outbound_channel_apply import OutboundChannelApplyValidationError
from app.services.sketch_chains import SketchChainValidationError, deploy_sketch_chain, ensure_sketch_chain_teardown, teardown_sketch_chain


def test_keyed_engagement_never_enters_chain_scoped_terraform_dispatch():
    with patch("app.services.sketch_chains.get_engagement", return_value=SimpleNamespace(
        sketch_state_schema="provider-keyed-v2"
    )), patch("app.services.sketch_chains.start_guarded_linode_sketch_run") as legacy_deploy, patch(
        "app.services.sketch_chains.start_guarded_linode_sketch_teardown"
    ) as legacy_teardown:
        with pytest.raises(SketchChainValidationError) as deploy_error:
            deploy_sketch_chain("eng-keyed", "chain-01", {})
        with pytest.raises(SketchChainValidationError) as teardown_error:
            teardown_sketch_chain("eng-keyed", "chain-01", {})
    assert "existing split-v1 engagement" in deploy_error.value.errors[0]
    assert "existing split-v1 engagement" in teardown_error.value.errors[0]
    legacy_deploy.assert_not_called()
    legacy_teardown.assert_not_called()


def test_missing_engagement_never_enters_chain_scoped_terraform_dispatch():
    with patch("app.services.sketch_chains.get_engagement", return_value=None), patch(
        "app.services.sketch_chains.start_guarded_linode_sketch_run"
    ) as legacy_deploy, patch(
        "app.services.sketch_chains.start_guarded_linode_sketch_teardown"
    ) as legacy_teardown:
        with pytest.raises(SketchChainValidationError) as deploy_error:
            deploy_sketch_chain("eng-missing", "chain-01", {})
        with pytest.raises(SketchChainValidationError) as teardown_error:
            teardown_sketch_chain("eng-missing", "chain-01", {})
    assert "existing split-v1 engagement" in deploy_error.value.errors[0]
    assert "existing split-v1 engagement" in teardown_error.value.errors[0]
    legacy_deploy.assert_not_called()
    legacy_teardown.assert_not_called()


@pytest.mark.parametrize(
    ("status", "deploy_job_id", "teardown_job_id"),
    [
        ("pending", "", ""),
        ("destroyed", "job-deploy", "job-teardown"),
        ("failed", "job-deploy", "job-teardown"),
        ("tearing_down", "job-deploy", "job-teardown"),
        ("deployed", "job-deploy", ""),
    ],
)
def test_keyed_engagement_cannot_bypass_chain_teardown_guard(
    status: str, deploy_job_id: str, teardown_job_id: str
):
    engagement_id = "eng-keyed"
    chain_id = "chain-01"
    repository = Mock()
    repository.get.return_value = SimpleNamespace(
        status=status,
        deploy_job_id=deploy_job_id,
        teardown_job_id=teardown_job_id,
        chain_id=chain_id,
    )
    with patch(
        "app.services.sketch_chains.get_engagement",
        return_value=SimpleNamespace(sketch_state_schema="provider-keyed-v2"),
    ), patch(
        "app.services.sketch_chains._assert_core_mutation_allowed"
    ) as lease_check, patch(
        "app.services.sketch_chains.start_guarded_linode_sketch_teardown"
    ) as legacy_start, patch(
        "app.services.sketch_chains.resume_guarded_linode_sketch_teardown"
    ) as legacy_resume:
        with pytest.raises(SketchChainValidationError) as error:
            ensure_sketch_chain_teardown(
                engagement_id,
                chain_id,
                {"confirmation": f"teardown-{chain_id}"},
                repository=repository,
            )
        assert "existing split-v1 engagement" in error.value.errors[0]
        lease_check.assert_not_called()
        repository.get.assert_not_called()
        repository.save.assert_not_called()
        legacy_start.assert_not_called()
        legacy_resume.assert_not_called()


def test_sketch_chain_ids_are_stable_per_proxy_region_and_burn_is_mark_only():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ZY01")

    first = _create_chain(client, engagement_id, "proxy01", "us-sea")
    second = _create_chain(client, engagement_id, "proxy01", "us-sea")

    assert first["chainId"] == "proxy01-sea-01"
    assert second["chainId"] == "proxy01-sea-02"

    burn_response = client.patch(
        f"/api/engagements/{engagement_id}/sketch-chains/{first['chainId']}",
        json={"burned": True, "burnedNote": "Edge observed by defender."},
    )
    assert burn_response.status_code == 200
    burned = burn_response.get_json()["sketchChain"]
    assert burned["burned"] is True
    assert burned["burnedNote"] == "Edge observed by defender."
    assert burned["status"] == "pending"


def test_pending_sketch_chain_persists_and_updates_edge_count():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ZY02")

    chain = _create_chain(client, engagement_id, "proxy01", "us-sea", edge_count=2)

    assert chain["edgeCount"] == 2

    update_response = client.patch(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}",
        json={"edgeCount": 3},
    )

    assert update_response.status_code == 200
    assert update_response.get_json()["sketchChain"]["edgeCount"] == 3


def test_pending_sketch_chain_preserves_distinct_edge_region_intent():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "MR01")
    client.patch(
        "/api/provider-catalog/sketch/region-policies/linode",
        json={"allowedRegions": ["us-sea", "us-lax"]},
    )

    created = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": "proxy01", "middleProvider": "linode", "middleRegion": "us-sea", "middleSize": "g6-nanode-1",
            "edges": [
                {"id": "edge-01", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
                {"id": "edge-02", "provider": "linode", "region": "us-lax", "size": "g6-nanode-1"},
            ],
        },
    )

    assert created.status_code == 201
    body = created.get_json()["sketchChain"]
    assert body["edgeRegion"] == "us-sea"
    assert [(edge["id"], edge["region"]) for edge in body["edges"]] == [
        ("edge-01", "us-sea"),
        ("edge-02", "us-lax"),
    ]


def test_pending_chain_persists_heterogeneous_sibling_edge_providers():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ME01")
    response = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": "proxy01", "middleProvider": "linode", "middleRegion": "us-sea", "middleSize": "g6-nanode-1",
            "edges": [
                {"id": "edge-01", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
                {"id": "edge-02", "provider": "digitalocean", "region": "sfo3", "size": "s-1vcpu-1gb"},
            ],
        },
    )
    assert response.status_code == 201
    body = response.get_json()["sketchChain"]
    assert [(edge["id"], edge["provider"], edge["size"]) for edge in body["edges"]] == [
        ("edge-01", "linode", "g6-nanode-1"),
        ("edge-02", "digitalocean", "s-1vcpu-1gb"),
    ]


def test_legacy_edge_count_patch_resizes_uniform_intents_without_overwriting_placement():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ME02")
    chain = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": "proxy01", "middleProvider": "linode", "middleRegion": "us-sea", "middleSize": "g6-nanode-1",
            "edges": [
                {"id": "edge-01", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
                {"id": "edge-02", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
            ],
        },
    ).get_json()["sketchChain"]
    updated = client.patch(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}", json={"edgeCount": 3}
    )
    assert updated.status_code == 200
    body = updated.get_json()["sketchChain"]
    assert body["edgeCount"] == 3
    assert [edge["id"] for edge in body["edges"]] == ["edge-01", "edge-02", "edge-03"]
    assert body["edges"][1] == {"id": "edge-02", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"}
    assert body["edges"][2] == {"id": "edge-03", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"}


def test_sketch_chain_rejects_invalid_edge_count():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ZY03")

    rejected = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": "proxy01",
            "middleProvider": "linode",
            "middleRegion": "us-sea",
            "middleSize": "g6-nanode-1",
            "edgeProvider": "linode",
            "edgeRegion": "us-sea",
            "edgeSize": "g6-nanode-1",
            "edgeCount": 0,
        },
    )

    assert rejected.status_code == 400
    assert rejected.get_json()["errors"] == ["edgeCount must be an integer from 1 to 10"]


def test_sketch_chain_create_enforces_non_destroyed_engagement_limit(monkeypatch):
    monkeypatch.setenv("BARRAGAN_MAX_SKETCH_CHAINS_PER_ENGAGEMENT", "2")
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ZY02")

    first = _create_chain(client, engagement_id, "proxy01", "us-sea")
    _create_chain(
        client,
        engagement_id,
        "proxy02",
        "sfo3",
        middle_provider="digitalocean",
        middle_region="sfo3",
        middle_size="s-1vcpu-1gb",
        edge_provider="digitalocean",
        edge_size="s-1vcpu-1gb",
    )

    rejected = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": "proxy01",
            "middleProvider": "linode",
            "middleRegion": "us-sea",
            "middleSize": "g6-nanode-1",
            "edgeProvider": "linode",
            "edgeRegion": "us-lax",
            "edgeSize": "g6-nanode-1",
        },
    )
    assert rejected.status_code == 400
    assert rejected.get_json()["errors"] == [
        "sketch chain limit reached for this engagement; 2 active chain records exist and the limit is 2"
    ]

    with app.storage_context():
        row = SketchChainModel.query.filter_by(engagement_id=engagement_id, chain_id=first["chainId"]).one()
        row.status = "aborted"
        db.session.commit()

    allowed = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": "proxy01",
            "middleProvider": "linode",
            "middleRegion": "us-sea",
            "middleSize": "g6-nanode-1",
            "edgeProvider": "linode",
            "edgeRegion": "us-sea",
            "edgeSize": "g6-nanode-1",
        },
    )
    assert allowed.status_code == 201


def test_pending_sketch_chain_cancel_aborts_without_destroying_record(monkeypatch):
    monkeypatch.setenv("BARRAGAN_MAX_SKETCH_CHAINS_PER_ENGAGEMENT", "1")
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ZY04")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")

    wrong_confirmation = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/cancel",
        json={"confirmation": "cancel-wrong-chain"},
    )
    assert wrong_confirmation.status_code == 400
    assert wrong_confirmation.get_json()["errors"] == [f'confirmation must equal "cancel-{chain["chainId"]}"']

    canceled_response = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/cancel",
        json={"confirmation": f"cancel-{chain['chainId']}"},
    )
    assert canceled_response.status_code == 200
    canceled = canceled_response.get_json()["sketchChain"]
    assert canceled["chainId"] == chain["chainId"]
    assert canceled["status"] == "aborted"
    assert canceled["deployJobId"] == ""
    assert canceled["nodes"] == []

    listed = client.get(f"/api/engagements/{engagement_id}/sketch-chains")
    assert listed.status_code == 200
    assert listed.get_json()["sketchChains"][0]["status"] == "aborted"

    replacement = _create_chain(client, engagement_id, "proxy01", "us-sea")
    assert replacement["chainId"] == "proxy01-sea-02"


def test_non_pending_sketch_chain_cancel_is_rejected():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ZY05")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    with storage_context_client_state(app, engagement_id, chain["chainId"], status="deployed"):
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/cancel",
            json={"confirmation": f"cancel-{chain['chainId']}"},
        )
    assert response.status_code == 400
    assert response.get_json()["errors"] == [f"chain {chain['chainId']} is deployed and cannot be canceled"]


def test_sketch_chain_create_and_update_reject_regions_outside_provider_policy():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "ZY03")

    rejected_create = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": "proxy01",
            "middleProvider": "linode",
            "middleRegion": "us-sea",
            "middleSize": "g6-nanode-1",
            "edgeProvider": "linode",
            "edgeRegion": "us-lax",
            "edgeSize": "g6-nanode-1",
        },
    )
    assert rejected_create.status_code == 400
    assert rejected_create.get_json()["errors"] == [
        "edge region linode/us-lax is not allowed by sketch provider region policy"
    ]

    client.patch("/api/provider-catalog/sketch/region-policies/linode", json={"allowedRegions": ["us-sea", "us-lax"]})
    allowed = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": "proxy01",
            "middleProvider": "linode",
            "middleRegion": "us-sea",
            "middleSize": "g6-nanode-1",
            "edgeProvider": "linode",
            "edgeRegion": "us-lax",
            "edgeSize": "g6-nanode-1",
        },
    )
    assert allowed.status_code == 201
    chain = allowed.get_json()["sketchChain"]

    rejected_update = client.patch(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}",
        json={"edgeRegion": "us-ord"},
    )
    assert rejected_update.status_code == 400
    assert rejected_update.get_json()["errors"] == [
        "edge region linode/us-ord is not allowed by sketch provider region policy"
    ]

    rejected_provider = client.patch(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}",
        json={"edgeProvider": "aws"},
    )
    assert rejected_provider.status_code == 400
    assert rejected_provider.get_json()["errors"] == ["edgeProvider must be linode or digitalocean"]


def test_deployed_sketch_chain_fields_are_locked_but_burned_metadata_is_editable():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "AB01")
    chain = _create_chain(client, engagement_id, "proxy02", "us-sea")

    with app.storage_context():
        row = SketchChainModel.query.filter_by(engagement_id=engagement_id, chain_id=chain["chainId"]).one()
        row.status = "deployed"
        row.nodes = [
            {
                "chainId": chain["chainId"],
                "hostname": "edge-ab01",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.77",
                "region": "us-sea",
                "proxy": "proxy02",
                "status": "deployed",
            }
        ]
        db.session.commit()

    locked_response = client.patch(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}",
        json={"edgeRegion": "us-sea"},
    )
    assert locked_response.status_code == 400

    burn_response = client.patch(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}",
        json={"burned": True, "burnedNote": "Burned but still serving callbacks."},
    )
    assert burn_response.status_code == 200
    assert burn_response.get_json()["sketchChain"]["burned"] is True
    assert burn_response.get_json()["sketchChain"]["status"] == "deployed"


def test_operations_overview_uses_durable_sketch_chains_with_burned_state():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "CD01")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")

    with app.storage_context():
        row = SketchChainModel.query.filter_by(engagement_id=engagement_id, chain_id=chain["chainId"]).one()
        row.status = "deployed"
        row.burned = True
        row.burned_note = "Replacement pending."
        row.nodes = [
            {
                "chainId": chain["chainId"],
                "hostname": "middle-cd01-proxy01-sea-01",
                "provider": "linode",
                "role": "middle",
                "publicIp": "203.0.113.10",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
            {
                "chainId": chain["chainId"],
                "hostname": "edge-cd01-us-sea-proxy01-sea-01",
                "provider": "linode",
                "role": "edge",
                "publicIp": "203.0.113.20",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": "deployed",
            },
        ]
        db.session.commit()

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    assert response.status_code == 200
    sketch_rows = response.get_json()["operations"]["sketchInfrastructure"]
    assert [row["hostname"] for row in sketch_rows] == [
        "middle-cd01-proxy01-sea-01",
        "edge-cd01-us-sea-proxy01-sea-01",
    ]
    assert all(row["burned"] is True for row in sketch_rows)
    assert all(row["burnedNote"] == "Replacement pending." for row in sketch_rows)


def test_operations_overview_reads_job_topology_without_reconciling_durable_chain():
    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "CD02")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")

    with app.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-cd02-sketch",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id, "terraformWorkingDirectory": "/tmp/cd02-sketch"},
                artifact_refs=[],
                created_at="2026-06-04T12:10:00+00:00",
                started_at="2026-06-04T12:11:00+00:00",
                finished_at="2026-06-04T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "sketch infrastructure recorded",
                        {
                            "sketchInfrastructure": [
                                {
                                    "hostname": "middle-cd02-proxy01-sea-01",
                                    "provider": "linode",
                                    "role": "middle",
                                    "publicIp": "203.0.113.10",
                                    "region": "us-sea",
                                    "proxy": "proxy01",
                                    "status": "deployed",
                                },
                                {
                                    "hostname": "edge-cd02-us-sea-proxy01-sea-01",
                                    "provider": "linode",
                                    "role": "edge",
                                    "publicIp": "203.0.113.20",
                                    "region": "us-sea",
                                    "proxy": "proxy01",
                                    "status": "deployed",
                                },
                            ]
                        },
                    )
                ],
            )
        )
        row = SketchChainModel.query.filter_by(engagement_id=engagement_id, chain_id=chain["chainId"]).one()
        row.status = "deploying"
        row.deploy_job_id = "job-cd02-sketch"
        db.session.commit()

    response = client.get(f"/api/engagements/{engagement_id}/operations")

    assert response.status_code == 200
    sketch_rows = response.get_json()["operations"]["sketchInfrastructure"]
    assert {row["status"] for row in sketch_rows} == {"deployed"}
    assert [row["hostname"] for row in sketch_rows] == [
        "middle-cd02-proxy01-sea-01",
        "edge-cd02-us-sea-proxy01-sea-01",
    ]
    with app.storage_context():
        durable = SketchChainModel.query.filter_by(
            engagement_id=engagement_id,
            chain_id=chain["chainId"],
        ).one()
        assert durable.status == "deploying"


def test_dashboard_get_does_not_save_chains_or_start_outbound_continuations():
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "CD03")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    with app.storage_context():
        row = SketchChainModel.query.filter_by(
            engagement_id=engagement_id,
            chain_id=chain["chainId"],
        ).one()
        row.status = "deploying"
        row.deploy_job_id = "job-finished-but-not-recovered"
        db.session.commit()

    writes = []
    commits = []

    def capture_write(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")):
            writes.append(statement)

    def capture_commit(_session):
        commits.append("commit")

    event.listen(app.state.database.engine, "before_cursor_execute", capture_write)
    event.listen(Session, "after_commit", capture_commit)
    with (
        patch("app.storage.sketch_chain_repository.SqlAlchemySketchChainRepository.save", side_effect=AssertionError("read saved chain")),
        patch("app.storage.job_repository.SqlAlchemyJobRepository.save", side_effect=AssertionError("read saved job")),
        patch("app.storage.job_repository.SqlAlchemyJobRepository.save_if_absent", side_effect=AssertionError("read created job")),
        patch("app.storage.job_repository.SqlAlchemyJobRepository.claim_lease", side_effect=AssertionError("read claimed job")),
        patch("app.services.sketch_chains.start_runtime_task", side_effect=AssertionError("read started task")),
        patch("app.services.sketch_chains._start_outbound_auto_configuration", side_effect=AssertionError("read started continuation")),
    ):
        dashboard_response = client.get("/api/dashboard")
        operations_response = client.get(f"/api/engagements/{engagement_id}/operations")
    event.remove(app.state.database.engine, "before_cursor_execute", capture_write)
    event.remove(Session, "after_commit", capture_commit)

    assert dashboard_response.status_code == 200
    assert operations_response.status_code == 200
    assert writes == []
    assert commits == []
    with app.storage_context():
        row = SketchChainModel.query.filter_by(
            engagement_id=engagement_id,
            chain_id=chain["chainId"],
        ).one()
        assert row.status == "deploying"


def test_competing_chain_recovery_uses_compare_and_swap():
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

    app = create_app(TestConfig)
    client = app.test_client()
    engagement_id = _create_engagement(client, "CD04")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    with app.storage_context():
        repository = SqlAlchemySketchChainRepository()
        current = repository.get(engagement_id, chain["chainId"])
        assert current is not None
        first = repository.save_if_matches(
            replace(current, status="deploying"),
            expected_status="pending",
            expected_deploy_job_id="",
            expected_teardown_job_id="",
        )
        stale = repository.save_if_matches(
            replace(current, status="failed"),
            expected_status="pending",
            expected_deploy_job_id="",
            expected_teardown_job_id="",
        )

        assert first is not None and first.status == "deploying"
        assert stale is None
        assert repository.get(engagement_id, chain["chainId"]).status == "deploying"


def test_chain_stop_and_start_use_provider_power_operations():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "EF01")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    stop_job = _fake_provider_job(chain["chainId"], provider="linode", action="sketch_chain_stop")
    start_job = _fake_provider_job(chain["chainId"], provider="linode", action="sketch_chain_start")

    with storage_context_client_state(client.application, engagement_id, chain["chainId"], status="deployed"):
        with patch("app.services.sketch_chains.run_sketch_power_job", return_value=stop_job) as stop_run:
            stop_response = client.post(
                f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/stop",
                json={"confirmation": f"stop-{chain['chainId']}"},
            )

    assert stop_response.status_code == 202
    stop_run.assert_called_once()
    stopped = stop_response.get_json()["chain"]
    assert stopped["status"] == "stopped"
    assert all(node["status"] == "stopped" for node in stopped["nodes"])

    with patch("app.services.sketch_chains.run_sketch_power_job", return_value=start_job) as start_run:
        start_response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/start",
            json={"confirmation": f"start-{chain['chainId']}"},
        )

    assert start_response.status_code == 202
    start_run.assert_called_once()
    started = start_response.get_json()["chain"]
    assert started["status"] == "deployed"
    assert all(node["status"] == "deployed" for node in started["nodes"])


def test_chain_stop_requires_confirmation_before_provider_power_operation():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "EF02")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    with storage_context_client_state(client.application, engagement_id, chain["chainId"], status="deployed"):
        with patch("app.services.sketch_chains.run_sketch_power_job") as stop_run:
            response = client.post(
                f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/stop",
                json={"confirmation": "wrong"},
            )

    assert response.status_code == 400
    assert response.get_json()["errors"] == [f'confirmation must equal "stop-{chain["chainId"]}"']
    stop_run.assert_not_called()


def test_digitalocean_sketch_chain_deploy_requires_digitalocean_confirmation():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "GH01")
    chain = _create_chain(
        client,
        engagement_id,
        "proxy01",
        "sfo3",
        middle_provider="digitalocean",
        middle_region="sfo3",
        middle_size="s-1vcpu-1gb",
        edge_provider="digitalocean",
        edge_size="s-1vcpu-1gb",
    )

    response = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
        json={"confirmMutation": "mutate-linode-sketch-testing"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ['confirmMutation must equal "mutate-digitalocean-sketch-testing"']


def test_live_sketch_chain_deploy_dispatches_mixed_provider_chain_to_composed_adapter():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "IJ01")
    chain = _create_chain(
        client,
        engagement_id,
        "proxy01",
        "sfo3",
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="g6-nanode-1",
        edge_provider="digitalocean",
        edge_size="s-1vcpu-1gb",
    )
    job = _fake_provider_job(chain["chainId"], provider="mixed", action="mixed_provider_sketch_deploy")

    with patch("app.services.sketch_chains.start_guarded_mixed_sketch_run", return_value=job) as start_run:
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
            json={"confirmMutation": "mutate-mixed-provider-sketch-testing"},
        )

    assert response.status_code == 202
    start_run.assert_called_once()
    request_body = start_run.call_args.args[0]
    assert request_body["middleProvider"] == "linode"
    assert request_body["edgeProvider"] == "digitalocean"
    assert request_body["confirmMutation"] == "mutate-mixed-provider-sketch-testing"
    assert response.get_json()["job"]["action"] == "mixed_provider_sketch_deploy"


def test_digitalocean_sketch_chain_deploy_dispatches_to_provider_adapter():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "KL01")
    chain = _create_chain(
        client,
        engagement_id,
        "proxy01",
        "sfo3",
        middle_provider="digitalocean",
        middle_region="sfo3",
        middle_size="s-1vcpu-1gb",
        edge_provider="digitalocean",
        edge_size="s-1vcpu-1gb",
    )
    job = _fake_provider_job(chain["chainId"], provider="digitalocean")

    with patch("app.services.sketch_chains.start_guarded_digitalocean_sketch_run", return_value=job) as start_run:
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
            json={"confirmMutation": "mutate-digitalocean-sketch-testing"},
        )

    assert response.status_code == 202
    start_run.assert_called_once()
    request_body = start_run.call_args.args[0]
    assert request_body["confirmMutation"] == "mutate-digitalocean-sketch-testing"
    assert request_body["middleRegion"] == "sfo3"
    assert request_body["edgeRegion"] == "sfo3"
    deployed = response.get_json()["chain"]
    assert deployed["status"] == "deployed"
    assert deployed["deployJobId"] == "job-digitalocean"
    assert deployed["nodes"][0]["provider"] == "digitalocean"


def test_sketch_deploy_persists_job_identity_before_provider_task_runs():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "KL02")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    provider_job = _fake_provider_job(chain["chainId"], provider="linode")
    observed = []

    def start_provider(_body, *, background_runner):
        def provider_task():
            row = SketchChainModel.query.filter_by(
                engagement_id=engagement_id,
                chain_id=chain["chainId"],
            ).one()
            observed.append((row.status, row.deploy_job_id))

        background_runner(provider_task)
        return provider_job

    with patch("app.services.sketch_chains.start_guarded_linode_sketch_run", side_effect=start_provider):
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
            json={"confirmMutation": "mutate-linode-sketch-testing"},
        )

    assert response.status_code == 202
    assert observed == [("deployed", provider_job.id)]


def test_successful_sketch_chain_deploy_returns_outbound_configuration_parent():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "LM01")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    job = _fake_provider_job(chain["chainId"], provider="linode")
    parent = _fake_outbound_parent(engagement_id, chain["chainId"], job.id)

    with (
        patch("app.services.sketch_chains.start_guarded_linode_sketch_run", return_value=job),
        patch("app.services.sketch_chains.apply_outbound_channel", return_value={"status": "Pending Validation", "job": {"id": "job-apply"}}) as apply_route,
        patch("app.services.sketch_chains.validate_outbound_channel", return_value={"status": "Validated", "job": {"id": "job-validate"}}) as validate_route,
        patch("app.services.sketch_chains._start_outbound_auto_configuration", return_value=parent),
    ):
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
            json={"confirmMutation": "mutate-linode-sketch-testing", "requestedBy": "operator"},
        )

    assert response.status_code == 202
    apply_route.assert_not_called()
    validate_route.assert_not_called()
    body = response.get_json()
    assert "outboundApply" not in body
    assert "outboundValidation" not in body
    assert body["outboundConfigurationJob"]["id"] == parent.id
    assert body["outboundConfigurationJob"]["input"]["configurationState"] == "Waiting"


def test_pending_outbound_channel_is_not_reapplied_by_concurrent_refresh():
    from app.services.sketch_chains import _auto_configure_outbound_channel_if_ready

    pending_job = StoredJobRun(
        id="job-pending-outbound",
        action="outbound_channel_apply",
        status="succeeded",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1", "chainId": "proxy01-sea-01"},
        artifact_refs=[],
        created_at="2026-07-07T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "outbound channel apply succeeded",
                {
                    "outboundChannels": [
                        {"chainId": "proxy01-sea-01", "status": "Pending Validation"}
                    ]
                },
            )
        ],
    )

    class PendingRepository:
        def list(self):
            return [pending_job]

    with (
        patch("app.services.sketch_chains.apply_outbound_channel") as apply_route,
        patch("app.services.sketch_chains.validate_outbound_channel") as validate_route,
    ):
        result = _auto_configure_outbound_channel_if_ready(
            "eng-1", "proxy01-sea-01", repository=PendingRepository()
        )

    assert result == {}
    apply_route.assert_not_called()
    validate_route.assert_not_called()


def test_auto_configure_applies_each_edge_channel_for_multi_edge_chain():
    from app.services.sketch_chains import _auto_configure_outbound_channel_if_ready

    outbound_job = StoredJobRun(
        id="job-outbound-rows",
        action="linode_sketch_deploy",
        status="succeeded",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1", "chainId": "proxy01-sea-02"},
        artifact_refs=[],
        created_at="2026-07-07T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "pending outbound channel artifacts derived",
                {
                    "outboundChannels": [
                        {
                            "channelId": "proxy01-sea-02-edge-01",
                            "chainId": "proxy01-sea-02",
                            "status": "Pending Proxy Configuration",
                            "artifacts": {},
                        },
                        {
                            "channelId": "proxy01-sea-02-edge-02",
                            "chainId": "proxy01-sea-02",
                            "status": "Pending Proxy Configuration",
                            "artifacts": {},
                        },
                    ]
                },
            )
        ],
    )

    class MultiEdgeRepository:
        def list(self):
            return [outbound_job]

    with (
        patch("app.services.sketch_chains.apply_outbound_channel", return_value={"status": "Pending Validation"}) as apply_route,
        patch("app.services.sketch_chains.validate_outbound_channel", return_value={"status": "Validated"}) as validate_route,
    ):
        result = _auto_configure_outbound_channel_if_ready(
            "eng-1", "proxy01-sea-02", repository=MultiEdgeRepository()
        )

    assert [call.args[1] for call in apply_route.call_args_list] == [
        "proxy01-sea-02-edge-01",
        "proxy01-sea-02-edge-02",
    ]
    assert [call.kwargs["confirmation"] for call in apply_route.call_args_list] == [
        "apply-outbound-proxy01-sea-02-edge-01",
        "apply-outbound-proxy01-sea-02-edge-02",
    ]
    assert [call.args[1] for call in validate_route.call_args_list] == [
        "proxy01-sea-02-edge-01",
        "proxy01-sea-02-edge-02",
    ]
    assert len(result["outboundApplies"]) == 2
    assert len(result["outboundValidations"]) == 2


def test_outbound_auto_configuration_is_persisted_single_flight_and_serial():
    from app.services.sketch_chains import _start_outbound_auto_configuration

    app = create_app(TestConfig)
    sequence = []
    with app.storage_context():
        repository = SqlAlchemyJobRepository()
        repository.save(_outbound_artifact_job("eng-auto", "proxy01-sea-02"))

        def apply(_engagement_id, channel_id, **_kwargs):
            sequence.append(f"apply:{channel_id}")
            return {"status": "Pending Validation", "job": {"id": f"job-apply-{channel_id}"}}

        def validate(_engagement_id, channel_id, **_kwargs):
            sequence.append(f"validate:{channel_id}")
            return {
                "status": "Validated with warnings" if channel_id.endswith("edge-01") else "Validated",
                "job": {"id": f"job-validate-{channel_id}"},
            }

        with (
            patch("app.services.sketch_chains.apply_outbound_channel", side_effect=apply),
            patch("app.services.sketch_chains.validate_outbound_channel", side_effect=validate),
        ):
            first = _start_outbound_auto_configuration(
                "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-auto", repository=repository
            )
            repeated = _start_outbound_auto_configuration(
                "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-auto", repository=repository
            )

        assert first is not None
        assert repeated is not None
        assert repeated.id == first.id
        assert repeated.status == "succeeded"
        assert repeated.input["configurationState"] == "Ready"
        assert sequence == [
            "apply:proxy01-sea-02-edge-01",
            "validate:proxy01-sea-02-edge-01",
            "apply:proxy01-sea-02-edge-02",
            "validate:proxy01-sea-02-edge-02",
        ]
        assert len([job for job in repository.list() if job.action == "outbound_channel_auto_configuration"]) == 1


def test_outbound_auto_configuration_concurrent_ensure_schedules_once(tmp_path):
    from app.services import sketch_chains

    repository = SqliteJobRepository(tmp_path / "jobs.sqlite")
    repository.save(_outbound_artifact_job("eng-auto", "proxy01-sea-02"))
    scheduled = []
    results = []
    sketch_chains._outbound_auto_configuration_active.clear()

    with patch("app.services.sketch_chains.start_runtime_task", side_effect=lambda task, **_kwargs: scheduled.append(task)):
        threads = [
            threading.Thread(
                target=lambda: results.append(
                    sketch_chains._start_outbound_auto_configuration(
                        "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-concurrent", repository=repository
                    )
                )
            )
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert len(scheduled) == 1
    assert len({result.id for result in results if result is not None}) == 1
    assert len([job for job in repository.list() if job.action == "outbound_channel_auto_configuration"]) == 1
    sketch_chains._outbound_auto_configuration_active.clear()


def test_outbound_auto_configuration_resumes_orphaned_running_job_and_skips_ready_channel(tmp_path):
    from app.services import sketch_chains

    repository = SqliteJobRepository(tmp_path / "jobs.sqlite")
    repository.save(_outbound_artifact_job("eng-auto", "proxy01-sea-02"))
    scheduled = []
    sketch_chains._outbound_auto_configuration_active.clear()
    with patch("app.services.sketch_chains.start_runtime_task", side_effect=lambda task, **_kwargs: scheduled.append(task)):
        parent = sketch_chains._start_outbound_auto_configuration(
            "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-resume", repository=repository
        )
    assert parent is not None and parent.status == "queued"

    repository.save(
        replace(
            parent,
            status="running",
            input={
                **parent.input,
                "claimOwner": "dead-runtime",
                "claimExpiresAt": "2000-01-01T00:00:00+00:00",
                "configurationState": "Configuring",
            },
        )
    )
    repository.save(_validated_outbound_job("eng-auto", "proxy01-sea-02-edge-01"))
    sketch_chains._outbound_auto_configuration_active.clear()
    sequence = []
    with (
        patch("app.services.sketch_chains.start_runtime_task", side_effect=lambda task, **_kwargs: task()),
        patch("app.services.sketch_chains.apply_outbound_channel", side_effect=lambda _eng, channel, **_kwargs: sequence.append(f"apply:{channel}") or {"status": "Pending Validation", "job": {"id": "apply"}}),
        patch("app.services.sketch_chains.validate_outbound_channel", side_effect=lambda _eng, channel, **_kwargs: sequence.append(f"validate:{channel}") or {"status": "Validated", "job": {"id": "validate"}}),
    ):
        resumed = sketch_chains._start_outbound_auto_configuration(
            "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-resume", repository=repository
        )

    assert resumed is not None and resumed.status == "succeeded"
    assert sequence == ["apply:proxy01-sea-02-edge-02", "validate:proxy01-sea-02-edge-02"]
    assert resumed.input["claimOwner"] == sketch_chains._outbound_auto_configuration_owner
    assert resumed.input["claimHeartbeatAt"]


def test_outbound_auto_configuration_crash_after_apply_resumes_with_validation_only(tmp_path):
    from app.services import sketch_chains

    repository = SqliteJobRepository(tmp_path / "jobs.sqlite")
    repository.save(_outbound_artifact_job("eng-auto", "proxy01-sea-02"))
    sketch_chains._outbound_auto_configuration_active.clear()
    with patch("app.services.sketch_chains.start_runtime_task", side_effect=lambda task, **_kwargs: None):
        parent = sketch_chains._start_outbound_auto_configuration(
            "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-apply-crash", repository=repository
        )
    assert parent is not None
    repository.save(
        replace(
            parent,
            status="running",
            input={
                **parent.input,
                "claimOwner": "dead-runtime",
                "claimExpiresAt": "2000-01-01T00:00:00+00:00",
                "configurationState": "Configuring",
            },
        )
    )
    repository.save(_pending_outbound_job("eng-auto", "proxy01-sea-02-edge-01"))
    sketch_chains._outbound_auto_configuration_active.clear()
    sequence = []
    with (
        patch("app.services.sketch_chains.start_runtime_task", side_effect=lambda task, **_kwargs: task()),
        patch("app.services.sketch_chains.apply_outbound_channel", side_effect=lambda _eng, channel, **_kwargs: sequence.append(f"apply:{channel}") or {"status": "Pending Validation", "job": {"id": "apply"}}),
        patch("app.services.sketch_chains.validate_outbound_channel", side_effect=lambda _eng, channel, **_kwargs: sequence.append(f"validate:{channel}") or {"status": "Validated", "job": {"id": "validate"}}),
    ):
        resumed = sketch_chains._start_outbound_auto_configuration(
            "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-apply-crash", repository=repository
        )

    assert resumed is not None and resumed.status == "succeeded"
    assert sequence == [
        "validate:proxy01-sea-02-edge-01",
        "apply:proxy01-sea-02-edge-02",
        "validate:proxy01-sea-02-edge-02",
    ]


def test_failed_outbound_auto_configuration_is_not_restarted(tmp_path):
    from app.services import sketch_chains

    repository = SqliteJobRepository(tmp_path / "jobs.sqlite")
    repository.save(_outbound_artifact_job("eng-auto", "proxy01-sea-02"))
    sketch_chains._outbound_auto_configuration_active.clear()
    with (
        patch("app.services.sketch_chains.start_runtime_task", side_effect=lambda task, **_kwargs: task()),
        patch("app.services.sketch_chains.apply_outbound_channel", return_value={"status": "Pending Validation", "job": {"id": "apply"}}),
        patch("app.services.sketch_chains.validate_outbound_channel", return_value={"status": "Failed", "job": {"id": "validate"}}),
    ):
        failed = sketch_chains._start_outbound_auto_configuration(
            "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-failed", repository=repository
        )
    assert failed is not None and failed.status == "failed"

    with patch("app.services.sketch_chains.start_runtime_task") as start:
        repeated = sketch_chains._start_outbound_auto_configuration(
            "eng-auto", "proxy01-sea-02", deploy_job_id="job-deploy-failed", repository=repository
        )
    assert repeated is not None and repeated.status == "failed"
    start.assert_not_called()


def test_terminal_failed_outbound_channel_is_not_reapplied_by_refresh():
    from app.services.sketch_chains import _auto_configure_outbound_channel_if_ready

    failed_job = StoredJobRun(
        id="job-failed-outbound",
        action="outbound_channel_validation",
        status="failed",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1", "chainId": "proxy01-sea-01"},
        artifact_refs=[],
        created_at="2026-08-26T00:00:00+00:00",
        started_at=None,
        finished_at="2026-08-26T00:01:00+00:00",
        events=[
            JobEvent(
                1,
                "error",
                "outbound channel validation failed",
                {
                    "outboundChannels": [
                        {"channelId": "proxy01-sea-01", "status": "Validation Failed"}
                    ]
                },
            )
        ],
    )

    class FailedRepository:
        def list(self):
            return [failed_job]

    with (
        patch("app.services.sketch_chains.apply_outbound_channel") as apply_route,
        patch("app.services.sketch_chains.validate_outbound_channel") as validate_route,
    ):
        result = _auto_configure_outbound_channel_if_ready(
            "eng-1", "proxy01-sea-01", repository=FailedRepository()
        )

    assert result == {}
    apply_route.assert_not_called()
    validate_route.assert_not_called()


def _outbound_artifact_job(engagement_id: str, chain_id: str) -> StoredJobRun:
    return StoredJobRun(
        id="job-outbound-artifacts",
        action="linode_sketch_deploy",
        status="succeeded",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by="operator",
        input={"engagementId": engagement_id, "chainId": chain_id},
        artifact_refs=[],
        created_at="2026-08-01T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "pending outbound channel artifacts derived",
                {
                    "outboundChannels": [
                        {"channelId": f"{chain_id}-edge-01", "chainId": chain_id, "status": "Pending Proxy Configuration"},
                        {"channelId": f"{chain_id}-edge-02", "chainId": chain_id, "status": "Pending Proxy Configuration"},
                    ]
                },
            )
        ],
    )


def _validated_outbound_job(engagement_id: str, channel_id: str) -> StoredJobRun:
    return StoredJobRun(
        id=f"job-validated-{channel_id}",
        action="outbound_channel_validation",
        status="succeeded",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by="operator",
        input={"engagementId": engagement_id, "channelId": channel_id},
        artifact_refs=[],
        created_at="2026-08-01T00:01:00+00:00",
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "validated", {"outboundChannels": [{"channelId": channel_id, "status": "Validated"}]})],
    )


def _pending_outbound_job(engagement_id: str, channel_id: str) -> StoredJobRun:
    return StoredJobRun(
        id=f"job-pending-{channel_id}",
        action="outbound_channel_apply",
        status="succeeded",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by="operator",
        input={"engagementId": engagement_id, "channelId": channel_id},
        artifact_refs=[],
        created_at="2026-08-01T00:01:00+00:00",
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "applied", {"outboundChannels": [{"channelId": channel_id, "status": "Pending Validation"}]})],
    )


def _fake_outbound_parent(engagement_id: str, chain_id: str, deploy_job_id: str) -> StoredJobRun:
    return StoredJobRun(
        id="job-outbound-auto-test",
        action="outbound_channel_auto_configuration",
        status="queued",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by="operator",
        input={
            "engagementId": engagement_id,
            "chainId": chain_id,
            "deployJobId": deploy_job_id,
            "configurationState": "Waiting",
        },
        artifact_refs=[],
        created_at="2026-08-01T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[],
    )


def test_sketch_chain_deploy_never_auto_applies_or_validates_outbound_channel():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "LM03")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    job = _fake_provider_job(chain["chainId"], provider="linode")

    with (
        patch("app.services.sketch_chains.start_guarded_linode_sketch_run", return_value=job),
        patch(
            "app.services.sketch_chains.apply_outbound_channel",
            side_effect=OutboundChannelApplyValidationError(["core connection details are missing"]),
        ) as apply_route,
        patch("app.services.sketch_chains.validate_outbound_channel") as validate_route,
    ):
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
            json={"confirmMutation": "mutate-linode-sketch-testing", "requestedBy": "operator"},
        )

    assert response.status_code == 202
    apply_route.assert_not_called()
    validate_route.assert_not_called()
    body = response.get_json()
    assert body["chain"]["status"] == "deployed"
    assert "outboundApply" not in body


def test_sketch_chain_deploy_returns_topology_without_outbound_side_effects():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "LM04")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    job = _fake_provider_job(chain["chainId"], provider="linode")

    with (
        patch("app.services.sketch_chains.start_guarded_linode_sketch_run", return_value=job),
        patch(
            "app.services.sketch_chains.apply_outbound_channel",
            side_effect=OutboundChannelApplyValidationError(["outbound channel chain-1 with rendered artifacts was not found"]),
        ) as apply_route,
        patch("app.services.sketch_chains.validate_outbound_channel") as validate_route,
    ):
        response = client.post(
            f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/deploy",
            json={"confirmMutation": "mutate-linode-sketch-testing", "requestedBy": "operator"},
        )

    assert response.status_code == 202
    apply_route.assert_not_called()
    validate_route.assert_not_called()
    body = response.get_json()
    assert body["chain"]["status"] == "deployed"
    assert "outboundApply" not in body


def test_sketch_chain_teardown_removes_outbound_channel_before_provider_destroy():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "LM02")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    teardown_job = _fake_provider_job(chain["chainId"], provider="linode", action="linode_sketch_teardown")
    teardown_job.id = "job-lm02-teardown"
    sequence = []

    def remove_outbound(*args, **kwargs):
        sequence.append("outbound")
        return {"status": "Removed", "job": {"id": "job-remove"}}

    def queue_provider(*args, background_runner, **kwargs):
        background_runner(lambda: sequence.append("provider"))
        return teardown_job

    with storage_context_client_state(client.application, engagement_id, chain["chainId"], status="deployed"):
        with (
            patch("app.services.sketch_chains.remove_outbound_channel", side_effect=remove_outbound) as remove_route,
            patch("app.services.sketch_chains.start_guarded_linode_sketch_teardown", side_effect=queue_provider) as provider_teardown,
        ):
            response = client.post(
                f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/teardown",
                json={"confirmation": f"teardown-{chain['chainId']}", "requestedBy": "operator"},
            )

    assert response.status_code == 202
    remove_route.assert_called_once_with(
        engagement_id,
        chain["chainId"],
        requested_by="operator",
        repository=remove_route.call_args.kwargs["repository"],
        require_confirmation=False,
    )
    provider_teardown.assert_called_once()
    assert provider_teardown.call_args.args == ("job-deploy",)
    assert callable(provider_teardown.call_args.kwargs["background_runner"])
    assert sequence == ["outbound", "provider"]
    assert response.get_json()["chain"]["status"] == "destroyed"


def test_refresh_preserves_destroyed_chain_after_successful_teardown_job():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "MN01")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    deploy_job = _fake_provider_job(chain["chainId"], provider="linode")
    teardown_job = _fake_provider_job(chain["chainId"], provider="linode", action="linode_sketch_teardown")
    teardown_job.id = "job-teardown"

    with client.application.storage_context():
        row = SketchChainModel.query.filter_by(engagement_id=engagement_id, chain_id=chain["chainId"]).one()
        row.status = "destroyed"
        row.deploy_job_id = deploy_job.id
        row.teardown_job_id = teardown_job.id
        row.nodes = []
        db.session.commit()

    with client.application.storage_context():
        SqlAlchemyJobRepository().save(_stored_job_from_detail(teardown_job))
    response = client.post(f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/refresh")

    assert response.status_code == 200
    refreshed = response.get_json()["sketchChain"]
    assert refreshed["status"] == "destroyed"
    assert refreshed["nodes"] == []
    assert refreshed["teardownJobId"] == "job-teardown"


def test_refresh_preserves_bootstrap_gate_without_outbound_side_effects():
    client = create_app(TestConfig).test_client()
    engagement_id = _create_engagement(client, "MN02")
    chain = _create_chain(client, engagement_id, "proxy01", "us-sea")
    deploy_job = _fake_provider_job(chain["chainId"], provider="linode")

    with storage_context_client_state(client.application, engagement_id, chain["chainId"], status="deploying"):
        with (
            patch(
                "app.services.sketch_chains.apply_outbound_channel",
                side_effect=OutboundChannelApplyValidationError(["core connection details are missing"]),
            ) as apply_route,
            patch("app.services.sketch_chains.validate_outbound_channel") as validate_route,
        ):
            SqlAlchemyJobRepository().save(_stored_job_from_detail(deploy_job, job_id="job-deploy"))
            response = client.post(f"/api/engagements/{engagement_id}/sketch-chains/{chain['chainId']}/refresh")

    assert response.status_code == 200
    apply_route.assert_not_called()
    validate_route.assert_not_called()
    body = response.get_json()
    assert body["sketchChain"]["status"] == "deploying"
    assert "outboundApply" not in body


def _create_engagement(client, name: str) -> str:
    response = client.post("/api/engagements", json={"name": name, "owner": "operator"})
    assert response.status_code == 201
    return response.get_json()["engagement"]["id"]


def _create_chain(
    client,
    engagement_id: str,
    proxy: str,
    edge_region: str,
    *,
    middle_provider: str = "linode",
    middle_region: str = "us-sea",
    middle_size: str = "g6-nanode-1",
    edge_provider: str = "linode",
    edge_size: str = "g6-nanode-1",
    edge_count: int = 1,
) -> dict:
    response = client.post(
        f"/api/engagements/{engagement_id}/sketch-chains",
        json={
            "assignedProxy": proxy,
            "middleProvider": middle_provider,
            "middleRegion": middle_region,
            "middleSize": middle_size,
            "edgeProvider": edge_provider,
            "edgeRegion": edge_region,
            "edgeSize": edge_size,
            "edgeCount": edge_count,
        },
    )
    assert response.status_code == 201
    return response.get_json()["sketchChain"]


@contextmanager
def storage_context_client_state(app, engagement_id: str, chain_id: str, *, status: str):
    with app.storage_context():
        row = SketchChainModel.query.filter_by(engagement_id=engagement_id, chain_id=chain_id).one()
        row.status = status
        row.deploy_job_id = "job-deploy"
        row.nodes = [
            {
                "chainId": chain_id,
                "hostname": f"middle-test-{chain_id}",
                "provider": "linode",
                "providerInstanceId": "1111",
                "role": "middle",
                "publicIp": "203.0.113.30",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": status,
            },
            {
                "chainId": chain_id,
                "hostname": f"edge-test-{chain_id}",
                "provider": "linode",
                "providerInstanceId": "2222",
                "role": "edge",
                "publicIp": "203.0.113.40",
                "region": "us-sea",
                "proxy": "proxy01",
                "status": status,
            },
        ]
        db.session.commit()
    yield


def _fake_provider_job(chain_id: str, *, provider: str, action: str | None = None):
    class FakeProviderJob:
        id = f"job-{provider}"
        status = "succeeded"
        input = {"terraformWorkingDirectory": f"/tmp/{provider}-workspace"}
        events = [
            JobEvent(
                1,
                "info",
                "terraform output recorded",
                {
                    "sketchInfrastructure": [
                        {
                            "chainId": chain_id,
                            "hostname": f"middle-kl01-{chain_id}",
                            "provider": provider,
                            "role": "middle",
                            "publicIp": "203.0.113.30",
                            "region": "sfo3",
                            "proxy": "proxy01",
                            "status": "deployed",
                        },
                        {
                            "chainId": chain_id,
                            "hostname": f"edge-kl01-sfo3-{chain_id}",
                            "provider": provider,
                            "role": "edge",
                            "publicIp": "203.0.113.40",
                            "region": "sfo3",
                            "proxy": "proxy01",
                            "status": "deployed",
                        },
                    ]
                },
            )
        ]

        def to_dict(self):
            return {
                "id": self.id,
                "action": action or f"{provider}_sketch_deploy",
                "status": self.status,
                "input": self.input,
                "events": [event.to_dict() for event in self.events],
            }

    return FakeProviderJob()


def _stored_job_from_detail(job, *, job_id: str | None = None) -> StoredJobRun:
    return StoredJobRun(
        id=job_id or job.id,
        action=job.to_dict()["action"],
        status=job.status,
        target="engagement:test",
        target_type="engagement",
        target_id="test",
        requested_by="operator",
        input=dict(job.input),
        artifact_refs=[],
        created_at="2026-08-04T00:00:00+00:00",
        started_at="2026-08-04T00:00:00+00:00",
        finished_at="2026-08-04T00:01:00+00:00",
        events=list(job.events),
    )
