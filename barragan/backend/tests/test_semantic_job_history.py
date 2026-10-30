# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import sqlite3

from app.domain import JobEvent
from app.storage.job_repository import (
    DashboardSemanticJobBatch,
    SEMANTIC_ROWS_PER_CATEGORY,
    SqlAlchemyJobRepository,
    SqliteJobRepository,
    StoredJobRun,
    _semantic_jobs_sql,
)


JOB_HISTORY_INDEXES = {
    "ix_job_runs_target_id_created_id",
    "ix_job_runs_target_created_id",
    "ix_job_runs_input_engagement_created_id",
    "ix_job_events_job_sequence",
}


def test_semantic_history_keeps_authoritative_state_beyond_250_newer_jobs(tmp_path):
    repository = SqliteJobRepository(tmp_path / "jobs.sqlite")
    authoritative = [
        _job("job-core", "pilot_standard_rti_guarded_execute", "connectionDetails"),
        _job("job-sketch", "linode_sketch_deploy", "sketchInfrastructure"),
        _job("job-outbound", "outbound_channel_validation", "outboundChannels"),
        _job("job-inbound", "inbound_channel_validation", "inboundChannels"),
        _job("job-capability", "custom_capability_writer", "capabilities"),
        _job("job-teardown", "engagement_comprehensive_teardown", "finalCleanupStatus"),
    ]
    for job in authoritative:
        repository.save(job)
    for index in range(251):
        repository.save(
            replace_time(
                _job(f"job-irrelevant-{index:03d}", "unrelated_read", "unrelated"),
                f"2026-08-04T00:{index // 60:02d}:{index % 60:02d}+00:00",
            )
        )

    selected = repository.list_semantic_for_engagement("eng-1", recent_limit=250)
    selected_ids = {job.id for job in selected}

    assert {job.id for job in authoritative} <= selected_ids
    assert len([job for job in selected if job.action == "unrelated_read"]) == 250


def test_semantic_history_cardinality_stays_bounded_with_repeated_state_jobs(tmp_path):
    repository = SqliteJobRepository(tmp_path / "jobs.sqlite")
    categories = [
        ("pilot_standard_rti_guarded_execute", "connectionDetails"),
        ("linode_sketch_deploy", "sketchInfrastructure"),
        ("outbound_channel_validation", "outboundChannels"),
        ("inbound_channel_validation", "inboundChannels"),
        ("custom_capability_writer", "capabilities"),
        ("engagement_comprehensive_teardown", "finalCleanupStatus"),
    ]
    for category_index, (action, event_key) in enumerate(categories):
        for index in range(40):
            repository.save(
                replace_time(
                    _job(f"job-state-{category_index}-{index:02d}", action, event_key),
                    f"2026-07-{category_index + 1:02d}T00:00:{index:02d}+00:00",
                )
            )
    for index in range(251):
        repository.save(
            replace_time(
                _job(f"job-newer-{index:03d}", "unrelated_read", "unrelated"),
                f"2026-08-04T00:{index // 60:02d}:{index % 60:02d}+00:00",
            )
        )

    selected = repository.list_semantic_for_engagement("eng-1", recent_limit=250)

    assert len(selected) <= 250 + (len(categories) * 32)
    for action, _event_key in categories:
        assert len([job for job in selected if job.action == action]) == 32


def test_sqlalchemy_semantic_history_uses_one_job_and_one_event_query(tmp_path):
    from sqlalchemy import event

    from app import create_app
    from app.core.config import TestConfig

    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'semantic.sqlite'}"

    app = create_app(Config)
    with app.storage_context():
        repository = SqlAlchemyJobRepository()
        repository.save(_job("job-core", "pilot_standard_rti_guarded_execute", "connectionDetails"))
        statements = []

        def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
            if statement.lstrip().upper().startswith(("SELECT", "WITH")):
                statements.append(statement)

        event.listen(app.state.database.engine, "before_cursor_execute", capture)
        try:
            selected = repository.list_semantic_for_engagement("eng-1")
        finally:
            event.remove(app.state.database.engine, "before_cursor_execute", capture)

    assert [job.id for job in selected] == ["job-core"]
    assert len(statements) == 2
    assert "WITH classified" in statements[0]
    assert "FROM job_events" in statements[1]


def test_operations_nested_lifecycle_reuses_one_bounded_job_snapshot(tmp_path):
    from sqlalchemy import event

    from app import create_app
    from app.core.config import TestConfig
    from app.services.engagement_operations import get_operations_overview
    from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement

    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'operations-semantic.sqlite'}"

    class TrackingRepository(SqlAlchemyJobRepository):
        selected_count = 0

        def list_semantic_for_engagement(self, engagement_id: str, *, recent_limit: int = 250):
            selected = super().list_semantic_for_engagement(engagement_id, recent_limit=recent_limit)
            self.selected_count = len(selected)
            return selected

        def list_for_engagement(self, engagement_id: str, *, limit: int | None = None):
            raise AssertionError("nested lifecycle must reuse the bounded semantic snapshot")

    app = create_app(Config)
    with app.storage_context():
        SqlAlchemyEngagementRepository().save(
            StoredEngagement(
                id="eng-1",
                name="ENG01",
                status="draft",
                owner="operator",
                template_id="",
                active_revision=None,
                input_parameters={},
                created_at="2026-08-01T00:00:00+00:00",
                updated_at="2026-08-01T00:00:00+00:00",
            )
        )
        repository = TrackingRepository()
        repository.save(_job("job-core", "pilot_standard_rti_guarded_execute", "connectionDetails"))
        for index in range(260):
            repository.save(
                replace_time(
                    _job(f"job-noise-{index:03d}", "unrelated_read", "unrelated"),
                    f"2026-08-04T{index // 60:02d}:{index % 60:02d}:00+00:00",
                )
            )
        statements = []

        def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
            lowered = statement.lower()
            if "job_runs" in lowered or "job_events" in lowered:
                statements.append(statement)

        event.listen(app.state.database.engine, "before_cursor_execute", capture)
        try:
            overview = get_operations_overview(
                "eng-1",
                job_repository=repository,
                include_provider_findings=False,
            )
        finally:
            event.remove(app.state.database.engine, "before_cursor_execute", capture)

    assert overview is not None
    assert overview["lifecycle"]["state"] == "not_deployed"
    assert repository.selected_count <= 250 + 32
    assert len(statements) == 2
    assert "WITH classified" in statements[0]
    assert "FROM job_events" in statements[1]


def test_standalone_repository_adds_indexes_to_existing_database_idempotently(tmp_path):
    path = tmp_path / "standalone-existing.sqlite"
    repository = SqliteJobRepository(path)
    with sqlite3.connect(path) as connection:
        for index_name in JOB_HISTORY_INDEXES:
            connection.execute(f"DROP INDEX {index_name}")

    SqliteJobRepository(path)
    SqliteJobRepository(path)

    assert _job_history_indexes(path) == JOB_HISTORY_INDEXES


def test_sqlalchemy_startup_adds_indexes_to_existing_database_idempotently(tmp_path):
    from app.core.bootstrap import initialize_database
    from app.core.config import TestConfig

    path = tmp_path / "sqlalchemy-existing.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE job_runs (
              id VARCHAR(64) PRIMARY KEY, action VARCHAR(80) NOT NULL,
              status VARCHAR(40) NOT NULL, target VARCHAR(200) NOT NULL,
              target_type VARCHAR(80) NOT NULL, target_id VARCHAR(120) NOT NULL,
              requested_by VARCHAR(120) NOT NULL, input JSON NOT NULL,
              artifact_refs JSON NOT NULL, created_at DATETIME NOT NULL,
              started_at DATETIME, finished_at DATETIME
            );
            CREATE TABLE job_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, job_id VARCHAR(64) NOT NULL,
              sequence INTEGER NOT NULL, level VARCHAR(40) NOT NULL,
              message VARCHAR(400) NOT NULL, data JSON NOT NULL,
              created_at DATETIME NOT NULL,
              FOREIGN KEY(job_id) REFERENCES job_runs(id)
            );
            """
        )

    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{path}"

    initialize_database(Config)
    initialize_database(Config)

    assert _job_history_indexes(path) == JOB_HISTORY_INDEXES


def test_semantic_query_plan_uses_engagement_and_event_indexes(tmp_path):
    path = tmp_path / "semantic-plan.sqlite"
    SqliteJobRepository(path)
    with sqlite3.connect(path) as connection:
        plan = connection.execute(
            "EXPLAIN QUERY PLAN " + _semantic_jobs_sql(named=False),
            ("eng-1", "engagement:eng-1", "eng-1", 250, SEMANTIC_ROWS_PER_CATEGORY),
        ).fetchall()

    details = "\n".join(str(row[3]) for row in plan)
    assert "MULTI-INDEX OR" in details
    assert "ix_job_runs_target_id_created_id" in details
    assert "ix_job_runs_target_created_id" in details
    assert "ix_job_runs_input_engagement_created_id" in details
    assert "ix_job_events_job_sequence" in details


def test_multi_engagement_semantic_history_matches_each_selector_and_keeps_old_authority(tmp_path):
    repository = SqliteJobRepository(tmp_path / "multi-semantic.sqlite")
    target_id_job = _for_engagement(
        _job("job-target-id", "pilot_standard_rti_guarded_execute", "connectionDetails"),
        "eng-target-id",
        branch="target_id",
    )
    target_job = _for_engagement(
        _job("job-target", "outbound_channel_validation", "outboundChannels"),
        "eng-target",
        branch="target",
    )
    input_job = _for_engagement(
        _job("job-input", "inbound_channel_validation", "inboundChannels"),
        "eng-input",
        branch="input",
    )
    for job in (target_id_job, target_job, input_job):
        repository.save(replace_time(job, "2026-07-01T00:00:00+00:00"))
    for index in range(251):
        repository.save(
            replace_time(
                _for_engagement(
                    _job(f"job-noise-{index:03d}", "unrelated_read", "unrelated"),
                    "eng-target-id",
                    branch="target_id",
                ),
                f"2026-08-04T00:{index // 60:02d}:{index % 60:02d}+00:00",
            )
        )

    engagement_ids = ["eng-target-id", "eng-target", "eng-input"]
    batch = repository.list_semantic_for_engagements(engagement_ids)
    batched = batch.jobs_by_engagement

    for engagement_id in engagement_ids:
        individual = repository.list_semantic_for_engagement(engagement_id)
        assert batched[engagement_id] == individual
    assert "job-target-id" in {job.id for job in batched["eng-target-id"]}


def test_sqlalchemy_multi_engagement_semantic_history_uses_one_job_and_event_query(tmp_path):
    from sqlalchemy import event

    from app import create_app
    from app.core.config import TestConfig

    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'multi-query-count.sqlite'}"

    app = create_app(Config)
    with app.storage_context():
        repository = SqlAlchemyJobRepository()
        for branch, engagement_id in (("target_id", "eng-a"), ("target", "eng-b"), ("input", "eng-c")):
            repository.save(_for_engagement(_job(f"job-{branch}", "unrelated_read", "unrelated"), engagement_id, branch=branch))
        statements = []

        def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
            lowered = statement.lower()
            if "job_runs" in lowered or "job_events" in lowered:
                statements.append(statement)

        event.listen(app.state.database.engine, "before_cursor_execute", capture)
        try:
            batch = repository.list_semantic_for_engagements(["eng-a", "eng-b", "eng-c"])
        finally:
            event.remove(app.state.database.engine, "before_cursor_execute", capture)

    assert {key: [job.id for job in value] for key, value in batch.jobs_by_engagement.items()} == {
        "eng-a": ["job-target_id"],
        "eng-b": ["job-target"],
        "eng-c": ["job-input"],
    }
    assert batch.total_job_count == 4
    assert batch.seed_job_exists is True
    assert len(statements) == 2


def test_multi_engagement_metadata_survives_no_matches_empty_ids_and_unseeded_database(tmp_path):
    repository = SqliteJobRepository(tmp_path / "batch-metadata.sqlite")

    unmatched = repository.list_semantic_for_engagements(["eng-missing"])

    assert unmatched.jobs_by_engagement == {"eng-missing": []}
    assert unmatched.total_job_count == 0
    assert unmatched.seed_job_exists is False

    repository.save(_job("job-seed-001", "seed", "unrelated"))
    empty_request = repository.list_semantic_for_engagements([])

    assert empty_request.jobs_by_engagement == {}
    assert empty_request.total_job_count == 1
    assert empty_request.seed_job_exists is True


def test_dashboard_event_projection_excludes_progress_and_preserves_relevant_sequence(tmp_path):
    repository = SqliteJobRepository(tmp_path / "dashboard-events.sqlite")
    job = _for_engagement(_job("job-events", "pilot_standard_rti_guarded_execute", "connectionDetails"), "eng-1", branch="target_id")
    repository.save(
        _with_events(
            job,
            [
                JobEvent(1, "info", "terraform progress", {"step": 1}),
                JobEvent(2, "info", "topology ready", {"connectionDetails": []}),
                JobEvent(3, "info", "operator teardown started", {"step": 2}),
                JobEvent(4, "info", "lifecycle ready", {"mutationStatus": "deployed"}),
            ],
        )
    )

    full = repository.list_semantic_for_engagements(["eng-1"])
    projected = repository.list_dashboard_semantic_for_engagements(["eng-1"])

    assert [event.sequence for event in full.jobs_by_engagement["eng-1"][0].events] == [1, 2, 3, 4]
    assert [event.sequence for event in projected.jobs_by_engagement["eng-1"][0].events] == [2, 3, 4]
    assert projected.total_job_count == full.total_job_count
    assert projected.seed_job_exists == full.seed_job_exists


def test_sqlalchemy_dashboard_raw_event_hydration_matches_full_json_semantics(tmp_path):
    from sqlalchemy import event

    from app import create_app
    from app.core.config import TestConfig

    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'dashboard-raw-events.sqlite'}"

    job = _with_events(
        _for_engagement(_job("job-json-events", "pilot_standard_rti_guarded_execute", "connectionDetails"), "eng-json", branch="target_id"),
        [
            JobEvent(1, "info", "teardown dict", {"mutationStatus": "deployed"}),
            JobEvent(2, "info", "teardown array", [{"phase": "done"}]),
            JobEvent(3, "info", "teardown null", None),
            JobEvent(4, "info", "teardown empty array", []),
        ],
    )
    standalone = SqliteJobRepository(tmp_path / "dashboard-raw-events-standalone.sqlite")
    standalone.save(job)
    standalone_projected = standalone.list_dashboard_semantic_for_engagements(["eng-json"])

    app = create_app(Config)
    with app.storage_context():
        repository = SqlAlchemyJobRepository()
        repository.save(job)
        full = repository.list_semantic_for_engagements(["eng-json"])
        statements = []

        def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
            if statement.lstrip().upper().startswith("SELECT") and "FROM job_events" in statement:
                statements.append(statement)

        event.listen(app.state.database.engine, "before_cursor_execute", capture)
        try:
            projected = repository.list_dashboard_semantic_for_engagements(["eng-json"])
        finally:
            event.remove(app.state.database.engine, "before_cursor_execute", capture)

    expected_data = [{"mutationStatus": "deployed"}, [{"phase": "done"}], {}, {}]
    assert [event.sequence for event in projected.jobs_by_engagement["eng-json"][0].events] == [1, 2, 3, 4]
    assert [event.data for event in projected.jobs_by_engagement["eng-json"][0].events] == expected_data
    assert [event.data for event in full.jobs_by_engagement["eng-json"][0].events] == expected_data
    assert [event.data for event in standalone_projected.jobs_by_engagement["eng-json"][0].events] == expected_data
    assert len(statements) == 1
    assert "job_events.id" not in statements[0]
    assert "job_events.created_at" not in statements[0]


def test_dashboard_batches_durable_reads_and_matches_per_engagement_projection(tmp_path, monkeypatch):
    from sqlalchemy import event

    from app import create_app
    from app.core.config import TestConfig
    from app.services import dashboard
    from app.services.engagement_operations import get_operations_overview as direct_operations
    from app.storage.database import db
    from app.storage.engagement_repository import SqlAlchemyEngagementRepository, StoredEngagement
    from app.storage.models import EngagementOperationsModel
    from app.storage.inspection_run_repository import (
        SqlAlchemyInspectionRunRepository,
        StoredInspectionRun,
    )
    from app.storage.provider_resource_repository import (
        SqlAlchemyProviderResourceRepository,
        StoredProviderResourceRecord,
    )

    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'dashboard-batch.sqlite'}"

    app = create_app(Config)
    fixed_disk_usage = dashboard.shutil.disk_usage(tmp_path)
    monkeypatch.setattr(dashboard.shutil, "disk_usage", lambda _path: fixed_disk_usage)
    with app.storage_context():
        engagements = SqlAlchemyEngagementRepository()
        jobs = SqlAlchemyJobRepository()
        for engagement_id in ("eng-a", "eng-b"):
            engagements.save(
                StoredEngagement(
                    id=engagement_id,
                    name=engagement_id.upper(),
                    status="draft",
                    owner="operator",
                    template_id="",
                    active_revision=None,
                    input_parameters={},
                    created_at="2026-08-01T00:00:00+00:00",
                    updated_at="2026-08-01T00:00:00+00:00",
                )
            )
        db.session.add(
            EngagementOperationsModel(
                engagement_id="eng-a",
                housekeeping_items="Retain this in ordinary Operations only.",
            )
        )
        db.session.commit()
        jobs.save(
            replace_time(
                _with_events(
                    _with_input(
                        _for_engagement(
                            _job("job-eng-a", "pilot_standard_rti_guarded_execute", "connectionDetails"),
                            "eng-a",
                            branch="target_id",
                        ),
                        {"engagementId": "eng-a"},
                    ),
                    [
                        JobEvent(1, "info", "terraform progress", {"step": "plan"}),
                        JobEvent(
                            2,
                            "info",
                            "core topology ready",
                            {
                                "connectionDetails": [],
                                "mutationStatus": "deployed",
                                "finalCleanupStatus": "pending_operator_teardown",
                                "remainingCount": 0,
                                "region": "us-east",
                                "target": {"region": "us-east"},
                                "inspectorTeardownVerification": {"ok": True},
                                "inspectorCleanup": {"ok": True},
                            },
                        ),
                        JobEvent(3, "info", "operator teardown phase recorded", {"progress": 100}),
                        JobEvent(
                            4,
                            "info",
                            "created resources recorded",
                            {
                                "createdResources": [
                                    {
                                        "provider": "oci",
                                        "type": "oci_core_instance",
                                        "resourceId": "core-resource-1",
                                        "displayName": "opaque-core-resource",
                                        "region": "us-east",
                                    }
                                ]
                            },
                        ),
                    ],
                ),
                "2026-07-01T00:00:00+00:00",
            )
        )
        representative_jobs = (
            ("job-sketch", "linode_sketch_deploy", "sketchInfrastructure", []),
            ("job-outbound", "outbound_channel_validation", "outboundChannels", []),
            (
                "job-inbound",
                "inbound_channel_validation",
                "inboundChannels",
                [
                    {
                        "channelId": "channel-public-443",
                        "status": "Validated",
                        "validation": {"status": "Validated"},
                    }
                ],
            ),
            ("job-capability", "custom_capability_writer", "capabilities", []),
            ("job-service", "custom_service_writer", "servicePlacements", []),
        )
        for job_id, action, event_key, event_value in representative_jobs:
            jobs.save(
                _with_events(
                    _for_engagement(_job(job_id, action, event_key), "eng-b", branch="target_id"),
                    [
                        JobEvent(1, "info", "irrelevant progress", {"percent": 50}),
                        JobEvent(2, "info", f"{event_key} recorded", {event_key: event_value}),
                    ],
                )
            )
        jobs.save(
            _for_engagement(
                _job("job-eng-b", "pilot_standard_rti_guarded_execute", "connectionDetails"),
                "eng-b",
                branch="target_id",
            )
        )
        for index in range(251):
            jobs.save(
                replace_time(
                    _for_engagement(
                        _job(f"job-dashboard-noise-{index:03d}", "unrelated_read", "unrelated"),
                        "eng-a",
                        branch="target_id",
                    ),
                    f"2026-08-04T00:{index // 60:02d}:{index % 60:02d}+00:00",
                )
            )
        engagements.save(
            StoredEngagement(
                id="eng-archived",
                name="ENG-ARCHIVED",
                status="archived",
                owner="operator",
                template_id="",
                active_revision=None,
                input_parameters={},
                created_at="2026-07-01T00:00:00+00:00",
                updated_at="2026-07-02T00:00:00+00:00",
            )
        )
        SqlAlchemyProviderResourceRepository().save(
            StoredProviderResourceRecord(
                id="record-archived-active",
                engagement_id="eng-archived",
                engagement_name="ENG-ARCHIVED",
                provider="linode",
                resource_type="instance",
                resource_id="resource-archived-active",
                name="opaque-resource",
                region="us-east",
                lifecycle_state="running",
                status="tracked",
                source="barragan",
                metadata={"barraganOwned": True},
                adoption_job_id="",
                adopted_at="2026-07-01T00:00:00+00:00",
                updated_at="2026-07-01T00:00:00+00:00",
            )
        )
        SqlAlchemyInspectionRunRepository().save(
            StoredInspectionRun(
                id="inspection-dashboard-count-only",
                engagement_id="eng-b",
                job_id="job-inspector-public",
                trigger_type="manual",
                mode="once",
                status="succeeded",
                provider="linode",
                region="us-east",
                host={},
                targets={},
                evidence={
                    "results": [
                        {
                            "channelId": "channel-public-443",
                            "type": "https",
                            "ok": True,
                        }
                    ]
                },
                findings=[],
                created_at="2026-08-01T00:00:00+00:00",
                started_at="2026-08-01T00:00:00+00:00",
                finished_at="2026-08-01T00:01:00+00:00",
            )
        )

        captured_local_records = []
        real_reconcile = dashboard.provider_reconciliation.reconcile_provider_inventory

        def capture_reconciliation(*args, **kwargs):
            captured_local_records.extend(kwargs.get("local_provider_resources") or [])
            return real_reconcile(*args, **kwargs)

        monkeypatch.setattr(
            dashboard.provider_reconciliation,
            "reconcile_provider_inventory",
            capture_reconciliation,
        )
        monkeypatch.setattr(
            dashboard.provider_reconciliation,
            "discover_provider_resources",
            lambda: [
                {
                    "provider": "oci",
                    "resourceType": "compute_instance",
                    "resourceId": "core-resource-1",
                    "name": "opaque-core-resource",
                    "region": "us-east",
                    "lifecycleState": "running",
                    "engagementId": "eng-a",
                    "engagementName": "ENG-A",
                    "source": "provider_inventory",
                    "metadata": {"barraganOwned": True},
                }
            ],
        )

        statements = []

        def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
            if statement.lstrip().upper().startswith(("SELECT", "WITH")):
                statements.append(statement)

        event.listen(app.state.database.engine, "before_cursor_execute", capture)
        try:
            batched = dashboard.get_dashboard_inventory(include_provider_reconciliation=True)
        finally:
            event.remove(app.state.database.engine, "before_cursor_execute", capture)

        real_operations = dashboard.get_operations_overview

        class FullEventDashboardRepository(SqlAlchemyJobRepository):
            def list_dashboard_semantic_for_engagements(self, engagement_ids, *, recent_limit=250):
                full = self.list_semantic_for_engagements(engagement_ids, recent_limit=recent_limit)
                return DashboardSemanticJobBatch(
                    jobs_by_engagement=full.jobs_by_engagement,
                    total_job_count=full.total_job_count,
                    seed_job_exists=full.seed_job_exists,
                )

        def without_snapshot(*args, **kwargs):
            kwargs.pop("read_snapshot", None)
            return direct_operations(*args, **kwargs)

        monkeypatch.setattr(dashboard, "get_operations_overview", without_snapshot)
        per_engagement = dashboard.get_dashboard_inventory(
            job_repository=FullEventDashboardRepository(),
            include_provider_reconciliation=True,
        )
        monkeypatch.setattr(dashboard, "get_operations_overview", real_operations)
        ordinary_operations = direct_operations("eng-a", include_provider_findings=False)
        ordinary_inspector_operations = direct_operations("eng-b", include_provider_findings=False)

    _normalize_dashboard_time(batched)
    _normalize_dashboard_time(per_engagement)
    assert batched == per_engagement
    assert batched["orphanCandidates"] == []
    assert batched["summary"]["orphanCandidates"] == 0
    assert any(
        row.get("resourceId") == "resource-archived-active"
        for row in captured_local_records
    )
    assert sum("WITH requested" in statement for statement in statements) == 1
    assert sum("job_runs" in statement for statement in statements) == 1
    assert sum(
        statement.lstrip().upper().startswith("SELECT") and "FROM job_events" in statement
        for statement in statements
    ) == 1
    assert batched["summary"]["jobRuns"] == 259
    assert batched["systemHealth"]["database"]["seedStatus"] == "seeded"
    assert ordinary_operations["housekeepingItems"] == "Retain this in ordinary Operations only."
    assert len(ordinary_inspector_operations["inboundChannels"]) == 1
    assert ordinary_inspector_operations["inboundChannels"][0]["validation"]["externalIngressVerified"] is True
    assert sum("FROM engagement_operations" in statement for statement in statements) == 0
    assert sum("FROM inspection_runs" in statement for statement in statements) == 0
    for table in (
        "engagements",
        "engagement_services",
        "sketch_chains",
        "provider_resource_records",
        "engagement_lifecycles",
    ):
        assert sum(f"FROM {table}" in statement for statement in statements) == 1


def _job(job_id: str, action: str, event_key: str) -> StoredJobRun:
    return StoredJobRun(
        id=job_id,
        action=action,
        status="succeeded",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1"},
        artifact_refs=[],
        created_at="2026-08-01T00:00:00+00:00",
        started_at=None,
        finished_at=None,
        events=[JobEvent(1, "info", "state", {event_key: [] if event_key != "finalCleanupStatus" else "verified_clean"})],
    )


def replace_time(job: StoredJobRun, created_at: str) -> StoredJobRun:
    return StoredJobRun(**{**job.__dict__, "created_at": created_at})


def _for_engagement(job: StoredJobRun, engagement_id: str, *, branch: str) -> StoredJobRun:
    values = {
        **job.__dict__,
        "target": "system:seed",
        "target_type": "system",
        "target_id": "seed",
        "input": {},
    }
    if branch == "target_id":
        values["target_id"] = engagement_id
    elif branch == "target":
        values["target"] = f"engagement:{engagement_id}"
    elif branch == "input":
        values["input"] = {"engagementId": engagement_id}
    else:
        raise ValueError(branch)
    return StoredJobRun(**values)


def _with_events(job: StoredJobRun, events: list[JobEvent]) -> StoredJobRun:
    return StoredJobRun(**{**job.__dict__, "events": events})


def _with_input(job: StoredJobRun, input_data: dict) -> StoredJobRun:
    return StoredJobRun(**{**job.__dict__, "input": input_data})


def _job_history_indexes(path) -> set[str]:
    with sqlite3.connect(path) as connection:
        job_indexes = {str(row[1]) for row in connection.execute("PRAGMA index_list('job_runs')")}
        event_indexes = {str(row[1]) for row in connection.execute("PRAGMA index_list('job_events')")}
    return (job_indexes | event_indexes) & JOB_HISTORY_INDEXES


def _normalize_dashboard_time(body: dict) -> None:
    def normalize(value):
        if isinstance(value, dict):
            for key, nested in value.items():
                if key in {"generatedAt", "checkedAt"}:
                    value[key] = "<generated>"
                else:
                    normalize(nested)
        elif isinstance(value, list):
            for nested in value:
                normalize(nested)

    normalize(body)
