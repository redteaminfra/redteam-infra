# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Iterator

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool


@dataclass(frozen=True)
class DatabaseState:
    uri: str
    engine: Engine
    session: scoped_session


class _QueryProperty:
    def __init__(self, database: "Database") -> None:
        self._database = database

    def __get__(self, _instance: object, model: type) -> Any:
        return self._database.session.query(model)


class Database:
    """Small framework-neutral SQLAlchemy facade used by Barragan.

    It intentionally preserves the existing ``db.Model``, ``Model.query``, and
    ``db.session`` surface while selecting the engine/session from an explicit
    framework-neutral context.
    """

    Column = Column
    String = String
    Text = Text
    Integer = Integer
    Boolean = Boolean
    DateTime = DateTime
    JSON = JSON
    ForeignKey = ForeignKey
    Index = Index
    UniqueConstraint = UniqueConstraint

    def __init__(self) -> None:
        self.Model = declarative_base()
        self.Model.query = _QueryProperty(self)
        self._current_state: ContextVar[DatabaseState | None] = ContextVar(
            "barragan_database_state",
            default=None,
        )
        self._default_state: DatabaseState | None = None
        self._configuration_lock = Lock()

    def configure(self, uri: str, *, make_default: bool = False) -> DatabaseState:
        engine_options: dict[str, Any] = {}
        if uri == "sqlite:///:memory:":
            engine_options.update(
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        elif uri.startswith("sqlite:"):
            engine_options["connect_args"] = {"check_same_thread": False}
        engine = create_engine(uri, **engine_options)
        state = DatabaseState(
            uri=uri,
            engine=engine,
            session=scoped_session(
                sessionmaker(bind=engine, autoflush=True, expire_on_commit=True)
            ),
        )
        if make_default:
            with self._configuration_lock:
                self._default_state = state
        return state

    @contextmanager
    def bind(self, state: DatabaseState) -> Iterator[None]:
        token = self._current_state.set(state)
        try:
            yield
        finally:
            state.session.remove()
            self._current_state.reset(token)

    @property
    def state(self) -> DatabaseState:
        state = self._current_state.get()
        if state is not None:
            return state
        if self._default_state is not None:
            return self._default_state
        raise RuntimeError("no database context is active")

    @property
    def session(self) -> scoped_session:
        return self.state.session

    @property
    def engine(self) -> Engine:
        return self.state.engine

    @property
    def uri(self) -> str:
        return self.state.uri

    def create_all(self) -> None:
        self.Model.metadata.create_all(bind=self.engine)


db = Database()


def ensure_database_schema() -> None:
    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()
    _ensure_job_history_indexes(table_names)
    _ensure_observer_settings_table(table_names)
    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()
    if "engagement_observer_settings" in table_names:
        _ensure_inspector_settings_columns(inspector)
    _ensure_inspection_runs_table(table_names)
    _ensure_domain_tables(table_names)
    _ensure_team_tables(table_names)
    _ensure_operator_uid_allocation()
    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()
    _ensure_authentication_tables(table_names)
    _ensure_certificate_tables(table_names)
    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()
    if "certificate_assets" in table_names:
        _ensure_certificate_asset_columns(inspector)
    if "domain_assignments" in table_names:
        _ensure_domain_assignment_columns(inspector)
    if "domain_assets" in table_names:
        _ensure_domain_asset_columns(inspector)
    if "domain_dns_record_ownership" in table_names:
        _ensure_domain_dns_ownership_columns(inspector)
    if "sketch_chains" in table_names:
        _ensure_sketch_chain_columns(inspector)
    if "sketch_ssh_keys" in table_names:
        _ensure_sketch_ssh_key_columns(inspector)
    if "engagements" in table_names:
        engagement_columns = {column["name"] for column in inspector.get_columns("engagements")}
        missing_engagement_columns = [
            ("sketch_state_schema", "VARCHAR(40) NOT NULL DEFAULT 'split-v1'"),
            ("description", "TEXT NOT NULL DEFAULT ''"),
            ("documentation_url", "VARCHAR(500) NOT NULL DEFAULT ''"),
            ("jira_url", "VARCHAR(500) NOT NULL DEFAULT ''"),
        ]
        if any(column not in engagement_columns for column, _definition in missing_engagement_columns):
            if db.engine.dialect.name != "sqlite":
                raise RuntimeError("engagement metadata migration is only implemented for local SQLite")
            for column, definition in missing_engagement_columns:
                if column not in engagement_columns:
                    db.session.execute(text(f"ALTER TABLE engagements ADD COLUMN {column} {definition}"))
            db.session.commit()
        if db.engine.dialect.name == "sqlite":
            db.session.execute(
                text("UPDATE engagements SET status = 'draft' WHERE status = 'pending_customization'")
            )
            db.session.commit()

    if "deployment_revisions" not in table_names:
        if "credentials" in table_names:
            _ensure_credential_default_column(inspector)
        return

    revision_columns = {column["name"] for column in inspector.get_columns("deployment_revisions")}
    if "validation_gates" in revision_columns:
        _ensure_credential_default_column(inspector)
        return

    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("deployment_revisions.validation_gates migration is only implemented for local SQLite")

    db.session.execute(
        text("ALTER TABLE deployment_revisions ADD COLUMN validation_gates JSON NOT NULL DEFAULT '[]'")
    )
    db.session.commit()
    _ensure_credential_default_column(inspector)


def _ensure_job_history_indexes(table_names: list[str]) -> None:
    """Add the read-path indexes to existing local SQLite databases."""
    if db.engine.dialect.name != "sqlite":
        return
    if "job_runs" in table_names:
        for statement in (
            "CREATE INDEX IF NOT EXISTS ix_job_runs_target_id_created_id "
            "ON job_runs (target_id, created_at DESC, id DESC)",
            "CREATE INDEX IF NOT EXISTS ix_job_runs_target_created_id "
            "ON job_runs (target, created_at DESC, id DESC)",
            "CREATE INDEX IF NOT EXISTS ix_job_runs_input_engagement_created_id "
            "ON job_runs (json_extract(input, '$.engagementId'), created_at DESC, id DESC)",
        ):
            db.session.execute(text(statement))
    if "job_events" in table_names:
        db.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_job_events_job_sequence "
                "ON job_events (job_id, sequence)"
            )
        )
    db.session.commit()


def _ensure_domain_tables(table_names: list[str]) -> None:
    required = {
        "domain_assets",
        "domain_assignments",
        "domain_dns_snapshots",
        "domain_dns_record_ownership",
    }
    if required.issubset(set(table_names)):
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("domain inventory table migration is only implemented for local SQLite")
    from app.storage import models  # noqa: F401

    db.create_all()


def _ensure_team_tables(table_names: list[str]) -> None:
    required = {
        "team_members",
        "team_member_ssh_keys",
        "engagement_team_memberships",
        "access_audit_events",
    }
    if required.issubset(set(table_names)):
        inspector = inspect(db.engine)
        _ensure_team_member_columns(inspector)
        _ensure_engagement_team_membership_columns(inspector)
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("team access table migration is only implemented for local SQLite")
    from app.storage import models  # noqa: F401

    db.create_all()
    inspector = inspect(db.engine)
    _ensure_team_member_columns(inspector)
    _ensure_engagement_team_membership_columns(inspector)


def _ensure_operator_uid_allocation() -> None:
    """Add the UID guard to existing databases without rewriting identities."""
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("operator UID allocation migration is only implemented for local SQLite")
    from app.storage.models import OperatorUidAllocationModel, TeamMemberModel

    with db.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        duplicate = connection.execute(text(
            "SELECT desired_uid FROM team_members WHERE desired_uid IS NOT NULL "
            "GROUP BY desired_uid HAVING COUNT(*) > 1 LIMIT 1"
        )).scalar()
        if duplicate is not None:
            raise RuntimeError(
                f"duplicate operator desired UID {duplicate}; reconcile existing assignments before startup")
        OperatorUidAllocationModel.__table__.create(bind=connection, checkfirst=True)
        next(index for index in TeamMemberModel.__table__.indexes
             if index.name == "ux_team_members_desired_uid").create(bind=connection, checkfirst=True)
        connection.execute(text(
            "INSERT OR IGNORE INTO operator_uid_allocation (id, high_water_uid) VALUES (1, 5999)"))
        connection.execute(text(
            "UPDATE operator_uid_allocation SET high_water_uid = MAX(high_water_uid, "
            "COALESCE((SELECT MAX(desired_uid) FROM team_members), 5999), 5999) WHERE id = 1"))


def _ensure_certificate_tables(table_names: list[str]) -> None:
    required = {
        "engagement_certificate_profiles",
        "certificate_assets",
        "certificate_versions",
        "certificate_bindings",
    }
    if required.issubset(set(table_names)):
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("certificate manager table migration is only implemented for local SQLite")
    from app.storage import models  # noqa: F401

    db.create_all()


def _ensure_authentication_tables(table_names: list[str]) -> None:
    required = {
        "authentication_credentials",
        "authentication_sessions",
        "authentication_audit_events",
    }
    if required.issubset(set(table_names)):
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("authentication table migration is only implemented for local SQLite")
    from app.storage import models  # noqa: F401

    db.create_all()


def _ensure_certificate_asset_columns(inspector) -> None:
    asset_columns = {column["name"] for column in inspector.get_columns("certificate_assets")}
    if "notes" in asset_columns:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("certificate_assets compatibility migration is only implemented for local SQLite")
    db.session.execute(text("ALTER TABLE certificate_assets ADD COLUMN notes TEXT NOT NULL DEFAULT ''"))
    db.session.commit()


def _ensure_team_member_columns(inspector) -> None:
    member_columns = {column["name"] for column in inspector.get_columns("team_members")}
    if "desired_uid" in member_columns:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("team_members.desired_uid compatibility migration is only implemented for local SQLite")
    db.session.execute(text("ALTER TABLE team_members ADD COLUMN desired_uid INTEGER"))
    db.session.commit()


def _ensure_engagement_team_membership_columns(inspector) -> None:
    membership_columns = {column["name"] for column in inspector.get_columns("engagement_team_memberships")}
    if "infrastructure_state" in membership_columns:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("engagement_team_memberships compatibility migration is only implemented for local SQLite")
    db.session.execute(text("ALTER TABLE engagement_team_memberships ADD COLUMN infrastructure_state VARCHAR(40) NOT NULL DEFAULT 'unknown'"))
    db.session.commit()


def _ensure_observer_settings_table(table_names: list[str]) -> None:
    if "engagement_observer_settings" in table_names:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("observer settings table migration is only implemented for local SQLite")
    from app.storage import models  # noqa: F401

    db.create_all()


def _ensure_inspector_settings_columns(inspector) -> None:
    settings_columns = {column["name"] for column in inspector.get_columns("engagement_observer_settings")}
    missing_columns = [
        ("enabled", "BOOLEAN NOT NULL DEFAULT 1"),
        ("mode", "VARCHAR(40) NOT NULL DEFAULT 'once'"),
        ("schedule_weekdays", "JSON NOT NULL DEFAULT '[\"mon\", \"tue\", \"wed\", \"thu\", \"fri\", \"sat\", \"sun\"]'"),
        ("schedule_time_utc", "VARCHAR(5) NOT NULL DEFAULT '00:00'"),
        ("check_families", "JSON NOT NULL DEFAULT '[\"inbound\", \"dns\", \"tls\", \"forbidden_tcp\"]'"),
        ("port_scan_profiles", "JSON NOT NULL DEFAULT '[]'"),
        ("current_host", "JSON NOT NULL DEFAULT '{}'"),
        ("idle_retention_until", "VARCHAR(80) NOT NULL DEFAULT ''"),
        ("last_scheduled_slot", "VARCHAR(80) NOT NULL DEFAULT ''"),
        ("last_mutation_job_inspected", "VARCHAR(80) NOT NULL DEFAULT ''"),
    ]
    if not any(column not in settings_columns for column, _definition in missing_columns):
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("inspector settings compatibility migration is only implemented for local SQLite")
    for column, definition in missing_columns:
        if column not in settings_columns:
            db.session.execute(text(f"ALTER TABLE engagement_observer_settings ADD COLUMN {column} {definition}"))
    db.session.commit()


def _ensure_inspection_runs_table(table_names: list[str]) -> None:
    if "inspection_runs" in table_names:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("inspection run table migration is only implemented for local SQLite")
    from app.storage import models  # noqa: F401

    db.create_all()


def _ensure_domain_assignment_columns(inspector) -> None:
    assignment_columns = {column["name"] for column in inspector.get_columns("domain_assignments")}
    if "purpose_tags" in assignment_columns:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("domain_assignments.purpose_tags migration is only implemented for local SQLite")
    db.session.execute(text("ALTER TABLE domain_assignments ADD COLUMN purpose_tags JSON NOT NULL DEFAULT '[]'"))
    db.session.commit()


def _ensure_domain_asset_columns(inspector) -> None:
    asset_columns = {column["name"] for column in inspector.get_columns("domain_assets")}
    if "catalog_state" in asset_columns:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("domain_assets.catalog_state migration is only implemented for local SQLite")
    db.session.execute(text("ALTER TABLE domain_assets ADD COLUMN catalog_state VARCHAR(40) NOT NULL DEFAULT 'auto'"))
    db.session.commit()


def _ensure_domain_dns_ownership_columns(inspector) -> None:
    columns = {column["name"] for column in inspector.get_columns("domain_dns_record_ownership")}
    if "retired_at" in columns:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("DNS record ownership retirement migration is only implemented for local SQLite")
    db.session.execute(text("ALTER TABLE domain_dns_record_ownership ADD COLUMN retired_at DATETIME"))
    db.session.commit()


def _ensure_credential_default_column(inspector) -> None:
    table_names = inspector.get_table_names()
    if "credentials" not in table_names:
        return

    credential_columns = {column["name"] for column in inspector.get_columns("credentials")}
    if "is_default" in credential_columns:
        return

    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("credentials.is_default migration is only implemented for local SQLite")

    db.session.execute(text("ALTER TABLE credentials ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT 0"))
    db.session.commit()


def _ensure_sketch_chain_columns(inspector) -> None:
    sketch_chain_columns = {column["name"] for column in inspector.get_columns("sketch_chains")}
    missing_columns = [
        ("burned", "BOOLEAN NOT NULL DEFAULT 0"),
        ("burned_note", "TEXT NOT NULL DEFAULT ''"),
        ("deploy_job_id", "VARCHAR(64) NOT NULL DEFAULT ''"),
        ("teardown_job_id", "VARCHAR(64) NOT NULL DEFAULT ''"),
        ("terraform_working_directory", "TEXT NOT NULL DEFAULT ''"),
        ("nodes", "JSON NOT NULL DEFAULT '[]'"),
        ("edge_count", "INTEGER NOT NULL DEFAULT 1"),
        ("edge_intents", "JSON NOT NULL DEFAULT '[]'"),
    ]
    if not any(column not in sketch_chain_columns for column, _definition in missing_columns):
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("sketch_chains compatibility migration is only implemented for local SQLite")
    for column, definition in missing_columns:
        if column not in sketch_chain_columns:
            db.session.execute(text(f"ALTER TABLE sketch_chains ADD COLUMN {column} {definition}"))
    db.session.commit()


def _ensure_sketch_ssh_key_columns(inspector) -> None:
    sketch_key_columns = {column["name"] for column in inspector.get_columns("sketch_ssh_keys")}
    if "retired_keys" in sketch_key_columns:
        return
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("sketch_ssh_keys compatibility migration is only implemented for local SQLite")
    db.session.execute(text("ALTER TABLE sketch_ssh_keys ADD COLUMN retired_keys JSON NOT NULL DEFAULT '[]'"))
    db.session.commit()


def seed_database() -> None:
    from app.storage.models import EngagementModel, JobRunModel

    if EngagementModel.query.count() == 0:
        db.session.add(
            EngagementModel(
                id="eng-of02-dev",
                name="of02-dev reference",
                status="observed",
                owner="infrastructure",
                template_id="standard-rti",
                active_revision="rev-observed-001",
                input_parameters={"source": "seed", "template": "standard-rti"},
            )
        )

    if JobRunModel.query.count() == 0:
        db.session.add(
            JobRunModel(
                id="job-seed-001",
                action="capture_reference",
                status="succeeded",
                target="of02-dev reference",
                target_type="engagement",
                target_id="eng-of02-dev",
                requested_by="system",
                input={"mode": "seed"},
                artifact_refs=["docs/of02-finished-deployment-reference.md"],
                created_at=datetime(2026, 5, 31, tzinfo=timezone.utc),
            )
        )

    db.session.commit()
