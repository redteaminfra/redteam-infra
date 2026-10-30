# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class StoredDeploymentRevision:
    id: str
    engagement_id: str
    revision_number: int
    status: str
    template_id: str
    input_parameters: dict[str, Any]
    resolved_topology: dict[str, Any]
    run_intent: list[dict[str, Any]]
    validation_gates: list[dict[str, Any]]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "engagementId": self.engagement_id,
            "revisionNumber": self.revision_number,
            "status": self.status,
            "templateId": self.template_id,
            "inputParameters": self.input_parameters,
            "resolvedTopology": self.resolved_topology,
            "runIntent": self.run_intent,
            "validationGates": self.validation_gates,
        }


class RevisionRepository(Protocol):
    def list_for_engagement(self, engagement_id: str) -> list[StoredDeploymentRevision]:
        ...

    def get(self, revision_id: str) -> StoredDeploymentRevision | None:
        ...

    def count_for_engagement(self, engagement_id: str) -> int:
        ...

    def save(self, revision: StoredDeploymentRevision) -> StoredDeploymentRevision:
        ...


class SqlAlchemyRevisionRepository:
    def list_for_engagement(self, engagement_id: str) -> list[StoredDeploymentRevision]:
        from app.storage.models import DeploymentRevisionModel

        rows = (
            DeploymentRevisionModel.query.filter_by(engagement_id=engagement_id)
            .order_by(DeploymentRevisionModel.revision_number.asc())
            .all()
        )
        return [_from_model(row) for row in rows]

    def get(self, revision_id: str) -> StoredDeploymentRevision | None:
        from app.storage.models import DeploymentRevisionModel

        row = DeploymentRevisionModel.query.get(revision_id)
        if row is None:
            return None
        return _from_model(row)

    def count_for_engagement(self, engagement_id: str) -> int:
        from app.storage.models import DeploymentRevisionModel

        return DeploymentRevisionModel.query.filter_by(engagement_id=engagement_id).count()

    def save(self, revision: StoredDeploymentRevision) -> StoredDeploymentRevision:
        from app.storage.database import db
        from app.storage.models import DeploymentRevisionModel

        row = DeploymentRevisionModel(
            id=revision.id,
            engagement_id=revision.engagement_id,
            revision_number=revision.revision_number,
            status=revision.status,
            template_id=revision.template_id,
            input_parameters=revision.input_parameters,
            resolved_topology=revision.resolved_topology,
            run_intent=revision.run_intent,
            validation_gates=revision.validation_gates,
        )
        db.session.add(row)
        db.session.commit()
        return _from_model(row)


class SqliteRevisionRepository:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS deployment_revisions (
                  id TEXT PRIMARY KEY,
                  engagement_id TEXT NOT NULL,
                  revision_number INTEGER NOT NULL,
                  status TEXT NOT NULL,
                  template_id TEXT NOT NULL,
                  input_parameters TEXT NOT NULL,
                  resolved_topology TEXT NOT NULL,
                  run_intent TEXT NOT NULL,
                  validation_gates TEXT NOT NULL
                )
                """
            )

    def list_for_engagement(self, engagement_id: str) -> list[StoredDeploymentRevision]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, engagement_id, revision_number, status, template_id,
                       input_parameters, resolved_topology, run_intent, validation_gates
                FROM deployment_revisions
                WHERE engagement_id = ?
                ORDER BY revision_number ASC
                """,
                (engagement_id,),
            ).fetchall()
        return [_from_sqlite_row(row) for row in rows]

    def get(self, revision_id: str) -> StoredDeploymentRevision | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, engagement_id, revision_number, status, template_id,
                       input_parameters, resolved_topology, run_intent, validation_gates
                FROM deployment_revisions
                WHERE id = ?
                """,
                (revision_id,),
            ).fetchone()
        if row is None:
            return None
        return _from_sqlite_row(row)

    def count_for_engagement(self, engagement_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM deployment_revisions WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
        return int(row["count"])

    def save(self, revision: StoredDeploymentRevision) -> StoredDeploymentRevision:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO deployment_revisions (
                  id, engagement_id, revision_number, status, template_id,
                  input_parameters, resolved_topology, run_intent, validation_gates
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    revision.id,
                    revision.engagement_id,
                    revision.revision_number,
                    revision.status,
                    revision.template_id,
                    json.dumps(revision.input_parameters, sort_keys=True),
                    json.dumps(revision.resolved_topology, sort_keys=True),
                    json.dumps(revision.run_intent, sort_keys=True),
                    json.dumps(revision.validation_gates, sort_keys=True),
                ),
            )
        stored = self.get(revision.id)
        if stored is None:
            raise RuntimeError("revision save did not persist a readable row")
        return stored

    def _connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection


def _from_model(row: Any) -> StoredDeploymentRevision:
    return StoredDeploymentRevision(
        id=row.id,
        engagement_id=row.engagement_id,
        revision_number=row.revision_number,
        status=row.status,
        template_id=row.template_id,
        input_parameters=row.input_parameters or {},
        resolved_topology=row.resolved_topology or {},
        run_intent=row.run_intent or [],
        validation_gates=row.validation_gates or [],
    )


def _from_sqlite_row(row: sqlite3.Row) -> StoredDeploymentRevision:
    return StoredDeploymentRevision(
        id=row["id"],
        engagement_id=row["engagement_id"],
        revision_number=row["revision_number"],
        status=row["status"],
        template_id=row["template_id"],
        input_parameters=json.loads(row["input_parameters"]),
        resolved_topology=json.loads(row["resolved_topology"]),
        run_intent=json.loads(row["run_intent"]),
        validation_gates=json.loads(row["validation_gates"]),
    )
