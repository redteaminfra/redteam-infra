# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.domain import EngagementDetail, EngagementSummary


@dataclass(frozen=True)
class StoredEngagement:
    id: str
    name: str
    status: str
    owner: str
    template_id: str
    active_revision: str | None
    input_parameters: dict[str, Any]
    sketch_state_schema: str = "split-v1"
    description: str = ""
    documentation_url: str = ""
    jira_url: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_summary(self) -> EngagementSummary:
        return EngagementSummary(
            id=self.id,
            name=self.name,
            status=self.status,
            owner=self.owner,
            template_id=self.template_id or None,
            active_revision=self.active_revision,
            sketch_state_schema=self.sketch_state_schema,
            description=self.description,
            documentation_url=self.documentation_url,
            jira_url=self.jira_url,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    def to_detail(self) -> EngagementDetail:
        return EngagementDetail(
            id=self.id,
            name=self.name,
            status=self.status,
            owner=self.owner,
            template_id=self.template_id or None,
            active_revision=self.active_revision,
            input_parameters=self.input_parameters,
            sketch_state_schema=self.sketch_state_schema,
            description=self.description,
            documentation_url=self.documentation_url,
            jira_url=self.jira_url,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class EngagementRepository(Protocol):
    def list(self) -> list[StoredEngagement]:
        ...

    def get(self, engagement_id: str) -> StoredEngagement | None:
        ...

    def save(self, engagement: StoredEngagement) -> StoredEngagement:
        ...

    def update_metadata(
        self,
        engagement_id: str,
        name: str,
        owner: str,
        description: str,
        documentation_url: str,
        jira_url: str,
    ) -> StoredEngagement | None:
        ...

    def update_status(self, engagement_id: str, status: str) -> StoredEngagement | None:
        ...

    def configure_infrastructure(
        self,
        engagement_id: str,
        template_id: str,
        input_parameters: dict[str, Any],
    ) -> StoredEngagement | None:
        ...

    def update_revision_state(
        self,
        engagement_id: str,
        active_revision: str,
        status: str,
    ) -> StoredEngagement | None:
        ...


class SqlAlchemyEngagementRepository:
    def list(self) -> list[StoredEngagement]:
        from app.storage.models import EngagementModel

        rows = EngagementModel.query.order_by(EngagementModel.name.asc()).all()
        return [_from_model(row) for row in rows]

    def get(self, engagement_id: str) -> StoredEngagement | None:
        from app.storage.models import EngagementModel

        row = EngagementModel.query.get(engagement_id)
        if row is None:
            return None
        return _from_model(row)

    def save(self, engagement: StoredEngagement) -> StoredEngagement:
        from app.storage.database import db
        from app.storage.models import EngagementModel

        row = EngagementModel(
            id=engagement.id,
            name=engagement.name,
            status=engagement.status,
            owner=engagement.owner,
            template_id=engagement.template_id,
            active_revision=engagement.active_revision,
            input_parameters=engagement.input_parameters,
            sketch_state_schema=engagement.sketch_state_schema,
            description=engagement.description,
            documentation_url=engagement.documentation_url,
            jira_url=engagement.jira_url,
        )
        db.session.add(row)
        db.session.commit()
        return _from_model(row)

    def update_metadata(
        self,
        engagement_id: str,
        name: str,
        owner: str,
        description: str,
        documentation_url: str,
        jira_url: str,
    ) -> StoredEngagement | None:
        from app.storage.database import db
        from app.storage.models import EngagementModel

        row = EngagementModel.query.get(engagement_id)
        if row is None:
            return None
        row.name = name
        row.owner = owner
        row.description = description
        row.documentation_url = documentation_url
        row.jira_url = jira_url
        db.session.commit()
        return _from_model(row)

    def update_status(self, engagement_id: str, status: str) -> StoredEngagement | None:
        from app.storage.database import db
        from app.storage.models import EngagementModel

        row = EngagementModel.query.get(engagement_id)
        if row is None:
            return None
        row.status = status
        db.session.commit()
        return _from_model(row)

    def configure_infrastructure(
        self,
        engagement_id: str,
        template_id: str,
        input_parameters: dict[str, Any],
    ) -> StoredEngagement | None:
        from app.storage.database import db
        from app.storage.models import EngagementModel

        row = EngagementModel.query.get(engagement_id)
        if row is None:
            return None
        row.template_id = template_id
        row.input_parameters = input_parameters
        db.session.commit()
        return _from_model(row)

    def update_revision_state(
        self,
        engagement_id: str,
        active_revision: str,
        status: str,
    ) -> StoredEngagement | None:
        from app.storage.database import db
        from app.storage.models import EngagementModel

        row = EngagementModel.query.get(engagement_id)
        if row is None:
            return None
        row.active_revision = active_revision
        row.status = status
        db.session.commit()
        return _from_model(row)


class SqliteEngagementRepository:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS engagements (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  status TEXT NOT NULL,
                  owner TEXT NOT NULL,
                  template_id TEXT NOT NULL,
                  active_revision TEXT,
                  input_parameters TEXT NOT NULL,
                  sketch_state_schema TEXT NOT NULL DEFAULT 'split-v1',
                  description TEXT NOT NULL DEFAULT '',
                  documentation_url TEXT NOT NULL DEFAULT '',
                  jira_url TEXT NOT NULL DEFAULT ''
                )
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(engagements)").fetchall()}
            for column, definition in [
                ("sketch_state_schema", "TEXT NOT NULL DEFAULT 'split-v1'"),
                ("description", "TEXT NOT NULL DEFAULT ''"),
                ("documentation_url", "TEXT NOT NULL DEFAULT ''"),
                ("jira_url", "TEXT NOT NULL DEFAULT ''"),
            ]:
                if column not in columns:
                    connection.execute(f"ALTER TABLE engagements ADD COLUMN {column} {definition}")
            connection.execute(
                "UPDATE engagements SET status = 'draft' WHERE status = 'pending_customization'"
            )

    def list(self) -> list[StoredEngagement]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, name, status, owner, template_id, active_revision, input_parameters,
                       sketch_state_schema, description, documentation_url, jira_url
                FROM engagements
                ORDER BY name ASC
                """
            ).fetchall()
        return [_from_sqlite_row(row) for row in rows]

    def get(self, engagement_id: str) -> StoredEngagement | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, name, status, owner, template_id, active_revision, input_parameters,
                       sketch_state_schema, description, documentation_url, jira_url
                FROM engagements
                WHERE id = ?
                """,
                (engagement_id,),
            ).fetchone()
        if row is None:
            return None
        return _from_sqlite_row(row)

    def save(self, engagement: StoredEngagement) -> StoredEngagement:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO engagements (
                  id, name, status, owner, template_id, active_revision, input_parameters,
                  sketch_state_schema, description, documentation_url, jira_url
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    engagement.name,
                    engagement.status,
                    engagement.owner,
                    engagement.template_id,
                    engagement.active_revision,
                    json.dumps(engagement.input_parameters, sort_keys=True),
                    engagement.sketch_state_schema,
                    engagement.description,
                    engagement.documentation_url,
                    engagement.jira_url,
                ),
            )
        stored = self.get(engagement.id)
        if stored is None:
            raise RuntimeError("engagement save did not persist a readable row")
        return stored

    def update_revision_state(
        self,
        engagement_id: str,
        active_revision: str,
        status: str,
    ) -> StoredEngagement | None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE engagements
                SET active_revision = ?, status = ?
                WHERE id = ?
                """,
                (active_revision, status, engagement_id),
            )
        if cursor.rowcount == 0:
            return None
        return self.get(engagement_id)

    def update_metadata(
        self,
        engagement_id: str,
        name: str,
        owner: str,
        description: str,
        documentation_url: str,
        jira_url: str,
    ) -> StoredEngagement | None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE engagements
                SET name = ?, owner = ?, description = ?, documentation_url = ?, jira_url = ?
                WHERE id = ?
                """,
                (name, owner, description, documentation_url, jira_url, engagement_id),
            )
        if cursor.rowcount == 0:
            return None
        return self.get(engagement_id)

    def update_status(self, engagement_id: str, status: str) -> StoredEngagement | None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE engagements
                SET status = ?
                WHERE id = ?
                """,
                (status, engagement_id),
            )
        if cursor.rowcount == 0:
            return None
        return self.get(engagement_id)

    def configure_infrastructure(
        self,
        engagement_id: str,
        template_id: str,
        input_parameters: dict[str, Any],
    ) -> StoredEngagement | None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE engagements
                SET template_id = ?, input_parameters = ?
                WHERE id = ?
                """,
                (template_id, json.dumps(input_parameters, sort_keys=True), engagement_id),
            )
        if cursor.rowcount == 0:
            return None
        return self.get(engagement_id)

    def _connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection


def _from_model(row: Any) -> StoredEngagement:
    return StoredEngagement(
        id=row.id,
        name=row.name,
        status=_normalized_status(row.status),
        owner=row.owner,
        template_id=row.template_id or "",
        active_revision=row.active_revision,
        input_parameters=row.input_parameters or {},
        sketch_state_schema=getattr(row, "sketch_state_schema", "split-v1") or "split-v1",
        description=row.description or "",
        documentation_url=row.documentation_url or "",
        jira_url=row.jira_url or "",
        created_at=_format_datetime(getattr(row, "created_at", None)),
        updated_at=_format_datetime(getattr(row, "updated_at", None)),
    )


def _from_sqlite_row(row: sqlite3.Row) -> StoredEngagement:
    return StoredEngagement(
        id=row["id"],
        name=row["name"],
        status=_normalized_status(row["status"]),
        owner=row["owner"],
        template_id=row["template_id"] or "",
        active_revision=row["active_revision"],
        input_parameters=json.loads(row["input_parameters"]),
        sketch_state_schema=row["sketch_state_schema"] or "split-v1",
        description=row["description"] or "",
        documentation_url=row["documentation_url"] or "",
        jira_url=row["jira_url"] or "",
    )


def _format_datetime(value: Any) -> str:
    return value.isoformat() if value is not None else ""


def _normalized_status(value: Any) -> str:
    status = str(value or "draft")
    return "draft" if status == "pending_customization" else status
