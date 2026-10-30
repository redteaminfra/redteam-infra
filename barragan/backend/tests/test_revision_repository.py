# Copyright (c) 2026, Oracle and/or its affiliates.
import tempfile
import unittest
from pathlib import Path

from app.services.engagements import create_draft_engagement
from app.services.revisions import (
    RevisionNotFoundError,
    create_revision,
    get_revision,
    list_revisions,
)
from app.storage.engagement_repository import SqliteEngagementRepository
from app.storage.revision_repository import SqliteRevisionRepository
from tests.test_catalog_service import valid_standard_rti_payload


class RevisionRepositoryTests(unittest.TestCase):
    def test_create_list_and_detail_persist_revisions_for_engagement(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "barragan.sqlite3"
            engagements = SqliteEngagementRepository(database_path)
            revisions = SqliteRevisionRepository(database_path)
            engagement = create_draft_engagement(
                {
                    "templateId": "standard-rti",
                    "owner": "operator@example.invalid",
                    "inputParameters": valid_standard_rti_payload(),
                },
                repository=engagements,
            )

            first = create_revision(
                engagement.id,
                revision_repository=revisions,
                engagement_repository=engagements,
            )
            second = create_revision(
                engagement.id,
                revision_repository=revisions,
                engagement_repository=engagements,
            )

            persisted_revisions = SqliteRevisionRepository(database_path)
            listed = list_revisions(engagement.id, revision_repository=persisted_revisions)
            detail = get_revision(second["id"], revision_repository=persisted_revisions)
            updated_engagement = SqliteEngagementRepository(database_path).get(engagement.id)

            self.assertEqual(first["revisionNumber"], 1)
            self.assertEqual(second["revisionNumber"], 2)
            self.assertEqual([revision["id"] for revision in listed], [first["id"], second["id"]])
            self.assertIsNotNone(detail)
            self.assertEqual(detail["status"], "compiled")
            self.assertEqual(detail["resolvedTopology"]["sketchChains"][0]["managementPath"][1], "homebase")
            self.assertEqual(detail["validationGates"][0]["id"], "core-topology")
            self.assertIsNotNone(updated_engagement)
            self.assertEqual(updated_engagement.active_revision, second["id"])
            self.assertEqual(updated_engagement.status, "planned")

    def test_create_revision_rejects_missing_engagement(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "barragan.sqlite3"
            engagements = SqliteEngagementRepository(database_path)
            revisions = SqliteRevisionRepository(database_path)

            with self.assertRaises(RevisionNotFoundError):
                create_revision(
                    "eng-missing",
                    revision_repository=revisions,
                    engagement_repository=engagements,
                )

    def test_create_revision_uses_engagement_template_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "barragan.sqlite3"
            engagements = SqliteEngagementRepository(database_path)
            revisions = SqliteRevisionRepository(database_path)
            payload = valid_standard_rti_payload()
            payload["proxyCount"] = 1
            payload["sketchChains"][0]["edgeCount"] = 2
            engagement = create_draft_engagement(
                {
                    "templateId": "dev-infra",
                    "owner": "operator@example.invalid",
                    "inputParameters": payload,
                },
                repository=engagements,
            )

            revision = create_revision(
                engagement.id,
                revision_repository=revisions,
                engagement_repository=engagements,
            )

            self.assertEqual(revision["templateId"], "dev-infra")
            self.assertEqual(revision["resolvedTopology"]["nodeGroups"][1]["count"], 1)
            self.assertEqual(revision["resolvedTopology"]["sketchChains"][0]["edgeCount"], 2)


if __name__ == "__main__":
    unittest.main()
