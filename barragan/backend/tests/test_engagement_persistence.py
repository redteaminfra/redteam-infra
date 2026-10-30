# Copyright (c) 2026, Oracle and/or its affiliates.
import tempfile
import unittest
import sqlite3
from pathlib import Path
from unittest.mock import patch

from app.services.engagements import (
    ActiveInfrastructureError,
    EngagementValidationError,
    archive_engagement,
    configure_engagement_infrastructure,
    create_draft_engagement,
    get_engagement,
    list_engagements,
    retire_engagement,
    update_engagement_metadata,
    _validate_sketch_schema,
)
from app.domain import JobEvent
from app.storage.engagement_repository import SqliteEngagementRepository
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import SqliteJobRepository, StoredJobRun
from tests.test_catalog_service import valid_standard_rti_payload


class EngagementPersistenceTests(unittest.TestCase):
    def test_existing_engagements_migrate_to_split_v1_schema(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "legacy.sqlite3"
            with sqlite3.connect(database_path) as connection:
                connection.execute(
                    """CREATE TABLE engagements (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
                    owner TEXT NOT NULL, template_id TEXT NOT NULL,
                    active_revision TEXT, input_parameters TEXT NOT NULL)"""
                )
                connection.execute(
                    "INSERT INTO engagements VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ("eng-existing", "Existing", "draft", "operator", "", None, "{}"),
                )
            engagement = SqliteEngagementRepository(database_path).get("eng-existing")
            self.assertIsNotNone(engagement)
            self.assertEqual(engagement.sketch_state_schema, "split-v1")
            self.assertEqual(engagement.to_detail().to_dict()["sketchStateSchema"], "split-v1")

    def test_unavailable_keyed_schema_cannot_be_selected_at_creation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteEngagementRepository(Path(temp_dir) / "engagements.sqlite3")
            with self.assertRaises(EngagementValidationError) as context:
                create_draft_engagement(
                    {"name": "Pilot", "owner": "operator", "sketchStateSchema": "provider-keyed-v2"},
                    repository=repository,
                )
            self.assertIn("DevTest", context.exception.errors[0])
            self.assertEqual(repository.list(), [])

    def test_devtest_keyed_metadata_persists_and_requires_two_digitalocean_chains(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "app.services.engagements.runtime_value", return_value="devtest"
        ):
            repository = SqliteEngagementRepository(Path(temp_dir) / "engagements.sqlite3")
            created = create_draft_engagement(
                {"name": "Pilot", "owner": "operator", "sketchStateSchema": "provider-keyed-v2"},
                repository=repository,
            )
            self.assertEqual(repository.get(created.id).sketch_state_schema, "provider-keyed-v2")
            payload = valid_standard_rti_payload()
            payload["sketchChains"][0].update(middleProvider="digitalocean", middleRegion="sfo3", middleSize="s-1vcpu-1gb")
            payload["sketchChains"].append({
                **payload["sketchChains"][0], "id": "chain-2", "assignedProxy": "proxy02", "edgeRegion": "sfo3",
            })
            with self.assertRaises(EngagementValidationError) as one_chain:
                configure_engagement_infrastructure(created.id, {
                    "templateId": "standard-rti", "inputParameters": {**payload, "sketchChains": payload["sketchChains"][:1]},
                }, repository=repository)
            self.assertTrue(any("exactly two" in error for error in one_chain.exception.errors))
            configured = configure_engagement_infrastructure(created.id, {
                "templateId": "standard-rti", "inputParameters": payload,
            }, repository=repository)
            self.assertEqual(configured.sketch_state_schema, "provider-keyed-v2")
            self.assertEqual(len(configured.input_parameters["sketchChains"]), 2)

            bad_target = {**payload, "deploymentTarget": "redteam-production"}
            with self.assertRaises(EngagementValidationError) as wrong_target:
                configure_engagement_infrastructure(created.id, {
                    "templateId": "standard-rti", "inputParameters": bad_target,
                }, repository=repository)
            self.assertTrue(any("deploymentTarget" in error or "barragan-testing" in error for error in wrong_target.exception.errors))
            self.assertEqual(repository.get(created.id).input_parameters, configured.input_parameters)

    def test_devtest_keyed_small_dev_accepts_one_uniform_chain_per_provider(self):
        for providers in (("linode", "digitalocean"), ("digitalocean", "linode")):
            with self.subTest(providers=providers), tempfile.TemporaryDirectory() as temp_dir, patch(
                "app.services.engagements.runtime_value", return_value="devtest"
            ):
                repository = SqliteEngagementRepository(Path(temp_dir) / "engagements.sqlite3")
                created = create_draft_engagement(
                    {"name": "Pilot", "owner": "operator", "sketchStateSchema": "provider-keyed-v2"},
                    repository=repository,
                )
                payload = valid_standard_rti_payload()
                payload.pop("elkEnabled")
                payload["proxyCount"] = 1
                payload["deploymentTarget"] = "barragan-testing"
                chains = []
                for index, provider in enumerate(providers, start=1):
                    region, size = (("us-sea", "g6-nanode-1") if provider == "linode"
                                    else ("sfo3", "s-1vcpu-1gb"))
                    chains.append({
                        "id": f"chain-{index}", "assignedProxy": "proxy01",
                        "middleProvider": provider, "edgeProvider": provider,
                        "middleRegion": region, "edgeRegion": region,
                        "middleSize": size, "edgeSize": size,
                    })
                payload["sketchChains"] = chains
                configured = configure_engagement_infrastructure(created.id, {
                    "templateId": "small-dev-infra", "inputParameters": payload,
                }, repository=repository)
                self.assertEqual([chain["middleProvider"] for chain in
                                  configured.input_parameters["sketchChains"]], list(providers))

                cross_provider = {**chains[0], "edgeProvider": providers[1]}
                errors = []
                _validate_sketch_schema("provider-keyed-v2", {
                    **payload, "sketchChains": [cross_provider, chains[1]]}, errors)
                self.assertTrue(any("same-provider" in error for error in errors))

    def test_existing_engagement_schema_cannot_be_changed_by_configuration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteEngagementRepository(Path(temp_dir) / "engagements.sqlite3")
            existing = repository.save(StoredEngagement(
                id="eng-existing", name="Existing", status="draft", owner="operator",
                template_id="", active_revision=None, input_parameters={},
            ))
            with self.assertRaises(EngagementValidationError) as context:
                configure_engagement_infrastructure(
                    existing.id,
                    {
                        "templateId": "standard-rti",
                        "inputParameters": valid_standard_rti_payload(),
                        "sketchStateSchema": "provider-keyed-v2",
                    },
                    repository=repository,
                )
            self.assertIn("immutable", context.exception.errors[0])
            self.assertEqual(repository.get(existing.id).sketch_state_schema, "split-v1")

    def test_legacy_pending_customization_status_migrates_to_draft(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "barragan.sqlite3"
            repository = SqliteEngagementRepository(database_path)
            repository.save(
                StoredEngagement(
                    id="eng-legacy",
                    name="Legacy draft",
                    status="pending_customization",
                    owner="operator",
                    template_id="",
                    active_revision=None,
                    input_parameters={},
                )
            )

            migrated = SqliteEngagementRepository(database_path).get("eng-legacy")

            self.assertIsNotNone(migrated)
            self.assertEqual(migrated.status, "draft")

    def test_create_list_and_detail_persist_to_sqlite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "barragan.sqlite3"
            repository = SqliteEngagementRepository(database_path)

            created = create_draft_engagement(
                {
                    "templateId": "standard-rti",
                    "owner": "operator@example.invalid",
                    "inputParameters": valid_standard_rti_payload(),
                },
                repository=repository,
            )

            self.assertEqual(created.status, "draft")
            self.assertEqual(created.template_id, "standard-rti")
            self.assertEqual(created.name, "of02-dev")

            persisted_repository = SqliteEngagementRepository(database_path)
            summaries = list_engagements(repository=persisted_repository)
            detail = get_engagement(created.id, repository=persisted_repository)

            self.assertEqual([summary.id for summary in summaries], [created.id])
            self.assertIsNotNone(detail)
            self.assertEqual(detail.owner, "operator@example.invalid")
            self.assertEqual(detail.input_parameters["proxyCount"], 2)

    def test_metadata_lifecycle_persists_to_sqlite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "barragan.sqlite3"
            repository = SqliteEngagementRepository(database_path)
            job_repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")

            created = create_draft_engagement(
                {
                    "name": "ZY01",
                    "owner": "example_operator",
                    "description": "Training engagement",
                    "documentationUrl": "https://docs.example.invalid/zy01",
                    "jiraUrl": "https://jira.example.invalid/browse/ZY01",
                },
                repository=repository,
            )

            self.assertIsNone(created.template_id)
            self.assertEqual(created.description, "Training engagement")

            updated = update_engagement_metadata(
                created.id,
                {
                    "name": "ZY01-updated",
                    "owner": "operator",
                    "description": "Updated",
                    "documentationUrl": "",
                    "jiraUrl": "",
                },
                repository=repository,
            )
            self.assertIsNotNone(updated)
            self.assertEqual(updated.name, "ZY01-updated")

            archived = archive_engagement(created.id, repository=repository, job_repository=job_repository)
            self.assertIsNotNone(archived)
            self.assertEqual(archived.status, "archived")
            self.assertEqual(list_engagements(repository=repository), [])
            self.assertEqual([engagement.id for engagement in list_engagements(repository=repository, include_inactive=True)], [created.id])

            retired = retire_engagement(created.id, repository=repository, job_repository=job_repository)
            self.assertIsNotNone(retired)
            self.assertEqual(retired.status, "retired")
            self.assertIsNotNone(get_engagement(created.id, repository=repository))

    def test_lifecycle_rejects_archive_or_delete_with_active_infrastructure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            engagement_repository = SqliteEngagementRepository(Path(temp_dir) / "engagements.sqlite3")
            job_repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            created = create_draft_engagement(
                {"name": "ZY01", "owner": "example_operator"},
                repository=engagement_repository,
            )
            job_repository.save(
                StoredJobRun(
                    id="job-active-infra",
                    action="pilot_standard_rti_guarded_execute",
                    status="succeeded",
                    target="oci-compartment:barragan-testing",
                    target_type="oci_compartment",
                    target_id="ocid1.compartment.oc1..testing",
                    requested_by="operator",
                    input={"engagementId": created.id},
                    artifact_refs=[],
                    created_at="2026-06-02T00:00:00+00:00",
                    started_at="2026-06-02T00:00:01+00:00",
                    finished_at="2026-06-02T00:10:00+00:00",
                    events=[
                        JobEvent(
                            1,
                            "info",
                            "pilot Standard RTI run finished",
                            {
                                "mutationStatus": "deployed",
                                "finalCleanupStatus": "pending_operator_teardown",
                            },
                        )
                    ],
                )
            )

            with self.assertRaises(ActiveInfrastructureError) as archive_error:
                archive_engagement(created.id, repository=engagement_repository, job_repository=job_repository)
            with self.assertRaises(ActiveInfrastructureError) as delete_error:
                retire_engagement(created.id, repository=engagement_repository, job_repository=job_repository)

            self.assertEqual(archive_error.exception.job_id, "job-active-infra")
            self.assertEqual(delete_error.exception.job_id, "job-active-infra")
            self.assertEqual(get_engagement(created.id, repository=engagement_repository).status, "draft")

    def test_lifecycle_rejects_archive_when_inspector_teardown_gate_failed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            engagement_repository = SqliteEngagementRepository(Path(temp_dir) / "engagements.sqlite3")
            job_repository = SqliteJobRepository(Path(temp_dir) / "jobs.sqlite3")
            created = create_draft_engagement(
                {"name": "ZY01", "owner": "example_operator"},
                repository=engagement_repository,
            )
            job_repository.save(
                StoredJobRun(
                    id="job-inspector-gate-failed",
                    action="pilot_standard_rti_guarded_execute",
                    status="failed",
                    target="oci-compartment:barragan-testing",
                    target_type="oci_compartment",
                    target_id="ocid1.compartment.oc1..testing",
                    requested_by="operator",
                    input={"engagementId": created.id},
                    artifact_refs=[],
                    created_at="2026-06-02T00:00:00+00:00",
                    started_at="2026-06-02T00:00:01+00:00",
                    finished_at="2026-06-02T00:10:00+00:00",
                    events=[
                        JobEvent(
                            1,
                            "info",
                            "cleanup verification completed",
                            {"status": "verified_clean", "ok": True, "remainingCount": 0},
                        ),
                        JobEvent(
                            2,
                            "error",
                            "Inspector teardown verification failed",
                            {
                                "ok": False,
                                "status": "verification_failed",
                                "targetCount": 1,
                            },
                        ),
                        JobEvent(
                            3,
                            "error",
                            "pilot Standard RTI teardown finished",
                            {
                                "mutationStatus": "destroyed",
                                "finalCleanupStatus": "verified_clean",
                                "inspectorTeardownVerification": {
                                    "ok": False,
                                    "status": "verification_failed",
                                },
                            },
                        ),
                    ],
                )
            )

            with self.assertRaises(ActiveInfrastructureError) as archive_error:
                archive_engagement(created.id, repository=engagement_repository, job_repository=job_repository)

            self.assertEqual(archive_error.exception.job_id, "job-inspector-gate-failed")
            self.assertEqual(get_engagement(created.id, repository=engagement_repository).status, "draft")

    def test_metadata_engagement_can_be_configured_for_infrastructure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "barragan.sqlite3"
            repository = SqliteEngagementRepository(database_path)
            created = create_draft_engagement(
                {"name": "ZY01", "owner": "example_operator"},
                repository=repository,
            )

            configured = configure_engagement_infrastructure(
                created.id,
                {
                    "templateId": "standard-rti",
                    "inputParameters": valid_standard_rti_payload(),
                },
                repository=repository,
            )

            self.assertIsNotNone(configured)
            self.assertEqual(configured.template_id, "standard-rti")
            self.assertEqual(configured.input_parameters["engagementName"], "of02-dev")

    def test_create_rejects_invalid_template_input_without_persisting(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SqliteEngagementRepository(Path(temp_dir) / "barragan.sqlite3")
            payload = valid_standard_rti_payload()
            payload["sketchChains"][0]["edgeProvider"] = "oci"

            with self.assertRaises(EngagementValidationError) as raised:
                create_draft_engagement(
                    {
                        "templateId": "standard-rti",
                        "owner": "operator@example.invalid",
                        "inputParameters": payload,
                    },
                    repository=repository,
                )

            self.assertIn("edgeProvider", raised.exception.errors[0])
            self.assertEqual(list_engagements(repository=repository), [])


if __name__ == "__main__":
    unittest.main()
