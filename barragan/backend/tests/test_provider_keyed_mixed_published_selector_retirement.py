# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted published selector retirement is exact and one-shot."""

import pytest
from dataclasses import replace

from app.services.provider_keyed_selector_retirement import DeleteResponse
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_inspector_negative import _proof
import app.services.provider_keyed_mixed_published_selector_retirement as service
import app.services.provider_keyed_mixed_zero_apply_inspector_negative as negative


class Catalog:
    def __init__(self, selector, visible):
        self.selector = selector
        self.visible = visible
        self.calls = []

    def request(self, base, method, path, token):
        self.calls.append(path)
        if path == f"/tags/{self.selector}":
            return {"tag": {"name": self.selector, "resources": {"count": 0}}}
        if path == "/firewalls?page=1&per_page=200":
            return {"firewalls": [], "meta": {"total": 0},
                    "links": {"pages": {}}}
        pytest.fail(f"unexpected provider inventory path: {path}")


class Delete:
    def __init__(self, visible, *, lost=False):
        self.visible = visible
        self.lost = lost
        self.deletes = 0

    def get_tag_status(self, token, selector):
        return 200 if self.visible["tag"] else 404

    def delete_tag(self, token, selector):
        self.deletes += 1
        self.visible["tag"] = False
        if self.lost:
            raise TimeoutError("DELETE response lost")
        return DeleteResponse(204, b"")


@pytest.mark.parametrize("present,lost", [(True, False), (True, True), (False, False)])
def test_published_selector_guarded_delete_and_no_replay(
        client, ready, tmp_path, monkeypatch, present, lost):
    with client.application.storage_context():
        source, receipt, jobs, calls, scans, proof_options = _proof(
            client, ready, tmp_path, monkeypatch)
        negative_result = negative.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **proof_options)
        initial = jobs.get(source.parent_job_id)
        selector = initial.events[5].data["reviewedPolicy"]["digitalocean"]["selector_tag"]
        visible = {"tag": present}
        catalog = Catalog(selector, visible)
        deleter = Delete(visible, lost=lost)
        monkeypatch.setattr(service, "_default_state_root", lambda: proof_options["state_root"])
        options = dict(
            environment="devtest", state_root=proof_options["state_root"],
            core_state_root=proof_options["core_state_root"], job_repository=jobs,
            plan_repository=proof_options["plan_repository"],
            credential_repository=ready.case.args["credential_repository"],
            lease_lookup=proof_options["lease_lookup"],
            catalog_transport=catalog, delete_transport=deleter,
            decrypt_secret=lambda encrypted: encrypted,
            post_source_reader=proof_options["post_source_reader"],
            oci_absence_recognizer=lambda *_a, **_k: receipt,
            negative_recognizer=lambda *_a, **_k: negative_result)
        if lost:
            with pytest.raises(service.PublishedMixedSelectorRetirementAttention):
                service.retire_published_mixed_selector(
                    source.engagement_id, source.core_job_id, **options)
            uncertain = jobs.get(service._child_id(source.core_job_id))
            assert uncertain.events[-1].message == "mixed published selector DELETE intended"
            # Recovery may take the child only after its prior claim expires.
            from sqlalchemy import update
            from app.storage.database import db
            from app.storage.models import JobRunModel
            db.session.execute(update(JobRunModel).where(
                JobRunModel.id == uncertain.id).values(input={
                    **uncertain.input, "claimExpiresAt": "2026-01-01T00:00:00+00:00"}))
            db.session.commit()
        result = service.retire_published_mixed_selector(
            source.engagement_id, source.core_job_id, **options)
        assert result.status == "succeeded"
        assert deleter.deletes == (1 if present else 0)
        assert service.retire_published_mixed_selector(
            source.engagement_id, source.core_job_id, **options) == result
        assert service.retire_published_mixed_selector(
            source.engagement_id, source.core_job_id,
            **{**options, "historical_negative": True,
               "negative_recognizer": lambda *_a, **_k: pytest.fail("negative reprobe")}) == result
        assert deleter.deletes == (1 if present else 0)
        assert calls == ["show", "apply"]
        assert len(scans) == 2
        assert all("databases" not in path for path in catalog.calls)


def test_published_selector_rejects_parent_drift_during_provider_get(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, receipt, jobs, _, _, proof_options = _proof(
            client, ready, tmp_path, monkeypatch)
        negative_result = negative.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **proof_options)
        initial = jobs.get(source.parent_job_id)
        selector = initial.events[5].data["reviewedPolicy"]["digitalocean"]["selector_tag"]
        parent = jobs.get(service.parent_id(source.core_job_id))
        visible = {"tag": True}
        deleter = Delete(visible)

        class DriftingCatalog(Catalog):
            def request(self, base, method, path, token):
                result = super().request(base, method, path, token)
                if path == f"/tags/{selector}":
                    jobs.save(replace(parent, input={**parent.input, "drift": True}))
                return result

        monkeypatch.setattr(service, "_default_state_root", lambda: proof_options["state_root"])
        with pytest.raises(service.PublishedMixedSelectorRetirementAttention):
            service.retire_published_mixed_selector(
                source.engagement_id, source.core_job_id,
                environment="devtest", state_root=proof_options["state_root"],
                core_state_root=proof_options["core_state_root"], job_repository=jobs,
                plan_repository=proof_options["plan_repository"],
                credential_repository=ready.case.args["credential_repository"],
                lease_lookup=proof_options["lease_lookup"],
                catalog_transport=DriftingCatalog(selector, visible),
                delete_transport=deleter, decrypt_secret=lambda encrypted: encrypted,
                post_source_reader=proof_options["post_source_reader"],
                oci_absence_recognizer=lambda *_a, **_k: receipt,
                negative_recognizer=lambda *_a, **_k: negative_result)
        assert deleter.deletes == 0
