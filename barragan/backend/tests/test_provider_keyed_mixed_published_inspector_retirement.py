# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published mixed Inspector tail reuses exact one-shot Linode deletion."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.storage.credential_repository import StoredCredential
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_inspector_negative import _proof
from test_provider_keyed_mixed_zero_apply_inspector_retirement import Provider
import app.services.provider_keyed_mixed_published_selector_retirement as selector_service
import app.services.provider_keyed_mixed_zero_apply_inspector_retirement as service
import app.services.provider_keyed_mixed_zero_apply_inspector_negative as negative


@pytest.mark.parametrize("lost_host,drift_selector", [
    (False, False), (True, False), (False, True),
])
def test_published_inspector_retires_only_owned_pair_and_preserves_settings(
        client, ready, tmp_path, monkeypatch, lost_host, drift_selector):
    with client.application.storage_context():
        source, _, jobs, calls, scans, proof_options = _proof(
            client, ready, tmp_path, monkeypatch)
        negative_result = negative.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **proof_options)
        parent = jobs.get(service._authority(
            source.engagement_id, source.core_job_id, jobs,
            proof_options["plan_repository"], proof_options["lease_lookup"],
            published=True,
            post_source_reader=proof_options["post_source_reader"])[0].id)
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings_repo.save(proof_options["settings_repository"].get(source.engagement_id))
        resources = SqlAlchemyProviderResourceRepository()
        rows = proof_options["provider_resource_repository"].list_for_engagement(source.engagement_id)
        for row in rows:
            resources.save(row)
        owner_id = rows[0].adoption_job_id
        owner = StoredJobRun(
            owner_id, "inspector_readiness", "succeeded",
            f"engagement:{source.engagement_id}", "engagement", source.engagement_id,
            "operator", {"credentialAlias": "linode-default"}, [],
            "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00",
            "2026-10-15T00:00:00+00:00", [JobEvent(1, "info", "ready", {})])
        jobs.save(owner)
        selector = StoredJobRun(
            selector_service._child_id(source.core_job_id), selector_service.ACTION,
            "succeeded", f"engagement:{source.engagement_id}", "engagement",
            source.engagement_id, parent.requested_by,
            {"teardownParentId": parent.id,
             "inspectorNegativeJobId": negative_result.id,
             "inspectorNegativeJournalSha256": job_event_digest(negative_result.events)},
            [], "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00",
            "2026-10-15T00:00:00+00:00", [JobEvent(1, "info", "terminal", {})])
        jobs.save(selector)
        selector = jobs.get(selector.id)
        credential = StoredCredential(
            "credential-linode", "linode", "linode-default", "active", "",
            "encrypted-offline-token", True,
            "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00")
        credentials = SimpleNamespace(get_default=lambda _: credential)
        class PublishedProvider(Provider):
            def request(self, method, path, token):
                result = super().request(method, path, token)
                if path == "/linode/instances/100":
                    result["label"] = next(row.name for row in rows
                                           if row.resource_type == "inspector_instance")
                    if drift_selector:
                        jobs.save(replace(selector, input={**selector.input,
                                                           "drift": True}))
                if path == "/networking/firewalls/200":
                    result["label"] = next(row.name for row in rows
                                           if row.resource_type == "inspector_firewall")
                return result

        provider = PublishedProvider()
        provider.lost_host = lost_host
        applied = jobs.get(
            f"job-provider-keyed-mixed-core-destroy-apply-{source.core_job_id.removeprefix('job-')}")
        monkeypatch.setattr(service, "retire_published_mixed_selector", lambda *_a, **_k: selector)
        post_reader = lambda *args, **kwargs: proof_options["post_source_reader"]()
        options = dict(
            environment="devtest", state_root=proof_options["state_root"],
            core_state_root=proof_options["core_state_root"], job_repository=jobs,
            plan_repository=proof_options["plan_repository"],
            settings_repository=settings_repo, provider_resource_repository=resources,
            credential_repository=credentials, lease_lookup=proof_options["lease_lookup"],
            read_transport=provider, delete_transport=provider, sleep=lambda _: None,
            decrypt_secret=lambda _: "offline-token",
            readiness_prover=lambda *_a, **_k: applied.events[5].data["inspectorReadySha256"],
            negative_recognizer=lambda *_a, **_k: negative_result,
            published=True, post_source_reader=post_reader)
        if drift_selector:
            with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
                service.retire_mixed_zero_apply_inspector(
                    source.engagement_id, source.core_job_id, **options)
            assert provider.host_deletes == provider.firewall_deletes == 0
            return
        if lost_host:
            with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
                service.retire_mixed_zero_apply_inspector(
                    source.engagement_id, source.core_job_id, **options)
            assert provider.host_deletes == 1 and provider.firewall_deletes == 0
        retired = service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **options)
        assert retired.action == service.PUBLISHED_ACTION and retired.status == "succeeded"
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)
        assert {row.status for row in resources.list_for_engagement(source.engagement_id)} == {"destroyed"}
        assert all(row.metadata.get("cleanupRequired") is False
                   for row in resources.list_for_engagement(source.engagement_id))
        assert settings_repo.get(source.engagement_id).current_host == {}
        assert settings_repo.get(source.engagement_id).enabled is True
        options["delete_transport"] = SimpleNamespace(delete=lambda *_: pytest.fail("DELETE replayed"))
        assert service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **options) == retired
        assert calls == ["show", "apply"] and len(scans) == 2
