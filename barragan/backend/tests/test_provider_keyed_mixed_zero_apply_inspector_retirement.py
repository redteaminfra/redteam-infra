# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline, persisted one-shot mixed Inspector host/firewall retirement."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import urllib.error

import pytest
from sqlalchemy import text, update

from app.integrations.linode_validation import LinodeValidationError
from app.services import provider_keyed_mixed_zero_apply_inspector_retirement as service
from app.services import provider_keyed_mixed_zero_apply_core_apply as go_service
from app.services import provider_keyed_mixed_zero_apply_core_absence as absence_service
from app.services import provider_keyed_mixed_zero_apply_inspector_negative as negative_service
from app.services.provider_keyed_inspector_linode_cleanup import LinodeDeleteResponse
from app.services.provider_keyed_inspector_provider_proof import InspectorProviderProof
from app.services.observer_checks import (
    INSPECTOR_ADMIN_IDENTITY_VERSION, INSPECTOR_ADMIN_USER,
    INSPECTOR_DEFAULT_SUPPORT_PACKAGES, INSPECTOR_SUPPORT_PREPARATION_VERSION,
    ObserverHost, ObserverSshKey, _record_inspector_resource,
)
from app.storage.credential_repository import StoredCredential
from app.storage.database import db
from app.domain import JobEvent
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.models import (
    CoreMutationLeaseModel, EngagementModel, EngagementObserverSettingsModel,
    JobRunModel, ProviderResourceRecordModel,
)
from app.storage.observer_settings_repository import (
    SqlAlchemyObserverSettingsRepository, StoredInspectorSettings,
)
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_mixed_zero_apply_core_apply import _go_case
from test_provider_keyed_mixed_zero_apply_core_absence import _empty_state, _absent
from test_provider_keyed_mixed_zero_apply_inspector_negative import case, _proof, CONTROL


def _recovered_show_applied(applied):
    """Retain the abandoned SHOW prefix ahead of the successful logical journal."""
    original = [replace(event) for event in applied.events[:4]]
    invocation = original[2].data["invocationId"]
    original[2] = replace(original[2], data={
        **original[2].data, "invocationId": f"abandoned-{invocation}"})
    original[3] = replace(original[3], data={
        **original[3].data, "invocationId": f"abandoned-{invocation}"})
    marker = JobEvent(5, "info", "mixed core SHOW recovery claimed", {
        "originalJournalSha256": job_event_digest(original),
        "originalInvocationId": original[2].data["invocationId"],
    })
    suffix = [replace(event, sequence=index) for index, event in enumerate(
        applied.events[2:], start=6)]
    return replace(applied, events=[*original, marker, *suffix])


class Provider:
    def __init__(self):
        self.host = True
        self.firewall = True
        self.host_deletes = 0
        self.firewall_deletes = 0
        self.foreign_device = False
        self.lost_host = False
        self.lost_firewall = False
        self.host_stale_gets = 0

    def request(self, method, path, token):
        assert method == "GET" and token == "offline-token"
        if "?" in path:
            endpoint = path.split("?", 1)[0]
            if endpoint == "/linode/instances":
                rows = [{"id": 100}] if self.host else []
            elif endpoint == "/networking/firewalls":
                rows = [{"id": 200}] if self.firewall else []
            elif endpoint == "/networking/firewalls/200/devices":
                rows = ([{"id": 300, "entity": {"type": "linode", "id": 100}}]
                        if self.host else [])
                if self.foreign_device:
                    rows.append({"id": 301, "entity": {"type": "linode", "id": 999}})
            else:
                raise AssertionError(path)
            return {"data": rows, "page": 1, "pages": 1, "results": len(rows)}
        if path == "/linode/instances/100" and (self.host or self.host_stale_gets > 0):
            if not self.host:
                self.host_stale_gets -= 1
            return {"id": 100, "label": "inspector", "tags": ["barragan", "inspector"]}
        if path == "/networking/firewalls/200" and self.firewall:
            return {"id": 200, "label": "inspector"}
        try:
            raise urllib.error.HTTPError("https://api.linode.com/v4" + path,
                                         404, "not found", {}, None)
        except urllib.error.HTTPError as exc:
            raise LinodeValidationError("not found") from exc

    def delete(self, path, token):
        assert token == "offline-token"
        if path == "/linode/instances/100":
            self.host_deletes += 1
            assert self.host_deletes == 1
            self.host = False
            if self.lost_host:
                raise TimeoutError("lost host response")
        elif path == "/networking/firewalls/200":
            self.firewall_deletes += 1
            assert self.firewall_deletes == 1
            self.firewall = False
            if self.lost_firewall:
                raise TimeoutError("lost firewall response")
        else:
            raise AssertionError(path)
        return LinodeDeleteResponse(200, b"{}")


def _sql_ready(case, monkeypatch, tmp_path):
    source, _, options, _ = _proof(case, monkeypatch)
    uri = f"sqlite:///{tmp_path / 'mixed-retirement.sqlite'}"
    state = db.configure(uri)
    return source, options, state


def _enter_sql(case, source, options, state, provider):
    db.create_all()
    db.session.add(EngagementModel(id=source.engagement_id, name="opaque-fixture",
                                   status="active", owner="operator", template_id="small"))
    db.session.add(CoreMutationLeaseModel(
        engagement_id=source.engagement_id, owner_id=source.core_plan_id,
        operation="provider_keyed_teardown_fence"))
    db.session.commit()
    jobs = SqlAlchemyJobRepository()
    instance_owner = next(row.adoption_job_id for row in case.rows
                          if row.resource_type == "inspector_instance")
    for row in case.jobs.list_for_engagement(source.engagement_id):
        inputs = ({**row.input, "credentialAlias": "linode-default"}
                  if row.id == instance_owner else row.input)
        jobs.save(replace(
            row, input=inputs,
            created_at=("2026-10-15T00:00:00+00:00" if row.created_at == "now"
                        else row.created_at),
            started_at=("2026-10-15T00:00:00+00:00" if row.started_at == "now"
                        else row.started_at),
            finished_at=("2026-10-15T00:00:00+00:00" if row.finished_at == "now"
                         else row.finished_at)))
    settings = SqlAlchemyObserverSettingsRepository()
    settings.save(options["settings_repository"].get(source.engagement_id))
    resources = SqlAlchemyProviderResourceRepository()
    for row in case.rows:
        resources.save(replace(row,
            adopted_at="2026-10-15T00:00:00+00:00",
            updated_at="2026-10-15T00:00:00+00:00"))
    credential = StoredCredential(
        "credential-linode", "linode", "linode-default", "active", "",
        "encrypted-offline-token", True,
        "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00")
    credentials = SimpleNamespace(get_default=lambda _: credential)
    negative_options = {**options, "job_repository": jobs,
                        "settings_repository": settings,
                        "provider_resource_repository": resources}
    negative_service.prove_mixed_zero_apply_inspector_negative(
        source.engagement_id, source.core_job_id, **negative_options)
    applied = jobs.get(
        f"job-provider-keyed-mixed-core-destroy-apply-{source.core_job_id.removeprefix('job-')}")
    kwargs = dict(environment="devtest", state_root=case.state_root,
                  core_state_root=case.core_state.parents[2],
                  job_repository=jobs, plan_repository=options["plan_repository"],
                  settings_repository=settings, provider_resource_repository=resources,
                  credential_repository=credentials,
                  lease_lookup=lambda _: (source.core_plan_id, "provider_keyed_teardown_fence"),
                  read_transport=provider, delete_transport=provider,
                  sleep=lambda _: None, decrypt_secret=lambda _: "offline-token",
                  readiness_prover=lambda *_args, **_kwargs: applied.events[5].data[
                      "inspectorReadySha256"], identity_reader=lambda: {})
    kwargs["negative_recognizer"] = lambda *args, **passed: (
        negative_service.prove_mixed_zero_apply_inspector_negative(
            *args, **{**passed, "ssh_key_factory": options["ssh_key_factory"],
                      "runner": SimpleNamespace(run=lambda **_: pytest.fail("reprobed"))}))
    return kwargs, jobs, settings, resources


def test_both_orders_retire_only_owned_pair_and_keep_desired_settings(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, settings, resources = _enter_sql(case, source, options, state, provider)
        result = service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs)
        assert result.status == "succeeded"
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)
        assert {row.status for row in resources.list_for_engagement(source.engagement_id)} == {"destroyed"}
        assert all(row.metadata.get("cleanupRequired") is False
                   for row in resources.list_for_engagement(source.engagement_id))
        saved = settings.get(source.engagement_id)
        assert saved.enabled is True and saved.mode == "continuous"
        assert saved.current_host == {}
        kwargs["delete_transport"] = SimpleNamespace(delete=lambda *_: pytest.fail("DELETE replayed"))
        assert service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs) == result


@pytest.mark.parametrize("recovered_show", [False, True])
def test_retirement_preflight_reads_logical_show_but_seals_raw_apply_journal(
        case, monkeypatch, tmp_path, recovered_show):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, _, _ = _enter_sql(case, source, options, state, provider)
        historical = service._authority(
            source.engagement_id, source.core_job_id, jobs,
            options["plan_repository"], kwargs["lease_lookup"])
        applied = historical[4]
        if recovered_show:
            applied = _recovered_show_applied(applied)
            historical = (*historical[:4], applied, *historical[5:])
            negative = jobs.get(service.negative_child_id(source.core_job_id))
            kwargs["negative_recognizer"] = lambda *_args, **_kwargs: negative
            forged_events = list(applied.events)
            forged_events[4] = replace(forged_events[4], data={
                **forged_events[4].data, "originalJournalSha256": "0" * 64})
            forged = (*historical[:4], replace(applied, events=forged_events),
                      *historical[5:])
            monkeypatch.setattr(service, "_authority", lambda *_args, **_kwargs: forged)
            with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
                service.retire_mixed_zero_apply_inspector(
                    source.engagement_id, source.core_job_id, **kwargs)
            assert jobs.get(service._child_id(source.core_job_id)) is None
            assert (provider.host_deletes, provider.firewall_deletes) == (0, 0)
            monkeypatch.setattr(service, "_authority", lambda *_args, **_kwargs: historical)
        kwargs["readiness_prover"] = lambda *_args, **_kwargs: (
            service.canonical_mixed_core_apply_events(applied)[5].data[
                "inspectorReadySha256"])
        result = service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs)
        assert result.status == "succeeded"
        assert result.input["ociApplyJournalSha256"] == job_event_digest(applied.events)
        assert result.input["inspectorReadySha256"] == (
            service.canonical_mixed_core_apply_events(applied)[5].data[
                "inspectorReadySha256"])
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)


@pytest.mark.parametrize("lost", ["host", "firewall"])
def test_lost_delete_response_reconciles_by_get_without_replay(
        case, monkeypatch, tmp_path, lost):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    setattr(provider, f"lost_{lost}", True)
    with db.bind(state):
        kwargs, jobs, settings, resources = _enter_sql(case, source, options, state, provider)
        with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
            service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id, **kwargs)
        child = jobs.get(service._child_id(source.core_job_id))
        assert child.status == "running"
        assert f"inspector {lost} DELETE intended" in [row.message for row in child.events]
        result = service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs)
        assert result.status == "succeeded"
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)


def test_foreign_firewall_attachment_vetoes_first_delete(case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    provider.foreign_device = True
    with db.bind(state):
        kwargs, jobs, _, _ = _enter_sql(case, source, options, state, provider)
        with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
            service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id, **kwargs)
        assert (provider.host_deletes, provider.firewall_deletes) == (0, 0)
        assert [event.message for event in jobs.get(service._child_id(source.core_job_id)).events] == [
            "mixed Inspector retirement queued", "mixed Inspector retirement started"]


def test_lease_loss_at_host_intent_cas_sends_no_delete(case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, _, _ = _enter_sql(case, source, options, state, provider)
        original_append = service._append
        injected = False

        def losing_lease(*args, **passed):
            nonlocal injected
            if not injected:
                injected = True
                db.session.query(CoreMutationLeaseModel).delete()
                db.session.commit()
            return original_append(*args, **passed)

        monkeypatch.setattr(service, "_append", losing_lease)
        with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
            service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id, **kwargs)
        assert injected and (provider.host_deletes, provider.firewall_deletes) == (0, 0)
        assert [event.message for event in jobs.get(service._child_id(source.core_job_id)).events] == [
            "mixed Inspector retirement queued", "mixed Inspector retirement started"]


def test_delayed_host_absence_waits_without_repeat_delete(case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    provider.host_stale_gets = 2
    pauses = []
    with db.bind(state):
        kwargs, _, _, _ = _enter_sql(case, source, options, state, provider)
        kwargs["sleep"] = pauses.append
        result = service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs)
        assert result.status == "succeeded" and len(pauses) >= 1
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)


def test_source_drift_after_lost_response_stops_reconciliation(case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    provider.lost_host = True
    with db.bind(state):
        kwargs, jobs, _, _ = _enter_sql(case, source, options, state, provider)
        with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
            service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id, **kwargs)
        parent = jobs.get(
            f"job-provider-keyed-mixed-zero-apply-cleanup-{source.core_job_id.removeprefix('job-')}")
        jobs.save(replace(parent, requested_by="other-operator"))
        with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
            service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id, **kwargs)
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 0)


def test_terminal_settings_failure_rolls_back_both_records_and_child(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, settings, resources = _enter_sql(case, source, options, state, provider)
        db.session.execute(text("""
            CREATE TRIGGER block_inspector_clear BEFORE UPDATE OF current_host
            ON engagement_observer_settings BEGIN
              SELECT RAISE(ABORT, 'offline settings failure');
            END
        """))
        db.session.commit()
        with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
            service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id, **kwargs)
        assert {row.status for row in resources.list_for_engagement(source.engagement_id)} == {"active"}
        assert settings.get(source.engagement_id).current_host != {}
        assert jobs.get(service._child_id(source.core_job_id)).status == "running"
        db.session.execute(text("DROP TRIGGER block_inspector_clear"))
        db.session.commit()
        result = service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs)
        assert result.status == "succeeded"
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)


@pytest.mark.parametrize("drift", ["parent", "settings", "resource"])
def test_terminal_writer_rereads_authority_after_late_sql_drift(
        case, monkeypatch, tmp_path, drift):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, settings, resources = _enter_sql(case, source, options, state, provider)
        original_finish = service._finish_atomic
        parent_id = ("job-provider-keyed-mixed-zero-apply-cleanup-"
                     + source.core_job_id.removeprefix("job-"))
        host_id = next(row.id for row in case.rows
                       if row.resource_type == "inspector_instance")

        def drift_before_finish(*args, **passed):
            # Simulate a separate writer landing after the last ordinary
            # fence, while this worker still holds ORM identity-map reads.
            if drift == "parent":
                db.session.execute(update(JobRunModel).where(
                    JobRunModel.id == parent_id).values(requested_by="other-operator"))
            elif drift == "settings":
                db.session.execute(update(EngagementObserverSettingsModel).where(
                    EngagementObserverSettingsModel.engagement_id == source.engagement_id
                ).values(region="changed-region"))
            else:
                db.session.execute(update(ProviderResourceRecordModel).where(
                    ProviderResourceRecordModel.id == host_id).values(name="changed-name"))
            db.session.commit()
            return original_finish(*args, **passed)

        monkeypatch.setattr(service, "_finish_atomic", drift_before_finish)
        with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
            service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id, **kwargs)
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)
        assert jobs.get(service._child_id(source.core_job_id)).status == "running"
        assert {row.status for row in resources.list_for_engagement(
            source.engagement_id)} == {"active"}
        assert settings.get(source.engagement_id).current_host != {}


def test_normal_persisted_inspector_go_digest_bridges_retirement_and_rotation(
        monkeypatch, tmp_path):
    """The real GO reader produces a stable retirement pre-DELETE seal."""
    state = db.configure(f"sqlite:///{tmp_path / 'real-readiness.sqlite'}")
    with db.bind(state):
        db.create_all()
        engagement_id = "eng-opaque"
        db.session.add(EngagementModel(id=engagement_id, name="opaque-fixture",
                                       status="active", owner="operator", template_id="small"))
        db.session.commit()
        host = ObserverHost(
            "linode", "instance", "100", "inspector-opaque", "us-east", "8.8.8.8",
            INSPECTOR_ADMIN_USER, "running", {
                "adminIdentityVersion": INSPECTOR_ADMIN_IDENTITY_VERSION,
                "rootLoginDisabled": True,
                "supportPreparationVersion": INSPECTOR_SUPPORT_PREPARATION_VERSION,
                "supportPreparedPackages": list(INSPECTOR_DEFAULT_SUPPORT_PACKAGES),
                "providerFirewall": {"provider": "linode", "resourceType": "firewall",
                                     "resourceId": "200", "name": "inspector-firewall-opaque",
                                     "managementSourceCidr": "8.8.8.8/32"},
            })
        SqlAlchemyObserverSettingsRepository().save(StoredInspectorSettings(
            engagement_id, True, "linode", "us-east", "g6-nanode-1", "continuous",
            ["mon"], "00:00", ["inbound"], [], [], host.to_dict(), "", "", "",
            "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00"))
        resources = SqlAlchemyProviderResourceRepository()
        _record_inspector_resource(resources, engagement_id, "opaque-fixture", host,
                                   "job-inspector-ready", status="active")
        owned = tuple(sorted(row.id for row in resources.list_for_engagement(engagement_id)))
        source = SimpleNamespace(owned_inspector_record_ids=owned)
        key = tmp_path / "inspector-key"
        key.write_text("private-fixture", encoding="utf-8")
        Path(str(key) + ".pub").write_text("ssh-ed25519 opaque-fixture", encoding="utf-8")
        selected = [StoredCredential(
            "credential-1", "linode", "linode-default", "active", "", "encrypted-token-1",
            True, "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00")]
        monkeypatch.setattr(go_service, "_safe_key_identity", lambda _: (str(key), "a" * 64))
        monkeypatch.setattr(go_service, "_verify_key_pair", lambda *_: None)
        monkeypatch.setattr(go_service, "SqlAlchemyCredentialRepository",
                            lambda: SimpleNamespace(get_default=lambda _: selected[0]))
        monkeypatch.setattr(go_service, "decrypt_secret_value", lambda _: "offline-token")
        monkeypatch.setattr(go_service, "prove_retained_keyed_inspector_provider",
                            lambda **_: InspectorProviderProof(host, "200", "8.8.8.8/32"))
        probes = []
        monkeypatch.setattr(go_service, "SshObserverRunner", lambda **_: SimpleNamespace(
            verify_access=lambda **kw: probes.append(kw)))
        go_digest = go_service._prove_retained_inspector(
            source, engagement_id, fence=lambda: None)
        retirement_digest = service._prove_retained_inspector(
            source, engagement_id, fence=lambda: None)
        assert retirement_digest == go_digest and len(probes) == 2
        selected[0] = replace(selected[0], encrypted_secret="encrypted-token-2",
                              updated_at="2026-10-15T00:01:00+00:00")
        assert service._prove_retained_inspector(
            source, engagement_id, fence=lambda: None) != go_digest


def test_persisted_normal_go_to_absence_to_negative_to_retirement(
        case, monkeypatch, tmp_path):
    """Exercise the saved cross-service handoff with the normal Inspector shape."""
    source, actions, _, go_options = _go_case(case, monkeypatch)
    state = db.configure(f"sqlite:///{tmp_path / 'normal-handoff.sqlite'}")
    provider = Provider()
    selected = [StoredCredential(
        "credential-1", "linode", "linode-default", "active", "",
        "encrypted-offline-token", True,
        "2026-10-15T00:00:00+00:00", "2026-10-15T00:00:00+00:00")]
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(
            id=source.engagement_id, name="opaque-fixture", status="active",
            owner="operator", template_id="small"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=source.engagement_id, owner_id=source.core_plan_id,
            operation="provider_keyed_teardown_fence"))
        db.session.commit()
        host = ObserverHost(
            "linode", "instance", "100", "inspector", "us-east", "4.4.4.4",
            INSPECTOR_ADMIN_USER, "running", {
                "adminIdentityVersion": INSPECTOR_ADMIN_IDENTITY_VERSION,
                "rootLoginDisabled": True,
                "supportPreparationVersion": INSPECTOR_SUPPORT_PREPARATION_VERSION,
                "supportPreparedPackages": list(INSPECTOR_DEFAULT_SUPPORT_PACKAGES),
                "providerFirewall": {"provider": "linode", "resourceType": "firewall",
                                     "resourceId": "200", "name": "inspector",
                                     "managementSourceCidr": "8.8.8.8/32"},
            })
        settings = SqlAlchemyObserverSettingsRepository()
        settings.save(StoredInspectorSettings(
            source.engagement_id, True, "linode", "us-east", "g6-nanode-1",
            "continuous", ["mon"], "00:00", ["inbound"], [], [],
            host.to_dict(), "", "", "", "2026-10-15T00:00:00+00:00",
            "2026-10-15T00:00:00+00:00"))
        resources = SqlAlchemyProviderResourceRepository()
        _record_inspector_resource(resources, source.engagement_id,
                                   "opaque-fixture", host,
                                   "job-inspector-inspector_instance", status="active")
        assert {row.id for row in resources.list_for_engagement(source.engagement_id)} == set(
            source.owned_inspector_record_ids)
        key = tmp_path / "inspector-key"
        key.write_text("private-fixture", encoding="utf-8")
        Path(str(key) + ".pub").write_text("ssh-ed25519 offline", encoding="utf-8")
        monkeypatch.setattr(go_service, "_safe_key_identity", lambda _: (str(key), "a" * 64))
        monkeypatch.setattr(go_service, "_verify_key_pair", lambda *_: None)
        monkeypatch.setattr(go_service, "SqlAlchemyCredentialRepository",
                            lambda: SimpleNamespace(get_default=lambda _: selected[0]))
        monkeypatch.setattr(go_service, "decrypt_secret_value", lambda _: "offline-token")
        monkeypatch.setattr(go_service, "prove_retained_keyed_inspector_provider",
                            lambda **_: InspectorProviderProof(host, "200", "8.8.8.8/32"))
        probes = []
        monkeypatch.setattr(go_service, "SshObserverRunner", lambda **_: SimpleNamespace(
            verify_access=lambda **kw: probes.append(kw)))
        go_options["inspector_prover"] = go_service._prove_retained_inspector
        applied = go_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **go_options)
        assert applied.status == "succeeded" and actions == ["show", "apply"]
        assert len(probes) >= 2
        _empty_state(case)
        monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
        monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                            case.core_state.parents[2])
        monkeypatch.setattr(absence_service, "_principal_digest", lambda _: "a" * 64)
        absence_options = dict(
            environment="devtest", state_root=case.state_root,
            core_state_root=case.core_state.parents[2], job_repository=case.jobs,
            plan_repository=case.args["plan_repository"],
            lease_lookup=go_options["lease_lookup"], identity_reader=lambda: {})
        absent = absence_service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, **absence_options,
            absence_prover=_absent, max_scans=2, poll_seconds=0)
        assert absent.status == "succeeded"
        core = case.jobs.get(source.core_job_id)
        details = [{"role": "homebase", "publicIp": "8.8.8.8"},
                   {"role": "proxy", "publicIp": "9.9.9.9"}]
        events = list(core.events)
        events[-1] = replace(events[-1], data={**events[-1].data,
                                               "connectionDetails": details})
        events.insert(-2, service.JobEvent(
            events[-2].sequence, "info", "operator inspection ready",
            {"connectionDetails": details}))
        events[-2] = replace(events[-2], sequence=events[-2].sequence + 1)
        events[-1] = replace(events[-1], sequence=events[-1].sequence + 1)
        case.jobs.save(replace(core, events=events))
        jobs = SqlAlchemyJobRepository()
        for row in case.jobs.list_for_engagement(source.engagement_id):
            input_data = ({**row.input, "credentialAlias": "linode-default"}
                          if row.id == "job-inspector-inspector_instance" else row.input)
            jobs.save(replace(row, input=input_data,
                created_at=("2026-10-15T00:00:00+00:00" if row.created_at == "now"
                            else row.created_at),
                started_at=("2026-10-15T00:00:00+00:00" if row.started_at == "now"
                            else row.started_at),
                finished_at=("2026-10-15T00:00:00+00:00" if row.finished_at == "now"
                             else row.finished_at)))
        negative_options = dict(
            environment="devtest", state_root=case.state_root,
            core_state_root=case.core_state.parents[2], positive_control=CONTROL,
            job_repository=jobs, plan_repository=case.args["plan_repository"],
            settings_repository=settings, provider_resource_repository=resources,
            lease_lookup=go_options["lease_lookup"],
            runner=SimpleNamespace(run=lambda *, spec, **_: {"ok": True, "results": [
                {"id": CONTROL["id"], "type": "tcp", "expected": "reachable",
                 "observed": "", "ok": True},
                *[{"id": target["id"], "type": "tcp-forbidden",
                   "expected": "closed", "observed": {"status": "closed",
                                                    "reason": "connection_refused"}, "ok": True}
                  for target in spec["negative"]]]}),
            ssh_key_factory=lambda _: ObserverSshKey(str(key), "ssh-ed25519 offline"),
            identity_reader=lambda: {})
        negative = negative_service.prove_mixed_zero_apply_inspector_negative(
            source.engagement_id, source.core_job_id, **negative_options)
        assert negative.status == "succeeded"
        credentials = SimpleNamespace(get_default=lambda _: selected[0])
        kwargs = dict(
            environment="devtest", state_root=case.state_root,
            core_state_root=case.core_state.parents[2], job_repository=jobs,
            plan_repository=case.args["plan_repository"],
            settings_repository=settings, provider_resource_repository=resources,
            credential_repository=credentials, lease_lookup=go_options["lease_lookup"],
            read_transport=provider, delete_transport=provider,
            sleep=lambda _: None, decrypt_secret=lambda _: "offline-token",
            identity_reader=lambda: {},
            negative_recognizer=lambda *args, **passed:
                negative_service.prove_mixed_zero_apply_inspector_negative(
                    *args, **{**passed, "ssh_key_factory": negative_options["ssh_key_factory"],
                             "runner": SimpleNamespace(run=lambda **_: pytest.fail("reprobed"))}),
        )
        assert service._prove_retained_inspector(
            source, source.engagement_id, fence=lambda: None
        ) == applied.events[5].data["inspectorReadySha256"]
        selected[0] = replace(selected[0], encrypted_secret="rotated-token",
                              updated_at="2026-10-15T00:01:00+00:00")
        with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
            service.retire_mixed_zero_apply_inspector(
                source.engagement_id, source.core_job_id, **kwargs)
        assert (provider.host_deletes, provider.firewall_deletes) == (0, 0)
        selected[0] = replace(selected[0], encrypted_secret="encrypted-offline-token",
                              updated_at="2026-10-15T00:00:00+00:00")
        result = service.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs)
        assert result.status == "succeeded"
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)


@pytest.mark.parametrize("historical", [False, True])
def test_new_metadata_clear_is_sealed_and_old_verified_receipt_stays_compatible(case, monkeypatch, tmp_path, historical):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, _, resources = _enter_sql(case, source, options, state, provider)
        result = service.retire_mixed_zero_apply_inspector(source.engagement_id, source.core_job_id, **kwargs)
        assert result.input["cleanupMetadataVersion"] == 1
        for row in resources.list_for_engagement(source.engagement_id):
            original = result.input["hostRecord" if row.resource_type == "inspector_instance" else "firewallRecord"]
            assert row.metadata == {**original["metadata"], "cleanupRequired": False}
            resources.save(replace(row, metadata=original["metadata"]))
        if historical:
            # Model a verified historical receipt and its original unchanged metadata.
            result = jobs.save(replace(result, input={key: value for key, value in result.input.items()
                                                     if key != "cleanupMetadataVersion"}))
        kwargs["delete_transport"] = SimpleNamespace(delete=lambda *_: pytest.fail("DELETE replayed"))
        if historical:
            assert service.retire_mixed_zero_apply_inspector(source.engagement_id, source.core_job_id, **kwargs) == result
        else:
            with pytest.raises(service.MixedZeroApplyInspectorRetirementAttention):
                service.retire_mixed_zero_apply_inspector(source.engagement_id, source.core_job_id, **kwargs)
