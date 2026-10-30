# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private source selector keeps pending and published teardown histories disjoint."""

from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from app.services import engagement_teardown as teardown
from app.services import provider_keyed_teardown_source as selector
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_published_teardown_source import (
    PublishedProviderKeyedSourceError, audit_published_provider_keyed_source,
)
from test_provider_keyed_published_teardown_source import _case as published_case
from test_provider_keyed_published_teardown_reservation import _case as reservation_case
from test_provider_keyed_teardown_handoff import _fixture as pending_case


def test_published_auditor_requires_exact_owned_fence_and_passes_parent_to_scope(tmp_path):
    _jobs, _initial, _manifest, _rows, state, options = published_case(tmp_path)
    state["lease"] = ("plan-core", "provider_keyed_teardown_fence")
    seen = []
    scope = state["scope"]
    options["scope_builder"] = lambda *_args, **kwargs: (seen.append(kwargs), scope)[1]
    with pytest.raises(PublishedProviderKeyedSourceError):
        audit_published_provider_keyed_source("job-core", **options)
    proof = audit_published_provider_keyed_source(
        "job-core", **options,
        expected_teardown_parent_id=teardown._parent_id("job-core"),
    )
    assert proof.core_job_id == "job-core"
    assert all(item["allowed_teardown_parent_id"] == teardown._parent_id("job-core")
               for item in seen)
    state["lease"] = None
    with pytest.raises(PublishedProviderKeyedSourceError):
        audit_published_provider_keyed_source(
            "job-core", **options,
            expected_teardown_parent_id=teardown._parent_id("job-core"),
        )
    state["lease"] = ("plan-core", "provider_keyed_initial")
    with pytest.raises(PublishedProviderKeyedSourceError):
        audit_published_provider_keyed_source(
            "job-core", **options,
            expected_teardown_parent_id=teardown._parent_id("job-core"),
        )


def test_pending_selector_reproves_terminal_then_handoff(tmp_path, monkeypatch):
    jobs, _initial, queued, scope, plans, options = pending_case(tmp_path)
    monkeypatch.setattr(selector, "build_digitalocean_keyed_teardown_scope",
                        options["scope_builder"])
    monkeypatch.setattr(selector, "_db_lease_lookup", options["lease_lookup"])
    kwargs = dict(environment="devtest", job_repository=jobs, plan_repository=plans,
                  )
    with pytest.raises(selector.ProviderKeyedTeardownSourceError):
        selector.load_keyed_teardown_source(queued.id, **kwargs)
    terminal = selector.load_keyed_teardown_source(queued.id, phase="pre_handoff", **kwargs)
    assert terminal.variant == "pending_terminal"
    from app.services.provider_keyed_teardown_handoff import handoff_terminal_provider_keyed_teardown
    handoff_terminal_provider_keyed_teardown(queued.id, **options)
    fenced = selector.load_keyed_teardown_source(queued.id, **kwargs)
    assert fenced.variant == "pending_handoff"
    assert fenced.initial_journal_sha256 != terminal.initial_journal_sha256
    with pytest.raises(selector.ProviderKeyedTeardownSourceError):
        selector.load_keyed_teardown_source(queued.id, phase="pre_handoff", **kwargs)
    plans.lease = (scope["corePlanId"], "provider_keyed_initial")
    with pytest.raises(selector.ProviderKeyedTeardownSourceError):
        selector.load_keyed_teardown_source(queued.id, **kwargs)


def test_published_selector_uses_only_sealed_persisted_variant(tmp_path, monkeypatch):
    jobs, initial, _manifest, _rows, state, options = published_case(tmp_path)
    core = jobs.get("job-core")
    proof = audit_published_provider_keyed_source("job-core", **options)
    state["lease"] = (proof.core_plan_id, "provider_keyed_teardown_fence")
    snapshot = {"engagementId": proof.engagement_id, "coreJobId": core.id,
                "providerScopes": [state["scope"]],
                "providerScopeSha256": teardown._fingerprint({"providerScopes": [state["scope"]]})}
    snapshot["snapshotId"] = teardown._fingerprint(snapshot)
    parent = SimpleNamespace(
        id=teardown._parent_id(core.id), target_id=proof.engagement_id,
        input={"publishedSource": json.loads(json.dumps(asdict(proof)))},
    )
    real_get = jobs.get
    jobs.get = lambda identifier: parent if identifier == parent.id else real_get(identifier)
    from app.services import provider_keyed_comprehensive_teardown as coordinator
    monkeypatch.setattr(coordinator, "_boundary", lambda *_args: (
        parent, core, snapshot, "provider_keyed_teardown_fence"))
    monkeypatch.setattr(selector, "build_digitalocean_keyed_teardown_scope",
                        options["scope_builder"])
    monkeypatch.setattr(selector, "_db_lease_lookup", options["lease_lookup"])
    kwargs = dict(environment="devtest", job_repository=jobs,
                  plan_repository=options["plan_repository"],
                  sketch_repository=options["sketch_repository"])
    result = selector.load_keyed_teardown_source(parent.id, **kwargs)
    assert result.variant == "published"
    assert result.published_source_sha256
    parent.input["publishedSource"]["state_sha256"] = "f" * 64
    with pytest.raises(selector.ProviderKeyedTeardownSourceError):
        selector.load_keyed_teardown_source(parent.id, **kwargs)
    parent.input["publishedSource"] = None
    with pytest.raises(selector.ProviderKeyedTeardownSourceError):
        selector.load_keyed_teardown_source(parent.id, **kwargs)


def test_post_destroy_rejects_an_unproved_history():
    with pytest.raises(selector.ProviderKeyedPostDestroySourceUnavailable):
        selector.load_keyed_teardown_source("queued-parent", phase="post_destroy")


def test_post_destroy_reconstructs_sealed_published_history_without_live_scope(tmp_path, monkeypatch):
    from app.services import provider_keyed_destroy_absence_preflight as preflight
    from app.services import sketch_state_workspaces

    jobs, initial, _manifest, rows, state, options = published_case(tmp_path)
    core = jobs.get("job-core")
    proof = audit_published_provider_keyed_source(core.id, **options)
    scope = state["scope"]
    snapshot = {
        "snapshotId": "snapshot", "providerScopeSha256": "scope",
        "dnsCleanupManifest": {
            "initialJobId": initial.id,
            "initialJournalSha256": proof.initial_journal_sha256,
        },
    }
    parent = SimpleNamespace(
        id=teardown._parent_id(core.id), target_id=proof.engagement_id,
        input={"publishedSource": json.loads(json.dumps(asdict(proof))),
               "scopeSnapshot": snapshot},
    )
    original_get = jobs.get
    jobs.get = lambda identifier: parent if identifier == parent.id else original_get(identifier)
    calls = []

    def successful_boundary(parent_id, **kwargs):
        assert parent_id == parent.id
        assert kwargs["state_root"] == tmp_path / "state"
        calls.append("saved-success-boundary")
        kwargs["handoff_auditor"](
            core.id, confirmed_scope=scope, workspace_root=selector.Path(scope["workspace"]),
            job_repository=jobs,
        )
        return SimpleNamespace(parent=parent, core=core, scope=scope)

    # The one-shot saved apply, empty state, phase, and credential checks are
    # exercised independently by the real success-boundary suite. This seam
    # checks the additional published-only historical reconstruction.
    monkeypatch.setattr(preflight, "_read_success_boundary", successful_boundary)
    monkeypatch.setattr(sketch_state_workspaces, "_default_state_root",
                        lambda: tmp_path / "state")
    monkeypatch.setattr(selector, "build_digitalocean_keyed_teardown_scope",
                        lambda *_a, **_kw: pytest.fail("live applied scope must not run"))
    kwargs = dict(
        phase="post_destroy", environment="devtest", state_root=tmp_path / "state",
        job_repository=jobs, plan_repository=options["plan_repository"],
        sketch_repository=options["sketch_repository"],
        lease_lookup=options["lease_lookup"],
    )
    result = selector.load_keyed_teardown_source(parent.id, **kwargs)
    assert result.variant == "published"
    assert result.initial_journal_sha256 == proof.initial_journal_sha256
    assert calls == ["saved-success-boundary", "saved-success-boundary"]

    parent.input["publishedSource"]["state_sha256"] = "f" * 64
    with pytest.raises(selector.ProviderKeyedPostDestroySourceUnavailable):
        selector.load_keyed_teardown_source(parent.id, **kwargs)
    parent.input["publishedSource"] = json.loads(json.dumps(asdict(proof)))
    snapshot["dnsCleanupManifest"]["initialJournalSha256"] = "f" * 64
    with pytest.raises(selector.ProviderKeyedPostDestroySourceUnavailable):
        selector.load_keyed_teardown_source(parent.id, **kwargs)
    snapshot["dnsCleanupManifest"]["initialJournalSha256"] = proof.initial_journal_sha256
    rows[0] = replace(rows[0], status="stopped")
    with pytest.raises(selector.ProviderKeyedPostDestroySourceUnavailable):
        selector.load_keyed_teardown_source(parent.id, **kwargs)


def test_persisted_reserved_parent_and_fence_compose_with_selector(client, monkeypatch, tmp_path):
    from app.storage.database import db
    from app.storage.models import CoreMutationLeaseModel

    with client.application.storage_context():
        jobs, proposal, source, _audits = reservation_case(client, monkeypatch, tmp_path)
        saved = jobs.reserve_published_keyed_teardown_parent(
            proposal, reviewed_source=source)
        calls = []
        def audited(core_id, **kwargs):
            calls.append((core_id, kwargs["expected_teardown_parent_id"]))
            assert kwargs["lease_lookup"](saved.target_id) == (
                source.core_plan_id, "provider_keyed_teardown_fence")
            return source
        monkeypatch.setattr(selector, "audit_published_provider_keyed_source", audited)
        proof = selector.load_keyed_teardown_source(saved.id)
        assert proof.variant == "published"
        assert calls == [(source.core_job_id, saved.id)]

        lease = db.session.get(CoreMutationLeaseModel, saved.target_id)
        db.session.delete(lease)
        db.session.commit()
        with pytest.raises(selector.ProviderKeyedTeardownSourceError):
            selector.load_keyed_teardown_source(saved.id)


def test_persisted_published_parent_journal_tamper_fails_before_audit(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        jobs, proposal, source, _audits = reservation_case(client, monkeypatch, tmp_path)
        saved = jobs.reserve_published_keyed_teardown_parent(
            proposal, reviewed_source=source)
        jobs.save(replace(saved, events=[replace(saved.events[0], data={"snapshotId": "wrong"})]))
        monkeypatch.setattr(selector, "audit_published_provider_keyed_source",
                            lambda *_args, **_kwargs: pytest.fail("auditor must not run"))
        with pytest.raises(selector.ProviderKeyedTeardownSourceError):
            selector.load_keyed_teardown_source(saved.id)
