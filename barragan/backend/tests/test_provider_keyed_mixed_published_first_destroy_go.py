# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline one-shot first-provider GO from a sealed published mixed parent."""

from dataclasses import replace
import fcntl
import hashlib
import json
import os

import pytest

from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_published_destroy_child import (
    child_id, recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_first_destroy_go import (
    PublishedMixedFirstDestroyGoAttention, run_published_mixed_first_provider_destroy,
)
from app.services.provider_keyed_terraform_release import ProviderKeyedTerraformRelease
from app.storage.job_repository import SqlAlchemyJobRepository
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_reservation import (
    _attested_plans, _persisted,
)
import app.services.provider_keyed_mixed_published_first_destroy_go as worker


def _sealed(ready, tmp_path, monkeypatch):
    jobs, collection, proposal = _persisted(ready, tmp_path, monkeypatch)
    queued = jobs.reserve_published_mixed_initial_cleanup_parent(
        proposal, collection=collection,
        expected_snapshot_id=proposal.input["reviewSnapshotId"])
    plans, states, paths, binary, shows = _attested_plans(
        jobs, collection, tmp_path, with_shows=True)
    parent = jobs.seal_published_mixed_initial_destroy_plans(
        queued, collection=collection, plan_set=plans, before_states=states)
    provider = collection.review.source.ordered_providers[0]
    root = collection.workspaces[provider]
    (root / ".terraform-data").mkdir(exist_ok=True)
    (root / ".barragan-apply-phase.json").write_text(json.dumps({
        "schema": "provider-keyed-v2", "phase": "applied"}))
    monkeypatch.setattr(worker, "collect_published_mixed_initial_teardown",
                        lambda *args, **kwargs: collection)
    release = ProviderKeyedTerraformRelease(
        binary, hashlib.sha256(binary.read_bytes()).hexdigest(),
        "1.15.5", "linux_amd64")
    kwargs = dict(
        environment="devtest", job_repository=jobs,
        lease_lookup=lambda engagement: (
            collection.review.source.core_plan_id, "provider_keyed_teardown_fence"),
        credential_repository=ready.case.args["credential_repository"],
        show_runner=lambda command, cwd: shows[provider],
        release_validator=lambda **kwargs: release,
    )
    return jobs, collection, parent, plans, provider, root, kwargs


def _fake_runner(provider, root, calls):
    def run(command, *, scratch_path, intent_callback, started_callback,
            heartbeat_callback, result_callback, **kwargs):
        calls.append(tuple(command))
        assert scratch_path == root
        assert kwargs["env"]["TF_DATA_DIR"] == str(root / ".terraform-data")
        descriptor = os.open(root / f".barragan-{provider}-plan.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        intent = CommandIntent("once", str(root), hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest())
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 234, 234, 1))
        started_callback(started)
        state_path = root / "terraform.tfstate"
        before = json.loads(state_path.read_text())
        state_path.write_text(json.dumps({
            **before, "serial": before["serial"] + 1, "resources": []}))
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
        return CommandResult(started, 0, "", "", False, False)
    return run


def test_first_provider_go_is_locked_one_shot_and_awaits_absence(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, plans, provider, root, kwargs = _sealed(
            ready, tmp_path, monkeypatch)
        calls = []
        kwargs["gated_command_runner"] = _fake_runner(provider, root, calls)
        child = run_published_mixed_first_provider_destroy(parent.id, **kwargs)
        assert recognize_published_mixed_destroy_child(
            child, parent, collection.review, plans, provider,
            collection.core_inspector_scope, "Opaque") == "awaiting_absence"
        assert len(calls) == 1
        assert json.loads((root / ".barragan-apply-phase.json").read_text())[
            "phase"] == "destroy_applied"
        with pytest.raises(PublishedMixedFirstDestroyGoAttention):
            run_published_mixed_first_provider_destroy(parent.id, **kwargs)
        assert len(calls) == 1


@pytest.mark.parametrize("drift", ["state", "plan", "binary", "phase"])
def test_first_provider_go_vetoes_pre_go_drift_without_child(
        client, ready, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, collection, parent, plans, provider, root, kwargs = _sealed(
            ready, tmp_path, monkeypatch)
        if drift == "state":
            path = root / "terraform.tfstate"
            path.write_bytes(path.read_bytes() + b" ")
        elif drift == "plan":
            (root / f".barragan-mixed-published-destroy-{provider}.tfplan").write_bytes(
                b"different plan")
        elif drift == "binary":
            binary = tmp_path / "terraform-test"
            binary.write_bytes(b"different binary")
        else:
            (root / ".barragan-apply-phase.json").write_text(json.dumps({
                "schema": "provider-keyed-v2", "phase": "destroy_started"}))
        calls = []
        kwargs["gated_command_runner"] = lambda *args, **kw: calls.append("GO")
        with pytest.raises(PublishedMixedFirstDestroyGoAttention):
            run_published_mixed_first_provider_destroy(parent.id, **kwargs)
        assert jobs.get(child_id(collection.review.source.core_job_id, provider)) is None
        assert calls == []


def test_first_provider_uncertain_intent_never_replays(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, _plans, provider, root, kwargs = _sealed(
            ready, tmp_path, monkeypatch)
        calls = []

        def stopped(command, *, intent_callback, **kwargs):
            calls.append("runner")
            intent_callback(CommandIntent("once", str(root), hashlib.sha256(
                json.dumps(command, separators=(",", ":")).encode()).hexdigest()))
            raise RuntimeError("stopped after durable intent")

        kwargs["gated_command_runner"] = stopped
        for _ in range(2):
            with pytest.raises(PublishedMixedFirstDestroyGoAttention):
                run_published_mixed_first_provider_destroy(parent.id, **kwargs)
        assert calls == ["runner"]
        child = SqlAlchemyJobRepository().get(child_id(
            collection.review.source.core_job_id, provider))
        assert len(child.events) == 4


def test_first_provider_fresh_review_drift_at_intent_vetoes_go(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, collection, parent, _plans, provider, root, kwargs = _sealed(
            ready, tmp_path, monkeypatch)
        reads = []

        def drift_after_child(*args, **kw):
            reads.append(1)
            if len(reads) >= 4:
                return replace(collection, core_inspector_scope={"changed": True})
            return collection

        monkeypatch.setattr(worker, "collect_published_mixed_initial_teardown",
                            drift_after_child)
        calls = []
        kwargs["gated_command_runner"] = _fake_runner(provider, root, calls)
        with pytest.raises(PublishedMixedFirstDestroyGoAttention):
            run_published_mixed_first_provider_destroy(parent.id, **kwargs)
        assert calls != []  # The gated runner entered, but GO was vetoed.
        child = jobs.get(child_id(collection.review.source.core_job_id, provider))
        assert len(child.events) == 3
        assert json.loads((root / ".barragan-apply-phase.json").read_text())[
            "phase"] == "applied"
