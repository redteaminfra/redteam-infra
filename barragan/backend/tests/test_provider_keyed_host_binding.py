# Copyright (c) 2026, Oracle and/or its affiliates.
"""Fenced host-identity binding is durable without touching Sketch hosts."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_host_binding as service
from app.services.provider_keyed_digitalocean_attachment import DigitalOceanAttachmentStillSettling
from app.services.provider_keyed_initial_continuation import ACTION, _job_ids, _new_job
from app.storage.job_repository import SqliteJobRepository
from test_provider_keyed_chain_projection import _fixture as projection_fixture
from test_provider_keyed_persisted_intent import _inputs


def _past():
    return (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()


def _setup(tmp_path):
    reviewed, attachment, proof, chains = projection_fixture()
    _engagement, _chains, core, plan, _profile = _inputs()
    core_root = tmp_path / "core"
    core_hosts = core_root / "ssh" / "known_hosts"
    core_hosts.parent.mkdir(parents=True)
    core_root.chmod(0o700)
    core_hosts.parent.chmod(0o700)
    core_hosts.write_text("8.8.8.8 ssh-ed25519 pinned-core-key\n")
    core_hosts.chmod(0o600)
    core = replace(core, events=[*core.events, JobEvent(2, "info", "core workspace", {"workspaceDir": str(core_root)})])
    provider_root = tmp_path / "state" / "digitalocean"
    provider_root.mkdir(parents=True)
    provider_root.chmod(0o700)
    workspace = SimpleNamespace(
        path=provider_root, provider_connection_id=attachment.credential_record_id,
        source_revision="a" * 40,
    )
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    jobs.save(core)
    parent_id, plan_child, apply_child = _job_ids(core.id)
    parent = _new_job(
        parent_id, ACTION, core, reviewed.engagement_id,
        {"engagementId": reviewed.engagement_id, "coreJobId": core.id, "corePlanId": plan.id,
         "planJobId": plan_child, "applyJobId": apply_child,
         "phase": "awaiting_host_proof", "mutation": True,
         "claimOwner": "previous-worker", "claimToken": "previous-token", "claimExpiresAt": _past()},
    )
    parent = replace(parent, status="running", started_at=_past(), events=[
        *parent.events, JobEvent(2, "info", "provider attachment proven; host proof pending",
                                 service._proof_data(proof, attachment)),
    ])
    jobs.save(parent)
    calls = []
    applied = object()
    def preflight(*_args, **_kwargs):
        calls.append("preflight")
        return reviewed, workspace, {}, applied
    def reconciler(*_args, **_kwargs):
        calls.append("get")
        return proof
    options = dict(
        environment="devtest", state_root=tmp_path / "state", job_repository=jobs,
        plan_repository=SimpleNamespace(get=lambda key: plan if key == plan.id else None),
        sketch_repository=SimpleNamespace(list_for_engagement=lambda _key: chains),
        credential_repository=object(), lease_lookup=lambda _key: (plan.id, ACTION),
        postapply_preflight=preflight, attachment_intent_builder=lambda *_args: attachment,
        attachment_reconciler=reconciler,
    )
    return jobs, parent_id, options, calls, workspace, core_hosts


def test_binds_exact_manifest_and_empty_private_file_once(tmp_path):
    jobs, parent_id, options, calls, workspace, core_hosts = _setup(tmp_path)
    bound = service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert bound.status == "running" and bound.input["phase"] == "host_identity_bound"
    intended = [event for event in bound.events if event.message == service._INTENT_MESSAGE]
    assert len(intended) == 1
    manifest = intended[0].data
    assert manifest["coreJobId"] == "job-core" and manifest["corePlanId"] == "plan-core"
    assert manifest["stateSha256"] == "a" * 64
    assert manifest["coreKnownHostsPath"] == str(core_hosts)
    assert manifest["coreKnownHostsSha256"] == service.hashlib.sha256(core_hosts.read_bytes()).hexdigest()
    assert len(manifest["chainFingerprints"]) == 2 and len(manifest["nodes"]) == 7
    assert [row["chainId"] for row in manifest["hostPolicies"]] == [
        "proxy01-sfo-01", "proxy02-sfo-01",
    ]
    path = workspace.path / service._KNOWN_HOSTS_NAME
    assert path.read_bytes() == b"" and path.stat().st_mode & 0o777 == 0o600
    assert calls == ["preflight", "get", "preflight"]
    with pytest.raises(service.ProviderKeyedHostBindingError):
        service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert calls == ["preflight", "get", "preflight"]
    assert all("apply" not in job.action for job in jobs.list())


def test_fresh_provider_get_may_settle_in_fewer_attempts(tmp_path):
    _jobs, parent_id, options, _calls, _workspace, _core_hosts = _setup(tmp_path)
    original = options["attachment_reconciler"]
    options["attachment_reconciler"] = lambda *args, **kwargs: replace(original(*args, **kwargs), attempts=1)
    bound = service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert bound.input["phase"] == "host_identity_bound"


def test_corrected_initial_plan_ignores_only_inert_aborted_prior_row(tmp_path):
    jobs, parent_id, options, _calls, _workspace, _core_hosts = _setup(tmp_path)
    current = options["sketch_repository"].list_for_engagement("eng-opaque")
    ghost = replace(current[0], chain_id="proxy01-nyc3-01", status="aborted")
    options["sketch_repository"] = SimpleNamespace(
        list_for_engagement=lambda _key: [ghost, *current])
    bound = service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert bound.input["phase"] == "host_identity_bound"
    manifest = next(event.data for event in bound.events if event.message == service._INTENT_MESSAGE)
    assert [row["chainId"] for row in manifest["chainFingerprints"]] == [
        chain.chain_id for chain in current]


def test_prior_row_with_durable_node_is_not_ignored(tmp_path):
    jobs, parent_id, options, _calls, workspace, _core_hosts = _setup(tmp_path)
    current = options["sketch_repository"].list_for_engagement("eng-opaque")
    ghost = replace(current[0], chain_id="proxy01-nyc3-01", status="aborted",
                    nodes=[{"providerInstanceId": "retained"}])
    options["sketch_repository"] = SimpleNamespace(
        list_for_engagement=lambda _key: [ghost, *current])
    stopped = service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert not (workspace.path / service._KNOWN_HOSTS_NAME).exists()


def test_transient_provider_settling_releases_claim_without_creating_file(tmp_path):
    jobs, parent_id, options, calls, workspace, _core_hosts = _setup(tmp_path)
    options["attachment_reconciler"] = lambda *_a, **_kw: (_ for _ in ()).throw(
        DigitalOceanAttachmentStillSettling("secret transport detail"))
    pending = service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert pending.status == "running" and pending.input["phase"] == "awaiting_host_proof"
    assert datetime.fromisoformat(pending.input["claimExpiresAt"]) <= datetime.now(timezone.utc)
    assert "secret transport detail" not in str(pending.events)
    assert not (workspace.path / service._KNOWN_HOSTS_NAME).exists()
    assert calls == ["preflight"]


def test_core_known_hosts_change_after_intent_blocks_bound_phase(tmp_path):
    jobs, parent_id, options, _calls, workspace, core_hosts = _setup(tmp_path)
    original = options["postapply_preflight"]
    count = 0
    def changed(*args, **kwargs):
        nonlocal count
        count += 1
        result = original(*args, **kwargs)
        if count == 2:
            core_hosts.write_text("9.9.9.9 ssh-ed25519 changed-key\n")
        return result
    options["postapply_preflight"] = changed
    stopped = service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert (workspace.path / service._KNOWN_HOSTS_NAME).exists()


def test_crash_after_intent_adopts_only_exact_empty_file(tmp_path, monkeypatch):
    jobs, parent_id, options, calls, workspace, _core_hosts = _setup(tmp_path)
    real_create = service._empty_known_hosts
    def crash_after_create(path, *, adopt):
        real_create(path, adopt=adopt)
        raise SystemExit("simulated process death")
    monkeypatch.setattr(service, "_empty_known_hosts", crash_after_create)
    with pytest.raises(SystemExit):
        service.bind_initial_digitalocean_host_identity(parent_id, **options)
    interrupted = jobs.get(parent_id)
    assert interrupted.input["phase"] == "binding_host_identity"
    assert (workspace.path / service._KNOWN_HOSTS_NAME).read_bytes() == b""
    jobs.save(replace(interrupted, input={**interrupted.input, "claimExpiresAt": _past()}))
    monkeypatch.setattr(service, "_empty_known_hosts", real_create)
    bound = service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert bound.input["phase"] == "host_identity_bound"
    assert len([event for event in bound.events if event.message == service._INTENT_MESSAGE]) == 1
    assert calls == ["preflight", "get", "preflight", "get", "preflight"]


@pytest.mark.parametrize("unsafe", ["nonempty", "symlink", "hardlink", "changed_evidence"])
def test_reentry_drift_fails_redacted_without_host_contact(tmp_path, monkeypatch, unsafe):
    jobs, parent_id, options, _calls, workspace, _core_hosts = _setup(tmp_path)
    real_create = service._empty_known_hosts
    monkeypatch.setattr(service, "_empty_known_hosts", lambda path, *, adopt: (_ for _ in ()).throw(SystemExit()))
    with pytest.raises(SystemExit):
        service.bind_initial_digitalocean_host_identity(parent_id, **options)
    interrupted = jobs.get(parent_id)
    jobs.save(replace(interrupted, input={**interrupted.input, "claimExpiresAt": _past()}))
    monkeypatch.setattr(service, "_empty_known_hosts", real_create)
    path = workspace.path / service._KNOWN_HOSTS_NAME
    if unsafe == "nonempty":
        path.write_text("unreviewed key\n")
    elif unsafe == "symlink":
        path.symlink_to(tmp_path / "outside")
    elif unsafe == "hardlink":
        path.touch(mode=0o600)
        (tmp_path / "other-link").hardlink_to(path)
    else:
        options["attachment_reconciler"] = lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("secret drift"))
    stopped = service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert stopped.status == "failed" and stopped.input["phase"] == "attention"
    assert "secret drift" not in str(stopped.events)


def test_losing_claim_cannot_persist_binding(tmp_path):
    jobs, parent_id, options, calls, workspace, _core_hosts = _setup(tmp_path)
    original = options["postapply_preflight"]
    def stolen(*args, **kwargs):
        result = original(*args, **kwargs)
        parent = jobs.get(parent_id)
        jobs.save(replace(parent, input={**parent.input, "claimOwner": "other", "claimToken": "other-token"}))
        return result
    options["postapply_preflight"] = stolen
    with pytest.raises(service.ProviderKeyedHostBindingError, match="reconciliation required"):
        service.bind_initial_digitalocean_host_identity(parent_id, **options)
    assert jobs.get(parent_id).input["phase"] == "awaiting_host_proof"
    assert not (workspace.path / service._KNOWN_HOSTS_NAME).exists()
    assert calls == ["preflight", "get"]
