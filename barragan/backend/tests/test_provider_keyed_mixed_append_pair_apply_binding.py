# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted paired approval is the only input to the first one-shot Apply."""

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_initial_plan_gate import DigitalOceanInitialFirewallIntent
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
import app.services.provider_keyed_mixed_append_pair_apply_binding as binder
import app.services.provider_keyed_mixed_append_pair_apply_child as apply_service
import app.services.provider_keyed_mixed_append_pair_parent as parent_service
from app.services.provider_keyed_mixed_append_pair_parent import (
    approve_mixed_append_pair, mixed_append_approval_sha256, reserve_mixed_append_pair,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, reopen_mixed_append_pair_plan_review
from app.services.provider_keyed_mixed_append_published_source import PublishedMixedAppendSource
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_append_pair_parent import _setup, complete_review
from test_provider_keyed_mixed_append_pair_plan_worker import fixture as pair_fixture, sha


@pytest.fixture(autouse=True)
def isolate_purchase_catalog(monkeypatch):
    # Isolate the full reviewed-availability prerequisite (policy, size, catalog).
    # Dedicated tests cover that guard; these fixtures exercise binding/GO authority.
    monkeypatch.setattr(parent_service, "require_reviewed_mixed_append_availability",
                        lambda *args, **kwargs: None)


def _admin_key_setup(monkeypatch, workspaces):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH).decode()
    private = key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    seal = {"orderedProviders": list(workspaces),
            "reviewedPolicy": {p: {"admin_public_key": public} for p in workspaces},
            "receiptSha256": []}
    for p, workspace in workspaces.items():
        receipt = workspace.path / f".barragan-{p}-plan-receipt.json"
        receipt.write_text(json.dumps({"adminPublicKeySha256": sha(public.encode())}, indent=2) + "\n")
        receipt.chmod(0o600)
        seal['receiptSha256'].append(binder._digest(json.loads(receipt.read_bytes())))
    monkeypatch.setattr(binder, 'retrieve_sketch_ssh_key', lambda _: SimpleNamespace(
        public_key=public, private_key=private))
    monkeypatch.setattr(binder, 'validate_mixed_initial_apply_seal', lambda _: seal)
    return public, private, seal


def _case(tmp_path, monkeypatch, order=("digitalocean", "linode")):
    kwargs, records, _ = pair_fixture(tmp_path, monkeypatch)
    source = kwargs["source"]
    kwargs["reviewed_provider_order"] = order
    kwargs["reviewed_chain_order"] = tuple(
        kwargs[f"{provider}_intent"].chain_id for provider in order)
    firewall = DigitalOceanInitialFirewallIntent("name", "tag", ("22",), (), ("192.0.2.1/32",))
    kwargs["digitalocean_firewall"] = firewall
    # Use actual persisted nonsecret inputs rather than the pair reopener's
    # deliberately minimal fixture data.
    for provider in ("digitalocean", "linode"):
        root = kwargs["workspaces"][provider].path
        material = root.parents[1] / ".plan-material" / provider
        material.mkdir(parents=True, exist_ok=True, mode=0o700)
        actual = {**kwargs[f"{provider}_intent"].nonsecret_varfile,
                  "ssh_pub_key_path": str(material / "admin-public"),
                  "ssh_priv_key_path": str(material / "admin-private")}
        kwargs[f"{provider}_intent"] = replace(kwargs[f"{provider}_intent"], nonsecret_varfile=actual)
        kwargs["reviewed_inputs"][provider] = actual
        root = kwargs["workspaces"][provider].path
        inputs = root / _name(provider, "inputs.json")
        inputs.write_text(json.dumps(actual))
        receipt_path = root / _name(provider, "plan-receipt.json")
        receipt = json.loads(receipt_path.read_text())
        receipt["inputSha256"] = sha(inputs.read_bytes())
        receipt_path.write_text(json.dumps(receipt))
    seal = reopen_mixed_append_pair_plan_review(**kwargs)
    pair_sha = seal.review_sha256
    published = PublishedMixedAppendSource(
        source, tuple((p, row.path) for p, row in kwargs["workspaces"].items()),
        0, "d" * 64, "e" * 64)
    current = {"publication": published}
    monkeypatch.setattr(parent_service, "_collect_published", lambda *_: current["publication"])
    state, jobs = _setup(source.engagement_id, source.core_job_id, source.core_plan_id)
    do, linode = kwargs["digitalocean_intent"], kwargs["linode_intent"]
    request = {
        "digitalocean": {"selectedChainId": do.chain_id,
                         "edgeRegion": do.new_edge.region, "edgeSize": do.new_edge.size,
                         "edgeImage": do.new_edge.image,
                         "selectorTag": do.new_edge.firewall_selector_tag},
        "linode": {"selectedChainId": linode.chain_id,
                   "edgeRegion": linode.new_edge.region,
                   "edgeType": linode.new_edge.node_type,
                   "edgeImage": linode.new_edge.image,
                   "engagementTag": linode.new_edge.tag},
    }
    def lease(engagement):
        row = db.session.get(CoreMutationLeaseModel, engagement)
        return (row.owner_id, row.operation) if row else None
    with db.bind(state):
        reserved = reserve_mixed_append_pair(
            source.engagement_id, source.core_job_id, source.core_plan_id,
            requested_by="operator", reviewed_request=request,
            provider_order=kwargs["reviewed_provider_order"],
            chain_order=kwargs["reviewed_chain_order"], job_repository=jobs)
        review_sha = mixed_append_approval_sha256(pair_sha, published)
        complete_review(jobs, reserved, review_sha, seal)
        approved = approve_mixed_append_pair(
            reserved.id,
            expected_review_sha256=review_sha,
            binding_manifest=kwargs["binding_manifest"],
            digitalocean_intent=do, linode_intent=linode,
            workspaces=kwargs["workspaces"],
            provider_states=kwargs["provider_states"],
            reviewed_inputs=kwargs["reviewed_inputs"],
            digitalocean_firewall=firewall,
            job_repository=jobs, credential_repository=kwargs["credential_repository"],
            lease_lookup=lease, release_check=kwargs["release_check"])
        # The fixture has no published 4-host journal. Keep the historical
        # recognizers at that boundary while exercising the real durable pair,
        # receipt, credential, lock, binary re-show, and final GO fences.
        core = jobs.get(source.core_job_id)
        for identifier in (
            binder.initial_parent_id(source.core_job_id),
            binder._binding_child_id(source.core_job_id),
            *(binder.initial_child_id(source.core_job_id, p)
              for p in ("digitalocean", "linode")),
        ):
            jobs.save(replace(core, id=identifier))
    monkeypatch.setattr(binder.parent_service, "_collect_published", lambda *_: current["publication"])
    monkeypatch.setattr(binder, "recognize_mixed_initial_host_binding", lambda *_: kwargs["binding_manifest"])
    monkeypatch.setattr(binder, "recognize_mixed_initial_apply_terminal", lambda *_: {})
    monkeypatch.setattr(binder, "_prior_workspace", lambda _parent, provider, _terminal: kwargs["workspaces"][provider])

    def show(command, **options):
        provider = options["scratch_path"].name
        options["intent_callback"](SimpleNamespace(
            scratch_path=str(options["scratch_path"]),
            argv_sha256=hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest()))
        options["started_callback"](object())
        options["result_callback"](object())
        return SimpleNamespace(returncode=0,
            stdout=(options["scratch_path"] / _name(provider, "show.json")).read_text(),
            stdout_truncated=False, stderr_truncated=False)

    _admin_key_setup(monkeypatch, kwargs["workspaces"])
    callbacks = binder.build_first_mixed_append_apply_bindings(
        approved.id, job_repository=jobs, lease_lookup=lease,
        credential_repository=kwargs["credential_repository"],
        release_check=kwargs["release_check"], show_runner=show,
        command_environment={})
    return state, jobs, approved, kwargs, records, current, callbacks


def test_persisted_parent_reopens_both_binaries_and_passes_final_go_fence(tmp_path, monkeypatch):
    state, jobs, parent, kwargs, _, _, callbacks = _case(tmp_path, monkeypatch)
    with db.bind(state):
        assert callbacks["pair_preflight"](jobs.get(parent.id), lambda: None) == parent.input["reviewSha256"]
        with callbacks["source_session"](jobs.get(parent.id), "digitalocean", lambda: None) as source:
            assert callbacks["pre_go_check"](jobs.get(parent.id), source, lambda: None) == parent.input["reviewSha256"]


@pytest.mark.parametrize("drift", ["bindings", "source", "receipt", "lease", "parent"])
def test_changed_authority_stops_before_apply_go(tmp_path, monkeypatch, drift):
    state, jobs, parent, kwargs, _, current, callbacks = _case(tmp_path, monkeypatch)
    with db.bind(state):
        callbacks["pair_preflight"](jobs.get(parent.id), lambda: None)
        if drift == "bindings":
            current["publication"] = replace(current["publication"], live_bindings_sha256="f" * 64)
        elif drift == "source":
            current["publication"] = replace(current["publication"], source=replace(
                current["publication"].source, core_plan_id="changed"))
        elif drift == "receipt":
            path = kwargs["workspaces"]["digitalocean"].path / _name("digitalocean", "plan-receipt.json")
            path.write_bytes(path.read_bytes() + b" ")
        elif drift == "lease":
            db.session.get(CoreMutationLeaseModel, parent.target_id).operation = "other"
            db.session.commit()
        else:
            jobs.save(replace(jobs.get(parent.id), input={**parent.input, "reviewSha256": "0" * 64}))
        with pytest.raises(binder.MixedAppendPairApplyBindingAttention):
            with callbacks["source_session"](parent, "digitalocean", lambda: None):
                pytest.fail("stale source acquired Apply authority")


@pytest.mark.parametrize("drift", ["bindings", "receipt", "lease", "parent"])
def test_drift_after_plan_lock_is_rejected_by_final_go_fence(tmp_path, monkeypatch, drift):
    state, jobs, parent, kwargs, _, current, callbacks = _case(tmp_path, monkeypatch)
    with db.bind(state):
        callbacks["pair_preflight"](jobs.get(parent.id), lambda: None)
        with callbacks["source_session"](parent, "digitalocean", lambda: None) as source:
            if drift == "bindings":
                current["publication"] = replace(current["publication"], historical_rows_sha256="f" * 64)
            elif drift == "receipt":
                path = kwargs["workspaces"]["linode"].path / _name("linode", "plan-receipt.json")
                path.write_bytes(path.read_bytes() + b" ")
            elif drift == "lease":
                db.session.get(CoreMutationLeaseModel, parent.target_id).operation = "other"
                db.session.commit()
            else:
                jobs.save(replace(jobs.get(parent.id), input={**parent.input, "reviewSha256": "0" * 64}))
            with pytest.raises(binder.MixedAppendPairApplyBindingAttention):
                callbacks["pre_go_check"](parent, source, lambda: None)


@pytest.mark.parametrize("order", [
    ("digitalocean", "linode"), ("linode", "digitalocean")])
@pytest.mark.parametrize("drift", ["none", "bindings", "receipt", "snapshot"])
def test_first_apply_worker_uses_persisted_binder_at_final_callback(
    tmp_path, monkeypatch, drift, order,
):
    state, jobs, parent, kwargs, _, current, callbacks = _case(tmp_path, monkeypatch, order)
    first, second = order
    root = kwargs["workspaces"][first].path
    phase = root / ".barragan-apply-phase.json"
    phase.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "applied"}))
    go = []

    def mark_started(_workspace):
        phase.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "apply_started"}))

    def mark_applied(_workspace):
        phase.write_text(json.dumps({"schema": "provider-keyed-v2", "phase": "applied"}))

    monkeypatch.setattr(apply_service, "mark_provider_keyed_apply_started", mark_started)
    monkeypatch.setattr(apply_service, "mark_provider_keyed_applied", mark_applied)

    def gated(command, **options):
        intent = CommandIntent("a" * 32, str(root), hashlib.sha256(
            json.dumps(command, separators=(",", ":")).encode()).hexdigest())
        for key in ('ssh_pub_key_path', 'ssh_priv_key_path'):
            assert binder.Path(kwargs['reviewed_inputs'][first][key]).is_file()
        options["intent_callback"](intent)
        # The external command has been prepared, but its GO gate has not
        # opened. A publication or receipt change must veto on_started.
        if drift == "bindings":
            current["publication"] = replace(
                current["publication"], live_bindings_sha256="f" * 64)
        elif drift == "receipt":
            receipt = kwargs["workspaces"][second].path / _name(second, "plan-receipt.json")
            receipt.write_bytes(receipt.read_bytes() + b" ")
        elif drift == "snapshot":
            snapshot = kwargs["workspaces"][second].path / _name(second, "predecessor.tfstate")
            snapshot.write_bytes(b"changed predecessor")
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        options["started_callback"](started)
        go.append(command)
        kwargs["workspaces"][first].state_path.write_bytes(b"new state")
        options["result_callback"](CommandAuditResult(started, 0, 2, 0, False, False))
        return CommandResult(started, 0, "ok", "", False, False)

    def lease(engagement):
        row = db.session.get(CoreMutationLeaseModel, engagement)
        return (row.owner_id, row.operation) if row else None

    with db.bind(state):
        options = dict(
            parent_id=parent.id, environment="devtest", job_repository=jobs,
            lease_lookup=lease, **callbacks,
            release_check=kwargs["release_check"],
            gated_command_runner=gated, command_environment={},
        )
        if drift == "none":
            child = apply_service.run_first_mixed_append_provider_apply(**options)
            assert child.events[-1].message == "mixed append first awaiting exact poststate proof"
            assert len(go) == 1
        else:
            with pytest.raises(binder.MixedAppendPairApplyBindingAttention):
                apply_service.run_first_mixed_append_provider_apply(**options)
            assert go == []


@pytest.mark.parametrize('order', [('digitalocean', 'linode'), ('linode', 'digitalocean')])
@pytest.mark.parametrize('failed', [False, True])
def test_first_session_stages_exact_sealed_key_and_cleans_on_exit(tmp_path, monkeypatch, order, failed):
    state, jobs, parent, kwargs, _, _, callbacks = _case(tmp_path, monkeypatch, order)
    provider = order[0]
    variables = kwargs['reviewed_inputs'][provider]
    public = binder.Path(variables['ssh_pub_key_path'])
    private = binder.Path(variables['ssh_priv_key_path'])
    with db.bind(state):
        callbacks['pair_preflight'](jobs.get(parent.id), lambda: None)
        try:
            with callbacks['source_session'](jobs.get(parent.id), provider, lambda: None) as source:
                assert public.is_file() and private.is_file()
                assert public.stat().st_mode & 0o777 == private.stat().st_mode & 0o777 == 0o600
                assert binder._matching_admin_key(public.read_text(), private.read_text())
                assert callbacks['pre_go_check'](jobs.get(parent.id), source, lambda: None) == parent.input['reviewSha256']
                if failed: raise RuntimeError('nonzero Apply boundary')
        except RuntimeError:
            assert failed
    assert not public.exists() and not private.exists()


@pytest.mark.parametrize('drift', ['public', 'private', 'symlink', 'path', 'sealed_key', 'receipt'])
def test_append_key_stage_rejects_mismatch_without_clobber(tmp_path, monkeypatch, drift):
    state, jobs, parent, kwargs, _, _, callbacks = _case(tmp_path, monkeypatch)
    provider = 'digitalocean'
    workspace = kwargs['workspaces'][provider]
    variables = dict(kwargs['reviewed_inputs'][provider])
    public = binder.Path(variables['ssh_pub_key_path'])
    private = binder.Path(variables['ssh_priv_key_path'])
    if drift in ('public', 'private'):
        selected = public if drift == 'public' else private
        selected.write_bytes(b'foreign'); selected.chmod(0o600)
    elif drift == 'symlink': public.symlink_to(tmp_path / 'absent')
    elif drift == 'path': variables['ssh_pub_key_path'] += '-foreign'
    elif drift == 'sealed_key': monkeypatch.setattr(binder, 'retrieve_sketch_ssh_key', lambda _: None)
    else:
        (workspace.path / '.barragan-digitalocean-plan-receipt.json').write_text('{}')
    with db.bind(state), pytest.raises(ValueError):
        with binder._staged_append_admin_material(parent, workspace, variables, jobs):
            pytest.fail('unproved material reached GO')
    if drift in ('public', 'private'): assert selected.read_bytes() == b'foreign'
    if drift == 'symlink': assert public.is_symlink()
    # Preserve only fixture foreign material; no shared test path leftovers.
    for path in (public, private):
        if path.exists() or path.is_symlink(): path.unlink()


def test_staged_key_changes_are_fenced_before_go(tmp_path, monkeypatch):
    state, jobs, parent, kwargs, _, _, callbacks = _case(tmp_path, monkeypatch)
    path = binder.Path(kwargs['reviewed_inputs']['digitalocean']['ssh_pub_key_path'])
    with db.bind(state):
        callbacks['pair_preflight'](parent, lambda: None)
        with pytest.raises(ValueError):
            with callbacks['source_session'](parent, 'digitalocean', lambda: None) as source:
                path.write_bytes(b'foreign-after-stage')
                with pytest.raises(ValueError, match='administration key changed'):
                    source.lock_fence()
    assert path.read_bytes() == b'foreign-after-stage'
    path.unlink()
    binder.Path(kwargs['reviewed_inputs']['digitalocean']['ssh_priv_key_path']).unlink()


def test_unreaped_apply_retains_exact_staged_material(tmp_path, monkeypatch):
    state, jobs, parent, kwargs, _, _, callbacks = _case(tmp_path, monkeypatch)
    public = binder.Path(kwargs['reviewed_inputs']['digitalocean']['ssh_pub_key_path'])
    private = binder.Path(kwargs['reviewed_inputs']['digitalocean']['ssh_priv_key_path'])
    with db.bind(state):
        callbacks['pair_preflight'](parent, lambda: None)
        with pytest.raises(binder.UnreapedGatedCommandError):
            with callbacks['source_session'](parent, 'digitalocean', lambda: None):
                raise binder.UnreapedGatedCommandError('group identity uncertain')
    assert public.is_file() and private.is_file()
    public.unlink(); private.unlink()
