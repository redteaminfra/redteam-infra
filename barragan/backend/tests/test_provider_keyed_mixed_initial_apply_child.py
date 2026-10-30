# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private mixed Apply one-shot journal; all provider effects are injected."""

from pathlib import Path
import stat
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from dataclasses import replace
import hashlib
import json
from contextlib import nullcontext

import pytest

from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_initial_apply_child import (
    ApplySource, MixedInitialApplyAttention,
    _child_id, recognize_mixed_initial_apply_result, recognize_mixed_initial_apply_terminal,
    reconcile_mixed_initial_apply_phase,
    run_mixed_initial_provider_apply,
)
import app.services.provider_keyed_mixed_initial_apply_child as child_service
from app.services.provider_keyed_mixed_initial_plan_parent import (
    prepare_or_reuse_mixed_initial_plans, seal_mixed_initial_apply,
)
from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import CoreMutationLeaseModel
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, prepare_provider_keyed_workspace
from test_provider_keyed_mixed_initial_plan_parent import case


@pytest.fixture
def ready(case):
    plan_bytes = b"private-mixed-saved-plan-fixture"
    plan_sha = hashlib.sha256(plan_bytes).hexdigest()
    for provider in ("linode", "digitalocean"):
        original_runner = case.args[f"{provider}_runner"]
        def saved_plan_runner(*, _provider=provider, _original=original_runner, **kwargs):
            receipt = {**_original(**kwargs), "planSha256": plan_sha}
            workspace = next((case.state_root / "eng-opaque" / "provider-keyed-v2" / _provider).iterdir())
            plan_name = (".barragan-linode-initial-full.tfplan" if _provider == "linode"
                         else ".barragan-digitalocean-initial-full.tfplan")
            (workspace / plan_name).write_bytes(plan_bytes)
            return receipt
        case.args[f"{provider}_runner"] = saved_plan_runner
    prepare_or_reuse_mixed_initial_plans(**case.args)
    parent = seal_mixed_initial_apply(**case.args)
    calls = []
    state = {"stop": None}

    def source_reader(saved, provider):
        assert saved == parent
        calls.append(("source", provider))
        index = parent.input["orderedProviders"].index(provider)
        workspace = next((case.state_root / "eng-opaque" / "provider-keyed-v2" / provider).iterdir())
        marker = json.loads((workspace / ".barragan-provider-keyed-state.json").read_text())
        source_sha = hashlib.sha256(json.dumps(marker["source_files"], sort_keys=True).encode()).hexdigest()
        record = ProviderKeyedWorkspace(
            workspace, workspace / "terraform.tfstate", workspace / ".terraform-data",
            "provider-keyed-v2", provider, marker["provider_connection_id"],
            workspace.name, marker["source_revision"], source_sha)
        plan_name = (".barragan-linode-initial-full.tfplan" if provider == "linode"
                     else ".barragan-digitalocean-initial-full.tfplan")
        policy = parent.events[5].data["reviewedPolicy"][provider]
        return ApplySource(
            workspace=record,
            command=("/usr/bin/terraform", "apply", "-input=false", "-lock=true",
                     "-no-color", str(workspace / plan_name)),
            receipt_sha256=parent.events[index + 2].data["receiptSha256"],
            plan_sha256=parent.events[index + 2].data["planSha256"],
            terraform_sha256="e" * 64,
            credential_secret_sha256=policy["credential_secret_sha256"],
            credential_updated_at=policy["credential_updated_at"],
            selector_tag=policy["selector_tag"] if provider == "digitalocean" else None,
            selector_token="ephemeral-test-token" if provider == "digitalocean" else None,
        )

    def selector_absence(source, fence):
        fence()
        calls.append(("selector-absence", source.selector_tag))
        return "a" * 64

    def selector_reserver(selector, token, *, fence, on_intent, on_receipt,
                          get_transport, post_transport):
        assert token == "ephemeral-test-token"
        fence()
        on_intent()
        calls.append(("selector-post", selector))
        if state["stop"] == "post":
            raise RuntimeError("interrupted selector POST")
        on_receipt(201, selector)
        fence()
        return (selector,)

    def command_runner(command, *, scratch_path, provider_keyed_v2,
                       gate_timeout_seconds, intent_callback, started_callback,
                       heartbeat_callback, result_callback, env):
        assert provider_keyed_v2 is True and gate_timeout_seconds == 1200
        assert command[1] == "apply"
        assert env["TF_DATA_DIR"] == str(scratch_path / ".terraform-data")
        assert env["TF_CLI_CONFIG_FILE"] == "/dev/null"
        assert set(env) <= {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
                            "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                            "TF_DATA_DIR", "TF_CLI_CONFIG_FILE"}
        import json
        digest = hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        intent = CommandIntent("a" * 32, str(scratch_path), digest)
        intent_callback(intent)
        calls.append(("command-intent", command[1]))
        if state["stop"] == "intent":
            raise RuntimeError("interrupted before command start")
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        started_callback(started)
        heartbeat_callback(started)
        (scratch_path / "terraform.tfstate").write_text("{}")
        result_callback(CommandAuditResult(started, 0, 4, 0, False, False))
        return CommandResult(started, 0, "done", "", False, False)

    args = dict(engagement_id="eng-opaque", core_job_id="job-core", environment="devtest",
                job_repository=case.jobs, lease_lookup=case.args["lease_lookup"],
                source_session=lambda parent, provider, renew: nullcontext(source_reader(parent, provider)),
                selector_absence_prover=selector_absence,
                selector_get_transport=object(), selector_post_transport=object(),
                release_check=lambda **kwargs: SimpleNamespace(path=Path("/usr/bin/terraform"),
                                                                 sha256="e" * 64),
                gated_command_runner=command_runner,
                selector_reserver=selector_reserver)
    return SimpleNamespace(args=args, parent=parent, case=case, calls=calls, state=state)


def test_apply_rejects_ambient_terraform_override_before_command_intent(ready, monkeypatch):
    monkeypatch.setenv("TF_CLI_ARGS_apply", "-auto-approve")
    provider = ready.parent.input["orderedProviders"][0]
    with pytest.raises(MixedInitialApplyAttention, match="unreviewed Terraform environment"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    child = ready.case.jobs.get(_child_id("job-core", provider))
    assert child is not None
    assert all(event.message != "mixed provider Apply command intended" for event in child.events)
    assert not list((ready.case.state_root / "eng-opaque" / "provider-keyed-v2" /
                     provider).glob("*/terraform.tfstate"))


def test_first_child_stops_at_awaiting_observation_and_second_is_closed(ready, monkeypatch):
    monkeypatch.setenv("LINODE_TOKEN", "must-not-reach-terraform-environment")
    monkeypatch.setenv("DIGITALOCEAN_TOKEN", "must-not-reach-terraform-environment")
    order = ready.parent.input["orderedProviders"]
    with pytest.raises(MixedInitialApplyAttention, match="first provider"):
        run_mixed_initial_provider_apply(provider=order[1], **ready.args)
    first = run_mixed_initial_provider_apply(provider=order[0], **ready.args)
    assert first.status == "running"
    assert first.events[-1].message == "mixed provider awaiting exact observation"
    assert recognize_mixed_initial_apply_result(first, ready.parent, order[0])["provider"] == order[0]
    with pytest.raises(MixedInitialApplyAttention, match="first provider"):
        run_mixed_initial_provider_apply(provider=order[1], **ready.args)
    assert [row[0] for row in ready.calls].count("command-intent") == 1
    with pytest.raises(MixedInitialApplyAttention, match="not safely pre-command"):
        run_mixed_initial_provider_apply(provider=order[0], **ready.args)


def _terminal_first(ready):
    provider = ready.parent.input["orderedProviders"][0]
    running = run_mixed_initial_provider_apply(provider=provider, **ready.args)
    result = recognize_mixed_initial_apply_result(running, ready.parent, provider)
    proof = {
        "classifierKind": "full", "stateSha256": "a" * 64,
        "lineage": "fixture-lineage", "serial": 1,
        "inventorySha256": "b" * 64, "observationSha256": "c" * 64,
        "resourceIds": {"node.address": "101"},
        "selectorResourcesCount": 1 if provider == "digitalocean" else None,
        "selectorAttachedNodeIds": ["101"] if provider == "digitalocean" else None,
        "linodeFirewallAttachedNodeIds": ["101"] if provider == "linode" else None,
        "inventoryCount": 1,
        "commandResultJournalSha256": result["commandResultJournalSha256"],
    }
    events = [*running.events,
              JobEvent(len(running.events) + 1, "info", "mixed provider full observation proved", proof),
              JobEvent(len(running.events) + 2, "info", "mixed provider initial Apply succeeded",
                       {"observationSha256": proof["observationSha256"]})]
    terminal = replace(running, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
                       events=events)
    ready.case.jobs.save(terminal)
    return ready.case.jobs.get(terminal.id)


def test_provider_two_needs_terminal_and_fresh_first_presence(ready):
    first, second = ready.parent.input["orderedProviders"]
    terminal = _terminal_first(ready)
    assert recognize_mixed_initial_apply_terminal(terminal, ready.parent, first)["proof"]["serial"] == 1
    assert run_mixed_initial_provider_apply(provider=first, **ready.args) == terminal
    before = list(ready.calls)
    def stale(*args, **kwargs):
        kwargs["fence"]()
        raise ValueError("first provider state changed")
    with pytest.raises(ValueError, match="state changed"):
        run_mixed_initial_provider_apply(provider=second, prior_fresh_prover=stale, **ready.args)
    assert ready.calls == before
    assert ready.case.jobs.get(_child_id("job-core", second)) is None
    observed = []
    def fresh(parent, child, workspace, **kwargs):
        assert child == terminal and workspace.provider == first
        observed.append(kwargs["fence"]())
        return SimpleNamespace(kind="full")
    second_child = run_mixed_initial_provider_apply(provider=second,
                                                     prior_fresh_prover=fresh, **ready.args)
    assert second_child.events[-1].message == "mixed provider awaiting exact observation"
    assert len(observed) == 1


def test_forged_prior_terminal_never_opens_provider_two(ready):
    first, second = ready.parent.input["orderedProviders"]
    terminal = _terminal_first(ready)
    forged_events = list(terminal.events)
    forged_events[-1] = replace(forged_events[-1], data={"observationSha256": "0" * 64})
    ready.case.jobs.save(replace(terminal, events=forged_events))
    before = list(ready.calls)
    with pytest.raises(MixedInitialApplyAttention, match="first provider terminal proof"):
        run_mixed_initial_provider_apply(
            provider=second, prior_fresh_prover=lambda *a, **kw: SimpleNamespace(kind="full"),
            **ready.args)
    assert ready.calls == before
    assert ready.case.jobs.get(_child_id("job-core", second)) is None


def test_result_recognizer_rejects_forged_success_or_copied_identity(ready):
    provider = ready.parent.input["orderedProviders"][0]
    child = run_mixed_initial_provider_apply(provider=provider, **ready.args)
    assert recognize_mixed_initial_apply_result(child, ready.parent, provider)
    forged = replace(child, status="succeeded")
    with pytest.raises(MixedInitialApplyAttention):
        recognize_mixed_initial_apply_result(forged, ready.parent, provider)
    forged = replace(child, requested_by="someone-else")
    with pytest.raises(MixedInitialApplyAttention):
        recognize_mixed_initial_apply_result(forged, ready.parent, provider)
    events = list(child.events)
    result_index = next(index for index, row in enumerate(events)
                        if row.message == "mixed provider Apply command result fenced")
    events[result_index] = replace(events[result_index], data={**events[result_index].data,
                                                                "returnCode": 1})
    with pytest.raises(MixedInitialApplyAttention):
        recognize_mixed_initial_apply_result(replace(child, events=events), ready.parent, provider)


def test_result_only_crash_reconciles_phase_without_replaying_apply(ready, monkeypatch):
    provider = ready.parent.input["orderedProviders"][0]
    original_mark = child_service.mark_provider_keyed_applied
    monkeypatch.setattr(child_service, "mark_provider_keyed_applied",
                        lambda workspace: (_ for _ in ()).throw(RuntimeError("phase write interrupted")))
    with pytest.raises(RuntimeError, match="phase write interrupted"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    child_id = _child_id("job-core", provider)
    child = ready.case.jobs.get(child_id)
    assert recognize_mixed_initial_apply_result(child, ready.parent, provider)["stage"] == "result"
    assert json.loads((Path(next((ready.case.state_root / "eng-opaque" / "provider-keyed-v2" / provider).iterdir()))
                       / ".barragan-apply-phase.json").read_text())["phase"] == "apply_started"
    monkeypatch.setattr(child_service, "mark_provider_keyed_applied", original_mark)
    with ready.case.jobs._connect() as connection:
        connection.execute("UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', ?) WHERE id = ?",
                           ("2020-01-01T00:00:00+00:00", child_id))
    child = ready.case.jobs.get(child_id)
    source = ready.args["source_session"](ready.parent, provider, lambda: None).__enter__()
    lock = source.workspace.path / (".barragan-linode-plan.lock" if provider == "linode"
                                    else ".barragan-digitalocean-plan.lock")
    lock.write_bytes(b"")
    lock.chmod(0o600)
    with pytest.raises(MixedInitialApplyAttention, match="process or retained state"):
        reconcile_mixed_initial_apply_phase(
            ready.parent, child, provider, source.workspace,
            process_quiescent=lambda identity: False, job_repository=ready.case.jobs,
            lease_lookup=ready.args["lease_lookup"])
    # Reconcile only after the old claim expires; the failed attempt claimed it.
    with ready.case.jobs._connect() as connection:
        connection.execute("UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', ?) WHERE id = ?",
                           ("2020-01-01T00:00:00+00:00", child_id))
    child = ready.case.jobs.get(child_id)
    applied = reconcile_mixed_initial_apply_phase(
        ready.parent, child, provider, source.workspace,
        process_quiescent=lambda identity: True, job_repository=ready.case.jobs,
        lease_lookup=ready.args["lease_lookup"])
    assert recognize_mixed_initial_apply_result(applied, ready.parent, provider)["stage"] == "awaiting"
    assert json.loads((source.workspace.path / ".barragan-apply-phase.json").read_text())["phase"] == "applied"
    assert [row[0] for row in ready.calls].count("command-intent") == 1


def test_command_intent_interruption_is_never_replayed(ready):
    provider = ready.parent.input["orderedProviders"][0]
    ready.state["stop"] = "intent"
    with pytest.raises(RuntimeError, match="interrupted"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    child = ready.case.jobs.get(_child_id("job-core", provider))
    assert any(event.message == "mixed provider Apply command intended" for event in child.events)
    before = list(ready.calls)
    with pytest.raises(MixedInitialApplyAttention, match="not safely pre-command"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    assert ready.calls == before


@pytest.mark.parametrize("case", [True, False], indirect=True)
def test_failed_apply_keeps_private_bounded_output_without_replay(ready):
    provider = ready.parent.input["orderedProviders"][0]
    original = ready.args["gated_command_runner"]
    stdout, stderr = "Terraform output\n", "provider failure detail\n"

    def failed(command, **kwargs):
        result_callback = kwargs["result_callback"]
        kwargs["result_callback"] = lambda value: result_callback(replace(
            value, returncode=1, stdout_bytes=len(stdout), stderr_bytes=len(stderr)))
        outcome = original(command, **kwargs)
        return replace(outcome, returncode=1, stdout=stdout, stderr=stderr)

    ready.args["gated_command_runner"] = failed
    with pytest.raises(MixedInitialApplyAttention, match="result is incomplete or failed"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    child = ready.case.jobs.get(_child_id("job-core", provider))
    assert child.events[-1].message == "mixed provider Apply command result fenced"
    assert child.events[-1].data["returnCode"] == 1
    assert stderr not in json.dumps(child.input) + json.dumps([row.data for row in child.events])
    root = next((ready.case.state_root / "eng-opaque" / "provider-keyed-v2" / provider).iterdir())
    files = list(root.glob(".barragan-initial-apply-failure-*.json"))
    assert len(files) == 1
    saved = json.loads(files[0].read_text())
    assert saved["stdout"] == stdout and saved["stderr"] == stderr
    assert saved["returnCode"] == 1 and saved["invocationId"] == "a" * 32
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600
    assert not files[0].is_symlink()
    assert not list(root.glob(".barragan-apply-output-*"))
    source = ready.args["source_session"](ready.parent, provider, lambda: None).__enter__()
    reopened = prepare_provider_keyed_workspace(
        "eng-opaque", provider, source.workspace.provider_connection_id,
        template_root=ready.case.args["template_root"],
        source_revision=source.workspace.source_revision,
        root=ready.case.state_root, environment="devtest",
        deployment_target="barragan-testing")
    assert reopened.path == root
    before = list(ready.calls)
    with pytest.raises(MixedInitialApplyAttention, match="not safely pre-command"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    assert ready.calls == before


def test_failed_apply_diagnostic_never_overwrites_symlink_or_changes_attention(ready, monkeypatch):
    provider = ready.parent.input["orderedProviders"][0]
    source = ready.args["source_session"](ready.parent, provider, lambda: None).__enter__()
    root = source.workspace.path
    sentinel = root / "sentinel"
    sentinel.write_text("keep")
    destination = root / (".barragan-initial-apply-failure-" + "a" * 32 + ".json")
    destination.symlink_to(sentinel)
    outcome = CommandResult(
        StartedCommand(CommandIntent("a" * 32, str(root), "b" * 64),
                       ProcessIdentity("boot", 123, 123, 99)),
        1, "out", "err", False, False)
    with pytest.raises(FileExistsError):
        child_service._save_failed_apply_output(source.workspace, outcome)
    assert sentinel.read_text() == "keep" and destination.is_symlink()
    assert not list(root.glob(".barragan-apply-output-*"))

    def failed(command, **kwargs):
        result_callback = kwargs["result_callback"]
        kwargs["result_callback"] = lambda value: result_callback(replace(value, returncode=1))
        original = ready_runner
        return replace(original(command, **kwargs), returncode=1, stderr="private failure")

    ready_runner = ready.args["gated_command_runner"]
    ready.args["gated_command_runner"] = failed
    with pytest.raises(MixedInitialApplyAttention, match="result is incomplete or failed"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    assert sentinel.read_text() == "keep"
    assert ready.case.jobs.get(_child_id("job-core", provider)).events[-1].data["returnCode"] == 1


@pytest.mark.parametrize("case", [False], indirect=True)
def test_selector_post_interruption_remains_tag_only_attention(ready):
    provider = "digitalocean"
    assert ready.parent.input["orderedProviders"][0] == provider
    ready.state["stop"] = "post"
    with pytest.raises(RuntimeError, match="interrupted selector"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    child = ready.case.jobs.get(_child_id("job-core", provider))
    assert any(event.message == "mixed selector POST intended" for event in child.events)
    assert not any(event.message == "mixed provider Apply command intended" for event in child.events)
    with pytest.raises(MixedInitialApplyAttention, match="not safely pre-command"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)


@pytest.mark.parametrize("case", [False], indirect=True)
def test_selector_tag_drift_rejects_before_post_intent(ready):
    source_session = ready.args["source_session"]
    ready.args["source_session"] = lambda parent, provider, renew: nullcontext(replace(
        source_session(parent, provider, renew).__enter__(), selector_tag="wrong-selector"))
    with pytest.raises(MixedInitialApplyAttention, match="selector source"):
        run_mixed_initial_provider_apply(provider="digitalocean", **ready.args)
    assert not any(row[0] == "selector-post" for row in ready.calls)
    assert not any(event.message == "mixed selector POST intended" for event in
                   ready.case.jobs.get(_child_id("job-core", "digitalocean")).events)


@pytest.mark.parametrize("drift", ["verb", "plan-bytes"])
def test_wrong_command_or_changed_saved_plan_rejects_before_intent(ready, drift):
    provider = ready.parent.input["orderedProviders"][0]
    source_session = ready.args["source_session"]
    def changed(parent, selected, renew):
        source = source_session(parent, selected, renew).__enter__()
        if drift == "verb":
            return replace(source, command=(source.command[0], "destroy", *source.command[2:]))
        Path(source.command[-1]).write_bytes(b"changed after reviewed receipt")
        return source
    ready.args["source_session"] = lambda parent, selected, renew: nullcontext(
        changed(parent, selected, renew))
    with pytest.raises(MixedInitialApplyAttention, match="saved plan source"):
        run_mixed_initial_provider_apply(provider=provider, **ready.args)
    assert not any(row[0] in {"selector-post", "command-intent"} for row in ready.calls)


def test_sqlalchemy_append_and_finish_cas_require_initial_core_lease():
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        repo = SqlAlchemyJobRepository()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-1", owner_id="plan-1", operation="provider_keyed_initial"))
        db.session.commit()
        now = datetime.now(timezone.utc)
        at = now.isoformat()
        later = (now + timedelta(minutes=5)).isoformat()
        base = {"engagementId": "eng-1", "coreJobId": "job-core", "corePlanId": "plan-1",
                "mixedParentId": "job-parent", "sealJournalSha256": "a" * 64,
                "provider": "linode", "providerIndex": 0, "chainId": "chain-1",
                "receiptSha256": "b" * 64, "mutation": True}
        job = StoredJobRun(
            "job-mixed", "provider_keyed_mixed_initial_apply_child", "running",
            "engagement:eng-1", "engagement", "eng-1", "operator", base, [],
            at, at, None, [JobEvent(1, "info", "queued", {}), JobEvent(2, "info", "started", {})])
        repo.save(job)
        current = repo.claim_lease(job.id, owner="worker", token="token", claimed_at=at,
                                   expires_at=later, eligible_statuses={"running"})
        assert current is not None
        from sqlalchemy import text
        db.session.execute(text("""UPDATE core_mutation_leases SET operation = 'provider_keyed_teardown_fence'
            WHERE engagement_id = 'eng-1'"""))
        db.session.commit()
        def append(value):
            return repo.append_event_if_running_claimed(
                value, owner="worker", token="token",
                expected_event_digest=job_event_digest(value.events),
                heartbeat_at=(now + timedelta(seconds=1)).isoformat(), expires_at=later,
                event=JobEvent(len(value.events) + 1, "info", "intent", {}))
        assert append(current) is None
        assert len(repo.get(job.id).events) == 2
        db.session.execute(text("""UPDATE core_mutation_leases SET operation = 'provider_keyed_initial'
            WHERE engagement_id = 'eng-1'"""))
        db.session.commit()
        appended = append(current)
        assert appended is not None and len(appended.events) == 3
        db.session.execute(text("""UPDATE core_mutation_leases SET operation = 'provider_keyed_teardown_fence'
            WHERE engagement_id = 'eng-1'"""))
        db.session.commit()
        finished = repo.finish_if_running_claimed(
            appended, owner="worker", token="token", expected_event_digest=job_event_digest(appended.events),
            status="succeeded", finished_at=(now + timedelta(seconds=2)).isoformat(),
            event=JobEvent(4, "info", "completed", {}))
        assert finished is None
        assert repo.get(job.id).status == "running"
