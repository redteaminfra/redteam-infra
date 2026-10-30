# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network composition of the dormant apply job and real saved-plan helper."""

import hashlib
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_initial_apply as apply_service
import app.services.provider_keyed_initial_apply_job as job_service
import app.services.provider_keyed_gated_runner as gated_service
from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity,
    StartedCommand, UnreapedGatedCommandError,
)
from app.services.provider_keyed_plan_evidence import DecodedProviderKeyedPlanEvidence
from app.services.provider_keyed_selector_preflight import SelectorPreflightEvidence
from app.storage.job_repository import StoredJobRun
from test_provider_keyed_initial_apply import prepared as audited_prepared
from test_provider_keyed_initial_apply_job import Jobs


@pytest.fixture
def composed(tmp_path, monkeypatch, audited_prepared):
    workspace, evidence, helper_kwargs, credentials, fake_terraform, _, _ = audited_prepared
    workspace.path.chmod(0o2750)
    (workspace.path.parents[1] / ".regional-ordinals.lock").chmod(0o640)
    monkeypatch.setattr("app.services.provider_keyed_saved_plan_runner._collaborator_group_gid",
                        lambda: workspace.path.stat().st_gid)
    monkeypatch.setattr(gated_service, "_collaborator_group_gid",
                        lambda: workspace.path.stat().st_gid)
    public_key = "ssh-ed25519 fixture\n"
    intent = SimpleNamespace(
        engagement_id="eng-opaque", core_job_id="core-job", core_plan_id="core-plan",
        revision_id=workspace.source_revision, selector_tag=helper_kwargs["expected_firewall"].selector_tag,
        engagement_name="eng-opaque", nodes=helper_kwargs["expected_nodes"],
        topology={"middles": {"primary": {"region": "nyc3", "ordinal": 1}},
                  "edge_groups": {"sfo": {"region": "sfo3", "middle_node": "primary", "ordinals": [1]}},},
        firewall=helper_kwargs["expected_firewall"],
    )
    job = StoredJobRun(
        id="apply-job", action=job_service.ACTION, status="queued",
        target="engagement:eng-opaque", target_type="engagement", target_id="eng-opaque",
        requested_by="operator", input={"engagementId": "eng-opaque", "coreJobId": "core-job",
            "corePlanId": "core-plan", "planJobId": "plan-job", "mutation": True},
        artifact_refs=[], created_at="2026-10-08T00:00:00+00:00", started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "queued", {})],
    )
    jobs = Jobs(job)
    monkeypatch.setattr(apply_service, "require_new_digitalocean_selector_available",
                        lambda *a, **kw: SelectorPreflightEvidence(0, 0, 0))
    monkeypatch.setattr(job_service, "decode_preflight_initial_plan_evidence",
                        lambda *a, **kw: DecodedProviderKeyedPlanEvidence(
                            evidence, hashlib.sha256(public_key.encode()).hexdigest()))
    monkeypatch.setattr(job_service, "retrieve_sketch_ssh_key", lambda *a: SimpleNamespace(
        private_key="PRIVATE-FIXTURE", public_key=public_key))
    monkeypatch.setattr(job_service, "decrypt_secret_value", lambda encrypted: (
        "provider-token" if encrypted == "encrypted-token" else None))
    def reserve(selector, token, *, fence, on_intent, on_receipt, **_):
        assert selector == intent.selector_tag and token == "provider-token"
        fence()
        on_intent()
        fence()
        on_receipt(201, selector)
        fence()
        return ("droplets",)
    monkeypatch.setattr(job_service, "reserve_and_verify_selector", reserve)
    calls = []

    def gate(args, *, scratch_path, intent_callback, started_callback,
             heartbeat_callback, result_callback, **kwargs):
        calls.append((args[1], tuple(args)))
        assert scratch_path == workspace.path
        if (scratch_path.stat().st_mode & 0o7777) == 0o2750:
            assert gated_service._private_scratch_path(scratch_path) == workspace.path
        intent_record = CommandIntent("invocation-" + args[1], str(scratch_path), "a" * 64)
        started = StartedCommand(intent_record, ProcessIdentity("boot", 1234, 1234, 42))
        intent_callback(intent_record)
        started_callback(started)
        heartbeat_callback(started)
        completed = fake_terraform(args, scratch_path, kwargs["env"])
        result_callback(CommandAuditResult(started, completed.returncode,
            len(completed.stdout.encode()), len(completed.stderr.encode()), False, False))
        return CommandResult(started, completed.returncode, completed.stdout, completed.stderr, False, False)

    def live_regions(base_url, method, path, token):
        assert (base_url, method, path, token) == (
            "https://api.digitalocean.com/v2", "GET", "/regions?per_page=200",
            "provider-token")
        return {"regions": [
            {"slug": "nyc3", "available": True, "sizes": ["s-1vcpu-1gb"]},
            {"slug": "sfo3", "available": True, "sizes": ["s-1vcpu-1gb"]},
        ], "links": {}, "meta": {"total": 2}}

    kwargs = dict(
        environment="devtest", state_root=tmp_path / "state", job_repository=jobs,
        credential_repository=credentials, ssh_key_repository=object(),
        lease_lookup=lambda _: ("core-plan", "provider_keyed_initial"),
        preflight=lambda *a, **kw: (intent, workspace, {"reviewed": True}),
        apply=apply_service.apply_digitalocean_keyed_initial_saved_plan,
        release_check=lambda **kw: SimpleNamespace(path=evidence.terraform_binary_path,
                                                     sha256=evidence.terraform_binary_sha256),
        gated_command_runner=gate,
        catalog_transport=SimpleNamespace(request=live_regions),
    )
    return kwargs, jobs, calls, workspace, evidence, gate


def test_real_helper_uses_gated_show_then_apply_and_finishes_claimed_job(composed):
    kwargs, jobs, calls, workspace, evidence, _ = composed
    result = job_service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert [name for name, _ in calls] == ["show", "apply"]
    assert calls[0][1] == (str(evidence.terraform_binary_path), "show", "-json", str(evidence.plan_path))
    assert calls[1][1] == (str(evidence.terraform_binary_path), "apply", "-input=false", "-lock=true",
                           "-no-color", str(evidence.plan_path))
    assert result.status == "succeeded" and result.input == jobs.saved[0].input
    assert [event.data["phase"] for event in result.events if event.message.startswith("provider apply command")] == [
        "show", "show", "show", "apply", "apply", "apply"]
    material = workspace.path.parents[1] / ".plan-material" / "digitalocean"
    assert not (material / "admin-private").exists()
    assert not (material / "admin-public").exists()
    assert workspace.state_path.is_file()


def test_real_helper_unreaped_apply_does_not_replay_or_clear_keys(composed):
    kwargs, jobs, calls, workspace, _, gate = composed

    def unreaped_on_apply(args, **fields):
        if args[1] == "show":
            return gate(args, **fields)
        calls.append(("apply", tuple(args)))
        intent = CommandIntent("unreaped-apply", str(fields["scratch_path"]), "b" * 64)
        fields["intent_callback"](intent)
        fields["started_callback"](StartedCommand(intent, ProcessIdentity("boot", 2345, 2345, 84)))
        raise UnreapedGatedCommandError("uncertain")

    kwargs["gated_command_runner"] = unreaped_on_apply
    with pytest.raises(job_service.ProviderKeyedInitialApplyJobError):
        job_service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert [name for name, _ in calls] == ["show", "apply"]
    assert jobs.current.status == "running" and jobs.current.input["claimToken"]
    assert jobs.current.events[-1].data["pid"] == 2345
    material = workspace.path.parents[1] / ".plan-material" / "digitalocean"
    assert (material / "admin-private").exists()
    before = len(calls)
    with pytest.raises(job_service.ProviderKeyedInitialApplyJobError):
        job_service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert len(calls) == before


def test_real_helper_lost_apply_result_audit_stops_with_retained_state(composed):
    kwargs, jobs, calls, workspace, _, _ = composed
    original_append = jobs.append_event_if_running_claimed

    def lose_apply_result(job, **fields):
        event = fields["event"]
        if event.message == "provider apply command result fenced" and event.data["phase"] == "apply":
            return None
        return original_append(job, **fields)

    jobs.append_event_if_running_claimed = lose_apply_result
    with pytest.raises(job_service.ProviderKeyedInitialApplyJobError):
        job_service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert [name for name, _ in calls] == ["show", "apply"]
    assert jobs.current.status == "failed"
    assert jobs.current.events[-2].data["phase"] == "apply"
    assert jobs.current.events[-2].message == "provider apply command started before GO"
    assert workspace.state_path.is_file()
    material = workspace.path.parents[1] / ".plan-material" / "digitalocean"
    assert (material / "admin-private").exists()
    before = len(calls)
    with pytest.raises(job_service.ProviderKeyedInitialApplyJobError):
        job_service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert len(calls) == before
