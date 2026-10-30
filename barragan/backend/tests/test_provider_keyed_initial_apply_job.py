# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant apply-job orchestration; Terraform/provider calls are injected fakes."""

import hashlib
import json
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_initial_apply_job as service
from app.domain import JobEvent
from app.services.provider_keyed_plan_evidence import DecodedProviderKeyedPlanEvidence
from app.services.provider_keyed_saved_plan_runner import ProviderKeyedInitialPlanEvidence
from app.services.provider_keyed_gated_runner import (CommandAuditResult, CommandIntent, CommandResult,
    ProcessIdentity, StartedCommand, UnreapedGatedCommandError)
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.provider_keyed_selector_preflight import SelectorPreflightEvidence
from app.storage.job_repository import StoredJobRun


class Jobs:
    def __init__(self, job):
        self.current = job
        self.saved = []

    def get(self, identifier):
        return self.current if identifier == self.current.id else None

    def save(self, job):
        self.current = job
        self.saved.append(job)
        return job

    def start_if_queued(self, job, *, started_at, event):
        if (self.current.status != "queued" or self.current.action != job.action
                or self.current.input != job.input or self.current.started_at is not None
                or self.current.finished_at is not None):
            return None
        return self.save(replace(self.current, status="running", started_at=started_at,
                                 events=[*self.current.events, event]))

    def finish_if_running(self, job, *, status, finished_at, event):
        if (self.current.status != "running" or self.current.action != job.action
                or self.current.input != job.input or self.current.started_at != job.started_at
                or self.current.finished_at is not None):
            return None
        return self.save(replace(self.current, status=status, finished_at=finished_at,
                                 events=[*self.current.events, event]))

    def claim_lease(self, job_id, *, owner, token, claimed_at, expires_at, eligible_statuses):
        if self.current.id != job_id or self.current.status not in eligible_statuses or self.current.input.get("claimOwner"):
            return None
        return self.save(replace(self.current, input={**self.current.input, "claimOwner": owner,
            "claimToken": token, "claimClaimedAt": claimed_at, "claimHeartbeatAt": claimed_at,
            "claimExpiresAt": expires_at}))

    def renew_lease(self, job_id, *, owner, token, heartbeat_at, expires_at):
        if self.current.id != job_id or self.current.input.get("claimOwner") != owner or self.current.input.get("claimToken") != token:
            return None
        return self.save(replace(self.current, input={**self.current.input,
            "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at}))

    def append_event_if_running_claimed(self, job, *, owner, token, expected_event_digest, heartbeat_at, expires_at, event):
        from app.storage.job_repository import job_event_digest
        if (self.current != job or self.current.status != "running" or
                self.current.input.get("claimOwner") != owner or self.current.input.get("claimToken") != token or
                job_event_digest(self.current.events) != expected_event_digest):
            return None
        return self.save(replace(self.current, input={**self.current.input,
            "claimHeartbeatAt": heartbeat_at, "claimExpiresAt": expires_at},
            events=[*self.current.events, event]))

    def finish_if_running_claimed(self, job, *, owner, token, expected_event_digest, status, finished_at, event):
        from app.storage.job_repository import job_event_digest
        if (self.current != job or self.current.status != "running" or
                self.current.input.get("claimOwner") != owner or self.current.input.get("claimToken") != token or
                job_event_digest(self.current.events) != expected_event_digest):
            return None
        return self.save(replace(self.current, status=status, finished_at=finished_at,
            input={k: v for k, v in self.current.input.items() if not k.startswith("claim")},
            events=[*self.current.events, event]))


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    root = tmp_path / "eng-opaque" / "provider-keyed-v2" / "digitalocean" / "fingerprint"
    material = root.parents[1] / ".plan-material" / "digitalocean"
    material.mkdir(parents=True, mode=0o700)
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    (material / "ssh-output").mkdir(mode=0o700)
    workspace = ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", "digitalocean", "connection", "fingerprint", "revision", "source",
    )
    evidence = ProviderKeyedInitialPlanEvidence(
        root / ".barragan-initial-full.tfplan", "a" * 64, "source", "b" * 64,
        "c" * 64, "d" * 64, None, ((str(material / "inputs.json"), "e" * 64),),
        "connection", "f" * 64, "today", "1.15.5", Path("/usr/bin/terraform"), "1" * 64,
    )
    public_key = "ssh-ed25519 PUBLIC-FIXTURE\n"
    decoded = DecodedProviderKeyedPlanEvidence(
        evidence, hashlib.sha256(public_key.encode()).hexdigest(),
    )
    intent = SimpleNamespace(
        engagement_id="eng-opaque", core_job_id="core-job", core_plan_id="core-plan",
        revision_id="revision", selector_tag="selector", engagement_name="opaque",
        nodes={
            'digitalocean_droplet.middle["middle_01"]': SimpleNamespace(
                name="middle01-opaque", region="nyc3", size="s-1vcpu-1gb"),
            'digitalocean_droplet.edge["sfo3-01"]': SimpleNamespace(
                name="edge-opaque-sfo3-01", region="sfo3", size="s-1vcpu-1gb"),
        },
        topology={"middles": {"middle_01": {}},
                  "edge_groups": {"sfo": {"region": "sfo3", "ordinals": [1]}}},
        firewall=object(),
    )
    job = StoredJobRun(
        id="apply-job", action=service.ACTION, status="queued",
        target="engagement:eng-opaque", target_type="engagement", target_id="eng-opaque",
        requested_by="operator", input={
            "engagementId": "eng-opaque", "coreJobId": "core-job", "corePlanId": "core-plan",
            "planJobId": "plan-job", "mutation": True,
        }, artifact_refs=[], created_at="today", started_at=None, finished_at=None,
        events=[JobEvent(1, "info", "job queued", {})],
    )
    jobs = Jobs(job)
    calls = []

    def preflight(engagement_id, core_job_id, plan_job_id, **kwargs):
        calls.append(("preflight", jobs.current.status, engagement_id, core_job_id, plan_job_id, kwargs))
        assert kwargs["lease_owner"] == "core-plan"
        assert kwargs["allowed_apply_job_id"] == "apply-job"
        assert kwargs["job_repository"] is jobs
        return intent, workspace, {"opaque": "preflight-evidence"}

    def decode(raw, current_workspace, **expected):
        calls.append(("decode", raw, expected))
        assert current_workspace is workspace
        assert expected == {
            "expected_core_job_id": "core-job", "expected_core_plan_id": "core-plan",
            "expected_revision_id": "revision", "expected_connection_id": "connection",
            "expected_selector_tag": "selector",
        }
        return decoded

    monkeypatch.setattr(service, "decode_preflight_initial_plan_evidence", decode)
    monkeypatch.setattr(service, "retrieve_sketch_ssh_key", lambda *a: SimpleNamespace(
        private_key="PRIVATE-FIXTURE", public_key=public_key,
    ))
    monkeypatch.setattr(service, "_credential_snapshot", lambda *a: ("f" * 64, "today", "encrypted"))
    monkeypatch.setattr(service, "decrypt_secret_value", lambda *_: "provider-token")
    class LiveCatalog:
        def request(self, base_url, method, path, token):
            calls.append(("catalog", base_url, method, path))
            assert (base_url, method, path, token) == (
                "https://api.digitalocean.com/v2", "GET", "/regions?per_page=200",
                "provider-token")
            return {"regions": [{"slug": region, "available": True,
                                "sizes": ["s-1vcpu-1gb"]} for region in ("nyc3", "sfo3")], "links": {}, "meta": {"total": 2}}
    def reserve(selector, token, *, fence, on_intent, on_receipt, **_):
        assert selector == "selector" and token == "provider-token"
        fence()
        on_intent()
        fence()
        on_receipt(201, selector)
        fence()
        return ("droplets",)
    monkeypatch.setattr(service, "reserve_and_verify_selector", reserve)

    def apply(current_workspace, current_evidence, **kwargs):
        calls.append(("apply", jobs.current.status, kwargs))
        assert current_workspace is workspace and current_evidence is evidence
        private, public = material / "admin-private", material / "admin-public"
        assert private.read_text() == "PRIVATE-FIXTURE"
        assert public.read_text() == public_key
        assert stat.S_IMODE(private.stat().st_mode) == 0o600
        assert stat.S_IMODE(public.stat().st_mode) == 0o600
        assert kwargs["expected_nodes"] is intent.nodes
        assert kwargs["expected_firewall"] is intent.firewall
        assert kwargs["expected_ssh_key_name"] == "do-key"
        assert kwargs["expected_ssh_public_key"] == public_key.strip()
        assert kwargs["engagement_tag"] == "opaque"
        assert kwargs["expected_local_files"]["local_file.ansible_inventory[0]"]["content"].startswith("[all:vars]\n")
        assert kwargs["expected_local_files"]["local_file.ssh_stanza[0]"]["filename"] == str(material / "ssh-output" / "opaque-sketch")
        shown = kwargs["command_runner"](["/usr/bin/terraform", "show", "-json", str(evidence.plan_path)], root, {})
        assert shown.stdout == '{"planned_values":{}}'
        kwargs["selector_absence_callback"](SelectorPreflightEvidence(0, 0, 0))
        kwargs["selector_reservation_callback"]()
        kwargs["command_runner"](["/usr/bin/terraform", "apply", "-input=false", "-lock=true", "-no-color",
                                  str(evidence.plan_path)], root, {})
        return SimpleNamespace(state_sha256="2" * 64, selector="selector", attachment_proof_pending=True)

    def gated_runner(args, *, scratch_path, intent_callback, started_callback, heartbeat_callback,
                     result_callback, max_output_bytes, **_):
        assert args == (["/usr/bin/terraform", "show", "-json", str(evidence.plan_path)]
                        if args[1] == "show" else
                        ["/usr/bin/terraform", "apply", "-input=false", "-lock=true", "-no-color",
                         str(evidence.plan_path)])
        assert max_output_bytes == (16 * 1024 * 1024 if args[1] == "show" else 65536)
        intent_record = CommandIntent(
            "invocation-" + args[1], str(scratch_path),
            hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
        )
        started = StartedCommand(intent_record, ProcessIdentity("boot", 1001, 1001, 42))
        intent_callback(intent_record)
        started_callback(started)
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
        return CommandResult(started, 0, '{"planned_values":{}}' if args[1] == "show" else "", "", False, False)

    kwargs = dict(
        environment="devtest", state_root=tmp_path / "state", job_repository=jobs,
        credential_repository=object(), ssh_key_repository=object(),
        lease_lookup=lambda _: ("core-plan", "provider_keyed_initial"),
        preflight=preflight, apply=apply,
        release_check=lambda **kw: SimpleNamespace(path=Path("/usr/bin/terraform"), sha256="1" * 64),
        gated_command_runner=gated_runner,
        catalog_transport=LiveCatalog(),
    )
    return kwargs, jobs, calls, material, intent, decoded


def test_queued_job_rechecks_running_record_then_applies_and_cleans_keys(prepared):
    kwargs, jobs, calls, material, _, _ = prepared
    result = service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert [item[0] for item in calls] == ["preflight", "preflight", "decode", "catalog", "apply"]
    assert [item[1] for item in calls if item[0] == "preflight"] == ["queued", "running"]
    assert [job.status for job in jobs.saved][-1] == "succeeded"
    assert [e.message for e in result.events[-10:]] == [
        "provider apply command intent fenced", "provider apply command started before GO",
        "provider apply command result fenced",
        "provider selector absent before initial apply",
        "provider selector creation POST intended", "provider selector creation 201 received",
        "provider apply command intent fenced", "provider apply command started before GO",
        "provider apply command result fenced", "provider saved-plan apply completed; proof pending"]
    assert [e.data["phase"] for e in result.events if e.message.startswith("provider apply command")] == [
        "show", "show", "show", "apply", "apply", "apply"]
    assert result.events[-1].data == {
        "stateSha256": "2" * 64, "selectorTag": "selector",
        "attachmentProofPending": True, "hostProofPending": True,
    }
    assert not (material / "admin-private").exists()
    assert not (material / "admin-public").exists()
    assert "PRIVATE-FIXTURE" not in str(result.events)


@pytest.mark.parametrize("unavailable_region", ["sfo3", "nyc3"])
def test_live_region_size_absence_stops_before_selector_or_terraform(prepared, unavailable_region):
    kwargs, jobs, calls, material, _, _ = prepared
    def catalog(base_url, method, path, token):
        assert (base_url, method, path, token) == (
            "https://api.digitalocean.com/v2", "GET", "/regions?per_page=200",
            "provider-token")
        calls.append(("catalog", base_url, method, path))
        return {"regions": [{"slug": region, "available": True,
                             "sizes": [] if region == unavailable_region else ["s-1vcpu-1gb"]}
                            for region in ("nyc3", "sfo3")], "links": {}, "meta": {"total": 2}}

    kwargs["catalog_transport"] = SimpleNamespace(request=catalog)
    with pytest.raises(service.ProviderKeyedInitialApplyJobError,
                       match=f"size s-1vcpu-1gb is unavailable in region {unavailable_region}"):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)

    assert [item[0] for item in calls] == ["preflight", "preflight", "decode", "catalog"]
    assert jobs.current.status == "failed"
    assert jobs.current.events[-1].message.endswith("no provider mutation started")
    assert all("selector" not in event.message and "command" not in event.message
               for event in jobs.current.events)
    assert not (material / "admin-private").exists()
    assert not (material / "admin-public").exists()


def test_incomplete_region_catalog_stops_before_mutation(prepared):
    kwargs, jobs, calls, material, _, _ = prepared
    kwargs["catalog_transport"] = SimpleNamespace(request=lambda *_: {
        "regions": [{"slug": "nyc3", "available": True, "sizes": ["s-1vcpu-1gb"]}],
        "links": {"pages": {"next": "https://api.digitalocean.com/v2/regions?page=2"}},
    })

    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert [item[0] for item in calls] == ["preflight", "preflight", "decode"]
    assert jobs.current.status == "failed"
    assert all("selector" not in event.message and "command" not in event.message
               for event in jobs.current.events)
    assert not (material / "admin-private").exists()


def test_ambiguous_selector_post_intent_is_one_shot_and_never_runs_apply(prepared, monkeypatch):
    kwargs, jobs, _, _, _, _ = prepared
    gate_calls = []
    original_gate = kwargs["gated_command_runner"]

    def gate(args, **fields):
        gate_calls.append(args[1])
        return original_gate(args, **fields)

    def ambiguous(selector, token, *, fence, on_intent, on_receipt, **_):
        fence()
        on_intent()
        raise TimeoutError("provider response may have been committed")

    monkeypatch.setattr(service, "reserve_and_verify_selector", ambiguous)
    kwargs["gated_command_runner"] = gate
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert gate_calls == ["show"]
    assert jobs.current.status == "failed"
    assert [event.message for event in jobs.current.events].count(
        "provider selector creation POST intended") == 1
    assert not any(event.message == "provider selector creation 201 received"
                   for event in jobs.current.events)
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert gate_calls == ["show"]


def test_credential_drift_during_selector_reservation_stops_apply(prepared, monkeypatch):
    kwargs, jobs, _, _, _, _ = prepared
    gate_calls = []
    original_gate = kwargs["gated_command_runner"]
    kwargs["gated_command_runner"] = lambda args, **fields: (
        gate_calls.append(args[1]) or original_gate(args, **fields))
    snapshots = 0

    def snapshot(*_):
        nonlocal snapshots
        snapshots += 1
        return (("f" if snapshots < 4 else "0") * 64, "today", "encrypted")

    monkeypatch.setattr(service, "_credential_snapshot", snapshot)
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert gate_calls == ["show"]
    assert jobs.current.status == "failed"
    assert any(event.message == "provider selector creation POST intended"
               for event in jobs.current.events)


@pytest.mark.parametrize("failure", ["first_preflight", "second_preflight", "key_rotation", "existing_key", "apply"])
def test_failure_is_redacted_and_cleans_only_owned_files(prepared, monkeypatch, failure):
    kwargs, jobs, calls, material, _, _ = prepared
    if failure in {"first_preflight", "second_preflight"}:
        original = kwargs["preflight"]
        count = 0
        def fail_preflight(*args, **kw):
            nonlocal count
            count += 1
            if count == (1 if failure == "first_preflight" else 2):
                raise ValueError("SECRET")
            return original(*args, **kw)
        kwargs["preflight"] = fail_preflight
    elif failure == "key_rotation":
        monkeypatch.setattr(service, "retrieve_sketch_ssh_key", lambda *a: SimpleNamespace(
            private_key="PRIVATE-FIXTURE", public_key="rotated",
        ))
    elif failure == "existing_key":
        (material / "admin-private").write_text("USER-OWNED")
    else:
        kwargs["apply"] = lambda *a, **kw: (_ for _ in ()).throw(ValueError("SECRET"))
    with pytest.raises(service.ProviderKeyedInitialApplyJobError) as error:
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert "SECRET" not in str(error.value)
    assert jobs.current.status == ("queued" if failure == "first_preflight" else "failed")
    assert jobs.current.events[-1].data == {}
    assert not (material / "admin-public").exists()
    if failure == "existing_key":
        assert (material / "admin-private").read_text() == "USER-OWNED"
    else:
        assert not (material / "admin-private").exists()
    if failure == "first_preflight":
        assert jobs.saved == []
        assert jobs.current.status == "queued"
    if failure == "second_preflight":
        assert [job.status for job in jobs.saved] == ["running", "failed"]


@pytest.mark.parametrize("change", [
    {"status": "running"}, {"action": "other"}, {"target_id": "other"},
    {"input": {"engagementId": "eng-opaque", "coreJobId": "core-job", "corePlanId": "core-plan", "planJobId": "plan-job", "mutation": False}},
    {"input": {"engagementId": "eng-opaque", "coreJobId": "core-job", "corePlanId": "core-plan", "planJobId": "plan-job", "mutation": True, "extra": "value"}},
])
def test_invalid_or_running_job_never_preflights(prepared, change):
    from dataclasses import replace

    kwargs, jobs, calls, material, _, _ = prepared
    jobs.current = replace(jobs.current, **change)
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert not jobs.saved and not calls
    assert not (material / "admin-private").exists()


def test_losing_apply_worker_stops_without_overwriting_winner(prepared):
    kwargs, jobs, calls, material, _, _ = prepared
    queued = jobs.current

    def lost_claim(_job, *, started_at, event):
        jobs.current = replace(queued, status="running", started_at=started_at,
                               events=[*queued.events, event])
        return None

    jobs.start_if_queued = lost_claim
    with pytest.raises(service.ProviderKeyedInitialApplyJobError, match="already claimed"):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)

    assert [item[0] for item in calls] == ["preflight"]
    assert jobs.current.status == "running"
    assert jobs.saved == []
    assert not (material / "admin-private").exists()
    assert not (material / "admin-public").exists()


def test_claim_error_is_redacted_and_does_not_mark_queued_job_failed(prepared):
    kwargs, jobs, calls, material, _, _ = prepared

    def fail_claim(*_args, **_kwargs):
        raise RuntimeError("SECRET database failure")

    jobs.start_if_queued = fail_claim
    with pytest.raises(service.ProviderKeyedInitialApplyJobError) as error:
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)

    assert "SECRET" not in str(error.value)
    assert [item[0] for item in calls] == ["preflight"]
    assert jobs.current.status == "queued" and jobs.saved == []
    assert not (material / "admin-private").exists()


@pytest.mark.parametrize("outcome", ["success", "failure"])
def test_recovery_terminal_writer_cannot_be_overwritten_by_apply_worker(prepared, outcome):
    kwargs, jobs, calls, material, _, _ = prepared
    original_apply = kwargs["apply"]

    def racing_apply(*args, **kw):
        result = original_apply(*args, **kw)
        jobs.current = replace(jobs.current, status="reconciliation_required",
                               finished_at="2026-10-07T00:03:00+00:00",
                               events=[*jobs.current.events,
                                       JobEvent(len(jobs.current.events) + 1, "error", "recovery owns terminal", {})])
        if outcome == "failure":
            raise ValueError("provider failure")
        return result

    kwargs["apply"] = racing_apply
    with pytest.raises(service.ProviderKeyedInitialApplyJobError, match="reconciliation required"):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)

    assert jobs.current.status == "reconciliation_required"
    assert jobs.current.events[-1].message == "recovery owns terminal"
    assert all(job.status == "running" for job in jobs.saved)
    assert not (material / "admin-private").exists()
    assert not (material / "admin-public").exists()


@pytest.mark.parametrize("failure", ["unlink", "replacement"])
def test_key_cleanup_failure_never_records_success(prepared, monkeypatch, failure):
    kwargs, jobs, calls, material, _, _ = prepared
    original_apply = kwargs["apply"]
    private = material / "admin-private"
    if failure == "unlink":
        original_unlink = Path.unlink

        def fail_unlink(path, *args, **kwargs):
            if path == private:
                raise OSError("SECRET cleanup failure")
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail_unlink)
    else:
        def replace_key(*args, **kwargs):
            result = original_apply(*args, **kwargs)
            private.unlink()
            private.write_text("UNOWNED REPLACEMENT")
            return result

        kwargs["apply"] = replace_key
    with pytest.raises(service.ProviderKeyedInitialApplyJobError) as error:
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert "SECRET" not in str(error.value)
    assert jobs.current.status == "failed"
    assert "key-material cleanup and reconciliation required" in jobs.current.events[-1].message
    assert not any(job.status == "succeeded" for job in jobs.saved)
    assert not (material / "admin-public").exists()
    if failure == "replacement":
        assert private.read_text() == "UNOWNED REPLACEMENT"


def test_start_gate_failure_never_executes_and_retains_staged_keys(prepared):
    kwargs, jobs, _, material, _, _ = prepared
    invoked = []

    def stopped_runner(args, *, scratch_path, intent_callback, started_callback, **_):
        intent = CommandIntent("attempt", str(scratch_path), "a" * 64)
        intent_callback(intent)
        started_callback(StartedCommand(intent, ProcessIdentity("boot", 1001, 1001, 42)))
        invoked.append("no-GO")
        raise RuntimeError("start gate rejected before GO")

    kwargs["gated_command_runner"] = stopped_runner
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert invoked == ["no-GO"]
    assert jobs.current.status == "failed"
    assert [e.message for e in jobs.current.events[-3:-1]] == [
        "provider apply command intent fenced", "provider apply command started before GO"]
    assert (material / "admin-private").exists()
    assert (material / "admin-public").exists()
    assert jobs.current.input == {
        "engagementId": "eng-opaque", "coreJobId": "core-job", "corePlanId": "core-plan",
        "planJobId": "plan-job", "mutation": True,
    }


def test_unreaped_process_keeps_keys_and_never_replays(prepared):
    kwargs, jobs, calls, material, _, _ = prepared

    def unreaped(args, *, scratch_path, intent_callback, started_callback, **_):
        intent = CommandIntent("attempt", str(scratch_path), "a" * 64)
        intent_callback(intent)
        started_callback(StartedCommand(intent, ProcessIdentity("boot", 1001, 1001, 42)))
        raise UnreapedGatedCommandError("unproved group")

    kwargs["gated_command_runner"] = unreaped
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert jobs.current.status == "running"
    assert jobs.current.events[-1].message == "provider apply command started before GO"
    assert jobs.current.input["claimToken"]
    assert (material / "admin-private").exists()
    prior = len(calls)
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert len(calls) == prior


def test_lost_claim_before_intent_blocks_command_and_terminal_overwrite(prepared):
    kwargs, jobs, _, material, _, _ = prepared
    original_apply = kwargs["apply"]

    def stale_apply(*args, **kw):
        jobs.current = replace(jobs.current, input={**jobs.current.input, "claimToken": "recovery-token"})
        return original_apply(*args, **kw)

    kwargs["apply"] = stale_apply
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert jobs.current.status == "running"
    assert jobs.current.input["claimToken"] == "recovery-token"
    assert not any("command intent" in e.message for e in jobs.current.events)
    assert not (material / "admin-private").exists()


def test_result_audit_failure_after_reaped_apply_blocks_replay_and_keeps_keys(prepared):
    kwargs, jobs, _, material, _, _ = prepared
    original_append = jobs.append_event_if_running_claimed

    def lose_result(job, **fields):
        if (fields["event"].message == "provider apply command result fenced"
                and fields["event"].data["phase"] == "apply"):
            return None
        return original_append(job, **fields)

    jobs.append_event_if_running_claimed = lose_result
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert jobs.current.status == "failed"
    assert [event.message for event in jobs.current.events][-2:] == [
        "provider apply command started before GO",
        "provider apply command completion audit unproved; staged keys retained for reconciliation",
    ]
    assert (material / "admin-private").exists()
    assert (material / "admin-public").exists()
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)


def test_unreaped_apply_after_gated_show_leaves_claimed_running_record(prepared):
    kwargs, jobs, _, material, _, _ = prepared
    original_gate = kwargs["gated_command_runner"]

    def gate(args, **fields):
        if args[1] == "show":
            return original_gate(args, **fields)
        intent = CommandIntent("unreaped-apply", str(fields["scratch_path"]), "a" * 64)
        fields["intent_callback"](intent)
        fields["started_callback"](StartedCommand(intent, ProcessIdentity("boot", 2002, 2002, 84)))
        raise UnreapedGatedCommandError("unproved")

    kwargs["gated_command_runner"] = gate
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert jobs.current.status == "running" and jobs.current.finished_at is None
    assert jobs.current.input["claimToken"]
    assert [(event.message, event.data.get("phase")) for event in jobs.current.events[-4:]] == [
        ("provider selector creation POST intended", None),
        ("provider selector creation 201 received", None),
        ("provider apply command intent fenced", "apply"),
        ("provider apply command started before GO", "apply"),
    ]
    assert jobs.current.events[-1].data["pid"] == 2002
    assert (material / "admin-private").exists()


def test_core_lease_loss_before_success_cannot_finish_apply(prepared):
    kwargs, jobs, _, material, _, _ = prepared
    lease = ["provider_keyed_initial"]
    kwargs["lease_lookup"] = lambda _: ("core-plan", lease[0])
    original_apply = kwargs["apply"]

    def lose_lease(*args, **fields):
        result = original_apply(*args, **fields)
        lease[0] = "provider_keyed_teardown_fence"
        return result

    kwargs["apply"] = lose_lease
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert jobs.current.status == "failed"
    assert not any(job.status == "succeeded" for job in jobs.saved)
    assert not (material / "admin-private").exists()


def test_truncated_gated_show_never_starts_apply(prepared):
    kwargs, jobs, _, material, _, _ = prepared
    original_gate = kwargs["gated_command_runner"]
    invocations = []

    def truncated(args, **fields):
        invocations.append(args[1])
        result = original_gate(args, **fields)
        return replace(result, stdout_truncated=True)

    kwargs["gated_command_runner"] = truncated
    with pytest.raises(service.ProviderKeyedInitialApplyJobError):
        service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert invocations == ["show"]
    assert jobs.current.status == "failed"
    assert not (material / "admin-private").exists()
