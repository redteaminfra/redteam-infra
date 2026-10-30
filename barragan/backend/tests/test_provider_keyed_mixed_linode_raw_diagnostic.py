# Copyright (c) 2026, Oracle and/or its affiliates.
"""Raw Linode capture is separate, private, and non-replayable."""

import hashlib
import json
import stat
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_mixed_linode_diagnostic as diagnostic
from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanHostIdentityEvidence, DigitalOceanRawFirewallEvidence,
    DigitalOceanRawHostCollection, DigitalOceanRawHostSurfaceEvidence,
)
from app.services.provider_keyed_mixed_linode_diagnostic import (
    MixedLinodeDiagnosticAttention, _diagnostic_raw_runner, _job_id,
    _verify_private_raw_evidence,
)
from app.services.provider_keyed_mixed_linode_host_probe import (
    LinodeHostProbeError, LinodeRawHostCollection, LinodeRawHostIdentity,
    probe_linode_host_identity,
)
from app.services.provider_keyed_mixed_linode_raw_diagnostic import (
    capture_mixed_linode_raw_diagnostic, main,
)
from app.services.sketch_bootstrap import SketchBootstrapCoreHost
from app.services.sketch_bootstrap import render_strict_v2_sketch_identity_ssh_config
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.job_repository import StoredJobRun
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_bootstrap import _inputs
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_linode_host_probe import _inputs as probe_inputs, _metadata


def _stderr_runner_case(tmp_path, stderr, *, audit_changes=None, result_changes=None,
                        raises_after_audit=False):
    invocation = "a" * 32
    intent = CommandIntent(invocation, str(tmp_path), "b" * 64)
    started = StartedCommand(intent, ProcessIdentity("boot", 100, 100, 1))
    result = CommandResult(started, 0, "ok", stderr, False, False)
    if result_changes:
        result = replace(result, **result_changes)
    audit = CommandAuditResult(started, 0, 2, len(stderr.encode()), False, False)
    if audit_changes:
        audit = replace(audit, **audit_changes)
    fenced = []

    def delegate(_command, **kwargs):
        kwargs["result_callback"](audit)
        if raises_after_audit:
            raise RuntimeError("supervision uncertain")
        return result

    wrapped = _diagnostic_raw_runner(
        workspace=tmp_path, diagnostic_id="job-provider-keyed-mixed-linode-raw-diagnostic-core",
        role="middle", fence=lambda: fenced.append("lease"), runner=delegate)
    return wrapped, result, fenced


def test_linode_diagnostic_retains_exact_private_stderr_and_returns_vetoing_result(tmp_path):
    tmp_path.chmod(0o700)
    stderr = "sudo: unable to resolve host middle01: Name or service not known\n"
    wrapped, result, fenced = _stderr_runner_case(tmp_path, stderr)
    audits = []
    assert wrapped(["unused"], scratch_path=tmp_path,
                   result_callback=audits.append) is result
    samples = list(tmp_path.glob(".barragan-linode-stderr-*.txt"))
    assert len(samples) == 1
    bound_name = hashlib.sha256(
        ("job-provider-keyed-mixed-linode-raw-diagnostic-core\0middle\0" + "a" * 32).encode()
    ).hexdigest()
    assert samples[0].name == f".barragan-linode-stderr-{bound_name}.txt"
    assert samples[0].read_bytes() == stderr.encode()
    assert stat.S_IMODE(samples[0].stat().st_mode) == 0o600
    assert samples[0].stat().st_nlink == 1
    assert audits[0].stderr_bytes == len(stderr.encode())
    assert fenced == ["lease"]
    assert result.stderr == stderr  # The shared collector still rejects it.


def test_linode_diagnostic_zero_stderr_has_no_private_sample(tmp_path):
    tmp_path.chmod(0o700)
    wrapped, result, fenced = _stderr_runner_case(tmp_path, "")
    assert wrapped(["unused"], scratch_path=tmp_path,
                   result_callback=lambda _: None) is result
    assert list(tmp_path.iterdir()) == []
    assert fenced == []


@pytest.mark.parametrize("audit_changes,result_changes,stderr", [
    ({"stderr_bytes": 1}, None, "warning"),
    ({"stdout_bytes": 1}, None, "warning"),
    ({"started": StartedCommand(CommandIntent("c" * 32, "different", "b" * 64),
                               ProcessIdentity("boot", 100, 100, 1))}, None, "warning"),
    ({"stderr_truncated": True}, None, "warning"),
    (None, {"stderr_truncated": True}, "warning"),
    (None, {"returncode": 1}, "warning"),
    (None, None, "x" * 4097),
    (None, None, "\ufffd"),
])
def test_linode_diagnostic_never_persists_uncertain_stderr(
    tmp_path, audit_changes, result_changes, stderr,
):
    tmp_path.chmod(0o700)
    wrapped, _, _ = _stderr_runner_case(
        tmp_path, stderr, audit_changes=audit_changes, result_changes=result_changes)
    with pytest.raises(ValueError):
        wrapped(["unused"], scratch_path=tmp_path, result_callback=lambda _: None)
    assert list(tmp_path.iterdir()) == []


def test_linode_diagnostic_never_persists_after_runner_error(tmp_path):
    tmp_path.chmod(0o700)
    wrapped, _, _ = _stderr_runner_case(tmp_path, "warning", raises_after_audit=True)
    with pytest.raises(RuntimeError, match="supervision uncertain"):
        wrapped(["unused"], scratch_path=tmp_path, result_callback=lambda _: None)
    assert list(tmp_path.iterdir()) == []


def test_linode_diagnostic_never_persists_when_audit_callback_fails(tmp_path):
    tmp_path.chmod(0o700)
    wrapped, _, _ = _stderr_runner_case(tmp_path, "warning")
    def unavailable(_audit):
        raise RuntimeError("journal write failed")
    with pytest.raises(RuntimeError, match="journal write failed"):
        wrapped(["unused"], scratch_path=tmp_path, result_callback=unavailable)
    assert list(tmp_path.iterdir()) == []


def test_linode_private_sample_does_not_relax_shared_firewall_collector(
    tmp_path, monkeypatch,
):
    import app.services.provider_keyed_host_identity_probe as collector

    tmp_path.chmod(0o700)
    intent = CommandIntent("a" * 32, str(tmp_path), "b" * 64)
    started = StartedCommand(intent, ProcessIdentity("boot", 100, 100, 1))

    def delegate(command, **kwargs):
        kwargs["intent_callback"](intent)
        kwargs["started_callback"](started)
        kwargs["result_callback"](CommandAuditResult(started, 0, 2, 13, False, False))
        return CommandResult(started, 0, "ok", "sudo warning\n", False, False)

    wrapped = _diagnostic_raw_runner(
        workspace=tmp_path, diagnostic_id="job-provider-keyed-mixed-linode-raw-diagnostic-core",
        role="middle", fence=lambda: None, runner=delegate)
    monkeypatch.setattr(collector, "_regular_file_digest", lambda *a, **k: "digest")
    monkeypatch.setattr(collector, "_sketch_file_snapshot", lambda *a: ("file", 0, "digest"))
    identity = DigitalOceanHostIdentityEvidence(
        "a" * 64, "chain", "address", "123", "region", "1.1.1.1",
        "middle", "boot", "alias", "prior-invocation", "a" * 64, "b" * 64)
    with pytest.raises(ValueError, match="firewall snapshot is incomplete"):
        collector._collect_raw_firewall(
            identity, Path("/usr/bin/ssh"), tmp_path / "config", "alias", tmp_path,
            tmp_path / "core", "digest", tmp_path / "sketch",
            ("file", 0, "digest"), lambda: None, lambda _: None,
            lambda _: None, lambda _: None, lambda _: None, wrapped)
    samples = list(tmp_path.glob(".barragan-linode-stderr-*.txt"))
    assert len(samples) == 1
    assert samples[0].read_bytes() == b"sudo warning\n"


def test_raw_capture_is_private_one_shot_and_does_not_publish(ready, tmp_path, monkeypatch):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_bootstrap._sketch_file_snapshot",
        lambda path: (str(path), 0, "c" * 64),
    )
    contacted = []
    middle_ip = {"value": None}

    def probe(*, node, manifest_sha256, scratch_path, scratch_intent_callback,
              intent_callback, started_callback, heartbeat_callback,
              result_callback, fence, collect_raw, **kwargs):
        assert collect_raw is True
        fence()
        scratch_intent_callback(str(scratch_path))
        for sequence in range(4):
            invocation = f"raw-{len(contacted)}-{sequence}"
            intent = CommandIntent(invocation, str(scratch_path), "a" * 64)
            intent_callback(intent)
            started = StartedCommand(intent, ProcessIdentity("boot", 100, 100, 1))
            started_callback(started)
            heartbeat_callback(started)
            result_callback(CommandAuditResult(started, 0, 10, 0, False, False))
        contacted.append(node["hostname"])
        if node["role"] == "middle":
            middle_ip["value"] = node["publicIp"]
        predecessor = "8.8.8.8" if node["role"] == "middle" else middle_ip["value"]
        identity = LinodeRawHostIdentity(
            manifest_sha256, node["chainId"], node["terraformAddress"],
            node["providerInstanceId"], "linode/ubuntu24.04", node["region"],
            node["publicIp"], node["hostname"], "boot",
            (predecessor, 12345, node["publicIp"], 22),
            f"raw-{len(contacted)-1}-0", "a" * 64, "c" * 64,
        )
        adapted = DigitalOceanHostIdentityEvidence(
            identity.manifest_sha256, identity.chain_id, identity.terraform_address,
            identity.provider_instance_id, identity.region, identity.public_ipv4,
            identity.hostname, identity.boot_id, "selected-alias", identity.invocation_id,
            identity.core_known_hosts_sha256, identity.sketch_known_hosts_sha256,
        )
        firewall = DigitalOceanRawFirewallEvidence(
            adapted, "snapshot-1", "boot", 1, 2, (), ())
        surface = DigitalOceanRawHostSurfaceEvidence(
            adapted, "surface-1", "boot", 3, 4, predecessor,
            identity.ssh_connection, (), (), "listener", ssh_proof={})
        raw = DigitalOceanRawHostCollection(adapted, firewall, surface,
                                            replace(firewall, invocation_id="snapshot-2",
                                                    started_at_ns=5, completed_at_ns=6))
        return LinodeRawHostCollection(identity, raw)

    homebase = SketchBootstrapCoreHost("homebase", "1.1.1.1", "user", "/tmp/identity")
    proxy = SketchBootstrapCoreHost("proxy", "192.168.2.12", "user", "/tmp/identity", "8.8.8.8")
    kwargs = dict(
        job_repository=ready.case.jobs, sketch_repository=args["sketch_repository"],
        lease_lookup=ready.case.args["lease_lookup"], probe=probe,
        fresh_observer=args["fresh_observer"],
        core_hosts=lambda *a, **k: (homebase, proxy),
        core_known_hosts=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
    )
    result = capture_mixed_linode_raw_diagnostic("eng-opaque", "job-core", **kwargs)
    assert result.status == "succeeded"
    assert result.action == "provider_keyed_mixed_linode_raw_diagnostic"
    assert result.events[-1].message == "Linode raw diagnostic complete; strict policy pending"
    assert len(contacted) == 2
    assert sum(e.message == "Linode diagnostic command intended" for e in result.events) == 8
    assert ready.case.jobs.get(_job_id("job-core")) is None
    for event in result.events:
        assert "listener" not in json.dumps(event.data)
        if event.message == "Linode diagnostic identity captured":
            path = Path(event.data["evidencePath"])
            content = path.read_bytes()
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert hashlib.sha256(content).hexdigest() == event.data["evidenceSha256"]
            assert b"listener" in content
    with pytest.raises(MixedLinodeDiagnosticAttention):
        capture_mixed_linode_raw_diagnostic("eng-opaque", "job-core", **kwargs)
    assert len(contacted) == 2


def test_cli_requires_explicit_devtest_environment(monkeypatch):
    monkeypatch.delenv("BARRAGAN_ENV", raising=False)
    monkeypatch.delenv("BARRAGAN_DATA_DIR", raising=False)
    with pytest.raises(SystemExit, match="explicit DevTest"):
        main(["eng-opaque", "job-core"])


def test_cli_binds_only_explicit_devtest_sqlite_without_initialization(monkeypatch, capsys):
    import app.services.provider_keyed_mixed_linode_raw_diagnostic as sidecar
    from app.core.config import Config
    import app.core.runtime as runtime
    from app.storage.database import db

    uri = "sqlite:////var/lib/barragan/devtest-data/barragan.sqlite3"
    monkeypatch.setenv("BARRAGAN_ENV", "devtest")
    monkeypatch.setenv("BARRAGAN_DATA_DIR", "/var/lib/barragan/devtest-data")
    monkeypatch.setattr(Config, "SQLALCHEMY_DATABASE_URI", uri)
    seen = []
    database = object()
    state = object()
    monkeypatch.setattr(db, "configure", lambda value: seen.append(("db", value)) or database)
    monkeypatch.setattr(runtime, "configure_runtime",
                        lambda config, value: seen.append(("runtime", config, value)) or state)

    @contextmanager
    def context(value):
        seen.append(("enter", value))
        yield
        seen.append(("exit", value))

    monkeypatch.setattr(runtime, "runtime_context", context)
    monkeypatch.setattr(sidecar, "capture_mixed_linode_raw_diagnostic",
                        lambda *ids: seen.append(("capture", *ids)) or
                        SimpleNamespace(id="job-raw", status="succeeded"))
    assert main(["eng-opaque", "job-core"]) == 0
    assert seen == [("db", uri), ("runtime", Config, database), ("enter", state),
                    ("capture", "eng-opaque", "job-core"), ("exit", state)]
    assert capsys.readouterr().out == "job-raw succeeded\n"


@pytest.mark.parametrize("change", ["mode", "digest", "symlink"])
def test_private_raw_evidence_must_match_owner_mode_path_and_digest(tmp_path, change):
    path = tmp_path / "raw.json"
    path.write_bytes(b'{"policy_interpreted":false}')
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if change == "mode":
        path.chmod(0o644)
    elif change == "digest":
        digest = "0" * 64
    else:
        target = tmp_path / "target.json"
        path.rename(target)
        path.symlink_to(target)
    with pytest.raises(ValueError):
        _verify_private_raw_evidence(path, digest)


def test_private_raw_evidence_readback_accepts_exact_private_file(tmp_path):
    path = tmp_path / "raw.json"
    path.write_bytes(b'{"policy_interpreted":false}')
    path.chmod(0o600)
    _verify_private_raw_evidence(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_reserved_raw_diagnostic_never_replays_host_contact(ready, tmp_path):
    from app.storage.job_repository import StoredJobRun
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    prior = StoredJobRun(
        _job_id("job-core", collect_raw=True),
        "provider_keyed_mixed_linode_raw_diagnostic", "running",
        "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
        {}, [], "2026-10-15T00:00:00+00:00", None, None, [],
    )
    ready.case.jobs.save(prior)
    contacted = []
    with pytest.raises(MixedLinodeDiagnosticAttention):
        capture_mixed_linode_raw_diagnostic(
            "eng-opaque", "job-core", job_repository=ready.case.jobs,
            sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
            probe=lambda **_: contacted.append(True),
        )
    assert contacted == []


def test_default_observe_path_supplies_stable_nonempty_provider_fence(
    ready, tmp_path, monkeypatch,
):
    """Exercise the production observe branch, without injected fresh_observer."""
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)
    observed = {provider: args["fresh_observer"](None, provider, lambda: "fixture")
                for provider in ready.parent.input["orderedProviders"]}
    state_paths = {}
    generations = []

    def prove(parent, child, workspace, *, fence, process_quiescent):
        first, second = fence(), fence()
        assert type(first) is str and first and second == first
        generations.append(first)
        state_paths[workspace.state_path] = observed[workspace.provider].state_json
        return observed[workspace.provider].classification

    monkeypatch.setattr(diagnostic, "prove_mixed_initial_prior_provider_fresh", prove)
    monkeypatch.setattr(diagnostic, "_read_regular", lambda path: state_paths[path])

    def stop_before_contact(*_args, **_kwargs):
        raise RuntimeError("stop after real observe path")

    with pytest.raises(MixedLinodeDiagnosticAttention):
        capture_mixed_linode_raw_diagnostic(
            "eng-opaque", "job-core", job_repository=ready.case.jobs,
            sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
            core_known_hosts=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
            core_hosts=stop_before_contact,
            probe=lambda **_: pytest.fail("host contact was not expected"),
        )
    assert len(generations) == 2
    assert generations[0] == generations[1]
    reserved = ready.case.jobs.get(_job_id("job-core", collect_raw=True))
    assert reserved is not None and reserved.status == "running"
    assert all(e.message != "Linode diagnostic command intended" for e in reserved.events)


def test_sqlalchemy_expired_three_event_raw_job_recovers_without_new_scratch_or_contact(
    ready, tmp_path, monkeypatch,
):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)
    monkeypatch.setattr(diagnostic, "_later", lambda at: (
        datetime.fromisoformat(at) + timedelta(seconds=1)).isoformat())
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_bootstrap._sketch_file_snapshot",
        lambda path: (str(path), 0, "c" * 64),
    )
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-opaque", owner_id="plan-1",
            operation="provider_keyed_initial"))
        db.session.commit()
        persisted = SqlAlchemyJobRepository()
        raw_id = _job_id("job-core", collect_raw=True)

        class Jobs:
            def get(self, job_id):
                return persisted.get(job_id) if job_id == raw_id else ready.case.jobs.get(job_id)

            def list(self):
                rows = {row.id: row for row in ready.case.jobs.list()}
                rows.update({row.id: row for row in persisted.list()})
                return list(rows.values())

            def list_for_engagement(self, engagement_id, *, limit=None):
                rows = sorted((row for row in self.list()
                               if row.input.get("engagementId") == engagement_id),
                              key=lambda row: row.created_at, reverse=True)
                return rows if limit is None else rows[:limit]

            def __getattr__(self, name):
                return getattr(persisted, name)

        calls = []

        def before_contact(*, scratch_path, scratch_intent_callback, ssh_spec, **kwargs):
            calls.append(str(scratch_path))
            scratch_intent_callback(str(scratch_path))
            # The fixture-like spec itself must pass the real strict renderer.
            rendered = render_strict_v2_sketch_identity_ssh_config(ssh_spec)
            assert "StrictHostKeyChecking yes" in rendered
            raise RuntimeError("stop before command intent")

        homebase = SketchBootstrapCoreHost("homebase", "1.1.1.1", "user", "/tmp/identity")
        proxy = SketchBootstrapCoreHost("proxy", "192.168.2.12", "user", "/tmp/identity", "8.8.8.8")
        kwargs = dict(
            job_repository=Jobs(), sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
            fresh_observer=args["fresh_observer"],
            core_hosts=lambda *a, **k: (homebase, proxy),
            core_known_hosts=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
            probe=before_contact,
        )
        with pytest.raises(MixedLinodeDiagnosticAttention):
            capture_mixed_linode_raw_diagnostic("eng-opaque", "job-core", **kwargs)
        first = persisted.get(raw_id)
        assert first.status == "running"
        assert [event.message for event in first.events] == [
            "Linode diagnostic reserved", "Linode diagnostic started",
            "Linode diagnostic scratch intended"]
        assert len(calls) == 1 and calls[0] == first.events[2].data["scratchPath"]
        assert list(Path(calls[0]).iterdir()) == []
        time.sleep(1.1)
        with pytest.raises(MixedLinodeDiagnosticAttention):
            capture_mixed_linode_raw_diagnostic("eng-opaque", "job-core", **kwargs)
        second = persisted.get(raw_id)
        assert second.status == "running" and second.events == first.events
        assert second.input["claimToken"] != first.input["claimToken"]
        assert calls == [calls[0], calls[0]]
        assert list(Path(calls[0]).iterdir()) == []


@pytest.mark.parametrize("change", ["extra_event", "changed_event", "nonempty",
                                   "symlink", "live_claim", "extra_claim"])
def test_precommand_recovery_rejects_any_other_running_boundary(tmp_path, change):
    now = datetime.now(timezone.utc)
    at = lambda minutes: (now + timedelta(minutes=minutes)).isoformat()
    node = {"hostname": "middle01", "terraformAddress": 'linode_instance.middle["middle_01"]',
            "providerInstanceId": "123"}
    scratch = tmp_path / (".barragan-linode-diagnostic-" + "a" * 32)
    scratch.mkdir(mode=0o700)
    scratch.chmod(0o700)
    queued = StoredJobRun(
        "job-raw", "provider_keyed_mixed_linode_raw_diagnostic", "queued",
        "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
        {"engagementId": "eng-opaque", "mutation": False}, [], at(-10), None, None,
        [JobEvent(1, "info", "Linode diagnostic reserved", {})],
    )
    prior = replace(
        queued, status="running", started_at=at(-9),
        input={**queued.input, "claimOwner": "mixed-linode-diagnostic-" + "b" * 32,
               "claimToken": "c" * 32, "claimClaimedAt": at(-8),
               "claimHeartbeatAt": at(-3), "claimExpiresAt": at(-2)},
        events=[*queued.events, JobEvent(2, "info", "Linode diagnostic started", {}),
                JobEvent(3, "info", "Linode diagnostic scratch intended",
                         {**node, "scratchPath": str(scratch)})],
    )
    assert diagnostic._precommand_recovery_scratch(prior, queued, node, tmp_path) == scratch
    if change == "extra_event":
        prior = replace(prior, events=[*prior.events,
            JobEvent(4, "info", "Linode diagnostic command intended", {})])
    elif change == "changed_event":
        prior = replace(prior, events=[*prior.events[:2],
            replace(prior.events[2], data={**prior.events[2].data, "hostname": "other"})])
    elif change == "nonempty":
        (scratch / "unexpected").write_text("file")
    elif change == "symlink":
        target = tmp_path / "old-scratch"
        scratch.rename(target)
        scratch.symlink_to(target, target_is_directory=True)
    elif change == "live_claim":
        prior = replace(prior, input={**prior.input,
            "claimHeartbeatAt": at(0), "claimExpiresAt": at(1)})
    else:
        prior = replace(prior, input={**prior.input, "extra": "unsafe"})
    with pytest.raises(MixedLinodeDiagnosticAttention, match="precommand"):
        diagnostic._precommand_recovery_scratch(prior, queued, node, tmp_path)


@pytest.mark.parametrize("changed_policy", [False, True])
def test_raw_probe_reuses_strict_route_and_rejects_changed_snapshot(
    tmp_path, monkeypatch, changed_policy,
):
    args, _ = probe_inputs(tmp_path)
    node = args["node"]
    predecessor = args["ssh_spec"].middle.public_ip
    commands = []

    def runner(command, *, scratch_path, provider_keyed_v2, env,
               intent_callback, started_callback, heartbeat_callback, result_callback):
        assert provider_keyed_v2 is True
        assert command[1] == "-F"
        assert command[3] == f"barragan-bootstrap-user-{node['hostname']}"
        rendered = __import__("pathlib").Path(command[2]).read_text()
        assert "ProxyJump barragan-bootstrap-proxy,barragan-bootstrap-user-middle-01" in rendered
        assert "StrictHostKeyChecking yes" in rendered
        commands.append("metadata")
        intent = CommandIntent("metadata-1", str(scratch_path), "a" * 64)
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
        started_callback(started)
        heartbeat_callback(started)
        raw = _metadata(node, predecessor)
        result_callback(CommandAuditResult(started, 0, len(raw.encode()), 0, False, False))
        return CommandResult(started, 0, raw, "", False, False)

    def firewall(identity, *tail, expected_stderr):
        assert expected_stderr == f"sudo: unable to resolve host {node['hostname']}: Name or service not known\n"
        commands.append("firewall")
        sequence = commands.count("firewall")
        from app.services.provider_keyed_host_identity_probe import RawFirewallCommandEvidence
        content = "changed" if changed_policy and sequence == 2 else "stable"
        row = RawFirewallCommandEvidence("ufw_status_verbose",
                                         hashlib.sha256(content.encode()).hexdigest(),
                                         len(content), content)
        return DigitalOceanRawFirewallEvidence(
            identity, f"firewall-{sequence}", identity.boot_id,
            1 if sequence == 1 else 5, 2 if sequence == 1 else 6,
            (row,), ())

    def surface(identity, selected_predecessor, *tail, expected_stderr):
        assert expected_stderr == f"sudo: unable to resolve host {node['hostname']}: Name or service not known\n"
        commands.append("surface")
        assert selected_predecessor == predecessor
        return DigitalOceanRawHostSurfaceEvidence(
            identity, "surface-1", identity.boot_id, 3, 4, predecessor,
            (predecessor, 40000, node["publicIp"], 22), (), (), "listener")

    monkeypatch.setattr(
        "app.services.provider_keyed_mixed_linode_host_probe._collect_raw_firewall", firewall)
    monkeypatch.setattr(
        "app.services.provider_keyed_mixed_linode_host_probe._collect_raw_host_surface", surface)
    if changed_policy:
        with pytest.raises(LinodeHostProbeError, match="unproved"):
            probe_linode_host_identity(**{**args, "runner": runner, "collect_raw": True})
    else:
        result = probe_linode_host_identity(**{**args, "runner": runner, "collect_raw": True})
        assert result.policy_interpreted is False
        assert result.identity.provider_instance_id == node["providerInstanceId"]
    assert commands == ["metadata", "firewall", "surface", "firewall"]
