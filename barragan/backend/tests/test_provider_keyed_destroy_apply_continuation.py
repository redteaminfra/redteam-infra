# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot destroy continuation; all provider and Terraform I/O stubbed."""

from types import SimpleNamespace
import hashlib
import urllib.error

import pytest

from app.services import provider_keyed_destroy_apply_continuation as service
from app.services import observer_checks
from app.services.provider_keyed_inspector_provider_proof import InspectorProviderProof


class Jobs:
    def __init__(self, parent, coordinator, applied=None):
        self.rows = {parent.id: parent, coordinator.id: coordinator}
        if applied is not None:
            self.rows[applied.id] = applied

    def get(self, job_id):
        return self.rows.get(job_id)

    def list_for_engagement(self, _engagement_id):
        return list(self.rows.values())


def _fixture(tmp_path, monkeypatch, *, applied=None):
    root = tmp_path / "state"
    root.mkdir()
    monkeypatch.setattr(service, "_default_state_root", lambda: root)
    parent = SimpleNamespace(id="job-parent", target_id="engagement-1",
                             action="engagement_teardown")
    core = SimpleNamespace(id="job-core", input={"corePlanId": "plan-1"})
    snapshot = {"snapshotId": "snapshot-1", "providerScopeSha256": "scope-1"}
    coordinator = SimpleNamespace(
        id=service._child_id(core.id), action=service.COORDINATOR_ACTION,
        status="running", input={"phase": "inspector_ready"},
        events=[SimpleNamespace(message="published_inspector_ready")],
    )
    jobs = Jobs(parent, coordinator, applied)
    monkeypatch.setattr(service, "_boundary", lambda *_args: (
        jobs.get(parent.id), core, snapshot, service._FENCE))
    calls = []

    def ready(*_args, **_kwargs):
        calls.append("ready")
        return SimpleNamespace(coordinator_job_id=coordinator.id)

    def preview(*_args, **_kwargs):
        calls.append("preview")
        return SimpleNamespace(
            teardown_parent_id=parent.id, core_job_id=core.id,
            core_plan_id="plan-1", scope_snapshot_id="snapshot-1",
            provider_scope_sha256="scope-1",
            preview_job_id="job-provider-keyed-initial-destroy-plan-core",
        )

    def apply(*_args, **_kwargs):
        calls.append("apply")
        result = SimpleNamespace(
            id="job-provider-keyed-initial-destroy-apply-core",
            action=service.APPLY_ACTION, status="succeeded",
        )
        jobs.rows[result.id] = result
        return result

    def absence(*_args, **_kwargs):
        calls.append("absence")
        return object()

    opts = dict(
        environment="devtest", state_root=root, job_repository=jobs,
        plan_repository=object(), lease_lookup=lambda _id: ("plan-1", service._FENCE),
        fresh_ready_recognizer=ready, preview_recognizer=preview,
        apply_runner=apply, absence_reconciler=absence,
    )
    return parent, core, coordinator, jobs, calls, opts


def test_first_apply_requires_saved_preview_and_fresh_ready_twice(tmp_path, monkeypatch):
    parent, _core, _coordinator, jobs, calls, opts = _fixture(tmp_path, monkeypatch)
    result = service.continue_digitalocean_keyed_destroy_apply(parent.id, **opts)
    assert result is not None
    assert calls == ["ready", "preview", "ready", "apply", "ready", "absence"]
    assert jobs.get(parent.id) == parent


@pytest.mark.parametrize("status", ["queued", "running", "failed"])
def test_existing_non_success_child_never_replays(tmp_path, monkeypatch, status):
    child = SimpleNamespace(
        id="job-provider-keyed-initial-destroy-apply-core",
        action=service.APPLY_ACTION, status=status,
    )
    parent, _core, _coordinator, _jobs, calls, opts = _fixture(
        tmp_path, monkeypatch, applied=child)
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.continue_digitalocean_keyed_destroy_apply(parent.id, **opts)
    assert calls == ["ready"]


def test_successful_saved_apply_goes_directly_to_read_only_absence(tmp_path, monkeypatch):
    child = SimpleNamespace(
        id="job-provider-keyed-initial-destroy-apply-core",
        action=service.APPLY_ACTION, status="succeeded",
    )
    parent, _core, _coordinator, _jobs, calls, opts = _fixture(
        tmp_path, monkeypatch, applied=child)
    service.continue_digitalocean_keyed_destroy_apply(parent.id, **opts)
    assert calls == ["ready", "ready", "absence"]


def test_absence_not_yet_visible_keeps_one_shot_success(tmp_path, monkeypatch):
    parent, _core, _coordinator, jobs, calls, opts = _fixture(tmp_path, monkeypatch)

    def delayed(*_args, **_kwargs):
        calls.append("absence")
        raise TimeoutError("provider still converging")

    opts["absence_reconciler"] = delayed
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.continue_digitalocean_keyed_destroy_apply(parent.id, **opts)
    assert calls.count("apply") == 1
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.continue_digitalocean_keyed_destroy_apply(parent.id, **opts)
    assert calls.count("apply") == 1
    assert jobs.get("job-provider-keyed-initial-destroy-apply-core").status == "succeeded"


def test_stale_inspector_ready_after_preview_never_applies(tmp_path, monkeypatch):
    parent, _core, coordinator, jobs, calls, opts = _fixture(tmp_path, monkeypatch)

    def preview_and_drift(*args, **kwargs):
        bound = _fixture_preview(parent)
        jobs.rows[coordinator.id] = SimpleNamespace(
            **{**vars(coordinator), "input": {"phase": "attention"}})
        calls.append("preview")
        return bound

    opts["preview_recognizer"] = preview_and_drift
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.continue_digitalocean_keyed_destroy_apply(parent.id, **opts)
    assert "apply" not in calls and "absence" not in calls


def _fixture_preview(parent):
    return SimpleNamespace(
        teardown_parent_id=parent.id, core_job_id="job-core", core_plan_id="plan-1",
        scope_snapshot_id="snapshot-1", provider_scope_sha256="scope-1",
        preview_job_id="job-provider-keyed-initial-destroy-plan-core",
    )


def test_duplicate_or_mismatched_apply_child_blocks_absence(tmp_path, monkeypatch):
    parent, _core, _coordinator, jobs, calls, opts = _fixture(tmp_path, monkeypatch)
    jobs.rows["job-provider-keyed-initial-destroy-apply-core"] = SimpleNamespace(
        id="job-provider-keyed-initial-destroy-apply-core",
        action=service.APPLY_ACTION, status="succeeded")
    jobs.rows["other"] = SimpleNamespace(
        id="other", action=service.APPLY_ACTION, status="succeeded")
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.continue_digitalocean_keyed_destroy_apply(parent.id, **opts)
    assert calls == ["ready"]


def test_environment_gate_rejects_before_any_reader(tmp_path, monkeypatch):
    parent, _core, _coordinator, _jobs, calls, opts = _fixture(tmp_path, monkeypatch)
    opts["environment"] = "prod"
    with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
        service.continue_digitalocean_keyed_destroy_apply(parent.id, **opts)
    assert calls == []


@pytest.mark.parametrize("resolved_source,provider_ips,expected_ssh,expected_success", [
    ("8.8.8.8/32", ("203.0.113.8", "203.0.113.8"), True, True),
    ("1.1.1.1/32", ("203.0.113.8",), False, False),
    ("error", ("203.0.113.8",), False, False),
    ("8.8.8.8/32", ("203.0.113.9",), False, False),
    ("8.8.8.8/32", ("203.0.113.8", "203.0.113.9"), True, False),
])
def test_live_proof_uses_exact_ready_inspector_selected_source_and_fences(
        tmp_path, monkeypatch, resolved_source, provider_ips, expected_ssh,
        expected_success):
    parent = SimpleNamespace(id="job-parent", target_id="engagement-1")
    core = SimpleNamespace(id="job-core")
    child = SimpleNamespace(
        id=service._child_id(core.id), action=service.COORDINATOR_ACTION,
        status="running", input={"phase": "inspector_ready"},
        events=[SimpleNamespace(message="selected-source proof",
                                data={"selectedSourceSshPolicySha256": "a" * 64})],
    )
    jobs = Jobs(parent, child)
    host = SimpleNamespace(
        resource_id="host-1", public_ip="203.0.113.8", provider="linode",
        metadata={"providerFirewall": {
            "resourceId": "firewall-1", "managementSourceCidr": "8.8.8.8/32"}},
    )
    settings = SimpleNamespace(current_host={"resourceId": "host-1"}, size="small")
    selected = SimpleNamespace(status="active", is_default=True,
                               encrypted_secret="encrypted")
    records = {
        "host-record": SimpleNamespace(
            resource_id="host-1", provider="linode", metadata={"publicIp": host.public_ip}),
        "firewall-record": SimpleNamespace(resource_id="firewall-1"),
    }
    monkeypatch.setattr(service, "_boundary", lambda *_args: (
        parent, core, {}, service._FENCE))
    monkeypatch.setattr(service, "recognize_published_keyed_inspector_readiness",
                        lambda *_args, **_kwargs: SimpleNamespace(
                            coordinator_job_id=child.id, host_record_id="host-record",
                            firewall_record_id="firewall-record"))
    monkeypatch.setattr(service, "_inspector_host_from_settings", lambda *_args, **_kwargs: host)
    public = b"ssh-ed25519 AAAA\n"
    private = tmp_path / "id_ed25519"
    private.write_text("unused-by-stub")
    private.with_suffix(".pub").write_bytes(public)
    private.with_suffix(".pub").chmod(0o600)
    monkeypatch.setattr(service, "_safe_key_identity", lambda *_args: (
        str(private), hashlib.sha256(public.strip()).hexdigest()))
    monkeypatch.setattr(service, "_verify_key_pair", lambda *_args: None)
    calls = []
    def ssh_proof(selected_host, key, source, fence, runner, *, timeout_seconds):
        calls.append((selected_host, key.private_key_path, source))
        assert timeout_seconds == 25
        fence()
        return "a" * 64, "Nmap version 7.94"
    monkeypatch.setattr(service, "verify_inspector_selected_source_ssh", ssh_proof)
    def exact_get(**kwargs):
        calls.append("GET")
        assert kwargs["expected_host"] is host
        assert kwargs["size"] == "small"
        assert kwargs["firewall_id"] == "firewall-1"
        assert kwargs["management_cidr"] == "8.8.8.8/32"
        assert kwargs["token"] == "token"
        kwargs["transport"].request("GET", "/linode/instances/host-1", "token")
        seen_host = SimpleNamespace(**{**vars(host), "public_ip": provider_ips[
            min(calls.count("GET") - 1, len(provider_ips) - 1)]})
        return InspectorProviderProof(seen_host, "firewall-1", "8.8.8.8/32")
    kwargs = dict(
        environment="devtest", job_repository=jobs, plan_repository=object(),
        lease_lookup=lambda _id: ("plan-1", service._FENCE),
        settings_repository=SimpleNamespace(get=lambda _id: settings),
        provider_resource_repository=SimpleNamespace(get=lambda record_id: records[record_id]),
        credential_repository=SimpleNamespace(get_default=lambda _provider: selected),
        source_resolver=(lambda: (_ for _ in ()).throw(TimeoutError("source unavailable")))
        if resolved_source == "error" else lambda: resolved_source,
        fence=lambda: calls.append("fence"),
        decrypt_secret=lambda _encrypted: "token",
        transport_factory=lambda _provider: SimpleNamespace(
            request=lambda method, path, token: calls.append((method, path, token)) or {}),
        provider_prover=exact_get,
    )
    if expected_success:
        service.prove_live_keyed_inspector_before_destroy_go(parent.id, **kwargs)
    else:
        with pytest.raises((ValueError, TimeoutError)):
            service.prove_live_keyed_inspector_before_destroy_go(parent.id, **kwargs)
    ssh_calls = [item for item in calls if isinstance(item, tuple) and item[0] is host]
    assert len(ssh_calls) == int(expected_ssh)
    if resolved_source != "8.8.8.8/32":
        assert "GET" not in calls
        assert calls.count("fence") >= 3  # initial read and before/after lookup
    else:
        assert calls.count("GET") == (2 if expected_ssh else 1)
        assert calls.index("GET") < next((index for index, item in enumerate(calls)
                                          if isinstance(item, tuple) and item[0] is host),
                                         len(calls))
    if expected_success:
        assert calls.count("fence") >= 3


def test_live_proof_is_devtest_only(tmp_path, monkeypatch):
    parent, _core, _coordinator, _jobs, calls, opts = _fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        service.prove_live_keyed_inspector_before_destroy_go(
            parent.id, environment="prod", fence=lambda: calls.append("fence"))
    assert calls == []


def test_pre_go_source_resolver_uses_one_bounded_round(monkeypatch):
    seen = []
    monkeypatch.setattr(service, "resolve_inspector_management_source_cidr",
                        lambda **kwargs: seen.append(kwargs) or "8.8.8.8/32")
    assert service._single_attempt_inspector_source() == "8.8.8.8/32"
    assert seen == [{"max_attempts": 1}]


def test_single_attempt_failure_does_not_retry_or_sleep(monkeypatch):
    calls = []
    def unavailable(_request, *, timeout):
        calls.append(timeout)
        raise urllib.error.URLError("unreachable")
    monkeypatch.setattr(observer_checks.urllib.request, "urlopen", unavailable)
    monkeypatch.setattr(observer_checks.time, "sleep",
                        lambda seconds: calls.append(("sleep", seconds)))
    with pytest.raises(observer_checks.ObserverProviderError):
        observer_checks.resolve_inspector_management_source_cidr(max_attempts=1)
    assert calls == [10]
    calls.clear()
    with pytest.raises(observer_checks.ObserverProviderError):
        observer_checks.resolve_inspector_management_source_cidr()
    assert calls == [10, ("sleep", 1), 10, ("sleep", 1), 10]
