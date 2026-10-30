# Copyright (c) 2026, Oracle and/or its affiliates.
"""The Linode identity diagnostic is a one-shot, nonpublication boundary."""

import pytest
from dataclasses import replace
from datetime import datetime, timezone

import app.services.provider_keyed_mixed_linode_diagnostic as diagnostic
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_linode_host_probe import LinodeRawHostIdentity
from app.services.sketch_bootstrap import SketchBootstrapCoreHost
from app.domain import JobEvent
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_bootstrap import _inputs
from test_provider_keyed_mixed_initial_plan_parent import case


def test_sqlalchemy_queued_insert_normalization_is_exact():
    from app.services.provider_keyed_mixed_initial_host_binding import _same_inserted_job
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        queued = StoredJobRun(
            "job-provider-keyed-mixed-linode-raw-diagnostic-core",
            "provider_keyed_mixed_linode_raw_diagnostic", "queued",
            "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
            {"mutation": False}, [], datetime.now(timezone.utc).isoformat(), None, None,
            [JobEvent(1, "info", "Linode diagnostic reserved", {})],
        )
        saved = jobs.save_if_absent(queued)
        assert saved.created_at != queued.created_at  # SQLite normalizes UTC storage.
        assert _same_inserted_job(saved, queued)
        started = jobs.start_if_queued(
            saved, started_at=datetime.now(timezone.utc).isoformat(),
            event=JobEvent(2, "info", "Linode diagnostic started", {}))
        assert started is not None and started.status == "running"


def _unstarted_reservation(ready, tmp_path):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)

    class Jobs:
        refuse_start = True

        def __getattr__(self, name):
            return getattr(ready.case.jobs, name)

        def start_if_queued(self, *values, **kwargs):
            if self.refuse_start:
                return None
            return ready.case.jobs.start_if_queued(*values, **kwargs)

    jobs = Jobs()
    contacts = []

    def stop_before_contact(*_args, **_kwargs):
        contacts.append("core-host-lookup")
        raise RuntimeError("stop before host contact")

    kwargs = dict(
        environment="devtest", job_repository=jobs,
        sketch_repository=args["sketch_repository"],
        lease_lookup=ready.case.args["lease_lookup"],
        fresh_observer=args["fresh_observer"],
        core_hosts=stop_before_contact,
        core_known_hosts=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
        probe=lambda **_: pytest.fail("no host contact expected"),
    )
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic(
            "eng-opaque", "job-core", **kwargs)
    saved = jobs.get(diagnostic._job_id("job-core"))
    assert saved is not None and saved.status == "queued" and len(saved.events) == 1
    assert contacts == []
    jobs.refuse_start = False
    return jobs, kwargs, contacts


def test_exact_unstarted_queued_reservation_resumes_after_fresh_rebind(ready, tmp_path):
    jobs, kwargs, contacts = _unstarted_reservation(ready, tmp_path)
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic(
            "eng-opaque", "job-core", **kwargs)
    current = jobs.get(diagnostic._job_id("job-core"))
    assert current.status == "running"
    assert [event.message for event in current.events] == [
        "Linode diagnostic reserved", "Linode diagnostic started"]
    assert contacts == ["core-host-lookup"]


def test_sqlalchemy_persisted_queued_reservation_resumes_before_contact(ready, tmp_path):
    """Run the actual diagnostic reservation/start path across SQLite reads."""
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        persisted = SqlAlchemyJobRepository()

        class SplitJobs:
            refuse_start = True

            def get(self, job_id):
                if job_id == diagnostic._job_id("job-core"):
                    return persisted.get(job_id)
                return ready.case.jobs.get(job_id)

            def list(self):
                rows = {row.id: row for row in ready.case.jobs.list()}
                rows.update({row.id: row for row in persisted.list()})
                return list(rows.values())

            def list_for_engagement(self, engagement_id, *, limit=None):
                rows = sorted((row for row in self.list()
                               if row.input.get("engagementId") == engagement_id),
                              key=lambda row: row.created_at, reverse=True)
                return rows if limit is None else rows[:limit]

            def save_if_absent(self, job):
                return persisted.save_if_absent(job)

            def start_if_queued(self, *values, **kwargs):
                if self.refuse_start:
                    return None
                return persisted.start_if_queued(*values, **kwargs)

            def claim_lease(self, *values, **kwargs):
                return persisted.claim_lease(*values, **kwargs)

        jobs = SplitJobs()
        contacts = []

        def stop_before_contact(*_args, **_kwargs):
            contacts.append("core-host-lookup")
            raise RuntimeError("stop before SSH")

        kwargs = dict(
            environment="devtest", job_repository=jobs,
            sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
            fresh_observer=args["fresh_observer"],
            core_hosts=stop_before_contact,
            core_known_hosts=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
            probe=lambda **_: pytest.fail("SSH contact was not expected"),
        )
        with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
            diagnostic.capture_mixed_linode_identity_diagnostic(
                "eng-opaque", "job-core", **kwargs)
        queued = persisted.get(diagnostic._job_id("job-core"))
        assert queued is not None and queued.status == "queued"
        assert queued.started_at is None and len(queued.events) == 1
        assert contacts == []
        jobs.refuse_start = False
        with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
            diagnostic.capture_mixed_linode_identity_diagnostic(
                "eng-opaque", "job-core", **kwargs)
        started = persisted.get(diagnostic._job_id("job-core"))
        assert started.status == "running" and started.started_at is not None
        assert [event.message for event in started.events] == [
            "Linode diagnostic reserved", "Linode diagnostic started"]
        assert contacts == ["core-host-lookup"]


@pytest.mark.parametrize("change", ["event", "input", "status", "claim"])
def test_tampered_queued_reservation_cannot_resume_or_contact(
    ready, tmp_path, change,
):
    jobs, kwargs, contacts = _unstarted_reservation(ready, tmp_path)
    saved = jobs.get(diagnostic._job_id("job-core"))
    if change == "event":
        modified = replace(saved, events=[replace(saved.events[0], data={"changed": True})])
    elif change == "input":
        modified = replace(saved, input={**saved.input, "bootstrapJobId": "job-other"})
    elif change == "status":
        modified = replace(saved, status="running", started_at=datetime.now(timezone.utc).isoformat())
    else:
        modified = replace(saved, input={**saved.input, "claimOwner": "other"})
    jobs.save(modified)
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic(
            "eng-opaque", "job-core", **kwargs)
    assert contacts == []


def test_requires_completed_bootstrap_and_reserves_no_diagnostic_before_it(ready, tmp_path):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic(
            "eng-opaque", "job-core", environment="devtest",
            job_repository=ready.case.jobs,
            sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
        )
    assert ready.case.jobs.get(diagnostic._job_id("job-core")) is None


def test_existing_diagnostic_blocks_any_repeat_contact(ready, tmp_path):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.storage.job_repository import StoredJobRun
    prior = StoredJobRun(
        diagnostic._job_id("job-core"), diagnostic.ACTION, "running",
        "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
        {}, [], "2026-10-15T00:00:00+00:00", None, None, [],
    )
    ready.case.jobs.save(prior)
    contacted = []
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic(
            "eng-opaque", "job-core", environment="devtest",
            job_repository=ready.case.jobs,
            sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
            probe=lambda **_: contacted.append(True),
        )
    assert contacted == []


def test_devtest_only_even_with_completed_source(ready, tmp_path):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic(
            "eng-opaque", "job-core", environment="prod",
            job_repository=ready.case.jobs,
            sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
        )
    assert ready.case.jobs.get(diagnostic._job_id("job-core")) is None


def test_completed_bootstrap_captures_two_identities_once(ready, tmp_path, monkeypatch):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_bootstrap._sketch_file_snapshot",
        lambda path: (str(path), 0, "c" * 64),
    )
    seen = []
    middle_ip = {"value": None}

    def probe(*, node, manifest_sha256, scratch_path, scratch_intent_callback,
              intent_callback, started_callback, heartbeat_callback, result_callback,
              fence, **kwargs):
        fence()
        scratch_intent_callback(str(scratch_path))
        invocation = "diagnostic-" + str(len(seen) + 1)
        intent = CommandIntent(invocation, str(scratch_path), "a" * 64)
        intent_callback(intent)
        started = StartedCommand(intent, ProcessIdentity("boot", 100, 100, 1))
        started_callback(started)
        heartbeat_callback(started)
        result_callback(CommandAuditResult(started, 0, 10, 0, False, False))
        seen.append(node["hostname"])
        if node["role"] == "middle":
            middle_ip["value"] = node["publicIp"]
        return LinodeRawHostIdentity(
            manifest_sha256, node["chainId"], node["terraformAddress"],
            node["providerInstanceId"], "linode/ubuntu24.04", node["region"],
            node["publicIp"], node["hostname"], "boot",
            ("8.8.8.8" if node["role"] == "middle" else middle_ip["value"],
             12345, node["publicIp"], 22),
            invocation, "a" * 64, "c" * 64,
        )

    homebase = SketchBootstrapCoreHost("homebase", "1.1.1.1", "user", "/tmp/identity")
    proxy = SketchBootstrapCoreHost("proxy", "192.168.2.12", "user", "/tmp/identity", "8.8.8.8")
    kwargs = dict(
        environment="devtest", job_repository=ready.case.jobs,
        sketch_repository=args["sketch_repository"],
        lease_lookup=ready.case.args["lease_lookup"], probe=probe,
        fresh_observer=args["fresh_observer"],
        core_hosts=lambda *a, **k: (homebase, proxy),
        core_known_hosts=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
    )
    result = diagnostic.capture_mixed_linode_identity_diagnostic(
        "eng-opaque", "job-core", **kwargs)
    assert result.status == "succeeded"
    assert len(seen) == 2
    assert result.events[-1].message == "Linode identity diagnostic complete; strict policy pending"
    assert sum(e.message == "Linode diagnostic command intended" for e in result.events) == 2
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic("eng-opaque", "job-core", **kwargs)
    assert len(seen) == 2


def test_interrupted_diagnostic_keeps_nonreplayable_command_intent(ready, tmp_path, monkeypatch):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_bootstrap._sketch_file_snapshot",
        lambda path: (str(path), 0, "c" * 64),
    )
    contacted = []
    def stop(*, scratch_intent_callback, intent_callback, scratch_path, **_):
        scratch_intent_callback(str(scratch_path))
        intent_callback(CommandIntent("uncertain", str(scratch_path), "a" * 64))
        contacted.append(True)
        raise RuntimeError("unknown host command outcome")
    homebase = SketchBootstrapCoreHost("homebase", "1.1.1.1", "user", "/tmp/identity")
    proxy = SketchBootstrapCoreHost("proxy", "192.168.2.12", "user", "/tmp/identity", "8.8.8.8")
    kwargs = dict(
        environment="devtest", job_repository=ready.case.jobs,
        sketch_repository=args["sketch_repository"],
        lease_lookup=ready.case.args["lease_lookup"], probe=stop,
        fresh_observer=args["fresh_observer"],
        core_hosts=lambda *a, **k: (homebase, proxy),
        core_known_hosts=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
    )
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic("eng-opaque", "job-core", **kwargs)
    retained = ready.case.jobs.get(diagnostic._job_id("job-core"))
    assert retained.status == "running"
    assert sum(event.message == "Linode diagnostic command intended" for event in retained.events) == 1
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic("eng-opaque", "job-core", **kwargs)
    assert contacted == [True]


def test_changed_linode_provider_identity_after_bootstrap_blocks_contact(ready, tmp_path):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)
    contacted = []
    original = args["fresh_observer"]
    def changed(parent, provider, fence):
        observed = original(parent, provider, fence)
        if provider == "linode":
            ids = list(observed.classification.resource_ids)
            address, _old = ids[0]
            ids[0] = (address, "99999999")
            return replace(observed, classification=replace(
                observed.classification, resource_ids=tuple(ids)))
        return observed
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic(
            "eng-opaque", "job-core", environment="devtest",
            job_repository=ready.case.jobs,
            sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
            fresh_observer=changed,
            probe=lambda **_: contacted.append(True),
        )
    assert contacted == []
    assert ready.case.jobs.get(diagnostic._job_id("job-core")) is None


def test_late_provider_drift_after_reservation_blocks_first_host_contact(
        ready, tmp_path, monkeypatch):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
    run_mixed_initial_bootstrap(**args)
    monkeypatch.setattr(
        "app.services.provider_keyed_initial_bootstrap._sketch_file_snapshot",
        lambda path: (str(path), 0, "c" * 64),
    )
    state = {"drift": False}
    original = args["fresh_observer"]
    def changed(parent, provider, fence):
        observed = original(parent, provider, fence)
        if provider == "linode" and state["drift"]:
            ids = list(observed.classification.resource_ids)
            address, _old = ids[0]
            ids[0] = (address, "99999999")
            return replace(observed, classification=replace(
                observed.classification, resource_ids=tuple(ids)))
        return observed
    homebase = SketchBootstrapCoreHost("homebase", "1.1.1.1", "user", "/tmp/identity")
    proxy = SketchBootstrapCoreHost("proxy", "192.168.2.12", "user", "/tmp/identity", "8.8.8.8")
    def late_core_hosts(*_args, **_kwargs):
        state["drift"] = True
        return homebase, proxy
    contacted = []
    with pytest.raises(diagnostic.MixedLinodeDiagnosticAttention):
        diagnostic.capture_mixed_linode_identity_diagnostic(
            "eng-opaque", "job-core", environment="devtest",
            job_repository=ready.case.jobs,
            sketch_repository=args["sketch_repository"],
            lease_lookup=ready.case.args["lease_lookup"],
            fresh_observer=changed, core_hosts=late_core_hosts,
            core_known_hosts=lambda _: (str(tmp_path / "core-known-hosts"), "a" * 64),
            probe=lambda **_: contacted.append(True),
        )
    assert contacted == []
    retained = ready.case.jobs.get(diagnostic._job_id("job-core"))
    assert retained is not None and retained.status == "running"
    assert not any(event.message == "Linode diagnostic command intended" for event in retained.events)
