# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network retained Inspector proof and five-event ready handoff."""

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_comprehensive_teardown as service
from app.services import provider_keyed_inspector_provider_proof as provider_proof
from app.services import provider_keyed_inspector_preparation_proof as ssh_proof
from app.services import provider_keyed_inspector_prepare_binder as key_binder
from app.services import provider_keyed_inspector_submit as key_submit
from app.storage.credential_repository import SqlAlchemyCredentialRepository, StoredCredential
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from app.domain.deployment_plan import DeploymentPlan
from test_provider_keyed_inspector_preflight import _case, _configured_firewall
from test_provider_keyed_comprehensive_teardown import _published_options


def _fixture(tmp_path, monkeypatch):
    source_jobs, queued, scope, _plans, _child, settings, resources, record, _options = _case(tmp_path)
    _configured_firewall(settings, resources, record)
    firewall = resources.rows[1]
    reviewed = {**settings.value.current_host["metadata"]["providerFirewall"],
                "resourceId": "7", "managementSourceCidr": "8.8.8.8/32"}
    settings.value = replace(settings.value, current_host={
        **settings.value.current_host,
        "metadata": {**settings.value.current_host["metadata"], "providerFirewall": reviewed},
    })
    resources.rows[0] = replace(resources.rows[0], metadata={
        **resources.rows[0].metadata, "providerFirewall": reviewed})
    resources.rows[1] = replace(firewall, id="linode:inspector-firewall:7",
                                resource_id="7", metadata={
                                    **firewall.metadata, "managementSourceCidr": "8.8.8.8/32"})
    state = db.configure("sqlite:///:memory:")
    return state, source_jobs, queued, scope, settings, resources


def _run(tmp_path, monkeypatch, *, fail_audit_on_ready=False, tamper_ready=None,
         extra_before_contact=False, destroy_started_reread=False,
         pending_destroy_started_reread=False, post_destroy_reread=False,
         pending_post_destroy_reread=False):
    state, source_jobs, queued, scope, settings, resources = _fixture(tmp_path, monkeypatch)
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        stamp = datetime.now(timezone.utc).isoformat()
        for row in source_jobs.list():
            jobs.save(replace(
                row, created_at=row.created_at or stamp,
                started_at=row.started_at or (stamp if row.status != "queued" else None),
                finished_at=row.finished_at or (
                    stamp if row.status in {"succeeded", "failed"} else None),
            ))
        jobs.save(StoredJobRun(
            id="job-original-inspector", action="inspector_readiness", status="succeeded",
            target=f"engagement:{queued.target_id}", target_type="engagement",
            target_id=queued.target_id, requested_by="operator", input={}, artifact_refs=[],
            created_at=stamp, started_at=stamp, finished_at=stamp,
            events=[JobEvent(1, "info", "ready", {})],
        ))
        plans = SqlAlchemyDeploymentPlanRepository()
        plans.save(DeploymentPlan(id=scope["corePlanId"], engagement_id=queued.target_id,
                                  revision_id="revision-1", status="applied", stage="applied",
                                  apply_job_id="job-core"))
        plans.acquire(queued.target_id, scope["corePlanId"], "provider_keyed_teardown_fence")
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings_repo.save(settings.value)
        resource_repo = SqlAlchemyProviderResourceRepository()
        for resource in resources.rows:
            resource_repo.save(resource)
        if extra_before_contact:
            resource_repo.save(replace(resources.rows[1],
                                       id="linode:inspector-firewall:8", resource_id="8"))
        credentials = SqlAlchemyCredentialRepository()
        credentials.save(StoredCredential(
            id="cred-1", provider="linode", alias="current", status="active",
            description="", encrypted_secret="ciphertext", is_default=True,
            created_at=stamp, updated_at=stamp,
        ))

        monkeypatch.setattr(key_binder, "_verify_key_pair", lambda *_: None)
        monkeypatch.setattr(key_binder, "_existing_key_identity",
                            lambda: (__import__("pathlib").Path(__file__), "a" * 64))
        monkeypatch.setattr(key_submit, "_existing_public_key", lambda: ("ssh-ed25519 AAA", "a" * 64))
        contacts = []

        def get_proof(**kwargs):
            contacts.append("provider")
            kwargs["transport"].request("GET", "/linode/instances/987654", kwargs["token"])
            return provider_proof.InspectorProviderProof(kwargs["expected_host"], "7", "8.8.8.8/32")

        def ssh_check(host, key, source, fence, runner):
            for _ in range(10):
                fence()
            contacts.append("ssh")
            return "b" * 64, "Nmap version 7.94"

        monkeypatch.setattr(provider_proof, "prove_retained_keyed_inspector_provider", get_proof)
        monkeypatch.setattr(ssh_proof, "verify_inspector_selected_source_ssh", ssh_check)

        class ReadTransport:
            def request(self, method, path, token):
                assert method == "GET" and path == "/linode/instances/987654"
                assert token == "plaintext"
                return {}

        def auditor(*_args, **_kwargs):
            if (fail_audit_on_ready
                    and jobs.get(service._child_id("job-core")).input["phase"] == "inspector_ready"):
                raise ValueError("bootstrap evidence changed after final fence")

        source_reads = []

        def current_source():
            source_reads.append("read")
            if jobs.get(service._child_id("job-core")).input["phase"] == "inspector_ready":
                pytest.fail("external egress resolver ran under SQLite publication lock")
            return "8.8.8.8/32"

        def run():
            return service.prove_retained_keyed_inspector_ready(
                queued.id, environment="devtest", job_repository=jobs,
                plan_repository=plans, settings_repository=settings_repo,
                provider_resource_repository=resource_repo,
                credential_repository=credentials, lease_lookup=_db_lease_lookup,
                pending_auditor=auditor,
                key_identity_reader=lambda: (__import__("pathlib").Path(__file__), "a" * 64),
                public_key_reader=lambda: ("ssh-ed25519 AAA", "a" * 64),
                decrypt_secret=lambda value: "plaintext" if value == "ciphertext" else "",
                management_source_resolver=current_source,
                transport=ReadTransport(), ssh_runner=object(),
            )

        monkeypatch.setattr(key_binder, "_safe_key_identity", lambda *_: (str(__file__), "a" * 64))
        if extra_before_contact:
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                run()
            assert contacts == []
            return
        if fail_audit_on_ready:
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                run()
            child = jobs.get(service._child_id("job-core"))
            assert child.status == "running"
            assert child.input["phase"] == "awaiting_inspector_preflight"
            assert len(child.events) == 4
            assert contacts == ["provider", "ssh"]
            return
        result = run()
        child = jobs.get(result.coordinator_job_id)
        assert child.input["phase"] == "inspector_ready"
        assert child.status == "running" and len(child.events) == 5
        assert contacts == ["provider", "ssh"]
        assert len(source_reads) == 2
        assert jobs.get(queued.id).status == "queued"
        assert _db_lease_lookup(queued.target_id) == (
            scope["corePlanId"], "provider_keyed_teardown_fence")
        if tamper_ready == "source":
            current = resource_repo.get("linode:inspector-firewall:7")
            resource_repo.save(replace(current, metadata={
                **current.metadata, "managementSourceCidr": "1.1.1.1/32"}))
        elif tamper_ready == "extra":
            current = resource_repo.get("linode:inspector-firewall:7")
            resource_repo.save(replace(current, id="linode:inspector-firewall:8",
                                       resource_id="8"))
        elif tamper_ready == "journal":
            events = list(child.events)
            events[-1] = replace(events[-1], data={**events[-1].data,
                                                   "sourceJournalSha256": "0" * 64})
            jobs.save(replace(child, events=events))
        elif tamper_ready == "claim":
            jobs.save(replace(child, input={**child.input, "claimOwner": "different-owner"}))
        if tamper_ready:
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                service.recognize_retained_keyed_inspector_ready(
                    queued.id, environment="devtest", job_repository=jobs,
                    plan_repository=plans, settings_repository=settings_repo,
                    provider_resource_repository=resource_repo,
                    credential_repository=credentials, lease_lookup=_db_lease_lookup,
                    pending_auditor=lambda *_a, **_kw: None)
            return
        recognized = service.recognize_retained_keyed_inspector_ready(
            queued.id, environment="devtest", job_repository=jobs,
            plan_repository=plans, settings_repository=settings_repo,
            provider_resource_repository=resource_repo,
            credential_repository=credentials, lease_lookup=_db_lease_lookup,
            pending_auditor=lambda *_a, **_kw: None)
        assert recognized == result
        if pending_post_destroy_reread:
            from types import SimpleNamespace
            from app.services import provider_keyed_destroy_absence_preflight as absence

            core = jobs.get("job-core")
            snapshot = {
                **queued.input["scopeSnapshot"],
                "dnsCleanupManifest": {"schema": "provider-keyed-empty-dns-prebinding-v1"},
            }
            destroy_id = "job-provider-keyed-initial-destroy-apply-core"
            destroy = SimpleNamespace(id=destroy_id, status="succeeded")

            class ReadJobs:
                def get(self, identifier):
                    return destroy if identifier == destroy_id else jobs.get(identifier)

                def list_for_engagement(self, engagement_id):
                    return jobs.list_for_engagement(engagement_id)

            monkeypatch.setattr(service, "_boundary", lambda *_args: (
                queued, core, snapshot, service._FENCE))
            reads = []

            def successful_boundary(parent_id, **kwargs):
                reads.append((parent_id, kwargs["state_root"]))
                return SimpleNamespace(parent=queued, core=core, scope=scope,
                                       apply_job=destroy)

            monkeypatch.setattr(absence, "_read_success_boundary", successful_boundary)
            arguments = dict(
                environment="devtest", job_repository=ReadJobs(), plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resource_repo,
                credential_repository=credentials, lease_lookup=_db_lease_lookup,
                pending_auditor=lambda *_a, **_kw: pytest.fail("pre-destroy audit reran"),
                state_root=tmp_path,
            )
            assert service.recognize_retained_keyed_inspector_ready(
                queued.id, **arguments) == result
            assert reads == [(queued.id, tmp_path)]
            return
        if pending_destroy_started_reread:
            active = object()
            checked = []

            def exact_pending(parent_row, core_row, snapshot_row, active_row, jobs_row,
                              *, state_root, failed_prebinding):
                checked.append(("child", parent_row == jobs.get(queued.id), core_row.id == "job-core",
                                snapshot_row == queued.input["scopeSnapshot"],
                                active_row is active, jobs_row is jobs,
                                state_root == tmp_path, failed_prebinding is True))

            def audit_pending(*_args, **_kwargs):
                checked.append("audit")

            monkeypatch.setattr(service, "_published_destroy_started_inspector_boundary",
                                exact_pending)
            arguments = dict(
                environment="devtest", job_repository=jobs, plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resource_repo,
                credential_repository=credentials, lease_lookup=_db_lease_lookup,
                state_root=tmp_path, active_destroy_child=active,
            )
            assert service.recognize_retained_keyed_inspector_ready(
                queued.id, pending_auditor=audit_pending, **arguments) == result
            assert checked == ["audit", ("child", True, True, True, True, True, True, True)]

            def changed_pending_source(*_args, **_kwargs):
                raise ValueError("pending source changed")

            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                service.recognize_retained_keyed_inspector_ready(
                    queued.id, pending_auditor=changed_pending_source, **arguments)
            assert checked == ["audit", ("child", True, True, True, True, True, True, True)]
            assert contacts == ["provider", "ssh"]
            return
        if post_destroy_reread:
            from types import SimpleNamespace

            from app.services import provider_keyed_teardown_source as sources

            core = jobs.get("job-core")
            snapshot = queued.input["scopeSnapshot"]
            published = replace(queued, input={**queued.input, "publishedSource": {}})
            destroy_id = "job-provider-keyed-initial-destroy-apply-core"
            destroy_status = ["running"]
            destroy = SimpleNamespace(id=destroy_id, status="succeeded")

            class ReadJobs:
                def get(self, identifier):
                    if identifier == destroy_id:
                        return SimpleNamespace(id=destroy_id, status=destroy_status[0])
                    return jobs.get(identifier)

                def list_for_engagement(self, engagement_id):
                    return jobs.list_for_engagement(engagement_id)

            monkeypatch.setattr(service, "_boundary", lambda *_args: (
                published, core, snapshot, service._FENCE))
            monkeypatch.setattr(service, "_verify_published_source",
                                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                                    ValueError("applied state has been destroyed")))
            post_reads = []

            def post_boundary(parent_id, **kwargs):
                assert parent_id == published.id
                assert kwargs["job_repository"] is read_jobs
                post_reads.append(kwargs["state_root"])
                return (SimpleNamespace(
                    variant="published", teardown_parent_id=published.id,
                    engagement_id=published.target_id,
                    core_job_id=core.id, core_plan_id=core.input["corePlanId"],
                    snapshot_id=snapshot["snapshotId"],
                    provider_scope_sha256=snapshot["providerScopeSha256"]),
                    SimpleNamespace(parent=published, core=core, scope=scope,
                                    apply_job=destroy))

            monkeypatch.setattr(sources, "_read_published_post_destroy_boundary", post_boundary)
            read_jobs = ReadJobs()
            arguments = dict(
                environment="devtest", job_repository=read_jobs, plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resource_repo,
                credential_repository=credentials, lease_lookup=_db_lease_lookup,
                pending_auditor=lambda *_a, **_kw: pytest.fail("published is not pending"),
                state_root=tmp_path,
            )
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                service.recognize_retained_keyed_inspector_ready(queued.id, **arguments)
            assert post_reads == []
            destroy_status[0] = "succeeded"
            # The historical boundary must bind the same persisted child.
            destroy = read_jobs.get(destroy_id)
            assert service.recognize_retained_keyed_inspector_ready(
                queued.id, **arguments) == result
            assert post_reads == [tmp_path]
            destroy = SimpleNamespace(id="job-unrelated", status="succeeded")
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                service.recognize_retained_keyed_inspector_ready(queued.id, **arguments)
            return
        if destroy_started_reread:
            import hashlib

            from app.services import provider_keyed_destroy_apply_continuation as continuation
            from app.services.provider_keyed_inspector_provider_proof import InspectorProviderProof
            snapshot = queued.input["scopeSnapshot"]
            published = replace(queued, input={**queued.input, "publishedSource": {
                "scope_sha256": service._fingerprint(scope),
                "state_sha256": scope["stateSha256"],
            }})
            core = jobs.get("job-core")
            active = object()
            phase_reads = []

            def exact_phase(parent_row, core_row, snapshot_row, child_row, jobs_row, *, state_root):
                assert (parent_row, core_row, snapshot_row, child_row) == (
                    published, core, snapshot, active)
                assert state_root in (None, tmp_path)
                phase_reads.append(jobs_row)

            monkeypatch.setattr(service, "_published_destroy_started_inspector_boundary",
                                exact_phase)

            class ReadJobs:
                def get(self, identifier):
                    return jobs.get(identifier)

                def list_for_engagement(self, engagement_id):
                    return jobs.list_for_engagement(engagement_id)

            monkeypatch.setattr(service, "_boundary", lambda *_args: (
                published, core, snapshot, service._FENCE))
            monkeypatch.setattr(service, "_verify_published_source",
                                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                                    ValueError("applied phase is gone")))
            arguments = dict(
                environment="devtest", job_repository=ReadJobs(), plan_repository=plans,
                settings_repository=settings_repo, provider_resource_repository=resource_repo,
                credential_repository=credentials, lease_lookup=_db_lease_lookup,
                pending_auditor=lambda *_a, **_kw: pytest.fail("published is not pending"),
                state_root=tmp_path,
            )
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                service.recognize_retained_keyed_inspector_ready(queued.id, **arguments)
            assert service.recognize_retained_keyed_inspector_ready(
                queued.id, active_destroy_child=active, **arguments) == result
            assert len(phase_reads) == 1
            monkeypatch.setattr(continuation, "_boundary", lambda *_args: (
                published, core, snapshot, service._FENCE))
            private = tmp_path / "inspector-private"
            public = private.with_suffix(".pub")
            private.write_text("unused-by-stub")
            public.write_bytes(b"ssh-ed25519 AAAA\n")
            public.chmod(0o600)
            monkeypatch.setattr(continuation, "_safe_key_identity", lambda *_args: (
                str(private), hashlib.sha256(public.read_bytes().strip()).hexdigest()))
            monkeypatch.setattr(continuation, "_verify_key_pair", lambda *_args: None)
            monkeypatch.setattr(continuation, "verify_inspector_selected_source_ssh",
                                lambda *_args, **_kwargs: (result.ssh_policy_sha256,
                                                           "Nmap version 7.94"))
            live_calls = []
            continuation.prove_live_keyed_inspector_before_destroy_go(
                queued.id, environment="devtest", job_repository=ReadJobs(),
                plan_repository=plans, lease_lookup=_db_lease_lookup,
                settings_repository=settings_repo,
                provider_resource_repository=resource_repo,
                credential_repository=credentials,
                active_destroy_child=lambda: live_calls.append("child") or active,
                fence=lambda: live_calls.append("fence"),
                source_resolver=lambda: "8.8.8.8/32",
                decrypt_secret=lambda _encrypted: "plaintext",
                transport_factory=lambda _provider: type("Transport", (), {
                    "request": lambda self, _method, _path, _token: {}})(),
                provider_prover=lambda **kwargs: InspectorProviderProof(
                    kwargs["expected_host"], "7", "8.8.8.8/32"),
            )
            assert live_calls.count("child") >= 2
            assert live_calls.count("fence") > live_calls.count("child")
            assert len(phase_reads) > 1
            assert contacts == ["provider", "ssh"]
            return
        with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
            run()
        assert contacts == ["provider", "ssh"]


def test_retained_inspector_sqlalchemy_ready_round_trip(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)


def test_retained_inspector_published_pre_go_reread_needs_exact_active_child(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, destroy_started_reread=True)


def test_retained_inspector_pending_pre_go_reread_audits_before_active_child(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, pending_destroy_started_reread=True)


def test_retained_inspector_post_destroy_uses_saved_success_boundary(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, post_destroy_reread=True)


def test_retained_inspector_pending_post_destroy_uses_saved_success_boundary(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, pending_post_destroy_reread=True)


def test_audited_bootstrap_drift_at_publication_rolls_back_ready(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, fail_audit_on_ready=True)


@pytest.mark.parametrize("tamper", ["source", "extra", "journal", "claim"])
def test_persisted_recognizer_rejects_firewall_drift_and_extra_owner(tmp_path, monkeypatch, tamper):
    _run(tmp_path, monkeypatch, tamper_ready=tamper)


def test_second_owned_firewall_blocks_live_contact(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, extra_before_contact=True)


@pytest.mark.parametrize("drift_at", [None, "pre_contact", "ready_cas"])
def test_published_source_retained_inspector_round_trip_and_restart(
    client, tmp_path, monkeypatch, drift_at,
):
    # Use the real completed-generation SQL reservation and coordinator. The
    # Inspector fixture supplies only an already owned support host; no cloud
    # resource is created by this test.
    inspector_fixture = tmp_path / "inspector-fixture"
    inspector_fixture.mkdir()
    _, _, _, _, _, settings, resources, record, _ = _case(inspector_fixture)
    _configured_firewall(settings, resources, record)
    firewall = {**settings.value.current_host["metadata"]["providerFirewall"],
                "resourceId": "7", "managementSourceCidr": "8.8.8.8/32"}
    settings.value = replace(settings.value, current_host={
        **settings.value.current_host,
        "metadata": {**settings.value.current_host["metadata"], "providerFirewall": firewall},
    })
    resources.rows[0] = replace(resources.rows[0], metadata={
        **resources.rows[0].metadata, "providerFirewall": firewall})
    resources.rows[1] = replace(resources.rows[1], id="linode:inspector-firewall:7",
                                resource_id="7", metadata={
                                    **resources.rows[1].metadata,
                                    "managementSourceCidr": "8.8.8.8/32"})
    with client.application.storage_context():
        jobs, parent, source, _reads, _clock, options = _published_options(
            client, monkeypatch, tmp_path)
        options["now"] = lambda: datetime.now(timezone.utc)
        child = service.run_provider_keyed_comprehensive_handoff(parent.id, **options)
        assert child.input["phase"] == "awaiting_inspector_preflight"
        from app.services import provider_keyed_teardown_source as source_selector
        source_drift_enabled = False
        audit_phases = []

        def current_published_source(_core_id, **_kwargs):
            phase = jobs.get(child.id).input["phase"]
            audit_phases.append(phase)
            if source_drift_enabled and (drift_at == "pre_contact"
                                         or (drift_at == "ready_cas" and phase == "inspector_ready")):
                return replace(source, state_sha256="f" * 64)
            return source

        monkeypatch.setattr(source_selector, "audit_published_provider_keyed_source",
                            current_published_source)
        stamp = datetime.now(timezone.utc).isoformat()
        jobs.save(StoredJobRun(
            id="job-original-inspector", action="inspector_readiness", status="succeeded",
            target=f"engagement:{parent.target_id}", target_type="engagement",
            target_id=parent.target_id, requested_by="operator", input={}, artifact_refs=[],
            created_at=stamp, started_at=stamp, finished_at=stamp,
            events=[JobEvent(1, "info", "ready", {})],
        ))
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings_repo.save(replace(settings.value, engagement_id=parent.target_id))
        resource_repo = SqlAlchemyProviderResourceRepository()
        for row in resources.rows:
            resource_repo.save(replace(row, engagement_id=parent.target_id))
        credentials = SqlAlchemyCredentialRepository()
        credentials.save(StoredCredential(
            id="cred-1", provider="linode", alias="current", status="active",
            description="", encrypted_secret="ciphertext", is_default=True,
            created_at=stamp, updated_at=stamp,
        ))
        monkeypatch.setattr(key_binder, "_safe_key_identity", lambda *_: (str(__file__), "a" * 64))
        monkeypatch.setattr(key_binder, "_verify_key_pair", lambda *_: None)
        monkeypatch.setattr(key_binder, "_existing_key_identity",
                            lambda: (__import__("pathlib").Path(__file__), "a" * 64))
        monkeypatch.setattr(key_submit, "_existing_public_key",
                            lambda: ("ssh-ed25519 AAA", "a" * 64))
        contacts = []

        def get_proof(**kwargs):
            contacts.append("GET")
            kwargs["transport"].request("GET", "/linode/instances/987654", kwargs["token"])
            return provider_proof.InspectorProviderProof(kwargs["expected_host"], "7", "8.8.8.8/32")

        def ssh_check(host, key, selected_source, fence, runner):
            fence()
            contacts.append("SSH")
            return "b" * 64, "Nmap version 7.94"

        monkeypatch.setattr(provider_proof, "prove_retained_keyed_inspector_provider", get_proof)
        monkeypatch.setattr(ssh_proof, "verify_inspector_selected_source_ssh", ssh_check)

        class ReadTransport:
            def request(self, method, path, token):
                assert (method, path, token) == ("GET", "/linode/instances/987654", "plaintext")
                return {}

        from app.services.provider_keyed_inspector_preflight import inspect_prepared_keyed_teardown_inspector
        from app.services.provider_keyed_inspector_preflight import ProviderKeyedInspectorPreflightError
        tampered = replace(parent, input={**parent.input,
            "publishedSource": {**parent.input["publishedSource"], "state_sha256": "f" * 64}})
        jobs.save(tampered)
        with pytest.raises(ProviderKeyedInspectorPreflightError):
            inspect_prepared_keyed_teardown_inspector(
                parent.id, environment="devtest", job_repository=jobs,
                plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
                settings_repository=settings_repo, provider_resource_repository=resource_repo,
                pending_auditor=options["pending_auditor"])
        jobs.save(parent)
        assert contacts == []
        if drift_at == "pre_contact":
            source_drift_enabled = True
            with pytest.raises(ProviderKeyedInspectorPreflightError):
                inspect_prepared_keyed_teardown_inspector(
                    parent.id, environment="devtest", job_repository=jobs,
                    plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
                    settings_repository=settings_repo, provider_resource_repository=resource_repo,
                    pending_auditor=options["pending_auditor"])
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                service.prove_retained_keyed_inspector_ready(
                    parent.id, environment="devtest", job_repository=jobs,
                    plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
                    settings_repository=settings_repo, provider_resource_repository=resource_repo,
                    credential_repository=credentials, pending_auditor=options["pending_auditor"])
            assert contacts == []
            assert jobs.get(child.id).input["phase"] == "awaiting_inspector_preflight"
            return
        evidence = inspect_prepared_keyed_teardown_inspector(
            parent.id, environment="devtest", job_repository=jobs,
            plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
            settings_repository=settings_repo, provider_resource_repository=resource_repo,
            pending_auditor=options["pending_auditor"])
        assert evidence.provider_resource_id == "987654" and not evidence.live_reachability_proven
        if drift_at == "ready_cas":
            source_drift_enabled = True
            with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
                service.prove_retained_keyed_inspector_ready(
                    parent.id, environment="devtest", job_repository=jobs,
                    plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
                    settings_repository=settings_repo, provider_resource_repository=resource_repo,
                    credential_repository=credentials, pending_auditor=options["pending_auditor"],
                    key_identity_reader=lambda: (__import__("pathlib").Path(__file__), "a" * 64),
                    public_key_reader=lambda: ("ssh-ed25519 AAA", "a" * 64),
                    decrypt_secret=lambda value: "plaintext" if value == "ciphertext" else "",
                    management_source_resolver=lambda: "8.8.8.8/32",
                    transport=ReadTransport(), ssh_runner=object(),
                )
            assert contacts == ["GET", "SSH"]
            persisted = jobs.get(child.id)
            assert persisted.input["phase"] == "awaiting_inspector_preflight"
            assert len(persisted.events) == 4
            assert "inspector_ready" in audit_phases
            return
        result = service.prove_retained_keyed_inspector_ready(
            parent.id, environment="devtest", job_repository=jobs,
            plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
            settings_repository=settings_repo, provider_resource_repository=resource_repo,
            credential_repository=credentials, pending_auditor=options["pending_auditor"],
            key_identity_reader=lambda: (__import__("pathlib").Path(__file__), "a" * 64),
            public_key_reader=lambda: ("ssh-ed25519 AAA", "a" * 64),
            decrypt_secret=lambda value: "plaintext" if value == "ciphertext" else "",
            management_source_resolver=lambda: "8.8.8.8/32",
            transport=ReadTransport(), ssh_runner=object(),
        )
        assert contacts == ["GET", "SSH"]
        restarted = SqlAlchemyJobRepository()
        recognized = service.recognize_retained_keyed_inspector_ready(
            parent.id, environment="devtest", job_repository=restarted,
            plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
            settings_repository=settings_repo, provider_resource_repository=resource_repo,
            credential_repository=credentials, pending_auditor=options["pending_auditor"])
        assert recognized == result
        assert service.run_provider_keyed_comprehensive_handoff(
            parent.id, **{**options, "job_repository": restarted}).id == result.coordinator_job_id
        assert contacts == ["GET", "SSH"]
        assert jobs.get(source.initial_job_id).status == "succeeded"
        assert "inspector_ready" in audit_phases
        jobs.save(tampered)
        with pytest.raises(service.ProviderKeyedComprehensiveTeardownAttention):
            service.recognize_retained_keyed_inspector_ready(
                parent.id, environment="devtest", job_repository=restarted,
                plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
                settings_repository=settings_repo, provider_resource_repository=resource_repo,
                credential_repository=credentials, pending_auditor=options["pending_auditor"])
        assert contacts == ["GET", "SSH"]
