# Copyright (c) 2026, Oracle and/or its affiliates.
"""Owned cleanup scope remains exact even when failed Apply history survives."""
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_published_initial_cleanup_authority as module
from app.services.engagement_teardown import _fingerprint
from app.services.inbound_channel_apply import (
    InboundResolvedRoute, InboundRouteTarget, _spec_from_channel, render_inbound_apply_workspace,
    _apply_phase_commands, _phase_command_dict, _resolved_spec_from_channel,
)
from app.services.inbound_channel_artifacts import render_inbound_channel_artifacts
from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_initial_continuation import _job_ids
from app.storage.job_repository import StoredJobRun
from test_provider_keyed_chain_projection import _fixture


def _job(identifier, action, status, engagement, *, hour=3, inputs=None, events=()):
    stamp = f"2026-10-20T{hour:02d}:00:00+00:00"
    return StoredJobRun(identifier, action, status, f"engagement:{engagement}", "engagement", engagement,
                        "operator", inputs or {}, [], stamp, stamp, stamp, list(events))


@pytest.fixture
def ready(client):
    with client.application.storage_context():
        reviewed, attachment, proof, pending = _fixture()
        chains = [replace(item.chain, status="deployed", nodes=[{**node, "status": "deployed",
                  "publicIp": f"11.0.0.{i * 10 + n + 1}"} for n, node in enumerate(item.chain.nodes)])
                  for i, item in enumerate(project_digitalocean_initial_chains(reviewed, attachment, proof, pending))]
        engagement = chains[0].engagement_id
        core_rows = [{"role": "homebase", "displayName": "homebase-example", "sshAlias": "homebase-example",
                      "publicIp": "12.0.0.1", "privateIp": "192.168.0.10", "sshUser": "user"}]
        for i, chain in enumerate(chains):
            core_rows.append({"role": "proxy", "displayName": f"{chain.assigned_proxy}-example",
                              "sshAlias": f"{chain.assigned_proxy}-example", "publicIp": f"12.0.0.{i+2}",
                              "privateIp": f"192.168.{i+2}.11", "sshUser": "user"})
        core = _job("job-core", "pilot_standard_rti_guarded_execute", "succeeded", engagement, hour=1,
                    inputs={"engagementId": engagement, "engagementName": "example", "proxyCount": 2, "corePlanId": "plan"},
                    events=[JobEvent(1, "info", "core deployed", {"connectionDetails": core_rows})])
        initial = _job(_job_ids(core.id)[0], "provider_keyed_initial", "succeeded", engagement, hour=2,
            inputs={"engagementId": engagement, "coreJobId": core.id, "corePlanId": "plan"})
        chain = chains[0]
        route = {}
        for role, row in (("homebase", core_rows[0]), ("proxy", core_rows[1])):
            route[role] = InboundRouteTarget(row["displayName"], row["publicIp"] if role == "homebase" else row["privateIp"],
                row["publicIp"], row["privateIp"], "", "user")
        for role, node in (("middle", chain.nodes[0]), ("edge", chain.nodes[1])):
            route[role] = InboundRouteTarget(node["hostname"], node["publicIp"], node["publicIp"], "", chain.chain_id)
        resolved = InboundResolvedRoute(**route, termination=None)
        channel = {"channelId": "attempt", "domain": "example.invalid", "protocol": "HTTP",
                   "mode": "http-openresty", "externalPort": "80", "internalPort": "80",
                   "proxy": route["proxy"].name, "middle": route["middle"].name, "edge": route["edge"].name,
                   "terminatesOn": route["proxy"].name, "service": "Static Web", "chainId": chain.chain_id,
                   "serviceType": "web-static", "serviceId": "web-example"}
        spec, resolved = _resolved_spec_from_channel("example", {
            "coreInfrastructure": core_rows,
            "sketchInfrastructure": [{**node, "chainId": chain.chain_id} for node in chain.nodes],
        }, channel)
        rendered = render_inbound_apply_workspace(spec, render_inbound_channel_artifacts(spec),
                     route=resolved, keyed_sketch_policy=True)
        workspace = rendered.to_dict()
        inventory = [route[role].name for role in ("proxy", "middle", "edge")]
        attempt = _job("job-attempt", "inbound_channel_apply", "failed", engagement,
            inputs={"engagementId": engagement, "channelId": "attempt", "proxyId": route["proxy"].name,
                    "mutation": True, "confirmation": "redacted"}, events=[
                JobEvent(1, "info", "inbound channel apply workspace rendered", {"channelId": "attempt",
                    "workspaceDir": "/private/tmp/fixture",
                    "resolvedRoute": resolved.to_dict(), "workspaceEvidence": workspace,
                    "inventoryTargets": inventory, "inboundChannels": [channel]}),
                JobEvent(2, "info", "inbound channel Ansible apply started", {"inventoryTargets": inventory,
                    "cwd": "/private/tmp/fixture", "commands": [_phase_command_dict(command)
                        for command in _apply_phase_commands("/usr/bin/ansible-playbook", rendered)]}),
                JobEvent(3, "info", "keyed channel ingress requires observation", {"errorType": "ValueError"}),
                JobEvent(4, "error", "inbound channel provider ingress sync failed", {"channelId": "attempt"}),
            ])
        attempt = replace(attempt, artifact_refs=[rendered.inventory.target, rendered.ssh_config.target,
            *[play.target for play in rendered.playbooks], rendered.manifest.target])
        saved = {row.id: row for row in (core, initial, attempt)}
        jobs = SimpleNamespace(get=saved.get, list_for_engagement=lambda _: list(saved.values()))
        repository = SimpleNamespace(list_for_engagement=lambda _: chains)
        snapshot = {"engagementId": engagement, "coreJobId": core.id, "domainAssignments": [],
                    "providerScopes": [{"chainIds": [row.chain_id for row in chains],
                        "coreJobId": core.id, "corePlanId": "plan", "provider": "digitalocean"}],
                    "core": {"proxyCount": 2}, "inspector": {}}
        def build():
            return module.build_cleanup_seal(core, snapshot, jobs=jobs, chains=repository)
        def parent(seal):
            scope = {**snapshot, module.KEY: seal, "publicVerificationTargets": seal["publicTargets"]["targets"],
                     "inspector": {"verificationTargetCount": len(seal["publicTargets"]["targets"])}}
            scope["snapshotId"] = _fingerprint(scope)
            return _job("job-parent", "engagement_comprehensive_teardown", "running", engagement, hour=4,
                inputs={"coreJobId": core.id, "scopeSnapshot": scope, module.MARKER: module.seal_marker(scope)},
                events=[JobEvent(1, "info", "engagement teardown queued", module.queued_cleanup_event_data(scope))])
        yield SimpleNamespace(core=core, initial=initial, attempt=attempt, saved=saved, jobs=jobs,
                              chains=chains, snapshot=snapshot, build=build, parent=parent)


def test_literal_generated_failed_workspace_seals_all_owned_numeric_targets(ready):
    seal = ready.build()
    parent = ready.parent(seal)
    assert len(seal["evidence"]) == 1
    assert {target["port"] for target in seal["publicTargets"]["targets"]} == {22, 80}
    assert all(target["type"] == "tcp-forbidden" for target in seal["publicTargets"]["targets"])
    assert module.validate_saved_cleanup(parent, ready.core, parent.input["scopeSnapshot"], ready.jobs) == seal
    # Destruction/retirement of mutable projections cannot invalidate immutable proof.
    ready.chains.clear()
    assert module.validate_saved_cleanup(parent, ready.core, parent.input["scopeSnapshot"], ready.jobs) == seal


@pytest.mark.parametrize("label", [None, ""])
def test_failed_workspace_requires_exact_retained_core_engagement_label(ready, label):
    if label is None:
        ready.core.input.pop("engagementName")
    else:
        ready.core.input["engagementName"] = label
    with pytest.raises(ValueError):
        ready.build()


def test_changed_core_label_invalidates_saved_source_identity(ready):
    parent = ready.parent(ready.build())
    ready.saved[ready.core.id] = replace(ready.core, input={**ready.core.input, "engagementName": "different"})
    with pytest.raises(ValueError, match="source job changed"):
        module.validate_saved_cleanup(parent, ready.core, parent.input["scopeSnapshot"], ready.jobs)


def test_only_exact_source_jobs_may_project_derived_not_ready_channels(ready):
    projection = {"outboundChannels": [{"channelId": "derived", "chainId": "inert-history", "status": "Not Ready"}]}
    ready.core.events.append(JobEvent(2, "info", "core completion projection", projection))
    ready.initial.events.append(JobEvent(1, "info", "initial completion projection", projection))
    seal = ready.build()
    assert [row["id"] for row in seal["evidence"]] == [ready.attempt.id]
    assert seal["source"]["core"]["journalSha256"] == module.job_event_digest(ready.core.events)
    assert seal["source"]["initial"]["journalSha256"] == module.job_event_digest(ready.initial.events)
    parent = ready.parent(seal)
    ready.core.events[-1].data["outboundChannels"][0]["status"] = "Changed"
    with pytest.raises(ValueError):
        module.validate_saved_cleanup(parent, ready.core, parent.input["scopeSnapshot"], ready.jobs)


@pytest.mark.parametrize("action", ["pilot_standard_rti_guarded_execute", "unknown_producer", "outbound_channel_apply"])
def test_source_shaped_projection_on_other_job_does_not_escape_classification(ready, action):
    ready.saved["job-unselected-source"] = _job("job-unselected-source", action, "failed", ready.core.target_id,
        events=[JobEvent(1, "info", "completion projection", {"outboundChannels": [
            {"channelId": "derived", "status": "Not Ready"}]})])
    with pytest.raises(ValueError, match="unreviewed binding history"):
        ready.build()


@pytest.mark.parametrize("drift", ["succeeded", "running", "queued", "outbound", "remove", "batch",
    "foreign_edge", "foreign_proxy", "missing_route", "prior_core", "new_core", "foreign_inventory",
    "malformed_manifest", "wrong_port", "unknown_phase", "unbound_host_write"])
def test_failed_history_or_route_drift_blocks_cleanup(ready, drift):
    attempt = ready.attempt
    first = json.loads(json.dumps(attempt.events[0].data))
    if drift in {"succeeded", "running", "queued"}:
        attempt = replace(attempt, status=drift)
    elif drift in {"outbound", "remove", "batch"}:
        attempt = replace(attempt, action={"outbound": "outbound_channel_apply", "remove": "inbound_channel_remove",
                                          "batch": "inbound_channel_batch_apply"}[drift])
    elif drift == "new_core":
        ready.saved["job-new-core"] = replace(ready.core, id="job-new-core", created_at=attempt.created_at)
    elif drift == "prior_core":
        attempt = replace(attempt, started_at=ready.core.created_at, created_at=ready.core.created_at)
    elif drift == "unbound_host_write":
        attempt = replace(attempt, events=[*attempt.events[:2],
            JobEvent(3, "info", "keyed channel routed command completed", {
                "phase": "host-policy", "invocationId": "opaque", "returnCode": 0,
                "stdoutTruncated": False, "stderrTruncated": False}),
            replace(attempt.events[2], sequence=4), replace(attempt.events[3], sequence=5)])
    elif drift == "unknown_phase":
        attempt = replace(attempt, events=[*attempt.events[:-1], JobEvent(4, "info", "provider write unknown", {}),
                                          replace(attempt.events[-1], sequence=5)])
    else:
        if drift == "foreign_edge": first["resolvedRoute"]["edge"]["publicIp"] = "13.0.0.1"
        if drift == "foreign_proxy": first["resolvedRoute"]["proxy"]["privateIp"] = "192.168.99.2"
        if drift == "missing_route": first.pop("resolvedRoute")
        if drift == "foreign_inventory": first["workspaceEvidence"]["inventory"]["content"] += "\nforeign ansible_host=13.0.0.1\n"
        if drift == "malformed_manifest": first["workspaceEvidence"]["manifest"]["content"] = "{"
        if drift == "wrong_port":
            manifest = json.loads(first["workspaceEvidence"]["manifest"]["content"])
            manifest["channel"]["externalPort"] = "8080"
            first["workspaceEvidence"]["manifest"]["content"] = json.dumps(manifest)
        attempt = replace(attempt, events=[replace(attempt.events[0], data=first), *attempt.events[1:]])
    ready.saved[attempt.id] = attempt
    with pytest.raises((ValueError, TypeError, KeyError)):
        ready.build()


@pytest.mark.parametrize("drift", ["journal", "input", "new_history", "target", "marker", "version", "marker_and_targets"])
def test_saved_authority_rejects_mutation_and_target_downgrade(ready, drift):
    parent = ready.parent(ready.build())
    scope = parent.input["scopeSnapshot"]
    if drift == "journal":
        ready.saved[ready.attempt.id] = replace(ready.attempt, events=[*ready.attempt.events,
            JobEvent(5, "error", "unaccounted write", {})])
    elif drift == "input": ready.saved[ready.attempt.id] = replace(ready.attempt, input={**ready.attempt.input, "channelId": "other"})
    elif drift == "new_history": ready.saved["job-remove"] = replace(ready.attempt, id="job-remove", action="inbound_channel_remove")
    elif drift == "target": scope["publicVerificationTargets"] = scope["publicVerificationTargets"][:-1]
    elif drift == "marker": parent.input.pop(module.MARKER)
    elif drift == "version": scope[module.KEY]["schema"] = "unknown"
    else:
        scope.pop(module.KEY); parent.input.pop(module.MARKER)
        scope["publicVerificationTargets"] = [row for row in scope["publicVerificationTargets"] if row["port"] == 22]
        parent = replace(parent, events=[replace(parent.events[0], data={"snapshotId": scope["snapshotId"]})])
    with pytest.raises(ValueError):
        module.validate_saved_cleanup(parent, ready.core, scope, ready.jobs)


def test_saved_negative_keeps_versioned_target_commitment(ready):
    parent = ready.parent(ready.build()); scope = parent.input["scopeSnapshot"]
    from app.services.observer_checks import _teardown_target
    targets = [_teardown_target(row) for row in scope["publicVerificationTargets"]]
    negative = replace(ready.attempt, input={module.MARKER: module.seal_marker(scope),
        "targetSha256": module.digest(targets), "targetCount": len(targets), "scopeSnapshotId": scope["snapshotId"]})
    module.validate_cleanup_negative(parent, ready.core, scope, negative, ready.jobs)
    negative.input.pop(module.MARKER)
    with pytest.raises(ValueError):
        module.validate_cleanup_negative(parent, ready.core, scope, negative, ready.jobs)


@pytest.mark.parametrize("value", [None, False, {}, {"schema": "unknown", "sha256": "a" * 64}])
def test_present_invalid_seal_cannot_use_legacy_queued_shape(value):
    assert module.queued_cleanup_event_data({"snapshotId": "legacy"}) == {"snapshotId": "legacy"}
    with pytest.raises(ValueError):
        module.queued_cleanup_event_data({"snapshotId": "sealed", module.KEY: value})


def test_new_malformed_readonly_producer_still_invalidates_review(ready):
    parent = ready.parent(ready.build())
    ready.saved["job-preview"] = _job("job-preview", "inbound_channel_apply_preview", "succeeded",
        ready.core.target_id, inputs={"engagementId": ready.core.target_id, "mutation": False})
    with pytest.raises(ValueError, match="producer journal"):
        module.validate_saved_cleanup(parent, ready.core, parent.input["scopeSnapshot"], ready.jobs)


def test_future_generation_history_does_not_rewrite_completed_cleanup(ready):
    seal = ready.build()
    parent = replace(ready.parent(seal), status="succeeded", finished_at="2026-10-20T04:00:00+00:00")
    ready.saved["job-future"] = _job("job-future", "inbound_channel_apply", "failed", ready.core.target_id, hour=5)
    assert module.validate_saved_cleanup(parent, ready.core, parent.input["scopeSnapshot"], ready.jobs) == seal


def test_unknown_active_work_blocks_current_review_without_entering_seal(ready):
    ready.saved["job-active"] = replace(_job("job-active", "unknown_active_mutation", "running",
        ready.core.target_id), finished_at=None)
    with pytest.raises(ValueError, match="outside exact cleanup"):
        ready.build()


@pytest.mark.parametrize("drift", [None, "id", "action", "lineage", "scope"])
def test_current_recheck_exempts_only_exact_coordinator_lineage(ready, drift):
    from app.services.engagement_teardown import _parent_id
    seal = ready.build()
    parent = replace(ready.parent(seal), id=_parent_id(ready.core.id), finished_at=None)
    ready.saved[parent.id] = parent
    child = replace(_job("job-provider-keyed-comprehensive-teardown-core", "provider_keyed_comprehensive_teardown",
        "running", ready.core.target_id, inputs={"coreJobId": ready.core.id, "corePlanId": "plan",
            "teardownParentId": parent.id, "scopeSnapshotId": parent.input["scopeSnapshot"]["snapshotId"]}), finished_at=None)
    if drift == "id": child = replace(child, id=child.id + "-other")
    if drift == "action": child = replace(child, action="other_active_mutation")
    if drift == "lineage": child = replace(child, input={**child.input, "teardownParentId": "foreign"})
    if drift == "scope": child = replace(child, input={**child.input, "scopeSnapshotId": "foreign"})
    ready.saved[child.id] = child
    if drift is None:
        assert ready.build() == seal
    else:
        with pytest.raises(ValueError):
            ready.build()


@pytest.mark.parametrize("binding", ["assignment", "dns", "asset", "certificate"])
def test_independent_binding_prevents_initial_cleanup(ready, monkeypatch, binding):
    from app.storage.domain_repository import SqlAlchemyDomainRepository
    from app.storage.certificate_repository import SqlAlchemyCertificateRepository
    from app.services import provider_keyed_mixed_append_live_bindings
    targets = {"assignment": (SqlAlchemyDomainRepository, "list_assignments"),
               "dns": (provider_keyed_mixed_append_live_bindings, "_owned_dns_rows"),
               "asset": (SqlAlchemyCertificateRepository, "list_assets"),
               "certificate": (SqlAlchemyCertificateRepository, "list_bindings")}
    owner, name = targets[binding]
    monkeypatch.setattr(owner, name, lambda *_a, **_k: [object()])
    with pytest.raises(ValueError, match="independent DNS"):
        ready.build()


def test_released_unused_assignment_is_retained_in_review_without_dns_cleanup(ready, monkeypatch):
    from app.storage.domain_repository import SqlAlchemyDomainRepository, StoredDomainAssignment
    released = StoredDomainAssignment(1, "domain-example", ready.core.target_id, "Example", "web",
        "released", "", "operator", "operator", ready.core.created_at, ready.attempt.created_at)
    monkeypatch.setattr(SqlAlchemyDomainRepository, "list_assignments", lambda *_a, **_k: [released])
    seal = ready.build()
    assert seal["releasedAssignments"] == [{"assignmentId": 1, "sha256": module.digest(released.__dict__)}]
    assert seal["publicTargets"]["dns"] == []
    assert all(target["type"] == "tcp-forbidden" for target in seal["publicTargets"]["targets"])


def _static_service(ready):
    from app.services.web_static_service import (
        WebStaticIntent, WebStaticCoreHost, WebStaticContentFile, render_web_static_apply_workspace,
        _workspace_evidence, _content_review_binding,
    )
    from app.storage.service_repository import SqlAlchemyEngagementServiceRepository
    intent = WebStaticIntent("web-example", "example", "example.invalid", ready.chains[0].assigned_proxy,
                             8081, "<html>example</html>", (WebStaticContentFile("index.html", "<html>example</html>"),))
    homebase = WebStaticCoreHost("homebase", "12.0.0.1", ssh_private_key_file="/private/tmp/core-key")
    proxy = WebStaticCoreHost(intent.proxy_id, "192.168.2.11", ssh_private_key_file="/private/tmp/core-key",
                              proxy_jump="user@12.0.0.1")
    preview_workspace = render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy)
    review = _job("job-site-review", "web_static_service_apply_preview", "succeeded", ready.core.target_id,
        inputs={"engagementId": ready.core.target_id, "serviceId": intent.service_id,
                "serviceType": "web-static", "mutation": False, "contentReview": {"binding": _content_review_binding(
                    ready.jobs, ready.core.target_id, intent, homebase, proxy)}},
        events=[JobEvent(1, "info", "static web service apply preview rendered", {
            "mutation": False, "workspace": preview_workspace.to_dict(), "service": intent.to_dict()})])
    ready.saved[review.id] = review
    intent = replace(intent, content_review_job_id=review.id)
    service = intent.to_service(ready.core.target_id, status="Configured", apply_job_id="job-site")
    workspace = render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy)
    apply = _job("job-site", "web_static_service_apply", "succeeded", ready.core.target_id,
                 inputs={"engagementId": ready.core.target_id, "serviceId": service.service_id,
                         "serviceType": "web-static", "proxyId": service.proxy_id, "mutation": True,
                         "contentReviewJobId": review.id, "contentAction": "preserve"},
                 events=[JobEvent(1, "info", "static web service apply workspace rendered", {
                     "service": intent.to_dict(), "inventoryTargets": ["selected_proxy"],
                     "workspaceDir": "/private/tmp/fixture-site", "workspaceEvidence": _workspace_evidence(workspace)}),
                     JobEvent(2, "info", "static web service Ansible apply started", {"inventoryTargets": ["selected_proxy"],
                         "cwd": "/private/tmp/fixture-site", "command": ["/usr/bin/ansible-playbook", "-i",
                             "ansible/inventory.ini", "ansible/apply_web_static.yml"]}),
                     JobEvent(3, "info", "static web service Ansible apply succeeded", {
                         "status": "Configured", "commandResult": {"ok": True, "returncode": 0}})])
    apply = replace(apply, artifact_refs=["ansible/inventory.ini", "ansible/apply_web_static.yml", "MANIFEST.json"])
    ready.saved[apply.id] = apply
    return SqlAlchemyEngagementServiceRepository(), service, apply


def test_static_site_is_bound_to_owned_proxy_and_creator_not_uninstalled(ready):
    repository, service, apply = _static_service(ready)
    repository.save(service)
    seal = ready.build()
    assert seal["services"][0]["apply"]["id"] == apply.id
    assert seal["services"][0]["proxy"]["displayName"] == "proxy01-example"
    assert repository.get(service.engagement_id, service.service_id).status == "Configured"
    parent = ready.parent(seal)
    repository.save(replace(service, status="Retired"))
    assert module.validate_saved_cleanup(parent, ready.core, parent.input["scopeSnapshot"], ready.jobs) == seal


@pytest.mark.parametrize("drift", ["foreign_proxy", "config", "missing_creator", "foreign_creator", "old_core", "failed", "unknown_type",
    "missing_metadata", "foreign_artifact", "command", "cwd"])
def test_static_site_needs_complete_current_provenance(ready, drift):
    repository, service, apply = _static_service(ready)
    if drift == "foreign_proxy": service = replace(service, proxy_id="unowned")
    elif drift == "config": service = replace(service, config={**service.config, "domain": "other.invalid"})
    elif drift == "missing_creator": ready.saved.pop(apply.id)
    elif drift == "foreign_creator": ready.saved[apply.id] = replace(apply, target_id="foreign")
    elif drift == "old_core": ready.saved[apply.id] = replace(apply, started_at=ready.core.started_at)
    elif drift == "failed": ready.saved[apply.id] = replace(apply, status="failed")
    elif drift == "unknown_type": service = replace(service, service_type="unknown")
    else:
        events = json.loads(json.dumps([event.data for event in apply.events]))
        if drift == "missing_metadata": events[0].pop("workspaceEvidence")
        elif drift == "foreign_artifact": events[0]["workspaceEvidence"]["inventory"]["path"] = "foreign.ini"
        elif drift == "command": events[1]["command"][-1] = "ansible/foreign.yml"
        elif drift == "cwd": events[1]["cwd"] = "/private/tmp/foreign"
        ready.saved[apply.id] = replace(apply, events=[replace(event, data=events[i]) for i, event in enumerate(apply.events)])
    repository.save(service)
    with pytest.raises(ValueError):
        ready.build()


@pytest.mark.parametrize("phase", ["applied", "destroy_started"])
def test_sealed_membership_uses_stronger_get_only_attachment_at_both_boundaries(ready, monkeypatch, phase):
    from app.services import provider_keyed_initial_destroy_apply_job as apply
    from app.services import provider_keyed_digitalocean_attachment as attachment
    parent = ready.parent(ready.build())
    monkeypatch.setattr(apply, "SqlAlchemySketchChainRepository", lambda:
                        SimpleNamespace(list_for_engagement=lambda _: ready.chains))
    seen = []
    def prove(workspace, intent, **kwargs):
        assert kwargs["expected_phase"] == phase
        assert kwargs["max_attempts"] == 1 and kwargs["poll_interval_seconds"] == 0
        seen.append((workspace, intent, kwargs["transport"]))
    monkeypatch.setattr(attachment, "reconcile_digitalocean_initial_attachment", prove)
    assert apply._sealed_cleanup_membership(parent, ready.jobs, "workspace", "intent",
        credentials="credentials", transport="get-only", environment="devtest", expected_phase=phase)
    assert seen == [("workspace", "intent", "get-only")]
    # A fresh provider proof failure is propagated; no weaker membership fallback.
    monkeypatch.setattr(attachment, "reconcile_digitalocean_initial_attachment",
                        lambda *_a, **_k: (_ for _ in ()).throw(ValueError("rules differ")))
    with pytest.raises(ValueError, match="rules differ"):
        apply._sealed_cleanup_membership(parent, ready.jobs, "workspace", "intent",
            credentials="credentials", transport="get-only", environment="devtest", expected_phase=phase)


def test_history_change_prevents_provider_get_at_membership_boundary(ready, monkeypatch):
    from app.services import provider_keyed_initial_destroy_apply_job as apply
    from app.services import provider_keyed_digitalocean_attachment as attachment
    parent = ready.parent(ready.build())
    ready.saved[ready.attempt.id] = replace(ready.attempt, input={**ready.attempt.input, "proxyId": "foreign"})
    monkeypatch.setattr(attachment, "reconcile_digitalocean_initial_attachment",
                        lambda *_a, **_k: pytest.fail("provider GET ran after authority drift"))
    with pytest.raises(ValueError):
        apply._sealed_cleanup_membership(parent, ready.jobs, "workspace", "intent",
            credentials="credentials", transport="get-only", environment="devtest")


@pytest.mark.parametrize("drift", ["missing", "binding", "foreign_homebase", "foreign_proxy", "actor", "late_review"])
def test_linked_static_review_must_prove_exact_core_hosts(ready, drift):
    repository, service, apply = _static_service(ready)
    review = ready.saved[apply.input["contentReviewJobId"]]
    if drift == "missing": ready.saved.pop(review.id)
    elif drift == "binding":
        ready.saved[review.id] = replace(review, input={**review.input, "contentReview": {"binding": "0" * 64}})
    elif drift == "actor": ready.saved[review.id] = replace(review, requested_by="other")
    elif drift == "late_review": ready.saved[review.id] = replace(review, finished_at="2026-10-20T05:00:00+00:00")
    else:
        data = json.loads(json.dumps(review.events[0].data))
        manifest = json.loads(data["workspace"]["manifest"]["content"])
        key = "homebaseJump" if drift == "foreign_homebase" else "selectedProxy"
        manifest["targets"][key]["ansibleHost"] = "13.0.0.99"
        data["workspace"]["manifest"]["content"] = json.dumps(manifest)
        ready.saved[review.id] = replace(review, events=[replace(review.events[0], data=data)])
    repository.save(service)
    with pytest.raises(ValueError):
        ready.build()


@pytest.mark.parametrize("producer", ["review", "apply"])
def test_sealed_static_creator_actor_drift_is_rejected(ready, producer):
    repository, service, apply = _static_service(ready)
    repository.save(service)
    parent = ready.parent(ready.build())
    job = ready.saved[apply.input["contentReviewJobId"]] if producer == "review" else apply
    ready.saved[job.id] = replace(job, requested_by="other")
    with pytest.raises(ValueError, match="history changed"):
        module.validate_saved_cleanup(parent, ready.core, parent.input["scopeSnapshot"], ready.jobs)


@pytest.mark.parametrize("drift", ["playbook", "compose", "extra_artifact", "metadata_bytes"])
def test_static_producer_requires_complete_canonical_workspace(ready, drift):
    repository, service, apply = _static_service(ready)
    repository.save(service)
    review = ready.saved[apply.input["contentReviewJobId"]]
    data = json.loads(json.dumps(review.events[0].data))
    if drift == "metadata_bytes":
        first = json.loads(json.dumps(apply.events[0].data))
        first["workspaceEvidence"]["compose"]["bytes"] += 1
        ready.saved[apply.id] = replace(apply, events=[replace(apply.events[0], data=first), *apply.events[1:]])
    else:
        workspace = data["workspace"]
        if drift == "playbook":
            workspace["playbook"]["content"] += "\n- hosts: foreign\n  tasks: []\n"
        elif drift == "compose":
            artifact = next(row for row in workspace["artifacts"] if row["target"] == "files/opt/web/docker-compose.yml")
            artifact["content"] += "\n# changed executable configuration\n"
        else:
            workspace["artifacts"].append({"target": "files/foreign", "content": "foreign", "encoding": "text"})
        ready.saved[review.id] = replace(review, events=[replace(review.events[0], data=data)])
    with pytest.raises(ValueError, match="canonical"):
        ready.build()
