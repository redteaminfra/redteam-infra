# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted append publication enters the existing one-action coordinator.

Provider reads and core/Inspector inventory are offline witnesses; append
journals, policies, six scopes, SQLite reservation and plan seals are real.
"""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain.deployment_plan import DeploymentPlan
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedSixTeardownSource, six_collection_review, six_historical_rows_sha256)
from app.services.provider_keyed_mixed_published_teardown_collector import PublishedMixedTeardownCollection
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup, saved_published_mixed_initial_review,
    recognize_published_mixed_plans_sealed, saved_published_mixed_destroy_plans)
from app.services.provider_keyed_mixed_published_dispatch import (
    preview_published_mixed_cleanup, start_published_mixed_cleanup)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from test_provider_keyed_mixed_published_six_integration import persisted_six_case
from test_provider_keyed_mixed_published_teardown_checkpoint import _core_scope
from test_provider_keyed_mixed_published_teardown_reservation import _attested_plans


def _persist(client, tmp_path, monkeypatch, reverse, before_collect=None, existing_case=None, inert_history=False, unpublished=False):
    from app.services import provider_keyed_mixed_published_six_collector as collector
    case = existing_case or persisted_six_case(client, tmp_path, monkeypatch, reverse=reverse, inert_history=inert_history)
    source = case["source"]
    jobs, plans, sketches = (SqlAlchemyJobRepository(), SqlAlchemyDeploymentPlanRepository(),
                             SqlAlchemySketchChainRepository())
    initial = jobs.get("job-provider-keyed-mixed-initial-core")
    core = jobs.save(replace(initial, id=source.core_job_id,
        action="pilot_standard_rti_guarded_execute", input={
            "engagementId": source.engagement_id, "corePlanId": source.core_plan_id,
            "engagementName": "Opaque"}, events=[]))
    plan = plans.save(DeploymentPlan(source.core_plan_id, source.engagement_id, "rev",
        "applied", "applied", apply_job_id=core.id, evidence={
            "pendingSketchChainFingerprints": {
                chain.chain_id: collector.sketch_chain_intent_fingerprint(chain)
                for chain in source.before_chains}}))
    for provider in source.provider_order:
        jobs.save(replace(initial, id=collector.initial_child_id(core.id, provider),
                          action="provider_keyed_mixed_initial_apply_child"))
    from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id
    from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
    from app.services.provider_keyed_mixed_strict_host_receipt import child_id as proof_id
    for identifier in (_binding_child_id(core.id), _worker_id(core.id), proof_id(core.id)):
        jobs.save(replace(initial, id=identifier))
    monkeypatch.setattr(collector, "active_core_connection_details", lambda *_: (core.id, []))
    monkeypatch.setattr(collector, "recognize_mixed_initial_apply_terminal", lambda *_: {})
    monkeypatch.setattr(collector, "_prior_workspace", lambda _p, provider, _t:
        case["workspaces"][provider] if "workspaces" in case else SimpleNamespace(path=Path(source.workspace_paths[source.provider_order.index(provider)]),
            state_path=Path(source.workspace_paths[source.provider_order.index(provider)]) / "terraform.tfstate"))
    monkeypatch.setattr(collector, "_fresh_observation", lambda provider, *_a, **_k:
                        case["observations"][provider])
    scope = _core_scope(SimpleNamespace(source=SimpleNamespace(
        core_job_id=source.core_job_id, core_plan_id=source.core_plan_id)))
    monkeypatch.setattr(collector, "_core_inspector_scope", lambda *_a, **_k: scope)
    for provider in source.provider_order:
        root = Path(source.workspace_paths[source.provider_order.index(provider)])
        (root / "terraform.tfstate").write_bytes(case["observations"][provider].state_json)
    if unpublished:
        from test_provider_keyed_unpublished_six_cleanup import unpublish_failed_host_case
        unpublish_failed_host_case(source, jobs, sketches, monkeypatch)
    if before_collect is not None:
        before_collect(source, jobs, initial)
    value = collector.collect_published_mixed_six_teardown(source.engagement_id, core.id)
    review = six_collection_review(value, jobs=jobs, plans=plans, sketches=sketches)
    return jobs, plans, sketches, core, PublishedMixedTeardownCollection(
        review, scope, value.observations, value.workspaces, value)


@pytest.mark.parametrize("reverse", [False, True])
def test_six_review_start_seal_and_restart(client, tmp_path, monkeypatch, reverse):
    with client.application.storage_context():
        jobs, plans, sketches, core, collection = _persist(client, tmp_path, monkeypatch, reverse)
        review = collection.review
        assert type(review.source) is PublishedSixTeardownSource
        initial = jobs.get(review.source.parent_job_id)
        # Initial order follows native providers; append order follows the
        # opposite provider's new edge on each retained foreign middle.
        assert tuple(initial.events[5].data["chainIds"]) == tuple(reversed(review.source.chain_ids))
        assert dict(zip(initial.events[5].data["orderedProviders"],
                        initial.events[5].data["chainIds"], strict=True)) == {
            chain.middle_provider: chain.chain_id for chain in review.source.six_node_source.before_chains}
        assert sum(len(scope["resources"]) for scope in review.provider_scopes) == 10
        assert all(len(policy["nodes"]) == 3 for policy in review.reviewed_policies.values())
        preview = preview_published_mixed_cleanup(core, environment="devtest", job_repository=jobs)
        assert preview["startAvailable"]
        saved = start_published_mixed_cleanup(core, {
            "snapshotId": preview["snapshotId"], "confirmation": preview["confirmationPhrase"]},
            environment="devtest", job_repository=jobs)
        assert saved_published_mixed_initial_review(saved) == review
        from app.services import provider_keyed_mixed_published_six_collector as six_collector
        monkeypatch.setattr(six_collector, "_fresh_observation",
                            lambda *_a, **_k: pytest.fail("provider GET under SQLite writer"))
        assert jobs.reserve_published_mixed_initial_cleanup_parent(saved,
            collection=collection, expected_snapshot_id=saved.input["reviewSnapshotId"]) == saved
        assert _db_lease_lookup(core.target_id) == (review.source.core_plan_id, "provider_keyed_teardown_fence")
        # Restart reopens the exact saved review without recollecting both full providers.
        again = preview_published_mixed_cleanup(core, environment="devtest", job_repository=jobs,
            collector=lambda *_a, **_k: pytest.fail("restart recollected full/full source"))
        assert again["snapshotId"] == preview["snapshotId"]
        assert not again["startAvailable"]
        # Same production binder seals exact six-state delete plans using final policies.
        plan_set, before, _binary, _digest = _attested_plans(jobs, collection, tmp_path)
        sealed = jobs.seal_published_mixed_initial_destroy_plans(saved,
            collection=collection, plan_set=plan_set, before_states=before)
        assert saved_published_mixed_destroy_plans(sealed) == plan_set
        assert recognize_published_mixed_plans_sealed(sealed, review, plan_set,
            collection.core_inspector_scope, "Opaque") == sealed
        assert six_historical_rows_sha256(review, jobs=jobs, plans=plans, sketches=sketches) == review.historical_rows_sha256


@pytest.mark.parametrize("drift", ["policy", "state", "journal"])
def test_six_start_rechecks_saved_local_source(client, tmp_path, monkeypatch, drift):
    with client.application.storage_context():
        jobs, plans, sketches, core, collection = _persist(client, tmp_path, monkeypatch, False)
        proposal = propose_published_mixed_initial_cleanup(
            collection.review, collection.core_inspector_scope, "Opaque", requested_by="operator")
        if drift == "state":
            next(iter(collection.workspaces.values())).joinpath("terraform.tfstate").write_bytes(b"drift")
        elif drift == "policy":
            collection.review.reviewed_policies["linode"]["nodes"] = {}
        else:
            source = collection.review.source.six_node_source
            append = jobs.get(source.parent_id)
            jobs.save(replace(append, events=append.events[:-1]))
        with pytest.raises(ValueError):
            jobs.reserve_published_mixed_initial_cleanup_parent(proposal, collection=collection,
                expected_snapshot_id=proposal.input["reviewSnapshotId"])
        assert jobs.get(proposal.id) is None
        assert _db_lease_lookup(core.target_id) is None


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("owned_dns", [False, True])
@pytest.mark.parametrize("inert_history", [False, True])
@pytest.mark.parametrize("unpublished", [False, True])
def test_six_post_first_transition_retains_final_second_policy(client, tmp_path, monkeypatch, reverse, owned_dns, inert_history, unpublished):
    from app.services.provider_keyed_mixed_published_absence import (
        prove_published_mixed_provider_absence, propose_published_mixed_first_absence_event,
        prove_published_mixed_both_absent, propose_published_mixed_second_absence_event)
    from app.services.provider_keyed_mixed_published_second_transition import review_published_mixed_second_transition
    from test_provider_keyed_mixed_published_absence import _awaiting, _empty_snapshot
    with client.application.storage_context():
        if unpublished and owned_dns:
            pytest.skip("unpublished cleanup requires no active bindings")
        zone = _owned_dns_setup(tmp_path, monkeypatch) if owned_dns else None
        jobs, plans_repo, sketches, core, collection = _persist(client, tmp_path, monkeypatch, reverse,
            before_collect=zone.seed if zone else None, inert_history=inert_history, unpublished=unpublished)
        review = collection.review
        source = review.source
        ignored = tuple(row for row in sketches.list_for_engagement(source.engagement_id)
                        if row.chain_id not in source.chain_ids)
        assert len(ignored) == int(inert_history)
        scope = collection.core_inspector_scope
        queued = propose_published_mixed_initial_cleanup(review, scope, "Opaque", requested_by="operator")
        queued = jobs.reserve_published_mixed_initial_cleanup_parent(queued, collection=collection,
            expected_snapshot_id=queued.input["reviewSnapshotId"])
        plans, states, _paths, _binary = _attested_plans(jobs, collection, tmp_path)
        parent = jobs.seal_published_mixed_initial_destroy_plans(queued, collection=collection,
            plan_set=plans, before_states=states)
        initial = jobs.get(source.parent_job_id)
        first, second = source.ordered_providers
        # A fixture command-result journal represents rc0 provider deletion.
        # All receipt and transition readers below are the production functions.
        first_child = _awaiting(parent, review, plans, scope, first)
        first_snapshot = _empty_snapshot(plans.plans[0])
        fence = lambda: "stable"
        receipt = prove_published_mixed_provider_absence(initial, parent, review, plans,
            first, first_child, first_snapshot, scope, "Opaque",
            fence=fence, process_quiescent=lambda _: True)
        first_child = jobs.save(replace(first_child, status="succeeded",
            finished_at=first_child.started_at,
            events=[*first_child.events, propose_published_mixed_first_absence_event(first_child, receipt)]))
        collection.workspaces[first].joinpath("terraform.tfstate").write_bytes(first_snapshot.state_json)
        assert six_historical_rows_sha256(review, jobs=jobs, plans=plans_repo,
            sketches=sketches) == review.historical_rows_sha256
        kwargs = dict(fence=fence, process_quiescent=lambda _: True,
            historical_source_unchanged=lambda: six_historical_rows_sha256(
                review, jobs=jobs, plans=plans_repo, sketches=sketches) == review.historical_rows_sha256,
            fresh_core_inspector_scope=lambda: scope,
            fresh_empty_bindings=lambda: {kind: () for kind in ("channels", "domains", "certificates", "sites")})
        transition = review_published_mixed_second_transition(initial, parent, review, plans,
            first_child, first_snapshot, collection.observations[second], scope, "Opaque", **kwargs)
        assert transition.second_provider == second
        assert transition.second_state_sha256 == plans.plans[1].before_state_sha256
        second_child = _awaiting(parent, review, plans, scope, second, prior=receipt.receipt_sha256)
        second_snapshot = _empty_snapshot(plans.plans[1])
        receipts = prove_published_mixed_both_absent(initial, parent, review, plans,
            {first: first_child, second: second_child}, {first: first_snapshot, second: second_snapshot},
            scope, "Opaque", fence=fence, process_quiescent=lambda _: True)
        second_child = jobs.save(replace(second_child, status="succeeded",
            finished_at=second_child.started_at, events=[*second_child.events,
                propose_published_mixed_second_absence_event(second_child, receipts[1], receipts[0])]))
        assert all(len(row.verified_absent_ids) == (4 if row.provider == "linode" else 5) for row in receipts)
        assert second_child.input["priorAbsenceReceiptSha256"] == receipts[0].receipt_sha256
        # Historical source remains valid once both states are empty.
        collection.workspaces[second].joinpath("terraform.tfstate").write_bytes(second_snapshot.state_json)
        assert six_historical_rows_sha256(review, jobs=jobs, plans=plans_repo,
            sketches=sketches) == review.historical_rows_sha256
        from app.services.provider_keyed_mixed_published_post_oci_source import audit_published_mixed_post_oci_source
        def audit_tail():
            if zone:
                from app.services.provider_keyed_mixed_published_binding_manifest import advance_published_owned_bindings
                assert zone.writes == 1
                advance_published_owned_bindings(parent, environment="devtest", state_root=tmp_path, jobs=jobs)
                assert zone.writes == 1
                from app.domain import JobEvent
                from app.storage.domain_repository import SqlAlchemyDomainRepository
                from app.services.provider_keyed_mixed_published_binding_manifest import (
                    require_published_bindings_unchanged, mixed_owned_dns_child_id)
                # Retired rows are accepted only with the exact existing DNS proof;
                # neither a forged terminal readback nor edited creating journal is normalized.
                dns_child = jobs.get(mixed_owned_dns_child_id(parent.id, "domain-six"))
                terminal_event = dns_child.events[-1]
                jobs.save(replace(dns_child, events=[*dns_child.events[:-1], replace(terminal_event,
                    data={**terminal_event.data, "freshFingerprint": "forged"})]))
                with pytest.raises(ValueError):
                    require_published_bindings_unchanged(review, jobs, SqlAlchemyDomainRepository(), require_dns_absent=True)
                jobs.save(dns_child)
                creator = jobs.get("job-dns-six")
                jobs.save(replace(creator, events=[*creator.events, JobEvent(2, "info", "changed", {})]))
                with pytest.raises(ValueError):
                    require_published_bindings_unchanged(review, jobs, SqlAlchemyDomainRepository(), require_dns_absent=True)
                jobs.save(creator)
                require_published_bindings_unchanged(review, jobs, SqlAlchemyDomainRepository(), require_dns_absent=True)
            post_oci = audit_published_mixed_post_oci_source(parent, initial, core,
                plans_repo.get(source.core_plan_id), jobs, _db_lease_lookup,
                sketch_repository=sketches,
                active_core_reader=lambda *_: (core.id, []),
                binding_reader=lambda *_: {kind: () for kind in ("channels", "domains", "certificates", "sites")},
                inspector_record_reader=lambda *_: tuple(scope["ownedInspectorRecordIds"]))
            assert post_oci.provider_absence_receipt_sha256 == tuple(row.receipt_sha256 for row in receipts)
        # The existing coordinator resumes this exact parent after both provider
        # receipts. External OCI/Inspector child engines are witnesses here;
        # their independent suites cover the actual irreversible commands.
        from app.services.provider_keyed_mixed_published_public import advance_published_mixed_cleanup
        calls = []
        def step(name):
            def run(*_a, **_k):
                calls.append(name)
                if name == "oci":
                    audit_tail()
                return SimpleNamespace(status="succeeded")
            return run
        from app.services import provider_keyed_mixed_published_terminal as terminal_service
        def terminal(*_a, **_k):
            calls.append("terminal")
            assert saved_published_mixed_initial_review(jobs.get(parent.id)) == review
            # Prior OCI/Inspector receipts are witnesses in this offline test.
            # Exercise the real atomic local retirement and lifecycle writer.
            def historical(*_args):
                assert six_historical_rows_sha256(review, jobs=jobs, plans=plans_repo,
                    sketches=sketches) == review.historical_rows_sha256
                from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
                selected = reviewed_mixed_chain_rows(sketches.list_for_engagement(
                    source.engagement_id), source.chain_ids, source.engagement_id)
                return parent, plans_repo.get(source.core_plan_id), selected, [], {
                        "providerJournalSha256": [row.destroy_child_journal_sha256 for row in receipts],
                        "ociAbsenceJournalSha256": "a" * 64,
                        "inspectorJournalSha256": "b" * 64}
            monkeypatch.setattr(terminal_service, "_history", historical)
            return terminal_service.finish_published_mixed_terminal(source.engagement_id,
                core.id, environment="devtest", job_repository=jobs)
        result = advance_published_mixed_cleanup(parent.id, environment="devtest",
            positive_control_ipv4="1.1.1.1", job_repository=jobs,
            first_runner=lambda *_a, **_k: pytest.fail("first destroy replayed"),
            first_absence=lambda *_a, **_k: pytest.fail("first receipt replayed"),
            second_runner=lambda *_a, **_k: pytest.fail("second destroy replayed"),
            second_absence=lambda *_a, **_k: pytest.fail("second receipt replayed"),
            oci_tail=step("oci"), inspector_tail=step("inspector"), terminal=terminal)
        assert result.status == "succeeded"
        assert calls == ["oci", "inspector", "terminal"]
        if zone:
            from app.storage.models import (CertificateAssetModel, CertificateBindingModel,
                EngagementServiceModel, DomainDnsRecordOwnershipModel)
            assert zone.writes == 1
            assert [(row.name, row.address) for row in zone.hosts] == [("unrelated", "retain")]
            assert all(row.retired_at is not None for row in db.session.query(DomainDnsRecordOwnershipModel).all())
            binding = db.session.get(CertificateBindingModel, "binding-six")
            assert binding.status == "unbound" and binding.last_job_id == result.id
            asset = db.session.get(CertificateAssetModel, "cert-six")
            assert asset.status == "issued" and asset.current_version_id == "version-retained"
            site = db.session.query(EngagementServiceModel).filter_by(service_id="site-six").one()
            assert site.status == "Removed" and site.config["assetId"] == "asset-retained"
            for key in ("inboundChannels", "outboundChannels"):
                assert result.events[-1].data[key][0]["status"] == "Pending Apply"
                assert result.events[-1].data[key][0]["validation"]["externalIngressVerified"] is False
            assert result.events[-1].data["inboundChannels"][0]["hostname"] == "www.opaque.example"
            assert result.events[-1].data["inboundChannels"][0]["certificate"]["status"] == "unbound"

        assert tuple(row for row in sketches.list_for_engagement(source.engagement_id)
                     if row.chain_id not in source.chain_ids) == ignored
        final_chains = [row for row in sketches.list_for_engagement(source.engagement_id)
                        if row.chain_id in source.chain_ids]
        assert all(row.status == "destroyed" and row.nodes == [] and row.edge_count == (1 if unpublished else 2)
                   for row in final_chains)
        assert _db_lease_lookup(source.engagement_id) is None
        assert terminal_service.recognize_published_mixed_terminal(source.engagement_id,
            core.id, environment="devtest", job_repository=jobs) == result
        # Startup/POST dispatch reads the same terminal parent without replay.
        assert advance_published_mixed_cleanup(parent.id, environment="devtest",
            positive_control_ipv4="1.1.1.1", job_repository=jobs,
            first_runner=lambda *_a, **_k: pytest.fail("terminal destroy replayed")) == result


def _owned_dns_setup(tmp_path, monkeypatch):
    from app.domain import JobEvent
    from app.services import engagement_dns
    from app.storage.models import (DomainAssetModel, DomainAssignmentModel,
        DomainDnsSnapshotModel, DomainDnsRecordOwnershipModel, CertificateAssetModel,
        CertificateBindingModel, EngagementServiceModel)
    from test_fastapi_domain_dns_runtime import FakeNamecheapHost
    monkeypatch.setenv("BARRAGAN_DNS01_LOCK_DIR", str(tmp_path / "dns-locks"))
    class Zone:
        writes = 0
        hosts = []
        def seed(self, source, jobs, initial):
            edge_ip = source.chains[0].nodes[2]["publicIp"]
            self.hosts = [FakeNamecheapHost("www", "A", edge_ip),
                FakeNamecheapHost("_acme-challenge.www", "TXT", "opaque-token", "60"),
                FakeNamecheapHost("unrelated", "TXT", "retain", "600")]
            db.session.add(DomainAssetModel(id="domain-six", domain_name="opaque.example", registrar="namecheap"))
            db.session.flush()
            assignment = DomainAssignmentModel(domain_id="domain-six", engagement_id=source.engagement_id,
                engagement_name="Opaque", status="active")
            db.session.add(assignment)
            db.session.flush()
            dns_job = jobs.save(replace(initial, id="job-dns-six", action="engagement_dns_apply",
                input={"domainId": "domain-six"}, events=[]))
            records = [{"name": row.name, "type": row.record_type, "address": row.address,
                "ttl": row.ttl, "mxPref": row.mx_pref} for row in self.hosts]
            snapshot = DomainDnsSnapshotModel(domain_id="domain-six", provider="namecheap", hosts=records,
                sync_job_id=dns_job.id)
            db.session.add(snapshot)
            db.session.flush()
            for record in records[:2]:
                db.session.add(DomainDnsRecordOwnershipModel(domain_id="domain-six", assignment_id=assignment.id,
                    engagement_id=source.engagement_id, creating_job_id=dns_job.id, snapshot_id=snapshot.id, record=record))
            db.session.add(CertificateAssetModel(id="cert-six", engagement_id=source.engagement_id,
                name="desired", source="acme", target_proxy_id="proxy-1", identifiers=["www.opaque.example"],
                primary_identifier="www.opaque.example", status="issued", current_version_id="version-retained"))
            db.session.flush()
            db.session.add(CertificateBindingModel(id="binding-six", engagement_id=source.engagement_id,
                certificate_id="cert-six", service_id="site-six", channel_id="channel-six",
                hostname="www.opaque.example", status="bound", validation={"status": "verified"}))
            db.session.add(EngagementServiceModel(engagement_id=source.engagement_id, service_id="site-six",
                service_type="web", name="desired", proxy_id="proxy-1", status="Applied",
                config={"hostname": "www.opaque.example", "assetId": "asset-retained"}))
            db.session.commit()
            jobs.save(replace(initial, id="job-channel-six", action="engagement_channels_update",
                input={}, events=[JobEvent(1, "info", "channels updated", {
                    "inboundChannels": [{"channelId": "channel-six", "status": "Applied", "kind": "https",
                        "hostname": "www.opaque.example", "validation": {"status": "Verified", "externalIngressVerified": True},
                        "certificate": {"certificateId": "cert-six", "status": "bound"}}],
                    "outboundChannels": [{"channelId": "out-six", "status": "Applied", "kind": "tcp"}]})]))
            jobs.save(replace(dns_job, events=[JobEvent(1, "info",
                "Namecheap DNS setHosts completed with full desired host list", {"snapshotId": snapshot.id})]))
        def get_hosts(self, domain_name):
            assert domain_name == "opaque.example"
            return list(self.hosts)
        def set_hosts(self, domain_name, hosts):
            self.writes += 1
            self.hosts = [FakeNamecheapHost(row.name, row.record_type, row.address, row.ttl, row.mx_pref) for row in hosts]
            # Exercise existing GET-only lost-response recovery, never replay.
            raise TimeoutError("lost response")
    zone = Zone()
    monkeypatch.setattr(engagement_dns, "_namecheap_dns_client", lambda: zone)
    return zone


# Reuse the persisted real ingress receipt/host-proof fixture, not a fabricated
# generation object: destroying provider one must preserve its historical advance.
from test_provider_keyed_channel_generation import case as advanced_case


def test_advanced_generation_survives_first_absence_in_actual_post_first_collector(
        client, tmp_path, monkeypatch, advanced_case):
    import json
    from hashlib import sha256
    from test_provider_keyed_channel_generation import _advance, _real_host_proof
    from test_provider_keyed_mixed_published_absence import _awaiting, _empty_snapshot
    from app.services.provider_keyed_mixed_published_absence import (
        prove_published_mixed_provider_absence, propose_published_mixed_first_absence_event)
    from app.services import provider_keyed_mixed_published_post_first_collector as post_first
    from app.services import provider_keyed_mixed_published_six_collector as six_collector
    from app.services.provider_keyed_channel_generation import read_channel_generation
    case = advanced_case
    job, artifacts, routes = _advance(case)
    _real_host_proof(case, job, routes, monkeypatch)
    source = case["source"]
    for index, provider in enumerate(source.provider_order):
        old = case["observations"][provider]
        raw = Path(source.workspace_paths[index]).joinpath("terraform.tfstate").read_bytes()
        case["observations"][provider] = replace(old, state_json=raw, classification=replace(
            old.classification, state_sha256=sha256(raw).hexdigest(), serial=json.loads(raw)["serial"]))
    jobs, plans_repo, sketches, core, collection = _persist(client, tmp_path, monkeypatch, False,
        existing_case=case)
    review, scope = collection.review, collection.core_inspector_scope
    queued = propose_published_mixed_initial_cleanup(review, scope, "Opaque", requested_by="operator")
    queued = jobs.reserve_published_mixed_initial_cleanup_parent(queued, collection=collection,
        expected_snapshot_id=queued.input["reviewSnapshotId"])
    plans, states, *_ = _attested_plans(jobs, collection, tmp_path)
    parent = jobs.seal_published_mixed_initial_destroy_plans(queued, collection=collection,
        plan_set=plans, before_states=states)
    initial = jobs.get(review.source.parent_job_id)
    first, second = source.provider_order
    child = _awaiting(parent, review, plans, scope, first)
    from test_provider_keyed_mixed_interrupted_source import _snapshot
    empty = _snapshot(first, tag=first == "digitalocean", phase="destroy_applied",
        state=_empty_snapshot(plans.plans[0]).state_json, generation=f"{parent.id}:{plans.plan_set_sha256}")
    receipt = prove_published_mixed_provider_absence(initial, parent, review, plans, first,
        child, empty, scope, "Opaque", fence=lambda: f"{parent.id}:{plans.plan_set_sha256}", process_quiescent=lambda _: True)
    child = jobs.save(replace(child, status="succeeded", finished_at=child.started_at,
        events=[*child.events, propose_published_mixed_first_absence_event(child, receipt)]))
    collection.workspaces[first].joinpath("terraform.tfstate").write_bytes(empty.state_json)
    with pytest.raises(ValueError, match="current state"):
        read_channel_generation(source, case["append_parent"], initial, jobs)
    assert six_historical_rows_sha256(review, jobs=jobs, plans=plans_repo, sketches=sketches) == review.historical_rows_sha256
    monkeypatch.setattr(post_first, "_core_inspector_scope", lambda *_a, **_k: scope)
    monkeypatch.setattr(post_first, "recognize_mixed_initial_apply_terminal", lambda *_: {})
    monkeypatch.setattr(post_first, "_prior_workspace", lambda _i, provider, _t:
        SimpleNamespace(path=collection.workspaces[provider]))
    monkeypatch.setattr(post_first, "collect_provider_inventory_snapshot", lambda *_a, **_k: empty)
    seen = []
    def observe(provider, *_args, current_generation=None, **_kwargs):
        assert provider == second
        assert len(current_generation.advances) == 2
        assert current_generation.policies == review.reviewed_policies
        seen.append(provider)
        return case["observations"][provider]
    monkeypatch.setattr(six_collector, "_fresh_observation", observe)
    reopened = post_first.collect_published_mixed_post_first_transition(parent.id,
        job_repository=jobs, plan_repository=plans_repo, sketch_repository=sketches,
        process_quiescent=lambda *_: True)
    assert seen == [second] and reopened.transition.second_provider == second


@pytest.mark.parametrize("drift", ["duplicate", "foreign", "native_association"])
def test_six_destroy_binding_rejects_changed_chain_membership_or_native_association(
        client, tmp_path, monkeypatch, drift):
    from app.services.provider_keyed_mixed_published_destroy_plan import PublishedMixedDestroyPlanAttention
    with client.application.storage_context():
        jobs, _plans, _sketches, _core, collection = _persist(client, tmp_path, monkeypatch, False)
        source = collection.review.source.six_node_source
        if drift == "duplicate":
            source = replace(source, chain_ids=(source.chain_ids[0], source.chain_ids[0]))
        elif drift == "foreign":
            source = replace(source, chain_ids=(source.chain_ids[0], "foreign-chain"))
        else:
            source = replace(source, before_chains=tuple(
                replace(chain, middle_provider=("linode" if chain.middle_provider == "digitalocean" else "digitalocean"))
                for chain in source.before_chains))
        review = replace(collection.review, source=replace(collection.review.source, six_node_source=source))
        collection = replace(collection, review=review)
        with pytest.raises(PublishedMixedDestroyPlanAttention):
            _attested_plans(jobs, collection, tmp_path)


def test_new_six_review_cannot_downgrade_to_historical_core_only_manifest(client, tmp_path, monkeypatch):
    from copy import deepcopy
    from app.services.provider_keyed_mixed_published_binding_manifest import _digest
    with client.application.storage_context():
        jobs, plans, sketches, core, collection = _persist(client, tmp_path, monkeypatch, False)
        manifest = deepcopy(collection.review.binding_manifest)
        manifest.pop("publicTargetSeal")
        manifest["manifestSha256"] = _digest({key: value for key, value in manifest.items()
                                              if key != "manifestSha256"})
        legacy_review = replace(collection.review, binding_manifest=manifest)
        with pytest.raises(ValueError, match="sealed public targets"):
            propose_published_mixed_initial_cleanup(legacy_review, collection.core_inspector_scope,
                "Opaque", requested_by="operator")
        # A read-only historical reconstruction keeps old bytes and their old coverage.
        legacy = propose_published_mixed_initial_cleanup(legacy_review, collection.core_inspector_scope,
            "Opaque", requested_by="operator", _historical=True)
        assert "publicTargetSealSha256" not in legacy.input
        assert saved_published_mixed_initial_review(legacy) == legacy_review
