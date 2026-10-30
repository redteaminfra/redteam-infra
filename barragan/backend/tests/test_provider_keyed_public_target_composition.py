# Copyright (c) 2026, Oracle and/or its affiliates.
"""The real persisted route proof producer feeds the target manifest."""
from types import SimpleNamespace

from app.services.provider_keyed_channel_apply import _prior_host_routes
from app.services.provider_keyed_mixed_published_binding_manifest import build_mixed_published_binding_manifest
from app.services.provider_keyed_mixed_published_six_scope import PublishedMixedSixScope
from app.services.provider_keyed_mixed_initial_host_binding import _digest
from app.services.provider_keyed_mixed_public_targets import published_targets
from app.services.provider_keyed_inspector_negative import _classified_results
from test_provider_keyed_channel_generation import case as generation_case, _advance, _real_host_proof
from test_provider_keyed_mixed_published_binding_manifest import _Domains
from test_provider_keyed_mixed_public_targets import core_targets, evidence, CONTROL


def test_persisted_six_host_interpreted_proof_joins_real_target_and_receipt_readers(generation_case, monkeypatch):
    case = generation_case
    job, _, routes = _advance(case)
    from dataclasses import asdict, replace
    from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
    chain = case["source"].chains[0]
    native = KeyedRouteIntent("native-site", "web", chain.nodes[1]["terraformAddress"],
        chain.nodes[0]["terraformAddress"], 443, 443, ("0.0.0.0/0",))
    routes = (*routes, native)
    job = case["jobs"].save(replace(job, events=[replace(event, data={**event.data,
        "routes": [asdict(route) for route in routes]}) if event.message == "keyed channel isolated host policy proved"
        else event for event in job.events]))
    _real_host_proof(case, job, routes, monkeypatch)
    assert _prior_host_routes(case["source"], case["jobs"]) == routes
    case["jobs"].save(replace(job, id="job-old-generation", events=[replace(event,
        data={**event.data, "sourceSha256": "old-generation"}) for event in job.events]))
    assert _prior_host_routes(case["source"], case["jobs"]) == routes
    # A removed channel projection is not proof that shared native plumbing vanished.
    from dataclasses import replace
    from app.domain import JobEvent
    case["jobs"].save(replace(job, id="job-removed-native-projection", action="engagement_channels_update",
        events=[JobEvent(1, "info", "engagement channels updated", {"inboundChannels": [
            {"channelId": native.channel_id, "status": "Removed"}]})]))
    assert _prior_host_routes(case["source"], case["jobs"]) == routes
    from app.storage.database import db
    from app.storage.models import EngagementServiceModel, CertificateAssetModel, CertificateBindingModel
    from app.services.provider_keyed_mixed_append_live_bindings import collect_mixed_append_live_bindings
    engagement = case["source"].engagement_id
    db.session.add(EngagementServiceModel(engagement_id=engagement, service_id="web-native",
        service_type="web-static", name="native", proxy_id="proxy01", status="Configured", config={}))
    db.session.add(CertificateAssetModel(id="cert-native", engagement_id=engagement, name="native",
        source="acme", target_proxy_id="proxy01", primary_identifier="native.example", status="issued"))
    db.session.flush()
    db.session.add(CertificateBindingModel(id="binding-native", engagement_id=engagement,
        certificate_id="cert-native", service_id="web-native", channel_id=native.channel_id,
        hostname="native.example", status="bound"))
    db.session.commit()
    bindings = collect_mixed_append_live_bindings(engagement, job_repository=case["jobs"],
        domain_repository=_Domains(), dns_ownership_reader=lambda _: [])
    assert bindings["sites"] and bindings["certificates"]
    scope = PublishedMixedSixScope(case["source"].source_sha256, "append-sha",
        _digest({"schema": "mixed-published-six-bindings-v1", "bindings": bindings}),
        sum(len(rows) for rows in bindings.values()), ({}, {}))
    manifest = build_mixed_published_binding_manifest(case["source"], scope,
        domain_repository=_Domains(), job_repository=case["jobs"], core_targets=core_targets(),
        binding_inventory=lambda _: bindings, dns_ownership_reader=lambda _: [])
    parent = SimpleNamespace(input={"bindingManifest": manifest,
        "publicTargetSealSha256": manifest["publicTargetSeal"]["sha256"]})
    targets = published_targets(parent, core_targets())
    assert len(targets) == 4 and len(manifest["publicTargetSeal"]["listeners"]) == 2
    assert any(target["host"] == chain.nodes[1]["publicIp"] and target.get("port") == 443 for target in targets)
    assert len(_classified_results(evidence(targets), targets, CONTROL)) == 4
