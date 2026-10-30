# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published target producer joined to sealed restart and probe receipt readers."""
from copy import deepcopy
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_public_targets import build_public_target_seal, published_targets, digest
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import _targets
from app.services.provider_keyed_inspector_negative import _classified_results
from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
from app.services.provider_keyed_mixed_published_binding_manifest import build_mixed_published_binding_manifest
from test_provider_keyed_mixed_published_binding_manifest import _case, _owned_setup, _Zone

CONTROL = {"id": "inspector-external-control", "type": "tcp", "host": "1.1.1.1", "port": 443}


def core_targets():
    core = SimpleNamespace(events=[JobEvent(1, "info", "pilot Standard RTI run finished", {
        "connectionDetails": [{"role": "homebase", "publicIp": "8.8.8.8"},
                              {"role": "proxy", "publicIp": "9.9.9.9"}]})])
    return _targets(core, 1)


def routes(source):
    result = []
    for index, chain in enumerate(source.chains):
        for edge_index, node in enumerate(chain.nodes[1:]):
            for offset in range(2):
                ordinal = index * 4 + edge_index * 2 + offset
                kind = "web" if ordinal < 2 else "udp" if offset else "tcp"
                port = (80 if offset == 0 else 443) if kind == "web" else 40000 + ordinal
                result.append(KeyedRouteIntent(f"channel-{ordinal}", kind, node["terraformAddress"],
                    chain.nodes[0]["terraformAddress"], port, port if kind == "web" else 8000 + ordinal,
                    ("0.0.0.0/0",)))
    return tuple(result)


def sealed_case(tmp_path, monkeypatch):
    source, scope, inventory = _case()
    jobs, domains, owned = _owned_setup(tmp_path, monkeypatch)
    second = replace(domains.ownership[0], id=12,
        record={**owned, "name": "second", "address": "198.51.100.22"})
    domains.ownership.append(second)
    domains.snapshot = replace(domains.snapshot, hosts=[owned, second.record])
    # The real creating-job receipt and real provider readback authenticate both rows.
    manifest = build_mixed_published_binding_manifest(source, scope,
        domain_repository=domains, job_repository=jobs,
        dns_adapter=_Zone([owned, second.record,
            {"name": "manual", "type": "CNAME", "address": "unrelated.example", "ttl": "600", "mxPref": ""}]),
        binding_inventory=inventory, dns_ownership_reader=lambda _: domains.ownership,
        core_targets=core_targets(), host_routes_reader=lambda *_: routes(source))
    parent = SimpleNamespace(input={"bindingManifest": manifest,
        "publicTargetSealSha256": manifest["publicTargetSeal"]["sha256"]})
    return source, manifest, parent


def evidence(targets):
    results = [{"id": CONTROL["id"], "type": "tcp", "expected": "reachable", "ok": True, "observed": ""}]
    timeout = False
    for target in targets:
        dns = target["type"] == "dns-record-absent"
        udp = target["type"] == "udp-forbidden"
        timeout |= udp
        observed = ({resolver: {"status": "answered", "answers": []} for resolver in ("1.1.1.1", "8.8.8.8")}
                    if dns else {"status": "inconclusive", "reason": "timed_out", "errorType": "TimeoutError"}
                    if udp else {"status": "closed", "reason": "connection_refused"})
        results.append({"id": target["id"], "type": target["type"],
            "expected": "absent" if dns else "closed", "ok": not udp, "observed": observed})
    return {"ok": not timeout, "results": results}


def test_manifest_seals_eight_channels_two_owned_names_and_core_with_real_receipt_validation(tmp_path, monkeypatch):
    source, manifest, parent = sealed_case(tmp_path, monkeypatch)
    seal = manifest["publicTargetSeal"]
    assert len(seal["listeners"]) == 8 and len(seal["dns"]) == 2
    targets = published_targets(parent, core_targets())
    assert len(targets) == 12
    assert all(target["host"] in manifest["edgePublicIps"] for target in targets
               if target["targetGroup"] == "former-public-listener")
    assert all(target["host"] != "manual.one.example" for target in targets)
    classified = _classified_results(evidence(targets), targets, CONTROL)
    assert len(classified) == 12
    assert any(row["classification"] == "non_responsive_udp_after_provider_absence" for row in classified)
    assert len([row for row in classified if row["classification"] == "previous_owned_record_answer_absent"]) == 2


@pytest.mark.parametrize("change", ["drop-listener", "drop-dns", "edge-ip", "prior-answer", "drop-seal", "core"])
def test_saved_scope_rejects_omission_or_tampering(tmp_path, monkeypatch, change):
    _, manifest, parent = sealed_case(tmp_path, monkeypatch)
    parent = deepcopy(parent)
    m = parent.input["bindingManifest"]
    if change == "drop-seal":
        del m["publicTargetSeal"]
    elif change == "drop-listener":
        m["publicTargetSeal"]["listeners"].pop()
    elif change == "drop-dns":
        m["publicTargetSeal"]["dns"].pop()
    elif change == "edge-ip":
        m["edgeTargets"][0]["publicIp"] = "7.7.7.7"
    elif change == "prior-answer":
        m["domains"][0]["ownedRecords"][0]["record"]["address"] = "7.7.7.7"
    with pytest.raises(ValueError):
        published_targets(parent, core_targets()[:-1] if change == "core" else core_targets())


@pytest.mark.parametrize("change", ["omit", "repeat", "reply", "resolver-error", "old-answer", "malformed-answer", "control"])
def test_real_receipt_reader_rejects_unaccounted_or_live_targets(tmp_path, monkeypatch, change):
    _, _, parent = sealed_case(tmp_path, monkeypatch)
    targets = published_targets(parent, core_targets())
    result = evidence(targets)
    dns = next(row for row in result["results"] if row["type"] == "dns-record-absent")
    if change == "omit":
        result["results"].pop()
    elif change == "repeat":
        result["results"][-1] = result["results"][-2]
    elif change == "reply":
        result["results"][1]["observed"] = {"status": "open", "reason": "connection_succeeded"}
    elif change == "resolver-error":
        dns["observed"]["1.1.1.1"] = {"status": "inconclusive", "error": "TimeoutError"}
    elif change == "malformed-answer":
        dns["observed"]["1.1.1.1"]["answers"] = ["not-an-address"]
    elif change == "old-answer":
        target = next(target for target in targets if target["id"] == dns["id"])
        dns["observed"]["1.1.1.1"]["answers"] = [target["previousAnswer"]]
    else:
        result["results"][0]["ok"] = False
    assert _classified_results(result, targets, CONTROL) is None


@pytest.mark.parametrize("kind,answer,mx", [("A", "198.51.100.21", ""), ("AAAA", "2606:4700:4700::1111", ""),
    ("CNAME", "previous.example", ""), ("TXT", "public text", ""), ("NS", "ns.example", ""),
    ("MX", "mx.example", "10")])
def test_all_owned_dns_record_types_preserve_previous_tuple(tmp_path, monkeypatch, kind, answer, mx):
    _, manifest, _ = sealed_case(tmp_path, monkeypatch)
    record = manifest["domains"][0]["ownedRecords"][0]["record"]
    record.update(type=kind, address=answer, mxPref=mx)
    seal = build_public_target_seal(manifest, core_targets(), ())
    target = next(target for target in seal["targets"] if target["id"].endswith(":11"))
    assert target["recordType"] == kind
    assert target["previousAnswer"] == ("10 " + answer if kind == "MX" else answer)


def test_legacy_saved_parent_stays_core_only_without_rewriting_receipts():
    parent = SimpleNamespace(input={"bindingManifest": {"schema": "old"}})
    assert published_targets(parent, core_targets()) == core_targets()


def test_manifest_targets_are_consumed_by_real_terminal_receipt_validator(tmp_path, monkeypatch):
    from app.services.provider_keyed_mixed_published_terminal import _saved_public_receipts
    from app.storage.job_repository import job_event_digest
    from test_provider_keyed_mixed_published_terminal import _job
    _, manifest, parent = sealed_case(tmp_path, monkeypatch)
    parent.id = "job-cleanup"
    parent.input["publishedSourceSha256"] = "a" * 64
    core = SimpleNamespace(id=manifest["coreJobId"], events=[JobEvent(1, "info", "pilot Standard RTI run finished", {
        "connectionDetails": [{"role": "homebase", "publicIp": "8.8.8.8"}, {"role": "proxy", "publicIp": "9.9.9.9"}]})])
    plan = SimpleNamespace(id="plan-core", evidence={"proxyCount": 1})
    preview, applied = _job("preview", "preview"), _job("apply", "apply")
    absent = _job("absence", "absence", inputs={"teardownParentId": parent.id,
        "coreJobId": core.id, "corePlanId": plan.id, "sourceSha256": "a" * 64,
        "previewJobId": preview.id, "previewJournalSha256": job_event_digest(preview.events),
        "applyJobId": applied.id, "applyJournalSha256": job_event_digest(applied.events)}, events=[
            JobEvent(1, "info", "mixed core absence queued", {}),
            JobEvent(2, "info", "mixed core absence started", {}),
            JobEvent(3, "info", "mixed core exact absence proved", {"ociAbsenceWitness": {"phase": "absent"}})])
    targets = published_targets(parent, core_targets())
    rounds = [evidence(targets), evidence(targets)]
    negative = _job("negative", "negative", inputs={"teardownParentId": parent.id,
        "coreJobId": core.id, "corePlanId": plan.id, "sourceSha256": "a" * 64,
        "ociAbsenceJobId": absent.id, "ociAbsenceJournalSha256": job_event_digest(absent.events),
        "publicTargetSealSha256": parent.input["publicTargetSealSha256"], "targetCount": len(targets),
        "targetSha256": digest(targets), "positiveControl": CONTROL}, events=[
            JobEvent(1, "info", "mixed Inspector negative queued", {}),
            JobEvent(2, "info", "mixed Inspector negative started", {}),
            JobEvent(3, "info", "mixed Inspector exact public negative proved", {
                "targetSha256": digest(targets), "rounds": rounds,
                "classifications": [_classified_results(result, targets, CONTROL) for result in rounds]})])
    _saved_public_receipts(parent, core, plan, preview, applied, absent, negative)
    for field, value in [("targetCount", 2), ("publicTargetSealSha256", None), ("targetSha256", digest(core_targets()))]:
        changed = replace(negative, input={**negative.input, field: value})
        with pytest.raises(ValueError, match="target seal"):
            _saved_public_receipts(parent, core, plan, preview, applied, absent, changed)


def test_shared_listener_probe_deduplicates_without_losing_channel_provenance(tmp_path, monkeypatch):
    source, manifest, _ = sealed_case(tmp_path, monkeypatch)
    original = routes(source)
    sibling = replace(original[0], channel_id="sibling-hostname")
    seal = build_public_target_seal(manifest, core_targets(), (*original, sibling))
    assert len(seal["listeners"]) == 9 and len(seal["targets"]) == 12
    identities = {row["channelId"]: row["targetId"] for row in seal["listeners"]}
    assert identities[sibling.channel_id] == identities[original[0].channel_id]
    with pytest.raises(ValueError, match="listener route"):
        build_public_target_seal(manifest, core_targets(), (replace(sibling, edge_node="unmanaged-edge"),))
