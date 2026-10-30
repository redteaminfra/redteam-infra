# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact external-binding review and existing owned-DNS cleanup handoff.

The manifest and local fences are read-only. After both provider absence
receipts, the coordinator delegates owned DNS removal to the existing
one-shot engine; desired channels, certificate assets and site config remain.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from app.services.engagement_dns import _canonical_record, preview_owned_dns_cleanup
from app.services.engagement_teardown import _active_keyed_domain_assignments
from app.services.provider_keyed_mixed_append_live_bindings import (
    _owned_dns_rows, collect_mixed_append_live_bindings,
)
from app.services.provider_keyed_mixed_append_pair_host_proof import (
    SixNodeHostSource, validate_six_node_host_source,
)
from app.services.provider_keyed_mixed_initial_host_binding import _digest as _scope_digest
from app.services.provider_keyed_mixed_published_six_scope import PublishedMixedSixScope
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.domain_repository import StoredDomainDnsRecordOwnership
from app.storage.job_repository import SqlAlchemyJobRepository


class MixedPublishedBindingManifestAttention(ValueError):
    """The exact owned external-binding preview could not be proved."""


_BINDING_KINDS = frozenset({"channels", "domains", "certificates", "sites"})
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def _binding_snapshot(value: Mapping[str, tuple]) -> dict[str, tuple]:
    if (not isinstance(value, Mapping) or set(value) != _BINDING_KINDS
            or any(type(rows) is not tuple or any(
                type(row) is not tuple or len(row) != 3
                or any(type(item) is not str or not item for item in row)
                for row in rows) for rows in value.values())):
        raise ValueError("engagement binding inventory is incomplete")
    return {kind: value[kind] for kind in sorted(_BINDING_KINDS)}


def build_mixed_published_binding_manifest(
    source: SixNodeHostSource, scope: PublishedMixedSixScope, *,
    domain_repository=None, job_repository=None, dns_adapter=None,
    binding_inventory: Callable[[str], Mapping[str, tuple]] = collect_mixed_append_live_bindings,
    dns_ownership_reader: Callable[[str], list] | None = None,
    dns_preview: Callable = preview_owned_dns_cleanup,
    expected_manifest: dict[str, Any] | None = None,
    core_targets: list[dict] | None = None,
    host_routes_reader: Callable | None = None,
) -> dict[str, Any]:
    """Preview exact owned DNS targets and all four public edges, without writes.

    ``expected_manifest`` turns the same read-only operation into a pre-GO
    comparison. The caller supplies the authenticated published six-node scope
    and holds its engagement mutation fence across this read.
    """
    try:
        validate_six_node_host_source(source)
        if (type(scope) is not PublishedMixedSixScope
                or scope.source_sha256 != source.source_sha256):
            raise ValueError("published six-node source changed")
        engagement_id = source.engagement_id
        bindings = _binding_snapshot(binding_inventory(engagement_id))
        binding_sha = _scope_digest({"schema": "mixed-published-six-bindings-v1",
                                     "bindings": bindings})
        if (binding_sha != scope.bindings_sha256
                or sum(len(rows) for rows in bindings.values()) != scope.binding_count):
            raise ValueError("published engagement binding inventory changed")

        edge_targets = sorted(({
            "chainId": chain.chain_id,
            "provider": node["provider"],
            "terraformAddress": node["terraformAddress"],
            "providerInstanceId": node["providerInstanceId"],
            "publicIp": node["publicIp"],
        } for chain in source.chains for node in chain.nodes
            if node["role"] == "edge"),
            key=lambda row: (row["chainId"], row["terraformAddress"]))
        edge_ips = sorted({row["publicIp"] for row in edge_targets})
        if len(edge_targets) != 4 or len(edge_ips) != 4:
            raise ValueError("four exact published edges are required")

        domains = domain_repository or SqlAlchemyDomainRepository()
        jobs = job_repository or SqlAlchemyJobRepository()
        assignments = _active_keyed_domain_assignments(engagement_id, domains)
        read_ownership = dns_ownership_reader or _owned_dns_rows

        def active_ownership() -> tuple[StoredDomainDnsRecordOwnership, ...]:
            rows = read_ownership(engagement_id)
            if type(rows) is not list or any(
                type(row) is not StoredDomainDnsRecordOwnership
                or row.engagement_id != engagement_id for row in rows
            ):
                raise ValueError("engagement-owned DNS inventory is incomplete")
            active = tuple(sorted((deepcopy(row) for row in rows if row.retired_at is None),
                                  key=lambda row: row.id))
            if (any(type(row.id) is not int or row.id <= 0
                    or type(row.assignment_id) is not int or row.assignment_id <= 0
                    or type(row.domain_id) is not str or not row.domain_id
                    or type(row.record) is not dict
                    for row in active)
                    or len({row.id for row in active}) != len(active)):
                raise ValueError("active owned DNS receipt identity is ambiguous")
            return active

        ownership = active_ownership()
        assignments_by_id = {row["domainId"]: row["assignmentId"]
                             for row in assignments}
        if any(assignments_by_id.get(row.domain_id) != row.assignment_id
               for row in ownership):
            raise ValueError("active DNS ownership has no matching active assignment")
        entries = []
        for assignment in assignments:
            preview = dns_preview(
                engagement_id, assignment["domainId"], edge_ips,
                repository=domains, job_repository=jobs, adapter=dns_adapter,
            )
            if (type(preview) is not dict
                    or preview.get("engagementId") != engagement_id
                    or preview.get("domainId") != assignment["domainId"]
                    or preview.get("assignmentId") != assignment["assignmentId"]
                    or preview.get("oldEdgeIps") != edge_ips
                    or type(preview.get("blockers")) is not list
                    or preview["blockers"]
                    or type(preview.get("ownedRecords")) is not list
                    or type(preview.get("zoneFingerprint")) is not str
                    or _SHA256.fullmatch(preview["zoneFingerprint"]) is None
                    or preview.get("planSha256") != _digest({
                        key: value for key, value in preview.items()
                        if key != "planSha256"})):
                raise ValueError("owned DNS preview differs or has blockers")
            owned = []
            for row in preview["ownedRecords"]:
                if (type(row) is not dict or type(row.get("ownershipId")) is not int
                        or row["ownershipId"] <= 0 or type(row.get("record")) is not dict):
                    raise ValueError("owned DNS receipt is malformed")
                record = _canonical_record(row["record"])
                if (not record["name"] or not record["type"]
                        or not record["address"] or not record["ttl"]):
                    raise ValueError("owned DNS target is not canonical")
                owned.append({"ownershipId": row["ownershipId"], "record": record})
            owned.sort(key=lambda row: row["ownershipId"])
            if len({row["ownershipId"] for row in owned}) != len(owned):
                raise ValueError("owned DNS receipt repeats")
            if {row["ownershipId"] for row in owned} != {
                    row.id for row in ownership if row.domain_id == assignment["domainId"]}:
                raise ValueError("active DNS ownership differs from provider preview")
            ownership_by_id = {row.id: row for row in ownership
                               if row.domain_id == assignment["domainId"]}
            if any(row["record"] != _canonical_record(
                    ownership_by_id[row["ownershipId"]].record) for row in owned):
                raise ValueError("active DNS receipt target differs from provider preview")
            from app.services.engagement_dns import _keyed_cleanup_receipts
            receipt_proofs = _keyed_cleanup_receipts(SimpleNamespace(
                target_id=engagement_id, input={"domainId": assignment["domainId"],
                    "previewPlan": preview, "authority": {"assignment_id": assignment["assignmentId"]}}),
                domains, jobs)
            entry = {
                "domainId": assignment["domainId"],
                "domainName": assignment["domainName"],
                "assignmentId": assignment["assignmentId"],
                "zoneFingerprint": preview["zoneFingerprint"],
                "cleanupPlanSha256": preview["planSha256"],
                "previewPlan": preview, "receiptProofs": receipt_proofs,
                "ownedRecords": owned,
                "ownedRecordsSha256": _digest(owned),
            }
            entry["entrySha256"] = _digest(entry)
            entries.append(entry)

        if (_active_keyed_domain_assignments(engagement_id, domains) != assignments
                or active_ownership() != ownership
                or _binding_snapshot(binding_inventory(engagement_id)) != bindings):
            raise ValueError("bindings changed during DNS preview")
        manifest = {
            "schema": "mixed-published-binding-manifest-v1",
            "engagementId": engagement_id,
            "coreJobId": source.core_job_id,
            "appendParentId": source.parent_id,
            "sourceSha256": source.source_sha256,
            "bindingsSha256": binding_sha,
            "bindingCount": scope.binding_count,
            "bindingSnapshot": json.loads(json.dumps(bindings)),
            "edgeTargets": edge_targets,
            "edgePublicIps": edge_ips,
            "domainAssignments": assignments,
            "domains": entries,
        }
        from app.services.provider_keyed_channel_apply import _prior_host_routes
        from app.services.provider_keyed_mixed_public_targets import build_public_target_seal
        routes = (host_routes_reader or _prior_host_routes)(source, jobs)
        manifest["publicTargetSeal"] = build_public_target_seal(manifest, core_targets or [], routes)
        manifest["manifestSha256"] = _digest(manifest)
        if expected_manifest is not None and manifest != expected_manifest:
            raise ValueError("reviewed external-binding manifest changed")
        return manifest
    except Exception:
        raise MixedPublishedBindingManifestAttention(
            "published external bindings require exact read-only review") from None


def mixed_owned_dns_child_id(parent_id, domain_id):
    key = hashlib.sha256(json.dumps({"parentId": parent_id, "domainId": domain_id,
        "schema": "keyed-owned-dns-cleanup-v1"}, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()[:32]
    return f"job-engagement-dns-owned-cleanup-{key}"


def require_published_bindings_unchanged(review, jobs, domains, *, require_dns_absent=False):
    """Local row fence; permit only exact receipt-backed DNS retirement.

    Channels, assignments, certificate assets/bindings and site configuration
    remain desired data until the terminal transaction retires host bindings.
    No registrar or infrastructure provider request occurs here.
    """
    from app.services.provider_keyed_mixed_published_teardown_authority import PublishedSixTeardownSource
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import parent_id
    from app.services.engagement_dns import DNS_CLEANUP_ACTION, _canonical_record
    if type(review.source) is not PublishedSixTeardownSource:
        from app.services.provider_keyed_mixed_published_teardown_collector import _empty_owned_bindings
        return _empty_owned_bindings(review.source.engagement_id, jobs, domains)
    manifest = review.binding_manifest
    if (type(manifest) is not dict or manifest.get("manifestSha256") != _digest({
            key: value for key, value in manifest.items() if key != "manifestSha256"})):
        raise ValueError("saved binding manifest changed")
    owned = _owned_dns_rows(review.source.engagement_id)
    by_id = {row.id: row for row in owned}
    retired = set()
    for entry in manifest["domains"]:
        ids = {row["ownershipId"] for row in entry["ownedRecords"]}
        if not ids <= set(by_id) or any(
                by_id[row["ownershipId"]].domain_id != entry["domainId"]
                or by_id[row["ownershipId"]].assignment_id != entry["assignmentId"]
                or _canonical_record(by_id[row["ownershipId"]].record) != row["record"]
                for row in entry["ownedRecords"]):
            raise ValueError("reviewed DNS ownership changed")
        changed = {key for key in ids if by_id[key].retired_at is not None}
        child = jobs.get(mixed_owned_dns_child_id(parent_id(review.source.core_job_id), entry["domainId"]))
        if changed or require_dns_absent:
            if (child is None or child.action != DNS_CLEANUP_ACTION or child.status != "succeeded"
                    or child.target_id != review.source.engagement_id
                    or child.input.get("teardownParentId") != parent_id(review.source.core_job_id)
                    or child.input.get("domainId") != entry["domainId"]
                    or child.input.get("previewPlan") != entry["previewPlan"]
                    or child.input.get("authority", {}).get("binding_sha256") != manifest["manifestSha256"]
                    or child.events[-1].message != "owned DNS cleanup verified"
                    or set(child.events[-1].data.get("retiredOwnershipIds", [])) != ids
                    or changed != ids):
                raise ValueError("owned DNS retirement receipt differs")
            retired.update(ids)
    normalized = [replace(row, retired_at=None) if row.id in retired else row for row in owned]
    from app.services.engagement_dns import _keyed_cleanup_receipts
    local_domains = SimpleNamespace(
        list_record_ownership=lambda domain_id, active_only=False: [row for row in normalized
            if row.domain_id == domain_id and (not active_only or row.retired_at is None)],
        list_snapshots=domains.list_snapshots)
    for entry in manifest["domains"]:
        proofs = _keyed_cleanup_receipts(SimpleNamespace(target_id=review.source.engagement_id,
            input={"domainId": entry["domainId"], "previewPlan": entry["previewPlan"],
                "authority": {"assignment_id": entry["assignmentId"]}}), local_domains, jobs)
        if proofs != entry["receiptProofs"]:
            raise ValueError("reviewed creating DNS receipt changed")
        if require_dns_absent or any(row["ownershipId"] in retired for row in entry["ownedRecords"]):
            child = jobs.get(mixed_owned_dns_child_id(parent_id(review.source.core_job_id), entry["domainId"]))
            _require_owned_dns_terminal_receipt(child, entry, domains)
    current = collect_mixed_append_live_bindings(
        review.source.engagement_id, job_repository=jobs, domain_repository=domains,
        dns_ownership_reader=lambda _: normalized)
    if json.loads(json.dumps(current)) != manifest["bindingSnapshot"]:
        raise ValueError("published desired bindings changed")
    return {kind: () for kind in ("channels", "domains", "certificates", "sites")}


def _require_owned_dns_terminal_receipt(child, entry, domains):
    """Reopen the exact one-shot journal and persisted provider readback."""
    from app.services.engagement_dns import _record_from_provider, dns_record_fingerprint
    terminal = child.events[-1]
    snapshots = {row.id: row for row in domains.list_snapshots(entry["domainId"])}
    snapshot = snapshots.get(terminal.data.get("snapshotId"))
    if (snapshot is None or snapshot.sync_job_id != child.id
            or snapshot.provider != "namecheap" or child.finished_at is None
            or child.events[0].message != "owned DNS cleanup reserved"
            or any(event.sequence != index or event.level != "info"
                   for index, event in enumerate(child.events, 1))):
        raise ValueError("owned DNS terminal journal changed")
    fresh = dns_record_fingerprint([_record_from_provider(row) for row in snapshot.hosts])
    if terminal.data.get("freshFingerprint") != fresh:
        raise ValueError("owned DNS readback snapshot changed")
    if not entry["ownedRecords"]:
        if len(child.events) != 2 or child.input.get("mutation") is not False or fresh != entry["zoneFingerprint"]:
            raise ValueError("read-only DNS cleanup receipt changed")
        return
    intent = child.events[1]
    accepted = [event for event in child.events if event.message == "owned DNS setHosts accepted"]
    if (child.input.get("mutation") is not True or intent.message != "owned DNS setHosts intended"
            or intent.data.get("receiptProofs") != entry["receiptProofs"]
            or intent.data.get("planSha256") != entry["cleanupPlanSha256"]
            or intent.data.get("assignmentId") != entry["assignmentId"]
            or intent.data.get("bindingSha256") != child.input["authority"]["binding_sha256"]
            or len(accepted) != 1 or accepted[0].sequence < 3
            or accepted[0].data.get("planSha256") != entry["cleanupPlanSha256"]
            or accepted[0].data.get("submittedFingerprint") != fresh
            or intent.data.get("submittedFingerprint") != fresh):
        raise ValueError("owned DNS mutation receipt changed")
    before = [_canonical_record(row) for row in intent.data["beforeRecords"]]
    submitted = [_canonical_record(row) for row in intent.data["submittedRecords"]]
    if (dns_record_fingerprint([_record_from_provider(row) for row in intent.data["beforeRecords"]])
            != entry["zoneFingerprint"]
            or dns_record_fingerprint([_record_from_provider(row) for row in intent.data["submittedRecords"]]) != fresh):
        raise ValueError("owned DNS zone proof changed")
    for owned in entry["ownedRecords"]:
        if before.count(owned["record"]) != 1:
            raise ValueError("owned DNS tuple differs")
        before.remove(owned["record"])
    if sorted(before, key=str) != sorted(submitted, key=str):
        raise ValueError("unowned DNS records changed")
    pending = [event for event in child.events[2:-1] if event is not accepted[0]]
    if any(event.message != "owned DNS readback pending" or event.data != {"attempt": index}
           for index, event in enumerate(pending, 1)):
        raise ValueError("owned DNS recovery journal changed")


def recheck_mixed_published_manifest_local(source, scope, saved, *, domains, jobs, core_targets=None):
    """Repeat local identity/source checks using the already reviewed DNS GET."""
    previews = {entry["domainId"]: entry["previewPlan"] for entry in saved["domains"]}
    return build_mixed_published_binding_manifest(
        source, scope, domain_repository=domains, job_repository=jobs,
        dns_preview=lambda engagement, domain, *args, **kwargs: previews[domain],
        expected_manifest=saved, core_targets=core_targets)


def load_mixed_published_dns_authority(parent, domain_id, *, jobs, plans, sketches, domains, lookup):
    """Bind the existing one-shot DNS engine to both terminal provider receipts."""
    from app.services.provider_keyed_dns_cleanup_authority import ProviderKeyedDnsCleanupAuthority
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
        saved_published_mixed_initial_review, saved_published_mixed_destroy_plans,
        recognize_published_mixed_plans_sealed)
    from app.services.provider_keyed_mixed_published_teardown_authority import (
        PublishedSixTeardownSource, six_historical_rows_sha256)
    from app.services.provider_keyed_mixed_published_destroy_child import child_id, recognize_published_mixed_destroy_child
    from app.storage.job_repository import job_event_digest
    review = saved_published_mixed_initial_review(parent)
    sealed = saved_published_mixed_destroy_plans(parent)
    source = review.source
    if type(source) is not PublishedSixTeardownSource:
        raise ValueError("six-node DNS source is required")
    recognize_published_mixed_plans_sealed(parent, review, sealed,
        parent.input["reviewScope"], parent.input["engagementName"])
    if (lookup(source.engagement_id) != (source.core_plan_id, "provider_keyed_teardown_fence")
            or six_historical_rows_sha256(review, jobs=jobs, plans=plans, sketches=sketches)
               != review.historical_rows_sha256):
        raise ValueError("mixed DNS source changed")
    require_published_bindings_unchanged(review, jobs, domains)
    children = [jobs.get(child_id(source.core_job_id, provider)) for provider in source.ordered_providers]
    for provider, child in zip(source.ordered_providers, children, strict=True):
        if child is None or recognize_published_mixed_destroy_child(child, parent, review, sealed,
                provider, parent.input["reviewScope"], parent.input["engagementName"]) != "absence_proved":
            raise ValueError("DNS cleanup requires both provider absence receipts")
    if children[1].input.get("priorAbsenceReceiptSha256") != children[0].events[7].data["receiptSha256"]:
        raise ValueError("mixed DNS provider handoff differs")
    entries = [entry for entry in review.binding_manifest["domains"] if entry["domainId"] == domain_id]
    asset = domains.get_asset(domain_id)
    assignments = [row for row in domains.list_assignments(domain_id=domain_id) if row.status == "active"]
    if (len(entries) != 1 or asset is None or asset.registrar != "namecheap"
            or len(assignments) != 1 or assignments[0].id != entries[0]["assignmentId"]
            or assignments[0].engagement_id != source.engagement_id):
        raise ValueError("mixed DNS assignment differs")
    initial = jobs.get(source.parent_job_id)
    return ProviderKeyedDnsCleanupAuthority(
        source.engagement_id, domain_id, assignments[0].id, parent.id,
        source.core_job_id, initial.id, children[1].id, parent.input["reviewSnapshotId"],
        parent.input["providerScopeSha256"], job_event_digest(parent.events),
        job_event_digest(initial.events), job_event_digest(children[1].events),
        review.binding_manifest["manifestSha256"], tuple(review.binding_manifest["edgePublicIps"]))


def advance_published_owned_bindings(parent, *, environment, state_root, jobs,
                                     domain_repository=None, dns_adapter=None):
    """Reuse the existing one-shot owned DNS engine inside the same parent."""
    from app.services.engagement_dns import run_private_keyed_owned_dns_cleanup, recover_private_keyed_owned_dns_cleanup
    from app.services.provider_keyed_mixed_published_teardown_checkpoint import saved_published_mixed_initial_review
    from app.services.provider_keyed_mixed_published_teardown_authority import PublishedSixTeardownSource
    review = saved_published_mixed_initial_review(parent)
    if type(review.source) is not PublishedSixTeardownSource:
        return
    domains = domain_repository or SqlAlchemyDomainRepository()
    require_published_bindings_unchanged(review, jobs, domains)
    for entry in review.binding_manifest["domains"]:
        identifier = mixed_owned_dns_child_id(parent.id, entry["domainId"])
        child = jobs.get(identifier)
        options = dict(environment=environment, state_root=state_root,
                       repository=domains, job_repository=jobs, adapter=dns_adapter)
        if child is not None and child.status == "running":
            child = recover_private_keyed_owned_dns_cleanup(identifier, **options)
        elif child is None or child.status == "queued":
            child = run_private_keyed_owned_dns_cleanup(parent.id, entry["domainId"],
                reviewed_preview=entry["previewPlan"], **options)
        if child is None or child.status != "succeeded":
            raise ValueError("owned DNS cleanup requires exact readback; no write replay")
        require_published_bindings_unchanged(review, jobs, domains)
    require_published_bindings_unchanged(review, jobs, domains, require_dns_absent=True)
