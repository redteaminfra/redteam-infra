# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, replay-free receipt for a complete mixed initial host proof.

The receipt is not a chain writer.  Every read rechecks the service-owned raw
artifact and interprets all four selected hosts against a freshly rebound
MixedInitialPublicationSource.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

from app.services.provider_keyed_append_host_collection import _decode_type
from app.services.provider_keyed_host_identity_probe import DigitalOceanRawHostCollection
from app.services.provider_keyed_host_policy_interpreter import (
    interpret_digitalocean_host_policy, interpret_linode_host_policy,
)
from app.services.provider_keyed_host_surface_interpreter import (
    interpret_digitalocean_host_surface, interpret_linode_host_surface,
)
from app.services.provider_keyed_mixed_initial_publication_source import MixedInitialPublicationSource
from app.services.provider_keyed_mixed_linode_host_probe import (
    LinodeRawHostCollection, _sudo_hostname_warning,
)
from app.storage.job_repository import StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_initial_strict_host_proof"
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class MixedStrictHostProofAttention(ValueError):
    """The exact four-host proof is absent, incomplete, or uncertain."""


@dataclass(frozen=True)
class MixedStrictHostReceipt:
    source: MixedInitialPublicationSource
    child_id: str
    child_event_sha256: str
    host_evidence_sha256: str
    hostnames: tuple[str, str, str, str]
    provider_instance_ids: tuple[str, str, str, str]
    evidence_path: str
    claim_owner: str
    claim_token: str
    admin_key_sha256: str
    transport_key_sha256: str


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def child_id(core_job_id: str) -> str:
    if not isinstance(core_job_id, str) or not core_job_id.startswith("job-"):
        raise MixedStrictHostProofAttention("strict proof core job differs")
    return f"job-provider-keyed-mixed-strict-host-proof-{core_job_id.removeprefix('job-')}"


def _ordered_rows(source: MixedInitialPublicationSource, manifest: Mapping[str, object],
                  projections: Sequence[object]) -> tuple[tuple[dict, object, str], ...]:
    if (type(source) is not MixedInitialPublicationSource or type(manifest) is not dict
            or manifest.get("schema") != "mixed-initial-host-binding-v1"
            or _sha(manifest) != source.binding_manifest_sha256
            or manifest.get("engagementId") != source.engagement_id
            or tuple(manifest.get("orderedProviders", ())) != source.ordered_providers
            or tuple(manifest.get("chainIds", ())) != source.chain_ids
            or type(projections) not in (tuple, list) or len(projections) != 2):
        raise MixedStrictHostProofAttention("reviewed mixed host projection differs")
    selected = []
    for provider, chain_id, projection in zip(source.ordered_providers, source.chain_ids,
                                              projections, strict=True):
        if (projection.chain.chain_id != chain_id
                or projection.chain.middle_provider != provider
                or len(projection.chain.nodes) != 2):
            raise MixedStrictHostProofAttention("mixed chain projection differs")
        rows = [row for row in manifest["nodes"] if row["chainId"] == chain_id]
        if len(rows) != 2 or [row["role"] for row in rows] != ["middle", "edge"]:
            raise MixedStrictHostProofAttention("mixed host ordering differs")
        for row, host in zip(rows, projection.chain.nodes, strict=True):
            if (row["provider"] != provider or row["hostname"] != host["hostname"]
                    or row["terraformAddress"] != host["terraformAddress"]
                    or row["providerInstanceId"] != host["providerInstanceId"]
                    or row["publicIp"] != host["publicIp"]
                    or row["assignedProxy"] != projection.chain.assigned_proxy):
                raise MixedStrictHostProofAttention("mixed host projection changed")
            predecessor = projection.proxy_egress_ip if row["role"] == "middle" else rows[0]["publicIp"]
            selected.append((row, projection.host_policies[row["hostname"]], predecessor))
    source_rows = tuple((row.chain_id, row.provider, row.role, row.hostname,
                         row.terraform_address, row.provider_instance_id, row.public_ip,
                         row.assigned_proxy) for row in source.host_rows)
    chosen_rows = tuple((row["chainId"], row["provider"], row["role"], row["hostname"],
                         row["terraformAddress"], row["providerInstanceId"], row["publicIp"],
                         row["assignedProxy"]) for row, _, _ in selected)
    if len(selected) != 4 or source_rows != chosen_rows:
        raise MixedStrictHostProofAttention("fresh source host rows differ")
    return tuple(selected)


def verify_mixed_strict_host_set(
    source: MixedInitialPublicationSource, manifest: Mapping[str, object],
    projections: Sequence[object], collections: Sequence[object], *,
    digitalocean_probe_manifest: Mapping[str, object],
    core_known_hosts_sha256: str,
    sketch_known_hosts_sha256: Mapping[str, str],
    admin_key_sha256: str, transport_key_sha256: str,
) -> str:
    """Interpret all four fresh captures; no partial result has authority."""
    try:
        selected = _ordered_rows(source, manifest, projections)
        if (type(digitalocean_probe_manifest) is not dict
                or digitalocean_probe_manifest != _digitalocean_probe_manifest(
                    source, manifest, projections,
                    source.chain_ids[source.ordered_providers.index("digitalocean")],
                    digitalocean_probe_manifest["sketchKnownHostsPath"],
                    (digitalocean_probe_manifest["coreKnownHostsPath"],
                     digitalocean_probe_manifest["coreKnownHostsSha256"]))):
            raise ValueError("DigitalOcean probe manifest differs")
        if (type(collections) not in (tuple, list) or len(collections) != 4
                or any(_HASH.fullmatch(value) is None for value in
                       (admin_key_sha256, transport_key_sha256, core_known_hosts_sha256))
                or set(sketch_known_hosts_sha256) != {"linode", "digitalocean"}
                or any(_HASH.fullmatch(value) is None
                       for value in sketch_known_hosts_sha256.values())
                or digitalocean_probe_manifest["coreKnownHostsSha256"]
                   != core_known_hosts_sha256):
            raise ValueError("host set or retained key identity differs")
        invocations = set()
        for (node, policy, predecessor), collection in zip(selected, collections, strict=True):
            provider = node["provider"]
            expected_kind = (LinodeRawHostCollection if provider == "linode"
                             else DigitalOceanRawHostCollection)
            if type(collection) is not expected_kind:
                raise ValueError("provider raw collection kind differs")
            identity = collection.identity
            if ((identity.manifest_sha256 != source.binding_manifest_sha256
                 if provider == "linode" else
                 identity.manifest_sha256 != _sha(digitalocean_probe_manifest))
                    or identity.chain_id != node["chainId"]
                    or identity.terraform_address != node["terraformAddress"]
                    or identity.provider_instance_id != node["providerInstanceId"]
                    or identity.region != node["region"]
                    or identity.public_ipv4 != node["publicIp"]
                    or identity.hostname != node["hostname"]
                    or identity.core_known_hosts_sha256 != core_known_hosts_sha256
                    or identity.sketch_known_hosts_sha256
                       != sketch_known_hosts_sha256[provider]):
                raise ValueError("raw host identity differs from fresh source")
            if provider == "linode":
                firewall = interpret_linode_host_policy(
                    collection, expected_identity=identity,
                    expected_predecessor_ipv4=predecessor, expected_policy=policy)
                surface = interpret_linode_host_surface(
                    collection, expected_identity=identity,
                    expected_predecessor_ipv4=predecessor, expected_role=node["role"],
                    expected_admin_key_sha256=admin_key_sha256,
                    expected_transport_key_sha256=transport_key_sha256,
                    expected_policy=policy)
                commands = (identity.invocation_id, collection.raw.firewall_before.invocation_id,
                            collection.raw.surface.invocation_id,
                            collection.raw.firewall_after.invocation_id)
            else:
                firewall = interpret_digitalocean_host_policy(
                    collection, expected_identity=identity,
                    expected_predecessor_ipv4=predecessor, expected_policy=policy)
                surface = interpret_digitalocean_host_surface(
                    collection, expected_identity=identity,
                    expected_predecessor_ipv4=predecessor, expected_role=node["role"],
                    expected_admin_key_sha256=admin_key_sha256,
                    expected_transport_key_sha256=transport_key_sha256,
                    expected_policy=policy)
                commands = (identity.invocation_id, collection.firewall_before.invocation_id,
                            collection.surface.invocation_id, collection.firewall_after.invocation_id)
            if (firewall.predecessor_ipv4 != predecessor or surface.complete_ssh_policy is not True
                    or len(set(commands)) != 4 or any(item in invocations for item in commands)):
                raise ValueError("complete independent host policy proof is absent")
            invocations.update(commands)
        return _sha([asdict(item) for item in collections])
    except Exception as exc:
        raise MixedStrictHostProofAttention("mixed four-host policy proof differs") from exc


def _digitalocean_probe_manifest(source: MixedInitialPublicationSource,
                                 manifest: Mapping[str, object], projections: Sequence[object],
                                 chain_id: str, sketch_known_hosts_path: str,
                                 core_known_hosts: tuple[str, str]) -> dict:
    """Translate only the selected DO rows to the existing strict probe schema."""
    index = source.chain_ids.index(chain_id)
    if source.ordered_providers[index] != "digitalocean":
        raise ValueError("DigitalOcean chain differs")
    projection = projections[index]
    rows = [row for row in manifest["nodes"] if row["chainId"] == chain_id]
    return {
        "schema": "provider-keyed-v2", "engagementId": source.engagement_id,
        "coreJobId": source.core_job_id, "corePlanId": source.core_plan_id,
        "revisionId": source.revision_id,
        "stateSha256": source.provider_states[index].state_sha256,
        "nodes": [{"chainId": chain_id, "role": row["role"],
                   "providerInstanceId": row["providerInstanceId"],
                   "terraformAddress": row["terraformAddress"],
                   "name": row["hostname"], "publicIp": row["publicIp"],
                   "region": row["region"]} for row in rows],
        "hostPolicies": [{"chainId": chain_id, "proxyEgressIp": projection.proxy_egress_ip,
                          "hosts": projection.host_policies}],
        "coreKnownHostsPath": core_known_hosts[0],
        "coreKnownHostsSha256": core_known_hosts[1],
        "sketchKnownHostsPath": sketch_known_hosts_path,
    }


def _read_private_evidence(path: Path, expected_sha256: str) -> bytes:
    if _HASH.fullmatch(expected_sha256) is None or path.is_symlink():
        raise MixedStrictHostProofAttention("mixed raw artifact identity differs")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0 or before.st_size > 10_000_000):
        raise MixedStrictHostProofAttention("mixed raw artifact is unsafe")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(10_000_001)
            if len(data) != before.st_size or stream.read(1):
                raise ValueError("raw artifact size changed")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_uid", "st_mode", "st_nlink")
    if (any(getattr(before, key) != getattr(after, key) for key in fields)
            or hashlib.sha256(data).hexdigest() != expected_sha256):
        raise MixedStrictHostProofAttention("mixed raw artifact changed")
    return data


def recognize_completed_mixed_initial_strict_host_proof(
    source: MixedInitialPublicationSource, child: StoredJobRun,
    manifest: Mapping[str, object], projections: Sequence[object], *,
    digitalocean_probe_manifest: Mapping[str, object],
    core_known_hosts_sha256: str,
    sketch_known_hosts_sha256: Mapping[str, str],
    admin_key_sha256: str, transport_key_sha256: str,
    evidence_path: Path,
) -> MixedStrictHostReceipt:
    """Verify terminal child, exact journal, private bytes, and all interpreters."""
    try:
        expected_id = child_id(source.core_job_id)
        source_sha = _sha(asdict(source))
        terminal = child.events[-1]
        expected_path = str(evidence_path)
        if (child.id != expected_id or child.action != ACTION or child.status != "running"
                or child.started_at is None or child.finished_at is not None
                or child.target_id != source.engagement_id or child.artifact_refs != []
                or not isinstance(child.input.get("claimOwner"), str)
                or not isinstance(child.input.get("claimToken"), str)
                or any(child.input.get(key) != value for key, value in {
                    "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
                    "corePlanId": source.core_plan_id, "mixedParentId": source.parent_job_id,
                    "handoffJournalSha256": source.parent_journal_sha256,
                    "bindingManifestSha256": source.binding_manifest_sha256,
                    "bootstrapJournalSha256": source.host_worker_journal_sha256,
                    "mutation": False,
                }.items())
                or terminal.message != "mixed strict host proof completed"
                or terminal.data.get("sourceSha256") != source_sha
                or terminal.data.get("evidencePath") != expected_path
                or _HASH.fullmatch(str(terminal.data.get("hostEvidenceSha256"))) is None):
            raise ValueError("mixed strict proof terminal differs")
        raw = _read_private_evidence(evidence_path, terminal.data["hostEvidenceSha256"])
        parsed = json.loads(raw)
        if type(parsed) is not list or len(parsed) != 4:
            raise ValueError("mixed raw artifact coverage differs")
        kinds = [LinodeRawHostCollection if row.provider == "linode" else DigitalOceanRawHostCollection
                 for row in source.host_rows]
        collections = tuple(_decode_type(kind, item) for kind, item in zip(kinds, parsed, strict=True))
        if json.loads(json.dumps([asdict(row) for row in collections])) != parsed:
            raise ValueError("mixed raw artifact round trip differs")
        digest = verify_mixed_strict_host_set(
            source, manifest, projections, collections,
            digitalocean_probe_manifest=digitalocean_probe_manifest,
            core_known_hosts_sha256=core_known_hosts_sha256,
            sketch_known_hosts_sha256=sketch_known_hosts_sha256,
            admin_key_sha256=admin_key_sha256,
            transport_key_sha256=transport_key_sha256)
        if digest != terminal.data["hostEvidenceSha256"]:
            raise ValueError("mixed raw artifact digest differs")
        _verify_journal(child.events, source, collections, expected_path, digest)
        receipt = MixedStrictHostReceipt(
            source, child.id, job_event_digest(child.events), digest,
            tuple(row.hostname for row in source.host_rows),
            tuple(row.provider_instance_id for row in source.host_rows), expected_path,
            child.input["claimOwner"], child.input["claimToken"],
            admin_key_sha256, transport_key_sha256)
        validate_receipt_child(source, child, receipt)
        return receipt
    except Exception as exc:
        raise MixedStrictHostProofAttention("mixed strict proof receipt differs") from exc


def validate_receipt_child(source: MixedInitialPublicationSource,
                           child: StoredJobRun, receipt: MixedStrictHostReceipt) -> None:
    """Disk-free transaction check after the caller's full artifact proof.

    A child and receipt cannot themselves authorize publication: the writer
    must also compare its parent/lease, workspaces and durable key identities.
    """
    try:
        source_sha = _sha(asdict(source))
        terminal = child.events[-1]
        expected_input = {
            "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
            "corePlanId": source.core_plan_id, "mixedParentId": source.parent_job_id,
            "handoffJournalSha256": source.parent_journal_sha256,
            "bindingJobId": f"job-provider-keyed-mixed-host-binding-{source.core_job_id.removeprefix('job-')}",
            "bindingManifestSha256": source.binding_manifest_sha256,
            "bootstrapJobId": f"job-provider-keyed-mixed-host-worker-{source.core_job_id.removeprefix('job-')}",
            "bootstrapJournalSha256": source.host_worker_journal_sha256,
            "mutation": False,
        }
        claim_keys = {"claimOwner", "claimToken", "claimClaimedAt",
                      "claimHeartbeatAt", "claimExpiresAt"}
        if (type(source) is not MixedInitialPublicationSource
                or type(child) is not StoredJobRun or type(receipt) is not MixedStrictHostReceipt
                or receipt.source != source or child.id != child_id(source.core_job_id)
                or receipt.child_id != child.id or child.action != ACTION
                or child.status != "running" or child.started_at is None
                or child.finished_at is not None or child.artifact_refs != []
                or child.target != f"engagement:{source.engagement_id}"
                or child.target_type != "engagement" or child.target_id != source.engagement_id
                or set(child.input) != set(expected_input) | claim_keys
                or any(child.input[key] != value for key, value in expected_input.items())
                or child.input["claimOwner"] != receipt.claim_owner
                or child.input["claimToken"] != receipt.claim_token
                or not receipt.claim_owner or not receipt.claim_token
                or job_event_digest(child.events) != receipt.child_event_sha256
                or tuple(row.hostname for row in source.host_rows) != receipt.hostnames
                or tuple(row.provider_instance_id for row in source.host_rows)
                   != receipt.provider_instance_ids
                or _HASH.fullmatch(receipt.host_evidence_sha256) is None
                or _HASH.fullmatch(receipt.admin_key_sha256) is None
                or _HASH.fullmatch(receipt.transport_key_sha256) is None
                or len(child.events) != 59
                or [row.sequence for row in child.events] != list(range(1, 60))
                or any(row.level != "info" for row in child.events)
                or child.events[0].message != "mixed strict host proof reserved"
                or child.events[0].data != {"sourceSha256": source_sha}
                or child.events[1].message != "mixed strict host proof started"
                or child.events[1].data != {"sourceSha256": source_sha}
                or terminal.message != "mixed strict host proof completed"
                or terminal.data != {
                    "sourceSha256": source_sha,
                    "hostEvidenceSha256": receipt.host_evidence_sha256,
                    "hostnames": list(receipt.hostnames),
                    "evidencePath": receipt.evidence_path,
                }):
            raise ValueError("strict receipt, claim or child journal differs")
        cursor = 2
        seen_invocations = set()
        for host in source.host_rows:
            fields = {"provider": host.provider, "hostname": host.hostname,
                      "terraformAddress": host.terraform_address,
                      "providerInstanceId": host.provider_instance_id}
            scratch = child.events[cursor]
            if (scratch.message != "mixed strict host scratch intended"
                    or set(scratch.data) != set(fields) | {"scratchPath"}
                    or any(scratch.data[key] != value for key, value in fields.items())
                    or not isinstance(scratch.data["scratchPath"], str)
                    or not scratch.data["scratchPath"].startswith("/")):
                raise ValueError("strict scratch journal differs")
            cursor += 1
            warning_size = len(_sudo_hostname_warning(host.hostname).encode())
            for command_index in range(4):
                intent, started, result = child.events[cursor:cursor + 3]
                invocation = intent.data.get("invocationId")
                if ([row.message for row in (intent, started, result)] != [
                        "mixed strict host command intended",
                        "mixed strict host command started before GO",
                        "mixed strict host command result fenced"]
                        or type(invocation) is not str or not invocation
                        or invocation in seen_invocations
                        or set(intent.data) != set(fields) | {
                            "invocationId", "argvSha256", "scratchPath"}
                        or set(started.data) != set(fields) | {
                            "invocationId", "bootId", "pid", "pgid", "startTicks"}
                        or set(result.data) != set(fields) | {
                            "invocationId", "returnCode", "stdoutBytes", "stderrBytes",
                            "stdoutTruncated", "stderrTruncated"}
                        or any(any(row.data.get(key) != value for key, value in fields.items())
                               for row in (intent, started, result))
                        or any(row.data.get("invocationId") != invocation
                               for row in (intent, started, result))
                        or _HASH.fullmatch(str(intent.data["argvSha256"])) is None
                        or intent.data["scratchPath"] != scratch.data["scratchPath"]
                        or type(started.data["bootId"]) is not str
                        or not started.data["bootId"]
                        or any(type(started.data[key]) is not int or started.data[key] <= 0
                               for key in ("pid", "pgid", "startTicks"))
                        or type(result.data["returnCode"]) is not int
                        or result.data["returnCode"] != 0
                        or type(result.data["stdoutBytes"]) is not int
                        or result.data["stdoutBytes"] < 0
                        or type(result.data["stderrBytes"]) is not int
                        or result.data["stderrBytes"] not in (
                            (0, warning_size) if host.provider == "linode" and command_index
                            else (0,))
                        or result.data["stdoutTruncated"] is not False
                        or result.data["stderrTruncated"] is not False):
                    raise ValueError("strict command journal differs")
                seen_invocations.add(invocation)
                cursor += 3
            captured = child.events[cursor]
            if (captured.message != "mixed strict host capture completed"
                    or set(captured.data) != set(fields) | {"collectionSha256"}
                    or any(captured.data[key] != value for key, value in fields.items())
                    or _HASH.fullmatch(str(captured.data["collectionSha256"])) is None):
                raise ValueError("strict capture journal differs")
            cursor += 1
        if cursor != len(child.events) - 1:
            raise ValueError("strict journal has extra events")
    except Exception as exc:
        raise MixedStrictHostProofAttention("mixed strict child receipt differs") from exc


def _verify_journal(events, source, collections, evidence_path: str, evidence_sha: str) -> None:
    """Require one ordered intent/start/result quartet per selected host."""
    source_sha = _sha(asdict(source))
    if (len(events) != 2 + 4 * 14 + 1
            or events[0].message != "mixed strict host proof reserved"
            or events[0].data != {"sourceSha256": source_sha}
            or events[1].message != "mixed strict host proof started"
            or events[1].data != {"sourceSha256": source_sha}
            or [row.sequence for row in events] != list(range(1, len(events) + 1))
            or events[-1].data != {
                "sourceSha256": source_sha, "hostEvidenceSha256": evidence_sha,
                "hostnames": [row.hostname for row in source.host_rows],
                "evidencePath": evidence_path,
            }):
        raise ValueError("mixed strict journal boundary differs")
    seen = set()
    cursor = 2
    for row, collection in zip(source.host_rows, collections, strict=True):
        fields = {"provider": row.provider, "hostname": row.hostname,
                  "terraformAddress": row.terraform_address,
                  "providerInstanceId": row.provider_instance_id}
        scratch = events[cursor]
        if (scratch.message != "mixed strict host scratch intended"
                or any(scratch.data.get(key) != value for key, value in fields.items())
                or not isinstance(scratch.data.get("scratchPath"), str)):
            raise ValueError("mixed strict scratch differs")
        path = scratch.data["scratchPath"]
        cursor += 1
        raw = collection.raw if row.provider == "linode" else collection
        invocations = (collection.identity.invocation_id, raw.firewall_before.invocation_id,
                       raw.surface.invocation_id, raw.firewall_after.invocation_id)
        warning_bytes = len(_sudo_hostname_warning(row.hostname).encode())
        for index, invocation in enumerate(invocations):
            intent, started, result = events[cursor:cursor + 3]
            if ([item.message for item in (intent, started, result)] != [
                    "mixed strict host command intended",
                    "mixed strict host command started before GO",
                    "mixed strict host command result fenced"]
                    or invocation in seen or not invocation
                    or any(any(item.data.get(key) != value for key, value in fields.items())
                           for item in (intent, started, result))
                    or any(item.data.get("invocationId") != invocation
                           for item in (intent, started, result))
                    or intent.data.get("scratchPath") != path
                    or _HASH.fullmatch(str(intent.data.get("argvSha256"))) is None
                    or not all(started.data.get(key) for key in
                               ("bootId", "pid", "pgid", "startTicks"))
                    or result.data.get("returnCode") != 0
                    or result.data.get("stdoutTruncated") is not False
                    or result.data.get("stderrTruncated") is not False
                    or result.data.get("stderrBytes") not in
                       ((0, warning_bytes) if row.provider == "linode" and index else (0,))):
                raise ValueError("mixed strict command differs")
            seen.add(invocation)
            cursor += 3
        captured = events[cursor]
        if (captured.message != "mixed strict host capture completed"
                or captured.data != {**fields, "collectionSha256": _sha(asdict(collection))}):
            raise ValueError("mixed strict capture differs")
        cursor += 1
    if cursor != len(events) - 1:
        raise ValueError("mixed strict journal contains extra events")
