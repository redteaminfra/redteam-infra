# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
import time
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import uuid4

import dns.exception
import dns.resolver

from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.integrations.namecheap import NamecheapDnsClient, NamecheapError, NamecheapHost, parse_namecheap_secret
from app.services.credentials import (
    CredentialStoreLockedError,
    CredentialValidationError,
    resolve_credential_secret,
    resolve_default_credential_alias,
)
from app.services.domains import get_cached_hosts, list_engagement_domains, normalize_domain_name
from app.services.engagement_operations import get_operations_overview
from app.services.engagements import get_engagement
from app.services.provider_keyed_dns_cleanup_authority import load_keyed_dns_cleanup_authority
from app.storage.domain_repository import DomainRepository, SqlAlchemyDomainRepository, StoredDomainAsset, StoredDomainDnsSnapshot
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun, job_event_digest


DNS_APPLY_ACTION = "engagement_dns_apply"
DNS_CLEANUP_ACTION = "engagement_dns_owned_cleanup"
SUPPORTED_DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT", "MX", "NS")
DEFAULT_DNS_TTL = 600
DNS01_TTL = 60
DNS_TTL_MIN = 60
DNS_TTL_MAX = 60000
DNS_READBACK_MAX_ATTEMPTS = 12
DNS_READBACK_ATTEMPTS_PER_RUN = 3
DNS_READBACK_DELAY_SECONDS = 5
DNS_PREINTENT_STARTUP_GRACE_SECONDS = 300
DNS_KEYED_CLEANUP_STARTUP_GRACE_SECONDS = 60
HOST_NAME_PATTERN = re.compile(r"^(@|\*|[A-Za-z0-9_*][A-Za-z0-9_*-]{0,62})(\.([A-Za-z0-9_*][A-Za-z0-9_*-]{0,62}))*$")
HOST_VALUE_PATTERN = re.compile(r"^([A-Za-z0-9_*][A-Za-z0-9_*-]{0,62})(\.([A-Za-z0-9_*][A-Za-z0-9_*-]{0,62}))*\.?$")
BackgroundRunner = Callable[[Callable[[], None]], None]


class Dns01ChallengeError(RuntimeError):
    pass


class EngagementDnsValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("engagement DNS validation failed")
        self.errors = errors


class NamecheapDnsAdapter(Protocol):
    def get_hosts(self, domain_name: str) -> list[Any]:
        ...

    def set_hosts(self, domain_name: str, hosts: list[NamecheapHost]) -> bool:
        ...


@dataclass(frozen=True)
class DnsRecord:
    name: str
    record_type: str
    address: str
    ttl: str
    mx_pref: str = ""
    host_id: str = ""

    def to_dict(self, *, include_host_id: bool = True) -> dict[str, str]:
        body = {
            "name": self.name,
            "type": self.record_type,
            "address": self.address,
            "ttl": self.ttl,
            "mxPref": self.mx_pref,
        }
        if include_host_id and self.host_id:
            body["hostId"] = self.host_id
        return body

    def to_namecheap_host(self) -> NamecheapHost:
        return NamecheapHost(
            name=self.name,
            record_type=self.record_type,
            address=self.address,
            ttl=self.ttl,
            mx_pref=self.mx_pref,
        )


def get_engagement_dns_workspace(
    engagement_id: str,
    *,
    repository: DomainRepository | None = None,
    job_repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = _repo(repository)
    domains = []
    for domain in list_engagement_domains(engagement_id, repository=repo):
        hosts = _cached_hosts_dict(str(domain["id"]), repo)
        domains.append({**domain, "dns": hosts})
    overview = get_operations_overview(engagement_id, job_repository=job_repository, include_provider_findings=False) or {}
    return {
        "engagementId": engagement_id,
        "domains": domains,
        "edgeTargets": _eligible_edge_targets(overview),
        "supportedRecordTypes": list(SUPPORTED_DNS_RECORD_TYPES),
        "defaultTtl": DEFAULT_DNS_TTL,
        "notice": "DNS records only change registrar host records; they do not create inbound channels, proxy routes, certificates, or services.",
    }


def preview_engagement_dns(
    engagement_id: str,
    body: dict[str, Any],
    *,
    repository: DomainRepository | None = None,
    adapter: NamecheapDnsAdapter | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = _repo(repository)
    asset = _assigned_domain_from_body(repo, engagement_id, body)
    desired_editable = _records_from_body(body, asset.domain_name)
    try:
        current = _provider_records(asset, adapter or _dns_client_for_asset(asset, body))
    except CredentialStoreLockedError:
        raise
    except (CredentialValidationError, NamecheapError) as exc:
        raise EngagementDnsValidationError([_safe_dns_error(exc)]) from exc
    desired = _submission_records(current, desired_editable)
    fingerprint = dns_record_fingerprint(current)
    return {
        "domain": _domain_summary_for_engagement(repo, engagement_id, asset),
        "currentRecords": [record.to_dict() for record in current],
        "desiredRecords": [record.to_dict(include_host_id=False) for record in desired],
        "diff": _diff_records(current, desired),
        "currentFingerprint": fingerprint,
    }


def start_engagement_dns_apply(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: DomainRepository | None = None,
    job_repository: JobRepository | None = None,
    adapter: NamecheapDnsAdapter | None = None,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    asset = _assigned_domain_from_body(repo, engagement_id, body)
    desired_editable = _records_from_body(body, asset.domain_name)
    expected_fingerprint = str(body.get("currentFingerprint") or "").strip()
    if not expected_fingerprint:
        raise EngagementDnsValidationError(["currentFingerprint is required; preview DNS changes before applying"])
    try:
        dns_client = adapter or _dns_client_for_asset(asset, body)
    except CredentialStoreLockedError:
        raise
    except (CredentialValidationError, NamecheapError) as exc:
        raise EngagementDnsValidationError([_safe_dns_error(exc)]) from exc
    timestamp = _now()
    job = jobs.save(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=DNS_APPLY_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={
                "engagementId": engagement_id,
                "domainId": asset.id,
                "domainName": asset.domain_name,
                "recordCount": len(desired_editable),
                "currentFingerprint": expected_fingerprint,
                "mutation": True,
                "provider": asset.registrar,
                "credentialAlias": _credential_alias_from_body(body),
            },
            artifact_refs=[],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "engagement DNS apply started",
                    {
                        "domainId": asset.id,
                        "domainName": asset.domain_name,
                        "recordCount": len(desired_editable),
                        "mutation": True,
                        "provider": asset.registrar,
                    },
                )
            ],
        )
    )
    completed: StoredJobRun | None = None

    def run_apply() -> None:
        nonlocal completed
        completed = _finish_engagement_dns_apply_job(jobs, repo, job, asset, desired_editable, expected_fingerprint, dns_client)

    task_runner = background_runner or _start_background_task
    task_runner(run_apply)
    result_job = completed or job
    return {"job": result_job.to_detail().to_dict(), "status": result_job.status}


def dns_record_fingerprint(records: list[DnsRecord] | list[dict[str, Any]]) -> str:
    normalized = [_canonical_record(record) for record in records]
    payload = json.dumps(sorted(normalized, key=lambda row: (row["name"], row["type"], row["address"], row["mxPref"], row["ttl"])), separators=(",", ":"), sort_keys=True)
    return f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


def preview_owned_dns_cleanup(
    engagement_id: str, domain_id: str, old_edge_ips: list[str], *,
    repository: DomainRepository | None = None,
    job_repository: JobRepository | None = None,
    adapter: NamecheapDnsAdapter | None = None,
    _lock_held: bool = False,
) -> dict[str, Any]:
    """Read-only proof for removing Barragan-created records at teardown."""
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    asset = repo.get_asset(domain_id)
    if asset is None or asset.registrar != "namecheap":
        raise EngagementDnsValidationError(["assigned Namecheap domain is required"])
    try:
        edge_ips = sorted({str(ipaddress.ip_address(value)) for value in old_edge_ips})
    except (TypeError, ValueError) as exc:
        raise EngagementDnsValidationError(["old edge IP targets must be valid IP addresses"]) from exc
    if not edge_ips:
        raise EngagementDnsValidationError(["old edge IP targets are required for DNS cleanup proof"])
    with (nullcontext() if _lock_held else _dns01_domain_lock(asset.id)):
        assignment_id = _active_assignment_id(repo, asset.id, engagement_id)
        current = _provider_records(asset, adapter or _namecheap_dns_client())
        ownership = repo.list_record_ownership(asset.id, active_only=True)
        snapshots = {snapshot.id: snapshot for snapshot in repo.list_snapshots(asset.id)}
        blockers: list[str] = []
        claimed_indices: set[int] = set()
        owned_rows: list[dict[str, Any]] = []
        for owned in ownership:
            if owned.assignment_id != assignment_id or owned.engagement_id != engagement_id:
                blockers.append(f"active ownership row {owned.id} belongs to another assignment")
                continue
            source_job = jobs.get(owned.creating_job_id)
            source_snapshot = snapshots.get(owned.snapshot_id)
            if (source_job is None or source_job.action != DNS_APPLY_ACTION
                    or source_job.status != "succeeded" or source_job.target_id != engagement_id
                    or source_job.input.get("domainId") != asset.id
                    or source_snapshot is None or source_snapshot.sync_job_id != owned.creating_job_id
                    or source_snapshot.domain_id != asset.id
                    or sum(_canonical_record(record) == _canonical_record(owned.record)
                           for record in source_snapshot.hosts) != 1
                    or not any(event.message == "Namecheap DNS setHosts completed with full desired host list"
                               and event.data.get("snapshotId") == owned.snapshot_id for event in source_job.events)):
                blockers.append(f"ownership row {owned.id} lacks creating-job/provider-snapshot proof")
                continue
            matches = [index for index, record in enumerate(current)
                       if _canonical_record(record) == _canonical_record(owned.record)]
            if len(matches) != 1 or matches[0] in claimed_indices:
                blockers.append(f"ownership row {owned.id} is absent or ambiguous in provider zone")
                continue
            claimed_indices.add(matches[0])
            # Namecheap may regenerate host IDs after any whole-zone setHosts.
            # Ownership is the exact canonical tuple, not that transient ID.
            owned_rows.append({"ownershipId": owned.id,
                               "record": current[matches[0]].to_dict(include_host_id=False)})
        owned_names = {_fqdn(row["record"]["name"], asset.domain_name) for row in owned_rows}
        for index, record in enumerate(current):
            if index in claimed_indices:
                continue
            if record.record_type in {"A", "AAAA"}:
                try:
                    address = str(ipaddress.ip_address(record.address))
                except ValueError:
                    address = ""
                if address in edge_ips:
                    blockers.append(f"unowned {record.record_type} record at {record.name} still targets an old edge IP")
            if record.record_type in {"CNAME", "MX", "NS"} and record.address.rstrip(".").lower() in owned_names:
                blockers.append(f"unowned {record.record_type} record at {record.name} depends on an owned name")
        zone_fingerprint = dns_record_fingerprint(current)
        proof = {
            "engagementId": engagement_id, "domainId": asset.id,
            "assignmentId": assignment_id, "oldEdgeIps": edge_ips,
            "zoneFingerprint": zone_fingerprint, "ownedRecords": owned_rows,
            "blockers": blockers,
        }
        proof["planSha256"] = "sha256:" + hashlib.sha256(json.dumps(
            proof, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        return proof


def reserve_private_keyed_owned_dns_cleanup(
    teardown_parent_id: str, domain_id: str, *, reviewed_preview: dict,
    environment: str, state_root: Path, repository: DomainRepository | None = None,
    job_repository: JobRepository | None = None, adapter: NamecheapDnsAdapter | None = None,
    authority_repositories: dict | None = None,
) -> StoredJobRun:
    """Reserve a reviewed private child; this does not call Namecheap setHosts."""
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    asset = repo.get_asset(domain_id)
    if (environment != "devtest" or asset is None or asset.registrar != "namecheap"
            or type(reviewed_preview) is not dict
            or set(authority_repositories or ()) & {"job_repository", "domain_repository",
                                                    "environment", "state_root"}):
        raise EngagementDnsValidationError(["reviewed Namecheap cleanup is required"])
    client = adapter or _namecheap_dns_client()
    authority_args = dict(environment=environment, state_root=state_root,
                          job_repository=jobs, domain_repository=repo,
                          **(authority_repositories or {}))
    try:
        with _dns01_domain_lock(domain_id):
            if repo.get_asset(domain_id) != asset:
                raise ValueError("domain asset changed before reservation")
            proof = load_keyed_dns_cleanup_authority(
                teardown_parent_id, domain_id, **authority_args)
            authority = json.loads(json.dumps(asdict(proof), sort_keys=True))
            body = {key: value for key, value in reviewed_preview.items()
                    if key != "planSha256"}
            digest = "sha256:" + hashlib.sha256(json.dumps(
                body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if (reviewed_preview.get("planSha256") != digest
                    or reviewed_preview.get("engagementId") != proof.engagement_id
                    or reviewed_preview.get("domainId") != domain_id
                    or reviewed_preview.get("assignmentId") != proof.assignment_id
                    or reviewed_preview.get("oldEdgeIps") != sorted(proof.edge_public_ips)
                    or reviewed_preview.get("blockers") != []):
                raise ValueError("reviewed DNS cleanup plan differs")
            fresh = preview_owned_dns_cleanup(
                proof.engagement_id, domain_id, list(proof.edge_public_ips),
                repository=repo, job_repository=jobs, adapter=client, _lock_held=True)
            if fresh != reviewed_preview:
                raise ValueError("DNS zone or ownership changed after review")
            current = _provider_records(asset, client)
            if (dns_record_fingerprint(current) != fresh["zoneFingerprint"]
                    or any(row.record_type not in SUPPORTED_DNS_RECORD_TYPES
                           for row in current)):
                raise ValueError("full Namecheap zone cannot be preserved")
            if json.loads(json.dumps(asdict(load_keyed_dns_cleanup_authority(
                    teardown_parent_id, domain_id, **authority_args)),
                    sort_keys=True)) != authority:
                raise ValueError("persisted teardown authority changed")
            key = hashlib.sha256(json.dumps({
                "parentId": teardown_parent_id, "domainId": domain_id,
                "schema": "keyed-owned-dns-cleanup-v1",
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
            now = _now()
            candidate = StoredJobRun(
                id=f"job-engagement-dns-owned-cleanup-{key}",
                action=DNS_CLEANUP_ACTION, status="queued",
                target=f"engagement:{proof.engagement_id}", target_type="engagement",
                target_id=proof.engagement_id, requested_by="barragan",
                input={"teardownParentId": teardown_parent_id, "domainId": domain_id,
                       "domainName": asset.domain_name, "authority": authority,
                       "previewPlan": fresh, "mutation": bool(fresh["ownedRecords"])},
                artifact_refs=[], created_at=now, started_at=None, finished_at=None,
                events=[JobEvent(1, "info", "owned DNS cleanup reserved",
                    {"planSha256": fresh["planSha256"],
                     "bindingSha256": proof.binding_sha256})],
            )
            saved = jobs.save_if_absent(candidate)
            if (saved.id != candidate.id or saved.action != candidate.action
                    or saved.status != "queued" or saved.started_at is not None
                    or saved.finished_at is not None
                    or saved.target_id != candidate.target_id
                    or saved.input != candidate.input
                    or saved.events != candidate.events):
                raise ValueError("competing owned DNS cleanup child differs")
            return saved
    except Exception:
        raise EngagementDnsValidationError([
            "reviewed owned DNS cleanup reservation is unverified"
        ]) from None


def _keyed_cleanup_authority_args(environment, state_root, jobs, repo, others):
    if (environment != "devtest" or set(others or ()) & {
            "job_repository", "domain_repository", "environment", "state_root"}):
        raise ValueError("private DevTest authority is required")
    return dict(environment=environment, state_root=state_root,
                job_repository=jobs, domain_repository=repo, **(others or {}))


def _keyed_cleanup_receipts(job, repo, jobs):
    plan = job.input["previewPlan"]
    receipts = repo.list_record_ownership(job.input["domainId"], active_only=True)
    expected = {row["ownershipId"]: _canonical_record(row["record"])
                for row in plan["ownedRecords"]}
    if len(expected) != len(plan["ownedRecords"]) or {row.id for row in receipts} != set(expected):
        raise ValueError("owned DNS receipt set changed")
    snapshots = {row.id: row for row in repo.list_snapshots(job.input["domainId"])}
    proofs = []
    for row in receipts:
        source = jobs.get(row.creating_job_id)
        snapshot = snapshots.get(row.snapshot_id)
        if (row.engagement_id != job.target_id
                or row.assignment_id != job.input["authority"]["assignment_id"]
                or _canonical_record(row.record) != expected[row.id]
                or source is None or source.action != DNS_APPLY_ACTION
                or source.status != "succeeded" or source.target_id != job.target_id
                or source.input.get("domainId") != job.input["domainId"]
                or snapshot is None or snapshot.sync_job_id != source.id
                or snapshot.domain_id != job.input["domainId"]
                or sum(_canonical_record(item) == expected[row.id]
                       for item in snapshot.hosts) != 1
                or not any(event.message ==
                    "Namecheap DNS setHosts completed with full desired host list"
                    and event.data.get("snapshotId") == row.snapshot_id
                    for event in source.events)):
            raise ValueError("owned DNS source proof changed")
        proofs.append({"ownershipId": row.id, "record": expected[row.id],
                       "creatingJobId": source.id, "creatingJournalSha256":
                       job_event_digest(source.events), "snapshotId": snapshot.id})
    return sorted(proofs, key=lambda row: row["ownershipId"])


def run_private_keyed_owned_dns_cleanup(
    teardown_parent_id: str, domain_id: str, *, reviewed_preview: dict,
    environment: str, state_root: Path, repository: DomainRepository | None = None,
    job_repository: JobRepository | None = None, adapter: NamecheapDnsAdapter | None = None,
    authority_repositories: dict | None = None,
) -> StoredJobRun:
    """Run the reserved private one-shot child, with a durable pre-call intent."""
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    client = adapter or _namecheap_dns_client()
    args = _keyed_cleanup_authority_args(environment, state_root, jobs, repo,
                                         authority_repositories)
    reserved = reserve_private_keyed_owned_dns_cleanup(
        teardown_parent_id, domain_id, reviewed_preview=reviewed_preview,
        environment=environment, state_root=state_root, repository=repo,
        job_repository=jobs, adapter=client, authority_repositories=authority_repositories)
    with _dns01_domain_lock(domain_id):
        job = jobs.get(reserved.id)
        if job is None or job.status != "queued" or job.events != reserved.events:
            raise EngagementDnsValidationError(["owned DNS child is not reserved for GO"])
        asset = repo.get_asset(domain_id)
        try:
            if asset is None or asset.domain_name != job.input["domainName"]:
                raise ValueError("domain asset changed")
            authority = json.loads(json.dumps(asdict(load_keyed_dns_cleanup_authority(
                teardown_parent_id, domain_id, **args)), sort_keys=True))
            if authority != job.input["authority"]:
                raise ValueError("saved authority changed")
            fresh = preview_owned_dns_cleanup(job.target_id, domain_id,
                job.input["previewPlan"]["oldEdgeIps"], repository=repo,
                job_repository=jobs, adapter=client, _lock_held=True)
            if fresh != job.input["previewPlan"] or fresh["blockers"]:
                raise ValueError("reviewed DNS zone changed")
            before = _provider_records(asset, client)
            if (dns_record_fingerprint(before) != fresh["zoneFingerprint"]
                    or any(row.record_type not in SUPPORTED_DNS_RECORD_TYPES for row in before)):
                raise ValueError("full Namecheap zone cannot be preserved")
            proofs = _keyed_cleanup_receipts(job, repo, jobs)
            submitted = list(before)
            for proof in proofs:
                matches = [i for i, row in enumerate(submitted)
                           if _canonical_record(row) == proof["record"]]
                if len(matches) != 1:
                    raise ValueError("owned tuple is ambiguous")
                submitted.pop(matches[0])
            # Take the last read under the domain lock before intent publication.
            if (json.loads(json.dumps(asdict(load_keyed_dns_cleanup_authority(
                    teardown_parent_id, domain_id, **args)), sort_keys=True)) != authority
                    or preview_owned_dns_cleanup(job.target_id, domain_id,
                        fresh["oldEdgeIps"], repository=repo, job_repository=jobs,
                        adapter=client, _lock_held=True) != fresh):
                raise ValueError("authority or provider zone changed before intent")
            if not proofs:
                return _publish_private_keyed_owned_dns_cleanup(
                    job, repo, jobs, asset, before, args, accepted_sequence=None)
            intent = JobEvent(2, "info", "owned DNS setHosts intended", {
                "planSha256": fresh["planSha256"],
                "bindingSha256": authority["binding_sha256"],
                "assignmentId": authority["assignment_id"],
                "beforeRecords": [row.to_dict() for row in before],
                "submittedRecords": [row.to_dict(include_host_id=False) for row in submitted],
                "submittedFingerprint": dns_record_fingerprint(submitted),
                "receiptProofs": proofs,
                "maxRemovedTtl": max(int(row["record"]["ttl"]) for row in proofs),
            })
            job = jobs.save(replace(job, status="running", started_at=_now(),
                                    events=[*job.events, intent]))
            if (json.loads(json.dumps(asdict(load_keyed_dns_cleanup_authority(
                    teardown_parent_id, domain_id, **args)), sort_keys=True)) != authority
                    or preview_owned_dns_cleanup(job.target_id, domain_id,
                        fresh["oldEdgeIps"], repository=repo, job_repository=jobs,
                        adapter=client, _lock_held=True) != fresh):
                # The intent now permanently prevents a replay. A changed
                # zone or authority needs review before any provider call.
                raise ValueError("authority or provider zone changed after intent")
            try:
                if not client.set_hosts(asset.domain_name,
                                        [row.to_namecheap_host() for row in submitted]):
                    raise NamecheapError("Namecheap setHosts did not report success")
            except Exception:
                # The call may have reached Namecheap. Recovery must not replay it.
                try:
                    return _recover_private_keyed_owned_dns_cleanup_locked(
                        job, repo, jobs, asset, client, args)
                except Exception:
                    return jobs.get(job.id) or job
            accepted = JobEvent(3, "info", "owned DNS setHosts accepted", {
                "planSha256": fresh["planSha256"],
                "submittedFingerprint": intent.data["submittedFingerprint"],
            })
            job = jobs.save(replace(job, events=[*job.events, accepted]))
            return _recover_private_keyed_owned_dns_cleanup_locked(
                job, repo, jobs, asset, client, args)
        except EngagementDnsValidationError:
            raise
        except Exception:
            raise EngagementDnsValidationError([
                "owned DNS cleanup is unverified; no further provider write is allowed"
            ]) from None


def recover_private_keyed_owned_dns_cleanup(
    job_id: str, *, environment: str, state_root: Path,
    repository: DomainRepository | None = None, job_repository: JobRepository | None = None,
    adapter: NamecheapDnsAdapter | None = None, authority_repositories: dict | None = None,
) -> StoredJobRun | None:
    """GET-only recovery; never submit a second Namecheap setHosts."""
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    args = _keyed_cleanup_authority_args(environment, state_root, jobs, repo,
                                         authority_repositories)
    job = jobs.get(job_id)
    if job is None or job.action != DNS_CLEANUP_ACTION or job.status != "running":
        return job
    with _dns01_domain_lock(job.input["domainId"]):
        current = jobs.get(job_id)
        asset = repo.get_asset(job.input["domainId"])
        if current is None or asset is None or asset.domain_name != current.input["domainName"]:
            raise EngagementDnsValidationError(["owned DNS recovery authority changed"])
        return _recover_private_keyed_owned_dns_cleanup_locked(
            current, repo, jobs, asset, adapter or _namecheap_dns_client(), args)


def _publish_private_keyed_owned_dns_cleanup(job, repo, jobs, asset, rows, args,
                                             *, accepted_sequence):
    if not isinstance(repo, SqlAlchemyDomainRepository) or not isinstance(jobs, SqlAlchemyJobRepository):
        raise ValueError("atomic DNS cleanup publication requires SQLite repositories")
    snapshot = StoredDomainDnsSnapshot(id=None, domain_id=asset.id,
        provider=asset.registrar, hosts=[row.to_dict() for row in rows],
        source="provider_snapshot", sync_job_id=job.id, fetched_at=_now())

    def authority():
        return json.loads(json.dumps(asdict(load_keyed_dns_cleanup_authority(
            job.input["teardownParentId"], asset.id, **args)), sort_keys=True))

    repo.complete_keyed_owned_dns_cleanup(snapshot=snapshot, job_id=job.id,
        accepted_sequence=accepted_sequence, fresh_fingerprint=dns_record_fingerprint(rows),
        authority=authority)
    return jobs.get(job.id) or job


def _recover_private_keyed_owned_dns_cleanup_locked(job, repo, jobs, asset, client, args):
    job = jobs.get(job.id) or job
    if job.status != "running" or job.action != DNS_CLEANUP_ACTION:
        return job
    if json.loads(json.dumps(asdict(load_keyed_dns_cleanup_authority(
            job.input["teardownParentId"], asset.id, **args)), sort_keys=True)) != job.input["authority"]:
        raise EngagementDnsValidationError(["owned DNS cleanup authority changed"])
    intent = [row for row in job.events if row.message == "owned DNS setHosts intended"]
    accepted = [row for row in job.events if row.message == "owned DNS setHosts accepted"]
    if len(intent) != 1 or intent[0].sequence != 2 or len(accepted) > 1:
        raise EngagementDnsValidationError(["owned DNS cleanup journal changed"])
    if accepted and (accepted[0].sequence < 3 or
                     accepted[0].data.get("submittedFingerprint")
                     != intent[0].data.get("submittedFingerprint")):
        raise EngagementDnsValidationError(["owned DNS acceptance differs"])
    attempts = sum(row.message == "owned DNS readback pending" for row in job.events)
    # After the journaled polling budget, each explicit recovery invocation
    # still gets one read-only reconciliation. Late provider convergence must
    # not require replaying the mutation or abandoning intact receipts.
    remaining = DNS_READBACK_MAX_ATTEMPTS - attempts
    read_count = min(DNS_READBACK_ATTEMPTS_PER_RUN, remaining) if remaining > 0 else 1
    for _ in range(read_count):
        rows = _provider_records(asset, client)
        if dns_record_fingerprint(rows) == intent[0].data["submittedFingerprint"]:
            if not accepted:
                marker = JobEvent(len(job.events) + 1, "info",
                    "owned DNS setHosts accepted", {
                        "planSha256": job.input["previewPlan"]["planSha256"],
                        "submittedFingerprint": intent[0].data["submittedFingerprint"],
                        "recoveredByProviderReadback": True,
                    })
                job = jobs.save(replace(job, events=[*job.events, marker]))
                accepted = [marker]
            return _publish_private_keyed_owned_dns_cleanup(
                job, repo, jobs, asset, rows, args,
                accepted_sequence=accepted[0].sequence)
        if attempts < DNS_READBACK_MAX_ATTEMPTS:
            attempts += 1
            job = jobs.save(replace(job, events=[*job.events, JobEvent(len(job.events) + 1,
                "info", "owned DNS readback pending", {"attempt": attempts})]))
        if attempts < DNS_READBACK_MAX_ATTEMPTS and _ + 1 < read_count:
            time.sleep(DNS_READBACK_DELAY_SECONDS)
    if attempts >= DNS_READBACK_MAX_ATTEMPTS:
        # An accepted or uncertain provider call may converge later. Preserve
        # the journal and receipts for operator review, never replay setHosts.
        return job
    return job


def _fqdn(name: str, zone: str) -> str:
    return zone.lower() if name == "@" else f"{name.lower()}.{zone.lower()}"


def set_dns01_challenge(
    engagement_id: str,
    identifier: str,
    validation: str,
    *,
    present: bool,
    repository: DomainRepository | None = None,
    adapter: NamecheapDnsAdapter | None = None,
    credential_alias: str = "default",
) -> dict[str, Any]:
    """Add or remove one exact ACME TXT value without exposing it in results."""
    repo = _repo(repository)
    asset = _assigned_domain_for_identifier(repo, engagement_id, identifier)
    record_name = _dns01_record_name(identifier, asset.domain_name)
    client = adapter or _dns_client_for_asset(asset, {"credentialAlias": credential_alias})
    with _dns01_domain_lock(asset.id):
        current = _provider_records(asset, client)
        exact = lambda row: (
            row.name.lower() == record_name.lower()
            and row.record_type == "TXT"
            and row.address == validation
        )
        if present:
            desired = list(current)
            if not any(exact(row) for row in desired):
                desired.append(DnsRecord(record_name, "TXT", validation, str(DNS01_TTL)))
        else:
            desired = [row for row in current if not exact(row)]
        if desired != current and not client.set_hosts(asset.domain_name, [row.to_namecheap_host() for row in desired]):
            raise Dns01ChallengeError("Namecheap did not accept the DNS-01 record update")
        refreshed = _provider_records(asset, client)
        observed = any(exact(row) for row in refreshed)
        if observed != present:
            state = "present" if present else "absent"
            raise Dns01ChallengeError(f"DNS-01 TXT record was not {state} in refreshed provider state")
    return {
        "domainAssetId": asset.id,
        "domainName": asset.domain_name,
        "identifier": identifier,
        "recordName": record_name,
        "present": present,
        "recordCount": len(refreshed),
    }


def wait_for_dns01_challenge(
    identifier: str,
    validation: str,
    *,
    zone: str | None = None,
    timeout_seconds: int = 600,
    poll_seconds: int = 10,
) -> dict[str, Any]:
    fqdn = f"_acme-challenge.{identifier.strip('.').lower()}"
    deadline = time.monotonic() + max(1, timeout_seconds)
    resolver = dns.resolver.Resolver()
    authoritative_servers = _authoritative_nameserver_addresses(zone or identifier, resolver)
    while time.monotonic() < deadline:
        propagated = True
        for address in authoritative_servers:
            direct = dns.resolver.Resolver(configure=False)
            direct.nameservers = [address]
            try:
                answers = direct.resolve(fqdn, "TXT", lifetime=min(10, max(1, poll_seconds)))
                values = {
                    b"".join(getattr(answer, "strings", ())).decode("utf-8", "replace")
                    for answer in answers
                }
                if validation not in values:
                    propagated = False
                    break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                propagated = False
                break
        if propagated:
            return {"fqdn": fqdn, "propagated": True, "authoritativeServerCount": len(authoritative_servers), "checkedAt": _now()}
        time.sleep(max(1, poll_seconds))
    raise Dns01ChallengeError(f"DNS-01 TXT record did not propagate for {fqdn} before timeout")


def _authoritative_nameserver_addresses(zone: str, resolver: dns.resolver.Resolver) -> list[str]:
    normalized = normalize_domain_name(zone)
    try:
        names = [str(answer.target).rstrip(".") for answer in resolver.resolve(normalized, "NS", lifetime=10)]
        addresses = sorted({
            str(address.address)
            for name in names
            for address in resolver.resolve(name, "A", lifetime=10)
        })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        raise Dns01ChallengeError(f"could not resolve authoritative nameservers for {normalized}") from exc
    if not addresses:
        raise Dns01ChallengeError(f"no authoritative nameservers resolved for {normalized}")
    return addresses


def _assigned_domain_for_identifier(repo: DomainRepository, engagement_id: str, identifier: str) -> StoredDomainAsset:
    normalized = normalize_domain_name(identifier)
    candidates = sorted(
        (
            asset
            for asset in repo.list_assets()
            if normalized == asset.domain_name or normalized.endswith(f".{asset.domain_name}")
        ),
        key=lambda asset: len(asset.domain_name),
        reverse=True,
    )
    for asset in candidates:
        if asset.registrar != "namecheap":
            continue
        if any(
            assignment.status == "active"
            for assignment in repo.list_assignments(domain_id=asset.id, engagement_id=engagement_id)
        ):
            return asset
    raise Dns01ChallengeError("identifier is not covered by an active Namecheap domain assignment")


def _dns01_record_name(identifier: str, zone: str) -> str:
    normalized = normalize_domain_name(identifier)
    normalized_zone = normalize_domain_name(zone)
    if normalized == normalized_zone:
        return "_acme-challenge"
    suffix = f".{normalized_zone}"
    if not normalized.endswith(suffix):
        raise Dns01ChallengeError("identifier is outside the assigned DNS zone")
    relative = normalized[: -len(suffix)]
    return f"_acme-challenge.{relative}"


@contextmanager
def _dns01_domain_lock(domain_id: str):
    import fcntl

    root = Path(os.environ.get("BARRAGAN_DNS01_LOCK_DIR", "/tmp/barragan-dns01-locks"))
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{re.sub(r'[^A-Za-z0-9_.-]+', '-', domain_id)}.lock"
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _finish_engagement_dns_apply_job(
    jobs: JobRepository,
    repo: DomainRepository,
    job: StoredJobRun,
    asset: StoredDomainAsset,
    desired: list[DnsRecord],
    expected_fingerprint: str,
    client: NamecheapDnsAdapter,
) -> StoredJobRun:
    accepted = False
    try:
        with _dns01_domain_lock(asset.id):
            current_job = jobs.get(job.id)
            if (current_job is None or current_job.status != "running"
                    or current_job.events != job.events):
                return current_job or job
            current = _provider_records(asset, client)
            actual_fingerprint = dns_record_fingerprint(current)
            if actual_fingerprint != expected_fingerprint:
                return jobs.save(replace(job, status="failed", finished_at=_now(), events=[
                    *job.events, JobEvent(len(job.events) + 1, "error",
                        "DNS provider state changed after preview; refresh and preview again",
                        {"domainId": asset.id, "domainName": asset.domain_name,
                         "expectedFingerprint": expected_fingerprint,
                         "actualFingerprint": actual_fingerprint, "mutation": False}),
                ]))

            assignment_id = _active_assignment_id(repo, asset.id, job.target_id)
            if any(row.assignment_id != assignment_id or row.engagement_id != job.target_id
                   for row in repo.list_record_ownership(asset.id, active_only=True)):
                raise ValueError("domain has active DNS ownership from another assignment")
            submitted_records = _submission_records(current, desired)
            candidates = _new_record_candidates(current, submitted_records)
            replacements = _owned_replacement_candidates(
                current, submitted_records, repo, jobs, asset.id, assignment_id, job.target_id,
            )
            intent = JobEvent(len(job.events) + 1, "info", "Namecheap DNS setHosts intended", {
                "domainId": asset.id, "assignmentId": assignment_id,
                "beforeRecords": [record.to_dict() for record in current],
                "submittedRecords": [record.to_dict(include_host_id=False) for record in submitted_records],
                "submittedFingerprint": dns_record_fingerprint(submitted_records),
                "candidateRecords": [record.to_dict(include_host_id=False) for record in candidates],
                "replacementCandidates": replacements,
                "mutation": True,
            })
            job = jobs.save(replace(job, events=[*job.events, intent]))
            # setHosts replaces the full zone. The durable intent fences any uncertain outcome.
            if not client.set_hosts(asset.domain_name, [record.to_namecheap_host() for record in submitted_records]):
                raise NamecheapError("Namecheap setHosts did not report success")
            accepted = True
            accepted_event = JobEvent(len(job.events) + 1, "info", "Namecheap DNS setHosts accepted", {
                "domainId": asset.id, "assignmentId": assignment_id,
                "submittedFingerprint": dns_record_fingerprint(submitted_records), "mutation": True,
            })
            job = jobs.save(replace(job, events=[*job.events, accepted_event]))
            # The live worker completes bounded readback itself. Recovery is
            # reserved for a process interruption after the accepted marker.
            while job.status == "running":
                job = _verify_accepted_dns_apply(jobs, repo, job, asset, client)
            return job
    except Exception as exc:
        if accepted:
            # A successful provider response is already journaled. A later retry is GET-only.
            return jobs.get(job.id) or job
        events = [
            *job.events,
            JobEvent(
                len(job.events) + 1,
                "error",
                "DNS setHosts outcome uncertain; manual review required" if any(
                    event.message == "Namecheap DNS setHosts intended" for event in job.events
                ) else _safe_dns_error(exc),
                {"domainId": asset.id, "domainName": asset.domain_name, "mutation": False,
                 "ownershipClaimed": False},
            ),
        ]
        return jobs.save(replace(job, status="failed", finished_at=_now(), events=events))


def _active_assignment_id(repo: DomainRepository, domain_id: str, engagement_id: str) -> int:
    active = [row for row in repo.list_assignments(domain_id=domain_id) if row.status == "active"]
    if len(active) != 1 or active[0].engagement_id != engagement_id or active[0].id is None:
        raise ValueError("domain assignment changed before DNS apply")
    return int(active[0].id)


def _new_record_candidates(current: list[DnsRecord], submitted: list[DnsRecord]) -> list[DnsRecord]:
    """Only a previously empty name/type slot can establish first-write ownership."""
    before = {(row.name.lower(), row.record_type) for row in current}
    counts: dict[tuple[str, str], int] = {}
    for row in submitted:
        key = (row.name.lower(), row.record_type)
        counts[key] = counts.get(key, 0) + 1
    return [row for row in submitted if row.record_type in SUPPORTED_DNS_RECORD_TYPES
            and (row.name.lower(), row.record_type) not in before
            and counts[(row.name.lower(), row.record_type)] == 1]


def _owned_replacement_candidates(
    current: list[DnsRecord], submitted: list[DnsRecord], repo: DomainRepository,
    jobs: JobRepository, domain_id: str, assignment_id: int, engagement_id: str,
) -> list[dict[str, Any]]:
    active = repo.list_record_ownership(domain_id, active_only=True)
    snapshots = {row.id: row for row in repo.list_snapshots(domain_id)}
    replacements: list[dict[str, Any]] = []
    for after in submitted:
        slot = (after.name.lower(), after.record_type)
        before_slot = [row for row in current if (row.name.lower(), row.record_type) == slot]
        submitted_slot = [row for row in submitted if (row.name.lower(), row.record_type) == slot]
        if len(before_slot) != 1 or len(submitted_slot) != 1:
            continue
        before = before_slot[0]
        if _canonical_record(before) == _canonical_record(after):
            continue
        receipts = [row for row in active if row.assignment_id == assignment_id
                    and row.engagement_id == engagement_id
                    and _canonical_record(row.record) == _canonical_record(before)]
        if len(receipts) != 1:
            continue
        owned = receipts[0]
        source_job = jobs.get(owned.creating_job_id)
        source_snapshot = snapshots.get(owned.snapshot_id)
        if (source_job is None or source_job.action != DNS_APPLY_ACTION
                or source_job.status != "succeeded" or source_job.target_id != engagement_id
                or source_job.input.get("domainId") != domain_id
                or source_snapshot is None or source_snapshot.sync_job_id != owned.creating_job_id
                or sum(_canonical_record(row) == _canonical_record(before)
                       for row in source_snapshot.hosts) != 1
                or not any(event.message == "Namecheap DNS setHosts completed with full desired host list"
                           and event.data.get("snapshotId") == owned.snapshot_id for event in source_job.events)):
            continue
        replacements.append({
            "priorOwnershipId": owned.id,
            "beforeRecord": before.to_dict(include_host_id=False),
            "afterRecord": after.to_dict(include_host_id=False),
        })
    return replacements


def _verify_accepted_dns_apply(
    jobs: JobRepository, repo: DomainRepository, job: StoredJobRun,
    asset: StoredDomainAsset, client: NamecheapDnsAdapter,
) -> StoredJobRun:
    intent = next((event for event in job.events if event.message == "Namecheap DNS setHosts intended"), None)
    accepted = next((event for event in job.events if event.message == "Namecheap DNS setHosts accepted"), None)
    if intent is None or accepted is None or intent.sequence + 1 != accepted.sequence:
        raise ValueError("DNS apply accepted journal is incomplete")
    assignment_id = int(intent.data["assignmentId"])
    if accepted.data.get("assignmentId") != assignment_id:
        raise ValueError("DNS apply assignment changed across provider call")
    before = [_record_from_provider(row) for row in intent.data.get("beforeRecords", [])]
    submitted = [_record_from_provider(row) for row in intent.data.get("submittedRecords", [])]
    if (dns_record_fingerprint(before) != job.input.get("currentFingerprint")
            or dns_record_fingerprint(submitted) != intent.data.get("submittedFingerprint")
            or accepted.data.get("submittedFingerprint") != intent.data.get("submittedFingerprint")
            or [row.to_dict(include_host_id=False) for row in _new_record_candidates(before, submitted)]
            != intent.data.get("candidateRecords")):
        raise ValueError("DNS apply intent proof is inconsistent")
    if _owned_replacement_candidates(before, submitted, repo, jobs, asset.id, assignment_id, job.target_id) != intent.data.get("replacementCandidates", []):
        raise ValueError("DNS apply replacement ownership proof changed")
    if _active_assignment_id(repo, asset.id, job.target_id) != assignment_id:
        raise ValueError("domain assignment changed before DNS verification")
    pending_count = sum(event.message == "Namecheap DNS readback pending" for event in job.events)
    if pending_count >= DNS_READBACK_MAX_ATTEMPTS:
        return _fail_dns_readback(jobs, job)
    last_pending = next((event for event in reversed(job.events)
                         if event.message == "Namecheap DNS readback pending"), None)
    if last_pending is not None:
        next_at = datetime.fromisoformat(str(last_pending.data["nextRetryAt"]))
        wait = (next_at - datetime.now(timezone.utc)).total_seconds()
        if wait > 0:
            time.sleep(min(wait, DNS_READBACK_DELAY_SECONDS))
    refreshed: list[DnsRecord] = []
    per_run = min(DNS_READBACK_ATTEMPTS_PER_RUN, DNS_READBACK_MAX_ATTEMPTS - pending_count)
    for index in range(per_run):
        try:
            refreshed = _provider_records(asset, client)
            if dns_record_fingerprint(refreshed) == intent.data["submittedFingerprint"]:
                break
            reason = "provider zone has not converged to submitted records"
        except Exception:
            reason = "provider readback unavailable"
        pending_count += 1
        next_at = datetime.now(timezone.utc) + timedelta(seconds=DNS_READBACK_DELAY_SECONDS)
        job = jobs.save(replace(job, events=[*job.events, JobEvent(len(job.events) + 1, "warning",
            "Namecheap DNS readback pending", {"domainId": asset.id, "attempt": pending_count,
                "reason": reason, "nextRetryAt": next_at.isoformat(), "mutation": False})]))
        if pending_count >= DNS_READBACK_MAX_ATTEMPTS:
            return _fail_dns_readback(jobs, job)
        if index + 1 < per_run:
            time.sleep(DNS_READBACK_DELAY_SECONDS)
    else:
        return job
    post_counts: dict[tuple[str, str], int] = {}
    for row in refreshed:
        key = (row.name.lower(), row.record_type)
        post_counts[key] = post_counts.get(key, 0) + 1
    owned = []
    expected_candidates = [*intent.data.get("candidateRecords", []),
                           *(entry["afterRecord"] for entry in intent.data.get("replacementCandidates", []))]
    for raw in expected_candidates:
        expected = _canonical_record(raw)
        key = (expected["name"], expected["type"])
        matching = [row for row in refreshed if _canonical_record(row) == expected]
        if post_counts.get(key) == 1 and len(matching) == 1:
            owned.append(matching[0].to_dict())
    snapshot = StoredDomainDnsSnapshot(
        id=None, domain_id=asset.id, provider=asset.registrar,
        hosts=[record.to_dict() for record in refreshed], source="provider_snapshot",
        sync_job_id=job.id, fetched_at=_now(),
    )
    if isinstance(repo, SqlAlchemyDomainRepository) and isinstance(jobs, SqlAlchemyJobRepository):
        repo.complete_dns_apply(
            snapshot=snapshot, assignment_id=assignment_id, engagement_id=job.target_id,
            job_id=job.id, owned_records=owned, accepted_sequence=accepted.sequence,
            fresh_fingerprint=dns_record_fingerprint(refreshed),
        )
        return jobs.get(job.id) or job
    snapshot = repo.save_snapshot(snapshot)
    return jobs.save(replace(job, status="succeeded", finished_at=_now(), events=[
        *job.events, JobEvent(len(job.events) + 1, "info",
            "Namecheap DNS setHosts completed with full desired host list",
            {"domainId": asset.id, "snapshotId": snapshot.id,
             "freshFingerprint": dns_record_fingerprint(refreshed), "mutation": True}),
    ]))


def _fail_dns_readback(jobs: JobRepository, job: StoredJobRun) -> StoredJobRun:
    return jobs.save(replace(job, status="failed", finished_at=_now(), events=[
        *job.events, JobEvent(len(job.events) + 1, "error",
            "DNS provider readback did not confirm the submitted zone; manual review required",
            {"mutation": False, "ownershipClaimed": False}),
    ]))


def recover_engagement_dns_apply(
    job_id: str, *, repository: DomainRepository | None = None,
    job_repository: JobRepository | None = None, adapter: NamecheapDnsAdapter | None = None,
) -> StoredJobRun | None:
    """Resolve an interrupted DNS apply without ever replaying setHosts."""
    repo = _repo(repository)
    jobs = job_repository or SqlAlchemyJobRepository()
    job = jobs.get(job_id)
    if job is None or job.action != DNS_APPLY_ACTION or job.status != "running":
        return job
    domain_id = str(job.input.get("domainId") or "")
    with _dns01_domain_lock(domain_id):
        # Another app worker may have completed the same job while this one
        # waited for the cross-process zone lock. Never publish a stale journal.
        job = jobs.get(job_id)
        if job is None or job.action != DNS_APPLY_ACTION or job.status != "running":
            return job
        accepted = any(event.message == "Namecheap DNS setHosts accepted" for event in job.events)
        if not accepted:
            return jobs.save(replace(job, status="failed", finished_at=_now(), events=[
                *job.events, JobEvent(len(job.events) + 1, "error",
                    "DNS setHosts outcome uncertain; manual review required",
                    {"mutation": False, "ownershipClaimed": False}),
            ]))
        asset = repo.get_asset(domain_id)
        if asset is None or asset.domain_name != job.input.get("domainName"):
            return _fail_dns_recovery(jobs, job)
        try:
            client = adapter or _namecheap_dns_client(str(job.input.get("credentialAlias") or "") or None)
            while job.status == "running":
                job = _verify_accepted_dns_apply(jobs, repo, job, asset, client)
            return job
        except Exception:
            return _fail_dns_recovery(jobs, jobs.get(job_id) or job)


def _fail_dns_recovery(jobs: JobRepository, job: StoredJobRun) -> StoredJobRun:
    if job.status != "running":
        return job
    return jobs.save(replace(job, status="failed", finished_at=_now(), events=[
        *job.events, JobEvent(len(job.events) + 1, "error",
            "DNS recovery could not verify the submitted zone; manual review required",
            {"mutation": False, "ownershipClaimed": False}),
    ]))


def recover_interrupted_engagement_dns_applies(
    *, schedule: BackgroundRunner, job_repository: JobRepository | None = None,
) -> int:
    """Schedule restart reconciliation without waiting for provider reads."""
    jobs = job_repository or SqlAlchemyJobRepository()
    schedule(lambda: _recover_dns_apply_startup_batch(jobs))
    return 1


def recover_interrupted_keyed_owned_dns_cleanups(
    *, environment: str, state_root: Path, schedule: BackgroundRunner,
    job_repository: JobRepository | None = None,
) -> int:
    """Schedule one DevTest-only GET reconciliation per eligible saved child."""
    from app.services.sketch_state_workspaces import _default_state_root

    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root()
                or not state_root.is_dir() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root):
            return 0
    except (OSError, ValueError):
        return 0
    jobs = job_repository or SqlAlchemyJobRepository()
    if isinstance(jobs, SqlAlchemyJobRepository):
        from app.storage.models import JobRunModel

        ids = [row.id for row in JobRunModel.query.with_entities(JobRunModel.id).filter_by(
            action=DNS_CLEANUP_ACTION, status="running",
        ).order_by(JobRunModel.created_at, JobRunModel.id).yield_per(100)]
    else:
        ids = [job.id for job in jobs.list()
               if job.action == DNS_CLEANUP_ACTION and job.status == "running"]
    selected: list[str] = []
    for job_id in ids:
        job = jobs.get(job_id)
        if (job is None or job.action != DNS_CLEANUP_ACTION or job.status != "running"
                or not isinstance(job.input, dict)
                or not job.input.get("teardownParentId")
                or not job.input.get("domainId")
                or sum(event.message == "owned DNS setHosts intended"
                       for event in job.events) != 1):
            continue
        selected.append(job_id)
    if selected:
        schedule(lambda: _recover_keyed_owned_dns_startup_batch(
            tuple(selected), jobs, state_root))
    return len(selected)


def _recover_keyed_owned_dns_startup_batch(
    job_ids: tuple[str, ...], jobs: JobRepository, state_root: Path,
) -> None:
    for job_id in job_ids:
        try:
            job = jobs.get(job_id)
            if (job is None or job.action != DNS_CLEANUP_ACTION
                    or job.status != "running"):
                continue
            started = datetime.fromisoformat(
                str(job.started_at or job.created_at).replace("Z", "+00:00"))
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            remaining = DNS_KEYED_CLEANUP_STARTUP_GRACE_SECONDS - (
                datetime.now(timezone.utc) - started).total_seconds()
            if remaining > 0:
                time.sleep(remaining)
            # This path performs GET and SQLite publication only. It never
            # calls run_private_keyed_owned_dns_cleanup or setHosts.
            recover_private_keyed_owned_dns_cleanup(
                job_id, environment="devtest", state_root=state_root,
                job_repository=jobs)
        except Exception:
            logging.getLogger("barragan.dns").warning(
                "keyed owned DNS startup recovery could not process job %s", job_id,
            )


def _recover_dns_apply_startup_batch(jobs: JobRepository) -> None:
    if isinstance(jobs, SqlAlchemyJobRepository):
        from app.storage.models import JobRunModel

        job_ids = [row.id for row in JobRunModel.query.with_entities(JobRunModel.id).filter_by(
            action=DNS_APPLY_ACTION, status="running",
        ).order_by(JobRunModel.created_at, JobRunModel.id).yield_per(100)]
    else:
        job_ids = [job.id for job in jobs.list()
                   if job.action == DNS_APPLY_ACTION and job.status == "running"]
    # Accepted mutations must not wait behind the grace for a freshly queued
    # job whose original worker has not had a chance to start.
    accepted_jobs: list[str] = []
    intended_jobs: list[str] = []
    pre_intent: list[str] = []
    for job_id in job_ids:
        job = jobs.get(job_id)
        if job is None or job.status != "running":
            continue
        if any(event.message == "Namecheap DNS setHosts accepted" for event in job.events):
            accepted_jobs.append(job_id)
        elif any(event.message == "Namecheap DNS setHosts intended" for event in job.events):
            intended_jobs.append(job_id)
        else:
            pre_intent.append(job_id)
    for job_id in [*accepted_jobs, *intended_jobs, *pre_intent]:
        try:
            _recover_dns_apply_after_startup_grace(job_id, jobs)
        except Exception:
            # Leave this job visible for a later recovery attempt, and do not
            # let one malformed journal strand every other running DNS job.
            logging.getLogger("barragan.dns").warning(
                "DNS startup recovery could not process job %s", job_id,
            )


def _recover_dns_apply_after_startup_grace(job_id: str, jobs: JobRepository) -> None:
    job = jobs.get(job_id)
    if job is None or job.action != DNS_APPLY_ACTION or job.status != "running":
        return
    if not any(event.message == "Namecheap DNS setHosts intended" for event in job.events):
        created = datetime.fromisoformat(job.created_at.replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        remaining = DNS_PREINTENT_STARTUP_GRACE_SECONDS - (datetime.now(timezone.utc) - created).total_seconds()
        if remaining > 0:
            time.sleep(remaining)
    recover_engagement_dns_apply(job_id, job_repository=jobs)


def _assigned_domain_from_body(repo: DomainRepository, engagement_id: str, body: dict[str, Any]) -> StoredDomainAsset:
    raw_domain_id = str(body.get("domainId") or "").strip()
    raw_domain_name = str(body.get("domainName") or "").strip()
    asset = repo.get_asset(raw_domain_id) if raw_domain_id else None
    if asset is None and raw_domain_name:
        asset = repo.get_asset_by_name(normalize_domain_name(raw_domain_name))
    if asset is None:
        raise EngagementDnsValidationError(["domainId must reference a known domain"])
    active = [
        assignment
        for assignment in repo.list_assignments(domain_id=asset.id, engagement_id=engagement_id)
        if assignment.status == "active"
    ]
    if not active:
        raise EngagementDnsValidationError(["domain must be actively assigned to this engagement before DNS can be changed"])
    if asset.registrar != "namecheap":
        raise EngagementDnsValidationError(["engagement DNS management currently supports Namecheap domains only"])
    return asset


def _domain_summary_for_engagement(repo: DomainRepository, engagement_id: str, asset: StoredDomainAsset) -> dict[str, Any]:
    for domain in list_engagement_domains(engagement_id, repository=repo):
        if domain["id"] == asset.id:
            return domain
    raise EngagementDnsValidationError(["domain must be actively assigned to this engagement before DNS can be changed"])


def _records_from_body(body: dict[str, Any], domain_name: str) -> list[DnsRecord]:
    raw_records = body.get("records")
    if not isinstance(raw_records, list):
        raise EngagementDnsValidationError(["records must be a complete list of desired DNS host records"])
    records = [_record_from_body(record, index, domain_name) for index, record in enumerate(raw_records, start=1)]
    seen: set[tuple[str, str, str, str]] = set()
    duplicates: list[str] = []
    for record in records:
        key = (record.name.lower(), record.record_type, record.address.lower(), record.mx_pref)
        if key in seen:
            duplicates.append(f"{record.name} {record.record_type} {record.address}")
        seen.add(key)
    if duplicates:
        raise EngagementDnsValidationError([f"duplicate DNS records are not allowed: {', '.join(duplicates)}"])
    return records


def _record_from_body(raw: Any, index: int, domain_name: str) -> DnsRecord:
    if not isinstance(raw, dict):
        raise EngagementDnsValidationError([f"records[{index}] must be an object"])
    record_type = str(raw.get("type") or raw.get("recordType") or "").strip().upper()
    errors: list[str] = []
    if record_type not in SUPPORTED_DNS_RECORD_TYPES:
        errors.append(f"records[{index}].type must be one of {', '.join(SUPPORTED_DNS_RECORD_TYPES)}")
    name = _normalize_record_name(str(raw.get("name") or "@"), domain_name)
    if not HOST_NAME_PATTERN.match(name):
        errors.append(f"records[{index}].name must be @, *, or a hostname relative to the assigned domain")
    address = str(raw.get("address") or raw.get("value") or "").strip()
    if not address:
        errors.append(f"records[{index}].address is required")
    ttl = _normalize_ttl(raw.get("ttl"), index, errors)
    mx_pref = str(raw.get("mxPref") or raw.get("mx_pref") or "").strip()
    if record_type == "A" and address:
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            errors.append(f"records[{index}].address must be an IPv4 address for A records")
    if record_type == "AAAA" and address:
        try:
            ipaddress.IPv6Address(address)
        except ValueError:
            errors.append(f"records[{index}].address must be an IPv6 address for AAAA records")
    if record_type in {"CNAME", "MX", "NS"} and address and not HOST_VALUE_PATTERN.match(address):
        errors.append(f"records[{index}].address must be a hostname for {record_type} records")
    if record_type == "MX":
        try:
            mx_value = int(mx_pref)
        except ValueError:
            errors.append(f"records[{index}].mxPref is required for MX records")
        else:
            if mx_value < 0 or mx_value > 65535:
                errors.append(f"records[{index}].mxPref must be between 0 and 65535")
            mx_pref = str(mx_value)
    else:
        mx_pref = ""
    if record_type == "TXT" and len(address.encode("utf-8")) > 4096:
        errors.append(f"records[{index}].address is too large for a TXT record")
    if errors:
        raise EngagementDnsValidationError(errors)
    return DnsRecord(name=name, record_type=record_type, address=address, ttl=ttl, mx_pref=mx_pref)


def _normalize_record_name(value: str, domain_name: str) -> str:
    name = value.strip().strip(".").lower() or "@"
    normalized_domain = domain_name.lower().strip(".")
    if name == normalized_domain:
        return "@"
    suffix = f".{normalized_domain}"
    if name.endswith(suffix):
        return name[: -len(suffix)] or "@"
    return name


def _normalize_ttl(value: Any, index: int, errors: list[str]) -> str:
    raw = str(value if value is not None else DEFAULT_DNS_TTL).strip() or str(DEFAULT_DNS_TTL)
    try:
        ttl = int(raw)
    except ValueError:
        errors.append(f"records[{index}].ttl must be a number")
        return str(DEFAULT_DNS_TTL)
    if ttl < DNS_TTL_MIN or ttl > DNS_TTL_MAX:
        errors.append(f"records[{index}].ttl must be between {DNS_TTL_MIN} and {DNS_TTL_MAX}")
    return str(ttl)


def _provider_records(asset: StoredDomainAsset, client: NamecheapDnsAdapter) -> list[DnsRecord]:
    return [_record_from_provider(host) for host in client.get_hosts(asset.domain_name)]


def _record_from_provider(host: Any) -> DnsRecord:
    if isinstance(host, dict):
        return DnsRecord(
            name=str(host.get("name") or "@").strip() or "@",
            record_type=str(host.get("type") or host.get("recordType") or "").strip().upper(),
            address=str(host.get("address") or host.get("value") or "").strip(),
            ttl=str(host.get("ttl") or "").strip(),
            mx_pref=str(host.get("mxPref") or host.get("mx_pref") or "").strip(),
            host_id=str(host.get("hostId") or host.get("host_id") or "").strip(),
        )
    return DnsRecord(
        name=str(getattr(host, "name", "@")).strip() or "@",
        record_type=str(getattr(host, "record_type", getattr(host, "type", ""))).strip().upper(),
        address=str(getattr(host, "address", "")).strip(),
        ttl=str(getattr(host, "ttl", "")).strip(),
        mx_pref=str(getattr(host, "mx_pref", getattr(host, "mxPref", ""))).strip(),
        host_id=str(getattr(host, "host_id", getattr(host, "hostId", ""))).strip(),
    )


def _cached_hosts_dict(domain_id: str, repo: DomainRepository) -> dict[str, Any]:
    hosts = get_cached_hosts(domain_id, repository=repo)
    if hosts is None:
        return {
            "domainId": domain_id,
            "domainName": "",
            "provider": "namecheap",
            "source": "provider_snapshot",
            "syncJobId": "",
            "fetchedAt": "",
            "hosts": [],
            "readOnly": False,
            "currentFingerprint": dns_record_fingerprint([]),
        }
    body = hosts.to_dict()
    body["readOnly"] = False
    body["currentFingerprint"] = dns_record_fingerprint([_record_from_provider(host) for host in body.get("hosts", []) if isinstance(host, dict)])
    return body


def _diff_records(current: list[DnsRecord], desired: list[DnsRecord]) -> dict[str, list[dict[str, Any]]]:
    remaining = list(current)
    added: list[dict[str, Any]] = []
    updated: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    for desired_record in desired:
        match_index = _matching_record_index(remaining, desired_record)
        if match_index is None:
            added.append(desired_record.to_dict(include_host_id=False))
            continue
        current_record = remaining.pop(match_index)
        if _canonical_record(current_record) == _canonical_record(desired_record):
            unchanged.append(desired_record.to_dict(include_host_id=False))
        else:
            updated.append({"before": current_record.to_dict(), "after": desired_record.to_dict(include_host_id=False)})
    return {
        "added": added,
        "updated": updated,
        "removed": [record.to_dict() for record in remaining],
        "unchanged": unchanged,
    }


def _submission_records(current: list[DnsRecord], desired_editable: list[DnsRecord]) -> list[DnsRecord]:
    preserved = [record for record in current if record.record_type not in SUPPORTED_DNS_RECORD_TYPES]
    return [*desired_editable, *preserved]


def _matching_record_index(records: list[DnsRecord], desired: DnsRecord) -> int | None:
    desired_canonical = _canonical_record(desired)
    for index, record in enumerate(records):
        if _canonical_record(record) == desired_canonical:
            return index
    for index, record in enumerate(records):
        if record.name.lower() == desired.name.lower() and record.record_type == desired.record_type:
            return index
    return None


def _canonical_record(record: DnsRecord | dict[str, Any]) -> dict[str, str]:
    if isinstance(record, DnsRecord):
        body = record.to_dict(include_host_id=False)
    else:
        body = {
            "name": str(record.get("name") or "@"),
            "type": str(record.get("type") or record.get("recordType") or ""),
            "address": str(record.get("address") or record.get("value") or ""),
            "ttl": str(record.get("ttl") or ""),
            "mxPref": str(record.get("mxPref") or record.get("mx_pref") or ""),
        }
    return {
        "name": body["name"].strip().lower() or "@",
        "type": body["type"].strip().upper(),
        "address": body["address"].strip(),
        "ttl": body["ttl"].strip(),
        "mxPref": body["mxPref"].strip() if body["type"].strip().upper() == "MX" else "",
    }


def _eligible_edge_targets(overview: dict[str, Any]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    rows = overview.get("sketchInfrastructure")
    if not isinstance(rows, list):
        return targets
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("role", "")).strip().lower() != "edge":
            continue
        public_ip = str(row.get("publicIp") or "").strip()
        status = str(row.get("status") or "").strip().lower()
        if not public_ip or public_ip in {"Not Deployed", "Not Ready", "N/A"}:
            continue
        if status not in {"active", "deployed", "healthy", "ready", "running", "validated"}:
            continue
        if bool(row.get("burned")):
            continue
        hostname = str(row.get("hostname") or "").strip()
        chain_id = str(row.get("chainId") or "").strip()
        targets.append(
            {
                "id": hostname or chain_id or public_ip,
                "label": f"{hostname or chain_id} ({public_ip})",
                "chainId": chain_id,
                "hostname": hostname,
                "provider": str(row.get("provider") or "").strip(),
                "publicIp": public_ip,
                "region": str(row.get("region") or "").strip(),
                "proxy": str(row.get("proxy") or "").strip(),
                "status": str(row.get("status") or "").strip(),
            }
        )
    return targets


def _dns_client_for_asset(asset: StoredDomainAsset, body: dict[str, Any]) -> NamecheapDnsClient:
    if asset.registrar != "namecheap":
        raise EngagementDnsValidationError(["engagement DNS management currently supports Namecheap domains only"])
    return _namecheap_dns_client(_credential_alias_from_body(body) or None)


def _credential_alias_from_body(body: dict[str, Any]) -> str:
    return str(body.get("credentialAlias") or "").strip() or "default"


def _namecheap_dns_client(alias: str | None = None) -> NamecheapDnsClient:
    resolved_alias = alias if alias and alias != "default" else resolve_default_credential_alias("namecheap")
    if not resolved_alias:
        raise CredentialValidationError(["no active default namecheap credential configured"])
    secret = resolve_credential_secret("namecheap", resolved_alias)
    username, api_key = parse_namecheap_secret(secret)
    return NamecheapDnsClient(username, api_key)


def _safe_dns_error(exc: Exception) -> str:
    if isinstance(exc, CredentialStoreLockedError):
        return str(exc)
    if isinstance(exc, CredentialValidationError):
        return "; ".join(exc.errors)
    message = str(exc)
    for marker in ("ApiKey", "apikey", "api_key", "secret", "token", "password", "?"):
        if marker.lower() in message.lower():
            return "DNS apply failed with redacted sensitive details"
    return message or "DNS apply failed"


def _repo(repository: DomainRepository | None) -> DomainRepository:
    return repository or SqlAlchemyDomainRepository()


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(
        task,
        name="barragan-engagement-dns-runner",
        synchronous_when_testing=True,
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
