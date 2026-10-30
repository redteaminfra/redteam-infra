# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only, fresh DNS authority check before keyed provider destroy intent."""

from __future__ import annotations

from dataclasses import fields, is_dataclass, replace
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from app.services.engagement_teardown import (
    ENGAGEMENT_TEARDOWN_ACTION, _fingerprint, _parent_id,
    _valid_keyed_dns_cleanup_manifest,
)
from app.services.provider_keyed_published_teardown_source import PublishedProviderKeyedSource
from app.services.provider_keyed_teardown_quiescence import audit_published_provider_keyed_bootstrap
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.job_repository import job_event_digest


class ProviderKeyedDnsCleanupCheckpointError(ValueError):
    """The confirmed DNS cleanup authority no longer matches live evidence."""


class _PreHandoffJobs:
    """Present the reviewed initial journal to the manifest builder, never a caller copy."""

    def __init__(self, jobs, initial_id: str, full_digest: str):
        self.jobs = jobs
        self.initial_id = initial_id
        self.full_digest = full_digest

    def get(self, job_id):
        row = self.jobs.get(job_id)
        if job_id != self.initial_id:
            return row
        if row is None or job_event_digest(row.events) != self.full_digest:
            raise ValueError("persisted initial journal changed")
        events = list(row.events[:-1])
        return (replace(row, events=events) if is_dataclass(row)
                else SimpleNamespace(**{**vars(row), "events": events}))

    def list_for_engagement(self, engagement_id):
        return [self.get(row.id) for row in self.jobs.list_for_engagement(engagement_id)]


class _FencedAdapter:
    def __init__(self, adapter, fence: Callable[[], None]):
        self.adapter = adapter
        self.fence = fence

    def get_hosts(self, domain_name):
        self.fence()
        rows = self.adapter.get_hosts(domain_name)
        self.fence()
        return rows

    def set_hosts(self, _domain_name, _hosts):
        raise AssertionError("DNS checkpoint cannot write Namecheap")


def prove_provider_keyed_dns_cleanup_checkpoint(
    confirmed_snapshot: dict, *, job_repository, domain_repository=None,
    adapter=None, fence: Callable[[], None] | None = None,
) -> dict:
    """Rebuild the reviewed DNS manifest from persisted evidence and fresh zones.

    This is DNS-specific evidence, not complete teardown source authority. Its
    caller must first prove the full published source before destroy GO and
    freeze the parent and deployed chain projection. Pending handoff adds one
    terminal event after confirmation; the manifest builder sees its prefix.
    No provider write or Terraform operation occurs here.
    """
    try:
        # The DNS service also imports the later destroy-absence authority.
        # Resolve it only when this pre-destroy check runs, after module startup.
        from app.services.engagement_dns import _namecheap_dns_client
        from app.services.provider_keyed_dns_cleanup_manifest import (
            build_provider_keyed_dns_cleanup_manifest,
        )
        if (type(confirmed_snapshot) is not dict
                or not _valid_keyed_dns_cleanup_manifest(confirmed_snapshot)
                or confirmed_snapshot.get("snapshotId") != _fingerprint({
                    key: value for key, value in confirmed_snapshot.items()
                    if key != "snapshotId"})):
            raise ValueError("confirmed DNS manifest differs")
        manifest = confirmed_snapshot["dnsCleanupManifest"]
        initial_id = manifest["initialJobId"]
        initial = job_repository.get(initial_id)
        if manifest["schema"] == "provider-keyed-empty-dns-prebinding-v1":
            if (initial is None or initial.status != "failed"
                    or initial.input.get("phase") != "attention"
                    or job_event_digest(initial.events) != manifest["initialJournalSha256"]):
                raise ValueError("failed prebinding journal changed")
            current_fence = fence or (lambda: None)
            current_fence()
            # Full source was proved by the caller before destroy_started. A
            # second phase-dependent source read here would reject that expected
            # marker before the DNS checkpoint can authorize the same GO.
            base_scope = {key: value for key, value in confirmed_snapshot.items()
                          if key not in {"snapshotId", "dnsCleanupManifest"}}
            fresh = build_provider_keyed_dns_cleanup_manifest(
                base_scope, job_repository=job_repository,
                domain_repository=domain_repository or SqlAlchemyDomainRepository(),
                active_destroy_apply_core_id=confirmed_snapshot["coreJobId"],
            )
            current_fence()
            if (fresh != manifest or job_event_digest(job_repository.get(initial_id).events)
                    != manifest["initialJournalSha256"]):
                raise ValueError("failed prebinding empty DNS manifest changed")
            checkpoint = {
                "dnsCleanupManifestSha256": manifest["manifestSha256"],
                "dnsCleanupHandoffJournalSha256": manifest["initialJournalSha256"],
            }
            checkpoint["dnsCleanupCheckpointSha256"] = _fingerprint({
                "scopeSnapshotId": confirmed_snapshot["snapshotId"], **checkpoint,
            })
            return checkpoint
        if manifest["schema"] == "provider-keyed-empty-dns-append-v1":
            from dataclasses import asdict
            from app.services.provider_keyed_append_source import (
                audit_published_provider_keyed_append_source,
            )

            core_id = confirmed_snapshot["coreJobId"]
            parent = job_repository.get(_parent_id(core_id))
            core = job_repository.get(core_id)
            append = job_repository.get(manifest["appendJobId"])
            sealed = parent.input.get("publishedAppendSource") if parent is not None else None
            scope = confirmed_snapshot["providerScopes"][0]
            if (initial is None or initial.status != "succeeded"
                    or core is None or parent is None or append is None
                    or append.status != "succeeded" or type(sealed) is not dict
                    or parent.action != ENGAGEMENT_TEARDOWN_ACTION
                    or parent.status != "queued" or parent.input.get("phase") != "queued"
                    or parent.input.get("scopeSnapshot") != confirmed_snapshot
                    or parent.target_id != confirmed_snapshot["engagementId"]
                    or manifest["initialJournalSha256"] != job_event_digest(initial.events)
                    or manifest["appendJournalSha256"] != job_event_digest(append.events)
                    or manifest["stateSha256"] != scope["stateSha256"]
                    or manifest["providerScopeSha256"] != confirmed_snapshot["providerScopeSha256"]):
                raise ValueError("published append DNS source changed")
            current_fence = fence or (lambda: None)
            current_fence()
            source = audit_published_provider_keyed_append_source(
                core_id, job_repository=job_repository)
            source_record = json.loads(json.dumps(asdict(source)))
            if (sealed != source_record or parent.input.get("publishedSource")
                    != source_record["initial_source"]
                    or source.append_job_id != append.id
                    or source.state_sha256 != scope["stateSha256"]):
                raise ValueError("reviewed append DNS generation changed")
            base_scope = {key: value for key, value in confirmed_snapshot.items()
                          if key not in {"snapshotId", "dnsCleanupManifest"}}
            fresh = build_provider_keyed_dns_cleanup_manifest(
                base_scope, job_repository=job_repository,
                domain_repository=domain_repository or SqlAlchemyDomainRepository(),
                active_destroy_apply_core_id=core_id)
            current_fence()
            if (fresh != manifest
                    or job_event_digest(job_repository.get(initial_id).events)
                       != manifest["initialJournalSha256"]
                    or job_event_digest(job_repository.get(append.id).events)
                       != manifest["appendJournalSha256"]):
                raise ValueError("fresh append empty DNS manifest changed")
            checkpoint = {
                "dnsCleanupManifestSha256": manifest["manifestSha256"],
                "dnsCleanupHandoffJournalSha256": manifest["initialJournalSha256"],
            }
            checkpoint["dnsCleanupCheckpointSha256"] = _fingerprint({
                "scopeSnapshotId": confirmed_snapshot["snapshotId"], **checkpoint,
            })
            return checkpoint
        if initial is None or len(initial.events) < 2:
            raise ValueError("initial host-binding journal is absent")
        full_digest = job_event_digest(initial.events)
        published = getattr(initial, "status", None) == "succeeded" and initial.input.get("phase") == "completed"
        if published:
            core = job_repository.get(confirmed_snapshot["coreJobId"])
            parent = job_repository.get(_parent_id(confirmed_snapshot["coreJobId"]))
            sealed = parent.input.get("publishedSource") if parent is not None else None
            scope = confirmed_snapshot["providerScopes"][0]
            if (core is None or parent is None or type(sealed) is not dict
                    or set(sealed) != {field.name for field in fields(PublishedProviderKeyedSource)}
                    or parent.action != ENGAGEMENT_TEARDOWN_ACTION
                    or parent.status != "queued" or parent.input.get("phase") != "queued"
                    or parent.target_id != confirmed_snapshot["engagementId"]
                    or parent.input.get("scopeSnapshot") != confirmed_snapshot
                    or manifest["initialJournalSha256"] != full_digest
                    or sealed["engagement_id"] != parent.target_id
                    or sealed["core_job_id"] != core.id
                    or sealed["core_plan_id"] != scope["corePlanId"]
                    or sealed["initial_job_id"] != initial_id
                    or sealed["initial_journal_sha256"] != full_digest
                    or sealed["core_journal_sha256"] != job_event_digest(core.events)
                    or sealed["scope_sha256"] != _fingerprint(scope)
                    or sealed["state_sha256"] != scope["stateSha256"]
                    or sealed["chain_ids"] != scope["chainIds"]):
                raise ValueError("published DNS source changed")
            bootstrap = audit_published_provider_keyed_bootstrap(
                core.id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
                job_repository=job_repository,
            )
            if (bootstrap.parent_job_id != initial_id
                    or bootstrap.chain_ids != tuple(scope["chainIds"])
                    or bootstrap.manifest_sha256 != sealed["manifest_sha256"]):
                raise ValueError("published bootstrap journal changed")
        else:
            handoff = initial.events[-1]
            prefix_digest = job_event_digest(initial.events[:-1])
            if (initial.input.get("phase") != "teardown_handoff_pending"
                    or handoff.level != "info"
                    or handoff.message != "provider bootstrap claim fenced for teardown handoff"
                    or handoff.sequence != len(initial.events)
                    or type(handoff.data) is not dict
                    or set(handoff.data) != {"phase", "sourceEventSha256",
                                             "scopeSnapshotSha256", "handoffClaimSha256"}
                    or handoff.data["phase"] != "teardown_handoff_pending"
                    or handoff.data["sourceEventSha256"] != prefix_digest
                    or handoff.data["scopeSnapshotSha256"] != _fingerprint(confirmed_snapshot)
                    or manifest["initialJournalSha256"] != prefix_digest):
                raise ValueError("reviewed pre-handoff journal differs")
        base_scope = {key: value for key, value in confirmed_snapshot.items()
                      if key not in {"snapshotId", "dnsCleanupManifest"}}
        current_fence = fence or (lambda: None)
        current_fence()
        selected_adapter = adapter or (_namecheap_dns_client()
                                       if manifest["domainAssignments"] else None)
        selected_adapter = (_FencedAdapter(selected_adapter, current_fence)
                            if selected_adapter is not None else None)
        fresh = build_provider_keyed_dns_cleanup_manifest(
            base_scope,
            job_repository=(job_repository if published else
                            _PreHandoffJobs(job_repository, initial_id, full_digest)),
            domain_repository=domain_repository or SqlAlchemyDomainRepository(),
            adapter=selected_adapter,
        )
        current_fence()
        if fresh != manifest or job_event_digest(job_repository.get(initial_id).events) != full_digest:
            raise ValueError("fresh DNS cleanup plan differs from confirmation")
        checkpoint = {
            "dnsCleanupManifestSha256": manifest["manifestSha256"],
            "dnsCleanupHandoffJournalSha256": full_digest,
        }
        checkpoint["dnsCleanupCheckpointSha256"] = _fingerprint({
            "scopeSnapshotId": confirmed_snapshot["snapshotId"], **checkpoint,
        })
        return checkpoint
    except Exception:
        raise ProviderKeyedDnsCleanupCheckpointError(
            "fresh confirmed DNS cleanup authority is unproved") from None
