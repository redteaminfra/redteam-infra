# Copyright (c) 2026, Oracle and/or its affiliates.
"""Engagement-scoped, read-only binding inventory for a published mixed append.

Only opaque row hashes leave this collector. The append source fences the
complete engagement-scoped mutation history and binding rows around provider
GETs, then hashes them in its returned review identity.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Callable

from app.services.engagement_operations import _is_default_backflip
from app.services.provider_keyed_mixed_initial_host_binding import _digest
from app.storage.certificate_repository import SqlAlchemyCertificateRepository
from app.storage.domain_repository import (
    SqlAlchemyDomainRepository, StoredDomainDnsRecordOwnership,
)
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository


class MixedAppendLiveBindingsAttention(ValueError):
    """A complete engagement-scoped binding snapshot could not be read."""


_NON_SEMANTIC_TIMES = frozenset({
    "created_at", "updated_at", "assigned_at", "released_at", "fetched_at",
    "createdAt", "updatedAt", "assignedAt", "releasedAt", "fetchedAt",
    "checkedAt", "lastCheckedAt", "externalIngressCheckedAt", "lastAttemptAt",
})


def _semantic(value: Any) -> Any:
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return {key: _semantic(item) for key, item in value.items()
                if key not in _NON_SEMANTIC_TIMES}
    if isinstance(value, (tuple, list)):
        return [_semantic(item) for item in value]
    return value


def _identity(kind: str, key: str, row: Any) -> tuple[str, str, str]:
    return kind, str(key), _digest(_semantic(row))


def _channel_history(jobs: list) -> tuple:
    """Fingerprint every raw mutation, not a potentially stale latest snapshot."""
    history = []
    for job in jobs:
        if job.action == "inspector_inspection":
            continue
        channel_events = []
        saw_channel_key = False
        for event in job.events:
            fields = {}
            for key in ("inboundChannels", "outboundChannels"):
                if key not in event.data:
                    continue
                saw_channel_key = True
                rows = event.data[key]
                if type(rows) is not list or any(type(row) is not dict for row in rows):
                    raise ValueError("raw channel mutation row is malformed")
                filtered = [row for row in rows
                            if key != "inboundChannels" or not _is_default_backflip(row)]
                # An empty snapshot is an authoritative removal; a nonempty
                # synthetic-only snapshot is not a real topology mutation.
                if filtered or not rows:
                    fields[key] = _semantic(filtered)
            if fields:
                channel_events.append(fields)
        mutation_action = (job.action == "engagement_channels_update"
                           or job.action.startswith(("inbound_channel_", "outbound_channel_")))
        if not channel_events and (saw_channel_key or not mutation_action):
            continue
        history.append(_identity("channel-mutation", job.id, {
            "action": job.action, "status": job.status, "input": job.input,
            "channelEvents": channel_events,
            "journal": [(event.sequence, event.level, event.message,
                         _semantic({key: value for key, value in event.data.items()
                                    if key not in {"inboundChannels", "outboundChannels"}}))
                        for event in job.events]
                       if mutation_action else [],
        }))
    return tuple(sorted(history))


def collect_mixed_append_live_bindings(
    engagement_id: str, *,
    job_repository=None,
    domain_repository=None, certificate_repository=None, service_repository=None,
    dns_ownership_reader: Callable[[str], list] | None = None,
) -> dict[str, tuple]:
    """Return opaque identities for this engagement's binding fence.

    Includes raw inbound and outbound channel mutation history, domain assignments and
    DNS record ownership rows, certificate assets and bindings, and services.
    Reads are engagement-scoped; this function never reads global job history
    or contacts a cloud provider. Channel events are unbounded within this one
    engagement because the 250-job UI projection can omit older live channel
    state. Historical ownership rows are included so a row's retirement or
    disappearance also changes the inventory.
    """
    try:
        if type(engagement_id) is not str or not engagement_id:
            raise ValueError("engagement identity absent")
        repository = job_repository or SqlAlchemyJobRepository()
        jobs = repository.list_channel_mutations_for_engagement(engagement_id)
        channels = _channel_history(jobs)
        domains = domain_repository or SqlAlchemyDomainRepository()
        certificates = certificate_repository or SqlAlchemyCertificateRepository()
        services = service_repository or SqlAlchemyEngagementServiceRepository()
        assignments = domains.list_assignments(engagement_id=engagement_id)
        ownership = (dns_ownership_reader or _owned_dns_rows)(engagement_id)
        assets = certificates.list_assets(engagement_id)
        bindings = certificates.list_bindings(engagement_id)
        service_rows = services.list_for_engagement(engagement_id)
        if (any(row.engagement_id != engagement_id for row in assignments)
                or any(row.engagement_id != engagement_id for row in ownership)
                or any(row.engagement_id != engagement_id for row in assets)
                or any(row.engagement_id != engagement_id for row in bindings)
                or any(row.engagement_id != engagement_id for row in service_rows)):
            raise ValueError("binding row belongs to another engagement")
        domain_rows = [
            *(_identity("assignment", str(row.id), row) for row in assignments),
            *(_identity("dns-ownership", str(row.id), row) for row in ownership),
        ]
        certificate_rows = [
            *(_identity("asset", row.id, row) for row in assets),
            *(_identity("binding", row.id, row) for row in bindings),
        ]
        site_rows = [_identity("service", row.service_id, row) for row in service_rows]
        return {
            "channels": channels,
            "domains": tuple(sorted(domain_rows)),
            "certificates": tuple(sorted(certificate_rows)),
            "sites": tuple(sorted(site_rows)),
        }
    except Exception:
        raise MixedAppendLiveBindingsAttention(
            "mixed append live bindings need exact engagement-scoped review") from None


def _owned_dns_rows(engagement_id: str) -> list:
    from app.storage.database import db
    from app.storage.models import DomainDnsRecordOwnershipModel

    rows = db.session.query(DomainDnsRecordOwnershipModel).filter_by(
        engagement_id=engagement_id).order_by(
            DomainDnsRecordOwnershipModel.id.asc()).all()
    return [StoredDomainDnsRecordOwnership(
        id=row.id, domain_id=row.domain_id,
        assignment_id=row.assignment_id, engagement_id=row.engagement_id,
        creating_job_id=row.creating_job_id, snapshot_id=row.snapshot_id,
        record=dict(row.record),
        retired_at=row.retired_at.isoformat() if row.retired_at else None,
    ) for row in rows]
