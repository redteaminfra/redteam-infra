# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private DevTest retirement of a successfully destroyed, unpublished keyed group.

No dispatcher calls this module. It is a recovery boundary after the existing
one-shot destroy and exact-ID provider absence; it never performs a destroy.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from app.services.engagement_teardown import _fingerprint
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.services.provider_keyed_comprehensive_teardown import (
    ACTION, ProviderKeyedComprehensiveTeardownAttention, _child_id,
    recognize_provider_keyed_destroy_absence,
)
from app.services.provider_keyed_destroy_absence_preflight import (
    _read_success_boundary, reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.services.provider_keyed_initial_continuation import _job_ids
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_teardown_quiescence import audit_pending_provider_keyed_bootstrap
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import (
    _PROVIDER_ABSENT_PROOF_KEYS, _utc_instant, _valid_provider_absent_handoff,
    SqlAlchemyJobRepository, job_event_digest,
)
from app.storage.provider_resource_repository import (
    SqlAlchemyProviderResourceRepository, TERMINAL_RECORD_STATUSES,
)
from app.storage.sketch_chain_repository import (
    SqlAlchemySketchChainRepository, _canonical_keyed_inspector_record,
)


_EVENT = "keyed_pending_provider_group_retired"
_PHASE = "pending_group_retired"
_EVENT_KEYS = frozenset({
    "scopeSnapshotId", "providerScopeSha256", "sourceJournalSha256",
    "applyJobId", "resourceIdsSha256", "verifiedAbsentDropletIds",
    "verifiedAbsentFirewallId", "verifiedAbsentSshKeyId",
    "confirmationCompletedAt", "confirmationExpiresAt", "chainIds",
    "chainFingerprints", "retiredRecordIds", "observedAt",
})


def _repositories(jobs, plans, chains, credentials, resources, lookup):
    return (
        jobs or SqlAlchemyJobRepository(),
        plans or SqlAlchemyDeploymentPlanRepository(),
        chains or SqlAlchemySketchChainRepository(),
        credentials or SqlAlchemyCredentialRepository(),
        resources or SqlAlchemyProviderResourceRepository(),
        lookup or _db_lease_lookup,
    )


def _boundary(parent_id: str, *, environment: str, state_root: Path,
              jobs, plans, chains, credentials, lookup):
    if (environment != "devtest" or not parent_id or not isinstance(state_root, Path)
            or state_root != _default_state_root()
            or state_root.resolve(strict=True) != state_root):
        raise ValueError("DevTest pending retirement only")
    parent = jobs.get(parent_id)
    if parent is None or "publishedSource" in parent.input:
        raise ValueError("pending source only")
    return _read_success_boundary(
        parent_id, jobs=jobs, plans=plans, chains=chains,
        credentials=credentials, lookup=lookup,
        handoff_auditor=audit_pending_provider_keyed_bootstrap,
        credential_check=_credential_snapshot, state_root=state_root,
    )


def retire_pending_keyed_group_after_absence(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, provider_resource_repository=None, lease_lookup=None,
    absence_preflight: Callable | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> tuple:
    """Use a fresh exact-ID GET, then one SQLite commit for two pending rows."""
    try:
        jobs, plans, chains, credentials, resources, lookup = _repositories(
            job_repository, plan_repository, sketch_repository,
            credential_repository, provider_resource_repository, lease_lookup,
        )
        child = recognize_provider_keyed_destroy_absence(
            teardown_parent_id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            credential_repository=credentials, lease_lookup=lookup,
        )

        def read():
            return _boundary(
                teardown_parent_id, environment=environment, state_root=state_root,
                jobs=jobs, plans=plans, chains=chains, credentials=credentials,
                lookup=lookup,
            )

        before = read()
        rows = tuple(sorted(before.chains, key=lambda item: item.chain_id))
        all_rows = tuple(sorted(chains.list_for_engagement(before.parent.target_id),
                                key=lambda item: item.chain_id))
        if (tuple(row for row in all_rows if not _inert_aborted_intent(
                row, before.parent.target_id)) != rows
                or len({row.chain_id for row in all_rows}) != len(all_rows)):
            raise ValueError("complete pending chain set differs")
        records = tuple(sorted(resources.list_for_engagement(before.parent.target_id),
                               key=lambda item: item.id))
        ids = before.intent.resource_ids
        fingerprints = before.scope["chainFingerprints"]
        droplets = sorted(value for key, value in ids.items()
                          if key.startswith("digitalocean_droplet."))
        if (child.action != ACTION or child.input.get("phase") != "provider_absent"
                or child.id != _child_id(before.core.id)
                or child.target_id != before.parent.target_id
                or child.input.get("coreJobId") != before.core.id
                or child.input.get("corePlanId") != before.core.input["corePlanId"]
                or child.input.get("teardownParentId") != before.parent.id
                or child.input.get("scopeSnapshotId") != before.parent.input[
                    "scopeSnapshot"]["snapshotId"]
                or child.input.get("providerScopeSha256") != before.parent.input[
                    "scopeSnapshot"]["providerScopeSha256"]
                or len(rows) != 2 or {row.chain_id for row in rows} != set(before.scope["chainIds"])
                or any(row.status != "pending" or row.nodes or row.deploy_job_id
                       or row.teardown_job_id or row.terraform_working_directory
                       or sketch_chain_intent_fingerprint(row) != fingerprints[row.chain_id]
                       for row in rows)
                or jobs.get(child.id) != child):
            raise ValueError("pending group identity differs")
        get_absence = absence_preflight or reconcile_successful_digitalocean_destroy_absence
        get_started = now()
        if get_started.tzinfo is None or get_started.utcoffset() is None:
            raise ValueError("provider GET clock differs")
        evidence = get_absence(
            teardown_parent_id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            credential_repository=credentials, lease_lookup=lookup, max_attempts=12,
        )
        if (type(evidence) is not DigitalOceanAbsenceEvidence
                or evidence.empty_state_sha256 != before.intent.empty_state_sha256
                or list(evidence.verified_absent_droplet_ids) != droplets
                or evidence.verified_absent_firewall_id != ids["digitalocean_firewall.firewall"]
                or evidence.verified_absent_ssh_key_id != ids["digitalocean_ssh_key.key"]
                or read() != before or jobs.get(child.id) != child
                or tuple(sorted(chains.list_for_engagement(before.parent.target_id),
                                key=lambda item: item.chain_id)) != all_rows
                or tuple(sorted(resources.list_for_engagement(before.parent.target_id),
                                key=lambda item: item.id)) != records):
            raise ValueError("fresh absence or pending authority changed")
        # The deadline begins before provider GET, not after potentially slow
        # provider and local revalidation. SQLite checks it again under writer.
        completed = get_started
        rechecked = now()
        if (rechecked.tzinfo is None or rechecked.utcoffset() is None
                or rechecked < completed or rechecked >= completed + timedelta(seconds=30)):
            raise ValueError("provider absence has aged out")
        proof = {
            "scopeSnapshotId": child.input["scopeSnapshotId"],
            "providerScopeSha256": child.input["providerScopeSha256"],
            "sourceJournalSha256": job_event_digest(child.events),
            "applyJobId": before.apply_job.id,
            "resourceIdsSha256": _fingerprint(ids),
            "verifiedAbsentDropletIds": droplets,
            "verifiedAbsentFirewallId": evidence.verified_absent_firewall_id,
            "verifiedAbsentSshKeyId": evidence.verified_absent_ssh_key_id,
            "confirmationCompletedAt": completed.isoformat(),
            "confirmationExpiresAt": (completed + timedelta(seconds=30)).isoformat(),
        }

        def locked_authority():
            if (read() != before or jobs.get(child.id) != replace(
                    child, input={**child.input, "phase": _PHASE})
                    or tuple(sorted(chains.list_for_engagement(before.parent.target_id),
                                    key=lambda item: item.chain_id)) != all_rows
                    or tuple(sorted(resources.list_for_engagement(before.parent.target_id),
                                    key=lambda item: item.id)) != records):
                raise ValueError("pending retirement authority changed")

        return chains.publish_provider_keyed_pending_group_retired(
            coordinator=child, prior_chains=rows, prior_all_chains=all_rows,
            prior_records=records,
            group_apply_job_id=before.apply_job.id, resource_ids=dict(ids),
            chain_fingerprints=dict(fingerprints), proof=proof,
            allowed_record_origins=frozenset({_job_ids(before.core.id)[2]}),
            authority=locked_authority,
        )
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "pending keyed group retirement is unverified; no core or Inspector cleanup advanced"
        ) from None


def recognize_pending_keyed_group_retired(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, provider_resource_repository=None, lease_lookup=None,
) -> tuple:
    """Validate the historic prefix and both saved rows without provider I/O."""
    try:
        jobs, plans, chains, credentials, resources, lookup = _repositories(
            job_repository, plan_repository, sketch_repository,
            credential_repository, provider_resource_repository, lease_lookup,
        )
        bound = _boundary(
            teardown_parent_id, environment=environment, state_root=state_root,
            jobs=jobs, plans=plans, chains=chains, credentials=credentials,
            lookup=lookup,
        )
        child = jobs.get(_child_id(bound.core.id))
        if (child is None or child.action != ACTION or child.status != "running"
                or child.input.get("phase") != _PHASE or child.finished_at is not None
                or child.target_id != bound.parent.target_id
                or child.input.get("coreJobId") != bound.core.id
                or child.input.get("corePlanId") != bound.core.input["corePlanId"]
                or child.input.get("teardownParentId") != bound.parent.id
                or child.input.get("scopeSnapshotId") != bound.parent.input[
                    "scopeSnapshot"]["snapshotId"]
                or child.input.get("providerScopeSha256") != bound.parent.input[
                    "scopeSnapshot"]["providerScopeSha256"]
                or len(child.events) not in (7, 14, 18)
                or [event.sequence for event in child.events]
                != list(range(1, len(child.events) + 1))
                or child.events[-1].message != _EVENT or child.events[-1].level != "info"
                or len([job for job in jobs.list_for_engagement(bound.parent.target_id)
                        if job.action == ACTION]) != 1):
            raise ValueError("pending retirement coordinator differs")
        absent_child = replace(child, input={**child.input, "phase": "provider_absent"},
                               events=child.events[:-1])
        ready = replace(absent_child, input={**absent_child.input, "phase": "inspector_ready"},
                        events=absent_child.events[:-1])
        absent = absent_child.events[-1]
        evidence = absent.data
        if (absent.message != "provider_absent" or absent.level != "info"
                or type(evidence) is not dict
                or set(evidence) != _PROVIDER_ABSENT_PROOF_KEYS | {"observedAt"}
                or not _valid_provider_absent_handoff(
                    ready, job_event_digest(ready.events),
                    {key: value for key, value in evidence.items() if key != "observedAt"})
                or _utc_instant(evidence["observedAt"]) is None
                or not (_utc_instant(evidence["confirmationCompletedAt"])
                        <= _utc_instant(evidence["observedAt"])
                        < _utc_instant(evidence["confirmationExpiresAt"]))
                or evidence["previewJobId"] != bound.preview_job.id
                or evidence["previewJournalSha256"] != job_event_digest(bound.preview_job.events)
                or evidence["applyJobId"] != bound.apply_job.id
                or evidence["applyJournalSha256"] != job_event_digest(bound.apply_job.events)
                or evidence["emptyStateSha256"] != bound.intent.empty_state_sha256
                or evidence["resourceIdsSha256"] != _fingerprint(bound.intent.resource_ids)):
            raise ValueError("pending absence prefix differs")
        ids = bound.intent.resource_ids
        droplets = sorted(value for key, value in ids.items()
                          if key.startswith("digitalocean_droplet."))
        if (evidence["verifiedAbsentDropletIds"] != droplets
                or evidence["verifiedAbsentFirewallId"] != ids["digitalocean_firewall.firewall"]
                or evidence["verifiedAbsentSshKeyId"] != ids["digitalocean_ssh_key.key"]):
            raise ValueError("pending absent IDs differ")
        event = child.events[-1].data
        rows = tuple(sorted(bound.chains, key=lambda row: row.chain_id))
        expected_fingerprints = bound.scope["chainFingerprints"]
        if (type(event) is not dict or set(event) != _EVENT_KEYS
                or event["sourceJournalSha256"] != job_event_digest(absent_child.events)
                or event["scopeSnapshotId"] != child.input["scopeSnapshotId"]
                or event["providerScopeSha256"] != child.input["providerScopeSha256"]
                or event["applyJobId"] != bound.apply_job.id
                or event["resourceIdsSha256"] != _fingerprint(ids)
                or event["verifiedAbsentDropletIds"] != droplets
                or event["verifiedAbsentFirewallId"] != ids["digitalocean_firewall.firewall"]
                or event["verifiedAbsentSshKeyId"] != ids["digitalocean_ssh_key.key"]
                or _utc_instant(event["confirmationCompletedAt"]) is None
                or _utc_instant(event["confirmationExpiresAt"]) is None
                or _utc_instant(event["confirmationExpiresAt"])
                > _utc_instant(event["confirmationCompletedAt"]) + timedelta(seconds=30)
                or _utc_instant(event["observedAt"]) is None
                or not (_utc_instant(event["confirmationCompletedAt"])
                        <= _utc_instant(event["observedAt"])
                        < _utc_instant(event["confirmationExpiresAt"]))
                or event["chainIds"] != sorted(bound.scope["chainIds"])
                or event["chainFingerprints"] != {key: expected_fingerprints[key]
                                                   for key in sorted(expected_fingerprints)}
                or type(event["retiredRecordIds"]) is not list
                or event["retiredRecordIds"] != sorted(set(event["retiredRecordIds"]))
                or len(rows) != 2
                or any(row.status != "destroyed" or row.nodes or row.deploy_job_id
                       or row.teardown_job_id != bound.apply_job.id
                       or row.terraform_working_directory
                       or sketch_chain_intent_fingerprint(row) != expected_fingerprints[row.chain_id]
                       for row in rows)):
            raise ValueError("pending retirement event or rows differ")
        records = resources.list_for_engagement(bound.parent.target_id)
        ready_data = ready.events[-1].data
        inspector_ids = ({ready_data.get("hostRecordId"), ready_data.get("firewallRecordId")}
                         if type(ready_data) is dict else set())
        if (len(inspector_ids) != 2
                or any(type(value) is not str or not value for value in inspector_ids)):
            raise ValueError("selected Inspector identity differs")
        if any(not (record.id in inspector_ids and _canonical_keyed_inspector_record(record))
               and str(record.status).lower() not in TERMINAL_RECORD_STATUSES
               for record in records):
            raise ValueError("active provider record remains")
        by_kind = {
            "digitalocean_droplet": {value for key, value in ids.items()
                                     if key.startswith("digitalocean_droplet.")},
            "digitalocean_firewall": {ids["digitalocean_firewall.firewall"]},
            "digitalocean_ssh_key": {ids["digitalocean_ssh_key.key"]},
        }
        aliases = {"droplet": "digitalocean_droplet", "firewall": "digitalocean_firewall",
                   "ssh_key": "digitalocean_ssh_key"}
        retired = [record for record in records if record.id in event["retiredRecordIds"]]
        eligible = [record.id for record in records
                    if record.adoption_job_id == _job_ids(bound.core.id)[2]
                    and record.provider == "digitalocean"
                    and isinstance(record.metadata, dict)
                    and record.metadata.get("barraganOwned") is True
                    and record.resource_id in by_kind.get(
                        aliases.get(record.resource_type, record.resource_type), set())]
        if (sorted(record.id for record in retired) != event["retiredRecordIds"]
                or sorted(eligible) != event["retiredRecordIds"]
                or any(record.id in inspector_ids
                       or str(record.status).lower() not in TERMINAL_RECORD_STATUSES
                       or record.provider != "digitalocean"
                       or not isinstance(record.metadata, dict)
                       or record.metadata.get("barraganOwned") is not True
                       or record.adoption_job_id != _job_ids(bound.core.id)[2]
                       or record.resource_id not in by_kind.get(
                           aliases.get(record.resource_type, record.resource_type), set())
                       for record in retired)):
            raise ValueError("retired provider record differs")
        return rows
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "sealed pending group retirement is unverified; fresh proof is required for later cleanup"
        ) from None
