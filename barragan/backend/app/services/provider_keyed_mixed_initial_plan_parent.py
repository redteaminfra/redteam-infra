# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant mixed-provider parent checkpoint: both plans before either Apply.

There is deliberately no dispatcher or Apply call in this module. The active
engagement lease comes from the applied core plan; this parent adds a fenced
worker claim and append-only, deterministic plan checkpoints.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services import provider_keyed_mixed_linode_saved_plan as linode
from app.services import provider_keyed_mixed_digitalocean_saved_plan as digitalocean
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, StoredJobRun, job_event_digest,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository


ACTION = "provider_keyed_mixed_initial"
_OWNER = f"mixed-plan-{uuid4().hex}"
_CLAIM_SECONDS = 3600
_PHASES = ("queued", "planning", "first_plan_saved", "second_plan_saved", "both_plans_saved", "apply_sealed")
_MESSAGES = ("mixed provider plans queued", "mixed provider planning started",
             "first mixed provider plan saved", "second mixed provider plan saved",
             "both mixed provider plans saved", "mixed provider Apply source sealed")
_RUNNERS = {"linode": linode.prepare_or_reuse_mixed_linode_saved_plan,
            "digitalocean": digitalocean.prepare_or_reuse_mixed_digitalocean_saved_plan}


class MixedInitialPlanParentError(ValueError):
    """The mixed plan checkpoint is missing, stale, or concurrently claimed."""


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parent_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-initial-{core_job_id.removeprefix('job-')}"


def _records(core_job_id, engagement_id, lease_owner, lookup, engagements, sketches,
             jobs, plans, credentials, keys, *,
             lease_operation: str = "provider_keyed_initial"):
    """Rebind both compilers to the same active applied core and lease."""
    lin = linode._current(engagement_id, core_job_id, lease_owner, lookup, engagements,
                          sketches, jobs, plans, credentials, keys, None,
                          lease_operation=lease_operation)
    do = digitalocean._current(engagement_id, core_job_id, lease_owner, lookup, engagements,
                                sketches, jobs, plans, credentials, keys, None,
                                lease_operation=lease_operation)
    _, chains, core, plan, lin_intent, _ = lin
    if (do[2] != core or do[3] != plan or do[4].review_fingerprint != lin_intent.review_fingerprint
            or do[4].engagement_id != lin_intent.engagement_id
            or do[4].core_plan_id != lin_intent.core_plan_id):
        raise MixedInitialPlanParentError("mixed provider compilers disagree")
    ids = plan.evidence["pendingSketchChainIds"]
    by_id = {chain.chain_id: chain for chain in chains}
    order = [by_id[chain_id].middle_provider for chain_id in ids]
    if len(ids) != 2 or set(order) != {"linode", "digitalocean"}:
        raise MixedInitialPlanParentError("reviewed mixed provider order differs")
    return core, plan, ids, order, {"linode": lin_intent, "digitalocean": do[4]}


def _validate_parent(parent: StoredJobRun, core, plan, ids, order) -> None:
    inputs = parent.input
    if (parent.id != _parent_id(core.id) or parent.action != ACTION
            or parent.status not in {"queued", "running"}
            or parent.target != f"engagement:{plan.engagement_id}"
            or parent.target_type != "engagement" or parent.target_id != plan.engagement_id
            or parent.requested_by != core.requested_by or parent.finished_at is not None
            or not isinstance(inputs, dict)
            or {k: v for k, v in inputs.items() if not k.startswith("claim")} != {
                "engagementId": plan.engagement_id, "coreJobId": core.id,
                "corePlanId": plan.id, "revisionId": plan.revision_id,
                "reviewFingerprint": plan.evidence["sketchAuthorization"]["fingerprint"],
                "chainIds": ids, "orderedProviders": order,
                "phase": inputs.get("phase"), "mutation": True,
            } or inputs.get("phase") not in _PHASES
            or len(parent.events) != _PHASES.index(inputs["phase"]) + 1
            or any(event.sequence != index or event.level != "info"
                   or event.message != _MESSAGES[index - 1]
                   for index, event in enumerate(parent.events, 1))
            or parent.events[0].data != {"coreJobId": core.id,
                                          "reviewFingerprint": inputs["reviewFingerprint"]}):
        raise MixedInitialPlanParentError("mixed plan parent differs from reviewed core")


def _receipt_data(provider: str, chain_id: str, receipt: dict, intent) -> dict[str, str]:
    schema = f"mixed-{provider}-saved-plan-v1"
    if (not isinstance(receipt, dict) or receipt.get("schema") != schema
            or receipt.get("engagementId") != intent.engagement_id
            or receipt.get("coreJobId") != intent.core_job_id
            or receipt.get("corePlanId") != intent.core_plan_id
            or receipt.get("revisionId") != intent.revision_id
            or receipt.get("reviewFingerprint") != intent.review_fingerprint
            or receipt.get("connectionId") != intent.provider_connection_id
            or receipt.get("credentialSecretSha256") != intent.credential_secret_sha256
            or receipt.get("credentialUpdatedAt") != intent.credential_updated_at
            or receipt.get("stateAbsent") is not True
            or any(not isinstance(receipt.get(key), str)
                   or len(receipt[key]) != 64 or any(ch not in "0123456789abcdef" for ch in receipt[key])
                   for key in ("planSha256", "journalSha256", "sourceSha256", "lockfileSha256",
                               "topologySha256", "inputSha256", "showJsonSha256"))):
        raise MixedInitialPlanParentError("provider plan receipt differs from reviewed core")
    return {"provider": provider, "chainId": chain_id,
            "receiptSha256": _digest(receipt), "planSha256": receipt["planSha256"],
            "journalSha256": receipt["journalSha256"]}


def _seal_data(parent: StoredJobRun, ids, order, intents) -> dict:
    """Bind reviewed identities and both immutable plan receipts, without secrets."""
    snapshots = [json.loads(json.dumps(asdict(intents[provider]), sort_keys=True))
                 for provider in order]
    # Intent dataclasses contain reviewed nonsecret inputs only. Persisting
    # them makes future partial-state classification independent of mutable
    # pending chain rows and credential records.
    policy = {provider: snapshot for provider, snapshot in zip(order, snapshots)}
    return {
        "schema": "mixed-initial-apply-seal-v1",
        "corePlanId": parent.input["corePlanId"],
        "reviewFingerprint": parent.input["reviewFingerprint"],
        "orderedProviders": list(order),
        "chainIds": list(ids),
        "providerConnectionIds": [intents[provider].provider_connection_id for provider in order],
        "receiptSha256": [parent.events[index + 2].data["receiptSha256"] for index in range(2)],
        "intentSha256": [_digest(snapshot) for snapshot in snapshots],
        "sourceCredentialSnapshotSha256": _digest(snapshots),
        "firstFiveJournalSha256": job_event_digest(parent.events[:5]),
        "reviewedPolicy": policy,
    }


def validate_mixed_initial_apply_seal(parent: StoredJobRun, *, intents=None) -> dict:
    """Recognize the historical seal without recompiling a future partial state."""
    data = parent.events[5].data if len(parent.events) >= 6 else None
    inputs = parent.input if isinstance(parent.input, dict) else {}
    if (parent.action != ACTION or not isinstance(inputs.get("engagementId"), str)
            or not inputs["engagementId"] or not isinstance(inputs.get("coreJobId"), str)
            or not inputs["coreJobId"] or not isinstance(inputs.get("corePlanId"), str)
            or not inputs["corePlanId"] or not isinstance(inputs.get("revisionId"), str)
            or not inputs["revisionId"]
            or parent.id != _parent_id(inputs["coreJobId"])
            or parent.target != f"engagement:{inputs['engagementId']}"
            or parent.target_type != "engagement" or parent.target_id != inputs["engagementId"]
            or inputs.get("mutation") is not True
            or not isinstance(inputs.get("orderedProviders"), list)
            or len(inputs["orderedProviders"]) != 2
            or set(inputs["orderedProviders"]) != {"linode", "digitalocean"}
            or not isinstance(inputs.get("chainIds"), list) or len(inputs["chainIds"]) != 2
            or [(event.sequence, event.level, event.message) for event in parent.events[:6]]
            != [(index, "info", _MESSAGES[index - 1]) for index in range(1, 7)]
            or parent.events[0].data != {"coreJobId": inputs.get("coreJobId"),
                                          "reviewFingerprint": inputs.get("reviewFingerprint")}
            or [parent.events[2].data.get("provider"), parent.events[3].data.get("provider")]
            != inputs.get("orderedProviders")
            or [parent.events[2].data.get("chainId"), parent.events[3].data.get("chainId")]
            != inputs.get("chainIds")
            or parent.events[4].data != {
                "firstReceiptSha256": parent.events[2].data.get("receiptSha256"),
                "secondReceiptSha256": parent.events[3].data.get("receiptSha256"),
                "reviewFingerprint": inputs.get("reviewFingerprint"),
            }
            or not isinstance(data, dict) or parent.events[5].sequence != 6
            or parent.events[5].level != "info" or parent.events[5].message != _MESSAGES[5]
            or data.get("schema") != "mixed-initial-apply-seal-v1"
            or data.get("corePlanId") != inputs.get("corePlanId")
            or data.get("reviewFingerprint") != inputs.get("reviewFingerprint")
            or data.get("orderedProviders") != inputs.get("orderedProviders")
            or data.get("chainIds") != inputs.get("chainIds")
            or data.get("receiptSha256") != [parent.events[2].data.get("receiptSha256"),
                                               parent.events[3].data.get("receiptSha256")]
            or data.get("firstFiveJournalSha256") != job_event_digest(parent.events[:5])
            or set(data) != {"schema", "corePlanId", "reviewFingerprint", "orderedProviders",
                             "chainIds", "providerConnectionIds", "receiptSha256",
                             "intentSha256", "sourceCredentialSnapshotSha256",
                             "firstFiveJournalSha256", "reviewedPolicy"}
            or not isinstance(data.get("providerConnectionIds"), list)
            or len(data["providerConnectionIds"]) != 2
            or any(not isinstance(value, str) or not value for value in data["providerConnectionIds"])
            or not isinstance(data.get("intentSha256"), list) or len(data["intentSha256"]) != 2
            or any(not isinstance(value, str) or len(value) != 64 for value in data["intentSha256"])
            or not isinstance(data.get("sourceCredentialSnapshotSha256"), str)
            or len(data["sourceCredentialSnapshotSha256"]) != 64
            or not isinstance(data.get("reviewedPolicy"), dict)
            or set(data["reviewedPolicy"]) != set(inputs.get("orderedProviders", []))
            or data["intentSha256"] != [_digest(data["reviewedPolicy"][provider])
                                        for provider in inputs["orderedProviders"]]
            or data["sourceCredentialSnapshotSha256"] != _digest(
                [data["reviewedPolicy"][provider] for provider in inputs["orderedProviders"]])):
        raise MixedInitialPlanParentError("mixed Apply seal differs from saved plans")
    if intents is not None:
        expected = _seal_data(parent, inputs["chainIds"], inputs["orderedProviders"], intents)
        if _digest(data) != _digest(expected):
            raise MixedInitialPlanParentError("mixed Apply source or credential snapshot changed")
    return data


def _advance(jobs, parent, token, phase: str, data: dict,
             lookup, engagement_id: str, lease_owner: str) -> StoredJobRun:
    _require_lease(lookup, engagement_id, lease_owner)
    index = _PHASES.index(phase)
    updated = jobs.append_mixed_plan_phase_if_claimed(
        parent, owner=_OWNER, token=token, lease_owner=lease_owner,
        expected_event_digest=job_event_digest(parent.events),
        next_phase=phase, event=JobEvent(len(parent.events) + 1, "info", _MESSAGES[index], data))
    if updated is None or updated.input.get("phase") != phase:
        raise MixedInitialPlanParentError("mixed plan parent checkpoint lost its claim")
    return updated


def prepare_or_reuse_mixed_initial_plans(
    core_job_id: str, *, engagement_id: str, lease_owner: str,
    environment: str, state_root: Path, template_root: Path,
    job_repository=None, engagement_repository=None, sketch_repository=None,
    plan_repository=None, credential_repository=None, ssh_key_repository=None,
    lease_lookup=None, linode_runner: Callable | None = None,
    digitalocean_runner: Callable | None = None,
) -> StoredJobRun:
    """Persist both audited plan receipts in reviewed order; never Apply."""
    if environment != "devtest" or not core_job_id or not engagement_id or not lease_owner:
        raise MixedInitialPlanParentError("mixed plan requires a DevTest reviewed core lease")
    jobs = job_repository or SqlAlchemyJobRepository()
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    lookup = lease_lookup or _db_lease_lookup
    previous = jobs.get(_parent_id(core_job_id))
    if previous is not None and previous.input.get("phase") == "apply_sealed":
        if (previous.target_id != engagement_id or previous.input.get("coreJobId") != core_job_id
                or previous.input.get("corePlanId") != lease_owner):
            raise MixedInitialPlanParentError("sealed mixed parent identity differs")
        validate_mixed_initial_apply_seal(previous)
        return previous
    runners = {"linode": linode_runner or _RUNNERS["linode"],
               "digitalocean": digitalocean_runner or _RUNNERS["digitalocean"]}

    core, plan, ids, order, intents = _records(
        core_job_id, engagement_id, lease_owner, lookup, engagements, sketches,
        jobs, plans, credentials, keys)
    initial = StoredJobRun(
        _parent_id(core.id), ACTION, "queued", f"engagement:{engagement_id}",
        "engagement", engagement_id, core.requested_by,
        {"engagementId": engagement_id, "coreJobId": core.id, "corePlanId": plan.id,
         "revisionId": plan.revision_id, "reviewFingerprint": intents["linode"].review_fingerprint,
         "chainIds": ids, "orderedProviders": order, "phase": "queued", "mutation": True},
        [], _now(), None, None,
        [JobEvent(1, "info", _MESSAGES[0],
                  {"coreJobId": core.id, "reviewFingerprint": intents["linode"].review_fingerprint})])
    parent = jobs.save_if_absent(initial)
    _validate_parent(parent, core, plan, ids, order)
    adapter_kwargs = {
        "engagement_id": engagement_id, "core_job_id": core.id, "lease_owner": lease_owner,
        "environment": environment, "state_root": state_root, "template_root": template_root,
        "engagement_repository": engagements, "sketch_repository": sketches,
        "job_repository": jobs, "plan_repository": plans,
        "credential_repository": credentials, "ssh_key_repository": keys,
        "lease_lookup": lookup,
    }
    if parent.input["phase"] == "both_plans_saved":
        # A completed checkpoint remains an audit record, not Apply authority.
        receipts = []
        for index, provider in enumerate(order):
            _require_lease(lookup, engagement_id, lease_owner)
            data = _receipt_data(provider, ids[index], runners[provider](**adapter_kwargs),
                                 intents[provider])
            if parent.events[index + 2].data != data:
                raise MixedInitialPlanParentError("joined provider receipt changed")
            receipts.append(data)
        if parent.events[4].data != {
            "firstReceiptSha256": receipts[0]["receiptSha256"],
            "secondReceiptSha256": receipts[1]["receiptSha256"],
            "reviewFingerprint": intents["linode"].review_fingerprint,
        }:
            raise MixedInitialPlanParentError("joined plan checkpoint differs")
        return parent
    now = _now()
    token = uuid4().hex
    expiry = (datetime.fromisoformat(now) + timedelta(seconds=_CLAIM_SECONDS)).isoformat()
    claimed = jobs.claim_lease(parent.id, owner=_OWNER, token=token,
                               claimed_at=now, expires_at=expiry,
                               eligible_statuses={"queued", "running"},
                               eligible_phases=set(_PHASES[:4]))
    if claimed is None:
        return jobs.get(parent.id) or parent
    parent = claimed
    _validate_parent(parent, core, plan, ids, order)
    if parent.input["phase"] == "queued":
        parent = _advance(jobs, parent, token, "planning", {}, lookup, engagement_id, lease_owner)
    receipts = {}
    for index, provider in enumerate(order):
        _require_lease(lookup, engagement_id, lease_owner)
        current = _records(core_job_id, engagement_id, lease_owner, lookup, engagements,
                           sketches, jobs, plans, credentials, keys)
        if current[2:4] != (ids, order) or current[4] != intents:
            raise MixedInitialPlanParentError("reviewed mixed plan inputs changed")
        receipt = runners[provider](**adapter_kwargs)
        data = _receipt_data(provider, ids[index], receipt, intents[provider])
        receipts[provider] = data
        phase = _PHASES[index + 2]
        if _PHASES.index(parent.input["phase"]) < _PHASES.index(phase):
            parent = _advance(jobs, parent, token, phase, data,
                              lookup, engagement_id, lease_owner)
        elif parent.events[index + 2].data != data:
            raise MixedInitialPlanParentError("saved provider receipt differs from parent journal")
    # The first source may have changed while the second plan ran. Reuse both
    # adapters once more under the same lease before recording the joined gate.
    for index, provider in enumerate(order):
        _require_lease(lookup, engagement_id, lease_owner)
        receipt = runners[provider](**adapter_kwargs)
        if _receipt_data(provider, ids[index], receipt, intents[provider]) != receipts[provider]:
            raise MixedInitialPlanParentError("provider receipt changed before joined checkpoint")
    joined = {"firstReceiptSha256": receipts[order[0]]["receiptSha256"],
              "secondReceiptSha256": receipts[order[1]]["receiptSha256"],
              "reviewFingerprint": intents["linode"].review_fingerprint}
    return _advance(jobs, parent, token, "both_plans_saved", joined,
                    lookup, engagement_id, lease_owner)


def seal_mixed_initial_apply(
    core_job_id: str, *, engagement_id: str, lease_owner: str,
    environment: str, state_root: Path, template_root: Path,
    job_repository=None, engagement_repository=None, sketch_repository=None,
    plan_repository=None, credential_repository=None, ssh_key_repository=None,
    lease_lookup=None, linode_runner: Callable | None = None,
    digitalocean_runner: Callable | None = None,
) -> StoredJobRun:
    """Seal both reviewed plans under the existing core lease before any Apply."""
    if environment != "devtest" or not core_job_id or not engagement_id or not lease_owner:
        raise MixedInitialPlanParentError("mixed Apply seal requires DevTest reviewed core lease")
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = jobs.get(_parent_id(core_job_id))
    if parent is None:
        raise MixedInitialPlanParentError("both mixed plans must be saved before Apply seal")
    if parent.input.get("phase") == "apply_sealed":
        if (parent.target_id != engagement_id or parent.input.get("coreJobId") != core_job_id
                or parent.input.get("corePlanId") != lease_owner):
            raise MixedInitialPlanParentError("sealed mixed parent identity differs")
        validate_mixed_initial_apply_seal(parent)
        return parent
    if parent.input.get("phase") != "both_plans_saved":
        raise MixedInitialPlanParentError("both mixed plans must be saved before Apply seal")
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    lookup = lease_lookup or _db_lease_lookup
    runners = {"linode": linode_runner or _RUNNERS["linode"],
               "digitalocean": digitalocean_runner or _RUNNERS["digitalocean"]}
    core, plan, ids, order, intents = _records(
        core_job_id, engagement_id, lease_owner, lookup, engagements, sketches,
        jobs, plans, credentials, keys)
    _validate_parent(parent, core, plan, ids, order)
    token = uuid4().hex
    now = _now()
    expiry = (datetime.fromisoformat(now) + timedelta(seconds=120)).isoformat()
    claimed = jobs.claim_lease(parent.id, owner=_OWNER, token=token,
                               claimed_at=now, expires_at=expiry,
                               eligible_statuses={"running"}, eligible_phases={"both_plans_saved"})
    if claimed is None:
        current = jobs.get(parent.id)
        if current is not None and current.input.get("phase") == "apply_sealed":
            validate_mixed_initial_apply_seal(current)
            return current
        raise MixedInitialPlanParentError("mixed Apply seal writer is concurrently claimed")
    parent = claimed
    _validate_parent(parent, core, plan, ids, order)
    kwargs = dict(engagement_id=engagement_id, core_job_id=core.id, lease_owner=lease_owner,
                  environment=environment, state_root=state_root, template_root=template_root,
                  engagement_repository=engagements, sketch_repository=sketches,
                  job_repository=jobs, plan_repository=plans,
                  credential_repository=credentials, ssh_key_repository=keys,
                  lease_lookup=lookup)
    for index, provider in enumerate(order):
        _require_lease(lookup, engagement_id, lease_owner)
        receipt_data = _receipt_data(provider, ids[index], runners[provider](**kwargs), intents[provider])
        if parent.events[index + 2].data != receipt_data:
            raise MixedInitialPlanParentError("provider plan changed before Apply seal")
    current = _records(core_job_id, engagement_id, lease_owner, lookup, engagements,
                       sketches, jobs, plans, credentials, keys)
    if current != (core, plan, ids, order, intents):
        raise MixedInitialPlanParentError("reviewed source or credential changed before Apply seal")
    data = _seal_data(parent, ids, order, intents)
    sealed = _advance(jobs, parent, token, "apply_sealed", data,
                      lookup, engagement_id, lease_owner)
    validate_mixed_initial_apply_seal(sealed, intents=intents)
    return sealed
