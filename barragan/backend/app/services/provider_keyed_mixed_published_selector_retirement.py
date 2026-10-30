# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot retirement of a published mixed DO selector.

Only the exact terminal two-provider, OCI, and Inspector-negative receipts
can reach DELETE. A saved intent is reconciled with GET; it is never replayed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.credentials import decrypt_secret_value
from app.services.engagement_teardown import _fingerprint
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_mixed_initial_apply_child import _child_id as apply_child_id
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_id
from app.services.provider_keyed_mixed_published_destroy_child import child_id as destroy_child_id
from app.services.provider_keyed_mixed_published_post_oci_source import (
    PublishedMixedPostOciSource, audit_published_mixed_post_oci_source,
)
from app.services.provider_keyed_mixed_published_selector_guard import read_published_selector_guard
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    parent_id, recognize_published_mixed_plans_sealed,
    saved_published_mixed_destroy_plans, saved_published_mixed_initial_review,
)
from app.services.provider_keyed_mixed_zero_apply_core_absence import (
    ACTION as OCI_ABSENCE_ACTION, _child_prefix as absence_prefix,
    prove_mixed_zero_apply_oci_core_absence,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
    ACTION as NEGATIVE_ACTION, latest_negative_attempt,
    prove_mixed_zero_apply_inspector_negative,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_selector_retirement import DeleteResponse, UrllibDeleteTransport
from app.services.sketch_state_workspaces import _default_state_root
from app.services.provider_keyed_mixed_published_teardown_authority import published_review_policy

from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_published_selector_retirement"


class PublishedMixedSelectorRetirementAttention(ValueError):
    """Exact published selector outcome requires read-only reconciliation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=60)).isoformat()


def _child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-published-selector-retirement-{core_job_id.removeprefix('job-')}"


def _base(engagement_id, core_job_id, parent, initial, review, plans,
          absent, negative, credential_repository, source):
    if (type(source) is not PublishedMixedPostOciSource
            or source.provider_absence_receipt_sha256 is None
            or len(source.provider_absence_receipt_sha256) != 2):
        raise ValueError("two provider absence receipts are missing")
    do_index = review.source.ordered_providers.index("digitalocean")
    scope = review.provider_scopes[do_index]
    policy = published_review_policy(review, initial, "digitalocean")
    selector = policy["selector_tag"]
    if (selector != "s" + hashlib.sha256(engagement_id.encode()).hexdigest()[:20]
            or parent.input["corePlanId"] != review.source.core_plan_id):
        raise ValueError("owned published selector differs")
    connection = policy["provider_connection_id"]
    secret_sha, updated_at, encrypted = _credential_snapshot(
        connection, credential_repository)
    if ((secret_sha, updated_at) != (policy["credential_secret_sha256"],
                                    policy["credential_updated_at"])):
        raise ValueError("reviewed DigitalOcean credential changed")
    return {
        "schema": "mixed-published-selector-retirement-v1",
        "engagementId": engagement_id, "coreJobId": core_job_id,
        "corePlanId": parent.input["corePlanId"], "teardownParentId": parent.id,
        "reviewSha256": parent.input["publishedSourceSha256"],
        "planSetSha256": plans.plan_set_sha256,
        "doScopeSha256": _fingerprint(scope), "selectorTag": selector,
        "providerConnectionId": connection,
        "credentialSecretSha256": secret_sha, "credentialUpdatedAt": updated_at,
        "ociAbsenceJobId": absent.id,
        "ociAbsenceJournalSha256": job_event_digest(absent.events),
        "inspectorNegativeJobId": negative.id,
        "inspectorNegativeJournalSha256": job_event_digest(negative.events),
        "doAbsenceReceiptSha256": source.provider_absence_receipt_sha256[do_index],
        "publishedParentJournalSha256": review.published_parent_journal_sha256,
        "mutation": True,
    }, encrypted


def retire_published_mixed_selector(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, job_repository=None,
    plan_repository=None, credential_repository=None, lease_lookup=None,
    catalog_transport=None, delete_transport=None,
    decrypt_secret: Callable = decrypt_secret_value,
    post_source_reader: Callable = audit_published_mixed_post_oci_source,
    oci_absence_recognizer: Callable = prove_mixed_zero_apply_oci_core_absence,
    negative_recognizer: Callable = prove_mixed_zero_apply_inspector_negative,
    identity_reader=None,
    historical_negative: bool = False,
) -> StoredJobRun:
    """Retire the reserved tag once, after full published tail proofs.

    No caller currently exposes this private action through HTTP. The later
    coordinator must finish it before retiring the Linode Inspector.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    plan_repo = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    catalog = catalog_transport or UrllibProviderCatalogTransport()
    deleter = delete_transport or UrllibDeleteTransport()
    current = None
    try:
        if (type(historical_negative) is not bool
                or environment != "devtest" or state_root != _default_state_root()
                or not state_root.is_absolute() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("private DevTest selector root differs")
        parent, initial = jobs.get(parent_id(core_job_id)), jobs.get(initial_id(core_job_id))
        core = jobs.get(core_job_id)
        if (parent is None or initial is None or core is None
                or parent.target_id != engagement_id):
            raise ValueError("published mixed parent is absent")
        plan = plan_repo.get(core.input["corePlanId"])
        if plan is None:
            raise ValueError("published core plan is absent")
        review = saved_published_mixed_initial_review(parent)
        plans = saved_published_mixed_destroy_plans(parent)
        recognize_published_mixed_plans_sealed(
            parent, review, plans, parent.input["reviewScope"],
            parent.input["engagementName"])
        source = post_source_reader(parent, initial, core, plan, jobs, lookup)
        if lookup(engagement_id) != (plan.id, "provider_keyed_teardown_fence"):
            raise ValueError("published teardown fence differs")
        candidates = [row for row in jobs.list_for_engagement(engagement_id)
                      if row.action == OCI_ABSENCE_ACTION and row.id.startswith(
                          absence_prefix(core_job_id) + "-attempt-")
                      and row.status == "succeeded"]
        if len(candidates) != 1:
            raise ValueError("exact OCI absence receipt missing")
        absent = candidates[0]
        negative = latest_negative_attempt(jobs, engagement_id, core_job_id)
        if negative is None or negative.action != NEGATIVE_ACTION or negative.status != "succeeded":
            raise ValueError("Inspector negative receipt missing")
        identifier = _child_id(core_job_id)
        if historical_negative:
            previous = jobs.get(identifier)
            if previous is None or previous.status != "succeeded":
                raise ValueError("historical negative requires terminal selector")

        def reprove_tail() -> None:
            if oci_absence_recognizer(
                    engagement_id, core_job_id, environment=environment,
                    state_root=state_root, core_state_root=core_state_root,
                    job_repository=jobs, plan_repository=plan_repo, lease_lookup=lookup,
                    identity_reader=identity_reader, published=True,
                    post_source_reader=post_source_reader) != absent:
                raise ValueError("OCI absence receipt changed")
            if not historical_negative and negative_recognizer(
                    engagement_id, core_job_id, environment=environment,
                    state_root=state_root, core_state_root=core_state_root,
                    positive_control=negative.input["positiveControl"],
                    job_repository=jobs, plan_repository=plan_repo, lease_lookup=lookup,
                    identity_reader=identity_reader, published=True,
                    post_source_reader=post_source_reader) != negative:
                raise ValueError("Inspector negative receipt changed")

        reprove_tail()
        base, encrypted = _base(engagement_id, core_job_id, parent, initial,
                                review, plans, absent, negative, credentials, source)
        token = decrypt_secret(encrypted)
        if type(token) is not str or not token:
            raise ValueError("DigitalOcean credential unavailable")
        related = [row for row in jobs.list_for_engagement(engagement_id)
                   if row.action == ACTION and row.input.get("coreJobId") == core_job_id]
        if any(row.id != identifier for row in related):
            raise ValueError("alien published selector child")
        original = jobs.get(apply_child_id(core_job_id, "digitalocean"))
        destroy = jobs.get(destroy_child_id(core_job_id, "digitalocean"))
        current = jobs.get(identifier)
        if original is None or destroy is None:
            raise ValueError("published DigitalOcean history missing")

        def fence() -> None:
            nonlocal current
            if (jobs.get(parent.id) != parent or jobs.get(initial.id) != initial
                    or jobs.get(absent.id) != absent or jobs.get(negative.id) != negative
                    or jobs.get(original.id) != original or jobs.get(destroy.id) != destroy
                    or jobs.get(identifier) != current
                    or lookup(engagement_id) != (plan.id, "provider_keyed_teardown_fence")
                    or post_source_reader(parent, initial, core, plan, jobs, lookup) != source
                    or _credential_snapshot(base["providerConnectionId"], credentials)
                    != (base["credentialSecretSha256"],
                        base["credentialUpdatedAt"], encrypted)):
                raise ValueError("published selector source changed")
            if current is not None and "claimToken" in current.input:
                at = _now()
                renewed = jobs.renew_lease(
                    identifier, owner=current.input["claimOwner"],
                    token=current.input["claimToken"], heartbeat_at=at,
                    expires_at=_later(at))
                if renewed is None or renewed.events != current.events:
                    raise ValueError("published selector claim lost")
                current = renewed

        def guard() -> bool:
            return read_published_selector_guard(
                catalog, deleter, token, base["selectorTag"], fence)

        prefix = "mixed published selector"
        intent = {
            "selectorTag": base["selectorTag"],
            "doAbsenceReceiptSha256": base["doAbsenceReceiptSha256"],
            "ociAbsenceJournalSha256": base["ociAbsenceJournalSha256"],
            "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"],
        }
        queued = JobEvent(1, "info", f"{prefix} retirement queued", {})
        started = JobEvent(2, "info", f"{prefix} retirement started", {})
        intended = JobEvent(3, "info", f"{prefix} DELETE intended", intent)
        if current is not None and current.status == "succeeded":
            if (current.action != ACTION or current.input != base
                    or current.target != f"engagement:{engagement_id}"
                    or current.target_type != "engagement"
                    or current.target_id != engagement_id
                    or current.requested_by != parent.requested_by
                    or current.events[:2] != [queued, started]
                    or current.finished_at is None or current.started_at is None
                    or current.artifact_refs != [] or len(current.events) not in (3, 4)
                    or (len(current.events) == 3 and current.events[2] != JobEvent(
                        3, "info", f"{prefix} already absent",
                        {"selectorTag": base["selectorTag"], "exactGetStatus": 404}))
                    or (len(current.events) == 4 and (
                        current.events[2] != intended or current.events[3] not in [
                            JobEvent(4, "info", f"{prefix} DELETE 204 received",
                                     {"selectorTag": base["selectorTag"], "httpStatus": 204}),
                            JobEvent(4, "info", f"{prefix} absence reconciled",
                                     {"selectorTag": base["selectorTag"],
                                      "exactGetStatus": 404})]))):
                raise ValueError("published selector terminal journal differs")
            if guard() is not False:
                raise ValueError("retired selector is visible")
            fence()
            return current
        if current is None:
            current = jobs.save_if_absent(StoredJobRun(
                identifier, ACTION, "queued", f"engagement:{engagement_id}",
                "engagement", engagement_id, parent.requested_by, base, [], _now(),
                None, None, [queued]))
        if (current is None or current.action != ACTION
                or {key: value for key, value in current.input.items()
                    if not key.startswith("claim")} != base
                or current.target_id != engagement_id or current.target_type != "engagement"
                or current.target != f"engagement:{engagement_id}"
                or current.requested_by != parent.requested_by
                or current.finished_at is not None or current.artifact_refs != []
                or not current.events or current.events[0] != queued):
            raise ValueError("published selector reservation differs")
        if current.status == "queued":
            if len(current.events) != 1 or current.started_at is not None:
                raise ValueError("published selector queued journal differs")
            current = jobs.start_if_queued(current, started_at=_now(), event=started)
        if (current is None or current.status != "running" or current.started_at is None
                or len(current.events) not in (2, 3) or current.events[1] != started
                or (len(current.events) == 3 and current.events[2] != intended)):
            raise ValueError("published selector running journal differs")
        owner, claim_token, at = f"mixed-published-selector-{uuid4().hex}", uuid4().hex, _now()
        current = jobs.claim_lease(identifier, owner=owner, token=claim_token,
                                   claimed_at=at, expires_at=_later(at),
                                   eligible_statuses={"running"})
        if current is None:
            raise ValueError("published selector claim unavailable")
        fence()
        reprove_tail()
        present = guard()
        if len(current.events) == 2 and present:
            reprove_tail()
            fence()
            at = _now()
            saved = jobs.append_mixed_published_selector_retirement_event_if_running_claimed(
                current, owner=owner, token=claim_token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at), event=intended)
            if saved is None:
                raise ValueError("selector DELETE intent was not durable")
            current = saved
            fence()
            response = deleter.delete_tag(token, base["selectorTag"])
            if response != DeleteResponse(204, b""):
                raise ValueError("selector DELETE outcome is uncertain")
            if guard() is not False:
                raise ValueError("selector remains visible after DELETE")
            message = f"{prefix} DELETE 204 received"
            data = {"selectorTag": base["selectorTag"], "httpStatus": 204}
        elif present:
            raise ValueError("saved selector DELETE intent is uncertain")
        elif len(current.events) == 2:
            message = f"{prefix} already absent"
            data = {"selectorTag": base["selectorTag"], "exactGetStatus": 404}
        else:
            message = f"{prefix} absence reconciled"
            data = {"selectorTag": base["selectorTag"], "exactGetStatus": 404}
        fence()
        at = _now()
        finished = jobs.finish_mixed_published_selector_retirement_if_running_claimed(
            current, owner=owner, token=claim_token,
            expected_event_digest=job_event_digest(current.events), finished_at=at,
            event=JobEvent(len(current.events) + 1, "info", message, data))
        if finished is None:
            raise ValueError("published selector terminal journal lost")
        return finished
    except Exception:
        raise PublishedMixedSelectorRetirementAttention(
            "published selector retirement needs exact read-only reconciliation") from None
