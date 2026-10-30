# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot retirement of the sealed empty DigitalOcean selector.

The Inspector public-negative and exact OCI absence are prerequisites. A
persisted DELETE intent is never replayed; a restart only proves absence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.credentials import decrypt_secret_value
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_id
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    _parent_id as cleanup_id, recognize_mixed_interrupted_sealed_plans,
)
from app.services.provider_keyed_mixed_interrupted_destroy_plan import _scope_sha
from app.services.provider_keyed_mixed_interrupted_dispatch import (
    _default_quiescent, _saved_plans, _saved_review, _workspace,
)
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import (
    _poststate, prove_mixed_interrupted_provider_absence,
)
from app.services.provider_keyed_mixed_interrupted_source import _empty_inventory
from app.services.provider_keyed_mixed_initial_apply_child import _child_id as apply_child_id
from app.services.provider_keyed_mixed_interrupted_destroy_child import _child_id as destroy_child_id
from app.services.provider_keyed_mixed_partial_apply_inventory import collect_provider_inventory_snapshot
from app.services.provider_keyed_mixed_zero_apply_core_absence import (
    ACTION as OCI_ABSENCE_ACTION, _child_prefix as absence_prefix,
    prove_mixed_zero_apply_oci_core_absence,
)
from app.services.provider_keyed_mixed_zero_apply_inspector_negative import (
    ACTION as NEGATIVE_ACTION, _child_id as negative_id, latest_negative_attempt,
    prove_mixed_zero_apply_inspector_negative,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
from app.services.provider_keyed_selector_retirement import (
    DeleteResponse, UrllibDeleteTransport, _read_empty_membership,
)
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_interrupted_selector_retirement"


class MixedInterruptedSelectorRetirementAttention(ValueError):
    """The exact selector outcome needs read-only reconciliation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=60)).isoformat()


def _child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-interrupted-selector-retirement-{core_job_id.removeprefix('job-')}"


def retire_mixed_interrupted_selector(
    engagement_id: str, core_job_id: str, *, environment: str, state_root: Path,
    core_state_root: Path, job_repository=None, plan_repository=None,
    credential_repository=None, lease_lookup=None, catalog_transport=None,
    delete_transport=None, decrypt_secret: Callable = decrypt_secret_value,
    inventory_collector: Callable = collect_provider_inventory_snapshot,
    process_quiescent: Callable = _default_quiescent,
    oci_absence_recognizer: Callable = prove_mixed_zero_apply_oci_core_absence,
    negative_recognizer: Callable = prove_mixed_zero_apply_inspector_negative,
    identity_reader=None,
    historical_negative: bool = False,
) -> StoredJobRun:
    """Delete a uniquely reserved selector after exact mixed teardown proof."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans_repo = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        if (type(historical_negative) is not bool or environment != "devtest"
                or state_root != _default_state_root()
                or not state_root.is_absolute() or state_root.is_symlink()
                or state_root.resolve(strict=True) != state_root):
            raise ValueError("private DevTest selector root differs")
        initial, parent = jobs.get(initial_id(core_job_id)), jobs.get(cleanup_id(core_job_id))
        if initial is None or parent is None or parent.target_id != engagement_id:
            raise ValueError("sealed mixed cleanup is absent")
        review, plan_set = _saved_review(parent), _saved_plans(parent)
        recognize_mixed_interrupted_sealed_plans(parent, initial, review, plan_set)
        scope = next(row for row in review.scopes if row.provider == "digitalocean")
        selector = scope.selector_tag
        if (scope.selector_retirement_pending is not True
                or selector != "s" + hashlib.sha256(engagement_id.encode()).hexdigest()[:20]
                or lookup(engagement_id) != (parent.input["corePlanId"],
                                             "provider_keyed_teardown_fence")):
            raise ValueError("owned selector or teardown fence differs")
        candidates = [row for row in jobs.list_for_engagement(engagement_id)
                      if row.action == OCI_ABSENCE_ACTION and row.id.startswith(
                          absence_prefix(core_job_id) + "-attempt-") and row.status == "succeeded"]
        if len(candidates) != 1:
            raise ValueError("exact OCI absence receipt missing")
        absent = candidates[0]
        negative = latest_negative_attempt(jobs, engagement_id, core_job_id)
        if (negative is None or negative.action != NEGATIVE_ACTION
                or negative.status != "succeeded"):
            raise ValueError("Inspector public-negative receipt missing")
        recognized_absent = oci_absence_recognizer(
            engagement_id, core_job_id, environment=environment, state_root=state_root,
            core_state_root=core_state_root, job_repository=jobs,
            plan_repository=plans_repo, lease_lookup=lookup,
            identity_reader=identity_reader, interrupted=True)
        if recognized_absent != absent:
            raise ValueError("OCI absence receipt changed")
        if historical_negative:
            saved_terminal = jobs.get(_child_id(core_job_id))
            if saved_terminal is None or saved_terminal.status != "succeeded":
                raise ValueError("historical negative requires terminal selector")
        else:
            recognized_negative = negative_recognizer(
                engagement_id, core_job_id, environment=environment, state_root=state_root,
                core_state_root=core_state_root,
                positive_control=negative.input["positiveControl"],
                job_repository=jobs, plan_repository=plans_repo, lease_lookup=lookup,
                identity_reader=identity_reader, interrupted=True)
            if recognized_negative != negative:
                raise ValueError("Inspector public-negative receipt changed")
        policy = initial.events[5].data["reviewedPolicy"]["digitalocean"]
        connection = policy["provider_connection_id"]
        secret_sha, updated_at, encrypted = _credential_snapshot(connection, credentials)
        if ((secret_sha, updated_at) != (policy["credential_secret_sha256"],
                                        policy["credential_updated_at"])):
            raise ValueError("sealed DigitalOcean credential changed")
        token = decrypt_secret(encrypted)
        if type(token) is not str or not token:
            raise ValueError("DigitalOcean credential unavailable")
        original = jobs.get(apply_child_id(core_job_id, "digitalocean"))
        destroy = jobs.get(destroy_child_id(core_job_id, "digitalocean"))
        workspace = _workspace(initial, "digitalocean", state_root)
        base = {
            "schema": "mixed-interrupted-selector-retirement-v1",
            "engagementId": engagement_id, "coreJobId": core_job_id,
            "corePlanId": parent.input["corePlanId"], "teardownParentId": parent.id,
            "reviewSha256": review.review_sha256,
            "planSetSha256": plan_set.plan_set_sha256,
            "doScopeSha256": _scope_sha(scope), "selectorTag": selector,
            "providerConnectionId": connection,
            "credentialSecretSha256": secret_sha, "credentialUpdatedAt": updated_at,
            "ociAbsenceJobId": absent.id,
            "ociAbsenceJournalSha256": job_event_digest(absent.events),
            "inspectorNegativeJobId": negative.id,
            "inspectorNegativeJournalSha256": job_event_digest(negative.events),
            "mutation": True,
        }
        identifier = _child_id(core_job_id)
        related = [row for row in jobs.list_for_engagement(engagement_id)
                   if row.action == ACTION and row.input.get("coreJobId") == core_job_id]
        if any(row.id != identifier for row in related):
            raise ValueError("alien selector retirement child")
        catalog = catalog_transport or UrllibProviderCatalogTransport()
        deleter = delete_transport or UrllibDeleteTransport()
        generation = f"{parent.id}:{plan_set.plan_set_sha256}"
        current = jobs.get(identifier)

        def all_quiescent() -> bool:
            for child in (original, destroy):
                if child is None:
                    continue
                for event in child.events:
                    if event.message in {"mixed provider Apply command started before GO",
                                         "mixed provider destroy command started before GO"}:
                        data = event.data
                        if (type(data) is not dict
                                or not {"bootId", "pid", "pgid", "startTicks"} <= set(data)
                                or process_quiescent({key: data[key] for key in (
                                    "bootId", "pid", "pgid", "startTicks")}) is not True):
                            return False
            return True

        def fence() -> str:
            nonlocal current
            if (jobs.get(initial.id) != initial or jobs.get(parent.id) != parent
                    or jobs.get(absent.id) != absent or jobs.get(negative.id) != negative
                    or jobs.get(identifier) != current
                    or jobs.get(apply_child_id(core_job_id, "digitalocean")) != original
                    or jobs.get(destroy_child_id(core_job_id, "digitalocean")) != destroy
                    or lookup(engagement_id) != (base["corePlanId"], "provider_keyed_teardown_fence")
                    or _credential_snapshot(connection, credentials)
                    != (secret_sha, updated_at, encrypted)):
                raise ValueError("selector retirement source changed")
            if current is not None and "claimToken" in current.input:
                at = _now()
                renewed = jobs.renew_lease(identifier, owner=current.input["claimOwner"],
                                           token=current.input["claimToken"],
                                           heartbeat_at=at, expires_at=_later(at))
                if renewed is None or renewed.events != current.events:
                    raise ValueError("selector retirement claim lost")
                current = renewed
            return generation

        def fresh_owned_absence(*, retired: bool = False) -> None:
            snapshot = inventory_collector(
                initial, "digitalocean", workspace, fence=fence,
                process_quiescent=all_quiescent,
                credential_repository=credentials,
                phase_mode=("destroy_applied" if scope.kind in {"partial", "full"}
                            else "apply"))
            if retired:
                _empty_inventory(initial, "digitalocean", snapshot)
                if (snapshot.selector_tag_exists is not False
                        or snapshot.selector_resources_count != 0
                        or snapshot.selector_attached_node_ids != ()
                        or any(str(row["id"]) in {value for _, value in scope.resource_ids}
                               for row in snapshot.inventory)):
                    raise ValueError("retired selector or owned resource is visible")
                if scope.kind in {"partial", "full"}:
                    if (snapshot.state_json is None or snapshot.phase != "destroy_applied"
                            or hashlib.sha256(snapshot.state_json).hexdigest()
                            != snapshot.state_sha256):
                        raise ValueError("retained destroyed state differs")
                    _poststate(snapshot.state_json, lineage=scope.lineage,
                               before_serial=scope.serial)
                elif (snapshot.state_json is not None or snapshot.phase != (
                        "apply_started" if scope.kind == "failed_absent" else None)):
                    raise ValueError("no-state selector source differs")
                return
            receipt = prove_mixed_interrupted_provider_absence(
                initial, parent, review, plan_set, "digitalocean", original, destroy,
                snapshot, fence=fence, process_quiescent=process_quiescent)
            if (receipt.selector_retirement_pending is not True
                    or receipt.scope_sha256 != base["doScopeSha256"]):
                raise ValueError("DigitalOcean owned absence changed")

        if current is not None and current.status == "succeeded":
            if (current.action != ACTION or current.input != base
                    or current.target != f"engagement:{engagement_id}"
                    or current.target_type != "engagement"
                    or current.target_id != engagement_id
                    or current.requested_by != parent.requested_by
                    or current.started_at is None or current.finished_at is None
                    or current.artifact_refs != [] or len(current.events) != 4
                    or current.events[:2] != [
                        JobEvent(1, "info", "mixed interrupted selector retirement queued", {}),
                        JobEvent(2, "info", "mixed interrupted selector retirement started", {})]
                    or current.events[2] != JobEvent(3, "info",
                        "mixed interrupted selector DELETE intended", {
                            "selectorTag": selector,
                            "doScopeSha256": base["doScopeSha256"],
                            "ociAbsenceJournalSha256": base["ociAbsenceJournalSha256"],
                            "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"]})
                    or current.events[3] not in [
                        JobEvent(4, "info", "mixed interrupted selector DELETE 204 received",
                                 {"selectorTag": selector, "httpStatus": 204}),
                        JobEvent(4, "info", "mixed interrupted selector absence reconciled",
                                 {"selectorTag": selector, "exactGetStatus": 404,
                                  "completeTagListAbsent": True})]):
                raise ValueError("terminal selector journal differs")
            fresh_owned_absence(retired=True)
            _read_empty_membership(catalog, token, selector, fence, tag_present=False)
            if deleter.get_tag_status(token, selector) != 404:
                raise ValueError("retired selector is visible")
            fence()
            return current
        if current is None:
            current = jobs.save_if_absent(StoredJobRun(
                identifier, ACTION, "queued", f"engagement:{engagement_id}",
                "engagement", engagement_id, parent.requested_by, base, [], _now(),
                None, None, [JobEvent(1, "info", "mixed interrupted selector retirement queued", {})]))
        if (current is None or current.action != ACTION
                or {key: value for key, value in current.input.items()
                    if not key.startswith("claim")} != base
                or current.target_id != engagement_id or current.finished_at is not None
                or current.artifact_refs != [] or current.events[0] != JobEvent(
                    1, "info", "mixed interrupted selector retirement queued", {})):
            raise ValueError("selector retirement reservation differs")
        if current.status == "queued":
            if len(current.events) != 1 or current.started_at is not None:
                raise ValueError("queued selector journal differs")
            current = jobs.start_if_queued(current, started_at=_now(), event=JobEvent(
                2, "info", "mixed interrupted selector retirement started", {}))
        if (current is None or current.status != "running" or current.started_at is None
                or len(current.events) not in (2, 3)
                or current.events[1] != JobEvent(
                    2, "info", "mixed interrupted selector retirement started", {})):
            raise ValueError("running selector journal differs")
        intent = {"selectorTag": selector, "doScopeSha256": base["doScopeSha256"],
                  "ociAbsenceJournalSha256": base["ociAbsenceJournalSha256"],
                  "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"]}
        if len(current.events) == 3 and current.events[2] != JobEvent(
                3, "info", "mixed interrupted selector DELETE intended", intent):
            raise ValueError("saved selector intent differs")
        owner, claim_token, at = f"mixed-interrupted-selector-{uuid4().hex}", uuid4().hex, _now()
        current = jobs.claim_lease(identifier, owner=owner, token=claim_token,
                                   claimed_at=at, expires_at=_later(at),
                                   eligible_statuses={"running"})
        if current is None:
            raise ValueError("selector retirement claim unavailable")
        fence()
        fresh_owned_absence(retired=len(current.events) == 3)
        if len(current.events) == 2:
            _read_empty_membership(catalog, token, selector, fence, tag_present=True)
            fence()
            at = _now()
            intended = jobs.append_mixed_interrupted_selector_retirement_event_if_running_claimed(
                current, owner=owner, token=claim_token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(3, "info", "mixed interrupted selector DELETE intended", intent))
            if intended is None:
                raise ValueError("selector DELETE intent not durable")
            current = intended
            fence()
            response = deleter.delete_tag(token, selector)
            if type(response) is not DeleteResponse or response != DeleteResponse(204, b""):
                raise ValueError("selector DELETE response differs")
            fresh_owned_absence(retired=True)
            _read_empty_membership(catalog, token, selector, fence, tag_present=False)
            if deleter.get_tag_status(token, selector) != 404:
                raise ValueError("selector exact GET is not absent")
            message = "mixed interrupted selector DELETE 204 received"
            terminal = {"selectorTag": selector, "httpStatus": 204}
        else:
            fresh_owned_absence(retired=True)
            _read_empty_membership(catalog, token, selector, fence, tag_present=False)
            fence()
            if deleter.get_tag_status(token, selector) != 404:
                raise ValueError("selector exact GET is not absent")
            message = "mixed interrupted selector absence reconciled"
            terminal = {"selectorTag": selector, "exactGetStatus": 404,
                        "completeTagListAbsent": True}
        at = _now()
        finished = jobs.finish_mixed_interrupted_selector_retirement_if_running_claimed(
            current, owner=owner, token=claim_token,
            expected_event_digest=job_event_digest(current.events), finished_at=at,
            event=JobEvent(4, "info", message, terminal))
        if finished is None:
            raise ValueError("selector terminal journal lost")
        return finished
    except Exception:
        raise MixedInterruptedSelectorRetirementAttention(
            "mixed selector retirement needs exact read-only reconciliation") from None
