# Copyright (c) 2026, Oracle and/or its affiliates.
"""One operator Review, with two provider plans produced by a background worker."""

from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
import stat
import logging
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services import provider_keyed_mixed_append_pair_parent as pair
from app.services.provider_keyed_mixed_append_plan_context import (
    collect_mixed_append_pair_plan_context, derive_mixed_append_review_request,
    MixedAppendAvailabilityContextAttention,
)
from app.services.provider_keyed_mixed_append_pair_plan_producer import (
    produce_mixed_append_pair_plan_review,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun


class MixedAppendReviewAttention(ValueError):
    """The selected Review is unavailable or needs read-only reconciliation."""


_RENEW_INTERVAL = timedelta(seconds=30)
_CLAIM_DURATION = timedelta(minutes=2)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def begin_mixed_append_review(
    engagement_id: str, core_job_id: str, choices: dict, requested_by: str, *,
    job_repository=None,
) -> StoredJobRun:
    """Derive server-owned inputs and atomically reserve the paired Review.

    This entry point never runs Terraform. The caller schedules
    ``run_mixed_append_review`` on its background worker after commit.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    try:
        existing = mixed_append_review_status(
            engagement_id, core_job_id, job_repository=jobs)
        if existing is not None:
            parent, child = existing
            selected = {
                provider: {key: parent.input["reviewRequest"][provider][key]
                           for key in ("selectedChainId", "edgeRegion",
                                       "edgeSize" if provider == "digitalocean" else "edgeType")}
                for provider in ("digitalocean", "linode")}
            if (choices != selected or parent.requested_by != requested_by
                    or _db_lease_lookup(engagement_id) != (
                        parent.input.get("corePlanId"), pair._OPERATION)):
                raise ValueError("mixed append duplicate Review differs")
            if child.status == "failed":
                return retry_precommand_mixed_append_review(parent, child, jobs=jobs)
            return parent
        derived = derive_mixed_append_review_request(
            engagement_id, core_job_id, choices, job_repository=jobs)
        return pair.reserve_mixed_append_pair(
            engagement_id, core_job_id, derived.core_plan_id,
            requested_by=requested_by, reviewed_request=derived.reviewed_request,
            provider_order=derived.provider_order, chain_order=derived.chain_order,
            job_repository=jobs)
    except MixedAppendAvailabilityContextAttention as exc:
        raise MixedAppendReviewAttention(str(exc)) from None
    except Exception:
        raise MixedAppendReviewAttention(
            "mixed append Review needs exact published generation") from None


def mixed_append_review_status(engagement_id: str, core_job_id: str, *,
                               job_repository=None) -> tuple[StoredJobRun, StoredJobRun] | None:
    """Return the reserved parent and plan child; its terminal holds the digest."""
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = jobs.get(pair._parent_id(core_job_id))
    if parent is None:
        return None
    child = jobs.get(pair._plan_child_id(parent.id))
    if (parent.action != pair.ACTION or parent.target_id != engagement_id
            or parent.input.get("coreJobId") != core_job_id
            or child is None or child.action != pair.PLAN_ACTION
            or child.input.get("appendParentId") != parent.id
            or child.input.get("requestSha256") != parent.input.get("requestSha256")):
        raise MixedAppendReviewAttention("mixed append Review status differs")
    return parent, child


def mixed_append_retry_choices(parent, child, *, jobs=None):
    """Offer a failed, never-approved Review; POST proves its bounded artifacts."""
    try:
        if (parent.status != "running" or parent.input.get("phase") != "planning"
                or parent.action != pair.ACTION or child.action != pair.PLAN_ACTION
                or child.status != "failed" or child.input.get("mutation") is not False
                or child.id != pair._plan_child_id(parent.id)
                or child.target_id != parent.target_id or child.target_type != "engagement"
                or child.finished_at is None or child.started_at is None
                or parent.finished_at is not None
                or parent.events != [
                    JobEvent(1, "info", "mixed append pair reserved", {"requestSha256": parent.input["requestSha256"]}),
                    JobEvent(2, "info", "mixed append pair planning started", {})]
                or child.input.get("appendParentId") != parent.id
                or child.input.get("requestSha256") != parent.input["requestSha256"]
                or child.artifact_refs or parent.artifact_refs
                or any(key in parent.input for key in ("claimOwner", "claimToken", "claimExpiresAt",
                    "reviewSummary", "reviewSha256", "intents"))):
            return None
        events = child.events
        if (len(events) < 3 or len(events) % 3 != 0
                or events[0] != JobEvent(1, "info", "mixed append pair plan reserved",
                    {"requestSha256": parent.input["requestSha256"]})):
            return None
        for offset in range(0, len(events), 3):
            if offset and (events[offset].data not in ({}, {"completedPlansOnly": True},
                        {"completedFirstProvider": parent.input["providerOrder"][0]})
                    or "completedPlansOnly" in events[offset].data and type(events[offset].data["completedPlansOnly"]) is not bool
                    or events[offset] != JobEvent(offset + 1, "info",
                        "mixed append pair Review retry requested", events[offset].data)):
                return None
            if events[offset + 1:offset + 3] != [
                    JobEvent(offset + 2, "info", "mixed append pair plan started", {}),
                    JobEvent(offset + 3, "error", "mixed append pair plan needs reconciliation", {})]:
                return None
        if jobs is not None:
            from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first
            from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second
            from app.services.provider_keyed_mixed_append_pair_host_proof import _child_id as host
            if any(jobs.get(identifier(parent.id)) is not None for identifier in (first, second, host)):
                return None
        return {provider: {key: parent.input["reviewRequest"][provider][key]
                    for key in ("selectedChainId", "edgeRegion",
                        "edgeSize" if provider == "digitalocean" else "edgeType")}
                for provider in ("digitalocean", "linode")}
    except (AttributeError, KeyError, TypeError):
        return None


def _completed_retry_files(context, approved, providers=None):
    """Read-only proof of selected completed plans, including missing receipts."""
    from app.services import provider_keyed_mixed_append_pair_plan_producer as producer
    from app.services.provider_keyed_mixed_append_pair_plan_worker import _read, _name, _sha
    credentials = producer.SqlAlchemyCredentialRepository()
    release = producer.require_devtest_terraform_release(environment="devtest")
    if (release.version != "1.15.5" or release.platform != "linux_amd64"
            or _sha(_read(release.path, private=False)) != release.sha256):
        raise MixedAppendReviewAttention("completed append release differs")
    result = {"authority": {release.path: _read(release.path, private=False)}}
    for provider, workspace in context.workspaces.items():
        if providers is not None and provider not in providers:
            continue
        root = workspace.path
        (producer._verify_audited_workspace if provider == "digitalocean"
         else producer.require_audited_linode_workspace)(workspace)
        paths = {suffix: root / _name(provider, suffix) for suffix in (
            "inputs.json", "saved.tfplan", "show.json", "plan-journal.jsonl", "plan-receipt.json", "secret.json")}
        variables = approved["reviewed_inputs"][provider]
        inputs = (json.dumps(variables, sort_keys=True) + "\n").encode()
        if _read(paths["inputs.json"]) != inputs:
            raise MixedAppendReviewAttention("completed append inputs differ")
        journal = producer._Journal(paths["plan-journal.jsonl"], MixedAppendReviewAttention)
        binary = str(release.path)
        commands = {
            "version": [binary, "version", "-json"],
            "init": [binary, "init", "-input=false", "-lockfile=readonly", "-no-color"],
            "plan": [binary, "plan", "-input=false", "-lock=true", "-no-color",
                     f"-out={paths['saved.tfplan']}", f"-var-file={paths['inputs.json']}",
                     f"-var-file={paths['secret.json']}"],
            "show": [binary, "show", "-json", str(paths["saved.tfplan"])],
        }
        rows = producer._exact_journal(journal, commands, complete=True,
                                      process_quiescence=producer._process_quiescent)
        blobs = {paths[suffix]: _read(paths[suffix]) for suffix in (
            "inputs.json", "saved.tfplan", "show.json", "plan-journal.jsonl")}
        shown = blobs[paths["show.json"]]
        if (not blobs[paths["saved.tfplan"]] or not shown
                or rows[-1][-1]["data"]["stdoutBytes"] != len(shown)):
            raise MixedAppendReviewAttention("completed append show differs")
        intent = approved[provider + "_intent"]
        producer._full_gate(provider, shown, workspace=workspace, intent=intent,
            provider_states=context.provider_states,
            digitalocean_firewall=approved["digitalocean_firewall"], reviewed_variables=variables)
        record = credentials.get(workspace.provider_connection_id)
        if (record is None or record.provider != provider or record.status != "active"
                or record.id != workspace.provider_connection_id):
            raise MixedAppendReviewAttention("completed append credential differs")
        receipt = paths["plan-receipt.json"]
        has_receipt = receipt.exists() or receipt.is_symlink()
        if has_receipt:
            blobs[receipt] = _read(receipt)
            if json.loads(blobs[receipt]) != producer._receipt(
                    provider=provider, source=context.source, intent=intent, workspace=workspace,
                    state=context.provider_states[provider], inputs=paths["inputs.json"],
                    plan=paths["saved.tfplan"], shown=paths["show.json"], journal=journal,
                    record=record, release=release):
                raise MixedAppendReviewAttention("completed append receipt differs")
        token = producer.decrypt_secret_value(record.encrypted_secret)
        if not isinstance(token, str) or not token:
            raise MixedAppendReviewAttention("completed append credential unavailable")
        public, private = producer._admin_material_paths(workspace, variables)
        for path, expected in {
                paths["secret.json"]: producer._secret_bytes(provider, token),
                public: context.admin_public_key.encode(), private: context.admin_private_key.encode()}.items():
            if not has_receipt or path.exists() or path.is_symlink():
                if _read(path) != expected:
                    raise MixedAppendReviewAttention("completed append material differs")
                (blobs if path.parent == root else result["authority"])[path] = expected
        for suffix in (".barragan-provider-keyed-state.json", ".terraform.lock.hcl"):
            result["authority"][root / suffix] = _read(root / suffix, private=False)
        # Compare credential identity during the writer recheck without provider requests.
        result["authority"]["credential:" + provider] = repr(record)
        result[provider] = blobs
    return result


def retry_precommand_mixed_append_review(parent, child, *, jobs):
    """Retry exact pre-command staging or reconcile both completed saved plans."""
    if mixed_append_retry_choices(parent, child, jobs=jobs) is None:
        raise MixedAppendReviewAttention("mixed append plan needs reconciliation")
    from app.services.provider_keyed_mixed_append_pair_plan_worker import _name, _read
    from app.services.provider_keyed_sketch import read_provider_topology
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
    plans, chains = SqlAlchemyDeploymentPlanRepository(), SqlAlchemySketchChainRepository()
    saved_jobs = jobs.list_for_engagement(parent.target_id)
    saved_plan = plans.get(parent.input["corePlanId"])
    saved_chains = chains.list_for_engagement(parent.target_id)
    context = collect_mixed_append_pair_plan_context(parent.id, job_repository=jobs)
    with ExitStack() as locks:
        staged = any(list(workspace.path.glob(".barragan-mixed-append-*"))
                     for workspace in context.workspaces.values())
        expected_topologies = context.original_topologies
        expected_ledger = context.original_regional_high_water
        expected_inputs = {}
        lock_files = {}
        completed_providers = {provider for provider, workspace in context.workspaces.items()
            if (workspace.path / _name(provider, "plan-journal.jsonl")).exists()
            or (workspace.path / _name(provider, "plan-journal.jsonl")).is_symlink()}
        first_provider = parent.input["providerOrder"][0]
        completed = bool(completed_providers)
        first_only = completed_providers == {first_provider}
        if (completed and completed_providers not in ({first_provider}, set(context.workspaces))
                or any(event.data == {"completedPlansOnly": True} for event in child.events)
                   and completed_providers != set(context.workspaces)
                or any(event.data == {"completedFirstProvider": first_provider} for event in child.events)
                   and first_provider not in completed_providers):
            raise MixedAppendReviewAttention("completed append plans are missing")
        if staged:
            from app.services.provider_keyed_mixed_append_reservation import propose_mixed_external_append_reservations
            # Open existing files only. Never create or wait for an active plan lock.
            for provider, workspace in sorted(context.workspaces.items()):
                path = workspace.path / _name(provider, "plan.lock")
                try:
                    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
                except OSError:
                    raise MixedAppendReviewAttention("append plan lock is unavailable") from None
                stream = locks.enter_context(os.fdopen(descriptor, "r+b"))
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size:
                    raise MixedAppendReviewAttention("append plan lock differs")
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise MixedAppendReviewAttention("append plan lock is active") from None
                lock_files[str(path)] = (info.st_dev, info.st_ino)
            approved = context.approval_kwargs()
            proposal = propose_mixed_external_append_reservations(
                source=context.source, binding_manifest=context.binding_manifest,
                digitalocean_intent=approved["digitalocean_intent"],
                linode_intent=approved["linode_intent"],
                current_topologies=context.original_topologies,
                regional_high_water=context.original_regional_high_water,
                reviewed_provider_order=context.reviewed_provider_order)
            expected_topologies = {row.provider: row.proposed_topology for row in proposal.reservations}
            expected_ledger = proposal.proposed_high_water
            expected_inputs = approved["reviewed_inputs"]

        def local_files():
            rows = {}
            completed_files = (_completed_retry_files(context, approved, (first_provider,)) if first_only
                else _completed_retry_files(context, approved) if completed else {})
            for provider, workspace in context.workspaces.items():
                artifacts = list(workspace.path.glob(".barragan-mixed-append-*"))
                allowed = {}
                if staged:
                    predecessor = workspace.path / _name(provider, "predecessor.tfstate")
                    lock = workspace.path / _name(provider, "plan.lock")
                    allowed = {predecessor: context.provider_states[provider], lock: b""}
                    path = workspace.path / _name(provider, "inputs.json")
                    if completed:
                        allowed.update(completed_files.get(provider, {}))
                    elif path.exists() or path.is_symlink():
                        if provider != context.reviewed_provider_order[0]:
                            raise MixedAppendReviewAttention("unexpected second-provider staging")
                        current = expected_inputs[provider]
                        old = {key: value for key, value in current.items()
                               if key not in {"ssh_pub_key_path", "ssh_priv_key_path", "ssh_config_path"}}
                        blob = _read(path)
                        if blob not in tuple((json.dumps(value, sort_keys=True) + "\n").encode()
                                             for value in (current, old)):
                            raise MixedAppendReviewAttention("staged append inputs differ")
                        allowed[path] = blob
                if set(artifacts) != set(allowed):
                    raise MixedAppendReviewAttention("append staging contains unreviewed files")
                for path, content in allowed.items():
                    info = path.lstat()
                    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                            or _read(path) != content
                            or (str(path) in lock_files and (info.st_dev, info.st_ino) != lock_files[str(path)])):
                        raise MixedAppendReviewAttention("append staging changed")
                    rows[str(path)] = content
                if (read_provider_topology(workspace) != expected_topologies[provider]
                        or _read(workspace.state_path, private=False) != context.provider_states[provider]):
                    raise MixedAppendReviewAttention("append source changed")
                for path in (workspace.state_path, workspace.path / ".barragan-topology.json",
                             workspace.path.parents[1] / "regional-ordinals.json"):
                    rows[str(path)] = _read(path, private=False)
            if any(json.loads(raw) != expected_ledger for path, raw in rows.items()
                   if path.endswith("/regional-ordinals.json")):
                raise MixedAppendReviewAttention("append ordinal ledger changed")
            if completed:
                for path, blob in completed_files["authority"].items():
                    rows[str(path)] = blob
            return rows
        before = local_files()
        # No provider requests or file changes inside the SQLite writer fence.
        def recheck():
            if (local_files() != before or jobs.list_for_engagement(parent.target_id) != saved_jobs
                    or plans.get(parent.input["corePlanId"]) != saved_plan
                    or chains.list_for_engagement(parent.target_id) != saved_chains):
                raise MixedAppendReviewAttention("append retry source changed")
        jobs.retry_precommand_mixed_append_review(parent, child, recheck=recheck, requested_at=_now(),
            completed_plans_only=completed and not first_only,
            completed_first_provider=first_provider if first_only else None)
        return jobs.get(parent.id)


def run_mixed_append_review(parent_id: str, *, job_repository=None,
                            lease_lookup=None) -> StoredJobRun:
    """Produce both saved plans, then publish a single durable Review digest.

    A running worker holds a fenced parent claim. An expired claim can resume
    only through the producer's exact command journal and saved receipts;
    uncertain Terraform commands are never replayed by this function.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    if (parent is None or parent.action != pair.ACTION
            or parent.input.get("phase") != "planning"
            or lookup(parent.target_id) != (
                parent.input.get("corePlanId"), pair._OPERATION)):
        raise MixedAppendReviewAttention("mixed append planning parent differs")
    child = jobs.get(pair._plan_child_id(parent.id))
    if (child is None or child.action != pair.PLAN_ACTION
            or child.input.get("appendParentId") != parent.id
            or child.input.get("requestSha256") != parent.input.get("requestSha256")):
        raise MixedAppendReviewAttention("mixed append planning child differs")
    if child.status == "succeeded":
        if (child.events[-1].message != "mixed append pair plan reviewed"
                or set(child.events[-1].data) != {"reviewSha256"}):
            raise MixedAppendReviewAttention("mixed append Review terminal differs")
        return child
    if child.status == "failed":
        raise MixedAppendReviewAttention("mixed append plan needs reconciliation")
    if parent.status == "queued":
        parent = jobs.start_if_queued(parent, started_at=_now(), event=JobEvent(
            len(parent.events) + 1, "info", "mixed append pair planning started", {}))
    if parent is None or parent.status != "running":
        raise MixedAppendReviewAttention("mixed append planning claim differs")
    at = _now()
    owner, token = f"mixed-append-plan-{uuid4().hex}", uuid4().hex
    parent = jobs.claim_lease(
        parent.id, owner=owner, token=token, claimed_at=at,
        expires_at=(datetime.fromisoformat(at) + _CLAIM_DURATION).isoformat(),
        eligible_statuses={"running"}, eligible_phases={"planning"})
    if parent is None:
        raise MixedAppendReviewAttention("mixed append planning worker is active")
    if child.status == "queued":
        child = jobs.start_if_queued(child, started_at=_now(), event=JobEvent(
            len(child.events) + 1, "info", "mixed append pair plan started", {}))
    if child is None or child.status != "running":
        raise MixedAppendReviewAttention("mixed append planning child claim differs")
    last_renewal = datetime.fromisoformat(at)

    def renew(*, force: bool = False) -> None:
        nonlocal parent, last_renewal
        now = datetime.now(timezone.utc)
        if force or now - last_renewal >= _RENEW_INTERVAL:
            parent = jobs.renew_mixed_append_review_claim(
                parent, heartbeat_at=now.isoformat(),
                expires_at=(now + _CLAIM_DURATION).isoformat())
            last_renewal = now

    def claimed_lookup(engagement_id: str):
        if engagement_id == parent.target_id:
            renew()
        return lookup(engagement_id)

    try:
        context = collect_mixed_append_pair_plan_context(
            parent.id, job_repository=jobs, lease_lookup=claimed_lookup)
        options = context.producer_kwargs()
        retries = [event for event in child.events
                   if event.message == "mixed append pair Review retry requested"]
        if retries and retries[-1].data == {"completedPlansOnly": True}:
            options["completed_plans_only"] = True
        elif retries and retries[-1].data == {"completedFirstProvider": parent.input["providerOrder"][0]}:
            options["completed_first_provider"] = parent.input["providerOrder"][0]
        seal = produce_mixed_append_pair_plan_review(
            **options, lease_lookup=claimed_lookup)
        source = pair._collect_published(
            parent.target_id, parent.input["coreJobId"], jobs, claimed_lookup)
        if (source.source != context.source
                or seal.engagement_id != parent.target_id
                or seal.core_job_id != parent.input["coreJobId"]
                or seal.provider_order != tuple(parent.input["providerOrder"])
                or seal.chain_order != tuple(parent.input["chainOrder"])):
            raise ValueError("mixed append reviewed source changed")
        summary = pair.mixed_append_review_summary(parent, seal)
        review_sha = pair.mixed_append_approval_sha256(seal.review_sha256, source)
        renew(force=True)
        event = JobEvent(len(child.events) + 1, "info",
                         "mixed append pair plan reviewed",
                         {"reviewSha256": review_sha})
        return jobs.finish_mixed_append_review(
            parent, child, status="succeeded", event=event, finished_at=_now(),
            review_summary=summary)
    except Exception:
        # A failed or uncertain command remains in its exact journal. The
        # child is terminal and visible to the operator; no automatic replay.
        logging.getLogger(__name__).exception("Mixed append Review worker stopped")
        try:
            jobs.finish_mixed_append_review(
                parent, child, status="failed", event=JobEvent(
                    len(child.events) + 1, "error",
                    "mixed append pair plan needs reconciliation", {}),
                finished_at=_now())
        except Exception:
            pass
        raise MixedAppendReviewAttention(
            "mixed append pair plan needs read-only reconciliation") from None


def recover_mixed_append_reviews(*, environment: str,
                                 schedule: Callable[[Callable[[], None]], None],
                                 job_repository=None, limit: int = 100) -> list[str]:
    """Schedule only unfinished paired Reviews with no live worker claim.

    The worker validates the exact saved Terraform command journal before it
    resumes any plan. Failed and succeeded children are never scheduled here.
    """
    if environment != "devtest":
        return []
    jobs = job_repository or SqlAlchemyJobRepository()
    now = datetime.now(timezone.utc)
    scheduled = []
    for parent in jobs.list_by_actions_and_statuses(
            actions={pair.ACTION}, statuses={"queued", "running"}, limit=limit):
        child = jobs.get(pair._plan_child_id(parent.id))
        if (parent.input.get("schema") != "mixed-append-pair-parent-v1"
                or parent.input.get("phase") != "planning"
                or child is None or child.action != pair.PLAN_ACTION
                or child.status not in {"queued", "running"}
                or child.input.get("appendParentId") != parent.id
                or child.input.get("requestSha256") != parent.input.get("requestSha256")
                or _db_lease_lookup(parent.target_id) != (
                    parent.input.get("corePlanId"), pair._OPERATION)):
            continue
        expires = parent.input.get("claimExpiresAt")
        if expires is not None:
            try:
                if datetime.fromisoformat(expires) > now:
                    continue
            except (TypeError, ValueError):
                continue
        schedule(lambda parent_id=parent.id: run_mixed_append_review(parent_id))
        scheduled.append(parent.id)
    return scheduled
