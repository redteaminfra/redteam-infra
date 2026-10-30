# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact no-Apply append reservation projected into the existing teardown.

The initial four-host publication stays authoritative. Saved append plans are
history, not provider mutations; this module never checks purchase availability.
"""
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path

from app.domain import JobEvent
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_append_pair_parent import (
    ACTION, PLAN_ACTION, _parent_id, _plan_child_id, mixed_append_approval_sha256,
    mixed_append_review_summary,
)
from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_id, _precommand, _CLAIM_KEYS
from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_id
from app.services.provider_keyed_mixed_append_pair_host_proof import _child_id as host_id
from app.services.provider_keyed_mixed_append_pair_plan_worker import _canonical, _name, _read, _journal_complete
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as initial_child_id, recognize_mixed_initial_apply_terminal,
)


KIND = "unapplied-append-v1"
_BASE = ("schema", "engagementId", "coreJobId", "corePlanId", "providerOrder",
         "chainOrder", "reviewRequest", "requestSha256", "mutation")


def _expired(row):
    claim = tuple(row.input.get(key) for key in ("claimOwner", "claimToken", "claimExpiresAt"))
    if all(value is None for value in claim):
        return
    if any(type(value) is not str or not value for value in claim):
        raise ValueError("append worker claim is incomplete")
    if datetime.fromisoformat(claim[2]) > datetime.now(timezone.utc):
        raise ValueError("append worker still owns a live claim")


def no_apply_rows(parent, jobs):
    """Cheap journal predicate; full plan/state proof is a separate boundary."""
    if (parent is None or parent.action != ACTION or parent.status != "running"
            or parent.finished_at is not None or parent.started_at is None
            or parent.target_type != "engagement" or parent.target != f"engagement:{parent.target_id}"
            or parent.id != _parent_id(parent.input["coreJobId"])
            or parent.input.get("engagementId") != parent.target_id
            or parent.input.get("schema") != "mixed-append-pair-parent-v1"
            or parent.input.get("phase") not in {"planning", "apply_sealed"}
            or parent.artifact_refs):
        raise ValueError("append no-Apply reservation differs")
    if any(type(parent.input.get(key)) is not str or re.fullmatch(r"[0-9a-f]{64}", parent.input[key]) is None
           for key in ("requestSha256",)):
        raise ValueError("append no-Apply request fingerprint differs")
    _expired(parent)
    plan = jobs.get(_plan_child_id(parent.id))
    if (plan is None or plan.action != PLAN_ACTION or plan.status != "succeeded"
            or plan.target != parent.target or plan.target_id != parent.target_id
            or plan.target_type != parent.target_type or plan.requested_by != parent.requested_by
            or plan.started_at is None or plan.finished_at is None or plan.artifact_refs
            or plan.input.get("appendParentId") != parent.id
            or {key: value for key, value in plan.input.items() if key not in _CLAIM_KEYS} != {
                "schema": "mixed-append-pair-plan-v1", "appendParentId": parent.id,
                "engagementId": parent.target_id, "coreJobId": parent.input["coreJobId"],
                "corePlanId": parent.input["corePlanId"], "requestSha256": parent.input["requestSha256"],
                "mutation": False}
            or len(plan.events) < 3 or len(plan.events) % 3 != 0
            or plan.events[0] != JobEvent(1, "info", "mixed append pair plan reserved",
                {"requestSha256": parent.input["requestSha256"]})
            or plan.events[1] != JobEvent(2, "info", "mixed append pair plan started", {})
            or plan.events[-1].sequence != len(plan.events) or plan.events[-1].level != "info"
            or plan.events[-1].message != "mixed append pair plan reviewed"
            or set(plan.events[-1].data) != {"reviewSha256"}):
        raise ValueError("append no-Apply plan review differs")
    if type(plan.events[-1].data["reviewSha256"]) is not str or re.fullmatch(
            r"[0-9a-f]{64}", plan.events[-1].data["reviewSha256"]) is None:
        raise ValueError("append no-Apply review fingerprint differs")
    # Reuse the existing exact retry grammar with a read-only failed-terminal
    # view; the real successful journal remains unchanged and hash-bound.
    from app.services.provider_keyed_mixed_append_review_runtime import mixed_append_retry_choices
    planning = replace(parent, input={**{key: parent.input[key] for key in _BASE}, "phase": "planning"},
                       events=parent.events[:2])
    failed_view = replace(plan, status="failed", events=[*plan.events[:-1],
        JobEvent(len(plan.events), "error", "mixed append pair plan needs reconciliation", {})])
    if mixed_append_retry_choices(planning, failed_view) is None:
        raise ValueError("append no-Apply plan retry grammar differs")
    _expired(plan)
    expected = [JobEvent(1, "info", "mixed append pair reserved",
                         {"requestSha256": parent.input["requestSha256"]}),
                JobEvent(2, "info", "mixed append pair planning started", {})]
    if parent.input["phase"] == "apply_sealed":
        expected.append(JobEvent(3, "info", "mixed append pair approved", {
            "reviewSha256": parent.input["reviewSha256"], "planChildId": plan.id}))
        if parent.input["reviewSha256"] != plan.events[-1].data["reviewSha256"]:
            raise ValueError("append no-Apply approval differs")
    if parent.events != expected:
        raise ValueError("append no-Apply parent journal differs")
    first = jobs.get(first_id(parent.id))
    if first is not None:
        if parent.input["phase"] != "apply_sealed" or not _precommand(first, parent):
            raise ValueError("append first command intent exists or is uncertain")
        _expired(first)
    if jobs.get(second_id(parent.id)) is not None or jobs.get(host_id(parent.id)) is not None:
        raise ValueError("append continuation exists")
    return plan, first


def no_apply_present(parent, jobs):
    try:
        no_apply_rows(parent, jobs)
        return True
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def _rows_digest(parent, jobs):
    plan, first = no_apply_rows(parent, jobs)
    return _canonical({"parent": asdict(parent), "plan": asdict(plan),
                       "first": asdict(first) if first is not None else None})


def _artifacts(workspaces):
    result = {}
    for provider, workspace in workspaces.items():
        root = workspace.path
        paths = [root / _name(provider, suffix) for suffix in (
            "predecessor.tfstate", "saved.tfplan", "show.json", "inputs.json",
            "plan-receipt.json", "plan-journal.jsonl")]
        paths += [root / name for name in (".barragan-provider-keyed-state.json",
                   ".barragan-topology.json", ".terraform.lock.hcl")]
        result[provider] = {str(path): hashlib.sha256(_read(path, private=False)).hexdigest()
                            for path in paths}
        receipt = json.loads(_read(root / _name(provider, "plan-receipt.json")))
        journal_path = root / _name(provider, "plan-journal.jsonl")
        _journal_complete(journal_path, receipt["journalSha256"])
        from app.services.provider_keyed_mixed_plan_journal import _Journal
        rows = _Journal(journal_path, ValueError)._commands()
        for command in rows:
            started = command[1]["data"]
            if _process_quiescent(started["bootId"], started["pid"],
                                  started["pgid"], started["startTicks"]) is not True:
                raise ValueError("append plan command quiescence is unproved")
    return result


def build_no_apply_recovery(review, initial, append, *, jobs, workspaces,
                            plans=None, sketches=None, lease_lookup=None,
                            credentials=None, release_check=None):
    """Reopen both plans once before destroy; preserve exact immutable proof."""
    from app.services.provider_keyed_mixed_append_plan_context import collect_mixed_append_pair_plan_context
    from app.services.provider_keyed_mixed_append_pair_plan_worker import reopen_mixed_append_pair_plan_review
    plan_child, _ = no_apply_rows(append, jobs)
    # A sealed parent retains the same planning inputs. This read-only view
    # opens the existing plan reader; it cannot reserve or approve a command.
    planning = replace(append, input={**{key: append.input[key] for key in _BASE},
                       "phase": "planning", "reviewSummary": append.input["reviewSummary"]},
                       events=append.events[:2])
    class PlanningReader:
        def get(self, identifier):
            return planning if identifier == append.id else jobs.get(identifier)
        def __getattr__(self, name):
            return getattr(jobs, name)
    actual_lookup = lease_lookup
    if actual_lookup is None:
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        actual_lookup = _db_lease_lookup
    held = actual_lookup(append.target_id)
    if held not in ((review.source.core_plan_id, "provider_keyed_mixed_append"),
                    (review.source.core_plan_id, "provider_keyed_teardown_fence")):
        raise ValueError("no-Apply cleanup lease differs")
    def original_lookup(engagement):
        return (review.source.core_plan_id, "provider_keyed_mixed_append") if (
            engagement == append.target_id and actual_lookup(engagement) == held) else None
    from app.services.provider_keyed_mixed_append_published_source import collect_published_mixed_append_source
    from app.services.provider_keyed_mixed_append_live_bindings import collect_mixed_append_live_bindings
    published = collect_published_mixed_append_source(append.target_id, review.source.core_job_id,
        binding_inventory=lambda: collect_mixed_append_live_bindings(append.target_id, job_repository=jobs),
        job_repository=jobs, plan_repository=plans, sketch_repository=sketches,
        lease_lookup=original_lookup)
    def published_reader(engagement, core):
        if (engagement, core) != (append.target_id, review.source.core_job_id):
            raise ValueError("no-Apply original source selection differs")
        return published
    context = collect_mixed_append_pair_plan_context(append.id,
        job_repository=PlanningReader(), plan_repository=plans, sketch_repository=sketches,
        lease_lookup=original_lookup, published_reader=published_reader)
    if context.source != review.source or {p: w.path for p, w in context.workspaces.items()} != {
            p: w.path for p, w in workspaces.items()}:
        raise ValueError("no-Apply original publication differs")
    options = context.approval_kwargs()
    kwargs = dict(source=context.source, **options,
        reviewed_provider_order=context.reviewed_provider_order,
        reviewed_chain_order=context.reviewed_chain_order,
        lease_lookup=original_lookup, lease_owner=review.source.core_plan_id,
        credential_repository=credentials)
    if release_check is not None:
        kwargs["release_check"] = release_check
    seal = reopen_mixed_append_pair_plan_review(**kwargs)
    digest = mixed_append_approval_sha256(seal.review_sha256, published)
    if (plan_child.events[-1].data != {"reviewSha256": digest}
            or append.input["reviewSummary"] != mixed_append_review_summary(append, seal)):
        raise ValueError("no-Apply saved review differs")
    if append.input["phase"] == "apply_sealed" and (
            append.input["sourceSha256"] != _canonical(asdict(context.source))
            or append.input["intents"] != {p: asdict(options[p + "_intent"]) for p in workspaces}
            or append.input["reviewedInputs"] != options["reviewed_inputs"]):
        raise ValueError("no-Apply sealed intent differs")
    from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
    release = (release_check or require_devtest_terraform_release)(environment="devtest")
    evidence = {"rowsSha256": _rows_digest(append, jobs), "artifacts": _artifacts(workspaces),
                "reviewSha256": digest, "initialSha256": _canonical(asdict(initial)),
                "terraform": {"path": str(release.path), "sha256": hashlib.sha256(
                    _read(release.path, private=False)).hexdigest()}}
    if evidence["terraform"]["sha256"] != release.sha256:
        raise ValueError("no-Apply Terraform release changed")
    return {"kind": KIND, "appendParentId": append.id, "failedProvider": None,
            "source": json.loads(json.dumps(asdict(review.source))), "evidence": evidence}


def no_apply_history(review, *, jobs, workspaces, initial):
    recovery = review.failed_append_recovery
    if (set(recovery) != {"kind", "appendParentId", "failedProvider", "source", "evidence"}
            or recovery["kind"] != KIND or recovery["failedProvider"] is not None
            or recovery["source"] != json.loads(json.dumps(asdict(review.source)))):
        raise ValueError("saved no-Apply review differs")
    append = jobs.get(recovery["appendParentId"])
    evidence = recovery["evidence"]
    plan, _ = no_apply_rows(append, jobs)
    if (evidence.get("reviewSha256") != plan.events[-1].data["reviewSha256"]
            or set(evidence) != {"rowsSha256", "artifacts", "reviewSha256", "initialSha256", "terraform"}
            or _rows_digest(append, jobs) != evidence["rowsSha256"]
            or _artifacts(workspaces) != evidence["artifacts"]
            or _canonical(asdict(initial)) != evidence["initialSha256"]
            or type(evidence["terraform"]) is not dict or set(evidence["terraform"]) != {"path", "sha256"}
            or not Path(evidence["terraform"]["path"]).is_absolute()
            or hashlib.sha256(_read(Path(evidence["terraform"]["path"]), private=False)).hexdigest()
               != evidence["terraform"]["sha256"]):
        raise ValueError("saved no-Apply history changed")
    return evidence


def fresh_no_apply_observation(initial, append, provider, workspace, *, fence, jobs):
    from app.services.provider_keyed_mixed_initial_apply_proof import prove_mixed_initial_prior_provider_fresh
    from app.services.provider_keyed_mixed_initial_host_binding import ProviderHostObservation
    no_apply_rows(append, jobs)
    child = jobs.get(initial_child_id(initial.input["coreJobId"], provider))
    classified = prove_mixed_initial_prior_provider_fresh(initial, child, workspace, fence=fence,
        process_quiescent=lambda identity: _process_quiescent(
            identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"]))
    raw = _read(workspace.state_path, private=False)
    if hashlib.sha256(raw).hexdigest() != classified.state_sha256:
        raise ValueError("no-Apply state changed during inventory read")
    fence()
    return ProviderHostObservation(classified, raw)
