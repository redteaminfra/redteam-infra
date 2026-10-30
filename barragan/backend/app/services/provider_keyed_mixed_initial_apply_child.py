# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, one-shot mixed-provider initial Apply boundary.

This module has no public dispatcher. Callers must inject audited local source,
selector transports, and exact post-Apply observation; an uncertain write is
never retried. The parent and first child remain the order authority.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Callable, ContextManager
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.services.provider_keyed_selector_reservation import reserve_and_verify_selector
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.provider_keyed_sketch import (
    ProviderKeyedWorkspace, mark_provider_keyed_apply_started, mark_provider_keyed_applied,
)
from app.services.provider_keyed_mixed_linode_saved_plan import _PLAN as _LINODE_PLAN
from app.services.provider_keyed_mixed_digitalocean_saved_plan import _PLAN as _DO_PLAN
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest


ACTION = "provider_keyed_mixed_initial_apply_child"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CLAIM_KEYS = {"claimOwner", "claimToken", "claimClaimedAt", "claimHeartbeatAt", "claimExpiresAt"}
_ENV = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE",
                  "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"})
_INVOCATION = re.compile(r"[0-9a-f]{32}\Z")


class MixedInitialApplyAttention(ValueError):
    """Provider write or its persisted journal is uncertain; do not replay."""


@dataclass(frozen=True)
class ApplySource:
    """Audited local saved plan and ephemeral credential supplied by a binder."""

    workspace: ProviderKeyedWorkspace
    command: tuple[str, ...]
    receipt_sha256: str
    plan_sha256: str
    terraform_sha256: str
    credential_secret_sha256: str
    credential_updated_at: str
    selector_tag: str | None = None
    selector_token: str | None = None
    lock_fence: Callable[[], None] | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=120)).isoformat()


def _child_id(core_job_id: str, provider: str) -> str:
    return f"job-provider-keyed-mixed-initial-apply-{provider}-{core_job_id.removeprefix('job-')}"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _saved_plan_sha(path: Path) -> str:
    """Check the exact regular saved plan bytes at the last pre-GO boundary."""
    try:
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1
                or metadata.st_size > 128 * 1024 * 1024):
            raise ValueError("saved plan is not a bounded regular file")
        with path.open("rb") as stream:
            content = stream.read(128 * 1024 * 1024 + 1)
        if len(content) != metadata.st_size:
            raise ValueError("saved plan changed while reading")
        return hashlib.sha256(content).hexdigest()
    except (OSError, ValueError):
        raise MixedInitialApplyAttention("saved provider plan bytes are unproved") from None


def _save_failed_apply_output(workspace: ProviderKeyedWorkspace, outcome, *,
                              prefix: str = ".barragan-initial-apply-failure") -> None:
    """Keep bounded Terraform output private without changing the job journal.

    A hard link publishes a complete temporary file only when the invocation's
    destination is absent. In particular, an existing file or symlink is never
    replaced. The workspace is already audited and locked by the Apply source.
    """
    if prefix not in {".barragan-initial-apply-failure", ".barragan-append-first-apply-failure",
                      ".barragan-append-second-apply-failure"}:
        raise ValueError("failed Apply output prefix differs")
    invocation = outcome.started.intent.invocation_id
    if (_INVOCATION.fullmatch(invocation) is None or outcome.returncode == 0
            or not isinstance(outcome.stdout, str) or not isinstance(outcome.stderr, str)
            or len(outcome.stdout) > 65536 or len(outcome.stderr) > 65536):
        raise ValueError("failed Apply output is not bounded or identified")
    root = workspace.path
    destination = root / f"{prefix}-{invocation}.json"
    payload = (json.dumps({
        "invocationId": invocation, "returnCode": outcome.returncode,
        "stdout": outcome.stdout, "stderr": outcome.stderr,
        "stdoutTruncated": outcome.stdout_truncated,
        "stderrTruncated": outcome.stderr_truncated,
    }, sort_keys=True) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".barragan-apply-output-", dir=root)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination, follow_symlinks=False)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _base(parent: StoredJobRun, seal: dict, provider: str, index: int) -> dict:
    return {
        "engagementId": parent.target_id,
        "coreJobId": parent.input["coreJobId"],
        "corePlanId": parent.input["corePlanId"],
        "mixedParentId": parent.id,
        "sealJournalSha256": job_event_digest(parent.events[:6]),
        "provider": provider,
        "providerIndex": index,
        "chainId": seal["chainIds"][index],
        "receiptSha256": seal["receiptSha256"][index],
        "mutation": True,
    }


def _precommand(child: StoredJobRun, base: dict, *, active_claim: bool = False) -> bool:
    if (child.action != ACTION or child.id != _child_id(base["coreJobId"], base["provider"])
            or child.target != f"engagement:{base['engagementId']}"
            or child.target_type != "engagement" or child.target_id != base["engagementId"]
            or child.finished_at is not None or child.artifact_refs != []
            or {key: value for key, value in child.input.items() if key not in _CLAIM_KEYS} != base):
        return False
    queued = JobEvent(1, "info", "mixed provider Apply queued", {})
    started = JobEvent(2, "info", "mixed provider Apply started", {})
    if child.status == "queued":
        return child.started_at is None and child.events == [queued] and child.input == base
    if child.status != "running" or child.started_at is None or child.events != [queued, started]:
        return False
    if not (set(child.input) - set(base)):
        return True
    try:
        return (child.input.get("claimOwner", "").startswith("mixed-initial-apply-")
                and isinstance(child.input.get("claimToken"), str)
                and (datetime.fromisoformat(child.input["claimExpiresAt"])
                     > datetime.now(timezone.utc)) == active_claim)
    except (KeyError, TypeError, ValueError):
        return False


def recognize_mixed_initial_apply_result(
    child: StoredJobRun, parent: StoredJobRun, provider: str,
) -> dict:
    """Read the exact durable zero-result prefix; it is not full-state proof."""
    seal = validate_mixed_initial_apply_seal(parent)
    if provider not in seal["orderedProviders"]:
        raise MixedInitialApplyAttention("provider differs from mixed seal")
    index = seal["orderedProviders"].index(provider)
    base = _base(parent, seal, provider, index)
    rows = child.events
    prefix = (["mixed provider Apply queued", "mixed provider Apply started"]
                + (["mixed selector absent before Apply", "mixed selector POST intended",
                    "mixed selector 201 received", "mixed selector exclusive visibility proved"]
                   if provider == "digitalocean" else [])
                + ["mixed provider Apply command intended",
                   "mixed provider Apply command started before GO",
                   "mixed provider phase apply_started",
                   "mixed provider Apply command result fenced"])
    trailing = ["mixed provider phase applied", "mixed provider awaiting exact observation",
                "mixed provider full observation proved"]
    messages = prefix + trailing[:max(0, len(rows) - len(prefix))]
    if (child.id != _child_id(base["coreJobId"], provider) or child.action != ACTION
            or child.status != "running" or child.started_at is None or child.finished_at is not None
            or child.target != f"engagement:{base['engagementId']}"
            or child.target_type != "engagement" or child.target_id != base["engagementId"]
            or child.requested_by != parent.requested_by or child.artifact_refs != []
            or {key: value for key, value in child.input.items() if key not in _CLAIM_KEYS} != base
            or not len(prefix) <= len(rows) <= len(prefix) + len(trailing)
            or [(event.sequence, event.level, event.message) for event in rows]
            != [(number, "info", message) for number, message in enumerate(messages, 1)]
            or rows[0].data != {} or rows[1].data != {}):
        raise MixedInitialApplyAttention("mixed Apply result journal differs")
    offset = 2
    if provider == "digitalocean":
        selector = seal["reviewedPolicy"][provider]["selector_tag"]
        absence, intent, receipt, visibility = (row.data for row in rows[2:6])
        if (set(absence) != {"absenceSha256", "selectorTag"}
                or absence["selectorTag"] != selector
                or _HASH.fullmatch(str(absence["absenceSha256"])) is None
                or intent != {"selectorTag": selector,
                              "absenceSha256": absence["absenceSha256"]}
                or receipt != {"selectorTag": selector, "httpStatus": 201}
                or set(visibility) != {"selectorTag", "visibleSha256"}
                or visibility["selectorTag"] != selector
                or _HASH.fullmatch(str(visibility["visibleSha256"])) is None):
            raise MixedInitialApplyAttention("mixed selector journal differs")
        offset = 6
    intent, started, phase_started, result = (row.data for row in rows[offset:offset + 4])
    plan_name = _LINODE_PLAN if provider == "linode" else _DO_PLAN
    plan_path = Path(str(intent.get("planPath", "")))
    terraform_path = Path(str(intent.get("terraformPath", "")))
    if (set(intent) != {"invocationId", "argvSha256", "planSha256", "planPath",
                        "terraformPath", "terraformSha256"}
            or not isinstance(intent["invocationId"], str) or not intent["invocationId"]
            or intent["planSha256"] != parent.events[index + 2].data["planSha256"]
            or not plan_path.is_absolute() or plan_path.name != plan_name
            or not terraform_path.is_absolute()
            or _HASH.fullmatch(str(intent["terraformSha256"])) is None
            or intent["argvSha256"] != _digest([
                str(terraform_path), "apply", "-input=false", "-lock=true",
                "-no-color", str(plan_path)])
            or set(started) != {"invocationId", "bootId", "pid", "pgid", "startTicks"}
            or started["invocationId"] != intent["invocationId"]
            or not isinstance(started["bootId"], str) or not started["bootId"]
            or any(type(started[key]) is not int or started[key] < 1
                   for key in ("pid", "pgid", "startTicks"))
            or started["pid"] != started["pgid"]
            or phase_started != {"commandStartSequence": offset + 2}
            or set(result) != {"invocationId", "returnCode", "stdoutBytes", "stderrBytes",
                               "stdoutTruncated", "stderrTruncated"}
            or result["invocationId"] != intent["invocationId"]
            or result["returnCode"] != 0 or result["stdoutTruncated"] is not False
            or result["stderrTruncated"] is not False
            or any(type(result[key]) is not int or result[key] < 0
                   for key in ("stdoutBytes", "stderrBytes"))):
        raise MixedInitialApplyAttention("mixed Terraform result journal differs")
    result_sequence = offset + 4
    result_digest = job_event_digest(rows[:result_sequence])
    if len(rows) > result_sequence and rows[result_sequence].data != {
            "commandResultSequence": result_sequence}:
        raise MixedInitialApplyAttention("mixed applied phase journal differs")
    if len(rows) > result_sequence + 1 and rows[result_sequence + 1].data != {
            "commandResultSequence": result_sequence}:
        raise MixedInitialApplyAttention("mixed awaiting-observation journal differs")
    if len(rows) > result_sequence + 2:
        proof = rows[result_sequence + 2].data
        if (set(proof) != {"classifierKind", "stateSha256", "lineage", "serial",
                           "inventorySha256", "observationSha256", "resourceIds",
                           "selectorResourcesCount", "selectorAttachedNodeIds",
                           "linodeFirewallAttachedNodeIds", "inventoryCount",
                           "commandResultJournalSha256"}
                or proof["classifierKind"] != "full"
                or proof["commandResultJournalSha256"] != result_digest
                or any(_HASH.fullmatch(str(proof[key])) is None for key in
                       ("stateSha256", "inventorySha256", "observationSha256"))
                or not isinstance(proof["lineage"], str) or not proof["lineage"]
                or type(proof["serial"]) is not int or proof["serial"] < 1
                or type(proof["inventoryCount"]) is not int or proof["inventoryCount"] < 0
                or not isinstance(proof["resourceIds"], dict) or not proof["resourceIds"]
                or list(proof["resourceIds"]) != sorted(proof["resourceIds"])
                or any(not isinstance(key, str) or not key or not isinstance(value, str)
                       or not value for key, value in proof["resourceIds"].items())
                or len(set(proof["resourceIds"].values())) != len(proof["resourceIds"])
                or (provider == "digitalocean" and (
                    type(proof["selectorResourcesCount"]) is not int
                    or proof["selectorResourcesCount"] < 0
                    or not isinstance(proof["selectorAttachedNodeIds"], list)
                    or any(type(value) is not str or not value
                           for value in proof["selectorAttachedNodeIds"])
                    or proof["selectorAttachedNodeIds"] != sorted(set(proof["selectorAttachedNodeIds"]))
                    or proof["selectorResourcesCount"] != len(proof["selectorAttachedNodeIds"])
                    or proof["linodeFirewallAttachedNodeIds"] is not None))
                or (provider == "linode" and (
                    proof["selectorResourcesCount"] is not None
                    or proof["selectorAttachedNodeIds"] is not None
                    or not isinstance(proof["linodeFirewallAttachedNodeIds"], list)
                    or any(type(value) is not str or not value
                           for value in proof["linodeFirewallAttachedNodeIds"])
                    or proof["linodeFirewallAttachedNodeIds"]
                    != sorted(set(proof["linodeFirewallAttachedNodeIds"]))))):
            raise MixedInitialApplyAttention("mixed full observation journal differs")
    stage = ("result", "applied", "awaiting", "proved")[len(rows) - result_sequence]
    return {"provider": provider, "planSha256": intent["planSha256"],
            "planPath": str(plan_path), "invocationId": intent["invocationId"],
            "startedIdentity": {key: started[key] for key in ("bootId", "pid", "pgid", "startTicks")},
            "commandResultSequence": result_sequence,
            "commandResultJournalSha256": result_digest,
            "stage": stage, "journalSha256": job_event_digest(rows)}


def recognize_mixed_initial_apply_terminal(
    child: StoredJobRun, parent: StoredJobRun, provider: str,
) -> dict:
    """Authenticate the exact completed full-proof child without provider reads."""
    if (child.status != "succeeded" or child.started_at is None
            or child.finished_at is None or len(child.events) < 2):
        raise MixedInitialApplyAttention("mixed Apply terminal status differs")
    try:
        if datetime.fromisoformat(child.finished_at) < datetime.fromisoformat(child.started_at):
            raise ValueError("terminal time precedes start")
    except (TypeError, ValueError):
        raise MixedInitialApplyAttention("mixed Apply terminal time differs") from None
    historical = replace(child, status="running", finished_at=None, events=child.events[:-1])
    result = recognize_mixed_initial_apply_result(historical, parent, provider)
    proof = child.events[-2].data
    terminal = child.events[-1]
    if (result["stage"] != "proved"
            or terminal.sequence != len(child.events) or terminal.level != "info"
            or terminal.message != "mixed provider initial Apply succeeded"
            or terminal.data != {"observationSha256": proof["observationSha256"]}):
        raise MixedInitialApplyAttention("mixed Apply terminal journal differs")
    return {**result, "proof": proof, "terminalJournalSha256": job_event_digest(child.events)}


def _prior_workspace(parent: StoredJobRun, provider: str, terminal: dict) -> ProviderKeyedWorkspace:
    """Reconstruct the first provider's exact retained workspace read-only."""
    policy = parent.events[5].data["reviewedPolicy"][provider]
    connection_id = policy["provider_connection_id"]
    fingerprint = hashlib.sha256(f"{provider}\0{connection_id}".encode()).hexdigest()
    root = Path(terminal["planPath"]).parent
    if (root.name != fingerprint or root.parent.name != provider
            or root.parent.parent.name != "provider-keyed-v2"
            or root.parent.parent.parent.name != parent.target_id
            or root.is_symlink() or root.resolve(strict=True) != root):
        raise MixedInitialApplyAttention("prior provider workspace identity differs")
    try:
        marker = json.loads((root / ".barragan-provider-keyed-state.json").read_text())
        source_sha = hashlib.sha256(json.dumps(
            marker["source_files"], sort_keys=True).encode()).hexdigest()
        if (marker["provider_connection_id"] != connection_id
                or not isinstance(marker["source_revision"], str)):
            raise ValueError("prior source marker differs")
    except (OSError, KeyError, ValueError, TypeError):
        raise MixedInitialApplyAttention("prior provider source marker differs") from None
    return ProviderKeyedWorkspace(
        root, root / "terraform.tfstate", root / ".terraform-data",
        "provider-keyed-v2", provider, connection_id, fingerprint,
        marker["source_revision"], source_sha)


def run_mixed_initial_provider_apply(
    engagement_id: str, core_job_id: str, provider: str, *, environment: str,
    job_repository=None, lease_lookup=None,
    source_session: Callable[[StoredJobRun, str, Callable[[], None]], ContextManager[ApplySource]],
    selector_absence_prover: Callable[[ApplySource, Callable[[], None]], str],
    selector_get_transport, selector_post_transport,
    release_check: Callable = require_devtest_terraform_release,
    gated_command_runner: Callable = run_gated_command,
    selector_reserver: Callable = reserve_and_verify_selector,
    prior_fresh_prover: Callable | None = None,
    credential_repository=None, linode_transport=None, digitalocean_transport=None,
) -> StoredJobRun:
    """Run at most one provider write; later calls never replay a command intent."""
    if environment != "devtest" or provider not in {"linode", "digitalocean"}:
        raise MixedInitialApplyAttention("mixed initial Apply is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(_parent_id(core_job_id))
    if (parent is None or parent.target_id != engagement_id
            or parent.input.get("phase") != "apply_sealed" or parent.status != "running"):
        raise MixedInitialApplyAttention("mixed initial Apply seal is unavailable")
    seal = validate_mixed_initial_apply_seal(parent)
    order = seal["orderedProviders"]
    index = order.index(provider)
    _require_lease(lookup, engagement_id, parent.input["corePlanId"])
    base = _base(parent, seal, provider, index)
    child_id = _child_id(core_job_id, provider)
    existing = jobs.get(child_id)
    if existing is not None and existing.status == "succeeded":
        recognize_mixed_initial_apply_terminal(existing, parent, provider)
        return existing
    if index:
        prior = order[index - 1]
        first = jobs.get(_child_id(core_job_id, prior))
        if first is None:
            raise MixedInitialApplyAttention("first provider terminal proof is unavailable")
        try:
            terminal = recognize_mixed_initial_apply_terminal(first, parent, prior)
        except MixedInitialApplyAttention:
            raise MixedInitialApplyAttention("first provider terminal proof is unavailable") from None
        workspace = _prior_workspace(parent, prior, terminal)
        if prior_fresh_prover is None:
            from app.services.provider_keyed_mixed_initial_apply_proof import (
                prove_mixed_initial_prior_provider_fresh,
            )
            prior_fresh_prover = prove_mixed_initial_prior_provider_fresh
        generation = _digest({"parent": job_event_digest(parent.events[:6]),
                              "first": terminal["terminalJournalSha256"]})

        def prior_fence() -> str:
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            if (jobs.get(parent.id) != parent or jobs.get(first.id) != first
                    or jobs.get(child_id) != existing):
                raise MixedInitialApplyAttention("first provider freshness generation changed")
            return generation

        prior_fence()
        classification = prior_fresh_prover(
            parent, first, workspace, fence=prior_fence,
            process_quiescent=lambda identity: _process_quiescent(
                identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"]),
            credential_repository=credential_repository,
            linode_transport=linode_transport,
            digitalocean_transport=digitalocean_transport)
        prior_fence()
        if getattr(classification, "kind", None) != "full":
            raise MixedInitialApplyAttention("first provider state and inventory are unproved")
    queued = StoredJobRun(
        child_id, ACTION, "queued", f"engagement:{engagement_id}", "engagement",
        engagement_id, parent.requested_by, base, [], _now(), None, None,
        [JobEvent(1, "info", "mixed provider Apply queued", {})],
    )
    if existing is not None and not _precommand(existing, base):
        raise MixedInitialApplyAttention("mixed provider Apply is not safely pre-command")
    saved = jobs.save_if_absent(queued)
    if existing is None or existing.status == "queued":
        if saved != queued and not _precommand(saved, base):
            raise MixedInitialApplyAttention("mixed provider Apply reservation changed")
        current = jobs.start_if_queued(
            saved, started_at=_now(),
            event=JobEvent(2, "info", "mixed provider Apply started", {}))
        if current is None:
            raise MixedInitialApplyAttention("mixed provider Apply start lost")
    else:
        current = existing
    owner, token = f"mixed-initial-apply-{uuid4().hex}", uuid4().hex
    at = _now()
    current = jobs.claim_lease(child_id, owner=owner, token=token,
                               claimed_at=at, expires_at=_later(at),
                               eligible_statuses={"running"})
    if current is None or not _precommand(current, base, active_claim=True):
        raise MixedInitialApplyAttention("mixed provider Apply claim lost")
    active_source: dict[str, ApplySource | None] = {"value": None}

    def fence() -> None:
        _require_lease(lookup, engagement_id, base["corePlanId"])
        if (jobs.get(parent.id) != parent or jobs.get(child_id) != current
                or datetime.now(timezone.utc) >= datetime.fromisoformat(current.input["claimExpiresAt"])):
            raise MixedInitialApplyAttention("mixed provider Apply authority changed")
        source_for_lock = active_source["value"]
        if source_for_lock is not None and source_for_lock.lock_fence is not None:
            source_for_lock.lock_fence()

    def renew() -> None:
        nonlocal current
        fence()
        at = _now()
        updated = jobs.renew_lease(child_id, owner=owner, token=token,
                                   heartbeat_at=at, expires_at=_later(at))
        if updated is None or updated.events != current.events:
            raise MixedInitialApplyAttention("mixed provider Apply heartbeat lost")
        current = updated

    def append(message: str, data: dict) -> None:
        nonlocal current
        fence()
        at = _now()
        updated = jobs.append_event_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            heartbeat_at=at, expires_at=_later(at),
            event=JobEvent(len(current.events) + 1, "info", message, data))
        if updated is None:
            raise MixedInitialApplyAttention("mixed provider Apply journal CAS lost")
        current = updated

    renew()
    with source_session(parent, provider, renew) as source:
        active_source["value"] = source
        renew()
        if not isinstance(source, ApplySource):
            raise MixedInitialApplyAttention("mixed provider saved plan source differs")
        release = release_check(environment=environment)
        plan_path = source.workspace.path / (_LINODE_PLAN if provider == "linode" else _DO_PLAN)
        policy = seal["reviewedPolicy"][provider]
        if (not source.workspace.path.is_absolute()
                or source.workspace.path.is_symlink() or not source.workspace.path.is_dir()
                or source.workspace.path.resolve(strict=True) != source.workspace.path
                or source.workspace.provider != provider
                or source.workspace.state_path != source.workspace.path / "terraform.tfstate"
                or source.workspace.terraform_data_dir != source.workspace.path / ".terraform-data"
                or not source.command or source.receipt_sha256 != base["receiptSha256"]
                or source.plan_sha256 != parent.events[index + 2].data["planSha256"]
                or not isinstance(getattr(release, "path", None), Path)
                or not release.path.is_absolute() or not isinstance(getattr(release, "sha256", None), str)
                or source.terraform_sha256 != release.sha256
                or source.command != (str(release.path), "apply", "-input=false", "-lock=true",
                                      "-no-color", str(plan_path))
                or _saved_plan_sha(plan_path) != source.plan_sha256
                or source.credential_secret_sha256 != policy["credential_secret_sha256"]
                or source.credential_updated_at != policy["credential_updated_at"]):
            raise MixedInitialApplyAttention("mixed provider saved plan source differs")
        # The saved-plan workers use this private provider install directory and
        # ignore ambient Terraform CLI configuration. Apply must use the same
        # provider bytes, without inheriting an operator's TF_* overrides.
        if any(key.upper().startswith("TF_") for key in os.environ):
            raise MixedInitialApplyAttention("unreviewed Terraform environment input")
        command_env = {key: value for key, value in os.environ.items() if key in _ENV}
        command_env.update(TF_DATA_DIR=str(source.workspace.terraform_data_dir),
                           TF_CLI_CONFIG_FILE="/dev/null")
        if provider == "digitalocean":
            if (not source.selector_token or source.selector_tag != policy["selector_tag"]):
                raise MixedInitialApplyAttention("DigitalOcean selector source is absent")
            renew()
            absent_sha = selector_absence_prover(source, renew)
            renew()
            if not isinstance(absent_sha, str) or _HASH.fullmatch(absent_sha) is None:
                raise MixedInitialApplyAttention("DigitalOcean selector absence is unproved")
            append("mixed selector absent before Apply", {"absenceSha256": absent_sha,
                                                          "selectorTag": source.selector_tag})
            selector_stage = "absent"

            def on_selector_intent() -> None:
                nonlocal selector_stage
                if selector_stage != "absent":
                    raise MixedInitialApplyAttention("selector POST order differs")
                append("mixed selector POST intended", {"selectorTag": source.selector_tag,
                                                         "absenceSha256": absent_sha})
                selector_stage = "intent"

            def on_selector_receipt(status: int, selector: str) -> None:
                nonlocal selector_stage
                if selector_stage != "intent" or status != 201 or selector != source.selector_tag:
                    raise MixedInitialApplyAttention("selector POST receipt differs")
                append("mixed selector 201 received", {"selectorTag": selector, "httpStatus": status})
                selector_stage = "receipt"

            visible = selector_reserver(
                source.selector_tag, source.selector_token, fence=renew,
                on_intent=on_selector_intent, on_receipt=on_selector_receipt,
                get_transport=selector_get_transport, post_transport=selector_post_transport)
            if selector_stage != "receipt" or not isinstance(visible, tuple):
                raise MixedInitialApplyAttention("selector exclusive visibility is unproved")
            append("mixed selector exclusive visibility proved", {"selectorTag": source.selector_tag,
                                                                  "visibleSha256": _digest(visible)})

        command_stage = "none"
        command_intent = None
        command_started = None
        argv_sha = _digest(list(source.command))

        def on_intent(value) -> None:
            nonlocal command_stage, command_intent
            if (command_stage != "none" or _saved_plan_sha(plan_path) != source.plan_sha256
                    or value.scratch_path != str(source.workspace.path)
                    or value.argv_sha256 != argv_sha):
                raise MixedInitialApplyAttention("Terraform Apply command intent differs")
            append("mixed provider Apply command intended", {
                "invocationId": value.invocation_id, "argvSha256": value.argv_sha256,
                "planSha256": source.plan_sha256,
                "planPath": str(plan_path), "terraformPath": str(release.path),
                "terraformSha256": release.sha256})
            command_intent, command_stage = value, "intent"

        def on_started(value) -> None:
            nonlocal command_stage, command_started
            if (command_stage != "intent" or value.intent != command_intent
                    or _saved_plan_sha(plan_path) != source.plan_sha256):
                raise MixedInitialApplyAttention("Terraform Apply command start differs")
            append("mixed provider Apply command started before GO", {
                "invocationId": command_intent.invocation_id,
                "bootId": value.identity.boot_id, "pid": value.identity.pid,
                "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks})
            command_started, command_stage = value, "started"
            mark_provider_keyed_apply_started(source.workspace)
            append("mixed provider phase apply_started", {
                "commandStartSequence": len(current.events)})
            fence()  # Short, local check only; slow reads preceded process spawn.

        def on_heartbeat(value) -> None:
            if command_stage != "started" or value != command_started:
                raise MixedInitialApplyAttention("Terraform Apply heartbeat identity differs")
            renew()

        def on_result(value) -> None:
            nonlocal command_stage
            if command_stage != "started" or value.started != command_started:
                raise MixedInitialApplyAttention("Terraform Apply command result differs")
            append("mixed provider Apply command result fenced", {
                "invocationId": command_intent.invocation_id, "returnCode": value.returncode,
                "stdoutBytes": value.stdout_bytes, "stderrBytes": value.stderr_bytes,
                "stdoutTruncated": value.stdout_truncated,
                "stderrTruncated": value.stderr_truncated})
            command_stage = "result"

        renew()
        outcome = gated_command_runner(
            list(source.command), scratch_path=source.workspace.path, provider_keyed_v2=True,
            gate_timeout_seconds=1200, intent_callback=on_intent,
            started_callback=on_started, heartbeat_callback=on_heartbeat,
            result_callback=on_result, env=command_env)
        if (command_stage == "result" and outcome.started == command_started
                and outcome.returncode != 0):
            try:
                _save_failed_apply_output(source.workspace, outcome)
            except (OSError, ValueError, TypeError, AttributeError):
                # Diagnostics never grant authority or weaken the no-replay gate.
                pass
        if (command_stage != "result" or outcome.started != command_started
                or outcome.returncode != 0 or outcome.stdout_truncated or outcome.stderr_truncated):
            raise MixedInitialApplyAttention("Terraform Apply result is incomplete or failed")
        mark_provider_keyed_applied(source.workspace)
        append("mixed provider phase applied", {"commandResultSequence": len(current.events)})
        append("mixed provider awaiting exact observation", {
            "commandResultSequence": len(current.events) - 1})
        return current


def reconcile_mixed_initial_apply_phase(
    parent: StoredJobRun, child: StoredJobRun, provider: str,
    workspace: ProviderKeyedWorkspace, *,
    process_quiescent: Callable[[dict], bool], job_repository=None, lease_lookup=None,
) -> StoredJobRun:
    """Finish only the local phase marker after exact rc0 and quiescence.

    This never launches Terraform or proves provider completeness. A separate
    read-only binder must classify the resulting state before child success.
    """
    from app.services.provider_keyed_mixed_initial_apply_source import locked_provider_saved_plan

    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    if (jobs.get(parent.id) != parent or jobs.get(child.id) != child
            or not isinstance(workspace, ProviderKeyedWorkspace)
            or workspace.provider != provider or not workspace.path.is_absolute()
            or workspace.path.is_symlink() or workspace.path.resolve(strict=True) != workspace.path
            or workspace.state_path != workspace.path / "terraform.tfstate"):
        raise MixedInitialApplyAttention("mixed phase reconciliation source changed")
    result = recognize_mixed_initial_apply_result(child, parent, provider)
    if result["stage"] not in {"result", "applied", "awaiting"}:
        raise MixedInitialApplyAttention("mixed phase is not awaiting reconciliation")
    if Path(result["planPath"]).parent != workspace.path:
        raise MixedInitialApplyAttention("mixed phase workspace differs")
    if result["stage"] == "awaiting":
        return child
    owner, token = f"mixed-initial-apply-{uuid4().hex}", uuid4().hex
    at = _now()
    current = jobs.claim_lease(child.id, owner=owner, token=token,
                               claimed_at=at, expires_at=_later(at),
                               eligible_statuses={"running"})
    if current is None or recognize_mixed_initial_apply_result(current, parent, provider)["stage"] != result["stage"]:
        raise MixedInitialApplyAttention("mixed phase reconciliation claim is unavailable")

    def fence() -> None:
        _require_lease(lookup, parent.target_id, parent.input["corePlanId"])
        if (jobs.get(parent.id) != parent or jobs.get(child.id) != current
                or datetime.now(timezone.utc) >= datetime.fromisoformat(current.input["claimExpiresAt"])):
            raise MixedInitialApplyAttention("mixed phase reconciliation authority changed")

    def renew() -> None:
        nonlocal current
        fence()
        at = _now()
        updated = jobs.renew_lease(child.id, owner=owner, token=token,
                                   heartbeat_at=at, expires_at=_later(at))
        if updated is None or updated.events != current.events:
            raise MixedInitialApplyAttention("mixed phase reconciliation heartbeat lost")
        current = updated

    def append(message: str, data: dict) -> None:
        nonlocal current
        fence()
        at = _now()
        updated = jobs.append_event_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            heartbeat_at=at, expires_at=_later(at),
            event=JobEvent(len(current.events) + 1, "info", message, data))
        if updated is None:
            raise MixedInitialApplyAttention("mixed phase reconciliation journal CAS lost")
        current = updated

    with locked_provider_saved_plan(workspace.path, provider, renew) as lock_fence:
        renew()
        lock_fence()
        phase_path = workspace.path / ".barragan-apply-phase.json"
        try:
            phase = json.loads(phase_path.read_text())
            state = workspace.state_path.lstat()
        except (OSError, ValueError):
            raise MixedInitialApplyAttention("retained Apply phase or state is unavailable") from None
        if (phase not in ({"schema": workspace.schema, "phase": "apply_started"},
                          {"schema": workspace.schema, "phase": "applied"})
                or not stat.S_ISREG(state.st_mode) or state.st_size < 1
                or not process_quiescent(result["startedIdentity"])):
            raise MixedInitialApplyAttention("Terraform process or retained state is unproved")
        renew()
        if result["stage"] == "result":
            if phase["phase"] == "apply_started":
                mark_provider_keyed_applied(workspace)
            lock_fence()
            append("mixed provider phase applied", {
                "commandResultSequence": result["commandResultSequence"]})
        append("mixed provider awaiting exact observation", {
            "commandResultSequence": result["commandResultSequence"]})
    return current
