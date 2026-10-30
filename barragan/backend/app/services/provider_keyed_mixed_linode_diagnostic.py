# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot routed Linode identity capture after the mixed bootstrap worker.

This records diagnostic evidence only. It does not interpret host firewall or
SSH policy, publish a chain, or authorize public mixed Deploy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_host_binding import _core_known_hosts
from app.services.provider_keyed_core_destroy_preview import _read_regular
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as _apply_child_id, _prior_workspace,
    recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_apply_proof import prove_mixed_initial_prior_provider_fresh
from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
from app.services.provider_keyed_mixed_initial_coordinator import (
    _core_matches, recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    ProviderHostObservation, _binding_child_id, _same_inserted_job,
    build_mixed_initial_host_binding,
    recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_initial_projection import project_mixed_initial_chains
from app.services.provider_keyed_mixed_linode_host_probe import (
    LinodeRawHostCollection, LinodeRawHostIdentity, _sudo_hostname_warning,
    probe_linode_host_identity,
)
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandResult, _private_scratch_path, run_gated_command,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.services.sketch_bootstrap import SketchBootstrapSpec
from app.services.sketch_bootstrap_apply import _core_hosts, _sketch_nodes
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


ACTION = "provider_keyed_mixed_linode_diagnostic"
_OWNER = f"mixed-linode-diagnostic-{uuid4().hex}"


class MixedLinodeDiagnosticAttention(ValueError):
    """Identity contact may have happened and cannot be replayed."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    return (datetime.fromisoformat(value) + timedelta(seconds=120)).isoformat()


def _job_id(core_job_id: str, *, collect_raw: bool = False) -> str:
    kind = "raw-diagnostic" if collect_raw else "diagnostic"
    return f"job-provider-keyed-mixed-linode-{kind}-{core_job_id.removeprefix('job-')}"


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _same_unstarted_reservation(saved: StoredJobRun, proposed: StoredJobRun) -> bool:
    """Accept only an exact prior queued row after fresh authority rebind."""
    try:
        created = datetime.fromisoformat(saved.created_at)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (created <= datetime.now(timezone.utc)
                and replace(saved, created_at=proposed.created_at) == proposed)
    except (AttributeError, TypeError, ValueError):
        return False


def _precommand_recovery_scratch(
    prior: StoredJobRun, queued: StoredJobRun, node: dict, workspace: Path,
) -> Path:
    """Recognize only the first-node scratch boundary before any SSH intent."""
    claim_keys = {"claimOwner", "claimToken", "claimClaimedAt",
                  "claimHeartbeatAt", "claimExpiresAt"}
    try:
        claim = prior.input
        created = datetime.fromisoformat(prior.created_at)
        started = datetime.fromisoformat(prior.started_at)
        claimed = datetime.fromisoformat(claim["claimClaimedAt"])
        heartbeat = datetime.fromisoformat(claim["claimHeartbeatAt"])
        expires = datetime.fromisoformat(claim["claimExpiresAt"])
        instants = [created, started, claimed, heartbeat, expires]
        instants = [value.replace(tzinfo=timezone.utc) if value.tzinfo is None
                    else value.astimezone(timezone.utc) for value in instants]
        if (prior.status != "running" or prior.finished_at is not None
                or len(prior.events) != 3 or prior.action != queued.action
                or prior.artifact_refs != [] or set(claim) != set(queued.input) | claim_keys
                or {key: claim[key] for key in queued.input} != queued.input
                or not re.fullmatch(r"mixed-linode-diagnostic-[0-9a-f]{32}", claim["claimOwner"])
                or type(claim["claimToken"]) is not str or len(claim["claimToken"]) < 16
                or not instants[0] <= instants[1] <= instants[2] <= instants[3] < instants[4]
                or instants[4] > instants[3] + timedelta(seconds=120)
                or instants[4] >= datetime.now(timezone.utc)
                or replace(prior, created_at=queued.created_at, status="queued",
                           started_at=None, input=queued.input,
                           events=queued.events) != queued
                or prior.events[:2] != [queued.events[0],
                    JobEvent(2, "info", "Linode diagnostic started", {})]):
            raise ValueError
        event = prior.events[2]
        fields = {"hostname": node["hostname"],
                  "terraformAddress": node["terraformAddress"],
                  "providerInstanceId": node["providerInstanceId"]}
        path_text = event.data.get("scratchPath")
        if (event != JobEvent(3, "info", "Linode diagnostic scratch intended",
                             {**fields, "scratchPath": path_text})
                or type(path_text) is not str):
            raise ValueError
        scratch = Path(path_text)
        if (scratch.parent != workspace or str(scratch) != path_text
                or re.fullmatch(r"\.barragan-linode-diagnostic-[0-9a-f]{32}", scratch.name) is None
                or scratch.is_symlink() or scratch.resolve(strict=True) != scratch):
            raise ValueError
        info = scratch.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or any(scratch.iterdir())):
            raise ValueError
        return scratch
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        raise MixedLinodeDiagnosticAttention(
            "Linode diagnostic precommand recovery boundary differs") from None


def _verify_private_raw_evidence(path: Path, expected_sha256: str) -> None:
    """Read back the exact service-owned 0600 file before recording success."""
    if (type(expected_sha256) is not str or len(expected_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_sha256)):
        raise ValueError("Linode raw evidence digest differs")
    before_path = path.lstat()
    if (not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1
            or before_path.st_uid != os.getuid()
            or stat.S_IMODE(before_path.st_mode) != 0o600):
        raise ValueError("Linode raw evidence path is unsafe")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before_fd = os.fstat(fd)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(2_500_001)
            if not raw or len(raw) > 2_500_000 or stream.read(1):
                raise ValueError("Linode raw evidence exceeds private bound")
        after_fd = os.fstat(fd)
    finally:
        os.close(fd)
    after_path = path.lstat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
              "st_uid", "st_gid", "st_mode", "st_nlink")
    if (any(getattr(before_path, field) != getattr(before_fd, field)
            or getattr(before_fd, field) != getattr(after_fd, field)
            or getattr(after_fd, field) != getattr(after_path, field)
            for field in fields)
            or hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise ValueError("Linode raw evidence changed before success")


def _diagnostic_raw_runner(*, workspace: Path, diagnostic_id: str, role: str,
                           fence: Callable[[], None], runner=run_gated_command):
    """Retain only an exact, completed Linode stderr sample for offline diagnosis.

    The original audit callback remains the durable command fence. The result
    is returned unchanged so the host collector's stderr policy still vetoes it.
    """
    if role not in {"middle", "edge"} or not diagnostic_id:
        raise ValueError("Linode diagnostic sample identity differs")
    private = _private_scratch_path(workspace)

    def run(command, **kwargs):
        callback = kwargs["result_callback"]
        audited = []

        def record(value):
            callback(value)
            audited.append(value)

        outcome = runner(command, **{**kwargs, "result_callback": record})
        if (type(outcome) is not CommandResult or len(audited) != 1
                or type(audited[0]) is not CommandAuditResult):
            raise ValueError("Linode diagnostic command audit differs")
        audit = audited[0]
        if (outcome.started != audit.started or outcome.returncode != audit.returncode
                or outcome.stdout_truncated != audit.stdout_truncated
                or outcome.stderr_truncated != audit.stderr_truncated
                or outcome.returncode != 0 or outcome.stdout_truncated
                or outcome.stderr_truncated or audit.stdout_bytes != len(outcome.stdout.encode("utf-8"))
                or "\ufffd" in outcome.stderr):
            raise ValueError("Linode diagnostic command result differs from bounded audit")
        stderr = outcome.stderr.encode("utf-8")
        if len(stderr) != audit.stderr_bytes or len(stderr) > 4096:
            raise ValueError("Linode diagnostic stderr differs from bounded audit")
        if stderr:
            invocation = audit.started.intent.invocation_id
            if (not re.fullmatch(r"[0-9a-f]{32}", invocation)
                    or audit.started.intent.scratch_path != str(kwargs["scratch_path"])):
                raise ValueError("Linode diagnostic sample invocation differs")
            fence()
            name = hashlib.sha256(
                f"{diagnostic_id}\0{role}\0{invocation}".encode()).hexdigest()
            path = private / f".barragan-linode-stderr-{name}.txt"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                offset = 0
                while offset < len(stderr):
                    written = os.write(fd, stderr[offset:])
                    if written <= 0:
                        raise OSError("Linode diagnostic stderr write was incomplete")
                    offset += written
                os.fsync(fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_size != len(stderr)):
                    raise ValueError("Linode diagnostic stderr file is unsafe")
            except BaseException:
                os.close(fd)
                path.unlink(missing_ok=True)
                raise
            else:
                os.close(fd)
        return outcome

    return run


def _verify_command_journal(events, expected, identities, *, collect_raw=False) -> None:
    """Require every started command to have a matching fenced result."""
    try:
        rows = list(events[2:])
        commands_per_host = 4 if collect_raw else 1
        rows_per_host = 2 + 3 * commands_per_host
        if len(expected) != 2 or len(identities) != 2 or len(rows) != rows_per_host * 2:
            raise ValueError
        seen = set()
        for index, (node, identity) in enumerate(zip(expected, identities)):
            if identity.hostname != node["hostname"]:
                raise ValueError
            warning_bytes = len(_sudo_hostname_warning(identity.hostname).encode("utf-8"))
            host_rows = rows[index * rows_per_host:(index + 1) * rows_per_host]
            scratch, captured = host_rows[0], host_rows[-1]
            fields = {"hostname": node["hostname"],
                      "terraformAddress": node["terraformAddress"],
                      "providerInstanceId": node["providerInstanceId"]}
            if (scratch.message != "Linode diagnostic scratch intended"
                    or captured.message != "Linode diagnostic identity captured"
                    or any(any(event.data.get(key) != value for key, value in fields.items())
                           for event in host_rows)
                    or captured.data.get("identitySha256") != _sha(asdict(identity))):
                raise ValueError
            for offset in range(commands_per_host):
                intended, started, result = host_rows[1 + 3 * offset:4 + 3 * offset]
                invocation = intended.data.get("invocationId")
                if ([row.message for row in (intended, started, result)]
                        != ["Linode diagnostic command intended",
                            "Linode diagnostic command started before GO",
                            "Linode diagnostic command result fenced"]
                        or not invocation or invocation in seen
                        or intended.data.get("scratchPath") != scratch.data.get("scratchPath")
                        or started.data.get("invocationId") != invocation
                        or result.data.get("invocationId") != invocation
                        or result.data.get("returnCode") != 0
                        or result.data.get("stdoutTruncated") is not False
                        or result.data.get("stderrTruncated") is not False
                        or result.data.get("stderrBytes") not in (
                            (0, warning_bytes) if collect_raw and offset else (0,))):
                    raise ValueError
                seen.add(invocation)
            if host_rows[1].data.get("invocationId") != identity.invocation_id:
                raise ValueError
    except Exception:
        raise MixedLinodeDiagnosticAttention("Linode diagnostic command journal differs") from None


def capture_mixed_linode_identity_diagnostic(
    engagement_id: str, core_job_id: str, *, environment: str,
    job_repository=None, sketch_repository=None, lease_lookup=None,
    probe: Callable = probe_linode_host_identity,
    fresh_observer: Callable[[StoredJobRun, str, Callable[[], None]], ProviderHostObservation] | None = None,
    core_hosts: Callable = _core_hosts,
    core_known_hosts: Callable = _core_known_hosts,
    collect_raw: bool = False,
) -> StoredJobRun:
    """Capture two exact Linode metadata identities under one nonreplayable job.

    This is deliberately a prerequisite to a separately reviewed Linode raw
    policy capture. A completed diagnostic is never treated as strict proof.
    """
    if environment != "devtest" or not engagement_id or not core_job_id:
        raise MixedLinodeDiagnosticAttention("mixed Linode diagnostic is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    diagnostic_id = _job_id(core_job_id, collect_raw=collect_raw)
    try:
        prior = jobs.get(diagnostic_id)
        recovery = bool(collect_raw and prior is not None and prior.status == "running"
                        and prior.finished_at is None and len(prior.events) == 3)
        if prior is not None and not recovery and (
                prior.status != "queued" or prior.started_at is not None
                or prior.finished_at is not None or len(prior.events) != 1):
            raise ValueError("Linode diagnostic already started; no contact replay")
        parent = jobs.get(_parent_id(core_job_id))
        core = jobs.get(core_job_id)
        worker = jobs.get(_worker_id(core_job_id))
        binding = jobs.get(_binding_child_id(core_job_id))
        if (parent is None or core is None or worker is None or binding is None
                or parent.target_id != engagement_id or parent.status != "running"
                or parent.finished_at is not None or parent.input.get("phase") != "awaiting_mixed_host_proof"
                or worker.action != "provider_keyed_mixed_initial_host_worker"
                or worker.status != "succeeded" or worker.finished_at is None
                or not worker.events or worker.events[-1].message !=
                   "mixed bootstrap completed; strict raw proof pending"):
            raise ValueError("completed mixed bootstrap is required")
        seal = validate_mixed_initial_apply_seal(parent)
        manifest = recognize_mixed_initial_host_binding(binding, parent)
        order = seal["orderedProviders"]
        children = {name: jobs.get(_apply_child_id(core_job_id, name)) for name in order}
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        recognize_mixed_initial_host_proof_handoff(parent, core, active_id, children)
        if not _core_matches(parent, core, active_id):
            raise ValueError("active core differs")
        _require_lease(lookup, engagement_id, parent.input["corePlanId"])
        if (worker.input.get("bindingJobId") != binding.id
                or worker.input.get("bindingManifestSha256") != binding.input["manifestSha256"]
                or worker.events[-1].data != {
                    "bindingManifestSha256": binding.input["manifestSha256"],
                    "chainIds": list(manifest["chainIds"]),
                }):
            raise ValueError("bootstrap and binding differ")
        durable = tuple(sketches.list_for_engagement(engagement_id))
        chains = {chain.chain_id: chain for chain in durable}
        if len(chains) != len(durable) or set(chains) != set(manifest["chainIds"]):
            raise ValueError("mixed chain intent changed")
        projections = project_mixed_initial_chains(manifest, chains, seal["reviewedPolicy"])
        selected = [item for item in projections if item.chain.middle_provider == "linode"]
        if len(selected) != 1 or len(selected[0].chain.nodes) != 2:
            raise ValueError("Linode diagnostic projection differs")
        projection = selected[0]
        expected = [row for row in manifest["nodes"] if row["chainId"] == projection.chain.chain_id]
        if len(expected) != 2 or [row["role"] for row in expected] != ["middle", "edge"]:
            raise ValueError("bound Linode node set differs")
        trust = core_known_hosts(core)
        if (not isinstance(trust, tuple) or len(trust) != 2
                or not isinstance(trust[0], str) or not isinstance(trust[1], str)):
            raise ValueError("pinned core trust is unavailable")
        generation = job_event_digest(parent.events)

        def fence() -> str:
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            active, _ = active_core_connection_details(jobs, engagement_id)
            if (active != core.id or jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or jobs.get(binding.id) != binding or jobs.get(worker.id) != worker
                    or any(jobs.get(children[name].id) != children[name] for name in order)
                    or tuple(sketches.list_for_engagement(engagement_id)) != durable
                    or core_known_hosts(core) != trust):
                raise ValueError("mixed diagnostic authority changed")
            return generation

        def observe(provider: str) -> ProviderHostObservation:
            if fresh_observer is not None:
                return fresh_observer(parent, provider, fence)
            terminal = recognize_mixed_initial_apply_terminal(
                children[provider], parent, provider)
            workspace = _prior_workspace(parent, provider, terminal)
            classified = prove_mixed_initial_prior_provider_fresh(
                parent, children[provider], workspace, fence=fence,
                process_quiescent=lambda identity: _process_quiescent(
                    identity["bootId"], identity["pid"], identity["pgid"],
                    identity["startTicks"]),
            )
            fence()
            raw = _read_regular(workspace.state_path)
            fence()
            return ProviderHostObservation(classified, raw)

        def rebind() -> None:
            fence()
            observed = {}
            for provider in order:
                fence()
                observed[provider] = observe(provider)
                fence()
            rebuilt = build_mixed_initial_host_binding(
                parent, core, core.id, children, chains, observed)
            if rebuilt != manifest:
                raise ValueError("fresh four-node provider binding changed")
            fence()

        rebind()
        terminal = recognize_mixed_initial_apply_terminal(children["linode"], parent, "linode")
        workspace = _prior_workspace(parent, "linode", terminal)
        queued = StoredJobRun(
            diagnostic_id, ("provider_keyed_mixed_linode_raw_diagnostic" if collect_raw else ACTION),
            "queued", f"engagement:{engagement_id}", "engagement",
            engagement_id, parent.requested_by,
            {"engagementId": engagement_id, "coreJobId": core_job_id,
             "corePlanId": parent.input["corePlanId"], "mixedParentId": parent.id,
             "handoffJournalSha256": job_event_digest(parent.events),
             "bindingJobId": binding.id,
             "bindingManifestSha256": binding.input["manifestSha256"],
             "bootstrapJobId": worker.id,
             "bootstrapJournalSha256": job_event_digest(worker.events),
             "mutation": False},
            [], _now(), None, None,
            [JobEvent(1, "info", "Linode diagnostic reserved",
                      {"bindingManifestSha256": binding.input["manifestSha256"]})],
        )
        recovered_scratch = None
        if recovery:
            recovered_scratch = _precommand_recovery_scratch(
                prior, queued, expected[0], workspace.path)
            if jobs.get(diagnostic_id) != prior:
                raise ValueError("Linode diagnostic recovery row changed")
            token = uuid4().hex
            at = _now()
            expires_at = _later(at)
            current = jobs.claim_lease(diagnostic_id, owner=_OWNER, token=token,
                                       claimed_at=at, expires_at=expires_at,
                                       eligible_statuses={"running"})
            expected_input = {**prior.input, "claimOwner": _OWNER,
                              "claimToken": token, "claimClaimedAt": at,
                              "claimHeartbeatAt": at, "claimExpiresAt": expires_at}
            if (current is None or current.events != prior.events
                    or current.input != expected_input
                    or replace(current, input=prior.input) != prior):
                raise ValueError("Linode diagnostic recovery claim was not retained")
        else:
            saved = jobs.save_if_absent(queued)
            if (prior is None and not _same_inserted_job(saved, queued)
                    or prior is not None and (saved != prior
                        or not _same_unstarted_reservation(saved, queued))):
                raise ValueError("Linode diagnostic reservation raced")
            start_event = JobEvent(2, "info", "Linode diagnostic started", {})
            current = jobs.start_if_queued(saved, started_at=_now(), event=start_event)
            if (current is None or current.status != "running"
                    or current.events != [*saved.events, start_event]
                    or current.input != saved.input):
                raise ValueError("Linode diagnostic start was not retained")
            token = uuid4().hex
            at = _now()
            current = jobs.claim_lease(diagnostic_id, owner=_OWNER, token=token,
                                       claimed_at=at, expires_at=_later(at),
                                       eligible_statuses={"running"})
            if current is None:
                raise ValueError("Linode diagnostic claim was not retained")

        def renew() -> None:
            nonlocal current
            fence()
            at = _now()
            updated = jobs.renew_lease(diagnostic_id, owner=_OWNER, token=token,
                                       heartbeat_at=at, expires_at=_later(at))
            if updated is None or updated.events != current.events:
                raise ValueError("Linode diagnostic claim lost")
            current = updated

        def append(message: str, data: dict) -> None:
            nonlocal current
            renew()
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                current, owner=_OWNER, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(current.events) + 1, "info", message, data))
            if updated is None:
                raise ValueError("Linode diagnostic journal lost")
            current = updated

        homebase, proxy = core_hosts(jobs, engagement_id, projection.chain.assigned_proxy,
                                     require_proxy_public_alias=True)
        middle, edges = _sketch_nodes(projection.chain, require_exact_roles=True)
        # The diagnostic uses only the selected operator route and the trust
        # file left by the one-shot bootstrap in the Linode state workspace.
        sketch_trust = workspace.path / ".barragan-sketch-known-hosts"
        from app.services.provider_keyed_initial_bootstrap import _sketch_file_snapshot
        sketch_sha = _sketch_file_snapshot(sketch_trust)[2]
        spec = SketchBootstrapSpec(
            homebase=homebase, proxy=proxy, middle=middle, edges=edges,
            admin_private_key_path=str(workspace.path / ".barragan-diagnostic-admin-key"),
            admin_public_key_path=str(workspace.path / ".barragan-diagnostic-admin-pub"),
            transport_public_key_path=str(workspace.path / ".barragan-diagnostic-transport-pub"),
            ssh_config_path=str(workspace.path / ".barragan-diagnostic-ssh-config"),
            upstream_root_playbook_path=str(workspace.path / ".barragan-diagnostic-playbook"),
            host_policies=projection.host_policies,
            proxy_egress_ip=projection.proxy_egress_ip,
            initial_sketch_known_hosts_path=str(sketch_trust),
            pinned_core_known_hosts_path=trust[0],
        )
        route = {"homebasePublicIp": homebase.host, "homebaseUser": homebase.user,
                 "proxyPrivateIp": proxy.host, "proxyPublicIp": proxy.host_key_alias,
                 "proxyUser": proxy.user, "coreSshKeyPath": homebase.ssh_private_key_path}
        identities = []
        for node in expected:
            # A slow first capture may outlive provider propagation or a
            # concurrent external change. Reprove all four IDs and addresses
            # before each new routed contact, never from the historical row.
            rebind()
            fields = {"hostname": node["hostname"],
                      "terraformAddress": node["terraformAddress"],
                      "providerInstanceId": node["providerInstanceId"]}
            resuming_first = recovered_scratch is not None and node is expected[0]
            if resuming_first:
                scratch = _precommand_recovery_scratch(
                    prior, queued, node, workspace.path)
                if scratch != recovered_scratch:
                    raise ValueError("Linode diagnostic scratch changed")
            else:
                scratch = workspace.path / f".barragan-linode-diagnostic-{uuid4().hex}"
                scratch.mkdir(mode=0o700)
                scratch.chmod(0o700)
            def on_scratch(value):
                if resuming_first:
                    renew()
                    if (value != str(scratch) or _precommand_recovery_scratch(
                            prior, queued, node, workspace.path) != scratch):
                        raise ValueError("Linode diagnostic recovery scratch differs")
                else:
                    append("Linode diagnostic scratch intended", {**fields, "scratchPath": value})
            def on_intent(value):
                append("Linode diagnostic command intended", {**fields,
                    "invocationId": value.invocation_id, "argvSha256": value.argv_sha256,
                    "scratchPath": value.scratch_path})
            def on_started(value):
                append("Linode diagnostic command started before GO", {**fields,
                    "invocationId": value.intent.invocation_id,
                    "bootId": value.identity.boot_id, "pid": value.identity.pid,
                    "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks})
            def on_result(value):
                append("Linode diagnostic command result fenced", {**fields,
                    "invocationId": value.started.intent.invocation_id,
                    "returnCode": value.returncode, "stdoutBytes": value.stdout_bytes,
                    "stderrBytes": value.stderr_bytes,
                    "stdoutTruncated": value.stdout_truncated,
                    "stderrTruncated": value.stderr_truncated})
            renew()
            observed = probe(
                manifest=manifest, manifest_sha256=binding.input["manifestSha256"],
                node=node, expected_image="linode/ubuntu24.04", ssh_spec=spec,
                reviewed_core_route=route, core_known_hosts_sha256=trust[1],
                sketch_known_hosts_sha256=sketch_sha, scratch_path=scratch,
                fence=renew, scratch_intent_callback=on_scratch,
                intent_callback=on_intent, started_callback=on_started,
                heartbeat_callback=lambda _value: renew(), result_callback=on_result,
                **({"collect_raw": True,
                    "runner": _diagnostic_raw_runner(
                        workspace=workspace.path, diagnostic_id=diagnostic_id,
                        role=node["role"], fence=renew)} if collect_raw else {}),
            )
            identity = observed.identity if type(observed) is LinodeRawHostCollection else observed
            if ((collect_raw and type(observed) is not LinodeRawHostCollection)
                    or (not collect_raw and type(observed) is not LinodeRawHostIdentity)
                    or type(identity) is not LinodeRawHostIdentity
                    or identity.manifest_sha256 != binding.input["manifestSha256"]
                    or identity.chain_id != node["chainId"]
                    or identity.terraform_address != node["terraformAddress"]
                    or identity.provider_instance_id != node["providerInstanceId"]
                    or identity.image != "linode/ubuntu24.04"
                    or identity.region != node["region"]
                    or identity.public_ipv4 != node["publicIp"]
                    or identity.hostname != node["hostname"]
                    or identity.core_known_hosts_sha256 != trust[1]
                    or identity.sketch_known_hosts_sha256 != sketch_sha
                    or identity.ssh_connection[0] != (
                        projection.proxy_egress_ip if node["role"] == "middle"
                        else expected[0]["publicIp"])
                    or identity.ssh_connection[2:] != (node["publicIp"], 22)):
                raise ValueError("Linode metadata observation differs")
            identities.append(identity)
            evidence = {}
            if collect_raw:
                # The payload includes authorized keys and SSH configuration.
                # Keep it in a private file, never in the job/API event log.
                raw_path = workspace.path / f".barragan-linode-raw-{diagnostic_id}-{node['role']}.json"
                payload = json.dumps(asdict(observed), sort_keys=True, separators=(",", ":")).encode()
                if len(payload) > 2_500_000:
                    raise ValueError("Linode raw evidence exceeds private bound")
                fd = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    offset = 0
                    while offset < len(payload):
                        count = os.write(fd, payload[offset:])
                        if count <= 0:
                            raise OSError("Linode raw evidence write was incomplete")
                        offset += count
                    os.fsync(fd)
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600):
                        raise ValueError("Linode raw evidence file is unsafe")
                finally:
                    os.close(fd)
                evidence = {"evidencePath": str(raw_path),
                            "evidenceSha256": hashlib.sha256(payload).hexdigest()}
            scratch.rmdir()
            append("Linode diagnostic identity captured", {
                **fields, "identitySha256": _sha(asdict(identity)), **evidence})
        renew()
        _verify_command_journal(current.events, expected, identities, collect_raw=collect_raw)
        if collect_raw:
            captured = [event for event in current.events
                        if event.message == "Linode diagnostic identity captured"]
            if len(captured) != len(expected):
                raise ValueError("Linode raw evidence journal differs")
            for node, event in zip(expected, captured):
                path = workspace.path / f".barragan-linode-raw-{diagnostic_id}-{node['role']}.json"
                if event.data.get("evidencePath") != str(path):
                    raise ValueError("Linode raw evidence path differs")
                renew()
                _verify_private_raw_evidence(path, event.data.get("evidenceSha256"))
                renew()
        finished = jobs.finish_if_running_claimed(
            current, owner=_OWNER, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(current.events) + 1, "info",
                           ("Linode raw diagnostic complete; strict policy pending" if collect_raw
                            else "Linode identity diagnostic complete; strict policy pending"),
                           {"identitySha256": _sha([asdict(row) for row in identities]),
                            "hostnames": [row.hostname for row in identities]}))
        if finished is None:
            raise ValueError("Linode diagnostic terminal write lost")
        return finished
    except Exception as exc:
        raise MixedLinodeDiagnosticAttention(
            "mixed Linode identity diagnostic stopped; no host contact may be replayed"
        ) from exc
