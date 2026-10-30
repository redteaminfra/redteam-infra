# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot mixed Sketch bootstrap through the operator management path.

The worker stops after upstream bootstrap and transport installation. Strict
raw host proof and publication are separate gates. A created worker is never
restarted across host contact, even if its claim expires.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping
from uuid import uuid4

from app.services.bootstrap_command_evidence import bootstrap_command_timing
from app.domain import JobEvent
from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_gated_runner import CommandResult, UnreapedGatedCommandError, run_gated_command
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_initial_bootstrap import _clean_scratch_result
from app.services.provider_keyed_core_destroy_preview import _read_regular
from app.services.provider_keyed_host_binding import _core_known_hosts, _empty_known_hosts
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as _apply_child_id, _prior_workspace,
    recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_coordinator import (
    _core_matches, recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_initial_apply_proof import prove_mixed_initial_prior_provider_fresh
from app.services.provider_keyed_mixed_initial_host_binding import (
    ProviderHostObservation, _binding_child_id, _same_inserted_job,
    build_mixed_initial_host_binding,
    recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_initial_projection import project_mixed_initial_chains
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease, reviewed_mixed_chain_rows
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_bootstrap_apply import (
    SketchBootstrapApplyResult, SketchBootstrapTimeoutError, BOOTSTRAP_COMMAND_TIMEOUT_SECONDS,
    BOOTSTRAP_TIMEOUT_MESSAGE, apply_sketch_bootstrap, require_pinned_sketch_ansible_source,
)
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


ACTION = "provider_keyed_mixed_initial_host_worker"
_OWNER = f"mixed-host-bootstrap-{uuid4().hex}"
_PHASES = (
    ("readiness", "wait_for_sketch_readiness.yml"),
    ("root", "upstream-sketch-playbook.compat.yml"),
    ("user_readiness", "wait_for_sketch_user_readiness.yml"),
    ("transport", "install_sketch_transport.yml"),
)


class MixedInitialBootstrapAttention(ValueError):
    """A host command may have run; never replay this worker."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(now: str) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=120)).isoformat()


def _worker_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-host-worker-{core_job_id.removeprefix('job-')}"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_mixed_initial_bootstrap(
    engagement_id: str, core_job_id: str, *, environment: str,
    bootstrap_env: Mapping[str, str],
    fresh_observer: Callable[[StoredJobRun, str, Callable[[], str]], ProviderHostObservation] | None = None,
    job_repository=None, sketch_repository=None, lease_lookup=None,
    bootstrap_helper: Callable = apply_sketch_bootstrap,
    gated_command_runner: Callable = run_gated_command,
    source_verifier: Callable = require_pinned_sketch_ansible_source,
    core_known_hosts_reader: Callable = _core_known_hosts,
    sketch_known_hosts_initializer: Callable = _empty_known_hosts,
) -> StoredJobRun:
    """Run two exact upstream chain bootstraps once, with fenced commands."""
    if environment != "devtest" or not engagement_id or not core_job_id:
        raise MixedInitialBootstrapAttention("mixed bootstrap is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    worker_id = _worker_id(core_job_id)
    try:
        parent = jobs.get(_parent_id(core_job_id))
        core = jobs.get(core_job_id)
        if (parent is None or core is None or parent.target_id != engagement_id
                or parent.input.get("phase") != "awaiting_mixed_host_proof"
                or parent.status != "running" or parent.finished_at is not None):
            raise ValueError("mixed host handoff is unavailable")
        seal = validate_mixed_initial_apply_seal(parent)
        order = seal["orderedProviders"]
        children = {provider: jobs.get(_apply_child_id(core_job_id, provider)) for provider in order}
        binding = jobs.get(_binding_child_id(core_job_id))
        manifest = recognize_mixed_initial_host_binding(binding, parent)
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        recognize_mixed_initial_host_proof_handoff(parent, core, active_id, children)
        if not _core_matches(parent, core, active_id):
            raise ValueError("active core differs")
        _require_lease(lookup, engagement_id, parent.input["corePlanId"])
        if jobs.get(worker_id) is not None:
            raise ValueError("mixed host worker already exists; no replay")
        durable = sketches.list_for_engagement(engagement_id)
        chains = {chain.chain_id: chain for chain in reviewed_mixed_chain_rows(
            durable, seal["chainIds"], engagement_id)}
        generation = _digest({"parent": job_event_digest(parent.events),
                              "children": [job_event_digest(children[p].events) for p in order],
                              "binding": job_event_digest(binding.events)})

        def observe(parent_row, provider, source_fence):
            terminal = recognize_mixed_initial_apply_terminal(
                children[provider], parent_row, provider)
            workspace = _prior_workspace(parent_row, provider, terminal)
            classified = prove_mixed_initial_prior_provider_fresh(
                parent_row, children[provider], workspace, fence=source_fence,
                process_quiescent=lambda identity: _process_quiescent(
                    identity["bootId"], identity["pid"], identity["pgid"],
                    identity["startTicks"]),
            )
            source_fence()
            raw = _read_regular(workspace.state_path)
            source_fence()
            return ProviderHostObservation(classified, raw)

        observe_provider = fresh_observer or observe

        def source_fence() -> str:
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            active, _ = active_core_connection_details(jobs, engagement_id)
            if (active != core.id or jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or jobs.get(binding.id) != binding or jobs.get(worker_id) is not None
                    or any(jobs.get(children[p].id) != children[p] for p in order)
                    or sketches.list_for_engagement(engagement_id) != durable):
                raise ValueError("mixed host source changed before contact")
            return generation

        observations = {}
        for provider in order:
            source_fence()
            observations[provider] = observe_provider(parent, provider, source_fence)
            source_fence()
        fresh_manifest = build_mixed_initial_host_binding(
            parent, core, core.id, children, chains, observations)
        if fresh_manifest != manifest or source_fence() != generation:
            raise ValueError("mixed host state changed from bound intent")
        projected = project_mixed_initial_chains(manifest, chains, seal["reviewedPolicy"])
        core_hosts = core_known_hosts_reader(core)
        if (not isinstance(core_hosts, tuple) or len(core_hosts) != 2
                or not isinstance(core_hosts[0], str) or not isinstance(core_hosts[1], str)
                or not isinstance(bootstrap_env, Mapping)
                or not isinstance(bootstrap_env.get(TEMPLATE_ROOT_ENV), str)):
            raise ValueError("pinned host bootstrap source is unavailable")
        source_root = Path(bootstrap_env[TEMPLATE_ROOT_ENV])
        workspaces = {}
        for provider in order:
            terminal = recognize_mixed_initial_apply_terminal(children[provider], parent, provider)
            workspace = _prior_workspace(parent, provider, terminal)
            source_verifier(env=bootstrap_env, required_source_root=source_root,
                            required_source_revision=workspace.source_revision)
            workspaces[provider] = workspace
        source_fence()
        binding_sha = binding.input["manifestSha256"]
        base = {
            "engagementId": engagement_id, "coreJobId": core_job_id,
            "corePlanId": parent.input["corePlanId"], "mixedParentId": parent.id,
            "handoffJournalSha256": job_event_digest(parent.events),
            "bindingJobId": binding.id, "bindingManifestSha256": binding_sha,
            "mutation": True,
        }
        queued = StoredJobRun(
            worker_id, ACTION, "queued", f"engagement:{engagement_id}", "engagement",
            engagement_id, parent.requested_by, base, [], _now(), None, None,
            [JobEvent(1, "info", "mixed host worker queued", {"bindingManifestSha256": binding_sha})],
        )
        current = jobs.save_if_absent(queued)
        if not _same_inserted_job(current, queued):
            raise ValueError("mixed worker reservation raced")
        current = jobs.start_if_queued(current, started_at=_now(),
                                       event=JobEvent(2, "info", "mixed host worker started", {}))
        if current is None:
            raise ValueError("mixed worker start was not retained")
        token = uuid4().hex
        at = _now()
        current = jobs.claim_lease(worker_id, owner=_OWNER, token=token,
                                   claimed_at=at, expires_at=_later(at),
                                   eligible_statuses={"running"})
        if current is None:
            raise ValueError("mixed worker claim was not retained")

        def fence() -> None:
            nonlocal current
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            if core_known_hosts_reader(core) != core_hosts:
                raise ValueError("pinned core known-hosts changed")
            active, _ = active_core_connection_details(jobs, engagement_id)
            if (active != core.id or jobs.get(parent.id) != parent or jobs.get(core.id) != core
                    or jobs.get(binding.id) != binding
                    or any(jobs.get(children[p].id) != children[p] for p in order)
                    or sketches.list_for_engagement(engagement_id) != durable
                    or jobs.get(worker_id) != current):
                raise ValueError("mixed host worker authority changed")
            at = _now()
            renewed = jobs.renew_lease(worker_id, owner=_OWNER, token=token,
                                       heartbeat_at=at, expires_at=_later(at))
            if renewed is None or renewed.events != current.events:
                raise ValueError("mixed host worker claim was lost")
            current = renewed

        def append(message: str, data: dict) -> None:
            nonlocal current
            fence()
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                current, owner=_OWNER, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(current.events) + 1, "info", message, data))
            if updated is None:
                raise ValueError("mixed host worker journal CAS lost")
            current = updated

        append("mixed host contact intended", {
            "bindingManifestSha256": binding_sha,
            "nodeAddresses": [node["terraformAddress"] for node in manifest["nodes"]],
        })
        for provider, projection in zip(order, projected):
            workspace = workspaces[provider]
            known_hosts = workspace.path / ".barragan-sketch-known-hosts"
            sketch_known_hosts_initializer(known_hosts, adopt=False)
            scratch = workspace.path / f".barragan-mixed-bootstrap-{uuid4().hex}"
            completed = []
            attempts = {}
            first_contact = False

            def reporter(status: str, data: dict) -> None:
                nonlocal first_contact
                fence()
                if (status == "checking" and data.get("phase") == "root-management-readiness"
                        and not first_contact):
                    append("mixed chain first contact fenced", {"provider": provider,
                                                                  "chainId": projection.chain.chain_id})
                    first_contact = True

            def command_runner(command: list[str], cwd: Path | None, command_env: Mapping[str, str]):
                if cwd != scratch:
                    raise ValueError("mixed bootstrap command scratch differs")
                names = [str(value) for value in command]
                matching = [name for name, path in _PHASES if any(value.endswith(path) for value in names)]
                if len(matching) != 1:
                    raise ValueError("mixed bootstrap command phase differs")
                phase = matching[0]
                index = [name for name, _ in _PHASES].index(phase)
                if index != len(completed):
                    raise ValueError("mixed bootstrap command order differs")
                attempt = attempts.get(phase, 0) + 1
                attempts[phase] = attempt
                fields = {"provider": provider, "chainId": projection.chain.chain_id,
                          "phase": phase, "attempt": attempt}
                record = {"intent": None, "started": None, "result": None}

                def on_intent(value):
                    if record["intent"] is not None or value.scratch_path != str(scratch):
                        raise ValueError("mixed bootstrap intent differs")
                    append("mixed bootstrap command intended", {
                        **fields, "invocationId": value.invocation_id,
                        "argvSha256": value.argv_sha256, "scratchPath": value.scratch_path})
                    record["intent"] = value

                def on_started(value):
                    if (record["intent"] is None or record["started"] is not None
                            or value.intent != record["intent"]):
                        raise ValueError("mixed bootstrap start differs")
                    identity = value.identity
                    append("mixed bootstrap command started before GO", {
                        **fields, "invocationId": value.intent.invocation_id,
                        "bootId": identity.boot_id, "pid": identity.pid,
                        "pgid": identity.pgid, "startTicks": identity.start_ticks})
                    record["started"] = value

                def on_result(value):
                    if (record["started"] is None or record["result"] is not None
                            or value.started != record["started"]):
                        raise ValueError("mixed bootstrap result differs")
                    append("mixed bootstrap command result fenced", {
                        **fields, "invocationId": value.started.intent.invocation_id,
                        "returnCode": value.returncode,
                        "stdoutBytes": value.stdout_bytes, "stderrBytes": value.stderr_bytes,
                        "stdoutTruncated": value.stdout_truncated,
                        "stderrTruncated": value.stderr_truncated, **bootstrap_command_timing(value)})
                    record["result"] = value

                def on_heartbeat(value):
                    if record["started"] is None or record["result"] is not None or value != record["started"]:
                        raise ValueError("mixed bootstrap command heartbeat differs")
                    fence()

                fence()
                outcome = gated_command_runner(
                    command, execution_timeout_seconds=BOOTSTRAP_COMMAND_TIMEOUT_SECONDS, scratch_path=scratch, provider_keyed_v2=True,
                    env=dict(command_env), intent_callback=on_intent,
                    started_callback=on_started, heartbeat_callback=on_heartbeat,
                    result_callback=on_result)
                if (not isinstance(outcome, CommandResult) or record["result"] is None
                        or outcome.started != record["started"]
                        or record["result"].timed_out is not False
                        or outcome.returncode != record["result"].returncode
                        or outcome.stdout_truncated or outcome.stderr_truncated):
                    raise ValueError("mixed bootstrap command result is incomplete")
                if outcome.returncode == 0:
                    completed.append(phase)
                return subprocess.CompletedProcess(command, outcome.returncode,
                                                   outcome.stdout, outcome.stderr)

            fence()
            result = bootstrap_helper(
                engagement_id, projection.chain, repository=jobs,
                env=bootstrap_env, workspace_root=scratch,
                host_policies=projection.host_policies,
                proxy_egress_ip=projection.proxy_egress_ip,
                initial_sketch_known_hosts_path=known_hosts,
                pinned_core_known_hosts_path=Path(core_hosts[0]),
                progress_reporter=reporter, runner=command_runner,
                required_source_root=source_root,
                required_source_revision=workspace.source_revision,
            )
            if (not isinstance(result, SketchBootstrapApplyResult)
                    or not first_contact
                    or completed != [name for name, _ in _PHASES]
                    or result.node_count != 2 or result.root_returncode != 0
                    or result.user_readiness_returncode != 0
                    or result.transport_returncode != 0):
                raise ValueError("mixed chain bootstrap result is incomplete")
            _clean_scratch_result(scratch)
            append("mixed chain bootstrap completed", {
                "provider": provider, "chainId": projection.chain.chain_id,
                "nodeAddresses": [node["terraformAddress"] for node in manifest["nodes"]
                                  if node["chainId"] == projection.chain.chain_id],
            })
        fence()
        finished = jobs.finish_if_running_claimed(
            current, owner=_OWNER, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(current.events) + 1, "info",
                           "mixed bootstrap completed; strict raw proof pending",
                           {"bindingManifestSha256": binding_sha,
                            "chainIds": list(manifest["chainIds"])}))
        if finished is None:
            raise ValueError("mixed bootstrap terminal CAS lost")
        return finished
    except (SketchBootstrapTimeoutError, UnreapedGatedCommandError) as exc:
        timed_out = isinstance(exc, SketchBootstrapTimeoutError)
        try:
            append("mixed bootstrap reconciliation required", {
                "bootstrap": "reconciliation_required", "timedOut": timed_out,
                "localQuiescenceUnproved": not timed_out,
            })
        except Exception:
            pass  # Preserve the uncertain-command outcome if the audit fence was lost.
        message = (BOOTSTRAP_TIMEOUT_MESSAGE if timed_out else
                   "local bootstrap process-group quiescence unproved; staged keys retained; reconciliation required")
        raise MixedInitialBootstrapAttention(message) from exc
    except Exception as exc:
        raise MixedInitialBootstrapAttention(
            "mixed bootstrap stopped; no host command may be replayed") from exc
