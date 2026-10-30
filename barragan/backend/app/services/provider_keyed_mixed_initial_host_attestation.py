# Copyright (c) 2026, Oracle and/or its affiliates.
"""Read-only proof that a mixed host worker finished every fenced command."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable, Mapping

from app.services.bootstrap_command_evidence import valid_bootstrap_result_keys
from app.domain import JobEvent
from app.services.provider_keyed_mixed_initial_bootstrap import ACTION, _PHASES, _worker_id
from app.services.provider_keyed_mixed_initial_coordinator import recognize_mixed_initial_host_proof_handoff
from app.services.provider_keyed_mixed_initial_host_binding import recognize_mixed_initial_host_binding
from app.storage.job_repository import StoredJobRun, job_event_digest


_HASH = re.compile(r"[0-9a-f]{64}\Z")


class MixedHostAttestationAttention(ValueError):
    """The one-shot host worker is active, incomplete, or differs from its binding."""


_CLAIM_KEYS = {"claimOwner", "claimToken", "claimClaimedAt", "claimHeartbeatAt",
               "claimExpiresAt"}


def recognize_safe_incomplete_mixed_host_worker(
    initial: StoredJobRun, core: StoredJobRun,
    children: Mapping[str, StoredJobRun], binding: StoredJobRun | None,
    worker: StoredJobRun | None, active_core_id: str,
    *, process_quiescent: Callable[[dict], bool],
) -> str | None:
    """Prove a stopped one-shot prefix; never infer that host commands succeeded."""
    try:
        recognize_mixed_initial_host_proof_handoff(initial, core, active_core_id, children)
        # Bootstrap cannot reserve a worker or contact a host until its inert
        # binding exists. Exact absence of both rows is therefore pre-GO.
        if binding is None:
            if worker is not None:
                raise ValueError("mixed host worker lacks its binding")
            return None
        manifest = recognize_mixed_initial_host_binding(binding, initial)
        if worker is None:
            return None
        binding_sha = binding.input["manifestSha256"]
        base = {
            "engagementId": initial.target_id, "coreJobId": core.id,
            "corePlanId": initial.input["corePlanId"], "mixedParentId": initial.id,
            "handoffJournalSha256": job_event_digest(initial.events),
            "bindingJobId": binding.id, "bindingManifestSha256": binding_sha,
            "mutation": True,
        }
        if worker.status == "succeeded":
            return recognize_completed_mixed_host_worker(
                initial, core, children, binding, worker, active_core_id,
                process_quiescent=process_quiescent)
        if (worker.id != _worker_id(core.id) or worker.action != ACTION
                or worker.target != initial.target or worker.target_type != "engagement"
                or worker.target_id != initial.target_id
                or worker.requested_by != initial.requested_by
                or worker.artifact_refs != [] or not isinstance(worker.events, list)
                or len(worker.events) > 512 or not worker.events):
            raise ValueError("mixed host worker identity differs")
        if worker.status == "queued":
            if (worker.input != base or worker.started_at is not None
                    or worker.finished_at is not None or worker.events != [
                        JobEvent(1, "info", "mixed host worker queued",
                                 {"bindingManifestSha256": binding_sha})]):
                raise ValueError("mixed queued host worker differs")
            return job_event_digest(worker.events)
        if worker.status == "running":
            data = worker.input
            if (type(data) is not dict or set(data) != set(base) | _CLAIM_KEYS
                    or any(data.get(key) != value for key, value in base.items())
                    or type(data["claimOwner"]) is not str
                    or not data["claimOwner"].startswith("mixed-host-bootstrap-")
                    or type(data["claimToken"]) is not str
                    or re.fullmatch(r"[0-9a-f]{32}", data["claimToken"]) is None
                    or worker.started_at is None or worker.finished_at is not None):
                raise ValueError("mixed running host claim differs")
            times = [datetime.fromisoformat(data[key]) for key in
                     ("claimClaimedAt", "claimHeartbeatAt", "claimExpiresAt")]
            if (any(value.tzinfo is None for value in times)
                    or not (times[0] <= times[1] <= times[2] <= datetime.now(timezone.utc))):
                raise ValueError("mixed host claim is active or invalid")
        elif worker.status == "failed":
            if (worker.input != base or worker.started_at is None
                    or worker.finished_at is None):
                raise ValueError("mixed failed host worker differs")
        else:
            raise ValueError("mixed host worker status differs")
        rows = worker.events
        if any(row != JobEvent(index, "info", row.message, row.data)
               for index, row in enumerate(rows, 1)):
            raise ValueError("mixed host worker sequence differs")
        expected = [
            JobEvent(1, "info", "mixed host worker queued",
                     {"bindingManifestSha256": binding_sha}),
            JobEvent(2, "info", "mixed host worker started", {}),
            JobEvent(3, "info", "mixed host contact intended", {
                "bindingManifestSha256": binding_sha,
                "nodeAddresses": [node["terraformAddress"] for node in manifest["nodes"]]}),
        ]
        if rows[:min(len(rows), 3)] != expected[:min(len(rows), 3)] or len(rows) < 2:
            raise ValueError("mixed host prefix differs")
        if len(rows) == 2:
            return job_event_digest(rows)
        cursor = 3
        scratch_paths: set[str] = set()
        invocations: set[str] = set()
        for provider, chain_id in zip(manifest["orderedProviders"], manifest["chainIds"], strict=True):
            if cursor == len(rows):
                return job_event_digest(rows)
            if rows[cursor] != JobEvent(cursor + 1, "info", "mixed chain first contact fenced",
                                       {"provider": provider, "chainId": chain_id}):
                raise ValueError("mixed chain contact differs")
            cursor += 1
            chain_scratch = None
            for phase, _ in _PHASES:
                attempt = 0
                while True:
                    if cursor == len(rows):
                        return job_event_digest(rows)
                    attempt += 1
                    if attempt > 100:
                        raise ValueError("mixed host attempts exceed bound")
                    fields = {"provider": provider, "chainId": chain_id,
                              "phase": phase, "attempt": attempt}
                    intent = rows[cursor]
                    data = intent.data
                    if (intent.message != "mixed bootstrap command intended"
                            or type(data) is not dict
                            or set(data) != {*fields, "invocationId", "argvSha256", "scratchPath"}
                            or any(data[key] != value for key, value in fields.items())
                            or type(data["invocationId"]) is not str
                            or not data["invocationId"] or data["invocationId"] in invocations
                            or type(data["argvSha256"]) is not str
                            or _HASH.fullmatch(data["argvSha256"]) is None
                            or type(data["scratchPath"]) is not str
                            or not data["scratchPath"].startswith("/")):
                        raise ValueError("mixed command intent differs")
                    invocations.add(data["invocationId"])
                    scratch = data["scratchPath"]
                    if chain_scratch is None:
                        chain_scratch = scratch
                        if scratch in scratch_paths:
                            raise ValueError("mixed chain scratch repeats")
                        scratch_paths.add(scratch)
                    elif scratch != chain_scratch:
                        raise ValueError("mixed chain scratch changed")
                    cursor += 1
                    if cursor == len(rows):
                        return job_event_digest(rows)
                    started = rows[cursor]
                    identity = {key: started.data.get(key) for key in
                                ("bootId", "pid", "pgid", "startTicks")}
                    if (started.message != "mixed bootstrap command started before GO"
                            or type(started.data) is not dict
                            or set(started.data) != {*fields, "invocationId", *identity}
                            or any(started.data[key] != value for key, value in fields.items())
                            or started.data["invocationId"] != data["invocationId"]
                            or type(identity["bootId"]) is not str or not identity["bootId"]
                            or any(type(identity[key]) is not int or identity[key] <= 0
                                   for key in ("pid", "pgid", "startTicks"))
                            or process_quiescent(identity) is not True):
                        raise ValueError("mixed host command process is uncertain")
                    cursor += 1
                    if cursor == len(rows):
                        return job_event_digest(rows)
                    result = rows[cursor]
                    result_data = result.data
                    if (result.message != "mixed bootstrap command result fenced"
                            or type(result_data) is not dict
                            or not valid_bootstrap_result_keys(result_data, {*fields, "invocationId", "returnCode",
                                                    "stdoutBytes", "stderrBytes",
                                                    "stdoutTruncated", "stderrTruncated"})
                            or any(result_data[key] != value for key, value in fields.items())
                            or result_data["invocationId"] != data["invocationId"]
                            or type(result_data["returnCode"]) is not int
                            or any(type(result_data[key]) is not int or result_data[key] < 0
                                   for key in ("stdoutBytes", "stderrBytes"))
                            or any(type(result_data[key]) is not bool
                                   for key in ("stdoutTruncated", "stderrTruncated"))):
                        raise ValueError("mixed host command result differs")
                    cursor += 1
                    if result_data.get("timedOut", False):
                        # The real worker may append its one sanitized stop marker.
                        # It is evidence of uncertainty, never another phase or retry.
                        suffix = [JobEvent(cursor + 1, "info", "mixed bootstrap reconciliation required", {
                            "bootstrap": "reconciliation_required", "timedOut": True,
                            "localQuiescenceUnproved": False,
                        })]
                        if (rows[cursor:] not in ([], suffix) or cursor < len(rows) and (
                                type(rows[cursor].data) is not dict
                                or rows[cursor].data.get("timedOut") is not True
                                or rows[cursor].data.get("localQuiescenceUnproved") is not False)):
                            raise ValueError("mixed host command followed timeout")
                        return job_event_digest(rows)
                    if result_data["returnCode"] == 0 and not result_data.get("timedOut", False) and not (
                            result_data["stdoutTruncated"] or result_data["stderrTruncated"]):
                        break
            if cursor == len(rows):
                return job_event_digest(rows)
            expected_nodes = [node["terraformAddress"] for node in manifest["nodes"]
                              if node["chainId"] == chain_id]
            if rows[cursor] != JobEvent(cursor + 1, "info", "mixed chain bootstrap completed", {
                    "provider": provider, "chainId": chain_id,
                    "nodeAddresses": expected_nodes}):
                raise ValueError("mixed chain completion differs")
            cursor += 1
        if cursor != len(rows):
            raise ValueError("nonterminal mixed host worker has a terminal event")
        return job_event_digest(rows)
    except Exception:
        raise MixedHostAttestationAttention("mixed host worker requires quiescent exact prefix") from None


def recognize_completed_mixed_host_worker(
    initial: StoredJobRun, core: StoredJobRun,
    children: Mapping[str, StoredJobRun], binding: StoredJobRun | None,
    worker: StoredJobRun | None, active_core_id: str,
    *, process_quiescent: Callable[[dict], bool],
) -> str:
    """Return immutable worker journal digest only after exact terminal bootstrap."""
    try:
        recognize_mixed_initial_host_proof_handoff(initial, core, active_core_id, children)
        manifest = recognize_mixed_initial_host_binding(binding, initial)
        binding_sha = binding.input["manifestSha256"]
        base = {
            "engagementId": initial.target_id, "coreJobId": core.id,
            "corePlanId": initial.input["corePlanId"], "mixedParentId": initial.id,
            "handoffJournalSha256": job_event_digest(initial.events),
            "bindingJobId": binding.id, "bindingManifestSha256": binding_sha,
            "mutation": True,
        }
        if (worker is None or worker.id != _worker_id(core.id) or worker.action != ACTION
                or worker.status != "succeeded" or worker.started_at is None
                or worker.finished_at is None or worker.artifact_refs != []
                or worker.target != initial.target or worker.target_type != "engagement"
                or worker.target_id != initial.target_id
                or worker.requested_by != initial.requested_by
                or worker.input != base
                or not isinstance(worker.events, list) or len(worker.events) > 512
                or len(worker.events) < 32):
            raise ValueError("mixed host worker identity or terminal status differs")
        rows = worker.events
        if any(row != JobEvent(index, "info", row.message, row.data)
               for index, row in enumerate(rows, 1)):
            raise ValueError("mixed host worker sequence differs")
        if rows[:3] != [
            JobEvent(1, "info", "mixed host worker queued",
                     {"bindingManifestSha256": binding_sha}),
            JobEvent(2, "info", "mixed host worker started", {}),
            JobEvent(3, "info", "mixed host contact intended", {
                "bindingManifestSha256": binding_sha,
                "nodeAddresses": [node["terraformAddress"] for node in manifest["nodes"]]}),
        ]:
            raise ValueError("mixed host contact journal differs")
        cursor = 3
        scratch_paths = set()
        for provider, chain_id in zip(manifest["orderedProviders"], manifest["chainIds"], strict=True):
            if rows[cursor] != JobEvent(cursor + 1, "info", "mixed chain first contact fenced",
                                       {"provider": provider, "chainId": chain_id}):
                raise ValueError("mixed chain contact journal differs")
            cursor += 1
            chain_scratch = None
            for phase, _ in _PHASES:
                attempt = 0
                while True:
                    attempt += 1
                    if attempt > 100 or cursor + 2 >= len(rows):
                        raise ValueError("mixed bootstrap command journal is incomplete")
                    intent, started, result = rows[cursor:cursor + 3]
                    fields = {"provider": provider, "chainId": chain_id,
                              "phase": phase, "attempt": attempt}
                    data = intent.data
                    if (intent.message != "mixed bootstrap command intended"
                            or type(data) is not dict
                            or set(data) != {*fields, "invocationId", "argvSha256", "scratchPath"}
                            or any(data[key] != value for key, value in fields.items())
                            or type(data["invocationId"]) is not str or not data["invocationId"]
                            or type(data["argvSha256"]) is not str
                            or _HASH.fullmatch(data["argvSha256"]) is None
                            or type(data["scratchPath"]) is not str
                            or not data["scratchPath"].startswith("/")):
                        raise ValueError("mixed command intent differs")
                    scratch = data["scratchPath"]
                    if chain_scratch is None:
                        chain_scratch = scratch
                        if scratch in scratch_paths:
                            raise ValueError("mixed chain scratch repeats")
                        scratch_paths.add(scratch)
                    elif scratch != chain_scratch:
                        raise ValueError("mixed chain scratch changed")
                    identity = {key: started.data.get(key) for key in
                                ("bootId", "pid", "pgid", "startTicks")}
                    if (started.message != "mixed bootstrap command started before GO"
                            or type(started.data) is not dict
                            or set(started.data) != {*fields, "invocationId", *identity}
                            or any(started.data[key] != value for key, value in fields.items())
                            or started.data["invocationId"] != data["invocationId"]
                            or type(identity["bootId"]) is not str or not identity["bootId"]
                            or any(type(identity[key]) is not int or identity[key] <= 0
                                   for key in ("pid", "pgid", "startTicks"))
                            or process_quiescent(identity) is not True):
                        raise ValueError("mixed host command process is uncertain")
                    result_data = result.data
                    if (result.message != "mixed bootstrap command result fenced"
                            or type(result_data) is not dict
                            or not valid_bootstrap_result_keys(result_data, {*fields, "invocationId", "returnCode",
                                                    "stdoutBytes", "stderrBytes",
                                                    "stdoutTruncated", "stderrTruncated"}, success=True)
                            or any(result_data[key] != value for key, value in fields.items())
                            or result_data["invocationId"] != data["invocationId"]
                            or type(result_data["returnCode"]) is not int
                            or any(type(result_data[key]) is not int or result_data[key] < 0
                                   for key in ("stdoutBytes", "stderrBytes"))
                            or result_data["stdoutTruncated"] is not False
                            or result_data["stderrTruncated"] is not False):
                        raise ValueError("mixed host command result differs")
                    cursor += 3
                    if result_data["returnCode"] == 0:
                        break
            expected_nodes = [node["terraformAddress"] for node in manifest["nodes"]
                              if node["chainId"] == chain_id]
            if rows[cursor] != JobEvent(cursor + 1, "info", "mixed chain bootstrap completed", {
                    "provider": provider, "chainId": chain_id,
                    "nodeAddresses": expected_nodes}):
                raise ValueError("mixed chain completion differs")
            cursor += 1
        if (cursor != len(rows) - 1 or rows[cursor] != JobEvent(
                cursor + 1, "info", "mixed bootstrap completed; strict raw proof pending", {
                    "bindingManifestSha256": binding_sha,
                    "chainIds": list(manifest["chainIds"])})):
            raise ValueError("mixed host terminal journal differs")
        return job_event_digest(rows)
    except Exception:
        raise MixedHostAttestationAttention("mixed host bootstrap requires exact terminal proof") from None
