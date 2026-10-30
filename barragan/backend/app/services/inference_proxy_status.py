# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bounded read-only service/discovery receipts for the current owned Homebase."""
from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import time
import tempfile
from typing import Any
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.services import inference_proxy_capability as capability
from app.services.capability_reconciliation import CONFLICTING_CORE_MUTATION_ACTIONS
from app.services.core_ssh import active_core_connection_details, CORE_DEPLOYMENT_ACTION, retained_core_known_hosts
from app.services.engagement_capabilities import capability_overrides_for_workspace
from app.services.engagement_operations import _core_identity
from app.services.engagement_workspaces import load_prepared_engagement_workspace
from app.services.engagements import get_engagement
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository, DeploymentPlanConflictError
from app.storage.engagement_workspace_repository import SqlAlchemyEngagementWorkspaceRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun

ACTION = "inference_proxy_status_check"
PROBE_TIMEOUT_SECONDS = 40
PROBE_OUTPUT_LIMIT = 16384
ERROR_CODES = {"oci_authorization_required", "oci_not_authorized_or_not_found", "oci_discovery_timeout", "oci_discovery_unavailable"}
DISCOVERY_STATUSES = {"discovering", "catalog_available", "no_eligible_models", "discovery_unavailable", "unknown"}


class InferenceProxyStatusError(ValueError):
    def __init__(self, message: str):
        super().__init__(message)
        self.errors = [message]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _binding(engagement_id, root, jobs, workspaces):
    try:
        return _binding_inputs(engagement_id, root, jobs, workspaces)
    except InferenceProxyStatusError:
        raise
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        raise InferenceProxyStatusError("Current Inference Proxy configuration or owned-core proof is unavailable.") from exc


def _binding_inputs(engagement_id, root, jobs, workspaces):
    workspace = load_prepared_engagement_workspace(engagement_id, root=root, repository=workspaces)
    if workspace is None or not capability.is_selected(capability_overrides_for_workspace(workspace)):
        raise InferenceProxyStatusError("Select and save Inference Proxy before checking its status.")
    config = capability.normalize_configuration(workspace.metadata.get(capability.CONFIGURATION_KEY), required=True)
    source = workspace.metadata.get(capability.SOURCE_KEY)
    if not isinstance(source, dict) or source.get("revision") != capability.SOURCE_REVISION or not re.fullmatch(r"[0-9a-f]{64}", str(source.get("sha256", ""))):
        raise InferenceProxyStatusError("Save the pinned Inference Proxy source before checking status.")
    core_id, details = active_core_connection_details(jobs, engagement_id)
    core = jobs.get(core_id) if core_id else None
    generations = [job for job in jobs.list_for_engagement(engagement_id) if job.action == CORE_DEPLOYMENT_ACTION and job.input.get("engagementId") == engagement_id]
    if core is None or core.status != "succeeded" or not generations or generations[0].id != core_id:
        raise InferenceProxyStatusError("A current successful core deployment is required.")
    history = jobs.list_for_engagement(engagement_id)
    core_index = next(i for i, row in enumerate(history) if row.id == core_id)
    if any(row.action == "engagement_comprehensive_teardown" for row in history[:core_index]):
        raise InferenceProxyStatusError("This core generation has entered teardown; its prior status is historical.")
    homebases = [row for row in details if row.get("role") == "homebase"]
    if len(homebases) != 1 or _core_identity(homebases[0], core) != ("homebase", core.input.get("resourceNames", {}).get("homebase")):
        raise InferenceProxyStatusError("Current Homebase ownership identity is unavailable or ambiguous.")
    homebase = homebases[0]
    host = str(homebase.get("publicIp", ""))
    ssh_user = str(homebase.get("sshUser") or "user")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", ssh_user):
        raise InferenceProxyStatusError("Current Homebase management user is invalid.")
    try:
        ipaddress.ip_address(host)
        known_hosts, trust_digest = retained_core_known_hosts(core)
    except (OSError, ValueError) as exc:
        raise InferenceProxyStatusError("Retained Homebase address or SSH host-key proof is unavailable; a new check cannot trust this host.") from exc
    target = core.input.get("target", {})
    compartment, region = target.get("compartmentId"), target.get("region")
    if not isinstance(compartment, str) or not re.fullmatch(r"ocid1\.compartment\.[a-z0-9-]+\.[a-z0-9.-]+", compartment) or not isinstance(region, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", region):
        raise InferenceProxyStatusError("Current core provider ownership scope is unavailable.")
    binding = {"engagementId": engagement_id, "coreDeploymentId": core_id,
        "homebaseName": homebase["displayName"], "homebaseIp": host, "sshUser": ssh_user,
        "coreCompartmentId": compartment, "coreRegion": region,
        "configuration": config, "source": {"revision": source["revision"], "sha256": source["sha256"]},
        "knownHostsSha256": trust_digest,
        "selectionFingerprint": workspace.metadata.get("capabilityApplyState", {}).get("selectionFingerprint", "")}
    return binding, known_hosts


def _conflicts(jobs, engagement_id, excluding=""):
    for job in jobs.list_for_engagement(engagement_id):
        if job.id != excluding and job.status in {"queued", "running"} and job.action in CONFLICTING_CORE_MUTATION_ACTIONS | {ACTION, "engagement_capability_apply"}:
            raise InferenceProxyStatusError("A core operation or status check is running; wait for it to finish.")


def get_inference_proxy_status(engagement_id, *, root: Path, repository=None, workspace_repository=None):
    if get_engagement(engagement_id) is None:
        return None
    jobs = repository or SqlAlchemyJobRepository()
    workspaces = workspace_repository or SqlAlchemyEngagementWorkspaceRepository()
    state = {"status": "not_checked", "configuration": None, "bindingFingerprint": None, "homebaseIdentity": None, "observation": None, "job": None, "errors": []}
    try:
        binding, _ = _binding(engagement_id, root, jobs, workspaces)
        fingerprint = _fingerprint(binding)
        state["bindingFingerprint"] = fingerprint
        state["configuration"] = binding["configuration"]
    except (InferenceProxyStatusError, capability.InferenceProxyConfigurationError, ValueError) as exc:
        state.update(status="blocked", errors=getattr(exc, "errors", ["Current Inference Proxy configuration or core proof is unavailable."]))
        return state
    latest = next((job for job in jobs.list_for_engagement(engagement_id) if job.action == ACTION and job.input.get("bindingFingerprint") == fingerprint), None)
    if latest is not None:
        state["job"] = latest.to_detail().to_dict()
        state["status"] = "checking" if latest.status in {"queued", "running"} else "checked" if latest.status == "succeeded" else "failed"
        if latest.status == "succeeded":
            receipt = latest.events[-1].data
            state["observation"] = receipt.get("observation")
            state["homebaseIdentity"] = receipt.get("homebaseIdentity")
        elif latest.status == "failed":
            state["errors"] = ["Status could not be verified. Check the service installation, retained SSH access and current configuration, then retry."]
    return state


def start_inference_proxy_status(engagement_id, body, *, root: Path, repository=None, workspace_repository=None, lease_repository=None, runner=None, background_runner=None, requested_by="operator"):
    if get_engagement(engagement_id) is None:
        return None
    jobs = repository or SqlAlchemyJobRepository()
    workspaces = workspace_repository or SqlAlchemyEngagementWorkspaceRepository()
    leases = lease_repository if lease_repository is not None else SqlAlchemyDeploymentPlanRepository()
    binding, known_hosts = _binding(engagement_id, root, jobs, workspaces)
    fingerprint = _fingerprint(binding)
    if not isinstance(body, dict) or set(body) != {"bindingFingerprint"} or body.get("bindingFingerprint") != fingerprint:
        raise InferenceProxyStatusError("Status inputs changed; reload the current status before checking again.")
    _conflicts(jobs, engagement_id)
    job_id = "job-" + uuid4().hex[:12]
    try:
        acquired = leases.acquire(engagement_id, job_id, ACTION)
        if acquired is not True:
            raise InferenceProxyStatusError("A fresh status-check lease could not be acquired; reload and retry.")
    except DeploymentPlanConflictError as exc:
        raise InferenceProxyStatusError("A core operation is running; wait for it to finish.") from exc
    try:
        _conflicts(jobs, engagement_id)
        if _fingerprint(_binding(engagement_id, root, jobs, workspaces)[0]) != fingerprint:
            raise InferenceProxyStatusError("Status inputs changed before scheduling; reload and retry.")
        job = StoredJobRun(id=job_id, action=ACTION, status="queued", target="engagement:" + engagement_id,
            target_type="engagement", target_id=engagement_id, requested_by=requested_by,
            input={"engagementId": engagement_id, "coreDeploymentId": binding["coreDeploymentId"], "bindingFingerprint": fingerprint, "mutation": False},
            artifact_refs=[], created_at=_now(), started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "read-only service and discovery check queued", {})])
        jobs.save(job)
    except Exception:
        leases.release(engagement_id, job_id)
        raise
    def task():
        _run(jobs, workspaces, leases, job_id, engagement_id, root, binding, known_hosts, runner)
    try:
        if background_runner is not None:
            background_runner(task)
        else:
            start_runtime_task(task, name="barragan-inference-proxy-status")
    except Exception:
        _fail(jobs, job_id)
        leases.release(engagement_id, job_id)
    return get_inference_proxy_status(engagement_id, root=root, repository=jobs, workspace_repository=workspaces)


def _fail(jobs, job_id):
    job = jobs.get(job_id)
    if job is not None:
        jobs.save(replace(job, status="failed", finished_at=_now(), events=[*job.events, JobEvent(len(job.events)+1, "error", "read-only service and discovery check could not be verified; retry is required", {})]))


def _run(jobs, workspaces, leases, job_id, engagement_id, root, binding, known_hosts, runner):
    try:
        job = jobs.get(job_id)
        if job is None or job.status != "queued":
            return
        _conflicts(jobs, engagement_id, job_id)
        if _fingerprint(_binding(engagement_id, root, jobs, workspaces)[0]) != job.input["bindingFingerprint"]:
            raise InferenceProxyStatusError("stale inputs")
        job = jobs.save(replace(job, status="running", started_at=_now()))
        payload = (runner or _probe)(binding, known_hosts)
        receipt = _sanitize(payload, binding)
        _conflicts(jobs, engagement_id, job_id)
        if _fingerprint(_binding(engagement_id, root, jobs, workspaces)[0]) != job.input["bindingFingerprint"]:
            raise InferenceProxyStatusError("stale inputs")
        jobs.save(replace(job, status="succeeded", finished_at=_now(), events=[*job.events, JobEvent(len(job.events)+1, "info", "service and discovery status observed; inference access remains unverified", receipt)]))
    except Exception:
        _fail(jobs, job_id)
    finally:
        leases.release(engagement_id, job_id)


def recover_interrupted_inference_proxy_status(*, repository=None, lease_repository=None):
    jobs = repository or SqlAlchemyJobRepository()
    leases = lease_repository if lease_repository is not None else SqlAlchemyDeploymentPlanRepository()
    for job in jobs.list():
        if job.action == ACTION and job.status in {"queued", "running"}:
            _fail(jobs, job.id)
            leases.release(job.target_id, job.id)


def _sanitize(payload, binding):
    if not isinstance(payload, dict) or set(payload) != {"identity", "health", "proof"} or payload["proof"] is not True:
        raise ValueError("invalid receipt")
    identity, health = payload["identity"], payload["health"]
    if not isinstance(identity, dict) or set(identity) != {"id", "compartmentId", "displayName", "region"}:
        raise ValueError("invalid identity")
    if not re.fullmatch(r"ocid1\.instance\.[a-z0-9-]+\.[a-z0-9.-]+", str(identity["id"])) or identity["compartmentId"] != binding["coreCompartmentId"] or identity["displayName"] != binding["homebaseName"] or identity["region"] != binding["coreRegion"]:
        raise ValueError("identity scope mismatch")
    if not isinstance(health, dict) or health.get("status") not in {"ready", "unready"}:
        raise ValueError("invalid readiness")
    ready = health["status"] == "ready"
    catalog, upstream = health.get("catalog", {}), health.get("upstream", {})
    status = upstream.get("status", "unknown")
    count, refresh, error = catalog.get("models"), catalog.get("last_refresh"), catalog.get("last_error")
    if ready:
        if health.get("region") != binding["configuration"]["region"] or status not in DISCOVERY_STATUSES - {"unknown"} or upstream.get("inference_verified_by_health") is not False or type(count) is not int or not 0 <= count <= 100000 or (error is not None and error not in ERROR_CODES):
            raise ValueError("invalid discovery")
        if refresh is not None:
            if not isinstance(refresh, str) or len(refresh) > 64:
                raise ValueError("invalid timestamp")
            datetime.fromisoformat(refresh.replace("Z", "+00:00"))
        if (status == "discovery_unavailable") != (error is not None) or (status == "catalog_available" and (not count or refresh is None)) or (status == "no_eligible_models" and (count != 0 or refresh is None)) or (status == "discovering" and (refresh is not None or count != 0)):
            raise ValueError("inconsistent discovery")
    else:
        status, count, refresh, error = "unknown", None, None, None
    return {"homebaseIdentity": {"coreDeploymentId": binding["coreDeploymentId"], "instanceId": identity["id"]},
        "observation": {"checkedAt": _now(), "localReady": ready, "discoveryStatus": status, "lastRefreshAt": refresh, "modelCount": count, "errorCode": error, "inferenceVerified": False}}


def _probe(binding, known_hosts):
    # SSH consumes a private snapshot of the already retained trust, never a live mutable path.
    with open(known_hosts, "rb") as trust_file:
        trust = trust_file.read(1048577)
    if len(trust) > 1048576 or hashlib.sha256(trust).hexdigest() != binding["knownHostsSha256"]:
        raise ValueError("retained trust changed")
    with tempfile.NamedTemporaryFile(prefix="barragan-inference-trust-", mode="wb") as pinned_trust:
        pinned_trust.write(trust)
        pinned_trust.flush()
        return _probe_pinned(binding, pinned_trust.name)


def _probe_pinned(binding, known_hosts):
    encoded = base64.b64encode(json.dumps(binding).encode()).decode()
    key = os.environ.get("BARRAGAN_VALIDATION_SSH_PRIVATE_KEY", "/var/lib/barragan/.ssh/barragan_testing")
    remote = "sudo -n timeout --kill-after=2s 30s /opt/inference-proxy/venv/bin/python - " + shlex.quote(encoded)
    command = ["ssh", "-F", "/dev/null", "-i", key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+known_hosts, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", binding["sshUser"]+"@"+binding["homebaseIp"], remote]
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=barragan_subprocess_env(), start_new_session=True) as process:
        try:
            process.stdin.write(PROBE_SCRIPT.encode())
            process.stdin.close()
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            output = bytearray()
            deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
            with selector:
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("status deadline")
                    for key_event, _ in selector.select(timeout=0.1):
                        chunk = os.read(key_event.fileobj.fileno(), 4096)
                        if not chunk:
                            selector.unregister(key_event.fileobj)
                            continue
                        output.extend(chunk)
                        if len(output) > PROBE_OUTPUT_LIMIT:
                            raise ValueError("status output limit")
            if process.wait(timeout=max(0.1, deadline-time.monotonic())) != 0:
                raise ValueError("status verification failed")
            return json.loads(output)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


PROBE_SCRIPT = r'''import base64, hashlib, json, os, pathlib, pwd, re, stat, subprocess, sys, urllib.request, urllib.error
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
b = json.loads(base64.b64decode(sys.argv[1]))
c, source = b["configuration"], b["source"]
def read_owned(path, limit):
    p = pathlib.Path(path)
    assert p.resolve(strict=True) == p and not p.is_symlink()
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        assert stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022 and st.st_nlink == 1 and st.st_size <= limit
        return f.read(limit + 1)
assert read_owned("/opt/inference-proxy/.installed-artifact", 128).decode().strip() == source["sha256"]
archive = read_owned("/opt/inference-proxy/source-" + source["sha256"] + ".tar.gz", 67108864)
assert hashlib.sha256(archive).hexdigest() == source["sha256"]
config = tomllib.loads(read_owned("/etc/inference-proxy/config.toml", 262144).decode())
assert config["server"]["host"] == "127.0.0.1" and type(config["server"]["port"]) is int and config["server"]["port"] == c["port"]
assert config["oci"]["region"] == c["region"] and config["oci"]["compartment_id"] == c["compartmentId"] and config["oci"]["auth"] == "instance_principal"
props = subprocess.run(["systemctl", "show", "inference-proxy.service", "--property=MainPID,User,ActiveState,SubState,ExecStart,Environment"], capture_output=True, text=True, check=True, timeout=4).stdout
props = dict(line.split("=", 1) for line in props.splitlines() if "=" in line)
pid = int(props["MainPID"])
assert pid > 0 and props["User"] == "inference-proxy" and props["ActiveState"] == "active" and props["SubState"] == "running"
assert "path=/opt/inference-proxy/venv/bin/inference-proxy-server ;" in props["ExecStart"]
assert "INFERENCE_PROXY_CONFIG=/etc/inference-proxy/config.toml" in props["Environment"]
assert os.stat("/proc/" + str(pid)).st_uid == pwd.getpwnam("inference-proxy").pw_uid
lines = subprocess.run(["ss", "-H", "-ltnp", "sport = :" + str(c["port"])], capture_output=True, text=True, check=True, timeout=4).stdout.splitlines()
assert len(lines) == 1 and lines[0].split()[3] == "127.0.0.1:" + str(c["port"]) and ("pid=" + str(pid) + ",") in lines[0]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("redirect refused")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
def get(url, limit, headers=None, unready=False):
    try:
        response = opener.open(urllib.request.Request(url, headers=headers or {}), timeout=4)
    except urllib.error.HTTPError as error:
        if not (unready and error.code == 503):
            raise
        response = error
    with response:
        raw = response.read(limit + 1)
        assert len(raw) <= limit
        return json.loads(raw)
metadata = get("http://169.254.169.254/opc/v2/instance/", 65536, {"Authorization": "Bearer Oracle"})
identity = {k: metadata.get(k) for k in ("id", "compartmentId", "displayName", "region")}
identity["region"] = metadata.get("regionInfo", {}).get("regionIdentifier") or identity["region"]
health = get("http://127.0.0.1:" + str(c["port"]) + "/health/ready", 8192, unready=True)
# Do not attribute a response to a service that restarted or lost its socket mid-check.
assert subprocess.run(["systemctl", "show", "inference-proxy.service", "--property=MainPID", "--value"], capture_output=True, text=True, check=True, timeout=4).stdout.strip() == str(pid)
assert subprocess.run(["ss", "-H", "-ltnp", "sport = :" + str(c["port"])], capture_output=True, text=True, check=True, timeout=4).stdout.splitlines() == lines
# Emit only the public health allowlist, never unknown fields or metadata payloads.
health = {"status": health.get("status"), "region": health.get("region"), "catalog": {k: health.get("catalog", {}).get(k) for k in ("models", "last_refresh", "last_error")}, "upstream": {k: health.get("upstream", {}).get(k) for k in ("status", "inference_verified_by_health")}}
print(json.dumps({"proof": True, "identity": identity, "health": health}))
'''
