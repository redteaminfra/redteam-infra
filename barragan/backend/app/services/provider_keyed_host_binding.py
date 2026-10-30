# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant, fenced binding of applied Sketch identities before host contact.

The binding is an audit intent, not host proof. This module performs only
repository reads, a bounded provider GET reconciliation, and creation of one
empty private known-hosts file. No runtime dispatcher calls it.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_digitalocean_attachment import (
    DigitalOceanAttachmentStillSettling, reconcile_digitalocean_initial_attachment,
)
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_attachment_recheck import _proof_data
from app.services.provider_keyed_initial_continuation import ACTION, CORE_ACTION, _job_ids, _same_parent
from app.services.provider_keyed_postapply_preflight import preflight_applied_digitalocean_provider
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_OWNER = f"provider-keyed-host-binding-{uuid4().hex}"
_CLAIM_SECONDS = 3600
_PHASES = {"awaiting_host_proof", "binding_host_identity"}
_INTENT_MESSAGE = "provider host identity binding intended"
_KNOWN_HOSTS_NAME = ".barragan-sketch-known-hosts"


class ProviderKeyedHostBindingError(ValueError):
    """Host identity cannot be bound to retained reviewed evidence."""


def bind_initial_digitalocean_host_identity(
    parent_id: str,
    *,
    environment: str,
    state_root: Path,
    job_repository: JobRepository | None = None,
    plan_repository=None,
    engagement_repository=None,
    sketch_repository=None,
    credential_repository=None,
    lease_lookup: Callable[[str], tuple[str, str] | None] | None = None,
    postapply_preflight: Callable = preflight_applied_digitalocean_provider,
    attachment_intent_builder: Callable = derive_digitalocean_initial_attachment_intent,
    attachment_reconciler: Callable = reconcile_digitalocean_initial_attachment,
    chain_projector: Callable = project_digitalocean_initial_chains,
) -> StoredJobRun:
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains_repo = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    values = parent.input if parent is not None and isinstance(parent.input, dict) else {}
    engagement_id, core_id, plan_id = (values.get(key) for key in ("engagementId", "coreJobId", "corePlanId"))
    if (environment != "devtest" or parent is None or parent.id != parent_id
            or any(not isinstance(value, str) or not value for value in (engagement_id, core_id, plan_id))):
        raise ProviderKeyedHostBindingError("DevTest binding parent is unavailable")
    core = jobs.get(core_id)
    plan = plans.get(plan_id)
    expected_parent, plan_child, apply_child = _job_ids(core_id)
    if (core is None or core.action != CORE_ACTION or core.status != "succeeded"
            or core.input.get("sketchStateSchema") != "provider-keyed-v2"
            or core.input.get("corePlanId") != plan_id or core.input.get("engagementId") != engagement_id
            or plan is None or plan.id != plan_id or plan.engagement_id != engagement_id
            or plan.status != "applied" or plan.apply_job_id != core_id
            or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or parent_id != expected_parent or not _same_parent(
                parent, core, engagement_id, plan_id, plan_child, apply_child)
            or parent.status != "running" or not parent.started_at or parent.finished_at is not None
            or values.get("phase") not in _PHASES
            or lookup(engagement_id) != (plan_id, ACTION)):
        raise ProviderKeyedHostBindingError("reviewed binding parent or core lease differs")
    token = uuid4().hex
    now = _now()
    claimed = jobs.claim_lease(
        parent_id, owner=_OWNER, token=token, claimed_at=now,
        expires_at=_later(now), eligible_statuses={"running"}, eligible_phases=_PHASES,
    )
    if claimed is None or claimed.input.get("phase") not in _PHASES:
        raise ProviderKeyedHostBindingError("host binding claim is unavailable")
    current = claimed
    try:
        _lease(lookup, engagement_id, plan_id)
        reviewed = postapply_preflight(
            engagement_id, core_id, lease_owner=plan_id, environment=environment,
            state_root=state_root, lease_lookup=lookup, job_repository=jobs,
            plan_repository=plans, engagement_repository=engagement_repository,
            sketch_repository=chains_repo, credential_repository=credentials,
        )
        if not isinstance(reviewed, tuple) or len(reviewed) != 4:
            raise ValueError("applied evidence is incomplete")
        intent = attachment_intent_builder(*reviewed)
        proof = attachment_reconciler(
            reviewed[1], intent, environment=environment,
            deployment_target="barragan-testing", credential_repository=credentials,
            max_attempts=12, poll_interval_seconds=10.0,
        )
        proof_data = _proof_data(proof, intent)
        recorded = [event.data for event in current.events
                    if event.message == "provider attachment proven; host proof pending"]
        stable_keys = set(proof_data) - {"attempts"}
        if (len(recorded) != 1 or set(recorded[0]) != set(proof_data)
                or type(recorded[0]["attempts"]) is not int
                or not 1 <= recorded[0]["attempts"] <= 12
                or any(recorded[0][key] != proof_data[key] for key in stable_keys)):
            raise ValueError("recorded provider attachment proof differs")
        durable = chains_repo.list_for_engagement(engagement_id)
        current_chains = [chain for chain in durable if not _inert_aborted_intent(chain, engagement_id)]
        projected = chain_projector(reviewed[0], intent, proof, current_chains)
        manifest = _manifest(core, reviewed, intent, projected, _core_known_hosts(core))
        existing = [event for event in current.events if event.message == _INTENT_MESSAGE]
        was_binding = current.input["phase"] == "binding_host_identity"
        if was_binding:
            if len(existing) != 1 or existing[0].data != manifest:
                raise ValueError("retained host binding intent differs")
        elif existing:
            raise ValueError("host binding intent already exists")
        _lease(lookup, engagement_id, plan_id)
        if not was_binding:
            current = _save(jobs, current, token, "binding_host_identity", _INTENT_MESSAGE, manifest)
        path = Path(manifest["sketchKnownHostsPath"])
        _empty_known_hosts(path, adopt=was_binding)
        # The first preflight ran before the file existed. A second complete
        # read proves it has not hidden changed state or reviewed chain rows.
        repeated = postapply_preflight(
            engagement_id, core_id, lease_owner=plan_id, environment=environment,
            state_root=state_root, lease_lookup=lookup, job_repository=jobs,
            plan_repository=plans, engagement_repository=engagement_repository,
            sketch_repository=chains_repo, credential_repository=credentials,
        )
        if (not isinstance(repeated, tuple) or len(repeated) != 4
                or repeated[0] != reviewed[0] or repeated[1] != reviewed[1]
                or repeated[2] != reviewed[2] or repeated[3] != reviewed[3]
                or _core_known_hosts(core) != (
                    manifest["coreKnownHostsPath"], manifest["coreKnownHostsSha256"])):
            raise ValueError("applied evidence changed during binding")
        _lease(lookup, engagement_id, plan_id)
        _empty_known_hosts(path, adopt=True)
        return _save(jobs, current, token, "host_identity_bound", "provider host identity bound",
                     {"manifestSha256": _digest_json(manifest), "hostProofPending": True})
    except DigitalOceanAttachmentStillSettling:
        return _save(jobs, current, token, current.input["phase"],
                     "provider attachment still settling; host binding pending",
                     {"attachmentProofPending": True, "hostProofPending": True}, release=True)
    except Exception:
        return _attention(jobs, current, token)


def _manifest(core, reviewed, intent, projected, core_hosts: tuple[str, str]) -> dict:
    persisted, workspace, _evidence, _apply = reviewed
    ids = core.input.get("pendingSketchChainIds")
    fingerprints = core.input.get("pendingSketchChainFingerprints")
    projected_by_id = {item.chain.chain_id: item for item in projected}
    if (not isinstance(ids, list) or len(ids) != 2 or len(set(ids)) != 2
            or not isinstance(fingerprints, dict) or set(fingerprints) != set(ids)
            or len(projected_by_id) != 2 or set(projected_by_id) != set(ids)
            or persisted.core_job_id != core.id or persisted.core_plan_id != core.input["corePlanId"]
            or persisted.engagement_id != core.input["engagementId"]
            or workspace.provider_connection_id != intent.credential_record_id):
        raise ValueError("reviewed binding identity differs")
    nodes = sorted(
        ({"chainId": item.chain.chain_id, "role": row["role"],
          "providerInstanceId": row["providerInstanceId"], "terraformAddress": row["terraformAddress"],
          "name": row["hostname"], "publicIp": row["publicIp"], "region": row["region"]}
         for item in projected for row in item.chain.nodes),
        key=lambda row: row["terraformAddress"],
    )
    if len(nodes) != len(intent.nodes) or len({row["terraformAddress"] for row in nodes}) != len(nodes):
        raise ValueError("projected node set differs")
    path = workspace.path / _KNOWN_HOSTS_NAME
    if (workspace.path.is_symlink() or workspace.path.resolve(strict=True) != workspace.path
            or path.exists() and path.is_symlink()):
        raise ValueError("provider workspace path differs")
    return {
        "schema": "provider-keyed-v2", "engagementId": persisted.engagement_id,
        "coreJobId": core.id, "corePlanId": persisted.core_plan_id,
        "revisionId": persisted.revision_id, "stateSha256": intent.state_sha256,
        "sourceRevision": workspace.source_revision,
        "providerConnectionId": workspace.provider_connection_id,
        "chainFingerprints": [{"chainId": chain_id, "fingerprint": fingerprints[chain_id]} for chain_id in ids],
        "nodes": nodes,
        "hostPolicies": [{"chainId": chain_id, "proxyEgressIp": projected_by_id[chain_id].proxy_egress_ip,
                          "hosts": projected_by_id[chain_id].host_policies} for chain_id in ids],
        "coreKnownHostsPath": core_hosts[0], "coreKnownHostsSha256": core_hosts[1],
        "sketchKnownHostsPath": str(path),
    }


def _core_known_hosts(core) -> tuple[str, str]:
    directories = {event.data.get("workspaceDir") for event in core.events
                   if isinstance(event.data, dict) and event.data.get("workspaceDir")}
    if len(directories) != 1:
        raise ValueError("core known-hosts workspace is unavailable or ambiguous")
    root = Path(directories.pop())
    path = root / "ssh" / "known_hosts"
    if not root.is_absolute():
        raise ValueError("core workspace path differs")
    for directory in (root, root / "ssh"):
        if directory.is_symlink() or directory.resolve(strict=True) != directory:
            raise ValueError("core workspace path differs")
        st = directory.stat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (os.getuid(), 0)
                or st.st_mode & 0o022):
            raise ValueError("core workspace path is unsafe")
    return str(path), _regular_file_digest(path, require_content=True)


def _regular_file_digest(path: Path, *, require_content: bool) -> str:
    if (path.is_symlink() or path.resolve(strict=True) != path):
        raise ValueError("known-hosts path is unsafe")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid not in (os.getuid(), 0)
                or st.st_nlink != 1 or st.st_mode & 0o022 or (require_content and st.st_size == 0)):
            raise ValueError("known-hosts file is unsafe")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 65536):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _empty_known_hosts(path: Path, *, adopt: bool) -> None:
    parent = path.parent
    if (parent.is_symlink() or parent.resolve(strict=True) != parent):
        raise ValueError("provider workspace path is unsafe")
    parent_stat = parent.stat()
    if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid not in (os.getuid(), 0)
            or parent_stat.st_mode & 0o022):
        raise ValueError("provider workspace path is unsafe")
    if path.exists() or path.is_symlink():
        if not adopt:
            raise ValueError("unreviewed sketch known-hosts file already exists")
    else:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
            or st.st_nlink != 1 or st.st_mode & 0o077 or st.st_size != 0):
        raise ValueError("sketch known-hosts file is unsafe")


def _save(jobs, parent, token, phase, message, data, *, release=False, failed=False):
    now = _now()
    renewed = jobs.renew_lease(parent.id, owner=_OWNER, token=token,
                               heartbeat_at=now, expires_at=_later(now))
    if renewed is None or renewed.input.get("claimToken") != token:
        raise ProviderKeyedHostBindingError("host binding claim was lost")
    updated = replace(
        renewed, status="failed" if failed else "running",
        finished_at=now if failed else None,
        input={**renewed.input, "phase": phase,
               "claimExpiresAt": now if release or phase == "host_identity_bound" else _later(now)},
        events=[*renewed.events, JobEvent(len(renewed.events) + 1,
            "error" if failed else "info", message, data)],
    )
    stored = jobs.save_if_leased(updated, owner=_OWNER, token=token)
    if stored is None or stored.input.get("phase") != phase:
        raise ProviderKeyedHostBindingError("host binding claim was lost")
    return stored


def _attention(jobs, parent, token):
    try:
        return _save(jobs, parent, token, "attention",
                     "host identity binding stopped; reconciliation required", {}, failed=True)
    except Exception:
        raise ProviderKeyedHostBindingError("host identity binding stopped; reconciliation required") from None


def _lease(lookup, engagement_id, plan_id):
    if lookup(engagement_id) != (plan_id, ACTION):
        raise ValueError("core plan lease changed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(now: str) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=_CLAIM_SECONDS)).isoformat()


def _digest_json(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
