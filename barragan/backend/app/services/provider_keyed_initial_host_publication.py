# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot DevTest host proof and atomic initial Sketch publication.

The deterministic child is an audit fence. Once created, startup recovery must
never contact these hosts again: a partial command needs operator reconciliation.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.domain import JobEvent
from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_digitalocean_attachment import reconcile_digitalocean_initial_attachment
from app.services.provider_keyed_host_binding import _core_known_hosts, _digest_json, _manifest
from app.services.provider_keyed_host_identity_probe import (
    collect_digitalocean_edge_host_evidence, collect_digitalocean_middle_host_evidence,
)
from app.services.provider_keyed_host_surface_interpreter import _key_digest
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_continuation import ACTION, _job_ids, _same_parent
from app.services.provider_keyed_postapply_preflight import preflight_applied_digitalocean_provider
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _inert_aborted_intent
from app.services.provider_keyed_strict_host_proof import verify_strict_host_set
from app.services.sketch_bootstrap import SketchBootstrapSpec
from app.services.sketch_bootstrap_apply import _core_hosts, _sketch_nodes
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.services.sketch_transport_ssh_keys import retrieve_sketch_transport_ssh_key
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_OWNER = f"provider-keyed-strict-host-proof-{uuid4().hex}"
_SECONDS = 3600


class ProviderKeyedInitialHostPublicationError(ValueError):
    """Reviewed one-shot host proof or its atomic publication stopped."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(now: str) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=_SECONDS)).isoformat()


def _child_id(core_id: str) -> str:
    return f"job-provider-keyed-initial-host-proof-{core_id.removeprefix('job-')}"


def publish_initial_digitalocean_host_proof(
    parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, postapply_preflight=preflight_applied_digitalocean_provider,
    attachment_intent_builder=derive_digitalocean_initial_attachment_intent,
    attachment_reconciler=reconcile_digitalocean_initial_attachment,
    chain_projector=project_digitalocean_initial_chains,
    middle_collector=collect_digitalocean_middle_host_evidence,
    edge_collector=collect_digitalocean_edge_host_evidence,
    proof_verifier=verify_strict_host_set,
) -> StoredJobRun:
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    parent = jobs.get(parent_id)
    inputs = parent.input if parent is not None and isinstance(parent.input, dict) else {}
    engagement_id, core_id, plan_id = (inputs.get(key) for key in
                                       ("engagementId", "coreJobId", "corePlanId"))
    core = jobs.get(core_id) if isinstance(core_id, str) else None
    plan = plans.get(plan_id) if isinstance(plan_id, str) else None
    expected_parent, plan_child, apply_child = _job_ids(core_id) if isinstance(core_id, str) else (None,) * 3
    child_id = _child_id(core_id) if isinstance(core_id, str) else None
    if (environment != "devtest" or state_root != _default_state_root()
            or parent is None or core is None or plan is None
            or parent_id != expected_parent or child_id is None
            or parent.status != "running" or parent.finished_at is not None
            or inputs.get("phase") != "awaiting_strict_host_proof"
            or not _same_parent(parent, core, engagement_id, plan_id, plan_child, apply_child)
            or plan.status != "applied" or plan.stage != "applied"
            or plan.apply_job_id != core_id or plan.engagement_id != engagement_id
            or _db_lease_lookup(engagement_id) != (plan_id, ACTION)
            or jobs.get(child_id) is not None
            or not parent.events or parent.events[-1].message !=
               "provider bootstrap completed; strict host proof pending"):
        raise ProviderKeyedInitialHostPublicationError("one-shot host proof authority differs")
    token = uuid4().hex
    now = _now()
    current = jobs.claim_lease(parent_id, owner=_OWNER, token=token, claimed_at=now,
                               expires_at=_later(now), eligible_statuses={"running"},
                               eligible_phases={"awaiting_strict_host_proof"})
    if current is None or jobs.get(child_id) is not None:
        raise ProviderKeyedInitialHostPublicationError("host proof claim is unavailable or already used")
    child = None
    try:
        # Reconstruct the exact applied set before any SSH command. Provider
        # reconciliation performs GETs only; it cannot create or change nodes.
        def reviewed():
            from app.services.provider_keyed_initial_dispatch import _phase_authority
            authority_core, authority_plan, _pin = _phase_authority(core_id, jobs, plans, environment)
            if authority_core != core or authority_plan != plan:
                raise ValueError("core source or plan changed")
            result = postapply_preflight(
                engagement_id, core_id, lease_owner=plan_id, environment=environment,
                state_root=state_root, job_repository=jobs, plan_repository=plans,
                sketch_repository=chains, credential_repository=credentials,
            )
            if not isinstance(result, tuple) or len(result) != 4:
                raise ValueError("applied preflight incomplete")
            intent = attachment_intent_builder(*result)
            attachment = attachment_reconciler(
                result[1], intent, environment=environment,
                deployment_target="barragan-testing", credential_repository=credentials,
                max_attempts=12, poll_interval_seconds=10.0,
            )
            durable = tuple(chains.list_for_engagement(engagement_id))
            pending = tuple(chain for chain in durable if not _inert_aborted_intent(chain, engagement_id))
            projections = chain_projector(result[0], intent, attachment, pending)
            manifest = _manifest(core, result, intent, projections, _core_known_hosts(core))
            return result, intent, durable, pending, tuple(projections), manifest

        result, intent, durable, pending, projections, manifest = reviewed()
        digest = _digest_json(manifest)
        bound = [event for event in current.events if event.message == "provider host identity binding intended"]
        if (len(bound) != 1 or bound[0].data != manifest or
                current.events[-1].data != {"manifestSha256": digest,
                    "chainIds": [chain.chain_id for chain in pending], "hostProofPending": True}):
            raise ValueError("bootstrap and host binding evidence differ")
        child = StoredJobRun(
            id=child_id, action="provider_keyed_initial_host_proof", status="queued",
            target=f"engagement:{engagement_id}", target_type="engagement",
            target_id=engagement_id, requested_by=parent.requested_by,
            input={"engagementId": engagement_id, "coreJobId": core_id,
                   "corePlanId": plan_id, "parentJobId": parent_id,
                   "manifestSha256": digest, "mutation": False},
            artifact_refs=[], created_at=_now(), started_at=None, finished_at=None,
            events=[JobEvent(1, "info", "strict host proof reserved", {"manifestSha256": digest})],
        )
        child = jobs.save_if_absent(child)
        if child.status != "queued" or len(child.events) != 1 or child.input.get("manifestSha256") != digest:
            raise ValueError("host proof journal already exists")
        claim_at = _now()
        child = jobs.claim_lease(child_id, owner=_OWNER, token=token, claimed_at=claim_at,
                                 expires_at=_later(claim_at), eligible_statuses={"queued"})
        if child is None:
            raise ValueError("host proof journal claim is unavailable")

        def fence() -> None:
            nonlocal current, child
            if _db_lease_lookup(engagement_id) != (plan_id, ACTION):
                raise ValueError("core lease changed during host proof")
            at = _now()
            current = jobs.renew_lease(parent_id, owner=_OWNER, token=token,
                                        heartbeat_at=at, expires_at=_later(at))
            if child.status in {"queued", "running"}:
                child = jobs.renew_lease(child_id, owner=_OWNER, token=token,
                                          heartbeat_at=at, expires_at=_later(at))
            if current is None or child is None or current.input.get("phase") != "awaiting_strict_host_proof":
                raise ValueError("host proof claim lost")

        def record(message: str, data: dict, *, status: str = "running") -> None:
            nonlocal child
            fence()
            event = JobEvent(len(child.events) + 1,
                             "error" if status == "failed" else "info", message, data)
            child = chains.append_provider_keyed_host_proof_event(
                child, event, owner=_OWNER, token=token,
                started_at=child.started_at or _now(),
                terminal_status="failed" if status == "failed" else None,
            )
            if child is None:
                raise ValueError("host proof journal write lost")

        record("strict host proof started", {"manifestSha256": digest})
        admin = retrieve_sketch_ssh_key(engagement_id)
        transport = retrieve_sketch_transport_ssh_key(engagement_id)
        if admin is None or transport is None:
            raise ValueError("durable sketch identities are missing")
        admin_sha = _key_digest(admin.public_key.strip() + "\n")
        transport_sha = _key_digest(transport.public_key.strip() + "\n")
        workspace = result[1]
        sketch_path = Path(manifest["sketchKnownHostsPath"])
        if sketch_path.parent != workspace.path:
            raise ValueError("selected sketch known-hosts path differs")
        collections = []
        by_address = {node.address: node for node in intent.nodes}
        for projection in projections:
            homebase, proxy = _core_hosts(jobs, engagement_id,
                                          projection.chain.assigned_proxy,
                                          require_proxy_public_alias=True)
            middle, edges = _sketch_nodes(projection.chain, require_exact_roles=True)
            unused_path = str(workspace.path / ".barragan-strict-proof-unused")
            spec = SketchBootstrapSpec(
                homebase=homebase, proxy=proxy, middle=middle, edges=edges,
                admin_private_key_path=unused_path, admin_public_key_path=unused_path,
                transport_public_key_path=unused_path, ssh_config_path=unused_path,
                upstream_root_playbook_path=unused_path, host_policies=projection.host_policies,
                proxy_egress_ip=projection.proxy_egress_ip,
                initial_sketch_known_hosts_path=str(sketch_path),
                pinned_core_known_hosts_path=manifest["coreKnownHostsPath"],
            )
            route = {"homebasePublicIp": homebase.host, "homebaseUser": homebase.user,
                     "proxyPrivateIp": proxy.host, "proxyPublicIp": proxy.host_key_alias,
                     "proxyUser": proxy.user, "coreSshKeyPath": homebase.ssh_private_key_path}
            for node in projection.chain.nodes:
                name = node["hostname"]
                expected = by_address[node["terraformAddress"]]
                scratch = workspace.path / f".barragan-strict-host-proof-{uuid4().hex}"
                scratch.mkdir(mode=0o700)
                scratch.chmod(0o700)
                fields = {"hostname": name, "terraformAddress": expected.address,
                          "providerInstanceId": expected.droplet_id}
                def on_scratch(value):
                    record("strict host proof scratch intended",
                           {**fields, "scratchPath": value.scratch_path})
                def on_intent(value):
                    record("strict host proof command intended",
                           {**fields, "invocationId": value.invocation_id,
                            "scratchPath": value.scratch_path, "argvSha256": value.argv_sha256})
                def on_started(value):
                    identity = value.identity
                    record("strict host proof command started before GO",
                           {**fields, "invocationId": value.intent.invocation_id,
                            "bootId": identity.boot_id, "pid": identity.pid,
                            "pgid": identity.pgid, "startTicks": identity.start_ticks})
                def on_result(value):
                    record("strict host proof command result fenced",
                           {**fields, "invocationId": value.started.intent.invocation_id,
                            "returnCode": value.returncode,
                            "stdoutBytes": value.stdout_bytes, "stderrBytes": value.stderr_bytes,
                            "stdoutTruncated": value.stdout_truncated,
                            "stderrTruncated": value.stderr_truncated})
                try:
                    fence()
                    collector = middle_collector if node["role"] == "middle" else edge_collector
                    collected = collector(
                        manifest=manifest, manifest_sha256=digest,
                        chain_id=projection.chain.chain_id, expected=expected,
                        ssh_spec=spec, reviewed_core_route=route,
                        sketch_known_hosts_sha256=hashlib.sha256(sketch_path.read_bytes()).hexdigest(),
                        scratch_path=scratch, fence=fence,
                        scratch_intent_callback=on_scratch,
                        intent_callback=on_intent, started_callback=on_started,
                        heartbeat_callback=lambda _value: fence(), result_callback=on_result,
                    )
                    collections.append(collected)
                    scratch.rmdir()
                    record("strict host proof capture completed", {**fields})
                except Exception:
                    # The probe retains scratch on unproved process quiescence.
                    # Never remove its private keys or attempt another contact.
                    raise
        strict = proof_verifier(projections, collections,
                                admin_key_sha256=admin_sha,
                                transport_key_sha256=transport_sha,
                                manifest_sha256=digest)
        repeated = reviewed()
        if (repeated[0] != result or repeated[1] != intent or repeated[2] != durable
                or repeated[3] != pending or repeated[4] != projections or repeated[5] != manifest):
            raise ValueError("reviewed source changed during host proof")
        record("strict host proof completed", {"hostEvidenceSha256": strict.raw_evidence_sha256,
              "hostnames": list(strict.hostnames)})
        fence()
        chains.publish_provider_keyed_initial_chains(
            parent=current, pending_chains=pending, projected_chains=projections,
            host_proof=strict, host_evidence_sha256=strict.raw_evidence_sha256,
            state_sha256=intent.state_sha256, manifest=manifest, manifest_sha256=digest,
            applied_workspace_path=str(workspace.path),
            expected_event_digest=job_event_digest(current.events),
            proof_child=child, proof_child_event_digest=job_event_digest(child.events),
            claim_owner=_OWNER, claim_token=token, finished_at=_now(),
        )
        return jobs.get(parent_id)
    except Exception:
        # No contact can be replayed once the child exists. Mark the parent
        # terminal only while this exact claim still belongs to this worker.
        try:
            if child is not None:
                latest_child = jobs.get(child_id)
                if (latest_child is not None and latest_child.status in {"queued", "running"}
                        and latest_child.input.get("claimToken") == token):
                    chains.append_provider_keyed_host_proof_event(
                        latest_child, JobEvent(len(latest_child.events) + 1, "error",
                            "strict host proof stopped; reconciliation required", {}),
                        owner=_OWNER, token=token,
                        started_at=latest_child.started_at or _now(), terminal_status="failed",
                    )
            latest = jobs.get(parent_id)
            if latest is not None and latest.input.get("claimToken") == token:
                attention = replace(latest, status="failed", finished_at=_now(),
                    input={**latest.input, "phase": "attention"},
                    events=[*latest.events, JobEvent(len(latest.events) + 1, "error",
                        "strict host proof stopped; reconciliation required", {})])
                jobs.save_if_leased(attention, owner=_OWNER, token=token)
        except Exception:
            pass
        raise ProviderKeyedInitialHostPublicationError(
            "strict host proof stopped; manual read-only reconciliation required") from None
