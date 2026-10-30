# Copyright (c) 2026, Oracle and/or its affiliates.
"""One-shot strict four-host proof for the reviewed mixed initial Deploy.

This worker never publishes chain rows.  The deterministic child is the contact
fence: once it exists, neither startup recovery nor a second Deploy may repeat
an uncertain SSH command.  The caller passes the returned receipt immediately
to the mixed-only atomic writer under the same parent/child leases.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.domain import JobEvent
from app.services.core_ssh import active_core_connection_details
from app.services.provider_keyed_core_destroy_preview import _read_regular
from app.services.provider_keyed_digitalocean_attachment import ExpectedDigitalOceanNode
from app.services.provider_keyed_host_binding import _core_known_hosts
from app.services.provider_keyed_host_identity_probe import (
    collect_digitalocean_edge_host_evidence, collect_digitalocean_middle_host_evidence,
)
from app.services.provider_keyed_host_surface_interpreter import _key_digest
from app.services.provider_keyed_initial_bootstrap import _sketch_file_snapshot
from app.services.provider_keyed_initial_destroy_pre_go_recovery import _process_quiescent
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id as _apply_child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_apply_proof import prove_mixed_initial_prior_provider_fresh
from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
from app.services.provider_keyed_mixed_initial_host_binding import (
    ProviderHostObservation, _binding_child_id, _same_inserted_job,
    recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_initial_projection import project_mixed_initial_chains
from app.services.provider_keyed_mixed_initial_publication_source import (
    recognize_mixed_initial_publication_source,
)
from app.services.provider_keyed_mixed_linode_host_probe import probe_linode_host_identity
from app.services.provider_keyed_mixed_strict_host_receipt import (
    ACTION, MixedStrictHostProofAttention, _digitalocean_probe_manifest,
    _ordered_rows, _sha, child_id, recognize_completed_mixed_initial_strict_host_proof,
    verify_mixed_strict_host_set,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease, reviewed_mixed_chain_rows
from app.services.sketch_bootstrap import SketchBootstrapSpec
from app.services.sketch_bootstrap_apply import _core_hosts, _sketch_nodes
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.services.sketch_transport_ssh_keys import retrieve_sketch_transport_ssh_key
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


_OWNER = f"mixed-strict-host-proof-{uuid4().hex}"
_CLAIM_SECONDS = 3600


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(now: str) -> str:
    return (datetime.fromisoformat(now) + timedelta(seconds=_CLAIM_SECONDS)).isoformat()


def _write_private(path: Path, payload: bytes) -> None:
    if not payload or len(payload) > 10_000_000:
        raise ValueError("mixed raw evidence exceeds private bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OSError("mixed raw evidence write incomplete")
            offset += written
        os.fsync(fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("mixed raw evidence ownership differs")
    finally:
        os.close(fd)


def collect_mixed_initial_strict_host_proof(
    engagement_id: str, core_job_id: str, *, environment: str,
    job_repository=None, plan_repository=None, sketch_repository=None,
    lease_lookup=None, fresh_observer=None,
    linode_collector=probe_linode_host_identity,
    digitalocean_middle_collector=collect_digitalocean_middle_host_evidence,
    digitalocean_edge_collector=collect_digitalocean_edge_host_evidence,
):
    """Return a claimed receipt with four fresh raw proofs; never write chains."""
    if environment != "devtest" or not engagement_id or not core_job_id:
        raise MixedStrictHostProofAttention("mixed strict proof is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    proof_id = child_id(core_job_id)
    parent_claim = child = None
    token = uuid4().hex
    try:
        if jobs.get(proof_id) is not None:
            raise ValueError("mixed strict host contact already reserved; no replay")
        parent = jobs.get(_parent_id(core_job_id))
        core = jobs.get(core_job_id)
        if (parent is None or core is None or parent.target_id != engagement_id
                or parent.status != "running" or parent.finished_at is not None
                or parent.input.get("phase") != "awaiting_mixed_host_proof"):
            raise ValueError("mixed host handoff is unavailable")
        plan = plans.get(parent.input["corePlanId"])
        seal = validate_mixed_initial_apply_seal(parent)
        order = tuple(seal["orderedProviders"])
        children = {provider: jobs.get(_apply_child_id(core_job_id, provider)) for provider in order}
        binding = jobs.get(_binding_child_id(core_job_id))
        worker = jobs.get(_worker_id(core_job_id))
        manifest = recognize_mixed_initial_host_binding(binding, parent)
        durable = tuple(sketches.list_for_engagement(engagement_id))
        chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
            durable, seal["chainIds"], engagement_id)}
        active_id, _ = active_core_connection_details(jobs, engagement_id)
        trust = _core_known_hosts(core)
        _require_lease(lookup, engagement_id, parent.input["corePlanId"])
        workspaces = {}
        for provider in order:
            terminal = recognize_mixed_initial_apply_terminal(children[provider], parent, provider)
            workspaces[provider] = _prior_workspace(parent, provider, terminal)
        sketch_trust = {
            provider: _sketch_file_snapshot(
                workspaces[provider].path / ".barragan-sketch-known-hosts")[2]
            for provider in order
        }
        generation = job_event_digest(parent.events)

        def observe(provider, source_fence):
            if fresh_observer is not None:
                return fresh_observer(parent, provider, source_fence)
            workspace = workspaces[provider]
            classified = prove_mixed_initial_prior_provider_fresh(
                parent, children[provider], workspace, fence=source_fence,
                process_quiescent=lambda identity: _process_quiescent(
                    identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"]),
            )
            source_fence()
            raw = _read_regular(workspace.state_path)
            source_fence()
            return ProviderHostObservation(classified, raw)

        def base_fence() -> str:
            _require_lease(lookup, engagement_id, parent.input["corePlanId"])
            active, _ = active_core_connection_details(jobs, engagement_id)
            if (active != active_id or active != core.id or jobs.get(core.id) != core
                    or plans.get(plan.id) != plan
                    or jobs.get(binding.id) != binding or jobs.get(worker.id) != worker
                    or any(jobs.get(children[p].id) != children[p] for p in order)
                    or tuple(sketches.list_for_engagement(engagement_id)) != durable
                    or _core_known_hosts(core) != trust
                    or any(_sketch_file_snapshot(
                        workspaces[provider].path / ".barragan-sketch-known-hosts")[2]
                        != sketch_trust[provider] for provider in order)):
                raise ValueError("mixed proof source changed")
            return generation

        def rebind():
            base_fence()
            observations = {}
            for provider in order:
                base_fence()
                observations[provider] = observe(provider, base_fence)
                base_fence()
            current_parent = jobs.get(parent.id)
            source = recognize_mixed_initial_publication_source(
                parent=current_parent, core=core, plan=plan,
                children=children, binding=binding, host_worker=worker,
                active_core_id=active_id, lease=lookup(engagement_id),
                chains=chains, observations=observations,
                process_quiescent=lambda identity: _process_quiescent(
                    identity["bootId"], identity["pid"], identity["pgid"], identity["startTicks"]),
            )
            base_fence()
            return source

        source = rebind()
        projections = project_mixed_initial_chains(manifest, chains, seal["reviewedPolicy"])
        selected = _ordered_rows(source, manifest, projections)
        admin = retrieve_sketch_ssh_key(engagement_id)
        transport = retrieve_sketch_transport_ssh_key(engagement_id)
        if admin is None or transport is None:
            raise ValueError("retained sketch key identities are unavailable")
        key_digests = (_key_digest(admin.public_key.strip() + "\n"),
                       _key_digest(transport.public_key.strip() + "\n"))
        at = _now()
        parent_claim = jobs.claim_lease(parent.id, owner=_OWNER, token=token,
                                        claimed_at=at, expires_at=_later(at),
                                        eligible_statuses={"running"},
                                        eligible_phases={"awaiting_mixed_host_proof"})
        if parent_claim is None or jobs.get(proof_id) is not None:
            raise ValueError("mixed parent claim unavailable")
        source_sha = _sha(asdict(source))
        child = StoredJobRun(
            proof_id, ACTION, "queued", f"engagement:{engagement_id}", "engagement",
            engagement_id, parent.requested_by,
            {"engagementId": engagement_id, "coreJobId": core_job_id,
             "corePlanId": source.core_plan_id, "mixedParentId": parent.id,
             "handoffJournalSha256": source.parent_journal_sha256,
             "bindingJobId": binding.id,
             "bindingManifestSha256": source.binding_manifest_sha256,
             "bootstrapJobId": worker.id,
             "bootstrapJournalSha256": source.host_worker_journal_sha256,
             "mutation": False}, [], _now(), None, None,
            [JobEvent(1, "info", "mixed strict host proof reserved",
                      {"sourceSha256": source_sha})],
        )
        saved = jobs.save_if_absent(child)
        if not _same_inserted_job(saved, child):
            raise ValueError("mixed strict child reservation raced")
        child = jobs.start_if_queued(saved, started_at=_now(),
                                     event=JobEvent(2, "info", "mixed strict host proof started",
                                                    {"sourceSha256": source_sha}))
        if child is None:
            raise ValueError("mixed strict child start lost")
        at = _now()
        child = jobs.claim_lease(proof_id, owner=_OWNER, token=token,
                                 claimed_at=at, expires_at=_later(at),
                                 eligible_statuses={"running"})
        if child is None:
            raise ValueError("mixed strict child claim lost")

        def renew() -> None:
            nonlocal child, parent_claim
            base_fence()
            if jobs.get(parent.id) != parent_claim or jobs.get(proof_id) != child:
                raise ValueError("mixed strict claim changed")
            at = _now()
            refreshed_parent = jobs.renew_lease(parent.id, owner=_OWNER, token=token,
                                                heartbeat_at=at, expires_at=_later(at))
            refreshed_child = jobs.renew_lease(proof_id, owner=_OWNER, token=token,
                                               heartbeat_at=at, expires_at=_later(at))
            if refreshed_parent is None or refreshed_child is None:
                raise ValueError("mixed strict claim lost")
            parent_claim, child = refreshed_parent, refreshed_child

        def record(message: str, data: dict) -> None:
            nonlocal child
            renew()
            at = _now()
            updated = jobs.append_event_if_running_claimed(
                child, owner=_OWNER, token=token,
                expected_event_digest=job_event_digest(child.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(child.events) + 1, "info", message, data))
            if updated is None:
                raise ValueError("mixed strict journal CAS lost")
            child = updated

        def current_source():
            renew()
            fresh = rebind()
            if fresh != source:
                raise ValueError("mixed strict source drifted during host contact")
            if (_key_digest(retrieve_sketch_ssh_key(engagement_id).public_key.strip() + "\n"),
                    _key_digest(retrieve_sketch_transport_ssh_key(engagement_id).public_key.strip() + "\n")) != key_digests:
                raise ValueError("retained sketch key identity changed")
            return fresh

        collections = []
        for (node, _policy, _predecessor) in selected:
            current_source()
            provider = node["provider"]
            workspace = workspaces[provider]
            projection = next(item for item in projections if item.chain.chain_id == node["chainId"])
            homebase, proxy = _core_hosts(jobs, engagement_id, projection.chain.assigned_proxy,
                                          require_proxy_public_alias=True)
            middle, edges = _sketch_nodes(projection.chain, require_exact_roles=True)
            sketch_path = workspace.path / ".barragan-sketch-known-hosts"
            sketch_sha = sketch_trust[provider]
            unused = str(workspace.path / ".barragan-mixed-strict-proof-unused")
            spec = SketchBootstrapSpec(
                homebase=homebase, proxy=proxy, middle=middle, edges=edges,
                admin_private_key_path=unused, admin_public_key_path=unused,
                transport_public_key_path=unused, ssh_config_path=unused,
                upstream_root_playbook_path=unused, host_policies=projection.host_policies,
                proxy_egress_ip=projection.proxy_egress_ip,
                initial_sketch_known_hosts_path=str(sketch_path),
                pinned_core_known_hosts_path=trust[0],
            )
            route = {"homebasePublicIp": homebase.host, "homebaseUser": homebase.user,
                     "proxyPrivateIp": proxy.host, "proxyPublicIp": proxy.host_key_alias,
                     "proxyUser": proxy.user, "coreSshKeyPath": homebase.ssh_private_key_path}
            fields = {"provider": provider, "hostname": node["hostname"],
                      "terraformAddress": node["terraformAddress"],
                      "providerInstanceId": node["providerInstanceId"]}
            scratch = workspace.path / f".barragan-mixed-strict-proof-{uuid4().hex}"
            scratch.mkdir(mode=0o700)
            scratch.chmod(0o700)

            def on_scratch(value):
                path = value if type(value) is str else value.scratch_path
                record("mixed strict host scratch intended", {**fields, "scratchPath": path})

            def on_intent(value):
                record("mixed strict host command intended", {**fields,
                    "invocationId": value.invocation_id,
                    "argvSha256": value.argv_sha256, "scratchPath": value.scratch_path})

            def on_started(value):
                identity = value.identity
                record("mixed strict host command started before GO", {**fields,
                    "invocationId": value.intent.invocation_id,
                    "bootId": identity.boot_id, "pid": identity.pid,
                    "pgid": identity.pgid, "startTicks": identity.start_ticks})

            def on_result(value):
                record("mixed strict host command result fenced", {**fields,
                    "invocationId": value.started.intent.invocation_id,
                    "returnCode": value.returncode, "stdoutBytes": value.stdout_bytes,
                    "stderrBytes": value.stderr_bytes,
                    "stdoutTruncated": value.stdout_truncated,
                    "stderrTruncated": value.stderr_truncated})

            kwargs = dict(scratch_path=scratch, fence=renew,
                          scratch_intent_callback=on_scratch,
                          intent_callback=on_intent, started_callback=on_started,
                          heartbeat_callback=lambda _value: renew(), result_callback=on_result)
            if provider == "linode":
                collection = linode_collector(
                    manifest=manifest, manifest_sha256=source.binding_manifest_sha256,
                    node=node, expected_image="linode/ubuntu24.04", ssh_spec=spec,
                    reviewed_core_route=route, core_known_hosts_sha256=trust[1],
                    sketch_known_hosts_sha256=sketch_sha,
                    collect_raw=True, **kwargs)
            else:
                do_probe_manifest = _digitalocean_probe_manifest(
                    source, manifest, projections, node["chainId"], str(sketch_path), trust)
                expected = ExpectedDigitalOceanNode(
                    node["terraformAddress"], node["providerInstanceId"],
                    node["hostname"], node["region"], node["publicIp"])
                collector = (digitalocean_middle_collector if node["role"] == "middle"
                             else digitalocean_edge_collector)
                collection = collector(
                    manifest=do_probe_manifest,
                    manifest_sha256=_sha(do_probe_manifest),
                    chain_id=node["chainId"], expected=expected,
                    ssh_spec=spec, reviewed_core_route=route,
                    sketch_known_hosts_sha256=sketch_sha, **kwargs)
            collections.append(collection)
            scratch.rmdir()
            record("mixed strict host capture completed",
                   {**fields, "collectionSha256": _sha(asdict(collection))})

        current_source()
        do_index = source.ordered_providers.index("digitalocean")
        do_workspace = workspaces["digitalocean"]
        do_probe_manifest = _digitalocean_probe_manifest(
            source, manifest, projections, source.chain_ids[do_index],
            str(do_workspace.path / ".barragan-sketch-known-hosts"), trust)
        evidence_sha = verify_mixed_strict_host_set(
            source, manifest, projections, collections,
            digitalocean_probe_manifest=do_probe_manifest,
            core_known_hosts_sha256=trust[1],
            sketch_known_hosts_sha256=sketch_trust,
            admin_key_sha256=key_digests[0], transport_key_sha256=key_digests[1])
        payload = json.dumps([asdict(item) for item in collections],
                             sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(payload).hexdigest() != evidence_sha:
            raise ValueError("mixed strict artifact digest changed")
        artifact = do_workspace.path / f".barragan-mixed-strict-host-proof-{proof_id}.json"
        _write_private(artifact, payload)
        record("mixed strict host proof completed", {
            "sourceSha256": source_sha, "hostEvidenceSha256": evidence_sha,
            "hostnames": [row.hostname for row in source.host_rows],
            "evidencePath": str(artifact),
        })
        renew()
        return recognize_completed_mixed_initial_strict_host_proof(
            source, child, manifest, projections,
            digitalocean_probe_manifest=do_probe_manifest,
            core_known_hosts_sha256=trust[1],
            sketch_known_hosts_sha256=sketch_trust,
            admin_key_sha256=key_digests[0], transport_key_sha256=key_digests[1],
            evidence_path=artifact)
    except Exception as exc:
        # A saved child is the permanent one-shot fence even if its first
        # command did not start.  Best-effort truthful terminal rows do not
        # permit replay; missing terminal rows are themselves attention.
        try:
            latest_child = jobs.get(proof_id)
            if (latest_child is not None and latest_child.status == "running"
                    and latest_child.input.get("claimOwner") == _OWNER
                    and latest_child.input.get("claimToken") == token):
                jobs.finish_if_running_claimed(
                    latest_child, owner=_OWNER, token=token,
                    expected_event_digest=job_event_digest(latest_child.events),
                    status="failed", finished_at=_now(),
                    event=JobEvent(len(latest_child.events) + 1, "error",
                                   "mixed strict host proof stopped; reconciliation required", {}))
            latest_parent = jobs.get(_parent_id(core_job_id))
            if (latest_parent is not None and latest_parent.status == "running"
                    and latest_parent.input.get("claimOwner") == _OWNER
                    and latest_parent.input.get("claimToken") == token):
                jobs.save_if_leased(replace(
                    latest_parent, status="failed", finished_at=_now(),
                    input={**latest_parent.input, "phase": "attention"},
                    events=[*latest_parent.events, JobEvent(
                        len(latest_parent.events) + 1, "error",
                        "mixed strict host proof stopped; reconciliation required", {})]),
                    owner=_OWNER, token=token)
        except Exception:
            pass
        raise MixedStrictHostProofAttention(
            "mixed strict host proof stopped; no host contact may be replayed") from exc
