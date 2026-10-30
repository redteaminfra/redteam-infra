# Copyright (c) 2026, Oracle and/or its affiliates.
"""Internal, non-applying job for one published DevTest DigitalOcean edge.

The parent and plan child must already be durably reserved under the core-plan
lease. This worker leaves the active four-node topology and chain rows alone.
"""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import stat
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_append_plan_runner import (
    ProviderKeyedAppendPlanPreparationError,
    prepare_digitalocean_keyed_edge_append_plan,
)
from app.services.provider_keyed_digitalocean_attachment import reconcile_digitalocean_initial_attachment
from app.services.provider_keyed_initial_attachment_adapter import derive_digitalocean_initial_attachment_intent
from app.services.provider_keyed_initial_plan_job import (
    _expected_inventory, _prepare_private_material_directory, _write_private_new,
)
from app.services.provider_keyed_initial_plan_gate import _SOURCE_SHA256
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_saved_plan_runner import (
    _credential_snapshot, _hash_file, _ordinal_lock, _unsafe_keyed_workspace,
)
from app.services.provider_keyed_persisted_intent import compile_fresh_digitalocean_persisted_intent
from app.services.provider_keyed_postapply_preflight import read_applied_digitalocean_provider_for_teardown
from app.services.provider_keyed_published_teardown_source import audit_published_provider_keyed_source
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.services.managed_host_image_continuity import managed_host_image_profile_named


class ProviderKeyedAppendPlanJobError(ValueError):
    """The durable append plan was not proven or saved."""


_PLAN_EVENT_KEYS = frozenset({
    "initialSourceSha256", "initialSource", "selectedChain", "retainedSharedIds",
    "newEdgeAddress", "planPath", "planSha256", "stateSha256",
    "topologySha256", "sourceSha256", "lockfileSha256", "inputSha256",
    "credentialRecordId", "credentialSecretSha256", "credentialUpdatedAt",
    "terraformBinaryPath", "terraformBinarySha256",
})
_EDGE_ADDRESS = re.compile(r'^digitalocean_droplet\.edge\["[a-z0-9-]+-[0-9]{2}"\]$')


def _only_attested_historical_no_go_apply_children(parent, jobs) -> bool:
    """Permit past fenced no-GO children, never a current or ambiguous Apply."""
    from app.services.provider_keyed_teardown_scope import (
        _reconciled_unapplied_append_state_sha,
    )

    related = jobs.list_for_engagement(parent.target_id)
    applied = [job for job in related
               if job.action in {"provider_keyed_edge_append_apply",
                                 "provider_keyed_edge_append_host_proof"}]
    if not applied:
        return True
    if any(job.input.get("parentJobId") == parent.id for job in applied):
        return False
    source = parent.input.get("initialSource")
    return bool(
        type(source) is dict
        and _reconciled_unapplied_append_state_sha(
            parent.target_id, jobs, allowed_active_parent_id=parent.id,
            expected_core_job_id=parent.input.get("coreJobId"),
            expected_core_plan_id=parent.input.get("corePlanId"),
        ) == source.get("state_sha256")
    )


def begin_published_digitalocean_edge_append_plan(
    core_job_id: str, chain_id: str, region: str, size: str, *,
    requested_by: str, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None,
    lease_lookup=None,
) -> tuple[StoredJobRun, StoredJobRun]:
    """Reserve one read-only append review after auditing the published source.

    The returned queued child is run separately. The lease remains held until
    either a reviewed Apply or audited no-mutation recovery completes.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    if (environment != "devtest" or not all(type(value) is str and value for value in (
            core_job_id, chain_id, region, size, requested_by))):
        raise ProviderKeyedAppendPlanJobError("append review requires exact DevTest inputs")
    core = jobs.get(core_job_id)
    engagement_id = core.input.get("engagementId") if core is not None else ""
    prior = [job for job in jobs.list_for_engagement(engagement_id)
             if job.action == "provider_keyed_edge_append"]
    if prior:
        from app.services.provider_keyed_teardown_scope import (
            _reconciled_unapplied_append_state_sha,
        )
        prior_sha = _reconciled_unapplied_append_state_sha(
            engagement_id, jobs, expected_core_job_id=core_job_id,
            expected_core_plan_id=core.input.get("corePlanId"))
        if prior_sha is None:
            raise ProviderKeyedAppendPlanJobError("previous append review is not proven unapplied")
    source = audit_published_provider_keyed_source(
        core_job_id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans, sketch_repository=chains,
        lease_lookup=lookup,
    )
    if prior and prior_sha != source.state_sha256:
        raise ProviderKeyedAppendPlanJobError("previous append review state differs")
    selected = chains.get(source.engagement_id, chain_id)
    if (selected is None or selected.status != "deployed" or selected.burned
            or selected.edge_count != 1 or len(selected.nodes) != 2
            or not isinstance(selected.edge_intents, list)
            or len(selected.edge_intents) != 1):
        raise ProviderKeyedAppendPlanJobError("published one-edge chain is unavailable")
    if prior:
        workspace = Path(selected.terraform_working_directory)
        material = workspace.parents[1] / ".plan-material" / "digitalocean"
        owned = [workspace / ".barragan-edge-append.tfplan",
                 material / "append-inputs.json", material / "admin-private",
                 material / "admin-public"]
        if (workspace.is_symlink() or not workspace.is_dir()
                or any(os.path.lexists(path) for path in owned)
                or any(path.name.startswith(".barragan-append-inputs-")
                       for path in workspace.iterdir())):
            raise ProviderKeyedAppendPlanJobError("previous append review artifacts remain")
    parent_id = f"job-provider-keyed-append-{uuid4().hex[:16]}"
    plan_job_id = f"job-provider-keyed-append-plan-{parent_id.removeprefix('job-provider-keyed-append-')}"
    now = _now()
    parent = StoredJobRun(
        parent_id, "provider_keyed_edge_append", "running",
        f"engagement:{source.engagement_id}", "engagement", source.engagement_id,
        requested_by, {"engagementId": source.engagement_id, "coreJobId": core_job_id,
                       "corePlanId": source.core_plan_id, "chainId": chain_id,
                       "region": region, "size": size, "planJobId": plan_job_id,
                       "initialSourceSha256": _fingerprint(asdict(source)),
                       "initialSource": json.loads(json.dumps(asdict(source))),
                       "phase": "planning", "mutation": True},
        [], now, now, None,
        [JobEvent(1, "info", "provider append review reserved", {
            "initialSourceSha256": _fingerprint(asdict(source))})],
    )
    child = StoredJobRun(
        plan_job_id, "provider_keyed_edge_append_plan", "queued",
        parent.target, "engagement", source.engagement_id, requested_by,
        {"engagementId": source.engagement_id, "parentJobId": parent_id,
         "coreJobId": core_job_id, "mutation": False},
        [], now, None, None,
        [JobEvent(1, "info", "provider append plan queued", {})],
    )
    try:
        if not plans.reserve_provider_keyed_append_plan(parent, child):
            raise ValueError("append review reservation was not committed")
        stored_parent, stored_child = jobs.get(parent.id), jobs.get(child.id)
        if (lookup(source.engagement_id) != (source.core_plan_id, "provider_keyed_edge_append")
                or stored_parent is None or stored_child is None
                or stored_parent.input != parent.input or stored_child.input != child.input
                or stored_parent.events != parent.events or stored_child.events != child.events
                or stored_parent.status != "running" or stored_child.status != "queued"):
            raise ValueError("append review reservation differs")
        again = audit_published_provider_keyed_source(
            core_job_id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            lease_lookup=lookup, expected_mutation_lease=(source.core_plan_id, "provider_keyed_edge_append"),
            allowed_append_plan_parent_id=parent.id,
        )
        if again != source or chains.get(source.engagement_id, chain_id) != selected:
            raise ValueError("published source moved while reserving append review")
        return stored_parent, stored_child
    except Exception:
        # Leave the lease and journal for explicit no-mutation reconciliation;
        # a crash or concurrent writer can make rollback ambiguous.
        raise ProviderKeyedAppendPlanJobError("append review reservation needs reconciliation") from None


def run_published_digitalocean_edge_append_plan(
    plan_job_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None,
    engagement_repository=None, credential_repository=None, ssh_key_repository=None,
    lease_lookup=None, attachment_membership=reconcile_digitalocean_initial_attachment,
    plan_runner=prepare_digitalocean_keyed_edge_append_plan,
):
    """Finish one already-reserved plan child without Terraform apply.

    No public route calls this yet. The saved binary plan remains private in
    the durable keyed workspace for a later, independently fenced Apply.
    """
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    child = jobs.get(plan_job_id)
    if (environment != "devtest" or child is None
            or child.action != "provider_keyed_edge_append_plan"
            or child.status != "queued" or child.target_type != "engagement"
            or child.target_id != child.input.get("engagementId")
            or child.input.get("mutation") is not False
            or set(child.input) != {"engagementId", "parentJobId", "coreJobId", "mutation"}):
        raise ProviderKeyedAppendPlanJobError("queued append plan child differs")
    parent = jobs.get(child.input["parentJobId"])
    if (parent is None or parent.action != "provider_keyed_edge_append"
            or parent.status != "running" or parent.target_id != child.target_id
            or parent.input.get("planJobId") != child.id
            or parent.input.get("coreJobId") != child.input["coreJobId"]
            or parent.input.get("engagementId") != child.target_id
            or parent.input.get("phase") != "planning"
            or type(parent.input.get("chainId")) is not str
            or type(parent.input.get("region")) is not str
            or type(parent.input.get("size")) is not str):
        raise ProviderKeyedAppendPlanJobError("append plan parent differs")
    core = jobs.get(child.input["coreJobId"])
    plan_id = core.input.get("corePlanId") if core is not None else None
    lease = (plan_id, "provider_keyed_edge_append")
    if (type(plan_id) is not str or parent.input.get("corePlanId") != plan_id
            or lookup(child.target_id) != lease):
        raise ProviderKeyedAppendPlanJobError("append mutation lease differs")
    claim_at = _now()
    claimed_parent = jobs.claim_lease(
        parent.id, owner="provider_keyed_append_plan", token=uuid4().hex,
        claimed_at=claim_at,
        expires_at=(datetime.fromisoformat(claim_at) + timedelta(hours=1)).isoformat(),
        eligible_statuses={"running"}, eligible_phases={"planning"},
    )
    started = jobs.start_if_queued(child, started_at=_now(), event=JobEvent(
        len(child.events) + 1, "info", "provider append plan preflight started", {})) if claimed_parent else None
    if started is None:
        raise ProviderKeyedAppendPlanJobError("append plan child claim differs")
    private = public = None
    try:
        source = audit_published_provider_keyed_source(
            core.id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            lease_lookup=lookup, expected_mutation_lease=lease,
            allowed_append_plan_parent_id=parent.id,
        )
        if (source.engagement_id != child.target_id
                or parent.input.get("initialSourceSha256") != _fingerprint(asdict(source))):
            raise ValueError("original publication differs from append reservation")
        original_rows = chains.list_for_engagement(child.target_id)
        selected = next(row for row in original_rows if row.chain_id == parent.input["chainId"])
        if (len(original_rows) != 2 or selected.edge_count != 1
                or selected.status != "deployed" or len(selected.nodes) != 2
                or any(row.edge_count != 1 or len(row.nodes) != 2 for row in original_rows)):
            raise ValueError("published chain selection differs")
        reviewed, workspace, initial_evidence, initial_apply = read_applied_digitalocean_provider_for_teardown(
            child.target_id, core.id, environment=environment, state_root=state_root,
            mode="materialized_read", engagement_repository=engagements,
            sketch_repository=chains, job_repository=jobs, plan_repository=plans,
            credential_repository=credentials,
        )
        attachment = derive_digitalocean_initial_attachment_intent(
            reviewed, workspace, initial_evidence, initial_apply)
        if attachment.state_sha256 != source.state_sha256:
            raise ValueError("retained state differs from original publication")
        attachment_membership(
            workspace, attachment, environment=environment,
            deployment_target="barragan-testing", credential_repository=credentials,
            max_attempts=12, poll_interval_seconds=5.0,
        )
        proposed = replace(selected, edge_count=2, edge_intents=[*selected.edge_intents, {
            "id": "edge-02", "provider": "digitalocean", "region": parent.input["region"],
            "size": parent.input["size"],
        }])
        ephemeral = [proposed if row.chain_id == selected.chain_id else row for row in original_rows]
        engagement = engagements.get(child.target_id)
        core_plan = plans.get(plan_id)
        profile = managed_host_image_profile_named(core_plan.evidence["managedHostImageProfile"])
        intent = compile_fresh_digitalocean_persisted_intent(
            engagement, ephemeral, core, core_plan, profile,
            environment=environment, provider_state_exists=True,
            mode="append_plan", reviewed_initial_chains=original_rows,
        )
        old_addresses = {node["terraformAddress"] for row in original_rows for node in row.nodes}
        new_addresses = set(intent.nodes) - old_addresses
        if len(new_addresses) != 1:
            raise ValueError("append does not create exactly one edge")
        new_address = next(iter(new_addresses))
        material_dir = workspace.path.parents[1] / ".plan-material" / "digitalocean"
        _prepare_private_material_directory(material_dir)
        output_dir = material_dir / "ssh-output"
        _prepare_private_material_directory(output_dir)
        private, public = material_dir / "admin-private", material_dir / "admin-public"
        admin = retrieve_sketch_ssh_key(child.target_id, ssh_key_repository)
        if admin is None or not admin.private_key or not admin.public_key:
            raise ValueError("stored Sketch administrator key is unavailable")
        _write_private_new(private, admin.private_key)
        _write_private_new(public, admin.public_key)
        varfile = material_dir / "append-inputs.json"
        variables = {**intent.nonsecret_varfile,
                     "ssh_priv_key_path": str(private), "ssh_pub_key_path": str(public),
                     "ssh_config_path": str(output_dir)}
        _write_private_new(varfile, json.dumps(variables, sort_keys=True) + "\n")
        raw_state = workspace.state_path.read_bytes()
        if hashlib.sha256(raw_state).hexdigest() != source.state_sha256:
            raise ValueError("retained state changed after provider GET")
        resources = _state_resources(json.loads(raw_state))
        release = require_devtest_terraform_release(environment=environment)
        evidence = plan_runner(
            workspace, retained_state_sha256=source.state_sha256,
            retained_resources=resources, new_edge_address=new_address,
            new_edge=intent.nodes[new_address], firewall=intent.firewall,
            expected_inventory_content=_expected_inventory(intent, private),
            reviewed_variables=variables,
            input_sha256={varfile: hashlib.sha256(varfile.read_bytes()).hexdigest()},
            var_files=[varfile], credential_repository=credentials,
            command_environment=os.environ, expected_terraform_sha256=release.sha256,
            environment=environment, deployment_target="barragan-testing",
            terraform=str(release.path),
        )
        if (lookup(child.target_id) != lease or jobs.get(parent.id) != claimed_parent
                or chains.list_for_engagement(child.target_id) != original_rows
                or evidence.state_sha256 != source.state_sha256):
            raise ValueError("append source changed during saved plan")
        private.unlink()
        public.unlink()
        private = public = None
        again = audit_published_provider_keyed_source(
            core.id, environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            lease_lookup=lookup, expected_mutation_lease=lease,
            allowed_append_plan_parent_id=parent.id,
        )
        if again != source:
            raise ValueError("original publication changed during append plan")
        result = {
            "initialSourceSha256": _fingerprint(asdict(source)),
            "initialSource": json.loads(json.dumps(asdict(source))),
            "selectedChain": selected.to_dict(),
            "retainedSharedIds": {address: str(resources[address]["id"]) for address in (
                "digitalocean_firewall.firewall", "digitalocean_ssh_key.key")},
            "newEdgeAddress": new_address, "planPath": str(evidence.plan_path),
            "planSha256": evidence.plan_sha256, "stateSha256": evidence.state_sha256,
            "topologySha256": evidence.topology_sha256,
            "sourceSha256": evidence.source_sha256,
            "lockfileSha256": evidence.lockfile_sha256,
            "inputSha256": list(evidence.input_sha256),
            "credentialRecordId": evidence.credential_record_id,
            "credentialSecretSha256": evidence.credential_secret_sha256,
            "credentialUpdatedAt": evidence.credential_updated_at,
            "terraformBinaryPath": str(evidence.terraform_binary_path),
            "terraformBinarySha256": evidence.terraform_binary_sha256,
        }
        # Cleanup takes these same locks before reclaiming an expired parent
        # claim. Keep the final claim check, child CAS, and review promotion in
        # one critical section so an old worker cannot publish after fencing.
        with _append_cleanup_locks(workspace.path):
            if (jobs.get(started.id) != started or jobs.get(parent.id) != claimed_parent
                    or datetime.now(timezone.utc) >= datetime.fromisoformat(claimed_parent.input["claimExpiresAt"])):
                raise ValueError("append worker claim expired before publication")
            terminal = JobEvent(len(started.events) + 1, "info", "reviewed append plan saved", result)
            finished = jobs.finish_if_running(started, status="succeeded", finished_at=_now(), event=terminal)
            if finished is None:
                raise ValueError("append plan child changed before publication")
            reconcile_reviewed_digitalocean_edge_append_plan(
                parent.id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                credential_repository=credentials, lease_lookup=lookup,
            )
        return finished
    except Exception as exc:
        failure_stage = exc.stage if isinstance(exc, ProviderKeyedAppendPlanPreparationError) else "preparation"
        failure = {"stage": failure_stage}
        if (isinstance(exc, ProviderKeyedAppendPlanPreparationError)
                and failure_stage == "saved_plan_gate" and exc.reason_code is not None):
            failure["reasonCode"] = exc.reason_code
        jobs.finish_if_running(started, status="failed", finished_at=_now(), event=JobEvent(
            len(started.events) + 1, "error", "provider append plan preparation failed",
            failure))
        raise ProviderKeyedAppendPlanJobError("provider append plan preparation failed") from None
    finally:
        if private is not None:
            private.unlink(missing_ok=True)
        if public is not None:
            public.unlink(missing_ok=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def reconcile_reviewed_digitalocean_edge_append_plan(
    parent_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None,
    lease_lookup=None,
):
    """Repair only the child-success to parent-review gap after a restart."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    if (environment != "devtest" or parent is None
            or parent.action != "provider_keyed_edge_append"
            or parent.status != "running"
            or parent.input.get("phase") not in {"planning", "awaiting_apply"}
            or lookup(parent.target_id) != (
                parent.input.get("corePlanId"), "provider_keyed_edge_append")):
        raise ProviderKeyedAppendPlanJobError("append review parent is unavailable")
    child = jobs.get(parent.input.get("planJobId"))
    if (child is None or child.status != "succeeded"
            or child.action != "provider_keyed_edge_append_plan"
            or child.target_id != parent.target_id
            or child.input.get("parentJobId") != parent.id
            or not child.events or child.events[-1].message != "reviewed append plan saved"
            or not _only_attested_historical_no_go_apply_children(parent, jobs)):
        raise ProviderKeyedAppendPlanJobError("append reviewed plan child is unproved")
    source = audit_published_provider_keyed_source(
        parent.input["coreJobId"], environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans, sketch_repository=chains,
        lease_lookup=lookup,
        expected_mutation_lease=(parent.input["corePlanId"], "provider_keyed_edge_append"),
        allowed_append_plan_parent_id=parent.id,
    )
    event = child.events[-1].data
    selected = chains.get(parent.target_id, parent.input["chainId"])
    if (type(event) is not dict or set(event) != _PLAN_EVENT_KEYS
            or selected is None or not selected.terraform_working_directory):
        raise ProviderKeyedAppendPlanJobError("append reviewed plan event is incomplete")
    plan_path = Path(event["planPath"])
    info = plan_path.lstat() if plan_path.exists() and not plan_path.is_symlink() else None
    root = Path(selected.terraform_working_directory)
    material = root.parents[1] / ".plan-material" / "digitalocean"
    expected_input = material / "append-inputs.json"
    input_rows = event["inputSha256"]
    retained = _state_resources(json.loads((root / "terraform.tfstate").read_bytes()))
    expected_shared = {address: str(retained[address]["id"]) for address in (
        "digitalocean_firewall.firewall", "digitalocean_ssh_key.key")}
    credential_sha, credential_updated, _ = _credential_snapshot(
        event["credentialRecordId"], credentials)
    binary = Path(event["terraformBinaryPath"])
    if (event.get("initialSource") != json.loads(json.dumps(asdict(source)))
            or event.get("initialSourceSha256") != _fingerprint(asdict(source))
            or parent.input.get("initialSourceSha256") != _fingerprint(asdict(source))
            or parent.input.get("initialSource") != json.loads(json.dumps(asdict(source)))
            or selected is None or event.get("selectedChain") != selected.to_dict()
            or event.get("stateSha256") != source.state_sha256
            or event["retainedSharedIds"] != expected_shared
            or not _EDGE_ADDRESS.fullmatch(event["newEdgeAddress"])
            or event["newEdgeAddress"] in retained
            or event["sourceSha256"] != _SOURCE_SHA256
            or event["credentialRecordId"] != json.loads((
                root / ".barragan-provider-keyed-state.json").read_text())[
                    "provider_connection_id"]
            or (event["credentialSecretSha256"], event["credentialUpdatedAt"])
               != (credential_sha, credential_updated)
            or event["topologySha256"] != _hash_file(root / ".barragan-topology.json")
            or event["lockfileSha256"] != _hash_file(root / ".terraform.lock.hcl")
            or type(input_rows) is not list or len(input_rows) != 1
            or input_rows[0] != [str(expected_input), _hash_file(expected_input)]
            or expected_input.is_symlink()
            or stat.S_IMODE(expected_input.stat().st_mode) & 0o077
            or not binary.is_absolute() or binary.is_symlink() or not binary.is_file()
            or event["terraformBinarySha256"] != _hash_file(binary)
            or not plan_path.is_absolute()
            or plan_path != Path(selected.terraform_working_directory) / ".barragan-edge-append.tfplan"
            or info is None or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077
            or _hash_file(plan_path) != event.get("planSha256")):
        raise ProviderKeyedAppendPlanJobError("retained append review artifact differs")
    digest = job_event_digest(child.events)
    if parent.input["phase"] == "awaiting_apply":
        if parent.input.get("planJournalSha256") != digest:
            raise ProviderKeyedAppendPlanJobError("append parent review journal differs")
        return parent
    saved = jobs.save(replace(parent, input={
        **{key: value for key, value in parent.input.items() if not key.startswith("claim")},
        "phase": "awaiting_apply", "planJournalSha256": digest,
    }, events=[*parent.events, JobEvent(
        len(parent.events) + 1, "info", "provider append plan ready for review", {
            "planJobId": child.id, "planSha256": event["planSha256"],
        })]))
    if saved.input.get("planJournalSha256") != digest or lookup(parent.target_id) != (
            parent.input["corePlanId"], "provider_keyed_edge_append"):
        raise ProviderKeyedAppendPlanJobError("append review restart repair differs")
    return saved


def reconcile_failed_artifact_free_edge_append_plan(
    parent_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None,
    lease_lookup=None,
):
    """Unblock initial teardown only when a failed plan left no owned artifacts."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    child = jobs.get(parent.input.get("planJobId")) if parent is not None else None
    if (environment != "devtest" or parent is None or child is None
            or parent.action != "provider_keyed_edge_append"
            or parent.status != "running" or parent.input.get("phase") != "planning"
            or child.action != "provider_keyed_edge_append_plan" or child.status != "failed"
            or child.input.get("parentJobId") != parent.id
            or not _only_attested_historical_no_go_apply_children(parent, jobs)
            or lookup(parent.target_id) != (
                parent.input.get("corePlanId"), "provider_keyed_edge_append")):
        raise ProviderKeyedAppendPlanJobError("failed plan has uncertain mutation history")
    selected = chains.get(parent.target_id, parent.input["chainId"])
    if selected is None or not selected.terraform_working_directory:
        raise ProviderKeyedAppendPlanJobError("retained append workspace is unavailable")
    workspace = Path(selected.terraform_working_directory)
    material = workspace.parents[1] / ".plan-material" / "digitalocean"
    owned = [workspace / ".barragan-edge-append.tfplan",
             material / "append-inputs.json", material / "admin-private",
             material / "admin-public"]
    if (workspace.is_symlink() or not workspace.is_dir()
            or any(os.path.lexists(path) for path in owned)
            or any(path.name.startswith(".barragan-append-inputs-")
                   for path in workspace.iterdir())):
        raise ProviderKeyedAppendPlanJobError("failed append has artifacts requiring owned cleanup")
    source = audit_published_provider_keyed_source(
        parent.input["coreJobId"], environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plans, sketch_repository=chains,
        lease_lookup=lookup,
        expected_mutation_lease=(parent.input["corePlanId"], "provider_keyed_edge_append"),
        allowed_append_plan_parent_id=parent.id,
    )
    if (source.engagement_id != parent.target_id
            or parent.input.get("initialSourceSha256") != _fingerprint(asdict(source))
            or chains.get(parent.target_id, selected.chain_id) != selected
            or lookup(parent.target_id) != (
                parent.input["corePlanId"], "provider_keyed_edge_append")):
        raise ProviderKeyedAppendPlanJobError("four-node source changed before failed-plan reconciliation")
    return plans.close_unapplied_provider_keyed_append_plan(
        parent, child, state_sha256=source.state_sha256)


def cancel_unscheduled_digitalocean_edge_append_plan(
    parent_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None, lease_lookup=None,
):
    """Fence an unstarted child after scheduling fails, then close no-apply lease."""
    jobs = job_repository or SqlAlchemyJobRepository()
    parent = jobs.get(parent_id)
    child = jobs.get(parent.input.get("planJobId")) if parent else None
    if (environment != "devtest" or parent is None or child is None
            or parent.action != "provider_keyed_edge_append"
            or parent.status != "running" or parent.input.get("phase") != "planning"
            or child.action != "provider_keyed_edge_append_plan" or child.status != "queued"
            or child.input.get("parentJobId") != parent.id):
        raise ProviderKeyedAppendPlanJobError("unstarted append child differs")
    now = datetime.now(timezone.utc)
    token = uuid4().hex
    claimed = jobs.claim_lease(child.id, owner="provider_keyed_append_schedule_failure",
        token=token, claimed_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(), eligible_statuses={"queued"})
    if claimed is None:
        raise ProviderKeyedAppendPlanJobError("append worker may have started")
    failed = jobs.save_if_leased(replace(claimed, status="failed",
        finished_at=_now(), events=[*claimed.events, JobEvent(
            len(claimed.events) + 1, "error", "append plan worker was not scheduled", {})]),
        owner="provider_keyed_append_schedule_failure", token=token)
    if failed is None or failed.status != "failed":
        raise ProviderKeyedAppendPlanJobError("append queue cancellation was not committed")
    return reconcile_failed_artifact_free_edge_append_plan(
        parent.id, environment=environment, state_root=state_root,
        job_repository=jobs, plan_repository=plan_repository,
        sketch_repository=sketch_repository, lease_lookup=lease_lookup,
    )


@contextmanager
def _append_cleanup_locks(root: Path):
    """Use the same lock order as the saved-plan runner."""
    if (root.is_symlink() or not root.is_dir() or root.resolve() != root
            or _unsafe_keyed_workspace(root) or root.parent.name != "digitalocean"):
        raise ProviderKeyedAppendPlanJobError("append workspace is unsafe")
    lock_path = root / ".barragan-initial-full-plan.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r+b") as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ProviderKeyedAppendPlanJobError("append plan lock is unsafe")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            with _ordinal_lock(SimpleNamespace(
                    path=root, schema=root.parents[1].name, provider=root.parent.name,
                    connection_fingerprint=root.name)):
                yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _owned_private_file(path: Path, *, expected_sha256: str | None = None) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077
            or (expected_sha256 is not None and _hash_file(path) != expected_sha256)):
        raise ProviderKeyedAppendPlanJobError("owned append artifact differs")


def discard_reviewed_digitalocean_edge_append_plan(
    parent_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None,
    credential_repository=None, lease_lookup=None,
):
    """Discard only a reviewed, never-applied plan; retain four-node deployment."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    if environment != "devtest":
        raise ProviderKeyedAppendPlanJobError("append discard is DevTest only")
    parent = jobs.get(parent_id)
    if parent is None:
        raise ProviderKeyedAppendPlanJobError("append review is unavailable")
    if parent.input.get("applyRequestedPlanSha256") is not None:
        raise ProviderKeyedAppendPlanJobError("approved append Apply cannot be discarded")
    selected = chains.get(parent.target_id, parent.input.get("chainId"))
    if selected is None or not selected.terraform_working_directory:
        raise ProviderKeyedAppendPlanJobError("append workspace is unavailable")
    root = Path(selected.terraform_working_directory)
    with _append_cleanup_locks(root):
        if parent.input.get("phase") == "awaiting_apply":
            if parent.input.get("applyRequestedPlanSha256") is not None:
                raise ProviderKeyedAppendPlanJobError("approved append Apply cannot be discarded")
            parent = reconcile_reviewed_digitalocean_edge_append_plan(
                parent_id, environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                credential_repository=credential_repository, lease_lookup=lookup,
            )
            child = jobs.get(parent.input["planJobId"])
            source = audit_published_provider_keyed_source(
                parent.input["coreJobId"], environment=environment, state_root=state_root,
                job_repository=jobs, plan_repository=plans, sketch_repository=chains,
                lease_lookup=lookup,
                expected_mutation_lease=(parent.input["corePlanId"], "provider_keyed_edge_append"),
                allowed_append_plan_parent_id=parent.id,
            )
            if (child is None or parent.input.get("initialSource")
                    != json.loads(json.dumps(asdict(source)))
                    or not _only_attested_historical_no_go_apply_children(parent, jobs)):
                raise ProviderKeyedAppendPlanJobError("retained four-node source differs")
            token = uuid4().hex
            now = _now()
            claimed = jobs.claim_lease(parent.id, owner="provider_keyed_append_discard",
                token=token, claimed_at=now,
                expires_at=(datetime.fromisoformat(now) + timedelta(minutes=5)).isoformat(),
                eligible_statuses={"running"}, eligible_phases={"awaiting_apply"})
            if claimed is not None and (claimed.input.get("applyRequestedPlanSha256") is not None
                                        or jobs.get(child.id) != child):
                jobs.save_if_leased(replace(claimed, input={
                    key: value for key, value in claimed.input.items()
                    if not key.startswith("claim")}),
                    owner="provider_keyed_append_discard", token=token)
            if (claimed is None or claimed.input.get("applyRequestedPlanSha256") is not None
                    or jobs.get(child.id) != child):
                raise ProviderKeyedAppendPlanJobError("approved append Apply cannot be discarded")
            parent = jobs.save_if_leased(replace(claimed, input={**claimed.input, "phase": "discarding"},
                events=[*parent.events, JobEvent(len(parent.events) + 1, "info",
                    "append plan discard requested", {
                        "planJournalSha256": job_event_digest(child.events),
                        "stateSha256": source.state_sha256,
                    })]), owner="provider_keyed_append_discard", token=token)
            if parent is None:
                raise ProviderKeyedAppendPlanJobError("append discard reservation changed")
        child = jobs.get(parent.input["planJobId"])
        marker = parent.events[-1] if parent.events else None
        if (parent.input.get("phase") != "discarding" or marker is None
                or marker.message != "append plan discard requested"
                or set(marker.data) != {"planJournalSha256", "stateSha256"}
                or marker.data["planJournalSha256"] != parent.input.get("planJournalSha256")
                or child is None or job_event_digest(child.events) != marker.data["planJournalSha256"]
                or child.status != "succeeded"
                or not child.events or child.events[-1].message != "reviewed append plan saved"
                or set(child.events[-1].data) != _PLAN_EVENT_KEYS
                or not _only_attested_historical_no_go_apply_children(parent, jobs)):
            raise ProviderKeyedAppendPlanJobError("append may have applied")
        event = child.events[-1].data
        plan_path = root / ".barragan-edge-append.tfplan"
        material = root.parents[1] / ".plan-material" / "digitalocean"
        varfile = material / "append-inputs.json"
        if (any(os.path.lexists(material / name) for name in ("admin-private", "admin-public"))
                or any(path.name.startswith(".barragan-append-inputs-")
                       for path in root.iterdir())):
            raise ProviderKeyedAppendPlanJobError("append has interrupted private inputs")
        if os.path.lexists(plan_path):
            _owned_private_file(plan_path, expected_sha256=event["planSha256"])
        if os.path.lexists(varfile):
            _owned_private_file(varfile, expected_sha256=event["inputSha256"][0][1])
        # The source is rechecked while both locks and the mutation lease are held.
        source = audit_published_provider_keyed_source(
            parent.input["coreJobId"], environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            lease_lookup=lookup,
            expected_mutation_lease=(parent.input["corePlanId"], "provider_keyed_edge_append"),
            allowed_append_plan_parent_id=parent.id,
        )
        if (parent.input.get("initialSource") != json.loads(json.dumps(asdict(source)))
                or marker.data["stateSha256"] != source.state_sha256
                or lookup(parent.target_id) != (
                    parent.input["corePlanId"], "provider_keyed_edge_append")):
            raise ProviderKeyedAppendPlanJobError("retained four-node source differs")
        plan_path.unlink(missing_ok=True)
        varfile.unlink(missing_ok=True)
        return plans.close_unapplied_provider_keyed_append_plan(
            parent, child, state_sha256=source.state_sha256)


def reconcile_no_go_digitalocean_edge_append_apply(
    parent_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None,
    lease_lookup=None,
):
    """Close only an expired Apply reservation whose child never started."""
    from app.services.provider_keyed_teardown_scope import _exact_no_go_apply_child

    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    selected = (chains.get(parent.target_id, parent.input.get("chainId"))
                if parent is not None else None)
    if (environment != "devtest" or parent is None
            or parent.action != "provider_keyed_edge_append"
            or parent.status != "failed"
            or parent.input.get("phase") not in {"attention", "no_go_cleaning"}
            or selected is None or not selected.terraform_working_directory):
        raise ProviderKeyedAppendPlanJobError("no-GO append recovery is unavailable")
    root = Path(selected.terraform_working_directory)
    with _append_cleanup_locks(root):
        parent = jobs.get(parent_id)
        if parent is None or parent.input.get("phase") not in {"attention", "no_go_cleaning"}:
            raise ProviderKeyedAppendPlanJobError("no-GO append recovery changed")
        related = jobs.list_for_engagement(parent.target_id)
        plan = jobs.get(parent.input.get("planJobId"))
        cleaning = parent.input["phase"] == "no_go_cleaning"
        apply_child = _exact_no_go_apply_child(parent, related, jobs, fenced=cleaning)
        requests = [event for event in parent.events
                    if event.message == "provider append Apply requested"]
        expiry = parent.input.get("claimExpiresAt")
        try:
            expired = (type(expiry) is str
                       and datetime.fromisoformat(expiry).tzinfo is not None
                       and datetime.now(timezone.utc) >= datetime.fromisoformat(expiry))
        except ValueError:
            expired = False
        if (not expired or apply_child is None or plan is None
                or lookup(parent.target_id) != (
                    parent.input.get("corePlanId"), "provider_keyed_edge_append")
                or parent.input.get("engagementId") != parent.target_id
                or parent.input.get("applyRequestedPlanSha256") !=
                plan.events[-1].data.get("planSha256")
                or parent.input.get("planJournalSha256") != job_event_digest(plan.events)
                or len(requests) != 1 or requests[0].data != {
                    "planJobId": plan.id,
                    "planSha256": parent.input.get("applyRequestedPlanSha256"),
                    "requestedBy": parent.input.get("applyRequestedBy"),
                    "requestedAt": parent.input.get("applyRequestedAt"),
                }
                or len([row for row in related
                        if row.action == "provider_keyed_edge_append" and
                        row.input.get("phase") != "unapplied_reconciled"]) != 1):
            raise ProviderKeyedAppendPlanJobError("no-GO append reservation is unproved")
        source = audit_published_provider_keyed_source(
            parent.input["coreJobId"], environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            lease_lookup=lookup,
            expected_mutation_lease=(parent.input["corePlanId"], "provider_keyed_edge_append"),
            allowed_append_plan_parent_id=parent.id,
        )
        event = plan.events[-1].data
        state_path = root / "terraform.tfstate"
        phase_path = root / ".barragan-apply-phase.json"
        if (parent.input.get("initialSource") != json.loads(json.dumps(asdict(source)))
                or parent.input.get("initialSourceSha256") != _fingerprint(asdict(source))
                or event.get("stateSha256") != source.state_sha256
                or state_path.is_symlink() or _hash_file(state_path) != source.state_sha256
                or phase_path.is_symlink() or not phase_path.is_file()
                or json.loads(phase_path.read_text()).get("phase") != "applied"
                or chains.get(parent.target_id, selected.chain_id) != selected):
            raise ProviderKeyedAppendPlanJobError("original four-node generation changed")
        material = root.parents[1] / ".plan-material" / "digitalocean"
        plan_path = root / ".barragan-edge-append.tfplan"
        varfile = material / "append-inputs.json"
        input_digests = event.get("inputSha256")
        if (event.get("planPath") != str(plan_path)
                or type(input_digests) is not list or len(input_digests) != 1
                or type(input_digests[0]) is not list or len(input_digests[0]) != 2
                or input_digests[0][0] != str(varfile)
                or type(input_digests[0][1]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", input_digests[0][1]) is None):
            raise ProviderKeyedAppendPlanJobError("reviewed append artifact identity differs")
        if (any(os.path.lexists(material / name) for name in ("admin-private", "admin-public"))
                or any(path.name.startswith(".barragan-append-inputs-")
                       for path in root.iterdir())):
            raise ProviderKeyedAppendPlanJobError("append private material remains")
        if os.path.lexists(plan_path):
            _owned_private_file(plan_path, expected_sha256=event["planSha256"])
        if os.path.lexists(varfile):
            _owned_private_file(varfile, expected_sha256=event["inputSha256"][0][1])
        if not cleaning:
            parent = plans.fence_no_go_provider_keyed_append_apply(
                parent, plan, apply_child, state_sha256=source.state_sha256)
            apply_child = jobs.get(apply_child.id)
            if (parent is None or apply_child is None
                    or _exact_no_go_apply_child(parent,
                        jobs.list_for_engagement(parent.target_id), jobs, fenced=True)
                    != apply_child):
                raise ProviderKeyedAppendPlanJobError("no-GO append fence changed")
        # The queued child is durably terminal before any artifact can be removed.
        for path in (plan_path, varfile):
            path.unlink(missing_ok=True)
        if (_hash_file(state_path) != source.state_sha256
                or chains.get(parent.target_id, selected.chain_id) != selected
                or lookup(parent.target_id) != (
                    parent.input["corePlanId"], "provider_keyed_edge_append")):
            raise ProviderKeyedAppendPlanJobError("no-GO append source changed after cleanup")
        return plans.close_no_go_provider_keyed_append_apply(
            parent, plan, apply_child, state_sha256=source.state_sha256)


def reconcile_interrupted_digitalocean_edge_append_plan(
    parent_id: str, *, environment: str = "devtest", state_root: Path | None = None,
    job_repository=None, plan_repository=None, sketch_repository=None,
    ssh_key_repository=None, lease_lookup=None,
):
    """Remove only owned plan residue after fencing an expired worker claim."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    chains = sketch_repository or SqlAlchemySketchChainRepository()
    lookup = lease_lookup or _db_lease_lookup
    parent = jobs.get(parent_id)
    if (environment != "devtest" or parent is None
            or parent.action != "provider_keyed_edge_append"
            or parent.status != "running" or parent.input.get("phase") != "planning"):
        raise ProviderKeyedAppendPlanJobError("interrupted append review is unavailable")
    selected = chains.get(parent.target_id, parent.input.get("chainId"))
    if selected is None or not selected.terraform_working_directory:
        raise ProviderKeyedAppendPlanJobError("interrupted append workspace is unavailable")
    root = Path(selected.terraform_working_directory)
    with _append_cleanup_locks(root):
        parent = jobs.get(parent_id)
        child = jobs.get(parent.input.get("planJobId")) if parent else None
        all_jobs = jobs.list_for_engagement(parent.target_id) if parent else []
        now = datetime.now(timezone.utc)
        owner = parent.input.get("claimOwner") if parent else None
        expiry = parent.input.get("claimExpiresAt") if parent else None
        try:
            expired = expiry is not None and now >= datetime.fromisoformat(expiry)
        except (TypeError, ValueError):
            expired = False
        if (parent is None or parent.status != "running" or parent.input.get("phase") != "planning"
                or child is None or child.action != "provider_keyed_edge_append_plan"
                or child.input.get("parentJobId") != parent.id
                or child.status not in {"running", "failed"}
                or not _only_attested_historical_no_go_apply_children(parent, jobs)
                or lookup(parent.target_id) != (
                    parent.input.get("corePlanId"), "provider_keyed_edge_append")
                or (owner != "provider_keyed_append_cleanup" and not expired)):
            raise ProviderKeyedAppendPlanJobError("interrupted append may still be running or applied")
        token = (parent.input["claimToken"] if owner == "provider_keyed_append_cleanup"
                 else uuid4().hex)
        claimed_at = now.isoformat()
        claimed = jobs.claim_lease(
            parent.id, owner="provider_keyed_append_cleanup", token=token,
            claimed_at=claimed_at, expires_at=(now + timedelta(minutes=5)).isoformat(),
            eligible_statuses={"running"}, eligible_phases={"planning"},
        )
        if claimed is None:
            raise ProviderKeyedAppendPlanJobError("interrupted append claim changed")
        parent = claimed
        # Fence the old worker's child terminal CAS before inspecting or
        # deleting any artifact. If its success won first, leave files alone.
        if child.status == "running":
            child = jobs.finish_if_running(child, status="failed", finished_at=_now(),
                event=JobEvent(len(child.events) + 1, "error",
                    "interrupted append plan reconciled without apply", {}))
            if child is None:
                raise ProviderKeyedAppendPlanJobError("interrupted append child changed")
        anchor = parent.input.get("initialSource")
        state_path = root / "terraform.tfstate"
        if (type(anchor) is not dict or parent.input.get("initialSourceSha256") != _fingerprint(anchor)
                or state_path.is_symlink() or not state_path.is_file()
                or hashlib.sha256(state_path.read_bytes()).hexdigest() != anchor.get("state_sha256")
                or chains.get(parent.target_id, selected.chain_id) != selected):
            raise ProviderKeyedAppendPlanJobError("retained four-node state differs")
        material = root.parents[1] / ".plan-material" / "digitalocean"
        plan_path = root / ".barragan-edge-append.tfplan"
        varfile = material / "append-inputs.json"
        private, public = material / "admin-private", material / "admin-public"
        staged = [path for path in root.iterdir()
                  if path.name.startswith(".barragan-append-inputs-")]
        if any(not re.fullmatch(r"\.barragan-append-inputs-[A-Za-z0-9_-]{8}", path.name)
               for path in staged):
            raise ProviderKeyedAppendPlanJobError("append staging ownership is ambiguous")
        for path in (plan_path, varfile, private, public):
            if os.path.lexists(path):
                _owned_private_file(path)
        if os.path.lexists(private) or os.path.lexists(public):
            admin = retrieve_sketch_ssh_key(parent.target_id, ssh_key_repository)
            if (admin is None
                    or (os.path.lexists(private) and private.read_bytes() != admin.private_key.encode())
                    or (os.path.lexists(public) and public.read_bytes() != admin.public_key.encode())):
                raise ProviderKeyedAppendPlanJobError("append administrator key residue differs")
        for directory in staged:
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ProviderKeyedAppendPlanJobError("append staging directory differs")
            files = list(directory.iterdir())
            if not {path.name for path in files} <= {"input-0.json", "credential.json"}:
                raise ProviderKeyedAppendPlanJobError("append staging contents differ")
            for path in files:
                _owned_private_file(path)
        for path in (private, public):
            path.unlink(missing_ok=True)
        for directory in staged:
            for path in directory.iterdir():
                path.unlink()
            directory.rmdir()
        source = audit_published_provider_keyed_source(
            parent.input["coreJobId"], environment=environment, state_root=state_root,
            job_repository=jobs, plan_repository=plans, sketch_repository=chains,
            lease_lookup=lookup,
            expected_mutation_lease=(parent.input["corePlanId"], "provider_keyed_edge_append"),
            allowed_append_plan_parent_id=parent.id,
        )
        if (anchor != json.loads(json.dumps(asdict(source)))
                or jobs.get(parent.id) != parent
                or lookup(parent.target_id) != (
                    parent.input["corePlanId"], "provider_keyed_edge_append")):
            raise ProviderKeyedAppendPlanJobError("interrupted append source differs")
        plan_path.unlink(missing_ok=True)
        varfile.unlink(missing_ok=True)
        return plans.close_unapplied_provider_keyed_append_plan(
            parent, child, state_sha256=source.state_sha256)
