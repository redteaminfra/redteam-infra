# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private one-shot OCI core GO for a fenced mixed zero-Apply generation.

Terraform Apply completion leaves exact provider absence pending. No public
dispatcher calls this module, and an interrupted child is never replayed.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.domain import JobEvent
from app.integrations.linode_validation import UrllibLinodeTransport
from app.integrations.oci_read_validation import resolve_oci_cli
from app.services.core_deployment_plans import require_keyed_core_terraform_source_manifest
from app.services.credentials import decrypt_secret_value
from app.services.engagement_teardown import _fingerprint
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT
from app.services.observer_checks import (
    ObserverSshKey, SshObserverRunner,
    _inspector_host_from_settings, _inspector_support_baseline_current,
)
from app.services.provider_catalog import UrllibProviderCatalogTransport
from app.services.provider_keyed_core_destroy_apply import _file_identity
from app.services.provider_keyed_core_destroy_preview import (
    _exact_destroy, _read_regular, _state_data_ids, _terraform_quiescent,
)
from app.services.provider_keyed_gated_runner import run_gated_command
from app.services.provider_keyed_inspector_prepare_binder import (
    _existing_key_identity, _safe_key_identity, _verify_key_pair,
)
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderPending, prove_retained_keyed_inspector_provider,
)
from app.services.provider_keyed_mixed_zero_apply_cleanup import _parent_id
from app.services.provider_keyed_mixed_interrupted_cleanup import _parent_id as _interrupted_parent_id
from app.services.provider_keyed_mixed_interrupted_oci_tail import (
    audit_current_interrupted_oci_tail, stable_interrupted_oci_authority,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    parent_id as _published_parent_id,
)
from app.services.provider_keyed_mixed_published_tail_authority import (
    PublishedMixedTailAuthority, audit_published_mixed_tail_authority,
    stable_published_mixed_tail_authority,
)
from app.services.provider_keyed_mixed_zero_apply_core_preview import (
    _child_id as _preview_child_id, _require_no_independent_bindings,
    recognize_interrupted_core_preview, recognize_published_core_preview,
)
from app.services.provider_keyed_mixed_interrupted_dispatch import _default_quiescent
from app.services.provider_keyed_mixed_zero_apply_teardown_source import _apply_pre_go_prefix
from app.services.provider_keyed_mixed_zero_apply_inventory import (
    inspect_mixed_zero_apply_provider_inventory,
)
from app.services.provider_keyed_mixed_post_sketch_absence import (
    audit_zero_apply_post_sketch_absence,
)
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_oci_exact_absence import (
    OciExactWitness, _default_runner as _oci_runner, prove_oci_core_visibility,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import (
    SqlAlchemyJobRepository, StoredJobRun, _valid_mixed_core_show_takeover,
    _valid_mixed_core_apply_no_go_takeover, _mixed_core_no_go_attempts,
    job_event_digest,
)
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


ACTION = "provider_keyed_mixed_zero_apply_core_destroy_apply"
_FENCE = "provider_keyed_teardown_fence"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_LOG = logging.getLogger(__name__)


class MixedZeroApplyCoreApplyAttention(ValueError):
    """One-shot OCI GO is unproved; reconcile its saved child."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(value: str) -> str:
    # A full multi-provider/Inspector audit can be slower than a minute.
    # Heartbeats remain frequent; the longer claim only bounds a single audit.
    return (datetime.fromisoformat(value) + timedelta(minutes=5)).isoformat()


def _child_id(core_job_id: str) -> str:
    return f"job-provider-keyed-mixed-core-destroy-apply-{core_job_id.removeprefix('job-')}"


_CLAIM_KEYS = {"claimOwner", "claimToken", "claimClaimedAt",
               "claimHeartbeatAt", "claimExpiresAt"}


def interrupted_show_restartable(
    child: StoredJobRun | None, parent: StoredJobRun,
    preview: StoredJobRun, core_job_id: str, *,
    process_quiescent: Callable[[dict], bool] = _default_quiescent,
    terraform_quiescent: Callable[[], bool] = _terraform_quiescent,
    published: bool = False,
) -> bool:
    """Only a quiescent, expired pre-GO SHOW can be considered for recovery.

    This selector is not mutation authority; the worker checks all retained
    plan, state, provider, Inspector and Sketch evidence before taking a CAS.
    """
    if (child is None or parent is None or preview is None
            or parent.action != ("provider_keyed_mixed_published_cleanup" if published
                                 else "provider_keyed_mixed_interrupted_cleanup")
            or preview.status != "succeeded" or len(preview.events) != 3
            or child.id != _child_id(core_job_id) or child.action != ACTION
            or child.target != f"engagement:{parent.target_id}"
            or child.target_type != "engagement" or child.target_id != parent.target_id
            or child.requested_by != parent.requested_by or child.artifact_refs != []
            or child.finished_at is not None):
        return False
    expected = {
        "teardownParentId": parent.id, "coreJobId": core_job_id,
        "corePlanId": parent.input.get("corePlanId"),
        "sourceSha256": parent.input.get(
            "publishedSourceSha256" if published else "sourceSha256"),
        "previewJobId": preview.id,
        "previewJournalSha256": job_event_digest(preview.events),
        "planSha256": preview.events[2].data.get("planSha256"), "mutation": True,
    }
    if {key: value for key, value in child.input.items()
            if key not in _CLAIM_KEYS} != expected:
        return False
    at = _now()
    if not _valid_mixed_core_show_takeover(
            child, expected_event_digest=job_event_digest(child.events),
            owner=f"provider-keyed-mixed-core-destroy-{uuid4().hex}",
            token=uuid4().hex, claimed_at=at, expires_at=_later(at)):
        return False
    try:
        identity = {key: child.events[3].data[key] for key in (
            "bootId", "pid", "pgid", "startTicks")}
        return process_quiescent(identity) is True and terraform_quiescent() is True
    except Exception:
        return False


def interrupted_apply_no_go_restartable(
    child: StoredJobRun | None, parent: StoredJobRun,
    preview: StoredJobRun, core_job_id: str, *,
    process_quiescent: Callable[[dict], bool] = _default_quiescent,
    terraform_quiescent: Callable[[], bool] = _terraform_quiescent,
    published: bool = False,
) -> bool:
    """Select only an exact quiescent chain of pre-GO Apply starts."""
    if (child is None or parent is None or preview is None
            or parent.action != ("provider_keyed_mixed_published_cleanup" if published
                                 else "provider_keyed_mixed_interrupted_cleanup")
            or preview.status != "succeeded" or len(preview.events) != 3
            or child.id != _child_id(core_job_id) or child.action != ACTION
            or child.target != f"engagement:{parent.target_id}"
            or child.target_type != "engagement" or child.target_id != parent.target_id
            or child.requested_by != parent.requested_by or child.artifact_refs != []
            or child.finished_at is not None):
        return False
    expected = {
        "teardownParentId": parent.id, "coreJobId": core_job_id,
        "corePlanId": parent.input.get("corePlanId"),
        "sourceSha256": parent.input.get(
            "publishedSourceSha256" if published else "sourceSha256"),
        "previewJobId": preview.id,
        "previewJournalSha256": job_event_digest(preview.events),
        "planSha256": preview.events[2].data.get("planSha256"), "mutation": True,
    }
    if {key: value for key, value in child.input.items()
            if key not in _CLAIM_KEYS} != expected:
        return False
    at = _now()
    if not _valid_mixed_core_apply_no_go_takeover(
            child, expected_event_digest=job_event_digest(child.events),
            owner=f"provider-keyed-mixed-core-destroy-{uuid4().hex}",
            token=uuid4().hex, claimed_at=at, expires_at=_later(at)):
        return False
    try:
        return (all(process_quiescent(identity) is True
                    for identity in _mixed_core_no_go_attempts(child.events))
                and terraform_quiescent() is True)
    except Exception:
        return False


def precommand_apply_restartable(child: StoredJobRun | None, parent: StoredJobRun,
                                 preview: StoredJobRun, core_job_id: str) -> bool:
    """Select only an exact queued or expired pre-intent Apply journal."""
    published = parent.action == "provider_keyed_mixed_published_cleanup"
    source = (parent.input.get("publishedSource" if published else "source")
              if isinstance(parent.input, dict) else None)
    if (child is None or preview is None or not isinstance(source, dict)
            or preview.status != "succeeded"
            or len(preview.events) != 3):
        return False
    expected = {
        "teardownParentId": parent.id, "coreJobId": core_job_id,
        "corePlanId": parent.input.get("corePlanId"),
        "sourceSha256": (parent.input.get("publishedSourceSha256") if published
                         else parent.input.get("sourceSha256")
                         if parent.action == "provider_keyed_mixed_interrupted_cleanup"
                         else _fingerprint(source)), "previewJobId": preview.id,
        "previewJournalSha256": job_event_digest(preview.events),
        "planSha256": preview.events[2].data.get("planSha256"), "mutation": True,
    }
    events = [JobEvent(1, "info", "mixed core destroy apply queued", {}),
              JobEvent(2, "info", "mixed core destroy apply started", {})]
    if (child.id != _child_id(core_job_id) or child.action != ACTION
            or child.target != f"engagement:{parent.target_id}"
            or child.target_type != "engagement" or child.target_id != parent.target_id
            or child.requested_by != parent.requested_by or child.artifact_refs != []
            or child.finished_at is not None
            or {key: value for key, value in child.input.items()
                if key not in _CLAIM_KEYS} != expected):
        return False
    if child.status == "queued":
        return child.input == expected and child.started_at is None and child.events == events[:1]
    if child.status != "running" or child.started_at is None or child.events != events:
        return False
    claim = set(child.input) - set(expected)
    if not claim:
        return True  # Crash after start and before first claim.
    if claim not in (_CLAIM_KEYS - {"claimHeartbeatAt"}, _CLAIM_KEYS):
        return False
    try:
        expires = datetime.fromisoformat(child.input["claimExpiresAt"])
        return (isinstance(child.input.get("claimOwner"), str)
                and child.input["claimOwner"].startswith("provider-keyed-mixed-core-destroy-")
                and isinstance(child.input.get("claimToken"), str)
                and len(child.input["claimToken"]) >= 16
                and isinstance(child.input.get("claimClaimedAt"), str)
                and ("claimHeartbeatAt" not in claim
                     or isinstance(child.input["claimHeartbeatAt"], str))
                and expires.tzinfo is not None and expires <= datetime.now(timezone.utc))
    except (KeyError, TypeError, ValueError):
        return False


def _prove_retained_inspector(source, engagement_id: str, *, fence: Callable[[], None]) -> str:
    """Read exact retained host and existing key, then SSH-probe without mutation."""
    settings = SqlAlchemyObserverSettingsRepository().get(engagement_id)
    rows = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)
    selected = [row for row in rows if row.id in source.owned_inspector_record_ids]
    if (settings is None or not settings.enabled or len(selected) != 2
            or {row.id for row in selected} != set(source.owned_inspector_record_ids)):
        raise ValueError("retained Inspector readiness differs")
    host_row = next(row for row in selected if row.resource_type == "inspector_instance")
    firewall = next(row for row in selected if row.resource_type == "inspector_firewall")
    host = _inspector_host_from_settings(settings.current_host, settings=settings)
    if host is None:
        raise ValueError("retained Inspector current host is absent")
    expected_host_metadata = {
        **host.metadata, "role": "inspector", "barraganOwned": True,
        "inspectionJobId": host_row.adoption_job_id, "cleanupRequired": True,
        "publicIp": host.public_ip, "publicIps": [host.public_ip],
        "sshUser": host.ssh_user,
    }
    firewall_data = host.metadata.get("providerFirewall")
    expected_firewall_metadata = {
        "role": "inspector_firewall", "barraganOwned": True,
        "inspectorHostResourceId": host.resource_id,
        "inspectionJobId": host_row.adoption_job_id,
        "managementSourceCidr": (
            firewall_data.get("managementSourceCidr") if isinstance(firewall_data, dict) else None),
        "cleanupRequired": True,
    }
    if (settings.current_host != host.to_dict() or not _inspector_support_baseline_current(host)
            or host.provider != "linode" or host.resource_id != firewall.metadata.get("inspectorHostResourceId")
            or host.status not in {"running", "active", "offline", "provisioning", "booting", "busy"}
            or host_row.resource_type != "inspector_instance"
            or host_row.provider != host.provider or host_row.resource_id != host.resource_id
            or host_row.name != host.name or host_row.region != host.region
            or host_row.metadata != expected_host_metadata
            or firewall.name != (firewall_data.get("name") if isinstance(firewall_data, dict) else None)
            or firewall.resource_id != (firewall_data.get("resourceId") if isinstance(firewall_data, dict) else None)
            or firewall.metadata != expected_firewall_metadata
            or firewall.adoption_job_id != host_row.adoption_job_id
            or firewall.provider != "linode" or firewall.status != "active"
            or host_row.status != "active"):
        raise ValueError("retained Inspector settings or ownership differs")
    path, digest = _safe_key_identity(_existing_key_identity)
    _verify_key_pair(path, digest)
    public = Path(path + ".pub").read_text(encoding="utf-8").strip()
    credential = SqlAlchemyCredentialRepository().get_default("linode")
    management_cidr = firewall.metadata.get("managementSourceCidr")
    if (credential is None or credential.provider != "linode"
            or credential.status != "active" or credential.is_default is not True
            or not isinstance(management_cidr, str)):
        raise ValueError("retained Inspector credential or source differs")
    token = decrypt_secret_value(credential.encrypted_secret)
    for attempt in range(6):
        fence()
        try:
            provider_proof = prove_retained_keyed_inspector_provider(
                expected_host=host, size=settings.size, token=token,
                transport=_RenewingLinode(fence), firewall_id=firewall.resource_id,
                management_cidr=management_cidr)
            break
        except InspectorProviderPending:
            if attempt == 5:
                raise
            fence()
            time.sleep(5)
    if provider_proof.host.status != "running":
        raise ValueError("retained Inspector provider is not running")
    fence()
    SshObserverRunner(readiness_attempts=1).verify_access(
        host=host, ssh_key=ObserverSshKey(path, public))
    fence()
    return _fingerprint({"host": host.to_dict(), "firewallId": firewall.id,
                         "keyFingerprintSha256": digest,
                         "credentialId": credential.id,
                         "credentialUpdatedAt": credential.updated_at,
                         "providerProof": asdict(provider_proof)})


class _RenewingLinode:
    def __init__(self, fence: Callable[[], None]):
        self.client, self.fence = UrllibLinodeTransport(), fence

    def request(self, method, path, token, body=None):
        self.fence()
        result = self.client.request(method, path, token, body)
        self.fence()
        return result


class _RenewingDigitalOcean:
    def __init__(self, fence: Callable[[], None]):
        self.client, self.fence = UrllibProviderCatalogTransport(), fence

    def request(self, base_url, method, path, token):
        self.fence()
        result = self.client.request(base_url, method, path, token)
        self.fence()
        return result


def _fresh_inventory(engagement_id, core_job_id, *, audit_options, fence):
    return inspect_mixed_zero_apply_provider_inventory(
        engagement_id, core_job_id, **audit_options,
        linode_transport=_RenewingLinode(fence),
        digitalocean_transport=_RenewingDigitalOcean(fence))


def apply_mixed_zero_apply_oci_core_destroy(
    engagement_id: str, core_job_id: str, *, environment: str,
    state_root: Path, core_state_root: Path, job_repository=None,
    plan_repository=None, lease_lookup=None,
    source_dependencies: Mapping[str, object] | None = None,
    binding_check: Callable = _require_no_independent_bindings,
    inspector_prover: Callable = _prove_retained_inspector,
    inventory_reader: Callable = _fresh_inventory,
    release_check: Callable = require_devtest_terraform_release,
    source_check: Callable = require_keyed_core_terraform_source_manifest,
    gated_command_runner: Callable = run_gated_command,
    visibility_prover: Callable = prove_oci_core_visibility,
    oci_command_runner: Callable = _oci_runner,
    oci_executable: Path | None = None,
    process_quiescent: Callable[[dict], bool] = _default_quiescent,
    terraform_quiescent: Callable[[], bool] = _terraform_quiescent,
    interrupted: bool = False, published: bool = False,
) -> StoredJobRun:
    """Run one claimed saved-plan Apply; preserve exact IDs for later absence."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    diagnostic_step = "source review"
    try:
        if (environment != "devtest" or state_root != _default_state_root()
                or core_state_root != DEFAULT_TERRAFORM_STATE_ROOT):
            raise ValueError("private DevTest root differs")
        dependencies = dict(source_dependencies or {})
        dependencies.update(job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
        core = jobs.get(core_job_id)
        plan_id = core.input["corePlanId"]
        if (type(interrupted) is not bool or type(published) is not bool
                or (interrupted and published)):
            raise ValueError("mixed OCI mode differs")
        parent = jobs.get((_published_parent_id if published else
                           _interrupted_parent_id if interrupted else _parent_id)(core_job_id))
        preview = jobs.get(_preview_child_id(core_job_id))
        if parent is None or preview is None or preview.status != "succeeded":
            raise ValueError("fenced mixed core preview is absent")

        def audit_source():
            if published:
                return audit_published_mixed_tail_authority(
                    parent.id, environment=environment, state_root=state_root,
                    core_state_root=core_state_root, **dependencies)
            if interrupted:
                return audit_current_interrupted_oci_tail(
                    engagement_id, core_job_id, environment=environment,
                    state_root=state_root, core_state_root=core_state_root,
                    **dependencies)
            return audit_zero_apply_post_sketch_absence(
                parent, engagement_id, core_job_id, environment=environment,
                state_root=state_root, core_state_root=core_state_root,
                lease_owner=plan_id, lease_operation=_FENCE, **dependencies).source

        source = audit_source()
        if (published and (type(source) is not PublishedMixedTailAuthority
                           or source.parent != parent
                           or source.core_job_id != core_job_id
                           or source.core_plan_id != plan_id
                           or parent.input.get("publishedSourceSha256")
                           != _fingerprint(parent.input.get("publishedSource")))):
            raise ValueError("published OCI source differs")
        def source_unchanged() -> bool:
            fresh = audit_source()
            if published:
                return (type(fresh) is PublishedMixedTailAuthority
                        and stable_published_mixed_tail_authority(fresh)
                        == stable_published_mixed_tail_authority(source))
            if not interrupted:
                return fresh == source
            return (stable_interrupted_oci_authority(fresh)
                    == stable_interrupted_oci_authority(source))
        plan = plans.get(plan_id)
        evidence = plan.evidence
        state_path = Path(evidence["terraformStatePath"])
        run_dir = Path(evidence["runDirectory"])
        data_dir = Path(evidence["terraformDataDir"])
        plan_path = state_path.parent / f".barragan-mixed-core-destroy-{core_job_id.removeprefix('job-')}.tfplan"
        receipt = (recognize_published_core_preview(
            preview, parent, core_job_id, source) if published
            else recognize_interrupted_core_preview(
            preview, parent, core_job_id, source) if interrupted
            else preview.events[2].data)
        release = release_check(environment=environment)
        if (release.version != evidence["terraformFingerprint"]
                or not _HASH.fullmatch(release.sha256)
                or receipt["terraformBinarySha256"] != release.sha256
                or ((interrupted or published) and (
                    receipt["planPath"] != str(plan_path)
                    or receipt["sourceManifestSha256"]
                    != _fingerprint(evidence["keyedCoreTerraformSourceManifest"])))
                or _file_identity(plan_path) != (
                    receipt["planDevice"], receipt["planInode"], receipt["planSha256"])):
            raise ValueError("reviewed saved plan differs")
        state_bytes = _read_regular(state_path)
        inventory = parse_applied_oci_core_state(
            state_bytes, proxy_count=evidence["proxyCount"],
            elk_enabled=evidence["elkEnabled"],
            compartment_id=evidence["target"]["compartmentId"],
            engagement_name=core.input["engagementName"])
        if (source.core_state_sha256 != inventory.raw_state_sha256
                or ((interrupted or published) and (
                    receipt["resourceCount"] != len(inventory.resources)
                    or source.core_inventory_sha256 != inventory.inventory_sha256))):
            raise ValueError("reviewed core state differs")
        source_check(run_dir, evidence["keyedCoreTerraformSourceManifest"])
        if (_file_identity(run_dir / ".terraform.lock.hcl")[2]
                != evidence["providerLockFingerprint"]
                or _file_identity(Path(evidence["sshPublicKeyPath"]))[2]
                != evidence["publicKeyFingerprint"]):
            raise ValueError("reviewed OCI source changed")
        binding_check(engagement_id)
        child_id = _child_id(core_job_id)
        base_input = {
            "teardownParentId": parent.id, "coreJobId": core.id,
            "corePlanId": plan.id,
            "sourceSha256": parent.input[
                "publishedSourceSha256" if published else "sourceSha256"],
            "previewJobId": preview.id,
            "previewJournalSha256": job_event_digest(preview.events),
            "planSha256": receipt["planSha256"], "mutation": True,
        }
        queued = StoredJobRun(
            child_id, ACTION, "queued", f"engagement:{engagement_id}",
            "engagement", engagement_id, parent.requested_by, base_input, [],
            _now(), None, None,
            [JobEvent(1, "info", "mixed core destroy apply queued", {})])
        existing = jobs.get(child_id)
        related = [row for row in jobs.list_for_engagement(engagement_id)
                   if row.action == ACTION and row.input.get("coreJobId") == core_job_id]
        if any(row.id != child_id for row in related):
            raise ValueError("alien mixed core Apply child exists")
        recovering_show = (interrupted or published) and interrupted_show_restartable(
            existing, parent, preview, core_job_id,
            process_quiescent=process_quiescent,
            terraform_quiescent=terraform_quiescent, published=published)
        recovering_apply = (interrupted or published) and not recovering_show and interrupted_apply_no_go_restartable(
            existing, parent, preview, core_job_id,
            process_quiescent=process_quiescent,
            terraform_quiescent=terraform_quiescent, published=published)
        if recovering_show or recovering_apply:
            _apply_pre_go_prefix(existing, core=core, plan=plan,
                                 inventory=inventory, preview=preview,
                                 interrupted=interrupted, terraform_path=release.path)
        if (existing is not None and not recovering_show and not recovering_apply
                and not precommand_apply_restartable(
                    existing, parent, preview, core_job_id)):
            raise ValueError("mixed core Apply is not safely pre-command")
        saved = existing if recovering_show or recovering_apply else jobs.save_if_absent(queued)
        if recovering_show or recovering_apply:
            current = existing
        elif existing is None or existing.status == "queued":
            if (saved.id != queued.id or saved.action != ACTION or saved.status != "queued"
                    or saved.input != base_input or saved.events != queued.events):
                raise ValueError("mixed core Apply reservation lost")
            current = jobs.start_if_queued(
                saved, started_at=_now(),
                event=JobEvent(2, "info", "mixed core destroy apply started", {}))
            if current is None:
                raise ValueError("mixed core Apply start lost")
        else:
            if saved != existing:
                raise ValueError("mixed core Apply journal changed before claim")
            current = existing
        owner = f"provider-keyed-mixed-core-destroy-{uuid4().hex}"
        token = uuid4().hex
        at = _now()
        current = (jobs.take_over_mixed_core_show(
            current, expected_event_digest=job_event_digest(current.events),
            owner=owner, token=token, claimed_at=at, expires_at=_later(at))
            if recovering_show else jobs.take_over_mixed_core_apply_no_go(
                current, expected_event_digest=job_event_digest(current.events),
                owner=owner, token=token, claimed_at=at, expires_at=_later(at))
            if recovering_apply else jobs.claim_lease(
                child_id, owner=owner, token=token, claimed_at=at,
                expires_at=_later(at), eligible_statuses={"running"}))
        expected_events = ([*existing.events, JobEvent(
            len(existing.events) + 1, "info", "mixed core SHOW recovery claimed", {
                "originalJournalSha256": job_event_digest(existing.events),
                "originalInvocationId": existing.events[2].data["invocationId"],
        })] if recovering_show else [*existing.events, JobEvent(
            len(existing.events) + 1, "info", "mixed core pre-GO Apply recovery claimed", {
                "originalJournalSha256": job_event_digest(existing.events),
                "originalInvocationId": existing.events[-2].data["invocationId"],
            })] if recovering_apply else [
                queued.events[0], JobEvent(2, "info", "mixed core destroy apply started", {})])
        if (current is None or current.events != expected_events
                or {key: value for key, value in current.input.items()
                    if key not in _CLAIM_KEYS} != base_input
                or current.input.get("claimOwner") != owner
                or current.input.get("claimToken") != token):
            raise ValueError("mixed core Apply claim lost")
        if recovering_apply:
            # Every gated process in the abandoned chain must remain absent.
            identities = _mixed_core_no_go_attempts(existing.events)
            if (any(process_quiescent(identity) is not True for identity in identities)
                    or terraform_quiescent() is not True):
                raise ValueError("prior pre-GO Apply process returned")

        def claim_fence():
            if (jobs.get(child_id) != current or jobs.get(parent.id) != parent
                    or jobs.get(core.id) != core or jobs.get(preview.id) != preview
                    or plans.get(plan.id) != plan or lookup(engagement_id) != (plan.id, _FENCE)
                    or datetime.now(timezone.utc) >= datetime.fromisoformat(
                        current.input["claimExpiresAt"])):
                raise ValueError("mixed core Apply claim or parent changed")

        def pre_go_fence():
            nonlocal diagnostic_step
            diagnostic_step = "core claim fence"
            claim_fence()
            diagnostic_step = "published source and provider audit" if published else "core source audit"
            if not source_unchanged():
                raise ValueError("mixed core GO source changed")
            diagnostic_step = "core state, plan, lock, key, and Terraform identity"
            if (_file_identity(state_path)[2] != inventory.raw_state_sha256
                    or _file_identity(plan_path) != (
                        receipt["planDevice"], receipt["planInode"], receipt["planSha256"])
                    or _file_identity(run_dir / ".terraform.lock.hcl")[2]
                    != evidence["providerLockFingerprint"]
                    or _file_identity(Path(evidence["sshPublicKeyPath"]))[2]
                    != evidence["publicKeyFingerprint"]
                    or release_check(environment=environment) != release):
                raise ValueError("mixed core GO source changed")
            diagnostic_step = "core source manifest"
            source_check(run_dir, evidence["keyedCoreTerraformSourceManifest"])
            diagnostic_step = "core engagement binding"
            binding_check(engagement_id)

        def renew(*, prestate: bool):
            nonlocal current
            pre_go_fence() if prestate else claim_fence()
            at = _now()
            updated = jobs.renew_lease(child_id, owner=owner, token=token,
                                       heartbeat_at=at, expires_at=_later(at))
            if updated is None or updated.events != current.events:
                raise ValueError("mixed core Apply heartbeat lost")
            current = updated

        def append(message: str, data: dict, *, prestate: bool = True):
            nonlocal current
            pre_go_fence() if prestate else claim_fence()
            at = _now()
            updated = jobs.append_core_destroy_apply_event_if_running_claimed(
                current, owner=owner, token=token,
                expected_event_digest=job_event_digest(current.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(current.events) + 1, "info", message, data))
            if updated is None:
                raise ValueError("mixed core Apply journal lost")
            current = updated

        audit_options = dict(environment=environment, state_root=state_root,
                             core_state_root=core_state_root, lease_owner=plan_id,
                             **dependencies)

        def check_support():
            nonlocal diagnostic_step
            # This is a read-only support probe bracketed by full source
            # fences at its callers and again immediately before Apply GO.
            # Keep the worker claim alive during slow Inspector/provider reads
            # without recursively repeating the complete provider audit.
            diagnostic_step = "support claim fence"
            renew(prestate=False)
            diagnostic_step = "retained Inspector proof"
            ready = inspector_prover(source, engagement_id,
                                     fence=lambda: renew(prestate=False))
            diagnostic_step = "support claim recheck"
            renew(prestate=False)
            diagnostic_step = "published provider absence audit" if published else "provider inventory audit"
            visibility = (audit_source().post_sketch_absence if interrupted else
                          audit_source() if published else
                          inventory_reader(
                              engagement_id, core_job_id, audit_options=audit_options,
                              fence=lambda: renew(prestate=True)))
            diagnostic_step = "support result fence"
            renew(prestate=True)
            observation = (visibility.checkpoint_sha256 if interrupted else
                           _fingerprint([asdict(row) for row in visibility.provider_receipts])
                           if published else
                           getattr(visibility, "observation_sha256", None))
            if (not isinstance(ready, str) or not _HASH.fullmatch(ready)
                    or not isinstance(observation, str) or not _HASH.fullmatch(observation)):
                raise ValueError("retained support proof differs")
            return ready, observation, (visibility if interrupted else None)

        diagnostic_step = "initial pre-GO source fence"
        pre_go_fence()
        diagnostic_step = "retained support checks"
        ready_sha, observation_sha, _ = check_support()

        def run(phase: str, args: list[str]):
            stage, intent, started = "requested", None, None

            def on_intent(value):
                nonlocal stage, intent
                if (stage != "requested" or value.scratch_path != str(run_dir)
                        or value.argv_sha256 != _fingerprint(args)):
                    raise ValueError("mixed core command intent differs")
                append("core destroy command intent fenced", {
                    "phase": phase, "invocationId": value.invocation_id,
                    "argvSha256": value.argv_sha256}, prestate=phase != "show")
                intent, stage = value, "intent"

            def on_started(value):
                nonlocal stage, started
                if stage != "intent" or value.intent != intent:
                    raise ValueError("mixed core command start differs")
                append("core destroy command started before GO", {
                    "phase": phase, "invocationId": intent.invocation_id,
                    "bootId": value.identity.boot_id, "pid": value.identity.pid,
                    "pgid": value.identity.pgid, "startTicks": value.identity.start_ticks},
                    prestate=phase != "show")
                started, stage = value, "started"
                if phase == "apply":
                    pre_go_fence()
                    current_ready, current_observation, current_absence = check_support()
                    if current_ready != ready_sha:
                        raise ValueError("retained Inspector changed at GO")
                    current_witness = visibility_prover(
                        inventory, compartment_id=evidence["target"]["compartmentId"],
                        region=evidence["target"]["region"],
                        engagement_name=core.input["engagementName"],
                        oci_executable=str(executable), runner=witnessed_command,
                        fence=lambda: renew(prestate=False))
                    # The OCI GET/LIST scan is read-only. Recheck the complete
                    # source after it, before recording support or releasing GO.
                    pre_go_fence()
                    if (type(current_witness) is not OciExactWitness
                            or current_witness.phase != "present"
                            or current_witness.inventory_sha256 != witness.inventory_sha256
                            or current_witness.resource_ids_sha256 != witness.resource_ids_sha256
                            or current_witness.compartment_id != witness.compartment_id
                            or current_witness.region != witness.region
                            or current_witness.auth != witness.auth
                            or current_witness.principal_sha256 != witness.principal_sha256
                            or not _HASH.fullmatch(current_witness.evidence_sha256)
                            or _file_identity(executable) != cli_identity):
                        raise ValueError("OCI pre-GO visibility changed")
                    # Provider inventory is an observation, not a durable
                    # account-wide equality gate: unrelated rows may change.
                    append("core destroy GO support rechecked", {
                        "inspectorReadySha256": current_ready,
                        "providerObservationSha256": current_observation,
                        "ociVisibilityWitness": asdict(current_witness),
                        "ociVisibilityWitnessSha256": _fingerprint(asdict(current_witness)),
                        **({"postSketchAbsence": asdict(current_absence)}
                           if interrupted else {})})
                    pre_go_fence()

            def on_heartbeat(value):
                if stage != "started" or value != started:
                    raise ValueError("mixed core command heartbeat differs")
                # Provider/Inspector audits can take longer than a heartbeat.
                # The full source check is repeated before accepting SHOW's
                # result and again immediately at Apply GO.
                renew(prestate=False)

            def on_result(value):
                nonlocal stage
                if stage != "started" or value.started != started:
                    raise ValueError("mixed core command result differs")
                renew(prestate=False)
                append("core destroy command result fenced", {
                    "phase": phase, "invocationId": intent.invocation_id,
                    "returnCode": value.returncode,
                    "stdoutBytes": value.stdout_bytes,
                    "stderrBytes": value.stderr_bytes,
                    "stdoutTruncated": value.stdout_truncated,
                    "stderrTruncated": value.stderr_truncated}, prestate=phase == "show")
                stage = "result"

            env = {key: value for key, value in barragan_subprocess_env().items()
                   if not key.upper().startswith("TF_")}
            env.update({"TF_DATA_DIR": str(data_dir), "TF_CLI_CONFIG_FILE": "/dev/null"})
            outcome = gated_command_runner(
                args, scratch_path=run_dir, provider_keyed_v2=True,
                max_output_bytes=16 * 1024 * 1024 if phase == "show" else 65536,
                gate_timeout_seconds=1200 if phase == "apply" else 30,
                env=env, intent_callback=on_intent, started_callback=on_started,
                heartbeat_callback=on_heartbeat, result_callback=on_result)
            if (stage != "result" or outcome.started != started
                    or outcome.returncode != 0 or outcome.stdout_truncated
                    or outcome.stderr_truncated):
                raise ValueError("mixed core command outcome differs")
            return outcome

        if recovering_show and terraform_quiescent() is not True:
            raise ValueError("active Terraform process prevents SHOW recovery")
        if not recovering_apply:
            shown = run("show", [str(release.path), "show", "-json", str(plan_path)])
            _exact_destroy(json.loads(shown.stdout), inventory, _state_data_ids(state_bytes))
        pre_go_fence()
        if (recovering_show or recovering_apply) and terraform_quiescent() is not True:
            raise ValueError("active Terraform process prevents OCI GO")
        executable = oci_executable
        if executable is None:
            resolved = resolve_oci_cli()
            if not resolved.ok or resolved.command is None:
                raise ValueError("OCI CLI unavailable")
            executable = Path(resolved.command).resolve(strict=True)
        if (not isinstance(executable, Path) or not executable.is_absolute()
                or executable.is_symlink() or not os.access(executable, os.X_OK)):
            raise ValueError("OCI CLI identity differs")
        cli_identity = _file_identity(executable)
        ocids = {row.address: row.ocid for row in inventory.resources}

        def witnessed_command(argv, env):
            renew(prestate=False)
            if _file_identity(executable) != cli_identity or argv[0] != str(executable):
                raise ValueError("OCI CLI changed")
            result = oci_command_runner(argv, env)
            renew(prestate=False)
            return result

        witness = visibility_prover(
            inventory, compartment_id=evidence["target"]["compartmentId"],
            region=evidence["target"]["region"],
            engagement_name=core.input["engagementName"],
            oci_executable=str(executable), runner=witnessed_command,
            fence=lambda: renew(prestate=False))
        pre_go_fence()
        if (type(witness) is not OciExactWitness or witness.phase != "present"
                or witness.inventory_sha256 != inventory.inventory_sha256
                or witness.resource_ids_sha256 != _fingerprint(ocids)
                or witness.compartment_id != evidence["target"]["compartmentId"]
                or witness.region != evidence["target"]["region"]
                or witness.auth != "instance_principal"
                or not _HASH.fullmatch(witness.principal_sha256)
                or not _HASH.fullmatch(witness.evidence_sha256)
                or _file_identity(executable) != cli_identity):
            raise ValueError("OCI provider-present witness differs")
        if recovering_apply:
            prior = existing.events[5].data
            if (prior["ociCliPath"] != str(executable)
                    or prior["ociCliSha256"] != cli_identity[2]
                    or prior["inspectorReadySha256"] != ready_sha
                    or any(getattr(witness, key) != prior["ociVisibilityWitness"][key]
                           for key in ("phase", "inventory_sha256", "resource_ids_sha256",
                                       "compartment_id", "region", "auth", "principal_sha256"))):
                raise ValueError("recovered OCI prestate or Inspector changed")
        else:
            append("core destroy prestate identity fenced", {
            "coreJobId": core.id, "corePlanId": plan.id,
            "preDestroyStateSha256": inventory.raw_state_sha256,
            "inventorySha256": inventory.inventory_sha256,
            "lineage": inventory.lineage, "serial": inventory.serial,
            "resourceIds": ocids, "resourceIdsSha256": _fingerprint(ocids),
            "planSha256": receipt["planSha256"],
            "ociCliPath": str(executable), "ociCliSha256": cli_identity[2],
            "ociVisibilityWitness": asdict(witness),
            "inspectorReadySha256": ready_sha,
            "providerObservationSha256": observation_sha,
            })
        if recovering_apply and (any(process_quiescent(identity) is not True
                                     for identity in identities)
                                 or terraform_quiescent() is not True):
            raise ValueError("prior pre-GO Apply process returned")
        run("apply", [str(release.path), "apply", "-input=false", "-lock=true",
                      "-no-color", f"-state={state_path}", str(plan_path)])
        claim_fence()
        terminal = jobs.finish_core_destroy_apply_if_running_claimed(
            current, owner=owner, token=token,
            expected_event_digest=job_event_digest(current.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(current.events) + 1, "info",
                           "core destroy applied; provider absence pending", {
                               "providerAbsenceProofPending": True,
                               "preDestroyResourceIdsSha256": _fingerprint(ocids)}))
        if terminal is None:
            raise ValueError("mixed core Apply terminal journal lost")
        return terminal
    except Exception as exc:
        # Private operator diagnosis only. Never log command output, source,
        # credentials, resource IDs or provider response bodies.
        child = locals().get("current")
        stage = (child.events[-1].message if isinstance(child, StoredJobRun)
                 and child.events else "before child claim")
        cause = exc.__cause__
        _LOG.warning("mixed core Apply attention at %s during %s (%s%s)",
                     stage, diagnostic_step, type(exc).__name__,
                     f" caused by {type(cause).__name__}" if cause is not None else "")
        raise MixedZeroApplyCoreApplyAttention(
            "mixed core Apply is unverified; reconcile retained one-shot child") from None
