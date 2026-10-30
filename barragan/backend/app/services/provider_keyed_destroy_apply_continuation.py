# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private DevTest handoff from a saved group destroy plan to absence proof.

The provider-group apply is one-shot. A completed child is inspected through
the read-only absence boundary; any other existing child needs reconciliation.
This module does not advance the parent, coordinator, or Inspector lifecycle.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import stat
from pathlib import Path
from typing import Callable

from app.services.observer_checks import (
    ObserverSshKey, SshObserverRunner, _inspector_host_from_settings,
    resolve_inspector_management_source_cidr,
)
from app.services.credentials import decrypt_secret_value
from app.services.provider_keyed_comprehensive_teardown import (
    ACTION as COORDINATOR_ACTION, ProviderKeyedComprehensiveTeardownAttention,
    _FENCE, _boundary, _child_id, recognize_retained_keyed_inspector_ready,
)
from app.services.provider_keyed_destroy_absence_preflight import (
    reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_initial_destroy_apply_job import (
    ACTION as APPLY_ACTION, preflight_digitalocean_initial_destroy_apply,
    run_digitalocean_initial_destroy_apply_job,
)
from app.services.provider_keyed_inspector_readiness_publish import (
    recognize_published_keyed_inspector_readiness,
)
from app.services.provider_keyed_inspector_preparation_proof import (
    verify_inspector_selected_source_ssh,
)
from app.services.provider_keyed_inspector_provider_proof import (
    InspectorProviderProof, prove_retained_keyed_inspector_provider,
)
from app.services.provider_keyed_inspector_settlement import (
    _GetOnlyTransport, _default_transport,
)
from app.services.provider_keyed_inspector_prepare_binder import (
    _existing_key_identity, _safe_key_identity, _verify_key_pair,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository


def _single_attempt_inspector_source() -> str:
    # Two independent reflectors, one bounded round. The destroy apply claim
    # is renewed before this proof and is still fenced again before GO.
    return resolve_inspector_management_source_cidr(max_attempts=1)


def prove_live_keyed_inspector_before_destroy_go(
    teardown_parent_id: str, *, environment: str,
    job_repository=None, plan_repository=None, lease_lookup=None,
    settings_repository=None, provider_resource_repository=None,
    credential_repository=None,
    source_resolver: Callable = _single_attempt_inspector_source,
    decrypt_secret: Callable = decrypt_secret_value,
    transport_factory: Callable = _default_transport,
    provider_prover: Callable = prove_retained_keyed_inspector_provider,
    ssh_runner=None, fence: Callable[[], None] | None = None,
    active_destroy_child: Callable[[], object] | None = None,
) -> None:
    """Reprove selected-source Inspector SSH while Terraform waits for GO."""
    if environment != "devtest" or fence is None:
        raise ValueError("DevTest gated destroy and claim fence required")
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    lookup = lease_lookup or _db_lease_lookup
    settings_repo = settings_repository or SqlAlchemyObserverSettingsRepository()
    resources = provider_resource_repository or SqlAlchemyProviderResourceRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    runner = ssh_runner or SshObserverRunner(readiness_attempts=1)
    if type(runner) is not SshObserverRunner:
        raise ValueError("concrete Inspector SSH runner required")

    def read():
        fence()
        parent, core, _snapshot, operation = _boundary(teardown_parent_id, jobs, plans, lookup)
        child = jobs.get(_child_id(core.id))
        if (operation != _FENCE or child is None or child.action != COORDINATOR_ACTION
                or child.status != "running" or child.input.get("phase") != "inspector_ready"):
            raise ValueError("Inspector ready coordinator differs")
        if len(child.events) == 5 and child.events[-1].message == "retained_inspector_ready":
            ready = recognize_retained_keyed_inspector_ready(
                parent.id, environment=environment, job_repository=jobs,
                plan_repository=plans, lease_lookup=lookup,
                **({"active_destroy_child": active_destroy_child()}
                   if active_destroy_child is not None else {}))
            policy_digest = ready.ssh_policy_sha256
        else:
            ready = recognize_published_keyed_inspector_readiness(
                child.id, parent.target_id, environment=environment,
                job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            policy_digest = child.events[-1].data["selectedSourceSshPolicySha256"]
        settings = settings_repo.get(parent.target_id)
        host = _inspector_host_from_settings(settings.current_host, settings=settings) if settings else None
        record = resources.get(ready.host_record_id)
        firewall = resources.get(ready.firewall_record_id)
        selected = credentials.get_default(host.provider) if host else None
        if (ready.coordinator_job_id != child.id or host is None or record is None
                or firewall is None or host.resource_id != record.resource_id
                or host.public_ip != record.metadata.get("publicIp")
                or host.provider != record.provider
                or host.metadata.get("providerFirewall", {}).get("resourceId")
                != firewall.resource_id or type(policy_digest) is not str
                or len(policy_digest) != 64 or selected is None
                or selected.status != "active" or not selected.is_default
                or not selected.encrypted_secret):
            raise ValueError("Inspector ready host identity differs")
        source = host.metadata["providerFirewall"]["managementSourceCidr"]
        if (type(source) is not str or not isinstance(ipaddress.ip_network(source, strict=True),
                                                      ipaddress.IPv4Network)):
            raise ValueError("Inspector selected source differs")
        return (parent, core, child, ready, settings, host, record, firewall, source,
                policy_digest, selected)

    original = read()
    source = original[8]

    def current_source():
        # The resolver performs two network requests. Fence immediately on
        # both sides so a slow or lost claim cannot authorize Terraform GO.
        fence()
        try:
            value = source_resolver()
        finally:
            fence()
        if read() != original:
            raise ValueError("Inspector identity changed during source lookup")
        return value

    if current_source() != source:
        raise ValueError("Inspector management source changed")
    key_path, digest = _safe_key_identity(_existing_key_identity)
    _verify_key_pair(key_path, digest)
    public_path = key_path + ".pub"
    fd = os.open(public_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        raw = os.read(fd, 4097)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022
                or len(raw) > 4096 or len(raw.splitlines()) != 1
                or hashlib.sha256(raw.strip()).hexdigest() != digest
                or not raw.strip().startswith(b"ssh-ed25519 ")):
            raise ValueError("Inspector public key changed")
        public_key = raw.decode("ascii").strip()
    finally:
        os.close(fd)

    def stable():
        if read() != original:
            raise ValueError("Inspector identity changed during live proof")

    stable()
    token = decrypt_secret(original[10].encrypted_secret)
    if type(token) is not str or not token:
        raise ValueError("Inspector provider credential unavailable")
    transport = _GetOnlyTransport(
        transport_factory(original[5].provider), before_get=stable, after_get=stable)
    def exact_provider_get():
        proof = provider_prover(
            expected_host=original[5], size=original[4].size, token=token,
            transport=transport, firewall_id=original[7].resource_id,
            management_cidr=source,
        )
        if (type(proof) is not InspectorProviderProof
                or proof.host.provider != original[5].provider
                or proof.host.resource_id != original[5].resource_id
                or proof.host.public_ip != original[5].public_ip
                or proof.firewall_id != original[7].resource_id
                or proof.management_cidr != source):
            raise ValueError("Inspector exact provider GET differs")

    # The first GET binds the SSH destination despite inherited permissive
    # host-key handling; the second checks that identity again just before GO.
    exact_provider_get()
    stable()
    policy_digest, _version = verify_inspector_selected_source_ssh(
        original[5], ObserverSshKey(key_path, public_key), source, stable, runner,
        timeout_seconds=25)
    if (policy_digest != original[9] or current_source() != source):
        raise ValueError("Inspector live policy or source changed")
    stable()
    exact_provider_get()
    stable()


def continue_digitalocean_keyed_destroy_apply(
    teardown_parent_id: str, *, environment: str, state_root: Path,
    job_repository=None, plan_repository=None, lease_lookup=None,
    retained_ready_recognizer: Callable | None = None,
    fresh_ready_recognizer: Callable | None = None,
    preview_recognizer: Callable | None = None,
    apply_runner: Callable | None = None,
    absence_reconciler: Callable | None = None,
):
    """Execute at most one saved-plan apply, then prove provider absence.

    Absence evidence is returned to a future coordinator, never persisted here.
    An interrupted or failed apply cannot be restarted through this entrypoint.
    """
    try:
        if (environment != "devtest" or not isinstance(state_root, Path)
                or state_root != _default_state_root()
                or not isinstance(teardown_parent_id, str) or not teardown_parent_id):
            raise ValueError("DevTest destroy boundary required")
        jobs = job_repository or SqlAlchemyJobRepository()
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        lookup = lease_lookup or _db_lease_lookup

        def ready_boundary():
            parent, core, snapshot, operation = _boundary(
                teardown_parent_id, jobs, plans, lookup)
            child = jobs.get(_child_id(core.id))
            if (operation != _FENCE or child is None
                    or child.action != COORDINATOR_ACTION or child.status != "running"
                    or child.input.get("phase") != "inspector_ready"):
                raise ValueError("Inspector ready coordinator differs")
            if len(child.events) == 5 and child.events[-1].message == "retained_inspector_ready":
                recognize = retained_ready_recognizer or recognize_retained_keyed_inspector_ready
                ready = recognize(parent.id, environment=environment, job_repository=jobs,
                                  plan_repository=plans, lease_lookup=lookup)
            else:
                recognize = fresh_ready_recognizer or recognize_published_keyed_inspector_readiness
                ready = recognize(child.id, parent.target_id, environment=environment,
                                  job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            if (ready.coordinator_job_id != child.id or jobs.get(parent.id) != parent
                    or jobs.get(child.id) != child
                    or lookup(parent.target_id) != (core.input["corePlanId"], _FENCE)):
                raise ValueError("Inspector ready authority changed")
            return parent, core, snapshot, child

        parent, core, snapshot, coordinator = ready_boundary()
        apply_id = f"job-provider-keyed-initial-destroy-apply-{core.id.removeprefix('job-')}"

        def applied_child():
            rows = [row for row in jobs.list_for_engagement(parent.target_id)
                    if row.action == APPLY_ACTION]
            by_id = jobs.get(apply_id)
            if not rows and by_id is None:
                return None
            if (len(rows) != 1 or rows[0].id != apply_id or by_id != rows[0]
                    or by_id.status != "succeeded"):
                raise ValueError("existing destroy apply requires reconciliation")
            return by_id

        applied = applied_child()
        if applied is None:
            inspect = preview_recognizer or preflight_digitalocean_initial_destroy_apply
            bound = inspect(parent.id, environment=environment, state_root=state_root,
                            job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            preview_id = f"job-provider-keyed-initial-destroy-plan-{core.id.removeprefix('job-')}"
            if (bound.teardown_parent_id != parent.id or bound.core_job_id != core.id
                    or bound.core_plan_id != core.input["corePlanId"]
                    or bound.scope_snapshot_id != snapshot["snapshotId"]
                    or bound.provider_scope_sha256 != snapshot["providerScopeSha256"]
                    or bound.preview_job_id != preview_id):
                raise ValueError("saved destroy preview authority differs")
            # The preview preflight can perform a slow provider GET. Reprove
            # Inspector readiness and the absence of a competing apply child.
            if ready_boundary() != (parent, core, snapshot, coordinator):
                raise ValueError("Inspector readiness changed after preview")
            if applied_child() is not None:
                raise ValueError("destroy apply appeared after preview")
            run = apply_runner or run_digitalocean_initial_destroy_apply_job
            applied = run(parent.id, environment=environment, state_root=state_root,
                          job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
            if (applied is None or applied.id != apply_id or applied.status != "succeeded"
                    or jobs.get(apply_id) != applied):
                raise ValueError("one-shot destroy apply did not finish")

        # The saved child may predate this process. Its full journal, retained
        # empty state, exact owned IDs, and provider GETs are audited below.
        if ready_boundary() != (parent, core, snapshot, coordinator):
            raise ValueError("Inspector readiness changed before absence")
        if applied_child() != applied:
            raise ValueError("destroy apply changed before absence")
        reconcile = absence_reconciler or reconcile_successful_digitalocean_destroy_absence
        return reconcile(parent.id, environment=environment, state_root=state_root,
                         job_repository=jobs, plan_repository=plans, lease_lookup=lookup)
    except Exception:
        raise ProviderKeyedComprehensiveTeardownAttention(
            "keyed group destroy or provider absence remains unverified; reconcile one-shot child"
        ) from None
