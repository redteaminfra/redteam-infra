# Copyright (c) 2026, Oracle and/or its affiliates.
"""Audited, locked local source session for a private mixed initial Apply.

Only a sealed pre-GO parent may open this context. The provider's existing
saved-plan flock remains held across selector reservation and gated Apply.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Callable, Iterator

from app.services.credentials import decrypt_secret_value
from app.services.provider_keyed_mixed_initial_apply_child import ApplySource
from app.services.provider_keyed_initial_destroy_plan_job import (
    _remove_owned_public_key, _stage_public_key,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id, _receipt_data, _records, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_zero_apply_teardown_source import _provider_receipt
from app.services.provider_keyed_mixed_linode_saved_plan import _LOCK as _LINODE_LOCK, _PLAN as _LINODE_PLAN
from app.services.provider_keyed_mixed_digitalocean_saved_plan import _LOCK as _DO_LOCK, _PLAN as _DO_PLAN
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup, _require_lease
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_state_workspaces import _default_state_root
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository


class MixedInitialApplySourceError(ValueError):
    """The locked saved plan or credential no longer matches the review."""


@contextmanager
def locked_provider_saved_plan(root: Path, provider: str, renew: Callable[[], None]):
    """Use the exact existing planner lock inode with bounded claim renewal."""
    lock_name = _LINODE_LOCK if provider == "linode" else _DO_LOCK
    lock_path = root / lock_name
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise MixedInitialApplySourceError("saved-plan lock is missing or unsafe") from None
    with os.fdopen(descriptor, "r+b") as lock:
        metadata = os.fstat(lock.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid()):
            raise MixedInitialApplySourceError("provider saved-plan lock is unsafe")
        deadline = time.monotonic() + 1200
        while True:
            renew()
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise MixedInitialApplySourceError("provider saved-plan lock remained busy") from None
                time.sleep(0.5)
        try:
            def lock_fence() -> None:
                try:
                    current = lock_path.lstat()
                except OSError:
                    raise MixedInitialApplySourceError("provider saved-plan lock disappeared") from None
                if (not stat.S_ISREG(current.st_mode) or current.st_dev != metadata.st_dev
                        or current.st_ino != metadata.st_ino):
                    raise MixedInitialApplySourceError("provider saved-plan lock changed inode")
            lock_fence()
            yield lock_fence
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


@contextmanager
def audited_mixed_initial_apply_source(
    parent: StoredJobRun, provider: str, renew: Callable[[], None], *,
    environment: str, state_root: Path, job_repository=None,
    engagement_repository=None, sketch_repository=None, plan_repository=None,
    credential_repository=None, ssh_key_repository=None, lease_lookup=None,
    release_check: Callable = require_devtest_terraform_release,
    token_decoder: Callable[[str], str] = decrypt_secret_value,
) -> Iterator[ApplySource]:
    """Reopen exact pre-GO evidence and hold the planner's provider lock."""
    if (environment != "devtest" or not isinstance(state_root, Path)
            or state_root != _default_state_root() or provider not in {"linode", "digitalocean"}):
        raise MixedInitialApplySourceError("mixed Apply requires configured DevTest source")
    jobs = job_repository or SqlAlchemyJobRepository()
    engagements = engagement_repository or SqlAlchemyEngagementRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    lookup = lease_lookup or _db_lease_lookup
    if (parent.id != _parent_id(parent.input.get("coreJobId", ""))
            or parent.input.get("phase") != "apply_sealed"
            or parent.status != "running" or jobs.get(parent.id) != parent):
        raise MixedInitialApplySourceError("mixed Apply seal is unavailable")
    seal = validate_mixed_initial_apply_seal(parent)
    if provider not in seal["orderedProviders"]:
        raise MixedInitialApplySourceError("provider differs from reviewed order")
    intent_policy = seal["reviewedPolicy"][provider]
    connection_id = intent_policy["provider_connection_id"]
    fingerprint = hashlib.sha256(f"{provider}\0{connection_id}".encode()).hexdigest()
    root = state_root / parent.target_id / "provider-keyed-v2" / provider / fingerprint
    if (root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root
            or root.parents[3] != state_root):
        raise MixedInitialApplySourceError("provider workspace identity differs")
    with locked_provider_saved_plan(root, provider, renew) as lock_fence:
        renew()
        _require_lease(lookup, parent.target_id, parent.input["corePlanId"])
        core, plan, ids, order, intents = _records(
            parent.input["coreJobId"], parent.target_id, parent.input["corePlanId"],
            lookup, engagements, sketches, jobs, plans, credentials, keys)
        if (jobs.get(parent.id) != parent or order != seal["orderedProviders"]
                or ids != seal["chainIds"] or plan.id != parent.input["corePlanId"]):
            raise MixedInitialApplySourceError("reviewed mixed source changed")
        validate_mixed_initial_apply_seal(parent, intents=intents)
        intent = intents[provider]
        receipt = _provider_receipt(provider, intent, state_root)
        index = order.index(provider)
        if _receipt_data(provider, ids[index], receipt, intent) != parent.events[index + 2].data:
            raise MixedInitialApplySourceError("saved provider receipt changed")
        release = release_check(environment=environment)
        if (receipt["terraformBinaryPath"] != str(release.path)
                or receipt["terraformBinarySha256"] != release.sha256):
            raise MixedInitialApplySourceError("pinned Terraform release changed")
        marker = json.loads((root / ".barragan-provider-keyed-state.json").read_text())
        source_sha = hashlib.sha256(json.dumps(marker["source_files"], sort_keys=True).encode()).hexdigest()
        workspace = ProviderKeyedWorkspace(
            root, root / "terraform.tfstate", root / ".terraform-data",
            "provider-keyed-v2", provider, connection_id, fingerprint,
            marker["source_revision"], source_sha)
        credential = credentials.get(connection_id)
        if (credential is None or hashlib.sha256(credential.encrypted_secret.encode()).hexdigest()
                != intent.credential_secret_sha256
                or credential.updated_at != intent.credential_updated_at):
            raise MixedInitialApplySourceError("provider credential snapshot changed")
        token = token_decoder(credential.encrypted_secret) if provider == "digitalocean" else None
        if provider == "digitalocean" and (not isinstance(token, str) or not token):
            raise MixedInitialApplySourceError("DigitalOcean selector credential is unavailable")
        material_root = root.parents[1] / ".plan-material"
        material_dir = material_root / provider
        for directory in (material_root, material_dir):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise MixedInitialApplySourceError("saved-plan material directory is unsafe")
        public = material_dir / "admin-public"
        plan_name = _LINODE_PLAN if provider == "linode" else _DO_PLAN
        renew()
        owned_public = _stage_public_key(public, intent.admin_public_key)
        try:
            yield ApplySource(
                workspace=workspace,
                command=(str(release.path), "apply", "-input=false", "-lock=true",
                         "-no-color", str(root / plan_name)),
                receipt_sha256=parent.events[index + 2].data["receiptSha256"],
                plan_sha256=receipt["planSha256"], terraform_sha256=release.sha256,
                credential_secret_sha256=intent.credential_secret_sha256,
                credential_updated_at=intent.credential_updated_at,
                selector_tag=intent.selector_tag if provider == "digitalocean" else None,
                selector_token=token,
                lock_fence=lock_fence,
            )
        finally:
            _remove_owned_public_key(owned_public)
