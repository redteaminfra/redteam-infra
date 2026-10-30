# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import re
import threading

from app.integrations.managed_host_images import (
    MANAGED_HOST_IMAGE_PROFILES,
    ManagedHostImageProfile,
    managed_host_image_profile,
)
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceRepository,
    SqlAlchemyEngagementWorkspaceRepository,
    StoredEngagementWorkspace,
)


MANAGED_HOST_IMAGE_PROFILE_METADATA_KEY = "managedHostImageProfile"
_PIN_LOCK = threading.RLock()
_IMAGE_PATTERNS = {
    "linode": re.compile(r"^(?:linode|private)/[A-Za-z0-9._-]+$"),
    "digitalocean": re.compile(r"^(?:[a-z][a-z0-9-]*|[1-9][0-9]*)$"),
    "oci": re.compile(
        r"^ocid1\.image\.oc[1-9][0-9]*\.[a-z0-9-]+\.[A-Za-z0-9_-]+$"
    ),
}


class ManagedHostImageContinuityError(ValueError):
    pass


def resolve_or_pin_managed_host_image_profile(
    workspace: StoredEngagementWorkspace,
    *,
    repository: EngagementWorkspaceRepository,
    permit_new_pin: bool,
    profile: ManagedHostImageProfile | None = None,
) -> tuple[StoredEngagementWorkspace, ManagedHostImageProfile]:
    """Atomically resolve the durable pin or create it after a clean-state proof."""

    with _PIN_LOCK:
        current = repository.get(workspace.engagement_id) or workspace
        existing_name = _metadata_profile_name(current)
        if existing_name:
            return current, _profile_named(existing_name)
        if not permit_new_pin:
            raise ManagedHostImageContinuityError(
                "engagement has retained managed infrastructure but no image profile; review state before adoption"
            )
        selected = profile or managed_host_image_profile()
        stored = repository.save(
            replace(
                current,
                metadata={**current.metadata, MANAGED_HOST_IMAGE_PROFILE_METADATA_KEY: selected.name},
            )
        )
        verified = repository.get(workspace.engagement_id) or stored
        if _metadata_profile_name(verified) != selected.name:
            raise ManagedHostImageContinuityError("managed-host image profile pin was not persisted")
        return verified, selected


def pinned_managed_host_image_profile(
    engagement_id: str,
    *,
    repository: EngagementWorkspaceRepository | None = None,
) -> ManagedHostImageProfile:
    """Resolve an engagement pin; missing or invalid pins require explicit recovery."""

    workspace = (repository or SqlAlchemyEngagementWorkspaceRepository()).get(engagement_id)
    if workspace is None:
        raise ManagedHostImageContinuityError(
            "engagement workspace must be prepared before managed infrastructure provisioning"
        )
    name = _metadata_profile_name(workspace)
    if not name:
        raise ManagedHostImageContinuityError(
            "engagement workspace has no managed-host image profile; review retained state before adoption"
        )
    return _profile_named(name)


def resolve_or_pin_profile_for_new_managed_host(
    engagement_id: str,
    *,
    repository: EngagementWorkspaceRepository | None = None,
    provider_resource_repository: object | None = None,
    retained_state_exists: bool = False,
) -> ManagedHostImageProfile:
    repo = repository or SqlAlchemyEngagementWorkspaceRepository()
    workspace = repo.get(engagement_id)
    if workspace is None:
        raise ManagedHostImageContinuityError(
            "engagement workspace must be prepared before managed infrastructure provisioning"
        )
    if _metadata_profile_name(workspace):
        _stored, profile = resolve_or_pin_managed_host_image_profile(
            workspace,
            repository=repo,
            permit_new_pin=False,
        )
        return profile
    retained = retained_state_exists or engagement_has_retained_terraform_state(workspace)
    if not retained:
        retained = _has_active_owned_provider_compute(
            engagement_id,
            repository=provider_resource_repository,
        )
    _stored, profile = resolve_or_pin_managed_host_image_profile(
        workspace,
        repository=repo,
        permit_new_pin=not retained,
    )
    return profile


def managed_host_image_profile_named(name: str) -> ManagedHostImageProfile:
    return _profile_named(name)


def retained_managed_compute_image(workspace: Path, provider: str) -> str:
    """Read the one exact managed-compute image identity from retained state."""

    resource_type = {
        "linode": "linode_instance",
        "digitalocean": "digitalocean_droplet",
    }.get(provider)
    if resource_type is None:
        raise ManagedHostImageContinuityError(f"unsupported managed-host provider: {provider}")
    state_path = workspace / "terraform.tfstate"
    if state_path.is_symlink() or not state_path.is_file():
        raise ManagedHostImageContinuityError("retained Terraform state is unavailable")
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedHostImageContinuityError("retained Terraform state is invalid") from exc
    resources = payload.get("resources") if isinstance(payload, dict) else None
    if not isinstance(resources, list):
        raise ManagedHostImageContinuityError("retained Terraform state is invalid")
    images: set[str] = set()
    compute_count = 0
    for resource in resources:
        if (
            not isinstance(resource, dict)
            or resource.get("mode", "managed") != "managed"
            or resource.get("type") != resource_type
        ):
            continue
        instances = resource.get("instances")
        if not isinstance(instances, list):
            raise ManagedHostImageContinuityError("retained Terraform compute state is malformed")
        for instance in instances:
            compute_count += 1
            attributes = instance.get("attributes") if isinstance(instance, dict) else None
            image = attributes.get("image") if isinstance(attributes, dict) else None
            if not isinstance(image, str) or not _valid_image(provider, image):
                raise ManagedHostImageContinuityError(
                    "retained Terraform compute state has no valid image identity"
                )
            images.add(image.strip())
    if compute_count == 0:
        raise ManagedHostImageContinuityError(
            "retained Terraform state contains no managed compute image identity"
        )
    if len(images) != 1:
        raise ManagedHostImageContinuityError(
            "retained Terraform compute state has conflicting image identities"
        )
    return next(iter(images))


def retained_oci_source_image(
    state_path: Path,
    *,
    allow_no_compute: bool = False,
) -> str:
    if state_path.is_symlink() or not state_path.is_file():
        raise ManagedHostImageContinuityError("retained core Terraform state is unavailable")
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedHostImageContinuityError("retained core Terraform state is invalid") from exc
    if not isinstance(payload, dict):
        raise ManagedHostImageContinuityError("retained core Terraform state is invalid")
    version = payload.get("version")
    serial = payload.get("serial")
    lineage = payload.get("lineage")
    outputs = payload.get("outputs")
    resources = payload.get("resources")
    if (
        isinstance(version, bool)
        or version != 4
        or isinstance(serial, bool)
        or not isinstance(serial, int)
        or serial < 0
        or not isinstance(lineage, str)
        or not lineage.strip()
        or not isinstance(outputs, dict)
        or not isinstance(resources, list)
    ):
        raise ManagedHostImageContinuityError("retained core Terraform state is invalid")
    images: set[str] = set()
    count = 0
    for resource in resources:
        if not isinstance(resource, dict):
            raise ManagedHostImageContinuityError("retained core Terraform state is invalid")
        mode = resource.get("mode")
        resource_type = resource.get("type")
        instances = resource.get("instances")
        if (
            not isinstance(mode, str)
            or mode not in {"managed", "data"}
            or not isinstance(resource_type, str)
            or not resource_type.strip()
            or not isinstance(instances, list)
        ):
            raise ManagedHostImageContinuityError("retained core Terraform state is invalid")
        for instance in instances:
            if not isinstance(instance, dict) or not isinstance(instance.get("attributes"), dict):
                raise ManagedHostImageContinuityError("retained core Terraform state is invalid")
            attributes = instance["attributes"]
            if mode != "managed" or resource_type != "oci_core_instance":
                continue
            count += 1
            details = attributes.get("source_details") if isinstance(attributes, dict) else None
            detail = details[0] if isinstance(details, list) and len(details) == 1 and isinstance(details[0], dict) else None
            image = detail.get("source_id") if detail is not None else None
            if not isinstance(image, str) or not _valid_image("oci", image):
                raise ManagedHostImageContinuityError("retained core compute state has no valid source image OCID")
            images.add(image.strip())
    if count == 0:
        if allow_no_compute:
            return ""
        raise ManagedHostImageContinuityError("retained core Terraform state contains no managed compute image identity")
    if len(images) != 1:
        raise ManagedHostImageContinuityError("retained core compute state has conflicting source image identities")
    return next(iter(images))


def engagement_has_retained_terraform_state(workspace: StoredEngagementWorkspace) -> bool:
    core_root = Path(os.environ.get("BARRAGAN_TERRAFORM_STATE_ROOT", "/var/lib/barragan/terraform-state"))
    if (core_root / workspace.slug / "core" / "terraform.tfstate").is_file():
        return True
    sketch_root = Path(os.environ.get("BARRAGAN_SKETCH_STATE_ROOT", "/var/lib/barragan/sketch-state"))
    engagement_root = sketch_root / workspace.engagement_id
    return engagement_root.is_dir() and any(engagement_root.rglob("terraform.tfstate"))


def _metadata_profile_name(workspace: StoredEngagementWorkspace) -> str:
    value = workspace.metadata.get(MANAGED_HOST_IMAGE_PROFILE_METADATA_KEY)
    return value.strip() if isinstance(value, str) else ""


def _valid_image(provider: str, value: str) -> bool:
    candidate = value.strip()
    pattern = _IMAGE_PATTERNS[provider]
    return bool(candidate and pattern.fullmatch(candidate))


def _has_active_owned_provider_compute(
    engagement_id: str,
    *,
    repository: object | None = None,
) -> bool:
    try:
        from app.storage.provider_resource_repository import (
            SqlAlchemyProviderResourceRepository,
            TERMINAL_RECORD_STATUSES,
            is_barragan_owned_record,
        )

        resource_repository = repository or SqlAlchemyProviderResourceRepository()
        return any(
            is_barragan_owned_record(record)
            and str(record.status or "").lower() not in TERMINAL_RECORD_STATUSES
            and str(record.resource_type or "").lower()
            in {
                "instance",
                "droplet",
                "compute_instance",
                "inspector_instance",
                "inspector_droplet",
                "observer_instance",
                "observer_droplet",
            }
            for record in resource_repository.list_for_engagement(engagement_id)
        )
    except RuntimeError as exc:
        raise ManagedHostImageContinuityError(
            "provider ownership inventory is unavailable; managed-host image profile cannot be pinned safely"
        ) from exc


def _profile_named(name: str) -> ManagedHostImageProfile:
    try:
        return MANAGED_HOST_IMAGE_PROFILES[name]
    except KeyError as exc:
        raise ManagedHostImageContinuityError(
            f"engagement workspace has unsupported managed-host image profile: {name}"
        ) from exc
