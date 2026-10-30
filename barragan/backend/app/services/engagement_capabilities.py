# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from dataclasses import replace
from typing import Any

from app.services import inference_proxy_capability as inference_proxy
from app.services import c2_observer_capability as c2_observer
from app.services import loottool_capability as loottool
from app.services import atc_capability as atc
from app.services.capability_profile_resolution import resolve_standard_rti_profile
from app.services.core_ssh import active_core_connection_details, core_proxy_identity
from app.services.engagements import get_engagement
from app.services.engagement_workspaces import (
    DEFAULT_PROFILE_ID,
    EngagementWorkspaceValidationError,
    load_prepared_engagement_workspace,
    prepare_engagement_workspace,
)
from app.services.redteam_infra_template import RedteamInfraTemplateSource
from app.services.retained_workspace_capability_roles import (
    import_selected_optional_capability_roles,
    importable_packaged_optional_role_selections,
)
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceRepository,
    SqlAlchemyEngagementWorkspaceRepository,
    StoredEngagementWorkspace,
)
from app.storage.service_repository import EngagementServiceRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.services.static_web_capability_state import (
    static_web_capability_state,
    static_web_is_selected,
    with_implied_static_web_selection,
)


CAPABILITY_OVERRIDES_METADATA_KEY = "capabilityOverrides"
CAPABILITY_APPLY_STATE_METADATA_KEY = "capabilityApplyState"
DESKTOP_CAPABILITY_IDS = ("google-chrome", "firefox", "vs-code", "libreoffice", "keepassxc")


class EngagementCapabilityValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("engagement capability validation failed")
        self.errors = errors


class CapabilityPreparationError(EngagementCapabilityValidationError):
    """The selection was saved, but its executable input could not be prepared."""


def engagement_capability_workspace(
    engagement_id: str,
    *,
    root: Path,
    repository: EngagementWorkspaceRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    core_provider = engagement_core_provider(engagement)
    repo = repository or SqlAlchemyEngagementWorkspaceRepository()
    try:
        workspace = load_prepared_engagement_workspace(engagement_id, root=root, repository=repo)
    except EngagementWorkspaceValidationError as exc:
        if exc.errors != ["engagement workspace must be prepared before rendering capability artifacts"]:
            raise
        workspace = None
    if workspace is None:
        resolution = resolve_standard_rti_profile(core_provider=core_provider).to_dict()
        overrides = _empty_overrides()
        state = static_web_capability_state(engagement_id, repository=service_repository)
        effective, implied = with_implied_static_web_selection(overrides, state)
        return _workspace_payload(workspace=None, resolution=resolution, overrides=effective, native_state=_native_state(engagement, state, implied, effective))
    resolution = _workspace_profile_resolution(workspace, core_provider=core_provider).to_dict()
    overrides = _workspace_overrides(workspace)
    state = static_web_capability_state(engagement_id, repository=service_repository)
    effective, implied = with_implied_static_web_selection(overrides, state)
    return _workspace_payload(workspace=workspace, resolution=resolution, overrides=effective, native_state=_native_state(engagement, state, implied, effective))


def update_engagement_capability_selection(
    engagement_id: str,
    body: dict[str, Any],
    *,
    root: Path,
    repository: EngagementWorkspaceRepository | None = None,
    core_provider: str | None = None,
    service_repository: EngagementServiceRepository | None = None,
    template_source: RedteamInfraTemplateSource | None = None,
) -> dict[str, Any] | None:
    repo = repository or SqlAlchemyEngagementWorkspaceRepository()
    requested = _normalize_overrides(body)
    existing = repo.get(engagement_id)
    try:
        configuration = inference_proxy.normalize_configuration(
            body.get("inferenceProxy", existing.metadata.get(inference_proxy.CONFIGURATION_KEY) if existing else None),
            required=inference_proxy.is_selected(requested),
        )
        atc_configuration = atc.normalize_configuration(
            body.get("atc", existing.metadata.get(atc.CONFIGURATION_KEY) if existing else None),
            required=atc.is_selected(requested),
        )
        atc_context = atc.engagement_context(get_engagement(engagement_id)) if atc.is_selected(requested) else None
        atc_release = atc.controller_release() if atc.is_selected(requested) else None
        archive = inference_proxy.source_archive() if inference_proxy.is_selected(requested) else None
        c2_artifacts = c2_observer.controller_artifacts() if c2_observer.is_selected(requested) else None
        loot_artifacts = loottool.controller_artifacts() if loottool.is_selected(requested) else None
    except (inference_proxy.InferenceProxyConfigurationError, c2_observer.C2ObserverArtifactError, loottool.LootToolArtifactError, atc.ATCCapabilityError) as exc:
        raise EngagementCapabilityValidationError([str(exc)]) from exc
    prepared = prepare_engagement_workspace(engagement_id, root=root, profile_id=DEFAULT_PROFILE_ID, repository=repo)
    if prepared is None:
        return None
    workspace = prepared.workspace
    try:
        source = (
            inference_proxy.prepare_source(Path(workspace.path), archive)
            if archive is not None else workspace.metadata.get(inference_proxy.SOURCE_KEY)
        )
        prepared_c2_artifacts = (
            c2_observer.prepare_artifacts(Path(workspace.path), c2_artifacts)
            if c2_artifacts is not None else workspace.metadata.get(c2_observer.ARTIFACTS_KEY)
        )
        prepared_atc_release = (
            atc.prepare_release(Path(workspace.path), atc_release)
            if atc_release is not None else workspace.metadata.get(atc.RELEASE_KEY)
        )
        prepared_loot_artifacts = (
            loottool.prepare_artifacts(Path(workspace.path), loot_artifacts, engagement_id=engagement_id)
            if loot_artifacts is not None else workspace.metadata.get(loottool.ARTIFACTS_KEY)
        )
    except (inference_proxy.InferenceProxyConfigurationError, c2_observer.C2ObserverArtifactError, loottool.LootToolArtifactError, atc.ATCCapabilityError) as exc:
        raise EngagementCapabilityValidationError([str(exc)]) from exc
    current = _workspace_overrides(workspace)
    static_state = static_web_capability_state(engagement_id, repository=service_repository)
    if static_state["claimed"] and static_web_is_selected(current) and not static_web_is_selected(requested):
        raise EngagementCapabilityValidationError([static_state["reason"]])
    requested, implied = with_implied_static_web_selection(requested, static_state)
    current_resolution = _workspace_profile_resolution(workspace, core_provider=core_provider).to_dict()
    importable = importable_packaged_optional_role_selections(requested["selectedOptionals"])
    errors = _selection_errors(current_resolution, requested, allowed_missing_optionals=importable)
    if errors:
        raise EngagementCapabilityValidationError(errors)
    workspace = import_selected_optional_capability_roles(
        workspace,
        requested["selectedOptionals"],
        repository=repo,
        template_source=template_source,
    )
    resolution = _workspace_profile_resolution(workspace, core_provider=core_provider).to_dict()
    errors = _selection_errors(resolution, requested)
    if errors:
        raise EngagementCapabilityValidationError(errors)
    workspace = replace(workspace, metadata={
        **workspace.metadata,
        inference_proxy.CONFIGURATION_KEY: configuration,
        atc.CONFIGURATION_KEY: atc_configuration,
        **({atc.CONTEXT_KEY: atc_context} if atc_context is not None else {}),
        **({atc.RELEASE_KEY: prepared_atc_release} if prepared_atc_release is not None else {}),
        **({inference_proxy.SOURCE_KEY: source} if source is not None else {}),
        **({c2_observer.ARTIFACTS_KEY: prepared_c2_artifacts} if prepared_c2_artifacts is not None else {}),
        **({loottool.ARTIFACTS_KEY: prepared_loot_artifacts} if prepared_loot_artifacts is not None else {}),
    })
    prior_apply_state = capability_apply_state_for_workspace(workspace)
    stored = _save_overrides(repo, workspace, requested)
    prepared_state = _preparing_apply_state(stored, resolution, requested)
    stored = _save_apply_state(repo, stored, prepared_state)
    try:
        # The renderer imports the profile helpers above.  Keeping this import
        # local lets a single Save action prepare its durable execution input
        # without introducing a module cycle.
        from app.services.capability_lock_rendering import render_capability_lock

        rendered = render_capability_lock(
            engagement_id,
            root=root,
            repository=repo,
            service_repository=service_repository,
        )
        if rendered is None:
            raise CapabilityPreparationError(["engagement capability workspace could not be prepared"])
    except EngagementWorkspaceValidationError as exc:
        _save_apply_state(repo, stored, _blocked_preparation_state(prepared_state, exc.errors))
        raise CapabilityPreparationError(exc.errors) from exc
    except CapabilityPreparationError as exc:
        _save_apply_state(repo, stored, _blocked_preparation_state(prepared_state, exc.errors))
        raise
    except Exception as exc:
        errors = [f"could not prepare saved capability changes: {str(exc) or 'unknown error'}"]
        _save_apply_state(repo, stored, _blocked_preparation_state(prepared_state, errors))
        raise CapabilityPreparationError(errors) from exc

    rendered_input_fingerprint = _rendered_input_fingerprint(rendered.lock)
    unchanged_applied_state = (
        prior_apply_state["status"] == "applied"
        and prior_apply_state["selectionFingerprint"] == prepared_state["selectionFingerprint"]
        and prior_apply_state["renderedInputFingerprint"] == rendered_input_fingerprint
    )
    final_state = {
        **prepared_state,
        "status": "applied" if unchanged_applied_state else "saved_ready",
        "preparedAt": rendered.lock["metadata"]["generatedAt"],
        "renderedInputFingerprint": rendered_input_fingerprint,
        "errors": [] if not unchanged_applied_state else prior_apply_state["errors"],
    }
    if unchanged_applied_state:
        final_state.update(
            {
                "startedAt": prior_apply_state["startedAt"],
                "finishedAt": prior_apply_state["finishedAt"],
                "parentJobId": prior_apply_state["parentJobId"],
                "children": prior_apply_state["children"],
            }
        )
    stored = _save_apply_state(repo, rendered.workspace, final_state)
    return _workspace_payload(
        workspace=stored,
        resolution=resolution,
        overrides=requested,
        native_state=_native_state(get_engagement(engagement_id), static_state, implied, requested),
    )


def capability_overrides_for_workspace(workspace: StoredEngagementWorkspace) -> dict[str, list[dict[str, str]]]:
    return _workspace_overrides(workspace)


def capability_apply_state_for_workspace(workspace: StoredEngagementWorkspace | None) -> dict[str, Any]:
    """Return the operator-safe durable state for the current selection.

    Older workspaces do not contain a prepared state.  They deliberately show
    as unsaved so an operator must Save before a page-level Apply can use them.
    """

    if workspace is None:
        return _unsaved_apply_state()
    raw = workspace.metadata.get(CAPABILITY_APPLY_STATE_METADATA_KEY)
    if not isinstance(raw, dict):
        return _unsaved_apply_state()
    status = str(raw.get("status") or "unsaved")
    allowed_statuses = {"unsaved", "saved_ready", "applying", "applied", "blocked", "partial", "failed"}
    if status not in allowed_statuses:
        return _unsaved_apply_state()
    children = raw.get("children")
    return {
        "status": status,
        "selectionFingerprint": str(raw.get("selectionFingerprint") or ""),
        "renderedInputFingerprint": str(raw.get("renderedInputFingerprint") or ""),
        "preparedAt": str(raw.get("preparedAt") or ""),
        "startedAt": str(raw.get("startedAt") or ""),
        "finishedAt": str(raw.get("finishedAt") or ""),
        "parentJobId": str(raw.get("parentJobId") or ""),
        "errors": [str(value) for value in raw.get("errors", []) if str(value).strip()] if isinstance(raw.get("errors"), list) else [],
        "children": [dict(value) for value in children if isinstance(value, dict)] if isinstance(children, list) else [],
    }


def save_capability_apply_state(
    workspace: StoredEngagementWorkspace,
    state: dict[str, Any],
    *,
    repository: EngagementWorkspaceRepository | None = None,
) -> StoredEngagementWorkspace:
    """Persist aggregate apply provenance alongside the saved selection."""

    repo = repository or SqlAlchemyEngagementWorkspaceRepository()
    return _save_apply_state(repo, workspace, state)


def desktop_capability_reconciliation_input(
    engagement_id: str,
    *,
    root: Path,
    repository: EngagementWorkspaceRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    payload = engagement_capability_workspace(
        engagement_id,
        root=root,
        repository=repository,
        service_repository=service_repository,
    )
    if payload is None:
        return None
    workspace = payload.get("workspace")
    if not isinstance(workspace, dict):
        raise EngagementCapabilityValidationError(
            ["save the engagement capability selection before reconciling Desktop capabilities"]
        )
    homebase = payload.get("profileResolution", {}).get("hostClasses", {}).get("homebase", {})
    entries: dict[str, dict[str, Any]] = {}
    for classification in ("essential", "default", "optional"):
        for entry in homebase.get(classification, []):
            if isinstance(entry, dict) and entry.get("id"):
                entries[str(entry["id"])] = entry
    missing = [capability_id for capability_id in DESKTOP_CAPABILITY_IDS if capability_id not in entries]
    if missing:
        raise EngagementCapabilityValidationError(
            [f"Desktop capability is unavailable in the engagement profile: {capability_id}" for capability_id in missing]
        )
    desired_apps = [
        {"slug": capability_id, "enabled": bool(entries[capability_id].get("selected"))}
        for capability_id in DESKTOP_CAPABILITY_IDS
    ]
    source = {
        "kind": "engagement-capability-selection",
        "workspaceStatus": str(workspace.get("status") or ""),
        "workspaceUpdatedAt": str(workspace.get("updatedAt") or ""),
        "selectedCapabilityIds": [row["slug"] for row in desired_apps if row["enabled"]],
    }
    return desired_apps, source


def engagement_core_provider(engagement: Any) -> str | None:
    input_parameters = getattr(engagement, "input_parameters", None)
    if not isinstance(input_parameters, dict):
        input_parameters = getattr(engagement, "inputParameters", None)
    if not isinstance(input_parameters, dict):
        return None
    return str(input_parameters.get("coreProvider") or "").strip() or None


def apply_capability_overrides_to_resolution(
    resolution: dict[str, Any],
    overrides: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    deselected_defaults = _selection_key_set(overrides.get("deselectedDefaults", []))
    selected_optionals = _selection_key_set(overrides.get("selectedOptionals", []))
    selected_defaults: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    selected_optional_rows: list[dict[str, str]] = []

    for host_class, classifications in resolution.get("hostClasses", {}).items():
        for classification, entries in classifications.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                capability_id = str(entry.get("id") or "")
                key = _selection_key(host_class, capability_id)
                selected = classification == "essential" or classification == "default"
                if classification == "default" and key in deselected_defaults:
                    selected = False
                    excluded.append(_selection_record(host_class, capability_id))
                elif classification == "default":
                    selected_defaults.append(_selection_record(host_class, capability_id))
                elif classification == "optional":
                    selected = key in selected_optionals
                    if selected:
                        selected_optional_rows.append(_selection_record(host_class, capability_id))
                entry["selected"] = selected
                entry["locked"] = classification == "essential"

    resolution["selection"] = {
        "selectedDefaults": selected_defaults,
        "deselectedDefaults": sorted(overrides.get("deselectedDefaults", []), key=lambda item: (item["hostClass"], item["id"])),
        "selectedOptionals": selected_optional_rows,
        "excludedCapabilities": excluded,
    }
    return resolution


def _workspace_profile_resolution(workspace: StoredEngagementWorkspace, *, core_provider: str | None = None):
    return resolve_standard_rti_profile(
        source=RedteamInfraTemplateSource(Path(workspace.path), "engagement-workspace"),
        core_provider=core_provider,
    )


def _workspace_payload(
    *,
    workspace: StoredEngagementWorkspace | None,
    resolution: dict[str, Any],
    overrides: dict[str, list[dict[str, str]]],
    native_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved = apply_capability_overrides_to_resolution(resolution, overrides)
    return {
        "workspace": workspace.to_dict() if workspace is not None else None,
        "profileResolution": resolved,
        "overrides": resolved["selection"],
        "nativeState": native_state or {},
        "applyState": capability_apply_state_for_workspace(workspace),
        "inferenceProxy": inference_proxy.public_state(workspace.metadata if workspace else {}),
        "atc": atc.public_state(workspace.metadata if workspace else {}),
        "executionPolicy": {
            "terraform": False,
            "ansible": True,
            "providerMutation": False,
            "reason": "Selected executable Ansible role capabilities are applied during core infrastructure deployment.",
        },
    }


def _native_state(
    engagement: Any,
    static_state: dict[str, Any],
    implied: bool,
    overrides: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    return {
        "staticWeb": {
            **static_state,
            "selected": static_web_is_selected(overrides),
            "implied": implied,
        },
        "backflips": _backflips_readiness(engagement),
    }


def _backflips_readiness(engagement: Any) -> dict[str, Any]:
    parameters = getattr(engagement, "input_parameters", {}) if engagement is not None else {}
    if not isinstance(parameters, dict):
        parameters = {}
    proxy_count = int(parameters.get("proxyCount") or 2)
    proxies = [f"proxy{index:02d}" for index in range(1, min(max(proxy_count, 1), 2) + 1)]
    latest_by_proxy: dict[str, Any] = {}
    try:
        repository = SqlAlchemyJobRepository()
        engagement_id = str(getattr(engagement, "id", "") or "")
        jobs = repository.list_for_engagement(engagement_id)
        core_deployment_id, core_details = active_core_connection_details(repository, engagement_id)
    except RuntimeError:
        jobs = []
        core_deployment_id, core_details = "", []
    for job in jobs:
        if job.action != "backflips_service_apply":
            continue
        proxy_id = str(job.input.get("proxyId") or "")
        current_proxy_identity = core_proxy_identity(core_details, proxy_id)
        belongs_to_current_core = (
            bool(core_deployment_id)
            and job.input.get("coreDeploymentId") == core_deployment_id
            and job.input.get("coreProxyIdentity") == current_proxy_identity
        )
        if proxy_id in proxies and belongs_to_current_core and proxy_id not in latest_by_proxy:
            latest_by_proxy[proxy_id] = job
    rows = []
    for proxy_id in proxies:
        job = latest_by_proxy.get(proxy_id)
        if job is None:
            status = "Waiting"
        elif job.status in {"queued", "running"}:
            status = "Configuring"
        elif job.status == "succeeded":
            status = "Ready"
        else:
            status = "Failed"
        rows.append({"proxyId": proxy_id, "status": status, "jobId": job.id if job is not None else ""})
    return {"configureRoute": "backflips", "proxies": rows}


def _workspace_overrides(workspace: StoredEngagementWorkspace) -> dict[str, list[dict[str, str]]]:
    raw = workspace.metadata.get(CAPABILITY_OVERRIDES_METADATA_KEY)
    return _normalize_overrides(raw if isinstance(raw, dict) else {})


def _empty_overrides() -> dict[str, list[dict[str, str]]]:
    return {"deselectedDefaults": [], "selectedOptionals": []}


def _normalize_overrides(body: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    return {
        "deselectedDefaults": _normalize_selection_rows(body.get("deselectedDefaults")),
        "selectedOptionals": _normalize_selection_rows(body.get("selectedOptionals")),
    }


def _normalize_selection_rows(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    normalized: dict[str, dict[str, str]] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        host_class = str(item.get("hostClass") or "").strip()
        capability_id = str(item.get("id") or "").strip()
        if not host_class or not capability_id:
            continue
        normalized[_selection_key(host_class, capability_id)] = _selection_record(host_class, capability_id)
    return sorted(normalized.values(), key=lambda item: (item["hostClass"], item["id"]))


def _selection_errors(
    resolution: dict[str, Any],
    overrides: dict[str, list[dict[str, str]]],
    *,
    allowed_missing_optionals: set[tuple[str, str]] = frozenset(),
) -> list[str]:
    index = _profile_entry_index(resolution)
    errors: list[str] = []
    for row in overrides["deselectedDefaults"]:
        entry = index.get(_selection_key(row["hostClass"], row["id"]))
        if entry is None:
            errors.append(f"unknown default capability: {row['hostClass']}/{row['id']}")
            continue
        if entry.get("classification") == "essential":
            errors.append(f"essential capability cannot be deselected: {row['hostClass']}/{row['id']}")
        elif entry.get("classification") != "default":
            errors.append(f"only default capabilities can be deselected: {row['hostClass']}/{row['id']}")
        elif not _entry_is_user_selectable(entry):
            errors.append(f"default capability is not selectable: {row['hostClass']}/{row['id']}")
    for row in overrides["selectedOptionals"]:
        entry = index.get(_selection_key(row["hostClass"], row["id"]))
        if entry is None:
            if (row["hostClass"], row["id"]) in allowed_missing_optionals:
                continue
            errors.append(f"unknown optional capability: {row['hostClass']}/{row['id']}")
            continue
        if entry.get("classification") != "optional":
            errors.append(f"only optional capabilities can be explicitly selected: {row['hostClass']}/{row['id']}")
        elif not _entry_is_user_selectable(entry):
            errors.append(f"optional capability is not selectable: {row['hostClass']}/{row['id']}")
    return errors


def _profile_entry_index(resolution: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for host_class, classifications in resolution.get("hostClasses", {}).items():
        for entries in classifications.values():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                capability_id = str(entry.get("id") or "")
                if capability_id:
                    index[_selection_key(str(host_class), capability_id)] = entry
    return index


def _entry_is_user_selectable(entry: dict[str, Any]) -> bool:
    operator = entry.get("operator") if isinstance(entry.get("operator"), dict) else {}
    return (
        bool(operator.get("selectable"))
        and bool(entry.get("executable"))
        and entry.get("resolution") == "catalog"
    )


def _save_overrides(
    repo: EngagementWorkspaceRepository,
    workspace: StoredEngagementWorkspace,
    overrides: dict[str, list[dict[str, str]]],
) -> StoredEngagementWorkspace:
    metadata = dict(workspace.metadata)
    metadata[CAPABILITY_OVERRIDES_METADATA_KEY] = overrides
    return repo.save(
        StoredEngagementWorkspace(
            engagement_id=workspace.engagement_id,
            slug=workspace.slug,
            path=workspace.path,
            status="capabilities-configured",
            profile_id=workspace.profile_id,
            template_source=workspace.template_source,
            metadata=metadata,
            created_at=workspace.created_at,
            updated_at=workspace.updated_at,
        )
    )


def _unsaved_apply_state() -> dict[str, Any]:
    return {
        "status": "unsaved",
        "selectionFingerprint": "",
        "renderedInputFingerprint": "",
        "preparedAt": "",
        "startedAt": "",
        "finishedAt": "",
        "parentJobId": "",
        "errors": [],
        "children": [],
    }


def _preparing_apply_state(
    workspace: StoredEngagementWorkspace,
    resolution: dict[str, Any],
    overrides: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    fingerprint_payload = {
        "engagementId": workspace.engagement_id,
        "profileId": workspace.profile_id,
        "templateSource": workspace.template_source,
        "selection": apply_capability_overrides_to_resolution(dict(resolution), overrides).get("selection", {}),
    }
    if inference_proxy.is_selected(overrides):
        fingerprint_payload["inferenceProxy"] = inference_proxy.execution_inputs(Path(workspace.path), workspace.metadata)
    if c2_observer.is_selected(overrides):
        fingerprint_payload["c2Observer"] = c2_observer.execution_inputs(Path(workspace.path), workspace.metadata)
    if loottool.is_selected(overrides):
        fingerprint_payload["loottool"] = loottool.execution_inputs(Path(workspace.path), workspace.metadata, engagement_id=workspace.engagement_id)
    if atc.is_selected(overrides):
        inputs = atc.execution_inputs(Path(workspace.path), workspace.metadata)
        if inputs["engagement"] != atc.engagement_context(get_engagement(workspace.engagement_id)):
            raise atc.ATCCapabilityError("ATC engagement context changed; save configuration again")
        fingerprint_payload["atc"] = inputs
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        **_unsaved_apply_state(),
        "status": "preparing",
        "selectionFingerprint": fingerprint,
    }


def _blocked_preparation_state(state: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    return {
        **state,
        "status": "blocked",
        "errors": [str(error) for error in errors if str(error).strip()],
    }


def _rendered_input_fingerprint(lock: dict[str, Any]) -> str:
    """Fingerprint the executable rendered inputs, excluding render timestamps."""

    payload = {
        "profile": lock.get("profile"),
        "selection": lock.get("selection"),
        "capabilities": lock.get("capabilities"),
        "templateSource": lock.get("templateSource"),
    }
    if "inferenceProxy" in lock:
        payload["inferenceProxy"] = lock["inferenceProxy"]
    if "c2Observer" in lock:
        payload["c2Observer"] = lock["c2Observer"]
    if "atc" in lock:
        payload["atc"] = lock["atc"]
    if "loottool" in lock:
        payload["loottool"] = lock["loottool"]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _save_apply_state(
    repo: EngagementWorkspaceRepository,
    workspace: StoredEngagementWorkspace,
    state: dict[str, Any],
) -> StoredEngagementWorkspace:
    metadata = dict(workspace.metadata)
    metadata[CAPABILITY_APPLY_STATE_METADATA_KEY] = state
    return repo.save(
        StoredEngagementWorkspace(
            engagement_id=workspace.engagement_id,
            slug=workspace.slug,
            path=workspace.path,
            status=workspace.status,
            profile_id=workspace.profile_id,
            template_source=workspace.template_source,
            metadata=metadata,
            created_at=workspace.created_at,
            updated_at=workspace.updated_at,
        )
    )


def _selection_key(host_class: str, capability_id: str) -> str:
    return f"{host_class.strip()}::{capability_id.strip()}"


def _selection_key_set(rows: list[dict[str, str]]) -> set[str]:
    return {_selection_key(row["hostClass"], row["id"]) for row in rows}


def _selection_record(host_class: str, capability_id: str) -> dict[str, str]:
    return {"hostClass": host_class, "id": capability_id}
