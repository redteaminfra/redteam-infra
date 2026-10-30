# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
import stat
import re
import yaml
import shutil
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from app.services import inference_proxy_capability as inference_proxy
from app.services import c2_observer_capability as c2_observer
from app.services import loottool_capability as loottool
from app.services import atc_capability as atc
from app.services.capability_profile_resolution import resolve_standard_rti_profile
from app.services.engagement_capabilities import (
    DESKTOP_CAPABILITY_IDS,
    apply_capability_overrides_to_resolution,
    capability_overrides_for_workspace,
    engagement_core_provider,
)
from app.services.engagements import get_engagement
from app.services.engagement_workspaces import EngagementWorkspaceValidationError, load_prepared_engagement_workspace
from app.services.redteam_infra_template import RedteamInfraTemplateSource, resolve_redteam_infra_template_source
from app.storage.engagement_workspace_repository import EngagementWorkspaceRepository, SqlAlchemyEngagementWorkspaceRepository


ROLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
APT_FAMILY_TASK_PATTERN = re.compile(
    r"^\s+(?:ansible\.builtin\.)?(?:apt|apt_key|apt_repository):\s*$",
    re.MULTILINE,
)
APT_LOCK_SETTLE_TASK = """- name: Barragan wait for apt locks after package task
  ansible.builtin.shell: |
    set -eu
    for _ in $(seq 1 120); do
      if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
        sleep 5
        if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
          exit 0
        fi
      fi
      sleep 5
    done
    exit 1
  args:
    executable: /bin/bash
  changed_when: false
  when: ansible_facts.os_family | default('') == 'Debian'
"""
GOOGLE_CHROME_LEGACY_RETRY = """  retries: 3
  delay: 5
  until: result is succeeded"""
GOOGLE_CHROME_REGISTERED_RETRY = """  register: google_chrome_gpg_key_result
  retries: 3
  delay: 5
  until: google_chrome_gpg_key_result is succeeded"""
FIREFOX_PPA_TASK = """- name: Add mozzila repository from PPA and install its signing key
  ansible.builtin.apt_repository:
    repo: ppa:mozillateam/ppa"""
FIREFOX_PPA_BOUNDED_LOOKUP = """- name: Read Firefox PPA signing metadata
  ansible.builtin.uri:
    url: https://api.launchpad.net/1.0/~mozillateam/+archive/ppa
    headers:
      Accept: application/json
    return_content: true
    validate_certs: true
    follow_redirects: none
    timeout: 60
    status_code: 200
  register: firefox_ppa_result
  retries: 3
  delay: 5
  until: firefox_ppa_result is succeeded
  changed_when: false

- name: Validate Firefox PPA signing fingerprint
  ansible.builtin.assert:
    that:
      - firefox_ppa_result.json.signing_key_fingerprint is string
      - firefox_ppa_result.json.signing_key_fingerprint is match('^[0-9A-F]{40}$')

- name: Install Firefox PPA signing key
  ansible.builtin.apt_key:
    id: "{{ firefox_ppa_result.json.signing_key_fingerprint }}"
    keyserver: hkp://keyserver.ubuntu.com:80
    state: present

- name: Add Firefox PPA repository
  ansible.builtin.apt_repository:
    repo: "deb https://ppa.launchpadcontent.net/mozillateam/ppa/ubuntu {{ ansible_distribution_release }} main"
    filename: "ppa_mozillateam_ppa_{{ ansible_distribution_release }}"
    state: present"""
CORE_HOST_CLASS_GROUPS = {
    "common": "pilot_rti",
    "homebase": "homebase",
    "proxy": "proxies",
    "elk": "elk",
}
HOST_CLASS_ORDER = ("common", "homebase", "proxy", "elk")
OPTIONAL_RECONCILIATION_EXCLUDED_CAPABILITY_IDS = frozenset(
    DESKTOP_CAPABILITY_IDS
)


@dataclass(frozen=True)
class CapabilityRoleApplyPlan:
    source: RedteamInfraTemplateSource
    roles_by_host_class: dict[str, list[dict[str, str]]]
    selected_count: int
    executable_count: int
    skipped: list[dict[str, str]]
    warnings: list[dict[str, str]]
    errors: list[dict[str, str]]
    inference_proxy_inputs: dict[str, Any] = field(default_factory=dict)
    c2_observer_inputs: dict[str, Any] = field(default_factory=dict)
    loottool_inputs: dict[str, Any] = field(default_factory=dict)
    engagement_id: str = ""
    atc_inputs: dict[str, Any] = field(default_factory=dict)

    @property
    def role_names(self) -> list[str]:
        seen: set[str] = set()
        roles: list[str] = []
        for host_class in HOST_CLASS_ORDER:
            for entry in self.roles_by_host_class.get(host_class, []):
                role = entry["role"]
                if role not in seen:
                    seen.add(role)
                    roles.append(role)
        return roles

    def to_summary(self) -> dict[str, Any]:
        return {
            "source": {
                "path": str(self.source.root),
                "kind": self.source.source,
                "warning": self.source.warning,
            },
            "selectedCount": self.selected_count,
            "executableCount": self.executable_count,
            "roleCount": len(self.role_names),
            "rolesByHostClass": {
                host_class: [dict(entry) for entry in self.roles_by_host_class.get(host_class, [])]
                for host_class in HOST_CLASS_ORDER
            },
            "skipped": [dict(entry) for entry in self.skipped],
            "warnings": [dict(entry) for entry in self.warnings],
            "errors": [dict(entry) for entry in self.errors],
            **({"inferenceProxy": self.inference_proxy_inputs} if self.inference_proxy_inputs else {}),
            **({"c2Observer": self.c2_observer_inputs} if self.c2_observer_inputs else {}),
            **({"loottool": self.loottool_inputs} if self.loottool_inputs else {}),
            **({"atc": self.atc_inputs} if self.atc_inputs else {}),
        }


class CapabilityRoleApplyPlanValidationError(ValueError):
    def __init__(self, errors: list[dict[str, str]], *, source: RedteamInfraTemplateSource) -> None:
        self.errors = [dict(error) for error in errors]
        self.source = source
        messages = "; ".join(error.get("reason", "unknown error") for error in self.errors)
        super().__init__(
            "Selected core capabilities could not be resolved into an executable Ansible role plan"
            + (f": {messages}" if messages else ".")
        )


def build_core_capability_role_apply_plan(
    *,
    engagement_id: str | None,
    engagement_repos_root: Path,
    repository: EngagementWorkspaceRepository | None = None,
    validate_selected_core_capabilities: bool = True,
    elk_enabled: bool = False,
) -> CapabilityRoleApplyPlan:
    repo = repository or SqlAlchemyEngagementWorkspaceRepository()
    engagement = get_engagement(engagement_id) if engagement_id else None
    workspace = None
    if engagement_id:
        try:
            workspace = load_prepared_engagement_workspace(
                engagement_id,
                root=engagement_repos_root,
                repository=repo,
            )
        except EngagementWorkspaceValidationError as exc:
            if exc.errors != ["engagement workspace must be prepared before rendering capability artifacts"]:
                raise

    if workspace is not None:
        source = RedteamInfraTemplateSource(Path(workspace.path), "engagement-workspace")
        overrides = capability_overrides_for_workspace(workspace)
    else:
        source = resolve_redteam_infra_template_source()
        overrides = {"deselectedDefaults": [], "selectedOptionals": []}

    resolution = resolve_standard_rti_profile(
        source=source,
        core_provider=engagement_core_provider(engagement) if engagement is not None else None,
    ).to_dict()
    resolution = apply_capability_overrides_to_resolution(resolution, overrides)
    if not elk_enabled:
        resolution.get("hostClasses", {}).pop("elk", None)
    plan = _plan_from_resolution(source, resolution)
    plan = replace(plan, engagement_id=engagement_id or "")
    _attach_atc_inputs(plan, workspace)
    _attach_loottool_inputs(plan, workspace)
    _attach_inference_proxy_inputs(plan, workspace)
    _attach_c2_observer_inputs(plan, workspace)
    if validate_selected_core_capabilities and plan.errors:
        raise CapabilityRoleApplyPlanValidationError(plan.errors, source=source)
    return plan


def build_optional_core_capability_role_apply_plan(
    *,
    engagement_id: str,
    engagement_repos_root: Path,
    repository: EngagementWorkspaceRepository | None = None,
    elk_enabled: bool = False,
) -> CapabilityRoleApplyPlan:
    """Resolve only the explicitly selected optional core role capabilities.

    Active-host reconciliation deliberately has a narrower contract than the
    core deployment renderer: it never replays essential/default roles,
    Desktop's dedicated lifecycle, or Barragan-native capabilities.
    """

    repo = repository or SqlAlchemyEngagementWorkspaceRepository()
    workspace = load_prepared_engagement_workspace(
        engagement_id,
        root=engagement_repos_root,
        repository=repo,
    )
    if workspace is None:
        raise EngagementWorkspaceValidationError(
            ["engagement workspace must be prepared before reconciling optional capabilities"]
        )
    source = RedteamInfraTemplateSource(Path(workspace.path), "engagement-workspace")
    engagement = get_engagement(engagement_id)
    resolution = resolve_standard_rti_profile(
        source=source,
        core_provider=engagement_core_provider(engagement) if engagement is not None else None,
    ).to_dict()
    resolution = apply_capability_overrides_to_resolution(
        resolution,
        capability_overrides_for_workspace(workspace),
    )
    if not elk_enabled:
        resolution.get("hostClasses", {}).pop("elk", None)
    plan = _plan_from_resolution(
        source,
        resolution,
        selected_classifications={"optional"},
        excluded_capability_ids=OPTIONAL_RECONCILIATION_EXCLUDED_CAPABILITY_IDS,
    )
    plan = replace(plan, engagement_id=engagement_id or "")
    _attach_atc_inputs(plan, workspace)
    _attach_loottool_inputs(plan, workspace)
    _attach_inference_proxy_inputs(plan, workspace)
    _attach_c2_observer_inputs(plan, workspace)
    if plan.errors:
        raise CapabilityRoleApplyPlanValidationError(plan.errors, source=source)
    return plan


def render_core_capability_apply_playbook(plan: CapabilityRoleApplyPlan) -> str:
    plays: list[str] = [
        "---",
        "- name: Apply Barragan-selected core Ansible capabilities",
        "  hosts: localhost",
        "  gather_facts: false",
        "  tasks:",
        "    - name: Report selected capability execution plan",
        "      ansible.builtin.debug:",
        f"        msg: \"Applying {len(plan.role_names)} selected executable role-backed capabilities.\"",
    ]
    for host_class in HOST_CLASS_ORDER:
        entries = plan.roles_by_host_class.get(host_class, [])
        if not entries:
            continue
        plays.extend(
            [
                "",
                f"- name: Apply {host_class} selected capabilities",
                f"  hosts: {CORE_HOST_CLASS_GROUPS[host_class]}",
                "  become: true",
                "  gather_facts: true",
                "  tasks:",
                f"    - name: Quiesce apt background services before {host_class} capabilities",
                "      ansible.builtin.systemd:",
                "        name: \"{{ item }}\"",
                "        state: stopped",
                "      loop:",
                "        - apt-daily.timer",
                "        - apt-daily-upgrade.timer",
                "        - apt-daily.service",
                "        - apt-daily-upgrade.service",
                "        - unattended-upgrades.service",
                "      failed_when: false",
                "      changed_when: false",
                f"    - name: Wait for apt and dpkg locks to remain clear before {host_class} capabilities",
                "      ansible.builtin.shell: |",
                "        set -eu",
                "        for _ in $(seq 1 120); do",
                "          if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then",
                "            sleep 10",
                "            if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then",
                "              exit 0",
                "            fi",
                "          fi",
                "          sleep 5",
                "        done",
                "        exit 1",
                "      args:",
                "        executable: /bin/bash",
                "      changed_when: false",
            ]
        )
        for entry in entries:
            plays.extend(
                [
                    f"    - name: Wait for apt and dpkg locks before capability {entry['id']}",
                    "      ansible.builtin.shell: |",
                    "        set -eu",
                    "        for _ in $(seq 1 60); do",
                    "          if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then",
                    "            exit 0",
                    "          fi",
                    "          sleep 5",
                    "        done",
                    "        exit 1",
                    "      args:",
                    "        executable: /bin/bash",
                    "      changed_when: false",
                    f"    - name: Apply capability {entry['id']}",
                    "      ansible.builtin.include_role:",
                    f"        name: {entry['role']}",
                ]
            )
            if entry["id"] == inference_proxy.CAPABILITY_ID:
                if not plan.inference_proxy_inputs:
                    raise ValueError("Inference Proxy execution inputs were not prepared")
                rendered_vars = yaml.safe_dump(inference_proxy.role_variables(plan.inference_proxy_inputs), sort_keys=False).rstrip()
                plays.append("      vars:")
                plays.extend("        " + line for line in rendered_vars.splitlines())
            if entry["id"] == c2_observer.CAPABILITY_ID:
                if not plan.c2_observer_inputs:
                    raise ValueError("C2 Observer execution inputs were not prepared")
                rendered_vars = yaml.safe_dump(c2_observer.role_variables(plan.c2_observer_inputs), sort_keys=False).rstrip()
                plays.append("      vars:")
                plays.extend("        " + line for line in rendered_vars.splitlines())
            if entry["id"] == loottool.CAPABILITY_ID:
                if not plan.loottool_inputs:
                    raise ValueError("LootTool execution inputs were not prepared")
                rendered_vars = yaml.safe_dump(loottool.role_variables(plan.loottool_inputs), sort_keys=False).rstrip()
                plays.append("      vars:")
                plays.extend("        " + line for line in rendered_vars.splitlines())
            if entry["id"] == atc.CAPABILITY_ID:
                if not plan.atc_inputs:
                    raise ValueError("ATC execution inputs were not prepared")
                rendered_vars = yaml.safe_dump(atc.role_variables(plan.atc_inputs), sort_keys=False).rstrip()
                plays.append("      vars:")
                plays.extend("        " + line for line in rendered_vars.splitlines())
        if host_class == "homebase" and any(entry["role"] == "homebase" for entry in entries):
            plays.extend(_HOMEBASE_POST_BASELINE_PROFILE_CANONICALIZATION)
    return "\n".join(plays) + "\n"


_HOMEBASE_POST_BASELINE_PROFILE_CANONICALIZATION = (
    "",
    "    - name: Canonicalize Dante-oriented homebase user profiles after upstream baseline",
    "      ansible.builtin.shell: |",
    "        set -eu",
    "        for legacy_profile in /etc/skel/proxy??/proxychains.conf /home/*/proxy??/proxychains.conf; do",
    "          if [ ! -e \"${legacy_profile}\" ] && [ ! -L \"${legacy_profile}\" ]; then",
    "            continue",
    "          fi",
    "          profile_dir=\"$(dirname \"${legacy_profile}\")\"",
    "          proxy_name=\"$(basename \"${profile_dir}\")\"",
    "          canonical_profile=\"${profile_dir}/${proxy_name}-http.conf\"",
    "          if [ -L \"${legacy_profile}\" ]; then",
    "            legacy_target=\"$(readlink \"${legacy_profile}\")\"",
    "            if [ \"${legacy_target}\" = \"${proxy_name}-http.conf\" ] || \\",
    "               { [ -e \"${canonical_profile}\" ] && [ \"$(readlink -f \"${legacy_profile}\")\" = \"$(readlink -f \"${canonical_profile}\")\" ]; }; then",
    "              ln -sfn \"${proxy_name}-http.conf\" \"${legacy_profile}\"",
    "              continue",
    "            fi",
    "          fi",
    "          cp --preserve=mode,ownership,timestamps --dereference \"${legacy_profile}\" \"${canonical_profile}\"",
    "          ln -sfn \"${proxy_name}-http.conf\" \"${legacy_profile}\"",
    "        done",
    "      args:",
    "        executable: /bin/bash",
    "      changed_when: false",
)


def copy_core_capability_roles(destination: Path, plan: CapabilityRoleApplyPlan) -> None:
    roles = _role_names_with_dependencies(plan.source, plan.role_names)
    if plan.atc_inputs:
        lock_path = plan.source.root / "barragan" / "capability-lock.yml"
        try:
            if any(path.is_symlink() for path in (lock_path, lock_path.parent)) or lock_path.stat().st_size > 1024 * 1024:
                raise atc.ATCCapabilityError("ATC retained capability lock is unsafe")
            retained_lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise atc.ATCCapabilityError("ATC retained capability lock is unavailable; save and retry") from exc
        if not isinstance(retained_lock, dict) or retained_lock.get("atc") != plan.atc_inputs:
            raise atc.ATCCapabilityError("ATC saved configuration/release changed; save and retry")
        if plan.atc_inputs["engagement"] != atc.engagement_context(get_engagement(plan.engagement_id)):
            raise atc.ATCCapabilityError("ATC engagement context changed; save configuration again")
        atc.copy_artifacts(destination, plan.source.root, plan.atc_inputs)
    if plan.loottool_inputs:
        loottool.copy_artifacts(destination, plan.source.root, plan.loottool_inputs, engagement_id=plan.engagement_id)
    if plan.c2_observer_inputs:
        c2_observer.copy_artifacts(destination, plan.source.root, plan.c2_observer_inputs)
    if plan.inference_proxy_inputs:
        # Verify the exact retained bytes immediately before copying to the
        # disposable execution workspace, not merely when Save rendered a lock.
        metadata = {
            inference_proxy.CONFIGURATION_KEY: plan.inference_proxy_inputs["configuration"],
            inference_proxy.SOURCE_KEY: plan.inference_proxy_inputs["source"],
        }
        checked = inference_proxy.execution_inputs(plan.source.root, metadata)
        relative = checked["source"]["relativePath"]
        target = inference_proxy._safe_artifact(destination, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.resolve() != (plan.source.root / relative).resolve():
            shutil.copyfile(plan.source.root / relative, target)
            target.chmod(0o600)
        inference_proxy.execution_inputs(destination, metadata)
    for role in roles:
        _copy_role(plan.source.ansible_role_path(role), destination / "ansible" / "roles" / role)


def copy_capability_role_for_runtime(source: Path, destination: Path) -> None:
    """Copy one upstream role into a disposable Barragan runtime workspace."""

    _copy_role(source, destination)


def _attach_inference_proxy_inputs(plan: CapabilityRoleApplyPlan, workspace: Any) -> None:
    if inference_proxy.CAPABILITY_ID not in {entry["id"] for entries in plan.roles_by_host_class.values() for entry in entries}:
        return
    try:
        if workspace is None:
            raise inference_proxy.InferenceProxyConfigurationError("Save Inference Proxy configuration before applying it")
        plan.inference_proxy_inputs.update(inference_proxy.execution_inputs(Path(workspace.path), workspace.metadata))
    except inference_proxy.InferenceProxyConfigurationError as exc:
        plan.errors.append({"id": inference_proxy.CAPABILITY_ID, "hostClass": "homebase", "reason": str(exc)})


def _attach_atc_inputs(plan: CapabilityRoleApplyPlan, workspace: Any) -> None:
    if atc.CAPABILITY_ID not in {entry["id"] for entries in plan.roles_by_host_class.values() for entry in entries}:
        return
    try:
        if workspace is None:
            raise atc.ATCCapabilityError("Save ATC configuration before applying it")
        inputs = atc.execution_inputs(Path(workspace.path), workspace.metadata)
        if inputs["engagement"] != atc.engagement_context(get_engagement(plan.engagement_id)):
            raise atc.ATCCapabilityError("ATC engagement context changed; save configuration again")
        plan.atc_inputs.update(inputs)
    except atc.ATCCapabilityError as exc:
        plan.errors.append({"id": atc.CAPABILITY_ID, "hostClass": "homebase", "reason": str(exc)})


def _attach_loottool_inputs(plan: CapabilityRoleApplyPlan, workspace: Any) -> None:
    if loottool.CAPABILITY_ID not in {entry["id"] for entries in plan.roles_by_host_class.values() for entry in entries}:
        return
    try:
        if workspace is None:
            raise loottool.LootToolArtifactError("Save LootTool selection before applying it")
        plan.loottool_inputs.update(loottool.execution_inputs(Path(workspace.path), workspace.metadata, engagement_id=plan.engagement_id))
    except loottool.LootToolArtifactError as exc:
        plan.errors.append({"id": loottool.CAPABILITY_ID, "hostClass": "homebase", "reason": str(exc)})


def _attach_c2_observer_inputs(plan: CapabilityRoleApplyPlan, workspace: Any) -> None:
    if c2_observer.CAPABILITY_ID not in {entry["id"] for entries in plan.roles_by_host_class.values() for entry in entries}:
        return
    try:
        if workspace is None:
            raise c2_observer.C2ObserverArtifactError("Save C2 Observer selection before applying it")
        plan.c2_observer_inputs.update(c2_observer.execution_inputs(Path(workspace.path), workspace.metadata))
    except c2_observer.C2ObserverArtifactError as exc:
        plan.errors.append({"id": c2_observer.CAPABILITY_ID, "hostClass": "homebase", "reason": str(exc)})


def _plan_from_resolution(
    source: RedteamInfraTemplateSource,
    resolution: dict[str, Any],
    *,
    selected_classifications: set[str] | None = None,
    excluded_capability_ids: frozenset[str] = frozenset(),
) -> CapabilityRoleApplyPlan:
    roles_by_host_class: dict[str, list[dict[str, str]]] = {host_class: [] for host_class in HOST_CLASS_ORDER}
    selected_count = 0
    executable_count = 0
    skipped: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []

    for host_class, classifications in resolution.get("hostClasses", {}).items():
        if not isinstance(classifications, dict):
            continue
        for classification, entries in classifications.items():
            if not isinstance(entries, list):
                continue
            if selected_classifications is not None and classification not in selected_classifications:
                continue
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("selected") is not True:
                    continue
                selected_count += 1
                capability_id = str(entry.get("id") or "").strip()
                if capability_id in excluded_capability_ids:
                    skipped.append(
                        {
                            "id": capability_id,
                            "hostClass": str(host_class),
                            "reason": "capability has a dedicated reconciliation workflow",
                        }
                    )
                    continue
                if host_class not in CORE_HOST_CLASS_GROUPS:
                    skipped.append({"id": capability_id, "hostClass": str(host_class), "reason": "host class is not part of core deployment"})
                    continue
                implementation = entry.get("implementation") if isinstance(entry.get("implementation"), dict) else {}
                implementation_type = str(implementation.get("type") or "").strip()
                if implementation_type == "barragan-native":
                    skipped.append({"id": capability_id, "hostClass": str(host_class), "reason": "capability is managed by a Barragan-native workflow"})
                    continue
                role = str(implementation.get("role") or "").strip()
                if not bool(entry.get("executable")) or implementation_type != "role" or not role:
                    _record_blocking_skip(
                        skipped,
                        errors,
                        id=capability_id,
                        host_class=str(host_class),
                        reason="selected core capability is not an executable Ansible role",
                    )
                    continue
                if not ROLE_NAME_PATTERN.fullmatch(role):
                    reason = "selected core capability role name is not safe"
                    warnings.append({"id": capability_id, "hostClass": str(host_class), "reason": reason})
                    errors.append({"id": capability_id, "hostClass": str(host_class), "reason": reason})
                    continue
                role_path = source.ansible_role_path(role)
                if not role_path.is_dir():
                    reason = f"selected core capability role path is missing: ansible/roles/{role}"
                    warnings.append({"id": capability_id, "hostClass": str(host_class), "reason": reason})
                    errors.append({"id": capability_id, "hostClass": str(host_class), "reason": reason})
                    continue
                executable_count += 1
                roles_by_host_class[str(host_class)].append({"id": capability_id, "role": role})

    for host_class in HOST_CLASS_ORDER:
        roles_by_host_class[host_class] = _dedupe_role_entries(roles_by_host_class[host_class])
    return CapabilityRoleApplyPlan(
        source=source,
        roles_by_host_class=roles_by_host_class,
        selected_count=selected_count,
        executable_count=executable_count,
        skipped=skipped,
        warnings=warnings,
        errors=errors,
    )


def _record_blocking_skip(
    skipped: list[dict[str, str]],
    errors: list[dict[str, str]],
    *,
    id: str,
    host_class: str,
    reason: str,
) -> None:
    entry = {"id": id, "hostClass": host_class, "reason": reason}
    skipped.append(entry)
    errors.append(dict(entry))


def _dedupe_role_entries(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: dict[str, dict[str, str]] = {}
    for entry in entries:
        deduped.setdefault(entry["role"], entry)
    return list(deduped.values())


def _role_names_with_dependencies(source: RedteamInfraTemplateSource, roles: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def visit(role: str) -> None:
        if not isinstance(role, str) or not ROLE_NAME_PATTERN.fullmatch(role) or role in {".", ".."}:
            raise ValueError("Ansible role dependency must be a safe role name without paths")
        if role in seen:
            return
        seen.add(role)
        ordered.append(role)
        for dependency in _role_dependencies(source.ansible_role_path(role)):
            visit(dependency)

    for role in roles:
        visit(role)
    return ordered


def _role_dependencies(role_path: Path) -> list[str]:
    # Keep the existing meta dependency interpretation; task discovery adds only
    # literal includes and never evaluates Ansible conditions or Jinja.
    dependencies: list[str] = []
    meta_path = role_path / "meta" / "main.yml"
    if meta_path.is_file():
        try:
            content = meta_path.read_text(encoding="utf-8")
        except OSError:
            content = ""
        if "dependencies" in content:
            dependency_section = content.split("dependencies:", 1)[1]
            # The legacy word-boundary matcher omits dot-only mapping values;
            # retain them so the shared role-name boundary can reject them.
            dependencies.extend(re.findall(r"\brole:\s*(\.{1,2})(?=\s|[,}\]]|$)", dependency_section))
            for match in re.finditer(r"\brole:\s*([A-Za-z0-9_.-]+)\b", dependency_section):
                dependencies.append(match.group(1))
            for line in dependency_section.splitlines():
                match = re.match(r"^\s*-\s*([A-Za-z0-9_.-]+)\s*$", line)
                if match:
                    dependencies.append(match.group(1))
    dependencies.extend(_literal_task_role_dependencies(role_path))
    return [role for role in dict.fromkeys(dependencies) if ROLE_NAME_PATTERN.fullmatch(role)]


def _literal_task_role_dependencies(role_path: Path) -> list[str]:
    tasks_root = role_path / "tasks"
    if role_path.is_symlink() or tasks_root.is_symlink():
        raise ValueError("Ansible role task dependency paths must not use symlinks")
    if not tasks_root.exists():
        return []
    if not tasks_root.is_dir():
        raise ValueError("Ansible role tasks must be a directory")
    root = tasks_root.resolve()
    dependencies: list[str] = []
    count = total = 0
    actions = {"include_role", "import_role", "ansible.builtin.include_role", "ansible.builtin.import_role"}

    def fail_walk(error: OSError) -> None:
        raise ValueError("Ansible role task dependencies could not be inspected safely") from error

    for directory, directories, files in os.walk(tasks_root, followlinks=False, onerror=fail_walk):
        directories.sort()
        for name in [*directories, *files]:
            path = Path(directory) / name
            if path.is_symlink() or root not in path.resolve().parents:
                raise ValueError("Ansible role task dependency paths must stay inside tasks without symlinks")
        for name in sorted(files):
            if Path(name).suffix not in {".yml", ".yaml"}:
                continue
            count += 1
            if count > 128:
                raise ValueError("Ansible role task dependency scan exceeds 128 YAML files")
            path = Path(directory) / name
            descriptor = None
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                    raise ValueError("Ansible role task dependency YAML must be a regular file of at most 1 MiB")
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = None
                    content = stream.read(1024 * 1024 + 1)
                total += len(content)
                if len(content) > 1024 * 1024 or total > 8 * 1024 * 1024:
                    raise ValueError("Ansible role task dependency YAML exceeds its 1 MiB file or 8 MiB total bound")
                tasks = yaml.safe_load(content.decode("utf-8"))
            except (OSError, UnicodeError, yaml.YAMLError, RecursionError) as exc:
                raise ValueError("Ansible role task dependency YAML is unavailable, unsafe or malformed") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if tasks is None:
                continue
            if not isinstance(tasks, list):
                raise ValueError("Ansible role task dependency YAML must contain a task list")
            pending, seen = [tasks], set()
            while pending:
                sequence = pending.pop()
                if id(sequence) in seen:
                    continue
                seen.add(id(sequence))
                for task in sequence:
                    if not isinstance(task, dict):
                        continue
                    for action in sorted(actions & task.keys()):
                        specification = task[action]
                        name = specification.get("name") if isinstance(specification, dict) else None
                        if not isinstance(name, str) or any(marker in name for marker in ("{{", "{%", "{#")):
                            continue
                        if not ROLE_NAME_PATTERN.fullmatch(name) or name in {".", ".."}:
                            raise ValueError("Ansible literal role dependency must be a safe role name without paths")
                        dependencies.append(name)
                    for key in ("always", "rescue", "block"):
                        if isinstance(task.get(key), list):
                            pending.append(task[key])
    return dependencies


def _copy_role(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise FileNotFoundError(f"Redteam-infra Ansible role not found: {source}")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    _normalize_role_for_barragan_runtime(destination)


def _normalize_role_for_barragan_runtime(role_path: Path) -> None:
    for path in role_path.rglob("*.yml"):
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        updated = _normalize_google_chrome_retry(role_path, path, content)
        updated = _normalize_firefox_ppa_retry(role_path, path, updated)
        updated = re.sub(r"^(\s*)systemd_service:\s*$", r"\1ansible.builtin.systemd:", updated, flags=re.MULTILINE)
        updated = _insert_apt_lock_settle_tasks(updated)
        if updated != content:
            path.write_text(updated, encoding="utf-8")


def _normalize_google_chrome_retry(role_path: Path, path: Path, content: str) -> str:
    if role_path.name != "google-chrome" or path.relative_to(role_path).as_posix() != "tasks/main.yml":
        return content
    legacy_count = content.count(GOOGLE_CHROME_LEGACY_RETRY)
    fixed_count = content.count(GOOGLE_CHROME_REGISTERED_RETRY)
    if legacy_count == 1 and fixed_count == 0:
        return content.replace(GOOGLE_CHROME_LEGACY_RETRY, GOOGLE_CHROME_REGISTERED_RETRY)
    if legacy_count == 0 and fixed_count == 1:
        return content
    if legacy_count or fixed_count or "until: result is succeeded" in content:
        raise RuntimeError("upstream Google Chrome retry compatibility form was not found exactly once")
    return content


def _normalize_firefox_ppa_retry(role_path: Path, path: Path, content: str) -> str:
    if role_path.name != "firefox" or path.relative_to(role_path).as_posix() != "tasks/main.yml":
        return content
    # apt_repository hardcodes a 10s PPA lookup; the stock Launchpad endpoint
    # took 15s in the failed fresh-host run. Keep its key/repo semantics while
    # using uri's supported bounded timeout. Persistent failures stop the role.
    tasks = list(re.finditer(r"(?ms)^- name: .*?(?=^- name: |\Z)", content))
    matching = [task for task in tasks if task.group().splitlines()[0] == FIREFOX_PPA_TASK.splitlines()[0]]
    if not matching:
        return content
    if len(matching) != 1 or matching[0].group().rstrip() != FIREFOX_PPA_TASK:
        raise RuntimeError("upstream Firefox PPA compatibility form was not found exactly once")
    task = matching[0]
    return content[:task.start()] + FIREFOX_PPA_BOUNDED_LOOKUP + task.group()[len(FIREFOX_PPA_TASK):] + content[task.end():]


def _insert_apt_lock_settle_tasks(content: str) -> str:
    if "Barragan wait for apt locks after package task" in content:
        return content
    task_starts = [match.start() for match in re.finditer(r"(?m)^- name:\s+", content)]
    if not task_starts:
        return content
    chunks: list[str] = []
    cursor = 0
    for index, start in enumerate(task_starts):
        chunks.append(content[cursor:start])
        end = task_starts[index + 1] if index + 1 < len(task_starts) else len(content)
        task = content[start:end]
        if APT_FAMILY_TASK_PATTERN.search(task) and not task.endswith("\n"):
            task += "\n"
        chunks.append(task)
        if APT_FAMILY_TASK_PATTERN.search(task):
            chunks.append(APT_LOCK_SETTLE_TASK)
        cursor = end
    chunks.append(content[cursor:])
    return "".join(chunks)
