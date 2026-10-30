# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


TEMPLATE_ROOT_ENV = "BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT"
APP_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SIBLING_TEMPLATE_ROOT = APP_ROOT.parent / "redteam-infra"
DEFAULT_OPT_TEMPLATE_ROOT = Path("/opt/redteam-infra")


@dataclass(frozen=True)
class RedteamInfraTemplateSource:
    root: Path
    source: str
    warning: str = ""

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    @property
    def ansible_roles_root(self) -> Path:
        return self.path("ansible", "roles")

    def ansible_role_path(self, role_name: str) -> Path:
        return self.ansible_roles_root / role_name

    def sketch_template_dir(self, provider: str) -> Path:
        return self.path("external", "sketch", provider)


def resolve_redteam_infra_template_source(
    *,
    env: Mapping[str, str] | None = None,
    app_root: Path | None = None,
    opt_root: Path | None = None,
) -> RedteamInfraTemplateSource:
    lookup = env if env is not None else os.environ
    root = app_root or APP_ROOT

    configured = str(lookup.get(TEMPLATE_ROOT_ENV, "")).strip()
    if configured:
        return RedteamInfraTemplateSource(Path(configured).expanduser().resolve(), "env")

    candidates = []
    opt_checkout = opt_root or DEFAULT_OPT_TEMPLATE_ROOT
    if opt_checkout != root:
        candidates.append((opt_checkout, "opt"))
    candidates.append((root.parent / "redteam-infra", "sibling"))

    seen: set[Path] = set()
    for candidate, source_name in candidates:
        resolved = candidate.expanduser().resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if _looks_like_redteam_infra(resolved):
            return RedteamInfraTemplateSource(resolved, source_name)

    missing = root.parent / "redteam-infra"
    return RedteamInfraTemplateSource(
        missing.resolve(),
        "missing",
        "No real redteam-infra checkout was found. Configure "
        f"{TEMPLATE_ROOT_ENV}, provide /opt/redteam-infra on barragan-app, or provide ../redteam-infra for local development.",
    )


def redteam_infra_template_root() -> Path:
    return resolve_redteam_infra_template_source().root


def redteam_infra_path(*parts: str) -> Path:
    return resolve_redteam_infra_template_source().path(*parts)


def redteam_infra_ansible_role_path(role_name: str) -> Path:
    return resolve_redteam_infra_template_source().ansible_role_path(role_name)


def redteam_infra_sketch_template_dir(provider: str) -> Path:
    return resolve_redteam_infra_template_source().sketch_template_dir(provider)


def component_safe_sketch_templates_available() -> tuple[bool, str]:
    """Return whether the checked-out modules implement Barragan's component contract.

    Individual-edge deployment needs independent middle/edge workspaces.  Never
    discover a missing contract by starting Terraform: reject it before a job
    or a provider mutation is created.
    """
    source = resolve_redteam_infra_template_source()
    if source.source == "missing":
        return False, source.warning
    for provider in ("linode", "digitalocean"):
        template_dir = source.sketch_template_dir(provider)
        variables = template_dir / "variables.tf"
        try:
            text = variables.read_text(encoding="utf-8")
        except OSError:
            return False, f"{provider} sketch template variables are unavailable"
        if 'variable "middle_ordinal"' not in text or 'variable "edge_ordinal"' not in text:
            return False, f"{provider} sketch template lacks the component ordinal contract"
        try:
            middle = (template_dir / "middle.tf").read_text(encoding="utf-8")
            edge = (template_dir / "edge.tf").read_text(encoding="utf-8")
            outputs = (template_dir / "output.tf").read_text(encoding="utf-8")
        except OSError:
            return False, f"{provider} sketch template component files are unavailable"
        if "var.middle_ordinal" not in middle or "var.edge_ordinal" not in edge:
            return False, f"{provider} sketch template declares but does not use component ordinals in resource naming"
        if 'output "middle_instance_ids"' not in outputs or 'output "edge_instance_ids"' not in outputs:
            return False, f"{provider} sketch template lacks component-correlatable instance outputs"
    providers = source.sketch_template_dir("digitalocean") / "providers.tf"
    try:
        provider_text = providers.read_text(encoding="utf-8")
    except OSError:
        return False, "digitalocean sketch provider template is unavailable"
    if 'data "digitalocean_ssh_keys" "matching_key"' not in provider_text:
        return False, "digitalocean sketch template lacks matching sketch SSH-key reuse"
    return True, ""


def _looks_like_redteam_infra(path: Path) -> bool:
    return (
        path.is_dir()
        and (path / ".git").exists()
        and (path / "ansible").is_dir()
        and (path / "external").is_dir()
    )
