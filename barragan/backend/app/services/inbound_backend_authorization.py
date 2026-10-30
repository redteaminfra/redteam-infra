# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.services.capability_catalog import DEFAULT_CAPABILITY_MANIFEST_ROOT, SUPPORTED_API_VERSION
from app.services.engagement_capabilities import capability_overrides_for_workspace
from app.storage.engagement_workspace_repository import (
    EngagementWorkspaceRepository,
    SqlAlchemyEngagementWorkspaceRepository,
)


SAFE_CAPABILITY_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
SAFE_HOST_CLASS = re.compile(r"^[a-z][a-z0-9_-]*$")
SAFE_HTTP_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
SAFE_AUTH_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")
SAFE_JSON_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_CONFIG_PATH = re.compile(r"^/etc/[A-Za-z0-9._/-]+$")


class InboundBackendAuthorizationValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("inbound backend authorization validation failed")
        self.errors = errors


@dataclass(frozen=True)
class InboundBackendAuthorization:
    capability_id: str
    host_class: str
    port: int
    max_request_body_bytes: int
    header_name: str
    scheme: str
    config_path: str
    array_field: str
    array_index: int

    @property
    def max_request_body_mb(self) -> int:
        return self.max_request_body_bytes // 1_000_000

    def proxy_header_line(self, inventory_group: str) -> str:
        return (
            f'proxy_set_header {self.header_name} '
            f'"{{{{ hostvars[groups[\'{inventory_group}\'][0]].barragan_inbound_backend_authorization }}}}";'
        )


def render_backend_authorization_fact_play(
    adapter: InboundBackendAuthorization,
    *,
    inventory_group: str,
) -> list[str]:
    """Render a secret-neutral play that loads the private backend value in memory."""

    return [
        f"- name: Load private backend authorization for {adapter.capability_id}",
        f"  hosts: {inventory_group}",
        "  gather_facts: false",
        "  become: true",
        "  vars:",
        f"    barragan_backend_auth_config_path: {json.dumps(adapter.config_path)}",
        f"    barragan_backend_auth_array_field: {json.dumps(adapter.array_field)}",
        f"    barragan_backend_auth_array_index: {adapter.array_index}",
        f"    barragan_backend_auth_scheme: {json.dumps(adapter.scheme)}",
        "  tasks:",
        "    - name: Inspect private backend configuration",
        "      ansible.builtin.stat:",
        "        path: \"{{ barragan_backend_auth_config_path }}\"",
        "      register: barragan_backend_auth_config_stat",
        "    - name: Require a regular private backend configuration",
        "      ansible.builtin.assert:",
        "        that:",
        "          - barragan_backend_auth_config_stat.stat.isreg | default(false)",
        "          - not (barragan_backend_auth_config_stat.stat.islnk | default(false))",
        "        fail_msg: Selected capability private backend configuration is unavailable.",
        "    - name: Read private backend configuration",
        "      ansible.builtin.slurp:",
        "        path: \"{{ barragan_backend_auth_config_path }}\"",
        "      register: barragan_backend_auth_config",
        "      no_log: true",
        "    - name: Resolve private backend authorization",
        "      ansible.builtin.set_fact:",
        "        barragan_inbound_backend_authorization: >-",
        "          {{ barragan_backend_auth_scheme ~ ' ' ~ (((barragan_backend_auth_config.content | b64decode | from_json)[barragan_backend_auth_array_field])[barragan_backend_auth_array_index] | string) }}",
        "      no_log: true",
        "    - name: Require a non-empty private backend authorization",
        "      ansible.builtin.assert:",
        "        that:",
        "          - barragan_inbound_backend_authorization | length > (barragan_backend_auth_scheme | length + 1)",
        "        fail_msg: Selected capability private backend authorization is unavailable.",
        "      no_log: true",
    ]


def resolve_selected_inbound_backend_authorization(
    engagement_id: str,
    *,
    host_class: str,
    port: int,
    workspace_repository: EngagementWorkspaceRepository | None = None,
    manifest_root: Path | None = None,
) -> InboundBackendAuthorization | None:
    try:
        workspace = (workspace_repository or SqlAlchemyEngagementWorkspaceRepository()).get(engagement_id)
    except RuntimeError as exc:
        # Renderers are deliberately usable outside an ASGI/database context
        # (for example, in plan previews and focused artifact tests).  There
        # cannot be a saved optional selection there, so no adapter applies.
        # Do not mask any other repository failure in a live application.
        if str(exc) != "no database context is active":
            raise
        workspace = None
    if workspace is None:
        return None
    selected = {
        (str(row.get("hostClass") or "").strip(), str(row.get("id") or "").strip())
        for row in capability_overrides_for_workspace(workspace).get("selectedOptionals", [])
    }
    if not selected:
        return None
    matches = []
    for adapter in _packaged_adapters(manifest_root=manifest_root):
        if (adapter.host_class, adapter.capability_id) not in selected:
            continue
        if adapter.host_class == host_class and adapter.port == port:
            matches.append(adapter)
    if len(matches) > 1:
        raise InboundBackendAuthorizationValidationError(
            ["more than one selected capability claims this inbound HTTP backend"]
        )
    return matches[0] if matches else None


def _packaged_adapters(*, manifest_root: Path | None) -> tuple[InboundBackendAuthorization, ...]:
    root = (manifest_root or DEFAULT_CAPABILITY_MANIFEST_ROOT).resolve(strict=False) / "capabilities"
    if not root.is_dir() or root.is_symlink():
        return ()
    adapters = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise InboundBackendAuthorizationValidationError(
                [f"packaged capability manifest could not be parsed: {path.name}"]
            ) from exc
        if not isinstance(payload, dict):
            continue
        integration = payload.get("integration")
        backend = integration.get("inboundHttpBackend") if isinstance(integration, dict) else None
        if backend is None:
            continue
        adapters.append(_adapter_from_manifest(payload, backend, path.name))
    return tuple(adapters)


def _adapter_from_manifest(
    payload: dict[str, Any],
    backend: Any,
    filename: str,
) -> InboundBackendAuthorization:
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    authorization = backend.get("authorization") if isinstance(backend, dict) else None
    source = authorization.get("source") if isinstance(authorization, dict) else None
    capability_id = str(metadata.get("id") or "").strip()
    host_class = str(backend.get("hostClass") or "").strip() if isinstance(backend, dict) else ""
    header_name = str(authorization.get("headerName") or "").strip() if isinstance(authorization, dict) else ""
    scheme = str(authorization.get("scheme") or "").strip() if isinstance(authorization, dict) else ""
    config_path = str(source.get("path") or "").strip() if isinstance(source, dict) else ""
    array_field = str(source.get("arrayField") or "").strip() if isinstance(source, dict) else ""
    port = backend.get("port") if isinstance(backend, dict) else None
    max_bytes = backend.get("maxRequestBodyBytes") if isinstance(backend, dict) else None
    index = source.get("index") if isinstance(source, dict) else None
    valid = (
        payload.get("apiVersion") == SUPPORTED_API_VERSION
        and payload.get("classification") == "optional"
        and bool(SAFE_CAPABILITY_ID.fullmatch(capability_id))
        and bool(SAFE_HOST_CLASS.fullmatch(host_class))
        and isinstance(port, int)
        and not isinstance(port, bool)
        and 1 <= port <= 65535
        and isinstance(max_bytes, int)
        and not isinstance(max_bytes, bool)
        and max_bytes >= 1_000_000
        and max_bytes % 1_000_000 == 0
        and bool(SAFE_HTTP_FIELD_NAME.fullmatch(header_name))
        and bool(SAFE_AUTH_SCHEME.fullmatch(scheme))
        and isinstance(source, dict)
        and source.get("type") == "json-file"
        and bool(SAFE_CONFIG_PATH.fullmatch(config_path))
        and ".." not in Path(config_path).parts
        and bool(SAFE_JSON_FIELD.fullmatch(array_field))
        and isinstance(index, int)
        and not isinstance(index, bool)
        and 0 <= index <= 10
    )
    if not valid:
        raise InboundBackendAuthorizationValidationError(
            [f"packaged inbound HTTP backend integration is invalid: {filename}"]
        )
    return InboundBackendAuthorization(
        capability_id=capability_id,
        host_class=host_class,
        port=port,
        max_request_body_bytes=max_bytes,
        header_name=header_name,
        scheme=scheme,
        config_path=config_path,
        array_field=array_field,
        array_index=index,
    )
