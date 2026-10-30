# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from app.integrations.oci_read_validation import OciDevelopmentTarget, resolve_oci_cli
from app.services.credentials import resolve_credential_secret, resolve_default_credential_alias


TARGET_VERSION = "24.04"
LINODE_IMAGE_ID = "linode/ubuntu24.04"
DIGITALOCEAN_IMAGE_SLUG = "ubuntu-24-04-x64"


class UbuntuImageInventoryError(Exception):
    pass


class ImageTransport(Protocol):
    def get(self, url: str, token: str) -> dict[str, Any]:
        ...


class UrllibImageTransport:
    def get(self, url: str, token: str) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            method="GET",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise UbuntuImageInventoryError(f"image inventory request failed with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise UbuntuImageInventoryError(f"image inventory request failed: {exc.reason}") from exc
        try:
            return json.loads(payload) if payload else {}
        except json.JSONDecodeError as exc:
            raise UbuntuImageInventoryError("image inventory response was not JSON") from exc


CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
CredentialResolver = Callable[[str, str], str]
AliasResolver = Callable[[str], str | None]


@dataclass(frozen=True)
class UbuntuImageInventory:
    target: dict[str, Any]
    providers: dict[str, dict[str, Any]]

    @property
    def ok(self) -> bool:
        return all(provider["ok"] for provider in self.providers.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mode": "read_only",
            "mutation": False,
            "targetUbuntuVersion": TARGET_VERSION,
            "target": self.target,
            "providers": self.providers,
        }


def collect_ubuntu_image_inventory(
    *,
    target: OciDevelopmentTarget | None = None,
    runner: CommandRunner | None = None,
    transport: ImageTransport | None = None,
    credential_resolver: CredentialResolver = resolve_credential_secret,
    alias_resolver: AliasResolver = resolve_default_credential_alias,
    env: Mapping[str, str] | None = None,
) -> UbuntuImageInventory:
    """Read candidate Ubuntu 24.04 metadata without creating cloud resources."""
    resolved_target = target or OciDevelopmentTarget()
    resolved_target.validate()
    image_transport = transport or UrllibImageTransport()
    return UbuntuImageInventory(
        target=resolved_target.to_dict(),
        providers={
            "oci": _collect_oci(resolved_target, runner=runner, env=env),
            "linode": _collect_sketch(
                "linode", image_transport, credential_resolver, alias_resolver
            ),
            "digitalocean": _collect_sketch(
                "digitalocean", image_transport, credential_resolver, alias_resolver
            ),
        },
    )


def _collect_oci(
    target: OciDevelopmentTarget,
    *,
    runner: CommandRunner | None,
    env: Mapping[str, str] | None,
) -> dict[str, Any]:
    resolution = resolve_oci_cli(env=env)
    command = build_oci_image_list_command(target, resolution.command or "oci")
    if not resolution.ok:
        return _failure(resolution.error or "OCI CLI could not be resolved", command=command)
    try:
        completed = (runner or _run_command)(command)
        if completed.returncode:
            return _failure((completed.stderr or completed.stdout).strip() or "OCI image list failed", command=command)
        payload = json.loads(completed.stdout or "{}")
        data = payload.get("data", [])
        if not isinstance(data, list):
            return _failure("OCI image list response did not contain an image list", command=command)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return _failure(str(exc), command=command)

    candidates = sorted(
        (_oci_image(item) for item in data if _is_standard_oci_ubuntu(item)),
        key=lambda item: item.get("timeCreated") or "",
        reverse=True,
    )
    return {
        "ok": bool(candidates),
        "candidate": candidates[0] if candidates else None,
        "candidates": candidates,
        "command": command,
        "error": None if candidates else "No standard x86 Ubuntu 24.04 OCI image was returned",
    }


def build_oci_image_list_command(target: OciDevelopmentTarget, executable: str = "oci") -> list[str]:
    target.validate()
    return [
        executable,
        "--auth", target.auth,
        "--region", target.region,
        "compute", "image", "list",
        "--compartment-id", target.compartment_id,
        "--operating-system", "Canonical Ubuntu",
        "--operating-system-version", TARGET_VERSION,
        "--lifecycle-state", "AVAILABLE",
        "--all", "--output", "json",
    ]


def _collect_sketch(
    provider: str,
    transport: ImageTransport,
    credential_resolver: CredentialResolver,
    alias_resolver: AliasResolver,
) -> dict[str, Any]:
    alias = alias_resolver(provider)
    if not alias:
        return _failure(f"No active default {provider} credential is configured")
    try:
        token = credential_resolver(provider, alias)
        images = _fetch_linode_images(transport, token) if provider == "linode" else _fetch_digitalocean_images(transport, token)
    except Exception as exc:
        return _failure(_safe_error(exc))
    candidate_id = LINODE_IMAGE_ID if provider == "linode" else DIGITALOCEAN_IMAGE_SLUG
    candidate = next((image for image in images if image["id"] == candidate_id), None)
    return {
        "ok": candidate is not None,
        "candidate": candidate,
        "candidates": [image for image in images if image["id"] == candidate_id],
        "error": None if candidate else f"{provider} did not return {candidate_id}",
    }


def _fetch_linode_images(transport: ImageTransport, token: str) -> list[dict[str, Any]]:
    images: list[dict[str, Any]] = []
    page = 1
    while page <= 20:
        payload = transport.get(f"https://api.linode.com/v4/images?page={page}&page_size=500", token)
        images.extend(payload.get("data", []))
        pages = int(payload.get("pages") or page)
        if page >= pages:
            break
        page += 1
    return [_linode_image(item) for item in images if str(item.get("id", "")) == LINODE_IMAGE_ID]


def _fetch_digitalocean_images(transport: ImageTransport, token: str) -> list[dict[str, Any]]:
    images: list[dict[str, Any]] = []
    url: str | None = "https://api.digitalocean.com/v2/images?type=distribution&page=1&per_page=200"
    pages = 0
    while url and pages < 20:
        payload = transport.get(url, token)
        images.extend(payload.get("images", []))
        next_url = payload.get("links", {}).get("pages", {}).get("next")
        url = next_url if isinstance(next_url, str) and next_url.startswith("https://api.digitalocean.com/v2/images?") else None
        pages += 1
    return [_digitalocean_image(item) for item in images if str(item.get("slug", "")) == DIGITALOCEAN_IMAGE_SLUG]


def _is_standard_oci_ubuntu(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    name = str(item.get("display-name") or "")
    return name.startswith("Canonical-Ubuntu-24.04-") and "Minimal" not in name and "aarch64" not in name


def _oci_image(item: dict[str, Any]) -> dict[str, Any]:
    return _safe_fields(item, {"id": "id", "displayName": "display-name", "timeCreated": "time-created", "lifecycleState": "lifecycle-state", "operatingSystem": "operating-system", "operatingSystemVersion": "operating-system-version"})


def _linode_image(item: dict[str, Any]) -> dict[str, Any]:
    return _safe_fields(item, {"id": "id", "label": "label", "vendor": "vendor", "type": "type", "created": "created", "deprecated": "deprecated", "eol": "eol", "regions": "regions"})


def _digitalocean_image(item: dict[str, Any]) -> dict[str, Any]:
    return _safe_fields(item, {"id": "slug", "name": "name", "distribution": "distribution", "type": "type", "created": "created", "status": "status", "regions": "regions", "minDiskSizeGb": "min_disk_size"})


def _safe_fields(item: dict[str, Any], fields: dict[str, str]) -> dict[str, Any]:
    return {key: item.get(source) for key, source in fields.items()}


def _failure(error: str, *, command: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "candidate": None, "candidates": [], "error": error}
    if command is not None:
        result["command"] = command
    return result


def _safe_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
