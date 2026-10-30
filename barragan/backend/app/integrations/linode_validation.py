# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from app.integrations.managed_host_images import managed_host_image_profile

LINODE_API_BASE = "https://api.linode.com/v4"
VALIDATION_CONFIRMATION = "validate-linode-sketch"


class LinodeValidationError(Exception):
    pass


class LinodeTransport(Protocol):
    def request(self, method: str, path: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        ...


class UrllibLinodeTransport:
    def __init__(self, base_url: str = LINODE_API_BASE, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(self, method: str, path: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        encoded_body = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=encoded_body,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise LinodeValidationError(f"Linode API {method} {path} failed with HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise LinodeValidationError(f"Linode API {method} {path} failed: {exc.reason}") from exc
        if not payload:
            return {}
        return json.loads(payload)


@dataclass(frozen=True)
class LinodeValidationStep:
    name: str
    status: str
    detail: str
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "data": self.data,
        }


@dataclass(frozen=True)
class LinodeValidationResult:
    ok: bool
    mutation: bool
    credential_alias: str
    label: str
    linode_id: int | None
    public_ip: str | None
    cleanup_verified: bool
    steps: list[LinodeValidationStep]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mutation": self.mutation,
            "credentialAlias": self.credential_alias,
            "label": self.label,
            "linodeId": self.linode_id,
            "publicIp": self.public_ip,
            "cleanupVerified": self.cleanup_verified,
            "steps": [step.to_dict() for step in self.steps],
        }


def validate_linode_sketch_create_destroy(
    token: str,
    credential_alias: str,
    label: str,
    region: str = "us-sea",
    image: str | None = None,
    linode_type: str = "g6-nanode-1",
    root_pass: str = "BarraganValidation-rotate-me-000000!",
    transport: LinodeTransport | None = None,
    poll_attempts: int = 18,
    poll_delay_seconds: float = 5.0,
) -> LinodeValidationResult:
    client = transport or UrllibLinodeTransport()
    steps: list[LinodeValidationStep] = []
    linode_id: int | None = None
    public_ip: str | None = None
    cleanup_verified = False

    def step(name: str, status: str, detail: str, data: dict[str, Any] | None = None) -> None:
        steps.append(LinodeValidationStep(name, status, detail, _safe(data or {})))

    try:
        profile = client.request("GET", "/profile", token)
        step("credential_check", "done", "Linode token authenticated.", {"username": profile.get("username")})

        regions = client.request("GET", "/regions", token)
        step("region_read", "done", "Linode region catalog read preflight passed.", {"count": len(regions.get("data", []))})
        types = client.request("GET", "/linode/types", token)
        step("type_read", "done", "Linode type catalog read preflight passed.", {"count": len(types.get("data", []))})

        create_body = {
            "label": label,
            "region": region,
            "type": linode_type,
        "image": image or managed_host_image_profile().linode_image,
            "root_pass": root_pass,
            "tags": ["barragan", "validation"],
        }
        created = client.request("POST", "/linode/instances", token, create_body)
        linode_id = int(created["id"])
        public_ip = _first_public_ip(created)
        step("create_instance", "done", "Disposable Linode instance created.", _instance_summary(created))

        for _attempt in range(poll_attempts):
            inspected = client.request("GET", f"/linode/instances/{linode_id}", token)
            public_ip = public_ip or _first_public_ip(inspected)
            status = str(inspected.get("status", "unknown"))
            if status in {"running", "offline"}:
                step("inspect_instance", "done", "Disposable Linode instance inspected.", _instance_summary(inspected))
                break
            time.sleep(poll_delay_seconds)
        else:
            inspected = client.request("GET", f"/linode/instances/{linode_id}", token)
            step("inspect_instance", "done", "Disposable Linode instance inspected after polling.", _instance_summary(inspected))

    except Exception as exc:
        step("validation_failed", "failed", str(exc))
        if linode_id is not None:
            cleanup_verified = _destroy_and_verify(client, token, linode_id, steps, poll_attempts, poll_delay_seconds)
        return LinodeValidationResult(False, True, credential_alias, label, linode_id, public_ip, cleanup_verified, steps)

    cleanup_verified = _destroy_and_verify(client, token, linode_id, steps, poll_attempts, poll_delay_seconds)
    return LinodeValidationResult(cleanup_verified, True, credential_alias, label, linode_id, public_ip, cleanup_verified, steps)


def _destroy_and_verify(
    client: LinodeTransport,
    token: str,
    linode_id: int,
    steps: list[LinodeValidationStep],
    poll_attempts: int,
    poll_delay_seconds: float,
) -> bool:
    try:
        client.request("DELETE", f"/linode/instances/{linode_id}", token)
        steps.append(LinodeValidationStep("destroy_instance", "done", "Disposable Linode instance destroy requested.", {"linodeId": linode_id}))
        for _attempt in range(poll_attempts):
            try:
                client.request("GET", f"/linode/instances/{linode_id}", token)
            except LinodeValidationError as exc:
                if "HTTP 404" in str(exc):
                    steps.append(LinodeValidationStep("verify_cleanup", "done", "Linode cleanup verified.", {"linodeId": linode_id}))
                    return True
                raise
            time.sleep(poll_delay_seconds)
        steps.append(LinodeValidationStep("verify_cleanup", "failed", "Linode instance still visible after destroy polling.", {"linodeId": linode_id}))
    except Exception as exc:
        steps.append(LinodeValidationStep("verify_cleanup", "failed", str(exc), {"linodeId": linode_id}))
    return False


def _first_public_ip(instance: dict[str, Any]) -> str | None:
    ipv4 = instance.get("ipv4")
    if isinstance(ipv4, list) and ipv4:
        return str(ipv4[0])
    return None


def _instance_summary(instance: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": instance.get("id"),
        "label": instance.get("label"),
        "region": instance.get("region"),
        "type": instance.get("type"),
        "status": instance.get("status"),
        "publicIp": _first_public_ip(instance),
    }


def _safe(data: dict[str, Any]) -> dict[str, Any]:
    unsafe_keys = {"token", "root_pass", "password", "secret", "linode_api_token"}
    return {key: ("<redacted>" if key in unsafe_keys else value) for key, value in data.items()}
