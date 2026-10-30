# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from app.integrations.managed_host_images import managed_host_image_profile

DIGITALOCEAN_API_BASE = "https://api.digitalocean.com/v2"
VALIDATION_CONFIRMATION = "validate-digitalocean-sketch"
DEFAULT_REGION = "sfo3"
DEFAULT_SIZE = "s-1vcpu-1gb"
DEFAULT_IMAGE = managed_host_image_profile().digitalocean_image


class DigitalOceanValidationError(Exception):
    pass


class DigitalOceanTransport(Protocol):
    def request(self, method: str, path: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        ...


class UrllibDigitalOceanTransport:
    def __init__(self, base_url: str = DIGITALOCEAN_API_BASE, timeout: int = 30):
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
            raise DigitalOceanValidationError(f"DigitalOcean API {method} {path} failed with HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise DigitalOceanValidationError(f"DigitalOcean API {method} {path} failed: {exc.reason}") from exc
        if not payload:
            return {}
        return json.loads(payload)


@dataclass(frozen=True)
class DigitalOceanValidationStep:
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
class DigitalOceanValidationResult:
    ok: bool
    mutation: bool
    credential_alias: str
    name: str
    droplet_id: int | None
    public_ip: str | None
    cleanup_verified: bool
    steps: list[DigitalOceanValidationStep]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mutation": self.mutation,
            "credentialAlias": self.credential_alias,
            "name": self.name,
            "dropletId": self.droplet_id,
            "publicIp": self.public_ip,
            "cleanupVerified": self.cleanup_verified,
            "steps": [step.to_dict() for step in self.steps],
        }


def validate_digitalocean_sketch_create_destroy(
    token: str,
    credential_alias: str,
    name: str,
    region: str = DEFAULT_REGION,
    image: str = DEFAULT_IMAGE,
    size: str = DEFAULT_SIZE,
    user_data: str = "#cloud-config\nruncmd:\n  - echo barragan-digitalocean-validation\n",
    transport: DigitalOceanTransport | None = None,
    poll_attempts: int = 18,
    poll_delay_seconds: float = 5.0,
) -> DigitalOceanValidationResult:
    client = transport or UrllibDigitalOceanTransport()
    steps: list[DigitalOceanValidationStep] = []
    droplet_id: int | None = None
    public_ip: str | None = None
    cleanup_verified = False

    def step(name: str, status: str, detail: str, data: dict[str, Any] | None = None) -> None:
        steps.append(DigitalOceanValidationStep(name, status, detail, _safe(data or {})))

    try:
        try:
            account = client.request("GET", "/account", token)
            step("credential_check", "done", "DigitalOcean account-read diagnostic passed.", {"emailVerified": account.get("account", {}).get("email_verified")})
        except DigitalOceanValidationError as exc:
            step("credential_check", "skipped", "DigitalOcean account-read diagnostic skipped; token may be least-privilege.", {"error": str(exc)})

        regions = client.request("GET", "/regions", token)
        step("region_read", "done", "DigitalOcean region catalog read preflight passed.", {"count": len(regions.get("regions", []))})
        sizes = client.request("GET", "/sizes", token)
        step("size_read", "done", "DigitalOcean size catalog read preflight passed.", {"count": len(sizes.get("sizes", []))})

        create_body = {
            "name": name,
            "region": region,
            "size": size,
            "image": image,
            "user_data": user_data,
        }
        created = client.request("POST", "/droplets", token, create_body)
        droplet = _droplet(created)
        droplet_id = int(droplet["id"])
        public_ip = _first_public_ip(droplet)
        step("create_droplet", "done", "Disposable DigitalOcean droplet created.", _droplet_summary(droplet))

        for _attempt in range(poll_attempts):
            inspected = _droplet(client.request("GET", f"/droplets/{droplet_id}", token))
            public_ip = public_ip or _first_public_ip(inspected)
            status = str(inspected.get("status", "unknown"))
            if status in {"active", "off"}:
                step("inspect_droplet", "done", "Disposable DigitalOcean droplet inspected.", _droplet_summary(inspected))
                break
            time.sleep(poll_delay_seconds)
        else:
            inspected = _droplet(client.request("GET", f"/droplets/{droplet_id}", token))
            step("inspect_droplet", "done", "Disposable DigitalOcean droplet inspected after polling.", _droplet_summary(inspected))

    except Exception as exc:
        step("validation_failed", "failed", str(exc))
        if droplet_id is not None:
            cleanup_verified = _destroy_and_verify(client, token, droplet_id, steps, poll_attempts, poll_delay_seconds)
        return DigitalOceanValidationResult(False, True, credential_alias, name, droplet_id, public_ip, cleanup_verified, steps)

    cleanup_verified = _destroy_and_verify(client, token, droplet_id, steps, poll_attempts, poll_delay_seconds)
    return DigitalOceanValidationResult(cleanup_verified, True, credential_alias, name, droplet_id, public_ip, cleanup_verified, steps)


def _destroy_and_verify(
    client: DigitalOceanTransport,
    token: str,
    droplet_id: int,
    steps: list[DigitalOceanValidationStep],
    poll_attempts: int,
    poll_delay_seconds: float,
) -> bool:
    try:
        client.request("DELETE", f"/droplets/{droplet_id}", token)
        steps.append(DigitalOceanValidationStep("destroy_droplet", "done", "Disposable DigitalOcean droplet destroy requested.", {"dropletId": droplet_id}))
        for _attempt in range(poll_attempts):
            try:
                client.request("GET", f"/droplets/{droplet_id}", token)
            except DigitalOceanValidationError as exc:
                if "HTTP 404" in str(exc):
                    steps.append(DigitalOceanValidationStep("verify_cleanup", "done", "DigitalOcean cleanup verified.", {"dropletId": droplet_id}))
                    return True
                raise
            time.sleep(poll_delay_seconds)
        steps.append(DigitalOceanValidationStep("verify_cleanup", "failed", "DigitalOcean droplet still visible after destroy polling.", {"dropletId": droplet_id}))
    except Exception as exc:
        steps.append(DigitalOceanValidationStep("verify_cleanup", "failed", str(exc), {"dropletId": droplet_id}))
    return False


def _droplet(response: dict[str, Any]) -> dict[str, Any]:
    droplet = response.get("droplet", response)
    if not isinstance(droplet, dict):
        raise DigitalOceanValidationError("DigitalOcean response did not contain a droplet object")
    return droplet


def _first_public_ip(droplet: dict[str, Any]) -> str | None:
    networks = droplet.get("networks")
    if isinstance(networks, dict):
        for network in networks.get("v4", []):
            if isinstance(network, dict) and network.get("type") == "public" and network.get("ip_address"):
                return str(network["ip_address"])
    return None


def _droplet_summary(droplet: dict[str, Any]) -> dict[str, Any]:
    region = droplet.get("region")
    size = droplet.get("size")
    return {
        "id": droplet.get("id"),
        "name": droplet.get("name"),
        "region": region.get("slug") if isinstance(region, dict) else region,
        "size": size.get("slug") if isinstance(size, dict) else size,
        "status": droplet.get("status"),
        "publicIp": _first_public_ip(droplet),
    }


def _safe(data: dict[str, Any]) -> dict[str, Any]:
    unsafe_keys = {"token", "user_data", "password", "secret", "do_pat", "digitalocean_token"}
    return {key: ("<redacted>" if key in unsafe_keys else value) for key, value in data.items()}
