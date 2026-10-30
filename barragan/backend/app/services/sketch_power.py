# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from app.domain import JobEvent, JobRunDetail
from app.services.credentials import resolve_credential_secret, resolve_default_credential_alias
from app.storage.credential_repository import CredentialRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


SKETCH_CHAIN_STOP_ACTION = "sketch_chain_stop"
SKETCH_CHAIN_START_ACTION = "sketch_chain_start"
SUPPORTED_POWER_PROVIDERS = {"linode", "digitalocean"}
SECRET_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "LINODE_TOKEN",
    "DIGITALOCEAN_TOKEN",
    "provider_token",
    "private_key_material",
)

CredentialResolver = Callable[[str, str], str]


class SketchPowerValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("sketch power validation failed")
        self.errors = errors


@dataclass(frozen=True)
class ProviderPowerResult:
    provider: str
    provider_instance_id: str
    action: str
    ok: bool
    status_code: int
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        body: dict[str, object] = {
            "provider": self.provider,
            "providerInstanceId": self.provider_instance_id,
            "action": self.action,
            "ok": self.ok,
            "statusCode": self.status_code,
        }
        if self.detail:
            body["detail"] = self.detail
        return body


class ProviderPowerRunner:
    def run(self, *, provider: str, provider_instance_id: str, action: str, token: str) -> ProviderPowerResult:
        if provider == "linode":
            return _run_linode_power(provider_instance_id, action, token)
        if provider == "digitalocean":
            return _run_digitalocean_power(provider_instance_id, action, token)
        raise SketchPowerValidationError([f"provider {provider} does not support power operations"])


def run_sketch_power_job(
    chain: StoredSketchChain,
    *,
    action: str,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    credential_repository: CredentialRepository | None = None,
    credential_resolver: CredentialResolver | None = None,
    runner: ProviderPowerRunner | None = None,
) -> JobRunDetail:
    if action not in {"stop", "start"}:
        raise SketchPowerValidationError(["action must be stop or start"])
    provider = _chain_provider(chain)
    if provider not in SUPPORTED_POWER_PROVIDERS:
        raise SketchPowerValidationError([f"provider {provider or 'unknown'} does not support power operations"])
    nodes = _power_nodes(chain)
    if not nodes:
        raise SketchPowerValidationError(["chain has no providerInstanceId values; redeploy or refresh the chain before stop/start"])
    credential_alias = _credential_alias(chain, repository or SqlAlchemyJobRepository(), provider)
    resolver = credential_resolver or (
        lambda credential_provider, alias: resolve_credential_secret(credential_provider, alias, credential_repository)
    )
    token = resolver(provider, credential_alias)
    if not token:
        raise SketchPowerValidationError([f"{provider} credential {credential_alias} resolved to an empty token"])
    power_runner = runner or ProviderPowerRunner()
    repo = repository or SqlAlchemyJobRepository()
    job = _new_power_job(chain, action, requested_by, credential_alias, nodes)
    job = repo.save(replace(job, status="running", started_at=_now(), events=job.events + [_started_event(chain, action, nodes)]))
    results: list[ProviderPowerResult] = []
    for node in nodes:
        results.append(
            power_runner.run(
                provider=provider,
                provider_instance_id=str(node["providerInstanceId"]),
                action=action,
                token=token,
            )
        )
    result_rows = [_result_with_node(result, nodes) for result in results]
    _assert_no_secret_material(result_rows)
    ok = all(result.ok for result in results)
    final_event = JobEvent(
        len(job.events) + 1,
        "info" if ok else "error",
        f"sketch chain {action} {'completed' if ok else 'failed'}",
        {
            "provider": provider,
            "chainId": chain.chain_id,
            "powerOperations": result_rows,
            "status": _success_status(action) if ok else "failed",
            "mutation": True,
            "opsecBoundary": {
                "providerApiOnly": True,
                "directSketchAccessFromAppHost": False,
                "middleAccess": "no SSH; provider API power operation",
                "edgeAccess": "no SSH; provider API power operation",
            },
        },
    )
    finished = replace(
        job,
        status="succeeded" if ok else "failed",
        finished_at=_now(),
        events=job.events + [final_event],
    )
    return repo.save(finished).to_detail()


def _new_power_job(
    chain: StoredSketchChain,
    action: str,
    requested_by: str,
    credential_alias: str,
    nodes: list[dict[str, Any]],
) -> StoredJobRun:
    provider = _chain_provider(chain)
    return StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=SKETCH_CHAIN_STOP_ACTION if action == "stop" else SKETCH_CHAIN_START_ACTION,
        status="queued",
        target=f"engagement:{chain.engagement_id}",
        target_type="engagement",
        target_id=chain.engagement_id,
        requested_by=requested_by,
        input={
            "engagementId": chain.engagement_id,
            "chainId": chain.chain_id,
            "provider": provider,
            "credentialAlias": credential_alias,
            "credentialRef": f"credential://{provider}/{credential_alias}",
            "mutation": True,
        },
        artifact_refs=[],
        created_at=_now(),
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                f"sketch chain {action} queued",
                {
                    "provider": provider,
                    "chainId": chain.chain_id,
                    "nodeCount": len(nodes),
                    "mutation": True,
                },
            )
        ],
    )


def _started_event(chain: StoredSketchChain, action: str, nodes: list[dict[str, Any]]) -> JobEvent:
    return JobEvent(
        2,
        "info",
        f"sketch chain {action} started",
        {
            "provider": _chain_provider(chain),
            "chainId": chain.chain_id,
            "nodes": [_safe_node(node) for node in nodes],
            "mutation": True,
        },
    )


def _chain_provider(chain: StoredSketchChain) -> str:
    if chain.middle_provider and chain.middle_provider == chain.edge_provider:
        return chain.middle_provider
    providers = {str(node.get("provider") or "").strip() for node in chain.nodes if isinstance(node, dict)}
    providers.discard("")
    return providers.pop() if len(providers) == 1 else ""


def _power_nodes(chain: StoredSketchChain) -> list[dict[str, Any]]:
    nodes = []
    for node in chain.nodes:
        if not isinstance(node, dict):
            continue
        provider_id = str(node.get("providerInstanceId") or node.get("providerId") or "").strip()
        if not provider_id:
            continue
        nodes.append({**node, "providerInstanceId": provider_id})
    return nodes


def _credential_alias(chain: StoredSketchChain, repository: JobRepository, provider: str) -> str:
    if chain.deploy_job_id:
        job = repository.get(chain.deploy_job_id)
        if job is not None:
            alias = str(job.input.get("middleCredentialAlias") or job.input.get("credentialAlias") or "").strip()
            if alias:
                return alias
    alias = resolve_default_credential_alias(provider)
    if not alias:
        raise SketchPowerValidationError([f"{provider} power operation requires an active default credential"])
    return alias


def _result_with_node(result: ProviderPowerResult, nodes: list[dict[str, Any]]) -> dict[str, object]:
    node = next((entry for entry in nodes if str(entry.get("providerInstanceId") or "") == result.provider_instance_id), {})
    return {
        **result.to_dict(),
        "hostname": str(node.get("hostname") or ""),
        "role": str(node.get("role") or ""),
    }


def _safe_node(node: dict[str, Any]) -> dict[str, str]:
    return {
        "hostname": str(node.get("hostname") or ""),
        "role": str(node.get("role") or ""),
        "provider": str(node.get("provider") or ""),
        "providerInstanceId": str(node.get("providerInstanceId") or ""),
    }


def _success_status(action: str) -> str:
    return "stopped" if action == "stop" else "deployed"


def _run_linode_power(provider_instance_id: str, action: str, token: str) -> ProviderPowerResult:
    linode_action = "shutdown" if action == "stop" else "boot"
    url = f"https://api.linode.com/v4/linode/instances/{provider_instance_id}/{linode_action}"
    return _http_post(provider="linode", provider_instance_id=provider_instance_id, action=action, token=token, url=url, body=None)


def _run_digitalocean_power(provider_instance_id: str, action: str, token: str) -> ProviderPowerResult:
    do_action = "shutdown" if action == "stop" else "power_on"
    url = f"https://api.digitalocean.com/v2/droplets/{provider_instance_id}/actions"
    return _http_post(provider="digitalocean", provider_instance_id=provider_instance_id, action=action, token=token, url=url, body={"type": do_action})


def _http_post(
    *,
    provider: str,
    provider_instance_id: str,
    action: str,
    token: str,
    url: str,
    body: dict[str, str] | None,
) -> ProviderPowerResult:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return ProviderPowerResult(provider, provider_instance_id, action, 200 <= response.status < 300, response.status)
    except urllib.error.HTTPError as exc:
        return ProviderPowerResult(provider, provider_instance_id, action, False, exc.code, exc.reason)
    except OSError as exc:
        return ProviderPowerResult(provider, provider_instance_id, action, False, 0, type(exc).__name__)


def _assert_no_secret_material(value: Any) -> None:
    rendered = json.dumps(value, sort_keys=True)
    matches = [marker for marker in SECRET_MARKERS if marker in rendered]
    if matches:
        raise SketchPowerValidationError([f"sketch power data contains forbidden secret marker: {matches[0]}"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
