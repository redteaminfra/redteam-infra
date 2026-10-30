# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from app.services.engagement_operations import get_operations_overview
from app.services.inbound_channel_artifacts import http_backend_service_name
from app.services.inbound_channel_apply import PROXY_RUNTIME_REGISTRY_PATH
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


INBOUND_JOB_ACTIONS = {
    "inbound_channel_apply",
    "inbound_channel_validation",
    "inbound_channel_remove",
    "inbound_channel_certificate_issue",
    "inbound_channel_certificate_renew",
    "inbound_channel_certificate_revoke",
    "inbound_channel_certificate_challenge_channel",
}
MANAGED_ARTIFACT_PREFIXES = (
    "/etc/nginx/streams/",
    "/opt/web/http/",
    "/opt/web/inbound/",
    "/opt/web/sites/",
    "/opt/web/streams/",
    "/opt/web/tls/",
)


class InboundManagedRuntimeNotFoundError(LookupError):
    pass


def get_inbound_managed_runtime(
    engagement_id: str,
    channel_id: str,
    *,
    job_repository: JobRepository | None = None,
) -> dict[str, Any] | None:
    """Return a small, read-only projection of Barragan-owned route state.

    The projection is deliberately assembled from already-sanitized durable
    Operations state. It never reads execution workspaces or generated config
    bodies, which keeps controller paths, commands, keys, and gate material out
    of this operator-facing endpoint.
    """

    repository = job_repository or SqlAlchemyJobRepository()
    overview = get_operations_overview(
        engagement_id,
        job_repository=repository,
        include_provider_findings=False,
    )
    if overview is None:
        return None
    channel = next(
        (
            dict(row)
            for row in overview.get("inboundChannels", [])
            if isinstance(row, dict) and str(row.get("channelId") or "") == channel_id
        ),
        None,
    )
    if channel is None:
        raise InboundManagedRuntimeNotFoundError(channel_id)

    mode = _text(channel.get("mode")) or "tcp-forward"
    shared_web = mode in {"http-openresty", "https-openresty"}
    # This endpoint is lazy and channel-scoped, so prefer correctness over the
    # Dashboard's bounded timeline: an old but still-active route must retain
    # its actual latest job rather than appear to have no history.
    latest_job = _latest_channel_job(repository.list_for_engagement(engagement_id), channel_id)
    artifacts = _managed_artifacts(channel)
    response: dict[str, Any] = {
        "routeId": channel_id,
        "channelId": channel_id,
        "mode": mode,
        "routingOwner": {
            "kind": "shared-web-ingress" if shared_web else "dedicated-stream",
            "label": "Shared web ingress" if shared_web else "Dedicated stream forward",
            "managedBy": "Barragan",
        },
        "selectedPath": {
            "chainId": _text(channel.get("chainId")) or None,
            "edge": _text(channel.get("edge")) or None,
            "middle": _text(channel.get("middle")) or None,
            "proxy": _text(channel.get("proxy")) or None,
        },
        "externalListener": {
            "host": _text(channel.get("edge")) or None,
            "port": _text(channel.get("externalPort")) or None,
            "protocol": _text(channel.get("protocol")).upper() or "TCP",
        },
        "termination": {
            "host": _text(channel.get("terminatesOn")) or None,
            "port": _text(channel.get("internalPort")) or None,
            "service": _text(channel.get("service")) or None,
        },
        "site": _site_projection(channel, shared_web),
        "certificate": _certificate_projection(channel.get("certificate")),
        "managedArtifacts": artifacts,
        "artifactStatus": (
            "recorded"
            if artifacts
            else "Legacy route metadata does not include managed artifact paths. Reapply is not required to view the route."
        ),
        "validation": _validation_projection(channel.get("validation"), channel.get("status")),
        "latestJob": _job_projection(latest_job),
        "readOnly": True,
    }
    if shared_web:
        response["failClosedDefault"] = {
            "target": "127.0.0.1:9",
            "detail": (
                "The shared proxy front intentionally sends unmatched Host or SNI traffic to an unreachable "
                "loopback target so it fails closed instead of reaching another managed site."
            ),
        }
    return response


def _managed_artifacts(channel: dict[str, Any]) -> list[dict[str, str]]:
    targets = channel.get("artifactTargets")
    rows: list[dict[str, str]] = []
    artifact_scopes = {
        "edgeStream": "edge",
        "middleStream": "middle",
        "proxyStream": "proxy",
    }
    if isinstance(targets, dict):
        for key, value in targets.items():
            scope = artifact_scopes.get(str(key))
            if scope is None:
                continue
            path = _safe_managed_path(value)
            if not path:
                continue
            rows.append({"scope": scope, "path": path})
    proxy = _text(channel.get("proxy"))
    if rows and proxy:
        rows.append({"scope": "proxy", "path": PROXY_RUNTIME_REGISTRY_PATH})
    return rows


def _safe_managed_path(value: Any) -> str:
    path = _text(value)
    if not path.startswith(MANAGED_ARTIFACT_PREFIXES):
        return ""
    normalized = str(PurePosixPath(path))
    if normalized != path or ".." in PurePosixPath(path).parts:
        return ""
    return path


def _site_projection(channel: dict[str, Any], shared_web: bool) -> dict[str, Any] | None:
    if not shared_web:
        return None
    channel_id = _text(channel.get("channelId"))
    service_type = _text(channel.get("serviceType"))
    service_id = _text(channel.get("serviceId"))
    if service_type == "web-static" and service_id.startswith("web-"):
        site_name = service_id.removeprefix("web-")
        service_name = f"web_{site_name.replace('-', '_')}"
        backend = {"kind": "static-content", "port": "8081"}
    else:
        service_name = http_backend_service_name(channel_id)
        backend = {
            "kind": "private-http-service",
            "host": "homebase" if service_type == "web-http-backend" else _text(channel.get("terminatesOn")) or None,
            "port": _text(channel.get("backendPort")) or _text(channel.get("internalPort")) or None,
        }
    return {
        "domain": _text(channel.get("domain")) or None,
        "serviceName": service_name,
        "containerPort": "8081",
        "backend": backend,
    }


def _certificate_projection(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    allowed = ("type", "managedBy", "status", "domain", "activationStatus", "expiresAt", "lastJobId")
    projected = {key: value[key] for key in allowed if isinstance(value.get(key), (str, bool, int))}
    return projected or None


def _validation_projection(value: Any, fallback_status: Any) -> dict[str, Any]:
    projected: dict[str, Any] = {"status": _text(fallback_status) or "Not recorded"}
    if not isinstance(value, dict):
        return projected
    for key in ("status", "profileType", "profileLabel", "checkedAt", "lastCheckedAt", "externalIngressVerified"):
        candidate = value.get(key)
        if isinstance(candidate, (str, bool, int)):
            projected[key] = candidate
    return projected


def _latest_channel_job(jobs: list[StoredJobRun], channel_id: str) -> StoredJobRun | None:
    return next(
        (
            job
            for job in jobs
            if job.action in INBOUND_JOB_ACTIONS and _text(job.input.get("channelId")) == channel_id
        ),
        None,
    )


def _job_projection(job: StoredJobRun | None) -> dict[str, Any] | None:
    if job is None:
        return None
    return {
        "id": job.id,
        "action": job.action,
        "status": job.status,
        "startedAt": job.started_at,
        "finishedAt": job.finished_at,
    }


def _text(value: Any) -> str:
    return str(value or "").strip()
