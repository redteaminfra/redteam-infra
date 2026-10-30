# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import base64
import binascii
import json
import hashlib
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
import threading
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import start_runtime_task
from app.core.request_identity import current_request_identity
from app.services import static_web_content
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.integrations.oci_disposable_terraform import DisposableCommandResult
from app.services.core_ssh import deployment_known_hosts_file, ensure_known_hosts_file, latest_core_connection_details
from app.services.engagements import get_engagement
from app.services.infra_orientation import try_enqueue_infra_orientation_refresh
from app.services.shared_proxy_stack import SharedProxyStackMutationConflict, reserve_shared_proxy_stack_mutation
from app.services.web_delivery_capabilities import (
    NATIVE_STATIC_WEB_CAPABILITY_ID,
    WebDeliveryCapabilityConflictError,
    assert_web_delivery_capability_available,
)
from app.storage.job_repository import (
    JobRepository, MixedAppendBindingFenceError, SqlAlchemyJobRepository, StoredJobRun,
)
from app.storage.certificate_repository import CertificateRepository, SqlAlchemyCertificateRepository
from app.storage.service_repository import (
    EngagementServiceRepository,
    SqlAlchemyEngagementServiceRepository,
    StoredEngagementService,
    service_with_status,
)


WEB_STATIC_APPLY_PREVIEW_ACTION = "web_static_service_apply_preview"
WEB_STATIC_APPLY_ACTION = "web_static_service_apply"
WEB_STATIC_REMOVE_PREVIEW_ACTION = "web_static_service_remove_preview"
WEB_STATIC_REMOVE_ACTION = "web_static_service_remove"
WEB_STATIC_SERVICE_TYPE = "web-static"
WEB_STATIC_SERVICE_NAME = "Static Web"
# Static Web sites are Docker-network services. The shared front OpenResty
# container owns host ports 80/443; each site listens only on its internal
# port 8081.
DEFAULT_INTERNAL_PORT = 8081
DEFAULT_INDEX_HTML = "<html><body><h1>It works!</h1></body></html>\n"
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-web-static-service-apply")
DEFAULT_KNOWN_HOSTS_ROOT = Path("/tmp/barragan-web-static-known-hosts")
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
CORE_SSH_OPTIONS = (
    "-o StrictHostKeyChecking=accept-new",
    "-o IdentitiesOnly=yes",
    "-o BatchMode=yes",
    "-o ConnectTimeout=10",
)
SAFE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
SAFE_DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}[a-zA-Z0-9]$")
SECRET_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "authorization:",
    "bearer ",
    "password=",
    "token=",
    "secret=",
)
SECRET_OUTPUT_REDACTIONS = (
    (re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-api-token)\s*:\s*).+$"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+\S+"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(api[_ -]?key|private[_ -]?key|password|passwd|token|secret)\s*[:=]\s*([^\s&;]+)"), r"\1=[REDACTED]"),
)

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]
SAFE_CONTENT_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
MAX_CONTENT_FILE_BYTES = 1024 * 1024
MAX_CONTENT_TREE_BYTES = 8 * 1024 * 1024


class WebStaticServiceValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("web static service validation failed")
        self.errors = errors


@dataclass(frozen=True)
class WebStaticCoreHost:
    name: str
    ansible_host: str
    ansible_user: str = "user"
    ssh_private_key_file: str = ""
    proxy_jump: str = ""
    known_hosts_file: str = ""

    def to_inventory_line(self) -> str:
        parts = [
            self.name,
            f"ansible_host={self.ansible_host}",
            f"ansible_user={self.ansible_user}",
        ]
        if self.ssh_private_key_file:
            parts.append(f"ansible_ssh_private_key_file={self.ssh_private_key_file}")
        ssh_args = list(CORE_SSH_OPTIONS)
        if self.known_hosts_file:
            ssh_args.append(f"-o UserKnownHostsFile={self.known_hosts_file}")
        if self.proxy_jump:
            proxy_known_hosts_option = (
                [f"-o UserKnownHostsFile={self.known_hosts_file}"]
                if self.known_hosts_file
                else []
            )
            proxy_command = [
                "ssh",
                "-i",
                self.ssh_private_key_file,
                *CORE_SSH_OPTIONS,
                *proxy_known_hosts_option,
                "-W",
                "%h:%p",
                self.proxy_jump,
            ]
            ssh_args.append(f"-o ProxyCommand='{' '.join(proxy_command)}'")
        parts.append(f"ansible_ssh_common_args={json.dumps(' '.join(ssh_args))}")
        return " ".join(parts)

    def to_dict(self) -> dict[str, str]:
        body = {
            "name": self.name,
            "ansibleHost": self.ansible_host,
            "ansibleUser": self.ansible_user,
        }
        if self.ssh_private_key_file:
            body["sshPrivateKeyFile"] = self.ssh_private_key_file
        if self.proxy_jump:
            body["proxyJump"] = self.proxy_jump
        if self.known_hosts_file:
            body["knownHostsFile"] = self.known_hosts_file
        return body


@dataclass(frozen=True)
class WebStaticContentFile:
    path: str
    content: str
    encoding: str = "text"

    def decoded_bytes(self) -> bytes:
        if self.encoding == "base64":
            return base64.b64decode(self.content.encode("ascii"), validate=True)
        return self.content.encode("utf-8")

    def to_artifact(self, site_name: str) -> "RenderedWebStaticArtifact":
        return RenderedWebStaticArtifact(
            f"files/opt/web/{site_name}/html/{self.path}",
            self.content,
            self.encoding,
        )

    def to_metadata(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "encoding": self.encoding,
            "bytes": len(self.decoded_bytes()),
        }


@dataclass(frozen=True)
class WebStaticIntent:
    service_id: str
    site_name: str
    domain: str
    proxy_id: str
    internal_port: int
    index_html: str
    content_files: tuple[WebStaticContentFile, ...]
    content_action: str = "preserve"
    content_fingerprint: str = ""
    content_review_job_id: str = ""

    def to_service(self, engagement_id: str, *, status: str, apply_job_id: str = "") -> StoredEngagementService:
        return StoredEngagementService(
            engagement_id=engagement_id,
            service_id=self.service_id,
            service_type=WEB_STATIC_SERVICE_TYPE,
            name=self.site_name,
            proxy_id=self.proxy_id,
            status=status,
            config={
                "siteName": self.site_name,
                "domain": self.domain,
                "internalPort": self.internal_port,
                "contentPath": f"/opt/web/{self.site_name}/html/",
                "indexPath": f"/opt/web/{self.site_name}/html/index.html",
                "contentFiles": [content_file.to_metadata() for content_file in self.content_files],
                "siteConfigPath": f"/opt/web/{self.site_name}/conf/default.conf",
                "stackModel": "containerized-openresty-v1",
                "composePath": "/opt/web/docker-compose.yml",
                "siteComposePath": f"/opt/web/sites/{self.site_name}.compose.yml",
                "stackOwnershipPath": "/opt/web/.barragan-stack.json",
                "frontProxyService": "reverse-proxy",
                "certbotService": "certbot",
                "siteService": self.service_id.replace("-", "_"),
                "tlsSiteService": f"{self.service_id.replace('-', '_')}_tls",
                "tlsSiteConfigPath": f"/opt/web/{self.site_name}/tls-conf/default.conf",
                "httpRoutePath": f"/opt/web/http/{self.site_name}.map",
                "tlsRoutePath": f"/opt/web/tls/{self.site_name}.map",
                "frontRoutePath": f"/opt/web/http/{self.site_name}.map",
                "containerPort": 8081,
            },
            apply_job_id=apply_job_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contentAction": self.content_action,
            "contentReviewJobId": self.content_review_job_id,
            "serviceId": self.service_id,
            "serviceType": WEB_STATIC_SERVICE_TYPE,
            "service": WEB_STATIC_SERVICE_NAME,
            "siteName": self.site_name,
            "domain": self.domain,
            "proxyId": self.proxy_id,
            "internalPort": self.internal_port,
            "contentPath": f"/opt/web/{self.site_name}/html/",
            "indexPath": f"/opt/web/{self.site_name}/html/index.html",
            "contentFiles": [content_file.to_metadata() for content_file in self.content_files],
            "siteConfigPath": f"/opt/web/{self.site_name}/conf/default.conf",
            "stackModel": "containerized-openresty-v1",
            "composePath": "/opt/web/docker-compose.yml",
            "siteComposePath": f"/opt/web/sites/{self.site_name}.compose.yml",
            "stackOwnershipPath": "/opt/web/.barragan-stack.json",
            "frontProxyService": "reverse-proxy",
            "certbotService": "certbot",
            "siteService": self.service_id.replace("-", "_"),
            "tlsSiteService": f"{self.service_id.replace('-', '_')}_tls",
            "tlsSiteConfigPath": f"/opt/web/{self.site_name}/tls-conf/default.conf",
            "httpRoutePath": f"/opt/web/http/{self.site_name}.map",
            "tlsRoutePath": f"/opt/web/tls/{self.site_name}.map",
            "frontRoutePath": f"/opt/web/http/{self.site_name}.map",
            "containerPort": 8081,
        }


@dataclass(frozen=True)
class RenderedWebStaticArtifact:
    target: str
    content: str
    encoding: str = "text"

    def to_dict(self) -> dict[str, str]:
        body = {"target": self.target, "encoding": self.encoding}
        if self.encoding == "base64":
            body["contentBase64"] = self.content
        else:
            body["content"] = self.content
        return body

    def write_to(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if self.encoding == "base64":
            path.write_bytes(base64.b64decode(self.content.encode("ascii"), validate=True))
            return
        path.write_text(self.content, encoding="utf-8")

    def byte_length(self) -> int:
        if self.encoding == "base64":
            return len(base64.b64decode(self.content.encode("ascii"), validate=True))
        return len(self.content.encode("utf-8"))


@dataclass(frozen=True)
class WebStaticApplyWorkspace:
    inventory: RenderedWebStaticArtifact
    playbook: RenderedWebStaticArtifact
    manifest: RenderedWebStaticArtifact
    content_files: tuple[RenderedWebStaticArtifact, ...]
    site_config: RenderedWebStaticArtifact
    site_observability_config: RenderedWebStaticArtifact
    compose: RenderedWebStaticArtifact
    site_compose: RenderedWebStaticArtifact
    front_http_config: RenderedWebStaticArtifact
    front_route: RenderedWebStaticArtifact
    sensitive_artifacts: tuple[RenderedWebStaticArtifact, ...] = ()

    @property
    def site_index(self) -> RenderedWebStaticArtifact:
        return next(
            (artifact for artifact in self.content_files if artifact.target.endswith("/index.html")),
            RenderedWebStaticArtifact("files/index.html", ""),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending Service Apply",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
            "artifacts": [
                *[artifact.to_dict() for artifact in self.content_files],
                self.site_config.to_dict(),
                self.site_observability_config.to_dict(),
                self.compose.to_dict(),
                self.site_compose.to_dict(),
                self.front_http_config.to_dict(),
                self.front_route.to_dict(),
            ],
        }


@dataclass(frozen=True)
class WebStaticRemoveWorkspace:
    inventory: RenderedWebStaticArtifact
    playbook: RenderedWebStaticArtifact
    manifest: RenderedWebStaticArtifact

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending Service Removal",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
            "artifacts": [],
        }


def list_web_static_services(
    engagement_id: str,
    *,
    service_repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    services = [
        service.to_dict()
        for service in (service_repository or SqlAlchemyEngagementServiceRepository()).list_for_engagement(engagement_id)
        if service.service_type == WEB_STATIC_SERVICE_TYPE
    ]
    return {"services": services}


def _content_actor(fallback: str) -> str:
    identity = current_request_identity()
    return identity.username if identity is not None else "operator"


def _content_review_binding(repo, engagement_id, intent, homebase, proxy):
    deployment_id, _ = latest_core_connection_details(repo, engagement_id)
    content = [{"path": entry.path, "sha256": hashlib.sha256(entry.decoded_bytes()).hexdigest()} for entry in intent.content_files]
    config = {key: value for key, value in intent.to_dict().items() if key not in {"contentAction", "contentReviewJobId"}}
    value = {"engagementId": engagement_id, "deploymentId": deployment_id,
             "service": config, "content": content,
             "homebase": homebase.to_dict(), "proxy": proxy.to_dict()}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _inspect_remote_content(intent, proxy, runner=None):
    """Bounded read-only command over the established homebase management path."""
    request = {"mode": "inspect", "root": "/opt/web", "site": intent.site_name}
    source = Path(static_web_content.__file__).read_text()
    script = source.rsplit('if __name__ == "__main__":', 1)[0]
    script += "\nmain(" + repr(request) + ")\n"
    payload = base64.b64encode(script.encode()).decode()
    remote = "sudo -n python3 -c " + shlex.quote("import base64;exec(base64.b64decode(" + repr(payload) + "))")
    ssh_options = shlex.split(" ".join(CORE_SSH_OPTIONS))
    jump = ["ssh", "-i", proxy.ssh_private_key_file, *ssh_options,
            "-o", "UserKnownHostsFile=" + proxy.known_hosts_file, "-W", "%h:%p", proxy.proxy_jump]
    command = ["ssh", "-i", proxy.ssh_private_key_file, *ssh_options,
               "-o", "UserKnownHostsFile=" + proxy.known_hosts_file,
               "-o", "ProxyCommand=" + shlex.join(jump),
               proxy.ansible_user + "@" + proxy.ansible_host, remote]
    _ensure_known_hosts_file(proxy.known_hosts_file)
    try:
        result = runner(command, None) if runner else subprocess.run(
            command, check=False, capture_output=True, text=True,
            env=barragan_subprocess_env(), timeout=25)
        if result.returncode != 0 or len(result.stdout or "") > 4096:
            raise ValueError("inspection command failed")
        observation = json.loads(result.stdout)
        if not isinstance(observation, dict):
            raise ValueError("invalid inspection receipt")
        if observation.get("state") not in {"empty", "existing"} or not re.fullmatch(r"[a-f0-9]{64}", str(observation.get("fingerprint") or "")):
            raise ValueError("invalid inspection receipt")
        return observation
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise WebStaticServiceValidationError([
            "Website inspection failed. Check proxy management access, owned directory permissions, symlinks and inspection limits, then request a fresh review."
        ]) from exc


def _authorize_content_apply(repo, engagement_id, intent, body, actor, homebase, proxy, runner):
    action = str(body.get("contentAction") or intent.content_action)
    if action not in {"preserve", "restore-starter", "publish"}:
        raise WebStaticServiceValidationError(["contentAction must be preserve, restore-starter or explicit API publish"])
    if action == "publish" and intent.content_action != "publish":
        raise WebStaticServiceValidationError(["publish requires explicit validated website content"])
    if action != "publish" and intent.content_action == "publish":
        raise WebStaticServiceValidationError(["preserve/restore cannot carry a custom publish payload"])
    review_id = str(body.get("contentReviewJobId") or "")
    observation = None
    if review_id:
        review = repo.get(review_id)
        saved = review.input.get("contentReview", {}) if review else {}
        try:
            fresh = False
            if review:
                created_at = datetime.fromisoformat(review.created_at)
                # SQLite job timestamps are persisted as UTC without an offset.
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                fresh = created_at.astimezone(timezone.utc) >= datetime.now(timezone.utc) - timedelta(minutes=15)
        except (ValueError, TypeError):
            fresh = False
        if not (review and review.action == WEB_STATIC_APPLY_PREVIEW_ACTION and review.status == "succeeded"
                and review.target_id == engagement_id and review.requested_by == actor and fresh
                and saved.get("binding") == _content_review_binding(repo, engagement_id, intent, homebase, proxy)):
            raise WebStaticServiceValidationError(["Website review is stale or belongs to a different site, configuration or operator; request a fresh review"])
        observation = _inspect_remote_content(intent, proxy, runner)
        if observation["fingerprint"] != saved.get("fingerprint"):
            raise WebStaticServiceValidationError(["Website files changed since review; request a fresh review"])
    elif action != "publish":
        raise WebStaticServiceValidationError(["Request a fresh website content review before applying this site"])
    else:
        observation = _inspect_remote_content(intent, proxy, runner)
    return replace(intent, content_action=action, content_fingerprint=observation["fingerprint"], content_review_job_id=review_id)


def preview_web_static_service_apply(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    intent = _intent_from_body(engagement.name, body)
    homebase, proxy = _core_apply_hosts(repo, engagement_id, intent.proxy_id)
    requested_by = _content_actor(requested_by)
    observation = _inspect_remote_content(intent, proxy, runner)
    binding = _content_review_binding(repo, engagement_id, intent, homebase, proxy)
    workspace = render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy)
    try:
        job = _save_preview_job(repo, engagement_id, requested_by, intent, workspace,
                                content_review={**observation, "binding": binding})
    except MixedAppendBindingFenceError as exc:
        raise WebStaticServiceValidationError([str(exc)]) from exc
    return {"job": job.to_detail().to_dict(), "workspace": workspace.to_dict(), "service": intent.to_service(engagement_id, status="Pending Service Apply").to_dict(),
            "contentReview": {"reviewJobId": job.id, "state": observation["state"], "fingerprint": observation["fingerprint"],
                              "defaultAction": "preserve", "allowedActions": ["preserve", "restore-starter"],
                              "message": "Existing website files found. Preserve them, or restore only index.html." if observation["state"] == "existing" else "The empty website will receive the starter page."}}


def preview_web_static_service_remove(
    engagement_id: str,
    service_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
) -> dict[str, Any] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    service_repo = service_repository or SqlAlchemyEngagementServiceRepository()
    service = _get_web_static_service(service_repo, engagement_id, service_id)
    intent = _intent_from_service(service)
    homebase, proxy = _core_apply_hosts(repo, engagement_id, intent.proxy_id)
    workspace = render_web_static_remove_workspace(intent=intent, homebase=homebase, proxy=proxy)
    confirmation = _remove_confirmation_token(intent)
    try:
        job = _save_remove_preview_job(repo, engagement_id, requested_by, intent, workspace, confirmation)
    except MixedAppendBindingFenceError as exc:
        raise WebStaticServiceValidationError([str(exc)]) from exc
    return {
        "job": job.to_detail().to_dict(),
        "workspace": workspace.to_dict(),
        "service": service.to_dict(),
        "confirmationToken": confirmation,
    }


def remove_web_static_service(
    engagement_id: str,
    service_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    certificate_repository: CertificateRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any] | None:
    prepared = _prepare_web_static_remove_job(
        engagement_id,
        service_id,
        body,
        requested_by=requested_by,
        repository=repository,
        service_repository=service_repository,
        certificate_repository=certificate_repository,
        runner=runner,
        env=env,
        workspace_root=workspace_root,
    )
    if prepared is None:
        return None
    repo, service_repo, service, intent, job, command, workspace_dir, command_runner = prepared
    return _finish_web_static_remove_job(repo, service_repo, service, intent, job, command, workspace_dir, command_runner)


def start_web_static_service_remove(
    engagement_id: str,
    service_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    certificate_repository: CertificateRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    prepared = _prepare_web_static_remove_job(
        engagement_id,
        service_id,
        body,
        requested_by=requested_by,
        repository=repository,
        service_repository=service_repository,
        certificate_repository=certificate_repository,
        runner=runner,
        env=env,
        workspace_root=workspace_root,
    )
    if prepared is None:
        return None
    repo, service_repo, service, intent, job, command, workspace_dir, command_runner = prepared
    task_runner = background_runner or _start_background_task
    task_runner(lambda: _finish_web_static_remove_job(repo, service_repo, service, intent, job, command, workspace_dir, command_runner))
    removing_service = service_repo.get(engagement_id, service_id) or service_with_status(service, "Removing", job.id)
    return {"job": job.to_detail().to_dict(), "service": removing_service.to_dict(), "status": "Removing"}


def _prepare_web_static_remove_job(
    engagement_id: str,
    service_id: str,
    body: dict[str, Any],
    *,
    requested_by: str,
    repository: JobRepository | None,
    service_repository: EngagementServiceRepository | None,
    certificate_repository: CertificateRepository | None,
    runner: CommandRunner | None,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
) -> tuple[
    JobRepository,
    EngagementServiceRepository,
    StoredEngagementService,
    WebStaticIntent,
    StoredJobRun,
    list[str],
    Path,
    CommandRunner | None,
] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok:
        raise WebStaticServiceValidationError([ansible_resolution.message])

    repo = repository or SqlAlchemyJobRepository()
    service_repo = service_repository or SqlAlchemyEngagementServiceRepository()
    service = _get_web_static_service(service_repo, engagement_id, service_id)
    certificate_repo = certificate_repository or SqlAlchemyCertificateRepository()
    if certificate_repo.get_binding_for_service(engagement_id, service_id) is not None:
        raise WebStaticServiceValidationError(
            ["remove the persisted certificate binding before removing this Static Web service"]
        )
    intent = _intent_from_service(service)
    confirmation = str(body.get("confirmation") or "")
    expected_confirmation = _remove_confirmation_token(intent)
    if confirmation != expected_confirmation:
        raise WebStaticServiceValidationError([f'confirmation must equal "{expected_confirmation}"'])

    homebase, proxy = _core_apply_hosts(repo, engagement_id, intent.proxy_id)
    workspace = render_web_static_remove_workspace(intent=intent, homebase=homebase, proxy=proxy)
    workspace_dir = _write_remove_workspace(workspace, workspace_root or DEFAULT_WORKSPACE_ROOT, intent.site_name)
    _ensure_known_hosts_file(homebase.known_hosts_file)
    command = [ansible_resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/remove_web_static.yml"]
    timestamp = _now()
    removing_service = service_with_status(service, "Removing")
    candidate_job = StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=WEB_STATIC_REMOVE_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "serviceId": intent.service_id, "serviceType": WEB_STATIC_SERVICE_TYPE, "proxyId": intent.proxy_id, "mutation": True},
            artifact_refs=["ansible/inventory.ini", "ansible/remove_web_static.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "static web service remove workspace rendered",
                    {
                        "service": intent.to_dict(),
                        "workspaceDir": str(workspace_dir),
                        "inventoryTargets": ["selected_proxy"],
                        "workspaceEvidence": _remove_workspace_evidence(workspace),
                        "servicePlacements": [_service_placement(intent, status="Removing")],
                        "mutation": True,
                    },
                ),
                JobEvent(
                    2,
                    "info",
                    "static web service Ansible remove started",
                    {
                        "serviceId": intent.service_id,
                        "proxyId": intent.proxy_id,
                        "command": command,
                        "cwd": str(workspace_dir),
                        "inventoryTargets": ["selected_proxy"],
                    },
                ),
            ],
    )
    try:
        job = reserve_shared_proxy_stack_mutation(repo, candidate_job, engagement_id=engagement_id, proxy_id=intent.proxy_id)
    except MixedAppendBindingFenceError as exc:
        _discard_web_static_execution_workspace(workspace_dir)
        raise WebStaticServiceValidationError([str(exc)]) from exc
    except SharedProxyStackMutationConflict as exc:
        raise WebStaticServiceValidationError(
            [f"Static Web mutation already running on {intent.proxy_id}: {exc.job.id} ({exc.job.action})"]
        ) from exc
    service_repo.save(removing_service)
    _assert_no_forbidden_markers(json.dumps([event.data for event in job.events], sort_keys=True), "web static remove job events")
    return repo, service_repo, service, intent, job, command, workspace_dir, runner


def _finish_web_static_remove_job(
    repo: JobRepository,
    service_repo: EngagementServiceRepository,
    service: StoredEngagementService,
    intent: WebStaticIntent,
    job: StoredJobRun,
    command: list[str],
    workspace_dir: Path,
    runner: CommandRunner | None,
) -> dict[str, Any]:
    job = repo.get(job.id) or job
    result = _run_guarded_command(command, workspace_dir, runner)
    finished_at = _now()
    final_status = "succeeded" if result.ok else "failed"
    service_status = "Removed" if result.ok else "Remove Failed"
    saved_service = service_repo.save(service_with_status(service, service_status, job.id))
    final_event = JobEvent(
        3,
        "info" if result.ok else "error",
        "static web service Ansible remove succeeded" if result.ok else "static web service Ansible remove failed",
        {
            "serviceId": intent.service_id,
            "proxyId": intent.proxy_id,
            "commandResult": _safe_command_result(result),
            "servicePlacements": [_service_placement(intent, status=service_status)],
            "status": service_status,
        },
    )
    saved = repo.save(replace(job, status=final_status, finished_at=finished_at, events=job.events + [final_event]))
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(service.engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "service": saved_service.to_dict(), "status": service_status}


def apply_web_static_service(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    certificate_repository: CertificateRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    before_start: Callable[[], None] | None = None,
) -> dict[str, Any] | None:
    prepared = _prepare_web_static_apply_job(
        engagement_id,
        body,
        requested_by=requested_by,
        repository=repository,
        service_repository=service_repository,
        certificate_repository=certificate_repository,
        runner=runner,
        env=env,
        workspace_root=workspace_root,
        before_start=before_start,
    )
    if prepared is None:
        return None
    repo, service_repo, intent, job, command, workspace_dir, command_runner, prior_service = prepared
    return _finish_web_static_apply_job(repo, service_repo, engagement_id, intent, job, command, workspace_dir, command_runner, prior_service)


def start_web_static_service_apply(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    service_repository: EngagementServiceRepository | None = None,
    certificate_repository: CertificateRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    background_runner: BackgroundRunner | None = None,
    before_start: Callable[[], None] | None = None,
) -> dict[str, Any] | None:
    prepared = _prepare_web_static_apply_job(
        engagement_id,
        body,
        requested_by=requested_by,
        repository=repository,
        service_repository=service_repository,
        certificate_repository=certificate_repository,
        runner=runner,
        env=env,
        workspace_root=workspace_root,
        before_start=before_start,
    )
    if prepared is None:
        return None
    repo, service_repo, intent, job, command, workspace_dir, command_runner, prior_service = prepared
    task_runner = background_runner or _start_background_task
    try:
        task_runner(lambda: _finish_web_static_apply_job(repo, service_repo, engagement_id, intent, job, command, workspace_dir, command_runner, prior_service))
    except Exception as exc:
        _discard_web_static_execution_workspace(workspace_dir)
        restored_service = service_repo.save(
            prior_service
            if prior_service is not None
            else intent.to_service(engagement_id, status="Failed", apply_job_id=job.id)
        )
        failed = replace(
            job,
            status="failed",
            finished_at=_now(),
            events=[
                *job.events,
                JobEvent(
                    len(job.events) + 1,
                    "error",
                    "static web service background apply could not be started",
                    {
                        "serviceId": intent.service_id,
                        "proxyId": intent.proxy_id,
                        "errorType": type(exc).__name__,
                        "servicePlacements": [
                            _service_placement(intent, status=restored_service.status)
                        ],
                        "status": restored_service.status,
                    },
                ),
            ],
        )
        _assert_no_forbidden_markers(
            json.dumps([event.data for event in failed.events], sort_keys=True),
            "web static scheduler failure events",
        )
        repo.save(failed)
        raise WebStaticServiceValidationError(
            ["Static Web apply could not be started; the job and service state were restored to a terminal status."]
        ) from exc
    applying_service = service_repo.get(engagement_id, intent.service_id) or intent.to_service(engagement_id, status="Applying", apply_job_id=job.id)
    return {"job": job.to_detail().to_dict(), "service": applying_service.to_dict(), "status": "Applying"}


def _prepare_web_static_apply_job(
    engagement_id: str,
    body: dict[str, Any],
    *,
    requested_by: str,
    repository: JobRepository | None,
    service_repository: EngagementServiceRepository | None,
    certificate_repository: CertificateRepository | None,
    runner: CommandRunner | None,
    env: Mapping[str, str] | None,
    workspace_root: Path | None,
    before_start: Callable[[], None] | None,
) -> tuple[
    JobRepository,
    EngagementServiceRepository,
    WebStaticIntent,
    StoredJobRun,
    list[str],
    Path,
    CommandRunner | None,
    StoredEngagementService | None,
] | None:
    engagement = get_engagement(engagement_id)
    if engagement is None:
        return None

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok:
        raise WebStaticServiceValidationError([ansible_resolution.message])

    repo = repository or SqlAlchemyJobRepository()
    service_repo = service_repository or SqlAlchemyEngagementServiceRepository()
    certificate_repo = certificate_repository or SqlAlchemyCertificateRepository()
    intent = _intent_from_body(engagement.name, body)
    prior_service = service_repo.get(engagement_id, intent.service_id)
    retained_binding = (
        certificate_repo.get_binding_for_service(engagement_id, intent.service_id)
        if prior_service is not None
        else None
    )
    try:
        assert_web_delivery_capability_available(
            engagement_id,
            host_id=intent.proxy_id,
            capability_id=NATIVE_STATIC_WEB_CAPABILITY_ID,
            service_id=intent.service_id,
            repository=service_repo,
        )
    except WebDeliveryCapabilityConflictError as exc:
        raise WebStaticServiceValidationError(exc.errors) from exc
    homebase, proxy = _core_apply_hosts(repo, engagement_id, intent.proxy_id)
    requested_by = _content_actor(requested_by)
    intent = _authorize_content_apply(repo, engagement_id, intent, body, requested_by, homebase, proxy, runner)
    workspace = render_web_static_apply_workspace(
        intent=intent,
        homebase=homebase,
        proxy=proxy,
        retained_binding=retained_binding,
    )
    if before_start is not None:
        before_start()
    workspace_dir = _write_workspace(workspace, workspace_root or DEFAULT_WORKSPACE_ROOT, intent.site_name)
    _ensure_known_hosts_file(homebase.known_hosts_file)
    command = [ansible_resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/apply_web_static.yml"]
    timestamp = _now()
    applying_service = intent.to_service(engagement_id, status="Applying")
    candidate_job = StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=WEB_STATIC_APPLY_ACTION,
            status="running",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "serviceId": intent.service_id, "serviceType": WEB_STATIC_SERVICE_TYPE, "proxyId": intent.proxy_id, "contentAction": intent.content_action, "contentReviewJobId": intent.content_review_job_id, "mutation": True},
            artifact_refs=["ansible/inventory.ini", "ansible/apply_web_static.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=None,
            events=[
                JobEvent(
                    1,
                    "info",
                    "static web service apply workspace rendered",
                    {
                        "service": intent.to_dict(),
                        "workspaceDir": str(workspace_dir),
                        "inventoryTargets": ["selected_proxy"],
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "servicePlacements": [_service_placement(intent, status="Applying")],
                        "mutation": True,
                    },
                ),
                JobEvent(
                    2,
                    "info",
                    "static web service Ansible apply started",
                    {
                        "serviceId": intent.service_id,
                        "proxyId": intent.proxy_id,
                        "command": command,
                        "cwd": str(workspace_dir),
                        "inventoryTargets": ["selected_proxy"],
                    },
                ),
            ],
    )
    try:
        job = reserve_shared_proxy_stack_mutation(repo, candidate_job, engagement_id=engagement_id, proxy_id=intent.proxy_id)
    except MixedAppendBindingFenceError as exc:
        _discard_web_static_execution_workspace(workspace_dir)
        raise WebStaticServiceValidationError([str(exc)]) from exc
    except SharedProxyStackMutationConflict as exc:
        _discard_web_static_execution_workspace(workspace_dir)
        raise WebStaticServiceValidationError(
            [f"Static Web mutation already running on {intent.proxy_id}: {exc.job.id} ({exc.job.action})"]
        ) from exc
    service_repo.save(applying_service)
    _assert_no_forbidden_markers(json.dumps([event.data for event in job.events], sort_keys=True), "web static job events")
    return repo, service_repo, intent, job, command, workspace_dir, runner, prior_service


def _finish_web_static_apply_job(
    repo: JobRepository,
    service_repo: EngagementServiceRepository,
    engagement_id: str,
    intent: WebStaticIntent,
    job: StoredJobRun,
    command: list[str],
    workspace_dir: Path,
    runner: CommandRunner | None,
    prior_service: StoredEngagementService | None,
) -> dict[str, Any]:
    job = repo.get(job.id) or job
    try:
        result = _run_guarded_command(command, workspace_dir, runner)
    finally:
        _scrub_retained_request_header_gate_files(workspace_dir)
    finished_at = _now()
    final_status = "succeeded" if result.ok else "failed"
    service_status = "Configured" if result.ok else (prior_service.status if prior_service is not None else "Failed")
    saved_service = service_repo.save(
        intent.to_service(engagement_id, status=service_status, apply_job_id=job.id)
        if result.ok or prior_service is None
        else prior_service
    )
    final_event = JobEvent(
        3,
        "info" if result.ok else "error",
        "static web service Ansible apply succeeded" if result.ok else "static web service Ansible apply failed",
        {
            "serviceId": intent.service_id,
            "proxyId": intent.proxy_id,
            "commandResult": _safe_command_result(result),
            "contentAction": intent.content_action,
            "contentReviewJobId": intent.content_review_job_id,
            "contentOutcome": _content_outcome(result.stdout),
            "contentRollback": _content_rollback_outcome(result.stdout),
            "servicePlacements": [_service_placement(intent, status=service_status)],
            "status": service_status,
        },
    )
    saved = repo.save(replace(job, status=final_status, finished_at=finished_at, events=job.events + [final_event]))
    if saved.status == "succeeded":
        try_enqueue_infra_orientation_refresh(engagement_id, repository=repo)
    return {"job": saved.to_detail().to_dict(), "service": saved_service.to_dict(), "status": service_status}


def render_web_static_apply_workspace(
    *,
    intent: WebStaticIntent,
    homebase: WebStaticCoreHost,
    proxy: WebStaticCoreHost,
    retained_binding: Any | None = None,
) -> WebStaticApplyWorkspace:
    from app.services.managed_site_observability import render_managed_site_observability_config

    _validate_core_hosts(homebase, proxy)
    content_artifacts = tuple(content_file.to_artifact(intent.site_name) for content_file in intent.content_files)
    playbook = _render_playbook(intent, retained_binding=retained_binding)
    operation_root = re.search(r'content_operation_root: "([^"]+)"', playbook).group(1)
    operation_request = {"root": "/opt/web", "site": intent.site_name, "action": intent.content_action,
                         "fingerprint": intent.content_fingerprint, "receipt": operation_root + "/receipt.json",
                         "conflicts": "/var/lib/barragan-static-content-conflicts/" + operation_root.rsplit("-", 1)[-1],
                         "starter": base64.b64encode(DEFAULT_INDEX_HTML.encode()).decode(),
                         "files": [{"path": entry.path, "data": base64.b64encode(entry.decoded_bytes()).decode()} for entry in intent.content_files]}
    sensitive_artifacts = (
        RenderedWebStaticArtifact("helpers/static_web_content.py", Path(static_web_content.__file__).read_text()),
        *[RenderedWebStaticArtifact(f"helpers/{mode}.json", json.dumps({**operation_request, "mode": mode})) for mode in ("apply", "rollback", "check")],
    )
    artifacts = WebStaticApplyWorkspace(
        inventory=RenderedWebStaticArtifact("ansible/inventory.ini", _render_inventory(proxy)),
        playbook=RenderedWebStaticArtifact(
            "ansible/apply_web_static.yml",
            playbook,
        ),
        manifest=RenderedWebStaticArtifact("MANIFEST.json", _render_manifest(intent, homebase, proxy)),
        content_files=content_artifacts,
        site_config=RenderedWebStaticArtifact(f"files/opt/web/{intent.site_name}/conf/default.conf", _render_site_config(intent)),
        site_observability_config=RenderedWebStaticArtifact(
            f"files/opt/web/{intent.site_name}/conf/00-barragan-observability.conf",
            # Static Web receives ordinary HTTP from the shared front. The
            # front carries the incoming PROXY source in X-Real-IP, so this
            # site must not reference the TLS-only PROXY fallback variable.
            render_managed_site_observability_config(receives_proxy_protocol=False),
        ),
        compose=RenderedWebStaticArtifact("files/opt/web/docker-compose.yml", _render_compose()),
        site_compose=RenderedWebStaticArtifact(f"files/opt/web/sites/{intent.site_name}.compose.yml", _render_site_compose(intent)),
        front_http_config=RenderedWebStaticArtifact("files/opt/web/nginx.conf", _render_front_http_config()),
        front_route=RenderedWebStaticArtifact(f"files/opt/web/http/{intent.site_name}.map", _render_front_route(intent)),
        sensitive_artifacts=sensitive_artifacts,
    )
    _assert_no_forbidden_markers(json.dumps(artifacts.to_dict(), sort_keys=True), "web static workspace")
    return artifacts


def render_web_static_remove_workspace(
    *,
    intent: WebStaticIntent,
    homebase: WebStaticCoreHost,
    proxy: WebStaticCoreHost,
) -> WebStaticRemoveWorkspace:
    _validate_core_hosts(homebase, proxy)
    workspace = WebStaticRemoveWorkspace(
        inventory=RenderedWebStaticArtifact("ansible/inventory.ini", _render_inventory(proxy)),
        playbook=RenderedWebStaticArtifact("ansible/remove_web_static.yml", _render_remove_playbook(intent)),
        manifest=RenderedWebStaticArtifact("MANIFEST.json", _render_remove_manifest(intent, homebase, proxy)),
    )
    _assert_no_forbidden_markers(json.dumps(workspace.to_dict(), sort_keys=True), "web static remove workspace")
    return workspace


def _intent_from_body(engagement_name: str, body: dict[str, Any]) -> WebStaticIntent:
    site_name = _slug(body.get("siteName") or body.get("name") or body.get("domain") or engagement_name)
    domain = str(body.get("domain") or f"{site_name}.invalid").strip().lower()
    proxy_id = str(body.get("proxyId") or body.get("proxy") or "proxy01").strip()
    index_html = str(body.get("indexHtml") or body.get("content") or DEFAULT_INDEX_HTML)
    content_files = _content_files_from_body(body, index_html)
    try:
        internal_port = int(body.get("internalPort") or DEFAULT_INTERNAL_PORT)
    except (TypeError, ValueError) as exc:
        raise WebStaticServiceValidationError(["internalPort must be a TCP port"]) from exc

    errors: list[str] = []
    if not SAFE_ID_PATTERN.match(site_name):
        errors.append("siteName must be a lowercase slug with letters, numbers, hyphens, and underscores")
    if not SAFE_DOMAIN_PATTERN.match(domain):
        errors.append("domain must look like a hostname")
    if not _is_proxy_id(proxy_id):
        errors.append("proxyId must look like proxy01")
    if internal_port != DEFAULT_INTERNAL_PORT:
        errors.append("Static Web site containers use Docker-internal port 8081; the shared proxy front owns public ports 80 and 443")
    if len(index_html.encode("utf-8")) > 131072:
        errors.append("indexHtml must be 128 KiB or smaller")
    if _contains_forbidden_marker(index_html):
        errors.append("indexHtml appears to contain secret material")
    if not content_files:
        errors.append("contentFiles must include at least index.html")
    if errors:
        raise WebStaticServiceValidationError(errors)
    return WebStaticIntent(
        service_id=f"web-{site_name}",
        site_name=site_name,
        domain=domain,
        proxy_id=proxy_id,
        internal_port=internal_port,
        index_html=index_html,
        content_files=content_files,
        content_action="publish" if (body.get("contentFiles") is not None or index_html != DEFAULT_INDEX_HTML) else "preserve",
    )


def _content_files_from_body(body: dict[str, Any], index_html: str) -> tuple[WebStaticContentFile, ...]:
    raw_files = body.get("contentFiles")
    content_files: list[WebStaticContentFile] = []
    if raw_files is not None:
        if not isinstance(raw_files, list):
            raise WebStaticServiceValidationError(["contentFiles must be a list of file objects"])
        for index, raw_file in enumerate(raw_files):
            if not isinstance(raw_file, Mapping):
                raise WebStaticServiceValidationError([f"contentFiles[{index}] must be an object"])
            content_files.append(_content_file_from_mapping(raw_file, index))

    if not any(content_file.path == "index.html" for content_file in content_files):
        content_files.insert(0, WebStaticContentFile("index.html", index_html, "text"))

    errors: list[str] = []
    seen_paths: set[str] = set()
    total_bytes = 0
    for content_file in content_files:
        if content_file.path in seen_paths:
            errors.append(f"contentFiles path {content_file.path} is duplicated")
            continue
        seen_paths.add(content_file.path)
        try:
            decoded = content_file.decoded_bytes()
        except (binascii.Error, ValueError) as exc:
            errors.append(f"contentFiles path {content_file.path} is not valid base64")
            continue
        file_bytes = len(decoded)
        total_bytes += file_bytes
        if file_bytes > MAX_CONTENT_FILE_BYTES:
            errors.append(f"contentFiles path {content_file.path} must be 1 MiB or smaller")
        if _contains_forbidden_marker(decoded.decode("utf-8", errors="ignore")):
            errors.append(f"contentFiles path {content_file.path} appears to contain secret material")
    if total_bytes > MAX_CONTENT_TREE_BYTES:
        errors.append("contentFiles total size must be 8 MiB or smaller")
    if errors:
        raise WebStaticServiceValidationError(errors)
    return tuple(content_files)


def _content_file_from_mapping(raw_file: Mapping[str, Any], index: int) -> WebStaticContentFile:
    path = _normalize_content_path(raw_file.get("path") or raw_file.get("name"), index)
    encoding = str(raw_file.get("encoding") or ("base64" if raw_file.get("contentBase64") is not None else "text")).strip().lower()
    if encoding not in {"text", "base64"}:
        raise WebStaticServiceValidationError([f"contentFiles[{index}].encoding must be text or base64"])
    if encoding == "base64":
        content = str(raw_file.get("contentBase64") if raw_file.get("contentBase64") is not None else raw_file.get("content") or "")
        if not content:
            raise WebStaticServiceValidationError([f"contentFiles[{index}].contentBase64 is required"])
        return WebStaticContentFile(path, content, encoding)
    return WebStaticContentFile(path, str(raw_file.get("content") or ""), encoding)


def _normalize_content_path(value: Any, index: int) -> str:
    raw_path = str(value or "").strip().replace("\\", "/")
    if not raw_path:
        raise WebStaticServiceValidationError([f"contentFiles[{index}].path is required"])
    if raw_path.startswith("/") or raw_path.endswith("/"):
        raise WebStaticServiceValidationError([f"contentFiles[{index}].path must be a relative file path"])
    if not SAFE_CONTENT_PATH_PATTERN.match(raw_path):
        raise WebStaticServiceValidationError([f"contentFiles[{index}].path contains unsupported characters"])
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise WebStaticServiceValidationError([f"contentFiles[{index}].path must stay inside the site content directory"])
    return path.as_posix()


def _intent_from_service(service: StoredEngagementService) -> WebStaticIntent:
    config = dict(service.config or {})
    body = {
        "siteName": config.get("siteName") or service.name,
        "domain": config.get("domain") or f"{service.name}.invalid",
        "proxyId": service.proxy_id,
        # Legacy records retained an obsolete host-published site port. A
        # reapply converges them to the fixed Docker-internal site port.
        "internalPort": str(DEFAULT_INTERNAL_PORT),
        "indexHtml": DEFAULT_INDEX_HTML,
    }
    intent = _intent_from_body(service.name, body)
    if intent.service_id != service.service_id:
        return replace(intent, service_id=service.service_id)
    return intent


def _get_web_static_service(
    service_repository: EngagementServiceRepository,
    engagement_id: str,
    service_id: str,
) -> StoredEngagementService:
    service = service_repository.get(engagement_id, service_id)
    if service is None or service.service_type != WEB_STATIC_SERVICE_TYPE:
        raise WebStaticServiceValidationError([f"web static service {service_id} was not found"])
    return service


def _core_apply_hosts(
    repository: JobRepository,
    engagement_id: str,
    proxy_id: str,
) -> tuple[WebStaticCoreHost, WebStaticCoreHost]:
    deployment_id, details = latest_core_connection_details(repository, engagement_id)
    homebase = next((entry for entry in details if str(entry.get("role") or "") == "homebase"), None)
    proxy = next((entry for entry in details if _entry_matches_proxy(entry, proxy_id)), None)
    if homebase is None:
        raise WebStaticServiceValidationError(["latest core deployment connectionDetails must include homebase"])
    if proxy is None:
        raise WebStaticServiceValidationError([f"latest core deployment connectionDetails must include {proxy_id}"])
    ssh_key = _core_ssh_private_key_path()
    known_hosts_file = _known_hosts_file(engagement_id, deployment_id)
    homebase_host = WebStaticCoreHost(
        "homebase",
        _required_text(homebase, "publicIp"),
        _entry_user(homebase),
        ssh_key,
        "",
        known_hosts_file,
    )
    proxy_host = WebStaticCoreHost(
        proxy_id,
        _required_text(proxy, "privateIp") or _required_text(proxy, "publicIp"),
        _entry_user(proxy),
        ssh_key,
        f"{homebase_host.ansible_user}@{homebase_host.ansible_host}",
        known_hosts_file,
    )
    return homebase_host, proxy_host


def _render_inventory(proxy: WebStaticCoreHost) -> str:
    return "\n".join(
        [
            "# Managed by Barragan static web service apply.",
            "# Target selected proxy only. Do not add middle or edge sketch nodes here.",
            "[selected_proxy]",
            proxy.to_inventory_line(),
            "",
        ]
    )


def _shared_front_collision_preflight_command(stack_root: str = "/opt/web") -> str:
    root = shlex.quote(stack_root)
    return f'''set -eu
stack_root={root}
owned_front_running=false
if [ -f "$stack_root/.barragan-stack.json" ] \
  && docker inspect proxy >/dev/null 2>&1 \
  && docker top proxy >/dev/null 2>&1; then
  owned_front_running=true
fi
owned_80=""
owned_443=""
if [ "$owned_front_running" = true ]; then
  owned_80="$(docker port proxy 80/tcp 2>/dev/null || true)"
  owned_443="$(docker port proxy 443/tcp 2>/dev/null || true)"
fi
if ! tcp_listeners="$(ss -H -ltn '( sport = :80 or sport = :443 )' 2>&1)"; then
  echo 'Unable to inspect TCP port 80/443 ownership; Barragan will not mutate the shared OpenResty front.' >&2
  exit 1
fi
listener_80="$(printf '%s' "$tcp_listeners" | awk '$4 ~ /:80$/ {{ print; exit }}')"
listener_443="$(printf '%s' "$tcp_listeners" | awk '$4 ~ /:443$/ {{ print; exit }}')"
if [ -n "$listener_80" ] && [ -z "$owned_80" ]; then
  echo 'A foreign process owns TCP port 80; Barragan will not stop it to start the shared OpenResty front.' >&2
  exit 1
fi
if [ -n "$listener_443" ] && [ -z "$owned_443" ]; then
  echo 'A foreign process owns TCP port 443; Barragan will not stop it to start the shared OpenResty front.' >&2
  exit 1
fi'''


def _render_playbook(intent: WebStaticIntent, *, retained_binding: Any | None = None) -> str:
    from app.services.inbound_request_header_gate import render_request_header_gate_http_runtime

    container_name = f"barragan_{intent.service_id.replace('-', '_')}"
    request_header_gate_runtime = render_request_header_gate_http_runtime().strip()
    content_operation_root = f"/tmp/barragan-static-content-{uuid4().hex}"
    binding_hostname = str(getattr(retained_binding, "hostname", "") or "")
    binding_certificate_id = str(getattr(retained_binding, "certificate_id", "") or "")
    collision_preflight = "\n".join(
        f"          {line}" for line in _shared_front_collision_preflight_command().splitlines()
    )
    playbook = f"""---
- name: Apply Barragan static web service to selected proxy
  hosts: selected_proxy
  become: true
  gather_facts: true
  vars:
    content_operation_root: "{content_operation_root}"
    site_name: "{intent.site_name}"
    site_domain: "{intent.domain}"
    internal_port: {intent.internal_port}
    site_root: "/opt/web/{intent.site_name}"
    compose_path: "/opt/web/docker-compose.yml"
    site_compose_path: "/opt/web/sites/{intent.site_name}.compose.yml"
    container_name: "{container_name}"
  tasks:
    - name: Detect Docker Compose v2
      ansible.builtin.command:
        argv: [docker, compose, version]
      register: barragan_compose_v2
      failed_when: false
      changed_when: false

    - name: Detect Docker Compose v1 fallback
      ansible.builtin.command:
        argv: [docker-compose, version]
      register: barragan_compose_v1
      when: barragan_compose_v2.rc != 0
      failed_when: false
      changed_when: false

    - name: Require a supported Docker Compose runtime
      ansible.builtin.assert:
        that:
          - barragan_compose_v2.rc == 0 or barragan_compose_v1.rc == 0

    - name: Select Docker Compose command
      ansible.builtin.set_fact:
        barragan_compose_argv: "{{{{ ['docker', 'compose'] if barragan_compose_v2.rc == 0 else ['docker-compose'] }}}}"

    - name: Check shared front ownership before mutation
      ansible.builtin.shell:
        cmd: python3 -c "import json,pathlib,sys; root=pathlib.Path('/opt/web'); owner=root/'.barragan-stack.json'; expected={{'managedBy':'barragan','stackModel':'containerized-openresty-v1'}}; nonempty=root.exists() and any(root.iterdir()); ok=(not nonempty) or (owner.exists() and json.loads(owner.read_text()) == expected); sys.exit(0 if ok else 1)"
      register: barragan_front_ownership
      changed_when: false
      failed_when: false

    - name: Refuse to mutate an unowned shared front stack
      ansible.builtin.assert:
        that:
          - barragan_front_ownership.rc == 0
        fail_msg: Barragan will not mutate /opt/web unless its stack manifest declares Barragan ownership.

    - name: Refuse shared front TCP port collision
      ansible.builtin.shell:
        cmd: |
{collision_preflight}
      changed_when: false

    - name: Validate current and legacy site runtime before mutation
      ansible.builtin.shell:
        cmd: |
          python3 - <<'PY'
          import pathlib, sys
          site = pathlib.Path('/opt/web/{intent.site_name}')
          legacy = pathlib.Path('/opt/web/streams/{intent.site_name}.map')
          http_route = pathlib.Path('/opt/web/http/{intent.site_name}.map')
          tls_route = pathlib.Path('/opt/web/tls/{intent.site_name}.map')
          tls_config = site / 'tls-conf/default.conf'
          plain_config = site / 'conf/default.conf'
          plain_target = '{intent.domain} {intent.service_id.replace('-', '_')}:8081;'
          tls_target = '{intent.domain} {intent.service_id.replace('-', '_')}_tls:8081;'
          binding_hostname = {binding_hostname!r}
          binding_live = {f"/etc/letsencrypt/live/barragan/{binding_certificate_id}/current"!r}
          def owned_route(path, target):
              if not path.exists() or path.is_symlink() or not path.is_file():
                  return False
              lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
              return bool(lines and lines[-1] == target and all(line.startswith('# Barragan-managed route ') for line in lines[:-1]))
          def has_symlink_component(path):
              return any(part.is_symlink() for part in (path, *path.parents) if str(part) != '/')
          for owned_path in (site, legacy, http_route, tls_route, plain_config, tls_config):
              if has_symlink_component(owned_path):
                  sys.exit('Static Web owned path contains a symlink component')
          if legacy.exists():
              if not owned_route(legacy, plain_target) or http_route.exists() or tls_route.exists() or not plain_config.is_file() or plain_config.is_symlink():
                  sys.exit('legacy Static Web route is not exact-owned or conflicts with split routes')
              text = plain_config.read_text()
              is_plain = text.count('listen 8081;') == 1 and 'ssl_certificate ' not in text
              is_tls = text.count('listen 8081 proxy_protocol ssl;') == 1 and text.count('/etc/letsencrypt/live/barragan/') >= 2
              if not (is_plain ^ is_tls):
                  sys.exit('legacy Static Web listener cannot be classified safely')
              if is_tls and (not binding_hostname or text.count('server_name '+binding_hostname+';') != 1 or text.count('ssl_certificate '+binding_live+'/fullchain.pem;') != 1 or text.count('ssl_certificate_key '+binding_live+'/privkey.pem;') != 1):
                  sys.exit('legacy Static Web TLS runtime does not match the persisted certificate binding')
          if http_route.exists() and not owned_route(http_route, plain_target):
              sys.exit('Static Web HTTP route is not exact-owned')
          split = [tls_config.exists(), tls_route.exists()]
          if any(split) and not all(split):
              sys.exit('Static Web TLS sibling state is incomplete')
          if all(split) and not owned_route(tls_route, tls_target):
              sys.exit('Static Web TLS route is not exact-owned')
          if tls_config.exists():
              if tls_config.is_symlink() or not tls_config.is_file() or not binding_hostname:
                  sys.exit('Static Web TLS runtime has no exact persisted certificate binding')
              text = tls_config.read_text()
              if text.count('listen 8081 proxy_protocol ssl;') != 1 or text.count('server_name '+binding_hostname+';') != 1 or text.count('ssl_certificate '+binding_live+'/fullchain.pem;') != 1 or text.count('ssl_certificate_key '+binding_live+'/privkey.pem;') != 1:
                  sys.exit('Static Web TLS listener is not an exact Barragan certificate listener')
          PY
      changed_when: false

    - name: Create private content operation directory
      ansible.builtin.file:
        path: "{{{{ content_operation_root }}}}"
        state: directory
        owner: root
        mode: "0700"

    - name: Stage private content operation requests
      ansible.builtin.copy:
        src: "../helpers/{{{{ item }}}}"
        dest: "{{{{ content_operation_root }}}}/{{{{ item }}}}"
        owner: root
        mode: "0600"
      loop: [apply.json, rollback.json, check.json]

    - name: Recheck reviewed content before runtime mutation
      ansible.builtin.script:
        cmd: "../helpers/static_web_content.py {{{{ content_operation_root }}}}/check.json"
        executable: python3
      changed_when: false

    - name: Ensure Docker service is running
      ansible.builtin.systemd:
        name: docker
        state: started
        enabled: true

    - name: Create Barragan web directories
      ansible.builtin.file:
        path: "{{{{ item }}}}"
        state: directory
        owner: root
        group: redteam
        mode: "0775"
      loop:
        - /opt/web
        - /opt/web/conf
        - /opt/web/http
        - /opt/web/streams
        - /opt/web/tls
        - /opt/web/sites
        - "{{{{ site_root }}}}/conf"
        - "{{{{ site_root }}}}/tls-conf"

    - name: Record Barragan proxy-stack ownership
      ansible.builtin.copy:
        dest: /opt/web/.barragan-stack.json
        owner: root
        group: redteam
        mode: "0640"
        content: '{{{{ {{"managedBy": "barragan", "stackModel": "containerized-openresty-v1"}} | to_json }}}}'

    - name: Apply reviewed Static Web content policy
      ansible.builtin.script:
        cmd: "../helpers/static_web_content.py {{{{ content_operation_root }}}}/apply.json"
        executable: python3
      register: static_content_result
      changed_when: "'preserved' not in static_content_result.stdout"

    - name: Record selected website content outcome
      ansible.builtin.debug:
        msg: "BARRAGAN_STATIC_CONTENT_OUTCOME={{{{ (static_content_result.stdout | trim | from_json).outcome }}}}"

    - name: Write site OpenResty config
      ansible.builtin.copy:
        src: "../files/opt/web/{intent.site_name}/conf/default.conf"
        dest: "{{{{ site_root }}}}/conf/default.conf"
        owner: root
        group: redteam
        mode: "0664"

    - name: Write site request observability config
      ansible.builtin.copy:
        src: "../files/opt/web/{intent.site_name}/conf/00-barragan-observability.conf"
        dest: "{{{{ site_root }}}}/conf/00-barragan-observability.conf"
        owner: root
        group: redteam
        mode: "0644"

    - name: Ensure request-header gate HTTP runtime sizing
      ansible.builtin.copy:
        dest: "{{{{ site_root }}}}/conf/00-request-header-gate-00-runtime.conf"
        owner: root
        group: redteam
        mode: "0640"
        content: "{request_header_gate_runtime}\\n"

    - name: Ensure retained request-header gate map hook exists
      ansible.builtin.copy:
        dest: "{{{{ site_root }}}}/conf/00-request-header-gate-map.conf"
        owner: root
        group: redteam
        mode: "0640"
        force: false
        content: "# Barragan request-header gate is disabled.\n"

    - name: Ensure retained request-header gate server hook exists
      ansible.builtin.copy:
        dest: "{{{{ site_root }}}}/conf/request-header-gate.inc"
        owner: root
        group: redteam
        mode: "0640"
        force: false
        content: "client_max_body_size 500000000;\n# Barragan request-header gate is disabled.\n"

    - name: Write shared front OpenResty config
      ansible.builtin.copy:
        src: "../files/opt/web/nginx.conf"
        dest: "/opt/web/nginx.conf"
        owner: root
        group: redteam
        mode: "0664"

    - name: Write static web compose file
      ansible.builtin.copy:
        src: "../files/opt/web/docker-compose.yml"
        dest: "{{{{ compose_path }}}}"
        owner: root
        group: redteam
        mode: "0664"

    - name: Write selected site compose fragment
      ansible.builtin.copy:
        src: "../files/opt/web/sites/{intent.site_name}.compose.yml"
        dest: "{{{{ site_compose_path }}}}"
        owner: root
        group: redteam
        mode: "0664"

    - name: Write selected site HTTP route
      ansible.builtin.copy:
        src: "../files/opt/web/http/{intent.site_name}.map"
        dest: "/opt/web/http/{intent.site_name}.map"
        owner: root
        group: redteam
        mode: "0664"

    - name: Create web directory guide
      ansible.builtin.copy:
        dest: /opt/web/README.md
        owner: root
        group: redteam
        mode: "0644"
        force: false
        follow: false
        content: |
          # Web directory guide

          This proxy runs a shared web front and independent site containers.
          `<site>` is the Static Web site name, not necessarily its DNS hostname.
          A DNS or hostname change does not rename its directory.

          | Host path | Purpose |
          | --- | --- |
          | `/opt/web/<site>/html/` | Operator website files, including `index.html`. |
          | `/opt/web/<site>/conf/` | Generated HTTP site configuration. |
          | `/opt/web/<site>/tls-conf/` | Generated HTTPS site configuration. |
          | `/opt/web/sites/<site>.compose.yml` | Generated site container definition. |
          | `/opt/web/http/` and `/opt/web/tls/` | Generated hostname routing maps. |
          | `/opt/web/streams/` | Generated shared transport routes. |
          | `/opt/web/conf/` | Retained compatibility directory; active front maps use `http/`, `tls/`, `streams/`. |
          | `/opt/web/nginx.conf` | Generated shared front configuration. |
          | `/opt/web/docker-compose.yml` | Shared front container definition. |

          Site containers mount their host `html/` directory read-only at
          `/var/www/html/<site>/`; `conf/` or `tls-conf/` mounts read-only at
          `/etc/nginx/conf.d/` in separate HTTP/HTTPS containers. In the front container,
          `/opt/web/nginx.conf` mounts at `/usr/local/openresty/nginx/conf/nginx.conf`;
          host `http/`, `tls/` and `streams/` mount at `/etc/openresty/http/`,
          `/etc/openresty/tls/` and `/etc/openresty/streams/`, all read-only.
          These proxy paths differ from edge/middle transport `/etc/nginx/streams/`.
          The front owns public ports 80/443; site port 8081 is Docker-internal.
          This guide is outside the served content directories.

          Manage listeners, routing and certificates through Barragan. Manual edits to
          generated configuration can be overwritten. Keep website content in the selected
          site's `html/` directory and keep backups: Apply can publish supplied content and
          overwrite matching files. Other sites have independent content directories.

          Historical upstream deployments often use the literal domain as `<site>`.
          Barragan uses the independent site name shown in the UI; do not rename directories
          to match DNS. The separate `/dropbox` NFS share is not the website document root.

    - name: Check for the production front proxy container
      ansible.builtin.command:
        argv: [docker, inspect, proxy]
      register: front_proxy_container
      failed_when: false
      changed_when: false

    - name: Check production front proxy HTTPS host binding
      ansible.builtin.command:
        argv: [docker, port, proxy, 443/tcp]
      register: front_proxy_https_binding
      failed_when: false
      changed_when: false

    - name: Remove legacy front proxy without required host binding
      ansible.builtin.command:
        argv: "{{{{ barragan_compose_argv + ['-f', compose_path, 'rm', '-s', '-f', 'reverse-proxy'] }}}}"
      when: front_proxy_container.rc != 0 or front_proxy_https_binding.rc != 0 or (front_proxy_https_binding.stdout | trim | length == 0)

    - name: Remove existing shared front proxy before convergence
      ansible.builtin.command:
        argv: [docker, rm, -f, proxy]
      register: front_proxy_remove
      failed_when: front_proxy_remove.rc not in [0, 1]
      changed_when: front_proxy_remove.rc == 0

    - name: Converge production front proxy with required host listeners
      ansible.builtin.command:
        argv: "{{{{ barragan_compose_argv + ['-f', compose_path, 'up', '-d', 'reverse-proxy'] }}}}"

    - name: Wait for shared front proxy exec readiness
      ansible.builtin.command:
        argv: [docker, exec, proxy, "true"]
      register: front_proxy_exec_ready
      retries: 12
      delay: 5
      until: front_proxy_exec_ready.rc == 0
      changed_when: false

    - name: Remove the prior Barragan-owned selected site container when present
      ansible.builtin.command:
        argv: [docker, rm, -f, "{container_name}"]
      register: prior_site_remove
      failed_when: prior_site_remove.rc not in [0, 1]
      changed_when: prior_site_remove.rc == 0

    - name: Find renamed selected plaintext Compose containers
      ansible.builtin.command:
        argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", --filter, "label=com.docker.compose.service={intent.service_id.replace('-', '_')}"]
      register: prior_plaintext_compose_containers
      changed_when: false

    - name: Remove renamed selected plaintext Compose containers
      ansible.builtin.command:
        argv: [docker, rm, -f, "{{{{ item }}}}"]
      loop: "{{{{ prior_plaintext_compose_containers.stdout_lines }}}}"
      when: item | length > 0

    - name: Start selected site on the production proxy network
      ansible.builtin.command:
        argv: "{{{{ barragan_compose_argv + ['-f', compose_path, '-f', site_compose_path, 'up', '-d', '{intent.service_id.replace('-', '_')}'] }}}}"

    - name: Inspect retained TLS sibling configuration
      ansible.builtin.stat:
        path: "{{{{ item }}}}"
      loop:
        - "/opt/web/{intent.site_name}/tls-conf/default.conf"
        - "/opt/web/tls/{intent.site_name}.map"
        - "/opt/web/streams/{intent.site_name}.map"
      register: retained_tls_sibling

    - name: Refuse a partial retained TLS sibling
      ansible.builtin.assert:
        that:
          - retained_tls_sibling.results | selectattr('stat.exists') | list | length in [0, 2]
        fail_msg: Static Web TLS sibling state is incomplete; Barragan will preserve HTTP and refuse a partial TLS restore.

    - name: Remove retained TLS sibling before Static Web reapply start
      ansible.builtin.command:
        argv: [docker, rm, -f, "barragan_{intent.service_id.replace('-', '_')}_tls"]
      register: retained_tls_remove
      failed_when: retained_tls_remove.rc not in [0, 1]
      when: retained_tls_sibling.results | selectattr('stat.exists') | list | length == 2

    - name: Find renamed retained TLS Compose containers
      ansible.builtin.command:
        argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", --filter, "label=com.docker.compose.service={intent.service_id.replace('-', '_')}_tls"]
      register: retained_tls_compose_containers
      changed_when: false
      when: retained_tls_sibling.results | selectattr('stat.exists') | list | length == 2

    - name: Remove renamed retained TLS Compose containers
      ansible.builtin.command:
        argv: [docker, rm, -f, "{{{{ item }}}}"]
      loop: "{{{{ retained_tls_compose_containers.stdout_lines | default([]) }}}}"
      when: item | length > 0

    - name: Start retained TLS sibling after Static Web reapply
      ansible.builtin.command:
        argv: "{{{{ barragan_compose_argv + ['-f', compose_path, '-f', site_compose_path, 'up', '-d', '{intent.service_id.replace('-', '_')}_tls'] }}}}"
      when: retained_tls_sibling.results | selectattr('stat.exists') | list | length == 2

    - name: Validate shared front OpenResty configuration
      ansible.builtin.command:
        argv: [docker, exec, proxy, openresty, -t]

    - name: Reload shared front OpenResty routes
      ansible.builtin.command:
        argv: [docker, exec, proxy, openresty, -s, reload]

    - name: Validate selected site OpenResty configuration
      ansible.builtin.command:
        argv: [docker, exec, "{container_name}", openresty, -t]
      register: web_static_check
      changed_when: false

    - name: Assert selected site OpenResty configuration is valid
      ansible.builtin.assert:
        that:
          - web_static_check.rc == 0
        fail_msg: "Static web service configuration is invalid on the selected proxy."
"""
    return _wrap_static_apply_mutations(playbook, intent)


def _render_remove_playbook(intent: WebStaticIntent) -> str:
    container_name = f"barragan_{intent.service_id.replace('-', '_')}"
    return f"""---
- name: Remove Barragan static web service from selected proxy
  hosts: selected_proxy
  become: true
  gather_facts: false
  vars:
    site_name: "{intent.site_name}"
    compose_path: "/opt/web/docker-compose.yml"
    site_compose_path: "/opt/web/sites/{intent.site_name}.compose.yml"
    container_name: "{container_name}"
  tasks:
    - name: Detect Docker Compose v2
      ansible.builtin.command:
        argv: [docker, compose, version]
      register: barragan_compose_v2
      failed_when: false
      changed_when: false
    - name: Detect Docker Compose v1 fallback
      ansible.builtin.command:
        argv: [docker-compose, version]
      register: barragan_compose_v1
      when: barragan_compose_v2.rc != 0
      failed_when: false
      changed_when: false
    - name: Require a supported Docker Compose runtime
      ansible.builtin.assert:
        that:
          - barragan_compose_v2.rc == 0 or barragan_compose_v1.rc == 0
    - name: Select Docker Compose command
      ansible.builtin.set_fact:
        barragan_compose_argv: "{{{{ ['docker', 'compose'] if barragan_compose_v2.rc == 0 else ['docker-compose'] }}}}"
    - name: Verify exact Barragan ownership before selected site removal
      ansible.builtin.shell:
        cmd: |
          python3 - <<'PY'
          import json, pathlib, sys
          marker = pathlib.Path('/opt/web/.barragan-stack.json')
          expected = {{'managedBy': 'barragan', 'stackModel': 'containerized-openresty-v1'}}
          if not marker.is_file() or marker.is_symlink() or json.loads(marker.read_text()) != expected:
              sys.exit('shared proxy stack is not exact-owned by Barragan')
          checks = [
              ('/opt/web/http/{intent.site_name}.map', '{intent.domain} {intent.service_id.replace('-', '_')}:8081;'),
              ('/opt/web/tls/{intent.site_name}.map', '{intent.domain} {intent.service_id.replace('-', '_')}_tls:8081;'),
              ('/opt/web/streams/{intent.site_name}.map', '{intent.domain} {intent.service_id.replace('-', '_')}:8081;'),
          ]
          for value, target in checks:
              path = pathlib.Path(value)
              if not path.exists(): continue
              lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
              if path.is_symlink() or not lines or lines[-1] != target or not all(line.startswith('# Barragan-managed route ') for line in lines[:-1]):
                  sys.exit(f'route is not exact-owned: {{path}}')
          PY
      changed_when: false
    - name: Stop selected static web service when present
      ansible.builtin.command:
        argv: "{{{{ barragan_compose_argv + ['-f', compose_path, '-f', site_compose_path, 'rm', '-s', '-f', item] }}}}"
      loop:
        - "{intent.service_id.replace('-', '_')}"
        - "{intent.service_id.replace('-', '_')}_tls"
      failed_when: false

    - name: Remove Barragan generated static web config
      ansible.builtin.file:
        path: "{{{{ item }}}}"
        state: absent
      loop:
        - "{{{{ site_compose_path }}}}"
        - "/opt/web/{intent.site_name}/conf/default.conf"
        - "/opt/web/http/{intent.site_name}.map"
        - "/opt/web/tls/{intent.site_name}.map"
        - "/opt/web/streams/{intent.site_name}.map"
        - "/opt/web/{intent.site_name}/tls-conf/default.conf"

    - name: Preserve operator website content directory
      ansible.builtin.file:
        path: "/opt/web/{intent.site_name}/html"
        state: directory
        owner: root
        group: redteam
        mode: "0775"
"""


def _wrap_static_apply_mutations(playbook: str, intent: WebStaticIntent) -> str:
    anchor = "    - name: Ensure Docker service is running\n"
    prefix, mutations = playbook.split(anchor, 1)
    staging_anchor = "    - name: Create private content operation directory\n"
    prefix, staging = prefix.split(staging_anchor, 1)
    staging = staging_anchor + staging
    indented_staging = "\n".join("    " + line if line else line for line in staging.splitlines())
    mutations = anchor + mutations
    operation_root = re.search(r'content_operation_root: "([^"]+)"', playbook).group(1)
    backup_root = operation_root + "/runtime-backup"
    paths = [
        "/opt/web/nginx.conf",
        "/opt/web/docker-compose.yml",
        "/opt/web/.barragan-stack.json",
        "/opt/web/README.md",
        f"/opt/web/sites/{intent.site_name}.compose.yml",
        f"/opt/web/{intent.site_name}/conf",
        f"/opt/web/{intent.site_name}/tls-conf",
        f"/opt/web/http/{intent.site_name}.map",
        f"/opt/web/tls/{intent.site_name}.map",
        f"/opt/web/streams/{intent.site_name}.map",
    ]
    path_literals = repr(paths)
    service = intent.service_id.replace("-", "_")
    indented = "\n".join(f"    {line}" if line else line for line in mutations.splitlines())
    return prefix + f'''    - name: Record prior selected container state
      ansible.builtin.command:
        argv: [docker, inspect, -f, "{{% raw %}}{{{{.State.Running}}}}{{% endraw %}}", "{{{{ item }}}}"]
      loop: [proxy, barragan_{service}, barragan_{service}_tls]
      register: prior_static_containers
      failed_when: false
      changed_when: false

    - name: Apply selected Static Web runtime transactionally
      block:
{indented_staging}
        - name: Snapshot exact selected runtime files
          ansible.builtin.shell:
            cmd: |
              python3 - <<'PY'
              import json, pathlib, shutil
              backup = pathlib.Path({backup_root!r})
              paths = [pathlib.Path(value) for value in {path_literals}]
              shutil.rmtree(backup, ignore_errors=True)
              backup.mkdir(parents=True)
              existing = []
              for source in paths:
                  if not source.exists() and not source.is_symlink():
                      continue
                  existing.append(str(source))
                  target = backup / source.relative_to('/')
                  target.parent.mkdir(parents=True, exist_ok=True)
                  if source.is_dir() and not source.is_symlink():
                      shutil.copytree(source, target, symlinks=True)
                  else:
                      shutil.copy2(source, target, follow_symlinks=False)
              (backup / 'manifest.json').write_text(json.dumps(existing))
              PY
        - name: Migrate exact-owned legacy Static Web route
          ansible.builtin.shell:
            cmd: |
              set -eu
              legacy=/opt/web/streams/{intent.site_name}.map
              test -e "$legacy" || exit 0
              if grep -Fq 'listen 8081 proxy_protocol ssl;' /opt/web/{intent.site_name}/conf/default.conf; then
                mkdir -p /opt/web/{intent.site_name}/tls-conf /opt/web/tls
                mv /opt/web/{intent.site_name}/conf/default.conf /opt/web/{intent.site_name}/tls-conf/default.conf
                for name in 00-barragan-observability.conf 00-request-header-gate-00-runtime.conf 00-request-header-gate-map.conf request-header-gate.inc; do
                  test ! -e "/opt/web/{intent.site_name}/conf/$name" || mv "/opt/web/{intent.site_name}/conf/$name" "/opt/web/{intent.site_name}/tls-conf/$name"
                done
                printf '%s\\n' '{intent.domain} {service}_tls:8081;' > /opt/web/tls/{intent.site_name}.map
              fi
              rm -f "$legacy"
{indented}
      rescue:
        - name: Roll back only this operation's unchanged content writes
          ansible.builtin.script:
            cmd: "../helpers/static_web_content.py {{{{ content_operation_root }}}}/rollback.json"
            executable: python3
          register: static_content_rollback
          failed_when: false
        - name: Record website content rollback outcome
          ansible.builtin.debug:
            msg: "BARRAGAN_STATIC_CONTENT_ROLLBACK_RC={{{{ static_content_rollback.rc | default(-1) }}}}"
        - name: Restore exact selected runtime files
          ansible.builtin.shell:
            cmd: |
              python3 - <<'PY'
              import json, pathlib, shutil
              backup = pathlib.Path({backup_root!r})
              paths = [pathlib.Path(value) for value in {path_literals}]
              manifest = backup / 'manifest.json'
              if not manifest.exists(): raise SystemExit(0)
              existing = set(json.loads(manifest.read_text()))
              for target in paths:
                  # An authorized first apply can leave operator uploads or
                  # empty site directories. Keep its exact new ownership marker
                  # so a failed apply remains inspectable and recoverable.
                  if target.name == '.barragan-stack.json' and str(target) not in existing and target.is_file() and not target.is_symlink():
                      if json.loads(target.read_text()) == {{"managedBy": "barragan", "stackModel": "containerized-openresty-v1"}}:
                          continue
                  if target.is_dir() and not target.is_symlink(): shutil.rmtree(target)
                  elif target.exists() or target.is_symlink(): target.unlink()
                  if str(target) not in existing: continue
                  source = backup / target.relative_to('/')
                  target.parent.mkdir(parents=True, exist_ok=True)
                  if source.is_dir() and not source.is_symlink(): shutil.copytree(source, target, symlinks=True)
                  else: shutil.copy2(source, target, follow_symlinks=False)
              PY
        - name: Remove candidate selected containers before rollback convergence
          ansible.builtin.command:
            argv: [docker, rm, -f, "{{{{ item }}}}"]
          loop: [proxy, barragan_{service}, barragan_{service}_tls]
          register: rollback_container_remove
          failed_when: rollback_container_remove.rc not in [0, 1]
        - name: Find renamed selected Compose containers before rollback
          ansible.builtin.command:
            argv: [docker, ps, -aq, --filter, "label=com.docker.compose.project=web", --filter, "label=com.docker.compose.service={{{{ item }}}}"]
          loop: [reverse-proxy, {service}, {service}_tls]
          register: rollback_compose_containers
          changed_when: false
        - name: Remove renamed selected Compose containers before rollback
          ansible.builtin.command:
            argv: [docker, rm, -f, "{{{{ item.1 }}}}"]
          loop: "{{{{ rollback_compose_containers.results | map(attribute='stdout_lines') | flatten }}}}"
          when: item | length > 0
        - name: Restore prior front proxy container
          ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', compose_path, 'up', '-d', 'reverse-proxy'] }}}}"
          when: prior_static_containers.results[0].rc == 0
        - name: Restore prior plaintext sibling container
          ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', compose_path, '-f', site_compose_path, 'up', '-d', '{service}'] }}}}"
          when: prior_static_containers.results[1].rc == 0
        - name: Restore prior TLS sibling container
          ansible.builtin.command:
            argv: "{{{{ barragan_compose_argv + ['-f', compose_path, '-f', site_compose_path, 'up', '-d', '{service}_tls'] }}}}"
          when: prior_static_containers.results[2].rc == 0
        - name: Wait for restored selected container readiness
          ansible.builtin.command:
            argv: [docker, exec, "{{{{ item.item }}}}", "true"]
          loop: "{{{{ prior_static_containers.results }}}}"
          when: item.rc == 0
          register: restored_static_readiness
          retries: 12
          delay: 5
          until: restored_static_readiness.rc == 0
          changed_when: false
        - name: Validate restored selected OpenResty configuration
          ansible.builtin.command:
            argv: [docker, exec, "{{{{ item.item }}}}", openresty, -t]
          loop: "{{{{ prior_static_containers.results }}}}"
          when: item.rc == 0
          changed_when: false
        - name: Return previously stopped containers to stopped state
          ansible.builtin.command:
            argv: [docker, stop, "{{{{ item.item }}}}"]
          loop: "{{{{ prior_static_containers.results }}}}"
          when: item.rc == 0 and item.stdout | trim != 'true'
        - name: Inspect restored selected container state
          ansible.builtin.command:
            argv: [docker, inspect, -f, "{{% raw %}}{{{{.State.Running}}}}{{% endraw %}}", "{{{{ item.item }}}}"]
          loop: "{{{{ prior_static_containers.results }}}}"
          when: item.rc == 0
          register: restored_static_containers
          changed_when: false
        - name: Require exact prior selected container state after rollback
          ansible.builtin.assert:
            that:
              - item.rc == 0
              - item.stdout | trim == item.item.stdout | trim
          loop: "{{{{ restored_static_containers.results | selectattr('skipped', 'undefined') | list }}}}"
        - name: Require previously absent selected containers to remain absent
          ansible.builtin.command:
            argv: [docker, inspect, "{{{{ item.item }}}}"]
          loop: "{{{{ prior_static_containers.results }}}}"
          when: item.rc != 0
          register: absent_static_containers
          failed_when: absent_static_containers.rc == 0
          changed_when: false
        - ansible.builtin.fail:
            msg: "Static Web apply failed. Runtime restoration completed. Content rollback: {{{{ static_content_rollback.stdout | default('unknown; inspect job evidence') }}}}"

      always:
        - ansible.builtin.file:
            path: "{{{{ content_operation_root }}}}"
            state: absent
          when: static_content_rollback is not defined or (static_content_rollback.rc | default(1)) == 0
        - ansible.builtin.debug:
            msg: "Content rollback needs review; private operation journal retained at {{{{ content_operation_root }}}}."
          when: static_content_rollback is defined and (static_content_rollback.rc | default(1)) != 0
        - ansible.builtin.file:
            path: {backup_root}
            state: absent
'''


def _render_manifest(intent: WebStaticIntent, homebase: WebStaticCoreHost, proxy: WebStaticCoreHost) -> str:
    return json.dumps(
        {
            "mode": "web_static_service_apply_preview",
            "mutation": False,
            "service": intent.to_dict(),
            "targets": {
                "selectedProxy": proxy.to_dict(),
                "homebaseJump": homebase.to_dict(),
            },
            "opsecBoundary": {
                "inventoryTargets": ["selected_proxy"],
                "sketchMiddleTargets": [],
                "sketchEdgeTargets": [],
                "reason": "Static web service configuration targets proxy hosts only; inbound channels bind edge/middle routing separately.",
            },
            "paths": {
                "content": f"/opt/web/{intent.site_name}/html/",
                "index": f"/opt/web/{intent.site_name}/html/index.html",
                "siteConfig": f"/opt/web/{intent.site_name}/conf/default.conf",
                "compose": "/opt/web/docker-compose.yml",
                "siteCompose": f"/opt/web/sites/{intent.site_name}.compose.yml",
                "frontProxyReference": f"/opt/web/http/{intent.site_name}.map",
                "tlsProxyReference": f"/opt/web/tls/{intent.site_name}.map",
            },
            "contentFiles": [content_file.to_metadata() for content_file in intent.content_files],
            "recommendedInboundBinding": {
                "service": WEB_STATIC_SERVICE_NAME,
                "terminatesOn": intent.proxy_id,
                "internalPort": "80",
                "mode": "http-openresty",
                "validationProfile": {
                    "type": "http",
                    "label": "HTTP route check",
                    "requestText": f"GET / HTTP/1.1\\r\\nHost: {intent.domain}\\r\\nConnection: close\\r\\n\\r\\n",
                    "expectedResponse": "<html",
                },
            },
        },
        indent=2,
        sort_keys=True,
    )


def _render_remove_manifest(intent: WebStaticIntent, homebase: WebStaticCoreHost, proxy: WebStaticCoreHost) -> str:
    return json.dumps(
        {
            "mode": "web_static_service_remove_preview",
            "mutation": False,
            "service": intent.to_dict(),
            "targets": {
                "selectedProxy": proxy.to_dict(),
                "homebaseJump": homebase.to_dict(),
            },
            "opsecBoundary": {
                "inventoryTargets": ["selected_proxy"],
                "sketchMiddleTargets": [],
                "sketchEdgeTargets": [],
                "reason": "Static web service removal targets proxy hosts only and preserves operator-owned website files.",
            },
            "removePaths": {
                "siteCompose": f"/opt/web/sites/{intent.site_name}.compose.yml",
                "siteConfig": f"/opt/web/{intent.site_name}/conf/default.conf",
                "frontProxyReference": f"/opt/web/http/{intent.site_name}.map",
                "tlsProxyReference": f"/opt/web/tls/{intent.site_name}.map",
            },
            "preservedPaths": {
                "contentDirectory": f"/opt/web/{intent.site_name}/html",
            },
        },
        indent=2,
        sort_keys=True,
    )


def _render_site_config(intent: WebStaticIntent) -> str:
    return f"""server {{
    listen 8081;
    server_name {intent.domain};
    root /var/www/html/{intent.site_name};
    index index.html;
    include /etc/nginx/conf.d/request-header-gate*.inc;

    location / {{
        try_files $uri $uri/ /index.html;
    }}
}}
"""


def _render_compose() -> str:
    return """services:
  reverse-proxy:
    image: openresty/openresty:latest
    container_name: proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/web/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro
      - /opt/web/http:/etc/openresty/http:ro
      - /opt/web/streams:/etc/openresty/streams:ro
      - /opt/web/tls:/etc/openresty/tls:ro
      - certbot-etc:/etc/letsencrypt
    networks:
      - web_webnet
volumes:
  certbot-etc:
networks:
  web_webnet:
"""


def _render_site_compose(intent: WebStaticIntent) -> str:
    service_name = intent.service_id.replace("-", "_")
    return f"""services:
  {service_name}:
    image: openresty/openresty:latest
    container_name: barragan_{service_name}
    restart: unless-stopped
    expose:
      - "8081"
    volumes:
      - /opt/web/{intent.site_name}/conf:/etc/nginx/conf.d:ro
      - /opt/web/{intent.site_name}/html:/var/www/html/{intent.site_name}:ro
      - certbot-etc:/etc/letsencrypt
    networks:
      - web_webnet
  {service_name}_tls:
    image: openresty/openresty:latest
    container_name: barragan_{service_name}_tls
    restart: unless-stopped
    expose:
      - "8081"
    volumes:
      - /opt/web/{intent.site_name}/tls-conf:/etc/nginx/conf.d:ro
      - /opt/web/{intent.site_name}/html:/var/www/html/{intent.site_name}:ro
      - certbot-etc:/etc/letsencrypt
    networks:
      - web_webnet
volumes:
  certbot-etc:
networks:
  web_webnet:
"""


def _render_front_http_config() -> str:
    return """# Managed by Barragan containerized OpenResty proxy stack.
user www-data;
worker_processes auto;
events { worker_connections 1024; }
http {
    map $host $barragan_http_backend {
        include /etc/openresty/http/*.map;
        default 127.0.0.1:9;
    }
    server {
        listen 80 proxy_protocol;
        server_name _;
        resolver 127.0.0.11;
        client_max_body_size 10240000000;
        location / {
            proxy_request_buffering off;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $proxy_protocol_addr;
            proxy_set_header X-Forwarded-For $proxy_protocol_addr;
            proxy_set_header X-Forwarded-Proto http;
            proxy_pass http://$barragan_http_backend;
        }
    }
}
stream {
    map $ssl_preread_server_name $barragan_tls_backend {
        include /etc/openresty/streams/*.map;
        include /etc/openresty/tls/*.map;
        default 127.0.0.1:9;
    }
    server {
        listen 443 proxy_protocol;
        resolver 127.0.0.11;
        ssl_preread on;
        proxy_protocol on;
        proxy_pass $barragan_tls_backend;
    }
}
"""


def _render_front_route(intent: WebStaticIntent) -> str:
    service_name = intent.service_id.replace("-", "_")
    return f"{intent.domain} {service_name}:8081;\n"


def _save_preview_job(
    repository: JobRepository,
    engagement_id: str,
    requested_by: str,
    intent: WebStaticIntent,
    workspace: WebStaticApplyWorkspace,
    content_review: dict[str, Any] | None = None,
) -> StoredJobRun:
    timestamp = _now()
    return repository.save(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=WEB_STATIC_APPLY_PREVIEW_ACTION,
            status="succeeded",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "serviceId": intent.service_id, "serviceType": WEB_STATIC_SERVICE_TYPE, "contentReview": content_review or {}, "mutation": False},
            artifact_refs=["ansible/inventory.ini", "ansible/apply_web_static.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=timestamp,
            events=[
                JobEvent(
                    1,
                    "info",
                    "static web service apply preview rendered",
                    {
                        "service": intent.to_dict(),
                        "workspace": workspace.to_dict(),
                        "workspaceEvidence": _workspace_evidence(workspace),
                        "mutation": False,
                    },
                )
            ],
        )
    )


def _save_remove_preview_job(
    repository: JobRepository,
    engagement_id: str,
    requested_by: str,
    intent: WebStaticIntent,
    workspace: WebStaticRemoveWorkspace,
    confirmation: str,
) -> StoredJobRun:
    timestamp = _now()
    return repository.save(
        StoredJobRun(
            id=f"job-{uuid4().hex[:12]}",
            action=WEB_STATIC_REMOVE_PREVIEW_ACTION,
            status="succeeded",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by=requested_by,
            input={"engagementId": engagement_id, "serviceId": intent.service_id, "serviceType": WEB_STATIC_SERVICE_TYPE, "mutation": False},
            artifact_refs=["ansible/inventory.ini", "ansible/remove_web_static.yml", "MANIFEST.json"],
            created_at=timestamp,
            started_at=timestamp,
            finished_at=timestamp,
            events=[
                JobEvent(
                    1,
                    "info",
                    "static web service remove preview rendered",
                    {
                        "service": intent.to_dict(),
                        "workspace": workspace.to_dict(),
                        "workspaceEvidence": _remove_workspace_evidence(workspace),
                        "confirmationToken": confirmation,
                        "mutation": False,
                    },
                )
            ],
        )
    )


def _write_workspace(workspace: WebStaticApplyWorkspace, root: Path, site_name: str) -> Path:
    workspace_dir = root / f"{site_name}-{uuid4().hex[:12]}"
    for artifact in (
        workspace.inventory,
        workspace.playbook,
        workspace.manifest,
        *workspace.content_files,
        workspace.site_config,
        workspace.site_observability_config,
        workspace.compose,
        workspace.site_compose,
        workspace.front_http_config,
        workspace.front_route,
        *workspace.sensitive_artifacts,
    ):
        path = workspace_dir / artifact.target
        artifact.write_to(path)
        if artifact in workspace.sensitive_artifacts:
            os.chmod(path, 0o600)
    return workspace_dir


def _scrub_retained_request_header_gate_files(workspace_dir: Path) -> None:
    files_root = workspace_dir / "files" / "opt" / "web"
    if not files_root.exists():
        return
    for path in files_root.glob("*/conf/*request-header-gate*"):
        try:
            path.unlink()
        except OSError:
            pass


def _discard_web_static_execution_workspace(workspace_dir: Path) -> None:
    _scrub_retained_request_header_gate_files(workspace_dir)
    shutil.rmtree(workspace_dir, ignore_errors=True)


def _write_remove_workspace(workspace: WebStaticRemoveWorkspace, root: Path, site_name: str) -> Path:
    workspace_dir = root / f"{site_name}-remove-{uuid4().hex[:12]}"
    for artifact in (
        workspace.inventory,
        workspace.playbook,
        workspace.manifest,
    ):
        path = workspace_dir / artifact.target
        artifact.write_to(path)
    return workspace_dir


def _workspace_evidence(workspace: WebStaticApplyWorkspace) -> dict[str, dict[str, object]]:
    return {
        "inventory": _artifact_evidence(workspace.inventory),
        "playbook": _artifact_evidence(workspace.playbook),
        "manifest": _artifact_evidence(workspace.manifest),
        "siteIndex": _artifact_evidence(workspace.site_index),
        "contentFiles": [_artifact_evidence(artifact) for artifact in workspace.content_files],
        "siteConfig": _artifact_evidence(workspace.site_config),
        "siteObservabilityConfig": _artifact_evidence(workspace.site_observability_config),
        "compose": _artifact_evidence(workspace.compose),
        "siteCompose": _artifact_evidence(workspace.site_compose),
        "frontHttpConfig": _artifact_evidence(workspace.front_http_config),
        "frontRoute": _artifact_evidence(workspace.front_route),
    }


def _remove_workspace_evidence(workspace: WebStaticRemoveWorkspace) -> dict[str, dict[str, object]]:
    return {
        "inventory": _artifact_evidence(workspace.inventory),
        "playbook": _artifact_evidence(workspace.playbook),
        "manifest": _artifact_evidence(workspace.manifest),
    }


def _artifact_evidence(artifact: RenderedWebStaticArtifact) -> dict[str, object]:
    return {
        "path": artifact.target,
        "bytes": artifact.byte_length(),
        "encoding": artifact.encoding,
    }


def _service_placement(intent: WebStaticIntent, *, status: str) -> dict[str, Any]:
    return {
        "hostId": intent.proxy_id,
        "hostRole": "proxy",
        "service": WEB_STATIC_SERVICE_NAME,
        "status": status,
        "port": str(intent.internal_port),
        "detail": _service_detail(intent, status),
        "serviceId": intent.service_id,
        "serviceType": WEB_STATIC_SERVICE_TYPE,
        "domain": intent.domain,
        "siteName": intent.site_name,
    }


def _service_detail(intent: WebStaticIntent, status: str) -> str:
    if status == "Configured":
        return f"Static web site {intent.site_name} is configured behind the shared proxy front (site container :{intent.internal_port})."
    if status == "Failed":
        return f"Static web site {intent.site_name} apply failed."
    if status == "Applying":
        return f"Static web site {intent.site_name} apply is running."
    if status == "Removing":
        return f"Static web site {intent.site_name} removal is running; content under /opt/web/{intent.site_name}/html is preserved."
    if status == "Removed":
        return f"Static web site {intent.site_name} generated config is removed; content under /opt/web/{intent.site_name}/html is preserved."
    if status == "Remove Failed":
        return f"Static web site {intent.site_name} removal failed."
    return f"Static web site {intent.site_name} apply has not run yet."


def _run_guarded_command(command: list[str], cwd: Path, runner: CommandRunner | None) -> DisposableCommandResult:
    if runner is None:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=barragan_subprocess_env(),
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        completed = runner(command, cwd)
    return DisposableCommandResult(
        command=list(command),
        cwd=str(cwd),
        returncode=int(completed.returncode),
        stdout=str(completed.stdout or ""),
        stderr=str(completed.stderr or ""),
        ok=int(completed.returncode) == 0,
    )


def _content_outcome(output: str) -> str:
    match = re.search(r"BARRAGAN_STATIC_CONTENT_OUTCOME=(preserved|initialized|restored-starter|published)\b", output)
    return match.group(1) if match else "not-recorded"


def _content_rollback_outcome(output: str) -> str:
    match = re.search(r"BARRAGAN_STATIC_CONTENT_ROLLBACK_RC=(-?[0-9]+)", output)
    return ("verified" if match.group(1) == "0" else "failed") if match else "not-recorded"


def _safe_command_result(result: DisposableCommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "cwd": result.cwd,
        "returncode": result.returncode,
        "ok": result.ok,
        "stdout": _sanitize_output(result.stdout),
        "stderr": _sanitize_output(result.stderr),
    }


def _sanitize_output(value: str) -> str:
    text = str(value or "")
    if len(text) > 4000:
        text = text[:4000] + "\n[truncated]"
    for pattern, replacement in SECRET_OUTPUT_REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _validate_core_hosts(homebase: WebStaticCoreHost, proxy: WebStaticCoreHost) -> None:
    errors = []
    if homebase.name != "homebase":
        errors.append("homebase host name must be homebase")
    if not _is_proxy_id(proxy.name):
        errors.append("proxy host name must look like proxy01")
    if not homebase.ansible_host:
        errors.append("homebase ansible_host is required")
    if not proxy.ansible_host:
        errors.append("proxy ansible_host is required")
    if not proxy.proxy_jump:
        errors.append("proxy target must be reached through homebase ProxyCommand")
    if errors:
        raise WebStaticServiceValidationError(errors)


def _entry_matches_proxy(entry: dict[str, Any], proxy_id: str) -> bool:
    role = str(entry.get("role") or "")
    display = str(entry.get("displayName") or entry.get("sshAlias") or "")
    return role in {"proxy", proxy_id} and (display == proxy_id or display.startswith(f"{proxy_id}-"))


def _entry_user(entry: dict[str, Any]) -> str:
    return str(entry.get("sshUser") or "user")


def _required_text(entry: dict[str, Any], key: str) -> str:
    return str(entry.get(key) or "").strip()


def _is_proxy_id(value: str) -> bool:
    return bool(value) and value.startswith("proxy") and len(value) == 7 and value[-2:].isdigit()


def _core_ssh_private_key_path() -> str:
    return os.environ.get(CORE_SSH_KEY_ENV, DEFAULT_CORE_SSH_PRIVATE_KEY)


def _known_hosts_file(engagement_id: str, deployment_id: str = "unknown-core") -> str:
    return deployment_known_hosts_file(DEFAULT_KNOWN_HOSTS_ROOT, engagement_id, deployment_id)


def _ensure_known_hosts_file(path: str) -> None:
    ensure_known_hosts_file(path)


def _slug(value: Any) -> str:
    text = re.sub(r"[./\\]+", "_", str(value or "").lower())
    slug = re.sub(r"[^a-z0-9_-]+", "-", text).strip("-_")
    return slug or "web-static"


def _remove_confirmation_token(intent: WebStaticIntent) -> str:
    return f"remove-web-{intent.site_name}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _contains_forbidden_marker(value: str) -> bool:
    lowered = value.lower()
    return any(marker.lower() in lowered for marker in SECRET_MARKERS)


def _assert_no_forbidden_markers(value: str, label: str) -> None:
    if _contains_forbidden_marker(value):
        raise WebStaticServiceValidationError([f"{label} appears to contain secret material"])


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-web-static-service-runner")
