# Copyright (c) 2026, Oracle and/or its affiliates.
"""DevTest-only, non-applying plan job for fresh DigitalOcean keyed Sketch.

The caller creates a queued job and holds its engagement mutation lease. This
runner reads the reviewed records again; its job input is never Terraform input.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from app.domain import JobEvent
from app.services.provider_keyed_runtime_preflight import preflight_fresh_digitalocean_provider
from app.services.provider_keyed_review_authorization import require_fresh_digitalocean_review_authorization
from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION
from app.services.provider_keyed_saved_plan_runner import prepare_digitalocean_keyed_initial_full_plan
from app.services.provider_keyed_sketch import (
    prepare_provider_keyed_workspace,
    reserve_provider_topology,
    resolve_default_provider_connection,
)
from app.services.provider_keyed_terraform_release import require_devtest_terraform_release
from app.services.sketch_ssh_keys import ensure_sketch_ssh_key, retrieve_sketch_ssh_key
from app.services.sketch_transport_ssh_keys import (
    ensure_sketch_transport_ssh_key, retrieve_sketch_transport_ssh_key,
)
from app.storage.credential_repository import CredentialRepository, SqlAlchemyCredentialRepository
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun


ACTION = "provider_keyed_initial_plan"
SOURCE_REVISION = _SOURCE_REVISION


class ProviderKeyedInitialPlanJobError(ValueError):
    """Plan job input or reviewed records are unavailable."""


def run_fresh_digitalocean_initial_plan_job(
    job_id: str,
    *,
    lease_owner: str,
    environment: str,
    state_root: Path,
    template_root: Path,
    lease_lookup=None,
    job_repository: JobRepository | None = None,
    credential_repository: CredentialRepository | None = None,
    ssh_key_repository=None,
    engagement_repository=None,
    sketch_repository=None,
    plan_repository=None,
) -> StoredJobRun:
    """Save exact initial plan evidence; never run Terraform apply.

    The stable key path is kept as an empty private directory between plan
    and apply. A later apply runner must recreate the *same* reviewed key at
    that path, compare its digest with this evidence, and then remove it.
    """

    jobs = job_repository or SqlAlchemyJobRepository()
    credentials = credential_repository or SqlAlchemyCredentialRepository()
    job = jobs.get(job_id)
    if (environment != "devtest" or job is None or job.id != job_id
            or job.action != ACTION or job.status != "queued"
            or not isinstance(lease_owner, str) or not lease_owner.strip()
            or job.target_type != "engagement" or job.target_id != job.input.get("engagementId")
            or not isinstance(job.input.get("coreJobId"), str)
            or set(job.input) != {"engagementId", "coreJobId", "mutation"}
            or job.input.get("mutation") is not False):
        raise ProviderKeyedInitialPlanJobError("queued DevTest provider plan job is invalid")
    now = _now()
    running = jobs.save(replace(job, status="running", started_at=now, events=[
        *job.events, JobEvent(len(job.events) + 1, "info", "provider plan preflight started", {}),
    ]))
    try:
        intent = preflight_fresh_digitalocean_provider(
            running.target_id, running.input["coreJobId"], lease_owner=lease_owner,
            environment=environment, state_root=state_root,
            engagement_repository=engagement_repository, sketch_repository=sketch_repository,
            job_repository=jobs, plan_repository=plan_repository, lease_lookup=lease_lookup,
        )
        if intent.core_plan_id != lease_owner or intent.core_job_id != running.input["coreJobId"]:
            raise ProviderKeyedInitialPlanJobError("preflight intent does not match queued core identity")
        connection_id = resolve_default_provider_connection("digitalocean", repository=credentials)
        plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
        require_fresh_digitalocean_review_authorization(
            intent, plans.get(intent.core_plan_id), connection_id=connection_id,
            credential_repository=credentials,
        )
        release = require_devtest_terraform_release(environment=environment)
        workspace = prepare_provider_keyed_workspace(
            intent.engagement_id, "digitalocean", connection_id,
            template_root=template_root, source_revision=SOURCE_REVISION,
            root=state_root, environment=environment, deployment_target="barragan-testing",
        )
        _write_plan_owner_marker(workspace.path, {
            "schema": "provider-keyed-v2", "engagementId": intent.engagement_id,
            "provider": "digitalocean", "providerConnectionId": connection_id,
            "coreJobId": intent.core_job_id, "planJobId": running.id,
            "sourceRevision": SOURCE_REVISION,
        })
        if reserve_provider_topology(
            workspace, intent.topology["middles"], intent.topology["edge_groups"],
        ) != intent.topology:
            raise ProviderKeyedInitialPlanJobError("reserved provider topology differs from reviewed intent")
        material = retrieve_sketch_ssh_key(intent.engagement_id, ssh_key_repository)
        if material is None:
            # A fresh v2 draft has no Sketch key yet. The caller's engagement
            # lease serializes this one-time durable key creation.
            ensure_sketch_ssh_key(intent.engagement_id, ssh_key_repository)
            material = retrieve_sketch_ssh_key(intent.engagement_id, ssh_key_repository)
        if material is None or not material.private_key or not material.public_key:
            raise ProviderKeyedInitialPlanJobError("stored Sketch administration key is unavailable")
        # The later bootstrap only materializes an existing transport key. Its
        # durable identity must therefore be created while this plan owns the
        # engagement lease, before any provider apply or host contact.
        transport = retrieve_sketch_transport_ssh_key(intent.engagement_id)
        if transport is None:
            ensure_sketch_transport_ssh_key(intent.engagement_id)
            transport = retrieve_sketch_transport_ssh_key(intent.engagement_id)
        if transport is None or not transport.private_key or not transport.public_key:
            raise ProviderKeyedInitialPlanJobError("stored Sketch transport key is unavailable")
        material_parent = workspace.path.parents[1] / ".plan-material"
        _prepare_private_material_directory(material_parent)
        material_dir = material_parent / "digitalocean"
        _prepare_private_material_directory(material_dir)
        private = material_dir / "admin-private"
        public = material_dir / "admin-public"
        output_dir = material_dir / "ssh-output"
        _prepare_private_material_directory(output_dir)
        inputs = material_dir / "inputs.json"
        if any(os.path.lexists(path) for path in (private, public, inputs)):
            raise ProviderKeyedInitialPlanJobError("provider plan material already exists")
        public_digest = hashlib.sha256(material.public_key.encode("utf-8")).hexdigest()
        try:
            _write_private_new(private, material.private_key)
            _write_private_new(public, material.public_key)
            varfile = {
                **intent.nonsecret_varfile,
                "ssh_priv_key_path": str(private),
                "ssh_pub_key_path": str(public),
                "ssh_config_path": str(output_dir),
            }
            _write_private_new(inputs, json.dumps(varfile, sort_keys=True) + "\n")
            inventory = _expected_inventory(intent, private)
            local_files = {
                "local_file.ansible_inventory[0]": _local_file("inventory.ini", inventory),
                "local_file.ssh_stanza[0]": _local_file(
                    str(output_dir / f"{intent.engagement_name}-sketch"), None,
                ),
            }
            evidence = prepare_digitalocean_keyed_initial_full_plan(
                workspace, environment=environment, deployment_target="barragan-testing",
                expected_connection_id=connection_id,
                input_sha256={inputs: hashlib.sha256(inputs.read_bytes()).hexdigest()},
                var_files=[inputs], expected_nodes=intent.nodes,
                expected_ssh_key_name="do-key", expected_ssh_public_key=material.public_key.strip(),
                expected_firewall=intent.firewall, expected_local_files=local_files,
                credential_repository=credentials, command_environment=os.environ,
                expected_terraform_sha256=release.sha256, terraform=str(release.path),
            )
        finally:
            private.unlink(missing_ok=True)
            public.unlink(missing_ok=True)
        result = {
            "coreJobId": intent.core_job_id, "corePlanId": intent.core_plan_id,
            "revisionId": intent.revision_id, "providerConnectionId": connection_id,
            "selectorTag": intent.selector_tag, "sourceRevision": SOURCE_REVISION,
            "planPath": str(evidence.plan_path), "planSha256": evidence.plan_sha256,
            "sourceSha256": evidence.source_sha256, "markerSha256": evidence.marker_sha256,
            "topologySha256": evidence.topology_sha256,
            "lockfileSha256": evidence.lockfile_sha256,
            "inputSha256": list(evidence.input_sha256),
            "credentialSecretSha256": evidence.credential_secret_sha256,
            "credentialUpdatedAt": evidence.credential_updated_at,
            "terraformBinaryPath": str(evidence.terraform_binary_path),
            "terraformBinarySha256": evidence.terraform_binary_sha256,
            "terraformVersion": evidence.terraform_version,
            "adminPublicKeySha256": public_digest,
            "adminPrivateKeyPath": str(private), "adminPublicKeyPath": str(public),
            "sshOutputDirectory": str(output_dir),
        }
        return jobs.save(replace(running, status="succeeded", finished_at=_now(),
            artifact_refs=[str(evidence.plan_path)], events=[*running.events,
                JobEvent(len(running.events) + 1, "info", "reviewed provider plan saved", result)]))
    except Exception:
        jobs.save(replace(running, status="failed", finished_at=_now(), events=[*running.events,
            JobEvent(len(running.events) + 1, "error", "provider plan preparation failed", {})]))
        raise ProviderKeyedInitialPlanJobError("provider plan preparation failed") from None


def _prepare_private_material_directory(path: Path) -> None:
    if not path.is_absolute() or path.resolve(strict=False) != path:
        raise ProviderKeyedInitialPlanJobError("provider plan material path is unsafe")
    if os.path.lexists(path):
        info = path.lstat()
        # A setgid parent may pass setgid to a newly created private directory.
        # Mode 2700 is still owner-only; no group access is granted.
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) not in {0o700, 0o2700}):
            raise ProviderKeyedInitialPlanJobError("provider plan material directory is unsafe")
    else:
        path.mkdir(mode=0o700)


def _write_private_new(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def _write_plan_owner_marker(root: Path, payload: dict[str, str]) -> None:
    """Durably bind a fresh workspace to its one plan job before reservation."""
    path = root / ".barragan-initial-plan-owner.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _local_file(filename: str, content: str | None) -> dict[str, object]:
    result: dict[str, object] = {
        "content_base64": None, "directory_permission": "0777",
        "file_permission": "0600", "filename": filename,
        "sensitive_content": None, "source": None,
    }
    if content is not None:
        result["content"] = content
    return result


def _expected_inventory(intent, private: Path) -> str:
    """Render the audited inventory template's exact stable, known fields."""
    middles = [intent.nodes[f'digitalocean_droplet.middle["{key}"]'].name
               for key in sorted(intent.topology["middles"])]
    # Audited upstream keyed mode uses sort(keys(local.edge_nodes)).
    edges = [intent.nodes[f'digitalocean_droplet.edge["{key}"]'].name
             for key in sorted({f'{group["region"]}-{number:02d}'
                                for group in intent.topology["edge_groups"].values()
                                for number in group["ordinals"]})]
    return (
        "[all:vars]\ninfra_user=ubuntu\nansible_connection=ssh\n"
        "ansible_ssh_user=root\nansible_ssh_host_key_checking=no\n"
        "ansible_ssh_common_args=-o UserKnownHostsFile=/dev/null "
        "-o ProxyCommand='ssh -o UserKnownHostsFile=/dev/null "
        f"-o StrictHostKeyChecking=no -i {private} -W %h:%p "
        f"{{{{ infra_user }}}}@homebase-{intent.engagement_name}'\n\n"
        "[middle]\n" + "".join(f"{name}\n" for name in middles) +
        "\n[edge]\n" + "".join(f"{name}\n" for name in edges)
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
