# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import base64
import hashlib
import os
import re
import subprocess
import threading
from functools import wraps
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core.command_environment import barragan_subprocess_env
from app.core.request_identity import current_request_identity
from app.core.runtime import start_runtime_task
from app.domain import JobEvent
from app.integrations.ansible_disposable_validation import resolve_ansible_playbook
from app.integrations.oci_disposable_terraform import DisposableCommandResult
from app.services.core_ssh import deployment_known_hosts_file, ensure_known_hosts_file, latest_core_connection_details
from app.services.engagements import get_engagement
from app.storage.database import db
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import (
    AccessAuditEventModel,
    EngagementTeamMembershipModel,
    OperatorUidAllocationModel,
    TeamMemberModel,
    TeamMemberSshKeyModel,
)


SUPPORTED_INFRA_GROUPS = ("redteam", "core", "volunteer", "infra")
DEFAULT_INFRA_GROUPS = ("redteam", "volunteer")
SUPPORTED_GLOBAL_ROLES = ("operator", "infrastructure_manager", "approver", "administrator", "service_account")
DEFAULT_GLOBAL_ROLES = ("operator",)
SUPPORTED_APP_PRIVILEGES = ("view", "operate", "approve_destructive", "administer")
DEFAULT_APP_PRIVILEGES = ("view",)
SUPPORTED_INFRASTRUCTURE_STATES = ("pending_enable", "enabled", "pending_disable", "disabled", "unknown")
CORE_ACCESS_TARGETS = ("homebase", "proxy01", "proxy02")
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
PROXY_ID_RE = re.compile(r"^(proxy[0-9]+)(?:-|$)")
MIN_OPERATOR_UID = 6000
MAX_OPERATOR_UID = 64999
CORE_ACCESS_APPLY_ACTION = "engagement_access_apply"
DEFAULT_WORKSPACE_ROOT = Path("/tmp/barragan-core-access-apply")
DEFAULT_KNOWN_HOSTS_ROOT = Path("/tmp/barragan-core-access-known-hosts")
DEFAULT_CORE_SSH_PRIVATE_KEY = "/var/lib/barragan/.ssh/barragan_testing"
CORE_SSH_KEY_ENV = "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY"
CORE_SSH_OPTIONS = (
    "-o StrictHostKeyChecking=accept-new",
    "-o IdentitiesOnly=yes",
    "-o BatchMode=yes",
    "-o ConnectTimeout=10",
)

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]


class TeamAccessValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("team access validation failed")
        self.errors = errors


def _uid_write(operation):
    """Serialize UID reads and writes across SQLite processes in one transaction."""
    @wraps(operation)
    def guarded(*args, **kwargs):
        session = db.session()
        if db.engine.dialect.name != "sqlite":
            raise TeamAccessValidationError(["operator UID allocation currently requires SQLite"])
        # Do not roll back or commit somebody else's pending work. Ordinary
        # auth SELECTs use pysqlite's legacy read behavior and can precede BEGIN.
        if session.new or session.dirty or session.deleted:
            raise TeamAccessValidationError(["finish pending database changes before changing operator UIDs"])
        connection = session.connection()
        if connection.connection.driver_connection.in_transaction:
            raise TeamAccessValidationError(["operator UID changes require a fresh database transaction; retry the request"])
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            session.expire_all()
            ledger = session.get(OperatorUidAllocationModel, 1)
            if ledger is None:
                ledger = OperatorUidAllocationModel(id=1, high_water_uid=MIN_OPERATOR_UID - 1)
                session.add(ledger)
            highest = session.query(func.max(TeamMemberModel.desired_uid)).scalar()
            ledger.high_water_uid = max(ledger.high_water_uid, highest or 0, MIN_OPERATOR_UID - 1)
            result = operation(*args, **kwargs)
            session.commit()
            return result
        except IntegrityError as exc:
            session.rollback()
            raise TeamAccessValidationError(["operator username or desired UID is already reserved; refresh and retry"]) from exc
        except OperationalError as exc:
            session.rollback()
            raise TeamAccessValidationError(["operator UID allocation is busy; retry the request"]) from exc
        except Exception:
            session.rollback()
            raise
    return guarded


def _reserve_operator_uid(uid: int | None = None) -> int:
    ledger = db.session.get(OperatorUidAllocationModel, 1)
    if uid is None:
        uid = ledger.high_water_uid + 1
        if uid > MAX_OPERATOR_UID:
            raise TeamAccessValidationError(["automatic operator UID range is exhausted; no member was created"])
    ledger.high_water_uid = max(ledger.high_water_uid, uid)
    return uid


@dataclass(frozen=True)
class CoreAccessHost:
    name: str
    ansible_host: str
    ansible_user: str
    ssh_private_key_file: str
    proxy_jump: str = ""
    known_hosts_file: str = ""

    def to_inventory_line(self) -> str:
        parts = [
            self.name,
            f"ansible_host={self.ansible_host}",
            f"ansible_user={self.ansible_user}",
            f"ansible_ssh_private_key_file={self.ssh_private_key_file}",
        ]
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
        if self.proxy_jump:
            body["proxyJump"] = self.proxy_jump
        if self.known_hosts_file:
            body["knownHostsFile"] = self.known_hosts_file
        return body


@dataclass(frozen=True)
class CoreAccessUser:
    membership_id: str
    username: str
    display_name: str
    desired_uid: int | None
    infra_groups: tuple[str, ...]
    ssh_public_keys: tuple[str, ...]
    infrastructure_state: str

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "membershipId": self.membership_id,
            "username": self.username,
            "displayName": self.display_name,
            "desiredUid": self.desired_uid,
            "infraGroups": list(self.infra_groups),
            "sshKeyCount": len(self.ssh_public_keys),
            "sshKeyFingerprints": [_fingerprint(key) for key in self.ssh_public_keys],
            "infrastructureState": self.infrastructure_state,
        }


@dataclass(frozen=True)
class RenderedCoreAccessArtifact:
    target: str
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "content": self.content}


@dataclass(frozen=True)
class CoreAccessApplyWorkspace:
    inventory: RenderedCoreAccessArtifact
    playbook: RenderedCoreAccessArtifact
    manifest: RenderedCoreAccessArtifact
    vars_file: RenderedCoreAccessArtifact

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "Pending Core Access Apply",
            "mutation": False,
            "inventory": self.inventory.to_dict(),
            "playbook": self.playbook.to_dict(),
            "manifest": self.manifest.to_dict(),
            "vars": self.vars_file.to_dict(),
        }


def list_team_members() -> dict[str, Any]:
    rows = TeamMemberModel.query.order_by(TeamMemberModel.username.asc()).all()
    return {
        "members": [_member_dict(row) for row in rows],
        "supportedInfraGroups": list(SUPPORTED_INFRA_GROUPS),
        "defaultInfraGroups": list(DEFAULT_INFRA_GROUPS),
        "supportedGlobalRoles": list(SUPPORTED_GLOBAL_ROLES),
        "supportedAppPrivileges": list(SUPPORTED_APP_PRIVILEGES),
    }


def preview_team_import(body: dict[str, Any]) -> dict[str, Any]:
    parsed = _parse_team_import(body)
    records = [_import_preview_record(record) for record in parsed["records"]]
    summary = {
        "creates": sum(1 for record in records if record["action"] == "create"),
        "updates": sum(1 for record in records if record["action"] == "update"),
        "unchanged": sum(1 for record in records if record["action"] == "unchanged"),
        "invalid": sum(1 for record in records if record["action"] == "invalid"),
        "keyAdditions": sum(record["keyAdditions"] for record in records),
    }
    warnings = [
        "Users with a usable SSH key in the file are active; users listed without a key are deactivated. Users missing from the file are not deactivated and existing SSH keys missing from the file are not retired.",
        *parsed["warnings"],
    ]
    return {
        "preview": {
            "format": parsed["format"],
            "fileName": parsed["fileName"],
            "summary": summary,
            "records": records,
            "warnings": warnings,
        }
    }


@_uid_write
def apply_team_import(body: dict[str, Any]) -> dict[str, Any]:
    preview = preview_team_import(body)["preview"]
    # Reserve all valid actionable explicit UIDs first, independent of file
    # order. Invalid/skipped records cannot consume automatic assignments.
    for record in preview["records"]:
        if record["action"] in {"create", "update"} and record["desiredUid"] is not None:
            _reserve_operator_uid(record["desiredUid"])
    applied = {
        "created": [],
        "updated": [],
        "unchanged": [],
        "skipped": [],
        "keyAdditions": 0,
    }
    for record in preview["records"]:
        if record["action"] == "invalid":
            applied["skipped"].append({"username": record["username"], "errors": record["errors"]})
            continue
        if record["action"] == "create":
            if record["desiredUid"] is None:
                record["desiredUid"] = _reserve_operator_uid()
            member = TeamMemberModel(
                id=f"user-{uuid4().hex[:12]}",
                username=record["username"],
                display_name=record["displayName"],
                email="",
                status=record["status"],
                deactivated_at=_now() if record["status"] == "deactivated" else None,
                desired_uid=record["desiredUid"],
                default_infra_groups=record["defaultInfraGroups"],
                global_roles=list(DEFAULT_GLOBAL_ROLES),
            )
            db.session.add(member)
            db.session.flush()
            applied["created"].append(record["username"])
            _audit(
                action="team_member_import_created",
                target_type="team_member",
                target_id=member.id,
                summary=f"Imported global team member {record['username']}.",
                metadata={"source": preview["fileName"], "defaultInfraGroups": record["defaultInfraGroups"], "desiredUid": record["desiredUid"]},
            )
        else:
            member = TeamMemberModel.query.filter_by(username=record["username"]).first()
            if member is None:
                applied["skipped"].append({"username": record["username"], "errors": ["member disappeared before apply"]})
                continue
            if record["action"] == "update":
                member.display_name = record["displayName"]
                member.desired_uid = record["desiredUid"]
                member.default_infra_groups = record["defaultInfraGroups"]
                if member.status != record["status"]:
                    member.status = record["status"]
                    member.deactivated_at = _now() if member.status == "deactivated" else None
                    _mark_member_memberships_for_status(member)
                applied["updated"].append(record["username"])
                _audit(
                    action="team_member_import_updated",
                    target_type="team_member",
                    target_id=member.id,
                    summary=f"Updated imported global team member {record['username']}.",
                    metadata={"source": preview["fileName"], "updates": record["changes"], "desiredUid": member.desired_uid},
                )
            else:
                applied["unchanged"].append(record["username"])
        existing_fingerprints = {
            key.fingerprint
            for key in TeamMemberSshKeyModel.query.filter_by(member_id=member.id, status="active").all()
        }
        for ssh_key in record["sshKeys"]:
            if ssh_key["fingerprint"] in existing_fingerprints:
                continue
            key = TeamMemberSshKeyModel(
                id=f"key-{uuid4().hex[:12]}",
                member_id=member.id,
                label=ssh_key["label"],
                public_key=ssh_key["publicKey"],
                fingerprint=ssh_key["fingerprint"],
                status="active",
            )
            db.session.add(key)
            existing_fingerprints.add(ssh_key["fingerprint"])
            applied["keyAdditions"] += 1
            _audit(
                action="team_member_import_ssh_key_added",
                target_type="team_member",
                target_id=member.id,
                summary=f"Imported SSH public key for {record['username']}.",
                metadata={"source": preview["fileName"], "fingerprint": ssh_key["fingerprint"]},
            )
    db.session.flush()
    return {"preview": preview, "applied": applied, "team": list_team_members()}


@_uid_write
def create_team_member(body: dict[str, Any]) -> dict[str, Any]:
    username = _username(body.get("username"))
    if TeamMemberModel.query.filter_by(username=username).first() is not None:
        raise TeamAccessValidationError([f"username {username} already exists"])
    row = TeamMemberModel(
        id=f"user-{uuid4().hex[:12]}",
        username=username,
        display_name=_compact(body.get("displayName") or body.get("display_name") or username, "displayName"),
        email=_compact(body.get("email"), "email"),
        desired_uid=_reserve_operator_uid(_desired_uid(body.get("desiredUid", body.get("desired_uid")), existing_member_id=None)),
        status="active",
        default_infra_groups=_infra_groups(body.get("defaultInfraGroups"), default=DEFAULT_INFRA_GROUPS),
        global_roles=_global_roles(body.get("globalRoles")),
    )
    db.session.add(row)
    _audit(
        action="team_member_created",
        target_type="team_member",
        target_id=row.id,
        summary=f"Created global team member {username}.",
        metadata={"username": username, "defaultInfraGroups": row.default_infra_groups, "desiredUid": row.desired_uid},
    )
    db.session.flush()
    return {"member": _member_dict(row)}


@_uid_write
def update_team_member(member_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    row = TeamMemberModel.query.get(member_id)
    if row is None:
        return None
    if "username" in body:
        username = _username(body.get("username"))
        duplicate = TeamMemberModel.query.filter_by(username=username).first()
        if duplicate is not None and duplicate.id != row.id:
            raise TeamAccessValidationError([f"username {username} already exists"])
        row.username = username
    if "displayName" in body or "display_name" in body:
        row.display_name = _compact(body.get("displayName") or body.get("display_name"), "displayName")
    if "email" in body:
        row.email = _compact(body.get("email"), "email")
    if "desiredUid" in body or "desired_uid" in body:
        requested_uid = _desired_uid(body.get("desiredUid", body.get("desired_uid")), existing_member_id=row.id)
        if requested_uid is not None:
            row.desired_uid = _reserve_operator_uid(requested_uid)
    if "status" in body:
        row.status = _member_status(body.get("status"))
        row.deactivated_at = _now() if row.status == "deactivated" else None
        _mark_member_memberships_for_status(row)
    if "defaultInfraGroups" in body:
        row.default_infra_groups = _infra_groups(body.get("defaultInfraGroups"), default=DEFAULT_INFRA_GROUPS)
    if "globalRoles" in body:
        row.global_roles = _global_roles(body.get("globalRoles"))
    _audit(
        action="team_member_updated",
        target_type="team_member",
        target_id=row.id,
        summary=f"Updated global team member {row.username}.",
        metadata={"username": row.username, "desiredUid": row.desired_uid},
    )
    db.session.flush()
    return {"member": _member_dict(row)}


def deactivate_team_member(member_id: str) -> dict[str, Any] | None:
    row = TeamMemberModel.query.get(member_id)
    if row is None:
        return None
    row.status = "deactivated"
    row.deactivated_at = _now()
    _mark_member_memberships_for_status(row)
    _audit(
        action="team_member_deactivated",
        target_type="team_member",
        target_id=row.id,
        summary=f"Deactivated global team member {row.username}.",
        metadata={"username": row.username},
    )
    db.session.commit()
    return {"member": _member_dict(row)}


def add_team_member_ssh_key(member_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    member = TeamMemberModel.query.get(member_id)
    if member is None:
        return None
    public_key = _public_key(body.get("publicKey") or body.get("public_key"))
    fingerprint = _fingerprint(public_key)
    existing = TeamMemberSshKeyModel.query.filter_by(member_id=member_id, fingerprint=fingerprint).first()
    if existing is not None and existing.status == "active":
        raise TeamAccessValidationError(["an active SSH key with this fingerprint already exists for this member"])
    if existing is not None:
        existing.status = "active"
        existing.public_key = public_key
        existing.retired_at = None
        existing.label = _compact(body.get("label") or existing.label or "primary", "label")
        key = existing
    else:
        key = TeamMemberSshKeyModel(
            id=f"key-{uuid4().hex[:12]}",
            member_id=member_id,
            label=_compact(body.get("label") or "primary", "label"),
            public_key=public_key,
            fingerprint=fingerprint,
            status="active",
        )
        db.session.add(key)
    _audit(
        action="team_member_ssh_key_added",
        target_type="team_member",
        target_id=member.id,
        summary=f"Added SSH public key for {member.username}.",
        metadata={"fingerprint": fingerprint},
    )
    db.session.commit()
    return {"member": _member_dict(member), "sshKey": _ssh_key_dict(key)}


def update_team_member_ssh_key(member_id: str, key_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    member = TeamMemberModel.query.get(member_id)
    if member is None:
        return None
    key = TeamMemberSshKeyModel.query.filter_by(member_id=member_id, id=key_id).first()
    if key is None:
        return None
    if "label" in body:
        key.label = _compact(body.get("label") or key.label or "primary", "label")
    if "publicKey" in body or "public_key" in body:
        public_key = _public_key(body.get("publicKey") or body.get("public_key"))
        fingerprint = _fingerprint(public_key)
        duplicate = TeamMemberSshKeyModel.query.filter_by(member_id=member_id, fingerprint=fingerprint).first()
        if duplicate is not None and duplicate.id != key.id and duplicate.status == "active":
            raise TeamAccessValidationError(["an active SSH key with this fingerprint already exists for this member"])
        key.public_key = public_key
        key.fingerprint = fingerprint
        key.status = "active"
        key.retired_at = None
    _audit(
        action="team_member_ssh_key_updated",
        target_type="team_member",
        target_id=member.id,
        summary=f"Updated SSH public key for {member.username}.",
        metadata={"fingerprint": key.fingerprint},
    )
    db.session.commit()
    return {"member": _member_dict(member), "sshKey": _ssh_key_dict(key)}


def retire_team_member_ssh_key(member_id: str, key_id: str) -> dict[str, Any] | None:
    member = TeamMemberModel.query.get(member_id)
    if member is None:
        return None
    key = TeamMemberSshKeyModel.query.filter_by(member_id=member_id, id=key_id).first()
    if key is None:
        return None
    key.status = "retired"
    key.retired_at = _now()
    _audit(
        action="team_member_ssh_key_retired",
        target_type="team_member",
        target_id=member.id,
        summary=f"Retired SSH public key for {member.username}.",
        metadata={"fingerprint": key.fingerprint},
    )
    db.session.commit()
    return {"member": _member_dict(member), "sshKey": _ssh_key_dict(key)}


def get_engagement_team(engagement_id: str) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    return {
        "engagementId": engagement_id,
        "memberships": [_membership_dict(row) for row in _membership_rows(engagement_id)],
        "availableMembers": [
            _member_dict(row)
            for row in TeamMemberModel.query.filter_by(status="active").order_by(TeamMemberModel.username.asc()).all()
        ],
        "supportedInfraGroups": list(SUPPORTED_INFRA_GROUPS),
        "supportedAppPrivileges": list(SUPPORTED_APP_PRIVILEGES),
        "defaultTargets": list(_preview_core_access_targets(engagement_id)),
    }


def enroll_engagement_member(engagement_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    member_id = _required_text(body.get("memberId") or body.get("member_id"), "memberId")
    member = TeamMemberModel.query.get(member_id)
    if member is None:
        raise TeamAccessValidationError(["memberId does not reference a global team member"])
    if member.status != "active":
        raise TeamAccessValidationError(["deactivated global team members cannot be included in an engagement"])
    row = EngagementTeamMembershipModel.query.filter_by(engagement_id=engagement_id, member_id=member_id).first()
    previous_enabled = False
    previous_groups: list[str] = []
    if row is None:
        row = EngagementTeamMembershipModel(
            id=f"membership-{uuid4().hex[:12]}",
            engagement_id=engagement_id,
            member_id=member_id,
        )
        db.session.add(row)
    else:
        previous_enabled = _membership_desired_enabled(row, member)
        previous_groups = _effective_groups(row)
    row.status = _membership_status(body.get("status") or "active")
    row.app_privileges = _app_privileges(body.get("appPrivileges"), default=DEFAULT_APP_PRIVILEGES)
    row.infra_access_enabled = _bool(body.get("infraAccessEnabled"), default=True)
    row.infra_groups_override = _override_groups(body)
    row.target_scope = "homebase_and_proxies"
    row.removed_at = None
    _sync_membership_infrastructure_state(row, previous_enabled=previous_enabled, previous_groups=previous_groups)
    _audit(
        action="engagement_member_enrolled",
        target_type="engagement_membership",
        target_id=row.id,
        engagement_id=engagement_id,
        summary=f"Enrolled {member.username} into engagement team.",
        metadata={"memberId": member_id, "appPrivileges": row.app_privileges, "effectiveInfraGroups": _effective_groups(row)},
    )
    db.session.commit()
    return {"membership": _membership_dict(row), **get_engagement_team(engagement_id)}


def update_engagement_membership(engagement_id: str, membership_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    row = EngagementTeamMembershipModel.query.filter_by(engagement_id=engagement_id, id=membership_id).first()
    if row is None:
        return None
    previous_enabled = _membership_desired_enabled(row)
    previous_groups = _effective_groups(row)
    if "status" in body:
        row.status = _membership_status(body.get("status"))
        row.removed_at = _now() if row.status == "removed" else None
    if "appPrivileges" in body:
        row.app_privileges = _app_privileges(body.get("appPrivileges"), default=DEFAULT_APP_PRIVILEGES)
    if "infraAccessEnabled" in body:
        row.infra_access_enabled = _bool(body.get("infraAccessEnabled"), default=True)
    if "infraGroupsOverride" in body or "inheritInfraGroups" in body:
        row.infra_groups_override = _override_groups(body)
    _sync_membership_infrastructure_state(row, previous_enabled=previous_enabled, previous_groups=previous_groups)
    _audit(
        action="engagement_member_updated",
        target_type="engagement_membership",
        target_id=row.id,
        engagement_id=engagement_id,
        summary=f"Updated engagement membership for {_membership_member(row).username}.",
        metadata={"appPrivileges": row.app_privileges, "effectiveInfraGroups": _effective_groups(row)},
    )
    db.session.commit()
    return {"membership": _membership_dict(row), **get_engagement_team(engagement_id)}


def remove_engagement_membership(engagement_id: str, membership_id: str) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    row = EngagementTeamMembershipModel.query.filter_by(engagement_id=engagement_id, id=membership_id).first()
    if row is None:
        return None
    row.status = "removed"
    row.infra_access_enabled = False
    if _membership_infrastructure_state(row) != "disabled":
        row.infrastructure_state = "pending_disable"
    row.removed_at = _now()
    _audit(
        action="engagement_member_removed",
        target_type="engagement_membership",
        target_id=row.id,
        engagement_id=engagement_id,
        summary=f"Removed engagement membership for {_membership_member(row).username}.",
        metadata={"memberId": row.member_id},
    )
    db.session.commit()
    return {"membership": _membership_dict(row), **get_engagement_team(engagement_id)}


def preview_engagement_access_plan(engagement_id: str) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    return {"plan": _access_plan(engagement_id)}


def start_engagement_access_apply(
    engagement_id: str,
    *,
    requested_by: str = "operator",
    repository: JobRepository | None = None,
    runner: CommandRunner | None = None,
    env: Mapping[str, str] | None = None,
    workspace_root: Path | None = None,
    background_runner: BackgroundRunner | None = None,
) -> dict[str, Any] | None:
    if get_engagement(engagement_id) is None:
        return None
    repo = repository or SqlAlchemyJobRepository()
    hosts = _core_access_hosts(repo, engagement_id)
    plan = _access_plan(engagement_id, target_hosts=tuple(host.name for host in hosts))
    active_users, disabled_users = _core_access_users(engagement_id)
    errors = _core_access_preflight_errors(plan, active_users)
    if errors:
        raise TeamAccessValidationError(errors)

    ansible_resolution = resolve_ansible_playbook(env=env)
    if not ansible_resolution.ok:
        raise TeamAccessValidationError([ansible_resolution.error or "Could not resolve ansible-playbook executable"])

    workspace = render_core_access_apply_workspace(
        active_users=active_users,
        disabled_users=disabled_users,
        hosts=hosts,
    )
    workspace_dir = _write_core_access_workspace(workspace, workspace_root or DEFAULT_WORKSPACE_ROOT, engagement_id)
    _ensure_known_hosts_file(hosts[0].known_hosts_file)
    command = [ansible_resolution.command or "ansible-playbook", "-i", "ansible/inventory.ini", "ansible/apply_core_access.yml"]
    now = _now()
    events = [
        JobEvent(
            1,
            "info",
            "core access workspace rendered",
            {
                "engagementId": engagement_id,
                "workspaceDir": str(workspace_dir),
                "inventoryTargets": plan["targetHosts"],
                "workspaceEvidence": _core_access_workspace_evidence(workspace),
                "mutation": True,
            },
        ),
        JobEvent(2, "info", "core host targets selected", {"targetHosts": plan["targetHosts"]}),
        JobEvent(3, "info", "sketch targets omitted for OPSEC", {"sketchTargets": []}),
        JobEvent(
            4,
            "info",
            "core access Ansible apply started",
            {
                "command": command,
                "cwd": str(workspace_dir),
                "enableUsers": [user.username for user in active_users],
                "disableUsers": [user.username for user in disabled_users],
            },
        ),
    ]
    job = repo.save(StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=CORE_ACCESS_APPLY_ACTION,
        status="running",
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by=requested_by,
        input={"plan": {**plan, "mode": "live-apply", "liveApply": True}, "liveApply": True, "mutation": True},
        artifact_refs=["ansible/inventory.ini", "ansible/apply_core_access.yml", "ansible/group_vars/core_access.yml", "MANIFEST.json"],
        created_at=now.isoformat(),
        started_at=now.isoformat(),
        finished_at=None,
        events=events,
    ))
    _assert_no_forbidden_markers(json.dumps([event.data for event in job.events], sort_keys=True), "core access job events")

    task_runner = background_runner or _start_background_task
    task_runner(
        lambda: _finish_engagement_access_apply_job(
            repo,
            job,
            engagement_id,
            active_users,
            disabled_users,
            plan,
            command,
            workspace_dir,
            runner,
            requested_by=requested_by,
        )
    )
    return {"job": job.to_detail().to_dict(), "plan": {**plan, "mode": "live-apply", "liveApply": True}, "status": job.status}


def _finish_engagement_access_apply_job(
    repo: JobRepository,
    job: StoredJobRun,
    engagement_id: str,
    active_users: tuple[CoreAccessUser, ...],
    disabled_users: tuple[CoreAccessUser, ...],
    plan: dict[str, Any],
    command: list[str],
    workspace_dir: Path,
    runner: CommandRunner | None,
    *,
    requested_by: str,
) -> None:
    error_message = ""
    try:
        result = _run_guarded_command(command, workspace_dir, runner)
        final_status = "succeeded" if result.ok else "failed"
        event_data = {
            "commandResult": _safe_command_result(result),
            "enabledUsers": [user.username for user in active_users] if result.ok else [],
            "disabledUsers": [user.username for user in disabled_users] if result.ok else [],
        }
    except Exception as exc:  # pragma: no cover - defensive guard for background worker failures
        final_status = "failed"
        error_message = _sanitize_output(str(exc))
        event_data = {
            "error": error_message,
            "enabledUsers": [],
            "disabledUsers": [],
        }

    finished_at = _now().isoformat()
    final_event = JobEvent(
        5,
        "info" if final_status == "succeeded" else "error",
        "core access Ansible apply succeeded" if final_status == "succeeded" else "core access Ansible apply failed",
        event_data,
    )
    stored = repo.save(replace(job, status=final_status, finished_at=finished_at, events=job.events + [final_event]))
    _assert_no_forbidden_markers(json.dumps([event.data for event in stored.events], sort_keys=True), "core access job events")
    if final_status == "succeeded":
        _mark_access_apply_succeeded(engagement_id, active_users, disabled_users, stored.id)
        audit_summary = "Applied engagement core-host access changes."
    else:
        _mark_access_apply_failed(engagement_id, stored.id)
        audit_summary = "Core-host access apply failed; pending states preserved."
    _audit(
        action=CORE_ACCESS_APPLY_ACTION,
        target_type="job",
        target_id=stored.id,
        engagement_id=engagement_id,
        actor_user_id=requested_by,
        summary=audit_summary,
        metadata={"plan": plan, "liveApply": True, "status": final_status, "error": error_message},
    )
    db.session.commit()


def _access_plan(engagement_id: str, *, target_hosts: tuple[str, ...] | None = None) -> dict[str, Any]:
    active_users = []
    disabled_users = []
    warnings = []
    for membership in _membership_rows(engagement_id):
        member = _membership_member(membership)
        active_keys = [key for key in _ssh_key_rows(member.id) if key.status == "active"]
        user = {
            "membershipId": membership.id,
            "memberId": member.id,
            "username": member.username,
            "displayName": member.display_name,
            "desiredUid": member.desired_uid,
            "infraGroups": _effective_groups(membership),
            "sshKeyFingerprints": [key.fingerprint for key in active_keys],
            "appPrivileges": list(membership.app_privileges or []),
            "infrastructureState": _membership_infrastructure_state(membership),
        }
        if membership.status == "active" and member.status == "active" and membership.infra_access_enabled:
            if not active_keys:
                warnings.append(f"{member.username} has infrastructure access enabled but no active SSH public key")
            if member.desired_uid is None:
                warnings.append(f"{member.username} has no desired UID; VNC port guidance may be unavailable")
            active_users.append(user)
        else:
            disabled_users.append(user)
    resolved_targets = target_hosts or _preview_core_access_targets(engagement_id)
    return {
        "mode": "intent-only",
        "liveApply": False,
        "targetHosts": list(resolved_targets),
        "sketchTargets": [],
        "sudoGroup": "redteam",
        "coreUsers": active_users,
        "disabledUsers": disabled_users,
        "warnings": warnings,
        "summary": f"{len(active_users)} active core user{'s' if len(active_users) != 1 else ''}; {len(disabled_users)} disabled or removed user{'s' if len(disabled_users) != 1 else ''}.",
    }


def _preview_core_access_targets(engagement_id: str) -> tuple[str, ...]:
    """Return deployed core targets when available, retaining pre-deploy guidance."""
    _deployment_id, details = latest_core_connection_details(SqlAlchemyJobRepository(), engagement_id)
    targets = _core_access_target_names(details)
    return targets or CORE_ACCESS_TARGETS


def _core_access_users(engagement_id: str) -> tuple[tuple[CoreAccessUser, ...], tuple[CoreAccessUser, ...]]:
    active_users: list[CoreAccessUser] = []
    disabled_users: list[CoreAccessUser] = []
    for membership in _membership_rows(engagement_id):
        member = _membership_member(membership)
        active_keys = [key.public_key for key in _ssh_key_rows(member.id) if key.status == "active"]
        user = CoreAccessUser(
            membership_id=membership.id,
            username=member.username,
            display_name=member.display_name or member.username,
            desired_uid=member.desired_uid,
            infra_groups=tuple(_effective_groups(membership)),
            ssh_public_keys=tuple(active_keys),
            infrastructure_state=_membership_infrastructure_state(membership),
        )
        if _membership_desired_enabled(membership, member):
            active_users.append(user)
        else:
            disabled_users.append(user)
    return tuple(active_users), tuple(disabled_users)


def _core_access_preflight_errors(plan: dict[str, Any], active_users: tuple[CoreAccessUser, ...]) -> list[str]:
    errors = []
    missing_keys = [user.username for user in active_users if not user.ssh_public_keys]
    if missing_keys:
        errors.append(f"active infrastructure users need at least one active SSH public key: {', '.join(missing_keys)}")
    if plan.get("sketchTargets"):
        errors.append("team access apply must not target sketch middle or edge nodes")
    target_hosts = list(plan.get("targetHosts") or [])
    if not target_hosts or target_hosts[0] != "homebase" or not all(name.startswith("proxy") for name in target_hosts[1:]):
        errors.append("team access apply target hosts must be one homebase followed by deployed proxies")
    return errors


def _core_access_hosts(repository: JobRepository, engagement_id: str) -> tuple[CoreAccessHost, ...]:
    deployment_id, details = latest_core_connection_details(repository, engagement_id)
    homebase = next((entry for entry in details if str(entry.get("role") or "") == "homebase"), None)
    if homebase is None:
        raise TeamAccessValidationError(["latest core deployment connectionDetails must include homebase"])
    ssh_key = _core_ssh_private_key_path()
    known_hosts_file = _known_hosts_file(engagement_id, deployment_id)
    homebase_host = CoreAccessHost(
        name="homebase",
        ansible_host=_required_entry_text(homebase, "publicIp"),
        ansible_user=_entry_user(homebase),
        ssh_private_key_file=ssh_key,
        known_hosts_file=known_hosts_file,
    )
    hosts = [homebase_host]
    proxy_entries = [(proxy_id, entry) for entry in details if (proxy_id := _entry_proxy_id(entry))]
    if not proxy_entries:
        raise TeamAccessValidationError(["latest core deployment connectionDetails must include at least one proxy"])
    seen_proxy_ids: set[str] = set()
    for proxy_id, proxy in proxy_entries:
        if proxy_id in seen_proxy_ids:
            raise TeamAccessValidationError([f"latest core deployment connectionDetails contains duplicate {proxy_id}"])
        seen_proxy_ids.add(proxy_id)
        private_ip = _required_entry_text(proxy, "privateIp")
        hosts.append(
            CoreAccessHost(
                name=proxy_id,
                ansible_host=private_ip,
                ansible_user=_entry_user(proxy),
                ssh_private_key_file=ssh_key,
                proxy_jump=f"{homebase_host.ansible_user}@{homebase_host.ansible_host}",
                known_hosts_file=known_hosts_file,
            )
        )
    return tuple(hosts)


def _core_access_target_names(details: list[dict[str, Any]]) -> tuple[str, ...]:
    homebase = next((entry for entry in details if str(entry.get("role") or "") == "homebase"), None)
    proxy_ids = [proxy_id for entry in details if (proxy_id := _entry_proxy_id(entry))]
    if homebase is None or not proxy_ids or len(proxy_ids) != len(set(proxy_ids)):
        return ()
    return ("homebase", *proxy_ids)


def render_core_access_apply_workspace(
    *,
    active_users: tuple[CoreAccessUser, ...],
    disabled_users: tuple[CoreAccessUser, ...],
    hosts: tuple[CoreAccessHost, ...],
) -> CoreAccessApplyWorkspace:
    _validate_core_access_hosts(hosts)
    workspace = CoreAccessApplyWorkspace(
        inventory=RenderedCoreAccessArtifact("ansible/inventory.ini", _render_core_access_inventory(hosts)),
        playbook=RenderedCoreAccessArtifact("ansible/apply_core_access.yml", _render_core_access_playbook()),
        vars_file=RenderedCoreAccessArtifact(
            "ansible/group_vars/core_access.yml",
            _render_core_access_vars(active_users, disabled_users),
        ),
        manifest=RenderedCoreAccessArtifact("MANIFEST.json", _render_core_access_manifest(active_users, disabled_users, hosts)),
    )
    _assert_no_forbidden_markers(json.dumps(workspace.to_dict(), sort_keys=True), "core access workspace")
    return workspace


def _render_core_access_inventory(hosts: tuple[CoreAccessHost, ...]) -> str:
    return "\n".join(
        [
            "# Managed by Barragan engagement Team access apply.",
            "# Target core hosts only. Do not add middle or edge sketch nodes here.",
            "[core_hosts]",
            *[host.to_inventory_line() for host in hosts],
            "",
        ]
    )


def _render_core_access_playbook() -> str:
    return """---
- name: Apply Barragan core operator access
  hosts: core_hosts
  become: true
  gather_facts: false
  vars_files:
    - group_vars/core_access.yml
  tasks:
    - name: Ensure infrastructure Linux groups exist
      ansible.builtin.group:
        name: "{{ item }}"
        state: present
      loop: "{{ core_access_supported_groups }}"

    - name: Ensure redteam sudoers policy
      ansible.builtin.copy:
        dest: /etc/sudoers.d/redteam
        owner: root
        group: root
        mode: "0440"
        content: "%redteam ALL=(ALL) NOPASSWD:ALL\\n"
        validate: "/usr/sbin/visudo -cf %s"

    - name: Read existing active operator passwd entries
      ansible.builtin.command:
        cmd: "getent passwd {{ item.username }}"
      loop: "{{ core_access_active_users }}"
      register: core_access_existing_active_users
      changed_when: false
      failed_when: false
      no_log: true

    - name: Refuse to change existing operator UID without explicit remediation
      ansible.builtin.assert:
        that:
          - item.item.desired_uid is none or item.rc != 0 or ((item.stdout.split(':')[2] | int) == (item.item.desired_uid | int))
        fail_msg: "UID drift for {{ item.item.username }}: host has UID {{ item.stdout.split(':')[2] if item.rc == 0 else 'missing' }}, Barragan wants UID {{ item.item.desired_uid }}. Fix this host manually before reapplying access."
      loop: "{{ core_access_existing_active_users.results | default([]) }}"

    - name: Ensure active operator accounts exist
      ansible.builtin.user:
        name: "{{ item.username }}"
        comment: "{{ item.display_name }}"
        shell: /bin/bash
        uid: "{{ item.desired_uid if item.desired_uid is not none else omit }}"
        password: "*"
        state: present
        group: "{{ item.primary_group }}"
        groups: "{{ item.supplementary_groups | join(',') }}"
        append: false
      loop: "{{ core_access_active_users }}"
      no_log: true

    - name: Ensure homebase VNC skeleton is available
      ansible.builtin.command:
        cmd: "test -f {{ item }}"
      loop:
        - /etc/skel/.vnc/xstartup
        - /etc/skel/.config/systemd/user/vncserver@.service
      changed_when: false
      when: inventory_hostname == "homebase"

    - name: Ensure active operator VNC directories exist on homebase
      ansible.builtin.file:
        path: "/home/{{ item.0.username }}/{{ item.1 }}"
        state: directory
        owner: "{{ item.0.username }}"
        group: "{{ item.0.primary_group }}"
        mode: "0700"
      loop: "{{ core_access_active_users | product(['.vnc', '.config/systemd/user']) | list }}"
      when: inventory_hostname == "homebase"
      no_log: true

    - name: Install active operator VNC xstartup on homebase
      ansible.builtin.copy:
        src: /etc/skel/.vnc/xstartup
        dest: "/home/{{ item.username }}/.vnc/xstartup"
        owner: "{{ item.username }}"
        group: "{{ item.primary_group }}"
        mode: "0755"
        remote_src: true
      loop: "{{ core_access_active_users }}"
      when: inventory_hostname == "homebase"
      no_log: true

    - name: Install active operator VNC user service on homebase
      ansible.builtin.copy:
        src: /etc/skel/.config/systemd/user/vncserver@.service
        dest: "/home/{{ item.username }}/.config/systemd/user/vncserver@.service"
        owner: "{{ item.username }}"
        group: "{{ item.primary_group }}"
        mode: "0644"
        remote_src: true
      loop: "{{ core_access_active_users }}"
      when: inventory_hostname == "homebase"
      no_log: true

    - name: Ensure active operator VNC password exists on homebase
      ansible.builtin.shell: |
        set -euo pipefail
        if [[ ! -s "/home/{{ item.username }}/.vnc/passwd" ]]; then
          runuser -u "{{ item.username }}" -- bash -lc 'vncpasswd -f <<< "$USER" > "$HOME/.vnc/passwd"'
          chmod 0600 "/home/{{ item.username }}/.vnc/passwd"
          chown "{{ item.username }}:{{ item.primary_group }}" "/home/{{ item.username }}/.vnc/passwd"
        fi
      args:
        executable: /bin/bash
      loop: "{{ core_access_active_users }}"
      changed_when: false
      when: inventory_hostname == "homebase"
      no_log: true

    - name: Enable and start active operator VNC user services on homebase
      ansible.builtin.shell: |
        set -euo pipefail
        uid="$(id -u "{{ item.username }}")"
        display="$((uid - 6000 + 1))"
        loginctl enable-linger "{{ item.username }}"
        systemctl start "user@${uid}.service"
        runuser -u "{{ item.username }}" -- env XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user daemon-reload
        runuser -u "{{ item.username }}" -- env XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user enable "vncserver@${display}.service"
        runuser -u "{{ item.username }}" -- env XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user start "vncserver@${display}.service"
      args:
        executable: /bin/bash
      loop: "{{ core_access_active_users }}"
      changed_when: false
      when: inventory_hostname == "homebase"
      no_log: true

    - name: Ensure active operator SSH directories exist
      ansible.builtin.file:
        path: "/home/{{ item.username }}/.ssh"
        state: directory
        owner: "{{ item.username }}"
        group: "{{ item.primary_group }}"
        mode: "0700"
      loop: "{{ core_access_active_users }}"
      no_log: true

    - name: Apply exclusive active operator SSH keys
      ansible.posix.authorized_key:
        user: "{{ item.username }}"
        state: present
        exclusive: true
        key: "{{ item.ssh_public_keys | join('\\n') }}"
        manage_dir: true
      loop: "{{ core_access_active_users }}"
      no_log: true

    - name: Check disabled operator home directories
      ansible.builtin.stat:
        path: "/home/{{ item.username }}"
      loop: "{{ core_access_disabled_users }}"
      register: core_access_disabled_homes
      no_log: true

    - name: Ensure disabled operator SSH directories exist when account home exists
      ansible.builtin.file:
        path: "/home/{{ item.item.username }}/.ssh"
        state: directory
        owner: "{{ item.item.username }}"
        group: "{{ item.item.primary_group }}"
        mode: "0700"
      loop: "{{ core_access_disabled_homes.results | default([]) }}"
      when: item.stat.exists
      no_log: true

    - name: Empty disabled operator authorized_keys without deleting account data
      ansible.builtin.copy:
        dest: "/home/{{ item.item.username }}/.ssh/authorized_keys"
        content: ""
        owner: "{{ item.item.username }}"
        group: "{{ item.item.primary_group }}"
        mode: "0600"
      loop: "{{ core_access_disabled_homes.results | default([]) }}"
      when: item.stat.exists
      no_log: true
"""


def _render_core_access_vars(
    active_users: tuple[CoreAccessUser, ...],
    disabled_users: tuple[CoreAccessUser, ...],
) -> str:
    return json.dumps(
        {
            "core_access_supported_groups": list(SUPPORTED_INFRA_GROUPS),
            "core_access_active_users": [_ansible_user_payload(user) for user in active_users],
            "core_access_disabled_users": [_ansible_user_payload(user) for user in disabled_users],
        },
        indent=2,
        sort_keys=True,
    )


def _render_core_access_manifest(
    active_users: tuple[CoreAccessUser, ...],
    disabled_users: tuple[CoreAccessUser, ...],
    hosts: tuple[CoreAccessHost, ...],
) -> str:
    return json.dumps(
        {
            "mode": "engagement_core_access_apply",
            "mutation": True,
            "targets": {
                "coreHosts": [host.to_dict() for host in hosts],
                "sketchMiddleTargets": [],
                "sketchEdgeTargets": [],
            },
            "users": {
                "enable": [user.to_safe_dict() for user in active_users],
                "disable": [user.to_safe_dict() for user in disabled_users],
            },
            "opsecBoundary": {
                "inventoryTargets": [host.name for host in hosts],
                "reason": "Named operator access is managed only on homebase/proxy core hosts; sketch nodes use separate management keys.",
            },
        },
        indent=2,
        sort_keys=True,
    )


def _ansible_user_payload(user: CoreAccessUser) -> dict[str, Any]:
    groups = list(user.infra_groups or ("redteam",))
    primary_group = "redteam" if "redteam" in groups else groups[0]
    return {
        "username": user.username,
        "display_name": user.display_name,
        "desired_uid": user.desired_uid,
        "primary_group": primary_group,
        "supplementary_groups": [group for group in groups if group != primary_group],
        "ssh_public_keys": list(user.ssh_public_keys),
        "ssh_key_fingerprints": [_fingerprint(key) for key in user.ssh_public_keys],
    }


def _write_core_access_workspace(workspace: CoreAccessApplyWorkspace, root: Path, engagement_id: str) -> Path:
    safe_id = "".join(character if character.isalnum() or character in {"-", "_"} else "_" for character in engagement_id)
    workspace_dir = root / f"{safe_id}-{uuid4().hex[:12]}"
    for artifact in (workspace.inventory, workspace.playbook, workspace.vars_file, workspace.manifest):
        path = workspace_dir / artifact.target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")
    return workspace_dir


def _core_access_workspace_evidence(workspace: CoreAccessApplyWorkspace) -> dict[str, dict[str, object]]:
    return {
        "inventory": _artifact_evidence(workspace.inventory, include_content=True),
        "playbook": _artifact_evidence(workspace.playbook, include_content=True),
        "vars": _artifact_evidence(workspace.vars_file, include_content=False),
        "manifest": _artifact_evidence(workspace.manifest, include_content=True),
    }


def _artifact_evidence(artifact: RenderedCoreAccessArtifact, *, include_content: bool) -> dict[str, object]:
    body: dict[str, object] = {"path": artifact.target, "bytes": len(artifact.content.encode("utf-8"))}
    if include_content:
        body["content"] = artifact.content
    return body


def _validate_core_access_hosts(hosts: tuple[CoreAccessHost, ...]) -> None:
    errors = []
    host_names = [host.name for host in hosts]
    if len(host_names) < 2 or host_names[0] != "homebase" or any(not PROXY_ID_RE.match(name) for name in host_names[1:]):
        errors.append("core access inventory must contain homebase followed by deployed proxies only")
    if len(host_names) != len(set(host_names)):
        errors.append("core access inventory must not contain duplicate host names")
    homebase = hosts[0] if hosts else None
    if homebase is not None and homebase.proxy_jump:
        errors.append("homebase must be the direct management entry point")
    for host in hosts:
        if not host.ansible_host:
            errors.append(f"{host.name} ansible_host is required")
        if host.name.startswith("proxy") and not host.proxy_jump:
            errors.append(f"{host.name} must be reached through homebase ProxyCommand")
    if errors:
        raise TeamAccessValidationError(errors)


def _mark_access_apply_succeeded(
    engagement_id: str,
    active_users: tuple[CoreAccessUser, ...],
    disabled_users: tuple[CoreAccessUser, ...],
    job_id: str,
) -> None:
    active_membership_ids = {user.membership_id for user in active_users}
    disabled_membership_ids = {user.membership_id for user in disabled_users}
    for membership in _membership_rows(engagement_id):
        if membership.id in active_membership_ids:
            membership.infrastructure_state = "enabled"
            membership.apply_job_id = job_id
        elif membership.id in disabled_membership_ids:
            membership.infrastructure_state = "disabled"
            membership.apply_job_id = job_id
    db.session.commit()


def _mark_access_apply_failed(engagement_id: str, job_id: str) -> None:
    for membership in _membership_rows(engagement_id):
        if _membership_infrastructure_state(membership) in {"pending_enable", "pending_disable", "unknown"}:
            membership.apply_job_id = job_id
    db.session.commit()


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


def _safe_command_result(result: DisposableCommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "cwd": result.cwd,
        "returncode": result.returncode,
        "ok": result.ok,
        "stdout": _sanitize_output(result.stdout),
        "stderr": _sanitize_output(result.stderr),
    }


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-team-access-runner")


def _sanitize_output(value: str) -> str:
    redacted = value
    for marker in ("BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "password", "secret", "token"):
        redacted = redacted.replace(marker, "[REDACTED]")
    return redacted[:4000] + ("\n[truncated]" if len(redacted) > 4000 else "")


def _assert_no_forbidden_markers(value: str, context: str) -> None:
    forbidden = ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "LINODE_TOKEN", "DIGITALOCEAN_TOKEN"]
    found = [marker for marker in forbidden if marker in value]
    if found:
        raise TeamAccessValidationError([f"{context} contains forbidden marker {found[0]}"])


def _entry_proxy_id(entry: dict[str, Any]) -> str:
    role = str(entry.get("role") or "")
    display = str(entry.get("displayName") or entry.get("sshAlias") or entry.get("name") or "")
    if role != "proxy" and not PROXY_ID_RE.match(role):
        return ""
    match = PROXY_ID_RE.match(display) or PROXY_ID_RE.match(role)
    return match.group(1) if match else ""


def _entry_user(entry: dict[str, Any]) -> str:
    return str(entry.get("sshUser") or "user")


def _required_entry_text(entry: dict[str, Any], key: str) -> str:
    text = str(entry.get(key) or "").strip()
    if not text:
        raise TeamAccessValidationError([f"latest core deployment connectionDetails missing {key} for {entry.get('displayName') or entry.get('role') or 'host'}"])
    return text


def _core_ssh_private_key_path() -> str:
    return os.environ.get(CORE_SSH_KEY_ENV, DEFAULT_CORE_SSH_PRIVATE_KEY)


def _known_hosts_file(engagement_id: str, deployment_id: str = "unknown-core") -> str:
    return deployment_known_hosts_file(DEFAULT_KNOWN_HOSTS_ROOT, engagement_id, deployment_id)


def _ensure_known_hosts_file(path: str) -> None:
    ensure_known_hosts_file(path)


def _parse_team_import(body: dict[str, Any]) -> dict[str, Any]:
    content = str(body.get("content") or "")
    if not content.strip():
        raise TeamAccessValidationError(["content is required"])
    file_name = _compact(body.get("fileName") or body.get("file_name") or "users import", "fileName")
    requested_format = str(body.get("format") or "").strip().lower()
    if requested_format not in {"", "json", "yml", "yaml"}:
        raise TeamAccessValidationError(["format must be json, yml, or yaml"])
    detected_format = requested_format or ("json" if file_name.endswith(".json") or content.lstrip().startswith("{") else "yml")
    warnings: list[str] = []
    if detected_format == "json":
        records = _parse_legacy_users_json(content)
    else:
        records = _parse_generated_users_yml(content)
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_uids: set[int] = set()
    for record in records:
        username = record.get("username", "")
        if username and username in seen:
            record = {**record, "errors": [*record.get("errors", []), f"duplicate username in import: {username}"]}
        seen.add(username)
        desired_uid = record.get("desiredUid")
        if desired_uid is not None:
            if desired_uid in seen_uids:
                record = {**record, "errors": [*record.get("errors", []), f"duplicate desired UID in import: {desired_uid}"]}
            seen_uids.add(desired_uid)
        deduped.append(record)
    if not deduped:
        warnings.append("No user records were found in the import content.")
    return {"format": detected_format, "fileName": file_name, "records": deduped, "warnings": warnings}


def _parse_legacy_users_json(content: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise TeamAccessValidationError([f"users.json is not valid JSON: {exc.msg}"]) from exc
    users = payload.get("users") if isinstance(payload, dict) else None
    if not isinstance(users, list):
        raise TeamAccessValidationError(["users.json must contain a users list"])
    records = []
    for index, raw_user in enumerate(users, start=1):
        if not isinstance(raw_user, dict):
            records.append(_invalid_import_record(index, "", ["user record must be an object"]))
            continue
        records.append(
            _normalize_import_record(
                index=index,
                username=raw_user.get("username"),
                display_name=raw_user.get("name") or raw_user.get("comment") or raw_user.get("username"),
                desired_uid=raw_user.get("uid"),
                groups=raw_user.get("tags"),
                raw_keys=_decode_authorized_keys(raw_user.get("authorized_keys"), index),
            )
        )
    return records


def _parse_generated_users_yml(content: str) -> list[dict[str, Any]]:
    user_records: dict[str, dict[str, Any]] = {}
    lines = content.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        add_user_match = re.match(r"^\s*-\s+name:\s+Add user\s+(.+?)\s*$", line)
        add_key_match = re.match(r"^\s*-\s+name:\s+Add ssh public key for\s+(.+?)\s*$", line)
        if add_user_match:
            task_lines = _collect_task_lines(lines, index + 1)
            fields = _parse_simple_yaml_fields(task_lines)
            username = fields.get("name") or add_user_match.group(1).strip()
            groups = [fields.get("group", "redteam"), *re.split(r"\s*,\s*", fields.get("groups", ""))]
            user_records.setdefault(
                username,
                {
                    "username": username,
                    "displayName": fields.get("comment") or username,
                    "desiredUid": fields.get("uid"),
                    "groups": groups,
                    "rawKeys": [],
                },
            )
        elif add_key_match:
            username = add_key_match.group(1).strip()
            task_lines = _collect_task_lines(lines, index + 1)
            keys = _extract_yaml_key_block(task_lines)
            user_records.setdefault(username, {"username": username, "displayName": username, "desiredUid": None, "groups": list(DEFAULT_INFRA_GROUPS), "rawKeys": []})
            user_records[username]["rawKeys"].extend(keys)
        index += 1
    return [
        _normalize_import_record(
            index=index,
            username=record["username"],
            display_name=record["displayName"],
            desired_uid=record["desiredUid"],
            groups=record["groups"],
            raw_keys=record["rawKeys"],
        )
        for index, record in enumerate(user_records.values(), start=1)
    ]


def _collect_task_lines(lines: list[str], start: int) -> list[str]:
    collected = []
    for line in lines[start:]:
        if re.match(r"^\s*-\s+name:\s+", line):
            break
        collected.append(line)
    return collected


def _parse_simple_yaml_fields(lines: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in lines:
        match = re.match(r"^\s{6,}([a-zA-Z_][a-zA-Z0-9_]*):\s*(.*?)\s*$", line)
        if not match:
            continue
        value = match.group(2).strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        fields[match.group(1)] = value
    return fields


def _extract_yaml_key_block(lines: list[str]) -> list[str]:
    keys: list[str] = []
    key_indent: int | None = None
    for line in lines:
        match = re.match(r"^(\s+)key:\s*(.*?)\s*$", line)
        if match:
            value = match.group(2)
            if value not in {"|", "|-", "|+"}:
                return [value.strip("\"'")] if value else []
            key_indent = len(match.group(1))
            continue
        if key_indent is not None and line.strip():
            if len(line) - len(line.lstrip()) <= key_indent:
                break
            keys.append(line.strip())
    return keys


def _decode_authorized_keys(value: Any, index: int) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    try:
        decoded = base64.b64decode("".join(text.split()).encode("ascii"), validate=True).decode("utf-8")
    except Exception:
        return [f"__BARRAGAN_INVALID_BASE64_RECORD_{index}__"]
    return [line.strip() for line in decoded.splitlines() if line.strip()]


def _normalize_import_record(*, index: int, username: Any, display_name: Any, desired_uid: Any, groups: Any, raw_keys: list[str]) -> dict[str, Any]:
    errors: list[str] = []
    normalized_username = ""
    normalized_groups: list[str] = []
    ssh_keys: list[dict[str, str]] = []
    try:
        normalized_username = _username(username)
    except TeamAccessValidationError as exc:
        errors.extend(exc.errors)
    try:
        normalized_groups = _infra_groups(groups, default=DEFAULT_INFRA_GROUPS)
    except TeamAccessValidationError as exc:
        errors.extend(exc.errors)
    try:
        normalized_uid = _desired_uid(desired_uid, existing_member_id=None, check_unique=False)
    except TeamAccessValidationError as exc:
        normalized_uid = None
        errors.extend(exc.errors)
    for key_index, raw_key in enumerate(raw_keys, start=1):
        if raw_key.startswith("__BARRAGAN_INVALID_BASE64"):
            errors.append("authorized_keys is not valid base64")
            continue
        try:
            public_key = _public_key(raw_key)
            ssh_keys.append(
                {
                    "label": "imported",
                    "publicKey": public_key,
                    "fingerprint": _fingerprint(public_key),
                    "sourceIndex": str(key_index),
                }
            )
        except TeamAccessValidationError as exc:
            errors.extend([f"SSH key {key_index}: {error}" for error in exc.errors])
    return {
        "sourceIndex": index,
        "username": normalized_username,
        "displayName": _compact(display_name or normalized_username, "displayName") if normalized_username else str(display_name or ""),
        "desiredUid": normalized_uid,
        "defaultInfraGroups": normalized_groups,
        "sshKeys": ssh_keys,
        "status": None if errors else ("active" if ssh_keys else "deactivated"),
        "errors": errors,
    }


def _invalid_import_record(index: int, username: str, errors: list[str]) -> dict[str, Any]:
    return {
        "sourceIndex": index,
        "username": username,
        "displayName": username,
        "desiredUid": None,
        "defaultInfraGroups": [],
        "sshKeys": [],
        "status": None,
        "errors": errors,
    }


def _import_preview_record(record: dict[str, Any]) -> dict[str, Any]:
    if record["errors"]:
        return {
            **record,
            "action": "invalid",
            "status": None,
            "memberId": "",
            "changes": [],
            "keyAdditions": 0,
            "existingKeyCount": 0,
        }
    existing = TeamMemberModel.query.filter_by(username=record["username"]).first()
    if existing is not None and record["desiredUid"] is None:
        record = {**record, "desiredUid": existing.desired_uid}
    if record.get("desiredUid") is not None:
        duplicate_uid = TeamMemberModel.query.filter_by(desired_uid=record["desiredUid"]).first()
        if duplicate_uid is not None and (existing is None or duplicate_uid.id != existing.id):
            return {
                **record,
                "errors": [*record.get("errors", []), f"desired UID {record['desiredUid']} already belongs to {duplicate_uid.username}"],
                "action": "invalid",
                "status": None,
                "memberId": existing.id if existing is not None else "",
                "changes": [],
                "keyAdditions": 0,
                "existingKeyCount": 0,
            }
    existing_fingerprints = set()
    changes: list[str] = []
    if existing is None:
        action = "create"
    else:
        action = "unchanged"
        existing_fingerprints = {key.fingerprint for key in TeamMemberSshKeyModel.query.filter_by(member_id=existing.id, status="active").all()}
        if existing.display_name != record["displayName"]:
            changes.append("displayName")
        if existing.desired_uid != record["desiredUid"]:
            changes.append("desiredUid")
        if list(existing.default_infra_groups or []) != record["defaultInfraGroups"]:
            changes.append("defaultInfraGroups")
        if existing.status != record["status"]:
            changes.append("status")
        if changes:
            action = "update"
    key_additions = sum(1 for key in record["sshKeys"] if key["fingerprint"] not in existing_fingerprints)
    if key_additions:
        if "sshKeys" not in changes:
            changes.append("sshKeys")
        if action == "unchanged":
            action = "update"
    return {
        **record,
        "action": action,
        "memberId": existing.id if existing is not None else "",
        "changes": changes,
        "keyAdditions": key_additions,
        "existingKeyCount": len(existing_fingerprints),
    }


def _membership_rows(engagement_id: str) -> list[EngagementTeamMembershipModel]:
    return (
        EngagementTeamMembershipModel.query.filter_by(engagement_id=engagement_id)
        .order_by(EngagementTeamMembershipModel.created_at.asc())
        .all()
    )


def _ssh_key_rows(member_id: str) -> list[TeamMemberSshKeyModel]:
    return (
        TeamMemberSshKeyModel.query.filter_by(member_id=member_id)
        .order_by(TeamMemberSshKeyModel.created_at.asc())
        .all()
    )


def _membership_member(row: EngagementTeamMembershipModel) -> TeamMemberModel:
    member = TeamMemberModel.query.get(row.member_id)
    if member is None:
        raise TeamAccessValidationError(["membership references a missing global team member"])
    return member


def _member_dict(row: TeamMemberModel) -> dict[str, Any]:
    return {
        "id": row.id,
        "username": row.username,
        "displayName": row.display_name,
        "email": row.email,
        "status": row.status,
        "desiredUid": row.desired_uid,
        "defaultInfraGroups": list(row.default_infra_groups or []),
        "globalRoles": list(row.global_roles or []),
        "sshKeys": [_ssh_key_dict(key) for key in _ssh_key_rows(row.id)],
        "createdAt": row.created_at.isoformat(),
        "updatedAt": row.updated_at.isoformat(),
        "deactivatedAt": row.deactivated_at.isoformat() if row.deactivated_at else None,
    }


def _ssh_key_dict(row: TeamMemberSshKeyModel) -> dict[str, Any]:
    return {
        "id": row.id,
        "label": row.label,
        "fingerprint": row.fingerprint,
        "status": row.status,
        "publicKey": row.public_key,
        "createdAt": row.created_at.isoformat(),
        "retiredAt": row.retired_at.isoformat() if row.retired_at else None,
    }


def _membership_dict(row: EngagementTeamMembershipModel) -> dict[str, Any]:
    member = _membership_member(row)
    return {
        "id": row.id,
        "engagementId": row.engagement_id,
        "memberId": row.member_id,
        "member": _member_dict(member),
        "appPrivileges": list(row.app_privileges or []),
        "infraAccessEnabled": bool(row.infra_access_enabled),
        "infraGroupsOverride": list(row.infra_groups_override) if row.infra_groups_override is not None else None,
        "effectiveInfraGroups": _effective_groups(row),
        "targetScope": row.target_scope,
        "targetHosts": list(_preview_core_access_targets(row.engagement_id)),
        "status": row.status,
        "infrastructureState": _membership_infrastructure_state(row),
        "applyJobId": row.apply_job_id,
        "createdAt": row.created_at.isoformat(),
        "updatedAt": row.updated_at.isoformat(),
        "removedAt": row.removed_at.isoformat() if row.removed_at else None,
    }


def _effective_groups(row: EngagementTeamMembershipModel) -> list[str]:
    member = _membership_member(row)
    if row.infra_groups_override is not None:
        return list(row.infra_groups_override or [])
    return list(member.default_infra_groups or [])


def _membership_desired_enabled(row: EngagementTeamMembershipModel, member: TeamMemberModel | None = None) -> bool:
    resolved_member = member or _membership_member(row)
    return row.status == "active" and resolved_member.status == "active" and bool(row.infra_access_enabled)


def _membership_infrastructure_state(row: EngagementTeamMembershipModel) -> str:
    state = str(getattr(row, "infrastructure_state", "") or "unknown")
    if state not in SUPPORTED_INFRASTRUCTURE_STATES:
        return "unknown"
    if not _membership_desired_enabled(row) and state in {"pending_enable", "enabled"}:
        return "pending_disable"
    return state


def _sync_membership_infrastructure_state(
    row: EngagementTeamMembershipModel,
    *,
    previous_enabled: bool,
    previous_groups: list[str],
) -> None:
    state = _membership_infrastructure_state(row)
    desired_enabled = _membership_desired_enabled(row)
    current_groups = _effective_groups(row)
    if desired_enabled:
        if not previous_enabled or state in {"pending_disable", "disabled", "unknown"} or current_groups != previous_groups:
            row.infrastructure_state = "pending_enable"
        else:
            row.infrastructure_state = state
        return
    row.infrastructure_state = "disabled" if state == "disabled" else "pending_disable"


def _mark_member_memberships_for_status(member: TeamMemberModel) -> None:
    for membership in EngagementTeamMembershipModel.query.filter_by(member_id=member.id).all():
        state = _membership_infrastructure_state(membership)
        if member.status == "deactivated":
            membership.infrastructure_state = "disabled" if state == "disabled" else "pending_disable"
        elif membership.status == "active" and membership.infra_access_enabled and state in {"pending_disable", "disabled", "unknown"}:
            membership.infrastructure_state = "pending_enable"


def _audit(
    *,
    action: str,
    target_type: str,
    target_id: str,
    summary: str,
    actor_user_id: str = "operator",
    engagement_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    request_identity = current_request_identity()
    effective_actor = request_identity.username if request_identity is not None else actor_user_id
    db.session.add(
        AccessAuditEventModel(
            actor_user_id=effective_actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            engagement_id=engagement_id,
            summary=summary,
            metadata_json=metadata or {},
        )
    )


def _username(value: Any) -> str:
    username = _required_text(value, "username").lower()
    if not USERNAME_RE.match(username):
        raise TeamAccessValidationError(["username must start with a letter or underscore and contain only lowercase letters, digits, underscores, or hyphens"])
    return username


def _member_status(value: Any) -> str:
    status = _required_text(value, "status")
    if status not in {"active", "deactivated"}:
        raise TeamAccessValidationError(["status must be active or deactivated"])
    return status


def _desired_uid(value: Any, *, existing_member_id: str | None, check_unique: bool = True) -> int | None:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    if type(value) is int:
        uid = value
    elif isinstance(value, str) and re.fullmatch(r"[+-]?[0-9]+", value.strip()):
        try:
            uid = int(value.strip())
        except ValueError as exc:
            raise TeamAccessValidationError(["desired UID must be an integer within the supported range"]) from exc
    else:
        raise TeamAccessValidationError(["desired UID must be an integer"])
    if uid < MIN_OPERATOR_UID or uid > MAX_OPERATOR_UID:
        raise TeamAccessValidationError([f"desired UID must be between {MIN_OPERATOR_UID} and {MAX_OPERATOR_UID}"])
    if check_unique:
        duplicate = TeamMemberModel.query.filter_by(desired_uid=uid).first()
        if duplicate is not None and duplicate.id != existing_member_id:
            raise TeamAccessValidationError([f"desired UID {uid} already belongs to {duplicate.username}"])
    return uid


def _membership_status(value: Any) -> str:
    status = _required_text(value, "status")
    if status not in {"active", "suspended", "removed"}:
        raise TeamAccessValidationError(["membership status must be active, suspended, or removed"])
    return status


def _app_privileges(value: Any, *, default: tuple[str, ...]) -> list[str]:
    privileges = _string_list(value, field="appPrivileges", default=default)
    unsupported = [privilege for privilege in privileges if privilege not in SUPPORTED_APP_PRIVILEGES]
    if unsupported:
        raise TeamAccessValidationError([f"unsupported app privilege: {unsupported[0]}"])
    return privileges


def _global_roles(value: Any) -> list[str]:
    roles = _string_list(value, field="globalRoles", default=DEFAULT_GLOBAL_ROLES)
    unsupported = [role for role in roles if role not in SUPPORTED_GLOBAL_ROLES]
    if unsupported:
        raise TeamAccessValidationError([f"unsupported global role: {unsupported[0]}"])
    return roles


def _infra_groups(value: Any, *, default: tuple[str, ...]) -> list[str]:
    groups = _string_list(value, field="infraGroups", default=default)
    unsupported = [group for group in groups if group not in SUPPORTED_INFRA_GROUPS]
    if unsupported:
        raise TeamAccessValidationError([f"unsupported infrastructure group: {unsupported[0]}"])
    if groups == ["volunteer"]:
        raise TeamAccessValidationError(["volunteer without redteam is not supported"])
    return groups


def _override_groups(body: dict[str, Any]) -> list[str] | None:
    if _bool(body.get("inheritInfraGroups"), default=False):
        return None
    if "infraGroupsOverride" not in body:
        return None
    value = body.get("infraGroupsOverride")
    if value is None:
        return None
    return _infra_groups(value, default=())


def _string_list(value: Any, *, field: str, default: tuple[str, ...]) -> list[str]:
    if value is None:
        return list(default)
    if not isinstance(value, list):
        raise TeamAccessValidationError([f"{field} must be a list"])
    normalized = []
    for item in value:
        text = _required_text(item, field)
        if text not in normalized:
            normalized.append(text)
    return normalized


def _public_key(value: Any) -> str:
    text = _required_text(value, "publicKey")
    if "PRIVATE" in text.upper():
        raise TeamAccessValidationError(["publicKey must be an SSH public key, not private key material"])
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise TeamAccessValidationError(["publicKey must contain exactly one OpenSSH public key line"])
    parts = lines[0].split()
    if len(parts) < 2:
        raise TeamAccessValidationError(["publicKey must contain a key type and key material"])
    key_type = parts[0]
    if not (key_type.startswith("ssh-") or key_type.startswith("ecdsa-") or key_type.startswith("sk-")):
        raise TeamAccessValidationError(["publicKey must use an OpenSSH public key type"])
    try:
        base64.b64decode(parts[1].encode("ascii"), validate=True)
    except Exception as exc:
        raise TeamAccessValidationError(["publicKey key material is not valid base64"]) from exc
    return " ".join(parts)


def _fingerprint(public_key: str) -> str:
    parts = public_key.split()
    digest = hashlib.sha256(base64.b64decode(parts[1].encode("ascii"))).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _required_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise TeamAccessValidationError([f"{field} is required"])
    return text


def _compact(value: Any, field: str, *, max_length: int = 500) -> str:
    text = str(value or "").strip()
    if len(text) > max_length:
        raise TeamAccessValidationError([f"{field} is too long"])
    return text


def _bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    return bool(value)


def _now() -> datetime:
    return datetime.now(timezone.utc)
