# Copyright (c) 2026, Oracle and/or its affiliates.
"""Explicit ATC bootstrap inputs and verified native-release delivery only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

from app.services.redteam_infra_template import resolve_redteam_infra_template_source

CAPABILITY_ID = "atc"
SOURCE_REVISION = "e9cda6c7ced6c828b619c30b68e24459708a3e16"
RELEASE_VERSION = "0.6.1"
ARCHIVE_ENV = "BARRAGAN_ATC_RELEASE_ARCHIVE"
SHA256_ENV = "BARRAGAN_ATC_RELEASE_SHA256"
POSTGRES_ENV = "BARRAGAN_ATC_POSTGRES_IMAGE"
CONFIGURATION_KEY = "atcConfiguration"
CONTEXT_KEY = "atcEngagement"
RELEASE_KEY = "atcRelease"
LIMIT = 1024 * 1024 * 1024
POSTGRES_PATTERN = r"docker\.io/library/postgres:16(?:[.-][A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}"
ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}"


class ATCCapabilityError(ValueError):
    pass


def is_selected(overrides: dict[str, Any]) -> bool:
    return any(row.get("id") == CAPABILITY_ID and row.get("hostClass") == "homebase"
               for row in overrides.get("selectedOptionals", []) if isinstance(row, dict))


def _display_name(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 128 and value == value.strip()
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def normalize_configuration(value: Any, *, required: bool = False) -> dict[str, Any]:
    value = {} if value is None else value
    if not isinstance(value, dict) or set(value) - {"operatorId", "operatorName", "port"}:
        raise ATCCapabilityError("ATC configuration permits only operatorId, operatorName and port")
    identifier, name, port = value.get("operatorId", ""), value.get("operatorName", ""), value.get("port", 8790)
    if not isinstance(identifier, str) or (identifier and not re.fullmatch(ID_PATTERN, identifier)):
        raise ATCCapabilityError("ATC requires a valid operator ID")
    if not isinstance(name, str) or (name and not _display_name(name)):
        raise ATCCapabilityError("ATC requires a single-line operator display name of at most 128 characters")
    if type(port) is not int or not 1024 <= port <= 65535 or port in {15432, 17474, 17687}:
        raise ATCCapabilityError("ATC port must be an unprivileged non-datastore port")
    if required and (not identifier or not name):
        raise ATCCapabilityError("Configure the initial ATC operator ID and name before selecting ATC")
    return {"operatorId": identifier, "operatorName": name, "port": port}


def public_state(metadata: dict[str, Any]) -> dict[str, Any]:
    return {"configuration": normalize_configuration(metadata.get(CONFIGURATION_KEY))}


def engagement_context(engagement: Any) -> dict[str, str]:
    # Callers pass the selected stored engagement, never a request-body mapping.
    identifier, codename = getattr(engagement, "id", None), getattr(engagement, "name", None)
    if not isinstance(identifier, str) or not re.fullmatch(ID_PATTERN, identifier) or not _display_name(codename):
        raise ATCCapabilityError("ATC requires a valid selected engagement identity and name")
    return {"id": identifier, "codename": codename}


def _context(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"id", "codename"}:
        raise ATCCapabilityError("ATC saved engagement context is missing")
    if not isinstance(value["id"], str) or not re.fullmatch(ID_PATTERN, value["id"]) or not _display_name(value["codename"]):
        raise ATCCapabilityError("ATC saved engagement context is invalid")
    return dict(value)


def _hash_stream(stream, output=None):
    digest, size = hashlib.sha256(), 0
    while content := stream.read(1024 * 1024):
        size += len(content)
        if size > LIMIT:
            raise ATCCapabilityError("ATC native release exceeds 1 GiB")
        digest.update(content)
        if output is not None:
            output.write(content)
    return digest.hexdigest()


def _open_regular(path: Path):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise ATCCapabilityError("ATC release must be a bounded regular file")
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        return stream
    except OSError as exc:
        raise ATCCapabilityError("ATC native release is unavailable or unsafe") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _digest(path: Path) -> str:
    with _open_regular(path) as stream:
        return _hash_stream(stream)


def _verify_release(path: Path, digest: str, postgres: str) -> dict[str, str]:
    root = resolve_redteam_infra_template_source().root
    helper = root / "ansible/roles/atc/files/verify_release.py"
    def clean():
        try:
            top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=root, check=True,
                                 capture_output=True, text=True, timeout=15).stdout.strip()
            dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root,
                                   check=True, capture_output=True, text=True, timeout=15).stdout.strip()
            tracked = subprocess.run(["git", "ls-files", "--error-unmatch", "ansible/roles/atc/files/verify_release.py"],
                                     cwd=root, check=True, capture_output=True, timeout=15)
            if Path(top).resolve() != root.resolve() or dirty or not tracked.stdout:
                raise ATCCapabilityError("ATC needs a clean configured RTI checkout containing its reviewed release verifier")
        except (OSError, subprocess.SubprocessError) as exc:
            raise ATCCapabilityError("ATC release verifier is unavailable in the configured RTI checkout") from exc
    if any(parent.is_symlink() for parent in [helper, *helper.parents]) or not helper.is_file():
        raise ATCCapabilityError("ATC release verifier is missing or unsafe in the configured RTI checkout")
    clean()
    try:
        result = subprocess.run([sys.executable, str(helper), str(path), digest,
                                 SOURCE_REVISION, RELEASE_VERSION, postgres], check=True,
                                capture_output=True, text=True, timeout=120)
        verified = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise ATCCapabilityError("ATC native bundle failed the RTI release contract; provide a reviewed app-built release") from exc
    clean()
    if not isinstance(verified, dict) or verified.get("sha256") != digest or verified.get("sourceRevision") != SOURCE_REVISION or verified.get("version") != RELEASE_VERSION or verified.get("postgresImage") != postgres or not isinstance(verified.get("migrationLevel"), str) or not re.fullmatch(r"[0-9a-f]{64}", verified["migrationLevel"]):
        raise ATCCapabilityError("ATC native bundle verification returned an unexpected identity")
    return {key: verified[key] for key in ("sha256", "sourceRevision", "version", "postgresImage", "migrationLevel")}


def controller_release() -> dict[str, Any]:
    values = {name: os.environ.get(name, "").strip() for name in (ARCHIVE_ENV, SHA256_ENV, POSTGRES_ENV)}
    if not values[ARCHIVE_ENV] or not re.fullmatch(r"[0-9a-f]{64}", values[SHA256_ENV]) or not re.fullmatch(POSTGRES_PATTERN, values[POSTGRES_ENV]):
        raise ATCCapabilityError(f"Controller administrator must prepare {ARCHIVE_ENV}, {SHA256_ENV} and {POSTGRES_ENV} with reviewed native release inputs")
    path = Path(values[ARCHIVE_ENV])
    if not path.is_absolute() or _digest(path) != values[SHA256_ENV]:
        raise ATCCapabilityError("ATC native release does not match the administrator-reviewed artifact")
    return {"path": str(path), "identity": _verify_release(path, values[SHA256_ENV], values[POSTGRES_ENV])}


def _safe_artifact(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not re.fullmatch(r"barragan/artifacts/atc-[0-9a-f]{40}-[0-9a-f]{64}\.tar\.gz", relative):
        raise ATCCapabilityError("ATC native artifact path is invalid")
    root = root.resolve()
    target = root / relative
    for path in [target, *target.parents]:
        if path == root:
            break
        if path.is_symlink():
            raise ATCCapabilityError("ATC artifact paths must not use symlinks")
    if root not in target.resolve().parents:
        raise ATCCapabilityError("ATC artifact escapes the workspace")
    return target


def _copy_verified(root: Path, relative: str, source: Path, expected: str) -> None:
    temporary = None
    try:
        target = _safe_artifact(root, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if _digest(target) != expected:
                raise ATCCapabilityError("Retained ATC native artifact has changed")
            return
        descriptor, name = tempfile.mkstemp(prefix=".atc-", suffix=".tmp", dir=target.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output, _open_regular(source) as stream:
            if _hash_stream(stream, output) != expected:
                raise ATCCapabilityError("ATC native release changed while preparing execution")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, _safe_artifact(root, relative), follow_symlinks=False)
        except FileExistsError:
            if _digest(_safe_artifact(root, relative)) != expected:
                raise ATCCapabilityError("Retained ATC native artifact has changed")
    except OSError as exc:
        raise ATCCapabilityError("ATC native artifact could not be prepared safely") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prepare_release(workspace_root: Path, release: dict[str, Any]) -> dict[str, str]:
    identity = release["identity"]
    relative = f"barragan/artifacts/atc-{SOURCE_REVISION}-{identity['sha256']}.tar.gz"
    _copy_verified(workspace_root, relative, Path(release["path"]), identity["sha256"])
    checked = _verify_release(_safe_artifact(workspace_root, relative), identity["sha256"], identity["postgresImage"])
    if checked != identity:
        raise ATCCapabilityError("ATC native release identity changed during preparation")
    return {**identity, "relativePath": relative}


def execution_inputs(workspace_root: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    configuration = normalize_configuration(metadata.get(CONFIGURATION_KEY), required=True)
    context = _context(metadata.get(CONTEXT_KEY))
    release = metadata.get(RELEASE_KEY)
    if not isinstance(release, dict):
        raise ATCCapabilityError("Save ATC configuration to prepare its reviewed native release")
    digest = release.get("sha256")
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or release.get("sourceRevision") != SOURCE_REVISION or release.get("version") != RELEASE_VERSION
            or not isinstance(release.get("postgresImage"), str) or not re.fullmatch(POSTGRES_PATTERN, release["postgresImage"])
            or not isinstance(release.get("migrationLevel"), str) or not re.fullmatch(r"[0-9a-f]{64}", release["migrationLevel"])):
        raise ATCCapabilityError("ATC native release identity is invalid or no longer pinned")
    relative = f"barragan/artifacts/atc-{SOURCE_REVISION}-{digest}.tar.gz"
    if set(release) != {"sha256", "sourceRevision", "version", "postgresImage", "migrationLevel", "relativePath"} or release.get("relativePath") != relative:
        raise ATCCapabilityError("ATC native release path does not match its pinned identity")
    if _digest(_safe_artifact(workspace_root, relative)) != digest:
        raise ATCCapabilityError("ATC native artifact is missing or changed; save and prepare again")
    return {"configuration": configuration, "engagement": context, "release": dict(release)}


def copy_artifacts(destination: Path, source_root: Path, inputs: dict[str, Any]) -> None:
    metadata = {CONFIGURATION_KEY: inputs["configuration"], CONTEXT_KEY: inputs["engagement"], RELEASE_KEY: inputs["release"]}
    checked = execution_inputs(source_root, metadata)
    release = checked["release"]
    _copy_verified(destination, release["relativePath"], _safe_artifact(source_root, release["relativePath"]), release["sha256"])
    execution_inputs(destination, metadata)


def role_variables(inputs: dict[str, Any]) -> dict[str, Any]:
    config, context, release = inputs["configuration"], inputs["engagement"], inputs["release"]
    return {"atc_release_archive": "{{ playbook_dir }}/../" + release["relativePath"],
            "atc_release_sha256": release["sha256"], "atc_source_revision": SOURCE_REVISION,
            "atc_release_version": RELEASE_VERSION, "atc_postgres_image": release["postgresImage"],
            "atc_install_root": "/opt/atc", "atc_python_executable": "/usr/bin/python3",
            "atc_port": config["port"], "atc_operator_os_user": "user",
            "atc_engagement_id": context["id"], "atc_engagement_codename": context["codename"],
            "atc_engagement_status": "active", "atc_operator_id": config["operatorId"],
            "atc_operator_name": config["operatorName"]}
