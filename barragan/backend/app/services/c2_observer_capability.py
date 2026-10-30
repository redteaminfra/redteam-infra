# Copyright (c) 2026, Oracle and/or its affiliates.
"""Pinned C2 Observer CLI tooling artifacts, with no collection or publication."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any

CAPABILITY_ID = "c2-observer"
SOURCE_REVISION = "9e7720e6c16d302d1a6f1758e788d5f8051752a1"
DEPENDENCY_SHA256 = "bbb76a70325e7974a7a3c7fdd2fb26bade5f2aa4b91094e91beaac80f367fd40"
SOURCE_ROOT_ENV = "BARRAGAN_C2_OBSERVER_SOURCE_ROOT"
DEPENDENCY_LOCK_ENV = "BARRAGAN_C2_OBSERVER_DEPENDENCY_LOCK"
ARTIFACTS_KEY = "c2ObserverArtifacts"
SOURCE_LIMIT = 64 * 1024 * 1024
LOCK_LIMIT = 256 * 1024


class C2ObserverArtifactError(ValueError):
    pass


def is_selected(overrides: dict[str, Any]) -> bool:
    return any(row.get("id") == CAPABILITY_ID and row.get("hostClass") == "homebase"
               for row in overrides.get("selectedOptionals", []) if isinstance(row, dict))


def _git(root: Path, *args: str, binary: bool = False) -> Any:
    try:
        return subprocess.run(["git", "--no-optional-locks", *args], cwd=root,
                              capture_output=True, text=not binary, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise C2ObserverArtifactError("C2 Observer controller source could not be verified or archived") from exc


def _read_regular(path: Path, limit: int) -> bytes:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise C2ObserverArtifactError("C2 Observer artifact must be a bounded regular file")
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        with stream:
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise C2ObserverArtifactError("C2 Observer artifact exceeds the allowed size")
        return content
    except OSError as exc:
        raise C2ObserverArtifactError("C2 Observer artifact is unavailable or unsafe") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def controller_artifacts() -> dict[str, bytes]:
    configured = os.environ.get(SOURCE_ROOT_ENV, "").strip()
    if not configured:
        raise C2ObserverArtifactError(f"Controller administrator must configure {SOURCE_ROOT_ENV}")
    root = Path(configured).resolve()
    if not root.is_dir() or Path(_git(root, "rev-parse", "--show-toplevel").strip()).resolve() != root:
        raise C2ObserverArtifactError("C2 Observer source must be its own Git checkout")
    def verify() -> None:
        if _git(root, "rev-parse", "HEAD").strip() != SOURCE_REVISION:
            raise C2ObserverArtifactError(f"C2 Observer source must be pinned at {SOURCE_REVISION}")
        if _git(root, "status", "--porcelain", "--untracked-files=all").strip():
            raise C2ObserverArtifactError("C2 Observer source checkout must be clean")
    verify()
    archive = _git(root, "archive", "--format=tar.gz", SOURCE_REVISION, binary=True)
    verify()
    if len(archive) > SOURCE_LIMIT:
        raise C2ObserverArtifactError("C2 Observer source archive exceeds the allowed size")
    lock_path = os.environ.get(DEPENDENCY_LOCK_ENV, "").strip()
    if not lock_path:
        raise C2ObserverArtifactError(f"Controller administrator must configure {DEPENDENCY_LOCK_ENV}")
    lock = _read_regular(Path(lock_path), LOCK_LIMIT)
    if hashlib.sha256(lock).hexdigest() != DEPENDENCY_SHA256:
        raise C2ObserverArtifactError("C2 Observer dependency lock does not match the reviewed pin")
    return {"source": archive, "dependencyLock": lock}


def _safe_artifact(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not re.fullmatch(
        r"barragan/artifacts/c2-observer-(?:[0-9a-f]{40}-[0-9a-f]{64}\.tar\.gz|dependencies-[0-9a-f]{64}\.lock)", relative
    ):
        raise C2ObserverArtifactError("C2 Observer artifact path is invalid")
    root = root.resolve()
    target = root / relative
    for path in [target, *target.parents]:
        if path == root:
            break
        if path.is_symlink():
            raise C2ObserverArtifactError("C2 Observer artifacts must not use symlinks")
    if root not in target.resolve().parents:
        raise C2ObserverArtifactError("C2 Observer artifact escapes the workspace")
    return target


def _write_artifact(root: Path, relative: str, content: bytes) -> None:
    temporary = None
    try:
        target = _safe_artifact(root, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        def verify_existing() -> None:
            if _read_regular(_safe_artifact(root, relative), SOURCE_LIMIT) != content:
                raise C2ObserverArtifactError("Retained C2 Observer artifact has changed")
        if target.exists():
            verify_existing()
            return
        descriptor, name = tempfile.mkstemp(prefix=".c2-observer-", suffix=".tmp", dir=target.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        # A final immutable name is visible only after the whole private file is
        # durable. Hard-link publication refuses to clobber a concurrent final.
        target = _safe_artifact(root, relative)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            verify_existing()
    except OSError as exc:
        raise C2ObserverArtifactError("C2 Observer artifact could not be prepared safely") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prepare_artifacts(workspace_root: Path, artifacts: dict[str, bytes]) -> dict[str, Any]:
    archive, lock = artifacts["source"], artifacts["dependencyLock"]
    digest = hashlib.sha256(archive).hexdigest()
    if len(archive) > SOURCE_LIMIT or len(lock) > LOCK_LIMIT or hashlib.sha256(lock).hexdigest() != DEPENDENCY_SHA256:
        raise C2ObserverArtifactError("C2 Observer artifacts do not match the reviewed bounds/pins")
    source_path = f"barragan/artifacts/c2-observer-{SOURCE_REVISION}-{digest}.tar.gz"
    lock_path = f"barragan/artifacts/c2-observer-dependencies-{DEPENDENCY_SHA256}.lock"
    _write_artifact(workspace_root, source_path, archive)
    _write_artifact(workspace_root, lock_path, lock)
    return {"source": {"revision": SOURCE_REVISION, "sha256": digest, "relativePath": source_path},
            "dependencyLock": {"sha256": DEPENDENCY_SHA256, "relativePath": lock_path}}


def execution_inputs(workspace_root: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    artifacts = metadata.get(ARTIFACTS_KEY)
    if not isinstance(artifacts, dict):
        raise C2ObserverArtifactError("Save C2 Observer selection to prepare its pinned source and dependency lock")
    source, lock = artifacts.get("source"), artifacts.get("dependencyLock")
    if not isinstance(source, dict) or not isinstance(lock, dict):
        raise C2ObserverArtifactError("C2 Observer artifact identities are missing")
    digest = source.get("sha256")
    if source.get("revision") != SOURCE_REVISION or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise C2ObserverArtifactError("C2 Observer source identity does not match the reviewed pin")
    expected = {
        "source": {"revision": SOURCE_REVISION, "sha256": digest,
                   "relativePath": f"barragan/artifacts/c2-observer-{SOURCE_REVISION}-{digest}.tar.gz"},
        "dependencyLock": {"sha256": DEPENDENCY_SHA256,
                           "relativePath": f"barragan/artifacts/c2-observer-dependencies-{DEPENDENCY_SHA256}.lock"},
    }
    if artifacts != expected:
        raise C2ObserverArtifactError("C2 Observer artifact paths/digests do not match their pinned identities")
    for kind, limit in [("source", SOURCE_LIMIT), ("dependencyLock", LOCK_LIMIT)]:
        identity = expected[kind]
        content = _read_regular(_safe_artifact(workspace_root, identity["relativePath"]), limit)
        if hashlib.sha256(content).hexdigest() != identity["sha256"]:
            raise C2ObserverArtifactError("C2 Observer artifact is missing or changed; save and prepare again")
    return expected


def copy_artifacts(destination: Path, source_root: Path, inputs: dict[str, Any]) -> None:
    checked = execution_inputs(source_root, {ARTIFACTS_KEY: inputs})
    # Read and hash the bytes actually copied, rather than reopening after a
    # separate checksum check. Verify the destination before running Ansible.
    for kind, limit in [("source", SOURCE_LIMIT), ("dependencyLock", LOCK_LIMIT)]:
        identity = checked[kind]
        content = _read_regular(_safe_artifact(source_root, identity["relativePath"]), limit)
        if hashlib.sha256(content).hexdigest() != identity["sha256"]:
            raise C2ObserverArtifactError("C2 Observer artifact changed while preparing execution")
        _write_artifact(destination, identity["relativePath"], content)
    execution_inputs(destination, {ARTIFACTS_KEY: inputs})


def role_variables(inputs: dict[str, Any]) -> dict[str, str]:
    source, lock = inputs["source"], inputs["dependencyLock"]
    return {"c2_observer_source_archive": "{{ playbook_dir }}/../" + source["relativePath"],
            "c2_observer_source_sha256": source["sha256"],
            "c2_observer_source_revision": source["revision"],
            "c2_observer_dependency_lock": "{{ playbook_dir }}/../" + lock["relativePath"],
            "c2_observer_dependency_sha256": lock["sha256"]}
