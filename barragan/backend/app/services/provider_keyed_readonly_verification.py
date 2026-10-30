# Copyright (c) 2026, Oracle and/or its affiliates.
"""Operation-local transcripts for already checked read-only Terraform commands.

Every lookup rereads the complete command inputs. The writer may only consume
an exact transcript captured before its transaction; it never runs a command.
This is not a cache of authority, credentials, gates or database results.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import threading


class ReadonlyVerificationChanged(ValueError):
    pass


def _owner():
    try:
        task = asyncio.current_task()
    except RuntimeError:
        task = None
    return threading.get_ident(), task


@dataclass
class _Scope:
    transcripts: dict[bytes, tuple[int, str, str]] = field(default_factory=dict)
    hits_only: bool = False
    owner: tuple = field(default_factory=_owner)
    runners: list = field(default_factory=list)

    def require_hits_only(self):
        self.hits_only = True


_current: ContextVar[_Scope | None] = ContextVar("keyed_readonly_verification", default=None)


@contextmanager
def readonly_verification_scope():
    existing = _current.get()
    if existing is not None:
        if existing.owner != _owner():
            raise ReadonlyVerificationChanged("read-only verification scope crossed an execution boundary")
        yield existing
        return
    scope = _Scope()
    token = _current.set(scope)
    try:
        yield scope
    finally:
        scope.transcripts.clear()
        scope.runners.clear()
        _current.reset(token)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def _links(path):
    """Include intermediate links that Path.resolve would otherwise hide."""
    pending = list(path.absolute().parts[1:])
    current = Path("/")
    links = []
    while pending:
        part = pending.pop(0)
        if part == "..":
            current = current.parent
            continue
        candidate = current / part
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode):
            if len(links) >= 64:
                raise ReadonlyVerificationChanged("verification input contains a symlink cycle")
            target = Path(os.readlink(candidate))
            links.append((str(candidate), _identity(info), str(target)))
            if target.is_absolute():
                current = Path("/")
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            current = candidate
    return links


def _file(path: Path, *, allow_link=False):
    before = path.lstat()
    link = os.readlink(path) if stat.S_ISLNK(before.st_mode) else None
    if link is not None and not allow_link:
        raise ReadonlyVerificationChanged("read-only verification input is a symlink")
    resolved = path.resolve(strict=True)
    descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not 0 <= opened.st_size <= 512 * 1024 * 1024:
            raise ReadonlyVerificationChanged("read-only verification input is not a bounded file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if (_identity(opened) != _identity(os.fstat(descriptor))
                or _identity(before) != _identity(path.lstat())
                or resolved != path.resolve(strict=True)
                or _identity(opened) != _identity(resolved.stat())):
            raise ReadonlyVerificationChanged("read-only verification input changed while read")
        return (str(path), _identity(before), link, _links(path), str(resolved),
                _identity(opened), digest.hexdigest())
    finally:
        os.close(descriptor)


def _tree(root: Path):
    """Bind every provider entry, including linked directories and target bytes."""
    rows = []
    active = set()

    def visit(path, label):
        if len(rows) >= 4096:
            raise ReadonlyVerificationChanged("provider input tree exceeds bound")
        info = path.lstat()
        resolved = path.resolve(strict=True)
        if resolved.is_dir():
            identity = (resolved.stat().st_dev, resolved.stat().st_ino)
            if identity in active:
                raise ReadonlyVerificationChanged("provider input tree contains a cycle")
            active.add(identity)
            names = tuple(sorted(child.name for child in path.iterdir()))
            rows.append((label, _identity(info),
                         os.readlink(path) if path.is_symlink() else None,
                         _links(path), str(resolved), _identity(resolved.stat()), names))
            for name in names:
                visit(path / name, label + "/" + name)
            if (names != tuple(sorted(child.name for child in path.iterdir()))
                    or _identity(info) != _identity(path.lstat())):
                raise ReadonlyVerificationChanged("provider input tree changed while read")
            active.remove(identity)
        else:
            rows.append((label, _file(path, allow_link=True)))

    visit(root, ".")
    return rows


def _inputs(argv, cwd, env, runner, options):
    if (type(argv) is not list or any(type(value) is not str for value in argv)
            or type(env) is not dict
            or any(type(key) is not str or type(value) is not str for key, value in env.items())):
        raise ReadonlyVerificationChanged("read-only verification command shape changed")
    if (set(options) != {"capture_output", "text", "check", "timeout"}
            or options["capture_output"] is not True or options["text"] is not True
            or options["check"] is not False or type(options["timeout"]) not in (int, float)
            or not 0 < options["timeout"] <= 60):
        raise ReadonlyVerificationChanged("read-only verification command options changed")
    binary = Path(argv[0])
    if not binary.is_absolute():
        raise ReadonlyVerificationChanged("read-only verification binary is not absolute")
    value = {"schema": 1, "argv": argv, "cwd": str(cwd), "environment": env,
             "runnerIdentity": id(runner), "options": options,
             "binary": _file(binary)}
    if argv[1:] == ["version", "-json"]:
        pass
    elif len(argv) == 4 and argv[1:3] == ["show", "-json"]:
        root = Path(cwd)
        plan = Path(argv[3])
        if not root.is_absolute() or plan.parent != root:
            raise ReadonlyVerificationChanged("read-only verification plan path changed")
        marker = root / ".barragan-provider-keyed-state.json"
        # Existing workspace audits still run before this function. Include all
        # source inventory members as well as auto-loaded source/input names.
        marker_raw = marker.read_bytes()
        ownership = json.loads(marker_raw)
        names = set(ownership["source_files"]) | set(ownership["rendered_files"])
        names.update((".barragan-provider-keyed-state.json", ".barragan-topology.json",
                      ".terraform.lock.hcl"))
        directories = [root]
        for path in root.rglob("*"):
            if path.is_dir():
                directories.append(path)
            if path.name.endswith((".tf", ".tf.json", ".tfvars", ".tfvars.json")):
                names.add(path.relative_to(root).as_posix())
        if any(Path(name).is_absolute() or ".." in Path(name).parts for name in names):
            raise ReadonlyVerificationChanged("read-only verification source path changed")
        source = [_file(root / name) for name in sorted(names)]
        marker_digest = next(row[-1] for row in source if row[0] == str(marker))
        if hashlib.sha256(marker_raw).hexdigest() != marker_digest:
            raise ReadonlyVerificationChanged("source inventory changed while read")
        value.update(plan=_file(plan), source=source,
                     sourceDirectories=[(str(path), _identity(path.lstat()), _links(path), str(path.resolve(strict=True)),
                                         _identity(path.stat())) for path in sorted(directories)],
                     providers=_tree(Path(env["TF_DATA_DIR"]) / "providers"))
    else:
        raise ReadonlyVerificationChanged("command is not read-only verification")
    # No raw paths, environment values, command output or input bytes leave memory.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).digest()


def run_readonly_verification(argv, *, cwd, env, runner, **options):
    scope = _current.get()
    if scope is None:
        return runner(argv, cwd=cwd, env=env, **options)
    if scope.owner != _owner():
        raise ReadonlyVerificationChanged("read-only verification scope crossed an execution boundary")
    # Detach caller-owned mutable command inputs before fingerprinting and use
    # those exact values for the actual command, including its postcheck.
    if type(argv) is not list or type(env) is not dict:
        raise ReadonlyVerificationChanged("read-only verification command shape changed")
    argv, env, options = list(argv), dict(env), dict(options)
    key = _inputs(argv, cwd, env, runner, options)
    if key in scope.transcripts:
        code, stdout, stderr = scope.transcripts[key]
        return subprocess.CompletedProcess(argv, code, stdout, stderr)
    if scope.hits_only:
        raise ReadonlyVerificationChanged("read-only verification requires a fresh prewriter capture")
    result = runner(argv, cwd=cwd, env=env, **options)
    if (result.returncode != 0 or type(result.stdout) is not str or type(result.stderr) is not str
            or len(result.stdout.encode()) + len(result.stderr.encode()) > 32 * 1024 * 1024
            or _inputs(argv, cwd, env, runner, options) != key):
        raise ReadonlyVerificationChanged("read-only verification capture changed")
    if len(scope.transcripts) >= 128:
        raise ReadonlyVerificationChanged("read-only verification capture set exceeds bound")
    scope.transcripts[key] = (result.returncode, result.stdout, result.stderr)
    scope.runners.append(runner)  # Retain identity until the owning operation ends.
    return result
