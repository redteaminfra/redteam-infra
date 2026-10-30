# Copyright (c) 2026, Oracle and/or its affiliates.
"""Bounded, no-follow Static Web content inspection and per-file transactions.

This module is also executed as a standalone script on the selected proxy.
No operator content is returned by inspection. Exchanges retain displaced bytes
until success; conflicts retain every captured version in a private directory.
"""
from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import grp
import json
import os
from pathlib import Path
import stat
import sys
import time
from uuid import uuid4

MAX_FILES = 4096
MAX_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 32
MAX_SECONDS = 8
OWNER = {"managedBy": "barragan", "stackModel": "containerized-openresty-v1"}


class ContentError(ValueError):
    pass


def _open_dir(path, *, create=False):
    """Open each absolute ancestor without following symlinks."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ContentError("content path must be absolute and confined")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None
                os.mkdir(part, 0o775, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.fchown(child, -1, grp.getgrnam("redteam").gr_gid)
                os.fchmod(child, 0o775)
            os.close(fd)
            fd = child
        return fd
    except OSError as exc:
        os.close(fd)
        raise ContentError("content directory is inaccessible or contains a symlink") from exc


def _bytes(fd, name, limit=MAX_BYTES):
    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o444 or before.st_size > limit:
            raise ContentError("content file is unreadable, unsupported or exceeds inspection limits")
        pieces = []
        total = 0
        while True:
            piece = os.read(file_fd, min(1024 * 1024, limit - total + 1))
            if not piece:
                break
            pieces.append(piece)
            total += len(piece)
            if total > limit:
                raise ContentError("content exceeds inspection limits")
        if _identity(before) != _identity(os.fstat(file_fd)):
            raise ContentError("website files changed during inspection; review again")
        return b"".join(pieces), before
    finally:
        os.close(file_fd)


def _identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def inspect_content(root, site):
    if not site or any(part in site for part in ("/", "\\", "..")):
        raise ContentError("invalid site path")
    root_fd = _open_dir(root)
    if root_fd is not None:
        try:
            names = os.listdir(root_fd)
            if names:
                try:
                    marker, _ = _bytes(root_fd, ".barragan-stack.json", 1024)
                    if json.loads(marker) != OWNER:
                        raise ContentError("web directory is not Barragan-owned")
                except (OSError, ValueError) as exc:
                    raise ContentError("web directory ownership could not be verified") from exc
        finally:
            os.close(root_fd)
    fd = _open_dir(Path(root) / site / "html")
    records = []
    total = 0
    deadline = time.monotonic() + MAX_SECONDS

    def scan(directory, prefix="", depth=0):
        nonlocal total
        if depth > MAX_DEPTH or not os.fstat(directory).st_mode & 0o555:
            raise ContentError("content directory is unreadable or exceeds inspection limits")
        before = os.fstat(directory)
        for name in sorted(os.listdir(directory)):
            if len(records) >= MAX_FILES or time.monotonic() > deadline:
                raise ContentError("website exceeds bounded inspection limits")
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            relative = prefix + name
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    records.append([relative, "directory", _identity(info)])
                    scan(child, relative + "/", depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                data, opened = _bytes(directory, name, MAX_BYTES - total)
                if _identity(info) != _identity(opened):
                    raise ContentError("website changed during inspection; review again")
                total += len(data)
                records.append([relative, "file", _identity(opened), hashlib.sha256(data).hexdigest()])
            else:
                raise ContentError("website contains a symlink or unsupported filesystem entry")
        if _identity(before) != _identity(os.fstat(directory)):
            raise ContentError("website changed during inspection; review again")

    try:
        if fd is not None:
            scan(fd)
        observation = {"exists": fd is not None, "entries": records}
        return {"state": "existing" if records else "empty", "fingerprint": hashlib.sha256(json.dumps(observation, sort_keys=True).encode()).hexdigest(), "entryCount": len(records), "bytes": total, "entries": records}
    except OSError as exc:
        raise ContentError("website inspection failed; check directory access and review again") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _exchange(fd, left, right):
    """Atomic swap; unlike replace, neither captured file is discarded."""
    libc = ctypes.CDLL(None, use_errno=True)
    if hasattr(libc, "renameat2"):
        result = libc.renameat2(fd, os.fsencode(left), fd, os.fsencode(right), 2)
    elif hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(fd, os.fsencode(left), fd, os.fsencode(right), 2)
    else:
        raise ContentError("atomic content exchange is unavailable on this host")
    if result:
        raise OSError(ctypes.get_errno(), "atomic content exchange failed")


def _write_private(directory, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        raise


def _retain(directory, name, private):
    """Copy a randomly named captured version privately before removing it."""
    data, _ = _bytes(directory, name)
    private = Path(private)
    private_fd = _open_dir(private, create=True)
    try:
        os.fchmod(private_fd, 0o700)
        filename = uuid4().hex
        _write_private(private_fd, filename, data)
    finally:
        os.close(private_fd)
    os.unlink(name, dir_fd=directory)
    return str(private / filename)


def _replace(directory, name, data, expected, conflicts, attributes=None):
    temporary = "." + uuid4().hex
    _write_private(directory, temporary, data)
    try:
        candidate = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            if attributes is not None:
                os.fchown(candidate, attributes["uid"], attributes["gid"])
                os.fchmod(candidate, attributes["mode"])
            else:
                os.fchown(candidate, -1, grp.getgrnam("redteam").gr_gid)
                os.fchmod(candidate, 0o664)
        finally:
            os.close(candidate)
        if expected is None:
            # Hard link is atomic create-only: a concurrent upload wins.
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
            return None, None
        _exchange(directory, temporary, name)
        try:
            old, info = _bytes(directory, temporary)
        except (OSError, ContentError):
            _exchange(directory, temporary, name)
            raise ContentError("content destination changed or became unsafe; review again")
        if hashlib.sha256(old).hexdigest() != expected[3] or _identity(info)[:4] != expected[2][:4]:
            # Put the displaced file back, retaining anything else captured by
            # the recovery exchange. Never destroy an operator's version.
            _exchange(directory, temporary, name)
            captured, _ = _bytes(directory, temporary)
            if captured != data:
                _retain(directory, temporary, conflicts)
            else:
                os.unlink(temporary, dir_fd=directory)
            raise ContentError("website changed during replacement; operator bytes preserved; review again")
        os.unlink(temporary, dir_fd=directory)
        return base64.b64encode(old).decode(), {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
    except Exception:
        try:
            _retain(directory, temporary, conflicts)
        except FileNotFoundError:
            pass
        raise


def _retain_prior(request, write):
    if write["prior"] is None:
        return
    private = _open_dir(request["conflicts"], create=True)
    try:
        os.fchmod(private, 0o700)
        _write_private(private, uuid4().hex, base64.b64decode(write["prior"]))
    finally:
        os.close(private)


def _journal(request, writes, outcome):
    if not request.get("receipt"):
        return
    path = Path(request["receipt"])
    private = _open_dir(path.parent)
    if private is None:
        raise ContentError("private operation directory is missing")
    temporary = uuid4().hex
    try:
        data = json.dumps({"action": request["action"], "outcome": outcome, "writes": writes}).encode()
        _write_private(private, temporary, data)
        os.replace(temporary, path.name, src_dir_fd=private, dst_dir_fd=private)
    finally:
        os.close(private)


def apply_content(request, *, before_write=None):
    root, site = request["root"], request["site"]
    if request["action"] not in {"preserve", "restore-starter", "publish"}:
        raise ContentError("unsupported content action")
    before = inspect_content(root, site)
    expected = request.get("fingerprint")
    if expected and before["fingerprint"] != expected:
        raise ContentError("website files changed since review; request a fresh review")
    action = request["action"]
    if action == "preserve" and before["state"] == "existing":
        return {"action": action, "outcome": "preserved", "writes": []}
    if before_write:
        before_write()
    # Recheck immediately before creating/opening any content directory.
    if inspect_content(root, site)["fingerprint"] != before["fingerprint"]:
        raise ContentError("website files changed before write; request a fresh review")
    directory = _open_dir(Path(root) / site / "html", create=True)
    writes = []
    entries = {entry[0]: entry for entry in before["entries"]}
    files = request["files"] if action == "publish" else [{"path": "index.html", "data": request["starter"]}]
    try:
        for item in files:
            relative = Path(item["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ContentError("publish path escapes website")
            parent_path = Path(root) / site / "html" / relative.parent
            parent = _open_dir(parent_path, create=True)
            try:
                prior = entries.get(relative.as_posix())
                if prior is not None and prior[1] != "file":
                    raise ContentError("index or publish destination is not a regular file")
                data = base64.b64decode(item["data"], validate=True)
                old, attributes = _replace(parent, relative.name, data, prior, request["conflicts"])
                info = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
                writes.append({"path": relative.as_posix(), "prior": old, "priorAttributes": attributes, "writtenHash": hashlib.sha256(data).hexdigest(), "identity": _identity(info)[:2]})
                _journal(request, writes, "content-write-in-progress")
            finally:
                os.close(parent)
        return {"action": action, "outcome": "initialized" if action == "preserve" else "published" if action == "publish" else "restored-starter", "writes": writes}
    except Exception:
        rollback_content({**request, "writes": writes})
        raise
    finally:
        os.close(directory)


def _rollback_one(request, write):
    relative = Path(write["path"])
    directory = _open_dir(Path(request["root"]) / request["site"] / "html" / relative.parent)
    if directory is None:
        raise ContentError("content rollback destination disappeared")
    try:
        current, info = _bytes(directory, relative.name)
        if hashlib.sha256(current).hexdigest() != write["writtenHash"] or _identity(info)[:2] != write["identity"]:
            raise ContentError("operator content changed after apply; rollback preserved it and requires review")
        if write["prior"] is not None:
            expected = [write["path"], "file", _identity(info), write["writtenHash"]]
            _replace(directory, relative.name, base64.b64decode(write["prior"]), expected, request["conflicts"], write["priorAttributes"])
        else:
            temporary = "." + uuid4().hex
            os.rename(relative.name, temporary, src_dir_fd=directory, dst_dir_fd=directory)
            captured, captured_info = _bytes(directory, temporary)
            if hashlib.sha256(captured).hexdigest() != write["writtenHash"] or _identity(captured_info)[:2] != write["identity"]:
                try:
                    os.link(temporary, relative.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                    os.unlink(temporary, dir_fd=directory)
                except FileExistsError:
                    _retain(directory, temporary, request["conflicts"])
                raise ContentError("operator upload raced rollback; its bytes were preserved")
            os.unlink(temporary, dir_fd=directory)
    finally:
        os.close(directory)


def rollback_content(request):
    errors = []
    for write in reversed(request.get("writes", [])):
        try:
            _rollback_one(request, write)
        except (OSError, ContentError, ValueError) as error:
            errors.append(error)
    if errors:
        # Retain every original version, including writes not reached by an
        # earlier failure. The remote operation journal is also retained by
        # Ansible when rollback fails, so retention errors cannot erase it.
        for write in request.get("writes", []):
            try:
                _retain_prior(request, write)
            except (OSError, ContentError, ValueError):
                pass
        raise ContentError("operator content changed or became inaccessible; rollback preserved current paths and retained prior bytes privately; review required") from errors[0]
    return {"outcome": "content-rollback-complete"}


def main(request):
    if request["mode"] == "inspect":
        result = inspect_content(request["root"], request["site"])
        result.pop("entries")
    elif request["mode"] == "check":
        result = inspect_content(request["root"], request["site"])
        result.pop("entries")
        if result["fingerprint"] != request["fingerprint"]:
            raise ContentError("website files changed since review; request a fresh review")
    elif request["mode"] == "apply":
        result = apply_content(request)
        _journal(request, result["writes"], result["outcome"])
        result = {key: value for key, value in result.items() if key != "writes"}
    elif request["mode"] == "rollback":
        receipt = Path(request["receipt"])
        result = rollback_content({**request, **json.loads(receipt.read_text())}) if receipt.exists() else {"outcome": "no-content-writes"}
    else:
        raise ContentError("unsupported content operation")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main(json.loads(Path(sys.argv[1]).read_text()))
    except (ContentError, OSError, ValueError, KeyError) as error:
        print(json.dumps({"error": str(error)}))
        sys.exit(1)
